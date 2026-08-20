//! `terminus push/pull` — file transfer, driven through the ledger.
//!
//! This command is a *producer* for `transfer_checkpoints`, and that is the
//! whole of what changed. It used to read the entire local file into memory
//! (`readFileAlloc(…, .limited(1 << 31))` — a hard 2 GiB ceiling), hand the
//! buffer to scp, write one `history` row with `catch {}` after it, and print a
//! byte count. It created no operation, no checkpoint and no receipt, so a
//! transfer that half-happened left nothing behind that anybody could reason
//! about, and a truncated one printed the smaller number as a success.
//!
//! What it does now is walk the machinery that was already there:
//!
//!   `execution.begin` → `transfers.create` → `probing` (identify the source,
//!   digest included) → `transferring` (stream, advancing a confirmed offset
//!   behind a prefix digest) → `verifying` (compare the two ends) →
//!   `publishing` (one rename) → `published`, or `completed_unverified` when no
//!   trustworthy remote digest was available.
//!
//! **The source is read twice on a push, and that is the design rather than a
//! compromise.** `FileIdentity.sha256` is deliberately null at `create` time,
//! and a non-zero confirmed offset may not exist without it — enforced by the
//! schema (`offset_needs_source_identity`) and again by `verifyResume`. So the
//! digest has to be recorded before any offset is confirmed, which means one
//! pass to hash and one to send. Folding them into a single pass would make
//! every intermediate offset unconfirmable and take resume with it. A source
//! that changes between the two reads is caught: the streaming pass hashes what
//! it sends, and a push whose two readings disagree is `failed_source_changed`.
//!
//! **Nothing is written at the destination until the digests agree.** Every
//! byte goes to a staging partial beside the destination; the last act is a
//! rename. So a hash mismatch, a full disk and a failed publish all leave what
//! was at the destination exactly as it was — by construction, not by care.
//!
//! **A transfer that did not publish keeps its destination**, so the next one
//! aimed there is refused rather than walking onto the leftovers
//! (`State.holdsDestination`). Two acts get past that, and they are for
//! different states:
//!
//!   * `--resume` **adopts** an adoptable checkpoint — `planned`, `probing`,
//!     `transferring`, `paused` — and continues it from its confirmed offset.
//!     Nothing is discarded: the partial's confirmed prefix is proven and kept,
//!     and the digest the artifact will be judged by is the one the interrupted
//!     attempt declared before its first byte. `execution.adoptCheckpoint` is
//!     the hand-over; `transfers.verifyResume` is the rule it must satisfy
//!     first.
//!   * `--restart` **supersedes** a settled failure and starts over.
//!     `transfers.supersedeLocked` writes `superseded` only over a `failed_*`
//!     state, and only when the attempt that owns the checkpoint can no longer
//!     be affecting the host. The three writes a restart is — the new
//!     operation, the supersession, the replacement checkpoint — are one
//!     transaction, in `execution.beginSupersedingCheckpoint`, because a
//!     supersession that committed alone would leave the path free with nothing
//!     on the way to it.
//!
//! The two sets are disjoint and every state falls in at most one of them, so
//! `wayThrough` names exactly one verb per holder. Offering both for a state
//! only one applies to is worse than the dead end this replaced.
//!
//! **A resume is verifiable end to end, and no pass is made for the sake of it.**
//! A SHA-256 cannot be continued from its own output, so a resumed transfer
//! appears to need either a whole extra read of the confirmed prefix to rebuild
//! the hasher or no end-to-end verification at all. Neither: the two readings a
//! resume must take anyway to be *allowed* — the source, to prove it is still
//! the one the checkpoint recorded, and the staged prefix, to prove it is the
//! bytes we counted — are passes over exactly those bytes, and
//! `transfer.readLocalFile` hands back the hasher as it stood at the mark
//! alongside the digest it was asked for. So the confirmed offset goes on
//! advancing behind a prefix digest exactly as on a fresh transfer, the final
//! digest covers the whole artifact, and the digest it is compared against is
//! `expected_sha256` — declared before the first byte and *unwritable* by the
//! resuming attempt, because `recordExpectedHash` refuses a row that already
//! carries one, is past offset zero, or is no longer before its first byte.
//!
//! Which side the prefix is read on follows from where the partial lives: for a
//! push it is on the host, so the prefix proof is a ranged remote digest and the
//! hasher comes from the local source's own pass; for a pull it is here, so one
//! local pass gives both.
//!
//! **`--resume` is exec-only above offset zero.** libssh2 offers
//! `libssh2_scp_send64` and `libssh2_scp_recv2` and nothing ranged: the first
//! must be told a whole file's length up front and the second fetches a whole
//! file. So `--via scp` together with `--resume` is refused by name rather than
//! attempted, and an unpinned resume reports which backend it was left with and
//! why.
//!
//! **Two backends, as before.** scp is tried first and the exec fallback
//! (base64 over the command channel) is used when the host has no scp binary.
//! Both are streaming now. Both directions run remote shell commands regardless
//! of backend — the probe, the verification and the publish — which is why the
//! remote path is validated unconditionally.
const std = @import("std");
const fatal = Cli.fail;
const Cli = @import("cli.zig");
const Core = @import("../core/core.zig");
const Store = Core.Store;
const digest = Core.digest;
const transfers = Store.transfers;

/// What `--help` and every argument refusal print.
///
/// `pub` so a gate can hold it against `skill/SKILL.md`: a flag documented for an
/// agent and missing from the usage an operator sees is the two audiences being
/// told different things about the same binary.
pub const usage =
    \\usage: terminus push <server> <local-path> <remote-path> [--mode 644] [--via scp|exec] [--resume|--restart] [--no-clobber] [--force] [--json]
    \\       terminus pull <server> <remote-path> <local-path> [--via scp|exec] [--resume|--restart] [--no-clobber] [--force] [--json]
    \\
    \\Bytes are staged beside the destination and renamed into place only after
    \\both ends agree on a SHA-256. A transfer the host cannot hash ends
    \\`completed_unverified`, never `published`.
    \\
    \\`--no-clobber` refuses to replace an existing destination, and refuses it in
    \\the kernel rather than by looking first: the publish becomes `ln` then an
    \\unlink on the host, and an atomic non-replacing rename locally.
    \\
    \\A failed transfer keeps its destination: the next transfer aimed there is
    \\refused until somebody says what to do about the leftovers. There are two
    \\answers and they are for different states. `--resume` continues an
    \\interrupted transfer from its confirmed offset and discards nothing.
    \\`--restart` releases a *settled failure*'s hold and starts over in the same
    \\transaction. Each refuses what the other is for.
    \\
;

pub const Verb = enum { push, pull };

/// Suffix of the staging file, beside the destination. Shared by both
/// directions so an operator finds leftovers under one name.
pub const partial_suffix = ".terminus-part";

/// How often a confirmed offset is written down, in bytes moved.
///
/// A durable offset costs one UPDATE, so this trades how much work a future
/// resume repeats against how many writes a transfer makes: 8 MiB is 256 rows
/// for a 2 GiB file and at most 8 MiB re-sent. The final chunk always confirms
/// regardless, so a completed stream leaves the whole prefix proven.
pub const confirm_every: u64 = 8 << 20;

/// What this transfer turned out to be.
///
/// A caller has to be able to tell these apart — `completed_unverified` above
/// all, which is a delivery nobody could check and must never read as
/// `published`. They carry different exit codes for the same reason.
pub const Outcome = enum {
    /// Both ends hashed to the digest declared before the first byte, and the
    /// rename was watched.
    published,
    /// The bytes arrived and matched their length, and no trustworthy digest
    /// was available to prove they are the right bytes. The artifact is at the
    /// destination; nothing establishes what it is.
    completed_unverified,
    /// The source this end sent is not the source this end hashed. A fresh push
    /// finds it by hashing twice; a resume in either direction finds it before
    /// it moves anything, because re-proving the source is what licenses the
    /// resume at all.
    failed_source_changed,
    /// The staged partial a resume was going to continue is not the prefix this
    /// transfer confirmed — the wrong length, or the right length and the wrong
    /// bytes. Only a resume can find this, and only before it moves anything.
    ///
    /// A separate verdict from `failed_source_changed` because they are separate
    /// facts and they send an operator to different files: one says the thing
    /// being copied changed, the other says the bytes sitting beside the
    /// destination are not the ones this transfer counted. Neither of them is
    /// "start over" — that is `--restart`, and it is the operator's call.
    failed_remote_partial_mismatch,
    /// The two ends disagreed. Nothing was renamed.
    failed_hash_mismatch,
    /// `--no-clobber` was asked for and the destination is already occupied.
    /// Nothing was linked, so the destination holds exactly what it held.
    ///
    /// The only publish refusal that is a fact about the operator's data rather
    /// than about the mechanism, which is why it is not `failed_publish`: a host
    /// that cannot hard-link and an empty destination are a mechanism failure,
    /// and reporting either as this would be a false statement about what is at
    /// the path.
    failed_clobber_conflict,
    /// The rename reported failure. Nothing was renamed.
    failed_publish,
    /// The rename was issued and its answer was lost. It may or may not have
    /// landed — never reported as a failure.
    indeterminate_publish,
    /// Interrupted before the destination came into it at all. The checkpoint
    /// is trustworthy and a later attempt can take it over.
    paused,

    pub fn ok(o: Outcome) bool {
        return o == .published;
    }

    /// The process exit code.
    ///
    /// `completed_unverified` is **not** 0, and the reason is what the ledger
    /// holds rather than an opinion about the bytes: the operation settles
    /// `indeterminate` and nothing resolves it, because no digest was declared
    /// for a reading of the destination to be compared against. A caller told
    /// `0` would be told the ledger agrees that this worked, and it does not.
    pub fn exitCode(o: Outcome) u8 {
        return switch (o) {
            .published => Cli.exit_code.ok,
            .failed_source_changed,
            .failed_remote_partial_mismatch,
            .failed_hash_mismatch,
            .failed_clobber_conflict,
            .failed_publish,
            => Cli.exit_code.failure,
            .completed_unverified, .indeterminate_publish, .paused => Cli.exit_code.indeterminate,
        };
    }

    pub fn text(o: Outcome) []const u8 {
        return @tagName(o);
    }

    /// The outcome that names this checkpoint state, or null when none does.
    ///
    /// Derived rather than switched. Every `Outcome` is named after a checkpoint
    /// state and a gate holds the two vocabularies against each other, so a
    /// hand-written mapping here would be a third copy of that correspondence
    /// and the first one to drift.
    pub fn naming(state: transfers.State) ?Outcome {
        return std.meta.stringToEnum(Outcome, state.text());
    }

    /// What this outcome establishes, in the field an agent reads before `ok`.
    pub fn proves(o: Outcome) []const u8 {
        return switch (o) {
            .published => "the artifact is at the destination and both ends hashed to the digest declared before the first byte",
            .completed_unverified => "bytes arrived and matched their length; no trustworthy remote digest was available, so nothing establishes they are the right bytes",
            .failed_source_changed => "the source is not the one this transfer was about; nothing was renamed and the destination is untouched",
            .failed_remote_partial_mismatch => "the staged partial beside the destination is not the prefix this transfer confirmed, so nothing could be spliced onto it; nothing was sent and the destination is untouched",
            .failed_hash_mismatch => "the two ends hashed to different digests; nothing was renamed and the destination is untouched",
            .failed_clobber_conflict => "--no-clobber was asked for and something already occupies the destination; nothing was linked and the destination holds exactly what it held",
            .failed_publish => "the rename reported failure; nothing was renamed and the destination is untouched",
            .indeterminate_publish => "the rename was issued and its answer was lost; it may or may not have landed",
            .paused => "the transfer stopped before the destination came into it; the destination is untouched and the staged partial is trustworthy",
        };
    }

    pub fn hint(o: Outcome) ?[]const u8 {
        return switch (o) {
            .published => null,
            .completed_unverified => "install sha256sum or shasum on the host for a verified transfer; this operation stays unresolved until an operator judges it",
            .failed_source_changed, .failed_hash_mismatch, .failed_publish => "the destination still holds what it held; the staged partial is left beside it",
            .failed_clobber_conflict => "the destination is occupied and this transfer promised not to replace it, so nothing was written there; read what is at that path, then either send elsewhere or re-run with --restart and without --no-clobber to replace it deliberately",
            .failed_remote_partial_mismatch => "the confirmed prefix could not be proven, so this attempt is over and it published nothing; re-run with --restart to discard the leftovers and start from zero",
            .indeterminate_publish => "read the destination and reconcile this request against what you find ('terminus request reconcile')",
            .paused => "re-run with --resume to continue from the confirmed offset; nothing is discarded",
        };
    }
};

/// Everything the steps below need, so each of them takes one parameter and
/// none of them can be handed a checkpoint belonging to another transfer.
const Run = struct {
    ctx: *Cli.Ctx,
    store: *Store,
    execution: *Core.execution.Execution,
    client: *Core.Ssh,
    verb: Verb,
    checkpoint: i64,
    /// Where the artifact lands, on whichever machine publishes it.
    dest_path: []const u8,
    /// Where the bytes are staged. Everything writes here; only the publish
    /// touches `dest_path`.
    partial_path: []const u8,
    source_path: []const u8,
    /// Whether this transfer promised not to replace an existing destination.
    ///
    /// On a fresh transfer and on a `--restart` it is this command line's flag,
    /// which is also what `create` wrote to the row. On a `--resume` it is read
    /// **off the row** — see `resumeFrom` — because the column is write-once and
    /// the promise was made before the first byte.
    no_clobber: bool = false,
    /// The digest declared before the first byte, or null when no trustworthy
    /// one was available. This one field decides `published` against
    /// `completed_unverified` all the way down.
    declared_sha256: ?[]const u8 = null,
    /// Whether the source carries a full identity, and therefore whether a
    /// non-zero confirmed offset may be stored at all. False for a pull whose
    /// host could not report an mtime — verification is unaffected, resume is
    /// not available.
    identified: bool = false,
    /// The source's size as the host reported it. A pull needs it for the exec
    /// backend, which asks for one byte range at a time and so has to know
    /// where the file ends.
    remote_size: u64 = 0,
    /// Where this run's first byte goes. Zero on a fresh transfer and on a
    /// resume whose verdict was `start_over`.
    resume_from: u64 = 0,
    /// The stream hasher as it stood at `resume_from`, recovered from the pass
    /// that proved the resume was allowed. Null when there is nothing to
    /// recover, which is every fresh transfer.
    ///
    /// This one field is what makes a resumed transfer's confirmed offsets and
    /// final digest mean the same thing a fresh one's do. Without it the running
    /// digest would cover only this run's bytes, every prefix digest written
    /// behind an advancing offset would describe a range nobody can re-derive,
    /// and the end-to-end comparison would be of a tail against a whole file.
    seed: ?digest.Running = null,
    /// Why this transfer had no choice of backend, when it had none.
    backend_reason: ?[]const u8 = null,
    /// Why the ledger declined to resolve a published transfer, when it did.
    /// Null on every other path, including the ones with nothing to resolve.
    resolution_refused: ?[]const u8 = null,

    fn executor(self: *const Run) Core.Executor {
        return .{ .direct = self.client };
    }

    fn requestId(self: *const Run) []const u8 {
        return self.execution.id();
    }

    fn setState(self: *const Run, to: transfers.State, reason: ?[]const u8) void {
        transfers.setState(self.store, self.checkpoint, self.requestId(), to, reason, self.ctx.now) catch |err|
            Cli.receiptFatal(self.requestId(), err, self.execution.status.text());
    }
};

pub fn run(ctx: *Cli.Ctx, verb: Verb, raw_args: []const []const u8) !void {
    const parsed = Cli.parseArgs(ctx, raw_args);
    if (parsed.boolean("json")) ctx.out.format = .json;

    const server_name = parsed.positional(0) orelse fatal("{s}", .{usage});
    const src = parsed.positional(1) orelse fatal("{s}", .{usage});
    const dst = parsed.positional(2) orelse fatal("{s}", .{usage});
    const via = parsed.flag("via");
    if (via != null and !std.mem.eql(u8, via.?, "scp") and !std.mem.eql(u8, via.?, "exec"))
        fatal("invalid --via '{s}' (scp|exec)", .{via.?});
    const mode: u32 = if (parsed.flag("mode")) |m|
        std.fmt.parseInt(u32, m, 8) catch fatal("invalid --mode '{s}' (octal, e.g. 644)", .{m})
    else
        0o644;

    const want_resume = parsed.boolean("resume");
    const want_restart = parsed.boolean("restart");
    const want_no_clobber = parsed.boolean("no-clobber");
    // Refused rather than ranked. They are for disjoint sets of states — see
    // `wayThrough` — so a command carrying both is a command whose author does
    // not know which situation they are in, and picking one for them would
    // either discard resume material or refuse a restart that was the right
    // answer.
    if (want_resume and want_restart) fatal(
        "--resume and --restart cannot be combined: --resume continues an interrupted transfer from its confirmed offset and discards nothing, --restart releases a settled failure's hold and starts from zero. They apply to different states; read the holder with 'terminus request ls' and pass one",
        .{},
    );
    // Checked here, before an operation exists and before anything is adopted,
    // because a resume's offset is not knowable until a checkpoint has been read
    // and taken over — and refusing after that would leave a live checkpoint
    // holding the path over a flag combination that was never going to work.
    // libssh2 has `libssh2_scp_send64` and `libssh2_scp_recv2` and nothing
    // ranged: the first must be told a whole file's length before the first
    // byte, the second fetches a whole file. There is no offset to give either.
    if (want_resume and via != null and std.mem.eql(u8, via.?, "scp")) fatal(
        "refused: --via scp cannot resume. libssh2's scp support is send64/recv2 — a whole file from byte zero, with no ranged form — so there is nowhere to give it an offset; nothing was sent. Drop --via, or pass --via exec",
        .{},
    );

    // Both backends drive the host's shell for the probe, the verification and
    // the publish, so the remote path is validated whichever one moves the
    // bytes. It used to be checked only on the exec path.
    validateRemotePath(switch (verb) {
        .push => dst,
        .pull => src,
    });

    var store = try Cli.openStore(ctx, &parsed);
    defer store.close();
    const resolved = Cli.resolveServer(ctx, &store, server_name);
    const owner_token = Store.policy.ownerToken(&store, ctx.arena, ctx.io, ctx.now) catch |err|
        Cli.storeFatal(&store, err);

    const dest_path = dst;
    const partial_path = try std.fmt.allocPrint(ctx.arena, "{s}{s}", .{ dest_path, partial_suffix });
    const summary = try std.fmt.allocPrint(ctx.arena, "{t} {s} -> {s}", .{ verb, src, dst });

    const dest_side: transfers.DestSide = switch (verb) {
        .push => .{ .server = resolved.server.id },
        .pull => .local,
    };

    // Everything about the checkpoint except its owner. The restart path mints
    // that id inside the transaction that supersedes the incumbent, so it cannot
    // be named here; the ordinary path fills it in below. One value either way,
    // because a second literal is a second thing to keep in step.
    const plan: transfers.CheckpointPlan = .{
        .direction = switch (verb) {
            .push => .push,
            .pull => .pull,
        },
        .dest_side = dest_side,
        .dest_path = dest_path,
        .partial_path = partial_path,
        .source = switch (verb) {
            .push => .{ .local_file = .{ .path = src } },
            .pull => .{ .remote_file = .{ .path = src } },
        },
        .chunk_size = Core.Ssh.chunk_bytes,
        .total_bytes = switch (verb) {
            // A push can size its source with a stat, which reads no bytes.
            .push => statSize(ctx, src),
            // A pull cannot, without a round trip — and taking one before the
            // checkpoint exists would put the reading outside the state that
            // exists to hold it. The size arrives with the probe instead.
            .pull => null,
        },
        // Honest at last, and it is this command line's flag that makes it so:
        // publishing is an *atomic non-replacing* act when the operator asks for
        // one — `ln` then an unlink on the host, `renamePreserve` locally — so a
        // no-clobber claim on the row is now a promise the driver keeps. See
        // `transfer.publishRemote` and `transfer.publishLocal`.
        //
        // Write-once: nothing updates this column after `create`. That is what
        // makes a `--resume` read it rather than restate it, and what makes a
        // `--resume` asking to *add* the promise a refusal — see `wayIn`.
        .no_clobber = want_no_clobber,
    };

    // Read before an operation exists and before the connection is opened, so a
    // refusal costs nothing and sends nothing. It is not the binding check —
    // that is the live-destination index, inside the same statement as the write
    // — and it does not need to be: everything it can conclude is a refusal, and
    // the two readings that proceed are re-checked under the write lock by
    // `supersedeLocked`'s own conjuncts and by the hand-over statement's.
    const way = wayIn(ctx, &store, dest_side, dest_path, want_resume, want_restart, want_no_clobber);

    // A transfer's blast radius is the path it publishes to, which is what
    // makes two transfers aimed at one directory see each other and a transfer
    // invisible to work elsewhere on the host. A local destination given
    // relatively is a weaker key than an absolute one — two pulls run from
    // different directories into `out.bin` would not collide here — and the
    // live-destination index is what still refuses that pair.
    const begin_opts: Core.execution.BeginOptions = .{
        .server_id = resolved.server.id,
        .server_name = resolved.server.name,
        .kind = switch (verb) {
            .push => .transfer_push,
            .pull => .transfer_pull,
        },
        .scope = .{ .kind = .path, .key = dest_path },
        .mutating = true,
        .argv_redacted = Store.history.redactSecrets(ctx.arena, summary) catch
            fatal("cannot redact the transfer description for the audit record", .{}),
        .transport = "direct",
        .owner_token = owner_token,
        .force = parsed.boolean("force"),
        .now = ctx.now,
    };

    // Non-null only on the restart path: the supersession, the operation and the
    // replacement checkpoint are one commit, so that path already has its
    // checkpoint by the time the connection is opened. The ordinary path still
    // mints its checkpoint after the dial, and that difference is deliberate —
    // a `create` before the connection would leave a `planned` checkpoint
    // holding the destination every time a host is unreachable. On the restart
    // path the destination was already held when the command started and is
    // still held if the dial fails, so nothing is barred that was not barred
    // before. The resume path is in the same position for the same reason: the
    // row it takes over already held the path, and a failed dial leaves it with
    // the owner it had.
    var restarted_checkpoint: ?i64 = null;

    var execution = open: {
        if (way == .supersede) {
            const holding = way.supersede;
            switch (Core.execution.beginSupersedingCheckpoint(
                &store,
                ctx.arena,
                ctx.io,
                begin_opts,
                holding.id,
                plan,
            ) catch |err| fatalRestart(err, holding, dest_path)) {
                .ready => |started| {
                    restarted_checkpoint = started.checkpoint;
                    break :open started.execution;
                },
                .blocked => |blocker| reportBlocked(blocker),
            }
        }
        break :open switch (Core.execution.begin(&store, ctx.arena, ctx.io, begin_opts) catch |err|
            Cli.storeFatal(&store, err)) {
            .ready => |e| e,
            .blocked => |blocker| reportBlocked(blocker),
        };
    };
    Cli.registerExecution(&execution);
    defer {
        Cli.clearExecution();
        execution.deinit();
    }

    execution.connecting() catch |err| Cli.receiptFatal(execution.id(), err, "created");

    var client = Cli.sshConnect(resolved.server, resolved.auth);
    defer client.deinit();

    // Where the checkpoint comes from, one arm per way in.
    //
    // `create` refuses unless the operation exists, has not submitted, its kind
    // matches the direction and its server matches the destination side — so the
    // fresh arm is also where a mismatched plan is caught. `adoptCheckpoint`
    // asks the same four things of the *heir* inside the statement that moves
    // ownership, plus the one a fresh transfer has no equivalent of: the attempt
    // being displaced must no longer be able to affect the host.
    const checkpoint = switch (way) {
        .supersede => restarted_checkpoint.?,
        .fresh => transfers.create(
            &store,
            plan.forRequest(execution.id(), ctx.now),
        ) catch |err| fatalCreate(err, &execution, &store, ctx.arena, dest_side, dest_path),
        .adopt => |held| adopt: {
            execution.adoptCheckpoint(held.id, held.request_id) catch |err|
                fatalAdopt(err, &execution, held, dest_path);
            break :adopt held.id;
        },
    };

    var r: Run = .{
        .ctx = ctx,
        .store = &store,
        .execution = &execution,
        .client = &client,
        .verb = verb,
        .checkpoint = checkpoint,
        .dest_path = dest_path,
        .partial_path = partial_path,
        .source_path = src,
        // The flag, for the two ways in that mint a checkpoint from `plan`. The
        // adopt path overwrites this from the row it took over.
        .no_clobber = want_no_clobber,
    };

    const started = std.Io.Timestamp.now(ctx.io, .awake);
    switch (way) {
        // Immediately, and before anything that can fail: `paused` — the state
        // every abort below parks in, so the checkpoint stays adoptable rather
        // than holding its destination forever — has no edge from `planned`.
        .fresh, .supersede => {
            r.setState(.probing, null);
            probe(&r);
        },
        // The resume's own probe. It walks the row to `probing` too, and it
        // *reads* the two commitments a fresh probe writes rather than writing
        // them — see `resumeFrom`.
        .adopt => resumeFrom(&r),
    }

    switch (execution.submitted() catch |err| Cli.receiptFatal(execution.id(), err, "about to submit")) {
        .submitted => {},
        .refused => |blocker| {
            // Parked rather than left in `probing`: a live checkpoint holds its
            // destination against every later transfer and its only way out is
            // a hand-over. `paused` is adoptable, so the next attempt can take
            // it over instead of finding the path barred for good.
            r.setState(.paused, "refused before submission: a peer claimed the scope");
            execution.abandon("a peer claimed the scope before this transfer submitted") catch |err|
                Cli.receiptFatal(execution.id(), err, execution.status.text());
            reportBlocked(blocker);
        },
    }

    var streamed = stream(&r, via, mode);
    const outcome = verifyAndPublish(&r, &streamed);

    const elapsed_ns = started.durationTo(std.Io.Timestamp.now(ctx.io, .awake)).nanoseconds;
    const duration_ms: i64 = @intCast(@divTrunc(elapsed_ns, std.time.ns_per_ms));
    // This run's bytes, not the artifact's. A resume that moved the last
    // megabyte of a nine-gigabyte file did not move nine gigabytes, and a rate
    // computed from the artifact would say it did.
    const moved_now = streamed.bytes - streamed.resumed_from;
    const mib_s: f64 = if (elapsed_ns > 0)
        @as(f64, @floatFromInt(moved_now)) / (1 << 20) / (@as(f64, @floatFromInt(elapsed_ns)) / std.time.ns_per_s)
    else
        0;

    settle(&r, outcome, streamed);

    // The audit row. Its failure used to be `catch {}`, which is the one thing
    // this project's rules forbid outright: a ledger write we could not make is
    // not a transfer we get to report as clean. `receiptFatal` is the route
    // every other verb already takes for it.
    Store.history.add(&store, resolved.server.id, .{
        .kind = @tagName(verb),
        .detail = try std.fmt.allocPrint(ctx.arena, "{s} -> {s} (via {s}, {s})", .{
            src, dst, streamed.backend, outcome.text(),
        }),
        .exit_code = outcome.exitCode(),
        .transport = "direct",
        .duration_ms = duration_ms,
    }, ctx.now) catch |err|
        Cli.receiptFatal(execution.id(), err, execution.status.text());

    // A published artifact whose resolution the ledger declined is not a clean
    // success: the scope stays barred and the operation stays unresolved. It is
    // reported as what it is — the transfer state stands, and only `ok`, the
    // hint and the exit code change. Re-labelling the *outcome* would have been
    // the easy version and a false one: the words for `indeterminate_publish`
    // say the rename may not have landed, and here it demonstrably did.
    const clean = outcome.ok() and r.resolution_refused == null;

    switch (ctx.out.format) {
        .json => try ctx.out.json(.{
            .ok = clean,
            .requestId = execution.id(),
            .action = @tagName(verb),
            .server = server_name,
            .source = src,
            .destination = dest_path,
            .bytes = streamed.bytes,
            // Where this run started, so `bytes` can be read as a position in
            // the artifact rather than as a count of what moved. Zero on every
            // fresh transfer.
            .resumedFrom = streamed.resumed_from,
            .backend = streamed.backend,
            // Why that backend, when there was no choice. Null when the ordinary
            // scp-then-exec selection was made.
            .backendReason = streamed.backend_reason,
            .transferState = outcome.text(),
            .status = execution.status.text(),
            // Which promise was in force, which on a resume is the row's and not
            // this command line's. An agent reading `failed_clobber_conflict`
            // needs to know the refusal was asked for.
            .noClobber = r.no_clobber,
            // The two digests the verdict rests on, and null when there was
            // none. A caller reading `verified = false` beside a null
            // `observedSha256` can see *why* it is unverified rather than
            // having to infer it.
            .verified = outcome == .published,
            .declaredSha256 = r.declared_sha256,
            .observedSha256 = streamed.observed_sha256,
            .resolutionRefused = r.resolution_refused,
            .durationMs = duration_ms,
            .mibPerSec = mib_s,
            .proves = outcome.proves(),
            .hint = r.resolution_refused orelse outcome.hint(),
        }),
        .human => try ctx.out.print(
            "{t} {s} -> {s}: {Bi} in {d} ms ({d:.1} MiB/s, via {s}) — {s}\n  {s}\n",
            .{ verb, src, dest_path, streamed.bytes, duration_ms, mib_s, streamed.backend, outcome.text(), outcome.proves() },
        ),
    }
    if (streamed.resumed_from > 0 and ctx.out.format == .human) {
        try ctx.out.print("  resumed from byte {d}{s}{s}\n", .{
            streamed.resumed_from,
            if (streamed.backend_reason != null) "; " else "",
            streamed.backend_reason orelse "",
        });
    }
    if (r.resolution_refused) |why| {
        if (ctx.out.format == .human) try ctx.out.print("  {s}\n", .{why});
    }

    try ctx.out.flush();
    // A published-but-unresolved transfer exits `indeterminate` rather than 0:
    // the artifact is there and the ledger does not say so, which is exactly
    // the state a caller must not read as done.
    if (!clean) Cli.exitNow(if (outcome.ok()) Cli.exit_code.indeterminate else outcome.exitCode());
}

/// The source's size without reading it. Null rather than fatal: `total_bytes`
/// is a diagnostic on the checkpoint, and a source that cannot be statted is
/// about to be reported by the probe, which is where that failure belongs.
fn statSize(ctx: *Cli.Ctx, path: []const u8) ?u64 {
    const file = std.Io.Dir.cwd().openFile(ctx.io, path, .{}) catch return null;
    defer file.close(ctx.io);
    return file.length(ctx.io) catch null;
}

// --- probing -----------------------------------------------------------------

/// Establishes what the source is, and what the result will be judged by.
///
/// Two writes, and they are independent on purpose:
///
///  * `recordExpectedHash` is the commitment the transfer is judged by. Without
///    it `published` is unreachable and `receipts.resolve` has nothing for a
///    reading of the destination to be compared against.
///  * `recordSourceIdentity` is what makes the source *re-identifiable*, and it
///    needs all three of size, mtime and digest. Without it no non-zero offset
///    may be stored (`offset_needs_source_identity`), so there is progress to
///    record but nowhere to record it and a later resume has nothing to check.
///
/// A push always has both. A pull has the first whenever the host can hash, and
/// the second only if it can also report an mtime — GNU `stat -c %Y` or BSD
/// `stat -f %m`, and there is no third portable spelling. Neither absence is
/// papered over with a default: a fabricated mtime is an identity that never
/// described anything.
fn probe(r: *Run) void {
    switch (r.verb) {
        .push => probeLocalSource(r),
        .pull => probeRemoteSource(r),
    }
}

fn probeLocalSource(r: *Run) void {
    var buf: [digest.hex_len]u8 = undefined;
    const reading = digest.readFile(r.ctx.io, r.source_path, &buf) catch |err| abort(
        r,
        "cannot read local file '{s}' ({s})",
        .{ r.source_path, @errorName(err) },
    );
    const sha = r.ctx.arena.dupe(u8, reading.sha256) catch fatal("out of memory", .{});

    transfers.recordSourceIdentity(
        r.store,
        r.checkpoint,
        r.requestId(),
        reading.size,
        reading.mtime_ns,
        sha,
        r.ctx.now,
    ) catch |err| Cli.receiptFatal(r.requestId(), err, r.execution.status.text());
    r.identified = true;

    // Asked *before* declaring, and this order is the whole of why the call
    // exists. A push can always hash its own source, so declaring
    // unconditionally is the obvious thing — and it strands the row: if the host
    // cannot hash the staged partial, `published` needs a reading nobody can
    // take and `completed_unverified` refuses a row that declared one, so the
    // checkpoint has no legal end at all. See `transfer.remoteHashTool`.
    const tool = Core.transfer.remoteHashTool(r.executor(), r.ctx.arena) catch |err| abort(
        r,
        "cannot ask '{s}' whether it can hash a file ({s}: {s})",
        .{ r.dest_path, @errorName(err), r.client.errorMessage() },
    );
    if (tool == null) return;

    // A push publishes its source, so what the destination must hash to is the
    // digest of the source we just read.
    transfers.recordExpectedHash(r.store, r.checkpoint, r.requestId(), sha, r.ctx.now) catch |err|
        Cli.receiptFatal(r.requestId(), err, r.execution.status.text());
    r.declared_sha256 = sha;
}

fn probeRemoteSource(r: *Run) void {
    const reading = Core.transfer.probeRemoteFile(r.executor(), r.ctx.arena, r.source_path) catch |err|
        switch (err) {
            error.RemoteFileMissing => abort(r, "remote file '{s}' does not exist", .{r.source_path}),
            else => abort(r, "cannot read remote file '{s}' ({s}: {s})", .{
                r.source_path, @errorName(err), r.client.errorMessage(),
            }),
        };
    r.remote_size = reading.size;

    // No `sha256sum`, no `shasum -a 256`. The transfer can still deliver; it
    // cannot be verified, and it must not declare a digest it has no way of
    // checking — `completed_unverified` refuses a row that declared one
    // (`CompletedUnverifiedHasDeclaredHash`), which is the rule that stops this
    // branch quietly ending in `published`.
    const sha = reading.sha256 orelse return;

    if (reading.mtime_ns) |mtime| {
        transfers.recordSourceIdentity(
            r.store,
            r.checkpoint,
            r.requestId(),
            reading.size,
            mtime,
            sha,
            r.ctx.now,
        ) catch |err| Cli.receiptFatal(r.requestId(), err, r.execution.status.text());
        r.identified = true;
    }

    transfers.recordExpectedHash(r.store, r.checkpoint, r.requestId(), sha, r.ctx.now) catch |err|
        Cli.receiptFatal(r.requestId(), err, r.execution.status.text());
    r.declared_sha256 = sha;
}

// --- resuming ----------------------------------------------------------------

/// What `failure_reason` records when a resume parks a row whose owner is gone.
const adopted_reason = "adopted by a resume; the owner that left it here is gone";

/// The two readings a resume is licensed by, taken on the sides they live on.
const Observed = struct {
    /// The source as it is *now*. Null when it is gone, which `verifyResume`
    /// has words for.
    source: ?transfers.SourceIdentity,
    partial: transfers.PartialObservation,
    /// The stream hasher as it stood at the confirmed offset, recovered from
    /// whichever of the two readings covers the artifact's own prefix: the
    /// source for a push, because the artifact is a copy of it, and the staged
    /// partial for a pull, because the artifact *is* it.
    ///
    /// Null when the reading it would have come from did not reach the mark —
    /// which is the same fact that makes `verifyResume` refuse, so nothing ever
    /// resumes on a null seed.
    seed: ?digest.Running,
};

/// The resume's probe: walks the row to `probing`, re-proves what the checkpoint
/// recorded, and decides where the stream starts.
///
/// It is a sibling of `probe` rather than a branch of it because the two do
/// opposite things with the same two facts. A fresh probe *writes* the source's
/// identity and the digest the result will be judged by; a resume **reads** both
/// and may not write either — `recordSourceIdentity` and `recordExpectedHash`
/// are write-once and are refused on a row past offset zero or past its first
/// byte. That refusal is not an obstacle to work around, it is the guarantee: the
/// digest a resumed artifact is judged against is the one the interrupted attempt
/// committed to before it sent anything, and this attempt cannot substitute a
/// reading of whatever has landed since.
fn resumeFrom(r: *Run) void {
    const row = readCheckpoint(r);

    // `probing`'s predecessors are `planned` and `paused` and nothing else, so a
    // row adopted in `probing` or `transferring` cannot be probed where it
    // stands. `paused` is the state each of them is *in* once its owner is gone
    // — nobody is probing and nobody is transferring — so parking it first is
    // the accurate write rather than a step taken to satisfy the graph.
    switch (row.state) {
        .planned, .paused => {},
        .probing, .transferring => r.setState(.paused, adopted_reason),
        // `wayIn` refuses everything `isAdoptable` excludes and the hand-over
        // statement refuses it again under the write lock, so arriving here means
        // those two and this switch have come apart. Reported under that
        // description rather than assumed away.
        else => fatal(
            "internal: checkpoint {d} was adopted in state {s}, which is not adoptable",
            .{ r.checkpoint, row.state.text() },
        ),
    }
    r.setState(.probing, null);

    // Read, never re-declared. Null here means the interrupted attempt never
    // declared one — a pull from a host that cannot hash — and this attempt
    // cannot supply what that one could not, so the resume ends
    // `completed_unverified` exactly as the original would have.
    r.declared_sha256 = row.expected_sha256;
    // Off the row rather than off this run's reading: whether a non-zero offset
    // may be stored at all is a fact about what was committed before the first
    // byte, and `recordSourceIdentity` cannot be called again to change it.
    r.identified = if (row.source.file()) |f| f.sha256 != null else false;
    // Read, never restated — the same rule and the same reason as the digest
    // above it. `no_clobber` is written once, by `create`, and no statement
    // updates it, so the promise a resumed publish keeps is the one the
    // interrupted attempt made before it sent anything.
    //
    // A command line that *omits* `--no-clobber` over a row that carries it does
    // not retract it: the instruction was about the destination, not about one
    // attempt, and this is also the safe direction — the worst it does is refuse
    // a publish the operator had already asked to have refused. The opposite
    // disagreement is a refusal, and `wayIn` made it before this row was ever
    // adopted.
    r.no_clobber = row.no_clobber;

    const confirmed: u64 = @intCast(@max(row.confirmed_offset, 0));
    const observed = observeForResume(r, confirmed);

    switch (transfers.verifyResume(row, observed.source, observed.partial)) {
        .resume_from => |offset| {
            r.resume_from = offset;
            r.seed = observed.seed;
        },
        .truncate_then_resume => |cut| {
            // Prove, then cut. The prefix was proven a conjunct ago and the bytes
            // above it were never confirmed, so they are discarded rather than
            // counted — but only in this order, because truncating first would
            // destroy the only thing that could have proven the prefix.
            //
            // At offset zero there is nothing to cut *to*: the stream itself
            // creates the partial truncating, so a separate truncate would be a
            // second write saying the same thing.
            if (cut.offset > 0) truncatePartial(r, cut.offset, cut.partial_len);
            r.resume_from = cut.offset;
            r.seed = observed.seed;
        },
        // Nothing staged and nothing confirmed. The checkpoint is ours and its
        // declaration stands; the stream starts at zero, which is not a silent
        // restart — no confirmed byte is being discarded, because there was none.
        .start_over => {
            r.resume_from = 0;
            r.seed = null;
        },
        // The two refusals, as themselves. Neither is "let me just start over":
        // one says the thing being copied is not the thing this checkpoint is
        // about, the other says the bytes beside the destination are not the ones
        // it counted, and discarding either on the operator's behalf is exactly
        // what `--restart` exists to make them ask for.
        .source_changed => |why| refuseResume(r, .failed_source_changed, why),
        .partial_mismatch => |why| refuseResume(r, .failed_remote_partial_mismatch, why),
        // Unreachable through this driver and handled anyway: the schema's
        // `offset_needs_source_identity` forbids the row and the observer refuses
        // to confirm an offset without an identity, so a row in this shape was not
        // written by this binary. It gets no `failed_*` verdict because none of
        // them describes "this record should not exist" — reported as the record
        // fault it is, and parked where it was.
        .unidentified_source => |why| abort(
            r,
            "cannot resume checkpoint {d}: {s}. Its confirmed offset is {d} and it carries no source digest, which the schema forbids",
            .{ r.checkpoint, why, confirmed },
        ),
    }

    // The invariant everything above exists to establish, asserted where it is
    // cheap. A stream that starts above zero must carry the hasher state at that
    // offset: without it every prefix digest this run writes describes a range
    // nobody can re-derive, and the final comparison is a tail against a whole
    // file — which is a wrong `published`, the one outcome that must never be
    // reachable by mistake. Unreachable today (every verdict that yields a
    // non-zero offset has already proven the pass that produces the seed), and
    // checked anyway, because the cost of being wrong here is silent.
    if (r.resume_from > 0 and r.seed == null) fatal(
        "internal: checkpoint {d} was cleared to resume at byte {d} with no digest state for the bytes below it",
        .{ r.checkpoint, r.resume_from },
    );
}

fn readCheckpoint(r: *Run) transfers.Checkpoint {
    const found = transfers.get(r.store, r.ctx.arena, r.checkpoint) catch |err|
        Cli.receiptFatal(r.requestId(), err, r.execution.status.text());
    // The hand-over just committed against this id, so the row exists. Reported
    // rather than unwrapped: a null here means the row went away between two
    // statements of ours, and that is a ledger fault and not a transfer verdict.
    return found orelse Cli.receiptFatal(
        r.requestId(),
        error.CheckpointRowMissing,
        r.execution.status.text(),
    );
}

/// Takes the source and the staged prefix, on whichever machine each lives on.
///
/// **Both passes are obligations, not costs added for the resume's convenience.**
/// `verifyResume` will not continue without an observed source identity and,
/// above offset zero, without a prefix digest of the partial. Those are reads of
/// exactly the bytes whose hasher state a resumed stream needs, so the state
/// comes back with them — see `transfer.readLocalFile`. There is no third pass
/// anywhere, and in particular nothing re-reads a prefix to rebuild a digest.
fn observeForResume(r: *Run, confirmed: u64) Observed {
    switch (r.verb) {
        // The partial is on the host, so its prefix proof is a ranged remote
        // digest and the hasher comes from the local source's own pass. The
        // artifact a push publishes is a copy of that source, so the source's
        // prefix and the partial's prefix are the same bytes when the partial is
        // sound — which is precisely what the remote reading is compared for.
        .push => {
            const pass = Core.transfer.readLocalFile(
                r.ctx.io,
                r.ctx.arena,
                r.source_path,
                confirmed,
            ) catch |err| abort(
                r,
                "cannot read local file '{s}' ({s})",
                .{ r.source_path, @errorName(err) },
            );
            const remote = Core.transfer.remotePartial(
                r.executor(),
                r.ctx.arena,
                r.partial_path,
                confirmed,
            ) catch |err| abort(
                r,
                "cannot read the staged partial '{s}' back off the host ({s}: {s})",
                .{ r.partial_path, @errorName(err), r.client.errorMessage() },
            );
            return .{
                .source = if (pass) |p| .{ .local_file = .{
                    .path = r.source_path,
                    .size = p.size,
                    .mtime_ns = p.mtime_ns,
                    .sha256 = p.sha256,
                } } else null,
                .partial = .{
                    .exists = remote.exists,
                    .len = remote.len,
                    .prefix_sha256 = remote.prefix_sha256,
                },
                .seed = if (pass) |p| p.at_mark else null,
            };
        },
        // The partial is here, so one local pass gives the prefix proof, the
        // length on disk and the hasher at the mark. The source is on the host
        // and its identity is the host's own reading of it.
        .pull => {
            const reading = Core.transfer.probeRemoteFile(
                r.executor(),
                r.ctx.arena,
                r.source_path,
            ) catch |err| switch (err) {
                // Not an abort: a source that is gone is a finding
                // `verifyResume` words as `source_changed`, and reporting it as a
                // probe failure would leave the checkpoint undecided.
                error.RemoteFileMissing => return .{
                    .source = null,
                    .partial = .{ .exists = false },
                    .seed = null,
                },
                else => abort(r, "cannot read remote file '{s}' ({s}: {s})", .{
                    r.source_path, @errorName(err), r.client.errorMessage(),
                }),
            };
            r.remote_size = reading.size;
            const pass = Core.transfer.readLocalFile(
                r.ctx.io,
                r.ctx.arena,
                r.partial_path,
                confirmed,
            ) catch |err| abort(
                r,
                "cannot read the staged partial '{s}' ({s})",
                .{ r.partial_path, @errorName(err) },
            );
            return .{
                .source = .{ .remote_file = .{
                    .path = r.source_path,
                    .size = reading.size,
                    .mtime_ns = reading.mtime_ns,
                    .sha256 = reading.sha256,
                } },
                .partial = if (pass) |p| .{
                    .exists = true,
                    .len = p.size,
                    .prefix_sha256 = p.prefix_sha256,
                } else .{ .exists = false },
                .seed = if (pass) |p| p.at_mark else null,
            };
        },
    }
}

/// Cuts the staged partial back to the offset whose prefix was just proven.
fn truncatePartial(r: *Run, offset: u64, was: u64) void {
    switch (r.verb) {
        .push => Core.transfer.truncateRemote(
            r.executor(),
            r.ctx.arena,
            r.partial_path,
            offset,
        ) catch |err| abort(
            r,
            "cannot cut the staged partial '{s}' back from {d} to the confirmed {d} bytes ({s}: {s})",
            .{ r.partial_path, was, offset, @errorName(err), r.client.errorMessage() },
        ),
        // Done by `pullFile`, which holds the handle it writes through: cutting
        // here would open the file a second time and leave the resume's own
        // writer's idea of the length to agree with it by luck.
        .pull => {},
    }
}

/// A resume that refused before it moved anything, recorded as the finding it is.
///
/// `never_submitted` is the accurate terminal and it is the one `abort` already
/// uses in this driver: the probe's readings reached the host, and the transfer
/// the caller asked for did not run. It settles `failed`, which stops blocking
/// the scope — so the next command aimed at this path is refused by the
/// checkpoint's own hold and not by a stale operation.
///
/// The checkpoint gets a decided failure, and that is the improvement over the
/// dead end this replaced. Both states here hold their destination and both are
/// `isSupersedable`, so `--restart` is the way on: a refused resume turns an
/// unjudged `paused` row that nothing could release into a judged one that an
/// operator can.
fn refuseResume(r: *Run, state: transfers.State, why: []const u8) noreturn {
    const reason = std.fmt.allocPrint(
        r.ctx.arena,
        "refused to resume: {s}; nothing was sent",
        .{why},
    ) catch "refused to resume";
    r.setState(state, reason);
    _ = r.execution.settle(
        .{ .never_submitted = .{ .transport_error = reason } },
        .{},
    ) catch |err| Cli.receiptFatal(r.requestId(), err, r.execution.status.text());
    // Derived from the state, so the pair cannot drift: every `Outcome` is named
    // after a checkpoint state and a gate holds the two lists against each other.
    const outcome = Outcome.naming(state) orelse fatal(
        "internal: no transfer outcome names the state {s}",
        .{state.text()},
    );
    reportOutcome(r, outcome, reason);
}

// --- transferring ------------------------------------------------------------

/// What the streaming step moved, and what it hashed on the way.
const Streamed = struct {
    /// Where the artifact ends: this run's bytes plus whatever a resume started
    /// from. A position in the file, not a count of work.
    bytes: u64,
    /// Where this run's first byte went. Zero on every fresh transfer.
    resumed_from: u64,
    backend: []const u8,
    /// Why that backend, when there was no choice to make. Null when the
    /// ordinary scp-then-exec selection ran.
    backend_reason: ?[]const u8 = null,
    /// The digest of the **whole artifact** as this end accounts for it. One half
    /// of the comparison `verifying` makes, in both directions.
    ///
    /// On a fresh transfer that is the digest of the bytes that went past. On a
    /// resume the same hasher is used, started from the state the licensing pass
    /// recovered at `resumed_from` — so this covers the confirmed prefix and this
    /// run's bytes together, and means exactly what it means on a fresh
    /// transfer. Without that seed it would be a digest of the tail, and every
    /// comparison downstream would be of a tail against a whole file.
    local_sha256: []const u8,
    /// The digest the *other* end reports, once `verifying` has asked for it.
    /// Null when the host cannot hash at all.
    observed_sha256: ?[]const u8 = null,
};

/// Advances the ledger behind the bytes as they move.
///
/// It hashes every chunk into a running digest — which is both the whole
/// stream's digest and, read at a chunk boundary, the prefix digest a confirmed
/// offset is required to carry — and writes an offset down every
/// `confirm_every` bytes, plus once at the end.
///
/// A resume starts this from `Run.seed` and `Run.resume_from` rather than from
/// zero, and that is what keeps the two claims it writes true: the offsets are
/// positions in the artifact, and each prefix digest is a digest of the artifact
/// up to that position. `moved` arrives absolute from both backends, so nothing
/// here has to know whether it is resuming.
///
/// A ledger failure here stops the transfer rather than being logged past: the
/// offset is a claim about bytes we can still prove are ours, and carrying on
/// past a claim we could not record means the next resume splices onto a prefix
/// nobody committed to. `Ssh.ChunkError` has one member, so the real error is
/// kept here where it still has a type.
const Progress = struct {
    r: *Run,
    stream: digest.Running,
    confirmed: u64 = 0,
    failure: ?anyerror = null,

    fn init(r: *Run) Progress {
        return .{
            .r = r,
            .stream = r.seed orelse .init(),
            .confirmed = r.resume_from,
        };
    }

    fn observer(self: *Progress) Core.Ssh.Observer {
        return .{ .context = @ptrCast(self), .on_chunk = onChunk };
    }

    fn onChunk(context: *anyopaque, chunk: []const u8, moved: u64, total: u64) Core.Ssh.ChunkError!void {
        const self: *Progress = @ptrCast(@alignCast(context));
        self.stream.update(chunk);
        // No identity, no offset: the schema refuses a non-zero one against a
        // source nothing can re-identify, and there is no point recording a
        // claim that could never be checked.
        if (!self.r.identified) return;
        if (moved != total and moved - self.confirmed < confirm_every) return;

        var buf: [digest.hex_len]u8 = undefined;
        const prefix = self.stream.peekHex(&buf);
        transfers.confirmOffset(
            self.r.store,
            self.r.checkpoint,
            self.r.requestId(),
            moved,
            moved,
            prefix,
            self.r.ctx.now,
        ) catch |err| {
            self.failure = err;
            return error.ObserverFailed;
        };
        self.confirmed = moved;
    }
};

/// Why a resumed transfer has no backend to choose between.
const scp_cannot_resume = "scp cannot resume: libssh2 offers send64 and recv2, which move a whole file from byte zero, so the exec backend is the only one that can continue from an offset";

/// Streams the bytes into the staging partial, whichever backend can.
///
/// The scp fallback is narrower than it was, and deliberately: a scp attempt
/// that failed *after* moving bytes has left a partial whose contents this
/// driver did not observe, and starting the exec backend over the top of it
/// would append to bytes nobody hashed. So the fallback fires only when the
/// channel never opened — which is the case it exists for, a host with no scp
/// binary.
///
/// Above offset zero scp is not attempted at all, and the reason travels with
/// the result rather than being left for a caller to work out. `--via scp` with
/// `--resume` was already refused at the top of `run`, so the only way here is
/// an unpinned resume, which gets the backend that can do the job and a sentence
/// saying why it had no alternative.
fn stream(r: *Run, via: ?[]const u8, mode: u32) Streamed {
    const want_exec = via != null and std.mem.eql(u8, via.?, "exec");
    const pinned_scp = via != null and std.mem.eql(u8, via.?, "scp");
    const resuming = r.resume_from > 0;

    var progress: Progress = .init(r);
    r.setState(.transferring, null);

    var moved: Core.Ssh.Moved = .{};
    if (!want_exec and !resuming) {
        if (scpAttempt(r, &progress, &moved, mode)) |bytes| {
            return finishStream(r, &progress, bytes, "scp", null);
        } else |err| {
            if (pinned_scp or err != error.ChannelOpenFailed or moved.arrived != 0)
                abortTransfer(r, &progress, err, moved, "scp");
        }
    }

    const bytes = execAttempt(r, &progress, &moved, mode) catch |err|
        abortTransfer(r, &progress, err, moved, "exec");
    return finishStream(r, &progress, bytes, "exec", if (resuming) scp_cannot_resume else null);
}

fn scpAttempt(r: *Run, progress: *Progress, moved: *Core.Ssh.Moved, mode: u32) Core.Ssh.TransferError!u64 {
    switch (r.verb) {
        .push => {
            const partial_z = r.ctx.arena.dupeZ(u8, r.partial_path) catch fatal("out of memory", .{});
            return r.client.scpSend(
                r.ctx.io,
                r.source_path,
                partial_z,
                @intCast(mode),
                progress.observer(),
                moved,
            );
        },
        .pull => {
            const src_z = r.ctx.arena.dupeZ(u8, r.source_path) catch fatal("out of memory", .{});
            return r.client.scpRecv(
                r.ctx.io,
                src_z,
                r.partial_path,
                progress.observer(),
                moved,
            );
        },
    }
}

fn execAttempt(r: *Run, progress: *Progress, moved: *Core.Ssh.Moved, mode: u32) Core.transfer.Error!u64 {
    return switch (r.verb) {
        .push => Core.transfer.pushFile(
            r.executor(),
            r.ctx.arena,
            r.ctx.io,
            r.source_path,
            r.partial_path,
            r.resume_from,
            mode,
            progress.observer(),
            moved,
        ),
        .pull => Core.transfer.pullFile(
            r.executor(),
            r.ctx.arena,
            r.ctx.io,
            r.source_path,
            r.partial_path,
            r.resume_from,
            r.remote_size,
            progress.observer(),
            moved,
        ),
    };
}

fn finishStream(
    r: *Run,
    progress: *Progress,
    bytes: u64,
    backend: []const u8,
    backend_reason: ?[]const u8,
) Streamed {
    var buf: [digest.hex_len]u8 = undefined;
    const sha = r.ctx.arena.dupe(u8, progress.stream.finalHex(&buf)) catch
        fatal("out of memory", .{});
    return .{
        .bytes = bytes,
        .resumed_from = r.resume_from,
        .backend = backend,
        .backend_reason = backend_reason,
        .local_sha256 = sha,
    };
}

/// Parks the checkpoint and reports a transfer that stopped mid-stream.
///
/// `paused` rather than one of the six `failed_*` states, and that is a claim
/// about what this driver can *diagnose* rather than a soft landing. Each
/// failure state names a specific finding — the far side's leftover partial did
/// not match, there was no space, the destination was occupied — and this slice
/// makes none of those readings. `failed_no_space` in particular would mean
/// matching the host's error text, which is locale dependent, and a wrong
/// diagnosis is worse than an honest interruption.
///
/// `paused` is also the state that keeps this recoverable: it is adoptable, so
/// a later attempt can take the checkpoint over, where a live `transferring`
/// row would hold the destination against everybody with no way out.
fn abortTransfer(
    r: *Run,
    progress: *Progress,
    err: anyerror,
    moved: Core.Ssh.Moved,
    backend: []const u8,
) noreturn {
    // A ledger write we could not make is not something to report a transfer
    // over: it is the failure, and it outranks the transport error that
    // exposed it.
    if (progress.failure) |ledger_err|
        Cli.receiptFatal(r.requestId(), ledger_err, r.execution.status.text());

    const reason = switch (err) {
        error.ShortSend, error.ShortReceive => std.fmt.allocPrint(
            r.ctx.arena,
            "short transfer over {s}: {d} bytes expected, {d} arrived",
            .{ backend, moved.expected, moved.arrived },
        ) catch "short transfer",
        else => std.fmt.allocPrint(
            r.ctx.arena,
            "{s} transfer stopped after {d} of {d} bytes: {s} ({s})",
            .{ backend, moved.arrived, moved.expected, @errorName(err), r.client.errorMessage() },
        ) catch "transfer stopped",
    };
    r.setState(.paused, reason);

    // After submission a transfer's only admissible terminal is
    // `indeterminate` — see `settle`. That is also the truth here: bytes went
    // out and what the far side did with them is not something this end
    // watched.
    _ = r.execution.settle(.{ .indeterminate = .{
        .reason = reason,
        .last_observed = r.execution.status,
    } }, .{}) catch |e| Cli.receiptFatal(r.requestId(), e, r.execution.status.text());

    reportOutcome(r, .paused, reason);
}

// --- verifying and publishing ------------------------------------------------

/// What `verifying` concludes from the two readings it holds.
///
/// Four answers, and a pure function over three values, because this is the
/// decision the whole command turns on and nothing in this tree can drive the
/// producer end to end to check it. Left inline it would be the one part of the
/// verification nothing tests — the same argument `cmd_read_write.writeScope`
/// makes for extracting a one-line scope.
pub const Verdict = enum {
    /// Both ends produced the same digest. `published` is available.
    agreed,
    /// Both ends produced a digest and they differ.
    disagreed,
    /// Neither end has a digest to offer. `completed_unverified` is the honest
    /// end, and it is available precisely because nothing was declared.
    unverifiable,
    /// A digest was declared before the first byte and the far end produced
    /// none. **Nothing may be published**: `published` needs the reading and
    /// `completed_unverified` refuses the declaration, so such a row has no
    /// legal end state at all — see the gate that walks it into the corner.
    declared_but_unread,
};

/// `declared` is the digest committed to before the first byte; `ours` is what
/// this end hashed as the bytes moved; `far_end` is what the other end reports.
pub fn verdictFor(declared: ?[]const u8, ours: []const u8, far_end: ?[]const u8) Verdict {
    const observed = far_end orelse
        return if (declared == null) .unverifiable else .declared_but_unread;
    return if (std.ascii.eqlIgnoreCase(ours, observed)) .agreed else .disagreed;
}

/// Compares the two ends, then renames once.
///
/// Takes the stream by pointer because the reading it takes off the far end is
/// part of the answer: the caller reports the digest that was actually compared
/// rather than re-deriving one.
fn verifyAndPublish(r: *Run, streamed: *Streamed) Outcome {
    // Before `verifying`, because this is the one failure only `transferring`
    // can diagnose: the push hashed its source at probe time and hashed it
    // again as it sent, and two different answers mean the file changed under
    // us. `failed_source_changed`'s predecessors are `probing` and
    // `transferring` for exactly that reason.
    //
    // It holds on a resumed push too, and for the same reason it holds on a
    // fresh one: the stream digest was seeded at the confirmed offset from the
    // source's own licensing pass, so what is compared here is still the whole
    // source against the whole declaration. A resume also has the earlier check
    // — `verifyResume` refuses a changed source before a byte moves — so on that
    // path this is the narrower window of a change that happened *during* the
    // resumed stream.
    if (r.verb == .push) {
        if (r.declared_sha256) |declared| {
            if (!std.ascii.eqlIgnoreCase(declared, streamed.local_sha256)) {
                r.setState(
                    .failed_source_changed,
                    "the source hashed differently when it was sent than when it was probed",
                );
                return .failed_source_changed;
            }
        }
    }

    r.setState(.verifying, null);

    const far_end: ?[]const u8 = switch (r.verb) {
        // The bytes went out; what the host holds is a reading this end cannot
        // take. Null when the host cannot hash at all.
        .push => Core.transfer.remoteDigest(r.executor(), r.ctx.arena, r.partial_path) catch |err|
            abortVerify(r, err),
        // The bytes came in and this end hashed them as they were written; the
        // other end is the host's own reading of the source, taken at probe
        // time, which is what `declared_sha256` holds.
        .pull => r.declared_sha256,
    };

    switch (verdictFor(r.declared_sha256, streamed.local_sha256, far_end)) {
        .agreed => {
            const observed = far_end.?;
            streamed.observed_sha256 = observed;
            transfers.recordVerifiedHash(r.store, r.checkpoint, r.requestId(), observed, r.ctx.now) catch |err|
                Cli.receiptFatal(r.requestId(), err, r.execution.status.text());
        },
        .disagreed => {
            streamed.observed_sha256 = far_end.?;
            r.setState(.failed_hash_mismatch, "the two ends hashed to different digests");
            return .failed_hash_mismatch;
        },
        // Nothing to check against, and nothing was declared, so the honest end
        // is `completed_unverified` — which the publish below chooses off the
        // absence of a reading.
        .unverifiable => {},
        // Declared and unread. `probeLocalSource` asks the host whether it can
        // hash at all precisely so this is not the usual way a minimal host is
        // handled; this is the guard for the host that answered yes and then
        // could not, which no ordering can rule out. It stops before the rename,
        // so the destination is untouched.
        .declared_but_unread => abortVerifyDeclaredButUnread(r),
    }

    r.setState(.publishing, null);
    return publish(r, streamed.observed_sha256 != null);
}

fn abortVerify(r: *Run, err: anyerror) noreturn {
    const reason = std.fmt.allocPrint(
        r.ctx.arena,
        "could not read the staged partial back off the host: {s} ({s})",
        .{ @errorName(err), r.client.errorMessage() },
    ) catch "could not read the staged partial back off the host";
    parkFromVerifying(r, reason);
}

/// The host declared it could hash during the probe and produced nothing here.
///
/// Its own entry point rather than a branch of `abortVerify`, because there is
/// no error to name: every call succeeded and the answer was empty. Reported as
/// what it is so an operator is not sent looking for a transport fault.
fn abortVerifyDeclaredButUnread(r: *Run) noreturn {
    parkFromVerifying(
        r,
        "this transfer declared a digest before it sent anything and the host produced none to check it against; nothing was published",
    );
}

/// `verifying → paused`, settled, reported, and out.
///
/// `verifying → paused` exists precisely so a verifier that stopped does not
/// wedge the row: nothing follows `verifying` but `publishing`, and `verifying`
/// is not adoptable.
fn parkFromVerifying(r: *Run, reason: []const u8) noreturn {
    r.setState(.paused, reason);
    _ = r.execution.settle(.{ .indeterminate = .{
        .reason = reason,
        .last_observed = r.execution.status,
    } }, .{}) catch |e| Cli.receiptFatal(r.requestId(), e, r.execution.status.text());
    reportOutcome(r, .paused, reason);
}

/// The one act that touches the destination.
///
/// Two primitives per side, chosen by `r.no_clobber`, and the three answers a
/// no-clobber publish can give are mapped by what each one is *about*.
/// `DestinationExists` is a fact about the operator's data, so it is
/// `failed_clobber_conflict`. `NoClobberUnsupported` — a host that cannot
/// hard-link, a filesystem with no atomic non-replacing rename, a staging path
/// on another device — is a fact about the mechanism, so it is `failed_publish`.
/// Collapsing the second into the first would tell an operator their destination
/// is occupied when it is empty, which is a lie about their data and the exact
/// class of pseudo-success this driver exists to remove.
fn publish(r: *Run, verified: bool) Outcome {
    switch (r.verb) {
        .push => Core.transfer.publishRemote(
            r.executor(),
            r.ctx.arena,
            r.partial_path,
            r.dest_path,
            r.no_clobber,
        ) catch |err| switch (err) {
            // `ln` refused because the name was taken. The link never happened,
            // so the destination holds exactly what it held — and this is the
            // kernel's answer to the race, not a reading we took beforehand.
            error.DestinationExists => {
                r.setState(
                    .failed_clobber_conflict,
                    "--no-clobber was asked for and the host reports something already at the destination",
                );
                return .failed_clobber_conflict;
            },
            // The link did not happen and the destination is not what refused
            // it. Reported as the mechanism failure it is, with what was
            // observed rather than a diagnosis of the host: `ln`'s reason lives
            // only in its stderr, which is locale dependent.
            error.NoClobberUnsupported => {
                r.setState(
                    .failed_publish,
                    "the host could not hard-link the staged partial into place and reports nothing at the destination, so a no-clobber publish could not be performed there — the filesystem may not support hard links",
                );
                return .failed_publish;
            },
            // The host answered, and its answer was that the rename failed.
            // The destination holds what it held.
            error.PublishFailed => {
                r.setState(.failed_publish, "the host's rename reported failure");
                return .failed_publish;
            },
            // The answer was lost. The rename may have landed, so this is not a
            // failure and must never be reported as one.
            else => {
                r.setState(
                    .indeterminate_publish,
                    "the rename was issued and its answer never came back",
                );
                return .indeterminate_publish;
            },
        },
        // A local rename either happens or reports why it did not; there is no
        // lost answer, so `indeterminate_publish` is unreachable on this side.
        .pull => Core.transfer.publishLocal(
            r.ctx.io,
            r.partial_path,
            r.dest_path,
            r.no_clobber,
        ) catch |err| switch (err) {
            error.DestinationExists => {
                r.setState(
                    .failed_clobber_conflict,
                    "--no-clobber was asked for and something already occupies the destination",
                );
                return .failed_clobber_conflict;
            },
            error.NoClobberUnsupported => {
                r.setState(
                    .failed_publish,
                    "this filesystem cannot publish without replacing: it reported no support for an atomic non-replacing rename, or the staged partial and the destination are not on one device",
                );
                return .failed_publish;
            },
            // Every other rename failure keeps its own name, which is the whole
            // reason `publishLocal` does not collapse them: this line is where
            // an operator learns it was a read-only directory or a locked file.
            else => {
                r.setState(.failed_publish, @errorName(err));
                return .failed_publish;
            },
        },
    }

    if (!verified) {
        r.setState(.completed_unverified, null);
        return .completed_unverified;
    }
    r.setState(.published, null);
    return .published;
}

// --- settling ----------------------------------------------------------------

/// Records the operation's outcome.
///
/// **A transfer has exactly one admissible terminal after submission, and it is
/// `indeterminate`.** `operations.Kind.capabilities` gives the three transfer
/// kinds `publishes_declared_artifact` and nothing else, and
/// `receipts.terminalDescribes` then refuses `exited`, `remote_deadline`,
/// `remote_cancel_confirmed`, `proven_failure` and both input terminals for
/// them — on positive arguments, not by omission: "a copier that renamed
/// nothing still exits 0". That module says so itself: "a transfer cannot reach
/// `completed` or `timed_out` through `settle` at all".
///
/// So a successful transfer settles `indeterminate` and is then **resolved**
/// against a reading of the destination, which is the route the same comment
/// names: "a producer that wants `completed` back must bring a terminal whose
/// content is the local effect it observed — the destination it wrote and the
/// digest it read back off it". `filesystem_effect` is exactly that reading, and
/// `resolve` compares all three of its fields against what this transfer
/// committed to before it sent a byte. The operation ends `indeterminate` with
/// `resolved_status = completed`, which releases the scope.
///
/// The outcomes that cannot be resolved mechanically are stated rather than
/// smoothed over. `completed_unverified` declared no digest, so
/// `expectedEffectLocked` is null and no reading can be compared with anything;
/// the `failed_*` outcomes are not parked publishes, so the destination
/// readings do not apply to them. All of them stay unresolved until an operator
/// judges them, and all of them say so in `hint`.
/// The reading a published transfer offers the ledger.
///
/// A function rather than a literal at the one call site, for the reason
/// `cmd_read_write.writeScope` is one: nothing in this tree can drive the
/// producer end to end, so this line — which decides *which machine* the
/// artifact is claimed to be on — would otherwise be the part of the settlement
/// nothing checks. `filesystem_effect.side` exists precisely because reading the
/// local copy of a push would "prove" that the host's destination landed, and
/// `resolve` compares this against the destination side the checkpoint recorded
/// before the first byte.
pub fn publishedEffect(
    verb: Verb,
    dest_path: []const u8,
    observed_sha256: []const u8,
) Store.receipts.ResolutionEvidence {
    return .{
        .filesystem_effect = .{
            .side = switch (verb) {
                // A push publishes on the host; a pull publishes here.
                .push => .remote,
                .pull => .local,
            },
            .path = dest_path,
            .sha256 = observed_sha256,
        },
    };
}

fn settle(r: *Run, outcome: Outcome, streamed: Streamed) void {
    const reason = std.fmt.allocPrint(
        r.ctx.arena,
        "transfer ended {s}; this operation kind has no terminal for a completed publish, so the verdict is the checkpoint's and any resolution over a reading of the destination",
        .{outcome.text()},
    ) catch "transfer ended";

    _ = r.execution.settle(.{ .indeterminate = .{
        .reason = reason,
        .last_observed = r.execution.status,
    } }, .{}) catch |err| Cli.receiptFatal(r.requestId(), err, r.execution.status.text());

    if (outcome != .published) return;
    const observed = streamed.observed_sha256 orelse return;

    const resolution = Store.receipts.resolve(
        r.store,
        r.ctx.arena,
        r.requestId(),
        .completed,
        publishedEffect(r.verb, r.dest_path, observed),
        r.ctx.now,
    ) catch |err| Cli.receiptFatal(r.requestId(), err, r.execution.status.text());

    if (std.meta.activeTag(resolution) != .resolved) {
        // The artifact is at the destination and the ledger declined to say so.
        // Reported rather than printed over: the scope stays barred and an
        // operator has to know which read refused it.
        r.resolution_refused = std.fmt.allocPrint(
            r.ctx.arena,
            "the artifact was published and the ledger declined to resolve the operation: {s}",
            .{@tagName(std.meta.activeTag(resolution))},
        ) catch "the ledger declined to resolve the operation";
    }
}

// --- reporting ---------------------------------------------------------------

/// Prints a terminated transfer and exits with its code.
///
/// Used by the abort paths, which have no byte count worth printing and no
/// duration anybody should read as throughput.
fn reportOutcome(r: *Run, outcome: Outcome, detail: []const u8) noreturn {
    switch (r.ctx.out.format) {
        .json => r.ctx.out.json(.{
            .ok = false,
            .requestId = r.requestId(),
            .action = @tagName(r.verb),
            .source = r.source_path,
            .destination = r.dest_path,
            .transferState = outcome.text(),
            .status = r.execution.status.text(),
            .detail = detail,
            .proves = outcome.proves(),
            .hint = outcome.hint(),
        }) catch {},
        .human => r.ctx.out.print("{s}: {s}\n  request: {s}\n  {s}\n", .{
            outcome.text(), detail, r.requestId(), outcome.proves(),
        }) catch {},
    }
    r.ctx.out.flush() catch {};
    Cli.exitNow(outcome.exitCode());
}

/// Parks the checkpoint and stops, for a failure before anything was submitted.
///
/// `never_submitted` is admissible here and is the accurate word: the guard has
/// not bound, no byte has left, and the probe's failure is this machine's own
/// reading. It settles `failed`, which does not block the scope.
fn abort(r: *Run, comptime fmt: []const u8, args: anytype) noreturn {
    const reason = std.fmt.allocPrint(r.ctx.arena, fmt, args) catch "the probe failed";
    r.setState(.paused, reason);
    _ = r.execution.settle(
        .{ .never_submitted = .{ .transport_error = reason } },
        .{},
    ) catch |err| Cli.receiptFatal(r.requestId(), err, r.execution.status.text());
    fatal("{s}", .{reason});
}

// --- the destination somebody else is standing on ---------------------------

/// How this command gets onto its destination.
///
/// Three arms, because there are three situations and each is reached by a
/// different write: nothing holds the path, `--restart` supersedes a settled
/// failure, `--resume` adopts an adoptable checkpoint. Naming them as one value
/// is what keeps the two flags from being read twice, in two places, with two
/// answers.
const WayIn = union(enum) {
    fresh,
    supersede: transfers.Holder,
    adopt: transfers.Holder,
};

/// Reads the holder once and decides which way in the caller asked for.
///
/// Every reading that is not one of the three exits here. A held path is a
/// refusal when nobody asked to do anything about it — releasing or taking over a
/// failed attempt's destination behind an operator's back is precisely the act
/// `holdsDestination` exists to make them look at.
///
/// With a flag it is a refusal whenever the write that flag reaches would refuse,
/// and it says so in that write's own terms rather than trying it to find out:
/// supersession wants a *settled failure* whose owning attempt can no longer
/// affect the host, and the hand-over wants an *adoptable* checkpoint under the
/// same settled-owner rule. Neither reading is binding — the statements re-ask
/// under the write lock — and neither needs to be, because everything decided
/// here is a refusal.
fn wayIn(
    ctx: *Cli.Ctx,
    store: *Store,
    dest_side: transfers.DestSide,
    dest_path: []const u8,
    want_resume: bool,
    want_restart: bool,
    want_no_clobber: bool,
) WayIn {
    const holder = transfers.findHolder(store, ctx.arena, dest_side, dest_path) catch |err|
        Cli.storeFatal(store, err);
    const held = holder orelse {
        // `--resume` with nothing to resume is a refusal, not a fresh start. An
        // operator who asked to continue an interrupted transfer and is silently
        // given a new one from zero has been told the opposite of what happened,
        // and on a large file the difference is hours.
        if (want_resume) fatal(
            "refused: nothing is holding '{s}', so there is no interrupted transfer to resume; nothing was sent. Run it without --resume to start one",
            .{dest_path},
        );
        return .fresh;
    };

    if (want_resume) {
        // Both refusals name the state, because the state is what decides which
        // verb applies, and an operator told only "refused" cannot tell whether
        // to reconcile, restart, or wait.
        if (!held.state.isAdoptable()) fatal(
            "refused: request {s} is standing on '{s}' and its transfer is {s}, which --resume may not continue — a resume takes over a checkpoint exactly as its row describes it, and {s} is not a state a row can be continued from; nothing was sent.\n  {s}",
            .{ held.request_id, dest_path, held.state.text(), held.state.text(), wayThrough(ctx.arena, held) },
        );
        if (held.owner_may_be_running) fatal(
            "refused: request {s} holds '{s}' and has not been settled, so a copier on the far side may still be writing to the partial this resume would splice onto; nothing was sent.\n  {s}",
            .{ held.request_id, dest_path, wayThrough(ctx.arena, held) },
        );
        if (want_no_clobber) refuseAddedNoClobber(ctx, store, held, dest_path);
        return .{ .adopt = held };
    }

    // `--restart` mints a *new* checkpoint from a fresh plan, so its
    // `no_clobber` is this command line's flag and there is nothing to
    // disagree with. That is not the promise being dropped: the operator typed
    // the command again, and a replacement checkpoint records the instruction
    // they gave it rather than the one its predecessor was given.
    if (want_restart and held.releasable()) return .{ .supersede = held };
    refuseHeld(ctx.arena, held, dest_path);
}

/// Refuses a `--resume` that asks to add a no-clobber promise the checkpoint
/// does not carry.
///
/// Refused rather than honoured, and refused *here* — before an operation
/// exists, before the dial and before the hand-over — for the reason the rest of
/// `wayIn` is read early: everything it concludes is a refusal, so it costs
/// nothing and sends nothing. Refusing after the adoption would leave a live row
/// owned by an operation that will never settle, which bars the next `--resume`
/// behind a reconcile.
///
/// Why it is a refusal at all: `no_clobber` is write-once. Honouring the flag
/// would make the driver refuse a publish while the column it is judged by says
/// replacing was permitted — a record contradicting the act. Honouring the
/// column and ignoring the flag would silently do the opposite of what was
/// typed. The verb that *can* carry a new promise is `--restart`, which mints a
/// fresh checkpoint, and the operator is told so.
fn refuseAddedNoClobber(
    ctx: *Cli.Ctx,
    store: *Store,
    held: transfers.Holder,
    dest_path: []const u8,
) void {
    const row = (transfers.get(store, ctx.arena, held.id) catch |err|
        Cli.storeFatal(store, err)) orelse fatal(
        "refused: the checkpoint holding '{s}' went away between being read and being examined for its no-clobber promise; nothing was taken over and nothing was sent. Run it again",
        .{dest_path},
    );
    if (row.no_clobber) return;
    fatal(
        "refused: --no-clobber cannot be added to a transfer that is already under way. Request {s} declared before its first byte that replacing '{s}' was permitted, and that declaration is write-once — honouring the flag now would refuse a publish the record says was allowed. Nothing was taken over and nothing was sent. Re-run with --resume alone to continue under the promise it already made, or with --restart --no-clobber to start over under this one",
        .{ held.request_id, dest_path },
    );
}

/// The refusal, in one wording, for every way a destination can be occupied.
///
/// It used to end at "it either has not finished or failed and has not been
/// released; nothing was sent", which described a dead end and stopped —
/// because before checkpoints had a producer there was nothing to name. There
/// is now: the request holding the path, what its transfer is doing, and the one
/// act that gets past it.
fn refuseHeld(arena: std.mem.Allocator, held: transfers.Holder, dest_path: []const u8) noreturn {
    fatal(
        "refused: request {s} is standing on '{s}' — its transfer is {s} and still holds the destination; nothing was sent.\n  {s}",
        .{ held.request_id, dest_path, held.state.text(), wayThrough(arena, held) },
    );
}

/// Which of the two verbs applies to a holder in this state, or null when
/// neither does.
///
/// **The two sets are disjoint and neither is total**, which is the whole reason
/// this is a function and not a sentence repeated in four messages.
/// `isAdoptable` is the four states a row can be continued from and
/// `isSupersedable` is the six settled failures; `indeterminate_publish`,
/// `verifying` and `publishing` are in neither, and the three states that hold no
/// destination cannot reach a holder at all. A message that offered both verbs
/// for a state only one applies to would send half its readers to a statement
/// that refuses them, which is worse than the dead end this replaced.
///
/// `pub` for the reason `verdictFor` and `publishedEffect` are: nothing in this
/// tree can drive the producer end to end, so a correspondence built inline would
/// be the part of this slice nothing checks — and it is the part this slice
/// exists to get right.
pub fn verbFor(state: transfers.State) ?[]const u8 {
    if (state.isAdoptable()) return "--resume";
    if (state.isSupersedable()) return "--restart";
    return null;
}

/// What an operator can actually do about this holder.
///
/// The order is the order the two write statements ask their questions in: the
/// owning attempt first, then the state. An unsettled owner blocks both verbs
/// through the same conjunct — a copier on the far side may still be writing —
/// so that branch names the reconcile and then whichever verb the state is for,
/// rather than guessing.
///
/// `pub` for the reason `verbFor` is.
pub fn wayThrough(arena: std.mem.Allocator, held: transfers.Holder) []const u8 {
    if (held.owner_may_be_running) {
        const verb = verbFor(held.state) orelse return std.fmt.allocPrint(
            arena,
            "request {s} has not been settled, so a copier on the far side may still be writing to the partial beside that path — and its checkpoint is {s}, which neither --resume nor --restart may touch. Establish what it did with 'terminus request reconcile {s}'; that is also what decides where a {s} checkpoint goes next.",
            .{ held.request_id, held.state.text(), held.request_id, held.state.text() },
        ) catch "reconcile the holding request";
        return std.fmt.allocPrint(
            arena,
            "request {s} has not been settled, so a copier on the far side may still be writing to the partial beside that path. Establish what it did — 'terminus request reconcile {s}' — and then re-run with {s}.",
            .{ held.request_id, held.request_id, verb },
        ) catch "reconcile the holding request, then re-run";
    }

    return switch (held.state) {
        .failed_source_changed,
        .failed_remote_partial_mismatch,
        .failed_hash_mismatch,
        .failed_no_space,
        .failed_clobber_conflict,
        .failed_publish,
        => "That attempt is over and it published nothing. Re-run with --restart to release its hold and start over; its record, its digests and its staged partial are all kept.",

        // Interrupted, and its checkpoint still describes a transfer that can be
        // picked up where it stands. `--restart` would release the path and throw
        // the confirmed prefix away with it, which is why supersession does not
        // reach these states and why the sentence does not offer it.
        .planned,
        .probing,
        .transferring,
        .paused,
        => std.fmt.allocPrint(
            arena,
            "that transfer was interrupted and its checkpoint is {s}, which is resumable. Re-run with --resume: it takes the checkpoint over, re-proves the source and the staged prefix, and continues from the confirmed offset — nothing is discarded and nothing is re-sent.",
            .{held.state.text()},
        ) catch "re-run with --resume to continue from the confirmed offset",

        // Not settled — unjudged. The rename may already have landed, so the
        // path may already hold an artifact nobody has looked at, and handing it
        // to a rival would let the rival overwrite a result nobody has judged.
        .indeterminate_publish => std.fmt.allocPrint(
            arena,
            "that transfer issued its rename and never saw the answer, so the artifact may already be at this path. Neither --resume nor --restart will discard it: adjudicate it first with 'terminus request reconcile {s}'.",
            .{held.request_id},
        ) catch "adjudicate the holding request before anything overwrites this path",

        // The two mid-act states. `adoptCheckpoint` refuses them because there is
        // no offset left to resume from, and `supersedeLocked` refuses them
        // because nobody decided the attempt was over. What they need is
        // `execution.recoverCheckpoint`, which normalises `verifying → paused`
        // and `publishing → indeterminate_publish` first — a different act with a
        // different claim behind it, and one this build has no verb for. Said
        // plainly rather than approximated to whichever flag is nearer.
        .verifying,
        .publishing,
        => std.fmt.allocPrint(
            arena,
            "that transfer's owner stopped in the middle of an act and its checkpoint is still {s}, which is past its last byte. --resume may not continue it — there is no offset left — and --restart may not release it, because nobody decided the attempt was over. Recovering a {s} row is a hand-over of its own ('execution.recoverCheckpoint') and no verb reaches it yet, so this path stays held — send to a different destination.",
            .{ held.state.text(), held.state.text() },
        ) catch "this path stays held; send to a different destination",

        // `findHolder` is rendered from `holdsDestination` and these three are
        // the states it excludes, so one arriving here means the query and the
        // predicate have come apart. Reported under that description rather than
        // given a sentence, which would read as advice about a real situation.
        .published,
        .completed_unverified,
        .superseded,
        => fatal(
            "internal: checkpoint {d} came back from a destination-holding query in state {s}, which holds no destination",
            .{ held.id, held.state.text() },
        ),
    };
}

/// Names the refusals of the one transaction that releases a destination.
///
/// Its guards are conjuncts of a single statement, so a refusal comes back as
/// one error rather than as a reading the caller can take apart — which is the
/// point (a status checked outside the transaction can change before the write
/// lands). What that costs is this function: the wording has to be rebuilt from
/// the holder we read on the way in.
fn fatalRestart(err: anyerror, held: transfers.Holder, dest_path: []const u8) noreturn {
    switch (err) {
        // The two `supersedeLocked` refusals that mean the reading above went
        // stale between it and the write lock — a peer settled, reconciled or
        // adjudicated the holder in between. Not an operator error: they asked
        // for something that was true when they asked.
        error.CheckpointNotSupersedable, error.SurrenderingOperationMayStillBeRunning => fatal(
            "refused: request {s} still holds '{s}' — its transfer or its attempt changed between the check and the write ({s}), so nothing was superseded and nothing was sent. Re-read it with 'terminus request show {s}' and try again",
            .{ held.request_id, dest_path, @errorName(err), held.request_id },
        ),
        // The supersession landed and the replacement did not, or the reverse —
        // neither is on disk, which is the whole reason the three are one
        // transaction. The destination is still held by the same checkpoint it
        // was held by before this command ran.
        else => fatal(
            "cannot restart the transfer on '{s}': {s}. Nothing was superseded, nothing was created and nothing was sent — request {s} still holds the destination",
            .{ dest_path, @errorName(err), held.request_id },
        ),
    }
}

/// Names the refusals of the transaction that moves a checkpoint to a new owner.
///
/// The sibling of `fatalRestart`, and it exists for the same reason: the
/// hand-over's guards are conjuncts of one statement, so a refusal comes back as
/// a single error and the wording has to be rebuilt from the holder read on the
/// way in. What differs is that this one has an *heir* clause as well as an
/// incumbent one, and the two send an operator to opposite places.
///
/// The operation is abandoned before every exit. A resume that could not take
/// the checkpoint over has an operation with nothing to do and no checkpoint of
/// its own, and leaving it unsettled would bar the scope on behalf of a transfer
/// that never started — the same reason `fatalCreate` abandons.
fn fatalAdopt(
    err: anyerror,
    execution: *Core.execution.Execution,
    held: transfers.Holder,
    dest_path: []const u8,
) noreturn {
    execution.abandon("the transfer checkpoint could not be taken over") catch {};
    switch (err) {
        // The reading on the way in went stale between it and the write lock: a
        // peer adopted the row, or its owner stopped being settled. Not an
        // operator error — they asked for something that was true when they
        // asked — so the instruction is to look again rather than to do
        // something different.
        error.CheckpointNotResumable,
        error.CheckpointOwnerChanged,
        error.SurrenderingOperationMayStillBeRunning,
        => fatal(
            "refused: request {s} still holds '{s}' — its checkpoint or its attempt changed between the check and the hand-over ({s}), so nothing was taken over and nothing was sent. Re-read it with 'terminus request show {s}' and try again",
            .{ held.request_id, dest_path, @errorName(err), held.request_id },
        ),
        // The heir clause. This attempt is the one at fault, and telling an
        // operator to reconcile the incumbent would send them to a request that
        // is fine.
        error.AdoptingOperationNotEligible => fatal(
            "refused: this attempt may not take over the checkpoint on '{s}' — the hand-over requires an heir that has not submitted, is bound to the same machine and matches the transfer's direction; nothing was taken over and nothing was sent",
            .{dest_path},
        ),
        else => fatal(
            "cannot resume the transfer on '{s}': {s}. Nothing was taken over and nothing was sent — request {s} still holds the destination",
            .{ dest_path, @errorName(err), held.request_id },
        ),
    }
}

/// Names the two `create` refusals that mean opposite things to an operator.
///
/// `DestinationHeld` is reachable here despite the read at the top of `run`,
/// and only by losing a race: another transfer took the path between that read
/// and this insert. So the holder is re-read rather than remembered — the row
/// that refused us is the newer one, and naming the older one would send an
/// operator to a request that has nothing to do with it.
fn fatalCreate(
    err: anyerror,
    execution: *Core.execution.Execution,
    store: *Store,
    arena: std.mem.Allocator,
    dest_side: transfers.DestSide,
    dest_path: []const u8,
) noreturn {
    execution.abandon("the transfer checkpoint could not be created") catch {};
    switch (err) {
        error.DestinationHeld => {
            // Three answers, and each gets its own sentence. A read that *failed*
            // is not "nobody holds it": saying so would describe a path as
            // contested by nothing while the index has just refused it, so the
            // failure is named beside the refusal it could not word.
            const found = transfers.findHolder(store, arena, dest_side, dest_path) catch |read_err| fatal(
                "refused: another transfer is standing on '{s}'; nothing was sent. Which one could not be read back ({s}) — 'terminus request ls' will show it",
                .{ dest_path, @errorName(read_err) },
            );
            if (found) |held| refuseHeld(arena, held, dest_path);
            // Refused by the index and gone by the time we looked, which means a
            // peer released or finished it in between. Nothing of ours was
            // written either way, so this is a retry, not a dead end.
            fatal(
                "refused: another transfer was standing on '{s}' when this one tried to claim it and had let go by the time we looked; nothing was sent. Run it again",
                .{dest_path},
            );
        },
        error.CheckpointAlreadyExists => fatal(
            "refused: this request already has a checkpoint; nothing was sent",
            .{},
        ),
        else => fatal("cannot record the transfer checkpoint: {s}", .{@errorName(err)}),
    }
}

/// Remote paths land inside single-quoted shell strings and, for the probe and
/// the publish, as arguments to `stat`, `tail` and `mv`.
///
/// The leading-dash rejection is the one that is not about quoting: a path
/// beginning with `-` is read as an option by every one of those, and
/// `mv -f -rf x` is not a rename.
pub fn validateRemotePath(path: []const u8) void {
    if (path.len == 0 or std.mem.indexOfAny(u8, path, "'\"\n`$") != null)
        fatal("remote path must not contain quotes, backticks, '$' or newlines", .{});
    if (path[0] == '-')
        fatal("remote path must not begin with '-' (it would be read as an option)", .{});
}

fn reportBlocked(blocker: Core.execution.Blocker) noreturn {
    switch (blocker) {
        .unsettled => |op| fatal(
            "refused: request {s} is {s} on an overlapping path, so this transfer could publish over work in flight; nothing was sent. Reconcile it ('terminus request reconcile {s}') or pass --force",
            .{ op.request_id, op.status.text(), op.request_id },
        ),
        .lease => |lease| fatal(
            "refused: request {s} (on {s}) holds a lease on an overlapping path until {d}; nothing was sent. Wait, take it over, or pass --force",
            .{ lease.owner_request_id, lease.profile_token, lease.expires_at },
        ),
    }
}

test {
    _ = @import("cmd_transfer_test.zig");
}
