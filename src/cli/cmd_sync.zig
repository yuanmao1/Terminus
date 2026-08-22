//! `terminus sync push/pull` — recursive directory transfer.
//!
//! Implementation: tar the tree (std.tar locally, `tar` remotely), move
//! one archive over SCP, unpack on the other side, verify with a whole-
//! archive MD5. One archive beats per-file SCP round trips by orders of
//! magnitude on many-small-file trees, and `tar` exists on any remote
//! that has a shell.
//!
//!   terminus sync push <server> <local-dir> <remote-dir> [--exclude p1,p2] [--dry-run] [--delete]
//!   terminus sync pull <server> <remote-dir> <local-dir> [--exclude p1,p2] [--dry-run]
//!
//! # The row this verb did not have
//!
//! Until now `sync` ran `rm -rf '<remote_dir>' && tar -xf …` on somebody's host
//! and wrote **nothing** to the operation ledger: no request id, no receipt, no
//! scope guard, no terminal. It reported `ok: true` on the strength of one
//! `client.exec` whose exit code, on a channel that closed without the remote
//! sending an exit-status message, is the *channel's* zero and not the command's.
//! A destructive verb reporting success from a default is the one shape this
//! tree refuses outright, and the four answers below are what replaced it.
//!
//! **Which kind: `.exec`.** Decided off `operations.Kind.capabilities`, not off
//! the name. A sync's remote act is one shell script this binary composed and
//! sent — `md5sum` the staged archive, refuse on a mismatch, optionally `rm -rf`,
//! `mkdir -p`, `tar -xf`, `rm -f` — and **that script's exit status is the
//! verdict**, which is exactly what `runs_our_command` says. The alternatives
//! were read the same way and each fails on a terminal it would need:
//!
//!   * `transfer_push`/`transfer_pull` declare `publishes_declared_artifact`, and
//!     `receipts.terminalDescribes` then admits only `never_submitted`,
//!     `local_abandon` and `indeterminate` for them. A sync that unpacked
//!     cleanly could not be settled at all — those kinds cannot reach
//!     `completed` through `settle` by construction, because their verdict is a
//!     reading of one address with a digest declared before submission. A tar
//!     extracted over a tree declares no such address: the md5 here is over the
//!     *archive*, checked by the host before it unpacks, and nothing reads the
//!     destination back afterwards.
//!   * `control` declares `supervises_another_subject` — its subject is somebody
//!     else's session — and refuses `exited`. A sync's subject is its own work.
//!   * `cleanup` declares `judgement_undeclared`, which does admit `exited`; but
//!     that field records that *nothing is known* about what such an operation is
//!     judged by, and `operations.zig` says a change that builds a producer for
//!     one must set it false and declare what it does. That is a store change,
//!     and this verb does not need one: `.exec` already describes it truthfully.
//!
//! `.exec` also makes two of its own axes true in fact rather than by permission:
//! the script goes out through `execution.runCommand`, so `supervisor.wrapShell`
//! reports the remote pid and start token onto the trail (`records_process_identity`)
//! and the far side is the supervisor that could report a deadline
//! (`supervised_deadline`). Nothing here sets a remote deadline, so
//! `remote_deadline` is simply never produced — admissible is not required.
//!
//! **Which scope: `.path`, keyed on the remote directory.** A sync's blast radius
//! is the directory it names on the host, and `scope.Scope.overlaps` already gives
//! the containment rule that needs: holding `/srv/app` blocks `/srv/app/dist` in
//! both directions, and a `terminus push` aimed at `/srv/app/config.json` — which
//! scopes `.path` on its own destination — is inside it. So a push and a sync to
//! overlapping paths contend today with no new machinery; nothing had to be added
//! to `scope.zig`.
//!
//! **Which side is a mutation.** A push writes the remote directory, so it holds
//! the scope. A pull only reads it — the host tars a directory into `/tmp` and
//! reports a digest — so it is `mutating = false` and bars nobody, per
//! `BeginOptions.mutating`. The bytes a pull writes land on *this* machine, and
//! that write is not a remote effect; see the note on `pull` for what that leaves
//! open.
//!
//! **What a lost channel settles as.** Nothing here decides that. `runCommand`
//! hands every transport error to `op_state.terminalForTransportLoss`, which
//! reads the state: before submission a proven failure, after submission
//! `indeterminate`. The staging upload is deliberately *before* submission — it
//! writes a temp file and nothing else, exactly as `Core.script.stage` does for
//! `exec`, so a failure there provably never unpacked anything. From the moment
//! the script goes out, a broken channel is `indeterminate` and so is a channel
//! that closes cleanly without the supervisor's exit marker: in both, the remote
//! may already have replaced the directory. That second arm is the whole reason
//! this verb goes through `runCommand` rather than calling `exec` itself.
const std = @import("std");
const fatal = Cli.fail;
const Cli = @import("cli.zig");
const Core = @import("../core/core.zig");
const Store = Core.Store;
/// The shared source reader the text-level gates in this tree use. See the gate
/// at the bottom of this file.
const Control = @import("../core/control.zig");

/// `pub` so a gate can hold the flags this verb takes against the ones it acts on.
pub const usage =
    \\usage: terminus sync push <server> <local-dir> <remote-dir> [--exclude p1,p2] [--dry-run] [--delete] [--force] [--json]
    \\       terminus sync pull <server> <remote-dir> <local-dir> [--exclude p1,p2] [--dry-run] [--force] [--json]
    \\
    \\  --exclude   comma-separated substring patterns (e.g. node_modules,.git)
    \\  --dry-run   list what would transfer, change nothing
    \\  --delete    (push) remove remote files not present locally
    \\  --force     proceed past a claim on the same remote directory, recording
    \\              the override on this attempt's trail
    \\
;

pub const Verb = enum { push, pull };

/// What a sync is, in the terms `receipts.terminalDescribes` decides in. The
/// argument is in this file's header; it belongs to the kind, not to a call site.
pub const kind: Store.operations.Kind = .exec;

/// The mutation scope a sync contends on: the remote directory it names.
///
/// `pub` because it is the claim two gates check — that two syncs to overlapping
/// remote paths see each other, and that a `terminus push` into one of them does
/// too. Both fall out of `scope.Scope.overlaps`'s `.path` arm.
pub fn scopeOf(remote_dir: []const u8) Core.execution.Scope {
    return .{ .kind = .path, .key = remote_dir };
}

/// Whether this sync changes the remote directory it named.
///
/// A push does. A pull reads it, and `--dry-run` in either direction changes
/// nothing anywhere. Read-only work still gets a row — `request ls` lists it and
/// it can be reconciled — but it must not hold the barrier: a dry-run that
/// refused the real run behind it is a guard that gets switched off.
pub fn mutates(verb: Verb, dry_run: bool) bool {
    return verb == .push and !dry_run;
}

/// The push script's own answer for "the digest I read is not the one you sent",
/// chosen out of the range no ordinary command uses. Nothing was unpacked.
pub const corrupt_exit: i32 = 43;

/// Both scripts' answer for "the directory you named is not there".
pub const missing_dir_exit: i32 = 44;

/// What the one remote act a sync is judged by came back as.
///
/// Three arms and not two: an exit status the host reported and *no* exit status
/// at all are different facts, and collapsing them is the defect this verb had.
pub const Verdict = union(enum) {
    /// The host ran the script and it reported success. Carries its stdout.
    completed: []const u8,
    /// The host ran the script and reported a status of its own.
    nonzero: struct { exit_code: i32, stdout: []const u8, stderr: []const u8 },
    /// No exit status came back — the channel broke after submission, or closed
    /// without the supervisor's marker. The remote may have done the work.
    unknown,
};

/// Either the script ran (however it ended), or the scope guard refused to let
/// it be sent. A refusal has no exit code and no remote effect.
pub const Act = union(enum) {
    ran: Verdict,
    refused: Core.execution.Blocker,
};

/// Reads a completed run without inventing an answer for one that had none.
///
/// `pub` so a gate can pin the mapping directly: the single thing that must never
/// happen here is `.unknown` being reported as a status, because a caller told
/// "failed" re-runs a destructive extract and a caller told "completed" believes
/// a directory it never saw.
pub fn verdictOf(outcome: Core.execution.RunOutcome) Verdict {
    if (outcome.status == .indeterminate) return .unknown;
    const code = outcome.exit_code orelse return .unknown;
    if (code == 0) return .{ .completed = outcome.stdout };
    return .{ .nonzero = .{
        .exit_code = code,
        .stdout = outcome.stdout,
        .stderr = outcome.stderr,
    } };
}

/// Sends the one script this sync is judged by, under the execution that owns it.
///
/// Every exit from here has recorded a terminal, because `runCommand` is the
/// thing that guarantees it — the submission, the scope guard's binding check,
/// the exit status, the transport loss and the marker-free close are all its.
pub fn remoteAct(
    execution: *Core.execution.Execution,
    executor: Core.Executor,
    script: []const u8,
) Act {
    const result = Core.execution.runCommand(execution, executor, script, null) catch |err|
        // The script may well have run; what failed is our record of it.
        Cli.receiptFatal(execution.id(), err, execution.status.text());
    return switch (result) {
        .refused => |blocker| .{ .refused = blocker },
        .ran => |outcome| .{ .ran = verdictOf(outcome) },
    };
}

pub fn run(ctx: *Cli.Ctx, raw_args: []const []const u8) !void {
    if (raw_args.len == 0) fatal("{s}", .{usage});
    const verb = std.meta.stringToEnum(Verb, raw_args[0]) orelse
        fatal("unknown verb 'sync {s}'\n{s}", .{ raw_args[0], usage });
    const parsed = Cli.parseArgs(ctx, raw_args[1..]);
    if (parsed.boolean("json")) ctx.out.format = .json;

    const server_name = parsed.positional(0) orelse fatal("{s}", .{usage});
    const src = parsed.positional(1) orelse fatal("{s}", .{usage});
    const dst = parsed.positional(2) orelse fatal("{s}", .{usage});
    const excludes = parseExcludes(ctx, parsed.flag("exclude"));
    const dry_run = parsed.boolean("dry-run");

    // The remote directory, whichever way the bytes go. It is this attempt's
    // scope key, so it is validated here — before an operation row exists and
    // before a connection does.
    const remote_dir = switch (verb) {
        .push => dst,
        .pull => src,
    };
    validateRemotePath(remote_dir);

    var store = try Cli.openStore(ctx, &parsed);
    defer store.close();
    const resolved = Cli.resolveServer(ctx, &store, server_name);
    const owner_token = Store.policy.ownerToken(&store, ctx.arena, ctx.io, ctx.now) catch |err|
        Cli.storeFatal(&store, err);

    const detail = try std.fmt.allocPrint(ctx.arena, "{s} {s} -> {s}{s}", .{
        @tagName(verb), src, dst, if (dry_run) " (dry-run)" else "",
    });

    const start = Core.execution.begin(&store, ctx.arena, ctx.io, .{
        .server_id = resolved.server.id,
        .server_name = resolved.server.name,
        .kind = kind,
        .scope = scopeOf(remote_dir),
        .mutating = mutates(verb, dry_run),
        .argv_redacted = Store.history.redactSecrets(ctx.arena, detail) catch
            // Storing it raw would write the very secrets the redaction exists
            // to keep out of an append-only ledger.
            fatal("cannot redact the sync description for the audit record; refusing to store it unredacted", .{}),
        .transport = "direct",
        .owner_token = owner_token,
        .force = parsed.boolean("force"),
        .now = ctx.now,
    }) catch |err| Cli.storeFatal(&store, err);
    var execution = switch (start) {
        .ready => |e| e,
        .blocked => |blocker| reportBlocked(blocker),
    };
    // `fail` exits with `std.process.exit`, which skips defers — so without this
    // every fatal path below would leave an attempt with no terminal.
    Cli.registerExecution(&execution);
    defer {
        Cli.clearExecution();
        execution.deinit();
    }

    const started = std.Io.Timestamp.now(ctx.io, .awake);
    execution.connecting() catch |err| Cli.receiptFatal(execution.id(), err, "created");

    var client = Cli.sshConnect(resolved.server, resolved.auth);
    defer client.deinit();
    // Two handles on one connection, and both are needed: `runCommand` takes an
    // `Executor`, while the scp staging paths are methods on the client itself.
    const executor: Core.Executor = .{ .direct = &client };

    const summary = switch (verb) {
        .push => try push(ctx, &execution, executor, &client, src, dst, excludes, dry_run, parsed.boolean("delete")),
        .pull => try pull(ctx, &execution, executor, &client, src, dst, excludes, dry_run),
    };

    const elapsed_ns = started.durationTo(std.Io.Timestamp.now(ctx.io, .awake)).nanoseconds;
    const duration_ms: i64 = @intCast(@divTrunc(elapsed_ns, std.time.ns_per_ms));

    // The history row, which is a different record from the receipt above it and
    // is kept for the same reason it always was: `terminus history` is the
    // per-server narrative an operator reads, and the ledger is the per-attempt
    // one. Its failure used to be `catch {}` with `.ok = true` two statements
    // below it — the one thing this project's rules forbid outright, stated in
    // `cli.zig` above `receiptFatal`, which names this very call. `auditFatal` is
    // that rule with the same exit code: this attempt now *has* a request id, but
    // what failed here is not the operation receipt, so `receiptFatal`'s envelope
    // would name the wrong thing as incomplete.
    Store.history.add(&store, resolved.server.id, .{
        .kind = "sync",
        .detail = detail,
        .exit_code = 0,
        .transport = "direct",
        .duration_ms = duration_ms,
    }, ctx.now) catch |err| Cli.auditFatal("sync", server_name, detail, err);

    const unknown = execution.status == .indeterminate;
    switch (ctx.out.format) {
        .json => try ctx.out.json(.{
            .ok = !unknown,
            .requestId = execution.id(),
            .status = execution.status.text(),
            .action = @tagName(verb),
            .server = server_name,
            .source = src,
            .destination = dst,
            .scopePath = remote_dir,
            .files = summary.files,
            .bytes = summary.bytes,
            .dryRun = dry_run,
            .verified = summary.verified,
            .durationMs = duration_ms,
        }),
        .human => {
            if (unknown) {
                try ctx.out.print("sync {s} {s} -> {s}: the remote outcome is unknown\n", .{
                    @tagName(verb), src, dst,
                });
            } else if (dry_run) {
                try ctx.out.print("dry-run: {d} files ({Bi}) would sync {s} -> {s}\n", .{
                    summary.files, summary.bytes, src, dst,
                });
            } else {
                try ctx.out.print("synced {d} files ({Bi}) {s} -> {s} in {d} ms{s}\n", .{
                    summary.files,                                   summary.bytes, src, dst, duration_ms,
                    if (summary.verified) " [md5 verified]" else "",
                });
            }
        },
    }

    // An unknown outcome gets its own exit code so it can never be mistaken for
    // a plain failure and retried — a retry of a sync push runs `rm -rf` again.
    if (unknown) {
        try ctx.out.flush();
        Cli.failIndeterminateAfterOutput(execution.id());
    }
}

const Summary = struct {
    files: u64,
    bytes: u64,
    verified: bool,
};

fn parseExcludes(ctx: *Cli.Ctx, flag: ?[]const u8) []const []const u8 {
    const text = flag orelse return &.{};
    var out: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, text, ',');
    while (it.next()) |p| {
        const trimmed = std.mem.trim(u8, p, " \t");
        if (trimmed.len > 0) out.append(ctx.arena, trimmed) catch fatal("out of memory", .{});
    }
    return out.toOwnedSlice(ctx.arena) catch fatal("out of memory", .{});
}

fn excluded(path: []const u8, excludes: []const []const u8) bool {
    for (excludes) |pattern| {
        if (std.mem.indexOf(u8, path, pattern) != null) return true;
    }
    return false;
}

/// Where a sync stages its archive on the host.
///
/// Derived from the request id rather than from the clock, so a temp file left
/// behind by an attempt that died names the attempt that left it. Ids are
/// Crockford base32 (`store/ids.zig`), so nothing here can become shell syntax.
pub fn stagingPath(arena: std.mem.Allocator, request_id: []const u8) ![]const u8 {
    return std.fmt.allocPrint(arena, "/tmp/.terminus_sync_{s}.tar", .{request_id});
}

/// The script the host runs to unpack a staged archive.
///
/// `pub` so a gate can read it without a host: it verifies the digest *before*
/// it touches the destination, so `corrupt_exit` is a refusal with nothing
/// applied, and `--delete`'s `rm -rf` is inside the same `set -e` sequence as the
/// extract that replaces what it removed.
pub fn unpackScript(
    arena: std.mem.Allocator,
    remote_tmp: []const u8,
    md5_hex: []const u8,
    remote_dir: []const u8,
    delete: bool,
) ![]const u8 {
    const delete_clause = if (delete)
        try std.fmt.allocPrint(arena, "rm -rf '{s}' && ", .{remote_dir})
    else
        "";
    return std.fmt.allocPrint(arena,
        \\set -e
        \\actual=$(md5sum {s} | cut -d' ' -f1)
        \\[ "$actual" = "{s}" ] || {{ echo "checksum mismatch: $actual"; rm -f {s}; exit {d}; }}
        \\{s}mkdir -p '{s}'
        \\tar -xf {s} -C '{s}'
        \\rm -f {s}
    , .{
        remote_tmp, md5_hex,    remote_tmp, corrupt_exit, delete_clause,
        remote_dir, remote_tmp, remote_dir, remote_tmp,
    });
}

/// The script the host runs to tar a directory up for a pull.
pub fn archiveScript(
    arena: std.mem.Allocator,
    remote_dir: []const u8,
    exclude_args: []const u8,
    remote_tmp: []const u8,
) ![]const u8 {
    return std.fmt.allocPrint(arena,
        \\set -e
        \\[ -d '{s}' ] || exit {d}
        \\tar -cf {s} -C '{s}'{s} .
        \\md5sum {s} | cut -d' ' -f1
    , .{ remote_dir, missing_dir_exit, remote_tmp, remote_dir, exclude_args, remote_tmp });
}

/// The script a `pull --dry-run` runs: a count and a size, and no write anywhere.
pub fn probeScript(arena: std.mem.Allocator, remote_dir: []const u8) ![]const u8 {
    return std.fmt.allocPrint(arena,
        \\[ -d '{s}' ] || exit {d}
        \\cd '{s}' && find . -type f | wc -l && du -sb . | cut -f1
    , .{ remote_dir, missing_dir_exit, remote_dir });
}

/// Local tree → tar in memory → SCP → remote `tar -x` → md5 verify.
///
/// The archive is built and staged *before* `remoteAct` submits, on the same rule
/// `cmd_exec` stages a script under: writing a temp file really does reach the
/// host, and a failure doing it provably never ran the destructive part. From
/// `remoteAct` onwards a lost channel is `indeterminate`.
///
/// The whole-tree-in-memory tar is a separate problem and is left alone here.
fn push(
    ctx: *Cli.Ctx,
    execution: *Core.execution.Execution,
    executor: Core.Executor,
    client: *Core.Ssh,
    local_dir: []const u8,
    remote_dir: []const u8,
    excludes: []const []const u8,
    dry_run: bool,
    delete: bool,
) !Summary {
    var dir = std.Io.Dir.cwd().openDir(ctx.io, local_dir, .{ .iterate = true }) catch
        fatal("cannot open local directory '{s}'", .{local_dir});
    defer dir.close(ctx.io);

    // Build the archive in memory (dev trees; not multi-GB datasets).
    var archive: std.Io.Writer.Allocating = .init(ctx.arena);
    var tar_writer: std.tar.Writer = .{ .underlying_writer = &archive.writer };

    var files: u64 = 0;
    var bytes: u64 = 0;
    var walker = try dir.walk(ctx.arena);
    defer walker.deinit();
    while (walker.next(ctx.io) catch |err| fatal("walk failed in '{s}': {s}", .{ local_dir, @errorName(err) })) |entry| {
        if (excluded(entry.path, excludes)) continue;
        if (entry.kind != .file) continue;
        files += 1;
        const posix_path = try ctx.arena.dupe(u8, entry.path);
        std.mem.replaceScalar(u8, posix_path, '\\', '/');
        if (dry_run) {
            const stat = entry.dir.statFile(ctx.io, entry.basename, .{}) catch continue;
            bytes += stat.size;
            continue;
        }
        const file = entry.dir.openFile(ctx.io, entry.basename, .{}) catch |err|
            fatal("cannot read {s}: {s}", .{ entry.path, @errorName(err) });
        defer file.close(ctx.io);
        var read_buffer: [1 << 16]u8 = undefined;
        var reader = file.reader(ctx.io, &read_buffer);
        tar_writer.writeFile(posix_path, &reader, 0) catch |err|
            fatal("tar write failed for {s}: {s}", .{ entry.path, @errorName(err) });
        bytes += reader.getSize() catch 0;
    }
    if (dry_run) {
        // Nothing was handed over and nothing is going to be. See `settleDryRun`
        // for why `local_abandon` is the only honest terminal here.
        settleDryRun(execution);
        return .{ .files = files, .bytes = bytes, .verified = false };
    }

    tar_writer.finishPedantically() catch fatal("tar finish failed", .{});
    const tar_bytes = archive.writer.buffered();

    var md5: [16]u8 = undefined;
    std.crypto.hash.Md5.hash(tar_bytes, &md5, .{});
    const md5_hex = try std.fmt.allocPrint(ctx.arena, "{x}", .{&md5});

    // Stage the archive remotely (scp, or base64-over-exec when the server has
    // no scp binary). Still before submission: this writes one temp file and
    // reads nothing of the destination, so a failure here settles a proven
    // failure through `Cli.fail`'s hook rather than an unknown.
    const remote_tmp = try stagingPath(ctx.arena, execution.id());
    const remote_tmp_z = try ctx.arena.dupeZ(u8, remote_tmp);
    _ = client.scpSendBytes(ctx.io, tar_bytes, remote_tmp_z, 0o600) catch {
        Core.transfer.pushBytes(client, ctx.arena, tar_bytes, remote_tmp, 0o600) catch |err|
            fatal("upload failed (scp and exec both): {s} ({s})", .{ client.errorMessage(), @errorName(err) });
    };

    const script = try unpackScript(ctx.arena, remote_tmp, md5_hex, remote_dir, delete);
    switch (remoteAct(execution, executor, script)) {
        .refused => |blocker| reportBlocked(blocker),
        .ran => |verdict| switch (verdict) {
            .completed => return .{ .files = files, .bytes = bytes, .verified = true },
            .nonzero => |answer| if (answer.exit_code == corrupt_exit)
                fatal("transfer corrupted (md5 mismatch): {s}", .{answer.stdout})
            else
                fatal("remote unpack failed (exit {d}): {s}", .{ answer.exit_code, answer.stderr }),
            // Reported by `run` as `indeterminate`, with exit 75 and no `ok`.
            // The archive was staged and the script went out, so the directory
            // may already have been replaced; saying "failed" here would invite
            // the retry that runs `rm -rf` a second time.
            .unknown => return .{ .files = files, .bytes = bytes, .verified = false },
        },
    }
}

/// Remote `tar -c` → SCP down → std.tar extract → md5 verify.
///
/// The operation covers the **remote** half: the host is asked to tar a directory
/// into `/tmp` and report its digest, and that script's exit status is the
/// verdict. The download and the local extract that follow write this machine's
/// filesystem, which is not a remote effect and is not what this row is about —
/// so the row is `mutating = false` and holds no barrier. Two concurrent pulls
/// into one local directory are therefore not guarded against each other; that
/// gap is older than this change and is not closed here.
fn pull(
    ctx: *Cli.Ctx,
    execution: *Core.execution.Execution,
    executor: Core.Executor,
    client: *Core.Ssh,
    remote_dir: []const u8,
    local_dir: []const u8,
    excludes: []const []const u8,
    dry_run: bool,
) !Summary {
    if (dry_run) {
        const script = try probeScript(ctx.arena, remote_dir);
        switch (remoteAct(execution, executor, script)) {
            .refused => |blocker| reportBlocked(blocker),
            .ran => |verdict| switch (verdict) {
                .completed => |out| {
                    var lines = std.mem.splitScalar(u8, std.mem.trim(u8, out, " \n\r"), '\n');
                    const files = std.fmt.parseInt(u64, std.mem.trim(u8, lines.next() orelse "0", " \r"), 10) catch 0;
                    const bytes = std.fmt.parseInt(u64, std.mem.trim(u8, lines.next() orelse "0", " \r"), 10) catch 0;
                    return .{ .files = files, .bytes = bytes, .verified = false };
                },
                .nonzero => |answer| if (answer.exit_code == missing_dir_exit)
                    fatal("remote directory '{s}' does not exist", .{remote_dir})
                else
                    fatal("probe failed (exit {d}): {s}", .{ answer.exit_code, answer.stderr }),
                .unknown => return .{ .files = 0, .bytes = 0, .verified = false },
            },
        }
    }

    var exclude_args: std.ArrayList(u8) = .empty;
    for (excludes) |pattern| {
        try exclude_args.appendSlice(ctx.arena, try std.fmt.allocPrint(ctx.arena, " --exclude='*{s}*'", .{pattern}));
    }

    // Remote: tar to a temp file (SCP needs a real file), report its md5.
    const remote_tmp = try stagingPath(ctx.arena, execution.id());
    const script = try archiveScript(ctx.arena, remote_dir, exclude_args.items, remote_tmp);
    const remote_md5 = switch (remoteAct(execution, executor, script)) {
        .refused => |blocker| reportBlocked(blocker),
        .ran => |verdict| switch (verdict) {
            .completed => |out| std.mem.trim(u8, out, " \n\r"),
            .nonzero => |answer| if (answer.exit_code == missing_dir_exit)
                fatal("remote directory '{s}' does not exist", .{remote_dir})
            else
                fatal("remote tar failed (exit {d}): {s}", .{ answer.exit_code, answer.stderr }),
            .unknown => return .{ .files = 0, .bytes = 0, .verified = false },
        },
    };

    const remote_tmp_z = try ctx.arena.dupeZ(u8, remote_tmp);
    const tar_bytes = client.scpRecvBytes(ctx.io, ctx.arena, remote_tmp_z) catch
        Core.transfer.pullBytes(client, ctx.arena, remote_tmp) catch |err|
        fatal("download failed (scp and exec both): {s} ({s})", .{ client.errorMessage(), @errorName(err) });

    // Removing the archive this request's own script wrote, at a path derived
    // from this request's id. It happens after the terminal because the download
    // has to happen in between, and it is not the act the row is about — but a
    // failure is reported rather than dropped, because what it leaves is a file
    // on somebody's host with this request id in its name.
    _ = executor.exec(ctx.arena, try std.fmt.allocPrint(ctx.arena, "rm -f {s}", .{remote_tmp})) catch |err|
        std.debug.print(
            "terminus: could not remove the staged archive {s} on the remote host: {s}; delete it by hand\n",
            .{ remote_tmp, @errorName(err) },
        );

    var md5: [16]u8 = undefined;
    std.crypto.hash.Md5.hash(tar_bytes, &md5, .{});
    const local_md5 = try std.fmt.allocPrint(ctx.arena, "{x}", .{&md5});
    const verified = std.mem.eql(u8, local_md5, remote_md5);
    if (!verified) fatal("transfer corrupted: remote md5 {s} != local {s}", .{ remote_md5, local_md5 });

    std.Io.Dir.cwd().createDirPath(ctx.io, local_dir) catch |err|
        fatal("cannot create '{s}': {s}", .{ local_dir, @errorName(err) });
    var dir = std.Io.Dir.cwd().openDir(ctx.io, local_dir, .{ .iterate = true }) catch
        fatal("cannot open '{s}'", .{local_dir});
    defer dir.close(ctx.io);

    var tar_reader = std.Io.Reader.fixed(tar_bytes);
    std.tar.extract(ctx.io, dir, &tar_reader, .{}) catch |err|
        fatal("extract failed: {s}", .{@errorName(err)});

    // Count what we extracted for the summary.
    var files: u64 = 0;
    var walker = try dir.walk(ctx.arena);
    defer walker.deinit();
    while (walker.next(ctx.io) catch null) |entry| {
        if (entry.kind == .file) files += 1;
    }
    return .{ .files = files, .bytes = tar_bytes.len, .verified = true };
}

/// What a `push --dry-run`'s terminal says, in full.
///
/// `pub` so a gate reads the sentence the ledger will actually carry rather than
/// its own transcription of it.
pub const dry_run_reason = "--dry-run: the local tree was listed and nothing was sent";

/// The terminal for a push that connected and then chose not to submit.
///
/// `local_abandon` — "nothing had been handed over, so there is nothing to
/// stop" — and it records `cancelled`. The two alternatives are both lies:
/// `never_submitted` records `failed` and claims a transport error that did not
/// happen, and `exited` cannot be constructed at all because no command ran.
/// Leaving it unsettled is worse than either: `Execution.deinit` would then file
/// `indeterminate` — an unknown remote outcome, for a run that made no remote
/// call.
///
/// A `pull --dry-run` does not come here. It really does ask the host something
/// (`find`, `du`), so it goes out through `remoteAct` like any other act and is
/// settled by the probe's own exit status.
pub fn settleDryRun(execution: *Core.execution.Execution) void {
    _ = execution.settle(.{ .local_abandon = .{ .reason = dry_run_reason } }, .{}) catch |err|
        Cli.receiptFatal(execution.id(), err, execution.status.text());
}

/// Refuses an attempt that another claim on the same remote directory makes
/// unsafe. Nothing was sent on either route into here.
fn reportBlocked(blocker: Core.execution.Blocker) noreturn {
    switch (blocker) {
        .unsettled => |op| fatal(
            "refused: request {s} is {s} on an overlapping path, so this sync could be applied twice; nothing was sent. Reconcile it ('terminus request reconcile {s}') or pass --force",
            .{ op.request_id, op.status.text(), op.request_id },
        ),
        .lease => |lease| fatal(
            "refused: request {s} (on {s}) holds a lease on an overlapping path until {d}; nothing was sent. Wait, take it over, or pass --force",
            .{ lease.owner_request_id, lease.profile_token, lease.expires_at },
        ),
    }
}

/// Remote paths land inside single-quoted shell strings.
fn validateRemotePath(path: []const u8) void {
    if (path.len == 0 or std.mem.indexOfAny(u8, path, "'\"\n`$") != null)
        fatal("remote path must not contain quotes, backticks, '$' or newlines", .{});
}

// The rule `cli.zig` states above `receiptFatal`, applied to the one audit write
// this verb makes.
//
// **Why it is read off the source and not driven.** Reaching the write needs an
// SSH connection and a remote `tar`, and the failure route ends in
// `std.process.exit`, so there is no in-process call that can observe the branch.
// What can be observed is that the branch is there — and that is the whole of the
// defect: the error was bound to nothing and `.ok = true` followed it. The
// envelope this routes into is driven by `cli.zig`'s own gate.
//
// Three things, because they are the three ways it came back: the write is made
// exactly once in this body, its failure is bound rather than discarded, and what
// it is bound to is a path that does not return.
test "gate: the audit write is routed, not swallowed" {
    const t = std.testing;
    const body = try Control.bodyOf(@embedFile("cmd_sync.zig"), "\npub fn run(");
    // Assembled so this gate's own text is not one of the sites it counts — the
    // gate lives outside `run`, but the needle must survive being moved into it.
    const call = "Store.history" ++ ".add(";

    var found: usize = 0;
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, body, i, call)) |at| : (i = at + 1) found += 1;
    if (found != 1) {
        std.debug.print(
            \\
            \\cmd_sync.zig's `run` makes {d} audit writes. It may have exactly one, and this
            \\gate reads the statement it opens to check that its failure is reported.
            \\
        , .{found});
        return error.AuditWriteNotFound;
    }

    const at = std.mem.indexOf(u8, body, call).?;
    const end = std.mem.indexOfScalarPos(u8, body, at, ';') orelse return error.AuditWriteUnterminated;
    const statement = body[at .. end + 1];
    if (std.mem.indexOf(u8, statement, "catch |err| Cli.auditFatal(") == null) {
        std.debug.print(
            \\
            \\cmd_sync.zig's audit write no longer routes its failure to `Cli.auditFatal`:
            \\
            \\  {s}
            \\
            \\`sync` reports `ok: true` two statements below this. A ledger write we could not
            \\make is not a sync we get to report as clean — cli.zig says so above
            \\`receiptFatal`, and names this call as the one that used to. If the route
            \\genuinely moved, point this gate at the new one; deleting it puts the swallow
            \\back where nothing can see it.
            \\
        , .{statement});
        return error.AuditWriteSwallowed;
    }
    // …and the thing it routes to does not come back, so the success document
    // below is unreachable from a failed write.
    try t.expect(@typeInfo(@TypeOf(Cli.auditFatal)).@"fn".return_type.? == noreturn);
}

test {
    _ = @import("cmd_sync_test.zig");
}
