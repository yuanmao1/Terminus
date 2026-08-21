//! CLI namespace: shared context plus per-command modules.
const std = @import("std");

pub const Output = @import("output.zig");
pub const Dispatch = @import("dispatch.zig");
pub const Args = @import("args.zig");
pub const Setup = @import("cmd_setup.zig");
/// The one reader for `skill/SKILL.md`, shared by the drift gates in
/// `cmd_job.zig` and `cmd_session.zig`.
///
/// Re-exported here rather than left file-private because the black-box gates need
/// the same bytes: `test/blackbox.zig`'s package root is `test/`, so it cannot
/// `@embedFile` a document outside it, and the build wires `terminus_skill` into
/// the library module alone. Through this it reaches `Terminus.Cli.skill_doc.text`
/// and reads the shipped text instead of the checkout's working directory.
pub const skill_doc = @import("skill_doc.zig");

const Core = @import("../core/core.zig");
/// The shared lease-renewal barrier, for `bodyOf` — the one source reader the
/// gates in this tree hold text-level rules with. See `cmd_job.zig`, which uses
/// the same one for the renewal-adjacency and release-ordering rules.
const Control = @import("../core/control.zig");
const Store = Core.Store;
const Ssh = Core.Ssh;
const DaemonClient = Core.DaemonClient;
const Executor = Core.Executor;

/// Everything a command handler needs, built once in main().
pub const Ctx = struct {
    io: std.Io,
    arena: std.mem.Allocator,
    environ: *std.process.Environ.Map,
    out: *Output,
    /// Unix seconds at process start; used for created_at/updated_at.
    now: i64,
    /// Top-level --db override (global flag, may also appear per-command).
    db_override: ?[]const u8 = null,
};

/// The active context, so `fail` can honor --json from anywhere (including
/// helpers with no Ctx parameter). Single-threaded CLI.
var active_ctx: ?*Ctx = null;

pub fn setActiveCtx(ctx: *Ctx) void {
    active_ctx = ctx;
}

/// The daemon socket this command is talking over, if it is talking over one.
///
/// `std.process.exit` skips defers, so `Connection.deinit` never runs on any of
/// the fatal paths below: the process dies with the socket still open and the
/// OS tears it down abruptly. The peer — the daemon, or the black-box gates'
/// stand-in for it — is sitting in a read at that moment, and on Windows an
/// abrupt teardown surfaces there as `STATUS_CONNECTION_RESET`, which std maps
/// to `error.Unexpected` and prints a stack trace for at the point the error is
/// created. Catching it at the peer does not suppress the trace, and the peer
/// cannot substitute its own read: the socket is an AFD handle std opened, and
/// std's Windows path maps three statuses and routes every other one through
/// `unexpectedStatus`. So the trace can only be prevented here, by the side
/// that owns the close.
///
/// A client that has finished is not a fault, and it should not arrive at the
/// other end looking like one — on a green run least of all, where the trace is
/// indistinguishable from a real transport failure.
///
/// Held by value rather than as a pointer to the caller's `Connection`: the
/// stream is a handle, a copy closes the same one, and a pointer would outlive
/// the `Connection` on every path that returns normally.
///
/// The daemon socket only, never a direct SSH session. Closing that one means a
/// libssh2 teardown handshake over a link a fatal path has usually just watched
/// fail, and a process on its way out must not be made to wait on it.
var active_daemon_socket: ?struct { io: std.Io, stream: std.Io.net.Stream } = null;

fn registerDaemonSocket(io: std.Io, stream: std.Io.net.Stream) void {
    active_daemon_socket = .{ .io = io, .stream = stream };
}

/// Forgets a socket somebody else is about to close, so this never closes a
/// handle twice. Matched by handle, not unconditionally: a command that opens a
/// second connection while the first is still live would otherwise have the
/// first one's `deinit` drop the registration belonging to the second.
fn clearDaemonSocket(stream: std.Io.net.Stream) void {
    const open = active_daemon_socket orelse return;
    if (open.stream.socket.handle != stream.socket.handle) return;
    active_daemon_socket = null;
}

/// Ends the conversation with the daemon before the process ends.
///
/// Called from every path here that reaches `std.process.exit`. Idempotent, and
/// it clears the registration before closing: a closed handle can be reissued
/// to something else, and a second close would then land on a stranger.
pub fn closeDaemonSocket() void {
    const open = active_daemon_socket orelse return;
    active_daemon_socket = null;
    var stream = open.stream;
    stream.close(open.io);
}

/// Everything the three refusals below do before they have a document to write:
/// end the daemon conversation, settle the execution, give the job name back, and
/// give the scope back.
///
/// The scope release is *returned* rather than dropped, and that is the whole
/// point of this function existing. Every refusal in the tree comes through one of
/// the three, and until now all three released through the `void` `releaseClaim()`
/// — so a `job kill` whose store call failed under a held lease exited 1 with
/// `{ok, error}`, and the leaked lease that would refuse the operator's next
/// command for its whole TTL reached stderr and nothing else. There is no
/// shortage of routes to here: `storeFatal`, `fatalTmux`, `fatalProbe` and the
/// bare `fatal` between them account for seventeen call sites inside bodies that
/// hold a claim. Publishing at each of them is seventeen chances to forget;
/// publishing here is none.
fn refusalCleanup() ClaimRelease {
    closeDaemonSocket();
    settleActiveExecution("command failed before recording an outcome");
    releaseReservation();
    // Above the document, like every other reporter of this answer: a value
    // written before the release has happened is a prediction, and the whole
    // point of the key is that it is the answer.
    return releaseClaimReporting();
}

/// The refusal envelope, in the one place that decides its shape.
///
/// Four shapes from two independent questions — does the caller have a stable
/// `errorCode`, and is there a lease answer to publish — written out rather than
/// composed, because `Output.json` takes a struct and a struct's key set is its
/// type.
///
/// **The lease keys are present exactly when a lease was held.** Not always: `fail`
/// is the tree-wide route and almost none of its callers ever take one, so two keys
/// on every bad `--limit` and every unknown server would say `not_taken` and
/// nothing else. Not never: that was the defect. A verb that publishes the keys as
/// part of a fixed set passes `always`, which is what `failReportingClaim` is.
fn writeRefusal(
    ctx: *Ctx,
    message: []const u8,
    code: ?[]const u8,
    lease: ClaimRelease,
    always: bool,
) void {
    const publish = always or !lease.tookNothing();
    if (code) |named| {
        if (publish) {
            ctx.out.json(.{
                .ok = false,
                .@"error" = message,
                .errorCode = named,
                .leaseRelease = lease.code,
                .leaseReleaseError = lease.detail,
            }) catch {};
        } else {
            ctx.out.json(.{ .ok = false, .@"error" = message, .errorCode = named }) catch {};
        }
    } else if (publish) {
        ctx.out.json(.{
            .ok = false,
            .@"error" = message,
            .leaseRelease = lease.code,
            .leaseReleaseError = lease.detail,
        }) catch {};
    } else {
        ctx.out.json(.{ .ok = false, .@"error" = message }) catch {};
    }
    ctx.out.flush() catch {};
}

/// Fail-loud exit: in JSON mode emits `{"ok":false,"error":...}` on stdout
/// (agents parse one stream); in human mode writes stderr. Always exit 1.
///
/// Two more keys when — and only when — this command was holding a scope lease
/// when it failed. See `writeRefusal`; human mode needs no extra line, because
/// `releaseClaimReporting` has already written the sentence for every answer that
/// is not an ordinary hand-back.
pub fn fail(comptime fmt: []const u8, args: anytype) noreturn {
    const lease = refusalCleanup();
    if (active_ctx) |ctx| {
        if (ctx.out.format == .json) {
            writeRefusal(ctx, std.fmt.allocPrint(ctx.arena, fmt, args) catch fmt, null, lease, false);
            std.process.exit(exit_code.failure);
        }
    }
    std.process.fatal(fmt, args);
}

/// `fail`, for a refusal a caller has to be able to branch on.
///
/// The prose says which barrier and how many rows; the code is what an agent
/// matches, so it never has to pattern-match the sentence. Same stream, same
/// exit status and the same `settleActiveExecution` / `releaseReservation`
/// discipline as `fail` — the only difference is that the reason has a stable
/// name as well as a wording.
///
/// The code is printed in human mode too. A refusal an operator can act on is
/// one they will want to search for, and a code that only exists in `--json`
/// is a code half the callers never see.
pub fn failWithCode(code: []const u8, comptime fmt: []const u8, args: anytype) noreturn {
    const lease = refusalCleanup();
    if (active_ctx) |ctx| {
        if (ctx.out.format == .json) {
            writeRefusal(ctx, std.fmt.allocPrint(ctx.arena, fmt, args) catch fmt, code, lease, false);
            std.process.exit(exit_code.failure);
        }
    }
    std.process.fatal(fmt ++ "\n  code: {s}", args ++ .{code});
}

/// `fail`, for a command whose key set publishes the lease answer unconditionally.
///
/// Same stream, same exit status and the same `settleActiveExecution` /
/// `releaseReservation` discipline as `fail`. The difference is one word:
/// `always`. `fail` publishes the two keys when a lease was held and omits them
/// when none was; this publishes them either way, including `not_taken`.
///
/// **Why that distinction is worth a second entry point.** `fail` is the tree-wide
/// route and almost none of its callers ever take a lease, so unconditional keys
/// would put `not_taken` on every refusal in the CLI — a bad `--limit`, an unknown
/// server, a missing key — where the answer says nothing. Conditional keys are
/// wrong for the opposite kind of caller: `Cli.connectReportingClaim`'s failures are
/// a documented envelope of exactly four keys, and a caller that has been told to
/// read `leaseRelease` there must find it whatever it says. Hence both, over one
/// emitter.
///
/// **Why this is not the verb's own fixed key set either.** The paths that reach
/// here fail before the verb has established anything: `Cli.connect` could not
/// reach the host or could not authenticate, so there is no step to report, and no
/// word in either verb's published `errorCode` vocabulary that means "we never got
/// a connection". Minting one is a protocol addition rather than something this
/// closes. What these paths *can* state, and now do, is what happened to the lease
/// they were holding.
pub fn failReportingClaim(comptime fmt: []const u8, args: anytype) noreturn {
    const lease = refusalCleanup();
    if (active_ctx) |ctx| {
        if (ctx.out.format == .json) {
            writeRefusal(ctx, std.fmt.allocPrint(ctx.arena, fmt, args) catch fmt, null, lease, true);
            std.process.exit(exit_code.failure);
        }
    }
    // Human mode needs no extra line: `releaseClaimReporting` has already written
    // the sentence for every answer that is not an ordinary hand-back.
    std.process.fatal(fmt, args);
}

/// The execution owning the current command, if any.
///
/// `fail` ends the process with `std.process.exit`, which skips defers — so
/// without this hook every fatal path would leave an attempt with no
/// terminal, and the boundary would be bypassable simply by erroring out.
var active_execution: ?*Core.execution.Execution = null;

pub fn registerExecution(e: *Core.execution.Execution) void {
    active_execution = e;
}

pub fn clearExecution() void {
    active_execution = null;
}

fn settleActiveExecution(reason: []const u8) void {
    const execution = active_execution orelse return;
    active_execution = null; // never re-enter, even if settling itself fails
    execution.abandon(reason) catch |err| {
        std.debug.print(
            "terminus: RECEIPT_PERSIST_FAILED for {s}: {s} (remote state unknown)\n",
            .{ execution.id(), @errorName(err) },
        );
    };
}

/// A job-name reservation held by the command currently running.
///
/// The `jobs` row has to be written *before* the launch path tears down and
/// rebuilds the job's remote tmux session, because its `UNIQUE(server_id,
/// name)` index is the only thing that makes two simultaneous launches pick a
/// winner atomically. Without it a second `run --name deploy` could still be
/// connecting when the first one starts sending keys, and would then kill the
/// session it had just filled with real work.
///
/// Reserving that early means every fatal exit in between would strand a row
/// for a job that never started — and `fail` exits with `std.process.exit`,
/// which skips defers. Hence this hook, the same shape as the execution one.
///
/// The reservation is identified by the launch that owns it, not by the job
/// name and not by the row id. A name is what a takeover transfers; a rowid
/// is reused by the next INSERT after a delete. Either would let an aborted
/// launcher release the row of the launcher that replaced it.
const Reservation = struct {
    store: *Store,
    request_id: []const u8,
    /// For the failure message only. Identity is `request_id`.
    name: []const u8,
};
var active_reservation: ?Reservation = null;

pub fn registerReservation(store: *Store, request_id: []const u8, name: []const u8) void {
    active_reservation = .{ .store = store, .request_id = request_id, .name = name };
}

/// Keeps the reservation: the command is in the remote's hands now, so the
/// row describes something that may be running and must not be dropped.
pub fn commitReservation() void {
    active_reservation = null;
}

/// Gives the name back, if this launch still owns it.
///
/// Called from `fail` (which skips defers) and from the launch path's own
/// `defer` — the latter both covers a plain error return and guarantees the
/// borrowed `*Store` never outlives the frame that owns it. A row that is no
/// longer `pending`, or no longer ours, is left exactly where it is.
pub fn releaseReservation() void {
    const held = active_reservation orelse return;
    active_reservation = null; // never re-enter
    _ = Store.jobs.releaseReservation(held.store, held.request_id) catch |err| {
        // Reported, not swallowed: what is left behind is a name that will
        // refuse the next launch until it is removed by hand.
        std.debug.print(
            "terminus: could not release the name reservation for job '{s}': {s}; " ++
                "clear it with 'terminus job rm' before relaunching\n",
            .{ held.name, @errorName(err) },
        );
    };
}

/// A scope lease held by the command currently running.
///
/// `job kill` and `job rm` take one before their first remote call and hold it
/// across probe → kill → settle, so a peer cannot start killing, removing or
/// relaunching the same job underneath them. Because the claim is taken that
/// early, every fatal exit in between would otherwise leave it held — and a
/// lease is owned by the *attempt*, so the operator's very next `job kill`
/// mints a new id and is refused by the corpse of the one that just failed,
/// for the whole TTL. `fail` exits with `std.process.exit`, which skips
/// defers, so it releases through here; the same shape as the reservation hook
/// above and for the same reason.
///
/// Identity is `owner_request_id`. Releasing by scope alone would let a failing
/// command hand away the claim of the peer that displaced it.
const Claim = struct {
    store: *Store,
    server_id: i64,
    scope: Core.execution.Scope,
    owner_request_id: []const u8,
    /// For the failure message only.
    job_name: []const u8,
};
var active_claim: ?Claim = null;

pub fn registerClaim(
    store: *Store,
    server_id: i64,
    scope: Core.execution.Scope,
    owner_request_id: []const u8,
    job_name: []const u8,
) void {
    active_claim = .{
        .store = store,
        .server_id = server_id,
        .scope = scope,
        .owner_request_id = owner_request_id,
        .job_name = job_name,
    };
}

/// What became of the scope lease a command took.
///
/// Returned rather than printed, and that is the defect this closes. Every
/// failure below used to write a line to stderr and hand `void` back, so the
/// caller went on to report `ok: true` — a leaked lease that refuses the
/// operator's next command for its whole TTL, under a JSON document claiming
/// success. The stderr line is still written, because it names the subject and a
/// human reading a terminal wants it; the value is what a machine reads.
///
/// `code` is the machine-readable half and is never null. `detail` is prose:
/// nothing may branch on it.
pub const ClaimRelease = struct {
    /// One of `codes`, and never null.
    code: []const u8,
    detail: ?[]const u8,

    /// The whole published vocabulary, in one namespace so it can be
    /// *enumerated* rather than transcribed.
    ///
    /// Three verbs publish this key — `session rm`, `job kill`, `job rm` — and
    /// `skill/SKILL.md` publishes the value list beside each of them. A list of
    /// words in prose is exactly what drifts, and the key-set gates read keys and
    /// skip parentheticals, so the values had nothing holding them. Held against
    /// this namespace instead: renaming a word here rewrites the check along with
    /// the code. See the gate in `cmd_job.zig`.
    pub const codes = struct {
        pub const not_taken = "not_taken";
        pub const released = "released";
        pub const not_ours = "not_ours";
        pub const left_held = "left_held";
    };

    /// No claim was registered by this command, so there is none to give back.
    /// The answer for every branch that refuses before the lease is acquired —
    /// distinct from `released`, because "nothing was taken" and "what was taken
    /// was handed back" are different facts about the scope.
    pub const not_taken: ClaimRelease = .{ .code = codes.not_taken, .detail = null };

    /// The row was ours and is now released and dated.
    pub const released: ClaimRelease = .{ .code = codes.released, .detail = null };

    /// `leases.release` matched no row: the claim is not ours to give back,
    /// because a peer displaced it. Nothing of ours is left holding the scope, so
    /// this is not a leak — but it is not a release either, and a caller that
    /// collapsed the two would report a lost claim as a clean hand-back.
    pub const not_ours: ClaimRelease = .{
        .code = codes.not_ours,
        .detail = "this command's scope lease was no longer ours to release; a peer had taken it over",
    };

    /// The claim is still held and will block further changes to this scope until
    /// its TTL lapses. The leak, named.
    fn leftHeld(detail: []const u8) ClaimRelease {
        return .{ .code = codes.left_held, .detail = detail };
    }

    pub fn holdsScope(r: ClaimRelease) bool {
        return std.mem.eql(u8, r.code, codes.left_held);
    }

    /// This command registered no claim, so there is nothing here to publish.
    ///
    /// The question the shared refusal envelopes branch on: `not_taken` beside a
    /// bad `--limit` is two keys of noise, and every other answer is a fact about
    /// a scope the caller is about to be told to retry on. Read through the code
    /// rather than by comparing against `not_taken` at each site, for the reason
    /// `holdsScope` exists.
    pub fn tookNothing(r: ClaimRelease) bool {
        return std.mem.eql(u8, r.code, codes.not_taken);
    }
};

/// Gives the scope back, and says what happened.
///
/// The form every verb that takes a scope lease now uses: `session rm`,
/// `job kill` and `job rm` all publish the answer. See `releaseClaim` for the
/// void form the process-ending paths below are left with, and `ClaimRelease`
/// for why the answer exists at all.
///
/// **The release is stamped with the clock as it is now**, read through the
/// store, and not with the `ctx.now` the claim used to be registered with.
/// `ctx.now` is one wall-clock read taken at process start (`main.zig`), and
/// `claimJobScope` used to stamp the acquisition with that same frozen value —
/// so a release stamped from it wrote `released_at == acquired_at` on every
/// `job kill` and `job rm`, recording a lease that was held for zero seconds no
/// matter how long the command actually ran. Once `holdClaim` started renewing
/// off a fresh clock, the same frozen stamp additionally landed *before* the
/// renewal that provably preceded it, whenever an integer-second boundary was
/// crossed in between. `leases.release` now refuses that second shape outright;
/// this is what stops us handing it one.
///
/// Every writer of a lease row now reads a live clock — the acquisition and the
/// takeover in `claimJobScope`, the renewal in `holdClaim`, and this — so the
/// claim carries no timestamp of its own at all. There is nothing here to pick
/// the wrong one from.
///
/// Read through `leases.clockSeconds` rather than `std.Io.Timestamp.now`
/// because this hook runs from `std.process.exit` paths where the only `io` in
/// reach is `active_ctx`'s — a global that `main` alone populates, so every
/// in-process caller (the gates included) would find it null and need a
/// fallback, and the only fallback on offer is the frozen stamp this exists to
/// stop using. See `leases.clockSeconds`.
pub fn releaseClaimReporting() ClaimRelease {
    const held = active_claim orelse return .not_taken;
    active_claim = null; // never re-enter
    const now = Store.leases.clockSeconds(held.store) catch |err| {
        // Reported, not swallowed, and the claim is deliberately left held: a
        // release we cannot date is a release we would have to invent a date
        // for, and an invented one is what this whole change removes.
        std.debug.print(
            "terminus: could not read the clock to date the release of the scope lease for job '{s}': {s}; " ++
                "the claim is left held and will lapse at its TTL\n",
            .{ held.job_name, @errorName(err) },
        );
        return ClaimRelease.leftHeld(
            "the clock could not be read, so this command's scope lease was left held and will block further changes to that scope until its TTL lapses",
        );
    };
    const released = Store.leases.release(
        held.store,
        held.server_id,
        held.scope,
        held.owner_request_id,
        .released,
        now,
    ) catch |err| {
        switch (err) {
            // The store refused the stamp as contradicting the row's own
            // history. Distinct from every other failure here on purpose: it
            // does not mean the database is unreachable and it does not mean
            // somebody took the claim — it means this machine's clock now reads
            // earlier than the moment that row was acquired or last renewed, so
            // either the clock moved backwards under us or something wrote that
            // row with a time it had no business writing. Left held rather than
            // forced through.
            error.LeaseTimestampsOutOfOrder => {
                std.debug.print(
                    "terminus: refused to date the release of the scope lease for job '{s}': the clock now reads " ++
                        "earlier than the lease's own acquisition or last renewal, so recording it would put that row's " ++
                        "timestamps out of order; the claim is left held and will lapse at its TTL\n",
                    .{held.job_name},
                );
                return ClaimRelease.leftHeld(
                    "the clock now reads earlier than this lease's own acquisition or last renewal, so dating the release would put that row's timestamps out of order; the claim was left held and will block further changes to that scope until its TTL lapses",
                );
            },
            // Reported, not swallowed: what is left behind is a scope that
            // refuses the operator's next attempt on this job until the lease
            // lapses.
            else => {
                std.debug.print(
                    "terminus: could not release the scope lease for job '{s}': {s}; " ++
                        "it will block further changes to that job until it expires\n",
                    .{ held.job_name, @errorName(err) },
                );
                return ClaimRelease.leftHeld(
                    "the store refused the release, so this command's scope lease was left held and will block further changes to that scope until its TTL lapses",
                );
            },
        }
    };
    return if (released) .released else .not_ours;
}

/// Gives the scope back and throws the answer away.
///
/// **One caller, and it is the only one that can have this be correct.**
/// `failIndeterminateAfterOutput` is reached after the caller has written its whole
/// document — including its own `leaseRelease`, from its own
/// `releaseClaimReporting` — so by the time it runs there is no claim registered and
/// this answers `not_taken`. It is a no-op that keeps the hook total rather than a
/// route that drops anything.
///
/// **Every other process-ending path in this file publishes.** `fail`,
/// `failWithCode`, `failIndeterminate` and `receiptFatal` write a document, and a
/// document is somewhere the answer can go: each of them now releases through
/// `releaseClaimReporting` and carries `leaseRelease` / `leaseReleaseError` when a
/// lease was held. That is what closed the seventeen call sites in `cmd_job.zig`
/// that reach one of them under a claim — through `storeFatal`, `fatalTmux`,
/// `fatalProbe` and the bare `fatal` — without touching one of them: the answer
/// travels with the envelope, so a new site cannot forget to bring it.
///
/// A claim that is no longer ours — a peer took it over with `--force` — matches no
/// row and is left exactly where it is. See `ClaimRelease`, and the gate at the
/// bottom of this file that holds this function to its single caller.
pub fn releaseClaim() void {
    _ = releaseClaimReporting();
}

/// `std.process.exit`, with the daemon conversation ended first.
///
/// The exits in this file are reached through `fail` and its siblings, which
/// close the socket themselves. A command that has already written its whole
/// response and only needs the status code exits directly instead, and those
/// sites are why this exists: they are the same abrupt teardown seen from a
/// path that did not fail. See `active_daemon_socket`.
pub fn exitNow(code: u8) noreturn {
    closeDaemonSocket();
    std.process.exit(code);
}

/// Process exit codes with a defined meaning to callers.
pub const exit_code = struct {
    pub const ok: u8 = 0;
    pub const failure: u8 = 1;
    /// The remote outcome could not be established. Distinct from `failure`
    /// on purpose (B6): an agent must be able to tell "it did not work" from
    /// "we do not know whether it worked", because the second one forbids a
    /// blind retry.
    pub const indeterminate: u8 = 75;
    /// The audit ledger could not be written. The remote effect may well have
    /// happened; what failed is our ability to record it.
    pub const receipt_persist_failed: u8 = 76;
};

/// The only exit for "the remote state is unknown".
///
/// Never collapses into `fail`: reporting an indeterminate result as a plain
/// error would invite exactly the blind retry that can double-apply a remote
/// side effect.
///
/// Carries the lease answer when a lease was held, on the same rule as `fail`, and
/// this is the envelope where it matters most: the hint tells the caller to
/// reconcile and then retry, and a lease this command could not hand back refuses
/// exactly that until its TTL lapses.
pub fn failIndeterminate(request_id: []const u8, reason: []const u8, last_observed: []const u8) noreturn {
    closeDaemonSocket();
    // Above the document that publishes it.
    const lease = releaseClaimReporting();
    if (active_ctx) |ctx| {
        if (ctx.out.format == .json) {
            if (lease.tookNothing()) {
                ctx.out.json(.{
                    .ok = false,
                    .status = "indeterminate",
                    .@"error" = reason,
                    .errorCode = "INDETERMINATE",
                    .requestId = request_id,
                    .lastObserved = last_observed,
                    .hint = indeterminate_hint,
                }) catch {};
            } else {
                ctx.out.json(.{
                    .ok = false,
                    .status = "indeterminate",
                    .@"error" = reason,
                    .errorCode = "INDETERMINATE",
                    .requestId = request_id,
                    .lastObserved = last_observed,
                    .leaseRelease = lease.code,
                    .leaseReleaseError = lease.detail,
                    .hint = indeterminate_hint,
                }) catch {};
            }
            ctx.out.flush() catch {};
            std.process.exit(exit_code.indeterminate);
        }
        ctx.out.print(
            "indeterminate: {s}\n  request: {s}\n  last observed: {s}\n  reconcile before retrying: terminus request reconcile {s}\n",
            .{ reason, request_id, last_observed, request_id },
        ) catch {};
        ctx.out.flush() catch {};
    }
    std.process.exit(exit_code.indeterminate);
}

const indeterminate_hint = "the remote outcome is unknown; reconcile with 'terminus request reconcile <request-id>' before retrying";

/// Ends a command whose response has already been written.
///
/// The caller has printed a full result carrying `status: "indeterminate"`;
/// all that remains is the exit code, which must not be 1 — an agent has to
/// be able to tell "it did not work" from "we do not know", because only the
/// first is safe to retry.
pub fn failIndeterminateAfterOutput(request_id: []const u8) noreturn {
    closeDaemonSocket();
    clearExecution(); // already settled by the execution itself
    releaseClaim();
    if (active_ctx) |ctx| {
        if (ctx.out.format == .human) {
            std.debug.print(
                "indeterminate: the remote outcome is unknown; reconcile before retrying: terminus request reconcile {s}\n",
                .{request_id},
            );
        }
        ctx.out.flush() catch {};
    }
    std.process.exit(exit_code.indeterminate);
}

/// The tree-wide receipt-failure envelope. No defaults, so a branch that omits a
/// key does not compile.
const ReceiptFatalJson = struct {
    ok: bool,
    @"error": []const u8,
    errorCode: []const u8,
    requestId: []const u8,
    cause: []const u8,
    remoteStatus: ?[]const u8,
    hint: []const u8,
};

/// The same envelope, for a caller that was holding a scope lease.
///
/// Written out rather than derived so the emitted key order is visible here; held
/// to the one above by the gate at the bottom of this file, which is what stops the
/// two from drifting apart the way two copies of anything else here would.
const ReceiptFatalWithClaimJson = struct {
    ok: bool,
    @"error": []const u8,
    errorCode: []const u8,
    requestId: []const u8,
    cause: []const u8,
    remoteStatus: ?[]const u8,
    leaseRelease: []const u8,
    leaseReleaseError: ?[]const u8,
    hint: []const u8,
};

const receipt_fatal_error = "could not persist the operation receipt";
const receipt_fatal_hint = "the remote action may have taken effect; the local ledger is incomplete";

/// A write to the operation ledger failed.
///
/// This must never be swallowed the way `history.add(...) catch {}` was: if
/// we cannot record what we did, we do not get to claim we did it cleanly.
/// The remote effect is reported as far as we know it, alongside an explicit
/// signal that the audit trail is incomplete.
///
/// The route for every caller that holds no scope lease: `exec`, `read`/`write`,
/// `run`, `request reconcile`, and the observing `job` verbs. It is safe for a
/// caller that *does* hold one — the lease answer travels with the envelope on the
/// same rule as `fail`'s — and `receiptFatalReportingClaim` is the form for a
/// caller whose key set publishes it unconditionally.
pub fn receiptFatal(
    request_id: []const u8,
    err: anyerror,
    known_remote_status: ?[]const u8,
) noreturn {
    closeDaemonSocket();
    // Above the document that publishes it.
    writeReceiptFatal(request_id, err, known_remote_status, releaseClaimReporting(), false);
}

/// `receiptFatal`, for a caller whose key set publishes the lease answer
/// unconditionally.
///
/// The ledger write that failed here was made *under* a claim, so the claim is
/// given back on the way out — and it used to go through the `void`
/// `releaseClaim()`, which drops the answer. That is the worst place to drop it:
/// this is the branch where the remote step already happened, the ledger does not
/// have it, and the caller is about to be told to reconcile. A `left_held` on top of
/// that means the reconcile-then-retry the hint asks for is refused for the lease's
/// whole TTL, and the only warning was a line on stderr under a JSON document that
/// never mentioned a lease.
///
/// The difference from `receiptFatal` is `always`, for the reason
/// `failReportingClaim` gives: `settleObserved` reads the claim it was handed and
/// picks between the two, so a verb that documents the two keys on every ledger
/// failure gets them even when the answer is `not_taken`.
pub fn receiptFatalReportingClaim(
    request_id: []const u8,
    err: anyerror,
    known_remote_status: ?[]const u8,
) noreturn {
    closeDaemonSocket();
    writeReceiptFatal(request_id, err, known_remote_status, releaseClaimReporting(), true);
}

/// One body for both, so the two envelopes cannot be filled differently.
///
/// The `ReceiptFatalJson` / `ReceiptFatalWithClaimJson` gate at the bottom of this
/// file holds their key sets to each other; this holds their *values* to each
/// other, which two hand-written call sequences did not.
fn writeReceiptFatal(
    request_id: []const u8,
    err: anyerror,
    known_remote_status: ?[]const u8,
    lease: ClaimRelease,
    always: bool,
) noreturn {
    if (active_ctx) |ctx| {
        if (ctx.out.format == .json) {
            if (always or !lease.tookNothing()) {
                ctx.out.json(ReceiptFatalWithClaimJson{
                    .ok = false,
                    .@"error" = receipt_fatal_error,
                    .errorCode = "RECEIPT_PERSIST_FAILED",
                    .requestId = request_id,
                    .cause = @errorName(err),
                    .remoteStatus = known_remote_status,
                    .leaseRelease = lease.code,
                    .leaseReleaseError = lease.detail,
                    .hint = receipt_fatal_hint,
                }) catch {};
            } else {
                ctx.out.json(ReceiptFatalJson{
                    .ok = false,
                    .@"error" = receipt_fatal_error,
                    .errorCode = "RECEIPT_PERSIST_FAILED",
                    .requestId = request_id,
                    .cause = @errorName(err),
                    .remoteStatus = known_remote_status,
                    .hint = receipt_fatal_hint,
                }) catch {};
            }
            ctx.out.flush() catch {};
            std.process.exit(exit_code.receipt_persist_failed);
        }
        ctx.out.print(
            "RECEIPT_PERSIST_FAILED: {s}\n  request: {s}\n  remote status: {s}\n  the remote action may have taken effect; the local ledger is incomplete\n",
            .{ @errorName(err), request_id, known_remote_status orelse "unknown" },
        ) catch {};
        if (lease.detail) |text| ctx.out.print("  {s}\n", .{text}) catch {};
        ctx.out.flush() catch {};
    }
    std.process.exit(exit_code.receipt_persist_failed);
}

// The claim-reporting envelope is the shared one plus exactly the two lease keys,
// in the same order, with the same types — and that is checked rather than
// asserted in a comment, because two hand-written copies of one envelope is the
// shape this whole pass exists to stop repeating. A key added to `receiptFatal`
// and not to its sibling would otherwise leave two verbs reporting a ledger
// failure differently, which is how `localRow` came to be missing from `job rm`'s.
test "gate: the claim-reporting receipt envelope is the shared one plus the lease answer" {
    const t = std.testing;
    const plain = @typeInfo(ReceiptFatalJson).@"struct".fields;
    const with_claim = @typeInfo(ReceiptFatalWithClaimJson).@"struct".fields;

    // `hint` is last on both, and the two lease keys sit immediately before it.
    const added = [_][]const u8{ "leaseRelease", "leaseReleaseError" };
    try t.expectEqual(plain.len + added.len, with_claim.len);
    try t.expectEqualStrings("hint", plain[plain.len - 1].name);
    try t.expectEqualStrings("hint", with_claim[with_claim.len - 1].name);

    // Every key the shared envelope has before `hint`, in the same order and with
    // the same type. A key added to one and not the other lands here.
    inline for (plain[0 .. plain.len - 1], 0..) |f, i| {
        try t.expectEqualStrings(f.name, with_claim[i].name);
        try t.expect(f.type == with_claim[i].type);
    }
    inline for (added, 0..) |name, k| {
        try t.expectEqualStrings(name, with_claim[plain.len - 1 + k].name);
    }
}

/// The *audit* ledger's failure envelope, for a verb that has no operation to
/// name. No defaults, on the same rule as the two above.
const AuditFatalJson = struct {
    ok: bool,
    @"error": []const u8,
    errorCode: []const u8,
    action: []const u8,
    server: []const u8,
    effect: []const u8,
    cause: []const u8,
    hint: []const u8,
};

const audit_fatal_error = "could not record the action in the audit ledger";
const audit_fatal_hint = "the action was already carried out; what failed is the record of it";

/// A write to the `history` ledger failed, on a verb that opened no operation.
///
/// **Why this is not `receiptFatal`.** That envelope names a `requestId` and every
/// caller of it has an `Execution` to take one from. `sync` has neither: it holds
/// no scope lease and opens no operation row, so the only way to reach
/// `receiptFatal` from it would be to invent an id — the same falsehood as the
/// `catch {}` this replaces, written more convincingly.
///
/// **What does carry over is the rule and the exit code.** The rule is the one
/// stated above `receiptFatal`: if we cannot record what we did, we do not get to
/// claim we did it cleanly. The code is **76** and not 1, because 1 means "it did
/// not work" and the files demonstrably moved — that distinction is the whole
/// reason `receipt_persist_failed` is not `failure`.
///
/// `effect` is what the verb actually did, in its own words, because the caller is
/// being handed an incomplete audit trail and this sentence is now the only place
/// that fact exists.
///
/// **For a caller holding no claim**, which is what "no operation row" means here:
/// nothing registers a claim without opening one. A verb that took a lease and
/// wants this envelope needs the two lease keys on it first, the way every other
/// document path in this file carries them.
pub fn auditFatal(
    action: []const u8,
    server: []const u8,
    effect: []const u8,
    err: anyerror,
) noreturn {
    closeDaemonSocket();
    if (active_ctx) |ctx| {
        writeAuditFatal(ctx, action, server, effect, err);
        ctx.out.flush() catch {};
    }
    std.process.exit(exit_code.receipt_persist_failed);
}

/// The document, split from the exit so a gate can read it.
fn writeAuditFatal(
    ctx: *Ctx,
    action: []const u8,
    server: []const u8,
    effect: []const u8,
    err: anyerror,
) void {
    switch (ctx.out.format) {
        .json => ctx.out.json(AuditFatalJson{
            .ok = false,
            .@"error" = audit_fatal_error,
            .errorCode = "AUDIT_PERSIST_FAILED",
            .action = action,
            .server = server,
            .effect = effect,
            .cause = @errorName(err),
            .hint = audit_fatal_hint,
        }) catch {},
        .human => ctx.out.print(
            "AUDIT_PERSIST_FAILED: {s}\n  action: {s} on {s}\n  what happened: {s}\n  {s}\n",
            .{ @errorName(err), action, server, effect, audit_fatal_hint },
        ) catch {},
    }
}

// The envelope, driven. What this holds is the one thing the defect got wrong:
// a failed audit write is reported as a failure, with a code a caller can branch
// on and an exit that is not 1. The route from `cmd_sync` into here is held by
// that file's own gate, which reads the call site — this path ends in
// `std.process.exit`, so nothing can drive it whole.
test "gate: a failed audit write is published as a failure, not as a clean run" {
    const t = std.testing;
    var buffer: [4096]u8 = undefined;
    var captured: Captured = .init(&buffer);
    writeAuditFatal(captured.ctxPtr(), "sync", "prod", "push ./src -> /srv/app", error.Sqlite);

    const text = captured.text();
    try t.expect(std.mem.indexOf(u8, text, "\"ok\": false") != null);
    try t.expect(std.mem.indexOf(u8, text, "\"errorCode\": \"AUDIT_PERSIST_FAILED\"") != null);
    // The effect is named. A caller told only that a write failed cannot tell
    // whether anything reached the host.
    try t.expect(std.mem.indexOf(u8, text, "push ./src -> /srv/app") != null);
    try t.expect(std.mem.indexOf(u8, text, "\"cause\": \"Sqlite\"") != null);
    // Not 1: the transfer happened, so "it did not work" is the wrong answer and
    // a blind retry is the wrong next step.
    try t.expect(exit_code.receipt_persist_failed != exit_code.failure);
}

/// How much of a job log's *end* a state probe reads. The sentinel is one
/// short line at the very end, so this only has to be large enough to survive
/// a burst of trailing output.
pub const probe_tail_bytes: i64 = 256 * 1024;

/// Whether a blocker could conceivably be settled by going and reading the
/// host.
///
/// Two conditions, both deliberately narrow:
///
///   * it has to be an unsettled operation. A lease is somebody's live claim
///     on the scope, not a stale outcome waiting to be read, and nothing on
///     the remote host can settle one;
///   * that operation has to be a job. A job writes its exit status to a known
///     address when it ends; an `exec` that never settled left nothing behind
///     to go and look at.
///
/// False means there is nothing to go and look for, so a caller that would
/// otherwise open a connection for the probe should not open one. `pub` for
/// that reason: it is the question a launch path has to answer before it can
/// decide whether a refusal is worth a round trip.
pub fn blockerMayBeProvable(blocker: Core.execution.Blocker) bool {
    return switch (blocker) {
        .lease => false,
        .unsettled => |op| std.mem.eql(u8, op.kind, "job"),
    };
}

test "only an unsettled job blocker is worth opening a connection for" {
    const t = std.testing;

    const op: Store.operations.Operation = .{
        .request_id = "01JQXW8ZK4N0RS7T3VYB2MCDEF",
        .schema_version = 1,
        .server_id = 1,
        .server_name = "prod",
        .kind = "job",
        .scope_kind = "job",
        .scope_key = "deploy",
        .alias = "deploy",
        .status = .indeterminate,
        .resolved_status = null,
        .reconciled_at = null,
        .resolution_evidence = null,
        .argv_redacted = null,
        .argv_sha256 = null,
        .cwd = null,
        .shell = null,
        .capability_json = null,
        .transport = null,
        .mutating = true,
        .created_at = 1750000000,
        .updated_at = 1750000000,
    };
    try t.expect(blockerMayBeProvable(.{ .unsettled = op }));

    // An exec leaves no durable record at a known address, so there is
    // nothing on the host a probe could read.
    var an_exec = op;
    an_exec.kind = "exec";
    try t.expect(!blockerMayBeProvable(.{ .unsettled = an_exec }));

    // A lease is a live claim by somebody else. Reading the host cannot
    // retire it, and a connection spent trying would be spent for nothing.
    const lease: Store.leases.Lease = .{
        .id = 1,
        .server_id = 1,
        .scope_kind = .job,
        .scope_key = "deploy",
        .owner_request_id = "01SOMEBODYELSE0123456789AB",
        .profile_token = "somebody-elses-machine",
        .owner_label = null,
        .note = null,
        .acquired_at = 1750000000,
        .renewed_at = 1750000000,
        .expires_at = 1750003600,
    };
    try t.expect(!blockerMayBeProvable(.{ .lease = lease }));
}

/// The store's vocabulary for what a probe found at a job's result-record
/// address, ready to travel into the terminal receipt.
///
/// An exhaustive switch and not a cast: `Store.receipts.ResultRecordReading` is a
/// separate type because nothing under `store/` may import `session/`, so this is
/// the seam where the two could drift. Adding a reading to `Tmux.SidecarReading`
/// is a compile error here until it has been named on the store side too, which is
/// the only thing keeping the receipt's vocabulary and the probe's the same list.
///
/// Every reading is carried, not just the four defective ones. "We looked and there
/// was nothing" and "we did not look" are different facts about the settlement, and
/// a receipt that recorded only anomalies could not tell either of them from a
/// settlement that predates this field.
///
/// **Why it lives here rather than beside its four callers in `cmd_job.zig`, which
/// is where it was.** There are five job-settlement paths and the fifth is in this
/// file: `settleProvableBlocker`. `cli.zig` cannot import `cmd_job.zig` —
/// `cmd_job.zig` imports this — so the seam above reached four of the five, and the
/// fifth duly wrote its terminal with the reading dropped. A new
/// `Tmux.SidecarReading` variant broke four settlements at compile time and was
/// structurally invisible to the one that had no switch to break. One home fixes
/// that for the fifth and for the sixth.
///
/// Takes the arena rather than the `Ctx` it used to, because the arena is all it
/// ever read and a `Ctx` is not something the gate below could honestly build.
pub fn resultRecordOf(
    arena: std.mem.Allocator,
    reading: Core.Tmux.SidecarReading,
) Store.receipts.TerminalExtra.ResultRecord {
    return .{
        .arena = arena,
        .reading = switch (reading) {
            .not_requested => .not_requested,
            .absent => .absent,
            .malformed => .malformed,
            .unknown_schema => .unknown_schema,
            .exit_code_out_of_range => .exit_code_out_of_range,
            .foreign => |claimed| .{ .foreign = claimed },
            .present => .present,
        },
    };
}

/// The receipt extra for a settlement proved by reading a blocking job's own log.
///
/// **A function taking the whole probe, and that is the fix rather than the
/// tidying.** The call site was a three-key literal, and there is nothing about a
/// literal that can be *missing* a key: `settleProvableBlocker` wrote its terminal
/// with `stdout` and `source` and no `result_record`, so a settlement that had just
/// read a foreign or unparseable document at this request's own address recorded
/// the null that `receipts.TerminalExtra.result_record` reserves for "this is not a
/// job observation". This is one. Here there is no argument list the sidecar can be
/// left out of — the probe arrives whole — so the reading reaches the receipt for
/// the same reason the byte count does.
fn provenSettlementExtra(
    arena: std.mem.Allocator,
    probe: Core.Tmux.JobProbe,
) Store.receipts.TerminalExtra {
    return .{
        .stdout = .{ .bytes = @intCast(probe.output.len) },
        .source = .reconcile,
        // The case this field exists for: the settlement can be perfectly sound —
        // the log sentinel answered — while a document that is not ours, or not
        // readable, sits at this request's own address. The verdict is right and
        // the anomaly is still a fact about the host.
        .result_record = resultRecordOf(arena, probe.sidecar),
    };
}

// The fifth job-settlement path, held to the four the compiler already holds.
//
// Driven over every `SidecarReading` there is, so a reading added to the probe has
// to appear here too — the loop is exhaustive by construction rather than by a list
// somebody keeps. What it checks is the one thing the fifth path got wrong: the
// extra it hands to `settleAttachedAndSyncJob` carries a reading at all, and the
// reading it carries is the one `resultRecordOf` gives the other four for the same
// probe.
test "gate: the proved settlement records what it read at the result-record address" {
    const t = std.testing;
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const readings = [_]Core.Tmux.SidecarReading{
        .not_requested,
        .absent,
        .malformed,
        .{ .unknown_schema = 9 },
        .{ .exit_code_out_of_range = 300 },
        .{ .foreign = "01SOMEBODYELSE0123456789AB" },
        .present,
    };
    // Every variant, or the loop is checking a subset of the seam it claims to
    // hold. `@typeInfo` counts them; the list above supplies the payloads.
    try t.expectEqual(@typeInfo(Core.Tmux.SidecarReading).@"union".fields.len, readings.len);

    for (readings) |reading| {
        const probe: Core.Tmux.JobProbe = .{
            .output = "hello\n",
            .next_cursor = 6,
            .exit_code = 0,
            .session_alive = true,
            .sidecar = reading,
        };
        const extra = provenSettlementExtra(arena, probe);
        const record = extra.result_record orelse {
            std.debug.print(
                \\
                \\`settleProvableBlocker`'s settlement recorded nothing about the result record
                \\for a probe that read `{s}`. Null is `receipts.TerminalExtra`'s word for "this
                \\settlement is not a job observation"; this one is. The other four job paths
                \\pass `resultRecordOf` and this one is the only one with no switch of its own to
                \\break, so nothing but this notices.
                \\
            , .{reading.code()});
            return error.ProvedSettlementDroppedTheReading;
        };
        // The same word the other four record for the same probe.
        try t.expectEqualStrings(
            resultRecordOf(arena, reading).reading.code(),
            record.reading.code(),
        );
        // …and the reading is the probe's own, not a placeholder that happens to
        // be non-null.
        try t.expectEqualStrings(reading.code(), record.reading.code());
        // The two facts that were already there stay there.
        try t.expectEqual(@as(?i64, @intCast(probe.output.len)), extra.stdout.bytes);
        try t.expectEqual(Store.receipts.Source.reconcile, extra.source);
    }
}

// …and the other half, which the gate above cannot see: that the fifth path
// actually uses it.
//
// `settleProvableBlocker` needs a store, a live `Executor` and a host with a tmux
// session before it will settle anything, so nothing in this process can drive it
// and read the receipt back. What can be read is the call, and the call is the
// whole defect: the path wrote a three-key `TerminalExtra` literal of its own, and
// a literal cannot fail to compile for want of a key. `.source = .reconcile` is the
// fingerprint of that literal — it is the one field only this path sets — so a
// hand-built extra reappearing here is caught by its own signature.
test "gate: the fifth settlement path builds its receipt extra through the shared one" {
    const body = try Control.bodyOf(@embedFile("cli.zig"), "\npub fn settleProvableBlocker(");
    // Assembled so this gate's own text is not what it finds, on the same rule as
    // the `releaseClaim()` gate at the bottom of this file.
    const shared = "provenSettlement" ++ "Extra(";
    if (std.mem.indexOf(u8, body, shared) == null) {
        std.debug.print(
            \\
            \\`settleProvableBlocker` no longer builds its terminal extra through
            \\`provenSettlementExtra`. That function takes the whole probe precisely so there
            \\is no argument list the sidecar reading can be left out of; a literal here has
            \\no such property, and the last one settled a job observation with
            \\`result_record` null — the store's word for "this is not a job observation".
            \\
        , .{});
        return error.FifthPathBuildsItsOwnExtra;
    }
    if (std.mem.indexOf(u8, body, ".source = " ++ ".reconcile") != null) {
        std.debug.print(
            \\
            \\`settleProvableBlocker` sets `.source = .reconcile` itself, which means it is
            \\assembling a `TerminalExtra` rather than asking `provenSettlementExtra` for one.
            \\That is the shape the reading went missing from.
            \\
        , .{});
        return error.FifthPathBuildsItsOwnExtra;
    }
}

/// One opportunistic attempt to settle a blocker that has already finished.
///
/// A job settles only when somebody looks at it, and the scope guard blocks on
/// any unsettled peer. So a job that ended hours ago but was never polled goes
/// on refusing every same-scope mutation — including a rerun under the same
/// name — while the host has been holding its exit code the whole time. That
/// is a trap rather than a guard, and the escape hatch (`request reconcile`)
/// is a second command the caller has to know to run.
///
/// This closes it in the one direction that is safe: it can turn "unsettled
/// but provable" into "settled", and it can do nothing else. A blocker with no
/// recorded attempt, no recorded tmux session, no exit status, two durable
/// records that disagree, or a probe that errors all leave the blocker exactly
/// where it was. Absence of evidence never releases a scope.
///
/// A *live* session is deliberately not on that list. A tmux session outlives
/// the command that ran in it, so a live pane is the normal state of a
/// finished job; what proves the command returned is the sidecar it wrote when
/// it did, and the pane's liveness is unrelated to that.
///
/// It is also not the check. `submitted()` re-runs the authoritative guard
/// straight afterwards and refuses exactly as it does today if the blocker
/// survived — which is why every failure in here is opportunistic: it is
/// reported on stderr and the launch carries on to the real gate. Making a
/// probe failure fatal would mean an unreachable log could stop a launch the
/// guard would have allowed.
///
/// Three call sites reach it, and they are not equivalent. `cmd_exec` and
/// `cmd_job` call it twice each: once from the `.blocked` arm of `begin`,
/// where the blocker is the thing standing between the caller and a launch —
/// this is the case the doc opens with, a rerun refused by a job that finished
/// hours ago — and once with `Execution.advisory`, which `begin` sets only on
/// the branch where it let the launch through while still having something to
/// report. The first needs a connection opened before the operation exists;
/// that is why the launch paths hold their connection in an optional and fill
/// it from whichever branch gets there first.
pub fn settleProvableBlocker(
    ctx: *Ctx,
    store: *Store,
    executor: Executor,
    advisory: ?Core.execution.Blocker,
) void {
    const blocker = advisory orelse return;
    // One definition of "worth going to look at", shared with the launch
    // paths that use it to decide whether to open a connection at all.
    if (!blockerMayBeProvable(blocker)) return;
    const op = blocker.unsettled; // the only variant that predicate admits

    const attempt = (Store.job_attempts.byRequest(store, ctx.arena, op.request_id) catch |err| {
        std.debug.print(
            "terminus: could not look up the attempt for blocking request {s}: {s}; leaving it blocked\n",
            .{ op.request_id, @errorName(err) },
        );
        return;
    }) orelse return;
    const session = attempt.tmux_session orelse return;
    const sentinel = attempt.sentinel orelse return;

    // Probed with the *blocker's* own request id: the sidecar lives at an
    // address derived from it, and reading it under ours would find nothing.
    const probe = Core.Tmux.probeTail(executor, ctx.arena, session, sentinel, op.request_id, probe_tail_bytes) catch |err| {
        std.debug.print(
            "terminus: could not read the log of blocking job '{s}' ({s}): {s}; the scope guard will decide on what it already has\n",
            .{ attempt.job_name, op.request_id, @errorName(err) },
        );
        return;
    };
    if (probe.conflict) |clash| {
        // Two mechanical records of the same fact contradicting each other is
        // the one case where more evidence makes us less certain. Settling
        // from either would be picking a winner by implementation order.
        std.debug.print(
            "terminus: blocking job '{s}' ({s}) has contradictory records (result file says {d}, log sentinel says {d}); it stays blocked until reconciled\n",
            .{ attempt.job_name, op.request_id, clash.result_exit_code, clash.sentinel_exit_code },
        );
        return;
    }
    const code = probe.exit_code orelse {
        // The sibling of the conflict arm above, and silent until now. The
        // blocker correctly stays blocked — absence of evidence never releases
        // a scope — but an operator whose launch has just been refused was told
        // nothing about *why* the one thing that could have cleared it did not.
        // `job status` and `request reconcile` both say this loudly; a caller
        // who has only ever run `run --name X` sees neither.
        //
        // Two shapes, because they send an operator to different places. A
        // refusal means a record was found at this request's own address and
        // was defective — a truncated or malformed sidecar, a document naming
        // somebody else — and the log's own answer was declined rather than
        // missing, so the code it carried is worth printing. Nothing at all
        // means the job left no readable end anywhere: it may still be running.
        if (probe.refused) |declined| {
            std.debug.print(
                "terminus: blocking job '{s}' ({s}) has an unreadable result record; its log says it exited {d}, " ++
                    "but a defective record is not evidence and settling from the log alone would be guessing. " ++
                    "It stays blocked until reconciled: terminus request reconcile {s}\n",
                .{ attempt.job_name, op.request_id, declined.sentinel_exit_code, op.request_id },
            );
        } else {
            std.debug.print(
                "terminus: blocking job '{s}' ({s}) has recorded no exit status yet — no result record and no log " ++
                    "sentinel — so it may still be running; it stays blocked. Check with 'terminus job status {s}'\n",
                .{ attempt.job_name, op.request_id, attempt.job_name },
            );
        }
        return;
    };

    var execution = (Core.execution.attach(store, ctx.arena, ctx.io, op.request_id) catch |err| {
        std.debug.print(
            "terminus: could not re-open blocking request {s} to settle it: {s}; leaving it blocked\n",
            .{ op.request_id, @errorName(err) },
        );
        return;
    }) orelse return; // already settled by somebody else in the meantime

    // The cache row is read before the settlement and written inside the same
    // transaction as it. Reading it first is what makes the write a
    // compare-and-swap: `jobs` refuses it if the row moved, rather than
    // stamping an outcome onto whatever ended up carrying that name.
    //
    // `syncJobRow` used to run afterwards, as a second transaction, and
    // documented the divergence it left behind — the ledger settled while the
    // row that `run --name X` checks first still said `running`. That gap is
    // what this composition closes.
    const sync = jobCacheSync(store, ctx.arena, op.request_id, code, probe.finished_at, ctx.now);
    const settled = execution.settleAttachedAndSyncJob(
        .{ .exited = .{ .exit_code = code } },
        provenSettlementExtra(ctx.arena, probe),
        sync,
    ) catch |err| {
        std.debug.print(
            "terminus: could not record the outcome of blocking request {s}: {s}; leaving it blocked\n",
            .{ op.request_id, @errorName(err) },
        );
        return;
    };
    // Reported, not swallowed: the ledger is settled, but the row a relaunch
    // consults before the scope guard still says the job is live, so the next
    // `run --name X` will refuse with a message the ledger cannot explain.
    if (settled.cache == .refused) std.debug.print(
        "terminus: settled request {s} but its local row for job '{s}' is no longer the row we read; a same-name relaunch may still be refused until 'terminus job rm' clears it\n",
        .{ op.request_id, attempt.job_name },
    );

    if (ctx.out.format != .human) return;
    // What gets announced is what the ledger now holds, not what we set out to
    // write. A peer can settle the same attempt between our `attach` and our
    // `settleAttached`, in which case `already_settled` hands back *their*
    // terminal and our exit code was never applied — claiming otherwise would
    // print a settlement that did not happen.
    switch (settled.outcome) {
        .recorded => |record| std.debug.print(
            "note: settled request {s} (job '{s}') as {s} from its recorded exit status {d}; it had finished but nobody had looked\n",
            .{ op.request_id, attempt.job_name, record.status.text(), code },
        ),
        .already_settled => |record| std.debug.print(
            "note: blocking request {s} (job '{s}') was settled as {s} by another process while we were reading its log; the exit status {d} we found was not applied\n",
            .{ op.request_id, attempt.job_name, record.status.text(), code },
        ),
    }
}

/// The cache write that belongs with a proved settlement, or `.none`.
///
/// The ledger is the record, but it is not the only gate a relaunch has to
/// pass: `run` refuses a name whose `jobs` row still says `running`, and that
/// check happens before the scope guard. Settling the operation and leaving
/// the row saying "running" would move the wall one step back rather than
/// removing it — the caller would be told the job is still going by the very
/// command that had just read its exit status.
///
/// **Addressed by the settled attempt's own request id, never by its name.**
/// The name is an alias, and this function runs at the one moment it is most
/// likely to have moved on: a blocker worth settling is a launch that finished
/// or was displaced, and a displaced launch's name belongs to its successor.
/// Looking the row up by name and handing the result to `finishExpectation`
/// produced an expectation the successor's own row satisfies in every field —
/// `Owner.of` reads the owner off the row that was just read — so the CAS could
/// not refuse it. A live job's row was overwritten with a dead one's exit code
/// and its `finished_at`, `applied` came back, and nothing was printed.
///
/// `.none` for a blocker that has no row of its own to bring along: it never
/// reserved one (an exec, or an attempt in the local realm), somebody has
/// already forgotten it, or a later launch took the name and this attempt's row
/// went with it. None of those is a failure and none of them is a divergence —
/// there is no row describing this attempt, so there is nothing for a relaunch
/// to be misled by. What would be a divergence is writing to a row that
/// describes somebody else.
/// Public so the gate that pins the addressing rule can call it without an SSH
/// round trip; `arena` and `now` are taken directly rather than off a `Ctx` for
/// the same reason.
pub fn jobCacheSync(
    store: *Store,
    arena: std.mem.Allocator,
    settled_request_id: []const u8,
    code: i32,
    remote_finished_at: ?i64,
    now: i64,
) Core.execution.JobCacheSync {
    const row = (Store.jobs.byOwner(store, arena, settled_request_id) catch |err| {
        std.debug.print(
            "terminus: settling request {s} but could not read its local job row: {s}\n",
            .{ settled_request_id, @errorName(err) },
        );
        return .none;
    }) orelse return .none;
    if (!row.status.live()) return .none;
    return .{
        .finish = .{
            .expected = row.finishExpectation(),
            .status = .exited,
            .exit_code = code,
            // The remote's own clock when it reported one; otherwise the time we
            // looked. That column mixes the two by nature — the ledger is where
            // the distinction is kept.
            .at = remote_finished_at orelse now,
        },
    };
}

/// `<server>` or `<server>:<session>` — the target syntax shared by exec,
/// memory, read, write, and session commands.
pub const Target = struct {
    server: []const u8,
    session: ?[]const u8,

    pub fn parse(spec: []const u8) Target {
        const colon = std.mem.indexOfScalar(u8, spec, ':') orelse
            return .{ .server = spec, .session = null };
        if (colon == 0 or colon + 1 == spec.len)
            fail("malformed target '{s}'", .{spec});
        return .{ .server = spec[0..colon], .session = spec[colon + 1 ..] };
    }
};

/// Resolves a server row plus its auth material, ready for Ssh.connect.
/// Fatals with a user-oriented message on any misconfiguration.
pub fn resolveServer(ctx: *Ctx, store: *Store, name: []const u8) struct {
    server: Store.servers.Server,
    auth: Ssh.Auth,
} {
    const server = (Store.servers.getByName(store, ctx.arena, name) catch |err|
        storeFatal(store, err)) orelse fail("unknown server '{s}'", .{name});
    const key_name = server.key orelse
        fail("server '{s}' has no key configured; set one with 'terminus server add --key'", .{name});
    const material = (Store.keys.material(store, ctx.arena, key_name) catch |err|
        storeFatal(store, err)) orelse fail("key '{s}' disappeared from the store", .{key_name});
    const auth: Ssh.Auth = if (std.mem.eql(u8, material.kind, "password"))
        .{ .password = material.passphrase orelse fail("password key '{s}' has no passphrase", .{key_name}) }
    else
        .{ .key = .{
            .private = material.private orelse fail("key '{s}' has no private key bytes", .{key_name}),
            .public = material.public,
            .passphrase = material.passphrase,
        } };
    // Validate key format before any transport is attempted (keys stored
    // by pre-0.1.3 versions were never format-checked).
    if (auth == .key) {
        const format = Ssh.KeyFormat.detect(auth.key.private);
        if (!format.supported())
            fail("key '{s}' is in an unsupported format.\n{s}", .{ key_name, Ssh.KeyFormat.adviceFor(format) });
    }
    return .{ .server = server, .auth = auth };
}

/// What a connection this command could not open means to the caller.
pub const OnConnectFailure = enum {
    /// The command cannot do its job without the host: say why and exit.
    fatal,
    /// `fatal`, for a command that took a scope lease before it dialled: the
    /// refusal publishes what became of that lease instead of dropping it on
    /// stderr. See `failReportingClaim`.
    fatal_reporting_claim,
    /// The connection was worth trying but is not required: say why on stderr,
    /// return null, and let the caller carry on with what it already knows.
    report_and_continue,
};

/// `fail` or `failReportingClaim`, according to what the caller was holding.
///
/// A bool rather than the enum, so this is total: `report_and_continue` never
/// reaches here — those branches return null above — and a switch with an
/// `unreachable` arm for it would be a claim about control flow instead of a
/// function that cannot be called wrongly.
fn connectFatal(reporting_claim: bool, comptime fmt: []const u8, args: anytype) noreturn {
    if (reporting_claim) failReportingClaim(fmt, args);
    fail(fmt, args);
}

/// Connect + authenticate, with user-oriented fatal messages.
pub fn sshConnect(server: Store.servers.Server, auth: Ssh.Auth) Ssh {
    return sshOpen(server, auth, .fatal).?;
}

fn sshOpen(server: Store.servers.Server, auth: Ssh.Auth, on_failure: OnConnectFailure) ?Ssh {
    const reporting_claim = on_failure == .fatal_reporting_claim;
    var client = Ssh.connect(server.host, server.port) catch |err| switch (on_failure) {
        // Reported rather than swallowed, and reported as its own kind of
        // failure: "we never reached the host" and "the host turned us away"
        // send the caller to different places, and an optional probe that
        // returns a bare null tells them neither.
        .report_and_continue => {
            std.debug.print("terminus: could not reach {s}:{d} ({s}); continuing without it\n", .{
                server.host, server.port, @errorName(err),
            });
            return null;
        },
        .fatal, .fatal_reporting_claim => connectFatal(reporting_claim, "cannot connect to {s}:{d}: {s} ({s})", .{
            server.host, server.port, @errorName(err), Ssh.lastConnectError(),
        }),
    };
    client.authenticate(server.username, auth) catch |err| {
        if (on_failure == .report_and_continue) {
            // Worth saying loudly even though this call was optional: the
            // credentials for this server are broken, and every later command
            // against it will fail the same way.
            std.debug.print("terminus: authentication failed for {s}@{s} ({s}): {s}\n", .{
                server.username, server.host, @errorName(err), client.errorMessage(),
            });
            client.deinit();
            return null;
        }
        switch (err) {
            error.UnsupportedKeyFormat => {
                const format = Ssh.KeyFormat.detect(auth.key.private);
                connectFatal(reporting_claim, "the key for '{s}' is in an unsupported format.\n{s}", .{
                    server.name, Ssh.KeyFormat.adviceFor(format),
                });
            },
            else => connectFatal(reporting_claim, "authentication failed for {s}@{s}: {s}", .{
                server.username, server.host, client.errorMessage(),
            }),
        }
    };
    return client;
}

/// A remote command channel: through the daemon's pooled connection when
/// available, else a direct SSH connection owned by this process. Which
/// one — and why the daemon was skipped — is recorded for output.
pub const Connection = struct {
    inner: union(enum) {
        direct: Ssh,
        daemon: DaemonClient,
    },
    /// "daemon" | "direct" — reported in JSON output.
    transport: []const u8,
    /// Present when the daemon was tried but unusable.
    daemon_error: ?[]const u8 = null,

    pub fn executor(conn: *Connection) Executor {
        return switch (conn.inner) {
            .direct => |*client| .{ .direct = client },
            .daemon => |*client| .{ .daemon = client },
        };
    }

    pub fn deinit(conn: *Connection) void {
        switch (conn.inner) {
            .direct => |*client| client.deinit(),
            // Forgotten before it is closed: the exit hooks must not find a
            // handle this call has already given back to the OS.
            .daemon => |*client| {
                clearDaemonSocket(client.stream);
                client.deinit();
            },
        }
        conn.* = undefined;
    }
};

/// Daemon-first connect. `--no-daemon` or TERMINUS_NO_DAEMON=1 skips the
/// daemon; a daemon failure falls back to direct SSH but is never silent —
/// the failure reason is carried on the Connection and surfaced in output.
pub fn connect(
    ctx: *Ctx,
    parsed: *const Args.Parsed,
    server: Store.servers.Server,
    auth: Ssh.Auth,
) Connection {
    return openConnection(ctx, parsed, server, auth, .fatal).?;
}

/// `connect` for a caller that has something useful to say either way.
///
/// Used where a connection buys extra certainty rather than being the point
/// of the command: an opportunistic probe must not turn "the host is down"
/// into the command's answer, replacing the answer it already had.
pub fn tryConnect(
    ctx: *Ctx,
    parsed: *const Args.Parsed,
    server: Store.servers.Server,
    auth: Ssh.Auth,
) ?Connection {
    return openConnection(ctx, parsed, server, auth, .report_and_continue);
}

/// `connect` for a caller that took a scope lease before it dialled.
///
/// The three destructive verbs — `job kill`, `job rm`, `session rm` — all claim
/// the scope *before* the connection is opened, on purpose: a peer's live claim
/// then refuses them with nothing sent, not even a dial. The cost is that every
/// connect and auth failure from there on happens with a lease held, and those
/// were the paths that dropped the release answer. This is the same connect with
/// that answer published. See `failReportingClaim`.
pub fn connectReportingClaim(
    ctx: *Ctx,
    parsed: *const Args.Parsed,
    server: Store.servers.Server,
    auth: Ssh.Auth,
) Connection {
    return openConnection(ctx, parsed, server, auth, .fatal_reporting_claim).?;
}

/// Why the pooled daemon connection cannot carry this command, or null when it
/// can.
///
/// Not a fallback and not a failure: the daemon protocol carries a command and
/// an answer, and a command that streams local bytes into a remote process's
/// standard input needs a third channel it does not have. The operator asked for
/// the input, not for the transport, so the transport is the thing that gives
/// way — and which one carried it is reported either way, in `transport` and in
/// the note below.
fn daemonCannotCarry(parsed: *const Args.Parsed) ?[]const u8 {
    if (parsed.flag("stdin-file") != null)
        return "the daemon protocol has no channel for --stdin-file input; used direct SSH";
    return null;
}

fn openConnection(
    ctx: *Ctx,
    parsed: *const Args.Parsed,
    server: Store.servers.Server,
    auth: Ssh.Auth,
    on_failure: OnConnectFailure,
) ?Connection {
    const env_disabled = if (ctx.environ.get("TERMINUS_NO_DAEMON")) |v|
        !std.mem.eql(u8, v, "0")
    else
        false;
    const cannot_carry = daemonCannotCarry(parsed);
    if (!parsed.boolean("no-daemon") and !env_disabled and cannot_carry == null) {
        const request = daemonRequest(server, auth);
        switch (DaemonClient.acquire(ctx.io, ctx.arena, ctx.environ, request)) {
            .ok => |client| {
                registerDaemonSocket(ctx.io, client.stream);
                return .{ .inner = .{ .daemon = client }, .transport = "daemon" };
            },
            .unavailable => |reason| {
                // Fall back, loudly: human mode warns on stderr now; JSON
                // mode carries transport+daemonError in the response. Warned
                // on the optional path too, because the connection it returns
                // is not thrown away — the launch paths keep it and run the
                // whole command over it.
                if (ctx.out.format == .human)
                    std.debug.print("warning: daemon unavailable ({s}); using direct SSH\n", .{reason});
                return .{
                    .inner = .{ .direct = sshOpen(server, auth, on_failure) orelse return null },
                    .transport = "direct",
                    .daemon_error = reason,
                };
            },
        }
    }
    return .{
        .inner = .{ .direct = sshOpen(server, auth, on_failure) orelse return null },
        .transport = "direct",
        .daemon_error = cannot_carry,
    };
}

fn daemonRequest(server: Store.servers.Server, auth: Ssh.Auth) Core.daemon_protocol.Request {
    return .{
        .v = Core.daemon_protocol.version,
        .op = .exec,
        .host = server.host,
        .port = server.port,
        .username = server.username,
        .auth = switch (auth) {
            .password => |password| .{ .password = password },
            .key => |key| .{ .key = .{
                .private = key.private,
                .public = key.public,
                .passphrase = key.passphrase,
            } },
        },
    };
}

/// Opens (and migrates) the metadata database. Honors `--db <path>` (both
/// the global flag and per-command), defaulting to
/// %APPDATA%\terminus\terminus.db (or ~/.terminus/terminus.db).
///
/// Every refusal `migrate.checkBeforeApply` can return writes the `Refusal`
/// before returning, and each arm below reads the variant its own error names —
/// see there. Without the numbers these all collapsed into "cannot open
/// database at <path>", which was worst exactly where it mattered most: the
/// refusal that exists to stop N resumable transfers from being destroyed
/// arrived as an unexplained failure, standing next to the one other database
/// message this binary can produce, which tells the operator to delete the file.
pub fn openStore(ctx: *Ctx, parsed: *const Args.Parsed) !Store {
    const path = try dbPath(ctx, parsed.flag("db") orelse ctx.db_override);
    var found: Store.migrate.Refusal = undefined;
    return Store.openDiagnosed(path, &found) catch |err| switch (err) {
        // Only reachable on a machine that ran a pre-release build of the
        // 0.2.0 branch; say exactly that instead of leaking a SQL error.
        error.PreReleaseSchemaDrift => fail(
            "database at {s} was created by a pre-release build whose schema has since changed: {s} is not the shape this binary writes. Delete it (and its -wal/-shm files) or point --db elsewhere",
            .{ path, found.pre_release_drift.probe },
        ),
        error.SchemaNewerThanBinary => fail(
            "database at {s} is at schema version {d}; this binary understands up to {d}. Upgrade terminus, or point --db at a different file — running these statements against a schema they were not written for would write, not merely misread",
            .{ path, found.future_version.found, found.future_version.known },
        ),
        // The one refusal whose whole purpose is to protect data, so it must
        // not be the one that reads like an invitation to delete the file.
        error.CheckpointsWouldBeDropped => fail(
            "database at {s} is at schema version {d} and holds {d} resumable transfer checkpoint(s); the upgrade to version {d} recreates that table and would destroy them. Finish or abandon those transfers with the binary that wrote them, or move this file aside and let a new one be created — this command will not decide that for you",
            .{ path, found.checkpoints_would_be_dropped.version, found.checkpoints_would_be_dropped.rows, Store.schema_version },
        ),
        error.NotATerminusStore => fail(
            "the file at {s} is not a terminus database: {s}. Nothing was written to it; pass --db with a different path",
            .{ path, found.foreign_database.detail },
        ),
        // The other data-protecting refusal, and it protects a *claim* rather
        // than bytes: those leases are what stops two sessions changing the
        // same scope at once, and version {d} named their owner by machine
        // rather than by attempt. Nothing here can work out which attempt held
        // one, so it says so instead of voiding them.
        error.LiveLeasesCannotBeReowned => fail(
            "database at {s} is at schema version {d} and holds {d} lease(s) nobody has released; the upgrade to version {d} makes a lease belong to one attempt rather than to the whole machine, and a pre-{d} row names no attempt to carry over. Release them with the binary that took them, or move this file aside and let a new one be created — this command will not void somebody's live claim for you",
            .{
                path,
                found.live_leases_cannot_be_reowned.version,
                found.live_leases_cannot_be_reowned.rows,
                Store.schema_version,
                Store.schema_version,
            },
        ),
        error.WalSetupExhausted => fail(
            "database at {s} could not be switched to WAL mode; another terminus process may be starting at the same instant under heavy load — retry",
            .{path},
        ),
        else => fail("cannot open database at {s}", .{path}),
    };
}

fn dbPath(ctx: *Ctx, override: ?[]const u8) ![:0]u8 {
    if (override) |p| return ctx.arena.dupeZ(u8, p);
    const dir = if (ctx.environ.get("APPDATA")) |appdata|
        try std.fs.path.join(ctx.arena, &.{ appdata, "terminus" })
    else if (ctx.environ.get("HOME")) |home|
        try std.fs.path.join(ctx.arena, &.{ home, ".terminus" })
    else
        fail("neither APPDATA nor HOME is set; pass --db <path>", .{});
    std.Io.Dir.cwd().createDirPath(ctx.io, dir) catch |err|
        fail("cannot create {s}: {s}", .{ dir, @errorName(err) });
    const path = try std.fs.path.join(ctx.arena, &.{ dir, "terminus.db" });
    return ctx.arena.dupeZ(u8, path);
}

/// For unexpected sqlite failures: report the connection's message and exit.
pub fn storeFatal(store: *Store, err: anyerror) noreturn {
    fail("database error: {s} ({s})", .{ store.db.errorMessage(), @errorName(err) });
}

pub fn parseArgs(ctx: *Ctx, raw: []const []const u8) Args.Parsed {
    return Args.parse(ctx.arena, raw) catch |err| switch (err) {
        error.MissingFlagValue => fail("a flag is missing its value", .{}),
        error.UnknownFlagSyntax => fail("malformed flag", .{}),
        error.OutOfMemory => fail("out of memory", .{}),
    };
}

/// What the byte-exact command channels found in the text they read.
///
/// Published because 0.2.0 stopped rewriting it. `--stdin` and `--<file_flag>`
/// are the two channels that carry an editor's or a heredoc's line endings
/// verbatim, a remote POSIX shell reads a trailing `\r` as part of the token
/// (`true\r` is not `true`), and 0.1.10 answered that by normalizing CRLF to LF
/// by default. The half of that worth keeping was making the operator *aware* of
/// the `\r`; the dangerous half was silently rewriting bytes nobody asked it to
/// touch. So the carriage returns are counted and reported, and only
/// `--normalize-lf` rewrites them.
pub const LineEndings = struct {
    /// Carriage returns in the text as it was read, before any rewrite.
    carriage_returns: usize = 0,
    /// Whether `--normalize-lf` rewrote them.
    normalized: bool = false,
};

/// The reading from this command's `trailingContent` call.
///
/// Module-level rather than part of the return value because `trailingContent`
/// is called by three commands and its signature is what they compile against;
/// only one of them publishes a `--json` document with room for this. Same
/// shape, and same single-threaded-CLI justification, as `active_execution`.
var command_line_endings: LineEndings = .{};

pub fn commandLineEndings() LineEndings {
    return command_line_endings;
}

/// Trailing command/content with quote-proof input channels, in priority:
/// `--stdin` (read all of standard input — immune to any shell parsing),
/// `--<file_flag> <path>` (read a local file), then Args.trailing
/// (--cmd/--content, `--`, bare positionals).
///
/// Only fully-blank input collapses to null; interior newlines and
/// trailing structure are preserved (heredocs need their final newline).
///
/// **These are the bytes of the command, not the bytes the command reads.** A
/// process's standard input is a different channel with a different flag; see
/// `cmd_exec`'s `--stdin-file`, which is never normalized and never inspected
/// for carriage returns, because there they are data.
pub fn trailingContent(
    ctx: *Ctx,
    parsed: *const Args.Parsed,
    comptime file_flag: []const u8,
    expected_positionals: usize,
) !?[]const u8 {
    const normalize = parsed.boolean("normalize-lf");
    if (parsed.boolean("stdin")) {
        var buffer: [4096]u8 = undefined;
        var reader = std.Io.File.stdin().readerStreaming(ctx.io, &buffer);
        const content = reader.interface.allocRemaining(ctx.arena, .limited(16 << 20)) catch
            fail("cannot read stdin", .{});
        if (std.mem.trim(u8, content, " \t\r\n").len == 0) return null;
        return try reportLineEndings(ctx.arena, content, normalize, "standard input");
    }
    if (parsed.flag(file_flag)) |path| {
        const content = std.Io.Dir.cwd().readFileAlloc(ctx.io, path, ctx.arena, .limited(16 << 20)) catch
            fail("cannot read {s}", .{path});
        if (std.mem.trim(u8, content, " \t\r\n").len == 0) return null;
        return try reportLineEndings(ctx.arena, content, normalize, path);
    }
    return parsed.trailing(ctx.arena, expected_positionals);
}

/// Records what `content`'s line endings are, says so once on stderr when there
/// is something to say, and rewrites them only if asked.
pub fn reportLineEndings(
    arena: std.mem.Allocator,
    content: []const u8,
    normalize: bool,
    source: []const u8,
) ![]const u8 {
    const count = std.mem.count(u8, content, "\r");
    command_line_endings = .{ .carriage_returns = count, .normalized = normalize and count != 0 };
    if (count == 0) return content;
    if (!normalize) {
        // Said, not done. An operator who meant the `\r` keeps it; one who did
        // not now knows why `true\r` did not match `true`, which is the thing
        // the old silent rewrite was actually buying.
        std.debug.print(
            "terminus: the command read from {s} contains {d} carriage return(s) and was sent " ++
                "unchanged; a POSIX shell reads a trailing \\r as part of the token, so `true\\r` " ++
                "is not `true`. Pass --normalize-lf to convert CRLF/CR to LF.\n",
            .{ source, count },
        );
        return content;
    }
    std.debug.print(
        "terminus: --normalize-lf rewrote {d} carriage return(s) in the command read from {s} to LF\n",
        .{ count, source },
    );
    return stripCarriageReturns(arena, content);
}

/// Rewrites CRLF and lone CR into LF. Returns the input unchanged (no copy)
/// when it already contains no carriage returns — the common Unix case.
pub fn stripCarriageReturns(arena: std.mem.Allocator, content: []const u8) ![]const u8 {
    if (std.mem.indexOfScalar(u8, content, '\r') == null) return content;
    var out: std.ArrayList(u8) = .empty;
    try out.ensureTotalCapacity(arena, content.len);
    var i: usize = 0;
    while (i < content.len) : (i += 1) {
        if (content[i] == '\r') {
            // Collapse CRLF to LF; a lone CR also becomes LF (old-Mac endings).
            if (i + 1 < content.len and content[i + 1] == '\n') continue;
            out.appendAssumeCapacity('\n');
        } else {
            out.appendAssumeCapacity(content[i]);
        }
    }
    return out.items;
}

/// Wraps a command in an interactive login shell so it sees the user's
/// full PATH. Login alone (-l) is not enough: distros guard ~/.bashrc
/// with an interactive-only early return, and version managers (nvm,
/// bun) initialize exactly there — so -i is required too. The known
/// job-control warnings that -i emits without a tty are stripped from
/// stderr by `stripLoginNoise`.
pub fn loginWrap(arena: std.mem.Allocator, command: []const u8) ![]const u8 {
    return std.fmt.allocPrint(arena, "bash -ilc {s}", .{try Core.shell.quote(arena, command)});
}

/// Removes bash's tty-less interactive-mode warnings from stderr.
pub fn stripLoginNoise(arena: std.mem.Allocator, stderr: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var lines = std.mem.splitScalar(u8, stderr, '\n');
    while (lines.next()) |line| {
        if (std.mem.indexOf(u8, line, "no job control in this shell") != null) continue;
        if (std.mem.indexOf(u8, line, "cannot set terminal process group") != null) continue;
        if (std.mem.indexOf(u8, line, "Inappropriate ioctl for device") != null) continue;
        try out.appendSlice(arena, line);
        try out.append(arena, '\n');
    }
    const result = out.items;
    return std.mem.trimEnd(u8, result, "\n");
}

/// Scratch database under `.zig-cache`, the shape the store gates use.
const Scratch = struct {
    io: std.Io,
    threaded: *std.Io.Threaded,
    path: [:0]u8,
    allocator: std.mem.Allocator,

    const dir = ".zig-cache/tmp";

    fn init(allocator: std.mem.Allocator, name: []const u8) !Scratch {
        const threaded = try allocator.create(std.Io.Threaded);
        threaded.* = .init(allocator, .{});
        const io = threaded.io();
        std.Io.Dir.cwd().createDirPath(io, dir) catch {};
        const unique = try std.fmt.allocPrint(allocator, "{s}_{d}", .{ name, std.Thread.getCurrentId() });
        defer allocator.free(unique);
        const path = try std.fmt.allocPrintSentinel(allocator, "{s}/{s}.db", .{ dir, unique }, 0);
        var s: Scratch = .{ .io = io, .threaded = threaded, .path = path, .allocator = allocator };
        s.removeFiles();
        return s;
    }

    fn removeFiles(s: *Scratch) void {
        const cwd = std.Io.Dir.cwd();
        cwd.deleteFile(s.io, s.path) catch {};
        for ([_][]const u8{ "-wal", "-shm" }) |suffix| {
            const side = std.fmt.allocPrint(s.allocator, "{s}{s}", .{ s.path, suffix }) catch return;
            defer s.allocator.free(side);
            cwd.deleteFile(s.io, side) catch {};
        }
    }

    fn deinit(s: *Scratch) void {
        s.removeFiles();
        s.allocator.free(s.path);
        s.threaded.deinit();
        s.allocator.destroy(s.threaded);
    }
};

// The half of the defect a reader notices, pinned as a number rather than as a
// property: `job kill` and `job rm` recorded a scope lease held for *exactly
// zero seconds*, every time, because `registerClaim` froze `ctx.now` — the
// process's start time, which is also what `claimJobScope` stamped the
// acquisition with — and `releaseClaim` handed that same value back to
// `leases.release`. Unlike the reversal, that half needed no clock boundary to
// be crossed and no timing luck: `acquired_at` and `released_at` came from one
// variable, so they could not differ.
//
// Both ends have since moved onto live clocks and the claim carries no
// timestamp at all, so the acquisition below is written by hand: what this gate
// pins is the release's stamp, and it has to be able to state the
// acquisition it is measured against.
//
// The gate reconstructs the shape rather than describing it: a claim taken by a
// process that started a minute ago, renewed thirty seconds in off a fresh
// clock (what `holdClaim` does today), then released through the real
// `releaseClaimReporting` — the one route every process-ending path in this file
// now takes, `fail`, `failWithCode`, `failIndeterminate` and `receiptFatal`
// included, because `std.process.exit` skips defers.
test "gate: a released claim records the time the scope was actually held" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "cli_claim_holding_period");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    try store.db.exec(
        \\INSERT INTO servers (id, name, host, port, username, created_at, updated_at)
        \\VALUES (1, 'box', '10.0.0.1', 22, 'ubuntu', 100, 100)
    );

    // A process that started a minute ago. Backdated off the store's own clock
    // rather than off a literal, so the renewal below stays in the past: a
    // fixture dated in the *future* would be refused by the ordering guard, and
    // would be testing that instead.
    const start = (try Store.leases.clockSeconds(&store)) - 60;
    const owner: []const u8 = "01CLAIMHOLDER0123456789ABC";
    const scope: Core.execution.Scope = .{ .kind = .job, .key = "deploy" };

    switch (try Store.leases.acquire(&store, arena, .{
        .server_id = 1,
        .scope = scope,
        .owner_request_id = owner,
        .profile_token = "one-machine",
        .owner_label = "deploy",
        .ttl_secs = 120,
        .now = start,
    })) {
        .acquired => {},
        .renewed, .conflict => return error.ClaimDidNotTake,
    }
    registerClaim(&store, 1, scope, owner, "deploy");

    // `holdClaim`'s renewal, which already reads a fresh clock.
    try t.expect(try Store.leases.renew(&store, 1, scope, owner, 120, start + 30));

    _ = releaseClaimReporting();

    var stmt = try store.db.prepare(
        \\SELECT acquired_at, renewed_at, released_at, release_reason FROM leases
        \\ WHERE owner_request_id = ?1
    );
    defer stmt.deinit();
    try stmt.bindText(1, owner);
    try t.expect(try stmt.step());
    const acquired_at = stmt.columnInt(0);
    const renewed_at = stmt.columnInt(1);
    const released_at = stmt.columnOptInt(2) orelse return error.ClaimWasNotReleased;
    try t.expectEqualStrings("released", stmt.columnText(3));

    // The whole point: the row says the lease was held for the minute it was
    // held for. With the release stamped from the frozen `ctx.now` this is 0.
    try t.expect(released_at - acquired_at >= 60);
    // ...and the release is not recorded before the renewal that preceded it.
    // With the frozen stamp this one is negative by thirty seconds.
    try t.expect(released_at >= renewed_at);
}

// A release that could not happen used to be a line on stderr and a `void`
// return, so the caller went on to report success. That is the shape called
// a pretend-success: the command's own act may well have completed, but it left a
// lease holding a scope, and the next command on that scope is refused for the
// whole TTL while the JSON said `ok: true` with nothing in it about a lease.
//
// The failure is reconstructed rather than described, and the ordering violation
// is the one of the three that can be arranged deterministically: a row acquired
// with a stamp in the future cannot be released against the real clock without
// putting its own timestamps out of order, which `leases.release` refuses
// outright. What the gate asserts is both halves of the fix — the answer names
// the leak in a value a caller can branch on, and the row really is still held.
test "gate: a release that could not be recorded reports the lease as still held" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "cli_claim_release_failed");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    try store.db.exec(
        \\INSERT INTO servers (id, name, host, port, username, created_at, updated_at)
        \\VALUES (1, 'box', '10.0.0.1', 22, 'ubuntu', 100, 100)
    );

    const owner: []const u8 = "01CLAIMLEAKED0123456789ABC";
    const scope: Core.execution.Scope = .{ .kind = .job, .key = "deploy" };
    // An hour ahead of this machine's clock, so the release below cannot be
    // dated without contradicting the row.
    const ahead = (try Store.leases.clockSeconds(&store)) + 3600;
    switch (try Store.leases.acquire(&store, arena, .{
        .server_id = 1,
        .scope = scope,
        .owner_request_id = owner,
        .profile_token = "one-machine",
        .owner_label = "deploy",
        .ttl_secs = 120,
        .now = ahead,
    })) {
        .acquired => {},
        .renewed, .conflict => return error.ClaimDidNotTake,
    }
    registerClaim(&store, 1, scope, owner, "deploy");

    const outcome = releaseClaimReporting();
    try t.expectEqualStrings("left_held", outcome.code);
    try t.expect(outcome.holdsScope());
    // Prose, and present: a caller reporting the code alone would leave an
    // operator with a word and no way to know what to do about it.
    try t.expect(outcome.detail != null);

    // The half that makes it worth reporting: the scope is still claimed, so the
    // next command on it is refused until this row lapses.
    const held = try Store.leases.active(&store, arena, 1, ahead);
    try t.expectEqual(@as(usize, 1), held.len);
    try t.expectEqualStrings(owner, held[0].owner_request_id);

    // And the ordinary release still says so, on a row that can be dated. The
    // discriminating control: a `releaseClaimReporting` that answered
    // `left_held` unconditionally would satisfy everything above.
    const fine: []const u8 = "01CLAIMDATED00123456789ABC";
    const other: Core.execution.Scope = .{ .kind = .job, .key = "build" };
    const past = (try Store.leases.clockSeconds(&store)) - 60;
    switch (try Store.leases.acquire(&store, arena, .{
        .server_id = 1,
        .scope = other,
        .owner_request_id = fine,
        .profile_token = "one-machine",
        .owner_label = "build",
        .ttl_secs = 120,
        .now = past,
    })) {
        .acquired => {},
        .renewed, .conflict => return error.ClaimDidNotTake,
    }
    registerClaim(&store, 1, other, fine, "build");
    const gave_back = releaseClaimReporting();
    try t.expectEqualStrings("released", gave_back.code);
    try t.expect(!gave_back.holdsScope());
    try t.expectEqual(@as(?[]const u8, null), gave_back.detail);

    // Nothing registered: not the same answer as a release, and not an error.
    const nothing = releaseClaimReporting();
    try t.expectEqualStrings("not_taken", nothing.code);
}

// --- The refusal envelope carries the answer, so no call site has to -----------
//
// Seventeen call sites in `cmd_job.zig` end the process while a claim is held —
// `Cli.storeFatal` ×6, `fatalTmux` ×5, `fatalProbe` ×2 and the bare `fatal` ×3,
// spread across `killJob`, `removeJob`, `reportFinishedDuringKill` and the shared
// `settleObserved`. Every one of them reaches `fail`, and `fail` dropped the
// release answer, so each was a leaked lease under `{ok, error}` with the warning
// on stderr.
//
// They are not fixed one at a time. The two gates below are the two halves of
// fixing them all at once: the envelope publishes the answer whenever there is one,
// and the form that throws it away has exactly one caller left — the one that has
// already published.

/// An `Output` over a buffer, so a gate can read a document instead of an exit code.
///
/// The exit is what makes these paths untestable in-process; it is also the one
/// part no gate needs. `writeRefusal` is the whole document-writing half of `fail`,
/// `failWithCode` and `failReportingClaim`, split out for exactly this.
const Captured = struct {
    writer: std.Io.Writer,
    out: Output,
    ctx: Ctx,

    fn init(buffer: []u8) Captured {
        return .{ .writer = std.Io.Writer.fixed(buffer), .out = undefined, .ctx = undefined };
    }

    /// Wired after `init` because all three fields point at each other.
    fn ctxPtr(c: *Captured) *Ctx {
        c.out = .{ .writer = &c.writer, .format = .json };
        // Every other field is `undefined` on purpose: `writeRefusal` reads
        // `ctx.out` and nothing else, and a fixture that invented an `io` or an
        // `environ` would be claiming this path uses them.
        c.ctx = .{ .io = undefined, .arena = undefined, .environ = undefined, .out = &c.out, .now = 0 };
        return &c.ctx;
    }

    fn text(c: *Captured) []const u8 {
        return c.writer.buffered();
    }
};

// The rule the seventeen sites now inherit, and its control in the same fixture.
// Both directions matter: an envelope that published `not_taken` on every bad
// `--limit` is the noise `fail` is shared too widely to carry, and one that
// published nothing on a held lease is the defect.
test "gate: a refusal publishes the lease answer exactly when there was a lease" {
    const t = std.testing;
    const held = ClaimRelease.leftHeld("the store refused the release");
    const gave_back: ClaimRelease = .released;
    const none: ClaimRelease = .not_taken;

    {
        // A leaked lease, on the shared envelope every `storeFatal`, `fatalTmux`
        // and `fatalProbe` in a claim-holding body ends up in.
        var buffer: [4096]u8 = undefined;
        var captured: Captured = .init(&buffer);
        writeRefusal(captured.ctxPtr(), "database error: disk I/O error", null, held, false);
        try t.expect(std.mem.indexOf(u8, captured.text(), "\"leaseRelease\": \"left_held\"") != null);
        try t.expect(std.mem.indexOf(u8, captured.text(), "the store refused the release") != null);
    }
    {
        // The discriminating control: the same envelope with the lease handed
        // back says so, rather than saying nothing or saying `left_held`.
        var buffer: [4096]u8 = undefined;
        var captured: Captured = .init(&buffer);
        writeRefusal(captured.ctxPtr(), "database error: disk I/O error", null, gave_back, false);
        try t.expect(std.mem.indexOf(u8, captured.text(), "\"leaseRelease\": \"released\"") != null);
        try t.expect(std.mem.indexOf(u8, captured.text(), "\"leaseReleaseError\": null") != null);
    }
    {
        // …and the other control: a verb that never took a lease keeps the two-key
        // envelope it has always had. This is why `fail` may be the shared route.
        var buffer: [4096]u8 = undefined;
        var captured: Captured = .init(&buffer);
        writeRefusal(captured.ctxPtr(), "unknown server 'box'", null, none, false);
        try t.expect(std.mem.indexOf(u8, captured.text(), "leaseRelease") == null);
        try t.expect(std.mem.indexOf(u8, captured.text(), "\"ok\": false") != null);
    }
    {
        // `failWithCode`'s shape: the code comes before the lease keys, and the
        // lease keys still come and go with the lease.
        var buffer: [4096]u8 = undefined;
        var captured: Captured = .init(&buffer);
        writeRefusal(captured.ctxPtr(), "refused", "SCOPE_HELD_BY_PEER", held, false);
        const at_code = std.mem.indexOf(u8, captured.text(), "errorCode") orelse return error.CodeMissing;
        const at_lease = std.mem.indexOf(u8, captured.text(), "leaseRelease") orelse return error.LeaseMissing;
        try t.expect(at_code < at_lease);
    }
    {
        var buffer: [4096]u8 = undefined;
        var captured: Captured = .init(&buffer);
        writeRefusal(captured.ctxPtr(), "refused", "INVALID_PARAM", none, false);
        try t.expect(std.mem.indexOf(u8, captured.text(), "leaseRelease") == null);
        try t.expect(std.mem.indexOf(u8, captured.text(), "INVALID_PARAM") != null);
    }
    {
        // `failReportingClaim`'s: a documented four-key envelope, so the keys are
        // there even when the answer is that nothing was taken. A caller told to
        // read `leaseRelease` must find it.
        var buffer: [4096]u8 = undefined;
        var captured: Captured = .init(&buffer);
        writeRefusal(captured.ctxPtr(), "cannot connect to 10.0.0.1:22", null, none, true);
        try t.expect(std.mem.indexOf(u8, captured.text(), "\"leaseRelease\": \"not_taken\"") != null);
    }
}

// The other half, and the one that answers "what stops the eighteenth site".
//
// Nothing in Zig's type system can stop a function from calling a `void` one: there
// is no effect on a signature to check, and a local shadow of a container-level
// declaration is itself a compile error, so the void form cannot be made
// unnameable from inside a claim-holding body. What *can* be made structural is the
// other end. `releaseClaim()` is the only way to throw the answer away, and every
// path in this file that writes a document now releases through
// `releaseClaimReporting` instead — so the void form's caller list is the whole
// audit, and this pins it at one.
//
// `failIndeterminateAfterOutput` is that one, and it is correct there: it runs after
// the caller has written its own document, including its own `leaseRelease` from its
// own `releaseClaimReporting`, so no claim is registered by the time it releases and
// the answer it discards is `not_taken`. A new caller here is a new dropped answer,
// and it fails this gate rather than shipping.
test "gate: the answer-dropping release has one caller, and it has already published" {
    const t = std.testing;
    const source = @embedFile("cli.zig");
    // Assembled rather than written out, so this gate's own text is not one of the
    // call sites it counts. The doc comments that mention the function by name are
    // excluded for free: they carry no semicolon.
    const void_release = "release" ++ "Claim();";

    var found: usize = 0;
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, source, i, void_release)) |at| : (i = at + 1) found += 1;
    if (found != 1) {
        std.debug.print(
            \\
            \\cli.zig calls the void `releaseClaim()` at {d} sites. It may have exactly one,
            \\in `failIndeterminateAfterOutput`, which runs after its caller has already
            \\published its own `leaseRelease`. Every other process-ending path here writes a
            \\document, and a document is somewhere the answer can go: release through
            \\`releaseClaimReporting()` and put its `code` and `detail` in the envelope, the
            \\way `fail`, `failWithCode`, `failIndeterminate` and `receiptFatal` do. A leaked
            \\lease goes on refusing the next command on that scope for its whole TTL.
            \\
        , .{found});
        return error.AnswerDroppedOnADocumentPath;
    }

    const body = try Control.bodyOf(source, "\npub fn failIndeterminateAfterOutput(");
    if (std.mem.indexOf(u8, body, void_release) == null) {
        std.debug.print(
            \\
            \\the one void `releaseClaim()` in cli.zig has moved out of
            \\`failIndeterminateAfterOutput`. That is the only body it can be correct in —
            \\everywhere else there is a document waiting for the answer.
            \\
        , .{});
        return error.AnswerDroppedOnADocumentPath;
    }
    // A body that stopped releasing at all would satisfy the count above by
    // deleting the site rather than by publishing: the claim would then survive
    // the process and lapse at its TTL with nothing said about it anywhere.
    try t.expect(std.mem.indexOf(u8, body, "clearExecution()") != null);
}

test {
    std.testing.refAllDecls(@This());
}
