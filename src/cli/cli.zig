//! CLI namespace: shared context plus per-command modules.
const std = @import("std");

pub const Output = @import("output.zig");
pub const Dispatch = @import("dispatch.zig");
pub const Args = @import("args.zig");
pub const Setup = @import("cmd_setup.zig");

const Core = @import("../core/core.zig");
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

/// Fail-loud exit: in JSON mode emits `{"ok":false,"error":...}` on stdout
/// (agents parse one stream); in human mode writes stderr. Always exit 1.
pub fn fail(comptime fmt: []const u8, args: anytype) noreturn {
    settleActiveExecution("command failed before recording an outcome");
    releaseReservation();
    if (active_ctx) |ctx| {
        if (ctx.out.format == .json) {
            const message = std.fmt.allocPrint(ctx.arena, fmt, args) catch fmt;
            ctx.out.json(.{ .ok = false, .@"error" = message }) catch {};
            ctx.out.flush() catch {};
            std.process.exit(1);
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
    settleActiveExecution("command failed before recording an outcome");
    releaseReservation();
    if (active_ctx) |ctx| {
        if (ctx.out.format == .json) {
            const message = std.fmt.allocPrint(ctx.arena, fmt, args) catch fmt;
            ctx.out.json(.{ .ok = false, .@"error" = message, .errorCode = code }) catch {};
            ctx.out.flush() catch {};
            std.process.exit(1);
        }
    }
    std.process.fatal(fmt ++ "\n  code: {s}", args ++ .{code});
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
pub fn failIndeterminate(request_id: []const u8, reason: []const u8, last_observed: []const u8) noreturn {
    if (active_ctx) |ctx| {
        if (ctx.out.format == .json) {
            ctx.out.json(.{
                .ok = false,
                .status = "indeterminate",
                .@"error" = reason,
                .errorCode = "INDETERMINATE",
                .requestId = request_id,
                .lastObserved = last_observed,
                .hint = "the remote outcome is unknown; reconcile with 'terminus request reconcile <request-id>' before retrying",
            }) catch {};
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

/// Ends a command whose response has already been written.
///
/// The caller has printed a full result carrying `status: "indeterminate"`;
/// all that remains is the exit code, which must not be 1 — an agent has to
/// be able to tell "it did not work" from "we do not know", because only the
/// first is safe to retry.
pub fn failIndeterminateAfterOutput(request_id: []const u8) noreturn {
    clearExecution(); // already settled by the execution itself
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

/// A write to the operation ledger failed.
///
/// This must never be swallowed the way `history.add(...) catch {}` was: if
/// we cannot record what we did, we do not get to claim we did it cleanly.
/// The remote effect is reported as far as we know it, alongside an explicit
/// signal that the audit trail is incomplete.
pub fn receiptFatal(
    request_id: []const u8,
    err: anyerror,
    known_remote_status: ?[]const u8,
) noreturn {
    if (active_ctx) |ctx| {
        if (ctx.out.format == .json) {
            ctx.out.json(.{
                .ok = false,
                .@"error" = "could not persist the operation receipt",
                .errorCode = "RECEIPT_PERSIST_FAILED",
                .requestId = request_id,
                .cause = @errorName(err),
                .remoteStatus = known_remote_status,
                .hint = "the remote action may have taken effect; the local ledger is incomplete",
            }) catch {};
            ctx.out.flush() catch {};
            std.process.exit(exit_code.receipt_persist_failed);
        }
        ctx.out.print(
            "RECEIPT_PERSIST_FAILED: {s}\n  request: {s}\n  remote status: {s}\n  the remote action may have taken effect; the local ledger is incomplete\n",
            .{ @errorName(err), request_id, known_remote_status orelse "unknown" },
        ) catch {};
        ctx.out.flush() catch {};
    }
    std.process.exit(exit_code.receipt_persist_failed);
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
        .owner_token = "somebody-else",
        .owner_label = null,
        .note = null,
        .request_id = null,
        .acquired_at = 1750000000,
        .renewed_at = 1750000000,
        .expires_at = 1750003600,
    };
    try t.expect(!blockerMayBeProvable(.{ .lease = lease }));
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
    const code = probe.exit_code orelse return;

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
    const settled = execution.settleAttachedAndSyncJob(.{ .exited = .{ .exit_code = code } }, .{
        .stdout = .{ .bytes = @intCast(probe.output.len) },
        .source = .reconcile,
    }, sync) catch |err| {
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
    /// The connection was worth trying but is not required: say why on stderr,
    /// return null, and let the caller carry on with what it already knows.
    report_and_continue,
};

/// Connect + authenticate, with user-oriented fatal messages.
pub fn sshConnect(server: Store.servers.Server, auth: Ssh.Auth) Ssh {
    return sshOpen(server, auth, .fatal).?;
}

fn sshOpen(server: Store.servers.Server, auth: Ssh.Auth, on_failure: OnConnectFailure) ?Ssh {
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
        .fatal => fail("cannot connect to {s}:{d}: {s} ({s})", .{
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
                fail("the key for '{s}' is in an unsupported format.\n{s}", .{
                    server.name, Ssh.KeyFormat.adviceFor(format),
                });
            },
            else => fail("authentication failed for {s}@{s}: {s}", .{
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
            .daemon => |*client| client.deinit(),
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
    if (!parsed.boolean("no-daemon") and !env_disabled) {
        const request = daemonRequest(server, auth);
        switch (DaemonClient.acquire(ctx.io, ctx.arena, ctx.environ, request)) {
            .ok => |client| return .{ .inner = .{ .daemon = client }, .transport = "daemon" },
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

/// Trailing command/content with quote-proof input channels, in priority:
/// `--stdin` (read all of standard input — immune to any shell parsing),
/// `--<file_flag> <path>` (read a local file), then Args.trailing
/// (--cmd/--content, `--`, bare positionals).
///
/// Only fully-blank input collapses to null; interior newlines and
/// trailing structure are preserved (heredocs need their final newline).
pub fn trailingContent(
    ctx: *Ctx,
    parsed: *const Args.Parsed,
    comptime file_flag: []const u8,
    expected_positionals: usize,
) !?[]const u8 {
    // stdin and file channels are byte-exact, so on Windows they carry the
    // CRLF line endings of the local editor/heredoc. A remote POSIX shell
    // treats a trailing `\r` as part of the token (`true\r` is not `true`),
    // which is the single most common Windows footgun. Normalize CRLF -> LF
    // by default; --raw preserves the bytes for the rare binary-in-script case.
    const keep_raw = parsed.boolean("raw");
    if (parsed.boolean("stdin")) {
        var buffer: [4096]u8 = undefined;
        var reader = std.Io.File.stdin().readerStreaming(ctx.io, &buffer);
        const content = reader.interface.allocRemaining(ctx.arena, .limited(16 << 20)) catch
            fail("cannot read stdin", .{});
        if (std.mem.trim(u8, content, " \t\r\n").len == 0) return null;
        return if (keep_raw) content else try stripCarriageReturns(ctx.arena, content);
    }
    if (parsed.flag(file_flag)) |path| {
        const content = std.Io.Dir.cwd().readFileAlloc(ctx.io, path, ctx.arena, .limited(16 << 20)) catch
            fail("cannot read {s}", .{path});
        if (std.mem.trim(u8, content, " \t\r\n").len == 0) return null;
        return if (keep_raw) content else try stripCarriageReturns(ctx.arena, content);
    }
    return parsed.trailing(ctx.arena, expected_positionals);
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
    return std.fmt.allocPrint(arena, "bash -ilc {s}", .{try Core.Tmux.shellQuote(arena, command)});
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

test {
    std.testing.refAllDecls(@This());
}
