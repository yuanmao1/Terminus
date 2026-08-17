//! `terminus session new/ls/rm` — remote tmux session lifecycle.
//!
//! `ls` reports live remote tmux state (source of truth) merged with the
//! local metadata rows (cursor, notes, memory counts).
//!
//! `rm` is the destructive one, and until now it was the only destructive
//! remote verb in the tree with **no authority of any kind**: no lease, no
//! operation row, no scope guard (`docs/m3b-job-control.md` §1.2). It killed a
//! remote session, deleted its pane log and dropped the local row — whose
//! delete cascades that session's memories — while contending with nothing and
//! recording nothing. Because a job's tmux session is `job-<name>` and
//! `session ls` shows it under that name, `session rm web job-deploy` would
//! stop a running job's shell with `job kill web deploy` holding a lease it
//! could not see.
//!
//! It now runs under a `control` operation and a scope lease, and renews that
//! lease immediately before every step that changes the host. What it already
//! got right is unchanged and is called out where it happens: the kill is
//! *proven* before anything is deleted, and the log is deleted only after that
//! proof.
const std = @import("std");
const fatal = Cli.fail;
const Cli = @import("cli.zig");
const Core = @import("../core/core.zig");
const Store = Core.Store;
const Tmux = Core.Tmux;
const fatalTmux = @import("cmd_exec.zig").fatalTmux;

const usage =
    \\usage: terminus session <verb> [...]
    \\
    \\  session new <server> <name>       create (or reattach) a remote tmux session
    \\  session ls  <server> [--json]     list live remote sessions
    \\  session rm  <server> <name>       kill remote session + local metadata/memories
    \\
;

pub fn run(ctx: *Cli.Ctx, raw_args: []const []const u8) !void {
    if (raw_args.len == 0) fatal("{s}", .{usage});
    const verb = raw_args[0];
    const parsed = Cli.parseArgs(ctx, raw_args[1..]);
    if (parsed.boolean("json")) ctx.out.format = .json;

    const server_name = parsed.positional(0) orelse fatal("{s}", .{usage});
    var store = try Cli.openStore(ctx, &parsed);
    defer store.close();
    const resolved = Cli.resolveServer(ctx, &store, server_name);

    // The connection is opened per verb rather than once up front, and that is
    // not tidying: `rm` has to be refusable *before* it dials, because the whole
    // point of a barrier it consults after opening a socket is that it no longer
    // proves "nothing was sent".
    if (std.mem.eql(u8, verb, "new")) {
        try newSession(ctx, &store, &parsed, resolved.server, resolved.auth, server_name);
    } else if (std.mem.eql(u8, verb, "ls")) {
        try listSessions(ctx, &store, &parsed, resolved.server, resolved.auth, server_name);
    } else if (std.mem.eql(u8, verb, "rm")) {
        try removeSession(ctx, &store, &parsed, resolved.server, resolved.auth, server_name);
    } else {
        fatal("unknown verb 'session {s}'\n{s}", .{ verb, usage });
    }
}

fn newSession(
    ctx: *Cli.Ctx,
    store: *Store,
    parsed: *const Cli.Args.Parsed,
    server: Store.servers.Server,
    auth: Core.Ssh.Auth,
    server_name: []const u8,
) !void {
    const name = parsed.positional(1) orelse fatal("{s}", .{usage});
    validateName(name);

    var conn = Cli.connect(ctx, parsed, server, auth);
    defer conn.deinit();
    const executor = conn.executor();

    Tmux.ensure(executor, ctx.arena, name) catch |err| fatalTmux(err, executor, name);
    _ = Store.sessions.ensure(store, server.id, name, ctx.now) catch |err|
        Cli.storeFatal(store, err);
    // Surface existing server-scope memories so an agent knows to read
    // them before starting work.
    const mems = Store.memories.list(store, ctx.arena, .{ .server_id = server.id }, .{}) catch |err|
        Cli.storeFatal(store, err);
    switch (ctx.out.format) {
        .json => try ctx.out.json(.{
            .ok = true,
            .action = "created",
            .session = name,
            .server = server_name,
            .serverMemories = mems.len,
        }),
        .human => {
            try ctx.out.print("session '{s}:{s}' is ready\n", .{ server_name, name });
            if (mems.len > 0)
                try ctx.out.print("hint: {d} server memories exist; read them with 'terminus memory ls {s}:{s}'\n", .{ mems.len, server_name, name });
        },
    }
}

fn listSessions(
    ctx: *Cli.Ctx,
    store: *Store,
    parsed: *const Cli.Args.Parsed,
    server: Store.servers.Server,
    auth: Core.Ssh.Auth,
    server_name: []const u8,
) !void {
    var conn = Cli.connect(ctx, parsed, server, auth);
    defer conn.deinit();
    const executor = conn.executor();

    const remote = Tmux.list(executor, ctx.arena) catch |err| fatalTmux(err, executor, "");
    const local = Store.sessions.list(store, ctx.arena, server.id) catch |err|
        Cli.storeFatal(store, err);
    const merged = try merge(ctx.arena, remote, local);
    switch (ctx.out.format) {
        .json => try ctx.out.json(.{ .ok = true, .server = server_name, .sessions = merged }),
        .human => {
            if (merged.len == 0) return ctx.out.print("no sessions on '{s}'\n", .{server_name});
            for (merged) |s| {
                try ctx.out.print("{s}:{s}  alive={s}  cursor={d}\n", .{
                    server_name, s.name, if (s.alive) "yes" else "no", s.cursor,
                });
            }
        },
    }
}

/// One reader for every branch of `session rm --json`.
///
/// Every key is present on every path, including the refusals. A caller gets
/// one parser rather than three, and — the part that matters — `action` alone
/// never says what survived: `sessionGone`, `logDeleted` and `localRow` each
/// report what actually happened to one thing, because a refusal that came
/// after the kill destroyed strictly more than one that came before it.
const RemovalJson = struct {
    ok: bool,
    /// `removed` | `not_removed`.
    action: []const u8,
    session: []const u8,
    server: []const u8,
    /// The control operation's own id. Everything this command did is on its
    /// trail, and this is how to ask for it.
    requestId: []const u8,
    /// What the ledger holds for that operation now.
    status: []const u8,
    sessionGone: bool,
    logDeleted: bool,
    /// `removed` | `absent` | `kept`.
    ///
    /// Three words rather than a bool, because `sessions.remove` answering
    /// false is not a refusal — see the call site.
    localRow: []const u8,
    /// `held` | `lapsed` | `unreadable`. Branch on this, never on the prose.
    authority: []const u8,
    authorityError: ?[]const u8,
    hint: ?[]const u8 = null,
};

fn removeSession(
    ctx: *Cli.Ctx,
    store: *Store,
    parsed: *const Cli.Args.Parsed,
    server: Store.servers.Server,
    auth: Core.Ssh.Auth,
    server_name: []const u8,
) !void {
    const name = parsed.positional(1) orelse fatal("{s}", .{usage});
    validateName(name);

    const owner_token = Store.policy.ownerToken(store, ctx.arena, ctx.io, ctx.now) catch |err|
        Cli.storeFatal(store, err);

    // The ledger entry this verb never had. `control` is the kind for a
    // supervisory act on somebody else's session (§3.1); the target it acted on
    // travels in `alias`, which is already where a session name goes
    // (`cmd_exec.zig`'s `.alias = target.session`). The dedicated `target_*`
    // columns of §7.2 are v13 and are not this slice.
    //
    // `mutating` is left at its default `true` and it is worth saying why out
    // loud: this is the most destructive verb in the tree. It stops a shell,
    // deletes a log and cascades away a session's memories.
    const start = Core.execution.begin(store, ctx.arena, ctx.io, .{
        .server_id = server.id,
        .server_name = server.name,
        .kind = .control,
        .scope = contentionScope(name),
        .alias = name,
        .owner_token = owner_token,
        .now = ctx.now,
    }) catch |err| Cli.storeFatal(store, err);

    // Refused here means refused before the connection is opened: no socket, no
    // tmux command, nothing on the host to undo. This is the arm that closes
    // §1.2 — a running job holds an unsettled writer on the scope its session
    // belongs to, and it is now something `session rm` can see.
    var execution = switch (start) {
        .ready => |e| e,
        .blocked => |blocker| reportBlocked(blocker, server_name, name),
    };
    Cli.registerExecution(&execution);
    defer {
        Cli.clearExecution();
        execution.deinit();
    }

    // The lease, owned by this command's own control operation. One identity
    // rather than two: `blockerLocked` exempts a lease whose owner is the
    // request id it was handed, so our own claim cannot refuse us, and a peer
    // arriving later sees a row that names the operation that took it.
    const claim = claimScope(ctx, store, server.id, name, execution.id(), owner_token);
    var authority: Authority = .held;

    execution.connecting() catch |err| Cli.receiptFatal(execution.id(), err, "created");

    var conn = Cli.connect(ctx, parsed, server, auth);
    defer conn.deinit();
    const executor = conn.executor();

    // The first renewal, and the only one that can still answer "nothing was
    // sent" in the ledger's own words. It sits *before* `submitted` on purpose:
    // a loss caught here leaves the attempt at `connecting`, where
    // `never_submitted` — "the command the caller asked for did not run" — is
    // admissible, and that is exactly what a withheld kill is. After
    // `submitted`, `op_state.canSettle` no longer admits it and the same loss
    // could only be recorded as `indeterminate`, which overstates a kill that
    // never left this machine.
    if (!stillOurs(claim, ctx.io, &authority)) refuseBeforeKill(ctx, &execution, server_name, name, authority);

    // The scope guard binds here rather than at `begin`, for the reason
    // `Execution.submitted` gives: the check and the write that makes this
    // attempt visible to the next caller have to be one transaction.
    switch (execution.submitted() catch |err| Cli.receiptFatal(execution.id(), err, "about to submit")) {
        .submitted => {},
        .refused => |blocker| {
            execution.abandon(
                "another command claimed an overlapping scope between this one dialing and the kill; nothing was sent to the host",
            ) catch |err| Cli.receiptFatal(execution.id(), err, execution.status.text());
            reportBlocked(blocker, server_name, name);
        },
    }

    // The kill has to be *proven* before anything else happens, and that rule
    // predates this change: deleting the local row for a session that is still
    // on the host leaves it orphaned — invisible to `session ls`'s local half,
    // and `ensure` treats an existing session as ready, so the next command
    // under this name would land in the shell we just claimed to have removed.
    //
    // The renewal the kill runs under, with nothing between it and the command
    // it gates — no store transaction, no probe, no second round trip. The one
    // above is on the far side of `submitted`'s transaction and answers about a
    // moment that has passed; a peer taking the lease inside it would leave this
    // command sending `kill-session` *by name* at a session the new holder may
    // already own. That window is narrowed, not closed: the host still acts some
    // interval after the renewal answered, and only a session identity the host
    // itself can check would close it (§2.4).
    if (!stillOurs(claim, ctx.io, &authority)) refuseBeforeKill(ctx, &execution, server_name, name, authority);
    const gone = Tmux.killSession(executor, ctx.arena, name) catch |err| fatalTmux(err, executor, name);
    if (!gone) refuseSurvivedKill(ctx, &execution, server_name, name, authority);
    // When the host answered, so the receipt's `absence_verified_at` is the
    // moment of the reading rather than this process's start time.
    const verified_at = wallClockSeconds(ctx.io);

    // The kill cannot be taken back; every step after it can still be declined,
    // so the scope is asked for again. A loss here keeps the log *and* the local
    // row, and the receipt records that this command established nothing.
    if (!stillOurs(claim, ctx.io, &authority)) refuseAfterKill(ctx, &execution, server_name, name, authority, false);
    // Only now: a live pane recreates its log through `pipe-pane`, so a log
    // deleted under a surviving session quietly comes back holding a partial
    // history that starts mid-stream. `gone` above is what licenses this line,
    // which is why the proof comes first and the deletion second.
    Tmux.removeLog(executor, ctx.arena, name) catch |err| {
        // The session's absence was established before this line and does not
        // become unknown because a later deletion failed, so the receipt keeps
        // it rather than being abandoned into `indeterminate` on the way out.
        // What is not claimed is a clean removal: the log is still on the host,
        // the local row is kept, and the exit says so.
        _ = execution.settle(provenCancellation(ctx, name, verified_at), .{}) catch |e|
            Cli.receiptFatal(execution.id(), e, execution.status.text());
        fatal(
            "session '{s}:{s}' was stopped but its log could not be deleted: {s} ({s}); the local record is kept",
            .{ server_name, name, executor.errorMessage(), @errorName(err) },
        );
    };

    // The last renewal, and the last chance to notice a loss that happened
    // during the log deletion's round trip. The local row is the one thing still
    // in front of us, and deleting it cascades this session's memories
    // (`sessions.remove`), so it is refusable too.
    if (!stillOurs(claim, ctx.io, &authority)) refuseAfterKill(ctx, &execution, server_name, name, authority, true);

    _ = execution.settle(provenCancellation(ctx, name, verified_at), .{}) catch |err|
        Cli.receiptFatal(execution.id(), err, execution.status.text());

    // The bool is no longer discarded, and this is the one place in the CLI
    // where discarding it was not a swallowed refusal. `sessions.remove` has no
    // owner, no expectation and no compare-and-swap: false means only that this
    // machine had no metadata row for the session, which `merge` below documents
    // as an ordinary state — a session started outside Terminus is alive
    // remotely with nothing local naming it. It is now *reported* rather than
    // merely justified (§2.2), because "there was no row" and "the row is gone"
    // are different facts about this machine and only one of them means a
    // cascade happened.
    const had_row = Store.sessions.remove(store, server.id, name) catch |err|
        Cli.storeFatal(store, err);
    Cli.releaseClaim();

    switch (ctx.out.format) {
        .json => try ctx.out.json(RemovalJson{
            .ok = true,
            .action = "removed",
            .session = name,
            .server = server_name,
            .requestId = execution.id(),
            .status = execution.status.text(),
            .sessionGone = true,
            .logDeleted = true,
            .localRow = if (had_row) "removed" else "absent",
            .authority = authority.code(),
            .authorityError = authority.note(ctx, name),
        }),
        .human => try ctx.out.print("removed session '{s}:{s}'\n", .{ server_name, name }),
    }
}

/// The terminal a proven session removal settles, in one place because two
/// sites write it and they must not disagree about what was established.
///
/// `remote_cancel_confirmed`, and the payload is where the honesty lives.
///
/// `pid = null`: no process was identified and none could be. This operation
/// names a *session*; the process in that pane belongs to whoever started it,
/// and recording its pid would be a reading about one thing offered as a verdict
/// on another — the mistake `receipts.appliesToKind` closed its `process_probe ×
/// job` cell over.
///
/// `term_sent = true, kill_sent = false`: `tmux kill-session` hangs the pane up
/// on our behalf, and nothing here sends SIGKILL to anything. Written as what
/// happened rather than as two convenient trues.
///
/// `verification_method` names both tmux commands, so a reader sees the
/// granularity of the proof beside the verdict. What was verified is that the
/// *session* is gone — this operation's whole subject — and not that anything it
/// had forked has stopped. A command that daemonized, called `disown` or ran
/// under `setsid` outlives the shell, and nothing on this receipt claims
/// otherwise.
fn provenCancellation(
    ctx: *Cli.Ctx,
    session: []const u8,
    verified_at: i64,
) Core.Store.op_state.Terminal {
    const target = Tmux.targetName(ctx.arena, session) catch
        fatal("out of memory recording the removal of session '{s}'", .{session});
    return .{ .remote_cancel_confirmed = .{
        .pid = null,
        .term_sent = true,
        .kill_sent = false,
        .absence_verified_at = verified_at,
        .verification_method = std.fmt.allocPrint(
            ctx.arena,
            "tmux kill-session -t ={s} then has-session reported the session absent",
            .{target},
        ) catch "tmux kill-session then has-session reported the session absent",
    } };
}

/// The kill went out and the host says the session is still there.
///
/// Nothing is deleted — not the log, not the local row — and that rule predates
/// every part of this change: the local row for a session still on the host
/// would orphan it, and `Tmux.ensure` treats an existing session as ready, so
/// the next command under this name would land in the shell we just claimed to
/// have removed.
///
/// Settled `indeterminate`, and the word is earned rather than convenient. The
/// reading establishes that a session by this name exists *now*; it does not
/// establish what `kill-session` did. Something recreated it, or tmux did not do
/// what it was asked, and this command cannot tell those apart. What it
/// definitely may not claim is `remote_cancel_confirmed`, whose whole content is
/// a verified absence.
///
/// The consequence is stated in the hint rather than hidden: `indeterminate`
/// blocks the scope, so the next removal of this session is refused until
/// somebody reconciles the record. That is why this exits 75 and not 1 — telling
/// an agent "plain failure, retry" would send it into a refusal it cannot read.
fn refuseSurvivedKill(
    ctx: *Cli.Ctx,
    execution: *Core.execution.Execution,
    server_name: []const u8,
    session: []const u8,
    authority: Authority,
) noreturn {
    const target = Tmux.targetName(ctx.arena, session) catch
        fatal("out of memory reporting that session '{s}' survived the kill", .{session});
    const reason = std.fmt.allocPrint(
        ctx.arena,
        "the kill was sent for session '{s}' and the host still reports it present, so what that kill achieved cannot be established; nothing was deleted — not the pane log, not the local row",
        .{session},
    ) catch "the kill was sent and the host still reports the session present; nothing was deleted";
    _ = execution.settle(.{ .indeterminate = .{
        .reason = reason,
        .last_observed = execution.status,
        .error_code = "SESSION_SURVIVED_KILL",
    } }, .{}) catch |err| Cli.receiptFatal(execution.id(), err, execution.status.text());
    report(ctx, .{
        .ok = false,
        .action = "not_removed",
        .session = session,
        .server = server_name,
        .requestId = execution.id(),
        .status = execution.status.text(),
        .sessionGone = false,
        .logDeleted = false,
        .localRow = "kept",
        .authority = authority.code(),
        .authorityError = authority.note(ctx, session),
        .hint = std.fmt.allocPrint(
            ctx.arena,
            "inspect it with 'tmux attach -t {s}' on the host, then settle the record with 'terminus request reconcile <request-id>' — until it is settled this session's scope stays barred",
            .{target},
        ) catch "inspect the session on the host, then settle the record with 'terminus request reconcile <request-id>'",
    }, reason);
    Cli.failIndeterminateAfterOutput(execution.id());
}

/// Refused before anything reached the host.
///
/// Settled through `Execution.abandon`, which routes to the one function allowed
/// to classify a give-up (`op_state.terminalForTransportLoss`): from
/// `connecting` that is `never_submitted`, whose whole claim is that the command
/// the caller asked for did not run. That is precisely a withheld kill, it
/// settles `failed`, and it is what §3.4 says a control operation that lost its
/// lease before sending anything records.
fn refuseBeforeKill(
    ctx: *Cli.Ctx,
    execution: *Core.execution.Execution,
    server_name: []const u8,
    session: []const u8,
    authority: Authority,
) noreturn {
    const reason = std.fmt.allocPrint(
        ctx.arena,
        "this command's scope lease for session '{s}' is no longer held ({s}), so the kill was never sent; nothing on the host and nothing in the local record was touched",
        .{ session, authority.code() },
    ) catch "the scope lease was lost before the kill was sent; nothing was touched";
    execution.abandon(reason) catch |err|
        Cli.receiptFatal(execution.id(), err, execution.status.text());
    report(ctx, .{
        .ok = false,
        .action = "not_removed",
        .session = session,
        .server = server_name,
        .requestId = execution.id(),
        .status = execution.status.text(),
        .sessionGone = false,
        .logDeleted = false,
        .localRow = "kept",
        .authority = authority.code(),
        .authorityError = authority.note(ctx, session),
        .hint = "nothing was sent to the host, so re-running this once the scope is free is safe",
    }, reason);
    // Exit 1, not 75. This command changed nothing, so nothing about the remote
    // is unknown *because of it* — the distinction the two codes exist for.
    Cli.releaseClaim();
    Cli.exitNow(Cli.exit_code.failure);
}

/// Refused after the kill landed, with everything downstream of it declined.
///
/// The kill cannot be undone and this does not pretend otherwise; what it
/// refuses is the log deletion and the local row, and `log_deleted` says which
/// side of the log this loss fell on.
///
/// Settled `indeterminate` carrying `AUTHORITY_LOST`, and not
/// `remote_cancel_confirmed`, even though `has-session` really did report the
/// session absent. The reading was true when it was taken; what it can no longer
/// support is a claim about *this name* now, because the peer holding the lease
/// has been free to create a session under it ever since. `job kill` reached the
/// same rule through `cancellationProvable`'s `authority.holds()` conjunct.
fn refuseAfterKill(
    ctx: *Cli.Ctx,
    execution: *Core.execution.Execution,
    server_name: []const u8,
    session: []const u8,
    authority: Authority,
    log_deleted: bool,
) noreturn {
    const reason = std.fmt.allocPrint(
        ctx.arena,
        "this command stopped session '{s}' and then found it no longer held the scope lease it took beforehand ({s}); another session may have created or acted on that name in between, so nothing here establishes what is there now",
        .{ session, authority.code() },
    ) catch "this command lost the scope lease for this session after stopping it";
    _ = execution.settle(.{ .indeterminate = .{
        .reason = reason,
        .last_observed = execution.status,
        .error_code = Authority.lost_code,
    } }, .{}) catch |err| Cli.receiptFatal(execution.id(), err, execution.status.text());
    report(ctx, .{
        .ok = false,
        .action = "not_removed",
        .session = session,
        .server = server_name,
        .requestId = execution.id(),
        .status = execution.status.text(),
        .sessionGone = true,
        .logDeleted = log_deleted,
        .localRow = "kept",
        .authority = authority.code(),
        .authorityError = authority.note(ctx, session),
        .hint = "the local row and this session's memories were kept; settle the record with 'terminus request reconcile <request-id>'",
    }, reason);
    Cli.releaseClaim();
    Cli.exitNow(Cli.exit_code.failure);
}

/// Writes one refusal, in whichever format the caller asked for.
///
/// Printed rather than raised through `fail`, so the request id reaches the
/// operator on every path: a refused removal is still a recorded attempt, and
/// auditing or reconciling it needs the id.
fn report(ctx: *Cli.Ctx, body: RemovalJson, reason: []const u8) void {
    switch (ctx.out.format) {
        .json => ctx.out.json(body) catch {},
        .human => {
            ctx.out.print("refused: {s}\n  request: {s}\n", .{ reason, body.requestId }) catch {};
            if (body.hint) |text| ctx.out.print("  {s}\n", .{text}) catch {};
        },
    }
    ctx.out.flush() catch {};
}

/// Refuses a removal that a peer's claim makes unsafe, before anything is sent.
fn reportBlocked(blocker: Core.execution.Blocker, server_name: []const u8, session: []const u8) noreturn {
    switch (blocker) {
        .unsettled => |op| fatal(
            "refused: request {s} is {s} on a scope that overlaps session '{s}:{s}', so removing it could destroy work that is still running; nothing was sent to the host. Reconcile it ('terminus request reconcile {s}') or wait for it to settle",
            .{ op.request_id, op.status.text(), server_name, session, op.request_id },
        ),
        .lease => |lease| fatal(
            "refused: request {s} (on {s}) holds a lease on a scope that overlaps session '{s}:{s}' until {d}; nothing was sent to the host. Wait for it to lapse",
            .{ lease.owner_request_id, lease.profile_token, server_name, session, lease.expires_at },
        ),
    }
}

/// The scope a command acting on session `name` contends on.
///
/// This is the line that closes §1.2, and the only place in this slice where a
/// name is taken apart.
///
/// A session called `job-<x>` is job `<x>`'s shell: `cmd_job` builds that name
/// (`jobSessionName`), and `Tmux.list` strips the `t-` prefix, so a running job
/// appears in `session ls` as `job-deploy`. `session rm web job-deploy` is
/// therefore aimed at the same shell `job kill web deploy` is aimed at — and
/// until now the two could not see each other. The job claims `.job:"deploy"`;
/// a lease keyed on the session name as typed would be `.job:"job-deploy"`,
/// which `Scope.overlaps` correctly reports as a different thing. Nothing
/// contended, and `session rm` killed running jobs.
///
/// So the *kill target* stays the physical session name and the *contention key*
/// is the logical thing that session belongs to — the split §4.3 states, applied
/// one verb early. The surgery lives here, at the call site that knows what it
/// is acting on, and never inside `Scope.overlaps`, which has to stay an
/// obviously correct key comparison (§7.10 rejected exactly that for this
/// reason).
///
/// Two limits, stated here rather than discovered later:
///
///  * a *user* session literally named `deploy` also maps to `.job:"deploy"` and
///    so now blocks against job `deploy`. That is §1.3's existing false
///    collision — `write` and `exec <server>:<session>` already spell a session
///    scope as `.job:<session name>` — widened by one verb rather than invented
///    here, and it is the safe direction: refusing once too often costs a wait,
///    refusing once too rarely destroys somebody's shell.
///  * `write web:job-deploy` claims `.job:"job-deploy"` and still does not
///    overlap this, so those two remain blind to each other. That is §1.3's
///    false *miss*, and it closes with the v13 `.session` scope — fixing it
///    *is* the scope-vocabulary change, and that is not this slice.
fn contentionScope(name: []const u8) Core.execution.Scope {
    const job_prefix = "job-";
    if (std.mem.startsWith(u8, name, job_prefix) and name.len > job_prefix.len)
        return .{ .kind = .job, .key = name[job_prefix.len..] };
    return .{ .kind = .job, .key = name };
}

test contentionScope {
    const t = std.testing;
    // The headline case: the session a running job lives in contends with the
    // job, because it *is* the job's shell.
    try t.expectEqualStrings("deploy", contentionScope("job-deploy").key);
    try t.expect(contentionScope("job-deploy").overlaps(.{ .kind = .job, .key = "deploy" }));
    // An ordinary session keeps the key `write` and `exec <server>:<session>`
    // already use for it.
    try t.expectEqualStrings("shell", contentionScope("shell").key);
    try t.expect(!contentionScope("shell").overlaps(.{ .kind = .job, .key = "deploy" }));
    // A session called exactly `job-` is not job ""; it is a session with an odd
    // name, and stripping the prefix would give it the empty key — which every
    // other empty-keyed `.job` scope would then collide with.
    try t.expectEqualStrings("job-", contentionScope("job-").key);
}

/// The scope lease `session rm` holds from before its first remote call until
/// the local row is gone.
///
/// Ownership is the control operation's own `request_id`, minted by
/// `execution.begin` before anything is sent. That is deliberate on both sides:
/// `blockerLocked` exempts a lease whose owner is the request id it was handed,
/// so this command's own claim can never refuse it, and a peer reading the row
/// finds the operation that took it rather than a token naming this machine.
const Claim = struct {
    store: *Store,
    server_id: i64,
    scope: Core.execution.Scope,
    owner_request_id: []const u8,
    session: []const u8,

    /// Long enough that kill → log → settle never renews in practice, short
    /// enough that a hard-killed `session rm` does not lock the operator out of
    /// its own session for long. A claim that outlives its holder is released by
    /// lapsing, which is the only thing a dead process can do.
    const ttl_secs: i64 = 120;
};

/// Takes the scope, after `begin` and before anything is sent.
///
/// There is no `--force` here, and the omission is deliberate rather than
/// pending: a takeover displaces somebody else's claim on a session that is
/// about to be destroyed along with its memories, and nothing in this slice
/// establishes whose shell it is. Waiting out the TTL is the escape hatch.
fn claimScope(
    ctx: *Cli.Ctx,
    store: *Store,
    server_id: i64,
    session: []const u8,
    owner_request_id: []const u8,
    owner_token: []const u8,
) Claim {
    const claim: Claim = .{
        .store = store,
        .server_id = server_id,
        .scope = contentionScope(session),
        .owner_request_id = owner_request_id,
        .session = session,
    };
    const outcome = Store.leases.acquire(store, ctx.arena, .{
        .server_id = server_id,
        .scope = claim.scope,
        .owner_request_id = owner_request_id,
        // Audit subject: which machine did this. It decides nothing — that is
        // the point of the column — but a claim with no record of who took it
        // is not much of an audit trail.
        .profile_token = owner_token,
        .owner_label = session,
        .ttl_secs = Claim.ttl_secs,
        // A live clock, not `ctx.now`. A lease is compared against a clock
        // rather than merely stamped with one, and `ctx.now` is this process's
        // start time — a TTL dated from it starts running before the store was
        // even opened.
        .now = wallClockSeconds(ctx.io),
    }) catch |err| Cli.storeFatal(store, err);

    return switch (outcome) {
        .acquired => blk: {
            Cli.registerClaim(store, server_id, claim.scope, owner_request_id, session);
            break :blk claim;
        },
        // The owner is a freshly minted request id, so it cannot already hold a
        // lease. Not folded into `acquired`: reaching this would mean two
        // commands are about to share an owner, which is the thing the whole
        // barrier exists to stop.
        .renewed => |lease| fatal(
            "internal: the id minted for this command ({s}) already held a lease on the scope for session '{s}'; refusing to share an owner with whatever took it",
            .{ lease.owner_request_id, session },
        ),
        // `begin` checked the same barrier a moment ago, so this is a peer that
        // arrived in between. Nothing has been sent.
        .conflict => |lease| fatal(
            "refused: request {s} (on {s}) took a lease on a scope that overlaps session '{s}' until {d} while this command was starting; nothing was sent to the host",
            .{ lease.owner_request_id, lease.profile_token, session, lease.expires_at },
        ),
    };
}

/// Whether this command still holds the scope it took before it reached the
/// host.
///
/// Three answers and not a bool, because the two failures are different facts
/// and the report says which one it got. `lapsed` is an answer — the row is not
/// ours, so another session may be acting on this name right now. `unreadable`
/// is the absence of one: the store could not be asked, so the question stands
/// open. Neither is `held`, and that is the whole of the rule every destructive
/// step runs under: **a question we could not ask is not a yes.**
const Authority = union(enum) {
    held,
    /// `leases.renew` matched no row: the lease lapsed, or a peer displaced it.
    lapsed,
    /// `leases.renew` could not be performed. Carries `@errorName`, which is
    /// diagnostic prose and not something a caller may branch on — `code` is.
    unreadable: []const u8,

    /// The `error_code` a settlement written after the authority was lost
    /// carries, inside the ordinary `indeterminate` terminal. Not a terminal of
    /// its own: `op_state` already has the variant for "we cannot establish the
    /// remote outcome", and the code is what lets a reader tell this cause apart
    /// from the others on the receipt.
    const lost_code = "AUTHORITY_LOST";

    fn holds(a: Authority) bool {
        return switch (a) {
            .held => true,
            .lapsed, .unreadable => false,
        };
    }

    fn code(a: Authority) []const u8 {
        return switch (a) {
            .held => "held",
            .lapsed => "lapsed",
            .unreadable => "unreadable",
        };
    }

    /// The sentence beside it, or null while the claim is still ours. Prose:
    /// nothing branches on it, which is what `code` is for.
    fn note(a: Authority, ctx: *Cli.Ctx, session: []const u8) ?[]const u8 {
        return switch (a) {
            .held => null,
            .lapsed => std.fmt.allocPrint(
                ctx.arena,
                "this command's lease on the scope for session '{s}' is no longer held — it lapsed, or another session took it over while the host was being contacted",
                .{session},
            ) catch "this command's lease on this session's scope is no longer held",
            .unreadable => |name| std.fmt.allocPrint(
                ctx.arena,
                "this command's lease on the scope for session '{s}' could not be renewed ({s}), so whether the scope is still ours could not be established",
                .{ session, name },
            ) catch "this command's lease on this session's scope could not be renewed",
        };
    }
};

/// Wall-clock seconds, as opposed to `ctx.now` — which is the process's start
/// time and is what every other row this file writes is stamped with.
///
/// A lease is the one thing here that is *compared* against a clock rather than
/// merely stamped with one: `expires_at` decides whether a peer may take the
/// scope, and `leases.renew` refuses a lease that has already lapsed. Renewing
/// with `ctx.now` would write back the expiry the acquisition already set, so a
/// command that outran its TTL would extend nothing while reporting that it had.
fn wallClockSeconds(io: std.Io) i64 {
    const ts = std.Io.Timestamp.now(io, .real);
    return @intCast(@divTrunc(ts.nanoseconds, std.time.ns_per_s));
}

/// Keeps the claim alive across the remote work, and says whether it is still
/// ours. The answer is the point: a renewal nobody reads is a line on stderr,
/// not a barrier.
fn holdClaim(claim: Claim, now: i64) Authority {
    const still_ours = Store.leases.renew(
        claim.store,
        claim.server_id,
        claim.scope,
        claim.owner_request_id,
        Claim.ttl_secs,
        now,
    ) catch |err| {
        std.debug.print(
            "terminus: could not renew the scope lease for session '{s}': {s}; " ++
                "this command will not take any step that changes the host or the local record\n",
            .{ claim.session, @errorName(err) },
        );
        return .{ .unreadable = @errorName(err) };
    };
    if (still_ours) return .held;
    std.debug.print(
        "terminus: this command's lease on the scope for session '{s}' is no longer held — it lapsed or was " ++
            "taken over while the host was being contacted, so another session may be acting on the same name\n",
        .{claim.session},
    );
    return .lapsed;
}

/// Renews the claim immediately before the next step, and says whether that step
/// may go ahead.
///
/// One renewal per step, not one per command: a single renewal at the top covers
/// the moment it ran and nothing after it.
///
/// `authority` only ever moves one way. Once a renewal has answered that the
/// scope is not ours the steps after it are forbidden, so there is nothing left
/// to renew — and asking again would let a later answer overwrite the first
/// loss, which is the one the report is built from.
fn stillOurs(claim: Claim, io: std.Io, authority: *Authority) bool {
    if (!authority.holds()) return false;
    authority.* = holdClaim(claim, wallClockSeconds(io));
    return authority.holds();
}

// --- Adjacency, held against the source that has to have it -----------------
//
// "Renew before the step" is not a property of a function; it is a property of
// where the call sits. `stillOurs` cannot enforce it and no type can: a renewal
// three statements and a store transaction above a `kill-session` type checks
// exactly as well as one on the line above it, and answers a different question.
//
// The end-to-end gates cannot reach that window. A fake host's lease seizure is
// deterministic only while the binary is blocked on a socket, and between a
// renewal and the call it gates there is — by construction, and that is the
// point — no round trip to block on. So the adjacency is checked where it lives:
// in the text. `cmd_job.zig` holds the same rule over its own two claim-holding
// verbs; this is the third destructive verb and it needs its own, because that
// gate scans `killJob` and `removeJob` and says so.

/// The calls that change a host, spelled as they are written.
const destructive_remote_calls = [_][]const u8{
    "Tmux.killSession(",
    "Tmux.removeLog(",
};

/// How many of them this file's claim-holding verb makes. Asserted so a scan
/// that found nothing — a renamed function, a body delimiter that moved — fails
/// instead of passing over an empty region.
const destructive_remote_call_count = 2;

/// The one function here that holds a `Claim` while it touches the host.
const claim_holding_bodies = [_][]const u8{"\nfn removeSession("};

/// A top-level function's text, from its `fn` line to the `}` in column zero
/// that closes it.
fn bodyOf(source: []const u8, header: []const u8) error{ FunctionMissing, FunctionUnterminated }![]const u8 {
    const start = std.mem.indexOf(u8, source, header) orelse return error.FunctionMissing;
    const rest = source[start + 1 ..];
    const end = std.mem.indexOf(u8, rest, "\n}\n") orelse return error.FunctionUnterminated;
    return rest[0 .. end + 1];
}

test "gate: `session rm`'s destructive remote calls are renewed on the line above them" {
    const t = std.testing;
    const source = @embedFile("cmd_session.zig");

    var found: usize = 0;
    for (claim_holding_bodies) |header| {
        const body = try bodyOf(source, header);
        var lines = std.mem.splitScalar(u8, body, '\n');
        // Every code line seen so far, so the check can look back past the
        // comments that explain each site — and only past those.
        var last_code: []const u8 = "";
        var number: usize = 0;
        while (lines.next()) |raw| {
            number += 1;
            const line = std.mem.trim(u8, raw, " \t\r");
            const destructive = for (destructive_remote_calls) |call| {
                if (std.mem.indexOf(u8, line, call) != null) break call;
            } else null;
            if (destructive) |call| {
                found += 1;
                if (std.mem.indexOf(u8, last_code, "stillOurs(") == null) {
                    std.debug.print(
                        \\
                        \\src/cli/cmd_session.zig: a destructive remote call is not gated on a
                        \\renewal taken immediately before it.
                        \\
                        \\  in:               {s}
                        \\  line {d} of it:    {s}
                        \\  the code above it: {s}
                        \\
                        \\Every call that changes the host must be preceded — with nothing but
                        \\comments in between — by a `stillOurs(...)` gate, so that no store
                        \\transaction, probe or second round trip can sit between the question
                        \\"is the scope still ours" and the act it authorises. A renewal on the
                        \\far side of a settlement answers about a moment that has passed, and
                        \\the peer that took the lease in between now owns the session this
                        \\`{s}` names.
                        \\
                    , .{ header[1..], number, line, last_code, call });
                    return error.DestructiveCallIsNotAdjacentToItsRenewal;
                }
            }
            if (line.len == 0 or std.mem.startsWith(u8, line, "//")) continue;
            last_code = line;
        }
    }
    // A scan that matched nothing would have reported nothing. Say how many
    // sites the rule is actually holding.
    try t.expectEqual(@as(usize, destructive_remote_call_count), found);
}

const MergedSession = struct {
    name: []const u8,
    alive: bool,
    cursor: i64,
    note: ?[]const u8,
};

/// Remote list ∪ local rows: a session may be alive remotely without local
/// metadata (created outside Terminus) or vice versa (server rebooted).
fn merge(
    arena: std.mem.Allocator,
    remote: []const Tmux.RemoteSession,
    local: []const Store.sessions.Session,
) ![]MergedSession {
    var out: std.ArrayList(MergedSession) = .empty;
    for (local) |l| {
        var alive = false;
        for (remote) |r| {
            if (std.mem.eql(u8, r.name, l.name)) {
                alive = true;
                break;
            }
        }
        try out.append(arena, .{ .name = l.name, .alive = alive, .cursor = l.cursor, .note = l.note });
    }
    for (remote) |r| {
        var known = false;
        for (local) |l| {
            if (std.mem.eql(u8, r.name, l.name)) {
                known = true;
                break;
            }
        }
        if (!known) try out.append(arena, .{ .name = r.name, .alive = true, .cursor = 0, .note = null });
    }
    return out.toOwnedSlice(arena);
}

/// Session names flow into tmux -t arguments and log file paths; keep them
/// to a safe charset instead of trying to quote for both contexts.
fn validateName(name: []const u8) void {
    if (name.len == 0 or name.len > 64) fatal("session name must be 1-64 chars", .{});
    for (name) |ch| {
        switch (ch) {
            'a'...'z', 'A'...'Z', '0'...'9', '-', '_', '.' => {},
            else => fatal("session name may only contain [a-zA-Z0-9._-]", .{}),
        }
    }
}
