//! `terminus run` / `terminus job` — tracked long-running remote tasks.
//!
//! A job runs inside a dedicated remote tmux session named `job-<name>`. When
//! the command returns, its shell records the exit status twice: into
//! `~/.terminus/results/<request-id>.json`, and as a sentinel line in the
//! output log. Either one makes the outcome recoverable later by any process,
//! but only the first stays findable once the job's own output has scrolled
//! the sentinel out of reach — see `Tmux.jobLaunchLine`.
//!
//! Jobs run under the execution boundary, with one twist: the launching
//! command exits while the work continues. `run` therefore *detaches* rather
//! than settling — deliberately leaving the attempt in flight, which keeps it
//! blocking its scope because something really is still running there.
//! Whoever next observes the job settles it.
//!
//! What this file no longer does is guess. A job session that has vanished
//! without recording an exit status used to be recorded as `killed`; but a
//! pane can disappear because the command finished and the shell exited,
//! because somebody killed it, or because the host rebooted mid-write. Those
//! are not the same outcome, and none of them is evidence for the others.
const std = @import("std");
const fatal = Cli.fail;
const Cli = @import("cli.zig");
const Core = @import("../core/core.zig");
const Store = Core.Store;
const Tmux = Core.Tmux;
const fatalTmux = @import("cmd_exec.zig").fatalTmux;

const run_usage =
    \\usage: terminus run <server> --name <job-name> [--cwd <dir>] [--login]
    \\                    [--strict] [--interpreter <bin>] [--json] <command input>
    \\
    \\command input: --stdin | --cmd-file <path> | --cmd "<command>" | -- <command...>
    \\Multiline input runs as a staged remote script. --strict = set -euo pipefail.
    \\--login wraps in `bash -ilc` for the full user PATH (nvm/pm2/etc).
    \\
;
const job_usage =
    \\usage: terminus job <verb> <server> [<name>] [...]
    \\
    \\  job ls      <server> [--active] [--name <substr>] [--limit N] [--json]
    \\  job status  <server> <name> [--json]     probe: running? exit code? businessResult?
    \\  job read    <server> <name> [--from-cursor] [--limit BYTES] [--json]
    \\  job watch   <server> <name> [--interval 15s] [--max N] [--json]
    \\  job kill    <server> <name>              settle it from its recorded
    \\                                           outcome if it already ended,
    \\                                           else terminate and verify
    \\  job rm      <server> <name>              forget the job (kills if running)
    \\  job inspect <server> <name> [--json]     what was launched, byte for byte
    \\
    \\A job can print '__TERMINUS_RESULT__:<value>' to report business state
    \\separately from its process exit code.
    \\
    \\Exit codes: the job's own code, or 75 when its outcome is unknown.
    \\
;

/// Job sessions are namespaced away from user sessions: session `work`
/// and job `work` never collide.
fn jobSessionName(arena: std.mem.Allocator, name: []const u8) ![]u8 {
    return std.fmt.allocPrint(arena, "job-{s}", .{name});
}

fn jobScope(name: []const u8) Core.execution.Scope {
    return .{ .kind = .job, .key = name };
}

/// Whether a still-live job row may be quietly taken over by a new launch.
///
/// A `pending` row is a reservation, and a launcher killed between taking one
/// and reaching the remote shell leaves one behind. Refusing forever would
/// make every crashed launch a manual cleanup; deleting it on age would
/// eventually delete the row of a launcher that is merely slow. Neither is
/// needed, because the owning attempt already records how far it got.
///
/// So the test is the scope guard's own predicate, asked of the owner: if
/// that operation no longer blocks a scope, it either provably never
/// submitted or its outcome is established, and nothing is running under this
/// name. Everything else stays put — including a `running` row, a row from
/// 0.1.x with no owner at all, and one whose operation has vanished. Those
/// need `job rm`, which looks at the host before it agrees.
fn reclaimable(store: *Store, arena: std.mem.Allocator, row: Store.jobs.Job) bool {
    if (row.status != .pending) return false;
    const owner = row.owner_request_id orelse return false;
    const op = (Store.operations.get(store, arena, owner) catch |err|
        Cli.storeFatal(store, err)) orelse return false;
    return !op.effectiveStatus().blocksScope();
}

pub fn runCmd(ctx: *Cli.Ctx, raw_args: []const []const u8) !void {
    const parsed = Cli.parseArgs(ctx, raw_args);
    if (parsed.boolean("json")) ctx.out.format = .json;

    const server_name = parsed.positional(0) orelse fatal("{s}", .{run_usage});
    const job_name = parsed.flag("name") orelse fatal("--name is required\n{s}", .{run_usage});
    validateJobName(job_name);
    const raw_command = (try Cli.trailingContent(ctx, &parsed, "cmd-file", 1)) orelse
        fatal("no command given\n{s}", .{run_usage});

    var store = try Cli.openStore(ctx, &parsed);
    defer store.close();
    const resolved = Cli.resolveServer(ctx, &store, server_name);
    const owner_token = Store.policy.ownerToken(&store, ctx.arena, ctx.io, ctx.now) catch |err|
        Cli.storeFatal(&store, err);

    // Launching a job is a mutation, so an unsettled peer on the same scope
    // or a foreign lease refuses it. That is the whole point: starting a
    // second `deploy` while the first one's fate is unknown is how work gets
    // applied twice.
    //
    // Held in a named value because a blocked launch asks a second time,
    // after trying to settle the blocker from evidence on the host.
    const begin_opts: Core.execution.BeginOptions = .{
        .server_id = resolved.server.id,
        .server_name = resolved.server.name,
        .kind = .job,
        .scope = jobScope(job_name),
        .alias = job_name,
        .mutating = true,
        .argv_redacted = Store.history.redactSecrets(ctx.arena, raw_command) catch
            // Falling back to the raw text would write the very secrets the
            // redaction exists to keep out of an append-only ledger.
            fatal("cannot redact the command for the audit record; refusing to store it unredacted", .{}),
        .argv_sha256 = try sha256Hex(ctx.arena, raw_command),
        .cwd = parsed.flag("cwd") orelse resolved.server.cwd,
        .shell = if (parsed.boolean("login")) "bash-login" else "bash",
        .owner_token = owner_token,
        .force = parsed.boolean("force"),
        .now = ctx.now,
    };
    const start = Core.execution.begin(&store, ctx.arena, ctx.io, begin_opts) catch |err|
        Cli.storeFatal(&store, err);

    // One connection for the whole command, opened wherever it is first
    // needed. The blocked path needs it before the execution exists, the
    // normal path after — and opening a second one would mean two SSH
    // handshakes for one launch.
    var conn_slot: ?Cli.Connection = null;
    defer if (conn_slot) |*c| c.deinit();

    var execution = switch (start) {
        .ready => |e| e,
        // A blocker that might already have finished is worth one connection
        // before we refuse. `begin` inserts nothing on this path, so settling
        // the blocker and asking again costs a round trip and leaks nothing —
        // and the second answer is the one that decides. Anything unprovable
        // (a lease, a non-job) still refuses without dialling at all, and an
        // unreachable host falls back to the refusal rather than reporting a
        // connection error in its place.
        .blocked => |blocker| retry: {
            if (!Cli.blockerMayBeProvable(blocker)) return reportBlocked(blocker);
            conn_slot = Cli.tryConnect(ctx, &parsed, resolved.server, resolved.auth) orelse
                return reportBlocked(blocker);
            Cli.settleProvableBlocker(ctx, &store, conn_slot.?.executor(), blocker);
            const second = Core.execution.begin(&store, ctx.arena, ctx.io, begin_opts) catch |err|
                Cli.storeFatal(&store, err);
            break :retry switch (second) {
                .ready => |e| e,
                .blocked => |still| return reportBlocked(still),
            };
        },
    };
    Cli.registerExecution(&execution);
    defer {
        Cli.clearExecution();
        // Covers the paths `fail`'s hook cannot: a plain error return unwinds
        // through here, and `store` dies with this frame.
        Cli.releaseReservation();
        execution.deinit();
    }

    // A name held by a live job is not something `--force` may take.
    //
    // `--force` means one thing: "I accept the risk of acting while an
    // overlapping operation's outcome is unknown." Letting it also mean "and
    // tear the name away from a launcher that is mid-setup, or from a job
    // that is running right now" is a different and much sharper decision,
    // and merging the two put it behind a flag people reach for casually.
    // Stopping a live job is `job kill` or `job rm`, both of which say what
    // they are doing and leave a record.
    if (Store.jobs.getByName(&store, ctx.arena, resolved.server.id, job_name) catch |err|
        Cli.storeFatal(&store, err)) |existing|
    {
        if (existing.status.live() and !reclaimable(&store, ctx.arena, existing)) fatal(
            "job '{s}' is {t} (since {d}); nothing was sent. Stop it first ('terminus job kill {s} {s}' or 'job rm'), or pick another --name — --force does not take a live job's name",
            .{ job_name, existing.status, existing.created_at, server_name, job_name },
        );
        _ = Store.jobs.remove(&store, resolved.server.id, job_name) catch |err| Cli.storeFatal(&store, err);
    }

    execution.connecting() catch |err| Cli.receiptFatal(execution.id(), err, "created");
    if (conn_slot == null) conn_slot = Cli.connect(ctx, &parsed, resolved.server, resolved.auth);
    var conn = &conn_slot.?;
    const executor = conn.executor();

    // The guard waved this launch through while something else still holds an
    // overlapping scope (`--force`). If that something is a job which already
    // finished, read its exit status before anything is torn down —
    // opportunistic and one-way, and `submitted()` below re-runs the
    // authoritative guard either way. It has to happen here, ahead of the
    // session teardown, because the blocker on a same-name rerun is the
    // previous attempt in this very session.
    //
    // The blocked path above has already done this for its own blocker; this
    // call covers the launches `begin` let through while still reporting one
    // (`--force`), where `advisory` is the only place the blocker appears.
    Cli.settleProvableBlocker(ctx, &store, executor, execution.advisory);

    const session = try jobSessionName(ctx.arena, job_name);
    const nonce: u64 = @intCast(@mod(std.Io.Timestamp.now(ctx.io, .real).nanoseconds, 1_000_000_007));
    const sentinel = try std.fmt.allocPrint(ctx.arena, "__TERMINUS_JOB_{d}__", .{nonce});

    // Claim the name before touching the remote host, and keep the claim for
    // the whole setup.
    //
    // The check above is a courtesy: it produces a good message, but two
    // launches racing on one name can both pass it. This insert cannot — the
    // `UNIQUE(server_id, name)` index picks exactly one winner, and the loser
    // is still holding an untouched remote when it finds out. That ordering is
    // the point. The next thing this function does is kill the job's tmux
    // session, and a loser that got that far would be killing the session the
    // winner had just filled with real work.
    //
    // The row also has to exist before `sendKeys` for a second reason: if the
    // database failed afterwards, the command would be running on the server
    // with nothing locally able to find it — `status`, `kill` and `reconcile`
    // all key off this row and the attempt.
    _ = Store.jobs.create(&store, resolved.server.id, job_name, raw_command, sentinel, execution.id(), ctx.now) catch |err| switch (err) {
        error.NameTaken => fatal("job '{s}' was claimed by another launch just now; nothing was sent", .{job_name}),
        else => Cli.storeFatal(&store, err),
    };
    // `fail` exits without running defers, so the release is a hook rather
    // than a `defer`. It is keyed on this launch's request id: if someone
    // takes the name over while we are still setting up, the row stops being
    // ours and we must not delete theirs on the way out.
    Cli.registerReservation(&store, execution.id(), job_name);

    // A leftover session from a forgotten job must be *confirmed* gone before
    // we reuse the name. `ensure` treats an existing session as ready, so a
    // kill that quietly failed would type this command into the previous
    // job's shell — with its cwd, its environment and its half-finished work.
    const cleared = Tmux.killSession(executor, ctx.arena, session) catch |err|
        fatalTmux(err, executor, session);
    if (!cleared) fatal(
        "a tmux session for job '{s}' still exists and could not be killed; refusing to reuse it (inspect it with 'tmux attach -t {s}' on the host)",
        .{ job_name, try Tmux.targetName(ctx.arena, session) },
    );
    Tmux.ensure(executor, ctx.arena, session) catch |err| fatalTmux(err, executor, session);

    var command = raw_command;
    var staged_path: ?[]const u8 = null;
    if (Core.script.shouldStage(raw_command) or parsed.flag("interpreter") != null) {
        const staged = Core.script.stage(executor, ctx.arena, raw_command, .{
            .interpreter = parsed.flag("interpreter") orelse "bash",
            .strict = parsed.boolean("strict"),
            .login = parsed.boolean("login"),
        }, nonce) catch |err| switch (err) {
            error.ScriptTooLarge => fatal("script exceeds {d} KiB; push it as a file and run that instead", .{Core.script.max_inline_script / 1024}),
            error.StagingFailed => fatal("could not stage the script on the remote host", .{}),
            else => fatal("staging failed: {s} ({s})", .{ executor.errorMessage(), @errorName(err) }),
        };
        command = staged.command;
        staged_path = staged.remote_path;
    } else if (parsed.boolean("strict")) {
        command = try std.fmt.allocPrint(ctx.arena, "set -euo pipefail; {s}", .{raw_command});
        if (parsed.boolean("login")) command = try Cli.loginWrap(ctx.arena, command);
    } else if (parsed.boolean("login")) {
        command = try Cli.loginWrap(ctx.arena, command);
    }

    const cwd = parsed.flag("cwd") orelse resolved.server.cwd;
    const full = try Tmux.jobLaunchLine(ctx.arena, command, cwd, sentinel, execution.id());

    // The immutable record of what was launched. Survives `job rm` and a
    // same-name rerun, which the mutable `jobs` row does not.
    const attempt_no = Store.job_attempts.nextAttemptNo(&store, resolved.server.id, job_name) catch |err|
        Cli.storeFatal(&store, err);
    _ = Store.job_attempts.create(&store, .{
        .request_id = execution.id(),
        .server_id = resolved.server.id,
        .server_name = resolved.server.name,
        .job_name = job_name,
        .attempt_no = attempt_no,
        .sentinel = sentinel,
        .tmux_session = session,
        .cwd = cwd,
        .interpreter = parsed.flag("interpreter") orelse "bash",
        .shell = if (parsed.boolean("login")) "bash-login" else "bash",
        .script_body_redacted = Store.history.redactSecrets(ctx.arena, raw_command) catch
            fatal("cannot redact the script for the audit record; refusing to store it unredacted", .{}),
        .script_sha256 = try sha256Hex(ctx.arena, raw_command),
        .script_bytes = @intCast(raw_command.len),
        .entry_path = staged_path,
        .now = ctx.now,
    }) catch |err| Cli.storeFatal(&store, err);

    // Keys are about to enter a live shell: from here the remote may act.
    // This is also where the scope guard binds — the check at `begin` was a
    // fast fail, this one is atomic with becoming visible to the next caller.
    switch (execution.submitted() catch |err| Cli.receiptFatal(execution.id(), err, "about to submit")) {
        .submitted => {},
        // `fail` releases the name reservation on the way out: we prepared
        // this launch and are not going to use it, and leaving the row behind
        // would make the next run report a job that never started. The
        // immutable attempt row stays — it is the record that this happened.
        .refused => |blocker| reportBlocked(blocker),
    }
    Tmux.sendKeys(executor, ctx.arena, session, full, false) catch {
        // The keys may have landed before the channel broke, so the job may
        // be running. Recording that and then exiting 1 would tell an agent
        // "failed, safe to retry" — the one conclusion that is not available.
        //
        // The reservation is kept, and deliberately left `pending`: it may
        // name something running on the host, so it must neither be reused
        // nor claimed as started.
        Cli.commitReservation();
        _ = execution.transportLoss(executor.errorMessage()) catch |receipt_err|
            Cli.receiptFatal(execution.id(), receipt_err, "submitted");
        // Nothing has been printed yet, so this needs the full body — an
        // agent parsing `--json` must get an object, not an empty stream and
        // a bare exit code.
        Cli.failIndeterminate(
            execution.id(),
            "the connection broke while handing the job to its remote shell; it may be running",
            "submitted",
        );
    };
    // The command is in the remote shell. The reservation is now a job.
    Cli.commitReservation();

    // Promotion can legitimately fail to find its row: another launcher may
    // have forced this name away while we were setting up. Either way the
    // command has already been sent, so neither a database error nor a
    // zero-row update may leave through the generic failure path — that reads
    // as "safe to retry" for work that is running right now.
    const promoted = Store.jobs.markStarted(&store, execution.id()) catch |err| promoted: {
        std.debug.print(
            "terminus: could not promote the tracking row for job '{s}': {s}\n",
            .{ job_name, @errorName(err) },
        );
        break :promoted false;
    };
    if (!promoted) {
        // The attempt row still carries this launch's own sentinel and
        // session, so the request id remains a complete handle on it even
        // though the job *name* may now belong to somebody else.
        execution.detach("job was handed to its remote shell; the local tracking row is not ours") catch |err|
            Cli.receiptFatal(execution.id(), err, "submitted");
        Cli.failIndeterminate(
            execution.id(),
            "the job was sent, but its local tracking row could not be promoted (another launcher may hold the name); settle it by request id",
            "submitted",
        );
    }

    if (Tmux.panePid(executor, ctx.arena, session) catch null) |pid| {
        execution.remoteStarted(.{ .pid = pid }) catch |err|
            Cli.receiptFatal(execution.id(), err, "remote_started");
    }

    // The work outlives this process. Detaching says so explicitly, and the
    // attempt keeps holding its scope until somebody establishes how it ended.
    execution.detach("job continues in its remote tmux session") catch |err|
        Cli.receiptFatal(execution.id(), err, "remote_started");

    switch (ctx.out.format) {
        .json => try ctx.out.json(.{
            .ok = true,
            .action = "started",
            .requestId = execution.id(),
            .attempt = attempt_no,
            .server = server_name,
            .job = job_name,
            .command = raw_command,
            .cwd = cwd,
            .transport = conn.transport,
            .daemonError = conn.daemon_error,
        }),
        .human => try ctx.out.print("started job '{s}' on '{s}' (request {s}); poll with 'terminus job status {s} {s}'\n", .{
            job_name, server_name, execution.id(), server_name, job_name,
        }),
    }
}

pub fn jobCmd(ctx: *Cli.Ctx, raw_args: []const []const u8) !void {
    if (raw_args.len == 0) fatal("{s}", .{job_usage});
    const verb = raw_args[0];
    const parsed = Cli.parseArgs(ctx, raw_args[1..]);
    if (parsed.boolean("json")) ctx.out.format = .json;

    const server_name = parsed.positional(0) orelse fatal("{s}", .{job_usage});
    var store = try Cli.openStore(ctx, &parsed);
    defer store.close();
    const resolved = Cli.resolveServer(ctx, &store, server_name);

    if (std.mem.eql(u8, verb, "ls")) return listJobs(ctx, &store, resolved.server.id, server_name, &parsed);

    const job_name = parsed.positional(1) orelse fatal("{s}", .{job_usage});

    if (std.mem.eql(u8, verb, "inspect")) return inspectJob(ctx, &store, resolved.server.id, job_name, &parsed);

    const job = (Store.jobs.getByName(&store, ctx.arena, resolved.server.id, job_name) catch |err|
        Cli.storeFatal(&store, err)) orelse fatal("unknown job '{s}' on '{s}'", .{ job_name, server_name });
    const session = try jobSessionName(ctx.arena, job_name);

    // The attempt links this job to its operation, so an observation here
    // settles the attempt the launching process left in flight.
    const attempt = Store.job_attempts.latest(&store, ctx.arena, resolved.server.id, job_name) catch |err|
        Cli.storeFatal(&store, err);

    var conn = Cli.connect(ctx, &parsed, resolved.server, resolved.auth);
    defer conn.deinit();
    const executor = conn.executor();

    if (std.mem.eql(u8, verb, "status")) {
        const state = refresh(ctx, &store, executor, session, job, attempt);
        try reportStatus(ctx, server_name, job, state, conn.transport, conn.daemon_error, attempt);
        if (state.status == .indeterminate) {
            try ctx.out.flush();
            Cli.failIndeterminateAfterOutput(if (attempt) |a| a.request_id else job.name);
        }
    } else if (std.mem.eql(u8, verb, "read")) {
        const limit: i64 = if (parsed.flag("limit")) |l|
            std.fmt.parseInt(i64, l, 10) catch fatal("invalid --limit '{s}'", .{l})
        else
            1 << 20;
        const from = if (parsed.boolean("from-cursor")) job.read_cursor else 0;
        const probe = Tmux.probeJob(
            executor,
            ctx.arena,
            session,
            job.sentinel,
            if (attempt) |a| a.request_id else null,
            from,
            limit,
        ) catch |err| fatalTmux(err, executor, session);
        if (parsed.boolean("from-cursor")) {
            Store.jobs.setCursor(&store, job.id, probe.next_cursor) catch |err| Cli.storeFatal(&store, err);
        }
        const state = applyProbe(ctx, &store, job, probe, attempt);
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{
                .ok = state.status != .indeterminate,
                .requestId = if (attempt) |a| a.request_id else null,
                .job = job.name,
                .status = state.status.text(),
                .exitCode = state.exit_code,
                .businessResult = state.business_result,
                .finishedAt = state.finished_at,
                .observedAt = state.observed_at,
                .conflict = ConflictJson.from(state.conflict),
                .from = from,
                .to = probe.next_cursor,
                .data = probe.output,
            }),
            .human => try ctx.out.print("{s}", .{probe.output}),
        }
        if (state.status == .indeterminate) {
            try ctx.out.flush();
            Cli.failIndeterminateAfterOutput(if (attempt) |a| a.request_id else job.name);
        }
    } else if (std.mem.eql(u8, verb, "watch")) {
        try watchJob(ctx, &store, executor, session, job, attempt, &parsed, server_name, conn);
    } else if (std.mem.eql(u8, verb, "kill")) {
        try killJob(ctx, &store, executor, session, job, attempt, resolved.server.id, &parsed);
    } else if (std.mem.eql(u8, verb, "rm")) {
        try removeJob(ctx, &store, executor, session, job, attempt, resolved.server.id, &parsed);
    } else {
        fatal("unknown verb 'job {s}'\n{s}", .{ verb, job_usage });
    }
}

const State = struct {
    status: Core.Store.op_state.Status,
    exit_code: ?i64,
    /// A remote finish time we can prove, and nothing else. Null whenever the
    /// only record that answered was the log sentinel, which carries no
    /// timestamp — see `observed_at` for what we can always say.
    finished_at: ?i64,
    /// Our own clock, at the moment we looked. Never presented as a finish
    /// time: it is when *we saw* the evidence, on a different machine.
    observed_at: i64,
    /// Set when the two durable records disagree. Carried all the way out to
    /// the caller: without it a contradiction reads as a plain `indeterminate`
    /// with no exit code, which is indistinguishable from "the job left
    /// nothing behind" and sends the operator to a reconcile that will refuse.
    conflict: ?Tmux.JobProbe.Conflict = null,
    business_result: ?[]const u8 = null,
};

/// The JSON shape of a `JobProbe.Conflict`. One definition so every command
/// that can hit a contradiction names its two halves the same way.
const ConflictJson = struct {
    resultExitCode: i32,
    sentinelExitCode: i32,

    fn from(clash: ?Tmux.JobProbe.Conflict) ?ConflictJson {
        const c = clash orelse return null;
        return .{ .resultExitCode = c.result_exit_code, .sentinelExitCode = c.sentinel_exit_code };
    }
};

/// How much of the log's end a state probe reads. Shared with the launch
/// paths' lazy settlement, so both windows are the same by construction.
const probe_tail_bytes = Cli.probe_tail_bytes;

/// One SSH probe of the log's *end*; settles the operation if it establishes
/// an outcome.
///
/// Deliberately does not use `jobs.read_cursor`. That cursor belongs to
/// whoever is streaming output, and a probe that shared it would (a) move a
/// consumer's position underneath them and (b) never reach the sentinel on a
/// job whose output exceeds one read window.
fn refresh(
    ctx: *Cli.Ctx,
    store: *Store,
    executor: Core.Executor,
    session: []const u8,
    job: Store.jobs.Job,
    attempt: ?Store.job_attempts.Attempt,
) State {
    const probe = Tmux.probeTail(
        executor,
        ctx.arena,
        session,
        job.sentinel,
        if (attempt) |a| a.request_id else null,
        probe_tail_bytes,
    ) catch |err| fatalTmux(err, executor, session);
    if (attempt) |a| {
        Store.job_attempts.recordProbe(store, a.request_id, .{
            .probe_cursor = probe.next_cursor,
            .latest_business_result = probe.business_result,
            .session_alive = probe.session_alive,
            .now = ctx.now,
        }) catch |err| Cli.storeFatal(store, err);
    }
    return applyProbe(ctx, store, job, probe, attempt);
}

/// Turns an observation into a settlement — or into nothing at all.
///
/// Four cases; three of them settle the ledger and the fourth records nothing:
///   * the two durable records disagree — the one case where more evidence
///     leaves us less certain. Settled `indeterminate`, naming both codes;
///   * a record carried an exit code — the job ended, and how. Settled;
///   * the session is gone with no exit code — something happened and we
///     cannot say what. Settled `indeterminate`, which keeps holding the
///     scope. Not `killed`: a pane also disappears when the command finishes
///     and the shell exits, or when the host reboots mid-write;
///   * otherwise it is still running, and there is nothing to record.
fn applyProbe(
    ctx: *Cli.Ctx,
    store: *Store,
    job: Store.jobs.Job,
    probe: Tmux.JobProbe,
    attempt: ?Store.job_attempts.Attempt,
) State {
    var execution = if (attempt) |a|
        Core.execution.attach(store, ctx.arena, ctx.io, a.request_id) catch |err| Cli.storeFatal(store, err)
    else
        null;

    // Checked before the exit code, not after. `probe.exit_code` is already
    // null on a conflict, but reading it first would make the ordering the
    // thing that keeps a contradiction from settling — and the reason string
    // below is the only place the two codes ever reach a human.
    if (probe.conflict) |clash| {
        if (execution) |*e| {
            _ = e.settleAttached(.{ .indeterminate = .{
                .reason = std.fmt.allocPrint(
                    ctx.arena,
                    "the job's two durable records disagree: its result file says exit {d}, the sentinel in its log says exit {d}. One of them is wrong and nothing here can say which",
                    .{ clash.result_exit_code, clash.sentinel_exit_code },
                ) catch "the job's result file and its log sentinel report different exit codes",
                .last_observed = e.status,
            } }, .{}) catch |err| Cli.storeFatal(store, err);
        }
        // The row is left as it stands. Writing a status here would have to
        // pick one of the two codes, which is precisely what we refuse to do.
        return .{
            .status = .indeterminate,
            .exit_code = null,
            .finished_at = null,
            .observed_at = ctx.now,
            .conflict = clash,
            .business_result = probe.business_result,
        };
    }

    if (probe.exit_code) |code| {
        if (execution) |*e| {
            _ = e.settleAttached(.{ .exited = .{ .exit_code = code } }, .{
                .stdout = .{ .bytes = @intCast(probe.output.len) },
            }) catch |err| Cli.storeFatal(store, err);
        }
        // `jobs.finished_at` takes the remote clock when the sidecar reported
        // one and ours otherwise, so the column mixes two machines' clocks and
        // cannot be read as a finish time on its own. That is tolerable only
        // because it is a cache: the ledger is the record. What must not mix
        // is what we *report* — see `State.finished_at` and `State.observed_at`.
        const row_stamp = probe.finished_at orelse ctx.now;
        Store.jobs.markFinished(store, job.id, .exited, code, row_stamp) catch |err| Cli.storeFatal(store, err);
        return .{
            .status = if (code == 0) .completed else .failed,
            .exit_code = code,
            .finished_at = probe.finished_at,
            .observed_at = ctx.now,
            .business_result = probe.business_result,
        };
    }

    if (!probe.session_alive) {
        if (execution) |*e| {
            _ = e.settleAttached(.{ .indeterminate = .{
                .reason = "job session disappeared without reporting an exit status",
                .last_observed = e.status,
            } }, .{}) catch |err| Cli.storeFatal(store, err);
        }
        // The legacy row keeps its own vocabulary; the ledger is the record.
        Store.jobs.markFinished(store, job.id, .killed, null, ctx.now) catch |err| Cli.storeFatal(store, err);
        return .{
            .status = .indeterminate,
            .exit_code = null,
            // Not `now`. We cannot say when this job finished, and we cannot
            // say that it finished — that is what `indeterminate` means. A
            // timestamp here would read as a finish we never witnessed.
            .finished_at = null,
            .observed_at = ctx.now,
            .business_result = probe.business_result,
        };
    }

    return .{
        .status = if (execution) |e| e.status else .remote_started,
        .exit_code = null,
        .finished_at = null,
        .observed_at = ctx.now,
        .business_result = probe.business_result,
    };
}

fn reportStatus(
    ctx: *Cli.Ctx,
    server_name: []const u8,
    job: Store.jobs.Job,
    state: State,
    transport: []const u8,
    daemon_error: ?[]const u8,
    attempt: ?Store.job_attempts.Attempt,
) !void {
    switch (ctx.out.format) {
        .json => try ctx.out.json(.{
            .ok = state.status != .indeterminate,
            .requestId = if (attempt) |a| a.request_id else null,
            .server = server_name,
            .job = job.name,
            .status = state.status.text(),
            .exitCode = state.exit_code,
            .businessResult = state.business_result,
            .command = job.command,
            .createdAt = job.created_at,
            // Two clocks, never merged. `finishedAt` is the remote's own
            // report and is null unless the result sidecar carried one — a
            // sentinel-only outcome has no timestamp, and filling it with our
            // clock would put this machine's time under a key that claims to
            // describe when work ended on another one. `observedAt` is that
            // local clock, labelled as what it is.
            .finishedAt = state.finished_at,
            .observedAt = state.observed_at,
            .conflict = ConflictJson.from(state.conflict),
            .transport = transport,
            .daemonError = daemon_error,
        }),
        .human => {
            try ctx.out.print("job '{s}': {s} (exit={?d})", .{ job.name, state.status.text(), state.exit_code });
            if (state.business_result) |br| try ctx.out.print(" result={s}", .{br});
            try ctx.out.print("\n", .{});
            if (state.conflict) |clash| try ctx.out.print(
                "  its result file says exit {d}, its log sentinel says exit {d}; one of them is wrong and nothing mechanical can say which\n",
                .{ clash.result_exit_code, clash.sentinel_exit_code },
            );
        },
    }
}

fn watchJob(
    ctx: *Cli.Ctx,
    store: *Store,
    executor: Core.Executor,
    session: []const u8,
    job: Store.jobs.Job,
    attempt: ?Store.job_attempts.Attempt,
    parsed: *const Cli.Args.Parsed,
    server_name: []const u8,
    conn: anytype,
) !void {
    const interval_ns = parseInterval(parsed.flag("interval") orelse "15s");
    const max_polls: u32 = if (parsed.flag("max")) |m|
        std.fmt.parseInt(u32, m, 10) catch fatal("invalid --max '{s}'", .{m})
    else
        240;

    var polls: u32 = 0;
    var state = refresh(ctx, store, executor, session, job, attempt);
    while (state.status != .completed and state.status != .failed and
        state.status != .indeterminate and polls < max_polls)
    {
        std.Io.sleep(ctx.io, .{ .nanoseconds = @intCast(interval_ns) }, .awake) catch {};
        polls += 1;
        state = refresh(ctx, store, executor, session, job, attempt);
    }

    const still_running = state.status != .completed and state.status != .failed and
        state.status != .indeterminate;
    switch (ctx.out.format) {
        .json => try ctx.out.json(.{
            .ok = state.status != .indeterminate,
            .requestId = if (attempt) |a| a.request_id else null,
            .server = server_name,
            .job = job.name,
            .status = state.status.text(),
            .exitCode = state.exit_code,
            .businessResult = state.business_result,
            .stillRunning = still_running,
            .conflict = ConflictJson.from(state.conflict),
            .polls = polls,
            .transport = conn.transport,
        }),
        .human => if (still_running)
            try ctx.out.print("job '{s}' still running after {d} polls\n", .{ job.name, polls })
        else {
            try ctx.out.print("job '{s}' {s} (exit={?d})", .{ job.name, state.status.text(), state.exit_code });
            if (state.business_result) |br| try ctx.out.print(" result={s}", .{br});
            try ctx.out.print("\n", .{});
            if (state.conflict) |clash| try ctx.out.print(
                "  its result file says exit {d}, its log sentinel says exit {d}; one of them is wrong and nothing mechanical can say which\n",
                .{ clash.result_exit_code, clash.sentinel_exit_code },
            );
        },
    }

    if (state.status == .indeterminate) {
        try ctx.out.flush();
        Cli.failIndeterminateAfterOutput(if (attempt) |a| a.request_id else job.name);
    }
    if (state.exit_code) |code| {
        if (code != 0) {
            try ctx.out.flush();
            std.process.exit(@intCast(std.math.clamp(code, 1, 255)));
        }
    }
}

/// What the ledger already holds for an attempt, without producing a second
/// opinion.
///
/// `attach` returns null once an attempt is terminal, and terminal includes
/// `indeterminate` — the case where nothing was ever established. Treating
/// "already settled" as "settled successfully" would turn an unknown into a
/// success in the caller's eyes, so the ledger is asked directly.
///
/// Null when the attempt names a request the ledger does not have: that is not
/// a status, and must not be flattened into one.
fn recordedEffective(ctx: *Cli.Ctx, store: *Store, request_id: []const u8) ?Core.Store.op_state.Status {
    const op = (Store.operations.get(store, ctx.arena, request_id) catch |err|
        Cli.storeFatal(store, err)) orelse return null;
    return op.effectiveStatus();
}

/// `recordedEffective` for callers that only need to print it.
fn recordedStatus(ctx: *Cli.Ctx, store: *Store, request_id: []const u8) []const u8 {
    const status = recordedEffective(ctx, store, request_id) orelse return "unknown";
    return status.text();
}

fn settledText(outcome: Core.Store.receipts.SettleOutcome) []const u8 {
    return switch (outcome) {
        .recorded => |r| r.status.text(),
        .already_settled => |r| r.status.text(),
    };
}

fn settledStatus(outcome: Core.Store.receipts.SettleOutcome) Core.Store.op_state.Status {
    return switch (outcome) {
        .recorded => |r| r.status,
        .already_settled => |r| r.status,
    };
}

/// Stops a job and records what that actually established.
///
/// Not a new operation: a kill settles the attempt already in flight, so the
/// receipt shows the launch and its cancellation on one trail.
///
/// Three rules, each of them a bug that was here.
///
/// *Look before you kill.* This used to kill first and ask questions after,
/// which turned a job that had already finished — exit status sitting in its
/// result sidecar — into `indeterminate`, because once the session is gone
/// "gone" proves nothing. The answer had been there the whole time and the
/// kill is what stopped us reading it. So the probe comes first; when it finds
/// a real outcome that is what gets recorded, and the kill becomes cleanup.
/// What is *reported* is then what the ledger holds, which is not always what
/// we set out to write: an attempt a peer already settled `indeterminate`
/// cannot be re-settled, and claiming the outcome anyway would turn an unknown
/// into a success.
///
/// *A contradiction is not a settlement.* When the two durable records report
/// different exit codes, killing the session and calling it `cancelled` would
/// paper over the one case where the evidence is actively untrustworthy.
///
/// *A kill is not proof.* `tmux has-session` reporting the session gone is not
/// evidence that the work stopped: a command that daemonized, called `disown`,
/// or ran under `setsid` outlives the pane that launched it. Under a
/// supervisor whose capability says it cannot prove a process is gone, this
/// settles `indeterminate` — which keeps the scope held — rather than
/// `cancelled`, which would release it and invite a relaunch alongside a
/// process that is still running.
///
/// The log is never deleted here. An `indeterminate` kill points the operator
/// at `request reconcile --from-log`, so this is exactly the caller that must
/// keep the evidence — which is why it uses `killSession` and never
/// `removeLog`.
fn killJob(
    ctx: *Cli.Ctx,
    store: *Store,
    executor: Core.Executor,
    session: []const u8,
    job: Store.jobs.Job,
    attempt: ?Store.job_attempts.Attempt,
    server_id: i64,
    parsed: *const Cli.Args.Parsed,
) !void {
    try requireNoForeignLease(ctx, store, server_id, job.name, parsed);

    const probe = Tmux.probeTail(
        executor,
        ctx.arena,
        session,
        job.sentinel,
        if (attempt) |a| a.request_id else null,
        probe_tail_bytes,
    ) catch |err| fatalTmux(err, executor, session);

    if (probe.conflict) |clash| {
        const reason = std.fmt.allocPrint(
            ctx.arena,
            "kill requested, but the job's two durable records already disagree: its result file says exit {d}, the sentinel in its log says exit {d}. One of them is wrong and nothing here can say which",
            .{ clash.result_exit_code, clash.sentinel_exit_code },
        ) catch "kill requested, but the job's result file and its log sentinel report different exit codes";

        var settled_status: []const u8 = "unknown";
        if (attempt) |a| {
            if (Core.execution.attach(store, ctx.arena, ctx.io, a.request_id) catch |err|
                Cli.storeFatal(store, err)) |loaded|
            {
                var execution = loaded;
                settled_status = settledText(execution.settleAttached(.{ .indeterminate = .{
                    .reason = reason,
                    .last_observed = execution.status,
                } }, .{}) catch |err| Cli.receiptFatal(a.request_id, err, "kill requested"));
            } else settled_status = recordedStatus(ctx, store, a.request_id);
        }

        // Still killed: the caller asked for the session to stop, and both
        // records claim the command already returned. What is refused is
        // reporting the kill as if it had established an outcome.
        const session_gone = Tmux.killSession(executor, ctx.arena, session) catch |err|
            fatalTmux(err, executor, session);
        if (job.status.live()) {
            Store.jobs.markFinished(store, job.id, .killed, null, ctx.now) catch |err|
                Cli.storeFatal(store, err);
        }

        switch (ctx.out.format) {
            .json => try ctx.out.json(.{
                .ok = false,
                .action = "killed",
                .job = job.name,
                .status = settled_status,
                .sessionGone = session_gone,
                .cancellationProven = false,
                .conflict = ConflictJson.from(clash),
                .requestId = if (attempt) |a| a.request_id else null,
                .hint = "the two records disagree; settle it by hand with 'terminus request reconcile <request-id> --override'",
            }),
            .human => try ctx.out.print(
                "job '{s}': session killed, but its result file says exit {d} while its log sentinel says exit {d}; the outcome is unknown\n",
                .{ job.name, clash.result_exit_code, clash.sentinel_exit_code },
            ),
        }
        try ctx.out.flush();
        Cli.failIndeterminateAfterOutput(if (attempt) |a| a.request_id else job.name);
    }

    if (probe.exit_code) |code| {
        var settled_status: []const u8 = "unknown";
        // Whether the *ledger* now holds a real outcome for this attempt.
        // Reading an exit code off the host is not the same as recording it:
        // `attach` returns null for an attempt that is already terminal, and
        // terminal includes `indeterminate`, which settles nothing and goes on
        // blocking the scope. With no attempt at all there is no operation to
        // settle and nothing holding a scope, so the exit status we just read
        // is the whole answer.
        var proven = attempt == null;
        if (attempt) |a| {
            if (Core.execution.attach(store, ctx.arena, ctx.io, a.request_id) catch |err|
                Cli.storeFatal(store, err)) |loaded|
            {
                var execution = loaded;
                // `already_settled` hands back the terminal that is actually
                // recorded, which need not be the one we just proved: a peer
                // may have settled this attempt `indeterminate` between our
                // `attach` and this call. Report the ledger, not the intent.
                const status = settledStatus(execution.settleAttached(.{ .exited = .{ .exit_code = code } }, .{
                    .stdout = .{ .bytes = @intCast(probe.output.len) },
                }) catch |err| Cli.receiptFatal(a.request_id, err, "kill requested"));
                settled_status = status.text();
                proven = status != .indeterminate;
            } else if (recordedEffective(ctx, store, a.request_id)) |effective| {
                settled_status = effective.text();
                proven = effective != .indeterminate;
            } else {
                // The attempt names a request the ledger does not have.
                settled_status = "unknown";
                proven = false;
            }
        }
        // Remote clock when the sidecar reported one, ours otherwise; see the
        // note in `applyProbe` on why this column mixes them.
        //
        // Guarded like its two sibling branches: a row already marked `killed`
        // records a decision somebody took, and overwriting it with `exited`
        // because we later read the exit status the job happened to leave
        // behind rewrites that history.
        if (job.status.live()) {
            Store.jobs.markFinished(store, job.id, .exited, code, probe.finished_at orelse ctx.now) catch |err|
                Cli.storeFatal(store, err);
        }

        const session_gone = Tmux.killSession(executor, ctx.arena, session) catch |err|
            fatalTmux(err, executor, session);

        // A surviving session is a real failure even though the outcome is
        // known: `ensure` treats one as ready, so the next launch under this
        // name would type into the dead job's shell.
        const ok = proven and session_gone;
        const hint: ?[]const u8 = if (!proven) unproven: {
            // The evidence is sitting on the host and `reconcile --from-log`
            // accepts exactly it, so name the command that would take it.
            const a = attempt orelse break :unproven
                "the host holds this job's exit status, but there is no recorded attempt to settle it against";
            break :unproven std.fmt.allocPrint(
                ctx.arena,
                "the host holds this job's exit status but the ledger records the attempt as {s}; settle it with 'terminus request reconcile {s} --from-log'",
                .{ settled_status, a.request_id },
            ) catch "the host holds this job's exit status but the ledger does not; settle it with 'terminus request reconcile <request-id> --from-log'";
        } else if (!session_gone)
            "the job's outcome is recorded, but its tmux session is still present; remove it on the host before relaunching under this name"
        else
            null;

        switch (ctx.out.format) {
            .json => try ctx.out.json(.{
                .ok = ok,
                .action = "already_finished",
                .job = job.name,
                .status = settled_status,
                .exitCode = code,
                .outcomeProven = proven,
                .finishedAt = probe.finished_at,
                .observedAt = ctx.now,
                .sessionCleanedUp = session_gone,
                // Nothing was cancelled: the job had already ended on its own.
                .cancellationProven = false,
                .requestId = if (attempt) |a| a.request_id else null,
                .hint = hint,
            }),
            .human => if (!proven)
                try ctx.out.print(
                    "job '{s}' had already finished (exit {d}) on the host, but its attempt is recorded as {s}; nothing here settled it\n",
                    .{ job.name, code, settled_status },
                )
            else if (session_gone)
                try ctx.out.print(
                    "job '{s}' had already finished (exit {d}); recorded its outcome and cleaned up the session\n",
                    .{ job.name, code },
                )
            else
                try ctx.out.print(
                    "job '{s}' had already finished (exit {d}); its outcome is recorded, but the session could not be cleaned up\n",
                    .{ job.name, code },
                ),
        }
        // Unproven outranks a surviving session: "we do not know what the
        // ledger holds for this work" is the conclusion that forbids a retry,
        // and the two sibling branches already exit 75 in this situation.
        if (!proven) {
            try ctx.out.flush();
            Cli.failIndeterminateAfterOutput(if (attempt) |a| a.request_id else job.name);
        }
        if (!session_gone) {
            try ctx.out.flush();
            std.process.exit(Cli.exit_code.failure);
        }
        return;
    }

    // No outcome to preserve, so this is a cancellation in the real sense.
    const session_gone = Tmux.killSession(executor, ctx.arena, session) catch |err|
        fatalTmux(err, executor, session);

    const capability = Core.supervisor.shell_capability;
    const can_prove = Core.supervisor.Requirement.verified_cancellation.satisfiedBy(capability);

    var settled_status: []const u8 = "unknown";
    if (attempt) |a| {
        if (Core.execution.attach(store, ctx.arena, ctx.io, a.request_id) catch |err|
            Cli.storeFatal(store, err)) |loaded|
        {
            var execution = loaded;
            const outcome = if (session_gone and can_prove)
                execution.settleAttached(.{ .remote_cancel_confirmed = .{
                    .pid = null,
                    .term_sent = true,
                    .kill_sent = true,
                    .absence_verified_at = ctx.now,
                    .verification_method = "supervisor verified the process group is gone",
                } }, .{})
            else
                execution.settleAttached(.{ .indeterminate = .{
                    .reason = if (session_gone)
                        "job session killed, but this supervisor cannot prove the process tree stopped (a daemonized or disowned child survives its pane)"
                    else
                        "kill issued but the job session is still present",
                    .last_observed = execution.status,
                } }, .{});
            settled_status = settledText(outcome catch |err| Cli.receiptFatal(a.request_id, err, "kill issued"));
        } else settled_status = recordedStatus(ctx, store, a.request_id);
    }

    if (job.status.live()) {
        Store.jobs.markFinished(store, job.id, .killed, null, ctx.now) catch |err|
            Cli.storeFatal(store, err);
    }

    const proven = session_gone and can_prove;
    switch (ctx.out.format) {
        .json => try ctx.out.json(.{
            .ok = proven,
            .action = "killed",
            .job = job.name,
            .status = settled_status,
            .sessionGone = session_gone,
            .cancellationProven = proven,
            .requestId = if (attempt) |a| a.request_id else null,
            .hint = if (proven) null else @as(?[]const u8, Core.supervisor.Requirement.verified_cancellation.explain()),
        }),
        .human => {
            if (proven) {
                try ctx.out.print("killed job '{s}' (absence verified)\n", .{job.name});
            } else if (session_gone) {
                try ctx.out.print("job '{s}': session killed, but absence of the process tree is unproven\n", .{job.name});
            } else {
                try ctx.out.print("kill issued for '{s}' but the session is still present\n", .{job.name});
            }
        },
    }
    if (!proven) {
        try ctx.out.flush();
        Cli.failIndeterminateAfterOutput(if (attempt) |a| a.request_id else job.name);
    }
}

/// Forgets a job's name while preserving what can still be proven.
///
/// The original version killed the session — which also deleted the remote log
/// — then settled `indeterminate` and reported `{ok:true, "removed"}`. That
/// destroyed the only mechanical evidence of how the job ended and left a human
/// override as the sole way to ever settle it, while telling the caller
/// everything went fine.
///
/// The version after that kept the log but faked the safety check: on the
/// `--discard-evidence` branch `cleared` was the literal `true`, so the guard
/// reading "refusing to forget a job that may still be running" was dead code
/// on precisely the branch that also deleted the evidence. A job whose session
/// survived the kill could lose its log, its result record and its local row
/// while the process kept running.
///
/// So the order below is the whole point, and it is the same for both
/// branches: probe, kill, *prove the session is gone*, and only then destroy
/// anything. Nothing is deleted on a session that is still there — not the
/// log, not the sidecar, not the row.
fn removeJob(
    ctx: *Cli.Ctx,
    store: *Store,
    executor: Core.Executor,
    session: []const u8,
    job: Store.jobs.Job,
    attempt: ?Store.job_attempts.Attempt,
    server_id: i64,
    parsed: *const Cli.Args.Parsed,
) !void {
    try requireNoForeignLease(ctx, store, server_id, job.name, parsed);
    const discard = parsed.boolean("discard-evidence");

    // Look before destroying: if the outcome is provable right now, it need
    // never become an override.
    const probe = Tmux.probeTail(
        executor,
        ctx.arena,
        session,
        job.sentinel,
        if (attempt) |a| a.request_id else null,
        probe_tail_bytes,
    ) catch |err| fatalTmux(err, executor, session);

    // The real boolean, on both branches. `killSession` never touches the log;
    // destroying evidence is a separate act below, gated on this answer.
    const cleared = Tmux.killSession(executor, ctx.arena, session) catch |err|
        fatalTmux(err, executor, session);
    if (!cleared) fatal(
        "job '{s}' session is still present after cleanup; refusing to forget a job that may still be running. Nothing was deleted — no log, no result record, no local row. Inspect it with 'tmux attach -t {s}' on the host",
        .{ job.name, try Tmux.targetName(ctx.arena, session) },
    );

    if (discard) {
        // Only now, with the session proven gone. A live pane recreates the
        // log through `pipe-pane`, so deleting it under a surviving session
        // would leave a file that quietly comes back holding a partial
        // history starting mid-job.
        Tmux.removeLog(executor, ctx.arena, session) catch |err|
            fatal("job '{s}': its session is stopped but its log could not be deleted: {s} ({s}); nothing was removed locally, so the job is still tracked", .{ job.name, executor.errorMessage(), @errorName(err) });
        // The sidecar is evidence too. Leaving it behind after being told to
        // discard evidence would make the next `reconcile --from-log` settle
        // from a file the caller believes is gone. A half-discarded evidence
        // set must not be reported as a clean removal, so this is fatal.
        if (attempt) |a| Tmux.removeResult(executor, ctx.arena, a.request_id) catch |err|
            fatal("job '{s}': its log was deleted but its result record could not be: {s} ({s}); the evidence set is now half gone. Delete {s}.json under ~/.terminus/results by hand, then re-run this command", .{ job.name, executor.errorMessage(), @errorName(err), a.request_id });
    }

    var settled_status: []const u8 = "unchanged";
    var proven = false;
    if (attempt) |a| {
        if (Core.execution.attach(store, ctx.arena, ctx.io, a.request_id) catch |err|
            Cli.storeFatal(store, err)) |loaded|
        {
            var execution = loaded;
            const outcome = if (probe.conflict) |clash|
                // Two mechanical records contradicting each other is not an
                // outcome. `proven` stays false, so this exits 75 and the
                // caller owes a reconcile.
                execution.settleAttached(.{ .indeterminate = .{
                    .reason = std.fmt.allocPrint(
                        ctx.arena,
                        "job removed while its two durable records disagreed: its result file says exit {d}, the sentinel in its log says exit {d}",
                        .{ clash.result_exit_code, clash.sentinel_exit_code },
                    ) catch "job removed while its result file and its log sentinel reported different exit codes",
                    .last_observed = execution.status,
                } }, .{})
            else if (probe.exit_code) |code| out: {
                proven = true;
                break :out execution.settleAttached(.{ .exited = .{ .exit_code = code } }, .{});
            } else execution.settleAttached(.{ .indeterminate = .{
                .reason = if (discard)
                    "job removed with --discard-evidence; the log was deleted, so its outcome can no longer be established mechanically"
                else
                    "job removed before its outcome was established; the log is retained for 'request reconcile --from-log'",
                .last_observed = execution.status,
            } }, .{});
            settled_status = settledText(outcome catch |err| Cli.receiptFatal(a.request_id, err, "job removed"));
        } else if (recordedEffective(ctx, store, a.request_id)) |effective| {
            // `attach` returns null for an attempt that is already terminal.
            // That is not the same as proven: an attempt settled
            // `indeterminate` is exactly the case where nothing was ever
            // established, and reporting "outcome recorded from its log"
            // would turn the unknown into a success in the caller's eyes.
            // Ask the ledger what it actually holds.
            settled_status = effective.text();
            proven = effective != .indeterminate;
        } else {
            // The attempt row names a request the ledger does not have.
            // Nothing here is established; say so rather than guess.
            settled_status = "unknown";
            proven = false;
        }
    }

    _ = Store.jobs.remove(store, server_id, job.name) catch |err| Cli.storeFatal(store, err);

    // Discarding evidence is not a success: it converts something that could
    // have been proven into an override the caller now owes. Neither is a
    // contradiction — the log is still on the host, but `reconcile --from-log`
    // will refuse two disagreeing records exactly as this did, so that case
    // also ends in an override and must not report `ok`.
    const ok = proven or (!discard and probe.conflict == null);
    const hint: ?[]const u8 = if (proven)
        null
    else if (probe.conflict != null)
        "the job's two durable records disagree; no mechanical reconcile can settle this — use 'terminus request reconcile <request-id> --override'"
    else if (discard)
        null
    else
        "outcome still unknown; settle it with 'terminus request reconcile <request-id> --from-log'";
    switch (ctx.out.format) {
        .json => try ctx.out.json(.{
            .ok = ok,
            .action = "removed",
            .job = job.name,
            .status = settled_status,
            .outcomeProven = proven,
            .evidenceRetained = !discard,
            .attemptRetained = attempt != null,
            .conflict = ConflictJson.from(probe.conflict),
            .requestId = if (attempt) |a| a.request_id else null,
            .hint = hint,
        }),
        .human => {
            if (proven) {
                try ctx.out.print("removed job '{s}' (outcome recorded from its log)\n", .{job.name});
            } else if (probe.conflict) |clash| {
                try ctx.out.print(
                    "removed job '{s}'; its result file says exit {d} while its log sentinel says exit {d}, so its outcome is unknown\n",
                    .{ job.name, clash.result_exit_code, clash.sentinel_exit_code },
                );
            } else if (discard) {
                try ctx.out.print("removed job '{s}' and deleted its log; its outcome can no longer be proven\n", .{job.name});
            } else {
                try ctx.out.print("removed job '{s}'; outcome unknown, log retained for reconcile\n", .{job.name});
            }
            // A proven or contradictory removal takes an earlier branch, so
            // the deletion has to be stated on its own rather than folded into
            // the discard branch — otherwise `--discard-evidence` on a job
            // with two disagreeing records never tells the operator that the
            // records it disagreed with are now gone.
            if (discard and (proven or probe.conflict != null))
                try ctx.out.print("  its log and result record were deleted; nothing can read them again\n", .{});
        },
    }
    if (!ok) {
        try ctx.out.flush();
        Cli.failIndeterminateAfterOutput(if (attempt) |a| a.request_id else job.name);
    }
}

/// One row of `job ls --json`.
///
/// A projection rather than the `Store.jobs.Job` row itself, for one field.
/// The row's `finished_at` falls back to local time when the host reported
/// none, and serializing the row verbatim published it under a name one
/// character away from `job status`'s `finishedAt` — which is documented as a
/// remote clock reading that is *never* backfilled with local time. Two
/// near-identical keys with opposite meanings, side by side in the same tool's
/// output, is a trap; `cachedFinishedAt` says what it is.
const ListedJob = struct {
    name: []const u8,
    command: []const u8,
    sentinel: []const u8,
    status: Store.jobs.Status,
    exitCode: ?i64,
    /// Local seconds when we last wrote this row, or the host's finish time
    /// if it happened to report one. Not authoritative: ask `job status`.
    cachedFinishedAt: ?i64,
    createdAt: i64,
    ownerRequestId: ?[]const u8,
};

fn listedJobs(ctx: *Cli.Ctx, rows: []const Store.jobs.Job) ![]ListedJob {
    const out = try ctx.arena.alloc(ListedJob, rows.len);
    for (rows, out) |row, *slot| slot.* = .{
        .name = row.name,
        .command = row.command,
        .sentinel = row.sentinel,
        .status = row.status,
        .exitCode = row.exit_code,
        .cachedFinishedAt = row.finished_at,
        .createdAt = row.created_at,
        .ownerRequestId = row.owner_request_id,
    };
    return out;
}

fn listJobs(
    ctx: *Cli.Ctx,
    store: *Store,
    server_id: i64,
    server_name: []const u8,
    parsed: *const Cli.Args.Parsed,
) !void {
    const all = Store.jobs.list(store, ctx.arena, server_id) catch |err| Cli.storeFatal(store, err);
    const only_active = parsed.boolean("active");
    const name_filter = parsed.flag("name");
    const limit: usize = if (parsed.flag("limit")) |l|
        std.fmt.parseInt(usize, l, 10) catch fatal("invalid --limit '{s}'", .{l})
    else
        20;

    var filtered: std.ArrayList(Store.jobs.Job) = .empty;
    for (all) |j| {
        if (only_active and !j.status.live()) continue;
        if (name_filter) |nf| if (std.mem.indexOf(u8, j.name, nf) == null) continue;
        try filtered.append(ctx.arena, j);
    }
    const total = filtered.items.len;
    const shown = filtered.items[0..@min(limit, total)];

    switch (ctx.out.format) {
        // Cached snapshot: these are last-observed values, not a live probe.
        .json => try ctx.out.json(.{
            .ok = true,
            .server = server_name,
            .jobs = try listedJobs(ctx, shown),
            .total = total,
            .shown = shown.len,
            .source = "cache",
        }),
        .human => {
            if (total == 0) return ctx.out.print("no jobs on '{s}'\n", .{server_name});
            for (shown) |j| {
                const first_line = std.mem.sliceTo(j.command, '\n');
                const brief = if (first_line.len > 60) first_line[0..60] else first_line;
                try ctx.out.print("{s}\t{t}\texit={?d}\t{s}\n", .{ j.name, j.status, j.exit_code, brief });
            }
            if (shown.len < total)
                try ctx.out.print("... {d} more (raise --limit to see all)\n", .{total - shown.len});
        },
    }
}

/// What was actually launched, from the immutable attempt record.
fn inspectJob(
    ctx: *Cli.Ctx,
    store: *Store,
    server_id: i64,
    job_name: []const u8,
    parsed: *const Cli.Args.Parsed,
) !void {
    const history = Store.job_attempts.history(store, ctx.arena, server_id, job_name) catch |err|
        Cli.storeFatal(store, err);
    if (history.len == 0) fatal("no recorded attempts for job '{s}'", .{job_name});
    const latest = history[0];

    switch (ctx.out.format) {
        .json => try ctx.out.json(.{
            .ok = true,
            .job = job_name,
            .attempt = latest.attempt_no,
            .totalAttempts = history.len,
            .requestId = latest.request_id,
            .cwd = latest.cwd,
            .interpreter = latest.interpreter,
            .shell = latest.shell,
            // Redacted body plus the hash of the raw text: enough to answer
            // "is this the script that ran?" without persisting credentials.
            .scriptSha256 = latest.script_sha256,
            .scriptBytes = latest.script_bytes,
            .script = if (parsed.boolean("show-script")) latest.script_body_redacted else null,
            .entryPath = latest.entry_path,
            .tmuxSession = latest.tmux_session,
            .createdAt = latest.created_at,
        }),
        .human => {
            try ctx.out.print("job '{s}' attempt {d} of {d}\n", .{ job_name, latest.attempt_no, history.len });
            try ctx.out.print("  request : {s}\n", .{latest.request_id});
            try ctx.out.print("  cwd     : {s}\n", .{latest.cwd orelse "(none)"});
            try ctx.out.print("  script  : {?s} ({?d} bytes)\n", .{ latest.script_sha256, latest.script_bytes });
            if (parsed.boolean("show-script")) {
                try ctx.out.print("---\n{s}\n---\n", .{latest.script_body_redacted orelse ""});
            }
        },
    }
}

/// Job mutations refuse while somebody else holds an overlapping lease.
fn requireNoForeignLease(
    ctx: *Cli.Ctx,
    store: *Store,
    server_id: i64,
    job_name: []const u8,
    parsed: *const Cli.Args.Parsed,
) !void {
    if (parsed.boolean("force")) return;
    const owner_token = Store.policy.ownerToken(store, ctx.arena, ctx.io, ctx.now) catch |err|
        Cli.storeFatal(store, err);
    const conflict = Store.leases.conflictFor(store, ctx.arena, server_id, jobScope(job_name), owner_token, ctx.now) catch |err|
        Cli.storeFatal(store, err);
    if (conflict) |lease| fatal(
        "refused: {s} holds a lease on an overlapping scope until {d}; wait, take it over, or pass --force",
        .{ lease.owner_token, lease.expires_at },
    );
}

/// Refuses an attempt that another claim on the same scope makes unsafe.
///
/// Reachable from `begin` (before we dial) and from `submitted` (the point of
/// no return). Both mean the same thing to the caller: the job was not
/// started, so retrying after reconciling is safe.
fn reportBlocked(blocker: Core.execution.Blocker) noreturn {
    switch (blocker) {
        .unsettled => |op| fatal(
            "refused: request {s} is {s} on an overlapping scope, so this could be applied twice; the job was not started. Reconcile it ('terminus request reconcile {s}') or pass --force",
            .{ op.request_id, op.status.text(), op.request_id },
        ),
        .lease => |lease| fatal(
            "refused: {s} holds a lease on an overlapping scope until {d}; the job was not started. Wait, take it over, or pass --force",
            .{ lease.owner_token, lease.expires_at },
        ),
    }
}

fn sha256Hex(arena: std.mem.Allocator, text: []const u8) ![]const u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(text, &digest, .{});
    return std.fmt.allocPrint(arena, "{x}", .{&digest});
}

fn validateJobName(name: []const u8) void {
    if (name.len == 0 or name.len > 60) fatal("job name must be 1-60 chars", .{});
    for (name) |ch| {
        switch (ch) {
            'a'...'z', 'A'...'Z', '0'...'9', '-', '_', '.' => {},
            else => fatal("job name may only contain [a-zA-Z0-9._-]", .{}),
        }
    }
}

/// Parses "15s" / "5m" / "1h" (bare number = seconds) into nanoseconds,
/// clamped to [1s, 1h] so a watch can never busy-spin or hang forever.
fn parseInterval(spec: []const u8) i64 {
    if (spec.len == 0) fatal("empty --interval", .{});
    const last = spec[spec.len - 1];
    const unit_ns: i64 = switch (last) {
        's' => std.time.ns_per_s,
        'm' => std.time.ns_per_min,
        'h' => std.time.ns_per_hour,
        '0'...'9' => std.time.ns_per_s,
        else => fatal("invalid --interval '{s}' (e.g. 15s, 5m, 1h)", .{spec}),
    };
    const digits = if (last >= '0' and last <= '9') spec else spec[0 .. spec.len - 1];
    const value = std.fmt.parseInt(i64, digits, 10) catch fatal("invalid --interval '{s}'", .{spec});
    return std.math.clamp(value * unit_ns, std.time.ns_per_s, std.time.ns_per_hour);
}
