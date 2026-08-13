//! `terminus run` / `terminus job` — tracked long-running remote tasks.
//!
//! A job runs inside a dedicated remote tmux session named `job-<name>` with
//! a sentinel appended (`cmd; echo <sentinel>:$?`), so its exit code is
//! recoverable from the output log at any later time, by any process.
//!
//! Jobs run under the execution boundary, with one twist: the launching
//! command exits while the work continues. `run` therefore *detaches* rather
//! than settling — deliberately leaving the attempt in flight, which keeps it
//! blocking its scope because something really is still running there.
//! Whoever next observes the job settles it.
//!
//! What this file no longer does is guess. A job session that has vanished
//! without leaving a sentinel used to be recorded as `killed`; but a pane can
//! disappear because the command finished and the shell exited, because
//! somebody killed it, or because the host rebooted mid-write. Those are not
//! the same outcome, and none of them is evidence for the others.
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
    \\  job kill    <server> <name>              terminate and verify it is gone
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
    const start = Core.execution.begin(&store, ctx.arena, ctx.io, .{
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
    }) catch |err| Cli.storeFatal(&store, err);

    var execution = switch (start) {
        .ready => |e| e,
        .blocked => |blocker| return reportBlocked(blocker),
    };
    Cli.registerExecution(&execution);
    defer {
        Cli.clearExecution();
        execution.deinit();
    }

    if (Store.jobs.getByName(&store, ctx.arena, resolved.server.id, job_name) catch |err|
        Cli.storeFatal(&store, err)) |existing|
    {
        if (existing.status == .running and !parsed.boolean("force"))
            fatal("job '{s}' is already running (started {d}); pick another --name, 'job rm' it, or pass --force", .{ job_name, existing.created_at });
        _ = Store.jobs.remove(&store, resolved.server.id, job_name) catch |err| Cli.storeFatal(&store, err);
    }

    execution.connecting() catch |err| Cli.storeFatal(&store, err);
    var conn = Cli.connect(ctx, &parsed, resolved.server, resolved.auth);
    defer conn.deinit();
    const executor = conn.executor();

    const session = try jobSessionName(ctx.arena, job_name);
    Tmux.kill(executor, ctx.arena, session) catch {}; // stale session from a forgotten job
    Tmux.ensure(executor, ctx.arena, session) catch |err| fatalTmux(err, executor, session);

    const nonce: u64 = @intCast(@mod(std.Io.Timestamp.now(ctx.io, .real).nanoseconds, 1_000_000_007));
    const sentinel = try std.fmt.allocPrint(ctx.arena, "__TERMINUS_JOB_{d}__", .{nonce});

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
    const full = if (cwd) |dir|
        try std.fmt.allocPrint(ctx.arena, "cd {s} && ({s}); echo {s}:$?", .{ dir, command, sentinel })
    else
        try std.fmt.allocPrint(ctx.arena, "({s}); echo {s}:$?", .{ command, sentinel });

    // Persist *before* handing anything to the remote.
    //
    // The sentinel and session name are already fixed, so the record can be
    // written first — and it must be. If these writes happened after
    // `sendKeys` and the local database then failed, the command would be
    // running on the server with nothing locally able to find it: `status`,
    // `kill` and `reconcile` all key off the job row and the attempt.
    const job_id = Store.jobs.create(&store, resolved.server.id, job_name, raw_command, sentinel, ctx.now) catch |err| switch (err) {
        error.NameTaken => fatal("job '{s}' already exists", .{job_name}),
        else => Cli.storeFatal(&store, err),
    };
    _ = job_id;

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
    execution.submitted() catch |err| Cli.receiptFatal(execution.id(), err, "about to submit");
    Tmux.sendKeys(executor, ctx.arena, session, full, false) catch |err| {
        _ = execution.transportLoss(executor.errorMessage()) catch {};
        fatalTmux(err, executor, session);
    };

    if (Tmux.panePid(executor, ctx.arena, session) catch null) |pid| {
        execution.remoteStarted(.{ .pid = pid }) catch |err|
            Cli.receiptFatal(execution.id(), err, "remote_started");
    }

    // The work outlives this process. Detaching says so explicitly, and the
    // attempt keeps holding its scope until somebody establishes how it ended.
    execution.detach("job continues in its remote tmux session") catch |err|
        Cli.storeFatal(&store, err);

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
        const probe = Tmux.probeJob(executor, ctx.arena, session, job.sentinel, from, limit) catch |err|
            fatalTmux(err, executor, session);
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
    finished_at: ?i64,
    business_result: ?[]const u8 = null,
};

/// How much of the log's end a state probe reads. The sentinel is one short
/// line at the very end, so this only has to be large enough to survive a
/// burst of trailing output.
const probe_tail_bytes: i64 = 256 * 1024;

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
    const probe = Tmux.probeTail(executor, ctx.arena, session, job.sentinel, probe_tail_bytes) catch |err|
        fatalTmux(err, executor, session);
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
/// Three cases, and only two of them are conclusions:
///   * the sentinel carried an exit code — the job ended, and how;
///   * the session is gone with no sentinel — something happened and we
///     cannot say what. Not `killed`: a pane also disappears when the command
///     finishes and the shell exits, or when the host reboots mid-write;
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

    if (probe.exit_code) |code| {
        if (execution) |*e| {
            _ = e.settleAttached(.{ .exited = .{ .exit_code = code } }, .{
                .stdout = .{ .bytes = @intCast(probe.output.len) },
            }) catch |err| Cli.storeFatal(store, err);
        }
        Store.jobs.markFinished(store, job.id, .exited, code, ctx.now) catch |err| Cli.storeFatal(store, err);
        return .{
            .status = if (code == 0) .completed else .failed,
            .exit_code = code,
            .finished_at = ctx.now,
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
            .finished_at = ctx.now,
            .business_result = probe.business_result,
        };
    }

    return .{
        .status = if (execution) |e| e.status else .remote_started,
        .exit_code = null,
        .finished_at = null,
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
            .finishedAt = state.finished_at,
            .transport = transport,
            .daemonError = daemon_error,
        }),
        .human => {
            try ctx.out.print("job '{s}': {s} (exit={?d})", .{ job.name, state.status.text(), state.exit_code });
            if (state.business_result) |br| try ctx.out.print(" result={s}", .{br});
            try ctx.out.print("\n", .{});
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
            .polls = polls,
            .transport = conn.transport,
        }),
        .human => if (still_running)
            try ctx.out.print("job '{s}' still running after {d} polls\n", .{ job.name, polls })
        else {
            try ctx.out.print("job '{s}' {s} (exit={?d})", .{ job.name, state.status.text(), state.exit_code });
            if (state.business_result) |br| try ctx.out.print(" result={s}", .{br});
            try ctx.out.print("\n", .{});
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

/// Kills a job's session and records what that actually established.
///
/// Not a new operation: a kill settles the attempt already in flight, so the
/// receipt shows the launch and its cancellation on one trail.
///
/// The hard part is what counts as proof. `tmux has-session` reporting the
/// session gone is *not* evidence that the work stopped: a command that
/// daemonized, called `disown`, or ran under `setsid` outlives the pane that
/// launched it. Under a supervisor whose capability says it cannot prove a
/// process is gone, this therefore settles `indeterminate` — which keeps the
/// scope held — rather than `cancelled`, which would release it and invite a
/// relaunch alongside a process that is still running.
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

    Tmux.kill(executor, ctx.arena, session) catch |err| fatalTmux(err, executor, session);
    const session_gone = !(Tmux.isAlive(executor, ctx.arena, session) catch |err| fatalTmux(err, executor, session));

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
            const settled = outcome catch |err| Cli.receiptFatal(a.request_id, err, "kill issued");
            settled_status = switch (settled) {
                .recorded => |r| r.status.text(),
                .already_settled => |r| r.status.text(),
            };
        }
    }

    if (job.status == .running) {
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

/// Forgets a job, but only once the remote side is actually clean.
///
/// This used to delete the local row and report success even when the remote
/// kill had failed, which turned a half-finished cleanup into a confident
/// "removed" and left a live session nobody was tracking.
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

    Tmux.kill(executor, ctx.arena, session) catch |err|
        fatal("cannot clean up job '{s}' on the remote: {s} ({s}); the local record is kept", .{ job.name, executor.errorMessage(), @errorName(err) });
    const gone = !(Tmux.isAlive(executor, ctx.arena, session) catch |err| fatalTmux(err, executor, session));
    if (!gone) {
        fatal("job '{s}' session is still present after cleanup; refusing to forget a job that may still be running (use 'job kill' and check, or --force)", .{job.name});
    }

    if (attempt) |a| {
        if (Core.execution.attach(store, ctx.arena, ctx.io, a.request_id) catch |err|
            Cli.storeFatal(store, err)) |loaded|
        {
            var execution = loaded;
            // Same proof limit as `job kill`: the session being gone does not
            // establish that the work stopped.
            _ = execution.settleAttached(.{ .indeterminate = .{
                .reason = "job removed; session absent, but this supervisor cannot prove the process tree stopped",
                .last_observed = execution.status,
            } }, .{}) catch |err| Cli.receiptFatal(a.request_id, err, "job removed");
        }
    }

    _ = Store.jobs.remove(store, server_id, job.name) catch |err| Cli.storeFatal(store, err);

    switch (ctx.out.format) {
        // The attempt row survives on purpose: `job inspect` still answers
        // what ran, after the job itself is forgotten.
        .json => try ctx.out.json(.{
            .ok = true,
            .action = "removed",
            .job = job.name,
            .attemptRetained = attempt != null,
            .requestId = if (attempt) |a| a.request_id else null,
        }),
        .human => try ctx.out.print("removed job '{s}' (attempt history retained)\n", .{job.name}),
    }
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
        if (only_active and j.status != .running) continue;
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
            .jobs = shown,
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

fn reportBlocked(blocker: Core.execution.Blocker) noreturn {
    switch (blocker) {
        .unsettled => |op| fatal(
            "refused: request {s} is {s} on an overlapping scope, so this could be applied twice; reconcile it ('terminus request reconcile {s}') or pass --force",
            .{ op.request_id, op.status.text(), op.request_id },
        ),
        .lease => |lease| fatal(
            "refused: {s} holds a lease on an overlapping scope until {d}; wait, take it over, or pass --force",
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
