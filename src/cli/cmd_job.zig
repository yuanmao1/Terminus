//! `terminus run` / `terminus job` — tracked long-running remote tasks.
//!
//! A job runs inside a dedicated remote tmux session named `job-<name>`
//! with a sentinel appended (`cmd; echo <sentinel>:$?`), so its exit code
//! and completion are recoverable from the output log at any later time,
//! by any process. Local sqlite caches the last observed state.
//!
//!   terminus run <server> --name build -- npm run build
//!   terminus job ls <server> [--json]
//!   terminus job status <server> <name> [--json]   # one SSH probe
//!   terminus job read <server> <name> [--from-cursor] [--json]
//!   terminus job kill <server> <name>
//!   terminus job rm <server> <name>                # forget + cleanup
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
    \\  job ls     <server> [--active] [--name <substr>] [--limit N] [--json]
    \\  job status <server> <name> [--json]     probe: running? exit code? businessResult?
    \\  job read   <server> <name> [--from-cursor] [--limit BYTES] [--json]
    \\  job watch  <server> <name> [--interval 15s] [--max N] [--json]  block until it ends
    \\  job kill   <server> <name>               terminate the job's session
    \\  job rm     <server> <name>               forget the job (kills if running)
    \\
    \\A job can print '__TERMINUS_RESULT__:<value>' to report business state
    \\(success/failure/rows=N) separately from its process exit code.
    \\
;

/// Job sessions are namespaced away from user sessions: session `work`
/// and job `work` never collide.
fn jobSessionName(arena: std.mem.Allocator, name: []const u8) ![]u8 {
    return std.fmt.allocPrint(arena, "job-{s}", .{name});
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

    if (Store.jobs.getByName(&store, ctx.arena, resolved.server.id, job_name) catch |err|
        Cli.storeFatal(&store, err)) |existing|
    {
        if (existing.status == .running)
            fatal("job '{s}' is already running (started {d}); pick another --name or 'job rm' it", .{ job_name, existing.created_at });
        // Finished job with the same name: replace it.
        _ = Store.jobs.remove(&store, resolved.server.id, job_name) catch |err| Cli.storeFatal(&store, err);
    }

    var conn = Cli.connect(ctx, &parsed, resolved.server, resolved.auth);
    defer conn.deinit();
    const executor = conn.executor();

    const session = try jobSessionName(ctx.arena, job_name);
    Tmux.kill(executor, ctx.arena, session) catch {}; // stale session from a forgotten job
    Tmux.ensure(executor, ctx.arena, session) catch |err| fatalTmux(err, executor, session);

    const nonce: u64 = @intCast(@mod(std.Io.Timestamp.now(ctx.io, .real).nanoseconds, 1_000_000_007));
    const sentinel = try std.fmt.allocPrint(ctx.arena, "__TERMINUS_JOB_{d}__", .{nonce});

    // Multiline or non-bash scripts are staged as remote files; the job's
    // session then runs one clean line. The staged file is NOT deleted on
    // completion here (the job outlives this CLI); the daily sweep in
    // script.cleanup handles it on later runs.
    var command = raw_command;
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
    } else if (parsed.boolean("strict")) {
        command = try std.fmt.allocPrint(ctx.arena, "set -euo pipefail; {s}", .{raw_command});
        if (parsed.boolean("login")) command = try Cli.loginWrap(ctx.arena, command);
    } else if (parsed.boolean("login")) {
        command = try Cli.loginWrap(ctx.arena, command);
    }

    // Optional cwd: job-level --cwd wins over the server workspace.
    const cwd = parsed.flag("cwd") orelse resolved.server.cwd;
    const full = if (cwd) |dir|
        try std.fmt.allocPrint(ctx.arena, "cd {s} && ({s}); echo {s}:$?", .{ dir, command, sentinel })
    else
        try std.fmt.allocPrint(ctx.arena, "({s}); echo {s}:$?", .{ command, sentinel });
    Tmux.sendKeys(executor, ctx.arena, session, full, false) catch |err| fatalTmux(err, executor, session);

    _ = Store.jobs.create(&store, resolved.server.id, job_name, raw_command, sentinel, ctx.now) catch |err| switch (err) {
        error.NameTaken => fatal("job '{s}' already exists", .{job_name}),
        else => Cli.storeFatal(&store, err),
    };

    Store.history.add(&store, resolved.server.id, .{
        .kind = "job",
        .detail = try std.fmt.allocPrint(ctx.arena, "start '{s}': {s}", .{ job_name, raw_command }),
        .cwd = cwd,
        .transport = conn.transport,
    }, ctx.now) catch {};

    switch (ctx.out.format) {
        .json => try ctx.out.json(.{
            .ok = true,
            .action = "started",
            .server = server_name,
            .job = job_name,
            .command = command,
            .cwd = cwd,
            .transport = conn.transport,
            .daemonError = conn.daemon_error,
        }),
        .human => try ctx.out.print("started job '{s}' on '{s}'; poll with 'terminus job status {s} {s}'\n", .{
            job_name, server_name, server_name, job_name,
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

    if (std.mem.eql(u8, verb, "ls")) {
        var list = Store.jobs.list(&store, ctx.arena, resolved.server.id) catch |err|
            Cli.storeFatal(&store, err);
        // Filters: --active keeps only running jobs; --name <substr> keeps
        // matching names; --limit N caps the (newest-first) result count.
        const only_active = parsed.boolean("active");
        const name_filter = parsed.flag("name");
        const limit: usize = if (parsed.flag("limit")) |l|
            std.fmt.parseInt(usize, l, 10) catch fatal("invalid --limit '{s}'", .{l})
        else
            20;
        var filtered: std.ArrayList(Store.jobs.Job) = .empty;
        for (list) |j| {
            if (only_active and j.status != .running) continue;
            if (name_filter) |nf| if (std.mem.indexOf(u8, j.name, nf) == null) continue;
            try filtered.append(ctx.arena, j);
        }
        const total = filtered.items.len;
        const shown = filtered.items[0..@min(limit, total)];
        list = shown;
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{
                .ok = true,
                .server = server_name,
                .jobs = list,
                .total = total,
                .shown = shown.len,
            }),
            .human => {
                if (total == 0) return ctx.out.print("no jobs on '{s}'\n", .{server_name});
                for (list) |j| {
                    // Compact: name, status, exit code, first line of cmd.
                    const first_line = std.mem.sliceTo(j.command, '\n');
                    const brief = if (first_line.len > 60) first_line[0..60] else first_line;
                    try ctx.out.print("{s}\t{t}\texit={?d}\t{s}\n", .{ j.name, j.status, j.exit_code, brief });
                }
                if (shown.len < total)
                    try ctx.out.print("... {d} more (raise --limit to see all)\n", .{total - shown.len});
            },
        }
        return;
    }

    const job_name = parsed.positional(1) orelse fatal("{s}", .{job_usage});
    const job = (Store.jobs.getByName(&store, ctx.arena, resolved.server.id, job_name) catch |err|
        Cli.storeFatal(&store, err)) orelse fatal("unknown job '{s}' on '{s}'", .{ job_name, server_name });
    const session = try jobSessionName(ctx.arena, job_name);

    var conn = Cli.connect(ctx, &parsed, resolved.server, resolved.auth);
    defer conn.deinit();
    const executor = conn.executor();

    if (std.mem.eql(u8, verb, "status")) {
        const state = refresh(ctx, &store, executor, session, job);
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{
                .ok = true,
                .server = server_name,
                .job = job.name,
                .status = @tagName(state.status),
                .exitCode = state.exit_code,
                .businessResult = state.business_result,
                .command = job.command,
                .createdAt = job.created_at,
                .finishedAt = state.finished_at,
                .transport = conn.transport,
                .daemonError = conn.daemon_error,
            }),
            .human => {
                try ctx.out.print("job '{s}': {t} (exit={?d})", .{ job.name, state.status, state.exit_code });
                if (state.business_result) |br| try ctx.out.print(" result={s}", .{br});
                try ctx.out.print("\n", .{});
            },
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
        const state = applyProbe(ctx, &store, job, probe);
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{
                .ok = true,
                .job = job.name,
                .status = @tagName(state.status),
                .exitCode = state.exit_code,
                .businessResult = state.business_result,
                .from = from,
                .to = probe.next_cursor,
                .data = probe.output,
            }),
            .human => try ctx.out.print("{s}", .{probe.output}),
        }
    } else if (std.mem.eql(u8, verb, "watch")) {
        // Poll until the job reaches a terminal state (or --max polls),
        // sleeping --interval between probes. One blocking call replaces an
        // agent's manual poll loop; it returns the moment the job ends.
        const interval_ns = parseInterval(parsed.flag("interval") orelse "15s");
        const max_polls: u32 = if (parsed.flag("max")) |m|
            std.fmt.parseInt(u32, m, 10) catch fatal("invalid --max '{s}'", .{m})
        else
            240; // 240 * 15s default ≈ 1h ceiling
        var polls: u32 = 0;
        var current = job;
        var state = refresh(ctx, &store, executor, session, current);
        while (state.status == .running and polls < max_polls) {
            std.Io.sleep(ctx.io, .{ .nanoseconds = @intCast(interval_ns) }, .awake) catch {};
            polls += 1;
            // Re-read the row so a completion persisted by refresh sticks.
            current = (Store.jobs.getByName(&store, ctx.arena, resolved.server.id, job_name) catch |err|
                Cli.storeFatal(&store, err)) orelse current;
            state = refresh(ctx, &store, executor, session, current);
        }
        const timed_out = state.status == .running;
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{
                .ok = true,
                .server = server_name,
                .job = current.name,
                .status = @tagName(state.status),
                .exitCode = state.exit_code,
                .businessResult = state.business_result,
                .timedOut = timed_out,
                .polls = polls,
            }),
            .human => {
                if (timed_out)
                    try ctx.out.print("job '{s}' still running after {d} polls\n", .{ current.name, polls })
                else {
                    try ctx.out.print("job '{s}' {t} (exit={?d})", .{ current.name, state.status, state.exit_code });
                    if (state.business_result) |br| try ctx.out.print(" result={s}", .{br});
                    try ctx.out.print("\n", .{});
                }
            },
        }
        if (state.status == .exited) {
            if (state.exit_code) |code| if (code != 0) {
                try ctx.out.flush();
                std.process.exit(@intCast(std.math.clamp(code, 1, 255)));
            };
        }
    } else if (std.mem.eql(u8, verb, "kill")) {
        Tmux.kill(executor, ctx.arena, session) catch |err| fatalTmux(err, executor, session);
        if (job.status == .running) {
            Store.jobs.markFinished(&store, job.id, .killed, null, ctx.now) catch |err|
                Cli.storeFatal(&store, err);
        }
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .action = "killed", .job = job.name }),
            .human => try ctx.out.print("killed job '{s}'\n", .{job.name}),
        }
    } else if (std.mem.eql(u8, verb, "rm")) {
        Tmux.kill(executor, ctx.arena, session) catch {};
        _ = Store.jobs.remove(&store, resolved.server.id, job_name) catch |err| Cli.storeFatal(&store, err);
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .action = "removed", .job = job.name }),
            .human => try ctx.out.print("removed job '{s}'\n", .{job.name}),
        }
    } else {
        fatal("unknown verb 'job {s}'\n{s}", .{ verb, job_usage });
    }
}

const State = struct {
    status: Store.jobs.Status,
    exit_code: ?i64,
    finished_at: ?i64,
    business_result: ?[]const u8 = null,
};

/// One SSH probe from the stored cursor; persists any completion it sees.
fn refresh(ctx: *Cli.Ctx, store: *Store, executor: Core.Executor, session: []const u8, job: Store.jobs.Job) State {
    if (job.status != .running)
        return .{ .status = job.status, .exit_code = job.exit_code, .finished_at = job.finished_at };
    const probe = Tmux.probeJob(executor, ctx.arena, session, job.sentinel, job.read_cursor, 1 << 20) catch |err|
        fatalTmux(err, executor, session);
    return applyProbe(ctx, store, job, probe);
}

fn applyProbe(ctx: *Cli.Ctx, store: *Store, job: Store.jobs.Job, probe: Tmux.JobProbe) State {
    if (job.status != .running)
        return .{ .status = job.status, .exit_code = job.exit_code, .finished_at = job.finished_at, .business_result = probe.business_result };
    if (probe.exit_code) |code| {
        Store.jobs.markFinished(store, job.id, .exited, code, ctx.now) catch |err| Cli.storeFatal(store, err);
        return .{ .status = .exited, .exit_code = code, .finished_at = ctx.now, .business_result = probe.business_result };
    }
    if (!probe.session_alive) {
        // Session gone without a sentinel: killed externally or crashed.
        Store.jobs.markFinished(store, job.id, .killed, null, ctx.now) catch |err| Cli.storeFatal(store, err);
        return .{ .status = .killed, .exit_code = null, .finished_at = ctx.now, .business_result = probe.business_result };
    }
    return .{ .status = .running, .exit_code = null, .finished_at = null, .business_result = probe.business_result };
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
    const ns = value * unit_ns;
    return std.math.clamp(ns, std.time.ns_per_s, std.time.ns_per_hour);
}
