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
    \\usage: terminus run <server> --name <job-name> [--cwd <dir>] [--json] -- <cmd...>
    \\
;
const job_usage =
    \\usage: terminus job <verb> <server> [<name>] [...]
    \\
    \\  job ls     <server> [--json]
    \\  job status <server> <name> [--json]     probe: running? exit code?
    \\  job read   <server> <name> [--from-cursor] [--limit BYTES] [--json]
    \\  job kill   <server> <name>               terminate the job's session
    \\  job rm     <server> <name>               forget the job (kills if running)
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
    const rest = parsed.rest orelse fatal("the command goes after '--'\n{s}", .{run_usage});
    if (rest.len == 0) fatal("empty command", .{});
    const command = try std.mem.join(ctx.arena, " ", rest);

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

    // Optional cwd: job-level --cwd wins over the server workspace.
    const cwd = parsed.flag("cwd") orelse resolved.server.cwd;
    const full = if (cwd) |dir|
        try std.fmt.allocPrint(ctx.arena, "cd {s} && ({s}); echo {s}:$?", .{ dir, command, sentinel })
    else
        try std.fmt.allocPrint(ctx.arena, "({s}); echo {s}:$?", .{ command, sentinel });
    Tmux.sendKeys(executor, ctx.arena, session, full, false) catch |err| fatalTmux(err, executor, session);

    _ = Store.jobs.create(&store, resolved.server.id, job_name, command, sentinel, ctx.now) catch |err| switch (err) {
        error.NameTaken => fatal("job '{s}' already exists", .{job_name}),
        else => Cli.storeFatal(&store, err),
    };

    Store.history.add(&store, resolved.server.id, .{
        .kind = "job",
        .detail = try std.fmt.allocPrint(ctx.arena, "start '{s}': {s}", .{ job_name, command }),
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
        const list = Store.jobs.list(&store, ctx.arena, resolved.server.id) catch |err|
            Cli.storeFatal(&store, err);
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .server = server_name, .jobs = list }),
            .human => {
                if (list.len == 0) return ctx.out.print("no jobs on '{s}'\n", .{server_name});
                for (list) |j| {
                    try ctx.out.print("{s}  {t}  exit={?d}  cmd: {s}\n", .{ j.name, j.status, j.exit_code, j.command });
                }
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
                .command = job.command,
                .createdAt = job.created_at,
                .finishedAt = state.finished_at,
                .transport = conn.transport,
                .daemonError = conn.daemon_error,
            }),
            .human => try ctx.out.print("job '{s}': {t} (exit={?d})\n", .{ job.name, state.status, state.exit_code }),
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
                .from = from,
                .to = probe.next_cursor,
                .data = probe.output,
            }),
            .human => try ctx.out.print("{s}", .{probe.output}),
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
        return .{ .status = job.status, .exit_code = job.exit_code, .finished_at = job.finished_at };
    if (probe.exit_code) |code| {
        Store.jobs.markFinished(store, job.id, .exited, code, ctx.now) catch |err| Cli.storeFatal(store, err);
        return .{ .status = .exited, .exit_code = code, .finished_at = ctx.now };
    }
    if (!probe.session_alive) {
        // Session gone without a sentinel: killed externally or crashed.
        Store.jobs.markFinished(store, job.id, .killed, null, ctx.now) catch |err| Cli.storeFatal(store, err);
        return .{ .status = .killed, .exit_code = null, .finished_at = ctx.now };
    }
    return .{ .status = .running, .exit_code = null, .finished_at = null };
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
