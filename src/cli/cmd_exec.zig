//! `terminus exec <server>[:<session>] -- <cmd...>` — synchronous remote
//! execution over SSH.
//!
//! Plain server target: one-shot exec channel (no state carried over).
//! Session target: runs inside the remote tmux session's shell, inheriting
//! its cwd/env/history, and advances the session's read cursor past the
//! command's output.
//!
//! The remote exit code becomes this process's exit code, so agents can
//! rely on it in both output formats.
const std = @import("std");
const fatal = Cli.fail;
const Cli = @import("cli.zig");
const Core = @import("../core/core.zig");
const Store = Core.Store;
const Tmux = Core.Tmux;

const usage =
    \\usage: terminus exec <server>[:<session>] [--json] [--timeout <sec>] [--login] <command input>
    \\
    \\command input, most quote-proof first:
    \\  --stdin              read the command/script from standard input
    \\  --cmd-file <path>    run a local script file's contents remotely
    \\  --cmd "<command>"    a single flag value (survives PowerShell)
    \\  -- <command...>      everything after --
    \\
    \\--login wraps the command in `bash -lc` so it sees the user's full
    \\PATH (nvm/bun/pm2 live in profile files that plain SSH exec skips).
    \\
;

pub fn run(ctx: *Cli.Ctx, raw_args: []const []const u8) !void {
    const parsed = Cli.parseArgs(ctx, raw_args);
    if (parsed.boolean("json")) ctx.out.format = .json;

    const target = Cli.Target.parse(parsed.positional(0) orelse fatal("{s}", .{usage}));
    var command = (try Cli.trailingContent(ctx, &parsed, "cmd-file", 1)) orelse
        fatal("no remote command given\n{s}", .{usage});
    if (parsed.boolean("login")) command = try Cli.loginWrap(ctx.arena, command);
    const timeout_ms: i64 = 1000 * (if (parsed.flag("timeout")) |t|
        std.fmt.parseInt(i64, t, 10) catch fatal("invalid --timeout '{s}'", .{t})
    else
        120);

    var store = try Cli.openStore(ctx, &parsed);
    defer store.close();
    const resolved = Cli.resolveServer(ctx, &store, target.server);
    // Recall hint: every JSON exec response carries the server's memory
    // keys (a local, zero-network query) so agents see what knowledge
    // exists before they re-discover it over SSH.
    const memory_keys = Store.memories.keys(&store, ctx.arena, resolved.server.id) catch |err|
        Cli.storeFatal(&store, err);

    const started = std.Io.Timestamp.now(ctx.io, .awake);
    var conn = Cli.connect(ctx, &parsed, resolved.server, resolved.auth);
    defer conn.deinit();
    const executor = conn.executor();

    var exit_code: i32 = undefined;
    var stdout_text: []const u8 = undefined;
    var stderr_text: []const u8 = "";

    if (target.session) |session_name| {
        const session_id = Store.sessions.ensure(&store, resolved.server.id, session_name, ctx.now) catch |err|
            Cli.storeFatal(&store, err);
        Tmux.ensure(executor, ctx.arena, session_name) catch |err|
            fatalTmux(err, executor, session_name);
        const cursor = Store.sessions.cursor(&store, session_id) catch |err| Cli.storeFatal(&store, err);
        const result = Tmux.execIn(executor, ctx.arena, ctx.io, session_name, command, cursor, timeout_ms) catch |err|
            fatalTmux(err, executor, session_name);
        Store.sessions.setCursor(&store, session_id, result.next_cursor, ctx.now) catch |err|
            Cli.storeFatal(&store, err);
        exit_code = result.exit_code;
        stdout_text = result.output; // tmux merges the two streams in the pane
    } else {
        // Workspace: plain exec runs in the server's default cwd when one
        // is set (session targets keep their own live cwd instead).
        const effective = if (parsed.flag("cwd") orelse resolved.server.cwd) |dir|
            try std.fmt.allocPrint(ctx.arena, "cd {s} && ({s})", .{ dir, command })
        else
            command;
        const result = executor.exec(ctx.arena, effective) catch |err|
            fatal("exec failed: {s} ({s})", .{ executor.errorMessage(), @errorName(err) });
        exit_code = result.exit_code;
        stdout_text = result.stdout;
        stderr_text = if (parsed.boolean("login"))
            try Cli.stripLoginNoise(ctx.arena, result.stderr)
        else
            result.stderr;
    }

    const duration_ms: i64 = @intCast(@divTrunc(
        started.durationTo(std.Io.Timestamp.now(ctx.io, .awake)).nanoseconds,
        std.time.ns_per_ms,
    ));

    Store.history.add(&store, resolved.server.id, .{
        .kind = "exec",
        .detail = command,
        .cwd = if (target.session == null) parsed.flag("cwd") orelse resolved.server.cwd else target.session,
        .exit_code = exit_code,
        .transport = conn.transport,
        .duration_ms = duration_ms,
    }, ctx.now) catch {};

    switch (ctx.out.format) {
        .json => try ctx.out.json(.{
            .ok = true,
            .server = resolved.server.name,
            .session = target.session,
            .command = command,
            .exitCode = exit_code,
            .stdout = stdout_text,
            .stderr = stderr_text,
            .durationMs = duration_ms,
            .transport = conn.transport,
            .daemonError = conn.daemon_error,
            .memoryKeys = memory_keys,
        }),
        .human => {
            try ctx.out.print("{s}", .{stdout_text});
            if (stderr_text.len != 0) std.debug.print("{s}", .{stderr_text});
            if (exit_code != 0) std.debug.print("(exit {d})\n", .{exit_code});
        },
    }

    if (exit_code != 0) {
        try ctx.out.flush();
        std.process.exit(@intCast(std.math.clamp(exit_code, 1, 255)));
    }
}

pub fn fatalTmux(err: anyerror, executor: Core.Executor, session_name: []const u8) noreturn {
    switch (err) {
        error.TmuxMissing => fatal("tmux is not installed on the remote server; use plain 'terminus exec <server> -- <cmd>' (no :session) which needs no tmux", .{}),
        error.SessionNotFound => fatal("session '{s}' does not exist on the remote server; create it with 'terminus session new'", .{session_name}),
        error.SessionDied => fatal("session '{s}' ended while the command was running (did it call 'exit'?)", .{session_name}),
        error.CommandTimeout => fatal("command still running in session '{s}'; read later output with 'terminus read'", .{session_name}),
        else => fatal("remote tmux operation failed: {s} ({s})", .{ executor.errorMessage(), @errorName(err) }),
    }
}
