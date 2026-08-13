//! `terminus exec <server>[:<session>] -- <cmd...>` — synchronous remote
//! execution over SSH.
//!
//! Plain server target: one-shot exec channel (no state carried over).
//! Session target: runs inside the remote tmux session's shell, inheriting
//! its cwd/env/history, and advances the session's read cursor past the
//! command's output.
//!
//! Both paths run under `Core.execution`, which owns operation identity, the
//! scope guard, state transitions and the terminal receipt. Nothing here
//! decides what a dropped connection meant — that judgement belongs to one
//! function, and this command only reports it. In particular a local timeout
//! is `indeterminate`, not a failure: the remote command is very likely
//! still running, and an agent that retries on "failed" would run it twice.
const std = @import("std");
const fatal = Cli.fail;
const Cli = @import("cli.zig");
const Core = @import("../core/core.zig");
const Store = Core.Store;
const Tmux = Core.Tmux;

const usage =
    \\usage: terminus exec <server>[:<session>] [--json] [--timeout <sec>] [--login]
    \\                    [--strict] [--interpreter <bin>] <command input>
    \\
    \\command input, most quote-proof first:
    \\  --stdin              read the command/script from standard input
    \\  --cmd-file <path>    run a local script file's contents remotely
    \\  --cmd "<command>"    a single flag value (survives PowerShell)
    \\  -- <command...>      everything after --
    \\
    \\Multiline input runs as a staged remote script (byte-exact: heredocs,
    \\quoting, and error line numbers all work). Flags for script mode:
    \\  --strict             set -euo pipefail: first failing line stops the
    \\                       script and becomes the exit code
    \\  --interpreter <bin>  run with e.g. python3 instead of bash
    \\--login wraps execution in `bash -ilc` for the full user PATH
    \\(nvm/bun/pm2 live in profile files that plain SSH exec skips).
    \\
    \\Exit codes: the remote command's own code, or 75 when the outcome could
    \\not be established (never retry blindly on 75 — reconcile first).
    \\
;

pub fn run(ctx: *Cli.Ctx, raw_args: []const []const u8) !void {
    const parsed = Cli.parseArgs(ctx, raw_args);
    if (parsed.boolean("json")) ctx.out.format = .json;

    const target = Cli.Target.parse(parsed.positional(0) orelse fatal("{s}", .{usage}));
    const raw_command = (try Cli.trailingContent(ctx, &parsed, "cmd-file", 1)) orelse
        fatal("no remote command given\n{s}", .{usage});
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

    const owner_token = Store.policy.ownerToken(&store, ctx.arena, ctx.io, ctx.now) catch |err|
        Cli.storeFatal(&store, err);

    // An arbitrary shell command is assumed to change things.
    //
    // We cannot inspect `systemctl restart api` and know what it touches, and
    // the cost of the two mistakes is not symmetric: wrongly treating a read
    // as a mutation costs a refusal the caller can override, while wrongly
    // treating a mutation as a read can apply a change twice. `--read-only`
    // declares the safe case explicitly.
    const start = Core.execution.begin(&store, ctx.arena, ctx.io, .{
        .server_id = resolved.server.id,
        .server_name = resolved.server.name,
        .kind = .exec,
        .scope = if (target.session) |name|
            .{ .kind = .job, .key = name }
        else
            .{ .kind = .server },
        .alias = target.session,
        .mutating = !parsed.boolean("read-only"),
        .argv_redacted = Store.history.redactSecrets(ctx.arena, raw_command) catch
            // Falling back to the raw text would write the very secrets the
            // redaction exists to keep out of an append-only ledger.
            fatal("cannot redact the command for the audit record; refusing to store it unredacted", .{}),
        .cwd = parsed.flag("cwd") orelse resolved.server.cwd,
        .shell = if (parsed.boolean("login")) "bash-login" else "bash",
        .owner_token = owner_token,
        .force = parsed.boolean("force"),
        .now = ctx.now,
    }) catch |err| Cli.storeFatal(&store, err);

    var execution = switch (start) {
        .ready => |e| e,
        .blocked => |blocker| reportBlocked(blocker),
    };
    Cli.registerExecution(&execution);
    defer {
        Cli.clearExecution();
        execution.deinit();
    }

    const started = std.Io.Timestamp.now(ctx.io, .awake);
    execution.connecting() catch |err| Cli.receiptFatal(execution.id(), err, "created");

    var conn = Cli.connect(ctx, &parsed, resolved.server, resolved.auth);
    defer conn.deinit();
    const executor = conn.executor();

    const outcome = if (target.session) |session_name|
        try runInSession(ctx, &store, &execution, executor, &parsed, session_name, raw_command, timeout_ms)
    else
        try runOneShot(ctx, &execution, executor, &parsed, raw_command, resolved.server.cwd);

    const duration_ms: i64 = @intCast(@divTrunc(
        started.durationTo(std.Io.Timestamp.now(ctx.io, .awake)).nanoseconds,
        std.time.ns_per_ms,
    ));

    const capability_json = execution.capability.toJson(ctx.arena) catch null;

    switch (ctx.out.format) {
        .json => try ctx.out.json(.{
            .ok = outcome.status != .indeterminate,
            .requestId = execution.id(),
            .status = outcome.status.text(),
            .server = resolved.server.name,
            .session = target.session,
            .command = raw_command,
            .exitCode = outcome.exit_code,
            .stdout = outcome.stdout,
            .stderr = outcome.stderr,
            .durationMs = duration_ms,
            .transport = conn.transport,
            .daemonError = conn.daemon_error,
            .capability = capability_json,
            .runningAlongside = advisoryText(ctx, execution.advisory),
            .memoryKeys = memory_keys,
        }),
        .human => {
            try ctx.out.print("{s}", .{outcome.stdout});
            if (outcome.stderr.len != 0) std.debug.print("{s}", .{outcome.stderr});
            if (advisoryText(ctx, execution.advisory)) |note|
                std.debug.print("note: {s}\n", .{note});
            if (outcome.exit_code) |code| {
                if (code != 0) std.debug.print("(exit {d})\n", .{code});
            }
        },
    }

    // An unknown outcome gets its own exit code so it can never be mistaken
    // for a plain failure and retried.
    if (outcome.status == .indeterminate) {
        try ctx.out.flush();
        Cli.failIndeterminateAfterOutput(execution.id());
    }
    if (outcome.exit_code) |code| {
        if (code != 0) {
            try ctx.out.flush();
            std.process.exit(@intCast(std.math.clamp(code, 1, 255)));
        }
    }
}

const Outcome = Core.execution.RunOutcome;

/// One-shot exec on a plain server target.
fn runOneShot(
    ctx: *Cli.Ctx,
    execution: *Core.execution.Execution,
    executor: Core.Executor,
    parsed: *const Cli.Args.Parsed,
    raw_command: []const u8,
    server_cwd: ?[]const u8,
) !Outcome {
    var command = raw_command;
    var staged_path: ?[]const u8 = null;

    // Staging happens before submission: it is setup, and a failure there
    // provably never ran the user's command.
    const wants_script = Core.script.shouldStage(raw_command) or parsed.flag("interpreter") != null;
    if (wants_script) {
        const nonce: u64 = @intCast(@mod(std.Io.Timestamp.now(ctx.io, .real).nanoseconds, 1_000_000_000_000));
        const staged = Core.script.stage(executor, ctx.arena, raw_command, .{
            .interpreter = parsed.flag("interpreter") orelse "bash",
            .strict = parsed.boolean("strict"),
            .login = parsed.boolean("login"),
        }, nonce) catch |err| switch (err) {
            error.ScriptTooLarge => fatal("script exceeds {d} KiB; push it as a file and exec it instead", .{Core.script.max_inline_script / 1024}),
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
    defer if (staged_path) |path| Core.script.cleanup(executor, ctx.arena, path);

    const effective = if (parsed.flag("cwd") orelse server_cwd) |dir|
        try std.fmt.allocPrint(ctx.arena, "cd {s} && ({s})", .{ dir, command })
    else
        command;

    const result = Core.execution.runCommand(execution, executor, effective) catch |err|
        // The command may well have run; what failed is our record of it.
        Cli.receiptFatal(execution.id(), err, execution.status.text());

    const outcome = switch (result) {
        .ran => |o| o,
        .refused => |blocker| reportBlocked(blocker),
    };

    return .{
        .status = outcome.status,
        .exit_code = outcome.exit_code,
        .stdout = outcome.stdout,
        .stderr = if (parsed.boolean("login"))
            try Cli.stripLoginNoise(ctx.arena, outcome.stderr)
        else
            outcome.stderr,
        .identity = outcome.identity,
    };
}

/// Exec inside a persistent tmux session.
///
/// The session shell already exists, so identity comes from the session
/// rather than a supervisor wrapper. What matters here is the timeout: a
/// local deadline expiring says nothing about the remote command, which is
/// still running in the session — reporting that as a failure (as this
/// command used to) invites a retry that runs the work twice.
fn runInSession(
    ctx: *Cli.Ctx,
    store: *Store,
    execution: *Core.execution.Execution,
    executor: Core.Executor,
    parsed: *const Cli.Args.Parsed,
    session_name: []const u8,
    raw_command: []const u8,
    timeout_ms: i64,
) !Outcome {
    const session_id = Store.sessions.ensure(store, execution.server_id.?, session_name, ctx.now) catch |err|
        Cli.storeFatal(store, err);
    Tmux.ensure(executor, ctx.arena, session_name) catch |err|
        fatalTmux(err, executor, session_name);

    var command = raw_command;
    if (Core.script.shouldStage(raw_command) or parsed.flag("interpreter") != null) {
        const nonce: u64 = @intCast(@mod(std.Io.Timestamp.now(ctx.io, .real).nanoseconds, 1_000_000_000_000));
        const staged = Core.script.stage(executor, ctx.arena, raw_command, .{
            .interpreter = parsed.flag("interpreter") orelse "bash",
            .strict = parsed.boolean("strict"),
            .login = parsed.boolean("login"),
        }, nonce) catch fatal("could not stage the script on the remote host", .{});
        command = staged.command;
    } else if (parsed.boolean("strict")) {
        command = try std.fmt.allocPrint(ctx.arena, "set -euo pipefail; {s}", .{raw_command});
    }

    const cursor = Store.sessions.cursor(store, session_id) catch |err| Cli.storeFatal(store, err);

    // Keys are about to be typed into a live shell: from here the remote may
    // act, so the attempt is submitted — and the scope guard gets its binding
    // say, because this is the last moment at which nothing has happened yet.
    switch (execution.submitted() catch |err| Cli.receiptFatal(execution.id(), err, "about to submit")) {
        .submitted => {},
        .refused => |blocker| reportBlocked(blocker),
    }

    const result = Tmux.execIn(executor, ctx.arena, ctx.io, session_name, command, cursor, timeout_ms) catch |err| {
        const settled = switch (err) {
            // The command is still running in the session. We do not know
            // how it will end, and must not say that it failed.
            error.CommandTimeout => execution.settle(.{ .indeterminate = .{
                .reason = "local timeout expired; the command is still running in the session",
                .last_observed = execution.status,
            } }, .{}),
            // The shell died mid-command: it may have completed first.
            error.SessionDied => execution.settle(.{ .indeterminate = .{
                .reason = "session ended while the command was running",
                .last_observed = execution.status,
            } }, .{}),
            else => execution.transportLoss(executor.errorMessage()),
        } catch |settle_err| Cli.receiptFatal(execution.id(), settle_err, execution.status.text());
        _ = settled;
        return .{
            .status = execution.status,
            .exit_code = null,
            .stdout = "",
            .stderr = "",
            .identity = null,
        };
    };

    // Terminal receipt first, derived state second.
    //
    // The cursor is a convenience: it remembers where this session's reader
    // got to. The receipt is the record that the command ran and how it
    // ended. Writing the cursor first meant a failure there took the whole
    // command down through `storeFatal` — exit 1, "database error" — for an
    // exec whose exit status we were holding in our hand. Losing a cursor
    // costs a re-read; losing the terminal costs the outcome.
    _ = execution.settle(.{ .exited = .{ .exit_code = result.exit_code } }, .{
        .stdout = .{ .bytes = @intCast(result.output.len) },
    }) catch |err| Cli.receiptFatal(execution.id(), err, "remote reported an exit status");

    Store.sessions.setCursor(store, session_id, result.next_cursor, ctx.now) catch |err| {
        // Reported, not fatal, and explicitly not swallowed: the next
        // `--from-cursor` read will start further back and repeat output.
        std.debug.print(
            "terminus: could not advance the read cursor for session '{s}': {s}; " ++
                "the next cursor read will repeat this command's output\n",
            .{ session_name, @errorName(err) },
        );
    };

    return .{
        .status = execution.status,
        .exit_code = result.exit_code,
        .stdout = result.output, // tmux merges the two streams in the pane
        .stderr = "",
        .identity = null,
    };
}

fn advisoryText(ctx: *Cli.Ctx, advisory: ?Core.execution.Blocker) ?[]const u8 {
    const blocker = advisory orelse return null;
    return switch (blocker) {
        .unsettled => |op| std.fmt.allocPrint(
            ctx.arena,
            "request {s} ({s}) is unsettled on an overlapping scope; reconcile it before changing anything",
            .{ op.request_id, op.status.text() },
        ) catch null,
        .lease => |lease| std.fmt.allocPrint(
            ctx.arena,
            "{s} holds a lease on an overlapping scope until {d}",
            .{ lease.owner_token, lease.expires_at },
        ) catch null,
    };
}

/// Refuses an attempt that another claim on the same scope makes unsafe.
///
/// Reachable from two places — `begin` (before we dial) and `submitted` (the
/// point of no return). Both mean the same thing to the caller: nothing was
/// sent, so retrying after reconciling is safe.
fn reportBlocked(blocker: Core.execution.Blocker) noreturn {
    switch (blocker) {
        .unsettled => |op| fatal(
            "refused: request {s} is {s} on an overlapping scope, so this change could be applied twice; nothing was sent. Reconcile it ('terminus request reconcile {s}') or pass --force",
            .{ op.request_id, op.status.text(), op.request_id },
        ),
        .lease => |lease| fatal(
            "refused: {s} holds a lease on an overlapping scope until {d}; nothing was sent. Wait, take it over, or pass --force",
            .{ lease.owner_token, lease.expires_at },
        ),
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
