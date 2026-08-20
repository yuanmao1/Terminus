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

/// `pub` so a gate can hold the flags the document publishes against the ones
/// `--help` prints.
pub const usage =
    \\usage: terminus exec <server>[:<session>] [--json] [--timeout <sec>] [--login]
    \\                    [--strict] [--interpreter <bin>] <command input>
    \\
    \\command input, most quote-proof first:
    \\  --stdin              read the command/script from standard input
    \\  --cmd-file <path>    run a local script file's contents remotely
    \\  --cmd "<command>"    a single flag value (survives PowerShell)
    \\  -- <command...>      everything after --
    \\
    \\Line endings in the command are sent as they were read. --normalize-lf
    \\converts CRLF/CR to LF; without it a carriage return is reported and kept.
    \\
    \\input for the command itself (a different channel from the ones above):
    \\  --stdin-file <path>  stream a local file to the remote command's stdin,
    \\                       byte for byte, at any size. The receipt records how
    \\                       many bytes the channel accepted and their SHA-256.
    \\                       Never normalized: those bytes are data.
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
    // Read straight after the command was, because the next call to
    // `trailingContent` anywhere would replace it.
    const line_endings = Cli.commandLineEndings();
    const timeout_ms: i64 = 1000 * (if (parsed.flag("timeout")) |t|
        std.fmt.parseInt(i64, t, 10) catch fatal("invalid --timeout '{s}'", .{t})
    else
        120);

    // The command's standard input, opened before anything is recorded and
    // before anything is dialled: a source that cannot be read has sent
    // nothing, and discovering that after the ledger row exists would file an
    // attempt that provably never reached a host.
    //
    // Streamed, never held: the window below is the whole of this command's
    // input memory and a 40 GiB source uses exactly as much of it as a 40 KiB
    // one.
    var input_reader: ?std.Io.File.Reader = null;
    if (parsed.flag("stdin-file")) |path| {
        if (target.session != null) fatal(
            "--stdin-file feeds a one-shot exec channel; a '<server>:<session>' target types into a live shell, which has no separate input channel. Drop the ':{s}' or send the file with 'terminus push'",
            .{target.session.?},
        );
        const file = std.Io.Dir.cwd().openFile(ctx.io, path, .{}) catch
            fatal("cannot read --stdin-file {s}", .{path});
        input_reader = file.reader(ctx.io, try ctx.arena.alloc(u8, Core.Ssh.chunk_bytes));
    }
    defer if (input_reader) |*r| r.file.close(ctx.io);
    const input: ?*std.Io.Reader = if (input_reader) |*r| &r.interface else null;
    // What the channel accepted, and the digest of exactly those bytes. Filled
    // by the run whether it succeeds or fails, and reported both to the ledger
    // and to the caller.
    var accepted: Core.Ssh.Accepted = .{};

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
    // Held in a named value because a blocked run asks a second time, after
    // trying to settle the blocker from evidence on the host.
    const begin_opts: Core.execution.BeginOptions = .{
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
    };
    const start = Core.execution.begin(&store, ctx.arena, ctx.io, begin_opts) catch |err|
        Cli.storeFatal(&store, err);

    // One connection for the whole command. A blocked run needs it before the
    // execution exists, so that a blocker which has already finished can be
    // read rather than guessed at; every other path needs it just after.
    var conn_slot: ?Cli.Connection = null;
    defer if (conn_slot) |*c| c.deinit();

    var execution = switch (start) {
        .ready => |e| e,
        // Worth one connection before refusing, but only when there is
        // something to go and read. `begin` inserts nothing when it blocks, so
        // asking again after settling the blocker leaks no operation row.
        //
        // An unreachable host is not an answer here: the refusal we already
        // hold is the more useful one, and "cannot connect" in its place would
        // hide the fact that nothing was sent.
        .blocked => |blocker| retry: {
            if (!Cli.blockerMayBeProvable(blocker)) reportBlocked(blocker);
            conn_slot = Cli.tryConnect(ctx, &parsed, resolved.server, resolved.auth) orelse
                reportBlocked(blocker);
            Cli.settleProvableBlocker(ctx, &store, conn_slot.?.executor(), blocker);
            const second = Core.execution.begin(&store, ctx.arena, ctx.io, begin_opts) catch |err|
                Cli.storeFatal(&store, err);
            break :retry switch (second) {
                .ready => |e| e,
                .blocked => |still| reportBlocked(still),
            };
        },
    };
    Cli.registerExecution(&execution);
    defer {
        Cli.clearExecution();
        execution.deinit();
    }

    const started = std.Io.Timestamp.now(ctx.io, .awake);
    execution.connecting() catch |err| Cli.receiptFatal(execution.id(), err, "created");

    if (conn_slot == null) conn_slot = Cli.connect(ctx, &parsed, resolved.server, resolved.auth);
    var conn = &conn_slot.?;
    const executor = conn.executor();

    // The guard waved this launch through while something else still holds an
    // overlapping scope (`--force`, or read-only work). If that something is a
    // job which already finished, read its exit status now. Opportunistic and
    // one-way: it can only settle a blocker whose evidence is sitting on the
    // host, and the authoritative check inside `submitted()` runs regardless.
    //
    // The blocked path above already handled its own blocker; this covers the
    // launches `begin` let through while still reporting one, where `advisory`
    // is the only place that blocker surfaces.
    Cli.settleProvableBlocker(ctx, &store, executor, execution.advisory);

    const outcome = if (target.session) |session_name|
        try runInSession(ctx, &store, &execution, executor, &parsed, session_name, raw_command, timeout_ms)
    else
        try runOneShot(ctx, &execution, executor, &parsed, raw_command, resolved.server.cwd, input, &accepted);

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
            // What went in, from the channel's own answer rather than from the
            // source's length. Null when no input was named, which is a
            // different fact from a zero-byte input.
            .stdinBytes = if (input == null) null else @as(?i64, @intCast(accepted.bytes)),
            .stdinSha256 = if (input == null) null else @as(?[]const u8, accepted.sha256[0..]),
            // The command text's line endings, as read. 0.2.0 sends them
            // unchanged, so an agent that needs LF asks for it and can see
            // whether it got it.
            .commandCarriageReturns = line_endings.carriage_returns,
            .commandNormalizedLf = line_endings.normalized,
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
    input: ?*std.Io.Reader,
    accepted: *Core.Ssh.Accepted,
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

    // A transport with no input channel is refused before the guard binds, so
    // the refusal is one where nothing was sent. `Cli.connect` already takes a
    // direct connection when `--stdin-file` is named, so reaching this means
    // the transport changed under us.
    if (input != null and !executor.carriesInput()) fatal(
        "this transport has no channel for --stdin-file input; nothing was sent. Re-run with --no-daemon",
        .{},
    );

    const result = Core.execution.runCommand(
        execution,
        executor,
        effective,
        if (input) |source| .{ .source = source, .accepted = accepted } else null,
    ) catch |err|
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
            "request {s} (on {s}) holds a lease on an overlapping scope until {d}",
            .{ lease.owner_request_id, lease.profile_token, lease.expires_at },
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
            "refused: request {s} (on {s}) holds a lease on an overlapping scope until {d}; nothing was sent. Wait, take it over, or pass --force",
            .{ lease.owner_request_id, lease.profile_token, lease.expires_at },
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

test {
    _ = @import("cmd_exec_test.zig");
}
