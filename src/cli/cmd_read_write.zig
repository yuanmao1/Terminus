//! `terminus read` / `terminus write` — cursor-based session output
//! reading and input typed into a live shell.
//!
//! `read --from-cursor` returns output since the stored cursor and
//! advances it. `--cursor N` reads from an explicit offset (does not move
//! the stored cursor). Default shows the last `--lines N` (default 50)
//! without moving the cursor, mirroring "peek at the terminal".
//!
//! `write` runs under `Core.execution`, like every other verb that can change
//! a remote host: it takes an operation id, observes the scope barrier, and
//! records a terminal receipt. What that receipt says is the whole subtlety of
//! this command. Typing into somebody else's shell establishes exactly one
//! thing — the terminal took the bytes — and nothing whatever about what the
//! shell then did with them. There is no exit status to record, so none is
//! recorded (`op_state.Terminal.input_accepted`), and every line of output
//! below is worded so that a reader cannot mistake "delivered" for "worked".
const std = @import("std");
const fatal = Cli.fail;
const Cli = @import("cli.zig");
const Core = @import("../core/core.zig");
const Store = Core.Store;
const Tmux = Core.Tmux;
const fatalTmux = @import("cmd_exec.zig").fatalTmux;

const read_usage =
    \\usage: terminus read <server>:<session> [--from-cursor | --cursor N] [--lines N] [--limit BYTES] [--raw] [--json]
    \\
;
const write_usage =
    \\usage: terminus write <server>:<session> [--no-enter] [--force] [--json] -- <input...>
    \\       (if your shell eats '--', use: terminus write <target> --cmd "<input>")
    \\
    \\A successful write means the terminal accepted the bytes. It does not
    \\mean the input ran, parsed, or succeeded — read the session to find out.
    \\
;

const Verb = enum { read, write };

pub fn run(ctx: *Cli.Ctx, verb: Verb, raw_args: []const []const u8) !void {
    const parsed = Cli.parseArgs(ctx, raw_args);
    if (parsed.boolean("json")) ctx.out.format = .json;

    const spec = parsed.positional(0) orelse fatal("{s}", .{if (verb == .read) read_usage else write_usage});
    const target = Cli.Target.parse(spec);
    const session_name = target.session orelse fatal("target must be <server>:<session>", .{});

    var store = try Cli.openStore(ctx, &parsed);
    defer store.close();
    const resolved = Cli.resolveServer(ctx, &store, target.server);
    const session_id = (Store.sessions.idByName(&store, resolved.server.id, session_name) catch |err|
        Cli.storeFatal(&store, err)) orelse
        fatal("unknown session '{s}'; create it with 'terminus session new {s} {s}'", .{ spec, target.server, session_name });

    switch (verb) {
        .write => try runWrite(
            ctx,
            &store,
            &parsed,
            resolved.server,
            resolved.auth,
            spec,
            session_name,
            session_id,
        ),
        .read => try runRead(
            ctx,
            &store,
            &parsed,
            resolved.server,
            resolved.auth,
            spec,
            session_name,
            session_id,
        ),
    }
}

/// What the remote said about the bytes we handed it.
///
/// Three answers rather than a bool, because they send the caller three
/// different ways and only one of them is safe to repeat. `unknown` is the
/// one that has to exist: a write whose answer was lost may be sitting in the
/// pane, and a caller told "failed" would type it again.
const Answer = enum { accepted, refused, unknown };

fn runWrite(
    ctx: *Cli.Ctx,
    store: *Store,
    parsed: *const Cli.Args.Parsed,
    server: Store.servers.Server,
    auth: Core.Ssh.Auth,
    spec: []const u8,
    session_name: []const u8,
    session_id: i64,
) !void {
    const input = (try parsed.trailing(ctx.arena, 1)) orelse
        fatal("no input given\n{s}", .{write_usage});
    const digest = try sha256Hex(ctx.arena, input);

    const owner_token = Store.policy.ownerToken(store, ctx.arena, ctx.io, ctx.now) catch |err|
        Cli.storeFatal(store, err);

    // Typing into a live shell is a mutation, unconditionally: we cannot read
    // the operator's input and know what it touches, and there is no
    // `--read-only` for it because a caller who wanted to look would use
    // `read`.
    //
    // The scope is the session, spelled the way `exec <server>:<session>`
    // spells it (cmd_exec.zig:82). That is not a coincidence to be tidied
    // away later — it is what makes a write and a run on the same session see
    // each other, and a write on one session invisible to work on another.
    const start = Core.execution.begin(store, ctx.arena, ctx.io, .{
        .server_id = server.id,
        .server_name = server.name,
        .kind = .session_write,
        .scope = writeScope(session_name),
        .alias = session_name,
        .mutating = true,
        .argv_redacted = Store.history.redactSecrets(ctx.arena, input) catch
            // Storing the raw text would write the very secrets the redaction
            // exists to keep out of an append-only ledger.
            fatal("cannot redact the input for the audit record; refusing to store it unredacted", .{}),
        .argv_sha256 = digest,
        .owner_token = owner_token,
        .force = parsed.boolean("force"),
        .now = ctx.now,
    }) catch |err| Cli.storeFatal(store, err);

    var execution = switch (start) {
        .ready => |e| e,
        .blocked => |blocker| reportBlocked(blocker),
    };
    Cli.registerExecution(&execution);
    defer {
        Cli.clearExecution();
        execution.deinit();
    }

    execution.connecting() catch |err| Cli.receiptFatal(execution.id(), err, "created");

    var conn = Cli.connect(ctx, parsed, server, auth);
    defer conn.deinit();
    const executor = conn.executor();

    // The bytes are about to enter a live shell: from here the remote may act,
    // and this is the last moment at which nothing has happened. The guard
    // binds here rather than at `begin`, for the reason `Execution.submitted`
    // gives — the check and the write that makes this attempt visible to the
    // next caller have to be one step.
    switch (execution.submitted() catch |err| Cli.receiptFatal(execution.id(), err, "about to submit")) {
        .submitted => {},
        .refused => |blocker| reportBlocked(blocker),
    }

    var answer: Answer = .accepted;
    // What the remote or the channel said, for the operator. Never a verdict
    // about the input itself, which nothing here has read.
    var detail: []const u8 = "the terminal accepted the bytes; nothing here says whether the input ran";

    if (Tmux.sendKeys(executor, ctx.arena, session_name, input, parsed.boolean("no-enter"))) |_| {
        // The one fact this operation has: the terminal took exactly these
        // bytes. It goes on the receipt as the input stream's size and digest,
        // and no exit status goes anywhere near it.
        _ = execution.settle(.{ .input_accepted = .{
            .bytes = @intCast(input.len),
            .sha256 = digest,
        } }, .{}) catch |err|
            Cli.receiptFatal(execution.id(), err, "the terminal accepted the input");
    } else |err| switch (err) {
        // tmux checks the session exists before it touches a pane and leaves
        // through the `|| exit 43` on that line when the check fails, so this
        // answer establishes that nothing was typed. A proven failure, and the
        // only one this command can prove.
        //
        // Two causes reach that check — the session is gone, or tmux is not on
        // the host at all — and the remote gives them one exit code, so the
        // message names both rather than picking one and sending an operator
        // to the wrong place.
        error.SessionNotFound => {
            answer = .refused;
            detail = "the remote's 'tmux has-session' check failed — the session is gone, or tmux is not installed — so nothing was typed";
            _ = execution.settle(.{ .input_refused = .{ .reason = detail } }, .{}) catch |e|
                Cli.receiptFatal(execution.id(), e, "the terminal refused the input");
        },
        // The script ran and reported failure — but `Tmux.sendKeys` collapses
        // two different failures into this one error, and they disagree about
        // the thing that matters. Exit 42 is the literal send failing, so
        // nothing was typed; a nonzero from the `Enter` that follows it means
        // the text *did* land and only the newline did not. Reporting `failed`
        // would invite a retry that types those bytes a second time onto the
        // end of the first, so the honest answer while the two are
        // indistinguishable is that we do not know.
        //
        // Separating them means `Tmux.sendKeys` surfacing the script's exit
        // code instead of erasing it, which is a change in a module this
        // command does not own.
        error.RemoteFailed => {
            answer = .unknown;
            detail = "the remote refused to complete the send; the bytes may already be in the pane";
            _ = execution.settle(.{ .indeterminate = .{
                .reason = detail,
                .last_observed = execution.status,
            } }, .{}) catch |e|
                Cli.receiptFatal(execution.id(), e, execution.status.text());
        },
        // The channel, not the remote. `transportLoss` is the only function
        // allowed to decide what that means, and after submission it means
        // `indeterminate`: the keys may have landed before the connection
        // broke.
        else => {
            answer = .unknown;
            detail = "the connection broke while handing the bytes to the terminal; they may already be in the pane";
            _ = execution.transportLoss(Core.execution.describe(executor, err)) catch |e|
                Cli.receiptFatal(execution.id(), e, execution.status.text());
        },
    }

    // Terminal receipt first, derived state second — the same ordering, for
    // the same reason, as `cmd_exec`'s cursor write. `last_seen_at` is a
    // convenience; losing it costs nothing but a stale listing, and taking the
    // whole command down over it would report a database error for a write
    // whose outcome we are holding in our hand.
    //
    // Touched only on acceptance: a session the remote says does not exist was
    // not seen.
    if (answer == .accepted) {
        Store.sessions.touch(store, session_id, ctx.now) catch |err| std.debug.print(
            "terminus: could not record the last-seen time for session '{s}': {s}; " ++
                "the bytes were delivered and the receipt records it\n",
            .{ session_name, @errorName(err) },
        );
    }

    // Computed once: the JSON body reports it as a field and human mode prints
    // it on stderr, and two calls would be two chances for them to disagree.
    const advisory = advisoryText(ctx, execution.advisory);

    switch (ctx.out.format) {
        .json => try ctx.out.json(.{
            .ok = answer == .accepted,
            .requestId = execution.id(),
            .status = execution.status.text(),
            .server = server.name,
            .session = spec,
            // What was accepted, and null when nothing was — never 0, which
            // would be indistinguishable from an empty write that succeeded.
            .acceptedBytes = if (answer == .accepted) @as(?i64, @intCast(input.len)) else null,
            .acceptedSha256 = if (answer == .accepted) @as(?[]const u8, digest) else null,
            .detail = detail,
            // Stated in every response, including the successful one, because
            // this is the field an agent would otherwise infer wrongly from
            // `ok`.
            .proves = "the terminal accepted these bytes; not that the input ran, parsed, or succeeded",
            .runningAlongside = advisory,
            .transport = conn.transport,
            .daemonError = conn.daemon_error,
        }),
        .human => {
            switch (answer) {
                .accepted => try ctx.out.print(
                    "typed {d} bytes into '{s}' — the terminal accepted them; read the session to see what they did\n",
                    .{ input.len, spec },
                ),
                // Printed rather than raised through `fail`, so the request id
                // reaches the operator on every path: a refused write is still
                // a recorded attempt, and reconciling or auditing it needs the
                // id.
                .refused => try ctx.out.print(
                    "refused: {s}\n  request: {s}\n  create the session with 'terminus session new {s} {s}'\n",
                    .{ detail, execution.id(), server.name, session_name },
                ),
                .unknown => try ctx.out.print("{s}\n", .{detail}),
            }
            if (advisory) |note| std.debug.print("note: {s}\n", .{note});
        },
    }

    switch (answer) {
        .accepted => {},
        // Its own exit code, never 1: an agent has to be able to tell "the
        // bytes are not there" from "we do not know whether they are", because
        // only the first is safe to repeat.
        .unknown => {
            try ctx.out.flush();
            Cli.failIndeterminateAfterOutput(execution.id());
        },
        .refused => {
            try ctx.out.flush();
            std.process.exit(Cli.exit_code.failure);
        },
    }
}

fn runRead(
    ctx: *Cli.Ctx,
    store: *Store,
    parsed: *const Cli.Args.Parsed,
    server: Store.servers.Server,
    auth: Core.Ssh.Auth,
    spec: []const u8,
    session_name: []const u8,
    session_id: i64,
) !void {
    var conn = Cli.connect(ctx, parsed, server, auth);
    defer conn.deinit();
    const executor = conn.executor();

    const limit: i64 = if (parsed.flag("limit")) |l|
        std.fmt.parseInt(i64, l, 10) catch fatal("invalid --limit '{s}'", .{l})
    else
        1 << 20;

    var from: i64 = undefined;
    var advance = false;
    if (parsed.boolean("from-cursor")) {
        from = Store.sessions.cursor(store, session_id) catch |err| Cli.storeFatal(store, err);
        advance = true;
    } else if (parsed.flag("cursor")) |c_text| {
        from = std.fmt.parseInt(i64, c_text, 10) catch fatal("invalid --cursor '{s}'", .{c_text});
    } else {
        from = -1; // tail mode, resolved below
    }

    var result: Tmux.ReadResult = undefined;
    if (from >= 0) {
        result = Tmux.readLog(executor, ctx.arena, session_name, from, limit) catch |err|
            fatalTmux(err, executor, session_name);
        // Remote log shrank (rotated/删除): restart from the top
        // rather than returning silence forever.
        if (result.log_size < from) {
            result = Tmux.readLog(executor, ctx.arena, session_name, 0, limit) catch |err|
                fatalTmux(err, executor, session_name);
            from = 0;
        }
    } else {
        // Tail mode: read the last chunk and keep the final N lines.
        const lines: usize = if (parsed.flag("lines")) |l|
            std.fmt.parseInt(usize, l, 10) catch fatal("invalid --lines '{s}'", .{l})
        else
            50;
        const probe = Tmux.readLog(executor, ctx.arena, session_name, 0, 0) catch |err|
            fatalTmux(err, executor, session_name);
        const window: i64 = @min(probe.log_size, limit);
        from = probe.log_size - window;
        result = Tmux.readLog(executor, ctx.arena, session_name, from, window) catch |err|
            fatalTmux(err, executor, session_name);
        result.data = lastLines(result.data, lines);
    }

    if (advance) {
        Store.sessions.setCursor(store, session_id, result.next_cursor, ctx.now) catch |err|
            Cli.storeFatal(store, err);
    }

    // Cursors are raw-byte offsets; only the displayed data is
    // cleaned. --raw exposes the untouched terminal stream.
    const data = if (parsed.boolean("raw"))
        result.data
    else
        try Tmux.stripTerminalNoise(ctx.arena, result.data);

    switch (ctx.out.format) {
        .json => try ctx.out.json(.{
            .ok = true,
            .session = spec,
            .from = from,
            .to = result.next_cursor,
            .logSize = result.log_size,
            .data = data,
            .cursorAdvanced = advance,
        }),
        .human => try ctx.out.print("{s}", .{data}),
    }
}

/// Refuses a write that another claim on the same scope makes unsafe.
///
/// Reachable from two places — `begin` (before we dial) and `submitted` (the
/// point of no return). Both mean the same thing to the caller: nothing was
/// typed, so retrying after reconciling is safe.
fn reportBlocked(blocker: Core.execution.Blocker) noreturn {
    switch (blocker) {
        .unsettled => |op| fatal(
            "refused: request {s} is {s} on an overlapping scope, so this input could be typed twice; nothing was sent. Reconcile it ('terminus request reconcile {s}') or pass --force",
            .{ op.request_id, op.status.text(), op.request_id },
        ),
        .lease => |lease| fatal(
            "refused: request {s} (on {s}) holds a lease on an overlapping scope until {d}; nothing was sent. Wait, take it over, or pass --force",
            .{ lease.owner_request_id, lease.profile_token, lease.expires_at },
        ),
    }
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

/// The scope a `write` claims: the session it types into.
///
/// A single expression, extracted only so a test can pin it. That is not
/// ceremony — this line decides whether a write and a run on the same session
/// block each other, it has to agree with the scope `exec <server>:<session>`
/// builds inline (cmd_exec.zig:82), and no test in this tree can drive the
/// command end to end to find out. Left inline it would be the one part of the
/// boundary nothing checks.
fn writeScope(session_name: []const u8) Core.execution.Scope {
    return .{ .kind = .job, .key = session_name };
}

test writeScope {
    const t = std.testing;
    // Same session: a write and anything else claiming that session collide.
    // This is the half that makes the barrier work at all.
    try t.expect(writeScope("build").overlaps(.{ .kind = .job, .key = "build" }));
    // A different session does not. This is the half a widened scope loses
    // silently: `.{ .kind = .server }` satisfies the first assertion, refuses
    // every write on the host, and is the shape people switch a guard off
    // over.
    try t.expect(!writeScope("build").overlaps(.{ .kind = .job, .key = "deploy" }));
    // A session is not a path, so a transfer publishing under a
    // similarly-named directory is not in the way of typing into a shell.
    try t.expect(!writeScope("build").overlaps(.{ .kind = .path, .key = "/srv/build" }));
}

fn sha256Hex(arena: std.mem.Allocator, text: []const u8) ![]const u8 {
    var raw: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(text, &raw, .{});
    return std.fmt.allocPrint(arena, "{x}", .{&raw});
}

fn lastLines(data: []const u8, n: usize) []const u8 {
    if (n == 0) return "";
    var count: usize = 0;
    var i = data.len;
    while (i > 0) {
        i -= 1;
        if (data[i] == '\n') {
            count += 1;
            if (count > n) return data[i + 1 ..];
        }
    }
    return data;
}

test lastLines {
    const t = std.testing;
    try t.expectEqualStrings("c\nd\n", lastLines("a\nb\nc\nd\n", 2));
    try t.expectEqualStrings("a\nb\n", lastLines("a\nb\n", 5));
}
