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
const Reservation = struct {
    store: *Store,
    server_id: i64,
    name: []const u8,
};
var active_reservation: ?Reservation = null;

pub fn registerReservation(store: *Store, server_id: i64, name: []const u8) void {
    active_reservation = .{ .store = store, .server_id = server_id, .name = name };
}

/// Keeps the reservation: the command is in the remote's hands now, so the
/// row describes something that may be running and must not be dropped.
pub fn commitReservation() void {
    active_reservation = null;
}

/// Gives the name back, if it is still held.
///
/// Called from `fail` (which skips defers) and from the launch path's own
/// `defer` — the latter both covers a plain error return and guarantees the
/// borrowed `*Store` never outlives the frame that owns it.
pub fn releaseReservation() void {
    const held = active_reservation orelse return;
    active_reservation = null; // never re-enter
    _ = Store.jobs.remove(held.store, held.server_id, held.name) catch |err| {
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

/// Connect + authenticate, with user-oriented fatal messages.
pub fn sshConnect(server: Store.servers.Server, auth: Ssh.Auth) Ssh {
    var client = Ssh.connect(server.host, server.port) catch |err|
        fail("cannot connect to {s}:{d}: {s} ({s})", .{
            server.host, server.port, @errorName(err), Ssh.lastConnectError(),
        });
    client.authenticate(server.username, auth) catch |err| switch (err) {
        error.UnsupportedKeyFormat => {
            const format = Ssh.KeyFormat.detect(auth.key.private);
            fail("the key for '{s}' is in an unsupported format.\n{s}", .{
                server.name, Ssh.KeyFormat.adviceFor(format),
            });
        },
        else => fail("authentication failed for {s}@{s}: {s}", .{
            server.username, server.host, client.errorMessage(),
        }),
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
                // mode carries transport+daemonError in the response.
                if (ctx.out.format == .human)
                    std.debug.print("warning: daemon unavailable ({s}); using direct SSH\n", .{reason});
                return .{
                    .inner = .{ .direct = sshConnect(server, auth) },
                    .transport = "direct",
                    .daemon_error = reason,
                };
            },
        }
    }
    return .{ .inner = .{ .direct = sshConnect(server, auth) }, .transport = "direct" };
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
pub fn openStore(ctx: *Ctx, parsed: *const Args.Parsed) !Store {
    const path = try dbPath(ctx, parsed.flag("db") orelse ctx.db_override);
    return Store.open(path) catch |err| switch (err) {
        // Only reachable on a machine that ran a pre-release build of the
        // 0.2.0 branch; say exactly that instead of leaking a SQL error.
        error.PreReleaseSchemaDrift => fail(
            "database at {s} was created by a pre-release build whose schema has since changed; delete it (and its -wal/-shm files) or point --db elsewhere",
            .{path},
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
