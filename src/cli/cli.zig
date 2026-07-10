//! CLI namespace: shared context plus per-command modules.
const std = @import("std");

pub const Output = @import("output.zig");
pub const Dispatch = @import("dispatch.zig");
pub const Args = @import("args.zig");

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
    return Store.open(path) catch
        fail("cannot open database at {s}", .{path});
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
pub fn trailingContent(
    ctx: *Ctx,
    parsed: *const Args.Parsed,
    comptime file_flag: []const u8,
    expected_positionals: usize,
) !?[]const u8 {
    if (parsed.boolean("stdin")) {
        var buffer: [4096]u8 = undefined;
        var reader = std.Io.File.stdin().readerStreaming(ctx.io, &buffer);
        const content = reader.interface.allocRemaining(ctx.arena, .limited(16 << 20)) catch
            fail("cannot read stdin", .{});
        const trimmed = std.mem.trim(u8, content, " \t\r\n");
        return if (trimmed.len == 0) null else trimmed;
    }
    if (parsed.flag(file_flag)) |path| {
        const content = std.Io.Dir.cwd().readFileAlloc(ctx.io, path, ctx.arena, .limited(16 << 20)) catch
            fail("cannot read {s}", .{path});
        const trimmed = std.mem.trim(u8, content, " \t\r\n");
        return if (trimmed.len == 0) null else trimmed;
    }
    return parsed.trailing(ctx.arena, expected_positionals);
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
