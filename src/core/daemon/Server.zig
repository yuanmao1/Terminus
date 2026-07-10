//! The Terminus daemon: a small local process that keeps SSH connections
//! warm so repeated CLI calls skip the ~2s TCP+handshake+auth cost.
//!
//! Lifecycle is designed around "no leftover processes":
//! * Single instance: binding the unix socket is the lock. If the address
//!   is in use, another daemon is already serving — exit immediately.
//! * Idle suicide: a watchdog thread exits the process after `idle_exit`
//!   with no requests. The CLI transparently respawns on demand, so an
//!   idle daemon costs nothing and can never accumulate.
//! * Stale sockets: on startup, an existing-but-dead socket file (bind
//!   fails, connect also fails) is deleted and rebound.
//! * The socket file is removed on every exit path.
//!
//! Serves one connection at a time: CLI requests are short-lived and
//! serialized per user; simplicity beats throughput here (M4+ can thread).
const std = @import("std");
const protocol = @import("protocol.zig");
const Ssh = @import("../ssh/Client.zig");

const default_idle_exit_ns: i96 = 5 * std.time.ns_per_min;

/// TERMINUS_DAEMON_IDLE_SECS overrides the idle-exit timeout (mainly for
/// tests; also lets users tune how long connections stay warm).
fn idleExitNs(environ: *std.process.Environ.Map) i96 {
    const text = environ.get("TERMINUS_DAEMON_IDLE_SECS") orelse return default_idle_exit_ns;
    const secs = std.fmt.parseInt(u32, text, 10) catch return default_idle_exit_ns;
    return @as(i96, secs) * std.time.ns_per_s;
}

/// Cache one connection per (host, port, username, auth) — in practice an
/// agent hammers one server at a time, and eviction is trivially correct.
const Pooled = struct {
    client: Ssh,
    key: []u8,
    gpa: std.mem.Allocator,

    fn keyOf(gpa: std.mem.Allocator, req: protocol.Request) ![]u8 {
        return std.fmt.allocPrint(gpa, "{s}\x00{d}\x00{s}\x00{t}", .{
            req.host, req.port, req.username, req.auth,
        });
    }

    fn deinit(p: *Pooled) void {
        p.client.deinit();
        p.gpa.free(p.key);
        p.* = undefined;
    }
};

var last_activity_ns: std.atomic.Value(i64) = .init(0);
/// Nonzero while a request is being processed (its start timestamp). The
/// daemon serves one request at a time, so a wedged SSH operation (hung
/// network, misbehaving crypto call) would block status/stop forever;
/// the watchdog kills the whole process instead — the CLI falls back to
/// direct SSH and the next invocation respawns a fresh daemon.
var request_started_ns: std.atomic.Value(i64) = .init(0);

const request_stuck_ns: i96 = 120 * std.time.ns_per_s;

pub fn socketPath(arena: std.mem.Allocator, environ: *std.process.Environ.Map) ![]u8 {
    const home = environ.get("USERPROFILE") orelse environ.get("HOME") orelse
        return error.NoHomeDirectory;
    return std.fs.path.join(arena, &.{ home, ".terminus", "daemon.sock" });
}

fn nowNs(io: std.Io) i64 {
    return @intCast(@divTrunc(std.Io.Timestamp.now(io, .awake).nanoseconds, 1));
}

pub fn run(io: std.Io, gpa: std.mem.Allocator, arena: std.mem.Allocator, environ: *std.process.Environ.Map) !void {
    const path = try socketPath(arena, environ);
    std.Io.Dir.cwd().createDirPath(io, std.fs.path.dirname(path).?) catch {};
    const idle_ns = idleExitNs(environ);

    const address = try std.Io.net.UnixAddress.init(path);
    var server = address.listen(io, .{}) catch |err| switch (err) {
        error.AddressInUse, error.AddressUnavailable => {
            // Either a live daemon (fine, nothing to do) or a stale file.
            if (isLive(io, path)) return;
            std.Io.Dir.cwd().deleteFile(io, path) catch {};
            var retry_address = try std.Io.net.UnixAddress.init(path);
            var retry = try retry_address.listen(io, .{});
            return serve(io, gpa, &retry, path, idle_ns);
        },
        else => return err,
    };
    return serve(io, gpa, &server, path, idle_ns);
}

fn isLive(io: std.Io, path: []const u8) bool {
    const address = std.Io.net.UnixAddress.init(path) catch return false;
    var stream = address.connect(io) catch return false;
    stream.close(io);
    return true;
}

fn serve(io: std.Io, gpa: std.mem.Allocator, server: *std.Io.net.Server, path: []const u8, idle_ns: i96) !void {
    last_activity_ns.store(nowNs(io), .monotonic);

    // Watchdog: exit the whole process after idle_ns with no requests.
    // process.exit skips defers, so it removes the socket file itself.
    const watchdog = try std.Thread.spawn(.{}, watchdogMain, .{ io, path, idle_ns });
    watchdog.detach();

    var pool: ?Pooled = null;
    defer if (pool) |*p| p.deinit();

    while (true) {
        var stream = server.accept(io) catch break;
        defer stream.close(io);
        last_activity_ns.store(nowNs(io), .monotonic);

        const stop = handleConnection(io, gpa, &stream, &pool) catch false;
        last_activity_ns.store(nowNs(io), .monotonic);
        if (stop) break;
    }

    std.Io.Dir.cwd().deleteFile(io, path) catch {};
}

fn watchdogMain(io: std.Io, path: []const u8, idle_ns: i96) void {
    while (true) {
        std.Io.sleep(io, .{ .nanoseconds = 5 * std.time.ns_per_s }, .awake) catch {};
        const now = nowNs(io);
        const idle: i96 = now - last_activity_ns.load(.monotonic);
        if (idle > idle_ns) {
            std.Io.Dir.cwd().deleteFile(io, path) catch {};
            std.process.exit(0);
        }
        // Stuck request: better a dead daemon (auto-respawned, with direct
        // fallback meanwhile) than one that blocks every CLI call.
        const started = request_started_ns.load(.monotonic);
        if (started != 0 and now - started > request_stuck_ns) {
            std.Io.Dir.cwd().deleteFile(io, path) catch {};
            std.process.exit(1);
        }
    }
}

/// Serves requests on one connection until the client disconnects (a CLI
/// invocation sends several — e.g. tmux poll loops). Returns true when the
/// daemon should shut down (stop request).
fn handleConnection(
    io: std.Io,
    gpa: std.mem.Allocator,
    stream: *std.Io.net.Stream,
    pool: *?Pooled,
) !bool {
    var read_buffer: [1 << 20]u8 = undefined;
    var reader = stream.reader(io, &read_buffer);
    var write_buffer: [1 << 16]u8 = undefined;
    var writer = stream.writer(io, &write_buffer);

    while (true) {
        // takeDelimiter consumes the '\n' (unlike takeDelimiterExclusive,
        // which leaves it to poison the next read) and returns null on a
        // clean client disconnect.
        const line = (reader.interface.takeDelimiter('\n') catch return false) orelse return false;
        if (line.len == 0) continue;
        last_activity_ns.store(nowNs(io), .monotonic);
        request_started_ns.store(nowNs(io), .monotonic);
        defer request_started_ns.store(0, .monotonic);

        // Per-request arena: request/response buffers die with the request.
        var request_arena = std.heap.ArenaAllocator.init(gpa);
        defer request_arena.deinit();
        const arena = request_arena.allocator();

        const request = protocol.parseMessage(protocol.Request, arena, line) catch |err| {
            try respondError(&writer.interface, @errorName(err));
            continue;
        };

        switch (request.op) {
            .ping => {
                try protocol.writeMessage(&writer.interface, protocol.Response{
                    .v = protocol.version,
                    .ok = true,
                    .pid = currentPid(),
                });
                continue;
            },
            .stop => {
                try protocol.writeMessage(&writer.interface, protocol.Response{
                    .v = protocol.version,
                    .ok = true,
                });
                return true;
            },
            .exec => {},
        }

        const client = acquire(pool, request) catch |err| {
            try respondError(&writer.interface, @errorName(err));
            continue;
        };

        const result = client.exec(arena, request.command) catch |err| {
            // Pooled connection may have died (server restart, network
            // drop); drop it so the next request reconnects fresh.
            if (pool.*) |*p| p.deinit();
            pool.* = null;
            try respondError(&writer.interface, @errorName(err));
            continue;
        };

        try protocol.writeMessage(&writer.interface, protocol.Response{
            .v = protocol.version,
            .ok = true,
            .exitCode = result.exit_code,
            .stdout = result.stdout,
            .stderr = result.stderr,
        });
    }
}

fn respondError(writer: *std.Io.Writer, message: []const u8) !void {
    try protocol.writeMessage(writer, protocol.Response{
        .v = protocol.version,
        .ok = false,
        .@"error" = message,
    });
}

fn acquire(pool: *?Pooled, request: protocol.Request) !*Ssh {
    const gpa = std.heap.smp_allocator;
    const key = try Pooled.keyOf(gpa, request);

    if (pool.*) |*p| {
        if (std.mem.eql(u8, p.key, key)) {
            gpa.free(key);
            return &p.client;
        }
        p.deinit();
        pool.* = null;
    }

    errdefer gpa.free(key);
    var client = try Ssh.connect(request.host, request.port);
    errdefer client.deinit();

    const auth: Ssh.Auth = switch (request.auth) {
        .none => return error.AuthMissing,
        .password => |password| .{ .password = password },
        .key => |key_auth| .{ .key = .{
            .private = key_auth.private,
            .public = key_auth.public,
            .passphrase = key_auth.passphrase,
        } },
    };
    try client.authenticate(request.username, auth);

    // Dupe key/auth-independent state into the pool's own allocator: the
    // request arena dies when this connection closes.
    pool.* = .{ .client = client, .key = key, .gpa = gpa };
    return &pool.*.?.client;
}

fn currentPid() u32 {
    return switch (@import("builtin").os.tag) {
        .windows => std.os.windows.GetCurrentProcessId(),
        else => @intCast(std.c.getpid()),
    };
}
