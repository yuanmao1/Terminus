//! The Terminus daemon: a small local process that keeps SSH connections
//! warm so repeated CLI calls skip the ~2s TCP+handshake+auth cost.
//!
//! Lifecycle is designed around "no leftover processes":
//! * Single instance: binding the unix socket is the lock. If the address
//!   is in use, another daemon is already serving — exit immediately.
//! * Idle suicide: a watchdog thread exits the process after `idle_exit`
//!   with no requests in flight. The CLI transparently respawns on
//!   demand, so an idle daemon costs nothing and can never accumulate.
//! * Stale sockets: on startup, an existing-but-dead socket file (bind
//!   fails, connect also fails) is deleted and rebound.
//! * The socket file is removed on every exit path.
//!
//! Each client connection gets its own thread, so ping/status/stop stay
//! responsive while a long exec (multi-minute table scans are legitimate)
//! is in flight. The pooled SSH session is mutex-guarded — libssh2
//! sessions are not thread-safe — and a request that finds it busy dials
//! a fresh one-shot connection instead of queueing behind the long one.
const std = @import("std");
const protocol = @import("protocol.zig");
const Ssh = @import("../ssh/Client.zig");

const default_idle_exit_ns: i96 = 5 * std.time.ns_per_min;
/// Backstop for a truly wedged request (transport hang the key-format
/// guards didn't catch): after this long with no request starting or
/// finishing, the daemon exits rather than linger forever. Long
/// legitimate work keeps the daemon alive as long as *something*
/// completes now and then; a lone request older than this is presumed
/// dead. Override with TERMINUS_DAEMON_REQUEST_MAX_SECS.
const default_request_max_ns: i96 = 60 * std.time.ns_per_min;

fn envNs(environ: *std.process.Environ.Map, name: []const u8, default: i96) i96 {
    const text = environ.get(name) orelse return default;
    const secs = std.fmt.parseInt(u32, text, 10) catch return default;
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
var active_requests: std.atomic.Value(i64) = .init(0);
var pool_mutex: std.Io.Mutex = .init;
var pool: ?Pooled = null;

pub fn socketPath(arena: std.mem.Allocator, environ: *std.process.Environ.Map) ![]u8 {
    const home = environ.get("USERPROFILE") orelse environ.get("HOME") orelse
        return error.NoHomeDirectory;
    return std.fs.path.join(arena, &.{ home, ".terminus", "daemon.sock" });
}

/// Records the daemon's pid so `daemon restart --force` can hard-kill a
/// wedged instance without going through the (possibly hung) socket.
pub fn pidFilePath(arena: std.mem.Allocator, environ: *std.process.Environ.Map) ![]u8 {
    const home = environ.get("USERPROFILE") orelse environ.get("HOME") orelse
        return error.NoHomeDirectory;
    return std.fs.path.join(arena, &.{ home, ".terminus", "daemon.pid" });
}

fn writePidFile(io: std.Io, path: []const u8) void {
    var buffer: [16]u8 = undefined;
    const text = std.fmt.bufPrint(&buffer, "{d}", .{currentPid()}) catch return;
    std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = text }) catch {};
}

fn nowNs(io: std.Io) i64 {
    return @intCast(@divTrunc(std.Io.Timestamp.now(io, .awake).nanoseconds, 1));
}

pub fn run(io: std.Io, gpa: std.mem.Allocator, arena: std.mem.Allocator, environ: *std.process.Environ.Map) !void {
    const path = try socketPath(arena, environ);
    const pid_path = try pidFilePath(arena, environ);
    std.Io.Dir.cwd().createDirPath(io, std.fs.path.dirname(path).?) catch {};
    const idle_ns = envNs(environ, "TERMINUS_DAEMON_IDLE_SECS", default_idle_exit_ns);
    const request_max_ns = envNs(environ, "TERMINUS_DAEMON_REQUEST_MAX_SECS", default_request_max_ns);

    const address = try std.Io.net.UnixAddress.init(path);
    var server = address.listen(io, .{}) catch |err| switch (err) {
        error.AddressInUse, error.AddressUnavailable => {
            // Either a live daemon (fine, nothing to do) or a stale file.
            if (isLive(io, path)) return;
            std.Io.Dir.cwd().deleteFile(io, path) catch {};
            var retry_address = try std.Io.net.UnixAddress.init(path);
            var retry = try retry_address.listen(io, .{});
            return serve(io, gpa, &retry, path, pid_path, idle_ns, request_max_ns);
        },
        else => return err,
    };
    return serve(io, gpa, &server, path, pid_path, idle_ns, request_max_ns);
}

fn isLive(io: std.Io, path: []const u8) bool {
    const address = std.Io.net.UnixAddress.init(path) catch return false;
    var stream = address.connect(io) catch return false;
    stream.close(io);
    return true;
}

fn serve(io: std.Io, gpa: std.mem.Allocator, server: *std.Io.net.Server, path: []const u8, pid_path: []const u8, idle_ns: i96, request_max_ns: i96) !void {
    last_activity_ns.store(nowNs(io), .monotonic);
    writePidFile(io, pid_path);

    // Watchdog: exits the whole process on idle (or wedge, see above).
    // process.exit skips defers, so it removes the socket + pid files itself.
    const watchdog = try std.Thread.spawn(.{}, watchdogMain, .{ io, path, pid_path, idle_ns, request_max_ns });
    watchdog.detach();

    while (true) {
        const stream = server.accept(io) catch break;
        const thread = std.Thread.spawn(.{}, connectionMain, .{ io, gpa, stream, path, pid_path }) catch {
            var s = stream;
            s.close(io);
            continue;
        };
        thread.detach();
    }

    std.Io.Dir.cwd().deleteFile(io, path) catch {};
    std.Io.Dir.cwd().deleteFile(io, pid_path) catch {};
}

fn watchdogMain(io: std.Io, path: []const u8, pid_path: []const u8, idle_ns: i96, request_max_ns: i96) void {
    while (true) {
        std.Io.sleep(io, .{ .nanoseconds = 5 * std.time.ns_per_s }, .awake) catch {};
        const idle: i96 = nowNs(io) - last_activity_ns.load(.monotonic);
        const active = active_requests.load(.monotonic);
        if (active == 0 and idle > idle_ns) {
            std.Io.Dir.cwd().deleteFile(io, path) catch {};
            std.Io.Dir.cwd().deleteFile(io, pid_path) catch {};
            std.process.exit(0);
        }
        // In-flight requests hold the daemon open — unless nothing has
        // started or finished for so long that the transport is presumed
        // wedged (the CLI falls back to direct SSH and respawns).
        if (active > 0 and idle > request_max_ns) {
            std.Io.Dir.cwd().deleteFile(io, path) catch {};
            std.Io.Dir.cwd().deleteFile(io, pid_path) catch {};
            std.process.exit(1);
        }
    }
}

fn connectionMain(io: std.Io, gpa: std.mem.Allocator, stream_value: std.Io.net.Stream, path: []const u8, pid_path: []const u8) void {
    var stream = stream_value;
    defer stream.close(io);
    const stop = handleConnection(io, gpa, &stream) catch false;
    if (stop) {
        std.Io.Dir.cwd().deleteFile(io, path) catch {};
        std.Io.Dir.cwd().deleteFile(io, pid_path) catch {};
        std.process.exit(0);
    }
}

/// Serves requests on one connection until the client disconnects (a CLI
/// invocation sends several — e.g. tmux poll loops). Returns true when the
/// daemon should shut down (stop request).
fn handleConnection(
    io: std.Io,
    gpa: std.mem.Allocator,
    stream: *std.Io.net.Stream,
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
        _ = active_requests.fetchAdd(1, .monotonic);
        defer {
            _ = active_requests.fetchSub(1, .monotonic);
            last_activity_ns.store(nowNs(io), .monotonic);
        }

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

        const result = execRequest(io, arena, request) catch |err| {
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

/// Runs one exec, preferring the pooled connection. If another thread
/// holds it (a long-running command), dial a fresh one-shot connection
/// rather than queue — concurrent CLI calls stay independent.
fn execRequest(io: std.Io, arena: std.mem.Allocator, request: protocol.Request) !Ssh.ExecResult {
    if (pool_mutex.tryLock()) {
        defer pool_mutex.unlock(io);
        const client = acquirePooledLocked(request) catch |err| return err;
        return client.exec(arena, request.command) catch |err| {
            // Pooled connection may have died (server restart, network
            // drop); drop it so the next request reconnects fresh.
            if (pool) |*p| p.deinit();
            pool = null;
            return err;
        };
    }

    // Pool busy: independent short-lived connection for this request.
    var client = try connectFor(request);
    defer client.deinit();
    return client.exec(arena, request.command);
}

/// Caller holds pool_mutex.
fn acquirePooledLocked(request: protocol.Request) !*Ssh {
    const gpa = std.heap.smp_allocator;
    const key = try Pooled.keyOf(gpa, request);

    if (pool) |*p| {
        if (std.mem.eql(u8, p.key, key)) {
            gpa.free(key);
            return &p.client;
        }
        p.deinit();
        pool = null;
    }

    errdefer gpa.free(key);
    const client = try connectFor(request);
    pool = .{ .client = client, .key = key, .gpa = gpa };
    return &pool.?.client;
}

fn connectFor(request: protocol.Request) !Ssh {
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
    return client;
}

fn respondError(writer: *std.Io.Writer, message: []const u8) !void {
    try protocol.writeMessage(writer, protocol.Response{
        .v = protocol.version,
        .ok = false,
        .@"error" = message,
    });
}

fn currentPid() u32 {
    return switch (@import("builtin").os.tag) {
        .windows => std.os.windows.GetCurrentProcessId(),
        else => @intCast(std.c.getpid()),
    };
}
