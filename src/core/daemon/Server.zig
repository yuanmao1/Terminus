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
    // Eight bytes is all this has to hold — the payload is read into the
    // per-request arena at exactly its announced size. It was a 1 MiB array on
    // every connection thread's stack.
    var read_buffer: [1 << 12]u8 = undefined;
    var reader = stream.reader(io, &read_buffer);
    var write_buffer: [1 << 16]u8 = undefined;
    var writer = stream.writer(io, &write_buffer);

    while (true) {
        // Per-request arena: request/response buffers die with the request. It
        // owns the frame payload too, so it must outlive the parse below.
        var request_arena = std.heap.ArenaAllocator.init(gpa);
        defer request_arena.deinit();
        const arena = request_arena.allocator();

        const payload = protocol.readFrame(&reader.interface, arena) catch |err| {
            // A framing error cannot be resynchronised — the stream position is
            // no longer known, so reading on would turn one bad frame into a
            // run of them. Say so once and end the connection. This is also the
            // path a *older* client lands on: its unframed line fails the
            // header, it gets one framed refusal terminated by the newline it
            // is delimiting on, and it falls back to direct SSH rather than
            // waiting for a reply that would never come.
            respondError(&writer.interface, @errorName(err)) catch {};
            return false;
        } orelse return false;
        if (payload.len == 0) continue;
        last_activity_ns.store(nowNs(io), .monotonic);
        _ = active_requests.fetchAdd(1, .monotonic);
        defer {
            _ = active_requests.fetchSub(1, .monotonic);
            last_activity_ns.store(nowNs(io), .monotonic);
        }

        const request = protocol.parseMessage(protocol.Request, arena, payload) catch |err| {
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

        var retained: Ssh.Retained = .{};
        const result = execRequest(io, arena, request, &retained) catch |err| {
            try respondError(&writer.interface, refusalText(err));
            continue;
        };

        const response = protocol.execResponse(
            result,
            if (request.output == .retained) retained else null,
        );

        protocol.writeMessage(&writer.interface, response) catch |err| switch (err) {
            // Only a `.whole` request can get here: `.retained` output is
            // bounded by `Ssh.output_ceiling` and a comptime assertion in
            // `protocol` holds its widest encoding under the frame. Refused by
            // name and never shortened — a `.whole` caller asked for every byte
            // precisely because it is going to verify a digest over them.
            error.FrameTooLarge => try respondTooLarge(&writer.interface, response),
            else => return err,
        };
    }
}

/// What running one exec can fail with. Named rather than inferred so the
/// signature says which layer each failure came from.
pub const RunError = Ssh.ExecError || Ssh.InputError || Ssh.ConnectError ||
    Ssh.AuthError || error{AuthMissing};

/// `@errorName`, except for the one refusal whose name alone would send an
/// operator looking for a network fault that is not there.
///
/// Any local process can write to this socket, so the refusal has to be
/// legible on its own — it is not only the CLI that reads it, and the CLI
/// does not dial the daemon for an exec at all while this holds.
pub fn refusalText(err: RunError) []const u8 {
    return switch (err) {
        error.NoTrustRoot =>
        \\the daemon has no trust store to check a host key against, so it will not open an SSH session.
        \\Its protocol carries auth material in every request precisely so it never touches the database,
        \\which is also why it cannot read the pin that authorises a host. Rerun with --no-daemon (or set
        \\TERMINUS_NO_DAEMON=1) and the direct transport will check the pin and connect.
        ,
        else => @errorName(err),
    };
}

/// Runs one exec, preferring the pooled connection. If another thread
/// holds it (a long-running command), dial a fresh one-shot connection
/// rather than queue — concurrent CLI calls stay independent.
///
/// `retained` carries the accounting for a `.retained` request and is left at
/// its zero value for a `.whole` one, which takes no digest.
fn execRequest(
    io: std.Io,
    arena: std.mem.Allocator,
    request: protocol.Request,
    retained: *Ssh.Retained,
) RunError!Ssh.ExecResult {
    if (pool_mutex.tryLock()) {
        defer pool_mutex.unlock(io);
        const client = acquirePooledLocked(request) catch |err| return err;
        return runOn(client, arena, request, retained) catch |err| {
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
    return runOn(&client, arena, request, retained);
}

/// The one place the daemon chooses an output discipline.
///
/// `.retained` goes through `Ssh.execRetained`, which applies
/// `Ssh.output_ceiling` **as the channel is drained** — so the daemon's own peak
/// is the ceiling and not the command's output. It used to call `Ssh.exec` for
/// everything, which keeps every byte by contract, and so a command printing ten
/// gigabytes cost the daemon ten gigabytes.
fn runOn(
    client: *Ssh,
    arena: std.mem.Allocator,
    request: protocol.Request,
    retained: *Ssh.Retained,
) RunError!Ssh.ExecResult {
    return switch (request.output) {
        .whole => client.exec(arena, request.command),
        // No input: the protocol carries a command and an answer and no third
        // channel, and `Executor.execRetained` refuses on this transport before
        // anything is sent rather than handing a stdin-reading command an
        // immediate EOF.
        .retained => client.execRetained(arena, request.command, null, retained),
    };
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
    // `.none`, and not a policy this process could satisfy. The daemon has no
    // trust store: its protocol carries auth material in every request
    // precisely so it never touches sqlite, so there is no `host_pins` row it
    // can read and nothing it could check this host's key against. Opening the
    // default database instead would be worse than refusing — a CLI running
    // against `--db <other>` would have its connections authorised by a trust
    // root the operator never recorded a pin in.
    //
    // So `Ssh.connect` refuses before it dials, and the CLI does not offer this
    // transport at all (`Cli.daemonCannotCarry`). Restoring the pooled
    // connection means the request carrying the expected fingerprint, which is
    // a change to the wire format in `protocol.zig`.
    var observed: ?Ssh.HostKey = null;
    var client = try Ssh.connect(request.host, request.port, .none, &observed);
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
        // Bounded here, because this is the one field of a reply whose width is
        // not a function of the output ceiling.
        .@"error" = message[0..@min(message.len, protocol.max_error_bytes)],
    });
}

/// The refusal for a reply that will not fit a frame.
///
/// Names both numbers, because "too large" without them tells an operator
/// nothing about whether the request was unreasonable or the limit is. The
/// remedy is the direct transport, which frames nothing.
fn respondTooLarge(writer: *std.Io.Writer, response: protocol.Response) !void {
    var buffer: [protocol.max_error_bytes]u8 = undefined;
    const size = protocol.payloadLen(response) catch 0;
    const message = std.fmt.bufPrint(
        &buffer,
        "reply of {d} bytes exceeds the {d}-byte daemon protocol frame; rerun with --no-daemon",
        .{ size, protocol.max_frame_bytes },
    ) catch "reply exceeds the daemon protocol frame; rerun with --no-daemon";
    try respondError(writer, message);
}

fn currentPid() u32 {
    return switch (@import("builtin").os.tag) {
        .windows => std.os.windows.GetCurrentProcessId(),
        else => @intCast(std.c.getpid()),
    };
}
