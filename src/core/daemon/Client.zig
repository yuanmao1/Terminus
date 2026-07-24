//! Daemon client: connects the CLI to the local daemon, spawning it on
//! demand.
//!
//! Failure policy: acquire() returns a diagnosis instead of silently
//! returning null — the caller (cli.connect) decides to fall back to
//! direct SSH but always *reports* which transport served the request and
//! why the daemon was skipped. A version-mismatched daemon (stale binary)
//! is stopped and respawned once, transparently.
const std = @import("std");
const protocol = @import("protocol.zig");
const Server = @import("Server.zig");
const Ssh = @import("../ssh/Client.zig");

const DaemonClient = @This();

io: std.Io,
arena: std.mem.Allocator,
stream: std.Io.net.Stream,
request: protocol.Request,
last_error: []const u8 = "",

pub const AcquireResult = union(enum) {
    ok: DaemonClient,
    /// Daemon unusable; carries the reason for transport reporting.
    unavailable: []const u8,
};

/// Tries: connect → (version-check via ping) → spawn + retry. Never
/// throws; the result says which and why.
pub fn acquire(
    io: std.Io,
    arena: std.mem.Allocator,
    environ: *std.process.Environ.Map,
    request: protocol.Request,
) AcquireResult {
    const path = Server.socketPath(arena, environ) catch
        return .{ .unavailable = "no home directory for socket path" };

    if (connectTo(io, path)) |stream| {
        var client: DaemonClient = .{ .io = io, .arena = arena, .stream = stream, .request = request };
        // Version handshake: a stale daemon (older binary) must not serve
        // new-protocol requests. Stop it and respawn below.
        if (client.ping()) |_| return .{ .ok = client };
        client.stop() catch {};
        client.deinit();
    }

    spawnDaemon(io, environ) catch |err| {
        return .{ .unavailable = std.fmt.allocPrint(arena, "spawn failed: {s}", .{@errorName(err)}) catch "spawn failed" };
    };

    // The daemon needs a moment to bind. Total worst-case wait ~1.6s.
    var delay_ms: u64 = 50;
    for (0..5) |_| {
        std.Io.sleep(io, .{ .nanoseconds = @intCast(delay_ms * std.time.ns_per_ms) }, .awake) catch {};
        if (connectTo(io, path)) |stream| {
            var client: DaemonClient = .{ .io = io, .arena = arena, .stream = stream, .request = request };
            if (client.ping()) |_| return .{ .ok = client };
            client.deinit();
            return .{ .unavailable = "daemon protocol version mismatch after respawn" };
        }
        delay_ms *= 2;
    }
    return .{ .unavailable = "daemon did not come up within 1.6s" };
}

pub fn deinit(client: *DaemonClient) void {
    client.stream.close(client.io);
    client.* = undefined;
}

pub fn errorMessage(client: *const DaemonClient) []const u8 {
    return client.last_error;
}

/// Sends the exec request over the daemon socket. Error surface matches
/// Ssh.exec so the Executor union stays uniform.
pub fn exec(client: *DaemonClient, arena: std.mem.Allocator, command: []const u8) Ssh.ExecError!Ssh.ExecResult {
    var request = client.request;
    request.v = protocol.version;
    request.op = .exec;
    request.command = command;

    const response = client.roundTrip(protocol.Response, request) orelse {
        client.last_error = "daemon connection lost mid-request";
        return error.ExecFailed;
    };
    if (!response.ok) {
        client.last_error = arena.dupe(u8, response.@"error" orelse "daemon error") catch "daemon error";
        return error.ExecFailed;
    }
    return .{
        .exit_code = response.exitCode,
        .stdout = arena.dupe(u8, response.stdout) catch return error.OutOfMemory,
        .stderr = arena.dupe(u8, response.stderr) catch return error.OutOfMemory,
    };
}

/// Pings over this client's connection; returns the daemon pid, or null
/// on any failure (including protocol version mismatch).
pub fn ping(client: *DaemonClient) ?u32 {
    const response = client.roundTrip(protocol.Response, protocol.Request{
        .v = protocol.version,
        .op = .ping,
    }) orelse return null;
    return if (response.ok) response.pid else null;
}

pub fn stop(client: *DaemonClient) !void {
    _ = client.roundTrip(protocol.Response, protocol.Request{
        .v = protocol.version,
        .op = .stop,
    }) orelse return error.StopFailed;
}

fn roundTrip(client: *DaemonClient, comptime R: type, request: anytype) ?R {
    var write_buffer: [1 << 16]u8 = undefined;
    var writer = client.stream.writer(client.io, &write_buffer);
    protocol.writeMessage(&writer.interface, request) catch return null;

    var read_buffer: [1 << 20]u8 = undefined;
    var reader = client.stream.reader(client.io, &read_buffer);
    const line = (reader.interface.takeDelimiter('\n') catch return null) orelse return null;
    return protocol.parseMessage(R, client.arena, line) catch null;
}

fn connectTo(io: std.Io, path: []const u8) ?std.Io.net.Stream {
    // Missing socket file surfaces as error.Unexpected on Windows, which
    // std prints a debug stack trace for — check existence first.
    std.Io.Dir.cwd().access(io, path, .{}) catch return null;
    const address = std.Io.net.UnixAddress.init(path) catch return null;
    return address.connect(io) catch null;
}

/// Spawns `terminus daemon run` fully detached: no inherited stdio, no
/// console window, and no retained handles — the OS owns the daemon.
///
/// Windows has no zombie concept: a process with no open handles to it is
/// fully reaped by the kernel on exit, so closing our handles right after
/// spawn guarantees nothing is left behind by this CLI. (POSIX arrives in
/// M5 and will need the double-fork/setsid treatment instead.)
fn spawnDaemon(io: std.Io, environ: *std.process.Environ.Map) !void {
    _ = environ;
    var exe_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const exe_len = try std.process.executablePath(io, &exe_buffer);
    const exe = exe_buffer[0..exe_len];

    const child = try std.process.spawn(io, .{
        .argv = &.{ exe, "daemon", "run" },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
        .create_no_window = true,
    });
    if (@import("builtin").os.tag == .windows) {
        if (child.id) |handle| std.os.windows.CloseHandle(handle);
        std.os.windows.CloseHandle(child.thread_handle);
    }
}

/// One-shot stop for `terminus daemon stop`; returns true if acknowledged.
pub fn stopDaemon(io: std.Io, arena: std.mem.Allocator, environ: *std.process.Environ.Map) bool {
    const path = Server.socketPath(arena, environ) catch return false;
    const stream = connectTo(io, path) orelse return false;
    var client: DaemonClient = .{ .io = io, .arena = arena, .stream = stream, .request = undefined };
    defer client.deinit();
    client.stop() catch return false;
    return true;
}

/// One-shot ping for `terminus daemon status`; returns the pid or null.
pub fn pingDaemon(io: std.Io, arena: std.mem.Allocator, environ: *std.process.Environ.Map) ?u32 {
    const path = Server.socketPath(arena, environ) catch return null;
    const stream = connectTo(io, path) orelse return null;
    var client: DaemonClient = .{ .io = io, .arena = arena, .stream = stream, .request = undefined };
    defer client.deinit();
    return client.ping();
}

pub const ForceKill = struct {
    /// A daemon process was found and terminated.
    killed: bool,
    /// The pid that was targeted (from the pidfile), if any.
    pid: ?u32,
};

/// Hard-restart path for a wedged daemon whose socket no longer responds:
/// read the pidfile and terminate that process directly (bypassing the
/// hung socket protocol), then delete the stale socket + pid files so the
/// next request spawns a clean daemon. Best-effort — a graceful `stop`
/// should be tried first; this is the sledgehammer.
pub fn forceKillDaemon(io: std.Io, arena: std.mem.Allocator, environ: *std.process.Environ.Map) ForceKill {
    // Try a graceful stop first so a *responsive* daemon exits cleanly and
    // removes its own files; only fall through to killing by pid if it's
    // truly wedged.
    _ = stopDaemon(io, arena, environ);

    const pid = readPidFile(io, arena, environ);
    var killed = false;
    if (pid) |p| killed = terminatePid(p);

    // Whether or not a process was killed, clear the stale artifacts so the
    // next CLI call spawns fresh.
    if (Server.socketPath(arena, environ)) |sock| std.Io.Dir.cwd().deleteFile(io, sock) catch {} else |_| {}
    if (Server.pidFilePath(arena, environ)) |pf| std.Io.Dir.cwd().deleteFile(io, pf) catch {} else |_| {}

    return .{ .killed = killed, .pid = pid };
}

fn readPidFile(io: std.Io, arena: std.mem.Allocator, environ: *std.process.Environ.Map) ?u32 {
    const path = Server.pidFilePath(arena, environ) catch return null;
    const text = std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(64)) catch return null;
    const trimmed = std.mem.trim(u8, text, " \t\r\n");
    return std.fmt.parseInt(u32, trimmed, 10) catch null;
}

/// Terminates a process by pid. Returns true on a successful kill (or if
/// the process was already gone). Windows-only for now (M4); POSIX kill(2)
/// arrives with the POSIX daemon in M5.
fn terminatePid(pid: u32) bool {
    if (@import("builtin").os.tag != .windows) return false;
    const windows = std.os.windows;
    const PROCESS_TERMINATE: u32 = 0x0001;
    const handle = OpenProcess(PROCESS_TERMINATE, 0, pid);
    // A null handle usually means the process is already gone — treat that
    // as success (the daemon we wanted dead is dead).
    if (handle == null or handle == windows.INVALID_HANDLE_VALUE) return true;
    defer windows.CloseHandle(handle.?);
    return TerminateProcess(handle.?, 1) != 0;
}

extern "kernel32" fn OpenProcess(
    dwDesiredAccess: u32,
    bInheritHandle: i32,
    dwProcessId: u32,
) callconv(.winapi) ?std.os.windows.HANDLE;

extern "kernel32" fn TerminateProcess(
    hProcess: std.os.windows.HANDLE,
    uExitCode: u32,
) callconv(.winapi) i32;
