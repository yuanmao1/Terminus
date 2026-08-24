//! Daemon client: connects the CLI to an explicitly started local daemon.
//!
//! Failure policy: acquire() returns a diagnosis instead of silently
//! returning null — the caller (cli.connect) decides to fall back to
//! direct SSH but always *reports* which transport served the request and
//! why the daemon was skipped.
//!
//! **A daemon from another build is named, not trusted.** Version skew falls
//! back to direct SSH with the reason attached to the receipt.
//!
//! **A missing daemon never delays SSH.** On Windows, auto-spawning a detached
//! daemon and immediately using it could wedge that spawning process's first
//! SSH connection for minutes. Absence now returns a named direct fallback;
//! Released Windows commands therefore use direct SSH by default.
//! Every way of finding nothing on the other side is bounded and named:
//!
//!   * **no socket file** — `connectTo` checks for the file before it dials, so
//!     this is `null` and not a Windows `error.Unexpected` with a stack trace;
//!   * **a socket file with nothing listening** (the stale file an unclean
//!     daemon exit leaves) — the connect fails and direct SSH is used. On Windows that connect
//!     fails with a status std does not map — `ConnectionRefused` is not in
//!     `net.UnixAddress.ConnectError` — so a Debug build prints a trace under
//!     it on the way past. Noise, not a wrong answer: the branch taken is the
//!     same one an absent file takes;
//!   * **accepted, then closed without a reply** — the EOF this whole paragraph
//!     is about. `protocol.readFrame` reads a clean close between frames as
//!     `null`, which is `.broken`, which is a named refusal;
//!   * **a reply that stopped part-way** — `error.FrameIncomplete`, also
//!     `.broken`; see `roundTrip`.
//!
//! What is *not* bounded is a peer that writes a well-formed header and then
//! neither writes nor closes: there is no read deadline on this side, and
//! `206c44b` recorded that as hardening. No fresh-start shape produces it — a
//! daemon that has not created its socket cannot have written a header — so it
//! is a wedged *live* daemon's failure and not this one's. The daemon's own
//! `TERMINUS_DAEMON_REQUEST_MAX_SECS` watchdog is what bounds it today.
//! Held to by `gate: a CLI that finds no daemon gets a named refusal, never a
//! hang and never a wrong cause`.
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
    /// The daemon answered, and what it answered is that it will not open a
    /// session for this host under this authority. Carries its own words.
    ///
    /// Distinct from `unavailable` because the two are not the same event and
    /// must not share a disposition. `unavailable` is a reason to use direct SSH;
    /// this is not, because the key the daemon judged is the key a direct
    /// connection would judge, so falling back would reach the same refusal by a
    /// longer route. Reported instead — and reported *here*, before the caller
    /// opens an operation, which is the whole reason this check exists.
    refused: []const u8,
};

/// Tries connect → version-check → authority-check. Never throws; the result
/// says which transport is available and why.
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
        // Version handshake: a stale daemon (older build) must not serve
        // new-protocol requests.
        switch (client.handshake()) {
            .ok => {
                // The authority check, before the caller has an operation to
                // settle. A refusal after `execution.submitted()` had no terminal
                // that was both true and admissible, and the one it settled for —
                // `indeterminate` — blocks the scope, so a single wrong pin made a
                // server refuse every later command until somebody reconciled an
                // attempt that had never run.
                if (client.authorise()) |refusal| {
                    client.deinit();
                    return .{ .refused = refusal };
                }
                return .{ .ok = client };
            },
            // Spawning past it is impossible and stopping it is impossible; the
            // operator is the only one who can clear it. See the file header.
            .skew => |reason| {
                client.deinit();
                return .{ .unavailable = reason };
            },
            // Connected, then the conversation broke for a reason that is not a
            // version. Best-effort stop, then use direct SSH below.
            .broken => {
                client.stop() catch {};
                client.deinit();
            },
        }
    }

    // A detached daemon spawned from this same Windows process can bind its Unix
    // socket and then wedge the parent's first SSH connection for minutes. A
    // missing pool is an optimization miss, not a reason to delay the command:
    // fall back immediately. Operators who want pooling can keep `daemon run`
    // under their process supervisor; an already-running daemon is still used.
    return .{ .unavailable = "daemon is not running; used direct SSH immediately" };
}

pub fn deinit(client: *DaemonClient) void {
    client.stream.close(client.io);
    client.* = undefined;
}

pub fn errorMessage(client: *const DaemonClient) []const u8 {
    return client.last_error;
}

/// Sends the exec request over the daemon socket, keeping the whole reply.
/// Error surface matches Ssh.exec so the Executor union stays uniform.
pub fn exec(client: *DaemonClient, arena: std.mem.Allocator, command: []const u8) Ssh.ExecError!Ssh.ExecResult {
    const response = try client.execExchange(arena, command, .whole);
    return .{
        .exit_code = response.exitCode,
        .stdout = response.stdout.bytes,
        .stderr = response.stderr.bytes,
    };
}

/// `exec` under `Ssh.output_ceiling`, applied by the daemon at the channel it
/// drained rather than by this process at a reply it already holds.
///
/// That is the whole of why this exists as its own entry point. The ceiling
/// cannot be applied here: by the time a reply is in hand every byte of it has
/// already been read, so a ceiling on this side would bound nothing and the
/// daemon's own peak would still grow with the command's output. Applied over
/// there, one constant — the same `Ssh.output_ceiling` the direct transport uses
/// — bounds the daemon's peak, this process's peak, and the width of the frame
/// between them.
///
/// `output` is filled from the accounting the daemon sends back, which is the
/// accounting its `Ssh.Capture` took over the bytes as they arrived. Not
/// recomputed here: a second pass over the *retained* rendering would describe
/// the truncated stream and report it as the whole one.
pub fn execRetained(
    client: *DaemonClient,
    arena: std.mem.Allocator,
    command: []const u8,
    output: *Ssh.Retained,
) Ssh.ExecError!Ssh.ExecResult {
    output.* = .{};
    const response = try client.execExchange(arena, command, .retained);
    // A reply with no accounting is a reply to some other question — a `.whole`
    // run took no digest and has none to give. Refused rather than defaulted:
    // zeros here would become a receipt claiming an empty stream was observed.
    const passed = response.passed orelse {
        client.last_error = "daemon replied without the output accounting a retained request asks for";
        return error.ExecFailed;
    };
    output.stdout = protocol.passedFrom(passed.stdout) catch return client.badReply();
    output.stderr = protocol.passedFrom(passed.stderr) catch return client.badReply();
    return .{
        .exit_code = response.exitCode,
        .stdout = response.stdout.bytes,
        .stderr = response.stderr.bytes,
    };
}

fn execExchange(
    client: *DaemonClient,
    arena: std.mem.Allocator,
    command: []const u8,
    output: protocol.Request.Output,
) Ssh.ExecError!protocol.Response {
    var request = client.request;
    request.v = protocol.version;
    request.op = .exec;
    request.command = command;
    request.output = output;

    // The caller's arena, not this client's: the reply's payloads are decoded
    // straight onto it and are the largest thing a command produces, so they
    // have to die when the caller's work does. `pullBytes` asks a hundred of
    // these questions in a row.
    const response = switch (client.roundTrip(arena, request)) {
        .reply => |r| r,
        .skew => |peer| {
            client.last_error = skewReason(client.arena, peer);
            return error.ExecFailed;
        },
        .broken => {
            client.last_error = "daemon connection lost mid-request";
            return error.ExecFailed;
        },
    };
    if (!response.ok) {
        // Onto this client's arena, because the message is read after the
        // caller's work — and its arena — may be gone.
        client.last_error = client.arena.dupe(u8, response.@"error" orelse "daemon error") catch "daemon error";
        // A refusal the daemon issued before it had a session is proof the
        // command did not run, and it settles differently: a proven failure,
        // which leaves the scope free, rather than `indeterminate`, which does
        // not. `error.ExecFailed` cannot carry that, so it gets its own member.
        //
        // Measured on a live host before this existed: one wrong host-key pin
        // made every later command on that server refuse, because the refusal
        // had settled `indeterminate` and `indeterminate` blocks the scope.
        //
        // `dialled` defaults to true, so a daemon that does not send the field
        // keeps the old, safe answer.
        if (!response.dialled) return error.RemoteRefused;
        return error.ExecFailed;
    }
    return response;
}

/// A reply this build could parse but could not believe: an accounting whose
/// digest is not one. Refused rather than stored — see `protocol.passedFrom`.
fn badReply(client: *DaemonClient) Ssh.ExecError {
    client.last_error = "daemon reported an output digest that is not a SHA-256";
    return error.ExecFailed;
}

/// What one request/response exchange produced.
const Exchange = union(enum) {
    reply: protocol.Response,
    /// The peer answered, but not in this build's protocol. Carries the version
    /// it claimed, when the reply was well-formed enough to read one — an older
    /// daemon's reply is not, because it is not framed.
    skew: ?u32,
    /// The conversation broke.
    broken,
};

/// Pings over this client's connection; returns the daemon pid, or null
/// on any failure (including protocol version mismatch).
pub fn ping(client: *DaemonClient) ?u32 {
    return switch (client.handshake()) {
        .ok => |pid| pid,
        .skew, .broken => null,
    };
}

const Handshake = union(enum) {
    ok: u32,
    /// A daemon speaking some other protocol, and the sentence that says so.
    skew: []const u8,
    /// Connected, but the conversation broke for a reason that is not a version.
    broken,
};

fn handshake(client: *DaemonClient) Handshake {
    return switch (client.roundTrip(client.arena, protocol.Request{ .v = protocol.version, .op = .ping })) {
        .reply => |response| if (response.ok) .{ .ok = response.pid } else .broken,
        .skew => |peer| .{ .skew = skewReason(client.arena, peer) },
        .broken => .broken,
    };
}

/// Asks the daemon to open the session this client's authority permits, and
/// returns its refusal if it will not.
///
/// `null` means authorised. The request carries the same host, auth and trust the
/// exec will, so what is checked here is what will be used — the daemon keys its
/// pool on exactly those, so the session this validates is the session that runs
/// the command.
///
/// A skew or a broken conversation is deliberately *not* a refusal: those mean the
/// daemon is unusable, and the caller's existing fallback to direct SSH is the
/// right answer for them.
fn authorise(client: *DaemonClient) ?[]const u8 {
    var request = client.request;
    request.op = .authorise;
    return switch (client.roundTrip(client.arena, request)) {
        .reply => |response| if (response.ok)
            null
        else
            client.arena.dupe(u8, response.@"error" orelse "the daemon refused to open a session") catch
                "the daemon refused to open a session",
        .skew, .broken => null,
    };
}

fn skewReason(arena: std.mem.Allocator, peer: ?u32) []const u8 {
    const fallback = "a daemon from another build holds the socket and does not speak this build's protocol; run `terminus daemon restart --force`, then retry";
    if (peer) |v| return std.fmt.allocPrint(
        arena,
        "a daemon from another build holds the socket (it speaks protocol v{d}, this build speaks v{d}); run `terminus daemon restart --force`, then retry",
        .{ v, protocol.version },
    ) catch fallback;
    return fallback;
}

pub fn stop(client: *DaemonClient) !void {
    switch (client.roundTrip(client.arena, protocol.Request{ .v = protocol.version, .op = .stop })) {
        .reply => {},
        .skew, .broken => return error.StopFailed,
    }
}

fn roundTrip(client: *DaemonClient, arena: std.mem.Allocator, request: protocol.Request) Exchange {
    var write_buffer: [1 << 16]u8 = undefined;
    var writer = client.stream.writer(client.io, &write_buffer);
    protocol.writeMessage(&writer.interface, request) catch return .broken;

    // Eight bytes is all this has to hold: the payload is read into an
    // allocation of exactly its announced size. The buffer used to be a 1 MiB
    // stack array that the whole reply had to fit inside, which is what turned a
    // large successful command into an unknown outcome.
    var read_buffer: [1 << 12]u8 = undefined;
    var reader = client.stream.reader(client.io, &read_buffer);
    const payload = (protocol.readFrame(&reader.interface, arena) catch |err| switch (err) {
        // An unframed answer is what a daemon from an older build sends. Its
        // version is unreadable from here, so the skew is named without one.
        error.MalformedFrame, error.FrameTooLarge => return .{ .skew = null },
        // A header this build could read, and a frame that did not arrive whole:
        // the daemon died, was killed, or had not finished starting. **Not a
        // skew**, and it used to be reported as one — which named a version that
        // was not the fault and told the operator to restart a daemon that had
        // already gone. See `protocol.FrameError.FrameIncomplete`.
        error.FrameIncomplete => return .broken,
        else => return .broken,
    }) orelse return .broken;

    const response = protocol.parseMessage(protocol.Response, arena, payload) catch |err| switch (err) {
        error.VersionMismatch => return .{ .skew = protocol.peerVersion(arena, payload) },
        error.MalformedMessage => return .broken,
    };
    return .{ .reply = response };
}

fn connectTo(io: std.Io, path: []const u8) ?std.Io.net.Stream {
    // Missing socket file surfaces as error.Unexpected on Windows, which
    // std prints a debug stack trace for — check existence first.
    std.Io.Dir.cwd().access(io, path, .{}) catch return null;
    const address = std.Io.net.UnixAddress.init(path) catch return null;
    return address.connect(io) catch null;
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
/// an explicit restart can launch a clean daemon. Best-effort — a graceful
/// `stop` should be tried first; this is the sledgehammer.
pub fn forceKillDaemon(io: std.Io, arena: std.mem.Allocator, environ: *std.process.Environ.Map) ForceKill {
    // Try a graceful stop first so a *responsive* daemon exits cleanly and
    // removes its own files; only fall through to killing by pid if it's
    // truly wedged.
    _ = stopDaemon(io, arena, environ);

    const pid = readPidFile(io, arena, environ);
    var killed = false;
    if (pid) |p| killed = terminatePid(p);

    // Whether or not a process was killed, clear the stale artifacts so the
    // an explicit start/restart can bind fresh.
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
