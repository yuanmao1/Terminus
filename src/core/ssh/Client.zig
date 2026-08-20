//! libssh2-backed SSH client: TCP connect, handshake, authenticate, run
//! one command over a session channel.
//!
//! The TCP socket is created with winsock directly rather than
//! std.Io.net: on Windows the std Io implementation hands out raw AFD
//! device handles, which libssh2's internal send()/recv() cannot use.
//! Blocking mode throughout — fine for the M1 CLI process model. The M3
//! daemon revisits this with long-lived sessions.
const std = @import("std");
const Allocator = std.mem.Allocator;
const c = @import("ssh2");

const Client = @This();

socket: c.libssh2_socket_t,
session: *c.LIBSSH2_SESSION,

/// libssh2_init is process-global; the CLI is single-threaded so a plain
/// flag suffices.
var libssh2_ready = false;

/// Flip to true and rebuild to dump libssh2 protocol trace to stderr.
const trace_enabled = false;

/// Failure detail for `connect` errors, which have no live session for
/// `errorMessage` to query. Single-threaded CLI, module-level is fine.
var connect_error_buf: [512]u8 = undefined;
var connect_error: []const u8 = "";

pub fn lastConnectError() []const u8 {
    return connect_error;
}

pub const ConnectError = error{
    Libssh2Init,
    HostNotFound,
    ConnectFailed,
    HandshakeFailed,
    HostNameTooLong,
    OutOfMemory,
};

pub fn connect(host: []const u8, port: u16) ConnectError!Client {
    connect_error = "";
    if (!libssh2_ready) {
        var wsa: c.WSADATA = undefined;
        if (c.WSAStartup((2 << 8) | 2, &wsa) != 0) return error.Libssh2Init;
        if (c.libssh2_init(0) != 0) return error.Libssh2Init;
        libssh2_ready = true;
    }

    const socket = try tcpConnect(host, port);
    errdefer _ = c.closesocket(socket);

    const session = c.libssh2_session_init_ex(null, null, null, null) orelse
        return error.OutOfMemory;
    errdefer _ = c.libssh2_session_free(session);

    c.libssh2_session_set_blocking(session, 1);
    c.libssh2_session_set_timeout(session, 30_000);

    if (c.libssh2_session_handshake(session, socket) != 0) {
        var msg: [*c]u8 = undefined;
        var len: c_int = 0;
        _ = c.libssh2_session_last_error(session, &msg, &len, 0);
        if (msg != null and len > 0) {
            const n = @min(@as(usize, @intCast(len)), connect_error_buf.len);
            @memcpy(connect_error_buf[0..n], msg[0..n]);
            connect_error = connect_error_buf[0..n];
        }
        return error.HandshakeFailed;
    }

    return .{ .socket = socket, .session = session };
}

pub fn deinit(client: *Client) void {
    _ = c.libssh2_session_disconnect_ex(client.session, c.SSH_DISCONNECT_BY_APPLICATION, "bye", "");
    _ = c.libssh2_session_free(client.session);
    _ = c.closesocket(client.socket);
    client.* = undefined;
}

/// Most recent libssh2 error message; owned by the session.
pub fn errorMessage(client: *const Client) []const u8 {
    var msg: [*c]u8 = undefined;
    var len: c_int = 0;
    _ = c.libssh2_session_last_error(client.session, &msg, &len, 0);
    if (msg == null or len <= 0) return "unknown libssh2 error";
    return msg[0..@intCast(len)];
}

pub const Auth = union(enum) {
    password: []const u8,
    key: struct {
        private: []const u8,
        public: ?[]const u8 = null,
        passphrase: ?[]const u8 = null,
    },
};

pub const AuthError = error{ AuthFailed, UnsupportedKeyFormat };

/// What the WinCNG backend can actually parse. Everything else must be
/// rejected *before* reaching libssh2: feeding it any other format does
/// not fail cleanly — it wedges the session (observed with OPENSSH-format
/// RSA and PEM EC keys: the auth call never returns and ignores the
/// session timeout). Empirically only PKCS#1 PEM RSA works end-to-end.
pub const KeyFormat = enum {
    pem_rsa, // -----BEGIN RSA PRIVATE KEY----- (PKCS#1) — the ONLY supported format
    pem_ec, // -----BEGIN EC PRIVATE KEY----- — wedges WinCNG (expects openssh-key-v1)
    openssh, // -----BEGIN OPENSSH PRIVATE KEY----- — wedges WinCNG
    pkcs8, // -----BEGIN (ENCRYPTED) PRIVATE KEY----- — unsupported
    unknown,

    pub fn detect(key_bytes: []const u8) KeyFormat {
        if (std.mem.indexOf(u8, key_bytes, "BEGIN OPENSSH PRIVATE KEY") != null) return .openssh;
        if (std.mem.indexOf(u8, key_bytes, "BEGIN RSA PRIVATE KEY") != null) return .pem_rsa;
        if (std.mem.indexOf(u8, key_bytes, "BEGIN EC PRIVATE KEY") != null) return .pem_ec;
        if (std.mem.indexOf(u8, key_bytes, "BEGIN ENCRYPTED PRIVATE KEY") != null) return .pkcs8;
        if (std.mem.indexOf(u8, key_bytes, "BEGIN PRIVATE KEY") != null) return .pkcs8;
        return .unknown;
    }

    pub fn supported(format: KeyFormat) bool {
        return format == .pem_rsa;
    }

    /// User-facing conversion instructions for unsupported formats.
    pub fn adviceFor(format: KeyFormat) []const u8 {
        return switch (format) {
            .openssh =>
            \\OPENSSH-format private keys are not supported by the Windows crypto backend.
            \\If this is an RSA key, convert a COPY to PEM (rewrites the file in place):
            \\  copy id_rsa id_rsa.pem && ssh-keygen -p -m PEM -f id_rsa.pem -N ""
            \\ed25519/ECDSA keys cannot be used at all (backend limitation). Generate a
            \\dedicated RSA key for Terminus and add its .pub to the server:
            \\  ssh-keygen -t rsa -b 4096 -m PEM -f terminus_key
            ,
            .pem_ec =>
            \\EC (ECDSA) private keys are not supported by the Windows crypto backend.
            \\Generate a dedicated RSA key for Terminus and add its .pub to the server:
            \\  ssh-keygen -t rsa -b 4096 -m PEM -f terminus_key
            ,
            .pkcs8 =>
            \\PKCS#8-format private keys are not supported. Convert to traditional PEM:
            \\  openssl rsa -in key.pk8 -out key.pem -traditional
            ,
            else =>
            \\Unrecognized private key format. Terminus needs a PKCS#1 PEM RSA key
            \\("-----BEGIN RSA PRIVATE KEY-----"). Generate one:
            \\  ssh-keygen -t rsa -b 4096 -m PEM -f terminus_key
            ,
        };
    }
};

pub fn authenticate(client: *Client, username: []const u8, auth: Auth) AuthError!void {
    if (auth == .key) {
        // Guard: see KeyFormat docs — unsupported formats wedge libssh2.
        if (!KeyFormat.detect(auth.key.private).supported())
            return error.UnsupportedKeyFormat;
    }
    const rc = switch (auth) {
        .password => |password| c.libssh2_userauth_password_ex(
            client.session,
            username.ptr,
            @intCast(username.len),
            password.ptr,
            @intCast(password.len),
            null,
        ),
        .key => |key| c.libssh2_userauth_publickey_frommemory(
            client.session,
            username.ptr,
            username.len,
            if (key.public) |p| p.ptr else null,
            if (key.public) |p| p.len else 0,
            key.private.ptr,
            key.private.len,
            if (key.passphrase) |p| p.ptr else null,
        ),
    };
    if (rc != 0) return error.AuthFailed;
}

pub const ExecResult = struct {
    exit_code: i32,
    stdout: []u8,
    stderr: []u8,
};

pub const ExecError = error{
    ChannelOpenFailed,
    ExecFailed,
    ReadFailed,
    OutOfMemory,
};

/// Runs one command over a fresh session channel and drains stdout/stderr
/// to completion.
///
/// The session's 30s timeout guards connect/handshake/auth, but a command
/// may legitimately stay silent for many minutes (large table scans,
/// builds). While waiting on command output the timeout is lifted; a dead
/// peer is eventually caught by TCP, the caller's own timeout, or the
/// user interrupting.
pub fn exec(client: *Client, arena: Allocator, command: []const u8) ExecError!ExecResult {
    if (trace_enabled) _ = c.libssh2_trace(client.session, ~@as(c_int, 0));
    const channel = c.libssh2_channel_open_ex(
        client.session,
        "session",
        "session".len,
        c.LIBSSH2_CHANNEL_WINDOW_DEFAULT,
        c.LIBSSH2_CHANNEL_PACKET_DEFAULT,
        null,
        0,
    ) orelse return error.ChannelOpenFailed;
    defer _ = c.libssh2_channel_free(channel);

    if (c.libssh2_channel_process_startup(
        channel,
        "exec",
        "exec".len,
        command.ptr,
        @intCast(command.len),
    ) != 0) return error.ExecFailed;

    // Read output under no timeout (a command may be silent for minutes),
    // then restore the default timeout *before* channel teardown so a slow
    // close can't wedge the next exec on the pooled connection.
    c.libssh2_session_set_timeout(client.session, 0);
    var stdout: std.ArrayList(u8) = .empty;
    var stderr: std.ArrayList(u8) = .empty;
    const drain_result = drainBoth(channel, arena, &stdout, &stderr);
    c.libssh2_session_set_timeout(client.session, 30_000);
    try drain_result;

    _ = c.libssh2_channel_close(channel);
    _ = c.libssh2_channel_wait_closed(channel);
    const exit_code = c.libssh2_channel_get_exit_status(channel);

    return .{
        .exit_code = exit_code,
        .stdout = try stdout.toOwnedSlice(arena),
        .stderr = try stderr.toOwnedSlice(arena),
    };
}

/// Runs a command feeding `input` to its stdin, then drains stdout/stderr.
/// The channel is 8-bit clean, so arbitrary binary can stream through —
/// this is how exec-based file transfer moves bytes in one round trip.
///
/// Unlike `exec`, the 30s session timeout stays armed: transfer data
/// should flow continuously, so a 30s stall means the channel is wedged
/// (an intermittent libssh2 blocking-read issue under bulk traffic) and
/// the caller retries rather than hanging forever.
pub fn execWithStdin(client: *Client, arena: Allocator, command: []const u8, input: []const u8) ExecError!ExecResult {
    const channel = c.libssh2_channel_open_ex(
        client.session,
        "session",
        "session".len,
        c.LIBSSH2_CHANNEL_WINDOW_DEFAULT,
        c.LIBSSH2_CHANNEL_PACKET_DEFAULT,
        null,
        0,
    ) orelse return error.ChannelOpenFailed;
    defer _ = c.libssh2_channel_free(channel);

    if (c.libssh2_channel_process_startup(
        channel,
        "exec",
        "exec".len,
        command.ptr,
        @intCast(command.len),
    ) != 0) return error.ExecFailed;

    var offset: usize = 0;
    while (offset < input.len) {
        const n = c.libssh2_channel_write_ex(channel, 0, input.ptr + offset, input.len - offset);
        if (n < 0) return error.ExecFailed;
        offset += @intCast(n);
    }
    _ = c.libssh2_channel_send_eof(channel);

    c.libssh2_session_set_timeout(client.session, 0);
    defer c.libssh2_session_set_timeout(client.session, 30_000);

    var stdout: std.ArrayList(u8) = .empty;
    var stderr: std.ArrayList(u8) = .empty;
    try drainBoth(channel, arena, &stdout, &stderr);

    _ = c.libssh2_channel_close(channel);
    _ = c.libssh2_channel_wait_closed(channel);

    return .{
        .exit_code = c.libssh2_channel_get_exit_status(channel),
        .stdout = try stdout.toOwnedSlice(arena),
        .stderr = try stderr.toOwnedSlice(arena),
    };
}

/// Interleaved blocking drain of stdout+stderr until channel EOF. Reading
/// one stream to EOF before the other can deadlock — libssh2's per-channel
/// receive window is shared, so draining both keeps it moving. Callers
/// keep any single command's stdout under a few hundred KiB (see
/// core/transfer.zig chunking); beyond that libssh2's blocking reader can
/// still wedge on window bookkeeping.
fn drainBoth(
    channel: *c.LIBSSH2_CHANNEL,
    arena: Allocator,
    out: *std.ArrayList(u8),
    err: *std.ArrayList(u8),
) ExecError!void {
    var buffer: [256 * 1024]u8 = undefined;
    var out_eof = false;
    var err_eof = false;
    while (!out_eof or !err_eof) {
        // Read stdout greedily first; only poll stderr once stdout is
        // drained (or the channel signals EOF) so an idle stderr never
        // stalls the loop, and each iteration moves as much as possible.
        if (!out_eof) {
            const no = c.libssh2_channel_read_ex(channel, 0, &buffer, buffer.len);
            if (no > 0) {
                try out.appendSlice(arena, buffer[0..@intCast(no)]);
                continue; // keep pulling stdout while it flows
            } else if (no == 0) {
                out_eof = true;
            } else if (no != c.LIBSSH2_ERROR_EAGAIN) {
                return error.ReadFailed;
            }
        }
        if (!err_eof) {
            const ne = c.libssh2_channel_read_ex(channel, c.SSH_EXTENDED_DATA_STDERR, &buffer, buffer.len);
            if (ne > 0) {
                try err.appendSlice(arena, buffer[0..@intCast(ne)]);
            } else {
                err_eof = true; // 0 (EOF) or error: stop reading stderr
            }
        }
    }
}

// --- Streaming file transfer over SCP ----------------------------------------
//
// Three properties hold across every function below, and each one replaces a
// pseudo-success this section used to report.
//
// **A short transfer is an error, never a byte count.** `libssh2_scp_send64` is
// told the length before the first byte goes out, so a send that stops early
// desynchronises the protocol and leaves a remote file that is not the one we
// described — and `scpSend` used to `break` out of the loop and `return sent`,
// which a caller reads as "this many bytes, successfully". A recv that stops
// early leaves fewer bytes than the remote's own stat announced, and both
// `scpRecv` and `scpRecvBytes` reported that the same way. What was expected and
// what arrived travel out through `moved`, because an error set cannot carry two
// numbers and the caller has to print both.
//
// **A recv writes where the caller stages, never at its destination.**
// `CreateFileOptions.truncate` defaults to true, so `createFile` on a
// destination destroys the file already there before a single byte has arrived —
// a pull that then fails halfway has already taken away what the operator had.
// The parameter is named `partial_path` for that reason and the only in-tree
// caller hands it a staging path beside the destination; the rename that
// publishes it is the driver's, and it happens after the digests agree.
//
// **Every chunk is offered to the caller before the next one is asked for.**
// That is how a driver hashes what it is moving and advances a durable offset
// without the bytes ever being held twice: `Observer` sees the transfer's own
// buffer, so the peak stays at the buffer size no matter how large the file is.

pub const TransferError = error{
    ChannelOpenFailed,
    ReadFailed,
    WriteFailed,
    LocalFileFailed,
    /// Fewer bytes left this machine than the SCP header promised the remote.
    /// The remote file is not the file we described, so this is a failure and
    /// not a smaller success. See `Moved` for the two numbers.
    ShortSend,
    /// Fewer bytes arrived than the remote's own stat announced. See `Moved`.
    ShortReceive,
    /// The caller's per-chunk observer refused, so the transfer stopped. Its
    /// own reason is in its own context — see `ChunkError`.
    ObserverFailed,
};

/// What a transfer moved, against what it was promised.
///
/// An out-parameter rather than part of the return value, because the caller
/// needs it on precisely the path where there is no return value: `ShortSend`
/// and `ShortReceive` are the two errors whose entire content is these two
/// numbers. Written before anything in the call can fail, so a caller reading it
/// after an error is reading this call's numbers rather than the last call's.
pub const Moved = struct {
    expected: u64 = 0,
    arrived: u64 = 0,
};

/// The one thing an observer may refuse with.
///
/// One member on purpose. An observer's real failure is its own — a ledger
/// write, a disk write, a digest that disagreed — and it belongs in the
/// observer's own context where it still has a type. Funnelling it through here
/// would make every primitive in this section return `anyerror` and would put
/// the ledger's error set inside the SSH layer's.
pub const ChunkError = error{ObserverFailed};

/// Called with each chunk as it moves, before the next one is asked for.
pub const Observer = struct {
    context: *anyopaque,
    /// `chunk` is the transfer's own buffer and is valid only for this call.
    /// `moved` is the running total *including* this chunk.
    on_chunk: *const fn (context: *anyopaque, chunk: []const u8, moved: u64, total: u64) ChunkError!void,

    /// Offers one chunk. `pub` because both backends call it: the exec-channel
    /// transfer in `core/transfer.zig` holds the same contract, so a driver
    /// hashes and records progress identically whichever one moved the bytes.
    pub fn offer(self: Observer, chunk: []const u8, moved: u64, total: u64) ChunkError!void {
        return self.on_chunk(self.context, chunk, moved, total);
    }
};

/// The streaming window, in both directions. Bounded and constant: this is the
/// number that makes a transfer's peak memory independent of the file's size.
pub const chunk_bytes = 1 << 20;

/// Uploads a local file over SCP in constant memory. `mode` is the remote
/// permission bits (e.g. 0o644).
///
/// `observer` sees every chunk as it goes out, which is what lets a driver hash
/// the bytes it is sending and record a durable offset behind them without ever
/// holding the file.
pub fn scpSend(
    client: *Client,
    io: std.Io,
    local_path: []const u8,
    remote_path: [:0]const u8,
    mode: c_int,
    observer: ?Observer,
    moved: *Moved,
) TransferError!u64 {
    moved.* = .{};
    const cwd = std.Io.Dir.cwd();
    const file = cwd.openFile(io, local_path, .{}) catch return error.LocalFileFailed;
    defer file.close(io);
    const total = file.length(io) catch return error.LocalFileFailed;
    moved.expected = total;

    const channel = c.libssh2_scp_send64(
        client.session,
        remote_path.ptr,
        mode,
        @intCast(total),
        0,
        0,
    ) orelse return error.ChannelOpenFailed;
    defer _ = c.libssh2_channel_free(channel);

    var read_buffer: [chunk_bytes]u8 = undefined;
    var reader = file.reader(io, &read_buffer);
    var sent: u64 = 0;
    while (sent < total) {
        const available = reader.interface.peekGreedy(1) catch |err| switch (err) {
            // The file ended before the length we already put in the SCP
            // header. The remote is waiting for bytes that do not exist, so
            // this is a short send and the caller is told both numbers.
            error.EndOfStream => {
                moved.arrived = sent;
                return error.ShortSend;
            },
            else => return error.LocalFileFailed,
        };
        // Clamped: a file that grew under us must not be sent past the length
        // the header promised, which the remote would read as the next file.
        const chunk = available[0..@min(available.len, @as(usize, @intCast(total - sent)))];
        // libssh2 may accept fewer bytes than offered; loop per chunk. A
        // non-positive return is a failure and not a reason to offer the same
        // bytes forever — zero used to spin here.
        var offset: usize = 0;
        while (offset < chunk.len) {
            const n = c.libssh2_channel_write_ex(channel, 0, chunk.ptr + offset, chunk.len - offset);
            if (n <= 0) return error.WriteFailed;
            offset += @intCast(n);
        }
        reader.interface.toss(chunk.len);
        sent += chunk.len;
        moved.arrived = sent;
        if (observer) |o| try o.offer(chunk, sent, total);
    }

    _ = c.libssh2_channel_send_eof(channel);
    _ = c.libssh2_channel_wait_eof(channel);
    _ = c.libssh2_channel_close(channel);
    _ = c.libssh2_channel_wait_closed(channel);
    return sent;
}

/// Uploads an in-memory buffer over SCP (sync uses this for tar archives).
///
/// Cannot under-send: the loop only leaves at `offset == data.len`. What it
/// could do was spin forever on a zero-length write, which is now a failure.
pub fn scpSendBytes(
    client: *Client,
    io: std.Io,
    data: []const u8,
    remote_path: [:0]const u8,
    mode: c_int,
) TransferError!u64 {
    _ = io;
    const channel = c.libssh2_scp_send64(
        client.session,
        remote_path.ptr,
        mode,
        @intCast(data.len),
        0,
        0,
    ) orelse return error.ChannelOpenFailed;
    defer _ = c.libssh2_channel_free(channel);

    var offset: usize = 0;
    while (offset < data.len) {
        const n = c.libssh2_channel_write_ex(channel, 0, data.ptr + offset, data.len - offset);
        if (n <= 0) return error.WriteFailed;
        offset += @intCast(n);
    }
    _ = c.libssh2_channel_send_eof(channel);
    _ = c.libssh2_channel_wait_eof(channel);
    _ = c.libssh2_channel_close(channel);
    _ = c.libssh2_channel_wait_closed(channel);
    return data.len;
}

/// Downloads a remote file over SCP into memory.
///
/// A truncated download used to come back as `data[0..received]` — a shorter
/// slice, which a caller reads as a shorter file. It is `ShortReceive` now, for
/// the same reason `scpRecv`'s is.
///
/// No `moved` out-parameter, unlike the two streaming primitives, and the
/// signature is the reason: `cmd_sync` calls this for its tar archive and
/// recovers by falling back to the exec backend, so it never asks how far the
/// SCP attempt got. Adding a parameter only the caller that does not exist would
/// read is a signature change made for nobody.
pub fn scpRecvBytes(
    client: *Client,
    io: std.Io,
    arena: Allocator,
    remote_path: [:0]const u8,
) (TransferError || Allocator.Error)![]u8 {
    _ = io;
    var sb: c.libssh2_struct_stat = undefined;
    const channel = c.libssh2_scp_recv2(client.session, remote_path.ptr, &sb) orelse
        return error.ChannelOpenFailed;
    defer _ = c.libssh2_channel_free(channel);
    const total: u64 = @intCast(@max(sb.st_size, 0));

    const data = try arena.alloc(u8, total);
    var received: usize = 0;
    while (received < total) {
        const n = c.libssh2_channel_read_ex(channel, 0, data.ptr + received, total - received);
        if (n < 0) return error.ReadFailed;
        if (n == 0) return error.ShortReceive;
        received += @intCast(n);
    }
    return data[0..received];
}

/// Downloads a remote file over SCP into `partial_path`, in constant memory.
///
/// **`partial_path` must be a staging path, never the caller's destination.**
/// The file is created with the default `truncate = true`, so a destination
/// handed here is emptied before a byte has arrived and a transfer that then
/// fails has already destroyed what was there. Publishing is the driver's job
/// and happens by rename, after the digests agree.
pub fn scpRecv(
    client: *Client,
    io: std.Io,
    remote_path: [:0]const u8,
    partial_path: []const u8,
    observer: ?Observer,
    moved: *Moved,
) TransferError!u64 {
    moved.* = .{};
    var sb: c.libssh2_struct_stat = undefined;
    const channel = c.libssh2_scp_recv2(client.session, remote_path.ptr, &sb) orelse
        return error.ChannelOpenFailed;
    defer _ = c.libssh2_channel_free(channel);
    const total: u64 = @intCast(@max(sb.st_size, 0));
    moved.expected = total;

    const cwd = std.Io.Dir.cwd();
    const file = cwd.createFile(io, partial_path, .{}) catch return error.LocalFileFailed;
    defer file.close(io);
    var write_buffer: [chunk_bytes]u8 = undefined;
    var writer = file.writerStreaming(io, &write_buffer);

    var buffer: [chunk_bytes]u8 = undefined;
    var received: u64 = 0;
    while (received < total) {
        const want: usize = @intCast(@min(buffer.len, total - received));
        const n = c.libssh2_channel_read_ex(channel, 0, &buffer, want);
        if (n < 0) return error.ReadFailed;
        // The channel closed before the length the remote's own stat
        // announced. The staged partial is short, so this is a failure — it
        // used to be a smaller return value.
        if (n == 0) {
            writer.interface.flush() catch {};
            moved.arrived = received;
            return error.ShortReceive;
        }
        const chunk = buffer[0..@intCast(n)];
        writer.interface.writeAll(chunk) catch return error.LocalFileFailed;
        received += chunk.len;
        moved.arrived = received;
        if (observer) |o| try o.offer(chunk, received, total);
    }
    writer.interface.flush() catch return error.LocalFileFailed;
    return received;
}

/// getaddrinfo + socket + connect, trying each resolved address.
fn tcpConnect(host: []const u8, port: u16) ConnectError!c.libssh2_socket_t {
    var host_buf: [256]u8 = undefined;
    if (host.len >= host_buf.len) return error.HostNameTooLong;
    const host_z = std.fmt.bufPrintZ(&host_buf, "{s}", .{host}) catch unreachable;
    var port_buf: [8]u8 = undefined;
    const port_z = std.fmt.bufPrintZ(&port_buf, "{d}", .{port}) catch unreachable;

    const hints: c.addrinfo = .{
        .ai_family = c.AF_UNSPEC,
        .ai_socktype = c.SOCK_STREAM,
        .ai_protocol = c.IPPROTO_TCP,
    };
    var info: [*c]c.addrinfo = null;
    if (c.getaddrinfo(host_z.ptr, port_z.ptr, &hints, &info) != 0)
        return error.HostNotFound;
    defer c.freeaddrinfo(info);

    var it = info;
    while (it != null) : (it = it.*.ai_next) {
        const socket = c.socket(it.*.ai_family, it.*.ai_socktype, it.*.ai_protocol);
        if (socket == c.INVALID_SOCKET) continue;
        if (c.connect(socket, it.*.ai_addr, @intCast(it.*.ai_addrlen)) == 0) {
            tuneSocket(socket);
            return socket;
        }
        _ = c.closesocket(socket);
    }
    return error.ConnectFailed;
}

/// TCP_NODELAY + large SO_RCVBUF. Without NODELAY, libssh2's small
/// request writes interleave with reads under Nagle + delayed-ACK, adding
/// ~40-200 ms per round trip — which turns a many-packet bulk transfer
/// into minutes. A big receive buffer lets the kernel pull whole windows.
fn tuneSocket(socket: c.libssh2_socket_t) void {
    // IPPROTO_TCP = 6, TCP_NODELAY = 1, SOL_SOCKET = 0xffff, SO_RCVBUF = 0x1002
    // (Winsock constants; translate-c can't render the macros).
    var one: c_int = 1;
    _ = c.setsockopt(socket, 6, 1, @ptrCast(&one), @sizeOf(c_int));
    var rcvbuf: c_int = 4 * 1024 * 1024;
    _ = c.setsockopt(socket, 0xffff, 0x1002, @ptrCast(&rcvbuf), @sizeOf(c_int));
}
