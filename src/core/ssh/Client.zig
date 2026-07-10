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
pub fn exec(client: *Client, arena: Allocator, command: []const u8) ExecError!ExecResult {
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

    var stdout: std.ArrayList(u8) = .empty;
    var stderr: std.ArrayList(u8) = .empty;
    try drainStream(channel, 0, arena, &stdout);
    try drainStream(channel, c.SSH_EXTENDED_DATA_STDERR, arena, &stderr);

    _ = c.libssh2_channel_close(channel);
    _ = c.libssh2_channel_wait_closed(channel);
    const exit_code = c.libssh2_channel_get_exit_status(channel);

    return .{
        .exit_code = exit_code,
        .stdout = try stdout.toOwnedSlice(arena),
        .stderr = try stderr.toOwnedSlice(arena),
    };
}

fn drainStream(
    channel: *c.LIBSSH2_CHANNEL,
    stream_id: c_int,
    arena: Allocator,
    out: *std.ArrayList(u8),
) ExecError!void {
    var buffer: [8192]u8 = undefined;
    while (true) {
        const n = c.libssh2_channel_read_ex(channel, stream_id, &buffer, buffer.len);
        if (n > 0) {
            try out.appendSlice(arena, buffer[0..@intCast(n)]);
        } else if (n == 0) {
            return; // EOF on this stream.
        } else {
            return error.ReadFailed;
        }
    }
}

pub const TransferError = error{
    ChannelOpenFailed,
    ReadFailed,
    WriteFailed,
    LocalFileFailed,
};

pub const Progress = struct {
    bytes: u64,
    total: u64,
};

/// Uploads a local file over SCP. `mode` is the remote permission bits
/// (e.g. 0o644). Streams in 1 MiB chunks; calls `on_progress` (if any)
/// after each chunk so the CLI can report throughput.
pub fn scpSend(
    client: *Client,
    io: std.Io,
    local_path: []const u8,
    remote_path: [:0]const u8,
    mode: c_int,
    on_progress: ?*const fn (Progress) void,
) TransferError!u64 {
    const cwd = std.Io.Dir.cwd();
    const file = cwd.openFile(io, local_path, .{}) catch return error.LocalFileFailed;
    defer file.close(io);
    const total = file.length(io) catch return error.LocalFileFailed;

    const channel = c.libssh2_scp_send64(
        client.session,
        remote_path.ptr,
        mode,
        @intCast(total),
        0,
        0,
    ) orelse return error.ChannelOpenFailed;
    defer _ = c.libssh2_channel_free(channel);

    var read_buffer: [1 << 20]u8 = undefined;
    var reader = file.reader(io, &read_buffer);
    var sent: u64 = 0;
    while (sent < total) {
        const chunk = reader.interface.peekGreedy(1) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return error.LocalFileFailed,
        };
        // libssh2 may accept fewer bytes than offered; loop per chunk.
        var offset: usize = 0;
        while (offset < chunk.len) {
            const n = c.libssh2_channel_write_ex(channel, 0, chunk.ptr + offset, chunk.len - offset);
            if (n < 0) return error.WriteFailed;
            offset += @intCast(n);
        }
        reader.interface.toss(chunk.len);
        sent += chunk.len;
        if (on_progress) |cb| cb(.{ .bytes = sent, .total = total });
    }

    _ = c.libssh2_channel_send_eof(channel);
    _ = c.libssh2_channel_wait_eof(channel);
    _ = c.libssh2_channel_close(channel);
    _ = c.libssh2_channel_wait_closed(channel);
    return sent;
}

/// Uploads an in-memory buffer over SCP (sync uses this for tar archives).
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
        if (n < 0) return error.WriteFailed;
        offset += @intCast(n);
    }
    _ = c.libssh2_channel_send_eof(channel);
    _ = c.libssh2_channel_wait_eof(channel);
    _ = c.libssh2_channel_close(channel);
    _ = c.libssh2_channel_wait_closed(channel);
    return data.len;
}

/// Downloads a remote file over SCP into memory.
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
        if (n == 0) break;
        received += @intCast(n);
    }
    return data[0..received];
}

/// Downloads a remote file over SCP into `local_path` (created/truncated).
pub fn scpRecv(
    client: *Client,
    io: std.Io,
    remote_path: [:0]const u8,
    local_path: []const u8,
    on_progress: ?*const fn (Progress) void,
) TransferError!u64 {
    var sb: c.libssh2_struct_stat = undefined;
    const channel = c.libssh2_scp_recv2(client.session, remote_path.ptr, &sb) orelse
        return error.ChannelOpenFailed;
    defer _ = c.libssh2_channel_free(channel);
    const total: u64 = @intCast(@max(sb.st_size, 0));

    const cwd = std.Io.Dir.cwd();
    const file = cwd.createFile(io, local_path, .{}) catch return error.LocalFileFailed;
    defer file.close(io);
    var write_buffer: [1 << 20]u8 = undefined;
    var writer = file.writerStreaming(io, &write_buffer);

    var buffer: [1 << 20]u8 = undefined;
    var received: u64 = 0;
    while (received < total) {
        const want: usize = @intCast(@min(buffer.len, total - received));
        const n = c.libssh2_channel_read_ex(channel, 0, &buffer, want);
        if (n < 0) return error.ReadFailed;
        if (n == 0) break; // EOF
        writer.interface.writeAll(buffer[0..@intCast(n)]) catch return error.LocalFileFailed;
        received += @intCast(n);
        if (on_progress) |cb| cb(.{ .bytes = received, .total = total });
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
        if (c.connect(socket, it.*.ai_addr, @intCast(it.*.ai_addrlen)) == 0)
            return socket;
        _ = c.closesocket(socket);
    }
    return error.ConnectFailed;
}
