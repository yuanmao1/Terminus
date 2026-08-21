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
// The input channel hashes what it sends as it sends it. `digest` imports only
// `std`, so this closes no cycle, and taking a second pass over the source
// instead would be both slower and a chance for the count and the digest to
// describe different bytes.
const digest = @import("../digest.zig");

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
/// to completion, **keeping the whole of both**.
///
/// No ceiling, deliberately, and one caller is the reason: `transfer.pullBytes`
/// verifies a SHA-256 over the entire object it downloads, so it must hold the
/// entire object. Everything else on this entry point asks a question with a
/// small answer — a stat, a `command -v`, one 128 KiB range of a file. The
/// command path, where the answer's size is the *user's* choice and there is no
/// upper bound on it at all, goes through `execRetained` instead.
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
    var stdout: Capture = .init(arena, null);
    var stderr: Capture = .init(arena, null);
    const drain_result = drainBoth(channel, &stdout, &stderr);
    c.libssh2_session_set_timeout(client.session, 30_000);
    try drain_result;

    _ = c.libssh2_channel_close(channel);
    _ = c.libssh2_channel_wait_closed(channel);
    const exit_code = c.libssh2_channel_get_exit_status(channel);

    return .{
        .exit_code = exit_code,
        .stdout = try stdout.render(arena),
        .stderr = try stderr.render(arena),
    };
}

// --- the input channel -------------------------------------------------------
//
// Local bytes into a remote process's standard input. Streaming from the first
// line rather than retrofitted onto a `[]const u8`: the source is a reader, the
// pump holds no buffer of its own, and nothing here ever knows the total — so
// there is no size at which this stops working and no ceiling to hit quietly.
//
// Two facts about `libssh2_channel_write_ex` shape the whole of it, and both are
// already written down twice in this file (`scpSend`, `scpSendBytes`):
//
//   * a return **smaller than the request is normal**. The channel takes what
//     its window allows and the rest is offered again. Treating it as an error
//     would fail ordinary traffic; treating it as the whole request would file a
//     count for bytes that never left.
//   * a return of **zero is a failure**, not a reason to offer the same bytes
//     forever. That spin is a bug this file has already had.

/// The hex digest of a stream with nothing in it.
///
/// A literal, so the zero value of `Accepted` is already a true statement about
/// zero bytes and a reading taken after a failure that accepted nothing needs no
/// special case. Held against `digest.hex("")` by a gate, so it cannot rot.
pub const empty_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// What the input channel took, and the digest of exactly those bytes.
///
/// An out-parameter rather than part of a return value, for the reason `Moved`
/// is one: the caller needs it precisely on the path where there is no return
/// value. `InputRejected`'s entire content is this number, and a receipt that
/// answered with the source's length instead would be claiming bytes arrived
/// that the channel never took.
///
/// The two fields move together, after every accepted piece, so they are one
/// observation of one set of bytes at every exit from the pump — including the
/// failing ones. A count advanced now and a digest finalised later is how the
/// two come to disagree.
pub const Accepted = struct {
    /// Bytes the channel accepted. Never what was offered.
    bytes: u64 = 0,
    /// Hex SHA-256 of exactly `bytes` bytes of input.
    sha256: [digest.hex_len]u8 = empty_sha256.*,
};

pub const InputError = error{
    /// The local source could not be read to its end. Whatever the channel had
    /// already taken is in `Accepted`, and the remote was never told the input
    /// ended.
    InputSourceUnreadable,
    /// The channel stopped taking bytes before the source was exhausted — it
    /// refused, or it accepted nothing at all. `Accepted` is what it did take.
    InputRejected,
    /// The bytes all went and the end-of-input marker did not. The remote
    /// process is reading a channel that will never close, so this is a failure
    /// and not a completed send.
    InputEofNotSent,
    /// This transport has no third channel to stream into. Not a fallback
    /// point: a command that reads stdin and is handed an immediate EOF
    /// "succeeds" having done nothing, which is the worst available answer.
    InputUnsupported,
};

/// Where accepted input bytes go.
///
/// An interface rather than the channel directly, because the channel is the one
/// part of this that no test can reach: there is no server to open one against.
/// Everything above the sink — the short-write loop, the refusal of a zero
/// accept, the digest of what was taken, the end-of-input marker — is driven
/// through a stand-in sink instead of reviewed.
pub const InputSink = struct {
    context: *anyopaque,
    /// Offers bytes; answers how many were **accepted**, which may be fewer.
    /// Zero is not this function's decision to make — see `pumpInput`.
    on_offer: *const fn (context: *anyopaque, bytes: []const u8) InputError!usize,
    /// Tells the far side the input has ended. Called once, after the last
    /// accepted byte, and never on a failing path.
    on_end: *const fn (context: *anyopaque) InputError!void,

    pub fn offer(self: InputSink, bytes: []const u8) InputError!usize {
        return self.on_offer(self.context, bytes);
    }

    pub fn end(self: InputSink) InputError!void {
        return self.on_end(self.context);
    }
};

/// Streams `source` into `sink`, recording exactly what was accepted.
///
/// No buffer of its own: it peeks at the reader's window and tosses what the
/// sink took, so the peak is the window the caller chose and does not move with
/// the length of the input. No allocator either, which is the strongest form of
/// that claim available — there is nowhere for a proportional allocation to
/// live.
///
/// **The end-of-input marker is the pump's, and only on success.** A remote
/// process reads until EOF, so failing to send it leaves that process waiting
/// for bytes that will never come. Sending it after a rejected write would be
/// worse: it would hand the remote a truncated input that looks complete, and
/// the command would act on a prefix believing it had the whole thing.
pub fn pumpInput(source: *std.Io.Reader, sink: InputSink, taken: *Accepted) InputError!void {
    // Written before anything can fail, so a caller reading it after an error is
    // reading this call's numbers and not the last call's.
    taken.* = .{};
    var running: digest.Running = .init();

    while (true) {
        const chunk = source.peekGreedy(1) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return error.InputSourceUnreadable,
        };
        var offset: usize = 0;
        while (offset < chunk.len) {
            const n = try sink.offer(chunk[offset..]);
            // Held here rather than in each sink, so no sink can spin by
            // forgetting it.
            if (n == 0) return error.InputRejected;
            std.debug.assert(n <= chunk.len - offset);
            running.update(chunk[offset..][0..n]);
            offset += n;
            taken.bytes += n;
            _ = running.peekHex(&taken.sha256);
        }
        source.toss(chunk.len);
    }

    try sink.end();
}

/// The libssh2 side of `InputSink`.
const ChannelInput = struct {
    channel: *c.LIBSSH2_CHANNEL,

    fn offer(context: *anyopaque, bytes: []const u8) InputError!usize {
        const self: *ChannelInput = @ptrCast(@alignCast(context));
        const n = c.libssh2_channel_write_ex(self.channel, 0, bytes.ptr, bytes.len);
        // Negative is the channel's failure. Zero is not judged here: the pump
        // owns that rule for every sink at once.
        if (n < 0) return error.InputRejected;
        return @intCast(n);
    }

    fn end(context: *anyopaque) InputError!void {
        const self: *ChannelInput = @ptrCast(@alignCast(context));
        // This return used to be discarded. A dropped EOF is not a cosmetic
        // loss: the remote process blocks on a read that never completes, and
        // the drain below blocks waiting for output it will never produce, so
        // the whole command hangs until somebody's timeout fires.
        if (c.libssh2_channel_send_eof(self.channel) != 0) return error.InputEofNotSent;
    }

    fn sink(self: *ChannelInput) InputSink {
        return .{ .context = self, .on_offer = offer, .on_end = end };
    }
};

/// Runs a command under a ceiling on what is kept from its output, optionally
/// streaming `input` to its standard input first. The channel is 8-bit clean, so
/// arbitrary binary goes through unchanged in both directions — no base64, no
/// shell quoting of the payload.
///
/// `input.accepted` is filled whether this succeeds or fails, and it is what the
/// receipt records: the count the channel accepted and the digest of those same
/// bytes. `output` is likewise filled on every path, including the failing ones,
/// so a caller reading it after an error is reading this call's numbers rather
/// than the last call's — and it carries the whole truth about the output even
/// though only the ends of it survive. See `Capture`.
///
/// Optional input rather than a second function: this and a no-input variant
/// differ in the two lines that pump, and in fifty identical ones. `runCommand`
/// makes the same choice for the same reason, and one function needs no gate
/// holding two copies of the drain against each other.
///
/// The 30s session timeout stays armed while the input flows: input should move
/// continuously, so a 30s stall means the channel is wedged (an intermittent
/// libssh2 blocking-read issue under bulk traffic) and the caller retries rather
/// than hanging forever. It is lifted only for the drain, where a command may
/// legitimately stay silent for minutes, and restored *before* channel teardown
/// so a slow close cannot wedge the next exec on the pooled connection. The
/// stdin path used to restore it on a `defer` instead, i.e. after teardown; two
/// orderings existed because two functions did, and this is the one with the
/// reason written beside it.
pub fn execRetained(
    client: *Client,
    arena: Allocator,
    command: []const u8,
    input: ?InputStream,
    output: *Retained,
) (ExecError || InputError)!ExecResult {
    output.* = .{};
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

    if (input) |in| {
        var sink: ChannelInput = .{ .channel = channel };
        try pumpInput(in.source, sink.sink(), in.accepted);
    }

    c.libssh2_session_set_timeout(client.session, 0);
    var stdout: Capture = .init(arena, output_ceiling);
    var stderr: Capture = .init(arena, output_ceiling);
    const drain_result = drainBoth(channel, &stdout, &stderr);
    c.libssh2_session_set_timeout(client.session, 30_000);
    // Before the error is raised, so a transport loss reports what did arrive
    // rather than a zero.
    output.stdout = stdout.passed();
    output.stderr = stderr.passed();
    try drain_result;

    _ = c.libssh2_channel_close(channel);
    _ = c.libssh2_channel_wait_closed(channel);

    return .{
        .exit_code = c.libssh2_channel_get_exit_status(channel),
        .stdout = try stdout.render(arena),
        .stderr = try stderr.render(arena),
    };
}

/// Interleaved blocking drain of stdout+stderr until channel EOF. Reading
/// one stream to EOF before the other can deadlock — libssh2's per-channel
/// receive window is shared, so draining both keeps it moving.
///
/// The reads are a fixed `read_bytes` and the captures bound what they keep, so
/// this loop's own cost does not move with the size of the output. What libssh2
/// does under bulk traffic is a separate matter: beyond a few hundred KiB its
/// blocking reader can still wedge on window bookkeeping, which is why
/// `core/transfer.zig` asks for one bounded range at a time rather than relying
/// on a ceiling here.
fn drainBoth(
    channel: *c.LIBSSH2_CHANNEL,
    out: *Capture,
    err: *Capture,
) ExecError!void {
    var buffer: [read_bytes]u8 = undefined;
    var out_eof = false;
    var err_eof = false;
    while (!out_eof or !err_eof) {
        // Read stdout greedily first; only poll stderr once stdout is
        // drained (or the channel signals EOF) so an idle stderr never
        // stalls the loop, and each iteration moves as much as possible.
        if (!out_eof) {
            const no = c.libssh2_channel_read_ex(channel, 0, &buffer, buffer.len);
            if (no > 0) {
                try out.push(buffer[0..@intCast(no)]);
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
                try err.push(buffer[0..@intCast(ne)]);
            } else {
                err_eof = true; // 0 (EOF) or error: stop reading stderr
            }
        }
    }
}

// --- the output ceiling ------------------------------------------------------
//
// A command's output has no upper bound. `drainBoth` used to append every byte
// of it into an `ArrayList` on the arena, so a command that printed ten
// gigabytes cost ten gigabytes of local memory. What follows bounds that, and
// the shape it bounds it into is decided by the supervisor's markers rather than
// chosen for elegance.
//
// `supervisor.wrapShell` puts an identity line **first** on stdout and an exit
// line **last**, with the command's own output between them, and
// `supervisor.parseShell` needs both. So:
//
//   * a head-only cap loses the exit marker, and every large-output command
//     settles `indeterminate` — a working command turned into an unknown
//     outcome, which is far worse than the memory it saved;
//   * a tail-only cap loses the start marker, and the attempt loses the
//     pid/pgid it would be reconciled by.
//
// Retention therefore keeps **both ends and drops the middle**. The tail is a
// ring, which is what makes it independent of where the reads happened to fall:
// it holds the last `tail` bytes of the stream whether or not a 256 KiB read
// stopped in the middle of the exit-marker line.
//
// Two things are true of every byte regardless of whether it was kept. It is
// **counted**, and it is **hashed**. That is the load-bearing idea here: the
// receipt can prove exactly what came out of a command whose middle the caller
// never sees, so a truncated run is still an auditable one.
//
// The digest is of the stream **as it arrived on the channel**, supervision
// markers included. Not a compromise: nothing can know which line is the exit
// marker until it has seen the whole stream, and a digest taken incrementally
// must therefore be taken before parsing. Shell mode already declares
// `binary_framing = false` for precisely this reason — the stream it produces is
// annotated and is not the command's bytes — so hashing what arrived is the only
// honest reading available, and it is the one the ledger stores.

/// The read size `drainBoth` uses, and the unit a transport that hands its reply
/// over whole is treated as having handed it over in. `pub` so a harness can
/// reproduce a read boundary falling inside the exit marker.
pub const read_bytes = 256 * 1024;

/// How much of a stream survives: the first `head` bytes and the last `tail`.
pub const Ceiling = struct {
    head: usize,
    tail: usize,

    pub fn total(self: Ceiling) usize {
        return self.head + self.tail;
    }
};

/// The ceiling on a command's output.
///
/// 1 MiB, split evenly, and each half of the split is doing something:
///
///   * The **head** carries the start-marker line, so the attempt keeps its
///     pid/pgid identity no matter how much followed it.
///   * The **tail** carries the exit-marker line, so the outcome is still known.
///     `execution.exit_marker_max_line` holds a compile-time floor under it —
///     losing that line is the one truncation that would change a command's
///     answer rather than merely shortening it.
///
/// The size is 1 MiB for three reasons. It is the same order as the daemon
/// transport's own reply frame (`daemon/Client.roundTrip` reads through a 1 MiB
/// buffer), so the two transports agree about what counts as a large output
/// rather than one truncating what the other refuses. It is four times
/// `read_bytes`, so the ring is never smaller than a single read and the
/// straddle case has margin rather than exact arithmetic. And a megabyte of text
/// is ten to fifteen thousand lines — more than any operator or agent reads in
/// full, and more than any command this tree issues through `runCommand`
/// produces.
pub const output_ceiling: Ceiling = .{ .head = 512 * 1024, .tail = 512 * 1024 };

comptime {
    // The ring holds the last `tail` bytes whatever the read boundaries were,
    // but only if it is at least as big as one read — otherwise a single read
    // overwrites it entirely and the margin above is a claim rather than a fact.
    std.debug.assert(output_ceiling.tail >= read_bytes);
    std.debug.assert(output_ceiling.head >= read_bytes);
}

/// The line `render` writes where the middle went.
///
/// In the stream itself, and not only beside it. A caller that pipes stdout to a
/// parser never sees a note on stderr or a field in a JSON envelope it did not
/// ask for, and an agent parsing output whose middle silently vanished draws a
/// wrong conclusion and never learns that it did. This is the one place a
/// truncated stream cannot be mistaken for a complete one.
pub const gap_marker = "__TERMINUS_OUTPUT_TRUNCATED__";

/// The gap line, at its widest.
///
/// A constant, so the whole retained rendering is a constant-size allocation:
/// without it a run's peak would move by the decimal width of its own byte
/// counts, and "the cost does not depend on the size of the output" would be
/// true only to within a few characters. Derived from the format string itself at
/// its maximum arguments, so it cannot drift from the line it bounds.
pub const gap_line_max = std.fmt.comptimePrint(gap_line_format, .{
    std.math.maxInt(u64),
    std.math.maxInt(u64),
    std.math.maxInt(usize),
    std.math.maxInt(usize),
    std.math.maxInt(u64),
    "f" ** digest.hex_len,
}).len;

const gap_line_format = "\n" ++ gap_marker ++
    " dropped={d} of {d} byte(s), keeping the first {d} and the last {d}; sha256 of all {d} is {s}\n";

/// What passed through one output stream, and whether all of it was kept.
///
/// The output counterpart of `Accepted`, and the same three-way discipline: the
/// count is of everything that passed rather than of what was retained, the
/// digest is of exactly those bytes, and `truncated` says whether the two can
/// differ. A receipt whose `bytes` reported the retained amount would describe a
/// 10 GiB run and a 1 MiB run identically.
pub const Passed = struct {
    /// Every byte that came off the channel, kept or dropped.
    bytes: u64 = 0,
    /// Hex SHA-256 of exactly `bytes` bytes, markers included.
    sha256: [digest.hex_len]u8 = empty_sha256.*,
    /// Whether the middle was dropped.
    truncated: bool = false,
};

/// Both output streams of one command.
pub const Retained = struct {
    stdout: Passed = .{},
    stderr: Passed = .{},
};

/// Local bytes for a command's standard input, and where the count of what the
/// channel accepted lands.
///
/// The two travel together because a caller that has one always has the other:
/// `accepted` is the only thing it learns about a rejected input, so a source
/// without somewhere to report its acceptance is a source whose failure is
/// unreportable.
pub const InputStream = struct {
    source: *std.Io.Reader,
    accepted: *Accepted,
};

/// One stream being drained under a ceiling.
///
/// `null` for the ceiling keeps the whole stream, which is `exec`'s contract and
/// one caller's requirement rather than a default: see `exec`.
///
/// Nothing is allocated until bytes arrive, and the ring is not allocated until
/// the head has filled — so `echo hi` costs three bytes and ten gigabytes costs
/// `Ceiling.total()`. Both are constants; neither moves with the output.
pub const Capture = struct {
    arena: Allocator,
    ceiling: ?Ceiling,
    /// The first `ceiling.head` bytes. With no ceiling, the whole stream.
    head: std.ArrayList(u8) = .empty,
    /// The last `ceiling.tail` bytes, as a ring: `ring_len` bytes starting at
    /// `ring_at` and wrapping. Allocated on the first byte that outlives the
    /// head.
    ring: []u8 = &.{},
    ring_at: usize = 0,
    ring_len: usize = 0,
    /// Bytes that passed and were kept by neither end.
    dropped: u64 = 0,
    /// Bytes that passed, kept or not.
    total: u64 = 0,
    running: digest.Running,

    pub fn init(arena: Allocator, ceiling: ?Ceiling) Capture {
        return .{ .arena = arena, .ceiling = ceiling, .running = .init() };
    }

    /// Takes one read's worth of stream.
    pub fn push(self: *Capture, chunk: []const u8) Allocator.Error!void {
        // No ceiling, no accounting. The caller is being handed every byte and
        // can hash them itself if it wants them hashed — and hashing here would
        // put a second SHA-256 pass over every byte of every file transfer,
        // which is the caller `exec` exists to serve.
        const ceiling = self.ceiling orelse
            return self.head.appendSlice(self.arena, chunk);

        // Counted and hashed before anything is retained or discarded, so the
        // two cannot disagree about which bytes passed.
        self.running.update(chunk);
        self.total += chunk.len;

        var rest = chunk;
        if (self.head.items.len < ceiling.head) {
            const n = @min(ceiling.head - self.head.items.len, rest.len);
            try self.head.appendSlice(self.arena, rest[0..n]);
            rest = rest[n..];
        }
        if (rest.len == 0) return;
        if (self.ring.len == 0) {
            if (ceiling.tail == 0) {
                self.dropped += rest.len;
                return;
            }
            self.ring = try self.arena.alloc(u8, ceiling.tail);
        }

        // A chunk at least as large as the ring replaces it whole: only its own
        // last `ring.len` bytes can survive, and everything they displaced —
        // whatever the ring held, plus the front of this chunk — is dropped.
        if (rest.len >= self.ring.len) {
            self.dropped += self.ring_len + (rest.len - self.ring.len);
            @memcpy(self.ring, rest[rest.len - self.ring.len ..]);
            self.ring_at = 0;
            self.ring_len = self.ring.len;
            return;
        }

        const free = self.ring.len - self.ring_len;
        if (rest.len > free) {
            const evicted = rest.len - free;
            self.ring_at = (self.ring_at + evicted) % self.ring.len;
            self.ring_len -= evicted;
            self.dropped += evicted;
        }
        // Into at most two spans, so the cost is the chunk and not its bytes.
        var at = (self.ring_at + self.ring_len) % self.ring.len;
        while (rest.len > 0) {
            const n = @min(self.ring.len - at, rest.len);
            @memcpy(self.ring[at..][0..n], rest[0..n]);
            self.ring_len += n;
            at = (at + n) % self.ring.len;
            rest = rest[n..];
        }
    }

    /// What passed, for the receipt. Valid at any point in the stream.
    ///
    /// Only a bounded capture has an answer: an unbounded one keeps everything
    /// and takes no digest, so asking it would report a count of zero and the
    /// digest of nothing as though they were observations.
    pub fn passed(self: *const Capture) Passed {
        std.debug.assert(self.ceiling != null);
        var out: Passed = .{ .bytes = self.total, .truncated = self.dropped > 0 };
        _ = self.running.peekHex(&out.sha256);
        return out;
    }

    /// The retained bytes in stream order, with the gap named where the middle
    /// went.
    ///
    /// A stream that fitted under the ceiling renders byte-for-byte as it
    /// arrived, with no marker anywhere in it — so the marker's presence means
    /// bytes are missing and its absence means none are.
    ///
    /// The allocation is `head + gap_line_max + tail` whatever the stream was,
    /// and the returned slice is a prefix of it. Sizing it to the gap line's
    /// actual width would make a run's peak move by the number of digits in its
    /// own byte count, which is a small dependency on the size of the output but
    /// is still one.
    pub fn render(self: *const Capture, arena: Allocator) Allocator.Error![]u8 {
        if (self.ring_len == 0 and self.dropped == 0) return self.head.items;

        var gap_buf: [gap_line_max]u8 = undefined;
        const gap: []const u8 = if (self.dropped == 0) "" else self.gapLine(&gap_buf);
        const out = try arena.alloc(u8, self.head.items.len + gap_line_max + self.ring_len);
        @memcpy(out[0..self.head.items.len], self.head.items);
        @memcpy(out[self.head.items.len..][0..gap.len], gap);

        const tail = out[self.head.items.len + gap.len ..][0..self.ring_len];
        const first = @min(self.ring.len - self.ring_at, self.ring_len);
        @memcpy(tail[0..first], self.ring[self.ring_at..][0..first]);
        @memcpy(tail[first..], self.ring[0 .. self.ring_len - first]);
        return out[0 .. self.head.items.len + gap.len + self.ring_len];
    }

    /// Its own line, on both sides, so it cannot merge with a line of real
    /// output and cannot be read as one. Carries the digest of the whole stream:
    /// a caller holding nothing but this stdout can still check it against the
    /// receipt.
    ///
    /// Written into the caller's buffer rather than allocated, for the reason
    /// `digest.hex` is: the buffer is a compile-time constant and the allocation
    /// it would otherwise make is inside the one path whose whole point is that
    /// its cost is fixed.
    fn gapLine(self: *const Capture, out: *[gap_line_max]u8) []const u8 {
        var sha: [digest.hex_len]u8 = undefined;
        _ = self.running.peekHex(&sha);
        return std.fmt.bufPrint(out, gap_line_format, .{
            self.dropped,
            self.total,
            self.head.items.len,
            self.ring_len,
            self.total,
            sha[0..],
        }) catch unreachable; // `gap_line_max` is this format at its widest.
    }
};

/// Applies the ceiling to output a transport handed over whole.
///
/// Two callers need it. The daemon protocol frames a reply as one message, so
/// `daemon/Client.exec` is already holding every byte by the time anything can
/// look at it; and `Scripted` replays a fixture. Neither gets a smaller peak out
/// of this — what it buys is that the receipt's three numbers mean the same
/// thing on every transport, and that a caller's stdout is bounded and its gap
/// marked whichever transport served it.
///
/// `pieces` is the size of the handovers the bytes are fed in. The daemon passes
/// its whole reply, because that is what actually happened; a harness passes
/// `read_bytes` to reproduce the channel's own boundaries.
pub fn retain(
    arena: Allocator,
    result: ExecResult,
    output: *Retained,
    pieces: usize,
) Allocator.Error!ExecResult {
    output.* = .{};
    var stdout: Capture = .init(arena, output_ceiling);
    var stderr: Capture = .init(arena, output_ceiling);
    try feed(&stdout, result.stdout, pieces);
    try feed(&stderr, result.stderr, pieces);
    output.stdout = stdout.passed();
    output.stderr = stderr.passed();
    return .{
        .exit_code = result.exit_code,
        .stdout = try stdout.render(arena),
        .stderr = try stderr.render(arena),
    };
}

fn feed(capture: *Capture, bytes: []const u8, pieces: usize) Allocator.Error!void {
    const step = @max(pieces, 1);
    var rest = bytes;
    while (rest.len > 0) {
        const n = @min(step, rest.len);
        try capture.push(rest[0..n]);
        rest = rest[n..];
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
