//! CLI↔daemon wire protocol: length-prefixed JSON frames over a local unix
//! socket. One request frame in, one response frame out.
//!
//! A frame is **eight hex digits of payload length, that many payload bytes,
//! and a newline**. Each of the three parts is load-bearing, and each replaces
//! something the newline-delimited version of this protocol got wrong.
//!
//! **The length comes first, so the reader never has to hold a whole frame in a
//! buffer it sized in advance.** `Client.roundTrip` used to read a reply with
//! `takeDelimiter('\n')` through a 1 MiB stack array, and `takeDelimiter`
//! answers `error.StreamTooLong` for a line longer than the reader's capacity.
//! That error became `error.ExecFailed`, and `execution.runCommand` records an
//! `ExecFailed` as a transport loss — so a command that succeeded perfectly with
//! two megabytes of output settled **`indeterminate`** on the transport the CLI
//! uses by default. Now the payload is read into an allocation of exactly its
//! announced size and the reader's own buffer only ever has to hold eight bytes.
//!
//! **The header has to be the length of the payload that follows it, and that is
//! the one invariant here whose failure is a hang rather than an error.** The
//! width is settled by a counting pass (`payloadLen`) and the payload is then
//! serialised a second time; if the two ever disagree the reader waits for a
//! remainder that is never coming, and no timeout in this protocol saves it. It
//! held once and then stopped: a reply field borrowed a digest from a stack slot
//! that the two passes read at different depths, and the two passes measured
//! different widths — see `Accounting.Stream.sha256`. What makes it true now is
//! that a `Response` borrows nothing whose life is shorter than its own, so the
//! two passes walk identical bytes. Held to by `gate: the frame's header is the
//! length of the payload that follows it`.
//!
//! **The newline is what keeps a version skew from hanging.** A daemon from an
//! older build reads with `takeDelimiter('\n')`; handed a frame with no newline
//! it would block forever waiting for one, and the client would block waiting
//! for the reply — a skew turned into a hang, which is worse than a refusal. The
//! terminator means an old reader gets a complete line, fails to parse it, and
//! answers; and a new reader fails on the eight-hex-digit header instead of
//! reading a v2 line as a length. Neither side waits. See `readFrame`.
//!
//! **The two output streams travel base64-encoded, and that is what makes "the
//! reply cannot exceed the frame" arithmetic instead of hope.** JSON escaping
//! expands a byte by a factor that depends on the byte, so a bound over
//! JSON-escaped output is a claim about `std.json`'s escape table. Base64
//! expands by exactly `4*ceil(n/3)`, and its alphabet is a subset of the
//! characters JSON passes through unchanged (asserted below), so the encoded
//! width of a reply is a function of the output ceiling and nothing else.
//!
//! Strict contract, unchanged: every message carries a protocol version (`v`);
//! mismatched versions, unknown fields, and missing fields all fail parsing. The
//! CLI treats any protocol failure as "daemon unusable" and reports it (no
//! silent schema drift). CLI and daemon come from the same binary in normal
//! operation, so a version bump only surfaces when a stale daemon from an older
//! build is still running — and that case is named rather than guessed at, see
//! `peerVersion`.
//!
//! Auth material travels in each exec request so the daemon never touches the
//! sqlite store (no locking, no schema coupling). The socket lives in the user's
//! profile directory; key bytes are already plaintext in sqlite at this
//! milestone, so this does not widen the exposure.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Ssh = @import("../ssh/Client.zig");
const digest = @import("../digest.zig");

pub const version = 3;

pub const Op = enum { exec, ping, stop };

pub const Request = struct {
    v: u32,
    op: Op,
    host: []const u8 = "",
    port: u16 = 22,
    username: []const u8 = "",
    auth: Auth = .none,
    command: []const u8 = "",
    /// What the daemon does with the command's output. The default is what the
    /// unbounded `Ssh.exec` does, because that is the entry point whose callers
    /// ask questions with small answers and one of which — `transfer.pullBytes`
    /// — verifies a digest over the whole reply and so may not be given a
    /// truncated one.
    output: Output = .whole,

    /// The two output disciplines, which are the two entry points on `Ssh`.
    pub const Output = enum {
        /// Every byte, held whole. Bounded by the caller's own question, not by
        /// this protocol — an answer that will not fit a frame is refused by
        /// name rather than shortened. See `Server.handleConnection`.
        whole,
        /// Under `Ssh.output_ceiling`, exactly as the direct transport applies
        /// it: both ends kept, the middle marked in-band, and every byte that
        /// passed counted and hashed. The accounting comes back in
        /// `Response.passed`.
        retained,
    };

    pub const Auth = union(enum) {
        none,
        password: []const u8,
        key: struct {
            private: []const u8,
            public: ?[]const u8 = null,
            passphrase: ?[]const u8 = null,
        },
    };
};

pub const Response = struct {
    v: u32,
    ok: bool,
    @"error": ?[]const u8 = null,
    exitCode: i32 = 0,
    /// The command's stdout as the daemon retained it — the rendering
    /// `Ssh.Capture.render` produced, gap line and all, so the caller's bytes
    /// are the same bytes whichever transport answered.
    stdout: Payload = .{},
    /// The command's stderr, same terms.
    stderr: Payload = .{},
    /// What passed through the two streams. Present **only** for a `.retained`
    /// request: a `.whole` run applies no ceiling and therefore takes no digest
    /// (see `Ssh.Capture.passed`), so there is nothing true to put here and an
    /// absent field says exactly that. Zeros would not — they would read as an
    /// observation of an empty stream.
    passed: ?Accounting = null,
    pid: u32 = 0,
};

/// A byte string that travels base64-encoded, and is encoded and decoded
/// **straight into and out of the frame**.
///
/// Custom hooks rather than a base64 field the callers fill, for two reasons,
/// and the first is the larger one. The retained output is the biggest thing
/// this protocol touches, and a materialised encoding would be a second copy of
/// it in the daemon at the same time — call it another 1.4 MiB per stream, for
/// nothing but a buffer on its way to a socket. The second is subtler: the
/// rendering's width moves by a few bytes with the decimal width of the byte
/// counts in `Ssh.Capture`'s gap line, so an allocation sized from it would make
/// the daemon's peak move with the size of the output. By four bytes — but
/// `Ssh.Capture.render` already refuses that trade for itself, and this is the
/// same trade.
///
/// Base64 rather than the bytes themselves because a command's output is bytes,
/// not text: NULs, invalid UTF-8, and the newline this protocol frames on all
/// occur in it. See the file header for why the encoding's *constant* expansion
/// is what makes the frame bound arithmetic.
pub const Payload = struct {
    bytes: []u8 = &.{},

    /// Encoded in fixed windows, each a multiple of three so that only the last
    /// one can be a partial base64 group.
    pub fn jsonStringify(self: Payload, jw: anytype) !void {
        const group = 3 * 1024;
        var window: [b64.Encoder.calcSize(group)]u8 = undefined;

        try jw.beginWriteRaw();
        defer jw.endWriteRaw();
        try jw.writer.writeByte('"');
        var rest: []const u8 = self.bytes;
        while (rest.len > group) {
            try jw.writer.writeAll(b64.Encoder.encode(&window, rest[0..group]));
            rest = rest[group..];
        }
        if (rest.len > 0) {
            try jw.writer.writeAll(b64.Encoder.encode(window[0..b64.Encoder.calcSize(rest.len)], rest));
        }
        try jw.writer.writeByte('"');
    }

    pub fn jsonParse(
        arena: Allocator,
        source: anytype,
        options: std.json.ParseOptions,
    ) !Payload {
        const token = try source.nextAllocMax(arena, .alloc_if_needed, options.max_value_len.?);
        const text = switch (token) {
            inline .string, .allocated_string => |slice| slice,
            else => return error.UnexpectedToken,
        };
        const len = b64.Decoder.calcSizeForSlice(text) catch return error.UnexpectedToken;
        const out = try arena.alloc(u8, len);
        b64.Decoder.decode(out, text) catch return error.UnexpectedToken;
        return .{ .bytes = out };
    }
};

/// `Ssh.Retained` on the wire.
pub const Accounting = struct {
    stdout: Stream,
    stderr: Stream,

    pub const Stream = struct {
        /// Every byte that came off the channel, kept or dropped.
        bytes: u64,
        /// Hex SHA-256 of exactly `bytes` bytes, markers included.
        ///
        /// The array and not a `[]const u8`, and this is load-bearing rather
        /// than tidy. A slice here has to point at something, and the only
        /// thing in reach is the `Ssh.Passed` the reply was built from — which
        /// is a value, so the pointer outlives whatever held it and the reply
        /// carries whatever that stack later held instead. Two failures came out
        /// of exactly that:
        ///
        ///   * both streams' digests came back as *one* stream's, because both
        ///     slices pointed at the same reused slot;
        ///   * and worse, `payloadLen`'s counting pass and the write that
        ///     follows it read that slot at different stack depths, so they
        ///     disagreed about the payload's width. The header then announced
        ///     more bytes than the frame carried, and every reader on a real
        ///     socket blocked forever waiting for a remainder that was never
        ///     coming. A wrong digest is a wrong receipt; a header that
        ///     overstates its payload is a hang.
        ///
        /// As a value the reply borrows nothing with a shorter life than itself,
        /// so the two serialisation passes are identical by construction. The
        /// width is the type's, which is also how `std.json` enforces it: a peer
        /// sending any other length fails the parse (`error.LengthMismatch`)
        /// rather than being padded or cut to fit.
        sha256: [digest.hex_len]u8,
        /// Whether the middle was dropped.
        truncated: bool,
    };
};

pub const ParseError = error{
    MalformedMessage,
    VersionMismatch,
};

pub const FrameError = error{
    /// The header was not eight hex digits, or the stream ended inside the
    /// payload, or the payload did not end where the header said it would. The
    /// stream position is no longer trustworthy after this: a framing error
    /// cannot be resynchronised, so the connection ends.
    MalformedFrame,
    /// A frame wider than `max_frame_bytes` — announced by a peer, or about to
    /// be written. Never shortened into one that fits: a truncated reply is a
    /// wrong answer, and this protocol's whole business is not producing those.
    FrameTooLarge,
    ReadFailed,
    WriteFailed,
    OutOfMemory,
};

/// Eight hex digits, so the header is a fixed read and never itself a scan.
pub const header_len = 8;

/// The most a single framed payload may be.
///
/// A round number above `max_exec_payload_bytes` rather than equal to it: the
/// derivation below is what must be true, and the headroom is what keeps a
/// small change to a field name from being a wire-breaking change.
pub const max_frame_bytes = 4 << 20;

/// An error message wider than this is cut at the write site. Bounds the one
/// field of a reply whose width is not a function of the output ceiling.
pub const max_error_bytes = 512;

const b64 = std.base64.standard;

/// The widest a stream's retained rendering can be: the ceiling, plus the one
/// gap line `Ssh.Capture.render` writes where the middle went.
pub const max_render_bytes = Ssh.output_ceiling.total() + Ssh.gap_line_max;

/// Everything in a *successful* exec reply that is not one of the two payloads:
/// field names, the two digests, the integers at their widest, the punctuation.
/// There is no `error` string on that path, which is why this is a constant and
/// not a function of one. Held to by `gate: the exec reply envelope fits the
/// width the frame bound reserves for it`.
pub const exec_envelope_bytes = 1024;

/// The widest a successful exec reply can be, and the whole of the argument
/// that a retained reply always fits a frame.
pub const max_exec_payload_bytes =
    exec_envelope_bytes + 2 * b64.Encoder.calcSize(max_render_bytes);

comptime {
    // The retained path can never trip the refusal in `writeMessage`. Without
    // this, "a large command settles with its real exit code" would depend on
    // the ceiling and the frame having been chosen to agree, and a later change
    // to either could part them silently.
    std.debug.assert(max_exec_payload_bytes <= max_frame_bytes);
    // Eight hex digits have to be able to say it.
    std.debug.assert(max_frame_bytes <= 0xffff_ffff);
    // Base64's alphabet is JSON's identity: no character in it is escaped, so
    // the encoded width of a payload really is `4*ceil(n/3)` and the bound above
    // is arithmetic rather than a claim about `std.json`'s escape table.
    for (b64.alphabet_chars ++ [_]u8{b64.pad_char.?}) |ch| {
        std.debug.assert(ch > 0x20 and ch < 0x7f and ch != '"' and ch != '\\');
    }
}

/// The exact width of `value`'s payload, without writing it.
///
/// A counting pass rather than a scratch buffer: the header has to carry the
/// length before the payload goes out, and the alternative is holding a second
/// copy of a reply that is already the largest thing the daemon touches.
pub fn payloadLen(value: anytype) error{WriteFailed}!u64 {
    var counter: std.Io.Writer.Discarding = .init(&.{});
    std.json.Stringify.value(value, .{}, &counter.writer) catch return error.WriteFailed;
    return counter.fullCount();
}

/// Writes one frame.
///
/// The width is settled **before a byte goes out**, so an oversized reply is
/// refused whole rather than half-written — this is the only place frames are
/// produced, which is what makes "no frame exceeds `max_frame_bytes`" a property
/// of the program and not of its callers.
pub fn writeMessage(writer: *std.Io.Writer, value: anytype) FrameError!void {
    const len = try payloadLen(value);
    if (len > max_frame_bytes) return error.FrameTooLarge;

    writer.print("{x:0>8}", .{len}) catch return error.WriteFailed;
    std.json.Stringify.value(value, .{}, writer) catch return error.WriteFailed;
    writer.writeAll("\n") catch return error.WriteFailed;
    writer.flush() catch return error.WriteFailed;
}

/// Reads one frame's payload, or `null` when the peer closed cleanly between
/// frames.
///
/// The payload lands on `arena` at exactly its announced size. A peer that
/// announces more than `max_frame_bytes` gets `FrameTooLarge` and no allocation
/// at all, so a lying header cannot be turned into a large allocation.
pub fn readFrame(reader: *std.Io.Reader, arena: Allocator) FrameError!?[]const u8 {
    // A stream that ends part-way through a header is reported as a clean
    // close, which is the same thing to every caller: the connection is over
    // and there is no reply on it.
    const header = reader.takeArray(header_len) catch |err| switch (err) {
        error.EndOfStream => return null,
        error.ReadFailed => return error.ReadFailed,
    };
    const len = std.fmt.parseInt(u32, header, 16) catch return error.MalformedFrame;
    if (len > max_frame_bytes) return error.FrameTooLarge;

    const payload = reader.readAlloc(arena, len) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.EndOfStream => return error.MalformedFrame,
        error.ReadFailed => return error.ReadFailed,
    };
    // The terminator both ends the frame and is what an older, line-oriented
    // reader delimits on. Its absence means the header and the payload disagree.
    const terminator = reader.takeByte() catch |err| switch (err) {
        error.EndOfStream => return error.MalformedFrame,
        error.ReadFailed => return error.ReadFailed,
    };
    if (terminator != '\n') return error.MalformedFrame;
    return payload;
}

/// Strict parse: unknown fields are errors, and `v` must match exactly.
pub fn parseMessage(comptime T: type, arena: Allocator, payload: []const u8) ParseError!T {
    const value = std.json.parseFromSliceLeaky(T, arena, payload, .{}) catch
        return error.MalformedMessage;
    if (value.v != version) return error.VersionMismatch;
    return value;
}

/// The `v` a peer claims, read leniently.
///
/// Only ever used to *name* a mismatch `parseMessage` has already refused. A
/// skew that reports "the daemon is unusable" and a skew that reports which
/// protocol the daemon speaks lead to the same fallback, but only the second
/// tells the operator which command clears it.
pub fn peerVersion(arena: Allocator, payload: []const u8) ?u32 {
    const probe = std.json.parseFromSliceLeaky(struct { v: u32 }, arena, payload, .{
        .ignore_unknown_fields = true,
    }) catch return null;
    return probe.v;
}

/// Packs one exec result for the wire.
///
/// `retained` is the accounting for a `.retained` run and `null` for a `.whole`
/// one — the distinction the reply has to carry, because a `.whole` run took no
/// digest and has no honest numbers to report.
///
/// Allocates nothing. The two output payloads are borrowed from the caller's own
/// buffers, which outlive the write; everything else — the digests included — is
/// copied, so nothing in the returned value points into this frame. See
/// `Accounting.Stream.sha256` for what happened when one thing did.
pub fn execResponse(
    result: Ssh.ExecResult,
    retained: ?Ssh.Retained,
) Response {
    return .{
        .v = version,
        .ok = true,
        .exitCode = result.exit_code,
        .stdout = .{ .bytes = result.stdout },
        .stderr = .{ .bytes = result.stderr },
        .passed = if (retained) |r| .{
            .stdout = streamOf(r.stdout),
            .stderr = streamOf(r.stderr),
        } else null,
    };
}

fn streamOf(p: Ssh.Passed) Accounting.Stream {
    return .{ .bytes = p.bytes, .sha256 = p.sha256, .truncated = p.truncated };
}

/// One stream's accounting, back into the shape a receipt is written from.
///
/// The digest is checked for being hex, because this is the last point before it
/// becomes a row in the ledger claiming to be a SHA-256. Its *width* is not
/// checked here and does not need to be: it is the field's type, so a peer that
/// sent a different length never got past `parseMessage`.
pub fn passedFrom(stream: Accounting.Stream) ParseError!Ssh.Passed {
    var out: Ssh.Passed = .{ .bytes = stream.bytes, .truncated = stream.truncated };
    for (stream.sha256, 0..) |ch, i| {
        _ = std.fmt.charToDigit(ch, 16) catch return error.MalformedMessage;
        out.sha256[i] = ch;
    }
    return out;
}

test {
    _ = @import("protocol_test.zig");
    _ = @import("transport_test.zig");
}
