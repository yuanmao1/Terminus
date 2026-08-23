//! Incremental SHA-256, and the one-shot form over a slice.
//!
//! It exists because of a size. A transfer's digest has to be taken over the
//! whole file, and the one-shot `std.crypto.hash.sha2.Sha256.hash(bytes, …)`
//! needs the whole file in memory to do it — which is exactly the shape
//! `cmd_transfer` used to have (`readFileAlloc(…, .limited(1 << 31))`), and
//! which cannot hash a file over 2 GiB at all. Everything here works in a fixed
//! buffer, so the peak is the buffer and not the file.
//!
//! **Hex is a fixed 64 bytes and is written into the caller's buffer.** That is
//! not a micro-optimisation: the alternative is `allocPrint` per digest, and the
//! two digests a transfer takes sit inside a loop over its chunks in the version
//! of this that advances a prefix hash. An arena grows there; a `[hex_len]u8` on
//! the caller's stack does not.
//!
//! There are two one-shot `sha256Hex` helpers already in the tree
//! (`cmd_job.zig`, `cmd_read_write.zig`). `hex` below is the same function and
//! either could adopt it, but neither is changed here: they hash a command line
//! and a line of operator input, both of which are already in memory and neither
//! of which is in this change's path.
const std = @import("std");
const Proc = @import("proc.zig");

/// Length of a hex SHA-256, which is what the ledger stores and compares.
pub const hex_len = 64;

/// Hex digest of `bytes`, written into `out`. No allocation.
pub fn hex(bytes: []const u8, out: *[hex_len]u8) []const u8 {
    var raw: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &raw, .{});
    return format(raw, out);
}

/// Hex digest of `bytes`, on `arena`, for a caller that wants it to outlive the
/// frame. The shape `cmd_job` and `cmd_read_write` each wrote for themselves.
pub fn hexAlloc(arena: std.mem.Allocator, bytes: []const u8) std.mem.Allocator.Error![]const u8 {
    var buf: [hex_len]u8 = undefined;
    return arena.dupe(u8, hex(bytes, &buf));
}

fn format(raw: [32]u8, out: *[hex_len]u8) []const u8 {
    // `{x}` over a byte slice is what the rest of the tree stores, so this
    // renders the same text `Store.history` and `cmd_read_write` do.
    return std.fmt.bufPrint(out, "{x}", .{&raw}) catch unreachable;
}

/// A digest taken a chunk at a time.
///
/// Two of these run during a transfer and they answer different questions, which
/// is why the type is worth having over a bare `Sha256`: one covers the whole
/// stream and becomes the digest the two ends are compared on, and the other is
/// re-read at chunk boundaries as the *prefix* digest a confirmed offset needs.
pub const Running = struct {
    state: std.crypto.hash.sha2.Sha256,

    pub fn init() Running {
        return .{ .state = .init(.{}) };
    }

    pub fn update(self: *Running, bytes: []const u8) void {
        self.state.update(bytes);
    }

    /// The digest of everything fed so far, without ending the digest.
    ///
    /// A copy is finalised, so this can be asked at every chunk boundary and
    /// the stream carries on — which is the whole point. `Sha256.final`
    /// consumes the state, so asking the live one would end the digest at the
    /// first offset that got confirmed and every later reading would be of a
    /// hasher that had already been drained.
    pub fn peekHex(self: *const Running, out: *[hex_len]u8) []const u8 {
        var copy = self.state;
        var raw: [32]u8 = undefined;
        copy.final(&raw);
        return format(raw, out);
    }

    /// The final digest. `peekHex` at the end of the stream returns the same
    /// text; this one says at the call site that the stream is over.
    pub fn finalHex(self: *Running, out: *[hex_len]u8) []const u8 {
        var raw: [32]u8 = undefined;
        self.state.final(&raw);
        return format(raw, out);
    }
};

/// One observation of one file: its digest, its size and its mtime.
///
/// The three travel together because `transfers.recordSourceIdentity` takes all
/// three and refuses a partial identity — "they are one observation of one file
/// at one moment". Keeping a size read earlier beside a digest read now would
/// store a triple that never described anything.
pub const FileReading = struct {
    /// Points into the caller's `out` buffer.
    sha256: []const u8,
    size: u64,
    mtime_ns: i128,
};

pub const FileError = error{
    /// The file could not be opened, statted or read to its end.
    SourceUnreadable,
};

/// Reads `path` once, in a fixed buffer, and reports what it found.
///
/// The size and mtime come from a stat of the *same open handle* as the bytes,
/// so the three fields describe one moment rather than three. A file that is
/// being written under us will still produce an inconsistent triple — nothing
/// short of a lock can prevent that — and that is what `failed_source_changed`
/// and the resume comparison in `transfers.verifyResume` exist to catch later.
pub fn readFile(
    io: std.Io,
    path: []const u8,
    out: *[hex_len]u8,
) FileError!FileReading {
    const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch return error.SourceUnreadable;
    defer file.close(io);
    const info = file.stat(io) catch return error.SourceUnreadable;

    var buffer: [1 << 20]u8 = undefined;
    var reader = file.reader(io, &buffer);
    var running: Running = .init();
    var read: u64 = 0;
    while (true) {
        const chunk = reader.interface.peekGreedy(1) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return error.SourceUnreadable,
        };
        running.update(chunk);
        reader.interface.toss(chunk.len);
        read += chunk.len;
    }

    return .{
        .sha256 = running.finalHex(out),
        // What was actually read, not what the stat said. They differ when the
        // file changed under us, and the digest covers the bytes — so reporting
        // the stat's number beside a digest of a different length would file an
        // identity whose own two halves disagree.
        .size = read,
        .mtime_ns = info.mtime.nanoseconds,
    };
}

test "hex matches the tree's one-shot form" {
    const t = std.testing;
    var buf: [hex_len]u8 = undefined;
    // The published SHA-256 of "abc", so this pins the rendering as well as the
    // hash: a change to `{x}` upper/lower case or separator lands here.
    try t.expectEqualStrings(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        hex("abc", &buf),
    );
    try t.expectEqual(@as(usize, hex_len), hex("abc", &buf).len);
}

test "a running digest fed in pieces equals the one-shot digest" {
    const t = std.testing;
    const whole = "the quick brown fox jumps over the lazy dog, twice, at length";

    var one_shot: [hex_len]u8 = undefined;
    const want = hex(whole, &one_shot);

    // Fed one byte at a time, which is the worst case for a chunk boundary
    // landing mid-block. If `update` were dropping or double-counting a tail
    // this is where it shows.
    var running: Running = .init();
    for (whole) |ch| running.update(&[_]u8{ch});
    var got: [hex_len]u8 = undefined;
    try t.expectEqualStrings(want, running.finalHex(&got));
}

test "peekHex reports the prefix and leaves the stream running" {
    const t = std.testing;
    const whole = "0123456789abcdef";

    var prefix_want: [hex_len]u8 = undefined;
    const want_prefix = hex(whole[0..8], &prefix_want);
    var whole_want: [hex_len]u8 = undefined;
    const want_whole = hex(whole, &whole_want);

    var running: Running = .init();
    running.update(whole[0..8]);

    // The prefix, read without ending the digest. This is the assertion that
    // stops `peekHex` being "simplified" into `final`: a consumed state would
    // make the first confirmed offset the last one this hasher could describe.
    var mid: [hex_len]u8 = undefined;
    try t.expectEqualStrings(want_prefix, running.peekHex(&mid));
    // Asked twice, because a peek that mutated would answer differently the
    // second time.
    var mid_again: [hex_len]u8 = undefined;
    try t.expectEqualStrings(want_prefix, running.peekHex(&mid_again));

    running.update(whole[8..]);
    var end: [hex_len]u8 = undefined;
    try t.expectEqualStrings(want_whole, running.finalHex(&end));
}

test "readFile hashes a file larger than its own buffer in bounded memory" {
    const t = std.testing;
    var threaded: std.Io.Threaded = .init(t.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const dir = ".zig-cache/tmp";
    std.Io.Dir.cwd().createDirPath(io, dir) catch {};
    // Unique per process and thread. A fixed name is shared by the two test
    // binaries this file is compiled into, and they run at the same time: one
    // deletes the other's file mid-read and the failure looks like a digest
    // bug.
    const path = try std.fmt.allocPrint(t.allocator, "{s}/digest_readfile_{d}_{d}_{d}.bin", .{
        dir, Proc.currentPid(), std.Thread.getCurrentId(), std.Io.Timestamp.now(io, .real).nanoseconds,
    });
    defer t.allocator.free(path);
    defer std.Io.Dir.cwd().deleteFile(io, path) catch {};

    // Two buffers' worth plus a remainder, so the loop runs more than once and
    // the last chunk is a partial one. A single-chunk file would pass even if
    // the loop only ever ran once.
    const total = (1 << 20) * 2 + 12345;
    {
        const file = try std.Io.Dir.cwd().createFile(io, path, .{});
        defer file.close(io);
        var buf: [1 << 16]u8 = undefined;
        var writer = file.writerStreaming(io, &buf);
        var written: usize = 0;
        var pattern: [4096]u8 = undefined;
        for (&pattern, 0..) |*b, i| b.* = @truncate(i * 7 + 3);
        while (written < total) {
            const n = @min(pattern.len, total - written);
            try writer.interface.writeAll(pattern[0..n]);
            written += n;
        }
        try writer.interface.flush();
    }

    var out: [hex_len]u8 = undefined;
    const reading = try readFile(io, path, &out);
    try t.expectEqual(@as(u64, total), reading.size);
    try t.expectEqual(@as(usize, hex_len), reading.sha256.len);

    // Compared against a digest built by feeding the same bytes through
    // `Running` directly, so the assertion is about the file walk and not about
    // SHA-256.
    var expect: Running = .init();
    {
        var pattern: [4096]u8 = undefined;
        for (&pattern, 0..) |*b, i| b.* = @truncate(i * 7 + 3);
        var fed: usize = 0;
        while (fed < total) {
            const n = @min(pattern.len, total - fed);
            expect.update(pattern[0..n]);
            fed += n;
        }
    }
    var want: [hex_len]u8 = undefined;
    try t.expectEqualStrings(expect.finalHex(&want), reading.sha256);
}

test "readFile names an unreadable source rather than reporting an empty one" {
    const t = std.testing;
    var threaded: std.Io.Threaded = .init(t.allocator, .{});
    defer threaded.deinit();
    var out: [hex_len]u8 = undefined;
    // The empty-string digest is a real value, so a missing file that came back
    // as a clean reading would be indistinguishable from an empty file — and a
    // transfer would then declare that digest and publish nothing against it.
    try t.expectError(
        error.SourceUnreadable,
        readFile(threaded.io(), ".zig-cache/tmp/digest_no_such_file.bin", &out),
    );
}
