//! Request identifiers for the operation ledger.
//!
//! A `request_id` is the only authoritative handle for a remote side effect.
//! Job names, session names and file paths are *aliases*: they get reused
//! and deleted, so they cannot anchor an audit record.
//!
//! Format is ULID-like: 10 characters of millisecond timestamp followed by
//! 16 characters of randomness, in Crockford base32. The timestamp *prefix*
//! is monotonic, so `ORDER BY request_id` groups by creation time to the
//! millisecond; ids minted within the same millisecond are ordered
//! arbitrarily relative to each other (their random suffixes decide), which
//! is why the ledger orders by `created_at` when exact ordering matters.
//! 80 bits of entropy make same-millisecond collisions a non-issue.
const std = @import("std");

/// Crockford base32: no I, L, O, U — unambiguous when read aloud or typed.
const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

pub const len = 26;
const time_chars = 10;
const random_chars = 16;

comptime {
    std.debug.assert(time_chars + random_chars == len);
    std.debug.assert(alphabet.len == 32);
}

pub const RequestId = [len]u8;

/// Generates a fresh id. Randomness comes from `io` (Zig 0.16 exposes the
/// CSPRNG through the Io vtable; there is no `std.crypto.random`).
pub fn generate(io: std.Io) RequestId {
    const ns = std.Io.Timestamp.now(io, .real).nanoseconds;
    const ms: u64 = @intCast(@divTrunc(ns, std.time.ns_per_ms));

    var out: RequestId = undefined;
    // Most-significant group first, so string order matches time order.
    var i: usize = 0;
    while (i < time_chars) : (i += 1) {
        const shift: u6 = @intCast(5 * (time_chars - 1 - i));
        out[i] = alphabet[(ms >> shift) & 0x1f];
    }

    var entropy: [random_chars]u8 = undefined;
    io.random(&entropy);
    for (entropy, 0..) |byte, j| out[time_chars + j] = alphabet[byte & 0x1f];
    return out;
}

/// Rejects anything that is not a well-formed id. Used when a request_id
/// arrives from outside (CLI flag, daemon request, imported ledger) so a
/// malformed handle can never silently address the wrong row.
pub fn validate(text: []const u8) error{InvalidRequestId}!void {
    if (text.len != len) return error.InvalidRequestId;
    for (text) |ch| {
        if (std.mem.indexOfScalar(u8, alphabet, ch) == null) return error.InvalidRequestId;
    }
}

test "generate is well formed, unique, and time-prefixed" {
    const t = std.testing;
    var threaded: std.Io.Threaded = .init(t.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const a = generate(io);
    const b = generate(io);
    try validate(&a);
    try validate(&b);

    // Two ids in the same millisecond still differ (80 bits of entropy).
    try t.expect(!std.mem.eql(u8, &a, &b));

    // The timestamp prefix never goes backwards. The full ids are NOT
    // comparable within one millisecond — the random suffixes decide — so
    // only the prefix is asserted here.
    try t.expect(std.mem.order(u8, a[0..time_chars], b[0..time_chars]) != .gt);
}

test "timestamp prefix advances across milliseconds" {
    const t = std.testing;
    var threaded: std.Io.Threaded = .init(t.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const first = generate(io);
    std.Io.sleep(io, .{ .nanoseconds = 3 * std.time.ns_per_ms }, .awake) catch {};
    const later = generate(io);
    try t.expect(std.mem.order(u8, first[0..time_chars], later[0..time_chars]) == .lt);
    // Across milliseconds the whole id is ordered too.
    try t.expect(std.mem.order(u8, &first, &later) == .lt);
}

test validate {
    const t = std.testing;
    try t.expectError(error.InvalidRequestId, validate("too-short"));
    try t.expectError(error.InvalidRequestId, validate("0" ** 27));
    // I, L, O, U are not in the alphabet.
    try t.expectError(error.InvalidRequestId, validate("0" ** 25 ++ "I"));
    try validate("0" ** 26);
}
