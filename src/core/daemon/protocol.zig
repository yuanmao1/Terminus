//! CLI↔daemon wire protocol: newline-delimited JSON over a local unix
//! socket. One request line in, one response line out.
//!
//! Strict contract: every message carries a protocol version (`v`);
//! mismatched versions, unknown fields, and missing fields all fail
//! parsing. The CLI treats any protocol failure as "daemon unusable" and
//! reports it (no silent schema drift). CLI and daemon come from the same
//! binary in normal operation, so a version bump only surfaces when a
//! stale daemon from an older binary is still running — the CLI then
//! stops it and respawns.
//!
//! Auth material travels in each exec request so the daemon never touches
//! the sqlite store (no locking, no schema coupling). The socket lives in
//! the user's profile directory; key bytes are already plaintext in sqlite
//! at this milestone, so this does not widen the exposure.
const std = @import("std");

pub const version = 2;

pub const Op = enum { exec, ping, stop };

pub const Request = struct {
    v: u32,
    op: Op,
    host: []const u8 = "",
    port: u16 = 22,
    username: []const u8 = "",
    auth: Auth = .none,
    command: []const u8 = "",

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
    stdout: []const u8 = "",
    stderr: []const u8 = "",
    pid: u32 = 0,
};

pub const ParseError = error{
    MalformedMessage,
    VersionMismatch,
};

pub fn writeMessage(writer: *std.Io.Writer, value: anytype) !void {
    try std.json.Stringify.value(value, .{}, writer);
    try writer.writeAll("\n");
    try writer.flush();
}

/// Strict parse: unknown fields are errors, and `v` must match exactly.
pub fn parseMessage(comptime T: type, arena: std.mem.Allocator, line: []const u8) ParseError!T {
    const value = std.json.parseFromSliceLeaky(T, arena, line, .{}) catch
        return error.MalformedMessage;
    if (value.v != version) return error.VersionMismatch;
    return value;
}

test "round trip and strictness" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var buffer: [4096]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try writeMessage(&writer, Request{ .v = version, .op = .ping });
    const line = std.mem.trimEnd(u8, writer.buffered(), "\n");
    const parsed = try parseMessage(Request, arena, line);
    try t.expectEqual(Op.ping, parsed.op);

    // Unknown field → hard failure.
    try t.expectError(error.MalformedMessage, parseMessage(Request, arena,
        \\{"v":2,"op":"ping","bogus":1}
    ));
    // Version mismatch → hard failure.
    try t.expectError(error.VersionMismatch, parseMessage(Request, arena,
        \\{"v":1,"op":"ping"}
    ));
    // Missing required field → hard failure.
    try t.expectError(error.MalformedMessage, parseMessage(Request, arena,
        \\{"v":2}
    ));
}
