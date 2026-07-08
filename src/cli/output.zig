//! Dual-format command output: human-readable lines or stable JSON.
//! Every agent-facing command decides once via `format` and emits through
//! this struct so the two formats stay in one place.
const std = @import("std");

const Output = @This();

pub const Format = enum { human, json };

writer: *std.Io.Writer,
format: Format = .human,

/// Serializes `value` as pretty-printed JSON followed by a newline.
pub fn json(out: *Output, value: anytype) !void {
    try std.json.Stringify.value(value, .{ .whitespace = .indent_2 }, out.writer);
    try out.writer.writeAll("\n");
}

pub fn print(out: *Output, comptime fmt: []const u8, fmt_args: anytype) !void {
    try out.writer.print(fmt, fmt_args);
}

pub fn flush(out: *Output) !void {
    try out.writer.flush();
}
