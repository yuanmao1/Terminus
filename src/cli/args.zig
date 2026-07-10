//! Hand-rolled CLI argument parsing: positionals, `--flag value`,
//! `--flag=value`, boolean flags, and a trailing `--` rest section.
const std = @import("std");
const Allocator = std.mem.Allocator;

/// Flags that never consume a value.
const bool_flags = [_][]const u8{ "json", "from-cursor", "no-enter", "raw", "no-daemon", "dry-run", "delete", "force", "stdin", "login", "append", "strict" };

pub const Parsed = struct {
    positionals: []const []const u8,
    flags: std.StringArrayHashMapUnmanaged([]const u8),
    bools: std.StringArrayHashMapUnmanaged(void),
    /// Arguments after a literal `--`, or null when absent.
    rest: ?[]const []const u8,

    pub fn flag(p: *const Parsed, name: []const u8) ?[]const u8 {
        return p.flags.get(name);
    }

    pub fn boolean(p: *const Parsed, name: []const u8) bool {
        return p.bools.contains(name);
    }

    pub fn positional(p: *const Parsed, index: usize) ?[]const u8 {
        return if (index < p.positionals.len) p.positionals[index] else null;
    }

    /// The trailing command/content for exec/run/write/memory-add, from
    /// (in priority order): `--cmd`/`--content` "<string>", everything
    /// after `--`, or — because some shells (notably PowerShell) swallow a
    /// bare `--` — any positionals beyond the first `expected` ones.
    /// Returns null when none of the three provide anything.
    pub fn trailing(p: *const Parsed, arena: Allocator, expected_positionals: usize) !?[]const u8 {
        if (p.flag("cmd") orelse p.flag("content")) |explicit| {
            if (explicit.len == 0) return null;
            return explicit;
        }
        if (p.rest) |rest| {
            if (rest.len == 0) return null;
            return try std.mem.join(arena, " ", rest);
        }
        if (p.positionals.len > expected_positionals) {
            return try std.mem.join(arena, " ", p.positionals[expected_positionals..]);
        }
        return null;
    }
};

pub const ParseError = error{
    MissingFlagValue,
    UnknownFlagSyntax,
} || Allocator.Error;

pub fn parse(arena: Allocator, args: []const []const u8) ParseError!Parsed {
    var positionals: std.ArrayList([]const u8) = .empty;
    var flags: std.StringArrayHashMapUnmanaged([]const u8) = .empty;
    var bools: std.StringArrayHashMapUnmanaged(void) = .empty;
    var rest: ?[]const []const u8 = null;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--")) {
            rest = args[i + 1 ..];
            break;
        }
        if (std.mem.startsWith(u8, arg, "--")) {
            const body = arg[2..];
            if (body.len == 0) return error.UnknownFlagSyntax;
            if (std.mem.indexOfScalar(u8, body, '=')) |eq| {
                try flags.put(arena, body[0..eq], body[eq + 1 ..]);
            } else if (isBoolFlag(body)) {
                try bools.put(arena, body, {});
            } else {
                i += 1;
                if (i >= args.len) return error.MissingFlagValue;
                try flags.put(arena, body, args[i]);
            }
        } else {
            try positionals.append(arena, arg);
        }
    }

    return .{
        .positionals = try positionals.toOwnedSlice(arena),
        .flags = flags,
        .bools = bools,
        .rest = rest,
    };
}

fn isBoolFlag(name: []const u8) bool {
    for (bool_flags) |b| {
        if (std.mem.eql(u8, name, b)) return true;
    }
    return false;
}

test parse {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const parsed = try parse(arena, &.{
        "add", "prod", "--host", "1.2.3.4", "--port=2222", "--json", "--", "echo", "hi",
    });
    try t.expectEqual(2, parsed.positionals.len);
    try t.expectEqualStrings("prod", parsed.positionals[1]);
    try t.expectEqualStrings("1.2.3.4", parsed.flag("host").?);
    try t.expectEqualStrings("2222", parsed.flag("port").?);
    try t.expect(parsed.boolean("json"));
    try t.expectEqual(2, parsed.rest.?.len);
}

test "trailing: --cmd, --, and bare positionals" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Explicit --cmd wins.
    var p = try parse(arena, &.{ "prod", "--cmd", "uname -a" });
    try t.expectEqualStrings("uname -a", (try p.trailing(arena, 1)).?);

    // Standard -- form.
    p = try parse(arena, &.{ "prod", "--", "echo", "hi" });
    try t.expectEqualStrings("echo hi", (try p.trailing(arena, 1)).?);

    // Shell swallowed the --: extra positionals become the command.
    p = try parse(arena, &.{ "prod", "hostname" });
    try t.expectEqualStrings("hostname", (try p.trailing(arena, 1)).?);

    // Nothing given.
    p = try parse(arena, &.{"prod"});
    try t.expectEqual(null, try p.trailing(arena, 1));
}
