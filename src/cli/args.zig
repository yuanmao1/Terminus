//! Hand-rolled CLI argument parsing: positionals, `--flag value`,
//! `--flag=value`, boolean flags, and a trailing `--` rest section.
const std = @import("std");
const Allocator = std.mem.Allocator;

/// Flags that never consume a value.
///
/// A flag missing from this list is not a compile error and is invisible to any
/// gate that calls a command's helpers directly: the parser falls through to
/// `--flag <value>`, so the flag written last fails with "a flag is missing its
/// value" and the flag written before another one silently eats it. Both were
/// found by running the binary. `cmd_transfer_test` gates `--restart` and
/// `--resume` against this list for that reason; a new boolean flag belongs
/// here and in a gate, in the same commit.
const bool_flags = [_][]const u8{ "json", "from-cursor", "no-enter", "raw", "no-daemon", "dry-run", "apply", "delete", "force", "stdin", "login", "append", "strict", "include-keys", "active", "discard-evidence", "from-log", "from-helper", "read-only", "show-script", "all", "restart", "resume", "no-clobber", "normalize-lf", "trust-on-first-use", "rotate", "revoke", "allow-helper-install", "detach", "follow", "mounts", "containers", "cleanup-candidates" };

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

test "gate: every boolean flag production code reads is registered, and every registration is read" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // A boolean read that is not registered is always `false`, and the argument
    // after the flag is eaten as that flag's value — so `--revoke --key-type X`
    // silently becomes `revoke = "--key-type"` with `revoke` reading false. Three
    // of `server pin`'s five actions shipped that way, and the comment above
    // `bool_flags` had already said a new flag belongs "here and in a gate, in
    // the same commit". The instruction was written down and still missed, so this
    // holds the class rather than the three instances.
    //
    // A directory walk and not a registry of files: a new file in src/cli/ is
    // covered without anybody remembering to add it.
    var threaded: std.Io.Threaded = .init(t.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var dir = try std.Io.Dir.cwd().openDir(io, "src/cli", .{ .iterate = true });
    defer dir.close(io);

    var read: std.StringArrayHashMapUnmanaged(void) = .empty;
    var files: usize = 0;
    var walker = try dir.walk(arena);
    defer walker.deinit();
    while (try walker.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.basename, ".zig")) continue;
        // Tests are excluded on purpose: cmd_exec_test.zig asserts that the
        // parser does NOT treat `stdin-file` as a boolean, precisely because
        // `--stdin-file` takes a value and registering it would make the path it
        // was given parse as a positional. A scan that included tests would
        // demand the opposite of what that assertion proves.
        //
        // The flag name above is deliberately not written in the shape this scan
        // looks for. The first version of this comment was, and the gate found its
        // own text and reported `stdin-file` as an unregistered production read —
        // the fourth time in this tree that a scanner has been confused by prose
        // about scanning.
        if (std.mem.indexOf(u8, entry.basename, "_test") != null) continue;
        files += 1;
        const body = try entry.dir.readFileAlloc(io, entry.basename, arena, .limited(1 << 23));
        var at: usize = 0;
        // Split inside the word, not at the quote. Splitting at the quote still
        // leaves the searched-for sequence intact — the first literal's closing
        // quote completes it — so the gate found itself a second time and reported
        // ` ++ ` as an unregistered flag. Then it found itself a third time, in the
        // comment that explained the second. Splitting mid-identifier is the only
        // spelling that cannot match, and no prose here may spell the sequence out.
        const needle = "bool" ++ "ean(\"";
        while (std.mem.indexOfPos(u8, body, at, needle)) |hit| {
            const start = hit + needle.len;
            const end = std.mem.indexOfScalarPos(u8, body, start, '"') orelse break;
            try read.put(arena, body[start..end], {});
            at = end;
        }
    }

    // The walk found files, so an empty scan cannot pass as agreement. This is the
    // failure mode a source-scanning gate has: it finds nothing and says nothing
    // is wrong.
    try t.expect(files >= 15);
    try t.expect(read.count() >= 20);

    for (read.keys()) |name| {
        if (!isBoolFlag(name)) {
            std.debug.print(
                \\
                \\production code asks the parser for the boolean "{s}", but "{s}" is not in
                \\`bool_flags`, so that read is always false and the argument after
                \\the flag is consumed as its value. Add it to the list.
                \\
            , .{ name, name });
            return error.BooleanFlagNotRegistered;
        }
    }

    // And the reverse, because a registration nothing reads means the flag was
    // renamed or dropped while the parser kept treating the old spelling as a
    // boolean — which silently changes how the next argument is read.
    for (bool_flags) |name| {
        if (read.get(name) == null) {
            std.debug.print(
                \\
                \\"{s}" is registered in `bool_flags` but no production file reads
                \\that boolean. Either it was renamed and the old spelling is
                \\still swallowing arguments, or it is dead and should go.
                \\
            , .{name});
            return error.RegisteredBooleanFlagNeverRead;
        }
    }
}
