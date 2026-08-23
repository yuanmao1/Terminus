//! The version, its one origin, and the pairing between the binary and the
//! document it installs.
//!
//! **What was wrong.** The same number was hand-written in three places: twice in
//! `dispatch.zig`'s `version` arm, once in `npm/package.json`, and once as the
//! minimum `skill/SKILL.md` states. Nothing held them together, and
//! `cmd_setup.autoRefresh` — which runs on *every* CLI startup — compared the
//! document's **content** and nothing else. So one local build would overwrite
//! `~/.claude/skills/terminus/SKILL.md` with a document describing flags that the
//! terminus on the reader's PATH does not have, and the far end of that is not
//! even loud: `args.zig` treats an unregistered flag as taking a value, so an
//! unknown `--restart` eats the argument after it and the command runs meaning
//! something else.
//!
//! **What these gates hold.** That the version has exactly one origin and a
//! second hand-written copy fails; that the comparison is numeric, because the
//! byte comparison puts `0.1.10` *below* `0.1.9` and that has already produced a
//! false claim in this tree; that an unreadable version on either side is refused
//! rather than assumed to satisfy; and that nothing installs a document this
//! binary cannot honour while a binary newer than the document installs normally.
//!
//! Deliberately **not** held: which way the current pair happens to compare. The
//! document's minimum is allowed to sit below the binary — that is the normal
//! case — and raising it above the binary is a legitimate, temporary pre-release
//! state. A gate that asserted a direction would go red for one of those two, and
//! the refusal that `autoRefresh` prints is what reports the state anyway.
const std = @import("std");
const Cli = @import("cli.zig");
const Dispatch = @import("dispatch.zig");
const Setup = @import("cmd_setup.zig");
const Version = Dispatch.Version;

const dispatch_source = @embedFile("dispatch.zig");
const setup_source = @embedFile("cmd_setup.zig");
const package_json = @embedFile("terminus_package_json");
const skill_document = Cli.skill_doc.text;

// --- 1. One origin -------------------------------------------------------------

fn digit(c: u8) bool {
    return c >= '0' and c <= '9';
}

/// Whether `line` holds a `<digits>.<digits>.<digits>` run anywhere in it.
///
/// The shape rather than a search for the current number, which is the point: a
/// gate looking for `0.1.10` would pass the day somebody wrote `0.2.0` by hand.
fn hasDottedTriple(line: []const u8) bool {
    var i: usize = 0;
    while (i < line.len) : (i += 1) {
        if (!digit(line[i])) continue;
        var j = i;
        var dots: usize = 0;
        while (j < line.len and (digit(line[j]) or
            (line[j] == '.' and j + 1 < line.len and digit(line[j + 1]))))
        {
            if (line[j] == '.') dots += 1;
            j += 1;
        }
        if (dots >= 2) return true;
        i = j;
    }
    return false;
}

const Scan = struct { lines: usize, hits: usize };

/// Every line of `source` that reports something to somebody — comments and
/// multiline string literals excluded, because that is where this tree's
/// historical version numbers legitimately live (a paragraph about what 0.1.10
/// did is not a copy of the version; a `const` holding it is).
fn scan(source: []const u8) Scan {
    var out: Scan = .{ .lines = 0, .hits = 0 };
    var lines = std.mem.splitScalar(u8, source, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (std.mem.startsWith(u8, line, "//")) continue;
        if (std.mem.startsWith(u8, line, "\\\\")) continue;
        out.lines += 1;
        if (hasDottedTriple(line)) out.hits += 1;
    }
    return out;
}

test "gate: the version has one origin, and a second hand-written copy fails" {
    const t = std.testing;

    // The origin itself. Two `"version"` keys would make which one is the origin
    // depend on byte order, which is the whole failure being removed.
    try t.expectEqual(@as(usize, 1), std.mem.count(u8, package_json, "\"version\""));

    // The comptime read, against an independent one done a different way. A gate
    // that reused `packageVersion` would only be checking that it agrees with
    // itself.
    const opener = "\"version\": \"";
    const at = std.mem.indexOf(u8, package_json, opener) orelse return error.ManifestVersionNotFound;
    const rest = package_json[at + opener.len ..];
    const close = std.mem.indexOfScalar(u8, rest, '"') orelse return error.ManifestVersionUnterminated;
    try t.expectEqualStrings(rest[0..close], Dispatch.version_string);

    // The derivation is still a derivation: the manifest is read, and the version
    // is what the read produced.
    try t.expectEqual(@as(usize, 1), std.mem.count(u8, dispatch_source, "@embedFile(\"terminus_package_json\")"));
    try t.expectEqual(@as(usize, 1), std.mem.count(u8, dispatch_source, "packageVersion(package_json)"));

    // The scanner works, held on a line that is exactly what it must catch.
    // Without this the two zeroes below would also be produced by a scanner that
    // never matches anything.
    try t.expect(hasDottedTriple("    .json => try ctx.out.json(.{ .version = \"0.1.10\" }),"));
    try t.expect(hasDottedTriple("terminus 0.2.0"));
    try t.expect(!hasDottedTriple("    const existing = read(io, path, .limited(1 << 20));"));
    try t.expect(!hasDottedTriple("    if (a.major != b.major) return order(a.major, b.major);"));

    // And neither of the two files that could report a version holds one. Both
    // line counts are asserted non-trivial, so a scan over an empty region — a
    // renamed file, an `@embedFile` that resolved to nothing — fails instead of
    // passing.
    const files = [_]struct { name: []const u8, source: []const u8 }{
        .{ .name = "dispatch.zig", .source = dispatch_source },
        .{ .name = "cmd_setup.zig", .source = setup_source },
    };
    var checked: usize = 0;
    for (files) |file| {
        const result = scan(file.source);
        if (result.lines < 60) {
            std.debug.print(
                \\
                \\src/cli/{s}: only {d} code lines were scanned for a hand-written version.
                \\Either the file shrank to nothing or the embed no longer resolves to it;
                \\either way this gate is checking an empty region and reporting a pass.
                \\
            , .{ file.name, result.lines });
            return error.VersionScanFoundNothingToScan;
        }
        if (result.hits != 0) {
            std.debug.print(
                \\
                \\src/cli/{s} writes a version number in code, on {d} line(s). The version has
                \\one origin — npm/package.json — because `npm publish` reads that file and
                \\cannot be made to read a Zig constant. A second copy here drifts the day
                \\somebody bumps one of them, which is how the binary came to report 0.1.10
                \\while shipping a document describing flags 0.1.10 rejects.
                \\
            , .{ file.name, result.hits });
            return error.VersionWrittenByHand;
        }
        checked += 1;
    }
    try t.expectEqual(files.len, checked);
}

// --- 2. Ordering ---------------------------------------------------------------

test "gate: versions order numerically — 0.1.10 is above 0.1.9, which bytes get wrong" {
    const t = std.testing;

    const cases = [_]struct { a: []const u8, b: []const u8, want: std.math.Order }{
        .{ .a = "0.1.10", .b = "0.1.9", .want = .gt },
        .{ .a = "0.1.9", .b = "0.1.10", .want = .lt },
        .{ .a = "0.1.10", .b = "0.1.10", .want = .eq },
        .{ .a = "0.2.0", .b = "0.1.99", .want = .gt },
        .{ .a = "1.0.0", .b = "0.99.99", .want = .gt },
        .{ .a = "0.10.0", .b = "0.9.0", .want = .gt },
        .{ .a = "10.0.0", .b = "9.0.0", .want = .gt },
        .{ .a = "0.0.100", .b = "0.0.99", .want = .gt },
    };

    // The second half of the reading: how many of those the byte comparison gets
    // wrong. Counted rather than asserted case by case, so the number itself is
    // the record — five of eight, every one of them a `10` against a `9`. This is
    // the shape that hid `v0.1.10` from `git tag -l | tail -5` and produced a
    // reported claim that the release had never been tagged.
    var disagreements: usize = 0;
    for (cases) |case| {
        const a = try Version.parse(case.a);
        const b = try Version.parse(case.b);
        try t.expectEqual(case.want, a.order(b));
        // `atLeast` is what every caller actually asks, so it is checked here and
        // not derived by a reader.
        try t.expectEqual(case.want != .lt, a.atLeast(b));
        if (std.mem.order(u8, case.a, case.b) != case.want) disagreements += 1;
    }
    try t.expectEqual(@as(usize, 8), cases.len);
    try t.expectEqual(@as(usize, 5), disagreements);
}

// --- 3. Unreadable is refused, never assumed -----------------------------------

test "gate: a version that cannot be read is refused, not assumed to satisfy" {
    const t = std.testing;

    const bad = [_]struct { text: []const u8, want: anyerror }{
        .{ .text = "", .want = error.VersionComponentEmpty },
        .{ .text = "0.1.", .want = error.VersionComponentEmpty },
        .{ .text = "0..1", .want = error.VersionComponentEmpty },
        .{ .text = "0.1", .want = error.VersionNotThreeComponents },
        .{ .text = "0.1.10.1", .want = error.VersionNotThreeComponents },
        .{ .text = "0.1.x", .want = error.VersionComponentNotANumber },
        .{ .text = "v0.1.10", .want = error.VersionComponentNotANumber },
        // A pre-release is refused rather than ordered: this tree has only ever
        // released plain triples, and guessing where `-rc.1` sorts would be
        // inventing the answer.
        .{ .text = "0.2.0-rc.1", .want = error.VersionComponentNotANumber },
        // `std.fmt.parseInt` would take both of these and read the second as ten.
        .{ .text = "0.1.+1", .want = error.VersionComponentNotANumber },
        .{ .text = "0.1.1_0", .want = error.VersionComponentNotANumber },
        .{ .text = " 0.1.10", .want = error.VersionComponentNotANumber },
        .{ .text = "0.1.10 ", .want = error.VersionComponentNotANumber },
        .{ .text = "0.1.4294967296", .want = error.VersionComponentTooLarge },
    };

    var refused: usize = 0;
    for (bad) |case| {
        refused += 1;
        try t.expectError(case.want, Version.parse(case.text));
    }
    try t.expectEqual(@as(usize, 13), refused);
}

// --- 4. The shipped document's minimum -----------------------------------------

test "gate: the shipped document states one minimum, and it is readable" {
    const t = std.testing;

    // One statement. Two would make "what does this document require" depend on
    // which one a reader found first.
    try t.expectEqual(
        @as(usize, 1),
        std.mem.count(u8, skill_document, "**Requires terminus >= "),
    );

    // It is the real document and not an empty embed, so the count above is a
    // reading of something.
    try t.expect(skill_document.len > 4096);
    try t.expect(std.mem.indexOf(u8, skill_document, "terminus exec") != null);

    // The comptime constants the refusals quote are the same thing a live parse
    // finds. This is the cross-check that catches a `@compileError` guard that
    // was satisfied by a *different* sentence than the one being read here.
    const stated = try Setup.requirementText(skill_document);
    try t.expectEqualStrings(stated, Setup.embedded_requirement_string);
    const floor = try Setup.requiredBy(skill_document);
    try t.expectEqual(Setup.embedded_requirement, floor);

    // And the decision the binary acts on is the policy applied to this binary
    // and this document, not something beside it. Which way it comes out is not
    // asserted — see the header.
    try t.expectEqual(Setup.mayInstall(Dispatch.version, skill_document), Setup.embeddedSatisfied());
}

// --- 5. What gets installed, and over what --------------------------------------

fn v(text: []const u8) !Version {
    return Version.parse(text);
}

/// A document stating `floor` as its minimum, in the sentence the real one uses.
fn doc(arena: std.mem.Allocator, floor: []const u8) ![]const u8 {
    return std.fmt.allocPrint(
        arena,
        "# a document\n\n**Requires terminus >= {s}.** and then some prose\n",
        .{floor},
    );
}

test "gate: a document requiring more than the binary provides is not installed" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Judged for binaries this build is not, which is the whole point: the pair
    // this checkout happens to hold exercises one answer, and the answers that
    // matter are the other ones.
    const cases = [_]struct { what: []const u8, binary: []const u8, floor: []const u8, may: bool }{
        .{ .what = "exactly what the document asks for", .binary = "0.1.10", .floor = "0.1.10", .may = true },
        .{ .what = "newer than the document asks for", .binary = "0.2.0", .floor = "0.1.10", .may = true },
        .{ .what = "newer by a patch that bytes would sort below", .binary = "0.1.10", .floor = "0.1.9", .may = true },
        .{ .what = "older by a patch", .binary = "0.1.9", .floor = "0.1.10", .may = false },
        .{ .what = "older by a minor", .binary = "0.1.99", .floor = "0.2.0", .may = false },
        .{ .what = "older by a major", .binary = "1.99.99", .floor = "2.0.0", .may = false },
    };
    var judged: usize = 0;
    for (cases) |case| {
        judged += 1;
        const text = try doc(arena, case.floor);
        t.expectEqual(case.may, Setup.mayInstall(try v(case.binary), text)) catch |err| {
            std.debug.print(
                \\
                \\a terminus {s} was {s} allowed to install a document requiring {s} ({s}).
                \\
            , .{ case.binary, if (case.may) "not" else "wrongly", case.floor, case.what });
            return err;
        };
    }
    try t.expectEqual(@as(usize, 6), judged);

    // Neither "no minimum stated" nor "a minimum nothing can read" is treated as
    // satisfied. This is the direction with no safe default: a document that
    // cannot say what it needs is one nobody can check, and installing it is
    // exactly the silence being removed.
    const unreadable = [_][]const u8{
        "# a document that states no minimum at all\n",
        try doc(arena, "banana"),
        try doc(arena, "0.1"),
        try doc(arena, "0.2.0-rc.1"),
        "**Requires terminus >= 1 2 3",
        "**Requires terminus >= 0.0.1.** and **Requires terminus >= 9.9.9.**\n",
    };
    var refused: usize = 0;
    for (unreadable) |text| {
        refused += 1;
        try t.expect(!Setup.mayInstall(try v("99999.0.0"), text));
    }
    try t.expectEqual(@as(usize, 6), refused);

    // Three distinct errors and not one catch-all, so a repair knows which
    // sentence to fix.
    try t.expectError(error.SkillRequirementMissing, Setup.requiredBy(unreadable[0]));
    try t.expectError(error.SkillRequirementUnterminated, Setup.requiredBy(unreadable[4]));
    try t.expectError(error.SkillRequirementRepeated, Setup.requiredBy(unreadable[5]));
}

test "gate: nothing overwrites a document a newer terminus installed" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const mine = try v("1.2.3");

    const Case = struct {
        what: []const u8,
        text: []const u8,
        allowed: bool,
        requires: []const u8,
    };
    const cases = [_]Case{
        .{
            .what = "the same version as the binary",
            .text = try doc(arena, "1.2.3"),
            .allowed = true,
            .requires = "1.2.3",
        },
        .{
            .what = "older than the binary, which is the normal case",
            .text = try doc(arena, "0.0.1"),
            .allowed = true,
            .requires = "0.0.1",
        },
        .{
            .what = "newer than the binary — installed by a terminus we are not",
            .text = try doc(arena, "1.2.4"),
            .allowed = false,
            .requires = "1.2.4",
        },
        .{
            .what = "no minimum at all, so nothing to violate",
            .text = "# a document with no requirement sentence\n",
            .allowed = true,
            .requires = "",
        },
        .{
            .what = "a minimum that is not a version",
            .text = try doc(arena, "banana"),
            .allowed = false,
            .requires = Setup.Overwrite.unreadable,
        },
        .{
            .what = "a minimum whose sentence never closes",
            .text = "**Requires terminus >= 1 2 3",
            .allowed = false,
            .requires = Setup.Overwrite.unreadable,
        },
        .{
            .what = "two minimums",
            .text = "**Requires terminus >= 0.0.1.** and **Requires terminus >= 9.9.9.**\n",
            .allowed = false,
            .requires = Setup.Overwrite.unreadable,
        },
    };

    var judged: usize = 0;
    for (cases) |case| {
        judged += 1;
        const verdict = Setup.overwriteVerdict(mine, case.text);
        t.expectEqual(case.allowed, verdict.allowed) catch |err| {
            std.debug.print(
                \\
                \\overwriteVerdict got {s} wrong: allowed={}, wanted {}.
                \\
            , .{ case.what, verdict.allowed, case.allowed });
            return err;
        };
        try t.expectEqualStrings(case.requires, verdict.requires);
    }
    try t.expectEqual(@as(usize, 7), judged);
}

// --- 6. The refresh itself ------------------------------------------------------

/// A scratch home directory with a `.claude` skill already installed, which is
/// the state `autoRefresh` actually meets.
const Home = struct {
    io: std.Io,
    threaded: *std.Io.Threaded,
    path: []u8,
    skill_dir: []u8,
    skill_path: []u8,
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator, name: []const u8) !Home {
        const threaded = try allocator.create(std.Io.Threaded);
        threaded.* = .init(allocator, .{});
        const io = threaded.io();
        const path = try std.fmt.allocPrint(
            allocator,
            ".zig-cache/tmp/home_{s}_{d}",
            .{ name, std.Thread.getCurrentId() },
        );
        const skill_dir = try std.fmt.allocPrint(allocator, "{s}/.claude/skills/terminus", .{path});
        try std.Io.Dir.cwd().createDirPath(io, skill_dir);
        const skill_path = try std.fmt.allocPrint(allocator, "{s}/SKILL.md", .{skill_dir});
        return .{
            .io = io,
            .threaded = threaded,
            .path = path,
            .skill_dir = skill_dir,
            .skill_path = skill_path,
            .allocator = allocator,
        };
    }

    fn install(h: *Home, data: []const u8) !void {
        try std.Io.Dir.cwd().writeFile(h.io, .{ .sub_path = h.skill_path, .data = data });
    }

    fn read(h: *Home, gpa: std.mem.Allocator) ![]u8 {
        return std.Io.Dir.cwd().readFileAlloc(h.io, h.skill_path, gpa, .limited(1 << 22));
    }

    /// One refresh against this home, for a chosen binary version and document,
    /// with nothing else in the environment: the only variable it reads is the
    /// home, and a full snapshot would make the gate depend on the machine.
    fn refresh(h: *Home, arena: std.mem.Allocator, binary: Version, document: []const u8) !void {
        var discard: std.Io.Writer.Discarding = .init(&.{});
        var out: Cli.Output = .{ .writer = &discard.writer };
        var environ: std.process.Environ.Map = .init(arena);
        defer environ.deinit();
        try environ.put("USERPROFILE", h.path);
        var ctx: Cli.Ctx = .{
            .io = h.io,
            .arena = arena,
            .environ = &environ,
            .out = &out,
            .now = 0,
        };
        Setup.refreshUserSkills(&ctx, h.path, binary, document);
    }

    fn deinit(h: *Home) void {
        const cwd = std.Io.Dir.cwd();
        cwd.deleteFile(h.io, h.skill_path) catch {};
        cwd.deleteDir(h.io, h.skill_dir) catch {};
        for ([_][]const u8{ ".claude/skills", ".claude" }) |rel| {
            const p = std.fmt.allocPrint(h.allocator, "{s}/{s}", .{ h.path, rel }) catch continue;
            defer h.allocator.free(p);
            cwd.deleteDir(h.io, p) catch {};
        }
        cwd.deleteDir(h.io, h.path) catch {};
        h.allocator.free(h.skill_path);
        h.allocator.free(h.skill_dir);
        h.allocator.free(h.path);
        h.threaded.deinit();
        h.allocator.destroy(h.threaded);
    }
};

// The behaviour, not the reasoning: the readings above decide, and this runs the
// startup path that acts on them against a real directory. It is the half a
// pure-function gate cannot cover — that a refusal means the bytes on disk are
// still there afterwards, and not merely that a function returned false.
//
// Driven for a binary and a document this build is not, deliberately. Pointed at
// the real pair it would exercise one answer and would go red the day somebody
// legitimately raises what `skill/SKILL.md` requires — which is a change the
// refusal is *for*, not one it should forbid.
//
// Each leg prints one line to stderr, which is the point of the design: a refusal
// that said nothing would be the silence this replaced.
test "gate: the refresh replaces an older installed document and refuses a newer one" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const binary = try v("1.2.3");
    const shipped = try doc(arena, "1.0.0");

    {
        // Installed by a terminus this binary is not. Left alone, byte for byte.
        var home = try Home.init(t.allocator, "refresh_newer");
        defer home.deinit();
        const newer = "# installed by a later terminus\n\n**Requires terminus >= 99999.0.0.**\n";
        try home.install(newer);
        try home.refresh(arena, binary, shipped);
        try t.expectEqualStrings(newer, try home.read(arena));
    }

    {
        // Installed by an older terminus, differing in content: replaced.
        var home = try Home.init(t.allocator, "refresh_older");
        defer home.deinit();
        try home.install("# installed by an earlier terminus\n\n**Requires terminus >= 0.0.1.**\n");
        try home.refresh(arena, binary, shipped);
        try t.expectEqualStrings(shipped, try home.read(arena));
    }

    {
        // A document stating a minimum nothing can read. "Unreadable" is not
        // "older", so it is not clobbered either.
        var home = try Home.init(t.allocator, "refresh_unreadable");
        defer home.deinit();
        const unreadable = "# hand-edited\n\n**Requires terminus >= banana.**\n";
        try home.install(unreadable);
        try home.refresh(arena, binary, shipped);
        try t.expectEqualStrings(unreadable, try home.read(arena));
    }

    {
        // No minimum stated: nothing to violate, so the refresh proceeds. Without
        // this leg the three above would also pass for a refresh that had stopped
        // writing anything at all.
        var home = try Home.init(t.allocator, "refresh_silent");
        defer home.deinit();
        try home.install("# a document that states no minimum\n");
        try home.refresh(arena, binary, shipped);
        try t.expectEqualStrings(shipped, try home.read(arena));
    }
}
