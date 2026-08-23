//! `terminus setup` — install the Terminus skill into coding agents.
//!
//! The skill text ships inside the binary (@embedFile), so setup works
//! offline and stays in sync with the CLI version.
//!
//! Install targets:
//! * claude    ~/.claude/skills/terminus/SKILL.md        (user-wide)
//! * codex     ~/.codex/skills/terminus/SKILL.md         (user-wide)
//! * cursor    ./.cursor/rules/terminus.mdc              (per-project)
//! * windsurf  ./.windsurf/rules/terminus.md             (per-project)
//! * agents    ./AGENTS.md                               (append, per-project)
const std = @import("std");
const fatal = Cli.fail;
const Cli = @import("cli.zig");

const skill_md = @embedFile("terminus_skill");

// --- What the document requires, against what this binary is -------------------
//
// The version in `dispatch.zig` is one fact with one origin. What the document
// states is a *different* fact — the oldest terminus that can honour it — and it
// moves only when the document starts describing something a released binary does
// not have. So it is not a copy to be generated from the version; it is a claim
// to be ordered against it. A binary newer than the claim is the normal case.
//
// What it may not be is unreadable, and what must not happen is the behaviour
// this replaced: `autoRefresh` compared *content* and nothing else, so one local
// build would overwrite `~/.claude/skills/terminus/SKILL.md` with a document
// describing flags the terminus on the reader's PATH does not have. That failure
// is not even loud at the far end — `args.zig` treats an unregistered flag as
// taking a value, so `--restart` on an older binary eats the argument after it
// and the command runs meaning something else.

/// The sentence the document states its minimum in, and what closes it. Read as
/// literals, the way `skill_doc.zig` reads every other claim in that file: a
/// reflow that defeats the reading fails the gate rather than quietly checking
/// nothing.
const requirement_needle = "**Requires terminus >= ";
const requirement_end = ".**";

pub const RequirementError = error{
    SkillRequirementMissing,
    SkillRequirementRepeated,
    SkillRequirementUnterminated,
} || Cli.Dispatch.Version.ParseError;

/// The version text a skill document states as its minimum.
///
/// Exactly one statement, because two would make "what does this document
/// require" depend on which one a reader found first.
pub fn requirementText(doc: []const u8) RequirementError![]const u8 {
    const at = std.mem.indexOf(u8, doc, requirement_needle) orelse
        return error.SkillRequirementMissing;
    if (std.mem.indexOfPos(u8, doc, at + requirement_needle.len, requirement_needle) != null)
        return error.SkillRequirementRepeated;
    const rest = doc[at + requirement_needle.len ..];
    const end = std.mem.indexOf(u8, rest, requirement_end) orelse
        return error.SkillRequirementUnterminated;
    return rest[0..end];
}

/// The same, ordered.
pub fn requiredBy(doc: []const u8) RequirementError!Cli.Dispatch.Version {
    return Cli.Dispatch.Version.parse(try requirementText(doc));
}

/// The minimum the document *in this binary* states.
///
/// Comptime, so a shipped document whose minimum cannot be read is a build
/// failure rather than a runtime branch nothing ever exercises. The reverse —
/// treating an unreadable minimum as satisfied — is the one answer nothing here
/// is allowed to give.
pub const embedded_requirement_string: []const u8 = blk: {
    // Two scans of a ~60 KB document, at compile time. The alternative is a
    // runtime read, which would give up the `@compileError` below — and a
    // document whose minimum cannot be read is a build defect, not a condition to
    // branch on in front of a user.
    @setEvalBranchQuota(20_000_000);
    break :blk requirementText(skill_md) catch |err| @compileError(
        "skill/SKILL.md must state its minimum once as \"" ++ requirement_needle ++
            "<major.minor.patch>" ++ requirement_end ++ "\": " ++ @errorName(err),
    );
};

pub const embedded_requirement: Cli.Dispatch.Version =
    Cli.Dispatch.Version.parse(embedded_requirement_string) catch |err| @compileError(
        "skill/SKILL.md requires terminus >= \"" ++ embedded_requirement_string ++
            "\", which is not major.minor.patch: " ++ @errorName(err),
    );

/// Whether a terminus at `binary` may install `doc`.
///
/// The policy both `setup` and `autoRefresh` apply to the document they are about
/// to write, taking the binary as a parameter so it can be judged for a version
/// this build is not — otherwise the only case ever exercised is whatever pair
/// this checkout happens to hold, and the interesting answers are the other ones.
///
/// A document with no minimum, or one whose minimum cannot be read, is refused.
/// That is the asymmetry with `overwriteVerdict` below and it is deliberate: a
/// document *shipped by this binary* is expected to state what it needs, and
/// "cannot tell" is not "satisfied". The mirror case — a file already on disk
/// that states nothing — is a file making no claim to violate.
pub fn mayInstall(binary: Cli.Dispatch.Version, doc: []const u8) bool {
    const floor = requiredBy(doc) catch return false;
    return binary.atLeast(floor);
}

/// Whether this binary can honour the document it ships.
///
/// A function and not a `const`, deliberately. Zig only analyses the branch a
/// comptime-known condition takes, so a `const` here would mean the refusals
/// below are not compiled at all on a build that happens to satisfy its own
/// document — and the first build that did *not* satisfy it would be the first to
/// compile them. This is the one decision in this file that has to be checked on
/// every build, so it is spelled in a way that cannot be folded away before the
/// compiler has looked at both answers.
pub fn embeddedSatisfied() bool {
    return mayInstall(Cli.Dispatch.version, skill_md);
}

/// Whether `binary` may replace a document already sitting at an install path.
///
/// The mirror of `mayInstall` and not the same question: that one asks whether
/// the document being written is honourable, this asks whether the one being
/// destroyed was written by a newer terminus. Both are the same harm — an agent
/// reading instructions that do not match the binary on its PATH — and this
/// direction is the one that arrives with the *next* release, when an old local
/// build is run in a checkout whose npm install has moved on.
///
/// A document stating no minimum states nothing this binary can violate, so it
/// may be replaced. One stating a minimum nothing can read is left alone:
/// "unreadable" is not "older".
pub const Overwrite = struct {
    allowed: bool,
    /// What the installed document states, for the refusal to quote.
    requires: []const u8,

    pub const unreadable = "a minimum this build cannot read";
};

pub fn overwriteVerdict(binary: Cli.Dispatch.Version, existing: []const u8) Overwrite {
    const stated = requirementText(existing) catch |err| switch (err) {
        error.SkillRequirementMissing => return .{ .allowed = true, .requires = "" },
        else => return .{ .allowed = false, .requires = Overwrite.unreadable },
    };
    const floor = Cli.Dispatch.Version.parse(stated) catch
        return .{ .allowed = false, .requires = Overwrite.unreadable };
    return .{ .allowed = binary.atLeast(floor), .requires = stated };
}

const usage =
    \\usage: terminus setup [<target>...] [--json]
    \\
    \\targets: claude codex cursor windsurf agents all
    \\default: claude codex (user-wide installs)
    \\project-local targets (cursor/windsurf/agents) write into the current directory.
    \\
;

const Target = enum { claude, codex, cursor, windsurf, agents };

const Result = struct {
    target: []const u8,
    path: []const u8,
    action: []const u8, // "installed" | "updated" | "up-to-date"
};

/// Self-healing skill: if a user-wide skill file exists but differs from
/// the one embedded in this binary (npm upgrade without re-running
/// setup), rewrite it — but only when this binary can honour both the document
/// it would write and the one it would destroy. Called on every CLI startup —
/// costs two small file reads; never *installs* anywhere the user hasn't opted
/// in, and never downgrades a document a newer terminus put there.
///
/// **Why a refusal rather than writing with a warning.** Writing and warning
/// warns exactly once: the next startup finds the content equal and returns
/// early, so the wrong document stays installed with nothing left to say about
/// it. Writing a marked-up copy is worse — the installed file then differs from
/// the embedded one for good, so every startup rewrites it and the document an
/// agent reads is no longer the document the gates in this tree check. Refusing
/// leaves the last honourable document in place and re-states why on each run of
/// the binary that cannot honour it, which is bounded to exactly the runs that
/// would otherwise do the damage and stops the moment the version moves.
pub fn autoRefresh(ctx: *Cli.Ctx) void {
    // The home first: a process with nowhere to install has nothing to refuse
    // either, and a startup path should not narrate a decision it was never in a
    // position to take.
    const home = ctx.environ.get("USERPROFILE") orelse ctx.environ.get("HOME") orelse return;
    if (!embeddedSatisfied()) {
        // Once per process rather than once per target: the reason is the same
        // for both, and this is a startup path.
        std.debug.print(
            "terminus: not refreshing the agent skill — the document in this binary requires " ++
                "terminus >= {s} and this build is {s}. Installing it would promise flags this " ++
                "binary rejects, and an unregistered flag consumes the argument after it " ++
                "instead of failing.\n",
            .{ embedded_requirement_string, Cli.Dispatch.version_string },
        );
        return;
    }
    refreshUserSkills(ctx, home, Cli.Dispatch.version, skill_md);
}

/// The write half of the refresh, over an explicit home, binary version and
/// document.
///
/// Parameterised for the reason `mayInstall` is: driven only through
/// `autoRefresh` it can be exercised for exactly one pair — whatever this
/// checkout happens to hold — and would then go red the day somebody legitimately
/// raises what the document requires. The gate drives it for a binary this build
/// is not, so what is checked is the rule and not the current numbers.
pub fn refreshUserSkills(
    ctx: *Cli.Ctx,
    home: []const u8,
    binary: Cli.Dispatch.Version,
    doc: []const u8,
) void {
    const targets = [_][]const []const u8{
        &.{ ".claude", "skills", "terminus", "SKILL.md" },
        &.{ ".codex", "skills", "terminus", "SKILL.md" },
    };
    const cwd = std.Io.Dir.cwd();
    for (targets) |parts| {
        const all = std.mem.concat(ctx.arena, []const u8, &.{ &.{home}, parts }) catch return;
        const path = std.fs.path.join(ctx.arena, all) catch return;
        const existing = cwd.readFileAlloc(ctx.io, path, ctx.arena, .limited(1 << 20)) catch continue;
        if (std.mem.eql(u8, existing, doc)) continue;
        const verdict = overwriteVerdict(binary, existing);
        if (!verdict.allowed) {
            // stderr: stdout may be machine-parsed JSON.
            std.debug.print(
                "terminus: left the agent skill at {s} alone — it states {s}, and this build " ++
                    "is {f}; a newer terminus installed it and overwriting it would hand an " ++
                    "agent older instructions than the binary on its PATH\n",
                .{ path, verdict.requires, binary },
            );
            continue;
        }
        cwd.writeFile(ctx.io, .{ .sub_path = path, .data = doc }) catch continue;
        // stderr: stdout may be machine-parsed JSON.
        std.debug.print("terminus: refreshed agent skill at {s}\n", .{path});
    }
}

pub fn run(ctx: *Cli.Ctx, raw_args: []const []const u8) !void {
    // An explicit `setup` is a request to install *this binary's* document, so
    // the check on that document applies here too — a document the binary cannot
    // honour is not made honourable by being asked for. The other half of
    // `autoRefresh`'s policy deliberately does not apply: refusing to replace a
    // newer installed copy is right for a startup side effect nobody asked for,
    // and wrong for an operator who typed the command.
    if (!embeddedSatisfied()) fatal(
        "refusing to install: the skill document in this binary requires terminus >= {s}, " ++
            "and this build is {s}. Bump the version in npm/package.json, or lower what " ++
            "skill/SKILL.md requires to a released version that has the flags it describes.",
        .{ embedded_requirement_string, Cli.Dispatch.version_string },
    );

    const parsed = Cli.parseArgs(ctx, raw_args);
    if (parsed.boolean("json")) ctx.out.format = .json;

    var targets: std.ArrayList(Target) = .empty;
    if (parsed.positionals.len == 0) {
        try targets.appendSlice(ctx.arena, &.{ .claude, .codex });
    } else for (parsed.positionals) |name| {
        if (std.mem.eql(u8, name, "all")) {
            try targets.appendSlice(ctx.arena, &.{ .claude, .codex, .cursor, .windsurf, .agents });
        } else {
            const t = std.meta.stringToEnum(Target, name) orelse
                fatal("unknown target '{s}'\n{s}", .{ name, usage });
            try targets.append(ctx.arena, t);
        }
    }

    var results: std.ArrayList(Result) = .empty;
    for (targets.items) |target| {
        try results.append(ctx.arena, try install(ctx, target));
    }

    switch (ctx.out.format) {
        .json => try ctx.out.json(.{ .ok = true, .results = results.items }),
        .human => for (results.items) |r| {
            try ctx.out.print("{s}: {s} ({s})\n", .{ r.target, r.action, r.path });
        },
    }
}

fn install(ctx: *Cli.Ctx, target: Target) !Result {
    return switch (target) {
        .claude => try writeSkillFile(ctx, "claude", try userPath(ctx, &.{ ".claude", "skills", "terminus" }), "SKILL.md", skill_md),
        .codex => try writeSkillFile(ctx, "codex", try userPath(ctx, &.{ ".codex", "skills", "terminus" }), "SKILL.md", skill_md),
        .cursor => try writeSkillFile(ctx, "cursor", ".cursor/rules", "terminus.mdc", try cursorRule(ctx)),
        .windsurf => try writeSkillFile(ctx, "windsurf", ".windsurf/rules", "terminus.md", stripFrontmatter(skill_md)),
        .agents => try appendAgentsMd(ctx),
    };
}

fn userPath(ctx: *Cli.Ctx, parts: []const []const u8) ![]u8 {
    const home = ctx.environ.get("USERPROFILE") orelse ctx.environ.get("HOME") orelse
        fatal("cannot locate home directory (no USERPROFILE/HOME)", .{});
    const all = try std.mem.concat(ctx.arena, []const u8, &.{ &.{home}, parts });
    return std.fs.path.join(ctx.arena, all);
}

fn writeSkillFile(ctx: *Cli.Ctx, target: []const u8, dir: []const u8, file_name: []const u8, content: []const u8) !Result {
    const cwd = std.Io.Dir.cwd();
    cwd.createDirPath(ctx.io, dir) catch |err|
        fatal("cannot create {s}: {s}", .{ dir, @errorName(err) });
    const path = try std.fs.path.join(ctx.arena, &.{ dir, file_name });

    // Idempotent: only touch the file when content differs.
    const existing = cwd.readFileAlloc(ctx.io, path, ctx.arena, .limited(1 << 20)) catch null;
    if (existing) |old| {
        if (std.mem.eql(u8, old, content))
            return .{ .target = target, .path = path, .action = "up-to-date" };
    }
    cwd.writeFile(ctx.io, .{ .sub_path = path, .data = content }) catch |err|
        fatal("cannot write {s}: {s}", .{ path, @errorName(err) });
    return .{
        .target = target,
        .path = path,
        .action = if (existing == null) "installed" else "updated",
    };
}

/// Cursor .mdc rules use their own frontmatter schema.
fn cursorRule(ctx: *Cli.Ctx) ![]u8 {
    return std.fmt.allocPrint(ctx.arena,
        \\---
        \\description: Remote server operations via the terminus CLI (SSH exec, persistent sessions, per-server memory)
        \\alwaysApply: false
        \\---
        \\
        \\{s}
    , .{stripFrontmatter(skill_md)});
}

const agents_begin_marker = "<!-- terminus:begin -->";
const agents_end_marker = "<!-- terminus:end -->";

/// AGENTS.md is shared with other tools, so Terminus owns only a marked
/// block: create it, or replace exactly that block on re-run.
fn appendAgentsMd(ctx: *Cli.Ctx) !Result {
    const cwd = std.Io.Dir.cwd();
    const block = try std.fmt.allocPrint(ctx.arena, "{s}\n{s}\n{s}\n", .{
        agents_begin_marker, stripFrontmatter(skill_md), agents_end_marker,
    });

    const existing = cwd.readFileAlloc(ctx.io, "AGENTS.md", ctx.arena, .limited(1 << 20)) catch null;
    var content: []u8 = undefined;
    var action: []const u8 = undefined;
    if (existing) |old| {
        if (std.mem.indexOf(u8, old, agents_begin_marker)) |begin| {
            const end_pos = std.mem.indexOfPos(u8, old, begin, agents_end_marker) orelse
                fatal("AGENTS.md has a terminus begin marker but no end marker; fix it manually", .{});
            const end = end_pos + agents_end_marker.len;
            const tail = std.mem.trimStart(u8, old[end..], "\n");
            content = try std.mem.concat(ctx.arena, u8, &.{ old[0..begin], block, tail });
            action = "updated";
            if (std.mem.eql(u8, old, content))
                return .{ .target = "agents", .path = "AGENTS.md", .action = "up-to-date" };
        } else {
            content = try std.mem.concat(ctx.arena, u8, &.{ old, "\n", block });
            action = "updated";
        }
    } else {
        content = try std.mem.concat(ctx.arena, u8, &.{block});
        action = "installed";
    }
    cwd.writeFile(ctx.io, .{ .sub_path = "AGENTS.md", .data = content }) catch |err|
        fatal("cannot write AGENTS.md: {s}", .{@errorName(err)});
    return .{ .target = "agents", .path = "AGENTS.md", .action = action };
}

fn stripFrontmatter(text: []const u8) []const u8 {
    if (!std.mem.startsWith(u8, text, "---")) return text;
    const end = std.mem.indexOfPos(u8, text, 3, "\n---") orelse return text;
    const after = std.mem.indexOfScalarPos(u8, text, end + 1, '\n') orelse return text;
    return std.mem.trimStart(u8, text[after + 1 ..], "\n");
}

test stripFrontmatter {
    const t = std.testing;
    try t.expectEqualStrings("# Body\n", stripFrontmatter("---\nname: x\n---\n\n# Body\n"));
    try t.expectEqualStrings("no frontmatter", stripFrontmatter("no frontmatter"));
}
