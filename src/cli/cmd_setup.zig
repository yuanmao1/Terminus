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
/// setup), silently rewrite it. Called on every CLI startup — costs two
/// small file reads; never *installs* anywhere the user hasn't opted in.
pub fn autoRefresh(ctx: *Cli.Ctx) void {
    const targets = [_][]const []const u8{
        &.{ ".claude", "skills", "terminus", "SKILL.md" },
        &.{ ".codex", "skills", "terminus", "SKILL.md" },
    };
    const home = ctx.environ.get("USERPROFILE") orelse ctx.environ.get("HOME") orelse return;
    const cwd = std.Io.Dir.cwd();
    for (targets) |parts| {
        const all = std.mem.concat(ctx.arena, []const u8, &.{ &.{home}, parts }) catch return;
        const path = std.fs.path.join(ctx.arena, all) catch return;
        const existing = cwd.readFileAlloc(ctx.io, path, ctx.arena, .limited(1 << 20)) catch continue;
        if (std.mem.eql(u8, existing, skill_md)) continue;
        cwd.writeFile(ctx.io, .{ .sub_path = path, .data = skill_md }) catch continue;
        // stderr: stdout may be machine-parsed JSON.
        std.debug.print("terminus: refreshed agent skill at {s}\n", .{path});
    }
}

pub fn run(ctx: *Cli.Ctx, raw_args: []const []const u8) !void {
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
