//! `terminus session new/ls/rm` — remote tmux session lifecycle.
//!
//! `ls` reports live remote tmux state (source of truth) merged with the
//! local metadata rows (cursor, notes, memory counts).
const std = @import("std");
const fatal = Cli.fail;
const Cli = @import("cli.zig");
const Core = @import("../core/core.zig");
const Store = Core.Store;
const Tmux = Core.Tmux;
const fatalTmux = @import("cmd_exec.zig").fatalTmux;

const usage =
    \\usage: terminus session <verb> [...]
    \\
    \\  session new <server> <name>       create (or reattach) a remote tmux session
    \\  session ls  <server> [--json]     list live remote sessions
    \\  session rm  <server> <name>       kill remote session + local metadata/memories
    \\
;

pub fn run(ctx: *Cli.Ctx, raw_args: []const []const u8) !void {
    if (raw_args.len == 0) fatal("{s}", .{usage});
    const verb = raw_args[0];
    const parsed = Cli.parseArgs(ctx, raw_args[1..]);
    if (parsed.boolean("json")) ctx.out.format = .json;

    const server_name = parsed.positional(0) orelse fatal("{s}", .{usage});
    var store = try Cli.openStore(ctx, &parsed);
    defer store.close();
    const resolved = Cli.resolveServer(ctx, &store, server_name);

    var conn = Cli.connect(ctx, &parsed, resolved.server, resolved.auth);
    defer conn.deinit();
    const executor = conn.executor();

    if (std.mem.eql(u8, verb, "new")) {
        const name = parsed.positional(1) orelse fatal("{s}", .{usage});
        validateName(name);
        Tmux.ensure(executor, ctx.arena, name) catch |err| fatalTmux(err, executor, name);
        _ = Store.sessions.ensure(&store, resolved.server.id, name, ctx.now) catch |err|
            Cli.storeFatal(&store, err);
        // Surface existing server-scope memories so an agent knows to read
        // them before starting work.
        const mems = Store.memories.list(&store, ctx.arena, .{ .server_id = resolved.server.id }, .{}) catch |err|
            Cli.storeFatal(&store, err);
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{
                .ok = true,
                .action = "created",
                .session = name,
                .server = server_name,
                .serverMemories = mems.len,
            }),
            .human => {
                try ctx.out.print("session '{s}:{s}' is ready\n", .{ server_name, name });
                if (mems.len > 0)
                    try ctx.out.print("hint: {d} server memories exist; read them with 'terminus memory ls {s}:{s}'\n", .{ mems.len, server_name, name });
            },
        }
    } else if (std.mem.eql(u8, verb, "ls")) {
        const remote = Tmux.list(executor, ctx.arena) catch |err| fatalTmux(err, executor, "");
        const local = Store.sessions.list(&store, ctx.arena, resolved.server.id) catch |err|
            Cli.storeFatal(&store, err);
        const merged = try merge(ctx.arena, remote, local);
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .server = server_name, .sessions = merged }),
            .human => {
                if (merged.len == 0) return ctx.out.print("no sessions on '{s}'\n", .{server_name});
                for (merged) |s| {
                    try ctx.out.print("{s}:{s}  alive={s}  cursor={d}\n", .{
                        server_name, s.name, if (s.alive) "yes" else "no", s.cursor,
                    });
                }
            },
        }
    } else if (std.mem.eql(u8, verb, "rm")) {
        const name = parsed.positional(1) orelse fatal("{s}", .{usage});
        Tmux.kill(executor, ctx.arena, name) catch |err| fatalTmux(err, executor, name);
        _ = Store.sessions.remove(&store, resolved.server.id, name) catch |err|
            Cli.storeFatal(&store, err);
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .action = "removed", .session = name }),
            .human => try ctx.out.print("removed session '{s}:{s}'\n", .{ server_name, name }),
        }
    } else {
        fatal("unknown verb 'session {s}'\n{s}", .{ verb, usage });
    }
}

const MergedSession = struct {
    name: []const u8,
    alive: bool,
    cursor: i64,
    note: ?[]const u8,
};

/// Remote list ∪ local rows: a session may be alive remotely without local
/// metadata (created outside Terminus) or vice versa (server rebooted).
fn merge(
    arena: std.mem.Allocator,
    remote: []const Tmux.RemoteSession,
    local: []const Store.sessions.Session,
) ![]MergedSession {
    var out: std.ArrayList(MergedSession) = .empty;
    for (local) |l| {
        var alive = false;
        for (remote) |r| {
            if (std.mem.eql(u8, r.name, l.name)) {
                alive = true;
                break;
            }
        }
        try out.append(arena, .{ .name = l.name, .alive = alive, .cursor = l.cursor, .note = l.note });
    }
    for (remote) |r| {
        var known = false;
        for (local) |l| {
            if (std.mem.eql(u8, r.name, l.name)) {
                known = true;
                break;
            }
        }
        if (!known) try out.append(arena, .{ .name = r.name, .alive = true, .cursor = 0, .note = null });
    }
    return out.toOwnedSlice(arena);
}

/// Session names flow into tmux -t arguments and log file paths; keep them
/// to a safe charset instead of trying to quote for both contexts.
fn validateName(name: []const u8) void {
    if (name.len == 0 or name.len > 64) fatal("session name must be 1-64 chars", .{});
    for (name) |ch| {
        switch (ch) {
            'a'...'z', 'A'...'Z', '0'...'9', '-', '_', '.' => {},
            else => fatal("session name may only contain [a-zA-Z0-9._-]", .{}),
        }
    }
}
