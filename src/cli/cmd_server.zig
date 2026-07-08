//! `terminus server add/ls/show/rm` — server resource management.
const std = @import("std");
const fatal = Cli.fail;
const Cli = @import("cli.zig");
const Core = @import("../core/core.zig");
const Store = Core.Store;

const usage =
    \\usage: terminus server <verb> [...]
    \\
    \\  server add <name> --host <host> --user <user> [--port 22] [--key <keyname>] [--note ...]
    \\  server ls [--json]
    \\  server show <name> [--json]
    \\  server rm <name>
    \\
;

pub fn run(ctx: *Cli.Ctx, raw_args: []const []const u8) !void {
    if (raw_args.len == 0) fatal("{s}", .{usage});
    const verb = raw_args[0];
    const parsed = Cli.parseArgs(ctx, raw_args[1..]);
    if (parsed.boolean("json")) ctx.out.format = .json;

    var store = try Cli.openStore(ctx, &parsed);
    defer store.close();

    if (std.mem.eql(u8, verb, "add")) {
        const name = parsed.positional(0) orelse fatal("{s}", .{usage});
        const host = parsed.flag("host") orelse fatal("--host is required", .{});
        const user = parsed.flag("user") orelse fatal("--user is required", .{});
        const port: u16 = if (parsed.flag("port")) |p|
            std.fmt.parseInt(u16, p, 10) catch fatal("invalid --port '{s}'", .{p})
        else
            22;
        _ = Store.servers.add(&store, .{
            .name = name,
            .host = host,
            .port = port,
            .username = user,
            .key = parsed.flag("key"),
            .note = parsed.flag("note"),
            .now = ctx.now,
        }) catch |err| switch (err) {
            error.NameTaken => fatal("server '{s}' already exists", .{name}),
            error.KeyNotFound => fatal("key '{s}' not found; add it with 'terminus key add'", .{parsed.flag("key").?}),
            else => Cli.storeFatal(&store, err),
        };
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .action = "added", .server = name }),
            .human => try ctx.out.print("added server '{s}' ({s}@{s}:{d})\n", .{ name, user, host, port }),
        }
    } else if (std.mem.eql(u8, verb, "ls")) {
        const list = Store.servers.list(&store, ctx.arena) catch |err| Cli.storeFatal(&store, err);
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .servers = list }),
            .human => {
                if (list.len == 0) return ctx.out.print("no servers. add one with 'terminus server add'\n", .{});
                for (list) |s| {
                    try ctx.out.print("{s}  {s}@{s}:{d}  key={s}  note={s}\n", .{
                        s.name, s.username, s.host, s.port, s.key orelse "-", s.note orelse "-",
                    });
                }
            },
        }
    } else if (std.mem.eql(u8, verb, "show")) {
        const name = parsed.positional(0) orelse fatal("{s}", .{usage});
        const server = (Store.servers.getByName(&store, ctx.arena, name) catch |err|
            Cli.storeFatal(&store, err)) orelse fatal("unknown server '{s}'", .{name});
        const mems = Store.memories.list(&store, ctx.arena, .{ .server_id = server.id }, .{}) catch |err|
            Cli.storeFatal(&store, err);
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .server = server, .memories = mems }),
            .human => {
                try ctx.out.print(
                    "name:  {s}\nhost:  {s}:{d}\nuser:  {s}\nkey:   {s}\nnote:  {s}\n",
                    .{ server.name, server.host, server.port, server.username, server.key orelse "-", server.note orelse "-" },
                );
                try ctx.out.print("memories: {d}\n", .{mems.len});
                for (mems) |m| {
                    try ctx.out.print("  [{d}] {s}: {s}\n", .{ m.id, m.key orelse "-", m.content });
                }
            },
        }
    } else if (std.mem.eql(u8, verb, "rm")) {
        const name = parsed.positional(0) orelse fatal("{s}", .{usage});
        const removed = Store.servers.remove(&store, name) catch |err| Cli.storeFatal(&store, err);
        if (!removed) fatal("unknown server '{s}'", .{name});
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .action = "removed", .server = name }),
            .human => try ctx.out.print("removed server '{s}'\n", .{name}),
        }
    } else {
        fatal("unknown verb 'server {s}'\n{s}", .{ verb, usage });
    }
}
