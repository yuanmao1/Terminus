//! `terminus fact` — machine-readable key/value facts per server.
//!
//! Facts are for orchestration (stable values an agent plugs into
//! commands: app_root, package_manager, service names). `memory` remains
//! the place for natural-language experience. Both are local sqlite.
const std = @import("std");
const fatal = Cli.fail;
const Cli = @import("cli.zig");
const Core = @import("../core/core.zig");
const Store = Core.Store;

const usage =
    \\usage: terminus fact <verb> <server> [...]
    \\
    \\  fact set <server> <key> <value>
    \\  fact get <server> <key> [--json]
    \\  fact ls  <server> [--json]
    \\  fact rm  <server> <key>
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
    const server = (Store.servers.getByName(&store, ctx.arena, server_name) catch |err|
        Cli.storeFatal(&store, err)) orelse fatal("unknown server '{s}'", .{server_name});

    if (std.mem.eql(u8, verb, "set")) {
        const key = parsed.positional(1) orelse fatal("{s}", .{usage});
        const value = parsed.positional(2) orelse fatal("{s}", .{usage});
        Store.facts.set(&store, server.id, key, value, ctx.now) catch |err| Cli.storeFatal(&store, err);
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .server = server_name, .key = key, .value = value }),
            .human => try ctx.out.print("{s}.{s} = {s}\n", .{ server_name, key, value }),
        }
    } else if (std.mem.eql(u8, verb, "get")) {
        const key = parsed.positional(1) orelse fatal("{s}", .{usage});
        const value = (Store.facts.get(&store, ctx.arena, server.id, key) catch |err|
            Cli.storeFatal(&store, err)) orelse fatal("no fact '{s}' on '{s}'", .{ key, server_name });
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .server = server_name, .key = key, .value = value }),
            .human => try ctx.out.print("{s}\n", .{value}),
        }
    } else if (std.mem.eql(u8, verb, "ls")) {
        const list = Store.facts.list(&store, ctx.arena, server.id) catch |err| Cli.storeFatal(&store, err);
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .server = server_name, .facts = list }),
            .human => {
                if (list.len == 0) return ctx.out.print("no facts for '{s}'\n", .{server_name});
                for (list) |f| try ctx.out.print("{s} = {s}\n", .{ f.key, f.value });
            },
        }
    } else if (std.mem.eql(u8, verb, "rm")) {
        const key = parsed.positional(1) orelse fatal("{s}", .{usage});
        const removed = Store.facts.remove(&store, server.id, key) catch |err| Cli.storeFatal(&store, err);
        if (!removed) fatal("no fact '{s}' on '{s}'", .{ key, server_name });
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .action = "removed", .key = key }),
            .human => try ctx.out.print("removed fact '{s}'\n", .{key}),
        }
    } else {
        fatal("unknown verb 'fact {s}'\n{s}", .{ verb, usage });
    }
}
