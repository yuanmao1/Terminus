//! `terminus workspace` — per-server default working directory.
//!
//! The workspace is applied automatically by `exec <server>` (plain,
//! non-session) and `run` — commands execute in it without fragile
//! `cd X && ...` prefixes. Session targets keep their own live cwd.
const std = @import("std");
const fatal = Cli.fail;
const Cli = @import("cli.zig");
const Core = @import("../core/core.zig");
const Store = Core.Store;

const usage =
    \\usage: terminus workspace <verb> <server> [...]
    \\
    \\  workspace set   <server> <remote-dir>
    \\  workspace show  <server> [--json]
    \\  workspace clear <server>
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
        const dir = parsed.positional(1) orelse fatal("{s}", .{usage});
        if (dir.len == 0 or std.mem.indexOfAny(u8, dir, "'\"\n") != null)
            fatal("workspace path must not contain quotes or newlines", .{});
        Store.servers.setCwd(&store, server.id, dir, ctx.now) catch |err| Cli.storeFatal(&store, err);
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .server = server_name, .workspace = dir }),
            .human => try ctx.out.print("workspace for '{s}' set to {s}\n", .{ server_name, dir }),
        }
    } else if (std.mem.eql(u8, verb, "show")) {
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .server = server_name, .workspace = server.cwd }),
            .human => try ctx.out.print("{s}\n", .{server.cwd orelse "(not set)"}),
        }
    } else if (std.mem.eql(u8, verb, "clear")) {
        Store.servers.setCwd(&store, server.id, null, ctx.now) catch |err| Cli.storeFatal(&store, err);
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .server = server_name, .workspace = null }),
            .human => try ctx.out.print("workspace for '{s}' cleared\n", .{server_name}),
        }
    } else {
        fatal("unknown verb 'workspace {s}'\n{s}", .{ verb, usage });
    }
}
