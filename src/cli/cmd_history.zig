//! `terminus history <server>` — the local audit trail: what ran, where,
//! with what exit code and transport, when.
const std = @import("std");
const fatal = Cli.fail;
const Cli = @import("cli.zig");
const Core = @import("../core/core.zig");
const Store = Core.Store;

const usage =
    \\usage: terminus history <server> [--limit N] [--json]
    \\
;

pub fn run(ctx: *Cli.Ctx, raw_args: []const []const u8) !void {
    const parsed = Cli.parseArgs(ctx, raw_args);
    if (parsed.boolean("json")) ctx.out.format = .json;

    const server_name = parsed.positional(0) orelse fatal("{s}", .{usage});
    const limit: i64 = if (parsed.flag("limit")) |l|
        std.fmt.parseInt(i64, l, 10) catch fatal("invalid --limit '{s}'", .{l})
    else
        50;

    var store = try Cli.openStore(ctx, &parsed);
    defer store.close();
    const server = (Store.servers.getByName(&store, ctx.arena, server_name) catch |err|
        Cli.storeFatal(&store, err)) orelse fatal("unknown server '{s}'", .{server_name});

    const entries = Store.history.list(&store, ctx.arena, server.id, limit) catch |err|
        Cli.storeFatal(&store, err);

    switch (ctx.out.format) {
        .json => try ctx.out.json(.{ .ok = true, .server = server_name, .history = entries }),
        .human => {
            if (entries.len == 0) return ctx.out.print("no history for '{s}'\n", .{server_name});
            for (entries) |e| {
                try ctx.out.print("[{d}] {s}  exit={?d}  via={s}  {s}\n", .{
                    e.created_at, e.kind, e.exit_code, e.transport orelse "?", e.detail,
                });
            }
        },
    }
}
