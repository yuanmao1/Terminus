//! `terminus server add/ls/show/rm` — server resource management.
const std = @import("std");
const fatal = Cli.fail;
const Cli = @import("cli.zig");
const Core = @import("../core/core.zig");
const Store = Core.Store;

const usage =
    \\usage: terminus server <verb> [...]
    \\
    \\  server add    <name> --host <host> --user <user> [--port 22] [--key <keyname>] [--note ...]
    \\  server ls     [--json]
    \\  server show   <name> [--json]
    \\  server ping   <name> [--json]     connect+auth check, ~1 round trip
    \\  server rename <old-name> <new-name>
    \\  server set    <name> [--host H] [--port P] [--user U] [--key K] [--note ...]
    \\  server rm     <name> [--force]
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
    } else if (std.mem.eql(u8, verb, "ping")) {
        const name = parsed.positional(0) orelse fatal("{s}", .{usage});
        const resolved = Cli.resolveServer(ctx, &store, name);
        const started = std.Io.Timestamp.now(ctx.io, .awake);
        var conn = Cli.connect(ctx, &parsed, resolved.server, resolved.auth);
        defer conn.deinit();
        const result = conn.executor().exec(ctx.arena, "true") catch |err|
            fatal("reachable but exec failed: {s} ({s})", .{ conn.executor().errorMessage(), @errorName(err) });
        const ms: i64 = @intCast(@divTrunc(
            started.durationTo(std.Io.Timestamp.now(ctx.io, .awake)).nanoseconds,
            std.time.ns_per_ms,
        ));
        _ = result;
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{
                .ok = true,
                .server = name,
                .reachable = true,
                .latencyMs = ms,
                .transport = conn.transport,
                .daemonError = conn.daemon_error,
            }),
            .human => try ctx.out.print("'{s}' is reachable ({d} ms via {s})\n", .{ name, ms, conn.transport }),
        }
    } else if (std.mem.eql(u8, verb, "rename")) {
        const old_name = parsed.positional(0) orelse fatal("{s}", .{usage});
        const new_name = parsed.positional(1) orelse fatal("{s}", .{usage});
        const server = (Store.servers.getByName(&store, ctx.arena, old_name) catch |err|
            Cli.storeFatal(&store, err)) orelse fatal("unknown server '{s}'", .{old_name});
        Store.servers.rename(&store, server.id, new_name, ctx.now) catch |err| switch (err) {
            error.NameTaken => fatal("server '{s}' already exists", .{new_name}),
            else => Cli.storeFatal(&store, err),
        };
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .action = "renamed", .from = old_name, .to = new_name }),
            .human => try ctx.out.print("renamed '{s}' -> '{s}' (memories/facts/jobs/history follow)\n", .{ old_name, new_name }),
        }
    } else if (std.mem.eql(u8, verb, "set")) {
        const name = parsed.positional(0) orelse fatal("{s}", .{usage});
        const server = (Store.servers.getByName(&store, ctx.arena, name) catch |err|
            Cli.storeFatal(&store, err)) orelse fatal("unknown server '{s}'", .{name});
        var changes: Store.servers.Update = .{
            .host = parsed.flag("host"),
            .username = parsed.flag("user"),
            .note = parsed.flag("note"),
        };
        if (parsed.flag("port")) |p|
            changes.port = std.fmt.parseInt(u16, p, 10) catch fatal("invalid --port '{s}'", .{p});
        if (parsed.flag("key")) |key_name| {
            changes.key_id = (Store.keys.idByName(&store, key_name) catch |err|
                Cli.storeFatal(&store, err)) orelse fatal("key '{s}' not found", .{key_name});
        }
        if (changes.host == null and changes.port == null and changes.username == null and
            changes.key_id == null and changes.note == null)
            fatal("nothing to change; pass at least one of --host/--port/--user/--key/--note", .{});
        Store.servers.update(&store, server.id, changes, ctx.now) catch |err| Cli.storeFatal(&store, err);
        const updated = (Store.servers.getByName(&store, ctx.arena, name) catch |err|
            Cli.storeFatal(&store, err)).?;
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .action = "updated", .server = updated }),
            .human => try ctx.out.print("updated '{s}': {s}@{s}:{d} key={s}\n", .{
                name, updated.username, updated.host, updated.port, updated.key orelse "-",
            }),
        }
    } else if (std.mem.eql(u8, verb, "rm")) {
        const name = parsed.positional(0) orelse fatal("{s}", .{usage});
        const server = (Store.servers.getByName(&store, ctx.arena, name) catch |err|
            Cli.storeFatal(&store, err)) orelse fatal("unknown server '{s}'", .{name});
        // Deleting a server cascades to everything learned about it; make
        // the blast radius explicit and require --force when it's nonzero.
        const counts = Store.servers.cascadeCounts(&store, server.id) catch |err|
            Cli.storeFatal(&store, err);
        const total = counts.sessions + counts.memories + counts.jobs + counts.facts + counts.history;
        if (total > 0 and !parsed.boolean("force")) {
            fatal(
                "removing '{s}' also deletes {d} memories, {d} facts, {d} sessions, {d} jobs, {d} history entries; re-run with --force",
                .{ name, counts.memories, counts.facts, counts.sessions, counts.jobs, counts.history },
            );
        }
        _ = Store.servers.remove(&store, name) catch |err| Cli.storeFatal(&store, err);
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .action = "removed", .server = name }),
            .human => try ctx.out.print("removed server '{s}'\n", .{name}),
        }
    } else {
        fatal("unknown verb 'server {s}'\n{s}", .{ verb, usage });
    }
}
