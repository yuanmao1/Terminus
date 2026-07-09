//! `terminus memory add/ls/show/rm` — persistent per-server / per-session
//! memory for agents.
//!
//! Target syntax: `<server>` for server scope, `<server>:<session>` for
//! session scope. Session-scope reads merge server-scope entries.
const std = @import("std");
const fatal = Cli.fail;
const Cli = @import("cli.zig");
const Core = @import("../core/core.zig");
const Store = Core.Store;

const usage =
    \\usage: terminus memory <verb> <server>[:<session>] [...]
    \\
    \\  memory add    <target> [--key K] [--tags t1,t2] [--append] <content input>
    \\  memory ls     <target> [--tags t] [--json]
    \\  memory show   <target> --key K | --id N [--json]
    \\  memory rm     <target> --key K | --id N
    \\  memory export <server>            all memories+facts as JSON (backup/migration)
    \\
    \\content input, most quote-proof first (PowerShell mangles ';' '*' in bare args):
    \\  --stdin                    read from standard input
    \\  --content-file <path>      read from a local file
    \\  --content "<text>"         a single flag value
    \\  -- <text...>               everything after --
    \\
    \\add semantics: --key upserts (same key replaces content; shown as
    \\"updated" with the previous value). --append appends a line instead.
    \\
;

pub fn run(ctx: *Cli.Ctx, raw_args: []const []const u8) !void {
    if (raw_args.len == 0) fatal("{s}", .{usage});
    const verb = raw_args[0];
    const parsed = Cli.parseArgs(ctx, raw_args[1..]);
    if (parsed.boolean("json")) ctx.out.format = .json;

    var store = try Cli.openStore(ctx, &parsed);
    defer store.close();

    const target = Cli.Target.parse(parsed.positional(0) orelse fatal("{s}", .{usage}));
    const server = (Store.servers.getByName(&store, ctx.arena, target.server) catch |err|
        Cli.storeFatal(&store, err)) orelse fatal("unknown server '{s}'", .{target.server});

    // Export ignores session targets: it dumps the server's full knowledge
    // (all memories incl. session-scoped, plus facts) as one JSON document.
    if (std.mem.eql(u8, verb, "export")) {
        ctx.out.format = .json;
        const all_memories = Store.memories.exportAll(&store, ctx.arena, server.id) catch |err|
            Cli.storeFatal(&store, err);
        const all_facts = Store.facts.list(&store, ctx.arena, server.id) catch |err|
            Cli.storeFatal(&store, err);
        try ctx.out.json(.{
            .ok = true,
            .server = server.name,
            .host = server.host,
            .exportedAt = ctx.now,
            .memories = all_memories,
            .facts = all_facts,
        });
        return;
    }

    // `add` creates the session metadata row on demand; read/delete verbs
    // on an unknown session fail loudly instead of silently narrowing to
    // server scope.
    var scope: Store.memories.Scope = .{ .server_id = server.id };
    if (target.session) |session_name| {
        if (std.mem.eql(u8, verb, "add")) {
            scope.session_id = Store.sessions.ensure(&store, server.id, session_name, ctx.now) catch |err|
                Cli.storeFatal(&store, err);
        } else {
            scope.session_id = (Store.sessions.idByName(&store, server.id, session_name) catch |err|
                Cli.storeFatal(&store, err)) orelse
                fatal("unknown session '{s}'; for server-scope memories use 'terminus memory {s} {s}'", .{
                    targetName(parsed), verb, target.server,
                });
        }
    }

    if (std.mem.eql(u8, verb, "add")) {
        var content = (try Cli.trailingContent(ctx, &parsed, "content-file", 1)) orelse
            fatal("no memory content given (use --stdin, --content-file, --content, or '-- <content>')\n{s}", .{usage});

        // Transparency: report exactly what an existing key held before this
        // write, and support append instead of replace.
        var previous: ?[]const u8 = null;
        if (parsed.flag("key")) |key| {
            if (Store.memories.find(&store, ctx.arena, scope, .{ .key = key }) catch |err|
                Cli.storeFatal(&store, err)) |existing|
            {
                // find() falls back to server scope for session targets;
                // only treat it as "existing" when scopes actually match.
                const same_scope = (scope.session_id == null) == (existing.scope == .server);
                if (same_scope) {
                    previous = existing.content;
                    if (parsed.boolean("append"))
                        content = try std.fmt.allocPrint(ctx.arena, "{s}\n{s}", .{ existing.content, content });
                }
            }
        }

        const result = Store.memories.add(&store, scope, .{
            .key = parsed.flag("key"),
            .content = content,
            .tags = parsed.flag("tags"),
            .now = ctx.now,
        }) catch |err| Cli.storeFatal(&store, err);
        const action: []const u8 = if (result == .inserted)
            "inserted"
        else if (parsed.boolean("append"))
            "appended"
        else
            "replaced";
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{
                .ok = true,
                .action = action,
                .target = targetName(parsed),
                .key = parsed.flag("key"),
                .content = content,
                .previous = previous,
            }),
            .human => try ctx.out.print("{s} memory for '{s}'{s}\n", .{
                action,             targetName(parsed),
                if (previous != null and !parsed.boolean("append")) " (previous content replaced)" else "",
            }),
        }
    } else if (std.mem.eql(u8, verb, "ls")) {
        const list = Store.memories.list(&store, ctx.arena, scope, .{
            .tag = parsed.flag("tags"),
        }) catch |err| Cli.storeFatal(&store, err);
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .target = targetName(parsed), .memories = list }),
            .human => {
                if (list.len == 0) return ctx.out.print("no memories for '{s}'\n", .{targetName(parsed)});
                for (list) |m| {
                    try ctx.out.print("[{d}] ({t}) {s}: {s}{s}{s}\n", .{
                        m.id,               m.scope,           m.key orelse "-",
                        m.content,          if (m.tags != null) "  #" else "", m.tags orelse "",
                    });
                }
            },
        }
    } else if (std.mem.eql(u8, verb, "show")) {
        const memory = (Store.memories.find(&store, ctx.arena, scope, selector(&parsed)) catch |err|
            Cli.storeFatal(&store, err)) orelse fatal("no matching memory in '{s}'", .{targetName(parsed)});
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .target = targetName(parsed), .memory = memory }),
            .human => try ctx.out.print("[{d}] ({t}) {s}: {s}\n", .{
                memory.id, memory.scope, memory.key orelse "-", memory.content,
            }),
        }
    } else if (std.mem.eql(u8, verb, "rm")) {
        const removed = Store.memories.remove(&store, scope, selector(&parsed)) catch |err|
            Cli.storeFatal(&store, err);
        if (!removed) fatal("no matching memory in '{s}'", .{targetName(parsed)});
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .action = "removed", .target = targetName(parsed) }),
            .human => try ctx.out.print("removed memory from '{s}'\n", .{targetName(parsed)}),
        }
    } else {
        fatal("unknown verb 'memory {s}'\n{s}", .{ verb, usage });
    }
}

fn targetName(parsed: Cli.Args.Parsed) []const u8 {
    return parsed.positionals[0];
}

fn selector(parsed: *const Cli.Args.Parsed) Store.memories.Selector {
    if (parsed.flag("key")) |key| return .{ .key = key };
    if (parsed.flag("id")) |id_text| {
        const id = std.fmt.parseInt(i64, id_text, 10) catch fatal("invalid --id '{s}'", .{id_text});
        return .{ .id = id };
    }
    fatal("select a memory with --key K or --id N", .{});
}
