//! `terminus export` / `terminus import` — knowledge portability between
//! machines.
//!
//! Export writes one JSON document with servers, keys (opt-in), and per-
//! server memories + facts. Import is agent-mergeable, not a blind
//! overwrite — three modes:
//!
//!   import backup.json --dry-run          # structured merge plan, no writes
//!   import backup.json                    # apply only conflict-free items
//!   import backup.json --strategy theirs  # conflicts: incoming wins
//!   import backup.json --strategy ours    # conflicts: local wins (= skip)
//!   import backup.json --only prod,web1   # limit to specific servers
//!
//! The dry-run plan labels every item `new` / `identical` / `conflict`
//! (with both values shown), so an agent can decide per-server what to
//! take, or resolve hand-picked conflicts afterwards with `memory add`.
const std = @import("std");
const fatal = Cli.fail;
const Cli = @import("cli.zig");
const Core = @import("../core/core.zig");
const Store = Core.Store;

const export_usage =
    \\usage: terminus export [--out <path>] [--include-keys] [--json]
    \\
    \\Exports all servers with their memories and facts as one JSON document
    \\(stdout by default). --include-keys embeds PRIVATE KEY MATERIAL AND
    \\PASSPHRASES IN PLAINTEXT — only use it for transfers you control.
    \\
;

const import_usage =
    \\usage: terminus import <path> [--dry-run] [--strategy ours|theirs]
    \\                       [--only s1,s2] [--json]
    \\
    \\Merges an export file into the local store. Default applies only
    \\conflict-free additions; --strategy decides conflicts (ours = keep
    \\local, theirs = take incoming). --dry-run prints the merge plan
    \\(new/identical/conflict per item) without writing anything.
    \\
;

// ---- export document shape (versioned) ----

const doc_version = 1;

const KeyDoc = struct {
    name: []const u8,
    kind: []const u8,
    private: ?[]const u8 = null,
    public: ?[]const u8 = null,
    passphrase: ?[]const u8 = null,
};

const MemoryDoc = struct {
    session: ?[]const u8 = null,
    key: ?[]const u8 = null,
    content: []const u8,
    tags: ?[]const u8 = null,
    updated_at: i64 = 0,
};

const FactDoc = struct {
    key: []const u8,
    value: []const u8,
    updated_at: i64 = 0,
};

const ServerDoc = struct {
    name: []const u8,
    host: []const u8,
    port: u16 = 22,
    username: []const u8,
    key: ?[]const u8 = null,
    note: ?[]const u8 = null,
    cwd: ?[]const u8 = null,
    memories: []MemoryDoc = &.{},
    facts: []FactDoc = &.{},
};

const Document = struct {
    v: u32,
    exportedAt: i64,
    servers: []ServerDoc,
    keys: []KeyDoc = &.{},
};

pub fn exportCmd(ctx: *Cli.Ctx, raw_args: []const []const u8) !void {
    const parsed = Cli.parseArgs(ctx, raw_args);
    var store = try Cli.openStore(ctx, &parsed);
    defer store.close();

    const servers = Store.servers.list(&store, ctx.arena) catch |err| Cli.storeFatal(&store, err);
    var server_docs: std.ArrayList(ServerDoc) = .empty;
    var key_names: std.StringArrayHashMapUnmanaged(void) = .empty;

    for (servers) |server| {
        const memories = Store.memories.exportAll(&store, ctx.arena, server.id) catch |err|
            Cli.storeFatal(&store, err);
        var memory_docs: std.ArrayList(MemoryDoc) = .empty;
        for (memories) |m| {
            try memory_docs.append(ctx.arena, .{
                .session = m.session,
                .key = m.key,
                .content = m.content,
                .tags = m.tags,
                .updated_at = m.updated_at,
            });
        }
        const facts = Store.facts.list(&store, ctx.arena, server.id) catch |err|
            Cli.storeFatal(&store, err);
        var fact_docs: std.ArrayList(FactDoc) = .empty;
        for (facts) |f| {
            try fact_docs.append(ctx.arena, .{ .key = f.key, .value = f.value, .updated_at = f.updated_at });
        }
        if (server.key) |key_name| try key_names.put(ctx.arena, key_name, {});
        try server_docs.append(ctx.arena, .{
            .name = server.name,
            .host = server.host,
            .port = server.port,
            .username = server.username,
            .key = server.key,
            .note = server.note,
            .cwd = server.cwd,
            .memories = try memory_docs.toOwnedSlice(ctx.arena),
            .facts = try fact_docs.toOwnedSlice(ctx.arena),
        });
    }

    var key_docs: std.ArrayList(KeyDoc) = .empty;
    if (parsed.boolean("include-keys")) {
        for (key_names.keys()) |key_name| {
            const material = (Store.keys.material(&store, ctx.arena, key_name) catch |err|
                Cli.storeFatal(&store, err)) orelse continue;
            try key_docs.append(ctx.arena, .{
                .name = key_name,
                .kind = material.kind,
                .private = material.private,
                .public = material.public,
                .passphrase = material.passphrase,
            });
        }
    }

    const document: Document = .{
        .v = doc_version,
        .exportedAt = ctx.now,
        .servers = server_docs.items,
        .keys = key_docs.items,
    };

    const rendered = std.json.Stringify.valueAlloc(ctx.arena, document, .{ .whitespace = .indent_2 }) catch
        fatal("out of memory", .{});
    if (parsed.flag("out")) |path| {
        std.Io.Dir.cwd().writeFile(ctx.io, .{ .sub_path = path, .data = rendered }) catch |err|
            fatal("cannot write {s}: {s}", .{ path, @errorName(err) });
        try ctx.out.print("exported {d} servers to {s}{s}\n", .{
            document.servers.len, path,
            if (parsed.boolean("include-keys")) " (INCLUDES PLAINTEXT KEYS — handle with care)" else "",
        });
    } else {
        try ctx.out.print("{s}\n", .{rendered});
    }
}

// ---- import ----

const ItemState = enum { new, identical, conflict };

const PlanItem = struct {
    server: []const u8,
    kind: []const u8, // server | memory | fact | key
    id: []const u8, // memory key / fact key / "" for the server row itself
    state: ItemState,
    local: ?[]const u8 = null, // present on conflict
    incoming: ?[]const u8 = null,
};

pub fn importCmd(ctx: *Cli.Ctx, raw_args: []const []const u8) !void {
    const parsed = Cli.parseArgs(ctx, raw_args);
    if (parsed.boolean("json")) ctx.out.format = .json;

    const path = parsed.positional(0) orelse fatal("{s}", .{import_usage});
    const strategy = parsed.flag("strategy") orelse "additive";
    if (!std.mem.eql(u8, strategy, "additive") and !std.mem.eql(u8, strategy, "ours") and
        !std.mem.eql(u8, strategy, "theirs"))
        fatal("invalid --strategy '{s}' (ours|theirs)", .{strategy});
    const dry_run = parsed.boolean("dry-run");
    const only = parseOnly(ctx, parsed.flag("only"));

    const raw = std.Io.Dir.cwd().readFileAlloc(ctx.io, path, ctx.arena, .limited(64 << 20)) catch |err|
        fatal("cannot read {s}: {s}", .{ path, @errorName(err) });
    const document = std.json.parseFromSliceLeaky(Document, ctx.arena, raw, .{
        .ignore_unknown_fields = true,
    }) catch fatal("{s} is not a terminus export file", .{path});
    if (document.v != doc_version)
        fatal("export version {d} not supported (this binary reads v{d})", .{ document.v, doc_version });

    var store = try Cli.openStore(ctx, &parsed);
    defer store.close();

    var plan: std.ArrayList(PlanItem) = .empty;
    var applied: usize = 0;
    var skipped_conflicts: usize = 0;

    // Keys first: imported servers may reference them.
    for (document.keys) |key_doc| {
        if (Store.keys.idByName(&store, key_doc.name) catch |err| Cli.storeFatal(&store, err)) |_| {
            // Never overwrite key material; flag mismatched names only.
            try plan.append(ctx.arena, .{ .server = "", .kind = "key", .id = key_doc.name, .state = .identical });
            continue;
        }
        try plan.append(ctx.arena, .{ .server = "", .kind = "key", .id = key_doc.name, .state = .new });
        if (!dry_run) {
            _ = Store.keys.add(&store, .{
                .name = key_doc.name,
                .kind = key_doc.kind,
                .private = key_doc.private,
                .public = key_doc.public,
                .passphrase = key_doc.passphrase,
                .now = ctx.now,
            }) catch |err| Cli.storeFatal(&store, err);
            applied += 1;
        }
    }

    for (document.servers) |incoming| {
        if (only) |names| if (!contains(names, incoming.name)) continue;

        const existing = Store.servers.getByName(&store, ctx.arena, incoming.name) catch |err|
            Cli.storeFatal(&store, err);

        var server_id: i64 = undefined;
        if (existing) |local| {
            server_id = local.id;
            const same = std.mem.eql(u8, local.host, incoming.host) and
                local.port == incoming.port and
                std.mem.eql(u8, local.username, incoming.username);
            if (same) {
                try plan.append(ctx.arena, .{ .server = incoming.name, .kind = "server", .id = "", .state = .identical });
            } else {
                const take_theirs = std.mem.eql(u8, strategy, "theirs");
                try plan.append(ctx.arena, .{
                    .server = incoming.name,
                    .kind = "server",
                    .id = "",
                    .state = .conflict,
                    .local = try std.fmt.allocPrint(ctx.arena, "{s}@{s}:{d}", .{ local.username, local.host, local.port }),
                    .incoming = try std.fmt.allocPrint(ctx.arena, "{s}@{s}:{d}", .{ incoming.username, incoming.host, incoming.port }),
                });
                if (!dry_run and take_theirs) {
                    Store.servers.update(&store, local.id, .{
                        .host = incoming.host,
                        .port = incoming.port,
                        .username = incoming.username,
                    }, ctx.now) catch |err| Cli.storeFatal(&store, err);
                    applied += 1;
                } else if (!take_theirs) skipped_conflicts += 1;
            }
        } else {
            try plan.append(ctx.arena, .{ .server = incoming.name, .kind = "server", .id = "", .state = .new });
            if (!dry_run) {
                server_id = Store.servers.add(&store, .{
                    .name = incoming.name,
                    .host = incoming.host,
                    .port = incoming.port,
                    .username = incoming.username,
                    .key = resolveKey(&store, incoming.key),
                    .note = incoming.note,
                    .now = ctx.now,
                }) catch |err| switch (err) {
                    error.KeyNotFound => blk: {
                        // Key not present locally: import the server keyless.
                        break :blk Store.servers.add(&store, .{
                            .name = incoming.name,
                            .host = incoming.host,
                            .port = incoming.port,
                            .username = incoming.username,
                            .note = incoming.note,
                            .now = ctx.now,
                        }) catch |err2| Cli.storeFatal(&store, err2);
                    },
                    else => Cli.storeFatal(&store, err),
                };
                if (incoming.cwd) |cwd|
                    Store.servers.setCwd(&store, server_id, cwd, ctx.now) catch |err| Cli.storeFatal(&store, err);
                applied += 1;
            }
        }

        // Children. For a brand-new server every child is trivially new; on
        // a real (non-dry) run the row above exists, so write through it.
        const child_server_id: ?i64 = if (existing != null or !dry_run) server_id else null;
        for (incoming.memories) |m| {
            if (m.session != null) continue; // session-scope memories are working state; skip
            try planMemory(ctx, &store, &plan, child_server_id, incoming.name, m, strategy, dry_run, &applied, &skipped_conflicts);
        }
        for (incoming.facts) |f| {
            try planFact(ctx, &store, &plan, child_server_id, incoming.name, f, strategy, dry_run, &applied, &skipped_conflicts);
        }
    }

    const conflicts = count(plan.items, .conflict);
    switch (ctx.out.format) {
        .json => try ctx.out.json(.{
            .ok = true,
            .dryRun = dry_run,
            .strategy = strategy,
            .plan = plan.items,
            .summary = .{
                .new = count(plan.items, .new),
                .identical = count(plan.items, .identical),
                .conflicts = conflicts,
                .applied = applied,
                .skippedConflicts = skipped_conflicts,
            },
        }),
        .human => {
            for (plan.items) |item| {
                if (item.state == .identical) continue;
                try ctx.out.print("{t}  {s} {s}{s}{s}\n", .{
                    item.state, item.kind, item.server,
                    if (item.id.len > 0) ":" else "", item.id,
                });
                if (item.state == .conflict) {
                    try ctx.out.print("    local:    {s}\n    incoming: {s}\n", .{ item.local orelse "?", item.incoming orelse "?" });
                }
            }
            if (dry_run) {
                try ctx.out.print("dry-run: {d} new, {d} identical, {d} conflicts. Re-run without --dry-run to apply additions; use --strategy ours|theirs for conflicts.\n", .{
                    count(plan.items, .new), count(plan.items, .identical), conflicts,
                });
            } else {
                try ctx.out.print("applied {d} items; {d} conflicts {s}\n", .{
                    applied, conflicts,
                    if (std.mem.eql(u8, strategy, "theirs")) "taken from import" else "kept local (use --strategy theirs to override)",
                });
            }
        },
    }
}

fn planMemory(
    ctx: *Cli.Ctx,
    store: *Store,
    plan: *std.ArrayList(PlanItem),
    local_server_id: ?i64,
    server_name: []const u8,
    m: MemoryDoc,
    strategy: []const u8,
    dry_run: bool,
    applied: *usize,
    skipped: *usize,
) !void {
    const id = m.key orelse firstWords(m.content);
    if (local_server_id == null) {
        // Parent server is new: every child is new by definition.
        try plan.append(ctx.arena, .{ .server = server_name, .kind = "memory", .id = id, .state = .new });
        if (!dry_run) applied.* += 1; // actually written below via add on the created row
        return;
    }
    const server_id = local_server_id.?;
    const scope: Store.memories.Scope = .{ .server_id = server_id };

    var state: ItemState = .new;
    var local_content: ?[]const u8 = null;
    if (m.key) |key| {
        if (Store.memories.find(store, ctx.arena, scope, .{ .key = key }) catch |err|
            Cli.storeFatal(store, err)) |local|
        {
            if (std.mem.eql(u8, local.content, m.content)) {
                state = .identical;
            } else {
                state = .conflict;
                local_content = local.content;
            }
        }
    } else if (Store.memories.hasContent(store, scope, m.content) catch |err| Cli.storeFatal(store, err)) {
        state = .identical;
    }

    try plan.append(ctx.arena, .{
        .server = server_name,
        .kind = "memory",
        .id = id,
        .state = state,
        .local = local_content,
        .incoming = if (state == .conflict) m.content else null,
    });

    if (dry_run) return;
    switch (state) {
        .identical => {},
        .new => {
            _ = Store.memories.add(store, scope, .{
                .key = m.key,
                .content = m.content,
                .tags = m.tags,
                .now = ctx.now,
            }) catch |err| Cli.storeFatal(store, err);
            applied.* += 1;
        },
        .conflict => {
            if (std.mem.eql(u8, strategy, "theirs")) {
                _ = Store.memories.add(store, scope, .{
                    .key = m.key,
                    .content = m.content,
                    .tags = m.tags,
                    .now = ctx.now,
                }) catch |err| Cli.storeFatal(store, err);
                applied.* += 1;
            } else skipped.* += 1;
        },
    }
}

fn planFact(
    ctx: *Cli.Ctx,
    store: *Store,
    plan: *std.ArrayList(PlanItem),
    local_server_id: ?i64,
    server_name: []const u8,
    f: FactDoc,
    strategy: []const u8,
    dry_run: bool,
    applied: *usize,
    skipped: *usize,
) !void {
    if (local_server_id == null) {
        try plan.append(ctx.arena, .{ .server = server_name, .kind = "fact", .id = f.key, .state = .new });
        if (!dry_run) applied.* += 1;
        return;
    }
    const server_id = local_server_id.?;

    var state: ItemState = .new;
    var local_value: ?[]const u8 = null;
    if (Store.facts.get(store, ctx.arena, server_id, f.key) catch |err| Cli.storeFatal(store, err)) |value| {
        if (std.mem.eql(u8, value, f.value)) state = .identical else {
            state = .conflict;
            local_value = value;
        }
    }
    try plan.append(ctx.arena, .{
        .server = server_name,
        .kind = "fact",
        .id = f.key,
        .state = state,
        .local = local_value,
        .incoming = if (state == .conflict) f.value else null,
    });
    if (dry_run) return;
    switch (state) {
        .identical => {},
        .new => {
            Store.facts.set(store, server_id, f.key, f.value, ctx.now) catch |err| Cli.storeFatal(store, err);
            applied.* += 1;
        },
        .conflict => {
            if (std.mem.eql(u8, strategy, "theirs")) {
                Store.facts.set(store, server_id, f.key, f.value, ctx.now) catch |err| Cli.storeFatal(store, err);
                applied.* += 1;
            } else skipped.* += 1;
        },
    }
}

fn resolveKey(store: *Store, key_name: ?[]const u8) ?[]const u8 {
    const name = key_name orelse return null;
    const id = Store.keys.idByName(store, name) catch return null;
    return if (id != null) name else null;
}

fn parseOnly(ctx: *Cli.Ctx, flag: ?[]const u8) ?[]const []const u8 {
    const text = flag orelse return null;
    var out: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, text, ',');
    while (it.next()) |name| {
        const trimmed = std.mem.trim(u8, name, " \t");
        if (trimmed.len > 0) out.append(ctx.arena, trimmed) catch fatal("out of memory", .{});
    }
    return out.items;
}

fn contains(names: []const []const u8, name: []const u8) bool {
    for (names) |n| if (std.mem.eql(u8, n, name)) return true;
    return false;
}

fn count(items: []const PlanItem, state: ItemState) usize {
    var n: usize = 0;
    for (items) |item| {
        if (item.state == state) n += 1;
    }
    return n;
}

fn firstWords(content: []const u8) []const u8 {
    const max = @min(content.len, 30);
    const cut = std.mem.indexOfScalar(u8, content[0..max], '\n') orelse max;
    return content[0..cut];
}
