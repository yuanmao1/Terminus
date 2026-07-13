//! CRUD for the `memories` table — persistent per-server / per-session
//! knowledge for agents.
//!
//! Scope rules:
//! * `session_id IS NULL` → server-scope entry (long-lived facts).
//! * otherwise → session-scope entry, cascade-deleted with the session.
//! * Reading a session scope merges in server-scope entries; a session
//!   entry with the same key shadows the server one.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Store = @import("Store.zig");
const Db = @import("Db.zig");

pub const Scope = struct {
    server_id: i64,
    session_id: ?i64 = null,
};

pub const Memory = struct {
    id: i64,
    scope: enum { server, session },
    key: ?[]const u8,
    content: []const u8,
    tags: ?[]const u8,
    created_at: i64,
    updated_at: i64,
};

pub const AddOptions = struct {
    key: ?[]const u8 = null,
    content: []const u8,
    tags: ?[]const u8 = null,
    now: i64,
};

pub const AddResult = enum { inserted, updated };

/// Keyed entries upsert: adding an existing key in the same scope updates
/// its content/tags in place.
pub fn add(store: *Store, scope: Scope, opts: AddOptions) Db.Error!AddResult {
    if (opts.key) |key| {
        if (try idByKey(store, scope, key)) |id| {
            var stmt = try store.db.prepare(
                "UPDATE memories SET content = ?1, tags = ?2, updated_at = ?3 WHERE id = ?4",
            );
            defer stmt.deinit();
            try stmt.bindText(1, opts.content);
            try stmt.bindOptText(2, opts.tags);
            try stmt.bindInt(3, opts.now);
            try stmt.bindInt(4, id);
            _ = try stmt.step();
            return .updated;
        }
    }
    var stmt = try store.db.prepare(
        \\INSERT INTO memories (server_id, session_id, key, content, tags, created_at, updated_at)
        \\VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
    );
    defer stmt.deinit();
    try stmt.bindInt(1, scope.server_id);
    try stmt.bindOptInt(2, scope.session_id);
    try stmt.bindOptText(3, opts.key);
    try stmt.bindText(4, opts.content);
    try stmt.bindOptText(5, opts.tags);
    try stmt.bindInt(6, opts.now);
    _ = try stmt.step();
    return .inserted;
}

pub const ListOptions = struct {
    /// Only entries carrying this tag (comma-separated `tags` column).
    tag: ?[]const u8 = null,
};

/// Lightweight recall hint: the keys (or first words for keyless entries)
/// of a server's memories. Cheap enough to attach to every exec response
/// so agents notice there is knowledge to read before acting.
pub fn keys(store: *Store, arena: Allocator, server_id: i64) (Db.Error || Allocator.Error)![][]const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var stmt = try store.db.prepare(
        \\SELECT key, substr(content, 1, 40) FROM memories
        \\WHERE server_id = ?1 AND session_id IS NULL ORDER BY id
    );
    defer stmt.deinit();
    try stmt.bindInt(1, server_id);
    while (try stmt.step()) {
        if (stmt.columnOptText(0)) |key| {
            try out.append(arena, try arena.dupe(u8, key));
        } else {
            try out.append(arena, try std.fmt.allocPrint(arena, "(id? \"{s}...\")", .{stmt.columnText(1)}));
        }
    }
    return out.toOwnedSlice(arena);
}

/// Lists the scope's entries. For a session scope this merges server-scope
/// entries, with session keys shadowing server keys. Order: server entries
/// first, then session entries, each oldest-first.
pub fn list(store: *Store, arena: Allocator, scope: Scope, opts: ListOptions) (Db.Error || Allocator.Error)![]Memory {
    var stmt = try store.db.prepare(
        \\SELECT id, session_id, key, content, tags, created_at, updated_at
        \\FROM memories
        \\WHERE server_id = ?1 AND (session_id IS NULL OR session_id IS ?2)
        \\ORDER BY (session_id IS NULL) DESC, id
    );
    defer stmt.deinit();
    try stmt.bindInt(1, scope.server_id);
    try stmt.bindOptInt(2, scope.session_id);

    var out: std.ArrayList(Memory) = .empty;
    var shadowed: std.StringArrayHashMapUnmanaged(void) = .empty;
    if (scope.session_id != null) {
        // Collect session-scope keys first so shadowed server entries can
        // be skipped while streaming rows below.
        var keys_stmt = try store.db.prepare(
            "SELECT key FROM memories WHERE server_id = ?1 AND session_id IS ?2 AND key IS NOT NULL",
        );
        defer keys_stmt.deinit();
        try keys_stmt.bindInt(1, scope.server_id);
        try keys_stmt.bindOptInt(2, scope.session_id);
        while (try keys_stmt.step()) {
            try shadowed.put(arena, try arena.dupe(u8, keys_stmt.columnText(0)), {});
        }
    }

    while (try stmt.step()) {
        const is_server_scope = stmt.columnOptInt(1) == null;
        const key = stmt.columnOptText(2);
        if (is_server_scope and key != null and shadowed.contains(key.?)) continue;
        const tags = stmt.columnOptText(4);
        if (opts.tag) |wanted| {
            if (tags == null or !hasTag(tags.?, wanted)) continue;
        }
        try out.append(arena, .{
            .id = stmt.columnInt(0),
            .scope = if (is_server_scope) .server else .session,
            .key = if (key) |k| try arena.dupe(u8, k) else null,
            .content = try arena.dupe(u8, stmt.columnText(3)),
            .tags = if (tags) |t| try arena.dupe(u8, t) else null,
            .created_at = stmt.columnInt(5),
            .updated_at = stmt.columnInt(6),
        });
    }
    return out.toOwnedSlice(arena);
}

/// Every memory on the server, session-scoped ones included (annotated
/// with their session name). For `memory export`.
pub const Exported = struct {
    session: ?[]const u8,
    key: ?[]const u8,
    content: []const u8,
    tags: ?[]const u8,
    updated_at: i64,
};

pub fn exportAll(store: *Store, arena: Allocator, server_id: i64) (Db.Error || Allocator.Error)![]Exported {
    var out: std.ArrayList(Exported) = .empty;
    var stmt = try store.db.prepare(
        \\SELECT s.name, m.key, m.content, m.tags, m.updated_at
        \\FROM memories m LEFT JOIN sessions s ON s.id = m.session_id
        \\WHERE m.server_id = ?1 ORDER BY m.id
    );
    defer stmt.deinit();
    try stmt.bindInt(1, server_id);
    while (try stmt.step()) {
        try out.append(arena, .{
            .session = if (stmt.columnOptText(0)) |v| try arena.dupe(u8, v) else null,
            .key = if (stmt.columnOptText(1)) |v| try arena.dupe(u8, v) else null,
            .content = try arena.dupe(u8, stmt.columnText(2)),
            .tags = if (stmt.columnOptText(3)) |v| try arena.dupe(u8, v) else null,
            .updated_at = stmt.columnInt(4),
        });
    }
    return out.toOwnedSlice(arena);
}

/// Whether an identical keyless memory already exists in the exact scope
/// (used by import to avoid duplicating free-form entries).
pub fn hasContent(store: *Store, scope: Scope, content: []const u8) Db.Error!bool {
    var stmt = try store.db.prepare(
        "SELECT 1 FROM memories WHERE server_id = ?1 AND session_id IS ?2 AND key IS NULL AND content = ?3",
    );
    defer stmt.deinit();
    try stmt.bindInt(1, scope.server_id);
    try stmt.bindOptInt(2, scope.session_id);
    try stmt.bindText(3, content);
    return try stmt.step();
}

pub const Selector = union(enum) {
    key: []const u8,
    id: i64,
};

/// Looks up one entry. A key selector on a session scope falls back to the
/// server-scope entry when the session has none (shadowing semantics).
pub fn find(store: *Store, arena: Allocator, scope: Scope, selector: Selector) (Db.Error || Allocator.Error)!?Memory {
    const entries = try list(store, arena, scope, .{});
    switch (selector) {
        .key => |key| {
            // Session entries come last and shadow, so scan backwards.
            var i = entries.len;
            while (i > 0) {
                i -= 1;
                const m = entries[i];
                if (m.key != null and std.mem.eql(u8, m.key.?, key)) return m;
            }
        },
        .id => |id| for (entries) |m| {
            if (m.id == id) return m;
        },
    }
    return null;
}

/// Returns false if the selector matched nothing. Deleting by key only
/// touches the exact scope (no shadow fallback) to avoid surprises.
pub fn remove(store: *Store, scope: Scope, selector: Selector) Db.Error!bool {
    switch (selector) {
        .key => |key| {
            const id = (try idByKey(store, scope, key)) orelse return false;
            return removeById(store, scope.server_id, id);
        },
        .id => |id| return removeById(store, scope.server_id, id),
    }
}

fn removeById(store: *Store, server_id: i64, id: i64) Db.Error!bool {
    var stmt = try store.db.prepare(
        "DELETE FROM memories WHERE id = ?1 AND server_id = ?2",
    );
    defer stmt.deinit();
    try stmt.bindInt(1, id);
    try stmt.bindInt(2, server_id);
    _ = try stmt.step();
    return store.db.changes() > 0;
}

fn idByKey(store: *Store, scope: Scope, key: []const u8) Db.Error!?i64 {
    var stmt = try store.db.prepare(
        "SELECT id FROM memories WHERE server_id = ?1 AND session_id IS ?2 AND key = ?3",
    );
    defer stmt.deinit();
    try stmt.bindInt(1, scope.server_id);
    try stmt.bindOptInt(2, scope.session_id);
    try stmt.bindText(3, key);
    if (!try stmt.step()) return null;
    return stmt.columnInt(0);
}

fn hasTag(tags: []const u8, wanted: []const u8) bool {
    var it = std.mem.splitScalar(u8, tags, ',');
    while (it.next()) |tag| {
        if (std.mem.eql(u8, std.mem.trim(u8, tag, " \t"), wanted)) return true;
    }
    return false;
}
