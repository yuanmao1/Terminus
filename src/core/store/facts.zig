//! Store CRUD for `facts` — stable machine-readable key/value pairs per
//! server, for command orchestration (vs. `memories`, which hold
//! natural-language experience for the agent to read).
const std = @import("std");
const Allocator = std.mem.Allocator;
const Store = @import("Store.zig");
const Db = @import("Db.zig");

pub const Fact = struct {
    key: []const u8,
    value: []const u8,
    updated_at: i64,
};

/// Upsert by (server, key).
pub fn set(store: *Store, server_id: i64, key: []const u8, value: []const u8, now: i64) Db.Error!void {
    var stmt = try store.db.prepare(
        \\INSERT INTO facts (server_id, key, value, updated_at) VALUES (?1, ?2, ?3, ?4)
        \\ON CONFLICT(server_id, key) DO UPDATE SET value = ?3, updated_at = ?4
    );
    defer stmt.deinit();
    try stmt.bindInt(1, server_id);
    try stmt.bindText(2, key);
    try stmt.bindText(3, value);
    try stmt.bindInt(4, now);
    _ = try stmt.step();
}

pub fn get(store: *Store, arena: Allocator, server_id: i64, key: []const u8) (Db.Error || Allocator.Error)!?[]const u8 {
    var stmt = try store.db.prepare("SELECT value FROM facts WHERE server_id = ?1 AND key = ?2");
    defer stmt.deinit();
    try stmt.bindInt(1, server_id);
    try stmt.bindText(2, key);
    if (!try stmt.step()) return null;
    return try arena.dupe(u8, stmt.columnText(0));
}

pub fn list(store: *Store, arena: Allocator, server_id: i64) (Db.Error || Allocator.Error)![]Fact {
    var out: std.ArrayList(Fact) = .empty;
    var stmt = try store.db.prepare(
        "SELECT key, value, updated_at FROM facts WHERE server_id = ?1 ORDER BY key",
    );
    defer stmt.deinit();
    try stmt.bindInt(1, server_id);
    while (try stmt.step()) {
        try out.append(arena, .{
            .key = try arena.dupe(u8, stmt.columnText(0)),
            .value = try arena.dupe(u8, stmt.columnText(1)),
            .updated_at = stmt.columnInt(2),
        });
    }
    return out.toOwnedSlice(arena);
}

pub fn remove(store: *Store, server_id: i64, key: []const u8) Db.Error!bool {
    var stmt = try store.db.prepare("DELETE FROM facts WHERE server_id = ?1 AND key = ?2");
    defer stmt.deinit();
    try stmt.bindInt(1, server_id);
    try stmt.bindText(2, key);
    _ = try stmt.step();
    return store.db.changes() > 0;
}
