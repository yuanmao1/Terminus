//! CRUD for the `sessions` table. In M1 a session row is pure local
//! metadata; the remote tmux session it maps to arrives in M2.
const std = @import("std");
const Store = @import("Store.zig");
const Db = @import("Db.zig");

pub fn idByName(store: *Store, server_id: i64, name: []const u8) Db.Error!?i64 {
    var stmt = try store.db.prepare(
        "SELECT id FROM sessions WHERE server_id = ?1 AND name = ?2",
    );
    defer stmt.deinit();
    try stmt.bindInt(1, server_id);
    try stmt.bindText(2, name);
    if (!try stmt.step()) return null;
    return stmt.columnInt(0);
}

/// Returns the session id, creating the metadata row if it does not exist
/// yet (session-scoped memories may be written before the remote tmux
/// session is ever started).
pub fn ensure(store: *Store, server_id: i64, name: []const u8, now: i64) Db.Error!i64 {
    if (try idByName(store, server_id, name)) |id| return id;
    var stmt = try store.db.prepare(
        "INSERT INTO sessions (server_id, name, created_at) VALUES (?1, ?2, ?3)",
    );
    defer stmt.deinit();
    try stmt.bindInt(1, server_id);
    try stmt.bindText(2, name);
    try stmt.bindInt(3, now);
    _ = try stmt.step();
    return store.db.lastInsertRowId();
}

pub const Session = struct {
    id: i64,
    name: []const u8,
    note: ?[]const u8,
    cursor: i64,
    last_seen_at: ?i64,
    created_at: i64,
};

pub fn list(store: *Store, arena: std.mem.Allocator, server_id: i64) (Db.Error || std.mem.Allocator.Error)![]Session {
    var out: std.ArrayList(Session) = .empty;
    var stmt = try store.db.prepare(
        \\SELECT id, name, note, cursor, last_seen_at, created_at
        \\FROM sessions WHERE server_id = ?1 ORDER BY name
    );
    defer stmt.deinit();
    try stmt.bindInt(1, server_id);
    while (try stmt.step()) {
        try out.append(arena, .{
            .id = stmt.columnInt(0),
            .name = try arena.dupe(u8, stmt.columnText(1)),
            .note = if (stmt.columnOptText(2)) |n| try arena.dupe(u8, n) else null,
            .cursor = stmt.columnInt(3),
            .last_seen_at = stmt.columnOptInt(4),
            .created_at = stmt.columnInt(5),
        });
    }
    return out.toOwnedSlice(arena);
}

/// Returns false if no such session row existed. Cascade-deletes the
/// session's memories.
///
/// Caller must hold the write transaction, and that requirement is the whole
/// reason this exists separately from `remove`. This delete is the local half of
/// `session rm`, and it has to land in the *same* transaction as the terminal
/// receipt that says the removal happened: settled first and deleted afterwards,
/// a failure in between leaves the ledger asserting a removal whose row, and
/// whose cascaded memories, are still on disk. See
/// `execution.Execution.settleAndRemoveSession`.
pub fn removeLocked(store: *Store, server_id: i64, name: []const u8) Db.Error!bool {
    try store.db.requireTransaction();
    var stmt = try store.db.prepare(
        "DELETE FROM sessions WHERE server_id = ?1 AND name = ?2",
    );
    defer stmt.deinit();
    try stmt.bindInt(1, server_id);
    try stmt.bindText(2, name);
    _ = try stmt.step();
    return store.db.changes() > 0;
}

/// `removeLocked` on its own.
///
/// **Not what `session rm` uses**, and a caller reaching for it should say why
/// it is not composing the delete with a terminal receipt: this drops a session
/// row and cascades that session's memories away with nothing in the ledger
/// recording that anybody did so. `session rm` goes through
/// `execution.Execution.settleAndRemoveSession` for exactly that reason. Kept as
/// the single-statement form because a caller that legitimately has no operation
/// to settle should still not open its own transaction by hand.
pub fn remove(store: *Store, server_id: i64, name: []const u8) Db.Error!bool {
    try store.db.exec("BEGIN IMMEDIATE");
    errdefer store.db.exec("ROLLBACK") catch {};
    const had_row = try removeLocked(store, server_id, name);
    try store.db.exec("COMMIT");
    return had_row;
}

pub fn cursor(store: *Store, session_id: i64) Db.Error!i64 {
    var stmt = try store.db.prepare("SELECT cursor FROM sessions WHERE id = ?1");
    defer stmt.deinit();
    try stmt.bindInt(1, session_id);
    if (!try stmt.step()) return 0;
    return stmt.columnInt(0);
}

pub fn setCursor(store: *Store, session_id: i64, value: i64, now: i64) Db.Error!void {
    var stmt = try store.db.prepare(
        "UPDATE sessions SET cursor = ?1, last_seen_at = ?2 WHERE id = ?3",
    );
    defer stmt.deinit();
    try stmt.bindInt(1, value);
    try stmt.bindInt(2, now);
    try stmt.bindInt(3, session_id);
    _ = try stmt.step();
}

pub fn touch(store: *Store, session_id: i64, now: i64) Db.Error!void {
    var stmt = try store.db.prepare("UPDATE sessions SET last_seen_at = ?1 WHERE id = ?2");
    defer stmt.deinit();
    try stmt.bindInt(1, now);
    try stmt.bindInt(2, session_id);
    _ = try stmt.step();
}
