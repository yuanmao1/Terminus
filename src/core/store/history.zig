//! Store CRUD for `history` — the local audit trail of remote actions.
//! Written best-effort by exec/run/push/pull/sync; read by `terminus
//! history`. Recording failures never break the command being recorded.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Store = @import("Store.zig");
const Db = @import("Db.zig");

pub const Entry = struct {
    id: i64,
    kind: []const u8,
    detail: []const u8,
    cwd: ?[]const u8,
    exit_code: ?i64,
    transport: ?[]const u8,
    duration_ms: ?i64,
    created_at: i64,
};

pub const Record = struct {
    kind: []const u8, // exec | job | push | pull | sync
    detail: []const u8,
    cwd: ?[]const u8 = null,
    exit_code: ?i64 = null,
    transport: ?[]const u8 = null,
    duration_ms: ?i64 = null,
};

pub fn add(store: *Store, server_id: i64, record: Record, now: i64) Db.Error!void {
    var stmt = try store.db.prepare(
        \\INSERT INTO history (server_id, kind, detail, cwd, exit_code, transport, duration_ms, created_at)
        \\VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
    );
    defer stmt.deinit();
    try stmt.bindInt(1, server_id);
    try stmt.bindText(2, record.kind);
    try stmt.bindText(3, record.detail);
    try stmt.bindOptText(4, record.cwd);
    try stmt.bindOptInt(5, record.exit_code);
    try stmt.bindOptText(6, record.transport);
    try stmt.bindOptInt(7, record.duration_ms);
    try stmt.bindInt(8, now);
    _ = try stmt.step();
}

pub fn list(store: *Store, arena: Allocator, server_id: i64, limit: i64) (Db.Error || Allocator.Error)![]Entry {
    var out: std.ArrayList(Entry) = .empty;
    var stmt = try store.db.prepare(
        \\SELECT id, kind, detail, cwd, exit_code, transport, duration_ms, created_at
        \\FROM history WHERE server_id = ?1 ORDER BY id DESC LIMIT ?2
    );
    defer stmt.deinit();
    try stmt.bindInt(1, server_id);
    try stmt.bindInt(2, limit);
    while (try stmt.step()) {
        try out.append(arena, .{
            .id = stmt.columnInt(0),
            .kind = try arena.dupe(u8, stmt.columnText(1)),
            .detail = try arena.dupe(u8, stmt.columnText(2)),
            .cwd = if (stmt.columnOptText(3)) |v| try arena.dupe(u8, v) else null,
            .exit_code = stmt.columnOptInt(4),
            .transport = if (stmt.columnOptText(5)) |v| try arena.dupe(u8, v) else null,
            .duration_ms = stmt.columnOptInt(6),
            .created_at = stmt.columnInt(7),
        });
    }
    return out.toOwnedSlice(arena);
}
