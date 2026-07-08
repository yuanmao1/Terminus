//! CRUD for the `servers` table.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Store = @import("Store.zig");
const Db = @import("Db.zig");
const keys = @import("keys.zig");

pub const Server = struct {
    id: i64,
    name: []const u8,
    host: []const u8,
    port: u16,
    username: []const u8,
    key: ?[]const u8, // key name, resolved via join
    note: ?[]const u8,
    /// Default remote working directory (workspace) for exec/run.
    cwd: ?[]const u8,
    created_at: i64,
    updated_at: i64,
};

pub const AddOptions = struct {
    name: []const u8,
    host: []const u8,
    port: u16 = 22,
    username: []const u8,
    key: ?[]const u8 = null, // key name
    note: ?[]const u8 = null,
    now: i64,
};

pub const AddError = Db.Error || error{ NameTaken, KeyNotFound };

pub fn add(store: *Store, opts: AddOptions) AddError!i64 {
    var key_id: ?i64 = null;
    if (opts.key) |key_name| {
        key_id = (try keys.idByName(store, key_name)) orelse return error.KeyNotFound;
    }
    var stmt = try store.db.prepare(
        \\INSERT INTO servers (name, note, host, port, username, key_id, created_at, updated_at)
        \\VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)
    );
    defer stmt.deinit();
    try stmt.bindText(1, opts.name);
    try stmt.bindOptText(2, opts.note);
    try stmt.bindText(3, opts.host);
    try stmt.bindInt(4, opts.port);
    try stmt.bindText(5, opts.username);
    try stmt.bindOptInt(6, key_id);
    try stmt.bindInt(7, opts.now);
    _ = stmt.step() catch |err| return switch (err) {
        error.Constraint => error.NameTaken,
        else => err,
    };
    return store.db.lastInsertRowId();
}

const select_columns =
    \\SELECT s.id, s.name, s.host, s.port, s.username, k.name, s.note, s.cwd, s.created_at, s.updated_at
    \\FROM servers s LEFT JOIN keys k ON k.id = s.key_id
;

fn rowToServer(arena: Allocator, stmt: *Db.Stmt) Allocator.Error!Server {
    return .{
        .id = stmt.columnInt(0),
        .name = try arena.dupe(u8, stmt.columnText(1)),
        .host = try arena.dupe(u8, stmt.columnText(2)),
        .port = @intCast(stmt.columnInt(3)),
        .username = try arena.dupe(u8, stmt.columnText(4)),
        .key = if (stmt.columnOptText(5)) |k| try arena.dupe(u8, k) else null,
        .note = if (stmt.columnOptText(6)) |n| try arena.dupe(u8, n) else null,
        .cwd = if (stmt.columnOptText(7)) |w| try arena.dupe(u8, w) else null,
        .created_at = stmt.columnInt(8),
        .updated_at = stmt.columnInt(9),
    };
}

pub fn setCwd(store: *Store, server_id: i64, cwd: ?[]const u8, now: i64) Db.Error!void {
    var stmt = try store.db.prepare("UPDATE servers SET cwd = ?1, updated_at = ?2 WHERE id = ?3");
    defer stmt.deinit();
    try stmt.bindOptText(1, cwd);
    try stmt.bindInt(2, now);
    try stmt.bindInt(3, server_id);
    _ = try stmt.step();
}

pub fn list(store: *Store, arena: Allocator) (Db.Error || Allocator.Error)![]Server {
    var out: std.ArrayList(Server) = .empty;
    var stmt = try store.db.prepare(select_columns ++ " ORDER BY s.name");
    defer stmt.deinit();
    while (try stmt.step()) try out.append(arena, try rowToServer(arena, &stmt));
    return out.toOwnedSlice(arena);
}

pub fn getByName(store: *Store, arena: Allocator, name: []const u8) (Db.Error || Allocator.Error)!?Server {
    var stmt = try store.db.prepare(select_columns ++ " WHERE s.name = ?1");
    defer stmt.deinit();
    try stmt.bindText(1, name);
    if (!try stmt.step()) return null;
    return try rowToServer(arena, &stmt);
}

/// Returns false if no server with that name existed.
pub fn remove(store: *Store, name: []const u8) Db.Error!bool {
    var stmt = try store.db.prepare("DELETE FROM servers WHERE name = ?1");
    defer stmt.deinit();
    try stmt.bindText(1, name);
    _ = try stmt.step();
    return store.db.changes() > 0;
}
