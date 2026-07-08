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

pub const RenameError = Db.Error || error{NameTaken};

pub fn rename(store: *Store, server_id: i64, new_name: []const u8, now: i64) RenameError!void {
    var stmt = try store.db.prepare("UPDATE servers SET name = ?1, updated_at = ?2 WHERE id = ?3");
    defer stmt.deinit();
    try stmt.bindText(1, new_name);
    try stmt.bindInt(2, now);
    try stmt.bindInt(3, server_id);
    _ = stmt.step() catch |err| return switch (err) {
        error.Constraint => error.NameTaken,
        else => err,
    };
}

pub const Update = struct {
    host: ?[]const u8 = null,
    port: ?u16 = null,
    username: ?[]const u8 = null,
    key_id: ?i64 = null,
    note: ?[]const u8 = null,
};

/// Partial update: only non-null fields change.
pub fn update(store: *Store, server_id: i64, changes: Update, now: i64) Db.Error!void {
    if (changes.host) |v| try updateColumn(store, server_id, "host", .{ .text = v }, now);
    if (changes.port) |v| try updateColumn(store, server_id, "port", .{ .int = v }, now);
    if (changes.username) |v| try updateColumn(store, server_id, "username", .{ .text = v }, now);
    if (changes.key_id) |v| try updateColumn(store, server_id, "key_id", .{ .int = v }, now);
    if (changes.note) |v| try updateColumn(store, server_id, "note", .{ .text = v }, now);
}

const Value = union(enum) { text: []const u8, int: i64 };

fn updateColumn(store: *Store, server_id: i64, comptime column: []const u8, value: Value, now: i64) Db.Error!void {
    var stmt = try store.db.prepare(
        "UPDATE servers SET " ++ column ++ " = ?1, updated_at = ?2 WHERE id = ?3",
    );
    defer stmt.deinit();
    switch (value) {
        .text => |v| try stmt.bindText(1, v),
        .int => |v| try stmt.bindInt(1, v),
    }
    try stmt.bindInt(2, now);
    try stmt.bindInt(3, server_id);
    _ = try stmt.step();
}

pub const CascadeCounts = struct {
    sessions: i64,
    memories: i64,
    jobs: i64,
    facts: i64,
    history: i64,
};

/// What `remove` would cascade-delete; shown to the user first.
pub fn cascadeCounts(store: *Store, server_id: i64) Db.Error!CascadeCounts {
    return .{
        .sessions = try countRows(store, "sessions", server_id),
        .memories = try countRows(store, "memories", server_id),
        .jobs = try countRows(store, "jobs", server_id),
        .facts = try countRows(store, "facts", server_id),
        .history = try countRows(store, "history", server_id),
    };
}

fn countRows(store: *Store, comptime table: []const u8, server_id: i64) Db.Error!i64 {
    var stmt = try store.db.prepare("SELECT COUNT(*) FROM " ++ table ++ " WHERE server_id = ?1");
    defer stmt.deinit();
    try stmt.bindInt(1, server_id);
    if (!try stmt.step()) return 0;
    return stmt.columnInt(0);
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
