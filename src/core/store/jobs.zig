//! Store CRUD for the `jobs` table. A job is a tracked long-running
//! remote command living in a dedicated tmux session (`job-<name>` on the
//! remote). The remote log + sentinel decide completion; the row caches
//! the last observed state so `job ls` can render without SSH.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Store = @import("Store.zig");
const Db = @import("Db.zig");

pub const Status = enum { running, exited, killed };

pub const Job = struct {
    id: i64,
    name: []const u8,
    command: []const u8,
    sentinel: []const u8,
    status: Status,
    exit_code: ?i64,
    read_cursor: i64,
    created_at: i64,
    finished_at: ?i64,
};

pub const CreateError = Db.Error || error{NameTaken};

pub fn create(store: *Store, server_id: i64, name: []const u8, command: []const u8, sentinel: []const u8, now: i64) CreateError!i64 {
    var stmt = try store.db.prepare(
        \\INSERT INTO jobs (server_id, name, command, sentinel, status, created_at)
        \\VALUES (?1, ?2, ?3, ?4, 'running', ?5)
    );
    defer stmt.deinit();
    try stmt.bindInt(1, server_id);
    try stmt.bindText(2, name);
    try stmt.bindText(3, command);
    try stmt.bindText(4, sentinel);
    try stmt.bindInt(5, now);
    _ = stmt.step() catch |err| return switch (err) {
        error.Constraint => error.NameTaken,
        else => err,
    };
    return store.db.lastInsertRowId();
}

fn rowToJob(arena: Allocator, stmt: *Db.Stmt) Allocator.Error!Job {
    return .{
        .id = stmt.columnInt(0),
        .name = try arena.dupe(u8, stmt.columnText(1)),
        .command = try arena.dupe(u8, stmt.columnText(2)),
        .sentinel = try arena.dupe(u8, stmt.columnText(3)),
        .status = std.meta.stringToEnum(Status, stmt.columnText(4)) orelse .running,
        .exit_code = stmt.columnOptInt(5),
        .read_cursor = stmt.columnInt(6),
        .created_at = stmt.columnInt(7),
        .finished_at = stmt.columnOptInt(8),
    };
}

const select_columns =
    \\SELECT id, name, command, sentinel, status, exit_code, read_cursor, created_at, finished_at
    \\FROM jobs
;

pub fn getByName(store: *Store, arena: Allocator, server_id: i64, name: []const u8) (Db.Error || Allocator.Error)!?Job {
    var stmt = try store.db.prepare(select_columns ++ " WHERE server_id = ?1 AND name = ?2");
    defer stmt.deinit();
    try stmt.bindInt(1, server_id);
    try stmt.bindText(2, name);
    if (!try stmt.step()) return null;
    return try rowToJob(arena, &stmt);
}

pub fn list(store: *Store, arena: Allocator, server_id: i64) (Db.Error || Allocator.Error)![]Job {
    var out: std.ArrayList(Job) = .empty;
    var stmt = try store.db.prepare(select_columns ++ " WHERE server_id = ?1 ORDER BY created_at DESC");
    defer stmt.deinit();
    try stmt.bindInt(1, server_id);
    while (try stmt.step()) try out.append(arena, try rowToJob(arena, &stmt));
    return out.toOwnedSlice(arena);
}

pub fn markFinished(store: *Store, job_id: i64, status: Status, exit_code: ?i64, now: i64) Db.Error!void {
    var stmt = try store.db.prepare(
        "UPDATE jobs SET status = ?1, exit_code = ?2, finished_at = ?3 WHERE id = ?4",
    );
    defer stmt.deinit();
    try stmt.bindText(1, @tagName(status));
    try stmt.bindOptInt(2, exit_code);
    try stmt.bindInt(3, now);
    try stmt.bindInt(4, job_id);
    _ = try stmt.step();
}

pub fn setCursor(store: *Store, job_id: i64, cursor: i64) Db.Error!void {
    var stmt = try store.db.prepare("UPDATE jobs SET read_cursor = ?1 WHERE id = ?2");
    defer stmt.deinit();
    try stmt.bindInt(1, cursor);
    try stmt.bindInt(2, job_id);
    _ = try stmt.step();
}

/// Removes the row (used by `job rm` after the remote session is gone).
pub fn remove(store: *Store, server_id: i64, name: []const u8) Db.Error!bool {
    var stmt = try store.db.prepare("DELETE FROM jobs WHERE server_id = ?1 AND name = ?2");
    defer stmt.deinit();
    try stmt.bindInt(1, server_id);
    try stmt.bindText(2, name);
    _ = try stmt.step();
    return store.db.changes() > 0;
}
