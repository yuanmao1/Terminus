//! Thin wrapper over the SQLite C API (imported via translate-c).
//!
//! Follows the std.Io.Dir/File style: a small value type whose methods
//! return typed errors; the detailed message stays queryable on the
//! handle via `errorMessage` until the next operation.
const std = @import("std");
const c = @import("sqlite");

const Db = @This();

handle: *c.sqlite3,

pub const Error = error{
    /// Any sqlite failure. Call `errorMessage` for the human-readable cause.
    Sqlite,
    /// A UNIQUE/FOREIGN KEY/CHECK constraint rejected the statement.
    Constraint,
};

/// SQLITE_TRANSIENT: sqlite copies the buffer before returning from bind.
/// The macro casts -1 to a function pointer, which translate-c cannot
/// express as a constant, so it is reproduced here.
const transient: c.sqlite3_destructor_type = @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))));

pub fn open(path: [:0]const u8) Error!Db {
    var handle: ?*c.sqlite3 = null;
    const rc = c.sqlite3_open_v2(
        path.ptr,
        &handle,
        c.SQLITE_OPEN_READWRITE | c.SQLITE_OPEN_CREATE,
        null,
    );
    if (rc != c.SQLITE_OK) {
        if (handle) |h| _ = c.sqlite3_close(h);
        return error.Sqlite;
    }
    var db: Db = .{ .handle = handle.? };
    _ = c.sqlite3_busy_timeout(db.handle, 5000);
    try db.exec("PRAGMA journal_mode=WAL");
    try db.exec("PRAGMA foreign_keys=ON");
    return db;
}

pub fn close(db: *Db) void {
    _ = c.sqlite3_close(db.handle);
    db.* = undefined;
}

/// Valid until the next operation on this connection.
pub fn errorMessage(db: *const Db) []const u8 {
    return std.mem.span(c.sqlite3_errmsg(db.handle));
}

pub fn exec(db: *Db, sql: [:0]const u8) Error!void {
    if (c.sqlite3_exec(db.handle, sql.ptr, null, null, null) != c.SQLITE_OK)
        return db.failure();
}

pub fn prepare(db: *Db, sql: [:0]const u8) Error!Stmt {
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db.handle, sql.ptr, -1, &stmt, null) != c.SQLITE_OK)
        return db.failure();
    return .{ .handle = stmt.?, .db = db.handle };
}

pub fn lastInsertRowId(db: *const Db) i64 {
    return c.sqlite3_last_insert_rowid(db.handle);
}

/// Rows changed by the most recent INSERT/UPDATE/DELETE.
pub fn changes(db: *const Db) i64 {
    return c.sqlite3_changes64(db.handle);
}

fn failure(db: *const Db) Error {
    return switch (c.sqlite3_errcode(db.handle) & 0xff) {
        c.SQLITE_CONSTRAINT => error.Constraint,
        else => error.Sqlite,
    };
}

pub const Stmt = struct {
    handle: *c.sqlite3_stmt,
    db: *c.sqlite3,

    pub fn deinit(s: *Stmt) void {
        _ = c.sqlite3_finalize(s.handle);
        s.* = undefined;
    }

    fn failure(s: *const Stmt) Error {
        return switch (c.sqlite3_errcode(s.db) & 0xff) {
            c.SQLITE_CONSTRAINT => error.Constraint,
            else => error.Sqlite,
        };
    }

    /// Parameter indexes are 1-based.
    pub fn bindText(s: *Stmt, index: c_int, value: []const u8) Error!void {
        if (c.sqlite3_bind_text(s.handle, index, value.ptr, @intCast(value.len), transient) != c.SQLITE_OK)
            return s.failure();
    }

    pub fn bindOptText(s: *Stmt, index: c_int, value: ?[]const u8) Error!void {
        if (value) |v| try s.bindText(index, v) else try s.bindNull(index);
    }

    pub fn bindBlob(s: *Stmt, index: c_int, value: []const u8) Error!void {
        if (c.sqlite3_bind_blob(s.handle, index, value.ptr, @intCast(value.len), transient) != c.SQLITE_OK)
            return s.failure();
    }

    pub fn bindInt(s: *Stmt, index: c_int, value: i64) Error!void {
        if (c.sqlite3_bind_int64(s.handle, index, value) != c.SQLITE_OK)
            return s.failure();
    }

    pub fn bindOptInt(s: *Stmt, index: c_int, value: ?i64) Error!void {
        if (value) |v| try s.bindInt(index, v) else try s.bindNull(index);
    }

    pub fn bindNull(s: *Stmt, index: c_int) Error!void {
        if (c.sqlite3_bind_null(s.handle, index) != c.SQLITE_OK)
            return s.failure();
    }

    /// Returns true while a row is available.
    pub fn step(s: *Stmt) Error!bool {
        return switch (c.sqlite3_step(s.handle)) {
            c.SQLITE_ROW => true,
            c.SQLITE_DONE => false,
            else => s.failure(),
        };
    }

    /// Column indexes are 0-based. The slice is only valid until the next
    /// step/deinit — dupe it before advancing.
    pub fn columnText(s: *Stmt, index: c_int) []const u8 {
        const ptr = c.sqlite3_column_text(s.handle, index) orelse return "";
        const len: usize = @intCast(c.sqlite3_column_bytes(s.handle, index));
        return ptr[0..len];
    }

    pub fn columnOptText(s: *Stmt, index: c_int) ?[]const u8 {
        if (c.sqlite3_column_type(s.handle, index) == c.SQLITE_NULL) return null;
        return s.columnText(index);
    }

    pub fn columnInt(s: *Stmt, index: c_int) i64 {
        return c.sqlite3_column_int64(s.handle, index);
    }

    pub fn columnOptInt(s: *Stmt, index: c_int) ?i64 {
        if (c.sqlite3_column_type(s.handle, index) == c.SQLITE_NULL) return null;
        return s.columnInt(index);
    }
};
