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
    /// The database could not be put into WAL mode within the retry budget.
    ///
    /// Distinct from `Sqlite` on purpose: this contention is invisible to
    /// `busy_timeout` (see `ensureWal`) and the retry budget is measured in
    /// iterations rather than time, so a heavily loaded machine is the one
    /// place it could plausibly run out. Naming it means a future occurrence
    /// identifies itself instead of arriving as an unexplained failure.
    WalSetupExhausted,
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
    try db.ensureWal();
    try db.exec("PRAGMA foreign_keys=ON");
    return db;
}

/// Switches the database to WAL, tolerating a concurrent first open.
///
/// WAL is what lets a reader and a writer coexist, which the CLI and daemon
/// both depend on. Setting it needs a brief exclusive lock, and SQLite does
/// **not** route that wait through the busy handler — so `busy_timeout` does
/// nothing here. Several processes starting in the same instant on a brand
/// new database therefore see "database is locked" (an agent firing parallel
/// commands hits this readily).
///
/// The lock is held only for the duration of the peer's own pragma, so
/// retrying closes the window. A peer winning the race is success: the mode
/// lives in the file header, so what matters is that the database *is* in WAL
/// when we return, not who put it there. Once set, later opens read `wal` and
/// never contend again.
///
/// Waiting spins briefly (the common case is a peer finishing a header write,
/// i.e. microseconds) and then yields, so a *preempted* peer can actually run.
/// A pure spin here is not enough: under scheduling pressure it exhausts its
/// budget while the lock holder never gets scheduled, which showed up as an
/// intermittent ReleaseSafe failure.
fn ensureWal(db: *Db) Error!void {
    // Generous: the lock is held only for a peer's own header write, so the
    // only way to exhaust this is a machine so loaded that nothing runs.
    const max_rounds = 64 * 1024;
    var round: usize = 0;
    while (round < max_rounds) : (round += 1) {
        if (db.exec("PRAGMA journal_mode=WAL")) |_| return else |_| {}
        if (try db.inWalMode()) return;
        var spin: usize = 0;
        while (spin < 64) : (spin += 1) std.atomic.spinLoopHint();
        std.Thread.yield() catch {};
    }
    // Never report success in a different journal mode: the concurrency
    // guarantees the rest of the code assumes would not hold.
    if (try db.inWalMode()) return;
    return error.WalSetupExhausted;
}

fn inWalMode(db: *Db) Error!bool {
    var stmt = try db.prepare("PRAGMA journal_mode");
    defer stmt.deinit();
    if (!try stmt.step()) return false;
    return std.ascii.eqlIgnoreCase(stmt.columnText(0), "wal");
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
