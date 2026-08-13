//! Store CRUD for the `jobs` table. A job is a tracked long-running
//! remote command living in a dedicated tmux session (`job-<name>` on the
//! remote). The remote log + sentinel decide completion; the row caches
//! the last observed state so `job ls` can render without SSH.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Store = @import("Store.zig");
const Db = @import("Db.zig");

/// `pending` is the launch window: the row exists, but nothing has been typed
/// into the remote shell yet.
///
/// It is a distinct state rather than an early `running` because the row is
/// written before the launcher touches the remote host at all — that is what
/// makes `UNIQUE(server_id, name)` able to pick a winner between two
/// simultaneous launches — and a reservation that never got that far is not
/// work in progress. Calling it `running` would put a job in `job ls` that
/// provably never started.
pub const Status = enum {
    pending,
    running,
    exited,
    killed,

    /// Names a row that may correspond to something on the remote host, and
    /// so must not be silently reused or overwritten.
    pub fn live(self: Status) bool {
        return switch (self) {
            .pending, .running => true,
            .exited, .killed => false,
        };
    }

    pub fn parse(text: []const u8) error{UnknownStatus}!Status {
        return std.meta.stringToEnum(Status, text) orelse error.UnknownStatus;
    }
};

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
    /// The launch that reserved this row. Null for rows written by 0.1.x,
    /// which predate the notion — those have no owner and only a human can
    /// clear them.
    owner_request_id: ?[]const u8,
};

/// An unreadable status is an error, never a default. Guessing `running` here
/// would be the safe direction by luck rather than by design, and the same
/// helper is used to decide whether a name may be reused.
pub const ReadError = Db.Error || Allocator.Error || error{UnknownStatus};
pub const CreateError = Db.Error || error{NameTaken};

/// Reserves the job name for one launch. The row starts `pending`: it says
/// "this name is claimed and the remote is being prepared", not "this job is
/// running".
///
/// `error.NameTaken` is the serialisation point of the whole launch path —
/// whoever loses here has not touched the remote host yet.
///
/// `owner_request_id` is what makes the reservation releasable. See the v9
/// migration for why neither the name nor the rowid can play that part.
pub fn create(
    store: *Store,
    server_id: i64,
    name: []const u8,
    command: []const u8,
    sentinel: []const u8,
    owner_request_id: []const u8,
    now: i64,
) CreateError!i64 {
    var stmt = try store.db.prepare(
        \\INSERT INTO jobs (server_id, name, command, sentinel, status, owner_request_id, created_at)
        \\VALUES (?1, ?2, ?3, ?4, 'pending', ?5, ?6)
    );
    defer stmt.deinit();
    try stmt.bindInt(1, server_id);
    try stmt.bindText(2, name);
    try stmt.bindText(3, command);
    try stmt.bindText(4, sentinel);
    try stmt.bindText(5, owner_request_id);
    try stmt.bindInt(6, now);
    _ = stmt.step() catch |err| return switch (err) {
        error.Constraint => error.NameTaken,
        else => err,
    };
    return store.db.lastInsertRowId();
}

/// Promotes a reservation once the command has actually reached the remote
/// shell.
///
/// Returns false when this row was not ours to promote — it has been taken
/// over by another launcher, or an observer already settled it. The caller
/// must not read that as success: by the time this runs the command has been
/// sent, so a false here means something is running on the host that nothing
/// local is tracking under this name.
pub fn markStarted(store: *Store, owner_request_id: []const u8) Db.Error!bool {
    var stmt = try store.db.prepare(
        \\UPDATE jobs SET status = 'running'
        \\WHERE owner_request_id = ?1 AND status = 'pending'
    );
    defer stmt.deinit();
    try stmt.bindText(1, owner_request_id);
    _ = try stmt.step();
    return store.db.changes() > 0;
}

/// Gives back a reservation this launcher still owns.
///
/// Keyed on the owning request and on the row still being `pending` — never
/// on the name, and never on the rowid. A name is what a takeover transfers;
/// a rowid is reused by the very next INSERT after a delete. Either would
/// have an aborted launcher remove the *replacement's* row, leaving that
/// launcher's command running on the host with nothing tracking it.
///
/// Returns false when the row is no longer ours, which is not an error: it
/// means somebody else owns the name now.
pub fn releaseReservation(store: *Store, owner_request_id: []const u8) Db.Error!bool {
    var stmt = try store.db.prepare(
        "DELETE FROM jobs WHERE owner_request_id = ?1 AND status = 'pending'",
    );
    defer stmt.deinit();
    try stmt.bindText(1, owner_request_id);
    _ = try stmt.step();
    return store.db.changes() > 0;
}

fn rowToJob(arena: Allocator, stmt: *Db.Stmt) (Allocator.Error || error{UnknownStatus})!Job {
    return .{
        .id = stmt.columnInt(0),
        .name = try arena.dupe(u8, stmt.columnText(1)),
        .command = try arena.dupe(u8, stmt.columnText(2)),
        .sentinel = try arena.dupe(u8, stmt.columnText(3)),
        .status = try Status.parse(stmt.columnText(4)),
        .exit_code = stmt.columnOptInt(5),
        .read_cursor = stmt.columnInt(6),
        .created_at = stmt.columnInt(7),
        .finished_at = stmt.columnOptInt(8),
        .owner_request_id = if (stmt.columnOptText(9)) |v| try arena.dupe(u8, v) else null,
    };
}

const select_columns =
    \\SELECT id, name, command, sentinel, status, exit_code, read_cursor, created_at,
    \\       finished_at, owner_request_id
    \\FROM jobs
;

pub fn getByName(store: *Store, arena: Allocator, server_id: i64, name: []const u8) ReadError!?Job {
    var stmt = try store.db.prepare(select_columns ++ " WHERE server_id = ?1 AND name = ?2");
    defer stmt.deinit();
    try stmt.bindInt(1, server_id);
    try stmt.bindText(2, name);
    if (!try stmt.step()) return null;
    return try rowToJob(arena, &stmt);
}

pub fn list(store: *Store, arena: Allocator, server_id: i64) ReadError![]Job {
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
