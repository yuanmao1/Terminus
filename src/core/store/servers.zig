//! CRUD for the `servers` table.
const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Store = @import("Store.zig");
const Db = @import("Db.zig");
const keys = @import("keys.zig");
// Read only, and only to answer the questions `remove` must not guess at:
// does deleting this server strand a transfer that can no longer be handed to
// anyone, is an attempt on it still unsettled, is a lease on it still held.
// The dependency runs one way — none of the three knows about `servers`, they
// know about `operations.server_id` — and all three are reads, so this adds no
// second writer to any of those tables.
const transfers = @import("transfers.zig");
const operations = @import("operations.zig");
const leases = @import("leases.zig");

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

/// How much *recorded knowledge* about this host the delete would erase.
///
/// Advisory, and only advisory. This is a volume warning — "you are about to
/// throw away 40 memories and 200 history rows, did you mean to" — and a caller
/// is free to let `--force` wave it through, because every number here is a
/// record of a host nobody wants any more.
///
/// It is **not** the safety check and must not be read as one. The barriers
/// that can refuse a removal are evaluated by `remove` inside the same write
/// transaction as the DELETE, and are reported by it; see there. This function
/// takes no transaction, so whatever it returns is already historical by the
/// time the caller acts on it — which is precisely why the barrier cannot live
/// here. It used to carry a `resumable_transfers` field for a caller wording a
/// refusal, and that field is gone: a number a caller has to remember to
/// consult is a barrier held by convention, and three of them would have been
/// three conventions.
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

/// A barrier standing between this server and its deletion, and how many rows
/// are behind it.
///
/// Three named variants rather than one counted "blockers" number, because the
/// three send an operator somewhere completely different — reconcile an
/// attempt, release a lease, finish or supersede a transfer — and a refusal
/// that cannot say which of the three it is leaves them guessing at the one
/// moment they most need not to be.
pub const Barrier = union(enum) {
    /// Attempts whose remote outcome is still open. Deleting the server sets
    /// their `server_id` to NULL, which lifts the scope block *and* hides them
    /// from every per-server listing at once.
    unsettled_operations: i64,
    /// Leases still held. `leases.server_id` is `ON DELETE CASCADE`, so these
    /// are destroyed rather than un-scoped, taking the takeover chain with them.
    active_leases: i64,
    /// Checkpoints that still depend on a hand-over to go anywhere. Every
    /// hand-over is guarded by a same-machine conjunct, so without the server
    /// row they can never be taken over by anybody, in any state, while going
    /// on holding their destination against every later transfer.
    resumable_transfers: i64,
};

/// What `remove` did, or what stopped it.
pub const Removal = union(enum) {
    removed,
    /// No server by that name. A distinct answer from `removed`, because a
    /// caller that folds the two together reports a successful deletion for a
    /// typo.
    unknown_server,
    refused: Barrier,
};

pub const RemoveError = Db.Error || error{
    /// The row was there when the barriers were checked and gone when the
    /// DELETE ran — impossible inside one `BEGIN IMMEDIATE`, which is why it is
    /// an error and not a quiet `unknown_server`. If this is ever seen, the
    /// check and the delete are no longer in one transaction and every
    /// guarantee below is void.
    ServerVanishedDuringRemoval,
};

/// Called between the barrier check and the DELETE.
///
/// A test seam, and it exists because the property that matters here cannot be
/// observed from outside: "the check and the delete see the same snapshot" is
/// only falsifiable by trying to change the answer in between, from a
/// connection that is not the one holding the transaction. The gate installs a
/// probe that attempts exactly that; under one `BEGIN IMMEDIATE` the probe
/// cannot get the write lock, and under two transactions it can.
///
/// `void` outside a test build — no storage, and the call site is behind
/// `comptime builtin.is_test`, so the shipped binary contains neither the
/// variable nor the branch.
pub var between_check_and_delete: if (builtin.is_test) ?*const fn () void else void =
    if (builtin.is_test) null else {};

/// Deletes a server, or refuses and says which barrier stopped it.
///
/// The check and the delete are one `BEGIN IMMEDIATE` transaction, and that is
/// the substance of this function rather than tidiness. SQLite allows one
/// writer at a time, so a transaction that has taken the write lock excludes
/// every other connection for its whole length: nothing can reach `submitted`,
/// acquire a lease or mint a checkpoint between the moment the barriers are
/// counted and the moment the row goes. Counting first and deleting afterwards
/// — which is what `server rm` did — leaves a window in exactly the state where
/// it costs the most: the count says "clear", a peer submits, the delete lands,
/// and the attempt it just un-scoped is one nobody will ever be told about.
///
/// None of the three barriers is coverable by a flag, and no parameter here can
/// express one. A `--force` may reasonably cover the cascade counts — those are
/// records of a host nobody wants any more — but an attempt whose remote
/// outcome is unknown, a lease somebody is holding, and a transfer with a legal
/// move left are not losses of the same kind: the way past each is to establish
/// the fact it is waiting on, and there is no fact a flag can supply. Adding
/// one is a decision for the programmer and not for a caller in a hurry.
///
/// `now` drives the lease expiry pass, so a dead session's lapsed lease does not
/// become a permanent refusal; see `leases.activeCountLocked`.
pub fn remove(store: *Store, name: []const u8, now: i64) RemoveError!Removal {
    try store.db.exec("BEGIN IMMEDIATE");
    errdefer store.db.exec("ROLLBACK") catch {};
    const outcome = try removeLocked(store, name, now);
    try store.db.exec("COMMIT");
    return outcome;
}

/// The whole decision, for a caller that already holds the write transaction.
///
/// Caller must hold it. A barrier evaluated outside the transaction that then
/// acts on what it found is not a barrier — whatever it checked can become
/// false before the DELETE lands.
pub fn removeLocked(store: *Store, name: []const u8, now: i64) RemoveError!Removal {
    try store.db.requireTransaction();

    const server_id = blk: {
        var stmt = try store.db.prepare("SELECT id FROM servers WHERE name = ?1");
        defer stmt.deinit();
        try stmt.bindText(1, name);
        if (!try stmt.step()) return .unknown_server;
        break :blk stmt.columnInt(0);
    };

    // Ordered cheapest-to-explain first, and each one reported alone: an
    // operator clears one barrier at a time anyway, and a refusal naming three
    // things at once is a refusal nobody reads to the end of.
    const unsettled = try operations.unsettledCountLocked(store, server_id);
    if (unsettled > 0) return .{ .refused = .{ .unsettled_operations = unsettled } };

    const held = try leases.activeCountLocked(store, server_id, now);
    if (held > 0) return .{ .refused = .{ .active_leases = held } };

    // Folded in here rather than left as the separate pre-check it used to be.
    // Two checks in two transactions is two windows, and the one this closes is
    // the same one: a checkpoint minted between the count and the delete would
    // have been stranded by a delete that had already decided there were none.
    const resumable = try transfers.handoverBoundCountLocked(store, server_id);
    if (resumable > 0) return .{ .refused = .{ .resumable_transfers = resumable } };

    if (comptime builtin.is_test) {
        if (between_check_and_delete) |probe| probe();
    }

    var stmt = try store.db.prepare("DELETE FROM servers WHERE id = ?1");
    defer stmt.deinit();
    try stmt.bindInt(1, server_id);
    _ = try stmt.step();
    // The row was read a few statements ago under this same lock, so a DELETE
    // matching nothing is not "it was already gone" — it is proof the lock is
    // not doing what the rest of this function assumes.
    if (store.db.changes() == 0) return error.ServerVanishedDuringRemoval;
    return .removed;
}
