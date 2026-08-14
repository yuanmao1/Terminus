//! Ownership leases (`leases`), so two agent sessions do not retry, restart
//! or rewrite the same thing at once.
//!
//! Three properties are deliberately enforced by the database rather than by
//! convention:
//!
//! * **No two active leases whose scopes overlap.** Two halves, and they are
//!   not interchangeable. A partial unique index on
//!   `(server_id, scope_kind, scope_key) WHERE released_at IS NULL` makes a
//!   double acquisition of the *identical* key impossible even under a race —
//!   that is all an index on three columns can see. Overlap is a relation
//!   between two different keys (`path:/srv/app` against
//!   `path:/srv/app/dist`), which no index expresses, so it is decided in code
//!   under the write lock: `acquire` refuses on any overlap and `takeover`
//!   displaces *every* overlap. A writer here that handled only the first
//!   overlap it found would leave the second one active and hit no constraint
//!   on the way out — the index cannot catch that mistake, so the loops have
//!   to.
//! * **Append only.** Acquiring never mutates a peer's row. Expiry and
//!   takeover *release* the old row (recording why) and insert a new one, so
//!   the table is its own audit chain via `superseded_by`.
//! * **Conflict decided inside a write transaction.** Expiring stale rows,
//!   checking for overlap and inserting all happen under `BEGIN IMMEDIATE`;
//!   a check-then-insert outside a transaction would let two acquirers both
//!   see a free scope.
//!
//! Leases are advisory for reads and enforced for writes: `run`, `fetch`,
//! `job kill/rm`, `push`, `sync push` and `write` refuse when a peer holds an
//! overlapping lease, while `exec` only reports it. Every lease carries a TTL
//! so a dead session can never block a scope forever.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Store = @import("Store.zig");
const Db = @import("Db.zig");
const scope_mod = @import("scope.zig");

/// Leases and the unsettled-operation guard share one definition of overlap;
/// see `scope.zig`. Two barriers with different rules is how a hole appears.
pub const ScopeKind = scope_mod.Kind;
pub const Scope = scope_mod.Scope;

pub const ReleaseReason = enum {
    /// Owner gave it up.
    released,
    /// TTL passed without a renewal.
    expired,
    /// Another owner deliberately took over.
    takeover,
    /// Overridden with --force.
    force,

    pub fn text(r: ReleaseReason) []const u8 {
        return @tagName(r);
    }
};

pub const Lease = struct {
    id: i64,
    server_id: i64,
    scope_kind: ScopeKind,
    scope_key: []const u8,
    owner_token: []const u8,
    owner_label: ?[]const u8,
    note: ?[]const u8,
    request_id: ?[]const u8,
    acquired_at: i64,
    renewed_at: i64,
    expires_at: i64,

    pub fn scope(l: Lease) Scope {
        return .{ .kind = l.scope_kind, .key = l.scope_key };
    }

    pub fn heldBy(l: Lease, owner_token: []const u8) bool {
        return std.mem.eql(u8, l.owner_token, owner_token);
    }
};

pub const Error = Db.Error || error{ UnknownScopeKind, OutOfMemory };

pub const AcquireOptions = struct {
    server_id: i64,
    scope: Scope,
    owner_token: []const u8,
    owner_label: ?[]const u8 = null,
    note: ?[]const u8 = null,
    request_id: ?[]const u8 = null,
    ttl_secs: i64,
    now: i64,
};

pub const AcquireOutcome = union(enum) {
    /// Freshly taken.
    acquired: Lease,
    /// We already held an overlapping lease; its TTL was extended.
    renewed: Lease,
    /// A peer holds it. Carries their lease so the caller can report who and
    /// until when, and offer takeover.
    conflict: Lease,
};

const select_columns =
    \\SELECT id, server_id, scope_kind, scope_key, owner_token, owner_label,
    \\       note, request_id, acquired_at, renewed_at, expires_at
    \\FROM leases
;

fn rowToLease(arena: Allocator, stmt: *Db.Stmt) Error!Lease {
    return .{
        .id = stmt.columnInt(0),
        .server_id = stmt.columnInt(1),
        .scope_kind = try ScopeKind.parse(stmt.columnText(2)),
        .scope_key = try arena.dupe(u8, stmt.columnText(3)),
        .owner_token = try arena.dupe(u8, stmt.columnText(4)),
        .owner_label = if (stmt.columnOptText(5)) |v| try arena.dupe(u8, v) else null,
        .note = if (stmt.columnOptText(6)) |v| try arena.dupe(u8, v) else null,
        .request_id = if (stmt.columnOptText(7)) |v| try arena.dupe(u8, v) else null,
        .acquired_at = stmt.columnInt(8),
        .renewed_at = stmt.columnInt(9),
        .expires_at = stmt.columnInt(10),
    };
}

/// Marks every lapsed lease on the server as expired. Caller holds the write
/// transaction. Lazy expiry keeps a dead session from blocking a scope while
/// still leaving the row as evidence that a lease once existed.
fn expireLapsedLocked(store: *Store, server_id: i64, now: i64) Db.Error!void {
    var stmt = try store.db.prepare(
        \\UPDATE leases SET released_at = ?1, release_reason = 'expired'
        \\ WHERE server_id = ?2 AND released_at IS NULL AND expires_at <= ?1
    );
    defer stmt.deinit();
    try stmt.bindInt(1, now);
    try stmt.bindInt(2, server_id);
    _ = try stmt.step();
}

/// Active leases on the server, newest first. Caller may hold the write lock.
fn activeLocked(store: *Store, arena: Allocator, server_id: i64) Error![]Lease {
    var out: std.ArrayList(Lease) = .empty;
    var stmt = try store.db.prepare(select_columns ++
        " WHERE server_id = ?1 AND released_at IS NULL ORDER BY acquired_at DESC");
    defer stmt.deinit();
    try stmt.bindInt(1, server_id);
    while (try stmt.step()) try out.append(arena, try rowToLease(arena, &stmt));
    return out.toOwnedSlice(arena);
}

/// Expiry + read, for a caller that already holds the write transaction.
///
/// The scope guard needs the conflict check and the operation insert to be
/// one atomic step; without this it would have to open a second transaction
/// and reintroduce the race it exists to close.
pub fn conflictForLocked(
    store: *Store,
    arena: Allocator,
    server_id: i64,
    target: Scope,
    owner_token: []const u8,
    now: i64,
) Error!?Lease {
    try store.db.requireTransaction();
    try expireLapsedLocked(store, server_id, now);
    for (try activeLocked(store, arena, server_id)) |lease| {
        if (lease.heldBy(owner_token)) continue;
        if (lease.scope().overlaps(target)) return lease;
    }
    return null;
}

/// Currently-held leases on a server (expired ones filtered out and marked).
pub fn active(store: *Store, arena: Allocator, server_id: i64, now: i64) Error![]Lease {
    try store.db.exec("BEGIN IMMEDIATE");
    errdefer store.db.exec("ROLLBACK") catch {};
    try expireLapsedLocked(store, server_id, now);
    const list = try activeLocked(store, arena, server_id);
    try store.db.exec("COMMIT");
    return list;
}

/// How many leases on this server are still held, after the lazy expiry pass.
///
/// The barrier `servers.remove` refuses over. `leases.server_id` is
/// `ON DELETE CASCADE`, so deleting the host does not merely un-scope the
/// leases the way it un-scopes operations — it destroys them, together with the
/// `superseded_by` chain that is the only record of who held what. A peer
/// session mid-deploy would find its claim gone with nothing saying where it
/// went.
///
/// The expiry pass runs first, and has to: without it a lease whose owner died
/// hours ago would block the removal for as long as the row sat there
/// un-swept, which is a trap with no way out rather than a barrier. After it,
/// what is left is what is genuinely still claimed.
///
/// Caller must hold the write transaction — both because the expiry pass
/// writes, and because a count taken outside it describes a moment that has
/// already passed by the time the DELETE runs.
pub fn activeCountLocked(store: *Store, server_id: i64, now: i64) Db.Error!i64 {
    try store.db.requireTransaction();
    try expireLapsedLocked(store, server_id, now);
    var stmt = try store.db.prepare(
        "SELECT COUNT(*) FROM leases WHERE server_id = ?1 AND released_at IS NULL",
    );
    defer stmt.deinit();
    try stmt.bindInt(1, server_id);
    if (!try stmt.step()) return error.Sqlite;
    return stmt.columnInt(0);
}

/// The lease blocking `scope`, if a *different* owner holds an overlapping
/// one. This is what the write-operation guard calls.
pub fn conflictFor(
    store: *Store,
    arena: Allocator,
    server_id: i64,
    scope: Scope,
    owner_token: []const u8,
    now: i64,
) Error!?Lease {
    const held = try active(store, arena, server_id, now);
    for (held) |lease| {
        if (lease.heldBy(owner_token)) continue;
        if (lease.scope().overlaps(scope)) return lease;
    }
    return null;
}

pub fn acquire(store: *Store, arena: Allocator, opts: AcquireOptions) Error!AcquireOutcome {
    try store.db.exec("BEGIN IMMEDIATE");
    errdefer store.db.exec("ROLLBACK") catch {};

    try expireLapsedLocked(store, opts.server_id, opts.now);
    const held = try activeLocked(store, arena, opts.server_id);

    // An overlapping lease held by someone else blocks us outright.
    for (held) |lease| {
        if (!lease.heldBy(opts.owner_token) and lease.scope().overlaps(opts.scope)) {
            try store.db.exec("COMMIT"); // the expiry pass is worth keeping
            return .{ .conflict = lease };
        }
    }
    // Our own overlapping lease is a renewal, which is how a long operation
    // holds its scope without a second row per heartbeat.
    for (held) |lease| {
        if (lease.heldBy(opts.owner_token) and lease.scope().overlaps(opts.scope)) {
            const renewed = try renewLocked(store, arena, lease.id, opts.ttl_secs, opts.now);
            try store.db.exec("COMMIT");
            return .{ .renewed = renewed };
        }
    }

    const lease = try insertLocked(store, arena, opts, &.{});
    try store.db.exec("COMMIT");
    return .{ .acquired = lease };
}

/// Inserts the new row and links every row it displaced to it.
///
/// `supersedes` is a list rather than one id because a takeover can displace
/// more than one lease at a time: two non-overlapping leases are legal, and a
/// third scope containing both overlaps them both. Every displaced row is
/// linked, so the audit chain is complete for each of them rather than for
/// whichever one happened to be looked at first.
fn insertLocked(store: *Store, arena: Allocator, opts: AcquireOptions, supersedes: []const i64) Error!Lease {
    var stmt = try store.db.prepare(
        \\INSERT INTO leases (server_id, scope_kind, scope_key, owner_token,
        \\                    owner_label, note, request_id,
        \\                    acquired_at, renewed_at, expires_at)
        \\VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, ?9)
    );
    defer stmt.deinit();
    try stmt.bindInt(1, opts.server_id);
    try stmt.bindText(2, @tagName(opts.scope.kind));
    try stmt.bindText(3, opts.scope.key);
    try stmt.bindText(4, opts.owner_token);
    try stmt.bindOptText(5, opts.owner_label);
    try stmt.bindOptText(6, opts.note);
    try stmt.bindOptText(7, opts.request_id);
    try stmt.bindInt(8, opts.now);
    try stmt.bindInt(9, opts.now + opts.ttl_secs);
    _ = try stmt.step();
    const id = store.db.lastInsertRowId();

    // One statement per displaced row. `Db.Stmt` has no `reset`, and adding
    // one to bind a second set of parameters to a live statement is a change to
    // the sqlite wrapper for a loop that runs over the handful of leases a
    // single scope can overlap.
    for (supersedes) |old_id| {
        var link = try store.db.prepare("UPDATE leases SET superseded_by = ?1 WHERE id = ?2");
        defer link.deinit();
        try link.bindInt(1, id);
        try link.bindInt(2, old_id);
        _ = try link.step();
    }

    return .{
        .id = id,
        .server_id = opts.server_id,
        .scope_kind = opts.scope.kind,
        .scope_key = try arena.dupe(u8, opts.scope.key),
        .owner_token = try arena.dupe(u8, opts.owner_token),
        .owner_label = if (opts.owner_label) |v| try arena.dupe(u8, v) else null,
        .note = if (opts.note) |v| try arena.dupe(u8, v) else null,
        .request_id = if (opts.request_id) |v| try arena.dupe(u8, v) else null,
        .acquired_at = opts.now,
        .renewed_at = opts.now,
        .expires_at = opts.now + opts.ttl_secs,
    };
}

fn renewLocked(store: *Store, arena: Allocator, id: i64, ttl_secs: i64, now: i64) Error!Lease {
    var stmt = try store.db.prepare(
        "UPDATE leases SET renewed_at = ?1, expires_at = ?2 WHERE id = ?3",
    );
    defer stmt.deinit();
    try stmt.bindInt(1, now);
    try stmt.bindInt(2, now + ttl_secs);
    try stmt.bindInt(3, id);
    _ = try stmt.step();

    var read = try store.db.prepare(select_columns ++ " WHERE id = ?1");
    defer read.deinit();
    try read.bindInt(1, id);
    if (!try read.step()) return error.Sqlite;
    return try rowToLease(arena, &read);
}

/// Extends an operation's own lease. Returns false when the lease is gone
/// (expired and taken over): a lost lease must be *visible*, not silently
/// re-acquired underneath a peer.
pub fn renew(store: *Store, server_id: i64, scope: Scope, owner_token: []const u8, ttl_secs: i64, now: i64) Error!bool {
    var stmt = try store.db.prepare(
        \\UPDATE leases SET renewed_at = ?1, expires_at = ?2
        \\ WHERE server_id = ?3 AND scope_kind = ?4 AND scope_key = ?5
        \\   AND owner_token = ?6 AND released_at IS NULL AND expires_at > ?1
    );
    defer stmt.deinit();
    try stmt.bindInt(1, now);
    try stmt.bindInt(2, now + ttl_secs);
    try stmt.bindInt(3, server_id);
    try stmt.bindText(4, @tagName(scope.kind));
    try stmt.bindText(5, scope.key);
    try stmt.bindText(6, owner_token);
    _ = try stmt.step();
    return store.db.changes() > 0;
}

/// Releases our own lease. Returns false when we did not hold it.
pub fn release(
    store: *Store,
    server_id: i64,
    scope: Scope,
    owner_token: []const u8,
    reason: ReleaseReason,
    now: i64,
) Error!bool {
    var stmt = try store.db.prepare(
        \\UPDATE leases SET released_at = ?1, release_reason = ?2
        \\ WHERE server_id = ?3 AND scope_kind = ?4 AND scope_key = ?5
        \\   AND owner_token = ?6 AND released_at IS NULL
    );
    defer stmt.deinit();
    try stmt.bindInt(1, now);
    try stmt.bindText(2, reason.text());
    try stmt.bindInt(3, server_id);
    try stmt.bindText(4, @tagName(scope.kind));
    try stmt.bindText(5, scope.key);
    try stmt.bindText(6, owner_token);
    _ = try stmt.step();
    return store.db.changes() > 0;
}

/// A takeover displaced a lease that was read as active a few statements
/// earlier under this transaction's own write lock, and the release matched no
/// row.
///
/// The same shape of impossibility as `servers.ServerVanishedDuringRemoval`,
/// and named for the same reason: nothing on this connection can have released
/// that lease in between, so a zero-row UPDATE is not "somebody got there
/// first" — it is proof the write lock is not doing what the rest of this
/// function assumes. Continuing would insert the new lease and report a
/// takeover of a row whose release never happened.
///
/// Declared on `takeover` alone rather than folded into `Error`: widening the
/// module's error set would reach every lease caller for a condition only this
/// function can produce.
pub const TakeoverError = Error || error{LeaseVanishedDuringTakeover};

pub const TakeoverOutcome = union(enum) {
    /// Took it from every lease that overlapped `scope`. Each row in `from` now
    /// records `takeover` as its release reason and links to `lease` through
    /// `superseded_by`.
    ///
    /// `from` is a list and not a single lease because more than one can be
    /// displaced at once: `acquire` only refuses overlaps, so two leases that do
    /// not overlap *each other* — `path:/srv/app/dist` and `path:/srv/app/build`
    /// — are both legally held, and a takeover of `path:/srv/app` contains both.
    /// A caller told about one of them would read "I displaced one owner" off a
    /// transaction that displaced two, and would notify half the peers it just
    /// took work away from. Newest first, the order `activeLocked` returns.
    ///
    /// Never empty in this variant: nothing displaced is `acquired`.
    taken: struct { lease: Lease, from: []const Lease },
    /// Nothing was held; a plain acquisition happened instead.
    acquired: Lease,
};

/// Deliberately seizes a scope, displacing every lease that overlaps it.
///
/// *Every* one, in this transaction, is the substance of the function. The
/// overlap relation is not one-to-one — `acquire` refuses an overlapping lease
/// but permits any number of mutually non-overlapping ones, so a scope wide
/// enough to contain several of them is ordinary rather than exotic. Stopping
/// at the first match released one incumbent and inserted the new lease beside
/// the rest, and nothing downstream objected: the partial unique index is on
/// `(server_id, scope_kind, scope_key)` exactly, so `path:/srv/app` and the
/// `path:/srv/app/build` it now overlapped were two different keys and the
/// transaction committed clean, holding the state the whole file exists to
/// prevent.
///
/// Each displaced row is released with `takeover` and linked via
/// `superseded_by`, so the audit chain shows who displaced whom and when — for
/// all of them. Dropping the second row's link would leave a lease that ends
/// with no successor recorded, which reads as an expiry rather than as a
/// seizure.
pub fn takeover(store: *Store, arena: Allocator, opts: AcquireOptions) TakeoverError!TakeoverOutcome {
    try store.db.exec("BEGIN IMMEDIATE");
    errdefer store.db.exec("ROLLBACK") catch {};

    try expireLapsedLocked(store, opts.server_id, opts.now);
    const held = try activeLocked(store, arena, opts.server_id);

    var displaced: std.ArrayList(Lease) = .empty;
    var displaced_ids: std.ArrayList(i64) = .empty;
    for (held) |lease| {
        if (!lease.scope().overlaps(opts.scope)) continue;
        try displaced.append(arena, lease);
        try displaced_ids.append(arena, lease.id);
    }

    for (displaced.items) |old| {
        var stmt = try store.db.prepare(
            \\UPDATE leases SET released_at = ?1, release_reason = 'takeover'
            \\ WHERE id = ?2 AND released_at IS NULL
        );
        defer stmt.deinit();
        try stmt.bindInt(1, opts.now);
        try stmt.bindInt(2, old.id);
        _ = try stmt.step();
        // `released_at IS NULL` is in the WHERE so this check has something to
        // catch: the row was read as active under this lock, so a release that
        // matches nothing means the lock did not hold.
        if (store.db.changes() == 0) return error.LeaseVanishedDuringTakeover;
    }

    const fresh = try insertLocked(store, arena, opts, displaced_ids.items);
    try store.db.exec("COMMIT");
    if (displaced.items.len == 0) return .{ .acquired = fresh };
    return .{ .taken = .{
        .lease = fresh,
        .from = try displaced.toOwnedSlice(arena),
    } };
}
