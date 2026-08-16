//! Ownership leases (`leases`), so two agent sessions do not retry, restart
//! or rewrite the same thing at once.
//!
//! **A lease is held by one attempt, named by its `request_id`.** Until v12 it
//! was held by `policy.ownerToken`, a token minted once per machine profile and
//! reused forever — so every agent, editor and terminal on one machine was the
//! same owner, and `acquire` reads its own owner's overlap as a renewal. Two
//! concurrent sessions therefore never conflicted: they renewed each other's
//! locks, and the layer that exists to isolate peers isolated nothing. The
//! profile token is still written on every row as `profile_token`, and is now
//! purely the audit subject — who the machine was. It decides nothing.
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
//! A fourth property is enforced here in code rather than by the schema, and
//! the difference is deliberate: **a row's own timestamps never go backwards.**
//! `acquired_at <= renewed_at <= released_at` is what makes the audit chain
//! above readable at all — a release recorded before the renewal that preceded
//! it is not a lease anybody can reconstruct a holding period from. Every
//! writer that stamps a time onto an *existing* row checks it against the row
//! as it stands in the same transaction and refuses with
//! `error.LeaseTimestampsOutOfOrder`; see there for why this is not a schema
//! `CHECK` and not a clamp.
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
    /// Who holds it: the `request_id` of the attempt that took it. This — and
    /// only this — decides whether an acquisition renews or conflicts.
    owner_request_id: []const u8,
    /// Which machine profile the holder was running as (`policy.ownerToken`).
    /// Audit subject only: it is written, reported and never compared. Two
    /// attempts on one machine share it, which is exactly why it cannot be the
    /// thing a conflict is decided by.
    profile_token: []const u8,
    owner_label: ?[]const u8,
    note: ?[]const u8,
    acquired_at: i64,
    renewed_at: i64,
    expires_at: i64,

    pub fn scope(l: Lease) Scope {
        return .{ .kind = l.scope_kind, .key = l.scope_key };
    }

    pub fn heldBy(l: Lease, owner_request_id: []const u8) bool {
        return std.mem.eql(u8, l.owner_request_id, owner_request_id);
    }
};

pub const Error = Db.Error || error{
    UnknownScopeKind,
    OutOfMemory,
    /// A lease operation was handed an empty owner.
    ///
    /// Named rather than left to the schema's `CHECK`, because only the two
    /// writers reach that CHECK: `conflictFor`, `renew` and `release` compare
    /// the owner instead, and an empty one there silently matches every other
    /// empty one — which is v11's "everybody is the same owner" defect
    /// reappearing one column narrower. A caller with no attempt id has nothing
    /// to hold a lease as, and that is a bug in the caller, not a conflict.
    EmptyLeaseOwner,
};

/// A write would have stamped a lease row with a time earlier than one the row
/// already carries.
///
/// **Three facts a caller has to be able to tell apart**, and this is the
/// third. `release` and `renew` answer `false` when the UPDATE matched nothing
/// — the claim was never ours, or a peer took it over, or it had already been
/// given back. They answer `Db.Error` when the database could not be reached or
/// refused the statement. And they answer *this* when the row was found, was
/// ours, and the timestamp about to be written contradicts the ones already on
/// it. Losing a claim, failing to reach the store, and writing a self-
/// contradictory row send an operator to three different places; a `bool` or a
/// bare `error.Sqlite` would send them to one.
///
/// **Not a clamp.** Raising the stamp to whichever of `acquired_at` /
/// `renewed_at` is larger would write a *plausible* number over a real defect:
/// the row would read as a lease held for zero seconds, or for exactly as long
/// as the clamp invented, and nothing downstream could ever tell that the
/// caller's clock had been wrong. That is precisely the shape the error-handling
/// rules forbid — a failed path made to look like a successful one. The defect
/// this exists to catch produced exactly such a row on every `job kill` and
/// `job rm`: the release was stamped with the process's *start* time, so
/// `released_at` equalled `acquired_at` (a zero-second holding period, always)
/// and preceded the `renewed_at` that provably happened before it.
///
/// **Not a schema `CHECK`, trigger, index or migration** — considered and
/// rejected, not overlooked. A CHECK converts the bad row into
/// `error.Constraint` raised by sqlite from inside whichever statement trips
/// it, which for `job kill` is *after* the remote work is done, and which a
/// caller cannot tell apart from a UNIQUE violation. Naming the refusal in Zig
/// puts it in front of the write, keeps it distinguishable, and needs no v13.
pub const OrderingError = error{LeaseTimestampsOutOfOrder};

/// What every lease *writer* can return.
///
/// The readers (`active`, `conflictFor`, `conflictForLocked`,
/// `activeCountLocked`) keep the narrower `Error` on purpose: they stamp
/// nothing of their own, so they cannot produce an ordering refusal, and
/// folding `OrderingError` into `Error` itself would hand the variant to
/// callers that can never see it — the same objection `TakeoverError` records
/// further down for `LeaseVanishedDuringTakeover`.
pub const WriteError = Error || OrderingError;

/// Refuses a stamp that would land before something the row already records.
///
/// `<` and not `<=`. Two writes inside one wall-clock second are ordinary — a
/// `job kill` over a warm connection to a fast host can acquire, renew and
/// release without the clock ticking over — and a lease whose holding period
/// rounds to zero *whole seconds* is a resolution artifact, not a
/// contradiction. What is a contradiction is a release stamped before the
/// renewal that provably preceded it, and that is what this catches.
///
/// Both columns are compared, not just `renewed_at`. They are equal on a lease
/// that was never renewed (`insertLocked` binds the same value into both), so
/// checking only one of them would miss the acquire-then-release case — which
/// is the unconditional half of the defect and the half a reader notices.
fn requireForwardStamp(stamp: i64, acquired_at: i64, renewed_at: i64) OrderingError!void {
    if (stamp < acquired_at or stamp < renewed_at) return error.LeaseTimestampsOutOfOrder;
}

pub const AcquireOptions = struct {
    server_id: i64,
    scope: Scope,
    /// The attempt taking the lease. Identity; see `Lease.owner_request_id`.
    owner_request_id: []const u8,
    /// The machine profile it is running as. Audit only; see
    /// `Lease.profile_token`.
    profile_token: []const u8,
    owner_label: ?[]const u8 = null,
    note: ?[]const u8 = null,
    ttl_secs: i64,
    now: i64,
};

/// Refuses an owner that names nobody, before it can be compared to anything.
fn requireOwner(owner_request_id: []const u8) error{EmptyLeaseOwner}!void {
    if (owner_request_id.len == 0) return error.EmptyLeaseOwner;
}

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
    \\SELECT id, server_id, scope_kind, scope_key, owner_request_id, profile_token,
    \\       owner_label, note, acquired_at, renewed_at, expires_at
    \\FROM leases
;

fn rowToLease(arena: Allocator, stmt: *Db.Stmt) Error!Lease {
    return .{
        .id = stmt.columnInt(0),
        .server_id = stmt.columnInt(1),
        .scope_kind = try ScopeKind.parse(stmt.columnText(2)),
        .scope_key = try arena.dupe(u8, stmt.columnText(3)),
        .owner_request_id = try arena.dupe(u8, stmt.columnText(4)),
        .profile_token = try arena.dupe(u8, stmt.columnText(5)),
        .owner_label = if (stmt.columnOptText(6)) |v| try arena.dupe(u8, v) else null,
        .note = if (stmt.columnOptText(7)) |v| try arena.dupe(u8, v) else null,
        .acquired_at = stmt.columnInt(8),
        .renewed_at = stmt.columnInt(9),
        .expires_at = stmt.columnInt(10),
    };
}

/// Marks every lapsed lease on the server as expired. Caller holds the write
/// transaction. Lazy expiry keeps a dead session from blocking a scope while
/// still leaving the row as evidence that a lease once existed.
///
/// The one writer of `released_at` that carries no `requireForwardStamp` call,
/// because it cannot need one: it only touches rows where `expires_at <= now`,
/// every writer in this file keeps `expires_at = renewed_at + ttl_secs`, and
/// `renewed_at >= acquired_at` on every row — so `now >= renewed_at >=
/// acquired_at` holds by arithmetic for any non-negative TTL rather than by
/// luck. Guarding it would also mean turning one bulk UPDATE into a row scan;
/// guarding it *by adding the comparison to the WHERE* would be worse still,
/// since a row silently left un-expired is the silent no-op the whole
/// `OrderingError` design refuses.
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
    owner_request_id: []const u8,
    now: i64,
) Error!?Lease {
    try requireOwner(owner_request_id);
    try store.db.requireTransaction();
    try expireLapsedLocked(store, server_id, now);
    for (try activeLocked(store, arena, server_id)) |lease| {
        if (lease.heldBy(owner_request_id)) continue;
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

/// The lease blocking `scope`, if a *different* attempt holds an overlapping
/// one. This is what the write-operation guard calls.
pub fn conflictFor(
    store: *Store,
    arena: Allocator,
    server_id: i64,
    scope: Scope,
    owner_request_id: []const u8,
    now: i64,
) Error!?Lease {
    try requireOwner(owner_request_id);
    const held = try active(store, arena, server_id, now);
    for (held) |lease| {
        if (lease.heldBy(owner_request_id)) continue;
        if (lease.scope().overlaps(scope)) return lease;
    }
    return null;
}

pub fn acquire(store: *Store, arena: Allocator, opts: AcquireOptions) WriteError!AcquireOutcome {
    try requireOwner(opts.owner_request_id);
    try store.db.exec("BEGIN IMMEDIATE");
    errdefer store.db.exec("ROLLBACK") catch {};

    try expireLapsedLocked(store, opts.server_id, opts.now);
    const held = try activeLocked(store, arena, opts.server_id);

    // An overlapping lease held by another attempt blocks us outright.
    for (held) |lease| {
        if (!lease.heldBy(opts.owner_request_id) and lease.scope().overlaps(opts.scope)) {
            try store.db.exec("COMMIT"); // the expiry pass is worth keeping
            return .{ .conflict = lease };
        }
    }
    // Our own overlapping lease is a renewal, which is how a long operation
    // holds its scope without a second row per heartbeat. "Our own" means the
    // same `request_id` — one attempt — and not merely the same machine.
    for (held) |lease| {
        if (lease.heldBy(opts.owner_request_id) and lease.scope().overlaps(opts.scope)) {
            const renewed = try renewLocked(store, arena, lease, opts.ttl_secs, opts.now);
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
        \\INSERT INTO leases (server_id, scope_kind, scope_key, owner_request_id,
        \\                    profile_token, owner_label, note,
        \\                    acquired_at, renewed_at, expires_at)
        \\VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, ?9)
    );
    defer stmt.deinit();
    try stmt.bindInt(1, opts.server_id);
    try stmt.bindText(2, @tagName(opts.scope.kind));
    try stmt.bindText(3, opts.scope.key);
    try stmt.bindText(4, opts.owner_request_id);
    try stmt.bindText(5, opts.profile_token);
    try stmt.bindOptText(6, opts.owner_label);
    try stmt.bindOptText(7, opts.note);
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
        .owner_request_id = try arena.dupe(u8, opts.owner_request_id),
        .profile_token = try arena.dupe(u8, opts.profile_token),
        .owner_label = if (opts.owner_label) |v| try arena.dupe(u8, v) else null,
        .note = if (opts.note) |v| try arena.dupe(u8, v) else null,
        .acquired_at = opts.now,
        .renewed_at = opts.now,
        .expires_at = opts.now + opts.ttl_secs,
    };
}

/// Extends one already-read lease row. Caller holds the write transaction.
///
/// Takes the `Lease` rather than its id so the ordering guard travels with the
/// write instead of sitting at the one call site that currently remembers it.
/// The values it compares are the row *as it stands in this transaction*:
/// `activeLocked` read them under this same `BEGIN IMMEDIATE`, after the expiry
/// pass, and nothing between there and here writes. A guard fed by a separate
/// read outside the lock would be a guard another connection can step over
/// between the check and the write, which is not a guard.
fn renewLocked(store: *Store, arena: Allocator, lease: Lease, ttl_secs: i64, now: i64) WriteError!Lease {
    try store.db.requireTransaction();
    try requireForwardStamp(now, lease.acquired_at, lease.renewed_at);

    var stmt = try store.db.prepare(
        "UPDATE leases SET renewed_at = ?1, expires_at = ?2 WHERE id = ?3",
    );
    defer stmt.deinit();
    try stmt.bindInt(1, now);
    try stmt.bindInt(2, now + ttl_secs);
    try stmt.bindInt(3, lease.id);
    _ = try stmt.step();

    var read = try store.db.prepare(select_columns ++ " WHERE id = ?1");
    defer read.deinit();
    try read.bindInt(1, lease.id);
    if (!try read.step()) return error.Sqlite;
    return try rowToLease(arena, &read);
}

/// Extends an attempt's own lease. Returns false when the lease is gone
/// (expired and taken over): a lost lease must be *visible*, not silently
/// re-acquired underneath a peer.
///
/// Runs inside `BEGIN IMMEDIATE` even though the write is a single statement,
/// and that is the point rather than an accident. The ordering guard has to see
/// the row the UPDATE is about to hit — same predicate, same instant — and a
/// SELECT taken outside a transaction describes a row a peer may already have
/// renewed or released by the time the UPDATE lands. Refusing on stale
/// evidence, or writing a contradictory stamp because the evidence went stale
/// the other way, are both worse than the single held write lock this costs.
pub fn renew(store: *Store, server_id: i64, scope: Scope, owner_request_id: []const u8, ttl_secs: i64, now: i64) WriteError!bool {
    try requireOwner(owner_request_id);
    try store.db.exec("BEGIN IMMEDIATE");
    errdefer store.db.exec("ROLLBACK") catch {};

    // Exactly the rows the UPDATE below will match, read under its own lock.
    // The `expires_at > ?1` half matters: a lapsed row is not renewable at all,
    // so raising an ordering refusal for one would report a contradiction about
    // a write that was never going to happen.
    {
        var read = try store.db.prepare(
            \\SELECT acquired_at, renewed_at FROM leases
            \\ WHERE server_id = ?2 AND scope_kind = ?3 AND scope_key = ?4
            \\   AND owner_request_id = ?5 AND released_at IS NULL AND expires_at > ?1
        );
        defer read.deinit();
        try read.bindInt(1, now);
        try read.bindInt(2, server_id);
        try read.bindText(3, @tagName(scope.kind));
        try read.bindText(4, scope.key);
        try read.bindText(5, owner_request_id);
        while (try read.step())
            try requireForwardStamp(now, read.columnInt(0), read.columnInt(1));
    }

    var stmt = try store.db.prepare(
        \\UPDATE leases SET renewed_at = ?1, expires_at = ?2
        \\ WHERE server_id = ?3 AND scope_kind = ?4 AND scope_key = ?5
        \\   AND owner_request_id = ?6 AND released_at IS NULL AND expires_at > ?1
    );
    defer stmt.deinit();
    try stmt.bindInt(1, now);
    try stmt.bindInt(2, now + ttl_secs);
    try stmt.bindInt(3, server_id);
    try stmt.bindText(4, @tagName(scope.kind));
    try stmt.bindText(5, scope.key);
    try stmt.bindText(6, owner_request_id);
    _ = try stmt.step();
    const renewed = store.db.changes() > 0;
    try store.db.exec("COMMIT");
    return renewed;
}

/// Releases our own lease. Returns false when we did not hold it.
///
/// Same `BEGIN IMMEDIATE` shape, and for the same reason, as `renew` above:
/// the guard reads the row the UPDATE is about to stamp, under the lock that
/// stops it moving in between. Note what the two answers mean — `false` is
/// "no such row was ours to give back", `error.LeaseTimestampsOutOfOrder` is
/// "the row is ours and this stamp contradicts it". A caller that collapsed
/// them would report a self-contradictory write as a lost claim.
pub fn release(
    store: *Store,
    server_id: i64,
    scope: Scope,
    owner_request_id: []const u8,
    reason: ReleaseReason,
    now: i64,
) WriteError!bool {
    try requireOwner(owner_request_id);
    try store.db.exec("BEGIN IMMEDIATE");
    errdefer store.db.exec("ROLLBACK") catch {};

    {
        var read = try store.db.prepare(
            \\SELECT acquired_at, renewed_at FROM leases
            \\ WHERE server_id = ?1 AND scope_kind = ?2 AND scope_key = ?3
            \\   AND owner_request_id = ?4 AND released_at IS NULL
        );
        defer read.deinit();
        try read.bindInt(1, server_id);
        try read.bindText(2, @tagName(scope.kind));
        try read.bindText(3, scope.key);
        try read.bindText(4, owner_request_id);
        while (try read.step())
            try requireForwardStamp(now, read.columnInt(0), read.columnInt(1));
    }

    var stmt = try store.db.prepare(
        \\UPDATE leases SET released_at = ?1, release_reason = ?2
        \\ WHERE server_id = ?3 AND scope_kind = ?4 AND scope_key = ?5
        \\   AND owner_request_id = ?6 AND released_at IS NULL
    );
    defer stmt.deinit();
    try stmt.bindInt(1, now);
    try stmt.bindText(2, reason.text());
    try stmt.bindInt(3, server_id);
    try stmt.bindText(4, @tagName(scope.kind));
    try stmt.bindText(5, scope.key);
    try stmt.bindText(6, owner_request_id);
    _ = try stmt.step();
    const released = store.db.changes() > 0;
    try store.db.exec("COMMIT");
    return released;
}

/// The database's own wall clock, in whole Unix seconds.
///
/// Exists because a lease is the one thing in this store that is *compared*
/// against a clock rather than merely stamped with one, and the CLI's `ctx.now`
/// is a single wall-clock read taken at process start. Stamping a release with
/// it produced a row whose `released_at` equalled its `acquired_at` — a holding
/// period of exactly zero seconds on every `job kill` and `job rm` — and, once
/// the renewal started reading a fresh clock, a release recorded *before* the
/// renewal that preceded it.
///
/// Read off the connection rather than from `std.Io`, and that is a deliberate
/// swap of one clock for another: `std.Io.Timestamp.now` needs an `io`, the only
/// `io` reachable from a process-exit hook is `Cli.active_ctx`, and that global
/// is populated by `main` alone. Every in-process caller — including the gates
/// that exist to prove this very behaviour — would find it null and would need a
/// fallback, and the only fallback available is the frozen stamp: the defect
/// back again, in the one place it cannot be observed. Sqlite's `'now'` is the
/// same system clock in UTC, available wherever a `*Store` is, which is
/// everywhere a lease can be written.
pub fn clockSeconds(store: *Store) Db.Error!i64 {
    var stmt = try store.db.prepare("SELECT CAST(strftime('%s', 'now') AS INTEGER)");
    defer stmt.deinit();
    if (!try stmt.step()) return error.Sqlite;
    return stmt.columnInt(0);
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
pub const TakeoverError = WriteError || error{LeaseVanishedDuringTakeover};

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
    try requireOwner(opts.owner_request_id);
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
        // The displaced row's own timestamps, read by `activeLocked` under this
        // transaction's write lock a few statements ago. A takeover writes a
        // `released_at` onto somebody *else's* row, so the stamp it uses is our
        // clock and the row's is theirs — which is exactly the pairing that can
        // go backwards, and exactly why the guard is here as well as in
        // `release`. A `--force` refused by this has sent nothing to the host
        // (`claimJobScope` runs before the connection exists), so the operator
        // loses a retry rather than an action.
        try requireForwardStamp(opts.now, old.acquired_at, old.renewed_at);
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

// ---------------------------------------------------------------------------
// Gates for the timestamp-ordering guard.
//
// They live here rather than in `gates_test.zig` because what they pin is this
// file's own contract — three answers a caller has to be able to tell apart —
// and because the refusal is the sort of thing a future "make the tests pass"
// edit would be tempted to relax into a clamp. A gate sitting next to the
// function it constrains is harder to miss on the way past.
// ---------------------------------------------------------------------------

/// Scratch database under `.zig-cache`, the shape the other store gates use.
///
/// A real store, not a fake: the property under test is what the table holds
/// after a write and what the *next* statement is allowed to write over it,
/// and a fake that answered would be answering for it.
const Scratch = struct {
    io: std.Io,
    threaded: *std.Io.Threaded,
    path: [:0]u8,
    allocator: Allocator,

    const dir = ".zig-cache/tmp";

    fn init(allocator: Allocator, name: []const u8) !Scratch {
        const threaded = try allocator.create(std.Io.Threaded);
        threaded.* = .init(allocator, .{});
        const io = threaded.io();
        std.Io.Dir.cwd().createDirPath(io, dir) catch {};
        const unique = try std.fmt.allocPrint(allocator, "{s}_{d}", .{ name, std.Thread.getCurrentId() });
        defer allocator.free(unique);
        const path = try std.fmt.allocPrintSentinel(allocator, "{s}/{s}.db", .{ dir, unique }, 0);
        var s: Scratch = .{ .io = io, .threaded = threaded, .path = path, .allocator = allocator };
        s.removeFiles();
        return s;
    }

    fn removeFiles(s: *Scratch) void {
        const cwd = std.Io.Dir.cwd();
        cwd.deleteFile(s.io, s.path) catch {};
        for ([_][]const u8{ "-wal", "-shm" }) |suffix| {
            const side = std.fmt.allocPrint(s.allocator, "{s}{s}", .{ s.path, suffix }) catch return;
            defer s.allocator.free(side);
            cwd.deleteFile(s.io, side) catch {};
        }
    }

    fn deinit(s: *Scratch) void {
        s.removeFiles();
        s.allocator.free(s.path);
        s.threaded.deinit();
        s.allocator.destroy(s.threaded);
    }
};

fn seedServer(store: *Store) !void {
    try store.db.exec(
        \\INSERT INTO servers (id, name, host, port, username, created_at, updated_at)
        \\VALUES (1, 'box', '10.0.0.1', 22, 'ubuntu', 100, 100)
    );
}

/// One row's four time columns, read straight off the table.
const Stamps = struct {
    acquired_at: i64,
    renewed_at: i64,
    expires_at: i64,
    released_at: ?i64,

    fn of(store: *Store, owner_request_id: []const u8) !Stamps {
        var stmt = try store.db.prepare(
            \\SELECT acquired_at, renewed_at, expires_at, released_at FROM leases
            \\ WHERE owner_request_id = ?1
        );
        defer stmt.deinit();
        try stmt.bindText(1, owner_request_id);
        if (!try stmt.step()) return error.NoSuchLease;
        return .{
            .acquired_at = stmt.columnInt(0),
            .renewed_at = stmt.columnInt(1),
            .expires_at = stmt.columnInt(2),
            .released_at = stmt.columnOptInt(3),
        };
    }
};

const owner_a: []const u8 = "01AAAAAAAA0123456789ABCDEF";
const owner_b: []const u8 = "01BBBBBBBB0123456789ABCDEF";

// The refusal itself, and — just as important — the two answers it must not be
// confused with. Before this guard existed, `release` had only
// `released_at IS NULL` in its WHERE: a stamp older than the row's own history
// was written without complaint, and the v12 DDL carries no CHECK, trigger or
// index on any time column to catch it afterwards.
test "gate: a release dated before the row's own history is refused, not written and not clamped" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "lease_release_ordering");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    try seedServer(&store);

    const scope: Scope = .{ .kind = .job, .key = "deploy" };
    const opts: AcquireOptions = .{
        .server_id = 1,
        .scope = scope,
        .owner_request_id = owner_a,
        .profile_token = "one-machine",
        .ttl_secs = 100,
        .now = 1000,
    };
    try t.expect((try acquire(&store, arena, opts)) == .acquired);
    try t.expect(try renew(&store, 1, scope, owner_a, 100, 1050));

    // The defect's exact shape: a release stamped from a clock frozen before
    // the renewal that provably preceded it.
    try t.expectError(
        error.LeaseTimestampsOutOfOrder,
        release(&store, 1, scope, owner_a, .released, 1020),
    );

    // Refused means *nothing was written*. A clamp would have left a released
    // row here carrying a plausible date, and no reader could ever have told.
    const after_refusal = try Stamps.of(&store, owner_a);
    try t.expectEqual(@as(?i64, null), after_refusal.released_at);
    try t.expectEqual(@as(i64, 1050), after_refusal.renewed_at);
    try t.expectEqual(@as(usize, 1), (try active(&store, arena, 1, 1060)).len);

    // Distinguishable from "the row is not ours": a peer's release of a scope
    // it never held answers `false`, not an error, even dated in the past.
    // Losing a claim and writing a contradictory row are different facts.
    try t.expect(!try release(&store, 1, scope, owner_b, .released, 1020));

    // Equal is not backwards. Acquire, renew and release inside one wall-clock
    // second is ordinary against a fast host, and a holding period that rounds
    // to zero *whole seconds* is a resolution artifact rather than a
    // contradiction — the guard must not turn it into a refusal.
    try t.expect(try release(&store, 1, scope, owner_a, .released, 1050));
    const settled = try Stamps.of(&store, owner_a);
    try t.expectEqual(@as(?i64, 1050), settled.released_at);
}

test "gate: a renewal that would move a lease's clock backwards is refused" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "lease_renew_ordering");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    try seedServer(&store);

    const scope: Scope = .{ .kind = .job, .key = "deploy" };
    try t.expect((try acquire(&store, arena, .{
        .server_id = 1,
        .scope = scope,
        .owner_request_id = owner_a,
        .profile_token = "one-machine",
        .ttl_secs = 100,
        .now = 1000,
    })) == .acquired);
    try t.expect(try renew(&store, 1, scope, owner_a, 100, 1050));

    try t.expectError(
        error.LeaseTimestampsOutOfOrder,
        renew(&store, 1, scope, owner_a, 100, 1010),
    );
    // `expires_at` too: a backwards renewal would not merely misdate the row,
    // it would *shorten* the lease under its own holder — 1010+100 is before
    // the 1150 a peer is currently being refused until.
    const after_refusal = try Stamps.of(&store, owner_a);
    try t.expectEqual(@as(i64, 1050), after_refusal.renewed_at);
    try t.expectEqual(@as(i64, 1150), after_refusal.expires_at);

    // A lapsed lease is still "not ours to renew" rather than an ordering
    // fault: the UPDATE would match nothing, so reporting a contradiction
    // about a write that was never going to happen would be inventing one.
    try t.expect(!try renew(&store, 1, scope, owner_a, 100, 9000));
    try t.expect(try renew(&store, 1, scope, owner_a, 100, 1050));
}

// `expireLapsedLocked` writes `released_at` too, and is the one such writer
// with no guard on it. This is the confirmation that it does not need one and
// has not been broken into needing one: it only touches rows whose
// `expires_at <= now`, and every writer keeps `expires_at = renewed_at + ttl`,
// so its stamp is after the row's renewal by arithmetic.
test "gate: lazy expiry still releases a lapsed lease, and dates it after the renewal" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "lease_expiry_ordering");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    try seedServer(&store);

    try t.expect((try acquire(&store, arena, .{
        .server_id = 1,
        .scope = .{ .kind = .job, .key = "deploy" },
        .owner_request_id = owner_a,
        .profile_token = "one-machine",
        .ttl_secs = 100,
        .now = 1000,
    })) == .acquired);

    try t.expectEqual(@as(usize, 0), (try active(&store, arena, 1, 5000)).len);
    const swept = try Stamps.of(&store, owner_a);
    try t.expectEqual(@as(?i64, 5000), swept.released_at);
    try t.expect(swept.released_at.? >= swept.renewed_at);
}

// `--force` writes a `released_at` onto somebody else's row, using its own
// clock against their timestamps — the one pairing in this file where the two
// sides come from different processes. Leaving it unguarded would have left the
// whole invariant reachable through one flag.
test "gate: a takeover dated before the lease it seizes is refused, and seizes nothing" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "lease_takeover_ordering");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    try seedServer(&store);

    const scope: Scope = .{ .kind = .job, .key = "deploy" };
    const incumbent: AcquireOptions = .{
        .server_id = 1,
        .scope = scope,
        .owner_request_id = owner_a,
        .profile_token = "peer-machine",
        .ttl_secs = 600,
        .now = 2000,
    };
    try t.expect((try acquire(&store, arena, incumbent)) == .acquired);

    var thief = incumbent;
    thief.owner_request_id = owner_b;
    thief.now = 1500; // a process that started before the incumbent renewed
    try t.expectError(error.LeaseTimestampsOutOfOrder, takeover(&store, arena, thief));

    // The refusal rolled the whole transaction back: the incumbent still holds
    // it, and no half-seized second row was inserted beside it.
    const still_held = try active(&store, arena, 1, 2100);
    try t.expectEqual(@as(usize, 1), still_held.len);
    try t.expectEqualStrings(owner_a, still_held[0].owner_request_id);

    // And a takeover dated after it goes through exactly as before.
    thief.now = 2100;
    const taken = try takeover(&store, arena, thief);
    try t.expectEqual(@as(usize, 1), taken.taken.from.len);
    try t.expectEqualStrings(owner_a, taken.taken.from[0].owner_request_id);
}

// The clock a release is dated from has to be a real one. Reading it off the
// connection is what makes it available from `Cli.releaseClaim`, which runs on
// process-exit paths where no `std.Io` is in reach.
test "gate: the store's clock is a real wall clock, not a stamp somebody passed in" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "lease_clock");
    defer scratch.deinit();

    var store = try Store.open(scratch.path);
    defer store.close();

    // 2024-01-01. A clock that answered 0, or a fixture value, fails here.
    try t.expect((try clockSeconds(&store)) > 1_704_067_200);
}
