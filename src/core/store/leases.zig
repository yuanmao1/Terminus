//! Ownership leases (`leases`), so two agent sessions do not retry, restart
//! or rewrite the same thing at once.
//!
//! Three properties are deliberately enforced by the database rather than by
//! convention:
//!
//! * **One active lease per scope.** A partial unique index on
//!   `(server_id, scope_kind, scope_key) WHERE released_at IS NULL` makes a
//!   double acquisition impossible even under a race.
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
const operations = @import("operations.zig");

pub const ScopeKind = operations.ScopeKind;

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

pub const Scope = struct {
    kind: ScopeKind,
    /// Empty for a whole-server lease; job name or path otherwise.
    key: []const u8 = "",

    /// The conflict matrix.
    ///
    /// * A `server` lease covers everything on that host, so it overlaps any
    ///   other scope.
    /// * `job` scopes overlap only on the same name.
    /// * `path` scopes overlap when one contains the other — holding
    ///   `/srv/app` must block `/srv/app/dist`, otherwise "do not let two
    ///   sessions modify the same directory" would not hold.
    pub fn overlaps(a: Scope, b: Scope) bool {
        if (a.kind == .server or b.kind == .server) return true;
        if (a.kind != b.kind) return false;
        return switch (a.kind) {
            .server => true,
            .job => std.mem.eql(u8, a.key, b.key),
            .path => pathContains(a.key, b.key) or pathContains(b.key, a.key),
        };
    }
};

/// True when `parent` contains `child` (or they are the same path). Compares
/// at separator boundaries so `/srv/app` does not "contain" `/srv/applied`.
fn pathContains(parent: []const u8, child: []const u8) bool {
    const p = std.mem.trimEnd(u8, parent, "/");
    const c = std.mem.trimEnd(u8, child, "/");
    if (p.len == 0) return true; // "/" contains everything
    if (!std.mem.startsWith(u8, c, p)) return false;
    return c.len == p.len or c[p.len] == '/';
}

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

/// Currently-held leases on a server (expired ones filtered out and marked).
pub fn active(store: *Store, arena: Allocator, server_id: i64, now: i64) Error![]Lease {
    try store.db.exec("BEGIN IMMEDIATE");
    errdefer store.db.exec("ROLLBACK") catch {};
    try expireLapsedLocked(store, server_id, now);
    const list = try activeLocked(store, arena, server_id);
    try store.db.exec("COMMIT");
    return list;
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

    const lease = try insertLocked(store, arena, opts, null);
    try store.db.exec("COMMIT");
    return .{ .acquired = lease };
}

fn insertLocked(store: *Store, arena: Allocator, opts: AcquireOptions, supersedes: ?i64) Error!Lease {
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

    if (supersedes) |old_id| {
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

pub const TakeoverOutcome = union(enum) {
    /// Took it from `from`, whose row now records the takeover.
    taken: struct { lease: Lease, from: Lease },
    /// Nothing was held; a plain acquisition happened instead.
    acquired: Lease,
};

/// Deliberately seizes a scope. The incumbent's row is released with
/// `takeover` and linked via `superseded_by`, so the audit chain shows who
/// displaced whom and when — a takeover is never invisible.
pub fn takeover(store: *Store, arena: Allocator, opts: AcquireOptions) Error!TakeoverOutcome {
    try store.db.exec("BEGIN IMMEDIATE");
    errdefer store.db.exec("ROLLBACK") catch {};

    try expireLapsedLocked(store, opts.server_id, opts.now);
    const held = try activeLocked(store, arena, opts.server_id);

    var incumbent: ?Lease = null;
    for (held) |lease| {
        if (lease.scope().overlaps(opts.scope)) {
            incumbent = lease;
            break;
        }
    }

    if (incumbent) |old| {
        var stmt = try store.db.prepare(
            \\UPDATE leases SET released_at = ?1, release_reason = 'takeover'
            \\ WHERE id = ?2
        );
        defer stmt.deinit();
        try stmt.bindInt(1, opts.now);
        try stmt.bindInt(2, old.id);
        _ = try stmt.step();

        const fresh = try insertLocked(store, arena, opts, old.id);
        try store.db.exec("COMMIT");
        return .{ .taken = .{ .lease = fresh, .from = old } };
    }

    const fresh = try insertLocked(store, arena, opts, null);
    try store.db.exec("COMMIT");
    return .{ .acquired = fresh };
}

test "scope overlap matrix" {
    const t = std.testing;
    const server: Scope = .{ .kind = .server };
    const job_a: Scope = .{ .kind = .job, .key = "build" };
    const job_b: Scope = .{ .kind = .job, .key = "deploy" };
    const path_app: Scope = .{ .kind = .path, .key = "/srv/app" };
    const path_dist: Scope = .{ .kind = .path, .key = "/srv/app/dist" };
    const path_other: Scope = .{ .kind = .path, .key = "/srv/applied" };

    // A server lease covers the whole host.
    try t.expect(server.overlaps(job_a));
    try t.expect(job_a.overlaps(server));
    try t.expect(server.overlaps(path_app));

    // Different jobs are independent; different kinds do not collide.
    try t.expect(job_a.overlaps(job_a));
    try t.expect(!job_a.overlaps(job_b));
    try t.expect(!job_a.overlaps(path_app));

    // Holding a directory blocks anything inside it, in both directions.
    try t.expect(path_app.overlaps(path_dist));
    try t.expect(path_dist.overlaps(path_app));
    // ...but not a sibling that merely shares a prefix string.
    try t.expect(!path_app.overlaps(path_other));
}

test pathContains {
    const t = std.testing;
    try t.expect(pathContains("/srv/app", "/srv/app"));
    try t.expect(pathContains("/srv/app", "/srv/app/dist"));
    try t.expect(pathContains("/srv/app/", "/srv/app/dist"));
    try t.expect(!pathContains("/srv/app", "/srv/applied"));
    try t.expect(!pathContains("/srv/app/dist", "/srv/app"));
    // Root contains everything.
    try t.expect(pathContains("/", "/anything"));
}
