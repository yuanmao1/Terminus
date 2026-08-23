//! Host key pins (`host_pins`) — the trust root every connection is checked
//! against.
//!
//! The verification call site is `Ssh.connect`, which takes a trust root as a
//! required argument and refuses before it returns a session. This module is
//! the storage half: it answers what is recorded for a `(host, port, key_type)`
//! and it records what an operator or a first use established. It does not
//! decide anything — `Ssh.judge` compares, in the SSH layer, where no caller
//! can reach past it.
//!
//! Trust model (no interactive prompt — agents have no TTY):
//!
//! * `explicit_pin` — the fingerprint was supplied up front. Strongest.
//! * `first_use` — nothing was known, so the first key seen was recorded.
//!   Honest about what it is: it protects every connection *after* the first,
//!   and it is never implied by the absence of a pin. `terminus server pin
//!   --trust-on-first-use` is the only thing that asks for it.
//! * A mismatch against an active pin is a hard failure, never a prompt and
//!   never an automatic update. Rotation is a deliberate act that supersedes
//!   the old pin and leaves both rows in place.
//!
//! A pin is keyed on `(host, port, key_type)` and not on a server row, and that
//! is a decision the schema made rather than an omission. Two server rows that
//! name the same `host:port` — a second account on one box — share one pin,
//! which is right: the pin describes the machine, not the login. A server whose
//! `host` or `port` is changed has no pin at its new address and is refused
//! until one is recorded there, which is also right: it is a different endpoint
//! and nothing has vouched for it.
//!
//! Private keys are never stored, exported or copied here — only public key
//! fingerprints.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Store = @import("Store.zig");
const Db = @import("Db.zig");

pub const TrustSource = enum {
    explicit_pin,
    first_use,
    rotated,
    imported,

    pub fn parse(raw: []const u8) error{UnknownTrustSource}!TrustSource {
        return std.meta.stringToEnum(TrustSource, raw) orelse error.UnknownTrustSource;
    }

    pub fn text(s: TrustSource) []const u8 {
        return @tagName(s);
    }
};

pub const Pin = struct {
    id: i64,
    host: []const u8,
    port: u16,
    key_type: []const u8,
    /// Base64 SHA-256, formatted the way OpenSSH prints it.
    fingerprint_sha256: []const u8,
    public_key_b64: ?[]const u8,
    trusted_at: i64,
    trust_source: TrustSource,
    note: ?[]const u8,
    /// When trust in this key was withdrawn, and null while it still
    /// authorises. `active` filters on it; `forEndpoint` returns it, because a
    /// row that no longer authorises is exactly what explains a refusal.
    revoked_at: ?i64,
};

pub const Error = Db.Error || error{ UnknownTrustSource, OutOfMemory };

const select_columns =
    \\SELECT id, host, port, key_type, fingerprint_sha256, public_key_b64,
    \\       trusted_at, trust_source, note, revoked_at
    \\FROM host_pins
;

fn rowToPin(arena: Allocator, stmt: *Db.Stmt) Error!Pin {
    return .{
        .id = stmt.columnInt(0),
        .host = try arena.dupe(u8, stmt.columnText(1)),
        .port = @intCast(stmt.columnInt(2)),
        .key_type = try arena.dupe(u8, stmt.columnText(3)),
        .fingerprint_sha256 = try arena.dupe(u8, stmt.columnText(4)),
        .public_key_b64 = if (stmt.columnOptText(5)) |v| try arena.dupe(u8, v) else null,
        .trusted_at = stmt.columnInt(6),
        .trust_source = try TrustSource.parse(stmt.columnText(7)),
        .note = if (stmt.columnOptText(8)) |v| try arena.dupe(u8, v) else null,
        .revoked_at = stmt.columnOptInt(9),
    };
}

/// The active pin for one `(host, port, key_type)`, or null.
///
/// The whole of what this module contributes to a connection's decision, and it
/// is a read: nothing here compares anything. `Ssh.judge` does the comparison,
/// and it is handed the answer to this without ever being able to hand back
/// what it saw — see `Ssh.TrustRoot.Pins.recorded` for why that direction of
/// ignorance is the point.
pub fn active(store: *Store, arena: Allocator, host: []const u8, port: u16, key_type: []const u8) Error!?Pin {
    var stmt = try store.db.prepare(select_columns ++
        " WHERE host = ?1 AND port = ?2 AND key_type = ?3 AND revoked_at IS NULL");
    defer stmt.deinit();
    try stmt.bindText(1, host);
    try stmt.bindInt(2, port);
    try stmt.bindText(3, key_type);
    if (!try stmt.step()) return null;
    return try rowToPin(arena, &stmt);
}

pub const RecordOptions = struct {
    host: []const u8,
    port: u16,
    key_type: []const u8,
    fingerprint_sha256: []const u8,
    public_key_b64: ?[]const u8 = null,
    trust_source: TrustSource,
    note: ?[]const u8 = null,
    now: i64,
};

/// Records a pin. Fails with `error.Constraint` if an active pin already
/// exists for the same host/port/key type — replacing one is `rotate`, which
/// says so out loud.
pub fn record(store: *Store, opts: RecordOptions) Error!i64 {
    var stmt = try store.db.prepare(
        \\INSERT INTO host_pins (host, port, key_type, fingerprint_sha256,
        \\                       public_key_b64, trusted_at, trust_source, note)
        \\VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
    );
    defer stmt.deinit();
    try stmt.bindText(1, opts.host);
    try stmt.bindInt(2, opts.port);
    try stmt.bindText(3, opts.key_type);
    try stmt.bindText(4, opts.fingerprint_sha256);
    try stmt.bindOptText(5, opts.public_key_b64);
    try stmt.bindInt(6, opts.now);
    try stmt.bindText(7, opts.trust_source.text());
    try stmt.bindOptText(8, opts.note);
    _ = try stmt.step();
    return store.db.lastInsertRowId();
}

/// Replaces an active pin with a new key, keeping the old row as evidence and
/// linking the two. Both steps happen in one transaction so a rotation can
/// never leave the host with no pin at all.
pub fn rotate(store: *Store, opts: RecordOptions, reason: []const u8) Error!i64 {
    try store.db.exec("BEGIN IMMEDIATE");
    errdefer store.db.exec("ROLLBACK") catch {};

    var old_id: ?i64 = null;
    {
        var stmt = try store.db.prepare(
            \\SELECT id FROM host_pins
            \\ WHERE host = ?1 AND port = ?2 AND key_type = ?3 AND revoked_at IS NULL
        );
        defer stmt.deinit();
        try stmt.bindText(1, opts.host);
        try stmt.bindInt(2, opts.port);
        try stmt.bindText(3, opts.key_type);
        if (try stmt.step()) old_id = stmt.columnInt(0);
    }

    if (old_id) |id| {
        var stmt = try store.db.prepare(
            "UPDATE host_pins SET revoked_at = ?1, revoke_reason = ?2 WHERE id = ?3",
        );
        defer stmt.deinit();
        try stmt.bindInt(1, opts.now);
        try stmt.bindText(2, reason);
        try stmt.bindInt(3, id);
        _ = try stmt.step();
    }

    var fresh = opts;
    fresh.trust_source = .rotated;
    const new_id = try record(store, fresh);

    if (old_id) |id| {
        var stmt = try store.db.prepare("UPDATE host_pins SET superseded_by = ?1 WHERE id = ?2");
        defer stmt.deinit();
        try stmt.bindInt(1, new_id);
        try stmt.bindInt(2, id);
        _ = try stmt.step();
    }

    try store.db.exec("COMMIT");
    return new_id;
}

/// Withdraws trust from a pin without putting anything in its place.
///
/// The contract's other three verbs cannot do this. A mismatch is a hard
/// failure but changes no row; rotation needs the *new* fingerprint, which an
/// operator who has just learned a key was stolen does not have. Without this
/// the only way to stop trusting a compromised key would be to hand the tool a
/// replacement nobody has, so the answer to "that key is no longer trusted" is
/// this: the row goes inactive, `active` stops returning it, and the host is
/// refused until something is recorded deliberately.
pub fn revoke(store: *Store, id: i64, reason: []const u8, now: i64) Error!bool {
    var stmt = try store.db.prepare(
        "UPDATE host_pins SET revoked_at = ?1, revoke_reason = ?2 WHERE id = ?3 AND revoked_at IS NULL",
    );
    defer stmt.deinit();
    try stmt.bindInt(1, now);
    try stmt.bindText(2, reason);
    try stmt.bindInt(3, id);
    _ = try stmt.step();
    return store.db.changes() > 0;
}

pub fn list(store: *Store, arena: Allocator) Error![]Pin {
    var out: std.ArrayList(Pin) = .empty;
    var stmt = try store.db.prepare(select_columns ++ " WHERE revoked_at IS NULL ORDER BY host, port");
    defer stmt.deinit();
    while (try stmt.step()) try out.append(arena, try rowToPin(arena, &stmt));
    return out.toOwnedSlice(arena);
}

/// Every pin for one endpoint, revoked rows included, newest first.
///
/// The revoked ones are the point: `server pin` shows an operator what this
/// machine has ever trusted for a host, and a superseded or withdrawn key is
/// exactly what somebody investigating a refusal needs to see. `active` is what
/// authorises; this is what explains.
pub fn forEndpoint(store: *Store, arena: Allocator, host: []const u8, port: u16) Error![]Pin {
    var out: std.ArrayList(Pin) = .empty;
    var stmt = try store.db.prepare(select_columns ++
        " WHERE host = ?1 AND port = ?2 ORDER BY trusted_at DESC, id DESC");
    defer stmt.deinit();
    try stmt.bindText(1, host);
    try stmt.bindInt(2, port);
    while (try stmt.step()) try out.append(arena, try rowToPin(arena, &stmt));
    return out.toOwnedSlice(arena);
}
