//! Host key pins (`host_pins`) — the trust root that must exist *before* any
//! "pinned" interface is offered.
//!
//! Terminus currently performs no host key verification at all: `Ssh.connect`
//! completes the handshake and returns. Every connection is therefore
//! trust-on-every-use and MITM-able. This module is the storage half of
//! closing that gap; the verification call site lands with the SSH work.
//!
//! Trust model (no interactive prompt — agents have no TTY):
//!
//! * `explicit_pin` — the fingerprint was supplied up front. Strongest.
//! * `first_use` — nothing was known, so the first key seen was recorded.
//!   Honest about what it is: it protects every connection *after* the first.
//! * A mismatch against an active pin is a hard failure, never a prompt and
//!   never an automatic update. Rotation is a deliberate act that supersedes
//!   the old pin and leaves both rows in place.
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
};

pub const Error = Db.Error || error{ UnknownTrustSource, OutOfMemory };

pub const Verdict = union(enum) {
    /// Key matches the active pin.
    match: Pin,
    /// A pin exists and the key is different. Always fatal at the call site.
    mismatch: struct { expected: Pin, observed_fingerprint: []const u8 },
    /// No pin recorded for this host/port/key type yet.
    unknown,
};

const select_columns =
    \\SELECT id, host, port, key_type, fingerprint_sha256, public_key_b64,
    \\       trusted_at, trust_source, note
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
    };
}

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

/// Compares an observed key against the active pin. Never mutates: recording
/// a first-use pin is a separate, explicit call so "we just trusted something
/// new" is always a deliberate step in the caller.
pub fn verify(
    store: *Store,
    arena: Allocator,
    host: []const u8,
    port: u16,
    key_type: []const u8,
    observed_fingerprint: []const u8,
) Error!Verdict {
    const pin = (try active(store, arena, host, port, key_type)) orelse return .unknown;
    if (std.mem.eql(u8, pin.fingerprint_sha256, observed_fingerprint)) return .{ .match = pin };
    return .{ .mismatch = .{ .expected = pin, .observed_fingerprint = try arena.dupe(u8, observed_fingerprint) } };
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

/// Formats a raw host key hash the way OpenSSH does: `SHA256:` + unpadded
/// base64, so a fingerprint can be compared against `ssh-keyscan` output by
/// eye without conversion.
pub fn formatFingerprint(arena: Allocator, sha256_digest: [32]u8) Allocator.Error![]u8 {
    const encoder = std.base64.standard_no_pad.Encoder;
    const encoded_len = encoder.calcSize(sha256_digest.len);
    const out = try arena.alloc(u8, "SHA256:".len + encoded_len);
    @memcpy(out[0.."SHA256:".len], "SHA256:");
    _ = encoder.encode(out["SHA256:".len..], &sha256_digest);
    return out;
}

test formatFingerprint {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("terminus", &digest, .{});
    const text = try formatFingerprint(arena_state.allocator(), digest);

    try t.expect(std.mem.startsWith(u8, text, "SHA256:"));
    // OpenSSH prints unpadded base64; a trailing '=' would not match.
    try t.expect(std.mem.indexOfScalar(u8, text, '=') == null);
    try t.expectEqual(@as(usize, "SHA256:".len + 43), text.len);
}
