//! Redaction rules, retention rules, and machine-local identity.
//!
//! Redaction policy: secrets are located by *declaration* first
//! (`--secret-env NAME`, `--secret-arg N`, a header name), with pattern
//! matching kept only as a backstop. Guessing alone is not a security
//! boundary — `history.redactSecrets` catches the common shapes, but a
//! caller that knows where its credentials are should say so.
//!
//! The hard rule this module exists to support: when redaction cannot be
//! applied, the audit record is **refused**, never written in the clear. The
//! caller surfaces `RECEIPT_PERSIST_FAILED` instead of quietly persisting a
//! token.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Store = @import("Store.zig");
const Db = @import("Db.zig");
const ids = @import("ids.zig");

pub const RuleKind = enum {
    /// Environment variable name whose value is a secret.
    env_name,
    /// Positional argv index whose value is a secret.
    arg_index,
    /// HTTP header whose value is a secret (Authorization, Cookie, ...).
    header_name,
    /// An exact string to mask wherever it appears.
    literal,

    pub fn parse(raw: []const u8) error{UnknownRuleKind}!RuleKind {
        return std.meta.stringToEnum(RuleKind, raw) orelse error.UnknownRuleKind;
    }

    pub fn text(k: RuleKind) []const u8 {
        return @tagName(k);
    }
};

pub const Rule = struct {
    id: i64,
    kind: RuleKind,
    pattern: []const u8,
    /// NULL applies everywhere; otherwise scoped to one server.
    server_id: ?i64,
    created_at: i64,
};

pub const Error = Db.Error || error{ UnknownRuleKind, OutOfMemory };

/// Header names that are always treated as secret-bearing, regardless of what
/// the user declared. These leak credentials often enough that opting in
/// would be the wrong default.
pub const builtin_secret_headers = [_][]const u8{
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
};

/// Environment variables masked without being declared.
pub const builtin_secret_env = [_][]const u8{
    "NODE_AUTH_TOKEN",
    "NPM_TOKEN",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "PGPASSWORD",
    "MYSQL_PWD",
};

pub fn isBuiltinSecretHeader(name: []const u8) bool {
    for (builtin_secret_headers) |known| {
        if (std.ascii.eqlIgnoreCase(name, known)) return true;
    }
    return false;
}

pub fn isBuiltinSecretEnv(name: []const u8) bool {
    for (builtin_secret_env) |known| {
        if (std.mem.eql(u8, name, known)) return true;
    }
    return false;
}

pub fn addRule(store: *Store, kind: RuleKind, pattern: []const u8, server_id: ?i64, now: i64) Error!void {
    var stmt = try store.db.prepare(
        \\INSERT INTO redaction_rules (rule_kind, pattern, server_id, created_at)
        \\VALUES (?1, ?2, ?3, ?4)
        \\ON CONFLICT(rule_kind, pattern, server_id) DO NOTHING
    );
    defer stmt.deinit();
    try stmt.bindText(1, kind.text());
    try stmt.bindText(2, pattern);
    try stmt.bindOptInt(3, server_id);
    try stmt.bindInt(4, now);
    _ = try stmt.step();
}

/// Global rules plus those scoped to this server.
pub fn rulesFor(store: *Store, arena: Allocator, server_id: ?i64) Error![]Rule {
    var out: std.ArrayList(Rule) = .empty;
    var stmt = try store.db.prepare(
        \\SELECT id, rule_kind, pattern, server_id, created_at
        \\FROM redaction_rules
        \\WHERE server_id IS NULL OR server_id IS ?1
        \\ORDER BY id
    );
    defer stmt.deinit();
    try stmt.bindOptInt(1, server_id);
    while (try stmt.step()) {
        try out.append(arena, .{
            .id = stmt.columnInt(0),
            .kind = try RuleKind.parse(stmt.columnText(1)),
            .pattern = try arena.dupe(u8, stmt.columnText(2)),
            .server_id = stmt.columnOptInt(3),
            .created_at = stmt.columnInt(4),
        });
    }
    return out.toOwnedSlice(arena);
}

pub fn removeRule(store: *Store, id: i64) Db.Error!bool {
    var stmt = try store.db.prepare("DELETE FROM redaction_rules WHERE id = ?1");
    defer stmt.deinit();
    try stmt.bindInt(1, id);
    _ = try stmt.step();
    return store.db.changes() > 0;
}

/// Retention is opt-in per table; NULL means keep forever. Receipt hashes are
/// meant to be kept indefinitely (they disclose nothing), so this exists for
/// bulky derived data rather than the ledger itself.
pub fn setRetention(store: *Store, table_name: []const u8, keep_days: ?i64, now: i64) Db.Error!void {
    var stmt = try store.db.prepare(
        \\INSERT INTO retention_rules (table_name, keep_days, updated_at)
        \\VALUES (?1, ?2, ?3)
        \\ON CONFLICT(table_name) DO UPDATE SET keep_days = ?2, updated_at = ?3
    );
    defer stmt.deinit();
    try stmt.bindText(1, table_name);
    try stmt.bindOptInt(2, keep_days);
    try stmt.bindInt(3, now);
    _ = try stmt.step();
}

pub fn retention(store: *Store, table_name: []const u8) Db.Error!?i64 {
    var stmt = try store.db.prepare("SELECT keep_days FROM retention_rules WHERE table_name = ?1");
    defer stmt.deinit();
    try stmt.bindText(1, table_name);
    if (!try stmt.step()) return null;
    return stmt.columnOptInt(0);
}

const owner_token_key = "owner_token";

/// The stable identity a lease is held under.
///
/// It must survive across processes: a host-pid string changes every
/// invocation, so an agent could never renew or release its own lease, and
/// "same owner renews, different owner conflicts" would be meaningless. The
/// token is minted once per machine-profile and reused thereafter.
pub fn ownerToken(store: *Store, arena: Allocator, io: std.Io, now: i64) Error![]const u8 {
    if (try localIdentity(store, arena, owner_token_key)) |existing| return existing;

    const minted = ids.generate(io);
    try setLocalIdentity(store, owner_token_key, &minted, now);
    // Re-read rather than returning what we minted: a peer may have won the
    // insert, and both of us must end up using the same token.
    return (try localIdentity(store, arena, owner_token_key)) orelse arena.dupe(u8, &minted);
}

pub fn localIdentity(store: *Store, arena: Allocator, key: []const u8) Error!?[]const u8 {
    var stmt = try store.db.prepare("SELECT value FROM local_identity WHERE key = ?1");
    defer stmt.deinit();
    try stmt.bindText(1, key);
    if (!try stmt.step()) return null;
    return try arena.dupe(u8, stmt.columnText(0));
}

pub fn setLocalIdentity(store: *Store, key: []const u8, value: []const u8, now: i64) Db.Error!void {
    var stmt = try store.db.prepare(
        \\INSERT INTO local_identity (key, value, created_at) VALUES (?1, ?2, ?3)
        \\ON CONFLICT(key) DO NOTHING
    );
    defer stmt.deinit();
    try stmt.bindText(1, key);
    try stmt.bindText(2, value);
    try stmt.bindInt(3, now);
    _ = try stmt.step();
}

test "builtin secret classification" {
    const t = std.testing;
    // Header matching is case-insensitive: HTTP headers are.
    try t.expect(isBuiltinSecretHeader("Authorization"));
    try t.expect(isBuiltinSecretHeader("authorization"));
    try t.expect(isBuiltinSecretHeader("Cookie"));
    try t.expect(!isBuiltinSecretHeader("Content-Type"));

    // Env names are case-sensitive: PATH and Path are different variables.
    try t.expect(isBuiltinSecretEnv("NODE_AUTH_TOKEN"));
    try t.expect(isBuiltinSecretEnv("PGPASSWORD"));
    try t.expect(!isBuiltinSecretEnv("PATH"));
    try t.expect(!isBuiltinSecretEnv("node_auth_token"));
}
