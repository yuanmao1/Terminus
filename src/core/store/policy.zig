//! Builtin secret classification, and machine-local identity.
//!
//! ## What redaction actually is
//!
//! There is one redactor: `history.redactSecrets`. Every command that writes
//! to the operations ledger runs its command text through it to produce
//! `argv_redacted` (`cmd_exec`, `cmd_job` ×2, `cmd_read_write`,
//! `cmd_transfer`), and so does `history.add`. This module owns the two lists
//! it consults — the header names and environment variable names that are
//! treated as secret-bearing without anybody declaring them.
//!
//! The hard rule the five ledger call sites hold: when redaction cannot be
//! applied, the audit record is **refused**, never written in the clear. Each
//! of them calls `fatal` rather than fall back to the raw text. `history.add`
//! is the exception and says so at the fallback — it stores the raw detail on
//! OOM. That asymmetry predates this change and is left as it was.
//!
//! ## What is not implemented
//!
//! Declaration-first redaction. This header used to claim secrets were located
//! by declaration first — `--secret-env NAME`, `--secret-arg N`, a header name
//! — "with pattern matching kept only as a backstop". No such flag exists, and
//! the `redaction_rules` CRUD that would have stored those declarations
//! (`addRule` / `rulesFor` / `removeRule`) had no caller and no test in any
//! build; the same was true of `setRetention` / `retention`, and nothing prunes
//! anything on a schedule. Those seven functions and the `RuleKind` vocabulary
//! are gone. **The backstop is all there is**, and saying otherwise invited a
//! reader to plan around a boundary that was not there.
//!
//! The `redaction_rules` and `retention_rules` tables stay (`migrate.zig` v7).
//! `redaction_rules` is counted by `servers.serverCounts` and is part of
//! `server rm`'s cascade disclosure, so it is load-bearing to the schema gates
//! even with no writer; whoever builds the declaration path writes against the
//! table rather than against a guess at its API.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Store = @import("Store.zig");
const Db = @import("Db.zig");
const ids = @import("ids.zig");

pub const Error = Db.Error || error{OutOfMemory};

/// Header names that are always treated as secret-bearing, regardless of what
/// the user declared. These leak credentials often enough that opting in
/// would be the wrong default.
///
/// Consulted by `history.redactSecrets`, which masks the value after a
/// `<name>:` whose name is in this list. Lower-case here; matching is
/// case-insensitive because HTTP header names are.
pub const builtin_secret_headers = [_][]const u8{
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
};

/// Environment variables masked without being declared.
///
/// Consulted by `history.redactSecrets` alongside its suffix rule
/// (`*PASSWORD` / `*TOKEN` / `*SECRET` / `*KEY` / …). Every name below happens
/// to match that suffix rule today, so this list changes no outcome as it
/// stands — its job is to be the place a name that does *not* match one goes,
/// and `redactSecrets` reads it so that adding one there is enough.
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

const owner_token_key = "owner_token";

/// This machine's stable identity, as an audit subject.
///
/// It must survive across processes, because that is what makes it a useful
/// thing to *record*: a host-pid string changes every invocation, so a trail
/// stamped with one could never be read as "these acts came from the same
/// installation". The token is minted once per machine-profile and reused
/// thereafter.
///
/// **Not an ownership identity, and this is the correction v12 made.** It used
/// to be what `leases.acquire` compared, and one token per machine means every
/// agent, editor and terminal on that machine was the same lease owner: two
/// concurrent sessions never conflicted, they renewed each other's claims, and
/// the lease layer isolated nothing. A lease is now held by an attempt's
/// `request_id`; this token rides along as `leases.profile_token`, is reported,
/// and decides nothing. Anything that compares it to decide who may act is
/// reintroducing that defect.
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

// The gate on the reduction above.
//
// What was cut from this module was unreached, and what is left has to stay
// reached — otherwise the next audit finds the same thing. Both lists and both
// predicates are consulted by `history.redactSecrets`, so this asserts the
// wiring end to end rather than the predicates in isolation: every builtin name
// must actually be masked by the production redactor. Removing either call in
// `history.zig` fails here, not just in a comment.
test "every builtin secret name is masked by the production redactor" {
    const t = std.testing;
    const history = @import("history.zig");
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    for (builtin_secret_headers) |name| {
        const command = try std.fmt.allocPrint(a, "curl -H '{s}: s3cr3t-value' https://api", .{name});
        const redacted = try history.redactSecrets(a, command);
        t.expect(std.mem.indexOf(u8, redacted, "s3cr3t-value") == null) catch {
            std.debug.print("header '{s}' reached the audit record in clear: {s}\n", .{ name, redacted });
            return error.BuiltinSecretHeaderNotRedacted;
        };
    }

    for (builtin_secret_env) |name| {
        const command = try std.fmt.allocPrint(a, "{s}=s3cr3t-value ./deploy", .{name});
        const redacted = try history.redactSecrets(a, command);
        t.expect(std.mem.indexOf(u8, redacted, "s3cr3t-value") == null) catch {
            std.debug.print("env '{s}' reached the audit record in clear: {s}\n", .{ name, redacted });
            return error.BuiltinSecretEnvNotRedacted;
        };
    }
}
