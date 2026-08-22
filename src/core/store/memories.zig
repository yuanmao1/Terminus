//! CRUD for the `memories` table — persistent per-server / per-session
//! knowledge for agents.
//!
//! Scope rules:
//! * `session_id IS NULL` → server-scope entry (long-lived facts).
//! * otherwise → session-scope entry, cascade-deleted with the session.
//! * Reading a session scope merges in server-scope entries; a session
//!   entry with the same key shadows the server one.
//!
//! **Freshness and trust (v13).** Two things a note carries besides its text:
//!
//! * *when the fact was observed*, which is not when the row was written.
//!   `updated_at` is a write time and always was; `observed_at` is the moment the
//!   thing being asserted was actually seen, and `observed_source` says how. A
//!   note saying "the API listens on 8080" seen six months ago and the same
//!   sentence seen this morning are different claims, and until v13 this table
//!   could not tell them apart.
//! * *whether its `verify_cmd` may be run*. That command is an arbitrary line
//!   that executes on a host, and memories arrive by `terminus import` from
//!   documents anybody can hand over — so it is inert until somebody grants it,
//!   and the grant records who and when. **Nothing in `AddOptions` can set a
//!   trust column.** `grantTrust` is the only writer of the three, which is what
//!   makes "an imported memory lands untrusted" a property of the type rather
//!   than of a check somebody has to remember to write.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Store = @import("Store.zig");
const Db = @import("Db.zig");
const receipts = @import("receipts.zig");
const digest = @import("../digest.zig");

/// Reading a row can fail on the value of `observed_source`, which is text in the
/// database and an enum here. Shaped like `operations.Error` for the same reason:
/// a store whose column holds a word this binary cannot name is a real answer,
/// not a sqlite failure, and a caller deserves to be told which.
pub const Error = Db.Error || error{UnknownObservedSource};

/// The `receipts.Source` members a memory row can carry.
///
/// Reused rather than re-invented: `receipts.Source` is already the tree's
/// considered vocabulary for "how was this known", and a second parallel set is
/// how two answers to one question come to disagree. The v13 CHECK spells out
/// exactly this list and a gate holds the two together.
///
/// What each means here:
///
/// * `live` — the `verify_cmd` was executed against the host and agreed. The only
///   member that means anything ran.
/// * `cache` — somebody wrote the note down. `memory add`'s answer: a stored
///   reading, which is what the operator's assertion is.
/// * `legacy_import` — the row was carried in from a document. The claim about
///   *when* comes from that document; the claim about how this store came to hold
///   it does not, and this is it.
/// * `backfill` — the timestamp is `updated_at` standing in for an observation,
///   because the row predates the column. Labelled precisely because a write time
///   wearing an observation's clothes is the confusion v13 removes.
///
/// `reconcile` is absent, and its absence is a decision rather than an oversight:
/// reconciliation adjudicates an operation whose outcome is unknown against later
/// evidence, and a memory has no ledger row and no outcome to adjudicate.
pub const observed_sources = [_]receipts.Source{ .live, .cache, .legacy_import, .backfill };

/// `observed_sources` as the SQL list the v13 CHECK spells out.
///
/// Exposed so the gate that holds the schema against this array reads the same
/// text a reader of the array would render, rather than a third transcription of
/// the same four words.
pub const observed_sources_sql = blk: {
    var out: []const u8 = "";
    for (observed_sources, 0..) |source, i| {
        out = out ++ (if (i == 0) "" else ",") ++ "'" ++ @tagName(source) ++ "'";
    }
    break :blk out;
};

pub const Scope = struct {
    server_id: i64,
    session_id: ?i64 = null,
};

/// A recorded permission to run one specific `verify_cmd`.
///
/// Three facts, because "why did this run" takes all three. `cmd_sha256` is the
/// one that is easy to leave out and the one that matters most: without it a
/// grant is a flag, and a flag keeps applying after the command text changes
/// under it. See `trustState`.
pub const Grant = struct {
    at: i64,
    by: []const u8,
    cmd_sha256: []const u8,
};

pub const Memory = struct {
    id: i64,
    scope: enum { server, session },
    key: ?[]const u8,
    content: []const u8,
    tags: ?[]const u8,
    created_at: i64,
    updated_at: i64,
    /// When the fact was observed. Null means nobody knows — which an imported
    /// document that carried no observation genuinely does not.
    observed_at: ?i64,
    observed_source: receipts.Source,
    verify_cmd: ?[]const u8,
    /// Never set by `add`, by an import, or by anything an export can influence.
    grant: ?Grant,
};

/// Whether this row's `verify_cmd` may be executed.
pub const TrustState = enum {
    /// There is no command, so there is nothing to run and nothing to trust.
    no_verify_cmd,
    /// A command with no grant. The default for everything, and unconditionally
    /// the state of anything an import produced.
    untrusted,
    /// A grant exists and authorises *different* text than the row now holds.
    /// Reads as untrusted everywhere, which is the point: the alternative is that
    /// trusting `systemctl is-active nginx` once licenses whatever the key's
    /// command is rewritten to afterwards.
    stale_grant,
    /// A grant that names this exact command. The only state that may run, and
    /// `cmd_memory.verify` says so in an exhaustive switch rather than a
    /// predicate — so a state added here has to be classified there instead of
    /// falling into whichever arm happens to be last.
    trusted,
};

/// The trust state of a row, decided from the row alone.
///
/// The digest comparison is the substance: a grant is a permission for the text
/// it was given, so a row whose `verify_cmd` no longer hashes to
/// `grant.cmd_sha256` has no permission at all. Nothing has to remember to revoke
/// on a rewrite — the rewrite revokes itself. Writing the same text back does
/// restore the grant, and that is correct: it is the text that was authorised.
pub fn trustState(m: Memory) TrustState {
    const command = m.verify_cmd orelse return .no_verify_cmd;
    const grant = m.grant orelse return .untrusted;
    var buf: [digest.hex_len]u8 = undefined;
    if (!std.mem.eql(u8, digest.hex(command, &buf), grant.cmd_sha256)) return .stale_grant;
    return .trusted;
}

/// When the fact a memory states was observed.
///
/// Three cases and not one optional, because "the caller did not say" and "the
/// caller says nobody knows" are different answers and an import needs the
/// second. Substituting the import moment for a missing observation is exactly
/// the write-time-as-observation confusion v13 exists to remove, so there has to
/// be a way to decline.
pub const Observation = union(enum) {
    /// The caller asserts the fact as of `AddOptions.now`. What `memory add`
    /// means when nobody passes a timestamp.
    now,
    /// A specific moment, which may be far older than the write. What an import
    /// carries verbatim out of the document.
    at: i64,
    /// Unknown. An import of a document from before observations were recorded.
    unknown,
};

pub const AddOptions = struct {
    key: ?[]const u8 = null,
    content: []const u8,
    tags: ?[]const u8 = null,
    now: i64,
    observed: Observation = .now,
    observed_source: receipts.Source = .cache,
    /// The command that would re-observe this fact. Storing it grants nothing;
    /// `grantTrust` is the only thing that does. On an upsert, null leaves an
    /// existing command in place rather than dropping it.
    verify_cmd: ?[]const u8 = null,
};

pub const AddResult = enum { inserted, updated };

/// Keyed entries upsert: adding an existing key in the same scope updates
/// its content/tags in place.
///
/// The upsert deliberately does **not** touch the three grant columns. It does
/// not need to: a changed `verify_cmd` invalidates a grant by digest, and an
/// unchanged one was already authorised. Clearing them here would be a second
/// mechanism for the same rule, and the two would eventually disagree.
pub fn add(store: *Store, scope: Scope, opts: AddOptions) Db.Error!AddResult {
    const observed_at: ?i64 = switch (opts.observed) {
        .now => opts.now,
        .at => |at| at,
        .unknown => null,
    };
    if (opts.key) |key| {
        if (try idByKey(store, scope, key)) |id| {
            var stmt = try store.db.prepare(
                \\UPDATE memories
                \\SET content = ?1, tags = ?2, updated_at = ?3,
                \\    observed_at = ?4, observed_source = ?5,
                \\    verify_cmd = COALESCE(?6, verify_cmd)
                \\WHERE id = ?7
            );
            defer stmt.deinit();
            try stmt.bindText(1, opts.content);
            try stmt.bindOptText(2, opts.tags);
            try stmt.bindInt(3, opts.now);
            try stmt.bindOptInt(4, observed_at);
            try stmt.bindText(5, @tagName(opts.observed_source));
            try stmt.bindOptText(6, opts.verify_cmd);
            try stmt.bindInt(7, id);
            _ = try stmt.step();
            return .updated;
        }
    }
    var stmt = try store.db.prepare(
        \\INSERT INTO memories (server_id, session_id, key, content, tags, created_at, updated_at,
        \\                      observed_at, observed_source, verify_cmd)
        \\VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7, ?8, ?9)
    );
    defer stmt.deinit();
    try stmt.bindInt(1, scope.server_id);
    try stmt.bindOptInt(2, scope.session_id);
    try stmt.bindOptText(3, opts.key);
    try stmt.bindText(4, opts.content);
    try stmt.bindOptText(5, opts.tags);
    try stmt.bindInt(6, opts.now);
    try stmt.bindOptInt(7, observed_at);
    try stmt.bindText(8, @tagName(opts.observed_source));
    try stmt.bindOptText(9, opts.verify_cmd);
    _ = try stmt.step();
    return .inserted;
}

/// Records that this row's fact was observed at `at`, by `source`.
///
/// Separate from `add` because an observation is not a rewrite: the text of the
/// note has not changed, only what is known about when it was last true. Returns
/// false if no such row belongs to `server_id`.
pub fn recordObservation(
    store: *Store,
    server_id: i64,
    id: i64,
    at: i64,
    source: receipts.Source,
) Db.Error!bool {
    var stmt = try store.db.prepare(
        \\UPDATE memories SET observed_at = ?1, observed_source = ?2
        \\WHERE id = ?3 AND server_id = ?4
    );
    defer stmt.deinit();
    try stmt.bindInt(1, at);
    try stmt.bindText(2, @tagName(source));
    try stmt.bindInt(3, id);
    try stmt.bindInt(4, server_id);
    _ = try stmt.step();
    return store.db.changes() > 0;
}

pub const GrantResult = union(enum) {
    granted: Grant,
    /// The selector matched nothing in this scope.
    no_such_memory,
    /// The memory exists and has no `verify_cmd`. There is nothing to authorise,
    /// and recording a grant against an absent command would pre-authorise
    /// whatever text arrived next.
    nothing_to_trust,
};

/// Grants permission to run one memory's `verify_cmd`, and records who and when.
///
/// The only writer of `trusted_at`, `trusted_by` and `trusted_cmd_sha256`. It is
/// deliberately not reachable from `add`, from an import, or from anything an
/// export document can influence: a snapshot that could carry a grant would be
/// arbitrary code execution by handing somebody a file.
///
/// The digest is taken from the row this call just read. If the command is
/// rewritten between the read and the write, the stored digest describes the
/// older text and `trustState` reports `stale_grant` — the safe direction, and
/// the reason the digest is stored rather than compared once and forgotten.
pub fn grantTrust(
    store: *Store,
    arena: Allocator,
    scope: Scope,
    selector: Selector,
    by: []const u8,
    now: i64,
) (Error || Allocator.Error)!GrantResult {
    const found = (try find(store, arena, scope, selector)) orelse return .no_such_memory;
    const command = found.verify_cmd orelse return .nothing_to_trust;
    const cmd_sha256 = try digest.hexAlloc(arena, command);

    var stmt = try store.db.prepare(
        \\UPDATE memories SET trusted_at = ?1, trusted_by = ?2, trusted_cmd_sha256 = ?3
        \\WHERE id = ?4 AND server_id = ?5
    );
    defer stmt.deinit();
    try stmt.bindInt(1, now);
    try stmt.bindText(2, by);
    try stmt.bindText(3, cmd_sha256);
    try stmt.bindInt(4, found.id);
    try stmt.bindInt(5, scope.server_id);
    _ = try stmt.step();
    if (store.db.changes() == 0) return .no_such_memory;
    return .{ .granted = .{ .at = now, .by = by, .cmd_sha256 = cmd_sha256 } };
}

pub const ListOptions = struct {
    /// Only entries carrying this tag (comma-separated `tags` column).
    tag: ?[]const u8 = null,
};

/// Lightweight recall hint: the keys (or first words for keyless entries)
/// of a server's memories. Cheap enough to attach to every exec response
/// so agents notice there is knowledge to read before acting.
pub fn keys(store: *Store, arena: Allocator, server_id: i64) (Db.Error || Allocator.Error)![][]const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var stmt = try store.db.prepare(
        \\SELECT key, substr(content, 1, 40) FROM memories
        \\WHERE server_id = ?1 AND session_id IS NULL ORDER BY id
    );
    defer stmt.deinit();
    try stmt.bindInt(1, server_id);
    while (try stmt.step()) {
        if (stmt.columnOptText(0)) |key| {
            try out.append(arena, try arena.dupe(u8, key));
        } else {
            try out.append(arena, try std.fmt.allocPrint(arena, "(id? \"{s}...\")", .{stmt.columnText(1)}));
        }
    }
    return out.toOwnedSlice(arena);
}

/// Lists the scope's entries. For a session scope this merges server-scope
/// entries, with session keys shadowing server keys. Order: server entries
/// first, then session entries, each oldest-first.
pub fn list(store: *Store, arena: Allocator, scope: Scope, opts: ListOptions) (Error || Allocator.Error)![]Memory {
    var stmt = try store.db.prepare(
        \\SELECT id, session_id, key, content, tags, created_at, updated_at,
        \\       observed_at, observed_source, verify_cmd,
        \\       trusted_at, trusted_by, trusted_cmd_sha256
        \\FROM memories
        \\WHERE server_id = ?1 AND (session_id IS NULL OR session_id IS ?2)
        \\ORDER BY (session_id IS NULL) DESC, id
    );
    defer stmt.deinit();
    try stmt.bindInt(1, scope.server_id);
    try stmt.bindOptInt(2, scope.session_id);

    var out: std.ArrayList(Memory) = .empty;
    var shadowed: std.StringArrayHashMapUnmanaged(void) = .empty;
    if (scope.session_id != null) {
        // Collect session-scope keys first so shadowed server entries can
        // be skipped while streaming rows below.
        var keys_stmt = try store.db.prepare(
            "SELECT key FROM memories WHERE server_id = ?1 AND session_id IS ?2 AND key IS NOT NULL",
        );
        defer keys_stmt.deinit();
        try keys_stmt.bindInt(1, scope.server_id);
        try keys_stmt.bindOptInt(2, scope.session_id);
        while (try keys_stmt.step()) {
            try shadowed.put(arena, try arena.dupe(u8, keys_stmt.columnText(0)), {});
        }
    }

    while (try stmt.step()) {
        const is_server_scope = stmt.columnOptInt(1) == null;
        const key = stmt.columnOptText(2);
        if (is_server_scope and key != null and shadowed.contains(key.?)) continue;
        const tags = stmt.columnOptText(4);
        if (opts.tag) |wanted| {
            if (tags == null or !hasTag(tags.?, wanted)) continue;
        }
        try out.append(arena, try rowToMemory(arena, &stmt, is_server_scope));
    }
    return out.toOwnedSlice(arena);
}

/// One row, read the same way wherever a full memory is needed.
///
/// The grant is all three columns or none — `grant_is_whole` makes the halfway
/// row unstorable — so a row that somehow held two of the three is refused here
/// rather than read as a grant with an invented third value.
fn rowToMemory(
    arena: Allocator,
    stmt: *Db.Stmt,
    is_server_scope: bool,
) (Error || Allocator.Error)!Memory {
    const key = stmt.columnOptText(2);
    const tags = stmt.columnOptText(4);
    const verify_cmd = stmt.columnOptText(9);
    const trusted_at = stmt.columnOptInt(10);
    const trusted_by = stmt.columnOptText(11);
    const trusted_sha = stmt.columnOptText(12);
    const grant: ?Grant = if (trusted_at != null and trusted_by != null and trusted_sha != null) .{
        .at = trusted_at.?,
        .by = try arena.dupe(u8, trusted_by.?),
        .cmd_sha256 = try arena.dupe(u8, trusted_sha.?),
    } else null;
    return .{
        .id = stmt.columnInt(0),
        .scope = if (is_server_scope) .server else .session,
        .key = if (key) |k| try arena.dupe(u8, k) else null,
        .content = try arena.dupe(u8, stmt.columnText(3)),
        .tags = if (tags) |t| try arena.dupe(u8, t) else null,
        .created_at = stmt.columnInt(5),
        .updated_at = stmt.columnInt(6),
        .observed_at = stmt.columnOptInt(7),
        .observed_source = receipts.Source.parse(stmt.columnText(8)) catch
            return error.UnknownObservedSource,
        .verify_cmd = if (verify_cmd) |v| try arena.dupe(u8, v) else null,
        .grant = grant,
    };
}

/// Every memory on the server, session-scoped ones included (annotated
/// with their session name). For `memory export`.
///
/// **No grant field, and that is the export boundary.** A document that carried
/// one would either be honoured on import — arbitrary code execution by handing
/// somebody a file — or ignored, which makes it a field that lies. Since import
/// must ignore it, there is nothing for it to be but absent. `verify_cmd` does
/// travel: the text is not the permission, and an operator who can read the
/// command is who decides whether to grant it.
pub const Exported = struct {
    session: ?[]const u8,
    key: ?[]const u8,
    content: []const u8,
    tags: ?[]const u8,
    updated_at: i64,
    observed_at: ?i64,
    verify_cmd: ?[]const u8,
};

pub fn exportAll(store: *Store, arena: Allocator, server_id: i64) (Db.Error || Allocator.Error)![]Exported {
    var out: std.ArrayList(Exported) = .empty;
    var stmt = try store.db.prepare(
        \\SELECT s.name, m.key, m.content, m.tags, m.updated_at, m.observed_at, m.verify_cmd
        \\FROM memories m LEFT JOIN sessions s ON s.id = m.session_id
        \\WHERE m.server_id = ?1 ORDER BY m.id
    );
    defer stmt.deinit();
    try stmt.bindInt(1, server_id);
    while (try stmt.step()) {
        try out.append(arena, .{
            .session = if (stmt.columnOptText(0)) |v| try arena.dupe(u8, v) else null,
            .key = if (stmt.columnOptText(1)) |v| try arena.dupe(u8, v) else null,
            .content = try arena.dupe(u8, stmt.columnText(2)),
            .tags = if (stmt.columnOptText(3)) |v| try arena.dupe(u8, v) else null,
            .updated_at = stmt.columnInt(4),
            .observed_at = stmt.columnOptInt(5),
            .verify_cmd = if (stmt.columnOptText(6)) |v| try arena.dupe(u8, v) else null,
        });
    }
    return out.toOwnedSlice(arena);
}

/// Whether an identical keyless memory already exists in the exact scope
/// (used by import to avoid duplicating free-form entries).
pub fn hasContent(store: *Store, scope: Scope, content: []const u8) Db.Error!bool {
    var stmt = try store.db.prepare(
        "SELECT 1 FROM memories WHERE server_id = ?1 AND session_id IS ?2 AND key IS NULL AND content = ?3",
    );
    defer stmt.deinit();
    try stmt.bindInt(1, scope.server_id);
    try stmt.bindOptInt(2, scope.session_id);
    try stmt.bindText(3, content);
    return try stmt.step();
}

pub const Selector = union(enum) {
    key: []const u8,
    id: i64,
};

/// Looks up one entry. A key selector on a session scope falls back to the
/// server-scope entry when the session has none (shadowing semantics).
pub fn find(store: *Store, arena: Allocator, scope: Scope, selector: Selector) (Error || Allocator.Error)!?Memory {
    const entries = try list(store, arena, scope, .{});
    switch (selector) {
        .key => |key| {
            // Session entries come last and shadow, so scan backwards.
            var i = entries.len;
            while (i > 0) {
                i -= 1;
                const m = entries[i];
                if (m.key != null and std.mem.eql(u8, m.key.?, key)) return m;
            }
        },
        .id => |id| for (entries) |m| {
            if (m.id == id) return m;
        },
    }
    return null;
}

/// Returns false if the selector matched nothing. Deleting by key only
/// touches the exact scope (no shadow fallback) to avoid surprises.
pub fn remove(store: *Store, scope: Scope, selector: Selector) Db.Error!bool {
    switch (selector) {
        .key => |key| {
            const id = (try idByKey(store, scope, key)) orelse return false;
            return removeById(store, scope.server_id, id);
        },
        .id => |id| return removeById(store, scope.server_id, id),
    }
}

fn removeById(store: *Store, server_id: i64, id: i64) Db.Error!bool {
    var stmt = try store.db.prepare(
        "DELETE FROM memories WHERE id = ?1 AND server_id = ?2",
    );
    defer stmt.deinit();
    try stmt.bindInt(1, id);
    try stmt.bindInt(2, server_id);
    _ = try stmt.step();
    return store.db.changes() > 0;
}

fn idByKey(store: *Store, scope: Scope, key: []const u8) Db.Error!?i64 {
    var stmt = try store.db.prepare(
        "SELECT id FROM memories WHERE server_id = ?1 AND session_id IS ?2 AND key = ?3",
    );
    defer stmt.deinit();
    try stmt.bindInt(1, scope.server_id);
    try stmt.bindOptInt(2, scope.session_id);
    try stmt.bindText(3, key);
    if (!try stmt.step()) return null;
    return stmt.columnInt(0);
}

fn hasTag(tags: []const u8, wanted: []const u8) bool {
    var it = std.mem.splitScalar(u8, tags, ',');
    while (it.next()) |tag| {
        if (std.mem.eql(u8, std.mem.trim(u8, tag, " \t"), wanted)) return true;
    }
    return false;
}
