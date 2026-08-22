//! Store CRUD for `history` — the local record of file transfers.
//!
//! **This is not the audit trail.** `exec`, `run`, `job` and `write` write no
//! history row; they record to the operations ledger (`operations` +
//! `receipts`, read by `terminus request ls|show`), which is the authoritative
//! append-only record. `history` has exactly two writers left — `cmd_sync` and
//! `cmd_transfer` — so `terminus history <server>` shows `push`, `pull` and
//! `sync` and nothing else. `cmd_history.zig`'s test counts those writers, and
//! fails if a third verb starts or one stops.
//!
//! `redactSecrets`, on the other hand, *is* on the audit path: it is the sole
//! redactor for the ledger's `argv_redacted` as well as for the `detail` below.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Store = @import("Store.zig");
const Db = @import("Db.zig");
const policy = @import("policy.zig");

pub const Entry = struct {
    id: i64,
    kind: []const u8,
    detail: []const u8,
    /// No writer sets this. Both call sites leave it null, so every row's
    /// `cwd` is null; it is kept because it is in the schema and in `--json`.
    cwd: ?[]const u8,
    exit_code: ?i64,
    transport: ?[]const u8,
    duration_ms: ?i64,
    created_at: i64,
};

pub const Record = struct {
    kind: []const u8, // push | pull | sync
    detail: []const u8,
    cwd: ?[]const u8 = null,
    exit_code: ?i64 = null,
    transport: ?[]const u8 = null,
    duration_ms: ?i64 = null,
};

/// Inserts one row, with the detail redacted before it reaches disk.
///
/// **The redaction is not best-effort, and it used to be.** This line was
/// `redactSecrets(...) catch record.detail` — the only arm in this tree that
/// writes unredacted text on purpose, justified as "history is an aid, not a
/// guarantee". Its sharpest form was inside one function: `cmd_sync.run` builds
/// a detail string, refuses to store it unredacted for the ledger's
/// `argv_redacted` ("cannot redact the sync description for the audit record;
/// refusing to store it unredacted", which exits), and then handed the *same
/// bytes* to this call, which stored them raw when the redaction allocator
/// failed. Two opposite decisions about identical bytes, five lines apart.
///
/// So the failure is returned. `Allocator.Error` joins the error set — `list`
/// already returns the same union — and both callers already route a failure
/// here to a process exit that says the audit write did not happen
/// (`Cli.auditFatal` in `cmd_sync`, `Cli.receiptFatal` in `cmd_transfer`). A
/// dropped history row is a gap an operator can see; a row holding a live
/// credential is one nobody can take back out of an append-only table.
pub fn add(store: *Store, server_id: i64, record: Record, now: i64) (Db.Error || Allocator.Error)!void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const detail = try redactSecrets(arena_state.allocator(), record.detail);

    var stmt = try store.db.prepare(
        \\INSERT INTO history (server_id, kind, detail, cwd, exit_code, transport, duration_ms, created_at)
        \\VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
    );
    defer stmt.deinit();
    try stmt.bindInt(1, server_id);
    try stmt.bindText(2, record.kind);
    try stmt.bindText(3, detail);
    try stmt.bindOptText(4, record.cwd);
    try stmt.bindOptInt(5, record.exit_code);
    try stmt.bindOptText(6, record.transport);
    try stmt.bindOptInt(7, record.duration_ms);
    try stmt.bindInt(8, now);
    _ = try stmt.step();
}

const placeholder = "[REDACTED]";

/// Masks common secret shapes in a command string so neither the operations
/// ledger nor this table ever persists live credentials. Conservative — masks
/// only high-signal patterns to avoid mangling legitimate commands:
///   * `NAME=value` where NAME ends in PASSWORD/TOKEN/SECRET/KEY/APIKEY
///     (also PGPASSWORD, *_API_KEY, etc.), or NAME is in
///     `policy.builtin_secret_env` — the value is masked.
///   * `Name: value` where Name is in `policy.builtin_secret_headers`
///     (Authorization, Cookie, Set-Cookie, X-Api-Key, …) — the value is
///     masked to the end of the enclosing quoted argument, or to the next
///     shell separator when unquoted.
///   * `Bearer <token>` — the token is masked.
///   * bare `sk-...` / `sk-ant-...` style API keys — masked.
/// Returns the input unchanged (no copy) when nothing matched.
///
/// The header rule masks the whole value, scheme included, so an
/// `Authorization: Bearer x` argument becomes `Authorization: [REDACTED]`
/// rather than `Authorization: Bearer [REDACTED]`. A scheme name is not worth
/// a special case on a security path, and before this rule existed
/// `-H 'Cookie: session=xyz'` reached the ledger in clear — the `Bearer` rule
/// was the only header handling there was.
pub fn redactSecrets(arena: Allocator, input: []const u8) Allocator.Error![]const u8 {
    // Fast path: skip the scan when no trigger substring is present. Both
    // `policy` lists are consulted here as well as in the scan below —
    // otherwise a name added to a list that matches no suffix would be found
    // by `secretNameEndsAt` on a scan that never runs.
    if (!containsAny(input, &.{ "PASSWORD", "TOKEN", "SECRET", "KEY", "Bearer", "sk-", "password", "token", "secret" }) and
        !containsAny(input, &policy.builtin_secret_env) and
        !containsBuiltinSecretHeader(input))
        return input;

    var out: std.ArrayList(u8) = .empty;
    try out.ensureTotalCapacity(arena, input.len);
    var i: usize = 0;
    // Which quote, if any, the scan is currently inside. The header rule needs
    // it: a header value contains spaces and `;`, so it runs to the closing
    // quote of its argument rather than to the next separator.
    var quote: ?u8 = null;
    while (i < input.len) {
        if (quote) |q| {
            if (input[i] == q) {
                quote = null;
                try out.append(arena, input[i]);
                i += 1;
                continue;
            }
        } else if (input[i] == '\'' or input[i] == '"') {
            quote = input[i];
            try out.append(arena, input[i]);
            i += 1;
            continue;
        }
        // "Bearer <token>"
        if (matchAt(input, i, "Bearer ")) {
            try out.appendSlice(arena, "Bearer ");
            i += "Bearer ".len;
            i = try maskToken(&out, arena, input, i);
            continue;
        }
        // bare sk-/sk-ant- API key at a token boundary
        if ((i == 0 or isSep(input[i - 1])) and matchAt(input, i, "sk-")) {
            try out.appendSlice(arena, "sk-");
            i += "sk-".len;
            i = try maskToken(&out, arena, input, i);
            continue;
        }
        // NAME=value where NAME ends in a secret-ish word
        if (input[i] == '=' and secretNameEndsAt(input, i)) {
            try out.append(arena, '=');
            i += 1;
            i = try maskToken(&out, arena, input, i);
            continue;
        }
        // `Cookie: ...` and friends
        if (input[i] == ':' and secretHeaderEndsAt(input, i)) {
            try out.append(arena, ':');
            i += 1;
            while (i < input.len and (input[i] == ' ' or input[i] == '\t')) {
                try out.append(arena, input[i]);
                i += 1;
            }
            i = try maskHeaderValue(&out, arena, input, i, quote);
            continue;
        }
        try out.append(arena, input[i]);
        i += 1;
    }
    return out.items;
}

/// Masks a header value from `start` to the end of the enclosing quoted
/// argument, or to the next shell separator when `quote` is null.
fn maskHeaderValue(
    out: *std.ArrayList(u8),
    arena: Allocator,
    input: []const u8,
    start: usize,
    quote: ?u8,
) Allocator.Error!usize {
    var i = start;
    if (quote) |q| {
        while (i < input.len and input[i] != q) i += 1;
    } else {
        while (i < input.len and !isSep(input[i])) i += 1;
    }
    if (i > start) try out.appendSlice(arena, placeholder);
    return i;
}

fn maskToken(out: *std.ArrayList(u8), arena: Allocator, input: []const u8, start: usize) Allocator.Error!usize {
    // A token runs until whitespace or a shell separator. A quoted value
    // (value follows an opening quote) runs to the matching quote.
    var i = start;
    if (i < input.len and (input[i] == '\'' or input[i] == '"')) {
        const quote = input[i];
        try out.append(arena, quote);
        i += 1;
        const value_start = i;
        while (i < input.len and input[i] != quote) i += 1;
        if (i > value_start) try out.appendSlice(arena, placeholder);
        if (i < input.len) { // closing quote
            try out.append(arena, quote);
            i += 1;
        }
        return i;
    }
    const value_start = i;
    while (i < input.len and !isSep(input[i])) i += 1;
    if (i > value_start) try out.appendSlice(arena, placeholder);
    return i;
}

fn isSep(ch: u8) bool {
    return ch == ' ' or ch == '\t' or ch == '\n' or ch == '\r' or
        ch == ';' or ch == '&' or ch == '|' or ch == '"' or ch == '\'';
}

fn matchAt(input: []const u8, i: usize, needle: []const u8) bool {
    return i + needle.len <= input.len and std.mem.eql(u8, input[i .. i + needle.len], needle);
}

/// True when the identifier ending just before the '=' at `eq` looks like a
/// secret env var (ends in PASSWORD/TOKEN/SECRET/KEY, case-insensitive) or is
/// one of `policy.builtin_secret_env` by exact name.
fn secretNameEndsAt(input: []const u8, eq: usize) bool {
    var start = eq;
    while (start > 0) {
        const c = input[start - 1];
        if ((c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z') or (c >= '0' and c <= '9') or c == '_') {
            start -= 1;
        } else break;
    }
    const name = input[start..eq];
    if (name.len == 0) return false;
    // The declared list first: it is the place a name that matches no suffix
    // goes, and the suffix rule is what it falls back on.
    if (policy.isBuiltinSecretEnv(name)) return true;
    const tails = [_][]const u8{ "PASSWORD", "TOKEN", "SECRET", "KEY", "APIKEY", "PASSWD", "PWD" };
    for (tails) |tail| if (endsWithIgnoreCase(name, tail)) return true;
    return false;
}

/// True when the header name ending just before the ':' at `colon` is one of
/// `policy.builtin_secret_headers`. Header names are alphanumerics plus `-`
/// and `_` (RFC 9110 tokens, narrowed to what a header name actually uses),
/// which is what keeps `scp host:/path` and `https://…` from matching.
fn secretHeaderEndsAt(input: []const u8, colon: usize) bool {
    var start = colon;
    while (start > 0) {
        const c = input[start - 1];
        if ((c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z') or (c >= '0' and c <= '9') or c == '_' or c == '-') {
            start -= 1;
        } else break;
    }
    if (start == colon) return false;
    return policy.isBuiltinSecretHeader(input[start..colon]);
}

/// Fast-path probe for the header rule. A command with no ':' cannot carry a
/// header, and only then is the case-insensitive name scan worth running.
fn containsBuiltinSecretHeader(input: []const u8) bool {
    if (std.mem.indexOfScalar(u8, input, ':') == null) return false;
    for (policy.builtin_secret_headers) |name| {
        if (name.len > input.len) continue;
        var i: usize = 0;
        while (i + name.len <= input.len) : (i += 1) {
            if (std.ascii.eqlIgnoreCase(input[i .. i + name.len], name)) return true;
        }
    }
    return false;
}

fn endsWithIgnoreCase(haystack: []const u8, tail: []const u8) bool {
    if (tail.len > haystack.len) return false;
    const start = haystack.len - tail.len;
    for (tail, haystack[start..]) |a, b| {
        if (std.ascii.toUpper(a) != std.ascii.toUpper(b)) return false;
    }
    return true;
}

fn containsAny(haystack: []const u8, needles: []const []const u8) bool {
    for (needles) |n| if (std.mem.indexOf(u8, haystack, n) != null) return true;
    return false;
}

test redactSecrets {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    try t.expectEqualStrings("PGPASSWORD=[REDACTED] psql -h db", try redactSecrets(a, "PGPASSWORD=secret123 psql -h db"));
    try t.expectEqualStrings("export API_KEY=[REDACTED]", try redactSecrets(a, "export API_KEY=sk-proj-xxxxx"));
    try t.expectEqualStrings("echo sk-[REDACTED]", try redactSecrets(a, "echo sk-ant-12345"));
    // No secrets: returned unchanged.
    try t.expectEqualStrings("ls -la /srv/app", try redactSecrets(a, "ls -la /srv/app"));
    // Quoted value.
    try t.expectEqualStrings("DB_PASSWORD=\"[REDACTED]\" run", try redactSecrets(a, "DB_PASSWORD=\"p@ss w0rd\" run"));

    // A builtin secret header masks its whole value, scheme included. This is
    // the case the `Bearer` rule alone used to leave in the clear: a cookie
    // carries no scheme keyword and matched none of the triggers, so
    // `-H 'Cookie: session=xyz'` was written to the ledger verbatim.
    try t.expectEqualStrings(
        "curl -H 'Cookie: [REDACTED]' https://api",
        try redactSecrets(a, "curl -H 'Cookie: session=xyz' https://api"),
    );
    // Case-insensitive, double quotes, and a value with its own separators.
    try t.expectEqualStrings(
        "curl -H \"x-api-key: [REDACTED]\"",
        try redactSecrets(a, "curl -H \"x-api-key: k1; k2\""),
    );
    // Unquoted: the value ends at the next shell separator, not at the
    // end of the line — `https://api` is a separate argument.
    try t.expectEqualStrings(
        "curl -H Cookie:[REDACTED] https://api",
        try redactSecrets(a, "curl -H Cookie:abc123 https://api"),
    );
    // Authorization now loses the scheme word too.
    try t.expectEqualStrings(
        "curl -H 'Authorization: [REDACTED]'",
        try redactSecrets(a, "curl -H 'Authorization: Bearer abc.def.ghi'"),
    );
    // A header that is not builtin keeps its name and still gets the
    // `Bearer` treatment — the header rule did not replace that one.
    try t.expectEqualStrings(
        "curl -H 'X-Trace: Bearer [REDACTED]'",
        try redactSecrets(a, "curl -H 'X-Trace: Bearer abc'"),
    );
    // A colon that is not a header: `host:` is not a builtin name, so the
    // path survives.
    try t.expectEqualStrings(
        "scp deploy.token host:/srv/app",
        try redactSecrets(a, "scp deploy.token host:/srv/app"),
    );
    // A non-secret header is left alone entirely.
    try t.expectEqualStrings(
        "curl -H 'Content-Type: application/json' -H 'Cookie: [REDACTED]'",
        try redactSecrets(a, "curl -H 'Content-Type: application/json' -H 'Cookie: s=1'"),
    );
}

test "gate: a redaction that could not be performed refuses rather than storing raw" {
    const t = std.testing;

    // This was the only arm in the tree that wrote unredacted text on purpose:
    // `redactSecrets(...) catch record.detail`, justified as "history is an aid,
    // not a guarantee". Its sharpest form was inside one function —
    // `cmd_sync.run` builds a detail string, refuses to store it unredacted for
    // the ledger's `argv_redacted`, and then handed the same bytes here.
    //
    // Driven off the type rather than off an injected failure, because `add`
    // builds its own arena from `page_allocator` and there is no seam to fail:
    // what is checkable, and what actually decides the behaviour, is that the
    // failure is in the signature at all. An error a caller must handle cannot
    // be the fallback that writes the secret.
    const set = @typeInfo(@typeInfo(@TypeOf(add)).@"fn".return_type.?).error_union.error_set;
    var carries_allocation_failure = false;
    for (@typeInfo(set).error_set.?) |member| {
        if (std.mem.eql(u8, member.name, "OutOfMemory")) carries_allocation_failure = true;
    }
    if (!carries_allocation_failure) {
        std.debug.print(
            \\
            \\`history.add` cannot report a redaction it could not perform. The only way to
            \\return from it is then to store `record.detail` as it stands, which is the
            \\credential the redaction exists to keep out of an append-only table. A dropped
            \\history row is a gap an operator can see; a row holding a live token is one
            \\nobody can take back out.
            \\
        , .{});
        return error.RedactionFailureUnreportable;
    }

    // …and the fallback is gone from the body rather than merely unreachable.
    const source = @embedFile("history.zig");
    const at = std.mem.indexOf(u8, source, "\npub fn add(") orelse return error.AddNotFound;
    const rest = source[at + 1 ..];
    const body = rest[0 .. std.mem.indexOf(u8, rest, "\n}\n") orelse return error.AddUnterminated];
    if (std.mem.indexOf(u8, body, "catch record.detail") != null) {
        std.debug.print(
            \\
            \\`history.add` still falls back to the unredacted detail:
            \\
            \\{s}
            \\
        , .{body});
        return error.RedactionSwallowed;
    }
    try t.expect(std.mem.indexOf(u8, body, "try redactSecrets(") != null);

    // The two callers route the failure to a process exit that says the audit
    // write did not happen, which is what makes returning it safe. The needle is
    // assembled so this gate is not itself counted as a third writer by
    // `cmd_history.zig`'s own scan.
    const writer_call = "Store.history." ++ "add(";
    try t.expect(std.mem.indexOf(u8, @embedFile("../../cli/cmd_sync.zig"), "Cli.auditFatal(\"sync\"") != null);
    try t.expect(std.mem.indexOf(u8, @embedFile("../../cli/cmd_sync.zig"), writer_call) != null);
    try t.expect(std.mem.indexOf(u8, @embedFile("../../cli/cmd_transfer.zig"), writer_call) != null);
}

pub fn list(store: *Store, arena: Allocator, server_id: i64, limit: i64) (Db.Error || Allocator.Error)![]Entry {
    var out: std.ArrayList(Entry) = .empty;
    var stmt = try store.db.prepare(
        \\SELECT id, kind, detail, cwd, exit_code, transport, duration_ms, created_at
        \\FROM history WHERE server_id = ?1 ORDER BY id DESC LIMIT ?2
    );
    defer stmt.deinit();
    try stmt.bindInt(1, server_id);
    try stmt.bindInt(2, limit);
    while (try stmt.step()) {
        try out.append(arena, .{
            .id = stmt.columnInt(0),
            .kind = try arena.dupe(u8, stmt.columnText(1)),
            .detail = try arena.dupe(u8, stmt.columnText(2)),
            .cwd = if (stmt.columnOptText(3)) |v| try arena.dupe(u8, v) else null,
            .exit_code = stmt.columnOptInt(4),
            .transport = if (stmt.columnOptText(5)) |v| try arena.dupe(u8, v) else null,
            .duration_ms = stmt.columnOptInt(6),
            .created_at = stmt.columnInt(7),
        });
    }
    return out.toOwnedSlice(arena);
}
