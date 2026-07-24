//! Store CRUD for `history` — the local audit trail of remote actions.
//! Written best-effort by exec/run/push/pull/sync; read by `terminus
//! history`. Recording failures never break the command being recorded.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Store = @import("Store.zig");
const Db = @import("Db.zig");

pub const Entry = struct {
    id: i64,
    kind: []const u8,
    detail: []const u8,
    cwd: ?[]const u8,
    exit_code: ?i64,
    transport: ?[]const u8,
    duration_ms: ?i64,
    created_at: i64,
};

pub const Record = struct {
    kind: []const u8, // exec | job | push | pull | sync
    detail: []const u8,
    cwd: ?[]const u8 = null,
    exit_code: ?i64 = null,
    transport: ?[]const u8 = null,
    duration_ms: ?i64 = null,
};

pub fn add(store: *Store, server_id: i64, record: Record, now: i64) Db.Error!void {
    // Redact obvious secrets before they ever hit disk. Best-effort: on OOM
    // we fall back to storing the raw detail (history is an aid, not a
    // guarantee) rather than dropping the audit entry.
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const detail = redactSecrets(arena_state.allocator(), record.detail) catch record.detail;

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

/// Masks common secret shapes in a command string so the local audit trail
/// never persists live credentials. Conservative — masks only high-signal
/// patterns to avoid mangling legitimate output:
///   * `NAME=value` where NAME ends in PASSWORD/TOKEN/SECRET/KEY/APIKEY
///     (also PGPASSWORD, *_API_KEY, etc.) — the value is masked.
///   * `Bearer <token>` — the token is masked.
///   * bare `sk-...` / `sk-ant-...` style API keys — masked.
/// Returns the input unchanged (no copy) when nothing matched.
pub fn redactSecrets(arena: Allocator, input: []const u8) Allocator.Error![]const u8 {
    // Fast path: skip the scan when no trigger substring is present.
    if (!containsAny(input, &.{ "PASSWORD", "TOKEN", "SECRET", "KEY", "Bearer", "sk-", "password", "token", "secret" }))
        return input;

    var out: std.ArrayList(u8) = .empty;
    try out.ensureTotalCapacity(arena, input.len);
    var i: usize = 0;
    while (i < input.len) {
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
        try out.append(arena, input[i]);
        i += 1;
    }
    return out.items;
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
/// secret env var (ends in PASSWORD/TOKEN/SECRET/KEY, case-insensitive).
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
    const tails = [_][]const u8{ "PASSWORD", "TOKEN", "SECRET", "KEY", "APIKEY", "PASSWD", "PWD" };
    for (tails) |tail| if (endsWithIgnoreCase(name, tail)) return true;
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
    try t.expectEqualStrings("curl -H 'Authorization: Bearer [REDACTED]'", try redactSecrets(a, "curl -H 'Authorization: Bearer abc.def.ghi'"));
    try t.expectEqualStrings("export API_KEY=[REDACTED]", try redactSecrets(a, "export API_KEY=sk-proj-xxxxx"));
    try t.expectEqualStrings("echo sk-[REDACTED]", try redactSecrets(a, "echo sk-ant-12345"));
    // No secrets: returned unchanged.
    try t.expectEqualStrings("ls -la /srv/app", try redactSecrets(a, "ls -la /srv/app"));
    // Quoted value.
    try t.expectEqualStrings("DB_PASSWORD=\"[REDACTED]\" run", try redactSecrets(a, "DB_PASSWORD=\"p@ss w0rd\" run"));
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
