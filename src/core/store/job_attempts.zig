//! Immutable job attempts (`job_attempts`) plus their mutable observation
//! cache (`job_probe_state`).
//!
//! The old `jobs` row cannot serve as an audit record: it is keyed
//! `UNIQUE(server_id, name)`, a same-name rerun deletes it, and `job rm`
//! removes it outright. So `jobs` stays as the "current attempt" alias for
//! back-compat, while every launch also writes a write-once attempt row that
//! survives both.
//!
//! Runtime observations live in a separate table on purpose. Mixing them into
//! the attempt row would make it mutable again, and the whole value of the
//! attempt is that what it says about the launch cannot drift. Every reading
//! carries `last_probed_at` so a cached value can never be mistaken for a
//! live one.
//!
//! The probe cursor here is *not* the user's output cursor. A consumer
//! reading output must never move the position that state detection depends
//! on, and two consumers must not move each other's.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Store = @import("Store.zig");
const Db = @import("Db.zig");

pub const schema_version: i64 = 1;

pub const Error = Db.Error || error{OutOfMemory};

/// Captured once, at launch. Fields describe the launch, not the run.
pub const CreateOptions = struct {
    request_id: []const u8,
    server_id: ?i64,
    server_name: []const u8,
    job_name: []const u8,
    attempt_no: i64,
    sentinel: ?[]const u8 = null,
    tmux_session: ?[]const u8 = null,
    cwd: ?[]const u8 = null,
    interpreter: ?[]const u8 = null,
    shell: ?[]const u8 = null,
    /// Already redacted. A raw script may carry credentials and must not be
    /// persisted; the hash below preserves integrity checking without it.
    script_body_redacted: ?[]const u8 = null,
    /// SHA-256 of the RAW script, so a later "is this the script that ran?"
    /// question has an answer even though the text is masked.
    script_sha256: ?[]const u8 = null,
    script_bytes: ?i64 = null,
    options_json: ?[]const u8 = null,
    env_redacted_json: ?[]const u8 = null,
    entry_path: ?[]const u8 = null,
    entry_sha256: ?[]const u8 = null,
    now: i64,
};

pub const Attempt = struct {
    id: i64,
    request_id: []const u8,
    server_id: ?i64,
    server_name: []const u8,
    job_name: []const u8,
    attempt_no: i64,
    sentinel: ?[]const u8,
    tmux_session: ?[]const u8,
    cwd: ?[]const u8,
    interpreter: ?[]const u8,
    shell: ?[]const u8,
    script_body_redacted: ?[]const u8,
    script_sha256: ?[]const u8,
    script_bytes: ?i64,
    options_json: ?[]const u8,
    env_redacted_json: ?[]const u8,
    entry_path: ?[]const u8,
    entry_sha256: ?[]const u8,
    created_at: i64,
};

pub fn create(store: *Store, opts: CreateOptions) Error!i64 {
    var stmt = try store.db.prepare(
        \\INSERT INTO job_attempts (
        \\  request_id, schema_version, server_id, server_name, job_name,
        \\  attempt_no, sentinel, tmux_session, cwd, interpreter, shell,
        \\  script_body_redacted, script_sha256, script_bytes, options_json,
        \\  env_redacted_json, entry_path, entry_sha256, created_at
        \\) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
        \\          ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)
    );
    defer stmt.deinit();
    try stmt.bindText(1, opts.request_id);
    try stmt.bindInt(2, schema_version);
    try stmt.bindOptInt(3, opts.server_id);
    try stmt.bindText(4, opts.server_name);
    try stmt.bindText(5, opts.job_name);
    try stmt.bindInt(6, opts.attempt_no);
    try stmt.bindOptText(7, opts.sentinel);
    try stmt.bindOptText(8, opts.tmux_session);
    try stmt.bindOptText(9, opts.cwd);
    try stmt.bindOptText(10, opts.interpreter);
    try stmt.bindOptText(11, opts.shell);
    try stmt.bindOptText(12, opts.script_body_redacted);
    try stmt.bindOptText(13, opts.script_sha256);
    try stmt.bindOptInt(14, opts.script_bytes);
    try stmt.bindOptText(15, opts.options_json);
    try stmt.bindOptText(16, opts.env_redacted_json);
    try stmt.bindOptText(17, opts.entry_path);
    try stmt.bindOptText(18, opts.entry_sha256);
    try stmt.bindInt(19, opts.now);
    _ = try stmt.step();
    return store.db.lastInsertRowId();
}

/// Attempt numbers are per (server, job name) and never reused, so a
/// same-name rerun is visibly attempt 2 rather than overwriting attempt 1.
pub fn nextAttemptNo(store: *Store, server_id: i64, job_name: []const u8) Db.Error!i64 {
    var stmt = try store.db.prepare(
        \\SELECT IFNULL(MAX(attempt_no), 0) + 1 FROM job_attempts
        \\ WHERE server_id = ?1 AND job_name = ?2
    );
    defer stmt.deinit();
    try stmt.bindInt(1, server_id);
    try stmt.bindText(2, job_name);
    if (!try stmt.step()) return 1;
    return stmt.columnInt(0);
}

const select_columns =
    \\SELECT id, request_id, server_id, server_name, job_name, attempt_no,
    \\       sentinel, tmux_session, cwd, interpreter, shell,
    \\       script_body_redacted, script_sha256, script_bytes, options_json,
    \\       env_redacted_json, entry_path, entry_sha256, created_at
    \\FROM job_attempts
;

fn rowToAttempt(arena: Allocator, stmt: *Db.Stmt) Error!Attempt {
    const dupOpt = struct {
        fn f(a: Allocator, v: ?[]const u8) Allocator.Error!?[]const u8 {
            return if (v) |value| try a.dupe(u8, value) else null;
        }
    }.f;
    return .{
        .id = stmt.columnInt(0),
        .request_id = try arena.dupe(u8, stmt.columnText(1)),
        .server_id = stmt.columnOptInt(2),
        .server_name = try arena.dupe(u8, stmt.columnText(3)),
        .job_name = try arena.dupe(u8, stmt.columnText(4)),
        .attempt_no = stmt.columnInt(5),
        .sentinel = try dupOpt(arena, stmt.columnOptText(6)),
        .tmux_session = try dupOpt(arena, stmt.columnOptText(7)),
        .cwd = try dupOpt(arena, stmt.columnOptText(8)),
        .interpreter = try dupOpt(arena, stmt.columnOptText(9)),
        .shell = try dupOpt(arena, stmt.columnOptText(10)),
        .script_body_redacted = try dupOpt(arena, stmt.columnOptText(11)),
        .script_sha256 = try dupOpt(arena, stmt.columnOptText(12)),
        .script_bytes = stmt.columnOptInt(13),
        .options_json = try dupOpt(arena, stmt.columnOptText(14)),
        .env_redacted_json = try dupOpt(arena, stmt.columnOptText(15)),
        .entry_path = try dupOpt(arena, stmt.columnOptText(16)),
        .entry_sha256 = try dupOpt(arena, stmt.columnOptText(17)),
        .created_at = stmt.columnInt(18),
    };
}

pub fn byRequest(store: *Store, arena: Allocator, request_id: []const u8) Error!?Attempt {
    var stmt = try store.db.prepare(select_columns ++ " WHERE request_id = ?1");
    defer stmt.deinit();
    try stmt.bindText(1, request_id);
    if (!try stmt.step()) return null;
    return try rowToAttempt(arena, &stmt);
}

pub fn latest(store: *Store, arena: Allocator, server_id: i64, job_name: []const u8) Error!?Attempt {
    var stmt = try store.db.prepare(select_columns ++
        " WHERE server_id = ?1 AND job_name = ?2 ORDER BY attempt_no DESC LIMIT 1");
    defer stmt.deinit();
    try stmt.bindInt(1, server_id);
    try stmt.bindText(2, job_name);
    if (!try stmt.step()) return null;
    return try rowToAttempt(arena, &stmt);
}

/// Every attempt ever made for a job name, newest first — the audit view that
/// survives `job rm` and same-name reruns.
pub fn history(store: *Store, arena: Allocator, server_id: i64, job_name: []const u8) Error![]Attempt {
    var out: std.ArrayList(Attempt) = .empty;
    var stmt = try store.db.prepare(select_columns ++
        " WHERE server_id = ?1 AND job_name = ?2 ORDER BY attempt_no DESC");
    defer stmt.deinit();
    try stmt.bindInt(1, server_id);
    try stmt.bindText(2, job_name);
    while (try stmt.step()) try out.append(arena, try rowToAttempt(arena, &stmt));
    return out.toOwnedSlice(arena);
}

/// What this binary wrote down as an attempt's sentinel, or why there is no
/// sentinel to compare against.
///
/// Three values rather than `?[]const u8`, because the two absences are two
/// different facts and they send an operator two different ways. "This job
/// launched without a sentinel" is a statement about the launcher — a shell-mode
/// run, or a build that predates sentinels — and no amount of looking at the
/// host will produce one. "There is no attempt row for this request" means the
/// evidence is aimed at something `cmd_job` never registered as a job launch at
/// all, which is a misrouted reading rather than a missing field. Collapsing
/// them into one null would tell the first operator to go looking for a row that
/// exists and the second to go looking for a sentinel that never will.
pub const RecordedSentinel = union(enum) {
    /// The launch recorded this sentinel. The only value evidence can match.
    sentinel: []const u8,
    /// An attempt row exists for this request and its `sentinel` column is
    /// NULL.
    attempt_recorded_none,
    /// No `job_attempts` row names this request.
    no_attempt,
};

/// The sentinel recorded at launch for `request_id`.
///
/// One column rather than `byRequest`'s nineteen, and it asserts its
/// transaction: this is read by `receipts.resolve` inside its `BEGIN IMMEDIATE`
/// to decide whether offered `job_sentinel` evidence is about this attempt, and
/// that decision releases the same-scope mutation barrier. Every sibling read
/// `resolve` makes from inside that transaction asserts the same way
/// (`transfers.expectedEffectLocked`, `transfers.committedDestinationLocked`,
/// `receipts.recordedProcessLocked`); a reading taken outside the lock describes
/// a moment that has already passed by the time the resolution lands.
///
/// `byRequest` is deliberately not reused. It asserts nothing, and a barrier
/// that borrows an unguarded reader inherits the absence of the guard.
pub fn sentinelForLocked(
    store: *Store,
    arena: Allocator,
    request_id: []const u8,
) Error!RecordedSentinel {
    try store.db.requireTransaction();
    var stmt = try store.db.prepare(
        "SELECT sentinel FROM job_attempts WHERE request_id = ?1",
    );
    defer stmt.deinit();
    try stmt.bindText(1, request_id);
    if (!try stmt.step()) return .no_attempt;
    const recorded = stmt.columnOptText(0) orelse return .attempt_recorded_none;
    // Duped: the statement is finalized before this is read, and the value
    // travels out of `resolve` inside the refusal.
    return .{ .sentinel = try arena.dupe(u8, recorded) };
}

/// Latest observation of a running attempt. `last_probed_at` travels with
/// every field so a stale reading is always identifiable as such.
///
/// **Nothing in production reads this row.** `probeState` below has no caller
/// outside `gates_leases_test.zig`, and `probe_cursor` is written from
/// `Tmux.probeTail`'s `next_cursor` and never fed back — `probeTail` takes a
/// `tail_bytes` window, not a cursor. So the whole nine-column table is written and
/// not read today, and that is the honest description of it: the columns are
/// correct, and the mechanisms they exist for are not wired up. `parser_carry` in
/// particular is now preserved across probes rather than destroyed by them, which
/// is what a reader would need — it does not mean a split
/// `__TERMINUS_PROGRESS__` line is currently reassembled anywhere.
pub const ProbeState = struct {
    request_id: []const u8,
    probe_cursor: i64,
    /// Bytes held back because a marker straddled the read window. Without
    /// this a `__TERMINUS_PROGRESS__` line split across two reads is lost.
    parser_carry: ?[]const u8,
    latest_progress_json: ?[]const u8,
    latest_business_result: ?[]const u8,
    latest_phase: ?[]const u8,
    session_alive: ?bool,
    last_probed_at: ?i64,
    updated_at: i64,
};

pub const ProbeUpdate = struct {
    probe_cursor: i64,
    parser_carry: ?[]const u8 = null,
    latest_progress_json: ?[]const u8 = null,
    latest_business_result: ?[]const u8 = null,
    latest_phase: ?[]const u8 = null,
    session_alive: ?bool = null,
    now: i64,
};

/// Upserts the observation cache. Carry, progress, business result and phase are
/// only overwritten when a new value was actually seen — a probe that reads no new
/// output must not erase what an earlier one established.
///
/// `parser_carry` was the one of the four not behind a `COALESCE`, and its single
/// production caller (`cmd_job.zig`'s `refresh`) sets neither it nor two of its
/// neighbours: it bound the struct default `null`, so every `job status` and every
/// `job read` overwrote the column with NULL. What that column holds is the bytes
/// held back because a marker straddled the read window, which is precisely the
/// state that has to survive from one probe to the next — see `ProbeState`.
pub fn recordProbe(store: *Store, request_id: []const u8, update: ProbeUpdate) Error!void {
    var stmt = try store.db.prepare(
        \\INSERT INTO job_probe_state (
        \\  request_id, probe_cursor, parser_carry, latest_progress_json,
        \\  latest_business_result, latest_phase, session_alive,
        \\  last_probed_at, updated_at
        \\) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)
        \\ON CONFLICT(request_id) DO UPDATE SET
        \\  probe_cursor = ?2,
        \\  parser_carry           = COALESCE(?3, parser_carry),
        \\  latest_progress_json   = COALESCE(?4, latest_progress_json),
        \\  latest_business_result = COALESCE(?5, latest_business_result),
        \\  latest_phase           = COALESCE(?6, latest_phase),
        \\  session_alive = ?7,
        \\  last_probed_at = ?8,
        \\  updated_at = ?8
    );
    defer stmt.deinit();
    try stmt.bindText(1, request_id);
    try stmt.bindInt(2, update.probe_cursor);
    try stmt.bindOptText(3, update.parser_carry);
    try stmt.bindOptText(4, update.latest_progress_json);
    try stmt.bindOptText(5, update.latest_business_result);
    try stmt.bindOptText(6, update.latest_phase);
    try stmt.bindOptInt(7, if (update.session_alive) |v| @as(i64, if (v) 1 else 0) else null);
    try stmt.bindInt(8, update.now);
    _ = try stmt.step();
}

pub fn probeState(store: *Store, arena: Allocator, request_id: []const u8) Error!?ProbeState {
    var stmt = try store.db.prepare(
        \\SELECT request_id, probe_cursor, parser_carry, latest_progress_json,
        \\       latest_business_result, latest_phase, session_alive,
        \\       last_probed_at, updated_at
        \\FROM job_probe_state WHERE request_id = ?1
    );
    defer stmt.deinit();
    try stmt.bindText(1, request_id);
    if (!try stmt.step()) return null;
    const dupOpt = struct {
        fn f(a: Allocator, v: ?[]const u8) Allocator.Error!?[]const u8 {
            return if (v) |value| try a.dupe(u8, value) else null;
        }
    }.f;
    return .{
        .request_id = try arena.dupe(u8, stmt.columnText(0)),
        .probe_cursor = stmt.columnInt(1),
        .parser_carry = try dupOpt(arena, stmt.columnOptText(2)),
        .latest_progress_json = try dupOpt(arena, stmt.columnOptText(3)),
        .latest_business_result = try dupOpt(arena, stmt.columnOptText(4)),
        .latest_phase = try dupOpt(arena, stmt.columnOptText(5)),
        .session_alive = if (stmt.columnOptInt(6)) |v| v != 0 else null,
        .last_probed_at = stmt.columnOptInt(7),
        .updated_at = stmt.columnInt(8),
    };
}
