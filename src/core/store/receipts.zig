//! Append-only receipt ledger (`operation_events`).
//!
//! This is the authoritative record of what happened, replacing the
//! best-effort `history` text log. Two invariants matter most:
//!
//! * **Append only.** Events are never updated or deleted.
//! * **Exactly one terminal per operation**, enforced by a partial unique
//!   index in the schema rather than by convention. Two racing writers
//!   cannot both settle a request: the loser gets `error.Constraint` and is
//!   handed the winner's terminal to reconcile against, never permitted to
//!   overwrite it.
//!
//! A failure to persist here must never be swallowed. `appendOrFail` is the
//! single door every write path goes through; see `Cli.receiptFatal`.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Store = @import("Store.zig");
const Db = @import("Db.zig");
const op_state = @import("op_state.zig");

pub const schema_version: i64 = 1;

pub const Kind = enum {
    /// Local record created; nothing sent.
    submit,
    connect,
    remote_start,
    progress,
    output,
    checkpoint,
    /// Settles the operation. At most one per request.
    terminal,
    reconcile,
    cleanup,
    audit,
    /// Lease acquire/release/takeover, for the coordination audit chain.
    lease,

    pub fn parse(text: []const u8) error{UnknownEventKind}!Kind {
        return std.meta.stringToEnum(Kind, text) orelse error.UnknownEventKind;
    }
};

/// Where an observation came from. `cache` readings must always travel with
/// their `observed_at` so a stale value cannot pass for a live one.
pub const Source = enum {
    live,
    cache,
    reconcile,
    legacy_import,
    backfill,

    pub fn parse(text: []const u8) error{UnknownSource}!Source {
        return std.meta.stringToEnum(Source, text) orelse error.UnknownSource;
    }
};

/// Byte-stream evidence: size and hash, never the payload itself.
pub const StreamEvidence = struct {
    bytes: ?i64 = null,
    sha256: ?[]const u8 = null,
    truncated: bool = false,
    /// Short, already-redacted human summary. Never raw output.
    digest: ?[]const u8 = null,
};

pub const Event = struct {
    request_id: []const u8,
    kind: Kind,
    observed_at: i64,
    source: Source = .live,

    phase: ?[]const u8 = null,
    status: ?op_state.Status = null,

    connected: ?bool = null,
    remote_started: ?bool = null,
    remote_pid: ?i64 = null,
    remote_pgid: ?i64 = null,
    /// Process start-time token. Without it a recycled pid could be
    /// mistaken for ours during reconcile.
    remote_start_token: ?[]const u8 = null,

    started_at: ?i64 = null,
    finished_at: ?i64 = null,
    duration_ms: ?i64 = null,
    exit_code: ?i64 = null,
    term_signal: ?i64 = null,
    timed_out: ?bool = null,

    transport_error: ?[]const u8 = null,
    error_code: ?[]const u8 = null,
    last_observed: ?[]const u8 = null,
    cancel_method: ?[]const u8 = null,

    stdin: StreamEvidence = .{},
    stdout: StreamEvidence = .{},
    stderr: StreamEvidence = .{},

    correlation_id: ?[]const u8 = null,
    /// Versioned, already-redacted structure for anything without a column.
    detail_json: ?[]const u8 = null,
};

/// Supplementary facts a caller may attach to a terminal.
///
/// Deliberately narrow. Everything that the `Terminal` evidence itself
/// determines — status, exit code, signal, timed_out, transport error,
/// error code, cancel method, last observed state — is filled in by `settle`
/// and cannot be supplied here, so a caller cannot pair, say, a clean exit
/// with `timed_out = true`.
pub const TerminalExtra = struct {
    phase: ?[]const u8 = null,
    started_at: ?i64 = null,
    finished_at: ?i64 = null,
    duration_ms: ?i64 = null,
    remote_pid: ?i64 = null,
    remote_pgid: ?i64 = null,
    remote_start_token: ?[]const u8 = null,
    stdin: StreamEvidence = .{},
    stdout: StreamEvidence = .{},
    stderr: StreamEvidence = .{},
    correlation_id: ?[]const u8 = null,
    detail_json: ?[]const u8 = null,
    source: Source = .live,
};

pub const Error = Db.Error || error{
    UnknownEventKind,
    UnknownSource,
    UnknownStatus,
    /// A terminal event may only be written by `settle`.
    TerminalRequiresSettle,
    /// The requested terminal does not follow from the current status.
    IllegalTransition,
    UnknownOperation,
    /// Supplementary fields contradict the evidence (e.g. a remote pid on a
    /// request that provably never left this machine).
    ContradictoryEvidence,
};

fn optBool(v: ?bool) ?i64 {
    return if (v) |b| @as(i64, if (b) 1 else 0) else null;
}

/// Appends one event, assigning the next sequence number. Caller must hold a
/// write transaction when ordering matters relative to other writes.
fn insert(store: *Store, event: Event, is_terminal: bool, seq: i64) Db.Error!i64 {
    var stmt = try store.db.prepare(
        \\INSERT INTO operation_events (
        \\  request_id, seq, schema_version, kind, phase, status, is_terminal,
        \\  connected, remote_started, remote_pid, remote_pgid, remote_start_token,
        \\  started_at, finished_at, duration_ms, exit_code, term_signal, timed_out,
        \\  transport_error, error_code, last_observed, cancel_method,
        \\  stdin_bytes, stdin_sha256,
        \\  stdout_bytes, stdout_sha256, stdout_truncated, stdout_digest,
        \\  stderr_bytes, stderr_sha256, stderr_truncated, stderr_digest,
        \\  observed_at, source, correlation_id, detail_json
        \\) VALUES (
        \\  ?1, ?2, ?3, ?4, ?5, ?6, ?7,
        \\  ?8, ?9, ?10, ?11, ?12,
        \\  ?13, ?14, ?15, ?16, ?17, ?18,
        \\  ?19, ?20, ?21, ?22,
        \\  ?23, ?24,
        \\  ?25, ?26, ?27, ?28,
        \\  ?29, ?30, ?31, ?32,
        \\  ?33, ?34, ?35, ?36
        \\)
    );
    defer stmt.deinit();
    try stmt.bindText(1, event.request_id);
    try stmt.bindInt(2, seq);
    try stmt.bindInt(3, schema_version);
    try stmt.bindText(4, @tagName(event.kind));
    try stmt.bindOptText(5, event.phase);
    try stmt.bindOptText(6, if (event.status) |s| s.text() else null);
    try stmt.bindInt(7, if (is_terminal) 1 else 0);
    try stmt.bindOptInt(8, optBool(event.connected));
    try stmt.bindOptInt(9, optBool(event.remote_started));
    try stmt.bindOptInt(10, event.remote_pid);
    try stmt.bindOptInt(11, event.remote_pgid);
    try stmt.bindOptText(12, event.remote_start_token);
    try stmt.bindOptInt(13, event.started_at);
    try stmt.bindOptInt(14, event.finished_at);
    try stmt.bindOptInt(15, event.duration_ms);
    try stmt.bindOptInt(16, event.exit_code);
    try stmt.bindOptInt(17, event.term_signal);
    try stmt.bindOptInt(18, optBool(event.timed_out));
    try stmt.bindOptText(19, event.transport_error);
    try stmt.bindOptText(20, event.error_code);
    try stmt.bindOptText(21, event.last_observed);
    try stmt.bindOptText(22, event.cancel_method);
    try stmt.bindOptInt(23, event.stdin.bytes);
    try stmt.bindOptText(24, event.stdin.sha256);
    try stmt.bindOptInt(25, event.stdout.bytes);
    try stmt.bindOptText(26, event.stdout.sha256);
    try stmt.bindOptInt(27, optBool(event.stdout.truncated));
    try stmt.bindOptText(28, event.stdout.digest);
    try stmt.bindOptInt(29, event.stderr.bytes);
    try stmt.bindOptText(30, event.stderr.sha256);
    try stmt.bindOptInt(31, optBool(event.stderr.truncated));
    try stmt.bindOptText(32, event.stderr.digest);
    try stmt.bindInt(33, event.observed_at);
    try stmt.bindText(34, @tagName(event.source));
    try stmt.bindOptText(35, event.correlation_id);
    try stmt.bindOptText(36, event.detail_json);
    _ = try stmt.step();
    return store.db.lastInsertRowId();
}

fn nextSeqLocked(store: *Store, request_id: []const u8) Db.Error!i64 {
    var stmt = try store.db.prepare(
        "SELECT IFNULL(MAX(seq), 0) + 1 FROM operation_events WHERE request_id = ?1",
    );
    defer stmt.deinit();
    try stmt.bindText(1, request_id);
    if (!try stmt.step()) return 1;
    return stmt.columnInt(0);
}

/// Appends a non-terminal event.
///
/// Rejects terminals at runtime rather than with `std.debug.assert`: asserts
/// vanish in ReleaseFast, and a terminal written here would bypass both the
/// transition check and the `operations.status` update, leaving a settled
/// receipt beside an operation that still reads as running.
pub fn append(store: *Store, event: Event) Error!i64 {
    if (event.kind == .terminal) return error.TerminalRequiresSettle;
    try store.db.exec("BEGIN IMMEDIATE");
    errdefer store.db.exec("ROLLBACK") catch {};
    const seq = try nextSeqLocked(store, event.request_id);
    const id = try insert(store, event, false, seq);
    try store.db.exec("COMMIT");
    return id;
}

/// A recorded terminal, as read back from the ledger.
pub const TerminalRecord = struct {
    status: op_state.Status,
    observed_at: i64,
    seq: i64,
};

pub const SettleOutcome = union(enum) {
    /// This call recorded the terminal.
    recorded: TerminalRecord,
    /// A peer already settled it. Carries the winner's terminal so the
    /// caller reconciles against it rather than overwriting.
    already_settled: TerminalRecord,
};

/// Builds the terminal event from evidence. Every field the evidence implies
/// is set here, so a caller cannot supply a contradictory combination.
fn terminalEvent(
    request_id: []const u8,
    terminal: op_state.Terminal,
    extra: TerminalExtra,
    now: i64,
) Error!Event {
    var event: Event = .{
        .request_id = request_id,
        .kind = .terminal,
        .observed_at = now,
        .source = extra.source,
        .status = terminal.status(),
        .phase = extra.phase,
        .started_at = extra.started_at,
        .finished_at = extra.finished_at orelse now,
        .duration_ms = extra.duration_ms,
        .remote_pid = extra.remote_pid,
        .remote_pgid = extra.remote_pgid,
        .remote_start_token = extra.remote_start_token,
        .stdin = extra.stdin,
        .stdout = extra.stdout,
        .stderr = extra.stderr,
        .correlation_id = extra.correlation_id,
        .detail_json = extra.detail_json,
        .error_code = terminal.errorCode(),
    };

    switch (terminal) {
        .exited => |e| {
            event.exit_code = e.exit_code;
            event.term_signal = if (e.term_signal) |s| @as(i64, s) else null;
            event.connected = true;
            event.remote_started = true;
            event.timed_out = false;
        },
        .never_submitted => |n| {
            // The whole claim is "nothing reached the remote", so any remote
            // process detail would contradict it.
            if (extra.remote_pid != null or extra.remote_pgid != null or extra.remote_start_token != null)
                return error.ContradictoryEvidence;
            event.transport_error = n.transport_error;
            event.connected = false;
            event.remote_started = false;
            event.timed_out = false;
        },
        .remote_deadline => |d| {
            event.timed_out = true;
            event.remote_started = true;
            event.duration_ms = extra.duration_ms orelse d.after_ms;
        },
        .cancelled_confirmed => |c| {
            event.cancel_method = c.method;
            event.timed_out = false;
        },
        .indeterminate => |i| {
            event.transport_error = i.reason;
            // Where we last knew the attempt to be, so reconcile knows where
            // to look. Persisted rather than kept only in memory.
            event.last_observed = i.last_observed.text();
            event.timed_out = null;
        },
    }
    return event;
}

/// Settles an operation: validates the transition, writes the single terminal
/// event and moves `operations.status`, all in one transaction.
///
/// Three things make this the only way an operation can end:
///
/// * `terminal` is an evidence variant, so `failed` needs either a real
///   remote exit status or proof the request never left this machine. A
///   transport error after submission can only produce `indeterminate`.
/// * The current status is read under the write lock and checked against
///   `canTransition`, so a terminal receipt can never disagree with the
///   status it implies (a `created` operation cannot report `completed`).
/// * The partial unique index means a peer racing us loses with
///   `error.Constraint` and is handed the winner's terminal instead of
///   overwriting it.
pub fn settle(
    store: *Store,
    request_id: []const u8,
    terminal: op_state.Terminal,
    extra: TerminalExtra,
    now: i64,
) Error!SettleOutcome {
    const status = terminal.status();
    const event = try terminalEvent(request_id, terminal, extra, now);

    try store.db.exec("BEGIN IMMEDIATE");
    errdefer store.db.exec("ROLLBACK") catch {};

    const current = try currentStatusLocked(store, request_id);
    if (!op_state.canTransition(current, status)) {
        // Already settled by a peer? Hand them the winner rather than
        // reporting a bogus programming error.
        if (current.isTerminal()) {
            if (try terminalOfLocked(store, request_id)) |winner| {
                store.db.exec("ROLLBACK") catch {};
                return .{ .already_settled = winner };
            }
        }
        store.db.exec("ROLLBACK") catch {};
        return error.IllegalTransition;
    }

    const seq = try nextSeqLocked(store, request_id);
    _ = insert(store, event, true, seq) catch |err| switch (err) {
        // The partial unique index fired: a peer settled first.
        error.Constraint => {
            const winner = try terminalOfLocked(store, request_id);
            store.db.exec("ROLLBACK") catch {};
            return .{ .already_settled = winner orelse return error.Sqlite };
        },
        else => return err,
    };

    var upd = try store.db.prepare(
        "UPDATE operations SET status = ?1, updated_at = ?2 WHERE request_id = ?3",
    );
    defer upd.deinit();
    try upd.bindText(1, status.text());
    try upd.bindInt(2, now);
    try upd.bindText(3, request_id);
    _ = try upd.step();

    try store.db.exec("COMMIT");
    return .{ .recorded = .{ .status = status, .observed_at = now, .seq = seq } };
}

pub const ResolveOutcome = union(enum) {
    resolved,
    /// Only an `indeterminate` attempt can be resolved. Carries what the
    /// status actually is, so the caller can say why it refused.
    not_indeterminate: op_state.Status,
    /// `resolved_status` is write-once; a second reconciler must not
    /// overwrite the first one's evidence.
    already_resolved: op_state.ResolvedStatus,
    unknown_operation,
};

/// Records the later-proven truth for an unsettled attempt.
///
/// Guarded because a resolution lifts the same-scope mutation barrier: writing
/// one against a still-running attempt would let a peer start a conflicting
/// change while the remote command is alive. Hence
///
/// * only `indeterminate` may be resolved (a `submitted` attempt is not
///   unknown, it is *in progress* — wait for it or reconcile it properly);
/// * `resolved_status` is write-once, enforced by a conditional UPDATE whose
///   row count is checked;
/// * the resolution and its append-only reconcile event commit together, so
///   a resolution can never exist without evidence explaining it.
pub fn resolve(
    store: *Store,
    request_id: []const u8,
    resolved: op_state.ResolvedStatus,
    evidence: []const u8,
    now: i64,
) Error!ResolveOutcome {
    try store.db.exec("BEGIN IMMEDIATE");
    errdefer store.db.exec("ROLLBACK") catch {};

    var current_status: op_state.Status = undefined;
    var current_resolution: ?op_state.ResolvedStatus = null;
    {
        var stmt = try store.db.prepare(
            "SELECT status, resolved_status FROM operations WHERE request_id = ?1",
        );
        defer stmt.deinit();
        try stmt.bindText(1, request_id);
        if (!try stmt.step()) {
            store.db.exec("ROLLBACK") catch {};
            return .unknown_operation;
        }
        current_status = try op_state.Status.parse(stmt.columnText(0));
        current_resolution = if (stmt.columnOptText(1)) |v| try op_state.ResolvedStatus.parse(v) else null;
    }

    if (current_resolution) |existing| {
        store.db.exec("ROLLBACK") catch {};
        return .{ .already_resolved = existing };
    }
    if (current_status != .indeterminate) {
        store.db.exec("ROLLBACK") catch {};
        return .{ .not_indeterminate = current_status };
    }

    {
        // Conditional update, then verify it matched: two reconcilers racing
        // must not both believe they wrote the resolution.
        var stmt = try store.db.prepare(
            \\UPDATE operations
            \\   SET resolved_status = ?1, reconciled_at = ?2,
            \\       resolution_evidence = ?3, updated_at = ?2
            \\ WHERE request_id = ?4
            \\   AND status = 'indeterminate'
            \\   AND resolved_status IS NULL
        );
        defer stmt.deinit();
        try stmt.bindText(1, resolved.text());
        try stmt.bindInt(2, now);
        try stmt.bindText(3, evidence);
        try stmt.bindText(4, request_id);
        _ = try stmt.step();
        if (store.db.changes() == 0) {
            store.db.exec("ROLLBACK") catch {};
            return .{ .already_resolved = resolved };
        }
    }

    const seq = try nextSeqLocked(store, request_id);
    _ = try insert(store, .{
        .request_id = request_id,
        .kind = .reconcile,
        .observed_at = now,
        .source = .reconcile,
        .status = resolved.toStatus(),
        .last_observed = op_state.Status.indeterminate.text(),
        .detail_json = evidence,
    }, false, seq);

    try store.db.exec("COMMIT");
    return .resolved;
}

fn currentStatusLocked(store: *Store, request_id: []const u8) Error!op_state.Status {
    var stmt = try store.db.prepare("SELECT status FROM operations WHERE request_id = ?1");
    defer stmt.deinit();
    try stmt.bindText(1, request_id);
    if (!try stmt.step()) return error.UnknownOperation;
    return try op_state.Status.parse(stmt.columnText(0));
}

fn terminalOfLocked(store: *Store, request_id: []const u8) Error!?TerminalRecord {
    var stmt = try store.db.prepare(
        "SELECT status, observed_at, seq FROM operation_events WHERE request_id = ?1 AND is_terminal = 1",
    );
    defer stmt.deinit();
    try stmt.bindText(1, request_id);
    if (!try stmt.step()) return null;
    return .{
        .status = try op_state.Status.parse(stmt.columnText(0)),
        .observed_at = stmt.columnInt(1),
        .seq = stmt.columnInt(2),
    };
}

/// The terminal event's status/time, if the operation is settled.
pub fn terminalOf(store: *Store, request_id: []const u8) Error!?TerminalRecord {
    return terminalOfLocked(store, request_id);
}

/// Full trail for `request receipt` / `job receipt`, oldest first.
pub const Row = struct {
    seq: i64,
    kind: []const u8,
    phase: ?[]const u8,
    status: ?[]const u8,
    is_terminal: bool,
    remote_pid: ?i64,
    remote_pgid: ?i64,
    exit_code: ?i64,
    term_signal: ?i64,
    timed_out: ?bool,
    duration_ms: ?i64,
    transport_error: ?[]const u8,
    error_code: ?[]const u8,
    stdout_bytes: ?i64,
    stdout_sha256: ?[]const u8,
    stderr_bytes: ?i64,
    stderr_sha256: ?[]const u8,
    observed_at: i64,
    source: []const u8,
    detail_json: ?[]const u8,
};

pub fn list(store: *Store, arena: Allocator, request_id: []const u8) (Error || Allocator.Error)![]Row {
    var out: std.ArrayList(Row) = .empty;
    var stmt = try store.db.prepare(
        \\SELECT seq, kind, phase, status, is_terminal, remote_pid, remote_pgid,
        \\       exit_code, term_signal, timed_out, duration_ms, transport_error,
        \\       error_code, stdout_bytes, stdout_sha256, stderr_bytes,
        \\       stderr_sha256, observed_at, source, detail_json
        \\FROM operation_events WHERE request_id = ?1 ORDER BY seq
    );
    defer stmt.deinit();
    try stmt.bindText(1, request_id);
    const dupOpt = struct {
        fn f(a: Allocator, v: ?[]const u8) Allocator.Error!?[]const u8 {
            return if (v) |value| try a.dupe(u8, value) else null;
        }
    }.f;
    while (try stmt.step()) {
        try out.append(arena, .{
            .seq = stmt.columnInt(0),
            .kind = try arena.dupe(u8, stmt.columnText(1)),
            .phase = try dupOpt(arena, stmt.columnOptText(2)),
            .status = try dupOpt(arena, stmt.columnOptText(3)),
            .is_terminal = stmt.columnInt(4) != 0,
            .remote_pid = stmt.columnOptInt(5),
            .remote_pgid = stmt.columnOptInt(6),
            .exit_code = stmt.columnOptInt(7),
            .term_signal = stmt.columnOptInt(8),
            .timed_out = if (stmt.columnOptInt(9)) |v| v != 0 else null,
            .duration_ms = stmt.columnOptInt(10),
            .transport_error = try dupOpt(arena, stmt.columnOptText(11)),
            .error_code = try dupOpt(arena, stmt.columnOptText(12)),
            .stdout_bytes = stmt.columnOptInt(13),
            .stdout_sha256 = try dupOpt(arena, stmt.columnOptText(14)),
            .stderr_bytes = stmt.columnOptInt(15),
            .stderr_sha256 = try dupOpt(arena, stmt.columnOptText(16)),
            .observed_at = stmt.columnInt(17),
            .source = try arena.dupe(u8, stmt.columnText(18)),
            .detail_json = try dupOpt(arena, stmt.columnOptText(19)),
        });
    }
    return out.toOwnedSlice(arena);
}
