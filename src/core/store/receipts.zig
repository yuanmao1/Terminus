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
const operations = @import("operations.zig");
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
    is_terminal: bool = false,

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

    stdin: StreamEvidence = .{},
    stdout: StreamEvidence = .{},
    stderr: StreamEvidence = .{},

    correlation_id: ?[]const u8 = null,
    /// Versioned, already-redacted structure for anything without a column.
    detail_json: ?[]const u8 = null,
};

pub const Error = Db.Error || error{ UnknownEventKind, UnknownSource, UnknownStatus };

fn optBool(v: ?bool) ?i64 {
    return if (v) |b| @as(i64, if (b) 1 else 0) else null;
}

/// Appends one event, assigning the next sequence number. Caller must hold a
/// write transaction when ordering matters relative to other writes.
fn insert(store: *Store, event: Event, seq: i64) Db.Error!i64 {
    var stmt = try store.db.prepare(
        \\INSERT INTO operation_events (
        \\  request_id, seq, schema_version, kind, phase, status, is_terminal,
        \\  connected, remote_started, remote_pid, remote_pgid, remote_start_token,
        \\  started_at, finished_at, duration_ms, exit_code, term_signal, timed_out,
        \\  transport_error, error_code,
        \\  stdin_bytes, stdin_sha256,
        \\  stdout_bytes, stdout_sha256, stdout_truncated, stdout_digest,
        \\  stderr_bytes, stderr_sha256, stderr_truncated, stderr_digest,
        \\  observed_at, source, correlation_id, detail_json
        \\) VALUES (
        \\  ?1, ?2, ?3, ?4, ?5, ?6, ?7,
        \\  ?8, ?9, ?10, ?11, ?12,
        \\  ?13, ?14, ?15, ?16, ?17, ?18,
        \\  ?19, ?20,
        \\  ?21, ?22,
        \\  ?23, ?24, ?25, ?26,
        \\  ?27, ?28, ?29, ?30,
        \\  ?31, ?32, ?33, ?34
        \\)
    );
    defer stmt.deinit();
    try stmt.bindText(1, event.request_id);
    try stmt.bindInt(2, seq);
    try stmt.bindInt(3, schema_version);
    try stmt.bindText(4, @tagName(event.kind));
    try stmt.bindOptText(5, event.phase);
    try stmt.bindOptText(6, if (event.status) |s| s.text() else null);
    try stmt.bindInt(7, if (event.is_terminal) 1 else 0);
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
    try stmt.bindOptInt(21, event.stdin.bytes);
    try stmt.bindOptText(22, event.stdin.sha256);
    try stmt.bindOptInt(23, event.stdout.bytes);
    try stmt.bindOptText(24, event.stdout.sha256);
    try stmt.bindOptInt(25, optBool(event.stdout.truncated));
    try stmt.bindOptText(26, event.stdout.digest);
    try stmt.bindOptInt(27, event.stderr.bytes);
    try stmt.bindOptText(28, event.stderr.sha256);
    try stmt.bindOptInt(29, optBool(event.stderr.truncated));
    try stmt.bindOptText(30, event.stderr.digest);
    try stmt.bindInt(31, event.observed_at);
    try stmt.bindText(32, @tagName(event.source));
    try stmt.bindOptText(33, event.correlation_id);
    try stmt.bindOptText(34, event.detail_json);
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
pub fn append(store: *Store, event: Event) Error!i64 {
    std.debug.assert(!event.is_terminal); // use `settle`
    try store.db.exec("BEGIN IMMEDIATE");
    errdefer store.db.exec("ROLLBACK") catch {};
    const seq = try nextSeqLocked(store, event.request_id);
    const id = try insert(store, event, seq);
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

/// Settles an operation: writes the single terminal event and moves
/// `operations.status`, atomically.
///
/// `terminal` is an evidence variant, so there is no way to record `failed`
/// without either a real remote exit status or proof the request never left
/// this machine. A transport error after submission can only ever produce
/// `indeterminate` (see `op_state.terminalForTransportLoss`).
pub fn settle(
    store: *Store,
    request_id: []const u8,
    terminal: op_state.Terminal,
    extra: Event,
    now: i64,
) Error!SettleOutcome {
    const status = terminal.status();

    try store.db.exec("BEGIN IMMEDIATE");
    errdefer store.db.exec("ROLLBACK") catch {};

    const seq = try nextSeqLocked(store, request_id);

    var event = extra;
    event.request_id = request_id;
    event.kind = .terminal;
    event.is_terminal = true;
    event.status = status;
    event.observed_at = now;
    event.error_code = terminal.errorCode() orelse extra.error_code;
    switch (terminal) {
        .exited => |e| {
            event.exit_code = e.exit_code;
            event.term_signal = if (e.term_signal) |s| @as(i64, s) else null;
        },
        .never_submitted => |n| {
            event.transport_error = n.transport_error;
            event.connected = false;
            event.remote_started = false;
        },
        .remote_deadline => |d| {
            event.timed_out = true;
            event.duration_ms = extra.duration_ms orelse d.after_ms;
        },
        .cancelled_confirmed => {},
        .indeterminate => |i| {
            event.transport_error = extra.transport_error orelse i.reason;
        },
    }

    _ = insert(store, event, seq) catch |err| switch (err) {
        // The partial unique index fired: a peer settled first.
        error.Constraint => {
            store.db.exec("ROLLBACK") catch {};
            const winner = try terminalOf(store, request_id);
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

/// The terminal event's status/time, if the operation is settled.
pub fn terminalOf(store: *Store, request_id: []const u8) Error!?TerminalRecord {
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
