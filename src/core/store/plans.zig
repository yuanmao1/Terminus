//! Fail-stop plan runs (`plan_runs`, `phase_attempts`).
//!
//! A plan is only an orchestration of `operations` — it owns no execution
//! model of its own. Its single job is to enforce ordering rules that a bare
//! sequence of commands cannot:
//!
//! * a phase is never submitted while the previous one is not `completed`;
//! * a mutating phase additionally needs an explicit approval;
//! * a phase that ended `indeterminate` halts the run until reconciled —
//!   proceeding would risk applying a change twice;
//! * nothing is retried automatically and no compensation runs on its own.
//!
//! `canSubmit` is a pure function so those rules are testable without a
//! database or a network, and so there is exactly one place that decides.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Store = @import("Store.zig");
const Db = @import("Db.zig");
const op_state = @import("op_state.zig");

pub const schema_version: i64 = 1;

pub const RunStatus = enum {
    created,
    running,
    completed,
    failed,
    timed_out,
    cancelled,
    indeterminate,
    awaiting_approval,
    awaiting_reconcile,

    pub fn parse(raw: []const u8) error{UnknownRunStatus}!RunStatus {
        return std.meta.stringToEnum(RunStatus, raw) orelse error.UnknownRunStatus;
    }

    pub fn text(s: RunStatus) []const u8 {
        return @tagName(s);
    }
};

pub const PhaseStatus = enum {
    pending,
    awaiting_approval,
    submitted,
    completed,
    failed,
    timed_out,
    cancelled,
    indeterminate,
    skipped,

    pub fn parse(raw: []const u8) error{UnknownPhaseStatus}!PhaseStatus {
        return std.meta.stringToEnum(PhaseStatus, raw) orelse error.UnknownPhaseStatus;
    }

    pub fn text(s: PhaseStatus) []const u8 {
        return @tagName(s);
    }

    /// Maps an operation's outcome onto the phase. Note the deliberate
    /// absence of any mapping that turns `indeterminate` into a failure.
    pub fn fromOperation(status: op_state.Status) PhaseStatus {
        return switch (status) {
            .created, .connecting => .pending,
            .submitted, .remote_started => .submitted,
            .completed => .completed,
            .failed => .failed,
            .timed_out => .timed_out,
            .cancelled => .cancelled,
            .indeterminate, .reconciled => .indeterminate,
        };
    }
};

pub const Error = Db.Error || error{ UnknownRunStatus, UnknownPhaseStatus, OutOfMemory };

/// Why a phase may not be submitted right now.
pub const Blocker = enum {
    /// The previous phase has not completed.
    previous_not_complete,
    /// The previous phase is unsettled; reconcile before touching the host.
    previous_indeterminate,
    /// A mutating phase without an approval.
    needs_approval,
    /// Already ran.
    already_settled,
};

pub const SubmitDecision = union(enum) {
    allowed,
    blocked: Blocker,
};

/// The single gate for "may this phase run now?".
pub fn canSubmit(
    previous: ?PhaseStatus,
    phase_status: PhaseStatus,
    is_mutation: bool,
    approved: bool,
) SubmitDecision {
    switch (phase_status) {
        .pending, .awaiting_approval => {},
        else => return .{ .blocked = .already_settled },
    }
    if (previous) |prev| switch (prev) {
        .completed, .skipped => {},
        // An unsettled predecessor is the dangerous case: its effect may or
        // may not have landed, so continuing could double-apply.
        .indeterminate => return .{ .blocked = .previous_indeterminate },
        else => return .{ .blocked = .previous_not_complete },
    };
    if (is_mutation and !approved) return .{ .blocked = .needs_approval };
    return .allowed;
}

pub const Run = struct {
    run_id: []const u8,
    server_id: ?i64,
    server_name: []const u8,
    name: ?[]const u8,
    plan_sha256: []const u8,
    plan_body_redacted: ?[]const u8,
    status: RunStatus,
    created_at: i64,
    updated_at: i64,
};

pub const CreateRunOptions = struct {
    run_id: []const u8,
    server_id: ?i64,
    server_name: []const u8,
    name: ?[]const u8 = null,
    plan_sha256: []const u8,
    plan_body_redacted: ?[]const u8 = null,
    now: i64,
};

pub fn createRun(store: *Store, opts: CreateRunOptions) Error!void {
    var stmt = try store.db.prepare(
        \\INSERT INTO plan_runs (run_id, schema_version, server_id, server_name,
        \\                       name, plan_sha256, plan_body_redacted,
        \\                       status, created_at, updated_at)
        \\VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'created', ?8, ?8)
    );
    defer stmt.deinit();
    try stmt.bindText(1, opts.run_id);
    try stmt.bindInt(2, schema_version);
    try stmt.bindOptInt(3, opts.server_id);
    try stmt.bindText(4, opts.server_name);
    try stmt.bindOptText(5, opts.name);
    try stmt.bindText(6, opts.plan_sha256);
    try stmt.bindOptText(7, opts.plan_body_redacted);
    try stmt.bindInt(8, opts.now);
    _ = try stmt.step();
}

pub fn setRunStatus(store: *Store, run_id: []const u8, status: RunStatus, now: i64) Error!void {
    var stmt = try store.db.prepare(
        "UPDATE plan_runs SET status = ?1, updated_at = ?2 WHERE run_id = ?3",
    );
    defer stmt.deinit();
    try stmt.bindText(1, status.text());
    try stmt.bindInt(2, now);
    try stmt.bindText(3, run_id);
    _ = try stmt.step();
}

pub fn getRun(store: *Store, arena: Allocator, run_id: []const u8) Error!?Run {
    var stmt = try store.db.prepare(
        \\SELECT run_id, server_id, server_name, name, plan_sha256,
        \\       plan_body_redacted, status, created_at, updated_at
        \\FROM plan_runs WHERE run_id = ?1
    );
    defer stmt.deinit();
    try stmt.bindText(1, run_id);
    if (!try stmt.step()) return null;
    return .{
        .run_id = try arena.dupe(u8, stmt.columnText(0)),
        .server_id = stmt.columnOptInt(1),
        .server_name = try arena.dupe(u8, stmt.columnText(2)),
        .name = if (stmt.columnOptText(3)) |v| try arena.dupe(u8, v) else null,
        .plan_sha256 = try arena.dupe(u8, stmt.columnText(4)),
        .plan_body_redacted = if (stmt.columnOptText(5)) |v| try arena.dupe(u8, v) else null,
        .status = try RunStatus.parse(stmt.columnText(6)),
        .created_at = stmt.columnInt(7),
        .updated_at = stmt.columnInt(8),
    };
}

pub const Phase = struct {
    id: i64,
    run_id: []const u8,
    phase_index: i64,
    phase_id: []const u8,
    attempt_no: i64,
    is_mutation: bool,
    approved_at: ?i64,
    approved_by: ?[]const u8,
    request_id: ?[]const u8,
    status: PhaseStatus,
    created_at: i64,
    updated_at: i64,
};

pub const CreatePhaseOptions = struct {
    run_id: []const u8,
    phase_index: i64,
    phase_id: []const u8,
    attempt_no: i64 = 1,
    is_mutation: bool = false,
    now: i64,
};

pub fn createPhase(store: *Store, opts: CreatePhaseOptions) Error!i64 {
    var stmt = try store.db.prepare(
        \\INSERT INTO phase_attempts (run_id, phase_index, phase_id, attempt_no,
        \\                            is_mutation, status, created_at, updated_at)
        \\VALUES (?1, ?2, ?3, ?4, ?5, 'pending', ?6, ?6)
    );
    defer stmt.deinit();
    try stmt.bindText(1, opts.run_id);
    try stmt.bindInt(2, opts.phase_index);
    try stmt.bindText(3, opts.phase_id);
    try stmt.bindInt(4, opts.attempt_no);
    try stmt.bindInt(5, if (opts.is_mutation) 1 else 0);
    try stmt.bindInt(6, opts.now);
    _ = try stmt.step();
    return store.db.lastInsertRowId();
}

/// Records an explicit approval (B13: `--approve <phase-id>`; no interactive
/// prompt, so the decision is auditable rather than ambient).
pub fn approve(store: *Store, run_id: []const u8, phase_id: []const u8, by: []const u8, now: i64) Error!bool {
    var stmt = try store.db.prepare(
        \\UPDATE phase_attempts SET approved_at = ?1, approved_by = ?2, updated_at = ?1
        \\ WHERE run_id = ?3 AND phase_id = ?4 AND approved_at IS NULL
    );
    defer stmt.deinit();
    try stmt.bindInt(1, now);
    try stmt.bindText(2, by);
    try stmt.bindText(3, run_id);
    try stmt.bindText(4, phase_id);
    _ = try stmt.step();
    return store.db.changes() > 0;
}

pub fn setPhaseStatus(
    store: *Store,
    id: i64,
    status: PhaseStatus,
    request_id: ?[]const u8,
    now: i64,
) Error!void {
    var stmt = try store.db.prepare(
        \\UPDATE phase_attempts
        \\   SET status = ?1, request_id = COALESCE(?2, request_id), updated_at = ?3
        \\ WHERE id = ?4
    );
    defer stmt.deinit();
    try stmt.bindText(1, status.text());
    try stmt.bindOptText(2, request_id);
    try stmt.bindInt(3, now);
    try stmt.bindInt(4, id);
    _ = try stmt.step();
}

pub fn phases(store: *Store, arena: Allocator, run_id: []const u8) Error![]Phase {
    var out: std.ArrayList(Phase) = .empty;
    var stmt = try store.db.prepare(
        \\SELECT id, run_id, phase_index, phase_id, attempt_no, is_mutation,
        \\       approved_at, approved_by, request_id, status, created_at, updated_at
        \\FROM phase_attempts WHERE run_id = ?1 ORDER BY phase_index, attempt_no
    );
    defer stmt.deinit();
    try stmt.bindText(1, run_id);
    while (try stmt.step()) {
        try out.append(arena, .{
            .id = stmt.columnInt(0),
            .run_id = try arena.dupe(u8, stmt.columnText(1)),
            .phase_index = stmt.columnInt(2),
            .phase_id = try arena.dupe(u8, stmt.columnText(3)),
            .attempt_no = stmt.columnInt(4),
            .is_mutation = stmt.columnInt(5) != 0,
            .approved_at = stmt.columnOptInt(6),
            .approved_by = if (stmt.columnOptText(7)) |v| try arena.dupe(u8, v) else null,
            .request_id = if (stmt.columnOptText(8)) |v| try arena.dupe(u8, v) else null,
            .status = try PhaseStatus.parse(stmt.columnText(9)),
            .created_at = stmt.columnInt(10),
            .updated_at = stmt.columnInt(11),
        });
    }
    return out.toOwnedSlice(arena);
}

test "canSubmit enforces fail-stop ordering" {
    const t = std.testing;
    // First phase, read-only: nothing in the way.
    try t.expect(canSubmit(null, .pending, false, false) == .allowed);
    // Previous completed: continue.
    try t.expect(canSubmit(.completed, .pending, false, false) == .allowed);

    // Previous failed or timed out: stop.
    try t.expectEqual(Blocker.previous_not_complete, canSubmit(.failed, .pending, false, false).blocked);
    try t.expectEqual(Blocker.previous_not_complete, canSubmit(.timed_out, .pending, false, false).blocked);
    try t.expectEqual(Blocker.previous_not_complete, canSubmit(.submitted, .pending, false, false).blocked);
}

test "canSubmit halts on an unsettled predecessor" {
    const t = std.testing;
    // The critical case: we do not know whether the previous phase landed,
    // so running the next one could apply a change twice.
    try t.expectEqual(
        Blocker.previous_indeterminate,
        canSubmit(.indeterminate, .pending, false, false).blocked,
    );
    // Even an approved mutation stays blocked.
    try t.expectEqual(
        Blocker.previous_indeterminate,
        canSubmit(.indeterminate, .pending, true, true).blocked,
    );
}

test "canSubmit requires approval for mutations only" {
    const t = std.testing;
    try t.expectEqual(Blocker.needs_approval, canSubmit(.completed, .pending, true, false).blocked);
    try t.expect(canSubmit(.completed, .pending, true, true) == .allowed);
    try t.expect(canSubmit(.completed, .pending, false, false) == .allowed);
}

test "canSubmit refuses to rerun a settled phase" {
    const t = std.testing;
    for ([_]PhaseStatus{ .completed, .failed, .submitted, .cancelled, .indeterminate }) |status| {
        try t.expectEqual(Blocker.already_settled, canSubmit(.completed, status, false, true).blocked);
    }
}

test "an indeterminate operation never becomes a failed phase" {
    const t = std.testing;
    try t.expectEqual(PhaseStatus.indeterminate, PhaseStatus.fromOperation(.indeterminate));
    try t.expectEqual(PhaseStatus.completed, PhaseStatus.fromOperation(.completed));
    try t.expectEqual(PhaseStatus.failed, PhaseStatus.fromOperation(.failed));
}
