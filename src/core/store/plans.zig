//! Fail-stop PlanRun / PhaseAttempt persistence.
//!
//! A plan is deliberately a small coordinator around already-created
//! `operations` rows. It does not execute commands, retry an operation, or
//! invent a compensating action. A caller creates an OperationAttempt through
//! the normal operation API, attaches it to one phase, and this module only
//! decides whether that phase may be associated with work yet.
//!
//! The safety boundary is `canSubmit`: a phase may be submitted only while it
//! is still pending, its predecessor is completed (or it is the first phase),
//! and a mutating phase has an explicit approval. The gate is used by the
//! transactional `attachOperation`, so the check and the phase's durable
//! association are one write. A phase whose operation becomes indeterminate
//! is never projected to failure; it remains a stop until the operation is
//! reconciled and `refreshPhase` observes the proven status.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Store = @import("Store.zig");
const Db = @import("Db.zig");
const op_state = @import("op_state.zig");

pub const schema_version: i64 = 1;

pub const Error = Db.Error || error{
    OutOfMemory,
    InvalidRequestId,
    UnknownStatus,
    UnknownRunStatus,
    UnknownPhaseStatus,
    UnknownRun,
    UnknownPhase,
    UnknownOperation,
    InvalidPhaseOrder,
    PhaseAlreadySettled,
    OperationAlreadyStarted,
    OperationAlreadyAttached,
    OperationServerMismatch,
    PreviousPhaseBlocked,
    PreviousPhaseIndeterminate,
    MutationNeedsApproval,
    ApprovalNotAllowed,
    InvalidStatusTransition,
    NoRetry,
};

/// A run is a projection of the independent phase attempts. `indeterminate`
/// is intentionally a first-class run state: it is never folded into failed.
pub const RunStatus = enum {
    created,
    running,
    completed,
    failed,
    timed_out,
    cancelled,
    indeterminate,

    pub fn parse(raw: []const u8) error{UnknownRunStatus}!RunStatus {
        return std.meta.stringToEnum(RunStatus, raw) orelse error.UnknownRunStatus;
    }

    pub fn text(status: RunStatus) []const u8 {
        return @tagName(status);
    }
};

/// Status copied from the operation attempt, with `pending` covering the
/// local-only portion before an operation is attached or submitted.
pub const PhaseStatus = enum {
    pending,
    submitted,
    completed,
    failed,
    timed_out,
    cancelled,
    indeterminate,

    pub fn parse(raw: []const u8) error{UnknownPhaseStatus}!PhaseStatus {
        return std.meta.stringToEnum(PhaseStatus, raw) orelse error.UnknownPhaseStatus;
    }

    pub fn text(status: PhaseStatus) []const u8 {
        return @tagName(status);
    }

    pub fn fromOperation(status: op_state.Status) PhaseStatus {
        return switch (status) {
            .created, .connecting => .pending,
            .submitted, .remote_started => .submitted,
            .completed => .completed,
            .failed => .failed,
            .timed_out => .timed_out,
            .cancelled => .cancelled,
            .indeterminate => .indeterminate,
        };
    }
};

/// Why a phase cannot be associated with an operation yet.
pub const Blocker = enum {
    previous_not_complete,
    previous_indeterminate,
    needs_approval,
    already_settled,
};

pub const SubmitDecision = union(enum) {
    allowed,
    blocked: Blocker,
};

/// The single ordering/approval gate. `previous` is the latest phase with a
/// lower `phase_index`; callers must not pass a phase from a different run.
pub fn canSubmit(
    previous: ?PhaseStatus,
    phase_status: PhaseStatus,
    is_mutation: bool,
    approved: bool,
) SubmitDecision {
    switch (phase_status) {
        .pending => {},
        else => return .{ .blocked = .already_settled },
    }
    if (previous) |prev| switch (prev) {
        .completed => {},
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
    /// There is intentionally one attempt per phase. A retry is a new plan,
    /// never an implicit second attempt hidden behind this API. Compensation
    /// is also never inserted here; an operator must create and approve a
    /// separate, explicit action and it remains subject to this same gate.
    attempt_no: i64 = 1,
    is_mutation: bool = true,
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

pub fn getRun(store: *Store, arena: Allocator, run_id: []const u8) (Error || Allocator.Error)!?Run {
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

pub fn createPhase(store: *Store, opts: CreatePhaseOptions) Error!i64 {
    if (opts.phase_index < 0 or opts.attempt_no != 1) return error.InvalidPhaseOrder;
    try store.db.exec("BEGIN IMMEDIATE");
    errdefer store.db.exec("ROLLBACK") catch {};
    if (try getRun(store, std.heap.page_allocator, opts.run_id) == null) return error.UnknownRun;

    // The schema permits attempt_no > 1 for historical compatibility, but the
    // production API does not. This is the no-auto-retry boundary.
    var existing = try store.db.prepare(
        "SELECT 1 FROM phase_attempts WHERE run_id = ?1 AND phase_id = ?2 LIMIT 1",
    );
    defer existing.deinit();
    try existing.bindText(1, opts.run_id);
    try existing.bindText(2, opts.phase_id);
    if (try existing.step()) return error.NoRetry;

    var order = try store.db.prepare(
        "SELECT 1 FROM phase_attempts WHERE run_id = ?1 AND phase_index = ?2 LIMIT 1",
    );
    defer order.deinit();
    try order.bindText(1, opts.run_id);
    try order.bindInt(2, opts.phase_index);
    if (try order.step()) return error.InvalidPhaseOrder;

    var stmt = try store.db.prepare(
        \\INSERT INTO phase_attempts (run_id, phase_index, phase_id, attempt_no,
        \\                            is_mutation, status, created_at, updated_at)
        \\VALUES (?1, ?2, ?3, 1, ?4, 'pending', ?5, ?5)
    );
    defer stmt.deinit();
    try stmt.bindText(1, opts.run_id);
    try stmt.bindInt(2, opts.phase_index);
    try stmt.bindText(3, opts.phase_id);
    try stmt.bindInt(4, if (opts.is_mutation) 1 else 0);
    try stmt.bindInt(5, opts.now);
    _ = try stmt.step();
    const id = store.db.lastInsertRowId();
    try store.db.exec("COMMIT");
    return id;
}

pub fn getPhase(store: *Store, arena: Allocator, run_id: []const u8, phase_id: []const u8) (Error || Allocator.Error)!?Phase {
    var stmt = try store.db.prepare(
        \\SELECT id, run_id, phase_index, phase_id, attempt_no, is_mutation,
        \\       approved_at, approved_by, request_id, status, created_at, updated_at
        \\FROM phase_attempts WHERE run_id = ?1 AND phase_id = ?2
        \\ORDER BY attempt_no DESC LIMIT 1
    );
    defer stmt.deinit();
    try stmt.bindText(1, run_id);
    try stmt.bindText(2, phase_id);
    if (!try stmt.step()) return null;
    return @as(?Phase, try rowToPhase(arena, &stmt));
}

fn rowToPhase(arena: Allocator, stmt: *Db.Stmt) (Error || Allocator.Error)!Phase {
    return .{
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
    };
}

pub fn phases(store: *Store, arena: Allocator, run_id: []const u8) (Error || Allocator.Error)![]Phase {
    var out: std.ArrayList(Phase) = .empty;
    var stmt = try store.db.prepare(
        \\SELECT id, run_id, phase_index, phase_id, attempt_no, is_mutation,
        \\       approved_at, approved_by, request_id, status, created_at, updated_at
        \\FROM phase_attempts WHERE run_id = ?1 ORDER BY phase_index, attempt_no
    );
    defer stmt.deinit();
    try stmt.bindText(1, run_id);
    while (try stmt.step()) try out.append(arena, try rowToPhase(arena, &stmt));
    return out.toOwnedSlice(arena);
}

/// Records a human approval. Approval is not inferred from a run status or an
/// environment variable and cannot be applied to a settled/attached phase.
pub fn approve(store: *Store, run_id: []const u8, phase_id: []const u8, by: []const u8, now: i64) Error!void {
    if (by.len == 0) return error.ApprovalNotAllowed;
    const phase = (try getPhase(store, std.heap.page_allocator, run_id, phase_id)) orelse return error.UnknownPhase;
    if (!phase.is_mutation or phase.status != .pending or phase.request_id != null) return error.ApprovalNotAllowed;

    var stmt = try store.db.prepare(
        \\UPDATE phase_attempts SET approved_at = ?1, approved_by = ?2, updated_at = ?1
        \\ WHERE run_id = ?3 AND phase_id = ?4 AND approved_at IS NULL AND status = 'pending'
    );
    defer stmt.deinit();
    try stmt.bindInt(1, now);
    try stmt.bindText(2, by);
    try stmt.bindText(3, run_id);
    try stmt.bindText(4, phase_id);
    _ = try stmt.step();
    if (store.db.changes() == 0) return error.ApprovalNotAllowed;
}

/// Attach an already-created operation to a phase. This function never creates
/// or submits an operation; the operation's own execution path remains the
/// sole producer of remote work.
pub fn attachOperation(
    store: *Store,
    run_id: []const u8,
    phase_id: []const u8,
    request_id: []const u8,
    now: i64,
) Error!void {
    try store.db.exec("BEGIN IMMEDIATE");
    errdefer store.db.exec("ROLLBACK") catch {};

    const phase = (try getPhase(store, std.heap.page_allocator, run_id, phase_id)) orelse return error.UnknownPhase;
    if (phase.status != .pending or phase.request_id != null) return error.PhaseAlreadySettled;
    const operation = (try Store.operations.get(store, std.heap.page_allocator, request_id)) orelse return error.UnknownOperation;
    if (operation.status != .created) return error.OperationAlreadyStarted;
    const run = (try getRun(store, std.heap.page_allocator, run_id)) orelse return error.UnknownRun;
    if (operation.server_id != run.server_id) return error.OperationServerMismatch;
    var attached = try store.db.prepare("SELECT 1 FROM phase_attempts WHERE request_id = ?1 LIMIT 1");
    defer attached.deinit();
    try attached.bindText(1, request_id);
    if (try attached.step()) return error.OperationAlreadyAttached;

    const previous = try previousStatusLocked(store, run_id, phase.phase_index);
    switch (canSubmit(previous, phase.status, phase.is_mutation, phase.approved_at != null)) {
        .allowed => {},
        .blocked => |blocker| return switch (blocker) {
            .previous_indeterminate => error.PreviousPhaseIndeterminate,
            .previous_not_complete => error.PreviousPhaseBlocked,
            .needs_approval => error.MutationNeedsApproval,
            .already_settled => error.PhaseAlreadySettled,
        },
    }

    var stmt = try store.db.prepare(
        \\UPDATE phase_attempts
        \\   SET request_id = ?1, updated_at = ?2
        \\ WHERE id = ?3 AND request_id IS NULL AND status = 'pending'
    );
    defer stmt.deinit();
    try stmt.bindText(1, request_id);
    try stmt.bindInt(2, now);
    try stmt.bindInt(3, phase.id);
    _ = try stmt.step();
    if (store.db.changes() == 0) return error.PhaseAlreadySettled;
    try store.db.exec("COMMIT");
}

/// Refreshes the phase from its operation's effective status. This is the only
/// operation-to-phase projection; it preserves indeterminate until a later
/// reconciliation supplies `resolved_status`.
pub fn refreshPhase(store: *Store, run_id: []const u8, phase_id: []const u8, now: i64) Error!PhaseStatus {
    const phase = (try getPhase(store, std.heap.page_allocator, run_id, phase_id)) orelse return error.UnknownPhase;
    const request_id = phase.request_id orelse return phase.status;
    const operation = (try Store.operations.get(store, std.heap.page_allocator, request_id)) orelse return error.UnknownOperation;
    const next = PhaseStatus.fromOperation(operation.effectiveStatus());
    if (next == phase.status) return next;
    if (phase.status != .pending and phase.status != .submitted and phase.status != .indeterminate)
        return error.InvalidStatusTransition;
    var stmt = try store.db.prepare("UPDATE phase_attempts SET status = ?1, updated_at = ?2 WHERE id = ?3");
    defer stmt.deinit();
    try stmt.bindText(1, next.text());
    try stmt.bindInt(2, now);
    try stmt.bindInt(3, phase.id);
    _ = try stmt.step();
    return next;
}

/// Refresh all phases and derive the run status. No phase is executed or
/// retried here. A run with any indeterminate phase remains indeterminate even
/// when another phase failed, because the remote effect is still unknown.
pub fn refreshRun(store: *Store, arena: Allocator, run_id: []const u8, now: i64) (Error || Allocator.Error)!RunStatus {
    if (try getRun(store, arena, run_id) == null) return error.UnknownRun;
    const rows = try phases(store, arena, run_id);
    for (rows) |p| {
        if (p.request_id == null) continue;
        _ = refreshPhase(store, run_id, p.phase_id, now) catch |err| switch (err) {
            error.UnknownPhase => return err,
            error.UnknownOperation => return err,
            else => return err,
        };
    }
    const updated = try phases(store, arena, run_id);
    const next = deriveRunStatus(updated);
    try setRunStatus(store, run_id, next, now);
    return next;
}

fn deriveRunStatus(rows: []const Phase) RunStatus {
    if (rows.len == 0) return .created;
    var all_completed = true;
    var has_pending = false;
    var has_indeterminate = false;
    var first_failure: ?PhaseStatus = null;
    for (rows) |p| switch (p.status) {
        .completed => {},
        .pending, .submitted => {
            all_completed = false;
            has_pending = true;
        },
        .indeterminate => {
            all_completed = false;
            has_indeterminate = true;
        },
        .failed, .timed_out, .cancelled => {
            all_completed = false;
            if (first_failure == null) first_failure = p.status;
        },
    };
    if (all_completed) return .completed;
    if (has_indeterminate) return .indeterminate;
    if (first_failure) |failure| return switch (failure) {
        .timed_out => .timed_out,
        .cancelled => .cancelled,
        else => .failed,
    };
    if (has_pending) return .running;
    return .failed;
}

pub fn setRunStatus(store: *Store, run_id: []const u8, status: RunStatus, now: i64) Error!void {
    if (try getRun(store, std.heap.page_allocator, run_id) == null) return error.UnknownRun;
    var stmt = try store.db.prepare("UPDATE plan_runs SET status = ?1, updated_at = ?2 WHERE run_id = ?3");
    defer stmt.deinit();
    try stmt.bindText(1, status.text());
    try stmt.bindInt(2, now);
    try stmt.bindText(3, run_id);
    _ = try stmt.step();
}

fn previousStatusLocked(store: *Store, run_id: []const u8, phase_index: i64) Error!?PhaseStatus {
    try store.db.requireTransaction();
    var stmt = try store.db.prepare(
        \\SELECT status FROM phase_attempts
        \\ WHERE run_id = ?1 AND phase_index < ?2
        \\ ORDER BY phase_index DESC LIMIT 1
    );
    defer stmt.deinit();
    try stmt.bindText(1, run_id);
    try stmt.bindInt(2, phase_index);
    if (!try stmt.step()) return null;
    return try PhaseStatus.parse(stmt.columnText(0));
}

test "canSubmit enforces fail-stop ordering and approval" {
    const t = std.testing;
    try t.expect(canSubmit(null, .pending, false, false) == .allowed);
    try t.expect(canSubmit(.completed, .pending, false, false) == .allowed);
    try t.expectEqual(Blocker.previous_not_complete, canSubmit(.failed, .pending, false, false).blocked);
    try t.expectEqual(Blocker.previous_not_complete, canSubmit(.timed_out, .pending, false, false).blocked);
    try t.expectEqual(Blocker.previous_not_complete, canSubmit(.cancelled, .pending, true, true).blocked);
    try t.expectEqual(Blocker.previous_indeterminate, canSubmit(.indeterminate, .pending, true, true).blocked);
    try t.expectEqual(Blocker.needs_approval, canSubmit(.completed, .pending, true, false).blocked);
    try t.expect(canSubmit(.completed, .pending, true, true) == .allowed);
}

test "phase status is exactly the operation projection" {
    const t = std.testing;
    const fields = @typeInfo(PhaseStatus).@"enum";
    var produced: [fields.field_names.len]bool = @splat(false);
    inline for (@typeInfo(op_state.Status).@"enum".field_names) |f_name| {
        produced[@backingInt(PhaseStatus.fromOperation(@field(op_state.Status, f_name)))] = true;
    }
    inline for (fields.field_names, 0..) |f_name, idx| try t.expect(produced[idx] or std.mem.eql(u8, f_name, "pending"));
}

test "deriveRunStatus preserves indeterminate and fail-stop terminals" {
    try std.testing.expectEqual(RunStatus.indeterminate, deriveRunStatus(&.{
        .{ .id = 1, .run_id = "r", .phase_index = 0, .phase_id = "a", .attempt_no = 1, .is_mutation = false, .approved_at = null, .approved_by = null, .request_id = null, .status = .indeterminate, .created_at = 0, .updated_at = 0 },
    }));
    try std.testing.expectEqual(RunStatus.failed, deriveRunStatus(&.{
        .{ .id = 1, .run_id = "r", .phase_index = 0, .phase_id = "a", .attempt_no = 1, .is_mutation = false, .approved_at = null, .approved_by = null, .request_id = null, .status = .failed, .created_at = 0, .updated_at = 0 },
    }));
}

test "persistent attach is fail-stop and mutation approval is explicit" {
    const fixtures = @import("gates_fixtures.zig");
    const t = std.testing;
    var scratch = try fixtures.Scratch.init(t.allocator, "plans_fail_stop");
    defer scratch.deinit();
    var store = try Store.open(scratch.path);
    defer store.close();

    try fixtures.seedServer(&store);
    const run_id = fixtures.testId("plan-run");
    try createRun(&store, .{
        .run_id = &run_id,
        .server_id = 1,
        .server_name = "lease-host",
        .plan_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        .now = 100,
    });
    _ = try createPhase(&store, .{
        .run_id = &run_id,
        .phase_index = 0,
        .phase_id = "observe",
        .is_mutation = false,
        .now = 101,
    });
    _ = try createPhase(&store, .{
        .run_id = &run_id,
        .phase_index = 1,
        .phase_id = "mutate",
        .is_mutation = true,
        .now = 101,
    });

    const first = fixtures.testId("first-operation");
    try Store.operations.create(&store, .{
        .request_id = &first,
        .server_id = 1,
        .server_name = "lease-host",
        .kind = .exec,
        .now = 102,
    });
    try attachOperation(&store, &run_id, "observe", &first, 103);

    const second = fixtures.testId("second-operation");
    try Store.operations.create(&store, .{
        .request_id = &second,
        .server_id = 1,
        .server_name = "lease-host",
        .kind = .exec,
        .now = 104,
    });
    try t.expectError(error.PreviousPhaseBlocked, attachOperation(&store, &run_id, "mutate", &second, 105));

    try approve(&store, &run_id, "mutate", "operator", 106);
    try t.expectError(error.PreviousPhaseBlocked, attachOperation(&store, &run_id, "mutate", &second, 107));

    try Store.operations.advance(&store, &first, .connecting, 108);
    try Store.operations.advance(&store, &first, .submitted, 109);
    _ = try Store.receipts.settle(&store, &first, .{ .exited = .{ .exit_code = 0 } }, .{}, 110);
    try t.expectEqual(PhaseStatus.completed, try refreshPhase(&store, &run_id, "observe", 111));
    try attachOperation(&store, &run_id, "mutate", &second, 112);
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    try t.expect((try getPhase(&store, arena_state.allocator(), &run_id, "mutate")).?.request_id != null);
}

test "every declaration in this module is compile-checked" {
    std.testing.refAllDecls(@This());
}
