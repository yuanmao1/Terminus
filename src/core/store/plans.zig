//! The fail-stop ordering rule for plan phases — **the rule only**.
//!
//! ## What is implemented
//!
//! `canSubmit`, a pure function answering "may this phase run now?", and
//! `PhaseStatus.fromOperation`, which projects an operation's outcome onto a
//! phase. Both are total, allocation-free and covered by the tests below.
//!
//! ## What is not implemented, and is not pending here
//!
//! There is no orchestrator, no persistence, and no `plan` verb. Nothing in
//! the tree calls `canSubmit`; `dispatch.TopCommand` has no `plan`, and the
//! only reference to this module is `Store.plans`.
//!
//! The `plan_runs` and `phase_attempts` tables exist and stay
//! (`migrate.zig` v7) — they are a deliberate advance on goal 16 (fail-stop
//! PlanRun / PhaseAttempt), which `docs/v2.0-progress.md` records as blocked
//! on an undecided question: plan mutation approval and reconciliation
//! semantics. This module used to also carry seven `plan_runs` /
//! `phase_attempts` CRUD functions written ahead of that decision. They had
//! no caller and no test, and because Zig analyses function bodies lazily and
//! `refAllDecls` is not recursive, their bodies were never semantically
//! analysed by `zig build test` at all — a `@compileError` planted in one of
//! them left 409/409 passing. They were seven unchecked guesses at an
//! undecided design, so they were removed; whoever settles goal 16 writes the
//! persistence against the answer rather than against them.
//!
//! The rule is kept because it is decidable without that answer: an
//! `indeterminate` phase must halt the run whatever the storage looks like.
//!
//! `refAllDecls` at the bottom is what stops the same rot recurring here: it
//! forces every declaration in this file to be analysed even while no
//! production caller exists.
const std = @import("std");
const op_state = @import("op_state.zig");

/// The state of one phase attempt.
///
/// Exactly the image of `fromOperation` — every variant is reachable from
/// some `op_state.Status`, and nothing else may be added without a producer.
/// `phaseStatusIsExactlyTheImageOfFromOperation` below holds that.
pub const PhaseStatus = enum {
    pending,
    submitted,
    completed,
    failed,
    timed_out,
    cancelled,
    indeterminate,

    /// Maps an operation's outcome onto the phase. Note the deliberate
    /// absence of any mapping that turns `indeterminate` into a failure.
    /// A resolved operation is read through `Operation.effectiveStatus()`
    /// before it gets here, so resolution is handled by the caller rather
    /// than by a second status vocabulary.
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
///
/// Approval is the `approved` parameter, not a status: a phase waiting on one
/// is `.pending` with `approved = false`. There used to be an
/// `awaiting_approval` variant as well, which encoded the same fact a second
/// way and could disagree with this argument; and a `skipped` variant that
/// nothing could produce or skip. Both are gone.
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
        // An unsettled predecessor is the dangerous case: its effect may or
        // may not have landed, so continuing could double-apply.
        .indeterminate => return .{ .blocked = .previous_indeterminate },
        else => return .{ .blocked = .previous_not_complete },
    };
    if (is_mutation and !approved) return .{ .blocked = .needs_approval };
    return .allowed;
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

// The gate on the reduction above.
//
// This module has no production caller, so nothing but this test stands
// between it and a second vocabulary of statuses nobody can produce — which
// is what `awaiting_approval`, `skipped` and the whole `RunStatus` enum were.
// Every `PhaseStatus` variant must be the image of some `op_state.Status`,
// and every `op_state.Status` must land somewhere. Adding a variant to either
// enum without wiring `fromOperation` fails here.
test "PhaseStatus is exactly the image of fromOperation" {
    const t = std.testing;
    const fields = @typeInfo(PhaseStatus).@"enum".fields;
    var produced = [_]bool{false} ** fields.len;
    inline for (@typeInfo(op_state.Status).@"enum".fields) |f| {
        produced[@intFromEnum(PhaseStatus.fromOperation(@field(op_state.Status, f.name)))] = true;
    }
    inline for (fields, 0..) |f, idx| {
        t.expect(produced[idx]) catch {
            std.debug.print(
                "PhaseStatus.{s} has no op_state.Status that produces it\n",
                .{f.name},
            );
            return error.PhaseStatusVariantHasNoProducer;
        };
    }
}

// Forces every declaration in this file to be analysed.
//
// Not decoration: before the reduction, seven `pub fn`s here were referenced
// by nothing — not by production, not by a test, and not by `Store.zig`'s
// `refAllDecls(Store)`, which is a single-level `inline for` over `Store`'s
// own decls and does not descend into an imported module's. Zig analyses a
// function body only when something references it, so those seven were never
// compiled by `zig build test`. Same reasoning as `control.zig`'s.
test "every decl in this module is compile-checked" {
    std.testing.refAllDecls(@This());
}
