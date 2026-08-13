//! The operation state machine.
//!
//! Every call that can produce a remote side effect is an *attempt* with an
//! immutable `request_id` and a status drawn from this module. The rules
//! below are the architecture contract, and each one is enforced by an API
//! shape rather than by documentation:
//!
//! 1. `failed` requires positive evidence — either the remote reported a
//!    real non-zero exit, or the connection layer proved the bytes never
//!    left this machine.
//! 2. `timed_out` means a *remote* deadline fired and said so. A local
//!    deadline expiring while the remote is unreachable is NOT a timeout.
//! 3. Everything else — submitted then lost, started then lost, finished
//!    but the response never arrived — is `indeterminate`.
//! 4. Reconciliation never rewrites `status`. It records the later-proven
//!    truth in `resolved_status`, so the ledger keeps "we believed X, then
//!    proved Y". Only an `indeterminate` attempt can be resolved, and only
//!    once.
//!
//! How the rules are held:
//!
//! * `operations.advance` takes a `LiveStatus`, which has no terminal
//!   members, so no caller can reach a terminal without evidence.
//! * `receipts.settle` is the sole terminal writer; it takes a `Terminal`
//!   evidence union, and no variant maps a transport failure after
//!   submission onto `failed`.
//! * `receipts.resolve` is the sole resolution writer; it refuses anything
//!   that is not an unresolved `indeterminate`.
const std = @import("std");

pub const Status = enum {
    /// Local record exists; nothing has been sent.
    created,
    /// Dialing / authenticating.
    connecting,
    /// Handed to the remote; start not yet confirmed.
    submitted,
    /// Remote confirmed a running process (pid/pgid known).
    remote_started,
    completed,
    failed,
    timed_out,
    cancelled,
    /// The remote outcome is unknown and we refuse to guess. Reconciliation
    /// may later prove the truth into `resolved_status`; this value is kept
    /// as the original observation and never overwritten.
    indeterminate,

    pub fn isTerminal(s: Status) bool {
        return switch (s) {
            .created, .connecting, .submitted, .remote_started => false,
            .completed, .failed, .timed_out, .cancelled, .indeterminate => true,
        };
    }

    /// True when the attempt may still be affecting the remote host, so a
    /// same-scope mutation must not proceed without reconcile or --force.
    pub fn blocksScope(s: Status) bool {
        return switch (s) {
            .submitted, .remote_started, .indeterminate => true,
            .created, .connecting => false,
            .completed, .failed, .timed_out, .cancelled => false,
        };
    }

    /// Strict parse. Unknown text is an error, never a default: a status we
    /// cannot interpret must not silently become `running`-ish.
    pub fn parse(raw: []const u8) error{UnknownStatus}!Status {
        return std.meta.stringToEnum(Status, raw) orelse error.UnknownStatus;
    }

    pub fn text(s: Status) []const u8 {
        return @tagName(s);
    }
};

/// The states an operation may be *advanced* into.
///
/// Terminal states are deliberately absent. `operations.advance` accepts
/// only this type, which makes "a terminal can be reached solely through
/// `settle`, with evidence" a property of the type system rather than a rule
/// a caller has to remember.
pub const LiveStatus = enum {
    created,
    connecting,
    submitted,
    remote_started,

    pub fn toStatus(s: LiveStatus) Status {
        return switch (s) {
            .created => .created,
            .connecting => .connecting,
            .submitted => .submitted,
            .remote_started => .remote_started,
        };
    }
};

/// The subset a reconciliation may prove. `indeterminate` is deliberately
/// absent: resolving to "still unknown" is not a resolution.
pub const ResolvedStatus = enum {
    completed,
    failed,
    timed_out,
    cancelled,

    pub fn parse(raw: []const u8) error{UnknownStatus}!ResolvedStatus {
        return std.meta.stringToEnum(ResolvedStatus, raw) orelse error.UnknownStatus;
    }

    pub fn text(s: ResolvedStatus) []const u8 {
        return @tagName(s);
    }

    pub fn toStatus(s: ResolvedStatus) Status {
        return switch (s) {
            .completed => .completed,
            .failed => .failed,
            .timed_out => .timed_out,
            .cancelled => .cancelled,
        };
    }
};

/// Legal forward transitions. A rejected transition is a programming error:
/// the ledger must never record a state it cannot justify from the previous
/// one. `settle` checks this inside its transaction, so a terminal receipt
/// and the status it implies can never disagree.
pub fn canTransition(from: Status, to: Status) bool {
    return switch (from) {
        // Nothing sent yet: we can start, abandon, or prove we never sent.
        .created => switch (to) {
            .connecting, .cancelled, .failed => true,
            else => false,
        },
        // Connect failures are the ONE place a transport error means failed,
        // because they prove nothing reached the remote.
        .connecting => switch (to) {
            .submitted, .failed, .cancelled, .indeterminate => true,
            else => false,
        },
        // A fast command can report start and finish in one response, so
        // submitted may jump straight to a terminal.
        .submitted => switch (to) {
            .remote_started, .completed, .failed, .timed_out, .cancelled, .indeterminate => true,
            else => false,
        },
        .remote_started => switch (to) {
            .completed, .failed, .timed_out, .cancelled, .indeterminate => true,
            else => false,
        },
        // Terminals are frozen. Reconciliation does not move `status`; it
        // records `resolved_status` beside it.
        .completed, .failed, .timed_out, .cancelled, .indeterminate => false,
    };
}

/// Evidence for a terminal state. Constructing one of these is the *only*
/// way to settle an attempt, which is what makes rule 1 unbreakable: there
/// is no variant that turns "the connection dropped after we submitted"
/// into `failed`.
pub const Terminal = union(enum) {
    /// The remote reported a real exit status (or fatal signal).
    exited: struct {
        exit_code: i32,
        term_signal: ?i32 = null,
    },
    /// The connection layer proved the request never left this machine
    /// (refused, DNS failure, auth rejected — all before submission).
    never_submitted: struct {
        transport_error: []const u8,
        error_code: []const u8 = "NEVER_SUBMITTED",
    },
    /// A remote supervisor enforced its own deadline and reported it.
    /// Not to be used for local deadlines — see `indeterminate`.
    remote_deadline: struct {
        after_ms: i64,
    },
    /// Cancellation was carried out and verified (process confirmed gone).
    cancelled_confirmed: struct {
        method: []const u8,
    },
    /// We cannot establish the remote outcome. Carries why, plus the last
    /// state we did observe, so reconcile knows where to look.
    indeterminate: struct {
        reason: []const u8,
        last_observed: Status,
        error_code: []const u8 = "INDETERMINATE",
    },

    pub fn status(t: Terminal) Status {
        return switch (t) {
            // A signal death is a failure even with exit_code 0 reported.
            .exited => |e| if (e.exit_code == 0 and e.term_signal == null) .completed else .failed,
            .never_submitted => .failed,
            .remote_deadline => .timed_out,
            .cancelled_confirmed => .cancelled,
            .indeterminate => .indeterminate,
        };
    }

    pub fn errorCode(t: Terminal) ?[]const u8 {
        return switch (t) {
            .exited => |e| if (e.exit_code == 0 and e.term_signal == null) null else "REMOTE_NONZERO_EXIT",
            .never_submitted => |n| n.error_code,
            .remote_deadline => "REMOTE_DEADLINE",
            .cancelled_confirmed => null,
            .indeterminate => |i| i.error_code,
        };
    }
};

/// What a transport failure means, given how far the attempt had progressed.
/// This is the function every SSH/daemon error path must go through instead
/// of deciding for itself.
pub fn terminalForTransportLoss(last_observed: Status, detail: []const u8) Terminal {
    return switch (last_observed) {
        // Nothing was sent, so the remote is untouched: a real failure.
        .created, .connecting => .{ .never_submitted = .{ .transport_error = detail } },
        // Bytes may already be executing. We do not know. Say so.
        .submitted, .remote_started => .{ .indeterminate = .{
            .reason = detail,
            .last_observed = last_observed,
        } },
        // Already settled: losing the connection changes nothing.
        .completed, .failed, .timed_out, .cancelled, .indeterminate => .{ .indeterminate = .{
            .reason = detail,
            .last_observed = last_observed,
        } },
    };
}

test "advance cannot express a terminal" {
    const t = std.testing;
    // Exhaustive: every LiveStatus maps to a non-terminal Status, so
    // `operations.advance` has no way to write one.
    inline for (@typeInfo(LiveStatus).@"enum".fields) |field| {
        const live: LiveStatus = @enumFromInt(field.value);
        try t.expect(!live.toStatus().isTerminal());
    }
}

test "terminals are frozen" {
    const t = std.testing;
    const terminals = [_]Status{ .completed, .failed, .timed_out, .cancelled, .indeterminate };
    for (terminals) |from| {
        try t.expect(from.isTerminal());
        inline for (@typeInfo(Status).@"enum".fields) |field| {
            const to: Status = @enumFromInt(field.value);
            // Nothing may follow a terminal — reconciliation records
            // `resolved_status` beside the observation instead of moving it.
            try t.expect(!canTransition(from, to));
        }
    }
}

test "transport loss after submission is never failed" {
    const t = std.testing;
    // Before anything is sent, a transport error is provably a failure.
    try t.expectEqual(Status.failed, terminalForTransportLoss(.connecting, "refused").status());
    try t.expectEqual(Status.failed, terminalForTransportLoss(.created, "no route").status());
    // After submission we must not guess, in either direction.
    try t.expectEqual(Status.indeterminate, terminalForTransportLoss(.submitted, "eof").status());
    try t.expectEqual(Status.indeterminate, terminalForTransportLoss(.remote_started, "reset").status());
}

test "terminal evidence maps to status" {
    const t = std.testing;
    try t.expectEqual(Status.completed, (Terminal{ .exited = .{ .exit_code = 0 } }).status());
    try t.expectEqual(Status.failed, (Terminal{ .exited = .{ .exit_code = 1 } }).status());
    // Killed by a signal is a failure even though exit_code reads 0.
    try t.expectEqual(Status.failed, (Terminal{ .exited = .{ .exit_code = 0, .term_signal = 9 } }).status());
    try t.expectEqual(Status.timed_out, (Terminal{ .remote_deadline = .{ .after_ms = 1000 } }).status());
    try t.expectEqual(Status.cancelled, (Terminal{ .cancelled_confirmed = .{ .method = "TERM" } }).status());
}

test canTransition {
    const t = std.testing;
    try t.expect(canTransition(.created, .connecting));
    try t.expect(canTransition(.connecting, .submitted));
    try t.expect(canTransition(.submitted, .remote_started));
    // Fast command: start and finish observed together.
    try t.expect(canTransition(.submitted, .completed));
    // A terminal never leads anywhere.
    try t.expect(!canTransition(.completed, .failed));
    try t.expect(!canTransition(.indeterminate, .completed));
    // Cannot go backwards.
    try t.expect(!canTransition(.remote_started, .submitted));
    try t.expect(!canTransition(.connecting, .remote_started));
    // Nothing may finish before it was ever sent.
    try t.expect(!canTransition(.created, .completed));
    try t.expect(!canTransition(.created, .timed_out));
    try t.expect(!canTransition(.created, .indeterminate));
}

test "strict parse rejects unknown status" {
    const t = std.testing;
    try t.expectEqual(Status.remote_started, try Status.parse("remote_started"));
    try t.expectEqual(Status.timed_out, try Status.parse("timed_out"));
    try t.expectError(error.UnknownStatus, Status.parse("running"));
    try t.expectError(error.UnknownStatus, Status.parse(""));
    // `reconciled` was removed: resolution lives in resolved_status, and a
    // stale reader must not silently accept the old vocabulary.
    try t.expectError(error.UnknownStatus, Status.parse("reconciled"));
    try t.expectError(error.UnknownStatus, ResolvedStatus.parse("indeterminate"));
}

test "blocksScope covers exactly the unsettled states" {
    const t = std.testing;
    try t.expect(Status.submitted.blocksScope());
    try t.expect(Status.remote_started.blocksScope());
    try t.expect(Status.indeterminate.blocksScope());
    try t.expect(!Status.completed.blocksScope());
    try t.expect(!Status.failed.blocksScope());
}
