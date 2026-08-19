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

    /// Whether the attempt has yet to hand its command to the remote.
    ///
    /// The window in which a commitment made *in advance* is still in advance
    /// of anything. `transfers` guards three statements on it: a checkpoint may
    /// only be minted, may only declare the digest it will be judged by, and
    /// may only be taken over by an heir, while that heir has sent nothing. A
    /// checkpoint minted after submission describes bytes already in flight,
    /// and a digest declared then is indistinguishable from a reading of
    /// whatever landed.
    ///
    /// No terminal is in the window, including the two that end without ever
    /// submitting (`never_submitted` proves the command did not leave, and
    /// `local_abandon` gives up before it does). A settled attempt has nothing
    /// left to commit to, and letting one adopt a transfer would hand live work
    /// to an operation that has already published its verdict.
    ///
    /// Exhaustive with no `else`, so a new status has to be classified rather
    /// than defaulting into whichever answer the author happened to write last.
    pub fn beforeSubmission(s: Status) bool {
        return switch (s) {
            .created, .connecting => true,
            .submitted, .remote_started => false,
            .completed, .failed, .timed_out, .cancelled, .indeterminate => false,
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

/// The statuses satisfying a role predicate, in enum declaration order.
fn statusesWhere(comptime role: fn (Status) bool) []const Status {
    comptime {
        var out: []const Status = &[_]Status{};
        for (@typeInfo(Status).@"enum".fields) |field| {
            const s: Status = @enumFromInt(field.value);
            if (role(s)) out = out ++ &[_]Status{s};
        }
        return out;
    }
}

/// Renders the statuses satisfying `role` as a SQL `IN` list:
/// `'created','connecting'`.
///
/// This module owns the status vocabulary, so it owns the lists too. Every
/// statement in `transfers` that constrains `operations.status` used to spell
/// its own out — three copies of `('created','connecting')`, none of which any
/// predicate here could reach. That is the same shape of duplication that let
/// the checkpoint states drift from the index enforcing them: the Zig predicate
/// moves, the hand-typed SQL does not, and nothing fails until a row is stuck.
///
/// An empty predicate is a compile error rather than a list nothing matches.
/// `transfers.State`'s renderer maps the empty set to `NULL` because "this
/// target has no legal predecessor" is a real answer there; a status set with
/// no members is only ever a predicate written by mistake.
pub fn sqlList(comptime role: fn (Status) bool) []const u8 {
    comptime {
        const members = statusesWhere(role);
        if (members.len == 0) @compileError(
            "an empty status list matches no operation, which is never what a guard means",
        );
        var out: []const u8 = "";
        for (members, 0..) |s, i| {
            out = out ++ (if (i == 0) "" else ",") ++ "'" ++ @tagName(s) ++ "'";
        }
        return out;
    }
}

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
        // because they prove the command was never handed over.
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
    /// The user's command was never submitted: the connection layer proved
    /// it did not leave this machine (refused, DNS failure, auth rejected —
    /// all before submission).
    ///
    /// This is deliberately narrower than "the remote was not touched".
    /// Setup before submission — staging a script into a temp file, `tmux
    /// new-session` — really does reach the host, and can leave artefacts
    /// behind when the attempt then dies. What this variant claims, and all
    /// it claims, is that the *command the caller asked for* did not run. A
    /// wider reading would be a lie a leftover `/tmp` file could disprove.
    never_submitted: struct {
        transport_error: []const u8,
        error_code: []const u8 = "NEVER_SUBMITTED",
    },
    /// A remote supervisor enforced its own deadline and reported it.
    /// Not to be used for local deadlines — see `indeterminate`.
    remote_deadline: struct {
        after_ms: i64,
    },
    /// Nothing had been handed over, so there is nothing to stop. Only
    /// legitimate before submission.
    local_abandon: struct {
        reason: []const u8,
    },
    /// A remote process was signalled *and its absence verified*.
    ///
    /// `absence_verified_at` and `verification_method` are required on
    /// purpose. "We sent TERM" is not evidence that anything stopped; a
    /// free-text method string alone would let a caller mark an operation
    /// `cancelled` — releasing the scope barrier — while the process tree is
    /// still alive. If absence could not be established, the honest terminal
    /// is `indeterminate`, and this variant cannot be constructed to say
    /// otherwise.
    ///
    /// `pid` is optional because proof comes at different granularities: a
    /// helper verifies a specific process, while tmux verifies that the
    /// session (and with it the process group) is gone. How strong the proof
    /// is belongs in the operation's recorded capability, not here.
    remote_cancel_confirmed: struct {
        pid: ?i64 = null,
        /// Process start time, so a recycled pid cannot masquerade as ours.
        start_token: ?[]const u8 = null,
        term_sent: bool,
        kill_sent: bool,
        /// When the process was observed to be gone.
        absence_verified_at: i64,
        /// How absence was established (e.g. "kill -0 -pgid => ESRCH").
        verification_method: []const u8,
    },
    /// A live terminal accepted the caller's bytes, and that is the whole of
    /// what was established.
    ///
    /// `terminus write` types input into a shell somebody else is running. The
    /// remote answers exactly one question — did the terminal take these bytes
    /// — and answers nothing else: the input may not have started, may not
    /// parse, may run for an hour, may fail. There is no exit status anywhere
    /// in that sentence, which is why this is a variant of its own rather than
    /// `exited` with a zero in it. A receipt carrying `exit_code = 0` for a
    /// write would say, in the column an auditor reads first, that a command
    /// succeeded. None did; one was typed.
    ///
    /// What it carries is what was taken — the byte count and the digest of
    /// exactly those bytes — because that is the only fact this terminal has.
    /// They live in the evidence rather than in `receipts.TerminalExtra` so
    /// that a receipt recording an acceptance cannot omit what was accepted,
    /// the same reason `ResultRecordReading.foreign` carries its claimed id in
    /// the type.
    input_accepted: struct {
        bytes: i64,
        /// Hex SHA-256 of the accepted bytes.
        sha256: []const u8,
    },
    /// A live terminal refused the caller's bytes *before the shell was
    /// touched*, so they provably did not reach it.
    ///
    /// The negative counterpart of `input_accepted`, and a proven failure
    /// rather than an unknown: the remote answered, and what it answered is
    /// that there was nothing to type into.
    ///
    /// Deliberately not `never_submitted`. That variant claims the bytes never
    /// left this machine; these did — the remote received them and declined to
    /// deliver them — and `canSettle` refuses it after submission for exactly
    /// that reason. Widening `never_submitted` instead would have let any
    /// attempt claim, from `submitted`, that nothing was ever handed over.
    ///
    /// Only for an answer that establishes the shell was untouched. A remote
    /// verdict that cannot tell "nothing was typed" from "the text landed and
    /// what followed did not" is `indeterminate`, not this: a caller told
    /// `failed` retries, and a retry types the same bytes into a pane that may
    /// already hold them.
    input_refused: struct {
        /// What the remote answered, e.g. "the session does not exist".
        reason: []const u8,
        error_code: []const u8 = "INPUT_REFUSED",
    },
    /// The act was submitted, and the host's own answer establishes that it did
    /// not take effect.
    ///
    /// The terminal for a failure that is **proven after submission**, which no
    /// variant above could express. `never_submitted` claims the command never
    /// left this machine and `canSettle` refuses it once anything has been handed
    /// over, so an attempt that got an answer proving its own failure had only
    /// `indeterminate` — "we could not establish what happened" — for something
    /// that had been established. That is a lie in the conservative direction: it
    /// never fakes success, but it blocks the scope of an attempt whose outcome is
    /// known and sends an operator to reconcile a settled question.
    ///
    /// Three places wanted it and all three settled `indeterminate` instead: a
    /// session identity mismatch, a `session rm` whose kill was sent and whose
    /// host reports the session still present, and `error.TmuxMissing` after
    /// submission, which proves the kill never ran.
    ///
    /// **Why a variant of its own, rather than either cheaper answer.**
    /// Reusing `input_refused` was rejected: it already means the right thing —
    /// "the remote answered, and nothing of ours was touched" — but its *name*
    /// is about input, and an identity mismatch types nothing. `input_accepted`
    /// and `input_refused` exist in the first place because settling a write as
    /// `.exited{0}` wrote a false word into the column an auditor reads first
    /// (`7d0898a`); reusing an input-named terminal for an act that offers no
    /// bytes repeats that mistake one level up. Reusing `indeterminate` with a
    /// distinct `error_code` was rejected for the reason given above: a mismatch
    /// is *proven*, and recording a proof as an unknown bars the scope. The cost
    /// of the variant — the build stopping in `receipts.terminalDescribesKind`
    /// for every kind — is the forcing function, not the objection.
    ///
    /// **Not for a kind whose verdict is an exit status.** For an `exec` or a
    /// `job` a proven post-submission failure is `exited` with the status that
    /// caused it, and for a `session_write` it is `input_refused`, which is this
    /// same shape of claim one axis over. `receipts.terminalDescribesKind` admits
    /// this only for a kind that supervises somebody else's subject, so it cannot
    /// be used to record a failure without the number or the reason the kind's own
    /// variant would have carried.
    ///
    /// `observation` is what was read, and `canSettle` refuses an empty one for
    /// the reason `remote_cancel_confirmed.absence_verified_at` and
    /// `destination_absent.verification_method` are required: "it failed" is a
    /// conclusion, and a receipt carrying the conclusion with no reading behind it
    /// cannot be argued with afterwards by anyone who doubts it. `error_code` has
    /// **no default**, unlike every other code in this union: there is no generic
    /// proven failure — each site knows which one it proved — and a default is how
    /// three different proofs would come to file under one word.
    proven_failure: struct {
        /// The reading that establishes the failure, e.g. "tmux has-session
        /// reported the session still present after kill-session".
        observation: []const u8,
        /// Machine word for *which* proven failure this is. Required.
        error_code: []const u8,
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
            .local_abandon, .remote_cancel_confirmed => .cancelled,
            // The operation is "hand these bytes to that terminal", and the
            // terminal took them. Nothing about the input's own fate is
            // claimed, here or anywhere else on the receipt.
            .input_accepted => .completed,
            .input_refused => .failed,
            // Proven, so it is a failure and not an unknown. That is the whole
            // point of the variant: `indeterminate` here would block a scope over
            // a question the host already answered.
            .proven_failure => .failed,
            .indeterminate => .indeterminate,
        };
    }

    pub fn errorCode(t: Terminal) ?[]const u8 {
        return switch (t) {
            .exited => |e| if (e.exit_code == 0 and e.term_signal == null) null else "REMOTE_NONZERO_EXIT",
            .never_submitted => |n| n.error_code,
            .remote_deadline => "REMOTE_DEADLINE",
            .local_abandon, .remote_cancel_confirmed => null,
            .input_accepted => null,
            .input_refused => |r| r.error_code,
            .proven_failure => |p| p.error_code,
            .indeterminate => |i| i.error_code,
        };
    }
};

/// What a transport failure means, given how far the attempt had progressed.
/// This is the function every SSH/daemon error path must go through instead
/// of deciding for itself.
pub fn terminalForTransportLoss(last_observed: Status, detail: []const u8) Terminal {
    return switch (last_observed) {
        // The command was never handed over, so it provably did not run: a
        // real failure. (Setup may already have touched the host — see
        // `never_submitted` — but the caller's command did not.)
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

/// Whether this evidence can legitimately settle an attempt in state `from`.
///
/// `canTransition` alone is not enough, because several evidence variants map
/// onto the same status and a status check cannot tell them apart. Without
/// this, the ledger would accept:
///
/// * `submitted` + `never_submitted` → `failed` — a receipt that claims both
///   that we handed the work over and that we never did;
/// * `created` + `exited(1)` → `failed` — an exit status, with
///   `connected = true`, for an attempt that never reached a connection.
///
/// Both are `failed`, so only the evidence distinguishes them.
pub fn canSettle(from: Status, terminal: Terminal) bool {
    // Terminals are frozen; reconciliation annotates them instead.
    if (from.isTerminal()) return false;
    return switch (terminal) {
        // Only credible while nothing has been handed over.
        .never_submitted => switch (from) {
            .created, .connecting => true,
            else => false,
        },
        // A real exit status requires something that actually ran.
        .exited, .remote_deadline => switch (from) {
            .submitted, .remote_started => true,
            else => false,
        },
        // Abandoning is only meaningful while nothing has been handed over.
        .local_abandon => switch (from) {
            .created, .connecting => true,
            else => false,
        },
        // Once work is out there, `cancelled` requires verified absence.
        // Sending a signal is not the same as the process being gone; if
        // absence could not be established the terminal is `indeterminate`.
        .remote_cancel_confirmed => switch (from) {
            .submitted, .remote_started => true,
            else => false,
        },
        // A terminal's answer about bytes it was offered only exists once they
        // were offered, and offering them *is* submission. Before that nothing
        // has been handed over and there is nobody to have answered — an
        // acceptance recorded from `created` would be a `completed` receipt
        // for an attempt that never dialed.
        .input_accepted, .input_refused => switch (from) {
            .submitted, .remote_started => true,
            else => false,
        },
        // A failure the host proved, so there has to have been something for it to
        // answer about: the act must be out there. Before submission the accurate
        // variant is `never_submitted` — the command did not leave this machine —
        // and admitting this one there would let an attempt that never dialled
        // record a *remote* proof of its failure.
        //
        // The observation is required to be non-empty here rather than only by the
        // type, for the reason `resolve` refuses an empty `verification_method`: a
        // field a caller can satisfy with `""` is the conclusion without the
        // reading, and this is the only guard between "the host proved it" and a
        // receipt that merely says so. The code is required for the same reason —
        // it is the machine-readable half, and a settlement carrying an empty one
        // would leave a caller branching on prose.
        .proven_failure => |p| switch (from) {
            .submitted, .remote_started => p.observation.len > 0 and p.error_code.len > 0,
            else => false,
        },
        // Only work that was in flight can become unknown, and the recorded
        // `last_observed` has to be the state we were actually in — otherwise
        // the field a reconciler navigates by would be fiction.
        .indeterminate => |i| switch (from) {
            .connecting, .submitted, .remote_started => i.last_observed == from,
            else => false,
        },
    };
}

test canSettle {
    const t = std.testing;

    // The two combinations a status-only check lets through.
    try t.expect(!canSettle(.submitted, .{ .never_submitted = .{ .transport_error = "eof" } }));
    try t.expect(!canSettle(.created, .{ .exited = .{ .exit_code = 1 } }));

    // ...and their legitimate counterparts.
    try t.expect(canSettle(.connecting, .{ .never_submitted = .{ .transport_error = "refused" } }));
    try t.expect(canSettle(.created, .{ .never_submitted = .{ .transport_error = "no route" } }));
    try t.expect(canSettle(.submitted, .{ .exited = .{ .exit_code = 1 } }));
    try t.expect(canSettle(.remote_started, .{ .exited = .{ .exit_code = 0 } }));

    // A remote deadline needs a remote that accepted the work.
    try t.expect(!canSettle(.connecting, .{ .remote_deadline = .{ .after_ms = 10 } }));
    try t.expect(canSettle(.remote_started, .{ .remote_deadline = .{ .after_ms = 10 } }));

    // Cancellation before submission is a local abandonment; after, it needs
    // verified absence. Neither is expressible in the other's stage.
    try t.expect(canSettle(.created, .{ .local_abandon = .{ .reason = "user aborted" } }));
    try t.expect(!canSettle(.remote_started, .{ .local_abandon = .{ .reason = "user aborted" } }));
    const verified: Terminal = .{ .remote_cancel_confirmed = .{
        .pid = 42,
        .term_sent = true,
        .kill_sent = false,
        .absence_verified_at = 1000,
        .verification_method = "kill -0 => ESRCH",
    } };
    try t.expect(canSettle(.remote_started, verified));
    try t.expect(canSettle(.submitted, verified));
    // Nothing was ever started, so there is no absence to verify.
    try t.expect(!canSettle(.created, verified));
    try t.expect(!canSettle(.connecting, verified));

    // last_observed must match reality, so the field can be trusted.
    try t.expect(canSettle(.submitted, .{ .indeterminate = .{ .reason = "eof", .last_observed = .submitted } }));
    try t.expect(!canSettle(.submitted, .{ .indeterminate = .{ .reason = "eof", .last_observed = .remote_started } }));
    try t.expect(!canSettle(.created, .{ .indeterminate = .{ .reason = "eof", .last_observed = .created } }));

    // Nothing settles an already-settled attempt.
    try t.expect(!canSettle(.completed, .{ .exited = .{ .exit_code = 0 } }));
    try t.expect(!canSettle(.indeterminate, .{ .exited = .{ .exit_code = 0 } }));

    // A terminal's answer about bytes it was offered needs the bytes to have
    // been offered, which is submission. Nothing before that has handed
    // anything over, so there is nobody to have answered.
    const accepted: Terminal = .{ .input_accepted = .{ .bytes = 5, .sha256 = "abc" } };
    const refused: Terminal = .{ .input_refused = .{ .reason = "no such session" } };
    try t.expect(canSettle(.submitted, accepted));
    try t.expect(canSettle(.submitted, refused));
    try t.expect(!canSettle(.created, accepted));
    try t.expect(!canSettle(.connecting, accepted));
    try t.expect(!canSettle(.created, refused));
    try t.expect(!canSettle(.connecting, refused));

    // A failure the host proved is admissible exactly where the answer could have
    // come from: after submission. Before it, `never_submitted` is the accurate
    // variant and this one would claim a remote proof for an attempt that never
    // dialled — the same shape of mistake as `submitted` + `never_submitted`, in
    // the other direction.
    const proven: Terminal = .{ .proven_failure = .{
        .observation = "tmux has-session reported the session still present after kill-session",
        .error_code = "SESSION_SURVIVED_KILL",
    } };
    try t.expect(canSettle(.submitted, proven));
    try t.expect(canSettle(.remote_started, proven));
    try t.expect(!canSettle(.created, proven));
    try t.expect(!canSettle(.connecting, proven));
    try t.expect(!canSettle(.failed, proven));

    // The reading and the machine word are both required, and "required" is
    // enforced rather than documented: neither can be satisfied with `""`.
    try t.expect(!canSettle(.submitted, .{ .proven_failure = .{
        .observation = "",
        .error_code = "SESSION_SURVIVED_KILL",
    } }));
    try t.expect(!canSettle(.submitted, .{ .proven_failure = .{
        .observation = "tmux has-session reported the session still present",
        .error_code = "",
    } }));
}

test "terminalForTransportLoss always produces settleable evidence" {
    const t = std.testing;
    // The single decision point must never hand back something `settle`
    // would then reject.
    for ([_]Status{ .created, .connecting, .submitted, .remote_started }) |from| {
        const terminal = terminalForTransportLoss(from, "dropped");
        try t.expect(canSettle(from, terminal));
    }
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
    try t.expectEqual(Status.cancelled, (Terminal{ .local_abandon = .{ .reason = "aborted" } }).status());
    try t.expectEqual(Status.cancelled, (Terminal{ .remote_cancel_confirmed = .{
        .pid = 1,
        .term_sent = true,
        .kill_sent = true,
        .absence_verified_at = 5,
        .verification_method = "ps",
    } }).status());
    // A terminal took the bytes, and that is all. `completed` is the
    // operation's own verdict — the bytes were delivered — and it carries no
    // error code because nothing failed and no command was judged.
    try t.expectEqual(
        Status.completed,
        (Terminal{ .input_accepted = .{ .bytes = 4, .sha256 = "abcd" } }).status(),
    );
    try t.expectEqual(
        @as(?[]const u8, null),
        (Terminal{ .input_accepted = .{ .bytes = 4, .sha256 = "abcd" } }).errorCode(),
    );
    // A refusal read before the shell was touched is a proven failure, and it
    // is named as its own kind of failure rather than borrowing an exit code's.
    try t.expectEqual(
        Status.failed,
        (Terminal{ .input_refused = .{ .reason = "no such session" } }).status(),
    );
    try t.expectEqualStrings(
        "INPUT_REFUSED",
        (Terminal{ .input_refused = .{ .reason = "no such session" } }).errorCode().?,
    );
    // A failure the host proved is `failed`, not `indeterminate`, and it carries
    // the site's own word for what was proven rather than a shared default.
    const proven: Terminal = .{ .proven_failure = .{
        .observation = "tmux has-session reported the session still present after kill-session",
        .error_code = "SESSION_SURVIVED_KILL",
    } };
    try t.expectEqual(Status.failed, proven.status());
    try t.expectEqualStrings("SESSION_SURVIVED_KILL", proven.errorCode().?);
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

test "beforeSubmission is the advance-commitment window, and holds no terminal" {
    const t = std.testing;

    // The two states in which the caller's command has provably not left.
    try t.expect(Status.created.beforeSubmission());
    try t.expect(Status.connecting.beforeSubmission());
    try t.expect(!Status.submitted.beforeSubmission());

    // Disjoint from the terminals, and the two that end without submitting are
    // the ones worth naming: `failed` via `never_submitted` and `cancelled` via
    // `local_abandon` both leave from inside the window, and neither is still
    // in it afterwards. A settled attempt has nothing left to commit to.
    inline for (@typeInfo(Status).@"enum".fields) |field| {
        const s: Status = @enumFromInt(field.value);
        try t.expect(!(s.beforeSubmission() and s.isTerminal()));
    }
    try t.expect(!Status.failed.beforeSubmission());
    try t.expect(!Status.cancelled.beforeSubmission());
}

test sqlList {
    const t = std.testing;
    // Declaration order, quoted, comma-separated — the shape a `status IN (...)`
    // guard needs, and the reason no statement has to spell one out.
    try t.expectEqualStrings("'created','connecting'", comptime sqlList(Status.beforeSubmission));
    try t.expectEqualStrings(
        "'completed','failed','timed_out','cancelled','indeterminate'",
        comptime sqlList(Status.isTerminal),
    );
    // The two are complementary in the only sense a guard cares about: no
    // status is in both, so a statement cannot be satisfied by both lists.
    try t.expectEqualStrings("'submitted','remote_started'", comptime sqlList(struct {
        fn f(s: Status) bool {
            return !s.beforeSubmission() and !s.isTerminal();
        }
    }.f));
}
