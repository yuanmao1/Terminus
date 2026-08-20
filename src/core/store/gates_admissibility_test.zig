//! The two capability matrices, transcribed a second time.
//!
//! `receipts.terminalDescribesKind` is 8 terminals × 11 kinds and
//! `receipts.ResolutionEvidence.appliesToKind` is 9 evidence variants × 11
//! kinds. Production decides both from `operations.Capabilities` — what the
//! work *is*, rather than what it is called. The gates here decide the same
//! cells from a table written out by hand, from the other direction, and then
//! compare the two answers cell by cell.
//!
//! **The mirror must stay independently derived.** It would be a few lines to
//! import the production table and loop over it, and the result would be a gate
//! that cannot fail: it would agree with any rule at all, including a wrong
//! one. The value of this file is exactly that the same 187 answers were reached
//! twice by different routes. So `pinnedCapabilities` restates every kind's
//! capabilities as literals, `pinnedEvidenceRule` and `pinnedTerminalRule`
//! restate the rules over them, and none of them may ask `operations` or
//! `receipts` for the answer.
//!
//! Nothing here may except a cell by naming a kind, which is why `admissibility
//! follows declared capability, not kind identity` flips one capability at a
//! time on a synthetic kind and demands the answer move with it.

const std = @import("std");
const Store = @import("Store.zig");
const op_state = @import("op_state.zig");

const EvidenceTag = std.meta.Tag(Store.receipts.ResolutionEvidence);

/// One legal value per evidence variant.
///
/// Exhaustive, so a new variant cannot exist without appearing in the matrix
/// below. The payloads do not matter to `appliesToKind` — it asks only what
/// class of claim this is — but they have to be *some* value the union admits.
fn sampleEvidence(tag: EvidenceTag) Store.receipts.ResolutionEvidence {
    return switch (tag) {
        .supervisor_report => .{ .supervisor_report = .{ .reported = .completed, .detail = "the wrapper reported an exit" } },
        .process_probe => .{ .process_probe = .{ .pid = 4242, .start_token = "boot+4242", .alive = false } },
        .job_sentinel => .{ .job_sentinel = .{ .sentinel = "__TERMINUS_JOB_1__", .exit_code = 0 } },
        .job_result => .{ .job_result = .{ .request_id = "01JQXW8ZK4N0RS7T3VYB2MCDEF", .exit_code = 0 } },
        .filesystem_effect => .{ .filesystem_effect = .{ .side = .remote, .path = "/srv/app/out.bin", .sha256 = "abc" } },
        .destination_absent => .{ .destination_absent = .{
            .side = .remote,
            .path = "/srv/app/out.bin",
            .verification_method = "stat => ENOENT",
        } },
        .destination_present_unverified => .{ .destination_present_unverified = .{
            .side = .remote,
            .path = "/srv/app/out.bin",
            .verification_method = "stat => 4096 bytes",
        } },
        .destination_present_contradicting => .{ .destination_present_contradicting = .{
            .side = .remote,
            .path = "/srv/app/out.bin",
            .sha256 = "0000ffff",
            .verification_method = "sha256sum => 0000ffff",
        } },
        .operator_override => .{ .operator_override = .{ .reason = "checked by hand", .by = "tester" } },
    };
}

/// The capability table, transcribed independently of the implementation.
///
/// This is what the two 187-cell matrices collapsed into, and it is the whole of
/// what this file now has to restate: eleven rows of eight booleans instead of
/// 187 hand-decided cells, plus one rule per terminal and per evidence variant
/// below. The purpose has not changed — a second statement of the same claim, so
/// nothing can be widened in `receipts.zig` alone — but the unit of the claim is
/// now "what is this kind of work", which is the question a new kind actually
/// raises.
///
/// Deliberately written from the *kind's* side, in this file's own words, without
/// asking `Store.operations.Kind.capabilities`. If it agreed by calling it, the
/// gate below would compare the store against itself.
///
/// Exhaustive with no `else`, and the struct has no defaults, so a new kind or a
/// new axis stops the build here as well as there.
fn pinnedCapabilities(kind: Store.operations.Kind) Store.operations.Capabilities {
    return switch (kind) {
        // One supervised remote command, and the only kind that records the
        // identity — pid *and* start token — of the process that ran it.
        .exec => .{
            .runs_our_command = true,
            .supervised_deadline = true,
            .records_process_identity = true,
            .offers_input_bytes = false,
            .publishes_declared_artifact = false,
            .supervises_another_subject = false,
            .wrapper_documents_exit = false,
            .judgement_undeclared = false,
        },
        // Also one supervised remote command, and its launch line carries our
        // wrapper: a sentinel echoed after the command, a sidecar written at an
        // address derived from the request id. It records no process identity of
        // its own — the pid on a job's trail is its *pane's*, with no start token,
        // and a probe of it is a reading about one process offered as a verdict on
        // another.
        .job => .{
            .runs_our_command = true,
            .supervised_deadline = true,
            .wrapper_documents_exit = true,
            .records_process_identity = false,
            .offers_input_bytes = false,
            .publishes_declared_artifact = false,
            .supervises_another_subject = false,
            .judgement_undeclared = false,
        },
        // Bytes typed into a shell somebody else is running. It runs no command of
        // the caller's — `tmux send-keys`'s own exit status is not the operation's
        // verdict — nothing on the far side enforces a deadline, it starts no
        // process and records none, it carries no wrapper and declares no
        // destination.
        .session_write => .{
            .offers_input_bytes = true,
            .runs_our_command = false,
            .supervised_deadline = false,
            .publishes_declared_artifact = false,
            .supervises_another_subject = false,
            .records_process_identity = false,
            .wrapper_documents_exit = false,
            .judgement_undeclared = false,
        },
        // A supervisory act on somebody else's session, judged by whether the
        // thing it named is gone — read from the host's own answer. It runs three
        // tmux invocations and is judged by none of their exit codes, offers no
        // bytes to a terminal, has somebody else's process in view rather than one
        // of its own, and the job documents it may be pointed at belong to the
        // job's own attempt.
        .control => .{
            .supervises_another_subject = true,
            .runs_our_command = false,
            .supervised_deadline = false,
            .offers_input_bytes = false,
            .publishes_declared_artifact = false,
            .records_process_identity = false,
            .wrapper_documents_exit = false,
            .judgement_undeclared = false,
        },
        // Judged by an artifact at a destination declared before a byte moved, and
        // by nothing about a process: a copier that renamed nothing still exits 0,
        // nothing supervises one, and "it is no longer running" is equally true of
        // one that finished and one that died mid-rename.
        .transfer_push, .transfer_pull, .fetch => .{
            .publishes_declared_artifact = true,
            .runs_our_command = false,
            .supervised_deadline = false,
            .offers_input_bytes = false,
            .supervises_another_subject = false,
            .records_process_identity = false,
            .wrapper_documents_exit = false,
            .judgement_undeclared = false,
        },
        // Nothing constructs one and nothing is known about what one would be
        // judged by. The four kinds that absorbed 204 of the old cells.
        .tunnel, .plan_phase, .audit, .cleanup => .{
            .judgement_undeclared = true,
            .runs_our_command = false,
            .supervised_deadline = false,
            .offers_input_bytes = false,
            .publishes_declared_artifact = false,
            .supervises_another_subject = false,
            .records_process_identity = false,
            .wrapper_documents_exit = false,
        },
    };
}

/// The resolve-side admissibility rules, transcribed independently.
///
/// One rule per evidence variant, stated as the property a kind must have, and
/// read against this file's own capability table rather than the store's. It was
/// 99 cells; the nine rules below say the same thing and say it once each.
///
/// Two rules are refusals rather than routings, and they are the ones a future
/// change is most likely to undo by accident:
///
///  * `supervisor_report` is refused for **every** kind, by a literal `false`
///    rather than by a property. It is the only mechanical variant with no
///    identity binding at all — a status and a sentence, nothing tying either to
///    the attempt it is handed to — while `isMechanical` grades it mechanical,
///    the grade that releases a scope barrier with no operator in the loop.
///    Nothing constructs one, so the refusal costs no reachable route.
///  * `process_probe` follows `records_process_identity`, which is a fact about
///    what the attempt *wrote down*, not about whether a process existed. `exec`
///    has it; a job runs a process and records its pane's pid instead, and
///    admitting it there let "the pane is gone" mean "the job was cancelled"
///    while a daemonized child ran on.
fn pinnedCell(kind: Store.operations.Kind, tag: EvidenceTag) bool {
    return pinnedEvidenceRule(pinnedCapabilities(kind), tag);
}

/// The rules alone, with no kind in scope — the shape `receipts.appliesTo` has,
/// and for the same reason: a rule that cannot see a kind cannot except one.
fn pinnedEvidenceRule(can: Store.operations.Capabilities, tag: EvidenceTag) bool {
    return switch (tag) {
        // No producer, and no field on the variant that could bind a report to the
        // attempt it is offered against.
        .supervisor_report => false,
        // A reading of a process, admissible only where an identity was recorded
        // for it to be checked against.
        .process_probe => can.records_process_identity,
        // The two documents our job wrapper writes. Only work whose launch line
        // carried that wrapper can be spoken about by them — a `session_write`
        // shares the tmux mechanism and carries no wrapper, and a control act's
        // target's documents settle the target.
        .job_sentinel, .job_result => can.wrapper_documents_exit,
        // All four readings of an address, positive and negative. Only work that
        // named a destination in advance has one on record, and they travel
        // together: a kind that can be told its artifact is there must be tellable
        // that it is not, that it is the wrong one, and that nothing could check
        // it, or some of its outcomes have no evidence that can express them.
        .filesystem_effect,
        .destination_absent,
        .destination_present_unverified,
        .destination_present_contradicting,
        => can.publishes_declared_artifact,
        // A human's decision, about the operation rather than about a mechanism's
        // output, and admissible everywhere on purpose: a kind that admitted no
        // evidence at all would hold its scope with no way out.
        .operator_override => true,
    };
}

test "gate: every kind × evidence cell is decided, and none of them by default" {
    const t = std.testing;

    // `appliesToKind` used to end in `else => true`: every kind it did not name
    // admitted every kind of evidence, and every kind added later inherited
    // that. Widening a cell is a decision about what may release the scope
    // barrier, so it has to be made twice, out loud — here and in the store.
    inline for (@typeInfo(Store.operations.Kind).@"enum".fields) |kind_field| {
        const kind: Store.operations.Kind = @field(Store.operations.Kind, kind_field.name);
        inline for (@typeInfo(EvidenceTag).@"enum".fields) |evidence_field| {
            const tag: EvidenceTag = @field(EvidenceTag, evidence_field.name);
            const got = sampleEvidence(tag).appliesToKind(kind);
            const pinned = pinnedCell(kind, tag);
            if (got != pinned) {
                std.debug.print(
                    "cell {s} x {s}: the store says {}, the pinned matrix says {}\n",
                    .{ kind_field.name, evidence_field.name, got, pinned },
                );
                return error.MatrixCellChanged;
            }
        }
    }

    // Six rules the two tables must not be able to agree to lose, stated a
    // third time and from the other direction — as a property of the kind
    // rather than as a row.
    for (std.enums.values(Store.operations.Kind)) |kind| {
        const publishes_a_declared_file = switch (kind) {
            .transfer_push, .transfer_pull, .fetch => true,
            else => false,
        };
        try t.expectEqual(publishes_a_declared_file, sampleEvidence(.filesystem_effect).appliesToKind(kind));
        // All three readings of a destination travel together: a kind that can
        // be told its artifact is there must be tellable that it is not and
        // that it is the wrong one, or some of its outcomes have no evidence
        // that can express them. That is not a tidiness rule — each of the
        // three was added because a parked publish with that answer had no
        // route out and held its destination forever.
        try t.expectEqual(publishes_a_declared_file, sampleEvidence(.destination_absent).appliesToKind(kind));
        try t.expectEqual(
            publishes_a_declared_file,
            sampleEvidence(.destination_present_unverified).appliesToKind(kind),
        );
        try t.expectEqual(
            publishes_a_declared_file,
            sampleEvidence(.destination_present_contradicting).appliesToKind(kind),
        );
        try t.expectEqual(kind == .job, sampleEvidence(.job_result).appliesToKind(kind));
        try t.expectEqual(kind == .job, sampleEvidence(.job_sentinel).appliesToKind(kind));
        // A probe is a reading of a pid, so it may only speak for a kind that
        // records the pid of the process that did the work. `exec` does; a job
        // records its *pane's* pid, which is a different process, and admitting
        // it there let "the pane is gone" mean "the job was cancelled" while a
        // daemonized child ran on.
        try t.expectEqual(kind == .exec, sampleEvidence(.process_probe).appliesToKind(kind));
        // A supervisor's report speaks for nothing at all until a producer
        // exists that binds it to the attempt it is offered against. It is the
        // only mechanical variant with no identity check in `resolve`, and
        // mechanical is the grade that releases a scope barrier unattended.
        try t.expect(!sampleEvidence(.supervisor_report).appliesToKind(kind));
        // Every kind keeps its escape hatch. A kind with no admissible
        // evidence at all would hold its scope forever with no way out, which
        // is the trap `request reconcile` exists to prevent — and with the two
        // refusals above, six of the eleven kinds now have this as their only
        // admissible evidence.
        try t.expect(sampleEvidence(.operator_override).appliesToKind(kind));
    }

    // Two of those six are reachable today rather than waiting on a producer,
    // and they are stated as their own claim for that reason: `terminus write`
    // creates a `session_write` every time it runs and `terminus session rm`
    // creates a `control`, while nothing in this binary creates a `tunnel`, a
    // `plan_phase`, an `audit` or a `cleanup`. So this is not "no producer has
    // been built yet" — it is that neither of the two records anything a later
    // mechanism could be a reading of, and the only attempts of either kind that
    // ever reach a reconcile are the ones whose answer was lost.
    inline for (@typeInfo(EvidenceTag).@"enum".fields) |field| {
        const tag: EvidenceTag = @field(EvidenceTag, field.name);
        try t.expectEqual(tag == .operator_override, sampleEvidence(tag).appliesToKind(.session_write));
        try t.expectEqual(tag == .operator_override, sampleEvidence(tag).appliesToKind(.control));
    }
}

const TerminalTag = std.meta.Tag(op_state.Terminal);

/// One legal value per terminal variant.
///
/// Exhaustive, so a new terminal cannot exist without appearing in the matrix
/// below. The payloads do not matter to `terminalDescribesKind` — it asks only
/// what class of claim this is — but they have to be *some* value the union
/// admits, and each is spelled the way its own producer spells it.
fn sampleTerminal(tag: TerminalTag) op_state.Terminal {
    return switch (tag) {
        .exited => .{ .exited = .{ .exit_code = 0 } },
        .never_submitted => .{ .never_submitted = .{ .transport_error = "connection refused" } },
        .remote_deadline => .{ .remote_deadline = .{ .after_ms = 30_000 } },
        .local_abandon => .{ .local_abandon = .{ .reason = "the operator gave up before dialing" } },
        .remote_cancel_confirmed => .{ .remote_cancel_confirmed = .{
            .pid = 4242,
            .start_token = "boot+4242",
            .term_sent = true,
            .kill_sent = false,
            .absence_verified_at = 900,
            .verification_method = "kill -0 -4242 => ESRCH",
        } },
        .input_accepted => .{ .input_accepted = .{ .bytes = 12, .sha256 = "aabbcc" } },
        .input_refused => .{ .input_refused = .{ .reason = "the session does not exist" } },
        .proven_failure => .{ .proven_failure = .{
            .observation = "tmux has-session reported the session still present after kill-session",
            .error_code = "SESSION_SURVIVED_KILL",
        } },
        .indeterminate => .{ .indeterminate = .{
            .reason = "the connection dropped",
            .last_observed = .submitted,
        } },
    };
}

/// The settle-side admissibility rules, transcribed independently and from the
/// same direction as the resolve-side ones above: one rule per terminal, stated
/// as the property a kind must have.
///
/// It was 88 cells written kind by kind — four distinct rows, each spelled out in
/// full so that a row agreeing with its neighbour by coincidence and one agreeing
/// by omission could not look the same. The rows are now the capability table,
/// which says the same thing better: two kinds have the same admissibility
/// *because* they declared the same properties, and the gate below asserts that
/// equal declarations produce equal rows, which is the coincidence-versus-omission
/// question answered rather than sidestepped.
///
/// Three refusals are worth restating, because they are what a reader will assume
/// is a mistake:
///
///  * a transfer admits **no business terminal at all** — `completed` and
///    `timed_out` are unreachable through `settle`, `failed` and `cancelled` only
///    before submission. Every terminal it refuses carries a fact about a process,
///    and its verdict is an artifact at a declared destination.
///  * `control`'s whole business vocabulary is the two terminals that read its
///    subject: `remote_cancel_confirmed` when the session is gone,
///    `proven_failure` when the host says it is not.
///  * the four undeclared kinds keep the three process-shaped terminals as a
///    blank, not a permit. A total refusal on this side has no escape hatch —
///    there is no operator variant in `op_state.Terminal` — so the first operation
///    of such a kind would be unsettleable and would hold its scope with no route
///    to `indeterminate` for a reconcile to act on.
fn pinnedTerminalCell(kind: Store.operations.Kind, tag: TerminalTag) bool {
    return pinnedTerminalRule(pinnedCapabilities(kind), tag);
}

/// The rules alone, with no kind in scope. See `pinnedEvidenceRule`.
fn pinnedTerminalRule(can: Store.operations.Capabilities, tag: TerminalTag) bool {
    return switch (tag) {
        // The three that describe the *attempt* rather than the work. Every kind
        // hands something over, every kind can fail to, every kind can be given up
        // on before it dials, and every kind can lose the answer. Literals, because
        // there is no property whose absence would make one of them meaningless —
        // and `terminalForTransportLoss` builds two of them from the state alone,
        // without being told the kind.
        .never_submitted, .local_abandon, .indeterminate => true,
        // An exit status is the verdict only where the operation ran a command of
        // ours. Widened for the undeclared kinds so the first one ever created is
        // not born unsettleable.
        .exited => can.runs_our_command or can.judgement_undeclared,
        // A deadline needs a far side that enforced and reported one.
        .remote_deadline => can.supervised_deadline or can.judgement_undeclared,
        // Either there was a process of ours to signal, or the act's subject is a
        // remote thing whose absence the host itself reports. A write starts
        // nothing; a transfer's copier being gone says nothing about the artifact.
        .remote_cancel_confirmed => can.runs_our_command or
            can.supervises_another_subject or
            can.judgement_undeclared,
        // The mirror image of the cell above: the host answered about the act's
        // subject and the answer is that it is still there, so the act provably did
        // not take effect. Only a kind judged by its subject can say it — for a
        // command it is `exited` with the status, for a write `input_refused` with
        // the reason, and for a transfer it would be a post-submission `failed`
        // with no reading of the destination behind it. Not widened for the
        // undeclared kinds, and that costs them nothing: they keep `exited`.
        .proven_failure => can.supervises_another_subject,
        // One act, one kind: bytes offered to a terminal somebody else is running.
        .input_accepted, .input_refused => can.offers_input_bytes,
    };
}

test "gate: every kind × terminal cell is decided, and none of them by default" {
    const t = std.testing;

    // The resolve-side table has a gate of exactly this shape, and this is its
    // settle-side twin. The axis is more dangerous, not less: a resolution
    // refused can be brought back with different evidence, and
    // `operator_override` is admissible everywhere so nothing is ever left with
    // no way out — while a settlement refused has no such hatch. `settle` is the
    // sole terminal writer, `op_state.Terminal` has no operator variant, and an
    // attempt whose only route to an outcome is refused stays live, holds its
    // scope, and never reaches `indeterminate` for a reconcile to act on.
    inline for (@typeInfo(Store.operations.Kind).@"enum".fields) |kind_field| {
        const kind: Store.operations.Kind = @field(Store.operations.Kind, kind_field.name);
        inline for (@typeInfo(TerminalTag).@"enum".fields) |terminal_field| {
            const tag: TerminalTag = @field(TerminalTag, terminal_field.name);
            const got = Store.receipts.terminalDescribesKind(sampleTerminal(tag), kind);
            const pinned = pinnedTerminalCell(kind, tag);
            if (got != pinned) {
                std.debug.print(
                    "cell {s} x {s}: the store says {}, the pinned matrix says {}\n",
                    .{ kind_field.name, terminal_field.name, got, pinned },
                );
                return error.TerminalMatrixCellChanged;
            }
        }
    }

    for (std.enums.values(Store.operations.Kind)) |kind| {
        // The three terminals that describe the *attempt* rather than the work.
        // Every kind admits all three, and this is the property that keeps the
        // universal give-up path honest: `op_state.terminalForTransportLoss`
        // builds `never_submitted` or `indeterminate` without being told the
        // kind, and `Execution.abandon` — through it `Execution.deinit`, the
        // last resort for a process that returned without deciding — calls it
        // for every operation there is. A cell refused here would turn "the
        // process exited without recording an outcome" into a lost receipt.
        //
        // `indeterminate` is load-bearing twice over since the transfer kinds
        // lost their business terminals: it is the *only* terminal a transfer
        // may take after submission, so refusing this cell for one of them would
        // leave it unsettleable, holding its scope forever, and never reaching
        // the state a reconcile acts on.
        try t.expect(Store.receipts.terminalDescribesKind(sampleTerminal(.never_submitted), kind));
        try t.expect(Store.receipts.terminalDescribesKind(sampleTerminal(.local_abandon), kind));
        try t.expect(Store.receipts.terminalDescribesKind(sampleTerminal(.indeterminate), kind));

        // Typing bytes into a shell somebody else is running is one act, and
        // exactly one kind performs it.
        const is_write = kind == .session_write;
        try t.expectEqual(is_write, Store.receipts.terminalDescribesKind(sampleTerminal(.input_accepted), kind));
        try t.expectEqual(is_write, Store.receipts.terminalDescribesKind(sampleTerminal(.input_refused), kind));

        // And the complement, which is no longer "everything else" and is no
        // longer one predicate either. The three terminals below all carry a
        // fact about something remote, but they do not all carry a fact about
        // the same thing, and `control` is the kind that forced them apart:
        //
        //  * `exited` and `remote_deadline` are about a *command this binary
        //    asked the host to run* — its status, and a deadline the far side
        //    held it to. A kind may admit them only if such a command is what it
        //    is judged by. A `session_write` runs none; a transfer's verdict is
        //    an artifact at a destination it declared, and a copier that wrote
        //    to the wrong path or whose rename never ran still exits 0 and can
        //    still be held to a deadline; a control act runs three tmux
        //    invocations of its own and is judged by none of their exit codes —
        //    settling one with a tmux client's status is the same false word in
        //    the same column that `input_accepted` had to be split out to stop.
        //  * `remote_cancel_confirmed` is about a remote *thing being gone*,
        //    verified. That is a wider set by exactly one: a control act's whole
        //    subject is whether the session it named is still there, and
        //    `tmux has-session` is a direct reading of it — the granularity the
        //    variant's optional `pid` is documented for. A transfer is still
        //    refused ("no longer running" is equally true of one that finished
        //    and one that died mid-rename) and a write still is (it starts
        //    nothing whose absence could be confirmed).
        //  * `proven_failure` is the same reading with the opposite answer, and
        //    its set is narrower than either: *only* a kind whose verdict is the
        //    state of somebody else's subject. `exec` and `job` are excluded even
        //    though they can obviously fail after submitting, because their proven
        //    failure is `exited` carrying the status that caused it, and a write's
        //    is `input_refused` carrying the reason. This is the one predicate here
        //    that no undeclared kind shares, and that is deliberate: refusing it
        //    for them costs nothing, because `exited` still carries a failure.
        //
        // Transcribed here as properties of the kind, deliberately without
        // asking the store, so that widening a rule in `receipts.zig` has to be
        // argued for twice. Exhaustive, so a new kind stops the build here too.
        const judged_by_a_command_it_asked_for = switch (kind) {
            .exec, .job, .tunnel, .plan_phase, .audit, .cleanup => true,
            .session_write, .control, .transfer_push, .transfer_pull, .fetch => false,
        };
        const stops_a_remote_thing = switch (kind) {
            .exec, .job, .control, .tunnel, .plan_phase, .audit, .cleanup => true,
            .session_write, .transfer_push, .transfer_pull, .fetch => false,
        };
        const judged_by_somebody_elses_subject = switch (kind) {
            .control => true,
            .exec,
            .job,
            .session_write,
            .transfer_push,
            .transfer_pull,
            .fetch,
            .tunnel,
            .plan_phase,
            .audit,
            .cleanup,
            => false,
        };
        try t.expectEqual(
            judged_by_a_command_it_asked_for,
            Store.receipts.terminalDescribesKind(sampleTerminal(.exited), kind),
        );
        try t.expectEqual(
            judged_by_a_command_it_asked_for,
            Store.receipts.terminalDescribesKind(sampleTerminal(.remote_deadline), kind),
        );
        try t.expectEqual(
            stops_a_remote_thing,
            Store.receipts.terminalDescribesKind(sampleTerminal(.remote_cancel_confirmed), kind),
        );
        try t.expectEqual(
            judged_by_somebody_elses_subject,
            Store.receipts.terminalDescribesKind(sampleTerminal(.proven_failure), kind),
        );
    }

    // What each kind can and cannot reach, walked over the statuses rather than
    // the variants, because a status is the thing a refused cell actually costs:
    // `exited` is the only route to `completed` for anything but a write,
    // `remote_deadline` the only route to `timed_out`, and
    // `remote_cancel_confirmed` the only post-submission route to `cancelled`.
    //
    // Three statuses are universal and that is what "no kind is wedged" now
    // means: every kind can record that it failed before submitting
    // (`never_submitted`), that it was abandoned before submitting
    // (`local_abandon`), and — the one that matters after submission — that we
    // do not know (`indeterminate`). A kind that could reach none of them would
    // hold its scope with no route out at all.
    //
    // `completed` and `timed_out` are *not* universal, and the exceptions are
    // decisions rather than gaps. This is where the transfer refusal is stated
    // as a consequence instead of as a cell: until a producer exists that brings
    // a terminal carrying what it read back off the destination, a transfer
    // cannot be settled `completed` by anything, and it does not need to be —
    // `indeterminate` plus a reading of the declared destination through
    // `resolve` is the route, and `transfers` reads `resolved_status` beside
    // `status`.
    for (std.enums.values(Store.operations.Kind)) |kind| {
        var reachable = std.EnumSet(op_state.Status).initEmpty();
        inline for (@typeInfo(TerminalTag).@"enum".fields) |field| {
            const tag: TerminalTag = @field(TerminalTag, field.name);
            const terminal = sampleTerminal(tag);
            if (Store.receipts.terminalDescribesKind(terminal, kind)) reachable.insert(terminal.status());
        }
        try t.expect(reachable.contains(.failed));
        try t.expect(reachable.contains(.cancelled));
        try t.expect(reachable.contains(.indeterminate));

        // `completed` needs a command this binary asked for to have ended well,
        // and two kinds have no such command: a transfer's completion is a file
        // and no terminal reads one yet, and a control act's success is the
        // absence of the session it named — recorded as `cancelled`, carrying
        // the reading that established it, rather than as a `completed` nothing
        // judged. Both refusals cost a word, not an outcome.
        const reaches_completed = switch (kind) {
            .exec, .job, .session_write, .tunnel, .plan_phase, .audit, .cleanup => true,
            .control, .transfer_push, .transfer_pull, .fetch => false,
        };
        try t.expectEqual(reaches_completed, reachable.contains(.completed));
        // `timed_out` needs a deadline something else enforced and reported. A
        // write has no far side to enforce one, a transfer has no supervisor,
        // and a control act supervises nothing of its own; for all three, a
        // local deadline expiring is `indeterminate` (`op_state` rule 2), which
        // is admitted above.
        const judged_by_a_command_it_asked_for = switch (kind) {
            .exec, .job, .tunnel, .plan_phase, .audit, .cleanup => true,
            .session_write, .control, .transfer_push, .transfer_pull, .fetch => false,
        };
        try t.expectEqual(judged_by_a_command_it_asked_for, reachable.contains(.timed_out));
    }
}

test "gate: admissibility follows declared capability, not kind identity" {
    const t = std.testing;
    const Kind = Store.operations.Kind;
    const Capabilities = Store.operations.Capabilities;
    const axes = @typeInfo(Capabilities).@"struct".fields;

    // The two matrices used to be 187 hand-decided cells with an independently
    // transcribed mirror each, and six of the eleven kinds — the ones nothing in
    // this binary constructs — accounted for 204 of the 374. They are now rules
    // over the table below, so this is the gate that has to hold what the cells
    // used to: that the derivation is real, that it is stated twice, and that no
    // kind is being excepted by name behind it.

    // 1. The table itself, stated twice. This is the double entry the cell tables
    //    had, moved to the unit that actually carries a decision: eight booleans
    //    per kind rather than seventeen cells.
    inline for (@typeInfo(Kind).@"enum".fields) |kind_field| {
        const kind: Kind = @field(Kind, kind_field.name);
        const got = kind.capabilities();
        const pinned = pinnedCapabilities(kind);
        inline for (axes) |axis| {
            if (@field(got, axis.name) != @field(pinned, axis.name)) {
                std.debug.print(
                    "capability {s}.{s}: the store says {}, this file says {}\n",
                    .{ kind_field.name, axis.name, @field(got, axis.name), @field(pinned, axis.name) },
                );
                return error.CapabilityChanged;
            }
        }
    }

    // 2. `judgement_undeclared` excludes every other axis. It is not a capability;
    //    it records that nothing is known about what a kind is judged by, and the
    //    two matrices read it in opposite directions — widening the settle side so
    //    the first such operation is not born unsettleable, ignored on the resolve
    //    side where an override always remains. A kind claiming both that nothing
    //    is known about it and that it publishes an artifact would be asking for
    //    both readings at once, and the answer to which one wins would be an
    //    accident of rule order.
    inline for (@typeInfo(Kind).@"enum".fields) |kind_field| {
        const kind: Kind = @field(Kind, kind_field.name);
        const can = kind.capabilities();
        if (can.judgement_undeclared) {
            inline for (axes) |axis| {
                const is_the_flag = comptime std.mem.eql(u8, axis.name, "judgement_undeclared");
                if (!is_the_flag and @field(can, axis.name)) {
                    std.debug.print(
                        "kind {s} declares nothing is known about it and also declares {s}\n",
                        .{ kind_field.name, axis.name },
                    );
                    return error.UndeclaredKindDeclaresSomething;
                }
            }
        }
    }

    // 3. Equal declarations produce equal admissibility, in both matrices. This is
    //    the claim the old tables answered by writing every row out in full,
    //    "because a row that agrees with its neighbour by coincidence and a row
    //    that agrees with it by omission look the same once they are collapsed" —
    //    asserted here instead of avoided. The transfer trio and the four
    //    undeclared kinds are where it has teeth: seven kinds, two declarations,
    //    and nothing may distinguish them but what they declared.
    for (std.enums.values(Kind)) |a| {
        for (std.enums.values(Kind)) |b| {
            if (!std.meta.eql(a.capabilities(), b.capabilities())) continue;
            inline for (@typeInfo(TerminalTag).@"enum".fields) |field| {
                const tag: TerminalTag = @field(TerminalTag, field.name);
                try t.expectEqual(
                    Store.receipts.terminalDescribesKind(sampleTerminal(tag), a),
                    Store.receipts.terminalDescribesKind(sampleTerminal(tag), b),
                );
            }
            inline for (@typeInfo(EvidenceTag).@"enum".fields) |field| {
                const tag: EvidenceTag = @field(EvidenceTag, field.name);
                try t.expectEqual(
                    sampleEvidence(tag).appliesToKind(a),
                    sampleEvidence(tag).appliesToKind(b),
                );
            }
        }
    }

    // 4. Every axis decides something. Run against the store's own rules, which
    //    take capabilities and not a kind, so a single axis can be flipped on its
    //    own — the eleven real kinds never differ by exactly one. An axis that
    //    changed no cell would be a declaration an author answers carefully and
    //    that nothing reads, which is worse than no axis at all: it reads as a
    //    guarantee.
    var nothing: Capabilities = undefined;
    inline for (axes) |axis| @field(nothing, axis.name) = false;
    inline for (axes) |axis| {
        var only: Capabilities = nothing;
        @field(only, axis.name) = true;
        var decides = false;
        inline for (@typeInfo(TerminalTag).@"enum".fields) |field| {
            const tag: TerminalTag = @field(TerminalTag, field.name);
            if (Store.receipts.terminalDescribes(sampleTerminal(tag), only) !=
                Store.receipts.terminalDescribes(sampleTerminal(tag), nothing)) decides = true;
        }
        inline for (@typeInfo(EvidenceTag).@"enum".fields) |field| {
            const tag: EvidenceTag = @field(EvidenceTag, field.name);
            if (sampleEvidence(tag).appliesTo(only) != sampleEvidence(tag).appliesTo(nothing))
                decides = true;
        }
        if (!decides) {
            std.debug.print("capability axis {s} changes no cell in either matrix\n", .{axis.name});
            return error.CapabilityDecidesNothing;
        }
    }

    // 5. The floor a set that declares nothing lands on, since that is what an
    //    author who fills in eight `false`s gets. The three attempt-level
    //    terminals and an operator's decision, and nothing else: it can record
    //    that it never sent, that it gave up, and that the answer was lost, so it
    //    is not wedged — and it can claim no exit status, no deadline, no verified
    //    absence, no proven failure and no reading of a file, because it declared
    //    nothing that would make one of those a statement about it.
    inline for (@typeInfo(TerminalTag).@"enum".fields) |field| {
        const tag: TerminalTag = @field(TerminalTag, field.name);
        const attempt_level = switch (tag) {
            .never_submitted, .local_abandon, .indeterminate => true,
            .exited, .remote_deadline, .remote_cancel_confirmed, .proven_failure, .input_accepted, .input_refused => false,
        };
        try t.expectEqual(attempt_level, Store.receipts.terminalDescribes(sampleTerminal(tag), nothing));
    }
    inline for (@typeInfo(EvidenceTag).@"enum".fields) |field| {
        const tag: EvidenceTag = @field(EvidenceTag, field.name);
        try t.expectEqual(tag == .operator_override, sampleEvidence(tag).appliesTo(nothing));
    }
}

test "gate: every kind can record a failure it proved after submitting, except a transfer" {
    const t = std.testing;

    // The hole `proven_failure` was added for. `canSettle` admits
    // `never_submitted` only from `created`/`connecting`, so after submission a
    // kind whose verdict is not an exit status had nothing but `indeterminate` —
    // "we could not establish what happened" — for outcomes it had established.
    // That never faked success, and it cost a blocked scope and a reconcile for a
    // settled question every time.
    //
    // One candidate per shape of proof, so the claim is about the vocabulary as a
    // whole rather than about one variant: an exit status, a terminal's refusal of
    // bytes, and a reading of somebody else's subject.
    const failures = [_]op_state.Terminal{
        .{ .exited = .{ .exit_code = 1 } },
        .{ .input_refused = .{ .reason = "the session does not exist" } },
        .{ .proven_failure = .{
            .observation = "tmux has-session reported the session still present after kill-session",
            .error_code = "SESSION_SURVIVED_KILL",
        } },
    };
    for (failures) |terminal| {
        try t.expectEqual(op_state.Status.failed, terminal.status());
        try t.expect(op_state.canSettle(.submitted, terminal));
    }

    for (std.enums.values(Store.operations.Kind)) |kind| {
        var proves = false;
        for (failures) |terminal| {
            if (Store.receipts.terminalDescribesKind(terminal, kind)) proves = true;
        }
        // A transfer is the exception, and it is a decision rather than a gap: its
        // verdict is an artifact at a destination it declared, and none of these
        // three is a reading of one. Post-submission it takes `indeterminate` and
        // is judged by `resolve`, which admits four readings of that destination
        // for exactly these kinds.
        const publishes_a_declared_file = switch (kind) {
            .transfer_push, .transfer_pull, .fetch => true,
            else => false,
        };
        try t.expectEqual(!publishes_a_declared_file, proves);
    }

    // For a control act it is the new terminal and nothing else. `exited` is
    // refused because no command of the caller's ran — `session rm` sends three
    // tmux invocations and is judged by none of their exit codes — and
    // `input_refused` because nothing in a session removal offers bytes to a
    // terminal, which is the trap `session_proven_gone` exists to avoid (`2b670a9`).
    try t.expect(!Store.receipts.terminalDescribesKind(.{ .exited = .{ .exit_code = 1 } }, .control));
    try t.expect(!Store.receipts.terminalDescribesKind(
        .{ .input_refused = .{ .reason = "the session does not exist" } },
        .control,
    ));
    try t.expect(Store.receipts.terminalDescribesKind(failures[2], .control));
}
