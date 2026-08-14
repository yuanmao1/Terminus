//! `terminus request` — inspect and settle operations by request id.
//!
//! This is the escape hatch for the scope guard. An attempt whose outcome is
//! unknown deliberately keeps blocking its scope, which is only workable if
//! there is a way to establish the truth afterwards. Without this command the
//! guard is a trap: a forgotten job blocks its name forever and the only way
//! out is `--force`, which is precisely the blind retry the guard exists to
//! prevent.
//!
//! Reconciliation is evidence-first. `--from-log` goes and looks at the
//! durable job log, which is the only thing that actually knows how a job
//! ended; `--override` is available when a human has checked by hand, and is
//! recorded as an override so it can never be mistaken for a mechanical
//! proof.
const std = @import("std");
const fatal = Cli.fail;
const Cli = @import("cli.zig");
const Core = @import("../core/core.zig");
const Store = Core.Store;
const Tmux = Core.Tmux;

const usage =
    \\usage: terminus request <verb> [...]
    \\
    \\  request ls      <server> [--all] [--limit N] [--json]
    \\                          unsettled attempts (what is blocking a scope)
    \\  request show    <request-id> [--json]     status, scope, capability
    \\  request receipt <request-id> [--json]     the full append-only trail
    \\  request reconcile <request-id> [--from-log]
    \\                          [--override "<reason>" --by <who> --resolved <status>]
    \\
    \\reconcile establishes what an attempt actually did, so the scope it
    \\holds can be released.
    \\
    \\  --from-log   re-reads what the job left behind: its result record
    \\               first, then its log. On an attempt still in flight (a job
    \\               whose caller walked away) this settles the real outcome
    \\               from the recorded exit status; if the session is alive it
    \\               reports that and settles nothing.
    \\  --override   for an `indeterminate` attempt a human has checked by
    \\               hand. Recorded as a decision, never as proof.
    \\
    \\<status> is one of: completed | failed | timed_out | cancelled
    \\
    \\Exit codes: 0 settled or still legitimately running, 75 the outcome is
    \\still unknown, 1 the request refused.
    \\
;

pub fn run(ctx: *Cli.Ctx, raw_args: []const []const u8) !void {
    if (raw_args.len == 0) fatal("{s}", .{usage});
    const verb = raw_args[0];
    const parsed = Cli.parseArgs(ctx, raw_args[1..]);
    if (parsed.boolean("json")) ctx.out.format = .json;

    var store = try Cli.openStore(ctx, &parsed);
    defer store.close();

    if (std.mem.eql(u8, verb, "ls")) return listRequests(ctx, &store, &parsed);

    const request_id = parsed.positional(0) orelse fatal("{s}", .{usage});
    Store.ids.validate(request_id) catch fatal("'{s}' is not a request id", .{request_id});

    if (std.mem.eql(u8, verb, "show")) return showRequest(ctx, &store, request_id);
    if (std.mem.eql(u8, verb, "receipt")) return showReceipt(ctx, &store, request_id);
    if (std.mem.eql(u8, verb, "reconcile")) return reconcile(ctx, &store, request_id, &parsed);
    fatal("unknown verb 'request {s}'\n{s}", .{ verb, usage });
}

fn listRequests(ctx: *Cli.Ctx, store: *Store, parsed: *const Cli.Args.Parsed) !void {
    const server_name = parsed.positional(0) orelse fatal("{s}", .{usage});
    const resolved = Cli.resolveServer(ctx, store, server_name);
    const limit: i64 = if (parsed.flag("limit")) |l|
        std.fmt.parseInt(i64, l, 10) catch fatal("invalid --limit '{s}'", .{l})
    else
        20;

    const list = if (parsed.boolean("all"))
        Store.operations.recent(store, ctx.arena, resolved.server.id, limit) catch |err| Cli.storeFatal(store, err)
    else
        Store.operations.unsettled(store, ctx.arena, resolved.server.id) catch |err| Cli.storeFatal(store, err);

    switch (ctx.out.format) {
        .json => try ctx.out.json(.{
            .ok = true,
            .server = server_name,
            .requests = try summarize(ctx, list),
            .unsettledOnly = !parsed.boolean("all"),
        }),
        .human => {
            if (list.len == 0) return ctx.out.print("nothing unsettled on '{s}'\n", .{server_name});
            for (list) |op| {
                try ctx.out.print("{s}  {s}  {s}:{s}  {s}\n", .{
                    op.request_id,
                    op.effectiveStatus().text(),
                    op.scope_kind orelse "server",
                    op.scope_key orelse "",
                    op.alias orelse op.kind,
                });
            }
        },
    }
}

const Summary = struct {
    requestId: []const u8,
    kind: []const u8,
    status: []const u8,
    effectiveStatus: []const u8,
    resolvedStatus: ?[]const u8,
    scopeKind: ?[]const u8,
    scopeKey: ?[]const u8,
    alias: ?[]const u8,
    blocksScope: bool,
    createdAt: i64,
};

fn summarize(ctx: *Cli.Ctx, list: []const Store.operations.Operation) ![]Summary {
    var out: std.ArrayList(Summary) = .empty;
    for (list) |op| {
        try out.append(ctx.arena, .{
            .requestId = op.request_id,
            .kind = op.kind,
            .status = op.status.text(),
            .effectiveStatus = op.effectiveStatus().text(),
            .resolvedStatus = if (op.resolved_status) |r| r.text() else null,
            .scopeKind = op.scope_kind,
            .scopeKey = op.scope_key,
            .alias = op.alias,
            .blocksScope = op.effectiveStatus().blocksScope(),
            .createdAt = op.created_at,
        });
    }
    return out.toOwnedSlice(ctx.arena);
}

fn showRequest(ctx: *Cli.Ctx, store: *Store, request_id: []const u8) !void {
    const op = (Store.operations.get(store, ctx.arena, request_id) catch |err| Cli.storeFatal(store, err)) orelse
        fatal("no such request '{s}'", .{request_id});

    switch (ctx.out.format) {
        .json => try ctx.out.json(.{
            .ok = true,
            .requestId = op.request_id,
            .server = op.server_name,
            .kind = op.kind,
            .alias = op.alias,
            // `status` is what we observed; `effectiveStatus` folds in a
            // later-proven truth without erasing the observation.
            .status = op.status.text(),
            .effectiveStatus = op.effectiveStatus().text(),
            .resolvedStatus = if (op.resolved_status) |r| r.text() else null,
            .reconciledAt = op.reconciled_at,
            .resolutionEvidence = op.resolution_evidence,
            .blocksScope = op.effectiveStatus().blocksScope(),
            .scopeKind = op.scope_kind,
            .scopeKey = op.scope_key,
            .command = op.argv_redacted,
            .commandSha256 = op.argv_sha256,
            .cwd = op.cwd,
            .capability = op.capability_json,
            .createdAt = op.created_at,
            .updatedAt = op.updated_at,
        }),
        .human => {
            try ctx.out.print("{s}\n", .{op.request_id});
            try ctx.out.print("  server  : {s}\n", .{op.server_name});
            try ctx.out.print("  kind    : {s}{s}{s}\n", .{ op.kind, if (op.alias != null) " / " else "", op.alias orelse "" });
            try ctx.out.print("  status  : {s}", .{op.status.text()});
            if (op.resolved_status) |r| try ctx.out.print(" (reconciled: {s})", .{r.text()});
            try ctx.out.print("\n", .{});
            try ctx.out.print("  blocks  : {s}\n", .{if (op.effectiveStatus().blocksScope()) "yes" else "no"});
            try ctx.out.print("  command : {s}\n", .{op.argv_redacted orelse "(not recorded)"});
        },
    }
}

fn showReceipt(ctx: *Cli.Ctx, store: *Store, request_id: []const u8) !void {
    const rows = Store.receipts.list(store, ctx.arena, request_id) catch |err| Cli.storeFatal(store, err);
    if (rows.len == 0) fatal("no receipt for '{s}'", .{request_id});

    switch (ctx.out.format) {
        .json => try ctx.out.json(.{ .ok = true, .requestId = request_id, .events = rows }),
        .human => for (rows) |row| {
            try ctx.out.print("{d:>3} {s:<13} {s:<14} {s}\n", .{
                row.seq,
                row.kind,
                row.status orelse "",
                row.transport_error orelse row.error_code orelse "",
            });
        },
    }
}

/// Establishes what an attempt did, from whichever state it is stuck in.
///
/// Two different states need reconciling, and they need different machinery:
///
///   * `indeterminate` — already settled as unknown. Its terminal is frozen,
///     so the truth is *annotated* beside it via `resolve`.
///   * `submitted` / `remote_started` — never settled at all. This is the
///     common case: `run` detaches, the caller walks away, and the attempt
///     holds its scope forever. Nothing has been recorded yet, so the log can
///     still produce a real terminal via `settle`.
///
/// Routing only the first one here (as this command originally did) left the
/// second with no way out but `--force`, which is the blind retry the guard
/// exists to prevent.
fn reconcile(ctx: *Cli.Ctx, store: *Store, request_id: []const u8, parsed: *const Cli.Args.Parsed) !void {
    const op = (Store.operations.get(store, ctx.arena, request_id) catch |err| Cli.storeFatal(store, err)) orelse
        fatal("no such request '{s}'", .{request_id});

    if (op.resolved_status) |existing| fatal(
        "request {s} was already reconciled as {s}; a resolution is written once",
        .{ request_id, existing.text() },
    );

    const outcome = switch (op.status) {
        .indeterminate => if (parsed.boolean("from-log"))
            try resolveFromLog(ctx, store, op, parsed)
        else if (parsed.flag("override")) |reason|
            try reconcileByOverride(ctx, store, op, reason, parsed)
        else
            fatal(
                "choose how to establish the outcome: --from-log (read the job's exit sentinel) or --override \"<reason>\" --by <who> --resolved <status>",
                .{},
            ),

        // Still in flight. An override may not settle this: the work might be
        // running right now, and a human assertion that it "completed" would
        // release the scope on top of a live process. --from-log is the only
        // route, and if it finds the session gone it records `indeterminate`
        // — which can then be overridden, in that order.
        .submitted, .remote_started => if (parsed.boolean("from-log"))
            try settleFromLog(ctx, store, op, parsed)
        else if (parsed.flag("override") != null)
            fatal(
                "request {s} is {s}: it was never settled, so there is nothing to override yet — the work may still be running. Run 'request reconcile {s} --from-log' first; it settles the real outcome from the job's log, or records indeterminate if the session is gone, and you can override that",
                .{ request_id, op.status.text(), request_id },
            )
        else
            fatal(
                "request {s} is {s} and still holds its scope; establish what happened with 'request reconcile {s} --from-log'",
                .{ request_id, op.status.text(), request_id },
            ),

        .created, .connecting => fatal(
            "request {s} is {s}: it was never handed to the remote, so there is nothing to establish (it does not block a scope either)",
            .{ request_id, op.status.text() },
        ),

        .completed, .failed, .timed_out, .cancelled => fatal(
            "request {s} is {s} — its outcome is already established",
            .{ request_id, op.status.text() },
        ),
    };

    switch (ctx.out.format) {
        .json => try ctx.out.json(.{
            .ok = outcome.ok,
            .requestId = request_id,
            .resolved = outcome.resolved,
            .status = outcome.status,
            .stillRunning = outcome.still_running,
            .mechanical = outcome.mechanical,
            // Present so a caller can branch without matching prose, and null
            // rather than absent so "this refusal has no code" is a value the
            // caller reads instead of a key it has to notice is missing. It is
            // deliberately not the same field as the one `receiptFatal` prints:
            // that one means the ledger could not be written, and these mean
            // the store declined to write it.
            .errorCode = outcome.error_code,
            .detail = outcome.detail,
        }),
        .human => {
            try ctx.out.print("{s}: {s} ({s})\n", .{
                request_id,
                outcome.resolved orelse outcome.status,
                outcome.detail,
            });
            if (outcome.error_code) |code| try ctx.out.print("  code: {s}\n", .{code});
        },
    }

    switch (outcome.exit) {
        .ok => {},
        .failure => {
            try ctx.out.flush();
            std.process.exit(1);
        },
        // Reconcile did its job and the answer is still "unknown". That is
        // not a failure of this command, and it must not read as one: an
        // agent that sees exit 1 here would treat the work as safe to retry.
        .indeterminate => {
            try ctx.out.flush();
            Cli.failIndeterminateAfterOutput(request_id);
        },
    }
}

const Outcome = struct {
    ok: bool,
    /// The outcome this call established, if it established one.
    resolved: ?[]const u8,
    mechanical: bool,
    /// The operation's status after this call.
    status: []const u8,
    /// The attempt is legitimately still in flight; nothing was settled.
    still_running: bool = false,
    /// A stable, machine-readable name for *why* this was refused, when the
    /// refusal is one a caller should be able to branch on without reading
    /// prose. Null when the outcome carries no code — the ordinary refusals
    /// below are told apart by `resolved`/`status` and their detail.
    error_code: ?[]const u8 = null,
    detail: []const u8,
    exit: enum { ok, failure, indeterminate },
};

/// The refusals `receipts.resolve` reports as errors rather than as outcomes.
///
/// These are *semantic* refusals: the store looked at what it was given, decided
/// it could not act on it, and deliberately wrote nothing. None is a storage
/// failure, and routing them through `Cli.receiptFatal` — which every `resolve`
/// call site used to do for any error at all — says the opposite twice over: it
/// prints `RECEIPT_PERSIST_FAILED` and "the local ledger is incomplete" and
/// exits 76, when nothing failed to persist and the ledger is exactly as
/// complete as it was. An agent reading 76 is being told the remote effect may
/// have happened and our record of it is broken, which is a much worse
/// situation than the one it is in.
///
/// Exit 1, with the rest of `resolve`'s refusals, and for the same reason: the
/// request was refused, the operation is untouched, and the caller can fix it
/// by bringing different evidence. Not 75 — that is reserved for "we
/// established nothing and the remote state is unknown", which is a statement
/// about the *world* rather than about this command, and it is what this
/// command exits with when a reconcile genuinely could not settle anything.
/// Here the reconcile was not performed at all.
///
/// The parameter is `receipts.Error` rather than `anyerror`, and that is the
/// substance of this function rather than a tidying-up. It used to take
/// `anyerror` and end in `else => null`, so the classification only covered the
/// two members somebody had thought about, and everything else was fatal by
/// omission. Then `resolve` started writing to the checkpoint table and
/// inherited ten refusals from `transfers.AdjudicateError` in one line — "this
/// transfer never read a digest back off its result", "another request adopted
/// the checkpoint out from under you" — every one of which arrived at the
/// operator as a corrupted ledger. Nothing warned, because `else` had already
/// agreed to catch them. With the concrete set, `refusalDetail` below refuses to
/// compile against an error nobody has classified, so the next member added to
/// `receipts.Error` has to declare which of the two kinds it is.
fn semanticRefusal(err: Store.receipts.Error, status: []const u8) ?Outcome {
    switch (err) {
        // Genuinely fatal, and each for its own reason.
        //
        // The first four are the storage layer failing, and `OutOfMemory` is
        // this process failing; for all five the write may have half-happened
        // and 76 is exactly right. The last two mean *this binary* called the
        // wrong writer — a terminal event routed anywhere but `settle`, a
        // reconcile routed anywhere but `resolve`. That is our defect, not a
        // request the caller can restate, and dressing it as a polite refusal
        // would hide a bug behind a message telling the operator to try
        // different evidence.
        error.Sqlite,
        error.Constraint,
        error.WalSetupExhausted,
        error.NotInTransaction,
        error.OutOfMemory,
        error.TerminalRequiresSettle,
        error.ReconcileRequiresResolve,
        => return null,

        inline else => |e| return .{
            .ok = false,
            .resolved = null,
            .mechanical = true,
            .status = status,
            .error_code = comptime errorCode(e),
            .detail = comptime refusalDetail(e),
            .exit = .failure,
        },
    }
}

/// `PublishNeedsVerifiedHash` → `PUBLISH_NEEDS_VERIFIED_HASH`.
///
/// Derived from the error's own name rather than written out beside it, so the
/// two cannot drift apart: renaming the error renames the code, and there is no
/// second list to keep in step. Both codes this function replaced were spelled
/// exactly this way by hand, so nothing an existing caller branches on moves.
fn errorCode(comptime err: anyerror) []const u8 {
    comptime {
        @setEvalBranchQuota(10_000);
        const name = @errorName(err);
        var buf: [name.len * 2]u8 = undefined;
        var n: usize = 0;
        for (name, 0..) |ch, i| {
            if (std.ascii.isUpper(ch) and i != 0) {
                buf[n] = '_';
                n += 1;
            }
            buf[n] = std.ascii.toUpper(ch);
            n += 1;
        }
        const frozen = buf[0..n].*;
        return &frozen;
    }
}

/// What each refusal means to somebody holding a terminal, in their terms.
///
/// One sentence saying what was refused and, wherever there is one, what the
/// next move is. The ones with no next move say so rather than inventing one:
/// "the row was written by another version" is not advice, but it is the truth
/// and it stops the operator hunting for evidence that would not have helped.
///
/// `@compileError` rather than a catch-all string, and this is the whole reason
/// the function exists: a member added to `receipts.Error` and left unclassified
/// stops the build, naming itself. A default sentence here would put every
/// future refusal in front of an operator wearing the wrong explanation, which
/// is the failure this pass is closing, one level further out.
fn refusalDetail(comptime err: anyerror) []const u8 {
    return switch (err) {
        // The operation is a transfer whose rename nobody watched, and the
        // evidence offered cannot say which way it went. Nothing was written:
        // resolving the operation while abandoning its checkpoint would lift
        // the scope barrier and leave the destination held against everyone.
        //
        // Every reading that *would* settle it is named, and the gate below
        // checks that against `receipts.adjudicatesParkedPublish` rather than
        // against a list kept here by hand. It was kept by hand, and it went
        // stale: the sentence offered two readings after there were four, and
        // the transfer whose only route was one of the two it omitted — parked,
        // with no declared digest — had `--override` refused by this very error
        // and a hash refused by `effect_hash_unproven`, each pointing at the
        // other. A refusal that names an incomplete set of exits is a refusal
        // that can close a loop.
        error.PublishAdjudicationUndetermined => "this transfer's rename was never observed, and the evidence offered cannot say whether it landed. Settle it with a reading of the destination it committed to, and which of the four you have depends on what is there: the published file's hash when the artifact is there and this transfer declared a digest it agrees with; a contradicting-destination reading when it declared one and the file disagrees with it; a presence reading with no digest when it declared none, so there is nothing to check the file against; or a destination-absent reading when the path is empty",

        // A stored column holds a word this binary cannot name. Not a
        // persistence failure — a row we refuse to reason about, because
        // guessing at its meaning is how an unrecognised value inherits the
        // most permissive branch.
        error.UnknownOperationKind => "this operation's kind is not one this binary knows, so nothing can decide which evidence may settle it; the row was written by another version or edited by hand",
        error.UnknownEventKind => "this operation's ledger contains an event kind this binary does not know, so its history cannot be read; the row was written by another version or edited by hand",
        error.UnknownSource => "this operation's ledger contains an event whose source this binary does not know, so it cannot be told apart from evidence we gathered ourselves; the row was written by another version or edited by hand",
        error.UnknownStatus => "this operation's stored status is not one this binary knows, so what may follow from it cannot be decided; the row was written by another version or edited by hand",
        error.UnknownDestSide => "this transfer's checkpoint records a destination side this binary does not know, so a reading of that destination cannot be matched against it; the row was written by another version or edited by hand",
        error.UnknownTransferState => "this transfer's checkpoint holds a state this binary does not know, so no move out of it can be judged legal; the row was written by another version or edited by hand",

        // The evidence was understood and does not fit.
        error.EvidenceDoesNotFit => "the evidence offered contradicts what the ledger already records about this attempt, so it cannot settle it; nothing was written",
        error.ContradictoryEvidence => "the supplementary fields offered contradict the evidence they accompany, so the pair cannot be recorded as one observation; nothing was written",
        error.IllegalTransition => "the outcome asked for does not follow from the status this operation is already in; re-read its status before deciding what to record",

        // The row the resolution would have judged is not the row it thought.
        error.UnknownOperation => "no operation with that request id is in the ledger",
        error.AmbiguousCheckpoint => "more than one of this request's checkpoints declared a digest, so which artifact a reading speaks about cannot be decided without choosing one by row order; nothing was written",
        error.CheckpointRowMissing => "this operation's transfer checkpoint is no longer in the store, so there is nothing left to adjudicate; the operation's own status is unchanged",
        error.CheckpointNotOurs => "another request has adopted this transfer's checkpoint — a resume took it over — so this operation is no longer the one that gets to say what became of it; reconcile the request that holds it now",

        // The move is refused by the state graph or by the evidence each end
        // state asserts. See `transfers.setStateSql`.
        error.IllegalCheckpointTransition => "this transfer's checkpoint cannot make the move this evidence implies from the state it is in; nothing was written",
        error.CheckpointAwaitingAdjudication => "this transfer is parked awaiting adjudication, and the move asked for is not one an adjudication may make",
        error.CheckpointNotAwaitingAdjudication => "this transfer is not parked awaiting adjudication — its publish is already decided, or it never reached one — so a reading of its destination has nothing to settle",
        error.NotAnAdjudicationTarget => "the state this evidence implies is not one of the four outcomes of an unobserved rename, so it cannot be recorded as an adjudication",
        error.SupersessionIsNotATransition => "releasing a transfer's destination is not something the transfer does to itself; it happens when a later request supersedes it",
        error.PublishNeedsVerifiedHash => "this transfer never read a digest back off its result, so it cannot be recorded as published; supply the hash of the file at the destination, or record it as completed-unverified if there is nothing to hash it against",
        error.PublishHashContradictsDeclared => "the digest recorded against this transfer disagrees with the one it declared before it sent anything, so the bytes at the destination are not the bytes that were promised; it cannot be recorded as published",
        error.CompletedUnverifiedHasVerifiedHash => "this transfer did read a digest back off its result, so it cannot be recorded as completed-unverified; the two end states are exclusive by construction",
        error.CompletedUnverifiedHasDeclaredHash => "this transfer declared in advance what its artifact would hash to, so it cannot be recorded as completed-unverified; that state is for a transfer with nothing to check its result against, and this one named the check before it sent a byte",
        error.HashMismatchWithAgreeingDigest => "this transfer's checkpoint records a digest equal to the one it declared, so it cannot also be recorded as a hash mismatch; a reading that disagrees has to be supplied with the verdict, and none was",

        else => @compileError(
            "receipts.Error." ++ @errorName(err) ++ " is neither classified as fatal in " ++
                "semanticRefusal nor given an operator-facing sentence here. Decide which it " ++
                "is; do not let it inherit one.",
        ),
    };
}

test "gate: a refusal to adjudicate is not reported as a failed write" {
    const t = std.testing;

    // `resolve` hands these back as errors, and the reconcile path used to
    // funnel every error into `Cli.receiptFatal`: exit 76,
    // `RECEIPT_PERSIST_FAILED`, "the local ledger is incomplete". All three are
    // false — the refusal is the store declining to act, and it wrote nothing
    // precisely so that the ledger would stay consistent.
    // Named rather than unwrapped, because the regression this guards against
    // is precisely "this error stopped being classified" — and a caller that
    // reads only the panic message would not know that is what happened.
    const undetermined = semanticRefusal(error.PublishAdjudicationUndetermined, "indeterminate") orelse
        return error.UndeterminedAdjudicationWouldBeReportedAsAFailedWrite;
    try t.expect(!undetermined.ok);
    try t.expectEqualStrings("PUBLISH_ADJUDICATION_UNDETERMINED", undetermined.error_code.?);
    try t.expect(undetermined.exit == .failure);
    // *Which* evidence would work is checked by the gate below, against the
    // store's own answer. Asserting only that the word "destination" appears
    // was how this gate went on passing while the sentence named two of the
    // four readings — including neither of the two a transfer that declared no
    // digest can use.

    const unknown_kind = semanticRefusal(error.UnknownOperationKind, "indeterminate") orelse
        return error.UnknownKindWouldBeReportedAsAFailedWrite;
    try t.expectEqualStrings("UNKNOWN_OPERATION_KIND", unknown_kind.error_code.?);
    try t.expect(unknown_kind.exit == .failure);

    // Distinguishable from each other, which is the whole point of a code: a
    // caller branching on one must not catch the other.
    try t.expect(!std.mem.eql(u8, undetermined.error_code.?, unknown_kind.error_code.?));

    // And a real storage failure is *not* absorbed. Anything unclassified stays
    // fatal, because reporting a broken write as a polite refusal is the same
    // lie in the other direction.
    try t.expectEqual(@as(?Outcome, null), semanticRefusal(error.Sqlite, "indeterminate"));
    try t.expectEqual(@as(?Outcome, null), semanticRefusal(error.OutOfMemory, "indeterminate"));
}

/// The phrase the undetermined-adjudication sentence must contain for a given
/// reading, or null when that evidence cannot adjudicate a parked publish.
///
/// Exhaustive with no `else`: a new evidence variant stops the build here, which
/// is the only way this table can be made to stay in step with the union. The
/// phrases are the ones the sentence uses, not paraphrases — a gate matching on
/// a word that happens to appear anyway ("destination") is a gate that cannot
/// fail.
fn adjudicatingPhrase(
    comptime tag: std.meta.Tag(Store.receipts.ResolutionEvidence),
) ?[]const u8 {
    return switch (tag) {
        .filesystem_effect => "the published file's hash",
        .destination_present_unverified => "a presence reading with no digest",
        .destination_present_contradicting => "a contradicting-destination reading",
        .destination_absent => "a destination-absent reading",
        .job_result, .job_sentinel, .process_probe, .supervisor_report, .operator_override => null,
    };
}

/// Whether the store would let this *kind* of evidence adjudicate a parked
/// publish.
///
/// Asked of a zeroed payload on purpose: `publishAdjudication` decides on the
/// variant alone, and reads a payload field only to carry a digest it does not
/// inspect. Going through the real function rather than restating its answer is
/// the whole point — a second copy of "which readings can adjudicate" is exactly
/// the thing that drifted.
fn adjudicatesTag(comptime tag: std.meta.Tag(Store.receipts.ResolutionEvidence)) bool {
    const E = Store.receipts.ResolutionEvidence;
    const Payload = @FieldType(E, @tagName(tag));
    const value: E = @unionInit(
        E,
        @tagName(tag),
        if (Payload == void) {} else std.mem.zeroes(Payload),
    );
    return Store.receipts.adjudicatesParkedPublish(value);
}

test "gate: the undetermined-adjudication refusal names every reading that would settle it" {
    const t = std.testing;
    const detail = comptime refusalDetail(error.PublishAdjudicationUndetermined);
    const E = Store.receipts.ResolutionEvidence;

    var named: usize = 0;
    inline for (@typeInfo(E).@"union".fields) |field| {
        const tag = @field(std.meta.Tag(E), field.name);
        const phrase = adjudicatingPhrase(tag);
        // The table and the store have to agree about which readings can settle
        // a parked publish. A phrase for one that cannot would send an operator
        // to evidence the store refuses; silence about one that can is how the
        // loop got closed in the first place.
        try t.expectEqual(adjudicatesTag(tag), phrase != null);
        if (phrase) |needle| {
            if (std.mem.indexOf(u8, detail, needle) == null) {
                std.debug.print(
                    "the undetermined-adjudication sentence does not name {s}: it should contain \"{s}\"\n",
                    .{ field.name, needle },
                );
                return error.UndeterminedSentenceOmitsAReading;
            }
            named += 1;
        }
    }
    // A sentence that named nothing would satisfy every loop above by vacuity.
    try t.expect(named >= 4);
}

test "gate: the refusals resolve inherited from the checkpoint table are classified too" {
    const t = std.testing;

    // `resolve` writes to `transfer_checkpoints` now, so its error set contains
    // that table's whole adjudication vocabulary. Each of these is the store
    // declining to move a row and writing nothing; every one of them used to
    // reach the operator as `RECEIPT_PERSIST_FAILED` / exit 76 / "the local
    // ledger is incomplete", which is three false statements about a store that
    // is perfectly intact.
    //
    // Listed by hand on purpose. `refusalDetail`'s `@compileError` already
    // guarantees *completeness* — nothing can be left unclassified — so what is
    // left to check is the part a compiler cannot: that these particular
    // members landed on the refusal side of the split rather than the fatal
    // one, and that each says something an operator can act on.
    const inherited = [_]Store.receipts.Error{
        error.UnknownTransferState,
        error.CheckpointRowMissing,
        error.CheckpointNotOurs,
        error.IllegalCheckpointTransition,
        error.CheckpointAwaitingAdjudication,
        error.CheckpointNotAwaitingAdjudication,
        error.SupersessionIsNotATransition,
        error.PublishNeedsVerifiedHash,
        error.PublishHashContradictsDeclared,
        error.CompletedUnverifiedHasVerifiedHash,
        error.NotAnAdjudicationTarget,
    };
    for (inherited) |err| {
        const out = semanticRefusal(err, "indeterminate") orelse {
            std.debug.print("unclassified, still fatal: {s}\n", .{@errorName(err)});
            return error.InheritedRefusalWouldBeReportedAsAFailedWrite;
        };
        try t.expect(!out.ok);
        try t.expect(out.exit == .failure);
        try t.expect(out.resolved == null);
        // A code, so a caller branches on the reason rather than on prose.
        try t.expect(out.error_code != null);
        try t.expect(out.error_code.?.len > 0);
        // A sentence, not a name: an operator reading `CHECKPOINT_NOT_OURS` and
        // nothing else has been told what happened in the vocabulary of a
        // module they cannot see.
        try t.expect(out.detail.len > 40);
        try t.expect(std.mem.indexOf(u8, out.detail, " ") != null);
    }

    // The codes are the error names, mechanically, so two errors cannot share
    // one code and a rename cannot leave a stale one behind.
    try t.expectEqualStrings("CHECKPOINT_NOT_OURS", (semanticRefusal(error.CheckpointNotOurs, "x").?).error_code.?);
    try t.expectEqualStrings(
        "PUBLISH_NEEDS_VERIFIED_HASH",
        (semanticRefusal(error.PublishNeedsVerifiedHash, "x").?).error_code.?,
    );

    // The other half of the split still holds: this widened the classification,
    // it did not turn the fatal bucket into a formality.
    try t.expectEqual(@as(?Outcome, null), semanticRefusal(error.Constraint, "x"));
    try t.expectEqual(@as(?Outcome, null), semanticRefusal(error.NotInTransaction, "x"));
    // An internal routing defect stays fatal as well: a terminal event that
    // reached `resolve` is a bug in this binary, and telling the operator to
    // bring better evidence would hide it.
    try t.expectEqual(@as(?Outcome, null), semanticRefusal(error.TerminalRequiresSettle, "x"));
}

/// What the job's own durable evidence says, and whether its session is
/// still there.
const LogEvidence = struct {
    alias: []const u8,
    sentinel: []const u8,
    exit_code: ?i32,
    /// Which record answered. Carried through so the receipt names the
    /// evidence it actually had rather than the one this command is called
    /// after.
    source: Tmux.JobProbe.ExitSource,
    finished_at: ?i64,
    /// The request id the sidecar document *itself* named. Non-null exactly
    /// when `source == .result_file`.
    ///
    /// Carried rather than re-derived from the operation we are reconciling:
    /// the Store re-checks that the evidence's id and the operation's agree,
    /// and filling both sides of that check from the same place makes it
    /// unfalsifiable.
    result_request_id: ?[]const u8,
    /// Set when the sidecar and the log sentinel both answered and disagreed.
    ///
    /// Carried, not dropped: without it `exit_code == null` means two very
    /// different things — "the job left nothing behind" and "it left two
    /// answers that cannot both be true" — and the message this command
    /// prints for the first is a lie about the second.
    conflict: ?Tmux.JobProbe.Conflict,
    session_alive: bool,
    output_bytes: usize,
};

/// Goes and reads what the job left behind: its result sidecar first, then
/// its log. Both are written by the remote shell after the command returns,
/// so either is available long after the process that launched the job is
/// gone — but only the sidecar stays findable once the job's own output has
/// buried the sentinel.
fn readLog(
    ctx: *Cli.Ctx,
    store: *Store,
    op: Store.operations.Operation,
    parsed: *const Cli.Args.Parsed,
) !LogEvidence {
    const alias = op.alias orelse fatal("--from-log needs a job; request {s} is a {s}", .{ op.request_id, op.kind });
    const attempt = (Store.job_attempts.byRequest(store, ctx.arena, op.request_id) catch |err|
        Cli.storeFatal(store, err)) orelse
        fatal("no recorded attempt for request {s}, so its log cannot be located", .{op.request_id});
    const sentinel = attempt.sentinel orelse
        fatal("attempt for {s} has no sentinel recorded", .{op.request_id});
    const session = attempt.tmux_session orelse
        fatal("attempt for {s} has no session recorded", .{op.request_id});

    const resolved_server = Cli.resolveServer(ctx, store, op.server_name);
    var conn = Cli.connect(ctx, parsed, resolved_server.server, resolved_server.auth);
    defer conn.deinit();

    // One round trip: the sidecar at its fixed address, plus a tail of the
    // log for the sentinel fallback and the output-size figure.
    const probe = Tmux.probeTail(conn.executor(), ctx.arena, session, sentinel, op.request_id, Cli.probe_tail_bytes) catch |err|
        fatal("cannot read the job log for '{s}': {s}", .{ alias, @errorName(err) });

    return .{
        .alias = alias,
        .sentinel = sentinel,
        .exit_code = probe.exit_code,
        .source = probe.exit_source,
        .finished_at = probe.finished_at,
        .result_request_id = probe.result_request_id,
        .conflict = probe.conflict,
        .session_alive = probe.session_alive,
        .output_bytes = probe.output.len,
    };
}

/// The evidence value matching whichever record answered, and the sentence
/// that describes it. Never says "sentinel" when it read a sidecar.
fn evidenceOf(e: LogEvidence, code: i32) struct {
    evidence: Store.receipts.ResolutionEvidence,
    detail: []const u8,
} {
    return switch (e.source) {
        .result_file => .{
            .evidence = .{
                .job_result = .{
                    // The document's own claim, never the operation we are
                    // reconciling: `resolve` compares the two, and a receipt
                    // filled from the id we searched with would be comparing a
                    // value against itself. `readingOf` guarantees this is
                    // non-null on this arm, so the `orelse` is an invariant
                    // check and not a fallback — there is no honest value to
                    // substitute if it ever fires.
                    .request_id = e.result_request_id orelse fatal(
                        "the job's result record answered for '{s}' but named no request; refusing to reconcile from it",
                        .{e.alias},
                    ),
                    .exit_code = code,
                    .finished_at = e.finished_at,
                },
            },
            .detail = "the job's result record carried its exit status",
        },
        // `.none` cannot reach here: the caller only calls this once it has an
        // exit code, and an exit code without a source is not producible.
        .log_sentinel, .none => .{
            .evidence = .{ .job_sentinel = .{ .sentinel = e.sentinel, .exit_code = code } },
            .detail = "exit sentinel found in the job log",
        },
    };
}

test "M2e gate: reconcile names the record it actually read" {
    const t = std.testing;
    // Deliberately different from `rid` below: the receipt has to carry what
    // the *document* claimed, so a test that used one id for both sides would
    // pass just as happily against the tautology this exists to prevent.
    const doc_rid = "01JQXW8ZK4N0RS7T3VYB2MCXYZ";
    const base: LogEvidence = .{
        .alias = "deploy",
        .sentinel = "__TERMINUS_JOB_5__",
        .exit_code = 3,
        .source = .result_file,
        .finished_at = 1750000000,
        .result_request_id = doc_rid,
        .conflict = null,
        .session_alive = false,
        .output_bytes = 12,
    };
    const rid = "01JQXW8ZK4N0RS7T3VYB2MCDEF";
    try t.expect(!std.mem.eql(u8, doc_rid, rid));

    // The receipt has to carry the evidence that answered. Reporting a
    // sentinel for a result file — or the reverse — would make the audit
    // trail describe a lookup that never happened.
    const from_file = evidenceOf(base, 3);
    try t.expectEqualStrings("job_result", from_file.evidence.kindName());
    try t.expectEqual(@as(i64, 3), from_file.evidence.job_result.exit_code);
    try t.expectEqual(@as(?i64, 1750000000), from_file.evidence.job_result.finished_at);
    try t.expectEqualStrings(doc_rid, from_file.evidence.job_result.request_id);
    try t.expect(std.mem.indexOf(u8, from_file.detail, "sentinel") == null);

    // A host with no usable clock writes no finish time. That absence has to
    // survive into the receipt as absence — recording the epoch would publish
    // 1970 as the moment the work ended.
    var no_clock = base;
    no_clock.finished_at = null;
    try t.expectEqual(@as(?i64, null), evidenceOf(no_clock, 3).evidence.job_result.finished_at);

    var legacy = base;
    legacy.source = .log_sentinel;
    legacy.finished_at = null;
    legacy.result_request_id = null;
    const from_log = evidenceOf(legacy, 3);
    try t.expectEqualStrings("job_sentinel", from_log.evidence.kindName());
    try t.expectEqualStrings("__TERMINUS_JOB_5__", from_log.evidence.job_sentinel.sentinel);
    try t.expect(std.mem.indexOf(u8, from_log.detail, "sentinel") != null);
}

/// Annotates an already-`indeterminate` attempt with what the job proves.
fn resolveFromLog(
    ctx: *Cli.Ctx,
    store: *Store,
    op: Store.operations.Operation,
    parsed: *const Cli.Args.Parsed,
) !Outcome {
    const evidence = try readLog(ctx, store, op, parsed);

    // A contradiction is checked before the exit code, because it is not a
    // weaker form of "no evidence": both records answered, and they cannot
    // both be right. Resolving from either would release the scope on a coin
    // flip, and `resolve` is the only guard on that barrier.
    if (evidence.conflict) |clash| return .{
        .ok = false,
        .resolved = null,
        .mechanical = true,
        .status = op.status.text(),
        .detail = std.fmt.allocPrint(
            ctx.arena,
            "the job's two durable records disagree: its result file says exit {d}, the sentinel in its log says exit {d}. Nothing mechanical can settle this — check the host and use --override",
            .{ clash.result_exit_code, clash.sentinel_exit_code },
        ) catch "the job's result file and its log sentinel report different exit codes; check the host and use --override",
        .exit = .indeterminate,
    };

    const code = evidence.exit_code orelse return .{
        .ok = false,
        .resolved = null,
        .mechanical = true,
        .status = op.status.text(),
        .detail = if (evidence.session_alive)
            "the job session is still alive and it has recorded no exit status; its outcome is not established yet"
        else
            "the job left no exit status behind — no result record and no sentinel in its log; its outcome is still unknown (the evidence may have been discarded, or the job never finished)",
        .exit = .indeterminate,
    };

    const resolved: Store.op_state.ResolvedStatus = if (code == 0) .completed else .failed;
    const chosen = evidenceOf(evidence, code);
    const result = Store.receipts.resolve(store, ctx.arena, op.request_id, resolved, chosen.evidence, ctx.now) catch |err|
        return semanticRefusal(err, op.status.text()) orelse
            Cli.receiptFatal(op.request_id, err, "reconcile");

    return interpret(result, resolved, true, chosen.detail, ctx.arena);
}

/// Settles an attempt that was never settled at all.
///
/// Four answers, kept strictly apart:
///
///   * the two durable records disagree — settled `indeterminate`, naming both
///     codes. This is *not* the "left nothing behind" case and must not borrow
///     its message: the evidence is present and untrustworthy, so no later
///     mechanical reconcile will do any better either;
///   * an exit status is recorded — the job ended and we can say how. Settled
///     for real, and the scope is released.
///   * no exit status, session alive — the job is running. Nothing is
///     settled; the scope stays held because it *should* be held.
///   * no exit status, session gone — something happened and the evidence is
///     gone with it. Settled `indeterminate`, which still blocks the scope.
///     An operator override can then release it, as an override.
fn settleFromLog(
    ctx: *Cli.Ctx,
    store: *Store,
    op: Store.operations.Operation,
    parsed: *const Cli.Args.Parsed,
) !Outcome {
    const evidence = try readLog(ctx, store, op, parsed);

    var execution = (Core.execution.attach(store, ctx.arena, ctx.io, op.request_id) catch |err|
        Cli.storeFatal(store, err)) orelse return .{
        .ok = false,
        .resolved = null,
        .mechanical = true,
        .status = op.status.text(),
        .detail = "the attempt was settled by someone else while we were reading its log; read it back with 'request show'",
        .exit = .failure,
    };

    if (evidence.conflict) |clash| {
        const reason = std.fmt.allocPrint(
            ctx.arena,
            "the job's two durable records disagree: its result file says exit {d}, the sentinel in its log says exit {d}. One of them is wrong and nothing here can say which",
            .{ clash.result_exit_code, clash.sentinel_exit_code },
        ) catch "the job's result file and its log sentinel report different exit codes";
        _ = execution.settleAttached(.{ .indeterminate = .{
            .reason = reason,
            .last_observed = execution.status,
        } }, .{ .source = .reconcile }) catch |err| Cli.receiptFatal(op.request_id, err, op.status.text());
        return .{
            .ok = false,
            .resolved = null,
            .mechanical = true,
            .status = Store.op_state.Status.indeterminate.text(),
            .detail = std.fmt.allocPrint(
                ctx.arena,
                "{s}. Recorded as indeterminate, which keeps holding the scope; re-reading the log will not help, so release it with --override once you have checked the host by hand",
                .{reason},
            ) catch reason,
            .exit = .indeterminate,
        };
    }

    if (evidence.exit_code) |code| {
        const settled = execution.settleAttached(.{ .exited = .{ .exit_code = code } }, .{
            .stdout = .{ .bytes = @intCast(evidence.output_bytes) },
            .source = .reconcile,
        }) catch |err| Cli.receiptFatal(op.request_id, err, op.status.text());
        const status = switch (settled) {
            .recorded => |r| r.status,
            .already_settled => |r| r.status,
        };
        return .{
            .ok = true,
            .resolved = status.text(),
            .mechanical = true,
            .status = status.text(),
            .detail = evidenceOf(evidence, code).detail,
            .exit = .ok,
        };
    }

    if (evidence.session_alive) {
        // Nothing to settle: the job really is running. Recording that we
        // looked keeps the trail honest without inventing a verdict.
        _ = Store.receipts.append(store, .{
            .request_id = op.request_id,
            .kind = .checkpoint,
            .phase = "reconcile_probe",
            .observed_at = ctx.now,
            .detail_json = try probeJson(ctx.arena, true),
        }) catch |err| Cli.receiptFatal(op.request_id, err, op.status.text());
        return .{
            .ok = true,
            .resolved = null,
            .mechanical = true,
            .status = op.status.text(),
            .still_running = true,
            .detail = "still running: the job session is alive and has recorded no exit status. Nothing to reconcile — poll it with 'job status'",
            .exit = .ok,
        };
    }

    _ = execution.settleAttached(.{ .indeterminate = .{
        .reason = "job session is gone and it recorded no exit status, in neither its result record nor its log",
        .last_observed = execution.status,
    } }, .{ .source = .reconcile }) catch |err| Cli.receiptFatal(op.request_id, err, op.status.text());

    return .{
        .ok = false,
        .resolved = null,
        .mechanical = true,
        .status = Store.op_state.Status.indeterminate.text(),
        .detail = "the job session is gone and left no exit status behind; recorded as indeterminate, which keeps holding the scope. Release it with --override once you have checked the host by hand",
        .exit = .indeterminate,
    };
}

fn probeJson(arena: std.mem.Allocator, session_alive: bool) ![]u8 {
    var writer: std.Io.Writer.Allocating = .init(arena);
    std.json.Stringify.value(.{
        .schemaVersion = Store.receipts.schema_version,
        .event = "reconcile_probe",
        .sessionAlive = session_alive,
        .exitStatusFound = false,
    }, .{}, &writer.writer) catch return error.OutOfMemory;
    return writer.toOwnedSlice();
}

fn reconcileByOverride(
    ctx: *Cli.Ctx,
    store: *Store,
    op: Store.operations.Operation,
    reason: []const u8,
    parsed: *const Cli.Args.Parsed,
) !Outcome {
    const by = parsed.flag("by") orelse fatal("--override requires --by <who>, so the decision has an owner", .{});
    const status_text = parsed.flag("resolved") orelse
        fatal("--override requires --resolved <completed|failed|timed_out|cancelled>", .{});
    const resolved = Store.op_state.ResolvedStatus.parse(status_text) catch
        fatal("invalid --resolved '{s}' (completed|failed|timed_out|cancelled)", .{status_text});

    const result = Store.receipts.resolve(store, ctx.arena, op.request_id, resolved, .{
        .operator_override = .{ .reason = reason, .by = by },
    }, ctx.now) catch |err|
        return semanticRefusal(err, op.status.text()) orelse
            Cli.receiptFatal(op.request_id, err, "reconcile");

    return interpret(result, resolved, false, "recorded as a human decision, not as proof", ctx.arena);
}

fn sideName(side: Store.transfers.Side) []const u8 {
    return switch (side) {
        .local => "local",
        .remote => "remote",
    };
}

/// Says which of the three ways a process probe missed its target.
///
/// Split out of `interpret` because the branches are not variations on one
/// sentence: the first two describe a probe that can be repeated correctly, the
/// third describes an attempt for which no probe will ever work, and an
/// operator who cannot tell them apart will keep re-running the one that cannot
/// succeed.
fn wrongProcessDetail(
    arena: std.mem.Allocator,
    m: @FieldType(Store.receipts.ResolveOutcome, "evidence_wrong_process"),
) []const u8 {
    const had = m.recorded orelse return std.fmt.allocPrint(
        arena,
        "this attempt never recorded a process identity, so a probe of pid {d} cannot speak about it; establish the outcome from what the work left behind, or use --override",
        .{m.probed_pid},
    ) catch "this attempt never recorded a process identity, so no probe can speak about it";

    if (had.pid != m.probed_pid) return std.fmt.allocPrint(
        arena,
        "the probe read pid {d}; this attempt's process was pid {d}, so the probe is of something else",
        .{ m.probed_pid, had.pid },
    ) catch "the probe is of a different process from the one this attempt started";

    // Same pid, so the start token is what refused — the store only reaches
    // this outcome on a mismatch, and an attempt that recorded no token is
    // judged on its pid alone. The generic sentence covers the case where that
    // stops being true rather than printing an empty token as if one existed.
    const want = had.start_token orelse
        return "the probe does not match the process this attempt recorded";
    return std.fmt.allocPrint(
        arena,
        "pid {d} is this attempt's, but its process started with token {s} and the probe {s}; a recycled pid is not the same process",
        .{
            m.probed_pid,
            want,
            if (m.probed_start_token) |got|
                std.fmt.allocPrint(arena, "reports {s}", .{got}) catch "reports another"
            else
                "could not read one",
        },
    ) catch "the probe's start token is not the one this attempt recorded; a recycled pid is not the same process";
}

/// Turns what the ledger decided into what the operator is told.
///
/// Five of the outcomes below — `publish_not_in_question`,
/// `unverified_reading_when_digest_declared`, `contradiction_not_established`,
/// `reading_has_no_method`, and `absence_wrong_destination` in its
/// has-a-checkpoint form — can only arise from a reading of a transfer's
/// destination, and **no command produces one yet**. `reconcile` offers
/// `--from-log` and `--override`, and neither can carry an address, a digest or
/// a method. That is not a gap this file may close on its own: nothing
/// constructs a checkpoint from the command line either (`transfers.create` has
/// no caller outside the store and its gates), so the states these readings
/// answer are unreachable from a terminal in both directions, and the flag
/// vocabulary belongs with the transfer verb that will make them reachable.
///
/// Stated here because the day that verb lands is the day
/// `indeterminate_publish` becomes reachable from the outside, and if these
/// readings are not wired up in the same change it becomes reachable with no way
/// back out. The arms are written and the store admits all of them; what is
/// missing is a way to type one. Their prose therefore names the *evidence*
/// required and never a flag spelling, so nothing here tells an operator to pass
/// an argument that does not exist.
fn interpret(
    result: Store.receipts.ResolveOutcome,
    resolved: Store.op_state.ResolvedStatus,
    mechanical: bool,
    detail: []const u8,
    arena: std.mem.Allocator,
) Outcome {
    return switch (result) {
        .resolved => .{
            .ok = true,
            .resolved = resolved.text(),
            .mechanical = mechanical,
            .status = Store.op_state.Status.indeterminate.text(),
            .detail = detail,
            .exit = .ok,
        },
        .already_resolved => |existing| .{
            .ok = false,
            .resolved = existing.text(),
            .mechanical = mechanical,
            .status = Store.op_state.Status.indeterminate.text(),
            .detail = "already reconciled by someone else; a resolution is written once",
            .exit = .failure,
        },
        .not_indeterminate => |status| .{
            .ok = false,
            .resolved = null,
            .mechanical = mechanical,
            .status = status.text(),
            .detail = "no longer indeterminate; nothing to reconcile",
            .exit = .failure,
        },
        .evidence_does_not_support => .{
            .ok = false,
            .resolved = null,
            .mechanical = mechanical,
            .status = Store.op_state.Status.indeterminate.text(),
            .detail = "the evidence does not establish that result",
            .exit = .failure,
        },
        // Names all three halves — side, path and digest — because any one of
        // them can be the thing that does not line up, and an operator who is
        // only told "hash mismatch" cannot tell a corrupted payload from a
        // reading taken on the wrong machine or at the wrong path.
        //
        // A digest that disagrees at the right address is the one case with
        // somewhere else to go, so the sentence says so. This variant proves
        // `completed` and only `completed`, and it goes on refusing a
        // contradicting hash exactly as it always has — what changed is that
        // there is now a reading whose verdict *is* a failure, and an operator
        // holding a hash that does not match needs to be told it exists rather
        // than left thinking they have hit a dead end.
        .effect_hash_unproven => |fx| .{
            .ok = false,
            .resolved = null,
            .mechanical = mechanical,
            .status = Store.op_state.Status.indeterminate.text(),
            .detail = if (fx.expected) |want| std.fmt.allocPrint(
                arena,
                "this transfer committed to publishing {s} on the {s} side hashing to {s}; what was read was {s} on the {s} side hashing to {s}. A hash proves delivery and nothing else — if that really is this transfer's destination and the artifact there is not the one it promised, offer a contradicting-destination reading instead, which settles it as a hash mismatch and keeps the path held",
                .{
                    want.path,        sideName(want.side),        want.sha256,
                    fx.observed.path, sideName(fx.observed.side), fx.observed.sha256,
                },
            ) catch "what was read is not the file this transfer committed to publishing" else std.fmt.allocPrint(
                arena,
                "this transfer never declared what its artifact would hash to, so reading {s} proves nothing about it. If its publish is still an open question, the reading that settles it is a presence reading with no digest — a hash cannot help here, there is nothing to check one against. Only if the publish is already decided is --override the way out, and then only if you have checked by hand",
                .{fx.observed.path},
            ) catch "this transfer never recorded which file would prove it landed",
            .exit = .failure,
        },
        // The same mismatch with no digest in it. Named separately from the
        // hash refusal on purpose: telling an operator the hash did not match
        // when what did not match is the *address* sends them to inspect bytes
        // that were never in question.
        .absence_wrong_destination => |miss| .{
            .ok = false,
            .resolved = null,
            .mechanical = mechanical,
            .status = Store.op_state.Status.indeterminate.text(),
            .detail = if (miss.committed) |want| std.fmt.allocPrint(
                arena,
                "this transfer committed to publishing {s} on the {s} side; the reading was taken at {s} on the {s} side, so its absence says nothing about this transfer",
                .{ want.path, sideName(want.side), miss.observed.path, sideName(miss.observed.side) },
            ) catch "the path that was inspected is not the one this transfer committed to publishing" else std.fmt.allocPrint(
                arena,
                "this request has no transfer checkpoint, so it committed to no destination and nothing can be absent from it; reading {s} proves nothing about it",
                .{miss.observed.path},
            ) catch "this request has no transfer checkpoint, so it committed to no destination",
            .exit = .failure,
        },
        .evidence_wrong_kind => |mismatch| .{
            .ok = false,
            .resolved = null,
            .mechanical = mechanical,
            .status = Store.op_state.Status.indeterminate.text(),
            // Both halves named. The refusal used to print one fixed sentence,
            // which left an operator unable to see *which* pairing was
            // rejected — and the payload it discarded is the only place that
            // fact exists.
            .detail = std.fmt.allocPrint(
                arena,
                "{s} evidence cannot speak about a {s} operation",
                .{ mismatch.evidence_kind, mismatch.operation_kind },
            ) catch "that evidence cannot speak about this kind of operation",
            .exit = .failure,
        },
        // The evidence is about a different request. Not a category error —
        // the document may be perfectly good, it just belongs to another
        // operation, and settling this one from it would release a scope on
        // the strength of somebody else's exit code.
        .evidence_wrong_operation => |mismatch| .{
            .ok = false,
            .resolved = null,
            .mechanical = mechanical,
            .status = Store.op_state.Status.indeterminate.text(),
            .detail = std.fmt.allocPrint(
                arena,
                "the evidence names request {s}, not {s}; it cannot settle this one",
                .{ mismatch.evidence_request_id, mismatch.request_id },
            ) catch "the evidence names a different request; it cannot settle this one",
            .exit = .failure,
        },
        // Three different situations wearing one refusal, and they send an
        // operator three different ways: go and look at the right pid, accept
        // that the pid was recycled and the process is not ours, or accept that
        // this attempt never had a process to look for. A single sentence
        // covering all three would leave the first two indistinguishable from
        // the third, which is the only one no amount of probing can fix.
        .evidence_wrong_process => |mismatch| .{
            .ok = false,
            .resolved = null,
            .mechanical = mechanical,
            .status = Store.op_state.Status.indeterminate.text(),
            .detail = wrongProcessDetail(arena, mismatch),
            .exit = .failure,
        },
        // A reading of a destination whose question is already answered. The
        // state is named because it is the whole of the refusal: `published`
        // means the delivery is on record and a later absence is somebody
        // having removed the artifact afterwards, which is a different event
        // from this transfer failing.
        .publish_not_in_question => |m| .{
            .ok = false,
            .resolved = null,
            .mechanical = mechanical,
            .status = Store.op_state.Status.indeterminate.text(),
            .detail = std.fmt.allocPrint(
                arena,
                "this transfer's checkpoint already records '{s}' for {s} on the {s} side, so what became of its publish is not an open question; a reading taken now cannot re-decide it",
                .{ m.state, m.observed.path, sideName(m.observed.side) },
            ) catch "this transfer's publish is not an open question; a reading taken now cannot re-decide it",
            .exit = .failure,
        },
        // The weaker of two available readings, refused so the stronger one is
        // taken. The digest is printed because it is what the operator needs in
        // hand to produce that stronger reading.
        //
        // Said in terms of the evidence rather than of a flag: no command wires
        // these readings up yet (see `interpret`'s note on them),
        // and naming a spelling that does not exist would be worse than naming
        // none.
        .unverified_reading_when_digest_declared => |m| .{
            .ok = false,
            .resolved = null,
            .mechanical = mechanical,
            .status = Store.op_state.Status.indeterminate.text(),
            .detail = std.fmt.allocPrint(
                arena,
                "this transfer declared in advance that its artifact would hash to {s}, so its destination can be checked rather than merely looked at; hash {s} on the {s} side and offer that digest instead of a bare presence reading",
                .{ m.expected_sha256, m.observed.path, sideName(m.observed.side) },
            ) catch "this transfer declared a digest, so hash the artifact at its destination and offer that instead of a bare presence reading",
            .exit = .failure,
        },
        // Two situations, two different next readings, and the payload is what
        // tells them apart. Collapsing them into one sentence would be the
        // worse failure here than usual: one of them ends in `completed` and
        // the other in `failed`, so an operator who cannot tell which they are
        // in cannot tell whether their artifact was delivered.
        .contradiction_not_established => |m| .{
            .ok = false,
            .resolved = null,
            .mechanical = mechanical,
            .status = Store.op_state.Status.indeterminate.text(),
            .detail = if (m.declared) |want| std.fmt.allocPrint(
                arena,
                "this transfer committed to publishing an artifact hashing to {s}, and {s} on the {s} side hashes to exactly that — nothing was contradicted, the artifact was delivered; offer that digest as a published-file hash instead",
                .{ want, m.observed.path, sideName(m.observed.side) },
            ) catch "the digest that was read is the one this transfer committed to; that is a delivery, not a mismatch" else std.fmt.allocPrint(
                arena,
                "this transfer never declared what its artifact would hash to, so reading {s} as {s} contradicts nothing; what the look established is that something is there, which is a presence reading with no digest",
                .{ m.observed.path, m.observed_sha256 },
            ) catch "this transfer declared no digest, so a hash read at its destination contradicts nothing",
            .exit = .failure,
        },
        .reading_has_no_method => |m| .{
            .ok = false,
            .resolved = null,
            .mechanical = mechanical,
            .status = Store.op_state.Status.indeterminate.text(),
            .detail = std.fmt.allocPrint(
                arena,
                "{s} evidence has to say how the destination was read (for example \"stat => ENOENT\"); it arrived with that empty, and an unattributed reading is a conclusion rather than an observation",
                .{m.evidence_kind},
            ) catch "a destination reading has to say how it was taken; it arrived with that empty",
            .exit = .failure,
        },
        // The digest was right and the conclusion drawn from it was not. Said
        // in exactly those terms, because the operator is holding a hash that
        // matches and being told "no" — without the state they would go and
        // re-hash a file that is precisely what they said it was.
        .effect_reading_against_recorded_outcome => |m| .{
            .ok = false,
            .resolved = null,
            .mechanical = mechanical,
            .status = Store.op_state.Status.indeterminate.text(),
            .detail = std.fmt.allocPrint(
                arena,
                "the digest is the one this transfer declared, but its checkpoint records '{s}' for {s} on the {s} side — this transfer never put an artifact there, so what is at that path is somebody else's and hashing it proves nothing about this operation. Settle the operation on its own evidence, and release the path with a restart if those bytes are to be replaced",
                .{ m.state, m.observed.path, sideName(m.observed.side) },
            ) catch "the digest matches, but this transfer's checkpoint records that it never published; what is at that path was not put there by this operation",
            .exit = .failure,
        },
        .unknown_operation => .{
            .ok = false,
            .resolved = null,
            .mechanical = mechanical,
            .status = "unknown",
            .detail = "request disappeared while reconciling",
            .exit = .failure,
        },
    };
}

test "gate: a probe of the wrong process says which process it read" {
    const t = std.testing;
    var arena_state: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Three situations, three different next actions. An operator told only
    // "the probe did not match" cannot tell "you read the wrong pid" from
    // "this attempt never had a process", and the second is the one where
    // probing again will never work.
    const wrong_pid = interpret(.{ .evidence_wrong_process = .{
        .probed_pid = 6001,
        .probed_start_token = "boot+6001",
        .recorded = .{ .pid = 5150, .start_token = "boot+5150" },
    } }, .cancelled, true, "unused", arena);
    try t.expect(!wrong_pid.ok);
    try t.expectEqual(@as(?[]const u8, null), wrong_pid.resolved);
    try t.expect(std.mem.indexOf(u8, wrong_pid.detail, "6001") != null);
    try t.expect(std.mem.indexOf(u8, wrong_pid.detail, "5150") != null);

    // The recycled pid. The pid is ours and is deliberately not reported as
    // the problem; the start token is.
    const recycled = interpret(.{ .evidence_wrong_process = .{
        .probed_pid = 5150,
        .probed_start_token = "boot+9999",
        .recorded = .{ .pid = 5150, .start_token = "boot+5150" },
    } }, .cancelled, true, "unused", arena);
    try t.expect(std.mem.indexOf(u8, recycled.detail, "boot+5150") != null);
    try t.expect(std.mem.indexOf(u8, recycled.detail, "boot+9999") != null);

    // A probe that read no token has to say so rather than print an empty one
    // as though the process reported nothing.
    const no_token = interpret(.{ .evidence_wrong_process = .{
        .probed_pid = 5150,
        .probed_start_token = null,
        .recorded = .{ .pid = 5150, .start_token = "boot+5150" },
    } }, .cancelled, true, "unused", arena);
    try t.expect(std.mem.indexOf(u8, no_token.detail, "could not read one") != null);

    // Nothing to probe, ever. This one must not read as "try again".
    const never = interpret(.{ .evidence_wrong_process = .{
        .probed_pid = 5150,
        .probed_start_token = "boot+5150",
        .recorded = null,
    } }, .cancelled, true, "unused", arena);
    try t.expect(std.mem.indexOf(u8, never.detail, "never recorded a process") != null);
    try t.expect(std.mem.indexOf(u8, never.detail, "--override") != null);

    // All three are distinct sentences, which is the property that would be
    // lost by collapsing them into one message.
    try t.expect(!std.mem.eql(u8, wrong_pid.detail, recycled.detail));
    try t.expect(!std.mem.eql(u8, recycled.detail, never.detail));
    try t.expect(!std.mem.eql(u8, recycled.detail, no_token.detail));
}

test "gate: a reading that contradicts nothing says which nothing it contradicts" {
    const t = std.testing;
    var arena_state: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const observed: Store.transfers.Destination = .{ .side = .remote, .path = "/srv/app/out.bin" };

    // Nothing was declared: the look established presence and nothing more, so
    // the next reading is a bare presence one and the verdict it reaches is
    // `completed_unverified`.
    const undeclared = interpret(.{ .contradiction_not_established = .{
        .observed = observed,
        .observed_sha256 = "0000ffff",
        .declared = null,
    } }, .failed, true, "unused", arena);
    try t.expect(!undeclared.ok);
    try t.expectEqual(@as(?[]const u8, null), undeclared.resolved);
    try t.expect(std.mem.indexOf(u8, undeclared.detail, "never declared") != null);
    try t.expect(std.mem.indexOf(u8, undeclared.detail, "0000ffff") != null);

    // The digest agrees: the artifact was delivered. This one must not read as
    // a failure of any kind — the two situations end in opposite verdicts, and
    // an operator who cannot tell them apart cannot tell whether their artifact
    // arrived.
    const agrees = interpret(.{ .contradiction_not_established = .{
        .observed = observed,
        .observed_sha256 = "deadbeef",
        .declared = "deadbeef",
    } }, .failed, true, "unused", arena);
    try t.expect(std.mem.indexOf(u8, agrees.detail, "deadbeef") != null);
    try t.expect(std.mem.indexOf(u8, agrees.detail, "delivered") != null);
    try t.expect(!std.mem.eql(u8, undeclared.detail, agrees.detail));
}

test "M2d gate: a refusal says which pair it rejected" {
    const t = std.testing;
    var arena_state: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Evidence that belongs to another request must be refused, and the
    // refusal must name both ids. Reporting it as a kind mismatch — the
    // nearest existing variant — would be a truthful-sounding lie: the
    // evidence's category is fine, its subject is not.
    const wrong_op = interpret(.{ .evidence_wrong_operation = .{
        .evidence_request_id = "01JQXW8ZK4N0RS7T3VYB2MCDEF",
        .request_id = "01JQXW8ZK4N0RS7T3VYB2MCDAA",
    } }, .completed, true, "unused", arena);
    try t.expect(!wrong_op.ok);
    try t.expectEqual(@as(?[]const u8, null), wrong_op.resolved);
    try t.expect(std.mem.indexOf(u8, wrong_op.detail, "01JQXW8ZK4N0RS7T3VYB2MCDEF") != null);
    try t.expect(std.mem.indexOf(u8, wrong_op.detail, "01JQXW8ZK4N0RS7T3VYB2MCDAA") != null);

    // A kind mismatch has to name the operation's kind, not repeat the
    // evidence's. The payload used to carry the evidence kind in both fields,
    // and this command used to print neither.
    const wrong_kind = interpret(.{ .evidence_wrong_kind = .{
        .operation_kind = "transfer_push",
        .evidence_kind = "job_result",
    } }, .completed, true, "unused", arena);
    try t.expect(!wrong_kind.ok);
    try t.expect(std.mem.indexOf(u8, wrong_kind.detail, "transfer_push") != null);
    try t.expect(std.mem.indexOf(u8, wrong_kind.detail, "job_result") != null);
}
