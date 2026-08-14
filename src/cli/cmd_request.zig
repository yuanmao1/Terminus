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
            .detail = outcome.detail,
        }),
        .human => try ctx.out.print("{s}: {s} ({s})\n", .{
            request_id,
            outcome.resolved orelse outcome.status,
            outcome.detail,
        }),
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
    detail: []const u8,
    exit: enum { ok, failure, indeterminate },
};

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
            .evidence = .{ .job_result = .{
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
            } },
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
    }, ctx.now) catch |err| Cli.receiptFatal(op.request_id, err, "reconcile");

    return interpret(result, resolved, false, "recorded as a human decision, not as proof", ctx.arena);
}

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
        .effect_hash_unproven => |fx| .{
            .ok = false,
            .resolved = null,
            .mechanical = mechanical,
            .status = Store.op_state.Status.indeterminate.text(),
            .detail = if (fx.expected_sha256) |want| std.fmt.allocPrint(
                arena,
                "the file at {s} hashes to {s}, but this transfer committed to {s}; the bytes that landed are not the bytes it was sending",
                .{ fx.path, fx.observed_sha256, want },
            ) catch "the published file does not hash to what this transfer committed to" else std.fmt.allocPrint(
                arena,
                "this transfer never recorded which digest would prove it landed, so the hash of {s} proves nothing about it; settle it with --override if you have checked by hand",
                .{fx.path},
            ) catch "this transfer never recorded which digest would prove it landed",
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
