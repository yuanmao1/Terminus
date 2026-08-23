//! Settlement: who may write a terminal, out of what evidence, and how a
//! reading is bound to the attempt it is allowed to speak about.
//!
//! Two questions, and they are not the same one.
//!
//! **What may be written.** Only `settle` writes a terminal. It is written
//! once, under contention as well as in a quiet process. It is refused when the
//! state machine cannot justify it, when the evidence contradicts itself, and
//! when the terminal does not describe this kind of work. A transport failure
//! after submission records `indeterminate` and can never be recorded as
//! `failed`. Resolution is write-once and cannot lift the barrier on an
//! operation that is still running. An operator's word is recorded as an
//! override, never as mechanical proof, and secrets in resolution evidence do
//! not reach the receipt.
//!
//! **What it may be written from.** A result document, a launch sentinel, a
//! process probe and a supervisor report are all *readings*, and a reading
//! settles the attempt that recorded it and no other. So: a result document
//! naming another request settles nothing here; a job sentinel settles only its
//! own job; an attempt that never read a start token is judged on its pid and
//! filed as such; an identity the attempt proved cannot be forgotten by a later
//! event; a job is not settled by a reading of its pane's process; and
//! connecting is not an established connection.

const std = @import("std");
const Store = @import("Store.zig");
const migrate = @import("migrate.zig");
const ids = @import("ids.zig");
const op_state = @import("op_state.zig");
const execution = @import("../execution.zig");

// The shared fixtures. Aliased under their own names so a gate reads the
// same here as it did when every gate was in one file.
const fixtures = @import("gates_fixtures.zig");
const Scratch = fixtures.Scratch;
const testId = fixtures.testId;
const seedOperation = fixtures.seedOperation;
const seedOperationOfKind = fixtures.seedOperationOfKind;
const recordProcess = fixtures.recordProcess;
const recordLaunchSentinel = fixtures.recordLaunchSentinel;
const seedServer = fixtures.seedServer;
const seedTransferBeforeSubmit = fixtures.seedTransferBeforeSubmit;
const driveToPublished = fixtures.driveToPublished;
const countKind = fixtures.countKind;

const SettleCtx = struct {
    path: [:0]const u8,
    request_id: []const u8,
    /// Racing writers deliberately disagree in the conflict test.
    exit_code: i32,
    gate: *std.atomic.Value(bool),
    outcome: ?Store.receipts.SettleOutcome = null,
    err: ?anyerror = null,
};

fn settleInThread(ctx: *SettleCtx) void {
    while (!ctx.gate.load(.acquire)) std.atomic.spinLoopHint();
    var store = Store.open(ctx.path) catch |err| {
        ctx.err = err;
        return;
    };
    defer store.close();
    ctx.outcome = Store.receipts.settle(
        &store,
        ctx.request_id,
        .{ .exited = .{ .exit_code = ctx.exit_code } },
        .{},
        200,
    ) catch |err| {
        ctx.err = err;
        return;
    };
}

test "gate: a terminal receipt is recorded exactly once under contention" {
    const t = std.testing;

    // Two writers that *disagree* — one says success, one says failure. The
    // ledger must keep whichever landed first and hand the loser that same
    // verdict, never let the later write redefine the outcome.
    for ([_][2]i32{ .{ 0, 0 }, .{ 0, 1 } }, 0..) |codes, round| {
        var name_buf: [40]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "gate_terminal_once_{d}", .{round});
        var scratch = try Scratch.init(t.allocator, name);
        defer scratch.deinit();

        const request_id = "01ABCDEFGH0123456789ABCDEF";
        {
            var store = try Store.open(scratch.path);
            defer store.close();
            try seedOperation(&store, request_id);
        }

        var gate: std.atomic.Value(bool) = .init(false);
        var a: SettleCtx = .{ .path = scratch.path, .request_id = request_id, .exit_code = codes[0], .gate = &gate };
        var b: SettleCtx = .{ .path = scratch.path, .request_id = request_id, .exit_code = codes[1], .gate = &gate };
        const ta = try std.Thread.spawn(.{}, settleInThread, .{&a});
        const tb = try std.Thread.spawn(.{}, settleInThread, .{&b});
        gate.store(true, .release);
        ta.join();
        tb.join();

        try t.expectEqual(@as(?anyerror, null), a.err);
        try t.expectEqual(@as(?anyerror, null), b.err);

        var recorded: usize = 0;
        var already: usize = 0;
        var winner_status: ?Store.op_state.Status = null;
        var loser_saw: ?Store.op_state.Status = null;
        for ([_]?Store.receipts.SettleOutcome{ a.outcome, b.outcome }) |maybe| {
            switch (maybe.?) {
                .recorded => |rec| {
                    recorded += 1;
                    winner_status = rec.status;
                },
                .already_settled => |rec| {
                    already += 1;
                    loser_saw = rec.status;
                },
            }
        }
        try t.expectEqual(@as(usize, 1), recorded);
        try t.expectEqual(@as(usize, 1), already);
        // The loser is told the winner's verdict, not its own.
        try t.expectEqual(winner_status.?, loser_saw.?);

        var store = try Store.open(scratch.path);
        defer store.close();
        var stmt = try store.db.prepare(
            "SELECT COUNT(*) FROM operation_events WHERE request_id = ?1 AND is_terminal = 1",
        );
        defer stmt.deinit();
        try stmt.bindText(1, request_id);
        try t.expect(try stmt.step());
        try t.expectEqual(@as(i64, 1), stmt.columnInt(0));

        // And the operation status agrees with the single terminal receipt.
        var arena_state = std.heap.ArenaAllocator.init(t.allocator);
        defer arena_state.deinit();
        const op = (try Store.operations.get(&store, arena_state.allocator(), request_id)).?;
        try t.expectEqual(winner_status.?, op.status);
    }
}

test "gate: only settle can write a terminal" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_terminal_guard");
    defer scratch.deinit();

    var store = try Store.open(scratch.path);
    defer store.close();
    const rid = testId("guard");
    const request_id: []const u8 = &rid;
    try seedOperation(&store, request_id);

    // `append` takes an ObservationKind, which has no `terminal` and no
    // `reconcile` member, so forging either is a compile error rather than a
    // runtime check. What it can still be handed is a reconcile *source*,
    // which would make a forged resolution indistinguishable from a real one
    // in the trail — that is refused at runtime.
    try t.expectError(error.ReconcileRequiresResolve, Store.receipts.append(&store, .{
        .request_id = request_id,
        .kind = .audit,
        .source = .reconcile,
        .observed_at = 200,
    }));

    // A plain observation cannot claim a verdict either: `status` is a
    // LiveStatus, so `.completed` is not expressible here.
    _ = try Store.receipts.append(&store, .{
        .request_id = request_id,
        .kind = .connect,
        .status = .connecting,
        .observed_at = 201,
    });

    // `advance` cannot even name a terminal: LiveStatus has no such member,
    // so the bypass is a compile error rather than a runtime check.
    try Store.operations.advance(&store, request_id, .remote_started, 201);

    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const op = (try Store.operations.get(&store, arena_state.allocator(), request_id)).?;
    try t.expectEqual(Store.op_state.Status.remote_started, op.status);
}

test "gate: settle rejects a terminal the state machine cannot justify" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_settle_transition");
    defer scratch.deinit();

    var store = try Store.open(scratch.path);
    defer store.close();
    try seedServer(&store);
    const rid = testId("fresh");
    const request_id: []const u8 = &rid;
    try Store.operations.create(&store, .{
        .request_id = request_id,
        .server_id = 1,
        .server_name = "lease-host",
        .kind = .exec,
        .now = 100,
    });

    // Nothing was ever sent, so a clean completion is not a story the ledger
    // can tell. Without the in-transaction transition check this succeeded.
    try t.expectError(error.IllegalTransition, Store.receipts.settle(
        &store,
        request_id,
        .{ .exited = .{ .exit_code = 0 } },
        .{},
        200,
    ));

    // The operation is untouched and no receipt was written.
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const op = (try Store.operations.get(&store, arena_state.allocator(), request_id)).?;
    try t.expectEqual(Store.op_state.Status.created, op.status);
    try t.expect((try Store.receipts.terminalOf(&store, request_id)) == null);

    // Proving we never submitted *is* justifiable from `created`.
    const outcome = try Store.receipts.settle(
        &store,
        request_id,
        .{ .never_submitted = .{ .transport_error = "connection refused" } },
        .{},
        210,
    );
    try t.expectEqual(Store.op_state.Status.failed, outcome.recorded.status);
}

test "gate: settle refuses evidence that contradicts itself" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_evidence");
    defer scratch.deinit();

    var store = try Store.open(scratch.path);
    defer store.close();
    try seedServer(&store);
    const rid = testId("evidence");
    const request_id: []const u8 = &rid;
    try Store.operations.create(&store, .{
        .request_id = request_id,
        .server_id = 1,
        .server_name = "lease-host",
        .kind = .exec,
        .now = 100,
    });
    try Store.operations.advance(&store, request_id, .connecting, 101);

    // From `connecting`, "the command was never handed over" is a legitimate
    // claim — but not alongside a remote process id.
    try t.expectError(error.ContradictoryEvidence, Store.receipts.settle(
        &store,
        request_id,
        .{ .never_submitted = .{ .transport_error = "refused" } },
        .{ .remote_pid = 4242 },
        200,
    ));

    // And once the work has been handed over, that claim is not available at
    // all: the evidence no longer fits the state we are in.
    try Store.operations.advance(&store, request_id, .submitted, 210);
    try t.expectError(error.EvidenceDoesNotFit, Store.receipts.settle(
        &store,
        request_id,
        .{ .never_submitted = .{ .transport_error = "refused" } },
        .{},
        220,
    ));

    // Symmetrically, an exit status cannot come from an attempt that never
    // reached a connection.
    const rid2 = testId("neverran");
    const other: []const u8 = &rid2;
    try Store.operations.create(&store, .{
        .request_id = other,
        .server_id = 1,
        .server_name = "lease-host",
        .kind = .exec,
        .now = 300,
    });
    try t.expectError(error.EvidenceDoesNotFit, Store.receipts.settle(
        &store,
        other,
        .{ .exited = .{ .exit_code = 1 } },
        .{},
        310,
    ));
}

test "gate: indeterminate evidence is persisted, not just mapped" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_evidence_persist");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    const rid = testId("persist");
    const request_id: []const u8 = &rid;
    try seedOperation(&store, request_id);

    _ = try Store.receipts.settle(
        &store,
        request_id,
        Store.op_state.terminalForTransportLoss(.submitted, "channel eof"),
        .{},
        300,
    );

    // `last_observed` tells a reconciler where to look; keeping it only in
    // memory would make the receipt unusable for that purpose.
    var stmt = try store.db.prepare(
        "SELECT last_observed, transport_error, error_code FROM operation_events WHERE request_id = ?1 AND is_terminal = 1",
    );
    defer stmt.deinit();
    try stmt.bindText(1, request_id);
    try t.expect(try stmt.step());
    try t.expectEqualStrings("submitted", stmt.columnText(0));
    try t.expectEqualStrings("channel eof", stmt.columnText(1));
    try t.expectEqualStrings("INDETERMINATE", stmt.columnText(2));

    // A confirmed cancellation records how it was carried out.
    const other_id = testId("cancel");
    const other: []const u8 = &other_id;
    try Store.operations.create(&store, .{
        .request_id = other,
        .server_id = 1,
        .server_name = "race",
        .kind = .exec,
        .now = 400,
    });
    try Store.operations.advance(&store, other, .connecting, 401);
    try Store.operations.advance(&store, other, .submitted, 402);
    _ = try Store.receipts.settle(
        &store,
        other,
        .{ .remote_cancel_confirmed = .{
            .pid = 8123,
            .start_token = "boot+41213",
            .term_sent = true,
            .kill_sent = true,
            .absence_verified_at = 409,
            .verification_method = "kill -0 -8123 => ESRCH",
        } },
        .{},
        410,
    );
    const rows = try Store.receipts.list(&store, arena, other);
    try t.expectEqualStrings("cancelled", rows[rows.len - 1].status.?);
}

test "gate: transport loss after submission records indeterminate, never failed" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_indeterminate");
    defer scratch.deinit();

    var store = try Store.open(scratch.path);
    defer store.close();
    const request_id = "01ZZZZZZZZ0123456789ABCDEF";
    // A job: the reconciliation below is a job's exit sentinel, and evidence
    // is only admissible for the kind of operation that produces it.
    try seedOperationOfKind(&store, request_id, .job);
    // ...and only for the operation that *recorded* it. See
    // `recordLaunchSentinel`.
    try recordLaunchSentinel(&store, request_id, "race", "migrate", "__TERMINUS_JOB_1__", 100);

    // The only decision point for a dropped connection.
    const terminal = op_state.terminalForTransportLoss(.submitted, "channel eof");
    const outcome = try Store.receipts.settle(&store, request_id, terminal, .{}, 300);
    try t.expectEqual(op_state.Status.indeterminate, outcome.recorded.status);

    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const op = (try Store.operations.get(&store, arena, request_id)).?;
    try t.expectEqual(op_state.Status.indeterminate, op.status);
    // Unsettled work must block a same-scope mutation until reconciled.
    try t.expect(op.status.blocksScope());
    try t.expectEqual(@as(usize, 1), (try Store.operations.unsettled(&store, arena, 1)).len);

    // Reconciliation proves the truth without erasing the observation.
    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .completed, .{ .job_sentinel = .{ .sentinel = "__TERMINUS_JOB_1__", .exit_code = 0 } }, 400)) == .resolved);
    const after = (try Store.operations.get(&store, arena, request_id)).?;
    try t.expectEqual(op_state.Status.indeterminate, after.status); // preserved
    try t.expectEqual(op_state.Status.completed, after.effectiveStatus());
    // Once resolved it no longer blocks the scope.
    try t.expectEqual(@as(usize, 0), (try Store.operations.unsettled(&store, arena, 1)).len);

    // And the resolution left an append-only reconcile event behind it.
    const rows = try Store.receipts.list(&store, arena, request_id);
    try t.expectEqualStrings("reconcile", rows[rows.len - 1].kind);
    try t.expectEqualStrings("reconcile", rows[rows.len - 1].source);
}

test "gate: resolution cannot lift the barrier on a running operation" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_resolve_guard");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    const rid = testId("running");
    const request_id: []const u8 = &rid;
    try seedOperation(&store, request_id); // leaves it `submitted`

    // A `submitted` attempt is not unknown, it is in progress. Resolving it
    // would drop it out of `unsettled()` and let a peer start a conflicting
    // mutation while the remote command is still alive.
    const refused = try Store.receipts.resolve(&store, arena, request_id, .completed, .{ .operator_override = .{ .reason = "wishful thinking", .by = "tester" } }, 300);
    try t.expectEqual(op_state.Status.submitted, refused.not_indeterminate);

    // The barrier is still up and nothing was recorded.
    try t.expectEqual(@as(usize, 1), (try Store.operations.unsettled(&store, arena, 1)).len);
    const op = (try Store.operations.get(&store, arena, request_id)).?;
    try t.expectEqual(@as(?op_state.ResolvedStatus, null), op.resolved_status);
    try t.expectEqual(@as(usize, 0), (try Store.receipts.list(&store, arena, request_id)).len);

    // Same for a settled operation: a completed run has nothing to resolve.
    const other_id = testId("done");
    const other: []const u8 = &other_id;
    try Store.operations.create(&store, .{
        .request_id = other,
        .server_id = 1,
        .server_name = "race",
        .kind = .exec,
        .now = 400,
    });
    try Store.operations.advance(&store, other, .connecting, 401);
    try Store.operations.advance(&store, other, .submitted, 402);
    _ = try Store.receipts.settle(&store, other, .{ .exited = .{ .exit_code = 0 } }, .{}, 410);
    const refused_done = try Store.receipts.resolve(&store, arena, other, .failed, .{ .operator_override = .{ .reason = "rewrite history", .by = "tester" } }, 420);
    try t.expectEqual(op_state.Status.completed, refused_done.not_indeterminate);
}

test "gate: resolution is write-once" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_resolve_once");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    const rid = testId("once");
    const request_id: []const u8 = &rid;
    try seedOperationOfKind(&store, request_id, .job);
    try recordLaunchSentinel(&store, request_id, "race", "once", "__S__", 100);
    _ = try Store.receipts.settle(
        &store,
        request_id,
        op_state.terminalForTransportLoss(.submitted, "eof"),
        .{},
        300,
    );

    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .completed, .{ .job_sentinel = .{ .sentinel = "__S__", .exit_code = 0 } }, 400)) == .resolved);
    // A second reconciler must not overwrite the first one's evidence. The
    // rival evidence has to be evidence this kind *admits*, or the refusal
    // comes back from `appliesToKind` a step earlier and this gate passes
    // without ever reaching the write-once rule it is about.
    const second = try Store.receipts.resolve(&store, arena, request_id, .failed, .{ .job_sentinel = .{ .sentinel = "__S__", .exit_code = 7 } }, 500);
    try t.expectEqual(op_state.ResolvedStatus.completed, second.already_resolved);

    const op = (try Store.operations.get(&store, arena, request_id)).?;
    try t.expectEqual(op_state.ResolvedStatus.completed, op.resolved_status.?);
    try t.expect(std.mem.indexOf(u8, op.resolution_evidence.?, "job_sentinel") != null);

    // An unknown request is answered before the evidence is examined at all,
    // which is why this may use a variant no kind admits: there is no kind to
    // check it against. The order matters — reporting "that evidence cannot
    // speak about a job" for a request that does not exist would send an
    // operator to look at the wrong thing.
    try t.expect((try Store.receipts.resolve(&store, arena, &testId("missing"), .completed, .{ .supervisor_report = .{ .reported = .completed, .detail = "x" } }, 600)) == .unknown_operation);
}

test "gate: illegal transitions are rejected" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_transitions");
    defer scratch.deinit();

    var store = try Store.open(scratch.path);
    defer store.close();
    const request_id = "01YYYYYYYY0123456789ABCDEF";
    try seedOperation(&store, request_id);

    // submitted -> connecting is backwards.
    try t.expectError(error.IllegalTransition, Store.operations.advance(&store, request_id, .connecting, 200));

    // Settling then advancing again must fail: terminals are frozen.
    _ = try Store.receipts.settle(&store, request_id, .{ .exited = .{ .exit_code = 3 } }, .{}, 210);
    try t.expectError(error.IllegalTransition, Store.operations.advance(&store, request_id, .remote_started, 220));
}

test "gate: an operator override cannot pass for mechanical proof" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_override");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    const rid = testId("override");
    const request_id: []const u8 = &rid;
    try seedOperation(&store, request_id);
    _ = try Store.receipts.settle(
        &store,
        request_id,
        op_state.terminalForTransportLoss(.submitted, "eof"),
        .{},
        300,
    );

    _ = try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .operator_override = .{ .reason = "checked by hand", .by = "czykl" },
    }, 400);

    // A resolution lifts the mutation barrier, so the trail has to say
    // whether it rested on proof or on a decision.
    const rows = try Store.receipts.list(&store, arena, request_id);
    const last = rows[rows.len - 1];
    try t.expectEqualStrings("reconcile", last.kind);
    try t.expectEqualStrings("OPERATOR_OVERRIDE", last.error_code.?);
    try t.expect(std.mem.indexOf(u8, last.detail_json.?, "\"mechanical\":false") != null);
    try t.expect(std.mem.indexOf(u8, last.detail_json.?, "\"schemaVersion\"") != null);

    // Mechanical evidence is marked as such.
    const probe: Store.receipts.ResolutionEvidence = .{
        .process_probe = .{ .pid = 991, .alive = false },
    };
    try t.expect(probe.isMechanical());
    const json = try probe.toJson(arena, .pid_only, null);
    try t.expect(std.mem.indexOf(u8, json, "\"mechanical\":true") != null);
}

test "gate: evidence must entail the result it is used to justify" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_evidence_supports");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    const rid = testId("supports");
    const request_id: []const u8 = &rid;
    // A job, because the evidence under test is a job's exit sentinel: the
    // question here is whether the evidence entails the *result*, and it can
    // only get asked of an operation the evidence is allowed to speak about.
    try seedOperationOfKind(&store, request_id, .job);
    // The sentinel below has to be one this attempt actually launched with, or
    // it is refused as another job's log line and this gate never reaches the
    // entailment question it is about. See `recordLaunchSentinel`.
    try recordLaunchSentinel(&store, request_id, "race", "supports", "__S__", 100);
    _ = try Store.receipts.settle(
        &store,
        request_id,
        op_state.terminalForTransportLoss(.submitted, "eof"),
        .{},
        300,
    );

    // A zero exit code cannot justify `failed`.
    const mismatch = try Store.receipts.resolve(&store, arena, request_id, .failed, .{
        .job_sentinel = .{ .sentinel = "__S__", .exit_code = 0 },
    }, 400);
    try t.expectEqualStrings("job_sentinel", mismatch.evidence_does_not_support.evidence_kind);

    // The probes below have to be readings of *this* attempt's process, or
    // they are refused one step earlier as readings of somebody else's and
    // this gate passes without ever reaching the question it is about.
    try recordProcess(&store, request_id, 77, "boot+77", 310);

    // The dangerous one: a process still *running* proves nothing, and must
    // not be able to release the mutation barrier by claiming completion.
    const alive = try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .process_probe = .{ .pid = 77, .start_token = "boot+77", .alive = true },
    }, 401);
    try t.expect(alive == .evidence_does_not_support);

    // A dead process establishes absence, i.e. cancellation — not success.
    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .process_probe = .{ .pid = 77, .start_token = "boot+77", .alive = false },
    }, 402)) == .evidence_does_not_support);

    // A published file hash says nothing about an arbitrary command.
    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .filesystem_effect = .{ .side = .remote, .path = "/srv/app/out.bin", .sha256 = "abc" },
    }, 403)) == .evidence_wrong_kind);

    // Nothing was recorded by any of the refusals.
    const op_before = (try Store.operations.get(&store, arena, request_id)).?;
    try t.expectEqual(@as(?op_state.ResolvedStatus, null), op_before.resolved_status);

    // A non-zero exit code does justify `failed`.
    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .failed, .{
        .job_sentinel = .{ .sentinel = "__S__", .exit_code = 3 },
    }, 410)) == .resolved);
    const op = (try Store.operations.get(&store, arena, request_id)).?;
    try t.expectEqual(op_state.ResolvedStatus.failed, op.resolved_status.?);
}

test "M2e gate: a result record is read like a sentinel, and named unlike one" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_job_result_evidence");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    const rid = testId("jobresult");
    const request_id: []const u8 = &rid;
    try seedOperationOfKind(&store, request_id, .job);
    _ = try Store.receipts.settle(
        &store,
        request_id,
        .{ .indeterminate = .{ .reason = "caller walked away", .last_observed = .submitted } },
        .{},
        200,
    );

    // An exit status is an exit status wherever it was recorded: it says how
    // the command ended and cannot speak to a deadline or a cancellation.
    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .job_result = .{ .request_id = request_id, .exit_code = 4, .finished_at = 900 },
    }, 300)) == .evidence_does_not_support);
    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .timed_out, .{
        .job_result = .{ .request_id = request_id, .exit_code = 0, .finished_at = 900 },
    }, 301)) == .evidence_does_not_support);

    // Nothing was recorded by the refusals.
    try t.expectEqual(
        @as(?op_state.ResolvedStatus, null),
        (try Store.operations.get(&store, arena, request_id)).?.resolved_status,
    );

    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .failed, .{
        .job_result = .{ .request_id = request_id, .exit_code = 4, .finished_at = 900 },
    }, 310)) == .resolved);

    const op = (try Store.operations.get(&store, arena, request_id)).?;
    try t.expectEqual(op_state.ResolvedStatus.failed, op.resolved_status.?);
    // The trail has to distinguish "a document at this operation's own
    // address said so" from "a line turned up in a shared log". Recording
    // both as `job_sentinel` would erase the difference in strength.
    try t.expect(std.mem.indexOf(u8, op.resolution_evidence.?, "job_result") != null);
    try t.expect(std.mem.indexOf(u8, op.resolution_evidence.?, "job_sentinel") == null);
    try t.expect(std.mem.indexOf(u8, op.resolution_evidence.?, request_id) != null);
    // Mechanical, unlike an operator override — it must not need a human's
    // name attached to release the scope.
    try t.expect(std.mem.indexOf(u8, op.resolution_evidence.?, "\"mechanical\":true") != null);
}

test "gate: a result document naming another request settles nothing here" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_job_result_identity");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    const rid = testId("mine");
    const request_id: []const u8 = &rid;
    const other = testId("theirs");
    try seedOperationOfKind(&store, request_id, .job);
    _ = try Store.receipts.settle(
        &store,
        request_id,
        .{ .indeterminate = .{ .reason = "caller walked away", .last_observed = .submitted } },
        .{},
        200,
    );

    // The exit code is perfectly good evidence — for the operation the
    // document names. Accepting it here would lift *this* operation's
    // mutation barrier on the strength of another one's outcome, possibly
    // from another host, with the contradiction persisted in the receipt
    // where only a human reading the JSON would ever notice it.
    //
    // This is the Store's own check, exercised the only way it can be
    // falsified: by handing it a pair whose two sides genuinely differ. The
    // reader that produces such evidence in production has a second, separate
    // check (`Tmux.parseJobResult` refuses a document naming another
    // request), and neither stands in for the other — the parser cannot see
    // where a caller later points a valid reading.
    const refused = try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .job_result = .{ .request_id = &other, .exit_code = 0, .finished_at = 900 },
    }, 300);
    try t.expectEqualStrings(&other, refused.evidence_wrong_operation.evidence_request_id);
    try t.expectEqualStrings(request_id, refused.evidence_wrong_operation.request_id);
    try t.expect(!std.mem.eql(
        u8,
        refused.evidence_wrong_operation.evidence_request_id,
        refused.evidence_wrong_operation.request_id,
    ));

    // Identity is checked before anything else, so a mismatch is reported as
    // a mismatch even when the evidence would have failed a later test too. A
    // caller told "that exit code cannot prove completion" would go looking
    // for the wrong bug.
    const also_unsupported = try Store.receipts.resolve(&store, arena, request_id, .timed_out, .{
        .job_result = .{ .request_id = &other, .exit_code = 0, .finished_at = 900 },
    }, 301);
    try t.expect(also_unsupported == .evidence_wrong_operation);

    // Nothing was recorded: no resolution, and no reconcile event to imply
    // one was attempted successfully.
    const unresolved = (try Store.operations.get(&store, arena, request_id)).?;
    try t.expectEqual(@as(?op_state.ResolvedStatus, null), unresolved.resolved_status);
    for (try Store.receipts.list(&store, arena, request_id)) |row| {
        try t.expect(!std.mem.eql(u8, row.kind, "reconcile"));
    }

    // The same document, naming this operation, does settle it.
    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .job_result = .{ .request_id = request_id, .exit_code = 0, .finished_at = 900 },
    }, 310)) == .resolved);
    try t.expectEqual(
        op_state.ResolvedStatus.completed,
        (try Store.operations.get(&store, arena, request_id)).?.resolved_status.?,
    );
}

// The third identity binding, and the one that was missing.
//
// A sentinel names nothing. It is a string scanned out of a window of an
// append-only log that anything on the host can write to, so unlike a result
// document (which carries a request id) and unlike a probe (which carries a
// pid), it has no address of its own at all. What makes one *this* operation's
// is that this binary chose it and wrote it into `job_attempts` before the
// launch line could reach the shell. Until that was compared, `job_sentinel`
// was the only mechanical variant in the union with nothing tying it to the
// operation it settled — and `isMechanical` grades it `true`, which is the
// grade that releases the same-scope mutation barrier with no operator in the
// loop.
//
// All four readings are exercised, because the union has to keep them apart:
// a matching sentinel still settles, a foreign one is refused, an attempt that
// recorded no sentinel is refused, and a request with no attempt row at all is
// refused — and the last three are three different things to go and do.
test "gate: a job sentinel settles only the job that recorded it" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_sentinel_identity");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    const rid = testId("mysent");
    const request_id: []const u8 = &rid;
    try seedOperationOfKind(&store, request_id, .job);
    try recordLaunchSentinel(&store, request_id, "race", "deploy", "__TERMINUS_JOB_9__", 100);
    _ = try Store.receipts.settle(
        &store,
        request_id,
        .{ .indeterminate = .{ .reason = "caller walked away", .last_observed = .submitted } },
        .{},
        200,
    );

    // Somebody else's sentinel, carrying a perfectly good exit code. Admitting
    // it would settle this operation from another job's log line — the exact
    // shape the result-document check refuses one variant over, arriving
    // through the variant that had no check.
    const foreign = try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .job_sentinel = .{ .sentinel = "__TERMINUS_JOB_4__", .exit_code = 0 },
    }, 300);
    try t.expectEqualStrings("__TERMINUS_JOB_4__", foreign.evidence_wrong_sentinel.offered);
    try t.expectEqualStrings("__TERMINUS_JOB_9__", foreign.evidence_wrong_sentinel.recorded.sentinel);

    // Nothing was written by the refusal: no resolution, and no reconcile event
    // claiming one was considered.
    try t.expectEqual(
        @as(?op_state.ResolvedStatus, null),
        (try Store.operations.get(&store, arena, request_id)).?.resolved_status,
    );
    try t.expectEqual(@as(usize, 0), try countKind(&store, arena, request_id, "reconcile"));

    // An attempt that recorded no sentinel. Refused, and refused *distinctly*:
    // no amount of re-reading that job's log will produce a sentinel that can
    // be tied to it, which is a different instruction from "you read the wrong
    // line".
    const nrid = testId("nosent");
    const no_sentinel: []const u8 = &nrid;
    try Store.operations.create(&store, .{
        .request_id = no_sentinel,
        .server_id = 1,
        .server_name = "race",
        .kind = .job,
        .now = 100,
    });
    try Store.operations.advance(&store, no_sentinel, .connecting, 101);
    try Store.operations.advance(&store, no_sentinel, .submitted, 102);
    _ = try Store.job_attempts.create(&store, .{
        .request_id = no_sentinel,
        .server_id = 1,
        .server_name = "race",
        .job_name = "sentinel-less",
        .attempt_no = 1,
        .now = 100,
    });
    _ = try Store.receipts.settle(
        &store,
        no_sentinel,
        .{ .indeterminate = .{ .reason = "caller walked away", .last_observed = .submitted } },
        .{},
        200,
    );
    const unrecorded = try Store.receipts.resolve(&store, arena, no_sentinel, .completed, .{
        .job_sentinel = .{ .sentinel = "__TERMINUS_JOB_9__", .exit_code = 0 },
    }, 300);
    try t.expect(unrecorded.evidence_wrong_sentinel.recorded == .attempt_recorded_none);

    // A request no launch ever registered. Also refused, and also distinctly:
    // this one is evidence aimed at something that is not a job launch, not a
    // job whose launch forgot to write something down.
    const arid = testId("noatt");
    const no_attempt: []const u8 = &arid;
    try Store.operations.create(&store, .{
        .request_id = no_attempt,
        .server_id = 1,
        .server_name = "race",
        .kind = .job,
        .now = 100,
    });
    try Store.operations.advance(&store, no_attempt, .connecting, 101);
    try Store.operations.advance(&store, no_attempt, .submitted, 102);
    _ = try Store.receipts.settle(
        &store,
        no_attempt,
        .{ .indeterminate = .{ .reason = "caller walked away", .last_observed = .submitted } },
        .{},
        200,
    );
    const unlaunched = try Store.receipts.resolve(&store, arena, no_attempt, .completed, .{
        .job_sentinel = .{ .sentinel = "__TERMINUS_JOB_9__", .exit_code = 0 },
    }, 300);
    try t.expect(unlaunched.evidence_wrong_sentinel.recorded == .no_attempt);

    // And the binding is not a blanket refusal: this attempt's own sentinel
    // still settles it, which is what keeps the check from costing the job its
    // route. Last, so the three refusals above cannot have been the resolution
    // having already happened.
    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .job_sentinel = .{ .sentinel = "__TERMINUS_JOB_9__", .exit_code = 0 },
    }, 400)) == .resolved);
    try t.expectEqual(
        op_state.ResolvedStatus.completed,
        (try Store.operations.get(&store, arena, request_id)).?.resolved_status.?,
    );
}

// A settlement records what was sitting at its result-record address.
//
// The hole this closes: a job settles cleanly from the sentinel in its log
// while a document that is *not* usable sits at the address derived from that
// same request — most sharply a `foreign` one, which means the result directory
// is being reused or two request ids collided. The settlement is correct and
// the anomaly is a fact about the host, and the receipt — the one durable
// record — kept the verdict and dropped the contradiction standing next to it.
// The operator saw it on screen once and nothing kept it.
//
// Recorded in `detail_json` rather than in a column, so the schema is untouched
// and the versioned document carries it the way it carries `probeIdentity` and
// `declaredSha256` for a resolution.
test "gate: a terminal records what was at the job's result-record address" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_result_record_receipt");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    // Settles one job with `reading` at its result address and hands back the
    // terminal receipt's detail document.
    const settleWith = struct {
        fn f(
            s: *Store,
            a: std.mem.Allocator,
            request_id: []const u8,
            reading: Store.receipts.ResultRecordReading,
        ) ![]const u8 {
            try Store.operations.create(s, .{
                .request_id = request_id,
                .server_id = 1,
                .server_name = "race",
                .kind = .job,
                .now = 100,
            });
            try Store.operations.advance(s, request_id, .connecting, 101);
            try Store.operations.advance(s, request_id, .submitted, 102);
            _ = try Store.receipts.settle(s, request_id, .{ .exited = .{ .exit_code = 0 } }, .{
                .result_record = .{ .arena = a, .reading = reading },
            }, 200);
            for (try Store.receipts.list(s, a, request_id)) |row| {
                if (row.is_terminal) return row.detail_json orelse
                    error.TerminalRecordedNoResultRecord;
            }
            return error.NoTerminalRecorded;
        }
    }.f;

    try store.db.exec(
        \\INSERT INTO servers (id, name, host, port, username, created_at, updated_at)
        \\VALUES (1, 'race', '10.0.0.1', 22, 'ubuntu', 100, 100);
    );

    // The loud one. A document naming somebody else was found at this
    // request's own address, and the receipt has to carry *which* somebody —
    // the tag alone would say a collision happened while withholding the only
    // thing that identifies it.
    const frid = testId("rrforeign");
    const foreign = try settleWith(&store, arena, &frid, .{ .foreign = "01OTHEROTHER0123456789ABCD" });
    try t.expect(std.mem.indexOf(u8, foreign, "\"reading\":\"foreign\"") != null);
    try t.expect(std.mem.indexOf(u8, foreign, "01OTHEROTHER0123456789ABCD") != null);

    // The three unremarkable readings, and the reason the field is not just a
    // flag for anomalies: "we looked and there was nothing" and "we did not
    // look" are different facts, and a receipt that told them apart from
    // nothing would also fail to tell either of them from a settlement written
    // before this field existed.
    const arid = testId("rrabsent");
    const absent = try settleWith(&store, arena, &arid, .absent);
    try t.expect(std.mem.indexOf(u8, absent, "\"reading\":\"absent\"") != null);
    try t.expect(std.mem.indexOf(u8, absent, "\"claimedRequestId\":null") != null);

    const nrid = testId("rrnotreq");
    const not_requested = try settleWith(&store, arena, &nrid, .not_requested);
    try t.expect(std.mem.indexOf(u8, not_requested, "\"reading\":\"not_requested\"") != null);
    // The distinctness itself, asserted rather than implied: these two must
    // never render to the same document.
    try t.expect(!std.mem.eql(u8, absent, not_requested));

    const prid = testId("rrpresent");
    const present = try settleWith(&store, arena, &prid, .present);
    try t.expect(std.mem.indexOf(u8, present, "\"reading\":\"present\"") != null);

    // The two remaining defect readings, so all six names reach the ledger and
    // none of them collapses into a neighbour.
    const mrid = testId("rrmalform");
    const malformed = try settleWith(&store, arena, &mrid, .malformed);
    try t.expect(std.mem.indexOf(u8, malformed, "\"reading\":\"malformed\"") != null);

    const urid = testId("rrunkschema");
    const unknown = try settleWith(&store, arena, &urid, .unknown_schema);
    try t.expect(std.mem.indexOf(u8, unknown, "\"reading\":\"unknown_schema\"") != null);

    const xrid = testId("rroutrange");
    const out_of_range = try settleWith(&store, arena, &xrid, .exit_code_out_of_range);
    try t.expect(std.mem.indexOf(u8, out_of_range, "\"reading\":\"exit_code_out_of_range\"") != null);

    // Every document is versioned, for the reason the resolution document is:
    // this field was added to a shape that already had readers.
    try t.expect(std.mem.indexOf(u8, foreign, "\"schemaVersion\"") != null);

    // And a caller handing in both its own detail document and a reading is
    // refused rather than having one of the two silently dropped. Nothing
    // constructs this pair today; the refusal is what keeps it that way instead
    // of letting the next caller discover which one survives.
    const crid = testId("rrclash");
    const clash: []const u8 = &crid;
    try Store.operations.create(&store, .{
        .request_id = clash,
        .server_id = 1,
        .server_name = "race",
        .kind = .job,
        .now = 100,
    });
    try Store.operations.advance(&store, clash, .connecting, 101);
    try Store.operations.advance(&store, clash, .submitted, 102);
    try t.expectError(error.ConflictingTerminalDetail, Store.receipts.settle(
        &store,
        clash,
        .{ .exited = .{ .exit_code = 0 } },
        .{
            .detail_json = "{\"mine\":true}",
            .result_record = .{ .arena = arena, .reading = .absent },
        },
        200,
    ));
    // The refusal wrote nothing: no terminal, so the attempt is still settleable.
    try t.expect((try Store.receipts.terminalOf(&store, clash)) == null);
}

test "gate: a result with no remote clock records absence, not the epoch" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_job_result_clockless");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    const rid = testId("clockless");
    const request_id: []const u8 = &rid;
    try seedOperationOfKind(&store, request_id, .job);
    _ = try Store.receipts.settle(
        &store,
        request_id,
        op_state.terminalForTransportLoss(.submitted, "eof"),
        .{},
        200,
    );

    // A host without a usable `date` produces a document with no finish time.
    // The exit code in it is still evidence, so the resolution stands — but
    // the receipt has to say the time is absent. Persisting 0 would publish
    // midnight 1970 as the moment a job finished, and every later reader
    // would have to know that one field's private convention to avoid
    // repeating it.
    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .job_result = .{ .request_id = request_id, .exit_code = 0, .finished_at = null },
    }, 300)) == .resolved);

    const op = (try Store.operations.get(&store, arena, request_id)).?;
    const evidence = op.resolution_evidence.?;
    try t.expect(std.mem.indexOf(u8, evidence, "\"finished_at\":null") != null);
    try t.expect(std.mem.indexOf(u8, evidence, "\"finished_at\":0") == null);
}

test "gate: an operation kind this binary cannot name admits nothing" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_kind_unknown");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    const rid = testId("longkind");
    const request_id: []const u8 = &rid;
    try seedOperationOfKind(&store, request_id, .job);
    _ = try Store.receipts.settle(
        &store,
        request_id,
        op_state.terminalForTransportLoss(.submitted, "eof"),
        .{},
        200,
    );

    // `kind` has no CHECK constraint, so a future version, a manual edit or a
    // corrupted row can put anything here. Whatever it is, it is not a kind
    // this binary knows, and `appliesToKind` — which decides whether evidence
    // may release the scope barrier — has no answer for it. Longer than any
    // kind that exists is the easy half.
    try store.db.exec(
        "UPDATE operations SET kind = 'job_with_a_name_far_longer_than_any_kind_this_binary_knows_about_and_then_some_more'",
    );
    try t.expectError(error.UnknownOperationKind, Store.receipts.resolve(
        &store,
        arena,
        request_id,
        .completed,
        .{ .job_result = .{ .request_id = request_id, .exit_code = 0 } },
        300,
    ));

    // The half that used to get through. A short unrecognised kind matched no
    // arm of a string comparison, fell into `else => true`, and admitted every
    // variant in the union — so an override settled an operation whose very
    // nature this binary could not read, and released its scope. The evidence
    // here is deliberately the one that is admissible for every kind that
    // exists: what refuses it is the kind being unreadable, nothing else.
    //
    // Checked to be unparseable rather than assumed: add a kind by this name
    // and the gate would go on passing while testing nothing.
    const not_a_kind = "jobs";
    try t.expectError(error.UnknownKind, Store.operations.Kind.parse(not_a_kind));
    try store.db.exec("UPDATE operations SET kind = '" ++ not_a_kind ++ "'");
    try t.expectError(error.UnknownOperationKind, Store.receipts.resolve(
        &store,
        arena,
        request_id,
        .completed,
        .{ .operator_override = .{ .reason = "checked by hand", .by = "tester" } },
        305,
    ));

    // Nothing was written by either refusal, and neither left a transaction
    // open — the next resolve would fail to BEGIN if it had.
    try t.expectEqual(
        @as(?op_state.ResolvedStatus, null),
        (try Store.operations.get(&store, arena, request_id)).?.resolved_status,
    );
    try t.expectEqual(@as(usize, 0), try countKind(&store, arena, request_id, "reconcile"));
    // Rendered from the enum: the control that proves the two refusals are not
    // just "resolve always fails here" has to write a kind this binary really
    // does know, and a rename must move it rather than break it silently.
    try store.db.exec("UPDATE operations SET kind = '" ++ @tagName(Store.operations.Kind.job) ++ "'");
    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .job_result = .{ .request_id = request_id, .exit_code = 0 },
    }, 310)) == .resolved);
}

test "gate: a job's exit status cannot settle a transfer" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_job_evidence_kind");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    const rid = testId("push");
    const request_id: []const u8 = &rid;

    // The whole advance commitment is made before the attempt goes out, and it
    // has to be: `create` binds to an operation that has not submitted yet, and
    // `recordExpectedHash` refuses after that point too. This gate used to seed
    // a settled operation and hand `create` a digest directly, which was the
    // bypass in gate form — the same door the write-once rule exists to shut.
    try seedTransferBeforeSubmit(&store, request_id);
    const checkpoint = try Store.transfers.create(&store, .{
        .request_id = request_id,
        .direction = .push,
        .dest_side = .{ .server = 1 },
        .dest_path = "/srv/app/out.bin",
        .partial_path = "/srv/app/out.bin.terminus-part",
        .source = .{ .local_file = .{ .path = "./out.bin" } },
        .chunk_size = 1 << 20,
        .now = 102,
    });
    try Store.transfers.recordExpectedHash(&store, checkpoint, request_id, "abc", 103);
    try Store.operations.advance(&store, request_id, .submitted, 104);
    _ = try Store.receipts.settle(
        &store,
        request_id,
        op_state.terminalForTransportLoss(.submitted, "eof"),
        .{},
        200,
    );

    // Both records are written by the job wrapper and exist only for jobs.
    // A transfer has no such wrapper, so an exit status offered for one was
    // misrouted — and "the command returned 0" says nothing about whether
    // the bytes landed, which is the only thing a transfer's outcome means.
    const wrong_file = try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .job_result = .{ .request_id = request_id, .exit_code = 0, .finished_at = 900 },
    }, 300);
    try t.expectEqualStrings("transfer_push", wrong_file.evidence_wrong_kind.operation_kind);
    try t.expectEqualStrings("job_result", wrong_file.evidence_wrong_kind.evidence_kind);
    // The two fields answer two different questions — "what refused" and
    // "what was offered" — and both used to be filled from the evidence, so a
    // refusal could not name the operation that issued it.
    try t.expect(!std.mem.eql(
        u8,
        wrong_file.evidence_wrong_kind.operation_kind,
        wrong_file.evidence_wrong_kind.evidence_kind,
    ));

    const wrong_sentinel = try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .job_sentinel = .{ .sentinel = "__S__", .exit_code = 0 },
    }, 301);
    try t.expectEqualStrings("transfer_push", wrong_sentinel.evidence_wrong_kind.operation_kind);
    try t.expectEqualStrings("job_sentinel", wrong_sentinel.evidence_wrong_kind.evidence_kind);

    // Nothing was recorded by either refusal.
    const unresolved = (try Store.operations.get(&store, arena, request_id)).?;
    try t.expectEqual(@as(?op_state.ResolvedStatus, null), unresolved.resolved_status);
    for (try Store.receipts.list(&store, arena, request_id)) |row| {
        try t.expect(!std.mem.eql(u8, row.kind, "reconcile"));
    }

    // The evidence a transfer actually produces still works — but only once
    // the transfer has said, in advance, which digest would prove it. Offered
    // against an operation that declared nothing, a hash is just the hash of
    // whatever is at that path: a leftover file from an earlier run would
    // settle this `completed` and release the scope.
    //
    // It takes a second request to say that now, because a digest has to be
    // declared before submission and one operation can no longer be both
    // "never declared" and "declared and matching". This one has a checkpoint
    // and no digest, which is the sharper claim anyway: a checkpoint existing
    // is not a declaration.
    const silent_rid = testId("undeclared");
    const silent: []const u8 = &silent_rid;
    try seedTransferBeforeSubmit(&store, silent);
    _ = try Store.transfers.create(&store, .{
        .request_id = silent,
        .direction = .push,
        .dest_side = .{ .server = 1 },
        .dest_path = "/srv/app/undeclared.bin",
        .partial_path = "/srv/app/undeclared.bin.terminus-part",
        .source = .{ .local_file = .{ .path = "./undeclared.bin" } },
        .chunk_size = 1 << 20,
        .now = 102,
    });
    try Store.operations.advance(&store, silent, .submitted, 104);
    _ = try Store.receipts.settle(
        &store,
        silent,
        op_state.terminalForTransportLoss(.submitted, "eof"),
        .{},
        200,
    );
    const undeclared = try Store.receipts.resolve(&store, arena, silent, .completed, .{
        .filesystem_effect = .{ .side = .remote, .path = "/srv/app/undeclared.bin", .sha256 = "abc" },
    }, 310);
    try t.expectEqual(
        @as(?Store.transfers.ExpectedEffect, null),
        undeclared.effect_hash_unproven.expected,
    );
    try t.expectEqualStrings("abc", undeclared.effect_hash_unproven.observed.sha256);

    // Declared, but the bytes that landed are not the bytes it was sending.
    const wrong_bytes = try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .filesystem_effect = .{ .side = .remote, .path = "/srv/app/out.bin", .sha256 = "def" },
    }, 311);
    try t.expectEqualStrings("abc", wrong_bytes.effect_hash_unproven.expected.?.sha256);

    // Right bytes, wrong destination. A digest is a statement about content,
    // not about where the content ended up: a push that also wrote the same
    // bytes to a scratch path would otherwise settle as if it had published.
    const wrong_path = try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .filesystem_effect = .{ .side = .remote, .path = "/tmp/scratch.bin", .sha256 = "abc" },
    }, 312);
    try t.expectEqualStrings("/srv/app/out.bin", wrong_path.effect_hash_unproven.expected.?.path);

    // Right bytes at the right path, read on the wrong machine. A push
    // publishes on the host; proving the local source still exists proves
    // nothing about what landed there.
    const wrong_side = try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .filesystem_effect = .{ .side = .local, .path = "/srv/app/out.bin", .sha256 = "abc" },
    }, 313);
    try t.expectEqual(Store.transfers.Side.remote, wrong_side.effect_hash_unproven.expected.?.side);

    // Still nothing recorded: four refusals in a row must not have leaked a
    // resolution between them.
    try t.expectEqual(
        @as(?op_state.ResolvedStatus, null),
        (try Store.operations.get(&store, arena, request_id)).?.resolved_status,
    );

    // Declared and matching, against a checkpoint whose own record says the
    // rename landed. This is the only pairing that settles — and the second
    // half of it is not decoration: driven straight from `planned`, the same
    // reading was settling `completed` for a transfer that had never written a
    // byte, because the digest binds the reading to the declaration and nothing
    // asked whether this transfer had put anything there. See
    // `State.renameMayHaveLanded`.
    try driveToPublished(&store, checkpoint, request_id, "abc");
    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .filesystem_effect = .{ .side = .remote, .path = "/srv/app/out.bin", .sha256 = "abc" },
    }, 314)) == .resolved);
}

test "gate: a terminal that does not describe this kind of work is refused at settle" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_terminal_kind");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    // A write, submitted: the bytes are with the remote and an answer is due.
    const wr = testId("wrkind");
    const write_id: []const u8 = &wr;
    try seedOperationOfKind(&store, write_id, .session_write);

    // An exit status for an operation that ran no command. Every other guard on
    // this path waves it through — `canTransition(.submitted, .completed)` is
    // legal, and `canSettle(.submitted, .exited)` is exactly the pairing that
    // check exists to admit — so the kind is the only thing standing between a
    // write and a receipt carrying `exit_code = 0` in the column an auditor
    // reads first.
    try t.expect(op_state.canTransition(.submitted, .completed));
    try t.expect(op_state.canSettle(.submitted, .{ .exited = .{ .exit_code = 0 } }));
    try t.expectError(error.TerminalDoesNotDescribeKind, Store.receipts.settle(
        &store,
        write_id,
        .{ .exited = .{ .exit_code = 0 } },
        .{},
        200,
    ));
    // A refusal that wrote nothing: no terminal event, and the attempt is still
    // where it was, so the caller can settle it correctly afterwards.
    try t.expectEqual(@as(?Store.receipts.TerminalRecord, null), try Store.receipts.terminalOf(&store, write_id));
    try t.expectEqual(
        op_state.Status.submitted,
        (try Store.operations.get(&store, arena, write_id)).?.status,
    );
    // Nor did it leave a transaction open behind it.
    try store.db.exec("BEGIN IMMEDIATE");
    try store.db.exec("ROLLBACK");

    // The control: the terminal built for this kind of work still settles it,
    // through the same door, one line later.
    const delivered = try Store.receipts.settle(&store, write_id, .{
        .input_accepted = .{ .bytes = 12, .sha256 = "aabbcc" },
    }, .{}, 210);
    try t.expectEqual(op_state.Status.completed, delivered.recorded.status);

    // The other direction, because a matrix that only refuses one way is half a
    // matrix: a terminal's acceptance of typed bytes offered for a command that
    // was judged by an exit status.
    const ex = testId("exkind");
    const exec_id: []const u8 = &ex;
    try Store.operations.create(&store, .{
        .request_id = exec_id,
        .server_id = 1,
        .server_name = "race",
        .kind = .exec,
        .now = 300,
    });
    try Store.operations.advance(&store, exec_id, .connecting, 301);
    try Store.operations.advance(&store, exec_id, .submitted, 302);
    try t.expectError(error.TerminalDoesNotDescribeKind, Store.receipts.settle(
        &store,
        exec_id,
        .{ .input_accepted = .{ .bytes = 12, .sha256 = "aabbcc" } },
        .{},
        310,
    ));
    const ran = try Store.receipts.settle(&store, exec_id, .{ .exited = .{ .exit_code = 0 } }, .{}, 311);
    try t.expectEqual(op_state.Status.completed, ran.recorded.status);

    // The check runs *before* the already-settled branch, and that ordering is
    // the point rather than an accident. Whether a terminal can describe work of
    // this kind is a property of the pair alone — it does not depend on who won
    // a race — so answering it afterwards would report this binary's defect only
    // to the caller that *lost*, which is the one way to have a bug nobody ever
    // sees. Both operations above are settled now, and both still name the
    // mismatch rather than handing back the winner.
    try t.expectError(error.TerminalDoesNotDescribeKind, Store.receipts.settle(
        &store,
        exec_id,
        .{ .input_refused = .{ .reason = "no such session" } },
        .{},
        320,
    ));
    switch (try Store.receipts.settle(&store, exec_id, .{ .exited = .{ .exit_code = 1 } }, .{}, 321)) {
        .already_settled => |winner| try t.expectEqual(op_state.Status.completed, winner.status),
        .recorded => return error.SettledTwice,
    }
}

test "gate: settle refuses an operation kind this binary cannot name" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_settle_kind_unknown");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    const rid = testId("settlekind");
    const request_id: []const u8 = &rid;
    try seedOperationOfKind(&store, request_id, .exec);

    // The same refusal `resolve` makes, one writer over, and for the same
    // reason: `kind` carries no CHECK constraint, so a future version, a hand
    // edit or a corrupt row can leave anything in it, and a kind this binary
    // cannot name is one it cannot decide a matrix cell for. Parsed rather than
    // compared as text — a short unrecognised value is the half that slipped
    // through on the resolve side, so it is the half checked here.
    //
    // This is also what proves `settle` reads the column at all: the terminal
    // offered is the one every kind that exists admits, so the only thing that
    // can refuse it is the kind being unreadable.
    const not_a_kind = "exe";
    try t.expectError(error.UnknownKind, Store.operations.Kind.parse(not_a_kind));
    try store.db.exec("UPDATE operations SET kind = '" ++ not_a_kind ++ "'");
    try t.expectError(error.UnknownOperationKind, Store.receipts.settle(
        &store,
        request_id,
        op_state.terminalForTransportLoss(.submitted, "eof"),
        .{},
        200,
    ));

    // Nothing was written, and the attempt is where it was: a row we refuse to
    // reason about is not a row we half-settle.
    try t.expectEqual(@as(?Store.receipts.TerminalRecord, null), try Store.receipts.terminalOf(&store, request_id));
    try t.expectEqual(
        op_state.Status.submitted,
        (try Store.operations.get(&store, arena, request_id)).?.status,
    );
    try store.db.exec("BEGIN IMMEDIATE");
    try store.db.exec("ROLLBACK");
}

test "gate: a delivered write records what was taken, and no exit status" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_write_accepted");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    const rid = testId("wraccept");
    const request_id: []const u8 = &rid;
    try seedOperationOfKind(&store, request_id, .session_write);

    // Nothing has been offered to a terminal before submission, so nothing can
    // have answered. The two answers are refused by different guards, and the
    // difference is worth pinning: `input_accepted` claims `completed`, which
    // the transition graph already forbids from `created`, while
    // `input_refused` claims `failed` — a status `created` may legally reach,
    // via `never_submitted`. So the *only* thing standing between an attempt
    // that never dialed and a receipt saying a remote terminal turned it away
    // is `canSettle`.
    {
        const early = testId("wrearly");
        const early_id: []const u8 = &early;
        try Store.operations.create(&store, .{
            .request_id = early_id,
            .server_id = 1,
            .server_name = "race",
            .kind = .session_write,
            .now = 100,
        });
        try t.expectError(error.IllegalTransition, Store.receipts.settle(&store, early_id, .{
            .input_accepted = .{ .bytes = 7, .sha256 = "d0" },
        }, .{}, 150));
        try t.expectError(error.EvidenceDoesNotFit, Store.receipts.settle(&store, early_id, .{
            .input_refused = .{ .reason = "no such session" },
        }, .{}, 151));
        try Store.operations.advance(&store, early_id, .connecting, 152);
        try t.expectError(error.EvidenceDoesNotFit, Store.receipts.settle(&store, early_id, .{
            .input_refused = .{ .reason = "no such session" },
        }, .{}, 153));
    }

    const outcome = try Store.receipts.settle(&store, request_id, .{
        .input_accepted = .{ .bytes = 12, .sha256 = "aabbcc" },
    }, .{}, 200);
    try t.expectEqual(op_state.Status.completed, outcome.recorded.status);

    const row = try terminalRowOf(&store, arena, request_id);
    // The whole point of the variant. `exited` is the only other route to
    // `completed`, and it writes a zero here — a number an auditor reads as
    // "the command succeeded" on a receipt where no command was judged.
    try t.expectEqual(@as(?i64, null), row.exit_code);
    try t.expectEqual(@as(?i64, null), row.term_signal);
    try t.expectEqual(@as(?[]const u8, null), row.error_code);
    try t.expectEqual(@as(?bool, false), row.timed_out);
    try t.expectEqual(@as(?bool, false), row.remote_started);
    // What *was* established, in the columns that describe the input stream.
    try t.expectEqual(@as(?i64, 12), row.stdin_bytes);
    try t.expectEqualStrings("aabbcc", row.stdin_sha256.?);

    // A caller may not supply a second reading of the same stream: the receipt
    // would then hold two answers to the one question this terminal exists to
    // answer, and nothing says which the ledger meant.
    const second = testId("wrdouble");
    const second_id: []const u8 = &second;
    try Store.operations.create(&store, .{
        .request_id = second_id,
        .server_id = 1,
        .server_name = "race",
        .kind = .session_write,
        .now = 100,
    });
    try Store.operations.advance(&store, second_id, .connecting, 101);
    try Store.operations.advance(&store, second_id, .submitted, 102);
    try t.expectError(error.ContradictoryEvidence, Store.receipts.settle(&store, second_id, .{
        .input_accepted = .{ .bytes = 12, .sha256 = "aabbcc" },
    }, .{ .stdin = .{ .bytes = 999 } }, 210));
}

test "gate: a refused write is a proven failure, and only a human can reconcile a lost one" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_write_refused");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    const rid = testId("wrrefuse");
    const request_id: []const u8 = &rid;
    try seedOperationOfKind(&store, request_id, .session_write);

    // The remote answered before it touched a pane, so the bytes provably did
    // not reach the shell. That is a failure with a name of its own — not an
    // exit code borrowed from a command nobody ran, and not `never_submitted`,
    // which claims the bytes never left this machine.
    const outcome = try Store.receipts.settle(&store, request_id, .{
        .input_refused = .{ .reason = "the remote tmux session does not exist" },
    }, .{}, 200);
    try t.expectEqual(op_state.Status.failed, outcome.recorded.status);

    const row = try terminalRowOf(&store, arena, request_id);
    try t.expectEqual(@as(?i64, null), row.exit_code);
    try t.expectEqualStrings("INPUT_REFUSED", row.error_code.?);
    try t.expectEqualStrings("the remote tmux session does not exist", row.transport_error.?);
    // Nothing arrived, so no stream evidence may say otherwise.
    try t.expectEqual(@as(?i64, null), row.stdin_bytes);
    try t.expectEqual(@as(?bool, false), row.remote_started);

    // A write whose answer was lost is `indeterminate`, and the only evidence
    // that may release its scope is a human saying what they saw. A job's
    // exit status is the tempting one — a write and a job both type into a
    // tmux session — and it is refused by category, before anything asks
    // whether the document is this operation's.
    const lost = testId("wrlost");
    const lost_id: []const u8 = &lost;
    try Store.operations.create(&store, .{
        .request_id = lost_id,
        .server_id = 1,
        .server_name = "race",
        .kind = .session_write,
        .now = 100,
    });
    try Store.operations.advance(&store, lost_id, .connecting, 101);
    try Store.operations.advance(&store, lost_id, .submitted, 102);
    _ = try Store.receipts.settle(
        &store,
        lost_id,
        op_state.terminalForTransportLoss(.submitted, "eof"),
        .{},
        210,
    );

    switch (try Store.receipts.resolve(&store, arena, lost_id, .completed, .{
        .job_result = .{ .request_id = lost_id, .exit_code = 0 },
    }, 220)) {
        .evidence_wrong_kind => |refusal| {
            try t.expectEqualStrings("session_write", refusal.operation_kind);
            try t.expectEqualStrings("job_result", refusal.evidence_kind);
        },
        else => return error.WrongKindEvidenceAdmitted,
    }
    // The escape hatch is open, and it is legible as a human's decision: the
    // reconcile event is stamped as an override rather than passing for proof.
    try t.expect((try Store.receipts.resolve(&store, arena, lost_id, .completed, .{
        .operator_override = .{ .reason = "read the pane by hand", .by = "tester" },
    }, 230)) == .resolved);
    const rows = try Store.receipts.list(&store, arena, lost_id);
    const last = rows[rows.len - 1];
    try t.expectEqualStrings("reconcile", last.kind);
    try t.expectEqualStrings("OPERATOR_OVERRIDE", last.error_code.?);
}

/// The one terminal row of an operation, for gates that assert its shape.
fn terminalRowOf(
    store: *Store,
    arena: std.mem.Allocator,
    request_id: []const u8,
) !Store.receipts.Row {
    for (try Store.receipts.list(store, arena, request_id)) |row| {
        if (row.is_terminal) return row;
    }
    return error.NoTerminalRecorded;
}

test "gate: a report about a process cannot settle a transfer" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_process_evidence_kind");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    const rid = testId("procpush");
    const request_id: []const u8 = &rid;

    try seedTransferBeforeSubmit(&store, request_id);
    const checkpoint = try Store.transfers.create(&store, .{
        .request_id = request_id,
        .direction = .push,
        .dest_side = .{ .server = 1 },
        .dest_path = "/srv/app/out.bin",
        .partial_path = "/srv/app/out.bin.terminus-part",
        .source = .{ .local_file = .{ .path = "./out.bin" } },
        .chunk_size = 1 << 20,
        .now = 102,
    });
    try Store.transfers.recordExpectedHash(&store, checkpoint, request_id, "abc", 103);
    try Store.operations.advance(&store, request_id, .submitted, 104);
    _ = try Store.receipts.settle(
        &store,
        request_id,
        op_state.terminalForTransportLoss(.submitted, "eof"),
        .{},
        200,
    );

    // The most dangerous cell in the matrix, back when it was a cell rather
    // than a blanket refusal. A supervisor report carries the status it
    // reports, so `supports` waves it straight through to `completed` — for a
    // transfer that would be a verdict of "the bytes landed" reached without
    // anybody reading the destination, past the digest comparison every other
    // route to that verdict has to pass. It is now refused for every kind (see
    // the gate on binding), and this assertion is kept because the transfer
    // reason is a different one and outlives it: even a report bound to its
    // attempt beyond doubt would still be a claim about a process.
    const by_report = try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .supervisor_report = .{ .reported = .completed, .detail = "the copier exited 0" },
    }, 300);
    try t.expectEqualStrings("transfer_push", by_report.evidence_wrong_kind.operation_kind);
    try t.expectEqualStrings("supervisor_report", by_report.evidence_wrong_kind.evidence_kind);

    // A probe is refused for the same reason one step further down: "it is no
    // longer running" is equally true of a copier that finished and one that
    // died halfway through its rename.
    //
    // The identity check runs before the kind check, so a transfer with no
    // recorded process would be refused as a reading of somebody else's and
    // this half of the gate would pass without testing the cell at all.
    // Nothing writes a process identity onto a transfer today; the gate writes
    // one so that the *kind* rule is what refuses — and so that the day a
    // transfer does record one, this is the cell that says no.
    try recordProcess(&store, request_id, 5150, "boot+5150", 301);
    const by_probe = try Store.receipts.resolve(&store, arena, request_id, .cancelled, .{
        .process_probe = .{ .pid = 5150, .start_token = "boot+5150", .alive = false },
    }, 302);
    try t.expectEqualStrings("transfer_push", by_probe.evidence_wrong_kind.operation_kind);
    try t.expectEqualStrings("process_probe", by_probe.evidence_wrong_kind.evidence_kind);

    // Neither refusal recorded anything.
    try t.expectEqual(
        @as(?op_state.ResolvedStatus, null),
        (try Store.operations.get(&store, arena, request_id)).?.resolved_status,
    );
    try t.expectEqual(@as(usize, 0), try countKind(&store, arena, request_id, "reconcile"));

    // The control that keeps the two refusals from being satisfied by refusing
    // everything: the evidence a transfer does produce still settles it.
    //
    // Driven to `published` first, and that is not scene-setting. A digest
    // match binds a reading to this transfer's *declaration* and says nothing
    // about whether this transfer ever put anything at that path, so
    // `filesystem_effect` also asks whether the checkpoint's own record leaves
    // room for it to have done — see `State.renameMayHaveLanded`. Against the
    // `planned` row this control used to use, the reading was settling
    // `completed` for a transfer that had not moved a byte.
    try driveToPublished(&store, checkpoint, request_id, "abc");
    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .filesystem_effect = .{ .side = .remote, .path = "/srv/app/out.bin", .sha256 = "abc" },
    }, 310)) == .resolved);
}

test "gate: a probe settles only the process the attempt recorded" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_probe_identity");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    const rid = testId("probe");
    const request_id: []const u8 = &rid;
    // An `exec`, because that is the only kind a probe may speak for at all:
    // it is the one that records the pid and start token of the process that
    // ran the command. Run against a `job` these calls are refused by kind
    // before the identity rules this gate is about are ever consulted.
    try seedOperationOfKind(&store, request_id, .exec);
    _ = try Store.receipts.settle(
        &store,
        request_id,
        op_state.terminalForTransportLoss(.submitted, "eof"),
        .{},
        200,
    );

    // Nothing may survive a refusal: not the resolution, and not a reconcile
    // event that would make the trail read as though one had been attempted and
    // judged. "Refused" has to mean nothing was recorded.
    const nothingRecorded = struct {
        fn check(s: *Store, a: std.mem.Allocator, id: []const u8) !void {
            try std.testing.expectEqual(
                @as(?op_state.ResolvedStatus, null),
                (try Store.operations.get(s, a, id)).?.resolved_status,
            );
            try std.testing.expectEqual(@as(usize, 0), try countKind(s, a, id, "reconcile"));
        }
    }.check;

    // An attempt that never recorded a process is one no probe can speak
    // about, exactly as a transfer with no declared digest is one no file hash
    // can speak about. Waving it through — there being nothing to contradict —
    // would make the check vacuous precisely where it matters: an attempt whose
    // process was never identified is the one nobody can go and look for.
    const unidentified = try Store.receipts.resolve(&store, arena, request_id, .cancelled, .{
        .process_probe = .{ .pid = 5150, .start_token = "boot+5150", .alive = false },
    }, 300);
    try t.expectEqual(@as(?Store.receipts.RecordedProcess, null), unidentified.evidence_wrong_process.recorded);
    try t.expectEqual(@as(i64, 5150), unidentified.evidence_wrong_process.probed_pid);
    try nothingRecorded(&store, arena, request_id);

    try recordProcess(&store, request_id, 5150, "boot+5150", 305);

    // A probe of some other process settles nothing here. Before this check
    // existed, any dead pid on any host released any operation's scope barrier.
    const other_pid = try Store.receipts.resolve(&store, arena, request_id, .cancelled, .{
        .process_probe = .{ .pid = 6001, .start_token = "boot+6001", .alive = false },
    }, 310);
    try t.expectEqual(@as(i64, 6001), other_pid.evidence_wrong_process.probed_pid);
    try t.expectEqual(@as(i64, 5150), other_pid.evidence_wrong_process.recorded.?.pid);
    try nothingRecorded(&store, arena, request_id);

    // The right pid and the wrong start token is the recycled-pid case, which
    // is the entire reason the token is recorded: the kernel handed 5150 to
    // something else, and that something else being dead says nothing about our
    // work.
    const recycled = try Store.receipts.resolve(&store, arena, request_id, .cancelled, .{
        .process_probe = .{ .pid = 5150, .start_token = "boot+9999", .alive = false },
    }, 311);
    try t.expectEqual(@as(i64, 5150), recycled.evidence_wrong_process.recorded.?.pid);
    try t.expectEqualStrings("boot+5150", recycled.evidence_wrong_process.recorded.?.start_token.?);
    try t.expectEqualStrings("boot+9999", recycled.evidence_wrong_process.probed_start_token.?);
    try nothingRecorded(&store, arena, request_id);

    // A probe that could not read a token at all is the same hole with the
    // evidence missing rather than wrong. Admitting it would leave the recorded
    // token as decoration: anyone who skipped reading it would be trusted.
    const tokenless = try Store.receipts.resolve(&store, arena, request_id, .cancelled, .{
        .process_probe = .{ .pid = 5150, .alive = false },
    }, 312);
    try t.expectEqual(@as(?[]const u8, null), tokenless.evidence_wrong_process.probed_start_token);
    try nothingRecorded(&store, arena, request_id);

    // And the arm that actually releases the barrier, which nothing exercised
    // before: this attempt's own pid, this attempt's own start token, and the
    // process is gone.
    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .cancelled, .{
        .process_probe = .{ .pid = 5150, .start_token = "boot+5150", .alive = false },
    }, 320)) == .resolved);
    const op = (try Store.operations.get(&store, arena, request_id)).?;
    try t.expectEqual(op_state.ResolvedStatus.cancelled, op.resolved_status.?);
    try t.expectEqual(op_state.Status.indeterminate, op.status); // the observation is kept
    try t.expect(!op.effectiveStatus().blocksScope());
    try t.expectEqual(@as(usize, 0), (try Store.operations.unsettled(&store, arena, 1)).len);
    try t.expectEqual(@as(usize, 1), try countKind(&store, arena, request_id, "reconcile"));
}

test "gate: an attempt that never read a start token is judged on its pid" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_probe_weak_identity");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    const rid = testId("weakid");
    const request_id: []const u8 = &rid;
    try seedOperationOfKind(&store, request_id, .exec);
    _ = try Store.receipts.settle(
        &store,
        request_id,
        op_state.terminalForTransportLoss(.submitted, "eof"),
        .{},
        200,
    );

    // Shell mode cannot always read a process start time, and records the pid
    // alone (`supervisor.Capability.pid_proof == .weak`). The pid is then the
    // whole of what this attempt ever knew about its own process, so it is the
    // whole of what a probe can be checked against — refusing every probe here
    // would make the weak supervisor unreconcilable by the only mechanical
    // route it has.
    //
    // The asymmetry is the point, and it is not symmetric by accident: a
    // recorded token the probe did not read is refused (above), because there
    // the attempt knew something the probe declined to check.
    try recordProcess(&store, request_id, 5150, null, 205);

    // With no recorded token there is nothing else left to refuse on, so this
    // is where the pid comparison is on its own. In the gate above a wrong pid
    // also carries a wrong token, and either conjunct alone would refuse it —
    // delete the pid comparison there and that gate still passes.
    const wrong_pid = try Store.receipts.resolve(&store, arena, request_id, .cancelled, .{
        .process_probe = .{ .pid = 6001, .alive = false },
    }, 210);
    try t.expectEqual(@as(i64, 6001), wrong_pid.evidence_wrong_process.probed_pid);
    try t.expectEqual(@as(i64, 5150), wrong_pid.evidence_wrong_process.recorded.?.pid);
    try t.expectEqual(@as(?[]const u8, null), wrong_pid.evidence_wrong_process.recorded.?.start_token);
    try t.expectEqual(
        @as(?op_state.ResolvedStatus, null),
        (try Store.operations.get(&store, arena, request_id)).?.resolved_status,
    );
    try t.expectEqual(@as(usize, 0), try countKind(&store, arena, request_id, "reconcile"));

    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .cancelled, .{
        .process_probe = .{ .pid = 5150, .start_token = "boot+5150", .alive = false },
    }, 300)) == .resolved);
    try t.expectEqual(
        op_state.ResolvedStatus.cancelled,
        (try Store.operations.get(&store, arena, request_id)).?.resolved_status.?,
    );

    // Admitted — and the receipt has to say on what. The probe volunteered a
    // token here and it was compared with nothing, because this attempt never
    // recorded one; grading the match by what the *probe* offered would let a
    // caller strengthen its own evidence by filling in a field. So the binding
    // is read off the recorded identity, and it is `pid_only`: a pid this
    // attempt used and the kernel is free to reissue.
    //
    // Without this the trail could not tell an admitted pid-only match from a
    // pid+token one, and the scope barrier is lifted on the strength of exactly
    // that difference.
    const trail = try Store.receipts.list(&store, arena, request_id);
    const reconcile = trail[trail.len - 1].detail_json.?;
    try t.expectEqualStrings("reconcile", trail[trail.len - 1].kind);
    try t.expect(std.mem.indexOf(u8, reconcile, "\"probeIdentity\":\"pid_only\"") != null);
}

test "gate: a probe backed by a recorded token is not filed as a pid-only match" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_probe_binding_strong");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    const rid = testId("strongid");
    const request_id: []const u8 = &rid;
    try seedOperationOfKind(&store, request_id, .exec);
    _ = try Store.receipts.settle(
        &store,
        request_id,
        op_state.terminalForTransportLoss(.submitted, "eof"),
        .{},
        200,
    );

    // The ordinary case on a host that can read a process start time:
    // `supervisor.wrapShell` reads it out of `/proc/<pid>/stat` or `ps -o
    // lstart=`, and `execution.remoteStarted` writes it onto the trail. The
    // field is not decoration — the pid-only reading above is the *fallback*,
    // not the norm — and the receipt has to distinguish the two or recording it
    // buys nothing.
    try recordProcess(&store, request_id, 5150, "boot+5150", 205);
    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .cancelled, .{
        .process_probe = .{ .pid = 5150, .start_token = "boot+5150", .alive = false },
    }, 210)) == .resolved);

    const trail = try Store.receipts.list(&store, arena, request_id);
    const reconcile = trail[trail.len - 1].detail_json.?;
    try t.expect(std.mem.indexOf(u8, reconcile, "\"probeIdentity\":\"pid_and_start_token\"") != null);
    try t.expect(std.mem.indexOf(u8, reconcile, "pid_only") == null);
}

test "gate: an identity the attempt proved cannot be forgotten by a later event" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_probe_identity_monotone");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    const rid = testId("keepsid");
    const request_id: []const u8 = &rid;
    try seedOperationOfKind(&store, request_id, .exec);
    _ = try Store.receipts.settle(
        &store,
        request_id,
        op_state.terminalForTransportLoss(.submitted, "eof"),
        .{},
        200,
    );

    // The attempt read a start time for its process, and then wrote a later
    // event about the same pid that did not carry one. `remote_pid` and
    // `remote_start_token` are independently optional on every writer — a
    // `remote_cancel_confirmed` fills each from `extra.x orelse c.x` on its own
    // — so this shape needs no misuse to occur, only a caller that had the pid
    // to hand and not the token.
    try recordProcess(&store, request_id, 5150, "boot+5150", 205);
    try recordProcess(&store, request_id, 5150, null, 206);

    // Reading the identity off the newest pid-bearing row alone would answer
    // "pid 5150, no token" here, and a probe that could not read a start time
    // would then be admitted — releasing the scope barrier on the strength of a
    // pid, for an attempt that had already demonstrated it could do better. The
    // token is read back for that pid instead, so the binding only ever
    // strengthens.
    const forgetful = try Store.receipts.resolve(&store, arena, request_id, .cancelled, .{
        .process_probe = .{ .pid = 5150, .alive = false },
    }, 210);
    // The tag first: reading the payload of a refusal that did not happen
    // panics on the union, and a regression here should say which outcome it
    // got rather than which field was active.
    try t.expectEqual(
        @as(std.meta.Tag(Store.receipts.ResolveOutcome), .evidence_wrong_process),
        std.meta.activeTag(forgetful),
    );
    try t.expectEqualStrings("boot+5150", forgetful.evidence_wrong_process.recorded.?.start_token.?);
    try t.expectEqual(@as(?[]const u8, null), forgetful.evidence_wrong_process.probed_start_token);
    try t.expectEqual(
        @as(?op_state.ResolvedStatus, null),
        (try Store.operations.get(&store, arena, request_id)).?.resolved_status,
    );
    try t.expectEqual(@as(usize, 0), try countKind(&store, arena, request_id, "reconcile"));

    // A token belonging to a *different* pid is still not this pid's. The
    // lookup is keyed on the pid it came back with, so an unrelated process on
    // the same trail cannot lend it one.
    try recordProcess(&store, request_id, 7000, "boot+7000", 211);
    const other = try Store.receipts.resolve(&store, arena, request_id, .cancelled, .{
        .process_probe = .{ .pid = 7000, .start_token = "boot+5150", .alive = false },
    }, 212);
    try t.expectEqualStrings("boot+7000", other.evidence_wrong_process.recorded.?.start_token.?);

    // And the probe that did read the right token still settles it.
    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .cancelled, .{
        .process_probe = .{ .pid = 7000, .start_token = "boot+7000", .alive = false },
    }, 213)) == .resolved);
}

test "gate: a supervisor report settles nothing until something binds it to an attempt" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_supervisor_report");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    const rid = testId("report");
    const request_id: []const u8 = &rid;
    try seedOperation(&store, request_id);
    _ = try Store.receipts.settle(
        &store,
        request_id,
        op_state.terminalForTransportLoss(.submitted, "eof"),
        .{},
        300,
    );

    // The reported status is part of the evidence, so claim and conclusion
    // cannot be chosen independently. This half is about `supports`, which runs
    // before the kind check and is a property of the variant rather than of
    // where it is aimed, so it survives the refusal below unchanged.
    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .supervisor_report = .{ .reported = .timed_out, .detail = "deadline hit" },
    }, 400)) == .evidence_does_not_support);

    // And the pairing that used to settle it now does not, on the one kind that
    // was its strongest case: an `exec` is a single supervised remote command,
    // so its supervisor's report really is a statement about the whole of it.
    // It is refused anyway, because nothing ties *this* report to *this*
    // attempt. Every other mechanical variant carries something `resolve`
    // checks against a fact the store wrote down first — a request id in the
    // document, a pid and start token on the trail, a side, path and digest
    // committed to before submission — and this one carries a status and a
    // sentence. `isMechanical` grades it mechanical all the same, which is the
    // grade that releases the same-scope mutation barrier with no operator in
    // the loop, so until a producer exists that binds identity the cell is a
    // permit nobody can be held to.
    const unbound = try Store.receipts.resolve(&store, arena, request_id, .timed_out, .{
        .supervisor_report = .{ .reported = .timed_out, .detail = "deadline hit" },
    }, 401);
    try t.expectEqualStrings("exec", unbound.evidence_wrong_kind.operation_kind);
    try t.expectEqualStrings("supervisor_report", unbound.evidence_wrong_kind.evidence_kind);

    // Refused everywhere, not merely here. Stated as a property so a single
    // cell going back to `true` cannot be hidden behind a gate that only ever
    // looked at one kind.
    for (std.enums.values(Store.operations.Kind)) |kind| {
        const report: Store.receipts.ResolutionEvidence = .{
            .supervisor_report = .{ .reported = .completed, .detail = "the wrapper reported an exit" },
        };
        try t.expect(!report.appliesToKind(kind));
    }

    // The refusal recorded nothing, and the attempt is still settleable — by an
    // operator, which is the honest description of what an unbound report is
    // worth. Without this control the gate above would be satisfied by an
    // operation that refuses everything.
    try t.expectEqual(
        @as(?op_state.ResolvedStatus, null),
        (try Store.operations.get(&store, arena, request_id)).?.resolved_status,
    );
    try t.expectEqual(@as(usize, 0), try countKind(&store, arena, request_id, "reconcile"));
    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .timed_out, .{
        .operator_override = .{ .reason = "the wrapper's log says it hit the deadline", .by = "tester" },
    }, 402)) == .resolved);
}

test "gate: a job is not settled by a reading of its pane's process" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_job_probe_refused");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    const rid = testId("panepid");
    const request_id: []const u8 = &rid;
    try seedOperationOfKind(&store, request_id, .job);
    // The launch record, for the same reason `recordProcess` below writes the
    // process identity: the closing assertion of this gate is that a job's
    // *other* evidence chain still settles it, and a sentinel no launch
    // recorded is not that chain — it is an unaddressed string. Seeding this is
    // what makes the last line prove the sentence the comment above it claims.
    try recordLaunchSentinel(&store, request_id, "race", "panepid", "__TERMINUS_JOB_1__", 100);
    _ = try Store.receipts.settle(
        &store,
        request_id,
        op_state.terminalForTransportLoss(.submitted, "eof"),
        .{},
        200,
    );

    // The identity a job actually records. `cmd_job` launches into a tmux
    // session and reports `Tmux.panePid` — the pane's pid, and no start token,
    // because a pane does not have one to read. Written the way `cmd_job`
    // writes it, so the gate is about the shape that exists rather than an
    // invented one.
    try recordProcess(&store, request_id, 4242, null, 210);

    // A probe of exactly that pid, correct in every way a probe can be checked:
    // it is the identity on the trail, so `evidence_wrong_process` does not
    // fire, and `supports` admits "gone therefore cancelled". While this cell
    // was open, that was enough — pane gone, `cancelled`, scope released, and a
    // command that daemonized or ran under `setsid` still running on the host.
    // The refusal is by *kind*, which is where it belongs: the pane is not the
    // job's process, so no reading of it is a reading of this operation however
    // carefully it is taken.
    const by_pane = try Store.receipts.resolve(&store, arena, request_id, .cancelled, .{
        .process_probe = .{ .pid = 4242, .alive = false },
    }, 220);
    try t.expectEqualStrings("job", by_pane.evidence_wrong_kind.operation_kind);
    try t.expectEqualStrings("process_probe", by_pane.evidence_wrong_kind.evidence_kind);
    try t.expectEqual(
        @as(?op_state.ResolvedStatus, null),
        (try Store.operations.get(&store, arena, request_id)).?.resolved_status,
    );
    try t.expectEqual(@as(usize, 0), try countKind(&store, arena, request_id, "reconcile"));

    // Nothing was taken away: a job has two evidence chains addressed to it,
    // and either still settles it. That is why refusing the probe costs the job
    // no route — unlike an `exec`, whose recorded pid *is* the command's.
    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .failed, .{
        .job_sentinel = .{ .sentinel = "__TERMINUS_JOB_1__", .exit_code = 4 },
    }, 230)) == .resolved);
}

test "gate: connecting is not recorded as an established connection" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_connected_tristate");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    try seedServer(&store);

    // `connecting` spans dialing *and* authenticating, so it cannot prove a
    // connection was established. Unknown must be recorded as unknown.
    const rid = testId("authfail");
    try Store.operations.create(&store, .{
        .request_id = &rid,
        .server_id = 1,
        .server_name = "lease-host",
        .kind = .exec,
        .now = 100,
    });
    try Store.operations.advance(&store, &rid, .connecting, 101);
    _ = try Store.receipts.settle(&store, &rid, .{
        .never_submitted = .{ .transport_error = "authentication failed" },
    }, .{}, 110);

    var rows = try Store.receipts.list(&store, arena, &rid);
    try t.expectEqual(@as(?bool, null), rows[rows.len - 1].connected);
    try t.expectEqual(@as(?bool, false), rows[rows.len - 1].remote_started);

    // The transport may state what it actually saw — here: TCP connected,
    // key rejected.
    const rid2 = testId("authfail2");
    try Store.operations.create(&store, .{
        .request_id = &rid2,
        .server_id = 1,
        .server_name = "lease-host",
        .kind = .exec,
        .now = 200,
    });
    try Store.operations.advance(&store, &rid2, .connecting, 201);
    _ = try Store.receipts.settle(&store, &rid2, .{
        .never_submitted = .{ .transport_error = "publickey rejected" },
    }, .{ .connected = true }, 210);
    rows = try Store.receipts.list(&store, arena, &rid2);
    try t.expectEqual(@as(?bool, true), rows[rows.len - 1].connected);

    // But it may not deny a connection for work that was handed over.
    const rid3 = testId("handedover");
    try Store.operations.create(&store, .{
        .request_id = &rid3,
        .server_id = 1,
        .server_name = "lease-host",
        .kind = .exec,
        .now = 300,
    });
    try Store.operations.advance(&store, &rid3, .connecting, 301);
    try Store.operations.advance(&store, &rid3, .submitted, 302);
    try t.expectError(error.ContradictoryEvidence, Store.receipts.settle(
        &store,
        &rid3,
        .{ .exited = .{ .exit_code = 0 } },
        .{ .connected = false },
        310,
    ));
}

test "gate: cancelling live work needs verified absence, not a signal" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_cancel_proof");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    const rid = testId("cancelproof");
    const request_id: []const u8 = &rid;
    try seedOperation(&store, request_id); // submitted

    // `local_abandon` is not available once work is out there: there is
    // something running that abandoning does not stop.
    try t.expectError(error.EvidenceDoesNotFit, Store.receipts.settle(
        &store,
        request_id,
        .{ .local_abandon = .{ .reason = "changed my mind" } },
        .{},
        400,
    ));

    // Sending TERM without confirming the process is gone has no expressible
    // form here — the only cancellation variant for live work requires
    // absence_verified_at and a verification_method. When absence cannot be
    // established the honest terminal is indeterminate.
    _ = try Store.receipts.settle(
        &store,
        request_id,
        .{ .indeterminate = .{
            .reason = "TERM sent, process still visible after grace period",
            .last_observed = .submitted,
        } },
        .{},
        410,
    );
    const op = (try Store.operations.get(&store, arena, request_id)).?;
    try t.expectEqual(op_state.Status.indeterminate, op.status);
    // ...and it keeps blocking the scope, which `cancelled` would not.
    try t.expect(op.status.blocksScope());
}

test "gate: secrets in resolution evidence do not reach the receipt" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_evidence_redaction");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    const rid = testId("redact");
    const request_id: []const u8 = &rid;
    try seedOperation(&store, request_id);
    _ = try Store.receipts.settle(
        &store,
        request_id,
        op_state.terminalForTransportLoss(.submitted, "eof"),
        .{},
        300,
    );

    // A reconciler pasting a command line into the note must not be how a
    // token lands in an append-only ledger.
    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .operator_override = .{
            .reason = "verified by hand with PGPASSWORD=hunter2 psql -h db",
            .by = "czykl",
        },
    }, 400)) == .resolved);

    const rows = try Store.receipts.list(&store, arena, request_id);
    const detail = rows[rows.len - 1].detail_json.?;
    try t.expect(std.mem.indexOf(u8, detail, "hunter2") == null);
    try t.expect(std.mem.indexOf(u8, detail, "[REDACTED]") != null);

    const op = (try Store.operations.get(&store, arena, request_id)).?;
    try t.expect(std.mem.indexOf(u8, op.resolution_evidence.?, "hunter2") == null);
}

test "gate: host key mismatch is reported, never auto-updated" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_host_pins");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    // Nothing known yet. This is the state every existing store is in: nothing
    // before the pinning slice ever recorded a host key, so `active` answering
    // null is what a first connection meets.
    try t.expect((try Store.host_pins.active(&store, arena, "h", 22, "ssh-ed25519")) == null);

    _ = try Store.host_pins.record(&store, .{
        .host = "h",
        .port = 22,
        .key_type = "ssh-ed25519",
        .fingerprint_sha256 = "SHA256:aaa",
        .trust_source = .first_use,
        .now = 100,
    });
    try t.expectEqualStrings(
        "SHA256:aaa",
        (try Store.host_pins.active(&store, arena, "h", 22, "ssh-ed25519")).?.fingerprint_sha256,
    );

    // A second active pin for the same key type is the schema's refusal, not a
    // convention: replacing one is `rotate`, which says so out loud.
    try t.expectError(error.Constraint, Store.host_pins.record(&store, .{
        .host = "h",
        .port = 22,
        .key_type = "ssh-ed25519",
        .fingerprint_sha256 = "SHA256:bbb",
        .trust_source = .explicit_pin,
        .now = 150,
    }));
    try t.expectEqualStrings(
        "SHA256:aaa",
        (try Store.host_pins.active(&store, arena, "h", 22, "ssh-ed25519")).?.fingerprint_sha256,
    );

    // A pin is keyed on the key *type* as well as the endpoint, so a second
    // type is a second pin and neither answers for the other.
    try t.expect((try Store.host_pins.active(&store, arena, "h", 22, "ssh-rsa")) == null);

    // Rotation is deliberate, keeps the old row, and links the two.
    _ = try Store.host_pins.rotate(&store, .{
        .host = "h",
        .port = 22,
        .key_type = "ssh-ed25519",
        .fingerprint_sha256 = "SHA256:bbb",
        .trust_source = .rotated,
        .now = 200,
    }, "server rebuilt");
    const rotated = (try Store.host_pins.active(&store, arena, "h", 22, "ssh-ed25519")).?;
    try t.expectEqualStrings("SHA256:bbb", rotated.fingerprint_sha256);
    try t.expectEqual(@as(usize, 1), (try Store.host_pins.list(&store, arena)).len);
    // The superseded row is still there, and `forEndpoint` is what shows it.
    try t.expectEqual(@as(usize, 2), (try Store.host_pins.forEndpoint(&store, arena, "h", 22)).len);

    // A revoked pin authorises nothing: `active` stops answering, so
    // `Ssh.judge` sees `not_pinned` and the connection is refused.
    try t.expect(try Store.host_pins.revoke(&store, rotated.id, "key was on a stolen backup", 300));
    try t.expect((try Store.host_pins.active(&store, arena, "h", 22, "ssh-ed25519")) == null);
    // And it does not vanish: withdrawing trust is a fact worth keeping.
    try t.expectEqual(@as(usize, 2), (try Store.host_pins.forEndpoint(&store, arena, "h", 22)).len);
    try t.expect(!try Store.host_pins.revoke(&store, rotated.id, "again", 310));
}

test "gate: the ledger records the time we looked, never a finish time we were not told" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_finished_at_honest");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    // A sentinel-only outcome: the exit code survived in the pane log, but
    // nothing on the host ever told us *when* the command ended.
    const silent_id = testId("silent");
    const silent: []const u8 = &silent_id;
    try seedOperation(&store, silent);
    _ = try Store.receipts.settle(&store, silent, .{ .exited = .{ .exit_code = 0 } }, .{}, 900);

    const silent_terminal = try terminalRow(&store, arena, silent);
    // `now` would have been a plausible-looking answer and a false one: it
    // says when we read the log, which on a job polled hours later is hours
    // wrong. A null here is what lets `job status` say "unknown" instead.
    try t.expectEqual(@as(?i64, null), silent_terminal.finished_at);
    try t.expectEqual(@as(i64, 900), silent_terminal.observed_at);

    // With a real remote clock reading, it is kept exactly as given — the
    // point is not to be shy about finish times, it is to only report ones
    // the host actually reported.
    const timed_id = testId("timed");
    const timed: []const u8 = &timed_id;
    try Store.operations.create(&store, .{
        .request_id = timed,
        .server_id = 1,
        .server_name = "race",
        .kind = .job,
        .now = 100,
    });
    try Store.operations.advance(&store, timed, .connecting, 101);
    try Store.operations.advance(&store, timed, .submitted, 102);
    _ = try Store.receipts.settle(
        &store,
        timed,
        .{ .exited = .{ .exit_code = 0 } },
        .{ .finished_at = 852 },
        900,
    );
    const timed_terminal = try terminalRow(&store, arena, timed);
    try t.expectEqual(@as(?i64, 852), timed_terminal.finished_at);
    try t.expectEqual(@as(i64, 900), timed_terminal.observed_at);
}

fn terminalRow(store: *Store, arena: std.mem.Allocator, request_id: []const u8) !Store.receipts.Row {
    for (try Store.receipts.list(store, arena, request_id)) |row| {
        if (row.is_terminal) return row;
    }
    return error.NoTerminalEvent;
}
