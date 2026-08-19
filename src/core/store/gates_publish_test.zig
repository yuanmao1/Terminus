//! Judging a rename nobody watched.
//!
//! A push issues its rename and the connection drops. The checkpoint parks in
//! `indeterminate_publish`, and all that is left is evidence about the
//! destination, taken later, by something that did not see the act. These gates
//! decide what such evidence may conclude.
//!
//! The line they hold is that adjudication is the last word on whether the
//! *rename landed*, and never a route to a verdict the transfer's own record
//! does not support. So: a driver may not pass its own verdict on a rename
//! nobody watched; evidence that cannot judge the rename resolves nothing at
//! all; a reading that will not say how it was taken settles nothing; a hash of
//! the destination cannot settle a transfer whose record says it never
//! published; and a destination reading cannot re-decide a publish that is
//! already decided.
//!
//! The three digest combinations — declared and verified, declared only,
//! neither — are the subject of most of the file, one column at a time. A
//! transfer walks the same edges to `indeterminate_publish` in all three, and
//! what a reconciler may then conclude is completely different in each, which is
//! why `seedUnjudgedPublishDigests` sets the two columns independently.

const std = @import("std");
const Store = @import("Store.zig");
const op_state = @import("op_state.zig");

// The shared fixtures. Aliased under their own names so a gate reads the
// same here as it did when every gate was in one file.
const fixtures = @import("gates_fixtures.zig");
const Scratch = fixtures.Scratch;
const locked = fixtures.locked;
const testId = fixtures.testId;
const seedOperationOfKind = fixtures.seedOperationOfKind;
const seedCheckpoint = fixtures.seedCheckpoint;
const driveToPublished = fixtures.driveToPublished;
const seedUnjudgedPublish = fixtures.seedUnjudgedPublish;
const seedUnjudgedPublishDigests = fixtures.seedUnjudgedPublishDigests;
const seedTransferOperation = fixtures.seedTransferOperation;
const countKind = fixtures.countKind;

test "gate: a driver may not pass its own verdict on a rename nobody watched" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_driver_cannot_adjudicate");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    // Parked, and carrying a verified digest that agrees with the declared one
    // — so every conjunct `published` adds is satisfied and the only thing left
    // to refuse the write is who is asking.
    const rid = testId("drvadj");
    const request_id: []const u8 = &rid;
    const id = try seedUnjudgedPublish(
        &store,
        request_id,
        "/srv/app/out.bin",
        "/srv/app/out.bin.part",
        "abc123",
    );
    const before = (try Store.transfers.get(&store, arena, id)).?;

    // The three edges out of the unjudged state belong to `adjudicateLocked`,
    // which reaches them only from `receipts.resolve` and only with evidence
    // that can speak about a rename. `setState` is the transfer driver's API
    // and it holds the owning request id — it has to, to write anything — so
    // without the route split it could record any of the three here, on the one
    // row that exists *because* nobody saw the rename. `published` written that
    // way is the exact fact `publishAdjudication` refuses an operator override
    // permission to write, obtained one module down by asking for it.
    for ([_]Store.transfers.State{ .published, .completed_unverified, .failed_publish }) |verdict| {
        try t.expectError(
            error.CheckpointAwaitingAdjudication,
            Store.transfers.setState(&store, id, request_id, verdict, null, 200),
        );
    }
    const after_refusals = (try Store.transfers.get(&store, arena, id)).?;
    try t.expectEqual(Store.transfers.State.indeterminate_publish, after_refusals.state);
    try t.expectEqual(before.updated_at, after_refusals.updated_at);

    // And the refusal is about the writer, not about the row: the same move,
    // asked for by the writer it belongs to, lands.
    try locked(&store, Store.transfers.adjudicateLocked, .{ &store, id, request_id, .published, null, 201 });
    try t.expectEqual(
        Store.transfers.State.published,
        (try Store.transfers.get(&store, arena, id)).?.state,
    );

    // The mirror. A resolution's authority is over a parked row and nothing
    // else; aimed at a transfer still mid-rename it is an ordinary state change
    // wearing a resolution's clothes, and it is refused under its own name so
    // the caller learns the id was wrong rather than the state.
    const live = testId("drvlive");
    const live_id: []const u8 = &live;
    const live_cp = try seedCheckpoint(&store, live_id, "/srv/app/two.bin", "/srv/app/two.bin.part");
    var clock: i64 = 300;
    for ([_]Store.transfers.State{ .probing, .transferring, .verifying, .publishing }) |step| {
        clock += 1;
        try Store.transfers.setState(&store, live_cp, live_id, step, null, clock);
    }
    try t.expectError(
        error.CheckpointNotAwaitingAdjudication,
        locked(&store, Store.transfers.adjudicateLocked, .{ &store, live_cp, live_id, .failed_publish, null, 310 }),
    );
    try t.expectEqual(
        Store.transfers.State.publishing,
        (try Store.transfers.get(&store, arena, live_cp)).?.state,
    );

    // ...while the driver's own route to that same target is open, which is
    // what stops the rule above from being "nobody may write `failed_publish`".
    try Store.transfers.setState(&store, live_cp, live_id, .failed_publish, "the rename failed", 311);
    try t.expectEqual(
        Store.transfers.State.failed_publish,
        (try Store.transfers.get(&store, arena, live_cp)).?.state,
    );
}

test "gate: adjudicating a resolution releases the destination it was holding" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_adjudicate_publish");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    const rid = testId("adjpub");
    const request_id: []const u8 = &rid;
    const id = try seedUnjudgedPublish(
        &store,
        request_id,
        "/srv/app/out.bin",
        "/srv/app/out.bin.part",
        "abc123",
    );

    // Before adjudication the path is claimed against everyone, which is
    // correct while nobody knows what is on it — and used to be permanent.
    // `indeterminate_publish` had no successor, is not adoptable, and no code
    // anywhere deletes a checkpoint row, so this refusal was the last word on
    // that destination for the life of the database.
    const rival = testId("adjrival");
    const rival_id: []const u8 = &rival;
    try Store.operations.create(&store, .{
        .request_id = rival_id,
        .server_id = 1,
        .server_name = "race",
        .kind = .transfer_push,
        .now = 200,
    });
    const rival_opts: Store.transfers.CreateOptions = .{
        .request_id = rival_id,
        .direction = .push,
        .dest_side = .{ .server = 1 },
        .dest_path = "/srv/app/out.bin",
        .partial_path = "/srv/app/out.bin.rival-part",
        .source = .{ .local_file = .{ .path = "./out.bin" } },
        .chunk_size = 100,
        .now = 201,
    };
    try t.expectError(error.DestinationHeld, Store.transfers.create(&store, rival_opts));

    // A reconciler reads the destination and finds exactly the file the
    // transfer committed to publishing before it sent anything. That settles
    // both halves at once: the operation completed, and the rename landed.
    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .filesystem_effect = .{
            .side = .remote,
            .path = "/srv/app/out.bin",
            .sha256 = "abc123",
        },
    }, 210)) == .resolved);

    const judged = (try Store.transfers.get(&store, arena, id)).?;
    try t.expectEqual(Store.transfers.State.published, judged.state);
    try t.expectEqual(
        Store.op_state.ResolvedStatus.completed,
        (try Store.operations.get(&store, arena, request_id)).?.resolved_status.?,
    );

    // And the destination is free, which is the whole point: a `published`
    // checkpoint does not hold its path.
    _ = try Store.transfers.create(&store, rival_opts);
}

test "gate: evidence that cannot judge the rename resolves nothing at all" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_adjudicate_undetermined");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    const rid = testId("adjnone");
    const request_id: []const u8 = &rid;
    const id = try seedUnjudgedPublish(
        &store,
        request_id,
        "/srv/app/out.bin",
        "/srv/app/out.bin.part",
        "abc123",
    );

    // An operator override is a decision about the *operation*, carrying no
    // reading of the destination. A resolution lifts the scope barrier, so
    // taking it and leaving the artifact unjudged would free the operation
    // while the checkpoint went on holding its path against every later
    // transfer — and writing `published` from it would be a fabricated fact
    // about a file on somebody's disk. Both halves are refused together.
    try t.expectError(error.PublishAdjudicationUndetermined, Store.receipts.resolve(
        &store,
        arena,
        request_id,
        .completed,
        .{ .operator_override = .{ .reason = "I am sure it landed", .by = "tester" } },
        210,
    ));

    // Nothing moved: not the ledger, not the trail, not the checkpoint.
    const unresolved = (try Store.operations.get(&store, arena, request_id)).?;
    try t.expectEqual(Store.op_state.Status.indeterminate, unresolved.status);
    try t.expectEqual(@as(?Store.op_state.ResolvedStatus, null), unresolved.resolved_status);
    try t.expectEqual(@as(usize, 0), try countKind(&store, arena, request_id, "reconcile"));
    try t.expectEqual(
        Store.transfers.State.indeterminate_publish,
        (try Store.transfers.get(&store, arena, id)).?.state,
    );

    // A supervisor's report of the process cannot judge the rename either, and
    // it is the more tempting one: exit 0 from the thing that ran the rename
    // looks like proof. It is compatible with a rename that landed and with one
    // whose reply was the thing that got lost, which is why the row is parked in
    // the first place.
    //
    // That reasoning is now enforced a step earlier than this gate's subject: a
    // report about a process cannot speak about a transfer *at all*, so it is
    // refused by kind before there is any rename to judge. Asserted here rather
    // than dropped, because the two refusals are one rule seen from two
    // distances, and a gate that stopped mentioning this evidence would leave
    // the tempting case unstated.
    const by_report = try Store.receipts.resolve(
        &store,
        arena,
        request_id,
        .completed,
        .{ .supervisor_report = .{ .reported = .completed, .detail = "wrapper exited 0" } },
        211,
    );
    try t.expectEqualStrings("transfer_push", by_report.evidence_wrong_kind.operation_kind);
    try t.expectEqualStrings("supervisor_report", by_report.evidence_wrong_kind.evidence_kind);
    try t.expectEqual(
        @as(?Store.op_state.ResolvedStatus, null),
        (try Store.operations.get(&store, arena, request_id)).?.resolved_status,
    );
    try t.expectEqual(
        Store.transfers.State.indeterminate_publish,
        (try Store.transfers.get(&store, arena, id)).?.state,
    );

    // And the control that keeps the two refusals from being satisfied by
    // refusing everything: a reading of the destination settles it.
    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .filesystem_effect = .{
            .side = .remote,
            .path = "/srv/app/out.bin",
            .sha256 = "abc123",
        },
    }, 212)) == .resolved);
}

test "gate: a destination that does not hold the artifact can be said so" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_absence_evidence");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    // Before this evidence existed, `publishAdjudication` mapped exactly one
    // variant to a state and everything else to null. A parked publish whose
    // artifact turned out to be *missing* therefore had no admissible answer at
    // all: `failed_publish` was underivable, the row stayed
    // `indeterminate_publish`, and it held its destination for the life of the
    // database. The positive answer had a route and the negative one did not.
    const rid = testId("absent");
    const request_id: []const u8 = &rid;
    const id = try seedUnjudgedPublish(
        &store,
        request_id,
        "/srv/app/gone.bin",
        "/srv/app/gone.bin.part",
        "abc123",
    );

    // Wrong path. An empty path somewhere else is not this transfer's
    // destination being empty, and without the comparison a reconciler could
    // nominate whichever path it liked and call the transfer failed.
    const wrong_path = try Store.receipts.resolve(&store, arena, request_id, .failed, .{
        .destination_absent = .{
            .side = .remote,
            .path = "/tmp/gone.bin",
            .verification_method = "stat => ENOENT",
        },
    }, 210);
    try t.expect(wrong_path == .absence_wrong_destination);
    try t.expectEqualStrings("/tmp/gone.bin", wrong_path.absence_wrong_destination.observed.path);
    try t.expectEqualStrings("/srv/app/gone.bin", wrong_path.absence_wrong_destination.committed.?.path);

    // Wrong side. A push publishes on the host; finding nothing at that path on
    // this machine says nothing about the host, and the two paths are equal, so
    // only the side can have refused it.
    const wrong_side = try Store.receipts.resolve(&store, arena, request_id, .failed, .{
        .destination_absent = .{
            .side = .local,
            .path = "/srv/app/gone.bin",
            .verification_method = "stat => ENOENT",
        },
    }, 211);
    try t.expect(wrong_side == .absence_wrong_destination);
    try t.expectEqual(
        Store.transfers.Side.remote,
        wrong_side.absence_wrong_destination.committed.?.side,
    );

    // An absence cannot say the transfer *worked*, whatever it names.
    const overreach = try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .destination_absent = .{
            .side = .remote,
            .path = "/srv/app/gone.bin",
            .verification_method = "stat => ENOENT",
        },
    }, 212);
    try t.expectEqualStrings("destination_absent", overreach.evidence_does_not_support.evidence_kind);

    // Three refusals, nothing written by any of them.
    try t.expectEqual(
        @as(?Store.op_state.ResolvedStatus, null),
        (try Store.operations.get(&store, arena, request_id)).?.resolved_status,
    );
    try t.expectEqual(@as(usize, 0), try countKind(&store, arena, request_id, "reconcile"));
    try t.expectEqual(
        Store.transfers.State.indeterminate_publish,
        (try Store.transfers.get(&store, arena, id)).?.state,
    );

    // The reading that does name this transfer's destination settles both
    // halves: the operation `failed`, and the rename did not put the artifact
    // where it was going.
    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .failed, .{
        .destination_absent = .{
            .side = .remote,
            .path = "/srv/app/gone.bin",
            .verification_method = "stat => ENOENT",
        },
    }, 213)) == .resolved);
    try t.expectEqual(
        Store.transfers.State.failed_publish,
        (try Store.transfers.get(&store, arena, id)).?.state,
    );
    try t.expectEqual(
        Store.op_state.ResolvedStatus.failed,
        (try Store.operations.get(&store, arena, request_id)).?.resolved_status.?,
    );

    // And it released nothing. A failure keeps its destination until somebody
    // supersedes it — there is a partial next to that path and a half-told
    // story about what is at it, and the next transfer aimed there has to be
    // let through deliberately rather than walk into the leftovers.
    const rival = testId("absrival");
    const rival_id: []const u8 = &rival;
    try seedTransferOperation(&store, rival_id, .transfer_push, 1);
    try t.expectError(error.DestinationHeld, Store.transfers.create(&store, .{
        .request_id = rival_id,
        .direction = .push,
        .dest_side = .{ .server = 1 },
        .dest_path = "/srv/app/gone.bin",
        .partial_path = "/srv/app/gone.bin.rival",
        .source = .{ .local_file = .{ .path = "./out.bin", .sha256 = "aaaa" } },
        .chunk_size = 100,
        .now = 220,
    }));

    // The receipt records a reading with the method attached, not a verdict on
    // its own. "It is not there" is a conclusion; a receipt carrying it without
    // saying how it was established cannot be argued with by anyone who doubts
    // it later.
    const trail = try Store.receipts.list(&store, arena, request_id);
    const reconcile = trail[trail.len - 1].detail_json.?;
    try t.expect(std.mem.indexOf(u8, reconcile, "destination_absent") != null);
    try t.expect(std.mem.indexOf(u8, reconcile, "stat => ENOENT") != null);
    try t.expect(std.mem.indexOf(u8, reconcile, "\"mechanical\":true") != null);
    // Mechanical, and therefore not stamped as somebody's decision — a reading
    // filed alongside an operator's opinion would make the two indistinguishable
    // in the one place that has to tell them apart.
    try t.expectEqual(@as(?[]const u8, null), trail[trail.len - 1].error_code);
}

test "gate: a rename judged from the destination is not blocked by the column the dead process never wrote" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_wedge_declared");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    // The wedge, exactly as it occurred. A transfer declares the digest its
    // artifact will hash to, gets as far as issuing the rename, and is killed
    // before it records what it read back. Recovery normalises it to
    // `indeterminate_publish`, which is right — the rename may have landed.
    //
    // An operator then goes and hashes the file at the destination and it is the
    // declared digest, byte for byte. `publishAdjudication` says `published`.
    // And the transition refused, because `published` requires
    // `verified_sha256 IS NOT NULL` and the column is null: the process that
    // would have written it is dead, `acceptsVerifiedHash` excludes the parked
    // state so nothing may write it now, `completed_unverified` refuses a row
    // whose digest agrees, and `failed_publish` would be a lie about a file that
    // is demonstrably there. Every exit closed, by paperwork, on the one row
    // where the reconciler's reading is *better* evidence than the column — it
    // was taken off the published artifact and compared against a promise made
    // before a byte moved.
    const rid = testId("wedgedec");
    const request_id: []const u8 = &rid;
    const id = try seedUnjudgedPublishDigests(
        &store,
        request_id,
        "/srv/app/late.bin",
        "/srv/app/late.bin.part",
        "deadbeef",
        null,
    );
    try t.expectEqual(
        @as(?[]const u8, null),
        (try Store.transfers.get(&store, arena, id)).?.verified_sha256,
    );

    // The weaker reading is refused first, and it has to be: "a file is there"
    // would settle this row `completed_unverified` while a stronger reading was
    // available from the same look, and `completed_unverified` is a permanent
    // claim that nothing checked the bytes.
    const too_weak = try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .destination_present_unverified = .{
            .side = .remote,
            .path = "/srv/app/late.bin",
            .verification_method = "stat => present, 4096 bytes",
        },
    }, 210);
    try t.expect(too_weak == .unverified_reading_when_digest_declared);
    try t.expectEqualStrings("deadbeef", too_weak.unverified_reading_when_digest_declared.expected_sha256);
    try t.expectEqual(
        Store.transfers.State.indeterminate_publish,
        (try Store.transfers.get(&store, arena, id)).?.state,
    );

    // A hash that is not the declared one proves no delivery, and this variant
    // proves delivery or nothing. It stays a loud refusal — the control for the
    // gate below, which admits the *same reading* offered as what it is. Two
    // digests that disagree can be read two ways, "the bytes I promised are
    // there" and "the wrong bytes are there", and only the second is true here;
    // relaxing this comparison would let the first be claimed by the same call.
    const contradicts = try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .filesystem_effect = .{
            .side = .remote,
            .path = "/srv/app/late.bin",
            .sha256 = "0000ffff",
        },
    }, 211);
    try t.expect(contradicts == .effect_hash_unproven);
    try t.expectEqualStrings("deadbeef", contradicts.effect_hash_unproven.expected.?.sha256);
    try t.expectEqual(
        @as(?[]const u8, null),
        (try Store.transfers.get(&store, arena, id)).?.verified_sha256,
    );

    // And the reading that matches the declaration gets through — which before
    // this it did not.
    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .filesystem_effect = .{
            .side = .remote,
            .path = "/srv/app/late.bin",
            .sha256 = "deadbeef",
        },
    }, 212)) == .resolved);
    const judged = (try Store.transfers.get(&store, arena, id)).?;
    try t.expectEqual(Store.transfers.State.published, judged.state);
    // The reading is *kept*, not merely used. The column is what a later reader
    // consults to know this transfer's result was checked at all, and a
    // `published` row with a null digest would contradict the invariant the
    // transition enforces on everybody else.
    try t.expectEqualStrings("deadbeef", judged.verified_sha256.?);
    try t.expectEqual(
        Store.op_state.ResolvedStatus.completed,
        (try Store.operations.get(&store, arena, request_id)).?.resolved_status.?,
    );

    // Judged means released: the next transfer aimed at that path is no longer
    // refused by a row nobody could decide.
    const rival = testId("wedgeriv");
    const rival_id: []const u8 = &rival;
    try seedTransferOperation(&store, rival_id, .transfer_push, 1);
    _ = try Store.transfers.create(&store, .{
        .request_id = rival_id,
        .direction = .push,
        .dest_side = .{ .server = 1 },
        .dest_path = "/srv/app/late.bin",
        .partial_path = "/srv/app/late.bin.rival",
        .source = .{ .local_file = .{ .path = "./out.bin" } },
        .chunk_size = 100,
        .now = 220,
    });
}

test "gate: an artifact at the destination that is the wrong artifact is a hash mismatch that keeps the path" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_wedge_contradicts");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    // The last `(crash point, state)` pair with no route out. A transfer
    // declares the digest its artifact will hash to, is killed mid-rename, and
    // parks in `indeterminate_publish`. An operator goes and hashes what is at
    // the destination — and it is *not* the declared digest. Every reading
    // refused that: `filesystem_effect` because the hash does not match,
    // `destination_present_unverified` because a digest was declared,
    // `destination_absent` because the file is demonstrably there, and an
    // override because it cannot adjudicate. The row stayed parked for the life
    // of the database, holding its destination, with its operation unresolvable
    // beside it.
    const rid = testId("wrongart");
    const request_id: []const u8 = &rid;
    const id = try seedUnjudgedPublishDigests(
        &store,
        request_id,
        "/srv/app/wrong.bin",
        "/srv/app/wrong.bin.part",
        "deadbeef",
        null,
    );

    // The reading that says what was actually seen. The verdict is `failed` and
    // the checkpoint lands on `failed_hash_mismatch`, whose literal meaning —
    // the digest did not match — is exactly what was proven.
    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .failed, .{
        .destination_present_contradicting = .{
            .side = .remote,
            .path = "/srv/app/wrong.bin",
            .sha256 = "0000ffff",
            .verification_method = "sha256sum => 0000ffff",
        },
    }, 210)) == .resolved);

    const judged = (try Store.transfers.get(&store, arena, id)).?;
    try t.expectEqual(Store.transfers.State.failed_hash_mismatch, judged.state);
    try t.expectEqual(
        Store.op_state.ResolvedStatus.failed,
        (try Store.operations.get(&store, arena, request_id)).?.resolved_status.?,
    );

    // Both digests are on the record, which is the whole content of this
    // verdict: one of them alone is half a fact. The one that was *read* is in
    // the evidence on the reconcile event; the one that was *promised* is
    // beside it in `declaredSha256`, read off the checkpoint by `resolve`
    // rather than supplied by the caller — a caller echoing a value back out of
    // this database would be comparing a number with itself.
    const trail = try Store.receipts.list(&store, arena, request_id);
    const reconcile = trail[trail.len - 1].detail_json.?;
    try t.expectEqualStrings("reconcile", trail[trail.len - 1].kind);
    try t.expect(std.mem.indexOf(u8, reconcile, "destination_present_contradicting") != null);
    try t.expect(std.mem.indexOf(u8, reconcile, "0000ffff") != null);
    try t.expect(std.mem.indexOf(u8, reconcile, "\"declaredSha256\":\"deadbeef\"") != null);
    try t.expect(std.mem.indexOf(u8, reconcile, "sha256sum => 0000ffff") != null);
    // Mechanical: something looked and reported what it read. Filing it as a
    // decision would put a reading next to an operator's opinion in the one
    // place that has to tell them apart.
    try t.expect(std.mem.indexOf(u8, reconcile, "\"mechanical\":true") != null);
    try t.expectEqual(@as(?[]const u8, null), trail[trail.len - 1].error_code);

    // The declared digest is untouched, and the column that means "what is at
    // the destination" now holds the reading that was taken there. See
    // `transfers.adjudicateLocked`: the two digests on a parked row are of
    // different bytes — a driver's is of the staged file before the rename,
    // this one is of what is at the destination after it — and the state
    // records the second, so the column has to hold the second.
    try t.expectEqualStrings("deadbeef", judged.expected_sha256.?);
    try t.expectEqualStrings("0000ffff", judged.verified_sha256.?);
    // The property those two columns exist to make checkable, and the one this
    // file asserted in three comments while nothing enforced it: a row whose
    // whole content is "the digest did not match" must not be a row whose
    // columns say it did.
    try t.expect(!std.mem.eql(u8, judged.expected_sha256.?, judged.verified_sha256.?));

    // And the property that makes a *failure* verdict safe to reach from a
    // *present* artifact: the destination is still held. The wrong bytes are
    // sitting at that path and the next transfer aimed there is refused rather
    // than clobbering them. If this released the path, the decision would be
    // "we found the wrong artifact, so go ahead and overwrite it unasked".
    try t.expect(Store.transfers.State.failed_hash_mismatch.holdsDestination());
    const rival = testId("wrongriv");
    const rival_id: []const u8 = &rival;
    try seedTransferOperation(&store, rival_id, .transfer_push, 1);
    const rival_opts: Store.transfers.CreateOptions = .{
        .request_id = rival_id,
        .direction = .push,
        .dest_side = .{ .server = 1 },
        .dest_path = "/srv/app/wrong.bin",
        .partial_path = "/srv/app/wrong.bin.rival",
        .source = .{ .local_file = .{ .path = "./out.bin" } },
        .chunk_size = 100,
        .now = 220,
    };
    try t.expectError(error.DestinationHeld, Store.transfers.create(&store, rival_opts));

    // The operator's exit, and the only one: having looked at the bytes that
    // are there, they release the path deliberately. That is the same two-step
    // every other failure gets, which is the point of adjudicating to a failure
    // rather than inventing a state of its own.
    try store.db.exec("BEGIN IMMEDIATE");
    try Store.transfers.supersedeLocked(&store, id, rival_id, 230);
    try store.db.exec("COMMIT");
    try t.expectEqual(
        Store.transfers.State.superseded,
        (try Store.transfers.get(&store, arena, id)).?.state,
    );
    _ = try Store.transfers.create(&store, rival_opts);
}

test "gate: a hash mismatch never lands on a row whose columns say the digest agreed" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_mismatch_selfconsistent");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    // The documented happy path, interrupted at the one point that leaves both
    // digest columns filled and agreeing. A transfer declares `deadbeef`,
    // reaches `verifying`, hashes the *staged* bytes and gets `deadbeef`,
    // records it, moves to `publishing`, and is killed mid-rename. The
    // normalisation to `indeterminate_publish` deliberately keeps the digest —
    // the bytes went to a rename and nobody may truncate them now — so the
    // parked row reads `expected = verified = deadbeef`.
    //
    // A reconciler then hashes the destination and finds a truncated file. The
    // verdict is `failed_hash_mismatch`, and until the reading reached the
    // column that produced a row saying, in its own columns, that the digest
    // agreed — the exact row `acceptsVerifiedHash`, `recordVerifiedHash` and
    // `adjudicateLocked` each said could not exist. Three comments, no
    // enforcement.
    const rid = testId("bothset");
    const request_id: []const u8 = &rid;
    const id = try seedUnjudgedPublishDigests(
        &store,
        request_id,
        "/srv/app/both.bin",
        "/srv/app/both.bin.part",
        "deadbeef",
        "deadbeef",
    );
    const parked = (try Store.transfers.get(&store, arena, id)).?;
    try t.expectEqualStrings("deadbeef", parked.expected_sha256.?);
    try t.expectEqualStrings("deadbeef", parked.verified_sha256.?);

    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .failed, .{
        .destination_present_contradicting = .{
            .side = .remote,
            .path = "/srv/app/both.bin",
            .sha256 = "0000ffff",
            .verification_method = "sha256sum => 0000ffff (truncated)",
        },
    }, 210)) == .resolved);

    const judged = (try Store.transfers.get(&store, arena, id)).?;
    try t.expectEqual(Store.transfers.State.failed_hash_mismatch, judged.state);
    // The state and the columns say the same thing. The pre-rename digest is
    // gone from the working record and the destination's is in its place,
    // which is what the state is a statement about.
    try t.expectEqualStrings("deadbeef", judged.expected_sha256.?);
    try t.expectEqualStrings("0000ffff", judged.verified_sha256.?);
    try t.expect(!std.mem.eql(u8, judged.expected_sha256.?, judged.verified_sha256.?));

    // It is not lost, either: the reconcile event carries the reading that was
    // taken and the digest it contradicts, so the trail still has both numbers
    // the verdict rests on.
    const trail = try Store.receipts.list(&store, arena, request_id);
    const reconcile = trail[trail.len - 1].detail_json.?;
    try t.expect(std.mem.indexOf(u8, reconcile, "0000ffff") != null);
    try t.expect(std.mem.indexOf(u8, reconcile, "\"declaredSha256\":\"deadbeef\"") != null);

    // And the conjunct is real rather than a consequence of the write above:
    // aimed at the same parked shape with no reading to put in the column, the
    // transition is refused by name instead of landing a self-contradictory
    // row. This is the call `adjudicateLocked` would make if a future verdict
    // forgot to carry its reading.
    const bare = testId("bareadj");
    const bare_id: []const u8 = &bare;
    const bare_cp = try seedUnjudgedPublishDigests(
        &store,
        bare_id,
        "/srv/app/bare.bin",
        "/srv/app/bare.bin.part",
        "deadbeef",
        "deadbeef",
    );
    try store.db.exec("BEGIN IMMEDIATE");
    try t.expectError(error.HashMismatchWithAgreeingDigest, Store.transfers.adjudicateLocked(
        &store,
        bare_cp,
        bare_id,
        .failed_hash_mismatch,
        null,
        220,
    ));
    try store.db.exec("ROLLBACK");
    try t.expectEqual(
        Store.transfers.State.indeterminate_publish,
        (try Store.transfers.get(&store, arena, bare_cp)).?.state,
    );
}

test "gate: a hash of the destination cannot settle a transfer that recorded it never published" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_effect_reading_state");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    // The sequence, and it is an ordinary one. A push declares that its
    // artifact will hash to `deadbeef`, probes the destination, and finds it
    // occupied — which for a re-push is most often the *previous delivery of
    // the same artifact*. The driver records `failed_clobber_conflict`; the
    // connection then drops before the operation is settled, so it normalises
    // to `indeterminate`.
    //
    // An operator hashes what is at the destination. It is `deadbeef`, because
    // it is the same artifact. All three halves of `filesystem_effect` match —
    // side, path, digest — and until the state was asked, that settled the
    // operation `completed`: the scope barrier lifted and the receipt said this
    // transfer had delivered its artifact, beside a checkpoint saying it never
    // wrote a byte to that path and still holding it against everyone.
    //
    // The digest binds the reading to the *declaration*. Only the checkpoint's
    // own state says whether this transfer ever put anything there.
    const rid = testId("clobber");
    const request_id: []const u8 = &rid;
    try seedTransferOperation(&store, request_id, .transfer_push, 1);
    const id = try Store.transfers.create(&store, .{
        .request_id = request_id,
        .direction = .push,
        .dest_side = .{ .server = 1 },
        .dest_path = "/srv/app/occupied.bin",
        .partial_path = "/srv/app/occupied.bin.part",
        .source = .{ .local_file = .{ .path = "./out.bin" } },
        .chunk_size = 100,
        .now = 110,
    });
    try Store.transfers.recordExpectedHash(&store, id, request_id, "deadbeef", 111);
    try Store.operations.advance(&store, request_id, .submitted, 112);
    try Store.transfers.setState(&store, id, request_id, .probing, null, 113);
    try Store.transfers.setState(&store, id, request_id, .failed_clobber_conflict, "the destination is occupied", 114);
    _ = try Store.receipts.settle(&store, request_id, .{ .indeterminate = .{
        .reason = "the connection dropped after the probe reported",
        .last_observed = .submitted,
    } }, .{}, 115);

    const refused = try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .filesystem_effect = .{ .side = .remote, .path = "/srv/app/occupied.bin", .sha256 = "deadbeef" },
    }, 200);
    try t.expect(refused == .effect_reading_against_recorded_outcome);
    // Not `effect_hash_unproven`: the hash *was* proven, and telling the
    // operator their digest did not match would send them to re-hash a file
    // that is exactly what they said it was. The state is what is wrong.
    try t.expectEqualStrings(
        "failed_clobber_conflict",
        refused.effect_reading_against_recorded_outcome.state,
    );
    try t.expectEqualStrings(
        "/srv/app/occupied.bin",
        refused.effect_reading_against_recorded_outcome.observed.path,
    );

    // Nothing was written: not the resolution, not a reconcile event, and not
    // the checkpoint — which is still holding the path, which is the whole
    // reason the refusal matters.
    try t.expectEqual(
        @as(?op_state.ResolvedStatus, null),
        (try Store.operations.get(&store, arena, request_id)).?.resolved_status,
    );
    try t.expectEqual(@as(usize, 0), try countKind(&store, arena, request_id, "reconcile"));
    try t.expectEqual(
        Store.transfers.State.failed_clobber_conflict,
        (try Store.transfers.get(&store, arena, id)).?.state,
    );

    // Every state that is not one of the three the reading may corroborate is
    // refused the same way, and the three are refused nothing — asserted
    // against the predicate rather than by listing states here, so a new
    // checkpoint state is classified in one place and checked in this one.
    inline for (@typeInfo(Store.transfers.State).@"enum".fields) |field| {
        const s: Store.transfers.State = @enumFromInt(field.value);
        switch (s) {
            .published, .completed_unverified, .indeterminate_publish => try t.expect(s.renameMayHaveLanded()),
            else => try t.expect(!s.renameMayHaveLanded()),
        }
    }

    // The control that stops this gate being satisfied by a transfer nothing
    // could settle: the same reading against a row that *did* publish resolves.
    const good = testId("clobok");
    const good_id: []const u8 = &good;
    try seedTransferOperation(&store, good_id, .transfer_push, 1);
    const good_cp = try Store.transfers.create(&store, .{
        .request_id = good_id,
        .direction = .push,
        .dest_side = .{ .server = 1 },
        .dest_path = "/srv/app/delivered.bin",
        .partial_path = "/srv/app/delivered.bin.part",
        .source = .{ .local_file = .{ .path = "./out.bin" } },
        .chunk_size = 100,
        .now = 110,
    });
    try Store.transfers.recordExpectedHash(&store, good_cp, good_id, "deadbeef", 111);
    try Store.operations.advance(&store, good_id, .submitted, 112);
    try driveToPublished(&store, good_cp, good_id, "deadbeef");
    _ = try Store.receipts.settle(&store, good_id, .{ .indeterminate = .{
        .reason = "the reply was lost after the artifact was published",
        .last_observed = .submitted,
    } }, .{}, 160);
    try t.expect((try Store.receipts.resolve(&store, arena, good_id, .completed, .{
        .filesystem_effect = .{ .side = .remote, .path = "/srv/app/delivered.bin", .sha256 = "deadbeef" },
    }, 200)) == .resolved);
}

test "gate: a transfer that declared a digest cannot be recorded as unverified" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_unverified_declared");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    // `completed_unverified` means the transfer had nothing to check its result
    // against — and it *releases the destination hold*, which is what makes
    // getting it wrong expensive: the operation settles `completed`, the path
    // stops being claimed, and the next `create` aimed there is an ordinary
    // overwrite. A transfer that named the digest that would prove it landed,
    // before it sent a byte, had something to check against; recording it
    // unverified is that check being skipped on the path that decides whether
    // an artifact counts as delivered.
    //
    // `receipts.resolve` refused exactly this shape already
    // (`unverified_reading_when_digest_declared`), so the same act was refused
    // when it arrived through a crash and admitted when it arrived through the
    // driver's own route — the lenient one being the route taken every time.
    try t.expect(!Store.transfers.State.completed_unverified.holdsDestination());

    const rid = testId("declunv");
    const request_id: []const u8 = &rid;
    try seedTransferOperation(&store, request_id, .transfer_push, 1);
    const id = try Store.transfers.create(&store, .{
        .request_id = request_id,
        .direction = .push,
        .dest_side = .{ .server = 1 },
        .dest_path = "/srv/app/declared.bin",
        .partial_path = "/srv/app/declared.bin.part",
        .source = .{ .local_file = .{ .path = "./out.bin" } },
        .chunk_size = 100,
        .now = 110,
    });
    try Store.transfers.recordExpectedHash(&store, id, request_id, "deadbeef", 111);
    try Store.operations.advance(&store, request_id, .submitted, 112);
    for ([_]Store.transfers.State{ .probing, .transferring, .verifying, .publishing }) |step|
        try Store.transfers.setState(&store, id, request_id, step, null, 113);

    try t.expectError(
        error.CompletedUnverifiedHasDeclaredHash,
        Store.transfers.setState(&store, id, request_id, .completed_unverified, null, 120),
    );
    // Refused, not narrowed to something else: the row is where it was, still
    // holding the destination.
    try t.expectEqual(
        Store.transfers.State.publishing,
        (try Store.transfers.get(&store, arena, id)).?.state,
    );

    // The two refusals this target can give are told apart, because they send a
    // driver two different ways: one has read a digest and should record
    // `published`, the other declared one and should not be here at all.
    try Store.transfers.recordVerifiedHash(&store, id, request_id, "deadbeef", 121);
    try t.expectError(
        error.CompletedUnverifiedHasVerifiedHash,
        Store.transfers.setState(&store, id, request_id, .completed_unverified, null, 122),
    );

    // The control: a transfer that really had nothing to check against still
    // reaches the state, so this is not "nothing can be recorded unverified".
    const bare = testId("bareunv");
    const bare_id: []const u8 = &bare;
    try seedTransferOperation(&store, bare_id, .transfer_push, 1);
    const bare_cp = try Store.transfers.create(&store, .{
        .request_id = bare_id,
        .direction = .push,
        .dest_side = .{ .server = 1 },
        .dest_path = "/srv/app/bare.bin",
        .partial_path = "/srv/app/bare.bin.part",
        .source = .{ .local_file = .{ .path = "./out.bin" } },
        .chunk_size = 100,
        .now = 110,
    });
    try Store.operations.advance(&store, bare_id, .submitted, 112);
    for ([_]Store.transfers.State{ .probing, .transferring, .verifying, .publishing }) |step|
        try Store.transfers.setState(&store, bare_cp, bare_id, step, null, 113);
    try Store.transfers.setState(&store, bare_cp, bare_id, .completed_unverified, null, 120);
    try t.expectEqual(
        Store.transfers.State.completed_unverified,
        (try Store.transfers.get(&store, arena, bare_cp)).?.state,
    );
}

test "gate: a contradicting reading is refused where there is nothing for it to contradict" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_contradiction_control");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    // The controls. A reading whose verdict is `failed` on a file that exists
    // is the most dangerous variant in the union to get wrong, so each of the
    // four things `resolve` asks of it is asked here with the other three
    // satisfied.

    // 1. A transfer that declared no digest. There is nothing for this reading
    //    to disagree with, and the honest reading is a bare presence one — a
    //    different verdict entirely (`completed`, `completed_unverified`).
    const und = testId("nodecl");
    const und_id: []const u8 = &und;
    const und_cp = try seedUnjudgedPublishDigests(
        &store,
        und_id,
        "/srv/app/nodecl.bin",
        "/srv/app/nodecl.bin.part",
        null,
        null,
    );
    const nothing_declared = try Store.receipts.resolve(&store, arena, und_id, .failed, .{
        .destination_present_contradicting = .{
            .side = .remote,
            .path = "/srv/app/nodecl.bin",
            .sha256 = "0000ffff",
            .verification_method = "sha256sum => 0000ffff",
        },
    }, 210);
    try t.expect(nothing_declared == .contradiction_not_established);
    try t.expectEqual(
        @as(?[]const u8, null),
        nothing_declared.contradiction_not_established.declared,
    );
    try t.expectEqualStrings(
        "0000ffff",
        nothing_declared.contradiction_not_established.observed_sha256,
    );
    try t.expectEqual(
        Store.transfers.State.indeterminate_publish,
        (try Store.transfers.get(&store, arena, und_cp)).?.state,
    );

    // 2. A digest the reading *agrees* with. This is the one that would turn a
    //    correctly delivered artifact into a failure on the caller's choice of
    //    variant, which is why it is refused rather than redirected.
    const agree = testId("agrees");
    const agree_id: []const u8 = &agree;
    const agree_cp = try seedUnjudgedPublishDigests(
        &store,
        agree_id,
        "/srv/app/agrees.bin",
        "/srv/app/agrees.bin.part",
        "deadbeef",
        null,
    );
    const agrees = try Store.receipts.resolve(&store, arena, agree_id, .failed, .{
        .destination_present_contradicting = .{
            .side = .remote,
            .path = "/srv/app/agrees.bin",
            .sha256 = "deadbeef",
            .verification_method = "sha256sum => deadbeef",
        },
    }, 210);
    try t.expect(agrees == .contradiction_not_established);
    try t.expectEqualStrings("deadbeef", agrees.contradiction_not_established.declared.?);
    try t.expectEqual(
        Store.transfers.State.indeterminate_publish,
        (try Store.transfers.get(&store, arena, agree_cp)).?.state,
    );
    // And the reading that *is* honest for that row still settles it the other
    // way, so the refusal above is not "this row cannot be judged".
    try t.expect((try Store.receipts.resolve(&store, arena, agree_id, .completed, .{
        .filesystem_effect = .{ .side = .remote, .path = "/srv/app/agrees.bin", .sha256 = "deadbeef" },
    }, 211)) == .resolved);
    try t.expectEqual(
        Store.transfers.State.published,
        (try Store.transfers.get(&store, arena, agree_cp)).?.state,
    );

    // 3. A reading taken somewhere else. Without the address comparison a
    //    reconciler could hash whatever file it liked and call the transfer
    //    failed.
    const addr = testId("elsewhre");
    const addr_id: []const u8 = &addr;
    const addr_cp = try seedUnjudgedPublishDigests(
        &store,
        addr_id,
        "/srv/app/here.bin",
        "/srv/app/here.bin.part",
        "deadbeef",
        null,
    );
    const elsewhere = try Store.receipts.resolve(&store, arena, addr_id, .failed, .{
        .destination_present_contradicting = .{
            .side = .remote,
            .path = "/tmp/here.bin",
            .sha256 = "0000ffff",
            .verification_method = "sha256sum => 0000ffff",
        },
    }, 210);
    try t.expect(elsewhere == .absence_wrong_destination);
    try t.expectEqualStrings("/srv/app/here.bin", elsewhere.absence_wrong_destination.committed.?.path);

    // 4. No account of how it was read. Shares the arm with the other two
    //    readings, and the rule is theirs: a conclusion with no reading behind
    //    it cannot be argued with by anyone who doubts it later.
    const silent = try Store.receipts.resolve(&store, arena, addr_id, .failed, .{
        .destination_present_contradicting = .{
            .side = .remote,
            .path = "/srv/app/here.bin",
            .sha256 = "0000ffff",
            .verification_method = "",
        },
    }, 211);
    try t.expect(silent == .reading_has_no_method);
    try t.expectEqualStrings(
        "destination_present_contradicting",
        silent.reading_has_no_method.evidence_kind,
    );

    // 5. And the outermost control: a contradicting hash offered somewhere that
    //    is not an adjudication at all. This row's publish was watched to its
    //    end, so what became of the rename is not an open question, and a hash
    //    taken now is a statement about a path with a verdict attached — an
    //    artifact replaced after a successful publish reads identically to one
    //    that was never right.
    try t.expect((try Store.receipts.resolve(&store, arena, addr_id, .failed, .{
        .destination_absent = .{
            .side = .remote,
            .path = "/srv/app/here.bin",
            .verification_method = "stat => ENOENT",
        },
    }, 212)) == .resolved);
    try t.expectEqual(
        Store.transfers.State.failed_publish,
        (try Store.transfers.get(&store, arena, addr_cp)).?.state,
    );
    const decided = try Store.receipts.resolve(&store, arena, addr_id, .failed, .{
        .destination_present_contradicting = .{
            .side = .remote,
            .path = "/srv/app/here.bin",
            .sha256 = "0000ffff",
            .verification_method = "sha256sum => 0000ffff",
        },
    }, 213);
    try t.expect(decided == .publish_not_in_question);
    try t.expectEqualStrings("failed_publish", decided.publish_not_in_question.state);
}

test "gate: a contradicting reading proves failure and nothing else" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_contradiction_supports");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    const rid = testId("onlyfail");
    const request_id: []const u8 = &rid;
    const id = try seedUnjudgedPublishDigests(
        &store,
        request_id,
        "/srv/app/only.bin",
        "/srv/app/only.bin.part",
        "deadbeef",
        null,
    );

    // `completed` is the one that matters — a caller pairing "the artifact is
    // there" with "it worked" is the natural mistake, and the digest is the
    // only thing saying otherwise. `timed_out` and `cancelled` are claims about
    // a deadline and about a process, and a hash of a file is neither.
    for ([_]Store.op_state.ResolvedStatus{ .completed, .timed_out, .cancelled }) |claim| {
        const refused = try Store.receipts.resolve(&store, arena, request_id, claim, .{
            .destination_present_contradicting = .{
                .side = .remote,
                .path = "/srv/app/only.bin",
                .sha256 = "0000ffff",
                .verification_method = "sha256sum => 0000ffff",
            },
        }, 210);
        try t.expect(refused == .evidence_does_not_support);
        try t.expectEqualStrings(
            "destination_present_contradicting",
            refused.evidence_does_not_support.evidence_kind,
        );
    }
    try t.expectEqual(
        Store.transfers.State.indeterminate_publish,
        (try Store.transfers.get(&store, arena, id)).?.state,
    );
    try t.expectEqual(@as(usize, 0), try countKind(&store, arena, request_id, "reconcile"));
}

test "gate: a transfer that promised no digest is still judged by a look at its destination" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_wedge_undeclared");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    // The other half of the same wedge, and the harder one to notice, because
    // nothing about the row looks incomplete. A transfer is not obliged to
    // declare a digest up front; this one never did. It is killed mid-publish
    // and parks. Now the artifact *is* at the destination — and there was no
    // route to say so: `filesystem_effect` compares against a declaration that
    // does not exist and refuses (`effect_hash_unproven`), and
    // `destination_absent` would be a lie about a file that is there. The only
    // admissible reading was the false one.
    const rid = testId("wedgeund");
    const request_id: []const u8 = &rid;
    const id = try seedUnjudgedPublishDigests(
        &store,
        request_id,
        "/srv/app/nodigest.bin",
        "/srv/app/nodigest.bin.part",
        null,
        null,
    );

    // Hashing it proves nothing here, and says so rather than quietly passing:
    // with no declaration to compare against, any digest matches nothing, and a
    // stale file from an earlier run would hash just as well.
    const unprovable = try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .filesystem_effect = .{
            .side = .remote,
            .path = "/srv/app/nodigest.bin",
            .sha256 = "aaaabbbb",
        },
    }, 210);
    try t.expect(unprovable == .effect_hash_unproven);
    try t.expectEqual(
        @as(?Store.transfers.ExpectedEffect, null),
        unprovable.effect_hash_unproven.expected,
    );

    // The honest reading is admitted, and lands on the state that says exactly
    // what was established: bytes arrived, nothing trustworthy proved they were
    // the right ones.
    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .destination_present_unverified = .{
            .side = .remote,
            .path = "/srv/app/nodigest.bin",
            .verification_method = "sftp stat => present, mtime 2026-08-13T10:04:02Z",
        },
    }, 211)) == .resolved);
    const judged = (try Store.transfers.get(&store, arena, id)).?;
    try t.expectEqual(Store.transfers.State.completed_unverified, judged.state);
    // `completed_unverified` means what it says: nothing here invented a digest
    // to make the row look better than the evidence was.
    try t.expectEqual(@as(?[]const u8, null), judged.verified_sha256);

    // The reading is on the receipt with the method attached. "It is there" is a
    // conclusion; without how it was taken, nobody who doubts it later has
    // anything to argue with.
    const trail = try Store.receipts.list(&store, arena, request_id);
    const reconcile = trail[trail.len - 1].detail_json.?;
    try t.expect(std.mem.indexOf(u8, reconcile, "destination_present_unverified") != null);
    try t.expect(std.mem.indexOf(u8, reconcile, "sftp stat => present") != null);
}

test "gate: a reading that will not say how it was taken settles nothing" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_reading_method");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    // `verification_method` is what makes these variants readings rather than
    // verdicts, and a field that is required only by its type is one a caller
    // satisfies with `""`. Both variants, because the rule lives in the arm they
    // share and a copy of it that only covered one would be worse than none.
    const rid = testId("nomethod");
    const request_id: []const u8 = &rid;
    const id = try seedUnjudgedPublishDigests(
        &store,
        request_id,
        "/srv/app/silent.bin",
        "/srv/app/silent.bin.part",
        null,
        null,
    );

    const absent = try Store.receipts.resolve(&store, arena, request_id, .failed, .{
        .destination_absent = .{
            .side = .remote,
            .path = "/srv/app/silent.bin",
            .verification_method = "",
        },
    }, 210);
    try t.expect(absent == .reading_has_no_method);
    try t.expectEqualStrings("destination_absent", absent.reading_has_no_method.evidence_kind);

    const present = try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .destination_present_unverified = .{
            .side = .remote,
            .path = "/srv/app/silent.bin",
            .verification_method = "",
        },
    }, 211);
    try t.expect(present == .reading_has_no_method);
    try t.expectEqualStrings("destination_present_unverified", present.reading_has_no_method.evidence_kind);

    // Refused before anything is written, in both halves. A resolution that
    // recorded the operation and left the checkpoint parked would lift the scope
    // barrier while the destination stayed held against everyone.
    try t.expectEqual(
        @as(?Store.op_state.ResolvedStatus, null),
        (try Store.operations.get(&store, arena, request_id)).?.resolved_status,
    );
    try t.expectEqual(@as(usize, 0), try countKind(&store, arena, request_id, "reconcile"));
    try t.expectEqual(
        Store.transfers.State.indeterminate_publish,
        (try Store.transfers.get(&store, arena, id)).?.state,
    );
}

test "gate: a destination reading cannot re-decide a publish that is already decided" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_publish_decided");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    // A reading of a destination answers one question: what became of a rename
    // nobody watched. Against a row that already records what became of it, the
    // same reading is a statement about a path with a verdict attached — an
    // artifact removed after a successful publish reads identically to one that
    // never arrived, and nothing in a `stat` can tell those apart.
    //
    // Without this, the second reconcile of a `published` transfer would be
    // refused for the wrong reason and by luck: `adjudicateLocked` would reject
    // the transition, so the *checkpoint* was safe, but the diagnosis handed to
    // the operator would be about the state graph rather than about the fact
    // that they are re-litigating a settled question.
    // The row has to be *decided but unresolved*, and getting there is itself
    // the point: the driver published normally, and then the connection dropped
    // before the operation could be settled. The checkpoint knows what happened;
    // the ledger does not. That is the only way this refusal is reachable, and
    // it is a real crash window rather than a contrivance.
    const rid = testId("decided");
    const request_id: []const u8 = &rid;
    try seedTransferOperation(&store, request_id, .transfer_push, 1);
    const id = try Store.transfers.create(&store, .{
        .request_id = request_id,
        .direction = .push,
        .dest_side = .{ .server = 1 },
        .dest_path = "/srv/app/done.bin",
        .partial_path = "/srv/app/done.bin.part",
        .source = .{ .local_file = .{ .path = "./out.bin" } },
        .chunk_size = 100,
        .now = 110,
    });
    try Store.operations.advance(&store, request_id, .submitted, 112);
    var clock: i64 = 112;
    for ([_]Store.transfers.State{ .probing, .transferring, .verifying }) |step| {
        clock += 1;
        try Store.transfers.setState(&store, id, request_id, step, null, clock);
    }
    try Store.transfers.recordVerifiedHash(&store, id, request_id, "cafe1234", 120);
    try Store.transfers.setState(&store, id, request_id, .publishing, null, 121);
    try Store.transfers.setState(&store, id, request_id, .published, null, 122);
    _ = try Store.receipts.settle(&store, request_id, .{ .indeterminate = .{
        .reason = "the connection dropped before the result came back",
        .last_observed = .submitted,
    } }, .{}, 123);

    const refused = try Store.receipts.resolve(&store, arena, request_id, .failed, .{
        .destination_absent = .{
            .side = .remote,
            .path = "/srv/app/done.bin",
            .verification_method = "stat => ENOENT",
        },
    }, 210);
    try t.expect(refused == .publish_not_in_question);
    // The state is named, because it is the whole of the refusal: the operator
    // has to see *which* answer is already on record to know whether what they
    // are looking at is a later deletion or a mistake.
    try t.expectEqualStrings("published", refused.publish_not_in_question.state);
    try t.expectEqualStrings("/srv/app/done.bin", refused.publish_not_in_question.observed.path);
    try t.expectEqual(
        @as(?Store.op_state.ResolvedStatus, null),
        (try Store.operations.get(&store, arena, request_id)).?.resolved_status,
    );
    try t.expectEqual(
        Store.transfers.State.published,
        (try Store.transfers.get(&store, arena, id)).?.state,
    );
}

test "gate: an absence reading cannot speak about work with no destination" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_absence_wrong_kind");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    // A job publishes no declared file, so "nothing is at that path" is not a
    // statement about what it did — however true the reading is. Refused by
    // kind, before there is any destination to compare against.
    const rid = testId("absjob");
    const request_id: []const u8 = &rid;
    try seedOperationOfKind(&store, request_id, .job);
    _ = try Store.receipts.settle(
        &store,
        request_id,
        op_state.terminalForTransportLoss(.submitted, "eof"),
        .{},
        200,
    );

    const refused = try Store.receipts.resolve(&store, arena, request_id, .failed, .{
        .destination_absent = .{
            .side = .remote,
            .path = "/srv/app/out.bin",
            .verification_method = "stat => ENOENT",
        },
    }, 210);
    try t.expectEqualStrings("job", refused.evidence_wrong_kind.operation_kind);
    try t.expectEqualStrings("destination_absent", refused.evidence_wrong_kind.evidence_kind);
    try t.expectEqual(
        @as(?Store.op_state.ResolvedStatus, null),
        (try Store.operations.get(&store, arena, request_id)).?.resolved_status,
    );
    try t.expectEqual(@as(usize, 0), try countKind(&store, arena, request_id, "reconcile"));
}

test "gate: a resolution leaves a checkpoint alone when there is no rename to judge" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_adjudicate_skip");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    // This transfer watched its own rename and recorded the answer. The
    // operation is still `indeterminate` for an unrelated reason — the reply
    // never came back — so it is reconcilable, but there is nothing left to
    // adjudicate.
    const rid = testId("adjskip");
    const request_id: []const u8 = &rid;
    const id = try seedUnjudgedPublish(
        &store,
        request_id,
        "/srv/app/done.bin",
        "/srv/app/done.bin.part",
        "abc123",
    );
    try locked(&store, Store.transfers.adjudicateLocked, .{ &store, id, request_id, .published, null, 130 });
    const before = (try Store.transfers.get(&store, arena, id)).?;

    // Skipping is silent and harmless: no error, no second write, no revision
    // of a state something already established. "Nothing to adjudicate" is not
    // a refusal, and treating it as one would make every non-transfer
    // reconcile fail.
    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .filesystem_effect = .{
            .side = .remote,
            .path = "/srv/app/done.bin",
            .sha256 = "abc123",
        },
    }, 210)) == .resolved);

    const after = (try Store.transfers.get(&store, arena, id)).?;
    try t.expectEqual(Store.transfers.State.published, after.state);
    // `updated_at` is what tells "unchanged" from "rewritten to the same
    // value". A second write would move it even where the state matched.
    try t.expectEqual(before.updated_at, after.updated_at);
    try t.expectEqual(
        Store.op_state.ResolvedStatus.completed,
        (try Store.operations.get(&store, arena, request_id)).?.resolved_status.?,
    );

    // `adjudicateLocked` is not a general state writer either: only the three
    // outcomes of a rename go through it, and anything else is refused rather
    // than coerced to the nearest legal state.
    try t.expectError(
        error.NotAnAdjudicationTarget,
        locked(&store, Store.transfers.adjudicateLocked, .{ &store, id, request_id, .paused, null, 220 }),
    );
}
