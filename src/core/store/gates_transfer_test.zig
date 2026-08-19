//! A transfer's own record: what it declared, what it identified, what it
//! confirmed, and what it holds.
//!
//! * **The digest.** Declared once, before any bytes go out, because a digest
//!   chosen after the fact describes what arrived instead of testing it. A
//!   transfer that has already sent cannot declare one, and a verified digest is
//!   written once and only while something is hashing.
//! * **The source.** Identified once, before the first byte, on a file, or not
//!   at all — and bytes confirmed against an unidentified source can never be
//!   resumed, because there is nothing to check the prefix against.
//! * **The offsets.** A confirmed offset needs a prefix hash and a source
//!   identity; an unchanged offset must carry an unchanged prefix digest; a
//!   write that lands on no row is an error, not a success.
//! * **The state machine.** A checkpoint reaches only states it has a path to,
//!   and `published` is earned by a digest rather than reached by walking the
//!   states in order.
//! * **The destination.** One request cannot hold two checkpoints, and two live
//!   transfers cannot hold one destination. A failure keeps its destination
//!   until something supersedes it; superseding releases it and destroys
//!   nothing; and only a settled failure may be superseded.
//!
//! Judging a rename after the fact is `gates_publish_test.zig`. Work whose owner
//! died is `gates_recovery_test.zig`.

const std = @import("std");
const Store = @import("Store.zig");

// The shared fixtures. Aliased under their own names so a gate reads the
// same here as it did when every gate was in one file.
const fixtures = @import("gates_fixtures.zig");
const Scratch = fixtures.Scratch;
const locked = fixtures.locked;
const testId = fixtures.testId;
const seedServer = fixtures.seedServer;
const seedTransferBeforeSubmit = fixtures.seedTransferBeforeSubmit;
const abandonOwner = fixtures.abandonOwner;
const seedCheckpoint = fixtures.seedCheckpoint;
const seedUnjudgedPublish = fixtures.seedUnjudgedPublish;
const seedTransferOperation = fixtures.seedTransferOperation;

test "gate: the digest a transfer will be judged by is declared once, before it sends" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_digest_write_once");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    const early_id = testId("early");
    const early: []const u8 = &early_id;
    try seedTransferBeforeSubmit(&store, early);
    const checkpoint = try Store.transfers.create(&store, .{
        .request_id = early,
        .direction = .push,
        .dest_side = .{ .server = 1 },
        .dest_path = "/srv/app/out.bin",
        .partial_path = "/srv/app/out.bin.terminus-part",
        .source = .{ .local_file = .{ .path = "./out.bin" } },
        .chunk_size = 1 << 20,
        .now = 100,
    });

    // Declaring it before the first byte leaves is the whole point, so that
    // one is allowed.
    try Store.transfers.recordExpectedHash(&store, checkpoint, early, "abc", 110);

    // A second declaration is refused even while the transfer is still early:
    // a digest that can be rewritten is a digest that can be made to match
    // whatever landed, which is the same as having none.
    try t.expectError(
        error.ExpectedHashLocked,
        Store.transfers.recordExpectedHash(&store, checkpoint, early, "def", 111),
    );
    try t.expectEqualStrings(
        "abc",
        (try Store.transfers.get(&store, arena, checkpoint)).?.expected_sha256.?,
    );

    // And a first declaration made after submission is refused too. By then
    // the bytes are already in flight, so "what I promised to publish" is
    // indistinguishable from "what I found afterwards".
    const late_id = testId("late");
    const late: []const u8 = &late_id;
    try seedTransferBeforeSubmit(&store, late);
    const late_checkpoint = try Store.transfers.create(&store, .{
        .request_id = late,
        .direction = .push,
        .dest_side = .{ .server = 1 },
        .dest_path = "/srv/app/late.bin",
        .partial_path = "/srv/app/late.bin.terminus-part",
        .source = .{ .local_file = .{ .path = "./late.bin" } },
        .chunk_size = 1 << 20,
        .now = 100,
    });
    try Store.operations.advance(&store, late, .submitted, 102);
    try t.expectError(
        error.ExpectedHashLocked,
        Store.transfers.recordExpectedHash(&store, late_checkpoint, late, "abc", 112),
    );
    try t.expectEqual(
        @as(?[]const u8, null),
        (try Store.transfers.get(&store, arena, late_checkpoint)).?.expected_sha256,
    );
}

test "gate: a transfer that has already sent bytes cannot declare what it will be judged by" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_expected_hash_after_bytes");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    // Half one: the state window, reached through a hand-over.
    //
    // This is the hole that made "before it sends" a fact about the operation
    // rather than about the transfer. The predecessor pushes and dies; the heir
    // adopting it is a brand-new operation, so it is `created` — and the old
    // guard, which asked only whether the *owning operation* had submitted,
    // said "nothing has been sent yet" about a transfer that had been running
    // for hours. The heir could then hash what had landed and file that as the
    // advance commitment its predecessor's bytes would be judged by, which is
    // exactly the substitution the write-once rule exists to stop, reached the
    // long way round.
    //
    // The offset is deliberately left at zero, so this half turns on the state
    // and nothing else. That is not a contrived shape either: a confirmed
    // offset is what the far side acknowledged, so a transfer can push a great
    // deal and still have none of it confirmed — which is why "no bytes
    // acknowledged" must not be read as "no bytes sent".
    const rid = testId("adoptdigest");
    const request_id: []const u8 = &rid;
    const id = try seedCheckpoint(&store, request_id, "/srv/app/out.bin", "/srv/app/out.bin.part");
    for ([_]Store.transfers.State{ .probing, .transferring, .verifying }) |step|
        try Store.transfers.setState(&store, id, request_id, step, null, 110);
    try Store.transfers.setState(&store, id, request_id, .paused, "verifier died", 113);

    const heir = testId("digestheir");
    const heir_id: []const u8 = &heir;
    try seedTransferOperation(&store, heir_id, .transfer_push, 1);
    // The attempt that pushed those bytes has to be settled before anyone may
    // take its checkpoint; adopting from a live one would put two writers on
    // the same partial.
    try abandonOwner(&store, request_id, "the pusher was killed", 114);
    try locked(&store, Store.transfers.adoptLocked, .{ &store, id, request_id, heir_id, 120 });
    try t.expectError(
        error.ExpectedHashLocked,
        Store.transfers.recordExpectedHash(&store, id, heir_id, "aaaa", 121),
    );
    try t.expectEqual(
        @as(?[]const u8, null),
        (try Store.transfers.get(&store, arena, id)).?.expected_sha256,
    );

    // Half two: the offset, which the state window does not imply. `probing` is
    // inside the window because a resume re-probes before it sends anything
    // more — so a row that is back in `probing` while already carrying
    // confirmed bytes has to be refused on the bytes themselves.
    const partial = testId("partialdigest");
    const partial_id: []const u8 = &partial;
    const partial_cp = try seedCheckpoint(&store, partial_id, "/srv/app/p.bin", "/srv/app/p.bin.part");
    try Store.transfers.setState(&store, partial_cp, partial_id, .probing, null, 130);
    try Store.transfers.confirmOffset(&store, partial_cp, partial_id, 400, 400, "bbbb", 131);
    try t.expectError(
        error.ExpectedHashLocked,
        Store.transfers.recordExpectedHash(&store, partial_cp, partial_id, "aaaa", 132),
    );

    // And the control that keeps both halves from being satisfied by refusing
    // everything: the same state, nothing sent, accepted.
    const clean = testId("cleandigest");
    const clean_id: []const u8 = &clean;
    const clean_cp = try seedCheckpoint(&store, clean_id, "/srv/app/c.bin", "/srv/app/c.bin.part");
    try Store.transfers.setState(&store, clean_cp, clean_id, .probing, null, 140);
    try Store.transfers.recordExpectedHash(&store, clean_cp, clean_id, "aaaa", 141);
}

test "gate: a verified digest is written once, and only while something is hashing" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_verified_hash_window");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    const rid = testId("verhash");
    const request_id: []const u8 = &rid;
    const id = try seedCheckpoint(&store, request_id, "/srv/app/out.bin", "/srv/app/out.bin.part");

    // Nothing has sent a byte here, let alone hashed one. This was accepted
    // until now: the statement's entire WHERE clause was an id and an owner,
    // so `verified_sha256` — the column whose name says the result was
    // checked — could be filled in on a `planned` row and the row walked to
    // `published` afterwards, ending up indistinguishable from one that really
    // was checked.
    try t.expectError(
        error.VerifiedHashLocked,
        Store.transfers.recordVerifiedHash(&store, id, request_id, "aaaa", 110),
    );
    try t.expectEqual(
        @as(?[]const u8, null),
        (try Store.transfers.get(&store, arena, id)).?.verified_sha256,
    );

    var clock: i64 = 110;
    for ([_]Store.transfers.State{ .probing, .transferring, .verifying }) |step| {
        clock += 1;
        try Store.transfers.setState(&store, id, request_id, step, null, clock);
    }
    try Store.transfers.recordVerifiedHash(&store, id, request_id, "aaaa", 120);

    // Write-once, for the same reason the declared digest is: a value the owner
    // can replace is decided by whoever wrote last, and "the digest we got"
    // means nothing if the answer can be revised once the answer is known.
    try t.expectError(
        error.VerifiedHashLocked,
        Store.transfers.recordVerifiedHash(&store, id, request_id, "zzzz", 121),
    );
    try t.expectEqualStrings(
        "aaaa",
        (try Store.transfers.get(&store, arena, id)).?.verified_sha256.?,
    );

    // The self-contradictory row, which is the sharpest version of the same
    // hole: a transfer whose digest provably disagreed, accepting a digest that
    // agrees. Both would be durable, and an auditor reading the row would find
    // it saying the check failed and here is the value that passed.
    const bad = testId("verhashbad");
    const bad_id: []const u8 = &bad;
    const bad_cp = try seedCheckpoint(&store, bad_id, "/srv/app/bad.bin", "/srv/app/bad.bin.part");
    clock = 130;
    for ([_]Store.transfers.State{ .probing, .transferring, .verifying }) |step| {
        clock += 1;
        try Store.transfers.setState(&store, bad_cp, bad_id, step, null, clock);
    }
    try Store.transfers.setState(&store, bad_cp, bad_id, .failed_hash_mismatch, "digest mismatch", 140);
    try t.expectError(
        error.VerifiedHashLocked,
        Store.transfers.recordVerifiedHash(&store, bad_cp, bad_id, "aaaa", 141),
    );
    try t.expectEqual(
        @as(?[]const u8, null),
        (try Store.transfers.get(&store, arena, bad_cp)).?.verified_sha256,
    );
}

test "gate: a checkpoint write that lands on no row is an error, not a success" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_checkpoint_missing");
    defer scratch.deinit();

    var store = try Store.open(scratch.path);
    defer store.close();

    // Every one of these used to return void on a zero-row UPDATE, which made
    // "the checkpoint we are writing progress into does not exist" look
    // exactly like "progress recorded". `CheckpointRowMissing` now means only
    // that — no such row — which is why this gate is the control for the three
    // refusals that used to hide inside it: nothing here exists to be owned, to
    // be in a state, or to have an offset.
    const nobody: []const u8 = "01NOB0DY000000000000000000";
    try t.expectError(
        error.CheckpointRowMissing,
        Store.transfers.confirmOffset(&store, 999, nobody, 4096, 4096, null, 100),
    );
    try t.expectError(
        error.CheckpointRowMissing,
        Store.transfers.setState(&store, 999, nobody, .transferring, null, 100),
    );
    try t.expectError(
        error.CheckpointRowMissing,
        Store.transfers.recordVerifiedHash(&store, 999, nobody, "abc", 100),
    );
}

test "gate: one request cannot hold two checkpoints, or two live transfers one destination" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_checkpoint_uniqueness");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    const rid = testId("uniq");
    const request_id: []const u8 = &rid;
    try seedTransferBeforeSubmit(&store, request_id);

    const opts: Store.transfers.CreateOptions = .{
        .request_id = request_id,
        .direction = .push,
        .dest_side = .{ .server = 1 },
        .dest_path = "/srv/app/out.bin",
        .partial_path = "/srv/app/out.bin.terminus-part",
        .source = .{ .local_file = .{ .path = "./out.bin" } },
        .chunk_size = 1 << 20,
        .now = 200,
    };
    const first = try Store.transfers.create(&store, opts);

    // A second checkpoint on the same request would give it two rows that
    // could each declare a digest, and settling from a published-file hash
    // would then have to pick one — turning insertion order into a
    // scope-releasing decision. `receipts.resolve` refuses that case; this is
    // what makes it unreachable.
    //
    // Aimed at a *different* destination on purpose. Reusing the same one
    // would be rejected by the live-destination index instead, and the
    // assertion would pass without the request-id constraint existing at all.
    // The two now come back under different names, which is the other half of
    // keeping them apart: one says the caller lost track of a checkpoint it
    // already owns, the other says somebody else is on the path.
    var second = opts;
    second.dest_path = "/srv/app/elsewhere.bin";
    second.partial_path = "/srv/app/elsewhere.bin.terminus-part";
    try t.expectError(error.CheckpointAlreadyExists, Store.transfers.create(&store, second));

    // A different request aimed at the same live destination is refused too,
    // and by a different rule. This is the only guard a locally-published
    // transfer gets: `unsettledInScope` filters by server, so two pulls from
    // different servers into one local path both clear the scope guard.
    const other = testId("uniq2");
    const other_id: []const u8 = &other;
    try Store.operations.create(&store, .{
        .request_id = other_id,
        .server_id = 1,
        .server_name = "race",
        .kind = .transfer_push,
        .now = 100,
    });
    var rival = opts;
    rival.request_id = other_id;
    try t.expectError(error.DestinationHeld, Store.transfers.create(&store, rival));

    // The destination stays held for the whole walk, not just while bytes are
    // moving. `verifying` and `publishing` are exactly the states a "live means
    // still sending" reading drops out of the index, and dropping them lets a
    // rival claim the path while the first transfer is hashing what it sent or
    // renaming it into place.
    var clock: i64 = 300;
    for ([_]Store.transfers.State{ .probing, .transferring, .verifying, .publishing }) |step| {
        clock += 1;
        try Store.transfers.setState(&store, first, request_id, step, null, clock);
        try t.expectError(error.DestinationHeld, Store.transfers.create(&store, rival));
    }

    // Published is where it stops holding the path, and only there: a finished
    // transfer blocking its own destination forever would be a leak. Getting
    // there takes more than the last edge, though — `published` asserts the
    // right bytes are at the destination, so the statement demands a digest
    // read back off the result. Recorded from `publishing`, which is inside the
    // window `acceptsVerifiedHash` allows; this transfer declared nothing in
    // advance, so there is nothing for the reading to contradict.
    try Store.transfers.recordVerifiedHash(&store, first, request_id, "cccc", 399);
    try Store.transfers.setState(&store, first, request_id, .published, null, 400);
    _ = try Store.transfers.create(&store, rival);

    // And the settled one stays settled: nothing may walk a terminal
    // checkpoint back into the set that holds a destination, where it could
    // collide with the transfer that replaced it. The refusal has a name now —
    // the row is there and it is ours, so "missing" was the wrong word for it.
    try t.expectError(
        error.IllegalCheckpointTransition,
        Store.transfers.setState(&store, first, request_id, .transferring, null, 410),
    );
    try t.expectEqual(
        Store.transfers.State.published,
        (try Store.transfers.get(&store, arena, first)).?.state,
    );
}

test "gate: a confirmed offset without a prefix hash, or without a source identity, is refused by the schema" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_offset_needs_hash");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    const rid = testId("offset");
    const request_id: []const u8 = &rid;
    try seedTransferBeforeSubmit(&store, request_id);
    // The source carries its content hash, because from v11 onwards a non-zero
    // offset may only be recorded against a source that has an identity — see
    // the `offset_needs_source_identity` case at the end of this gate. Without
    // it every assertion below would fail on that constraint instead of on the
    // prefix-hash rule they are here to prove.
    const id = try Store.transfers.create(&store, .{
        .request_id = request_id,
        .direction = .push,
        .dest_side = .{ .server = 1 },
        .dest_path = "/srv/app/out.bin",
        .partial_path = "/srv/app/out.bin.terminus-part",
        .source = .{ .local_file = .{ .path = "./out.bin", .sha256 = "aaaa" } },
        .chunk_size = 100,
        .now = 100,
    });

    // The confirmed offset is a claim about bytes we can still prove are ours,
    // and the prefix hash is the proof. Advancing without one used to be
    // possible in two ways: passing null, or letting the old `COALESCE` keep
    // the *previous* offset's hash while the offset moved past it. Either way
    // the pair `verifyResume` compares stopped describing the same bytes.
    try t.expectError(
        error.Constraint,
        Store.transfers.confirmOffset(&store, id, request_id, 400, 400, null, 110),
    );
    try t.expectEqual(
        @as(i64, 0),
        (try Store.transfers.get(&store, arena, id)).?.confirmed_offset,
    );

    // With the proof, it advances.
    try Store.transfers.confirmOffset(&store, id, request_id, 400, 400, "bbbb", 111);
    const advanced = (try Store.transfers.get(&store, arena, id)).?;
    try t.expectEqual(@as(i64, 400), advanced.confirmed_offset);
    try t.expectEqualStrings("bbbb", advanced.partial_sha256.?);

    // The dangerous case, and the one the old `COALESCE` allowed: advancing
    // *past* proven bytes while passing no new proof. Under COALESCE the
    // offset moved to 800 and kept the hash of the first 400, so the pair
    // `verifyResume` compares silently stopped describing the same bytes —
    // and a resume would then splice at 800 on the strength of a digest that
    // only ever covered half of it. A plain assignment turns it into a null,
    // which the schema refuses outright.
    try t.expectError(
        error.Constraint,
        Store.transfers.confirmOffset(&store, id, request_id, 800, 800, null, 112),
    );
    const unmoved = (try Store.transfers.get(&store, arena, id)).?;
    try t.expectEqual(@as(i64, 400), unmoved.confirmed_offset);
    try t.expectEqualStrings("bbbb", unmoved.partial_sha256.?);

    // A regressing offset matches no row: a late reply from an earlier chunk
    // must not walk the durable offset backwards. It is named, because a caller
    // told only "no row" cannot tell a stale reply from a wrong id.
    try t.expectError(
        error.CheckpointNotAdvanced,
        Store.transfers.confirmOffset(&store, id, request_id, 300, 300, "aaaa", 113),
    );
    try t.expectEqualStrings(
        "bbbb",
        (try Store.transfers.get(&store, arena, id)).?.partial_sha256.?,
    );

    // Zero needs no proof — there is nothing to prove.
    const fresh = testId("fresh");
    const fresh_id: []const u8 = &fresh;
    try Store.operations.create(&store, .{
        .request_id = fresh_id,
        .server_id = 1,
        .server_name = "race",
        .kind = .transfer_push,
        .now = 100,
    });
    const second = try Store.transfers.create(&store, .{
        .request_id = fresh_id,
        .direction = .push,
        .dest_side = .{ .server = 1 },
        .dest_path = "/srv/app/other.bin",
        .partial_path = "/srv/app/other.bin.terminus-part",
        .source = .{ .local_file = .{ .path = "./other.bin" } },
        .chunk_size = 100,
        .now = 100,
    });
    try Store.transfers.confirmOffset(&store, second, fresh_id, 0, 0, null, 110);

    // And a checkpoint that has settled cannot take progress at all. Reaching
    // a settled state takes the whole walk — a hash cannot be found to mismatch
    // before anything has hashed it — so the failure is diagnosed from
    // `verifying`, which is the only state that can diagnose it.
    try Store.transfers.setState(&store, second, fresh_id, .probing, null, 116);
    try Store.transfers.setState(&store, second, fresh_id, .transferring, null, 117);
    try Store.transfers.setState(&store, second, fresh_id, .verifying, null, 118);
    try Store.transfers.setState(&store, second, fresh_id, .failed_hash_mismatch, "digest mismatch", 120);
    try t.expectError(
        error.IllegalCheckpointTransition,
        Store.transfers.confirmOffset(&store, second, fresh_id, 100, 100, "cccc", 130),
    );

    // A prefix hash proves the bytes in the partial are the ones we put there.
    // It says nothing about *which file* they came from — and a resume splices
    // new bytes onto that head, so a source that cannot be re-identified makes
    // the whole partial unattributable. `verifyResume` compares a content hash
    // for a file source and a strong validator for an HTTP one; a source known
    // only by its path offers neither, so there is no observation that could
    // ever fail the comparison. `offset_needs_source_identity` refuses to store
    // the offset rather than leaving a resume to be waved through later.
    const anon = testId("anon");
    const anon_id: []const u8 = &anon;
    try Store.operations.create(&store, .{
        .request_id = anon_id,
        .server_id = 1,
        .server_name = "race",
        .kind = .transfer_push,
        .now = 100,
    });
    const unidentified = try Store.transfers.create(&store, .{
        .request_id = anon_id,
        .direction = .push,
        .dest_side = .{ .server = 1 },
        .dest_path = "/srv/app/anon.bin",
        .partial_path = "/srv/app/anon.bin.terminus-part",
        .source = .{ .local_file = .{ .path = "./anon.bin" } },
        .chunk_size = 100,
        .now = 100,
    });
    // The digest cannot arrive at `create` for a real transfer: hashing the
    // source means reading it, and the checkpoint has to exist before the
    // probe that reads it can report anything against it. So the row starts
    // unidentifiable, and stays that way until the probe says what it found.
    try t.expectError(
        error.Constraint,
        Store.transfers.confirmOffset(&store, unidentified, anon_id, 400, 400, "bbbb", 140),
    );
    try t.expectEqual(
        @as(i64, 0),
        (try Store.transfers.get(&store, arena, unidentified)).?.confirmed_offset,
    );
    // Zero is still fine: it claims nothing, so it needs no identity either.
    try Store.transfers.confirmOffset(&store, unidentified, anon_id, 0, 0, null, 141);

    // Once the probe has said what the source is, the very same offset is
    // accepted — which is the property this gate is really about. The
    // constraint is not "declare your digest up front", it is "no offset may
    // outlive the identity it was measured against".
    try Store.transfers.recordSourceIdentity(&store, unidentified, anon_id, 1000, 42, "aaaa", 142);
    try Store.transfers.confirmOffset(&store, unidentified, anon_id, 400, 400, "bbbb", 143);
    const identified = (try Store.transfers.get(&store, arena, unidentified)).?;
    try t.expectEqual(@as(i64, 400), identified.confirmed_offset);
    try t.expectEqualStrings("aaaa", identified.source.file().?.sha256.?);
    try t.expectEqual(@as(?u64, 1000), identified.source.file().?.size);
}

test "gate: a source cannot be identified once its transfer has submitted" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_source_after_submit");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    // The shape the hole lived in: the *operation* has submitted, so bytes may
    // already be moving, while the *checkpoint* is still parked at `planned`
    // and offset zero because nothing has written to it since. Every conjunct
    // `recordSourceIdentity` used to have is satisfied here — file source, no
    // digest yet, zero offset, a `beforeFirstByte` state — and the write went
    // through, binding "this is the file those bytes came from" after the first
    // byte may have gone. Resume identity is exactly that commitment, so a
    // resume would then splice new bytes onto a head nobody had committed to.
    const late = testId("srclate");
    const late_id: []const u8 = &late;
    const late_cp = try seedCheckpoint(
        &store,
        late_id,
        "/srv/app/late.bin",
        "/srv/app/late.bin.part",
    );
    // Clear the digest `seedCheckpoint` plants, so the write is refused by the
    // conjunct under test and not by the write-once one.
    try store.db.exec("UPDATE transfer_checkpoints SET source_sha256 = NULL");
    try Store.operations.advance(&store, late_id, .connecting, 101);
    try Store.operations.advance(&store, late_id, .submitted, 102);
    try t.expectEqual(
        Store.transfers.State.planned,
        (try Store.transfers.get(&store, arena, late_cp)).?.state,
    );

    try t.expectError(
        error.SourceIdentityAfterSubmission,
        Store.transfers.recordSourceIdentity(&store, late_cp, late_id, 1000, 42, "aaaa", 103),
    );
    // Refused means nothing was written: not the digest, not the size, not the
    // mtime. A partial identity would be worse than none — `verifyResume`
    // compares whichever fields are there.
    const untouched = (try Store.transfers.get(&store, arena, late_cp)).?.source.file().?;
    try t.expectEqual(@as(?[]const u8, null), untouched.sha256);
    try t.expectEqual(@as(?u64, null), untouched.size);

    // The refusal is named, and named apart from the checkpoint's own. A row
    // that already carries an identity is `SourceIdentityLocked` — a fact about
    // the row — while the one above is a fact about the operation, and a caller
    // that saw one name for both could not tell "you already did this" from
    // "this transfer is already in flight".
    const early = testId("srcearly");
    const early_id: []const u8 = &early;
    const early_cp = try seedCheckpoint(
        &store,
        early_id,
        "/srv/app/early.bin",
        "/srv/app/early.bin.part",
    );
    try store.db.exec(
        "UPDATE transfer_checkpoints SET source_sha256 = NULL WHERE id = " ++
            "(SELECT MAX(id) FROM transfer_checkpoints)",
    );
    // The control, and it is the half that stops this gate passing because
    // `recordSourceIdentity` has simply stopped working: before submission the
    // identical call lands.
    try Store.transfers.recordSourceIdentity(&store, early_cp, early_id, 1000, 42, "aaaa", 110);
    try t.expectEqualStrings(
        "aaaa",
        (try Store.transfers.get(&store, arena, early_cp)).?.source.file().?.sha256.?,
    );
    // ...and a second one is the *other* refusal, on a row whose operation is
    // still `created`. Both names are reachable, and each on its own cause.
    try t.expectError(
        error.SourceIdentityLocked,
        Store.transfers.recordSourceIdentity(&store, early_cp, early_id, 1000, 42, "bbbb", 111),
    );
}

test "gate: a checkpoint cannot reach a state it has no path to" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_transfer_transitions");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    const rid = testId("walk");
    const request_id: []const u8 = &rid;
    const id = try seedCheckpoint(&store, request_id, "/srv/app/out.bin", "/srv/app/out.bin.part");

    // The jump a bare "not settled yet" guard admits, and the reason the guard
    // is a transition table instead. `published` is a claim that the right
    // bytes are at the destination; nothing has read a byte of this transfer.
    // Its only predecessor is `publishing`, reachable only through `verifying`.
    try t.expectError(
        error.IllegalCheckpointTransition,
        Store.transfers.setState(&store, id, request_id, .published, null, 110),
    );
    // A hash cannot be found to disagree before anything hashed it, and a
    // publish cannot fail before one was attempted. Both were reachable from
    // `planned` under the old list.
    try t.expectError(
        error.IllegalCheckpointTransition,
        Store.transfers.setState(&store, id, request_id, .failed_hash_mismatch, "mismatch", 111),
    );
    try t.expectError(
        error.IllegalCheckpointTransition,
        Store.transfers.setState(&store, id, request_id, .failed_publish, "rename failed", 112),
    );
    // Nor may anything be moved *back* to `planned`: `create` is its only
    // writer, so the target has no predecessors at all and the rendered guard
    // is one nothing satisfies.
    try t.expectError(
        error.IllegalCheckpointTransition,
        Store.transfers.setState(&store, id, request_id, .planned, null, 113),
    );
    try t.expectEqual(
        Store.transfers.State.planned,
        (try Store.transfers.get(&store, arena, id)).?.state,
    );

    // And the real path walks end to end, one edge at a time.
    //
    // The digest is recorded partway, and it has to be: the table orders the
    // walk, and the two end states are told apart by the evidence conjuncts
    // `setStateSql` adds on top of it. Without a reading of the result this
    // same walk is refused at `published` and accepted at
    // `completed_unverified` — which is the property the gate below proves, and
    // the reason this one has to supply the digest rather than assume ordering
    // is enough.
    var clock: i64 = 120;
    for ([_]Store.transfers.State{ .probing, .transferring, .verifying }) |step| {
        clock += 1;
        try Store.transfers.setState(&store, id, request_id, step, null, clock);
    }
    try Store.transfers.recordVerifiedHash(&store, id, request_id, "cccc", 124);
    for ([_]Store.transfers.State{ .publishing, .published }) |step| {
        clock += 1;
        try Store.transfers.setState(&store, id, request_id, step, null, clock);
    }
    try t.expectEqual(
        Store.transfers.State.published,
        (try Store.transfers.get(&store, arena, id)).?.state,
    );
}

test "gate: published is earned by a digest, not reached by walking in order" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_published_needs_digest");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    // The transition table orders the walk and says nothing about what was
    // collected along it, so every edge of
    // planned→probing→transferring→verifying→publishing→published is legal for
    // a transfer that confirmed no bytes and read back no digest. That walk
    // used to end in `published` — an artifact recorded as proven by a
    // checkpoint holding no proof — while `completed_unverified`, the state
    // that names exactly that outcome, had nothing routing to it.
    const bare = testId("bare");
    const bare_id: []const u8 = &bare;
    const bare_cp = try seedCheckpoint(&store, bare_id, "/srv/app/bare.bin", "/srv/app/bare.bin.part");
    var clock: i64 = 110;
    for ([_]Store.transfers.State{ .probing, .transferring, .verifying, .publishing }) |step| {
        clock += 1;
        try Store.transfers.setState(&store, bare_cp, bare_id, step, null, clock);
    }
    try t.expectError(
        error.PublishNeedsVerifiedHash,
        Store.transfers.setState(&store, bare_cp, bare_id, .published, null, 120),
    );
    try t.expectEqual(
        Store.transfers.State.publishing,
        (try Store.transfers.get(&store, arena, bare_cp)).?.state,
    );
    // The honest end for the same row, from the same predecessor. Nothing in
    // the graph separates the two; the evidence conjuncts do.
    try Store.transfers.setState(&store, bare_cp, bare_id, .completed_unverified, null, 121);

    // A transfer that declared a digest before it sent anything and read the
    // same one back off the result. This is the only shape `published` accepts
    // — and `completed_unverified` refuses it, because "no trustworthy hash was
    // available" is not what happened here.
    const proven = testId("proven");
    const proven_id: []const u8 = &proven;
    const proven_cp = try seedCheckpoint(&store, proven_id, "/srv/app/proven.bin", "/srv/app/proven.bin.part");
    try Store.transfers.recordExpectedHash(&store, proven_cp, proven_id, "abc123", 130);
    clock = 130;
    for ([_]Store.transfers.State{ .probing, .transferring, .verifying }) |step| {
        clock += 1;
        try Store.transfers.setState(&store, proven_cp, proven_id, step, null, clock);
    }
    try Store.transfers.recordVerifiedHash(&store, proven_cp, proven_id, "abc123", 140);
    try Store.transfers.setState(&store, proven_cp, proven_id, .publishing, null, 141);
    try t.expectError(
        error.CompletedUnverifiedHasVerifiedHash,
        Store.transfers.setState(&store, proven_cp, proven_id, .completed_unverified, null, 142),
    );
    try Store.transfers.setState(&store, proven_cp, proven_id, .published, null, 143);
    try t.expectEqual(
        Store.transfers.State.published,
        (try Store.transfers.get(&store, arena, proven_cp)).?.state,
    );

    // And a reading that contradicts the declaration. Its own error, because
    // "you have no digest" and "your digest says the wrong file arrived" send a
    // reader to opposite places — and neither of them to the transition table,
    // which is where a single `IllegalCheckpointTransition` would have sent
    // them.
    const wrong = testId("wrongdigest");
    const wrong_id: []const u8 = &wrong;
    const wrong_cp = try seedCheckpoint(&store, wrong_id, "/srv/app/wrong.bin", "/srv/app/wrong.bin.part");
    try Store.transfers.recordExpectedHash(&store, wrong_cp, wrong_id, "abc123", 150);
    clock = 150;
    for ([_]Store.transfers.State{ .probing, .transferring, .verifying }) |step| {
        clock += 1;
        try Store.transfers.setState(&store, wrong_cp, wrong_id, step, null, clock);
    }
    try Store.transfers.recordVerifiedHash(&store, wrong_cp, wrong_id, "zzzzzz", 160);
    try Store.transfers.setState(&store, wrong_cp, wrong_id, .publishing, null, 161);
    try t.expectError(
        error.PublishHashContradictsDeclared,
        Store.transfers.setState(&store, wrong_cp, wrong_id, .published, null, 162),
    );
    // `completed_unverified` is not the way out either: the row did read a
    // digest back, it simply disagreed. Recording it as unverified would erase
    // the disagreement, which is the one fact anybody needs from this row.
    try t.expectError(
        error.CompletedUnverifiedHasVerifiedHash,
        Store.transfers.setState(&store, wrong_cp, wrong_id, .completed_unverified, null, 163),
    );
    try Store.transfers.setState(&store, wrong_cp, wrong_id, .failed_hash_mismatch, "digest mismatch", 164);
}

test "gate: a transfer whose rename may already have landed keeps its destination" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_indeterminate_publish");
    defer scratch.deinit();

    var store = try Store.open(scratch.path);
    defer store.close();

    const rid = testId("parked");
    const request_id: []const u8 = &rid;
    const id = try seedCheckpoint(&store, request_id, "/srv/app/out.bin", "/srv/app/out.bin.part");

    var clock: i64 = 100;
    for ([_]Store.transfers.State{ .probing, .transferring, .verifying, .publishing, .indeterminate_publish }) |step| {
        clock += 1;
        try Store.transfers.setState(&store, id, request_id, step, null, clock);
    }

    // `indeterminate_publish` is not a failure and must never be reported as
    // one: the rename may have succeeded. So the path may already hold an
    // artifact that nobody has adjudicated, and a rival aimed at it would
    // overwrite a result while the question of what is there is still open.
    //
    // The claim is released only by an adjudication, never by time or by the
    // operation ending on its own — see the gate below, which resolves one and
    // watches the path come free.
    const other = testId("parkedrival");
    const other_id: []const u8 = &other;
    try Store.operations.create(&store, .{
        .request_id = other_id,
        .server_id = 1,
        .server_name = "race",
        .kind = .transfer_push,
        .now = 100,
    });
    try t.expectError(error.DestinationHeld, Store.transfers.create(&store, .{
        .request_id = other_id,
        .direction = .push,
        .dest_side = .{ .server = 1 },
        .dest_path = "/srv/app/out.bin",
        .partial_path = "/srv/app/out.bin.rival-part",
        .source = .{ .local_file = .{ .path = "./out.bin" } },
        .chunk_size = 100,
        .now = 200,
    }));
}

test "gate: a displaced owner cannot keep writing to a checkpoint it lost" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_checkpoint_ownership");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    const rid = testId("owner");
    const request_id: []const u8 = &rid;
    const id = try seedCheckpoint(&store, request_id, "/srv/app/out.bin", "/srv/app/out.bin.part");
    try Store.transfers.setState(&store, id, request_id, .probing, null, 110);
    try Store.transfers.setState(&store, id, request_id, .transferring, null, 111);
    try Store.transfers.confirmOffset(&store, id, request_id, 400, 400, "bbbb", 112);

    // A resume takes the checkpoint over. The first operation still holds the
    // row id — nothing invalidated it — and under a WHERE clause keyed on `id`
    // alone it would go on reporting progress and states for a transfer it no
    // longer runs, over the top of the operation that does.
    const heir = testId("ownerheir");
    const heir_id: []const u8 = &heir;
    try Store.operations.create(&store, .{
        .request_id = heir_id,
        .server_id = 1,
        .server_name = "race",
        .kind = .transfer_push,
        .now = 200,
    });
    try abandonOwner(&store, request_id, "the pusher was killed", 200);
    try locked(&store, Store.transfers.adoptLocked, .{ &store, id, request_id, heir_id, 201 });

    try t.expectError(
        error.CheckpointNotOurs,
        Store.transfers.setState(&store, id, request_id, .paused, "displaced", 210),
    );
    try t.expectError(
        error.CheckpointNotOurs,
        Store.transfers.confirmOffset(&store, id, request_id, 500, 500, "cccc", 211),
    );
    try t.expectError(
        error.CheckpointNotOurs,
        Store.transfers.recordVerifiedHash(&store, id, request_id, "cccc", 212),
    );
    // A second adopt by the displaced owner is the race this closes: two
    // resumes must not both believe they won the same abandoned transfer. It
    // gets its own name — an heir that lost a race may re-read and decide
    // again, where a displaced writer must simply stop.
    try t.expectError(
        error.CheckpointOwnerChanged,
        locked(&store, Store.transfers.adoptLocked, .{ &store, id, request_id, request_id, 213 }),
    );

    // Nothing the displaced owner tried left a mark.
    const row = (try Store.transfers.get(&store, arena, id)).?;
    try t.expectEqual(Store.transfers.State.transferring, row.state);
    try t.expectEqual(@as(i64, 400), row.confirmed_offset);
    try t.expectEqualStrings("bbbb", row.partial_sha256.?);
    try t.expectEqual(@as(?[]const u8, null), row.verified_sha256);
    try t.expectEqualStrings(heir_id, row.request_id);

    // The new owner writes normally.
    try Store.transfers.confirmOffset(&store, id, heir_id, 500, 500, "cccc", 220);
}

test "gate: an unchanged offset must carry an unchanged prefix digest" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_same_offset_hash");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    const rid = testId("reconfirm");
    const request_id: []const u8 = &rid;
    const id = try seedCheckpoint(&store, request_id, "/srv/app/out.bin", "/srv/app/out.bin.part");
    try Store.transfers.confirmOffset(&store, id, request_id, 400, 400, "bbbb", 110);

    // Two different digests for the same offset means one of the two readings
    // of those bytes is wrong, and nothing here can tell which. Taking the
    // newer one would overwrite the record `verifyResume` compares against
    // with a value that may describe a different file.
    try t.expectError(
        error.PrefixHashConflict,
        Store.transfers.confirmOffset(&store, id, request_id, 400, 400, "cccc", 111),
    );
    try t.expectEqualStrings(
        "bbbb",
        (try Store.transfers.get(&store, arena, id)).?.partial_sha256.?,
    );

    // The same offset with the *same* digest still succeeds, and this is the
    // assertion that stops the rule being "simplified" into banning equality.
    // Re-confirming an unchanged offset is routine: it is what a
    // truncate-then-resume does, and what `contiguousPrefix` returns whenever a
    // chunk closes on the far side of a gap. `partial_len` may legitimately
    // have grown in the meantime — bytes were written past the confirmed
    // prefix and not yet acknowledged — so the write is not a no-op.
    try Store.transfers.confirmOffset(&store, id, request_id, 400, 900, "bbbb", 112);
    const reconfirmed = (try Store.transfers.get(&store, arena, id)).?;
    try t.expectEqual(@as(i64, 400), reconfirmed.confirmed_offset);
    try t.expectEqual(@as(i64, 900), reconfirmed.partial_len);
    try t.expectEqualStrings("bbbb", reconfirmed.partial_sha256.?);
    try t.expectEqual(@as(i64, 112), reconfirmed.updated_at);
}

test "gate: a checkpoint may only be created under an operation that agrees with it" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_create_binds_operation");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    // Aimed at server 2 under an operation bound to server 1. Neither half is
    // malformed — it is the *pair* that is wrong, which is precisely the class
    // of mistake no constraint on one table can see, and the reason `create`
    // is an `INSERT ... SELECT` over `operations` at all.
    const wrong_server = testId("wrongsrv");
    const wrong_server_id: []const u8 = &wrong_server;
    try seedTransferOperation(&store, wrong_server_id, .transfer_push, 1);
    try t.expectError(error.CheckpointOperationMismatch, Store.transfers.create(&store, .{
        .request_id = wrong_server_id,
        .direction = .push,
        .dest_side = .{ .server = 2 },
        .dest_path = "/srv/app/out.bin",
        .partial_path = "/srv/app/out.bin.part",
        .source = .{ .local_file = .{ .path = "./out.bin" } },
        .chunk_size = 100,
        .now = 110,
    }));
    // Refused, not repaired. Deriving `dest_side` from the operation would
    // have turned "publish this on server 2" into a silent push to server 1,
    // and the caller would never learn its request had been rewritten.
    try t.expectEqual(
        @as(?Store.transfers.Checkpoint, null),
        try Store.transfers.byRequest(&store, arena, wrong_server_id),
    );

    // A pull's operation cannot run a push. The kinds are what `receipts`
    // later uses to decide which evidence is admissible, so a checkpoint filed
    // under the wrong one would be judged by rules meant for other work.
    const wrong_kind = testId("wrongkind");
    const wrong_kind_id: []const u8 = &wrong_kind;
    try seedTransferOperation(&store, wrong_kind_id, .transfer_pull, 1);
    try t.expectError(error.CheckpointOperationMismatch, Store.transfers.create(&store, .{
        .request_id = wrong_kind_id,
        .direction = .push,
        .dest_side = .{ .server = 1 },
        .dest_path = "/srv/app/out.bin",
        .partial_path = "/srv/app/out.bin.part",
        .source = .{ .local_file = .{ .path = "./out.bin" } },
        .chunk_size = 100,
        .now = 110,
    }));

    // A push reads a local file. Recording one that reads a remote file would
    // make `verifyResume` re-prove the source on the wrong machine — the same
    // path on the host is a different file, and it might well exist.
    const wrong_source = testId("wrongsrc");
    const wrong_source_id: []const u8 = &wrong_source;
    try seedTransferOperation(&store, wrong_source_id, .transfer_push, 1);
    try t.expectError(error.CheckpointOperationMismatch, Store.transfers.create(&store, .{
        .request_id = wrong_source_id,
        .direction = .push,
        .dest_side = .{ .server = 1 },
        .dest_path = "/srv/app/out.bin",
        .partial_path = "/srv/app/out.bin.part",
        .source = .{ .remote_file = .{ .path = "/srv/app/in.bin" } },
        .chunk_size = 100,
        .now = 110,
    }));

    // A fetch has no server at all, so it has nowhere on a server to publish.
    // This is the case the live-destination index cannot help with either:
    // `unsettledInScope` filters by `server_id` and a fetch has none.
    const wrong_fetch = testId("wrongfetch");
    const wrong_fetch_id: []const u8 = &wrong_fetch;
    try seedTransferOperation(&store, wrong_fetch_id, .fetch, null);
    try t.expectError(error.CheckpointOperationMismatch, Store.transfers.create(&store, .{
        .request_id = wrong_fetch_id,
        .direction = .fetch,
        .dest_side = .{ .server = 1 },
        .dest_path = "/var/tmp/out.bin",
        .partial_path = "/var/tmp/out.bin.part",
        .source = .{ .http = .{ .url = "https://h/f.bin", .etag = "W1" } },
        .chunk_size = 100,
        .now = 110,
    }));

    // And a checkpoint minted after the operation submitted describes bytes
    // already in flight. Same window as `recordExpectedHash`, same reason.
    const late = testId("latecheck");
    const late_id: []const u8 = &late;
    try seedTransferOperation(&store, late_id, .transfer_push, 1);
    try Store.operations.advance(&store, late_id, .submitted, 102);
    try t.expectError(error.CheckpointOperationMismatch, Store.transfers.create(&store, .{
        .request_id = late_id,
        .direction = .push,
        .dest_side = .{ .server = 1 },
        .dest_path = "/srv/app/late.bin",
        .partial_path = "/srv/app/late.bin.part",
        .source = .{ .local_file = .{ .path = "./late.bin" } },
        .chunk_size = 100,
        .now = 110,
    }));

    // All three legitimate shapes still go through, which is what keeps the
    // clause above from being satisfied by refusing everything.
    const ok_push = testId("okpush");
    const ok_push_id: []const u8 = &ok_push;
    try seedTransferOperation(&store, ok_push_id, .transfer_push, 1);
    _ = try Store.transfers.create(&store, .{
        .request_id = ok_push_id,
        .direction = .push,
        .dest_side = .{ .server = 1 },
        .dest_path = "/srv/app/push.bin",
        .partial_path = "/srv/app/push.bin.part",
        .source = .{ .local_file = .{ .path = "./push.bin" } },
        .chunk_size = 100,
        .now = 110,
    });

    const ok_pull = testId("okpull");
    const ok_pull_id: []const u8 = &ok_pull;
    try seedTransferOperation(&store, ok_pull_id, .transfer_pull, 1);
    _ = try Store.transfers.create(&store, .{
        .request_id = ok_pull_id,
        .direction = .pull,
        .dest_side = .local,
        .dest_path = "/var/tmp/pull.bin",
        .partial_path = "/var/tmp/pull.bin.part",
        .source = .{ .remote_file = .{ .path = "/srv/app/in.bin" } },
        .chunk_size = 100,
        .now = 110,
    });

    const ok_fetch = testId("okfetch");
    const ok_fetch_id: []const u8 = &ok_fetch;
    try seedTransferOperation(&store, ok_fetch_id, .fetch, null);
    _ = try Store.transfers.create(&store, .{
        .request_id = ok_fetch_id,
        .direction = .fetch,
        .dest_side = .local,
        .dest_path = "/var/tmp/fetch.bin",
        .partial_path = "/var/tmp/fetch.bin.part",
        .source = .{ .http = .{ .url = "https://h/f.bin", .etag = "W1" } },
        .chunk_size = 100,
        .now = 110,
    });
}

test "gate: a refused create returns no id, least of all another transfer's" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_create_id_trap");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    const good = testId("idtrapok");
    const good_id: []const u8 = &good;
    const bad = testId("idtrapbad");
    const bad_id: []const u8 = &bad;
    // Both operations are seeded first, deliberately. Any insert between the
    // two `create` calls — even into another table — would move
    // `last_insert_rowid` off the first checkpoint and blunt the trap into
    // "returned some stale rowid" instead of "returned that exact checkpoint".
    try seedTransferOperation(&store, good_id, .transfer_push, 1);
    try seedTransferOperation(&store, bad_id, .transfer_push, 1);

    const first = try Store.transfers.create(&store, .{
        .request_id = good_id,
        .direction = .push,
        .dest_side = .{ .server = 1 },
        .dest_path = "/srv/app/first.bin",
        .partial_path = "/srv/app/first.bin.part",
        .source = .{ .local_file = .{ .path = "./first.bin" } },
        .chunk_size = 100,
        .now = 110,
    });

    if (Store.transfers.create(&store, .{
        .request_id = bad_id,
        .direction = .push,
        .dest_side = .{ .server = 2 },
        .dest_path = "/srv/app/second.bin",
        .partial_path = "/srv/app/second.bin.part",
        .source = .{ .local_file = .{ .path = "./second.bin" } },
        .chunk_size = 100,
        .now = 120,
    })) |returned| {
        // An `INSERT ... SELECT` that matches no row is not an error to
        // sqlite, and `last_insert_rowid` still holds the previous successful
        // insert's value. A `create` that returned it hands this caller the
        // checkpoint above — a different destination, on a different machine,
        // owned by a different operation — to write its progress and its
        // prefix digests into.
        if (returned == first) return error.RefusedCreateReturnedTheOtherCheckpointsId;
        return error.RefusedCreateReturnedAnId;
    } else |err| {
        try t.expectEqual(Store.transfers.Error.CheckpointOperationMismatch, err);
    }

    // The refusal left nothing behind, and the earlier checkpoint is intact.
    try t.expectEqual(
        @as(?Store.transfers.Checkpoint, null),
        try Store.transfers.byRequest(&store, arena, bad_id),
    );
    try t.expectEqual(first, (try Store.transfers.byRequest(&store, arena, good_id)).?.id);
}

test "gate: a source is identified once, before the first byte, on a file, or not at all" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_source_identity_once");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    const rid = testId("srcid");
    const request_id: []const u8 = &rid;
    try seedTransferOperation(&store, request_id, .transfer_push, 1);
    const id = try Store.transfers.create(&store, .{
        .request_id = request_id,
        .direction = .push,
        .dest_side = .{ .server = 1 },
        .dest_path = "/srv/app/out.bin",
        .partial_path = "/srv/app/out.bin.part",
        .source = .{ .local_file = .{ .path = "./out.bin" } },
        .chunk_size = 100,
        .now = 110,
    });

    // A foreign owner cannot identify someone else's source, for the same
    // reason it cannot write their offsets: it is not running that transfer.
    const stranger: []const u8 = "01STRANGER00000000000000AB";
    try t.expectError(
        error.CheckpointNotOurs,
        Store.transfers.recordSourceIdentity(&store, id, stranger, 1000, 42, "aaaa", 111),
    );

    try Store.transfers.recordSourceIdentity(&store, id, request_id, 1000, 42, "aaaa", 112);

    // Write-once, and this is the laundering it stops: a stalled transfer that
    // could re-identify its source would replace the digest `verifyResume`
    // compares against with a reading of whatever is at that path now — the
    // substitution the comparison exists to catch, made through the front door.
    try t.expectError(
        error.SourceIdentityLocked,
        Store.transfers.recordSourceIdentity(&store, id, request_id, 900, 99, "zzzz", 113),
    );
    const kept = (try Store.transfers.get(&store, arena, id)).?.source.file().?;
    try t.expectEqualStrings("aaaa", kept.sha256.?);
    try t.expectEqual(@as(?u64, 1000), kept.size);
    try t.expectEqual(@as(?i128, 42), kept.mtime_ns);

    // Nor may a first identity arrive once bytes are moving. The digest would
    // be read from the source at one moment and attached to bytes taken out of
    // it at another, which is the splice the whole comparison exists to refuse.
    const moving = testId("srcidmove");
    const moving_id: []const u8 = &moving;
    try seedTransferOperation(&store, moving_id, .transfer_push, 1);
    const moving_cp = try Store.transfers.create(&store, .{
        .request_id = moving_id,
        .direction = .push,
        .dest_side = .{ .server = 1 },
        .dest_path = "/srv/app/moving.bin",
        .partial_path = "/srv/app/moving.bin.part",
        .source = .{ .local_file = .{ .path = "./moving.bin" } },
        .chunk_size = 100,
        .now = 110,
    });
    try Store.transfers.setState(&store, moving_cp, moving_id, .probing, null, 111);
    // Still inside the window here: probing is where the source gets read.
    try Store.transfers.setState(&store, moving_cp, moving_id, .transferring, null, 112);
    try t.expectError(
        error.SourceIdentityLocked,
        Store.transfers.recordSourceIdentity(&store, moving_cp, moving_id, 1000, 42, "aaaa", 113),
    );
    try t.expectEqual(
        @as(?[]const u8, null),
        (try Store.transfers.get(&store, arena, moving_cp)).?.source.file().?.sha256,
    );

    // An http source has no file identity to record at all, and this is the
    // damage the guard prevents rather than a tidy-up. `source_sha256` and
    // `source_mtime_ns` are read by no http path — such a source is re-proved
    // from its validator — but `source_size` *is* read, and the write used to
    // overwrite it. Worse, it burned the write-once on a row that never had a
    // file identity to give, so the column could never hold a real one after.
    //
    // This block used to prove something else: that `confirmed_offset = 0` was
    // not implied by write-once, using an http row far into its bytes with a
    // null digest. The kind guard refuses that row a conjunct earlier, so the
    // old assertion would now pass for the wrong reason. That conjunct is no
    // longer isolable by any row — see `recordSourceIdentity` — and this gate
    // does not pretend otherwise.
    const fetched = testId("srcidhttp");
    const fetched_id: []const u8 = &fetched;
    try seedTransferOperation(&store, fetched_id, .fetch, null);
    const fetch_cp = try Store.transfers.create(&store, .{
        .request_id = fetched_id,
        .direction = .fetch,
        .dest_side = .local,
        .dest_path = "/var/tmp/f.bin",
        .partial_path = "/var/tmp/f.bin.part",
        .source = .{ .http = .{ .url = "https://h/f.bin", .etag = "W1", .size = 4096 } },
        .chunk_size = 100,
        .now = 110,
    });

    // Refused at offset zero, in `planned`, write-once intact: every other
    // conjunct in the statement is satisfied, so the kind is the only thing
    // that can have refused it.
    try t.expectError(
        error.SourceIdentityLocked,
        Store.transfers.recordSourceIdentity(&store, fetch_cp, fetched_id, 1000, 42, "aaaa", 111),
    );
    const untouched = (try Store.transfers.get(&store, arena, fetch_cp)).?.source.http;
    try t.expectEqual(@as(?u64, 4096), untouched.size);
    try t.expectEqualStrings("W1", untouched.etag.?);

    // And still refused once it is far into its bytes, which is the state a
    // fetch spends most of its life in with `source_sha256` legitimately null.
    try Store.transfers.confirmOffset(&store, fetch_cp, fetched_id, 400, 400, "bbbb", 112);
    try t.expectError(
        error.SourceIdentityLocked,
        Store.transfers.recordSourceIdentity(&store, fetch_cp, fetched_id, 1000, 42, "aaaa", 113),
    );
    try t.expectEqual(
        @as(?u64, 4096),
        (try Store.transfers.get(&store, arena, fetch_cp)).?.source.http.size,
    );
}

test "gate: bytes confirmed against an unidentified source can never be resumed" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_unidentified_resume");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    const rid = testId("noident");
    const request_id: []const u8 = &rid;
    try seedTransferOperation(&store, request_id, .transfer_push, 1);
    const id = try Store.transfers.create(&store, .{
        .request_id = request_id,
        .direction = .push,
        .dest_side = .{ .server = 1 },
        .dest_path = "/srv/app/out.bin",
        .partial_path = "/srv/app/out.bin.part",
        .source = .{ .local_file = .{ .path = "./out.bin" } },
        .chunk_size = 100,
        .now = 110,
    });

    // Half one: such a row cannot be made durable.
    try t.expectError(
        error.Constraint,
        Store.transfers.confirmOffset(&store, id, request_id, 400, 400, "bbbb", 111),
    );

    // Half two: and if one existed anyway, no resume would accept it. The two
    // are not redundant. The schema cannot see `verifyResume`'s inputs — the
    // function is pure and every caller hands it a struct, including callers
    // that assembled one from somewhere other than this table — while
    // `verifyResume` cannot stop a durable row existing in a shape no resume
    // could ever accept. So the struct below is deliberately the one the
    // schema just refused to store.
    var unprovable = (try Store.transfers.get(&store, arena, id)).?;
    unprovable.confirmed_offset = 400;
    unprovable.partial_sha256 = "bbbb";

    // Note what the observation carries: a full identity. The refusal is not
    // "we could not read the source", it is "we never wrote down what the
    // source was, so there is nothing this reading could disagree with". Size
    // and mtime are absent from the record too, so every comparison in
    // `sourceChanged` is skipped and it returns a clean bill of health for a
    // file nobody identified.
    //
    // And it has its own verdict rather than borrowing `source_changed`. The
    // tag is what a caller switches on, and this source is byte-for-byte the
    // one it always was: reporting a change would send an operator to diff a
    // file that is fine while the real fault — a record stored without the one
    // field that makes it checkable — went unnamed.
    const verdict = Store.transfers.verifyResume(unprovable, .{ .local_file = .{
        .path = "./out.bin",
        .size = 1000,
        .mtime_ns = 42,
        .sha256 = "aaaa",
    } }, .{ .exists = true, .len = 400, .prefix_sha256 = "bbbb" });
    try t.expect(verdict == .unidentified_source);

    // The neighbouring verdict still means what it says. Same struct, same
    // observation shape — the only difference is that this record *has* an
    // identity and the reading disagrees with it. If the two were collapsed
    // back into one tag, this assertion and the one above would be the same
    // assertion twice.
    var identified = unprovable;
    identified.source = .{ .local_file = .{
        .path = "./out.bin",
        .size = 1000,
        .mtime_ns = 42,
        .sha256 = "aaaa",
    } };
    try t.expect(Store.transfers.verifyResume(identified, .{ .local_file = .{
        .path = "./out.bin",
        .size = 1000,
        .mtime_ns = 42,
        .sha256 = "zzzz",
    } }, .{ .exists = true, .len = 400, .prefix_sha256 = "bbbb" }) == .source_changed);

    // Identified, the same resume goes through — the rule is about the record,
    // not about being unable to resume pushes.
    try Store.transfers.recordSourceIdentity(&store, id, request_id, 1000, 42, "aaaa", 112);
    try Store.transfers.confirmOffset(&store, id, request_id, 400, 400, "bbbb", 113);
    const proven = (try Store.transfers.get(&store, arena, id)).?;
    try t.expectEqual(@as(u64, 400), Store.transfers.verifyResume(proven, .{ .local_file = .{
        .path = "./out.bin",
        .size = 1000,
        .mtime_ns = 42,
        .sha256 = "aaaa",
    } }, .{ .exists = true, .len = 400, .prefix_sha256 = "bbbb" }).resume_from);
}

/// Walks a fresh checkpoint to one of the `failed_*` states.
///
/// Each failure is diagnosable only from where it could have been observed, so
/// the route differs per target: a clobber conflict can be found by the probe,
/// a digest mismatch cannot be found before something hashed. The route is
/// derived from the target rather than passed in, so a caller cannot reach a
/// failure by a path the transition table does not have.
fn seedFailed(
    store: *Store,
    request_id: []const u8,
    dest_path: []const u8,
    partial_path: []const u8,
    target: Store.transfers.State,
) !i64 {
    const S = Store.transfers.State;
    const route: []const S = switch (target) {
        .failed_source_changed,
        .failed_remote_partial_mismatch,
        .failed_no_space,
        .failed_clobber_conflict,
        => &.{.probing},
        .failed_hash_mismatch => &.{ .probing, .transferring, .verifying },
        .failed_publish => &.{ .probing, .transferring, .verifying, .publishing },
        else => return error.NotAFailureState,
    };
    const id = try seedCheckpoint(store, request_id, dest_path, partial_path);
    var clock: i64 = 200;
    for (route) |step| {
        clock += 1;
        try Store.transfers.setState(store, id, request_id, step, null, clock);
    }
    try Store.transfers.setState(store, id, request_id, target, "the gate put it here", clock + 1);
    return id;
}

/// A transfer operation with nothing attached yet, for a rival `create`.
/// The caller fills in the destination; a rival is only a rival once it names
/// the same one.
fn seedRival(store: *Store, request_id: []const u8, now: i64) !Store.transfers.CreateOptions {
    try Store.operations.create(store, .{
        .request_id = request_id,
        .server_id = 1,
        .server_name = "race",
        .kind = .transfer_push,
        .now = now,
    });
    return .{
        .request_id = request_id,
        .direction = .push,
        .dest_side = .{ .server = 1 },
        .dest_path = "",
        .partial_path = "",
        .source = .{ .local_file = .{ .path = "./out.bin" } },
        .chunk_size = 100,
        .now = now,
    };
}

test "gate: every failure keeps its destination until something supersedes it" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_failure_holds_dest");
    defer scratch.deinit();

    var store = try Store.open(scratch.path);
    defer store.close();

    // A failed run leaves a partial beside the destination and a half-told
    // story about what is at it. Releasing the path the moment the failure was
    // recorded meant the next `create` walked straight into that with nothing
    // making an operator say "yes, discard it" — and `--restart`, which is what
    // was supposed to make them say it, was a requirement written down and
    // enforced by nothing.
    //
    // Driven off `isSupersedable` rather than a list of names, so a state
    // dropped from `holdsDestination` is still visited here and still asked to
    // refuse a rival.
    var seq: usize = 0;
    inline for (@typeInfo(Store.transfers.State).@"enum".fields) |field| {
        const failed: Store.transfers.State = @enumFromInt(field.value);
        if (comptime failed.isSupersedable()) {
            seq += 1;
            var dest_buf: [64]u8 = undefined;
            const dest = try std.fmt.bufPrint(&dest_buf, "/srv/app/{s}.bin", .{@tagName(failed)});
            var part_buf: [96]u8 = undefined;
            const part = try std.fmt.bufPrint(&part_buf, "{s}.terminus-part", .{dest});
            var label_buf: [16]u8 = undefined;

            const owner = testId(try std.fmt.bufPrint(&label_buf, "hold{d}", .{seq}));
            _ = try seedFailed(&store, &owner, dest, part, failed);

            const rival_id = testId(try std.fmt.bufPrint(&label_buf, "riv{d}", .{seq}));
            var rival = try seedRival(&store, &rival_id, 400);
            rival.dest_path = dest;
            rival.partial_path = "/srv/app/rival.terminus-part";
            try t.expectError(error.DestinationHeld, Store.transfers.create(&store, rival));
        }
    }

    // And the two states that do release it, which is what keeps the rule from
    // being "a destination is never free again". In both the path stopped being
    // a claim and became the artifact: `published` says the right bytes are
    // there, `completed_unverified` says bytes are there and nothing could
    // prove they were the right ones. Either way the next transfer aimed at
    // that path is an ordinary overwrite, not a collision with unfinished work.
    inline for (.{
        .{ "unver", "/srv/app/unverified.bin", Store.transfers.State.completed_unverified },
        .{ "pubed", "/srv/app/published.bin", Store.transfers.State.published },
    }) |case| {
        const owner = testId(case[0]);
        const owner_id: []const u8 = &owner;
        const cp = try seedCheckpoint(&store, owner_id, case[1], case[1] ++ ".part");
        var clock: i64 = 500;
        for ([_]Store.transfers.State{ .probing, .transferring, .verifying }) |step| {
            clock += 1;
            try Store.transfers.setState(&store, cp, owner_id, step, null, clock);
        }
        // `published` needs a digest read back off the result and
        // `completed_unverified` needs the absence of one, so only one of the
        // two is reachable from a given row — see the evidence conjuncts.
        if (case[2] == .published)
            try Store.transfers.recordVerifiedHash(&store, cp, owner_id, "cccc", clock);
        try Store.transfers.setState(&store, cp, owner_id, .publishing, null, clock + 1);
        try Store.transfers.setState(&store, cp, owner_id, case[2], null, clock + 2);

        const rival_id = testId(case[0] ++ "r");
        var rival = try seedRival(&store, &rival_id, 600);
        rival.dest_path = case[1];
        rival.partial_path = case[1] ++ ".rival-part";
        _ = try Store.transfers.create(&store, rival);
    }
}

test "gate: superseding releases a failed destination and destroys nothing" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_supersede");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    // A push that got 400 bytes in and then found its digest wrong. The offset
    // and its prefix hash are recorded because the point of superseding rather
    // than deleting is that all of it survives.
    const rid = testId("supold");
    const request_id: []const u8 = &rid;
    const id = try seedCheckpoint(&store, request_id, "/srv/app/out.bin", "/srv/app/out.bin.part");
    try Store.transfers.setState(&store, id, request_id, .probing, null, 110);
    try Store.transfers.setState(&store, id, request_id, .transferring, null, 111);
    try Store.transfers.confirmOffset(&store, id, request_id, 400, 400, "bbbb", 112);
    try Store.transfers.setState(&store, id, request_id, .verifying, null, 113);
    try Store.transfers.setState(&store, id, request_id, .failed_hash_mismatch, "digest mismatch", 114);

    const heir = testId("supnew");
    const heir_id: []const u8 = &heir;
    var rival = try seedRival(&store, heir_id, 200);
    rival.dest_path = "/srv/app/out.bin";
    rival.partial_path = "/srv/app/out.bin.heir-part";
    try t.expectError(error.DestinationHeld, Store.transfers.create(&store, rival));

    // The failed attempt does not get to clear its own path. `setState` is the
    // driver's API and every statement it renders is keyed on the owning
    // request id, so leaving the release edges in its route would let the run
    // that failed decide by itself that its leftovers may be discarded — which
    // is the acknowledgement the hold exists to require.
    try t.expectError(
        error.SupersessionIsNotATransition,
        Store.transfers.setState(&store, id, request_id, .superseded, null, 210),
    );

    // A supersession names who is taking over, and the name has to be real: the
    // single thing this call produces is a record of who released the path, and
    // one pointing at no operation reads as provenance while being none.
    const ghost = testId("ghost");
    const ghost_id: []const u8 = &ghost;
    try t.expectError(error.SupersedingOperationMissing, locked(
        &store,
        Store.transfers.supersedeLocked,
        .{ &store, id, ghost_id, 211 },
    ));
    try t.expectEqual(
        Store.transfers.State.failed_hash_mismatch,
        (try Store.transfers.get(&store, arena, id)).?.state,
    );

    // An id nobody wrote comes back as missing rather than as a state refusal.
    try t.expectError(error.CheckpointRowMissing, locked(
        &store,
        Store.transfers.supersedeLocked,
        .{ &store, id + 9_999, heir_id, 212 },
    ));

    try locked(&store, Store.transfers.supersedeLocked, .{ &store, id, heir_id, 213 });

    // The path is free, which is the whole purpose...
    const heir_cp = try Store.transfers.create(&store, rival);
    try t.expect(heir_cp != id);

    // ...and the old row is untouched apart from the release. The partial, the
    // offset, the prefix digest and the destination all stay, because what an
    // operator was being asked about is precisely that there is something at
    // that path worth knowing about.
    const old = (try Store.transfers.get(&store, arena, id)).?;
    try t.expectEqual(Store.transfers.State.superseded, old.state);
    try t.expectEqual(@as(i64, 400), old.confirmed_offset);
    try t.expectEqualStrings("bbbb", old.partial_sha256.?);
    try t.expectEqualStrings("/srv/app/out.bin", old.dest_path);
    try t.expectEqualStrings("/srv/app/out.bin.part", old.partial_path);
    try t.expectEqualStrings(request_id, old.request_id);
    // Who released it, in the only column there is for it. Prose, not a join —
    // see `supersedeLocked` for why the state and not a column carries the
    // release, and what that costs.
    try t.expect(std.mem.indexOf(u8, old.failure_reason.?, heir_id) != null);

    // Released once. A second supersession would only overwrite the first one's
    // provenance with a later request's, on a row that is no longer holding
    // anything.
    try t.expectError(error.CheckpointNotSupersedable, locked(
        &store,
        Store.transfers.supersedeLocked,
        .{ &store, id, heir_id, 214 },
    ));
}

test "gate: only a settled failure may be superseded" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_supersede_states");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    const taker = testId("taker");
    const taker_id: []const u8 = &taker;
    // Before any operation, because `operations.server_id` is a foreign key and
    // foreign keys are on.
    try seedServer(&store);
    try Store.operations.create(&store, .{
        .request_id = taker_id,
        .server_id = 1,
        .server_name = "race",
        .kind = .transfer_push,
        .now = 100,
    });

    // Live, at three points along the walk. Nobody has decided the attempt is
    // over and a process may still be appending to the partial, so releasing
    // the path would hand it to a rival while the first writer is using it.
    // Stopping the transfer is a different operation and has to happen first.
    inline for (.{
        .{ "supplan", "/srv/app/planned.bin", [_]Store.transfers.State{} },
        .{ "supxfer", "/srv/app/xfer.bin", [_]Store.transfers.State{ .probing, .transferring } },
        .{ "suppub", "/srv/app/pubbing.bin", [_]Store.transfers.State{ .probing, .transferring, .verifying, .publishing } },
    }) |case| {
        const owner = testId(case[0]);
        const owner_id: []const u8 = &owner;
        const cp = try seedCheckpoint(&store, owner_id, case[1], case[1] ++ ".part");
        var clock: i64 = 300;
        for (case[2]) |step| {
            clock += 1;
            try Store.transfers.setState(&store, cp, owner_id, step, null, clock);
        }
        const before = (try Store.transfers.get(&store, arena, cp)).?;
        try t.expectError(error.CheckpointNotSupersedable, locked(
            &store,
            Store.transfers.supersedeLocked,
            .{ &store, cp, taker_id, 400 },
        ));
        const after = (try Store.transfers.get(&store, arena, cp)).?;
        try t.expectEqual(before.state, after.state);
        try t.expectEqual(before.updated_at, after.updated_at);
    }

    // Unjudged, not settled. The rename may already have landed, so superseding
    // would throw away the open question of what is at the path and let a rival
    // overwrite a result nobody has looked at. `adjudicateLocked` is the way
    // out, and it needs evidence.
    const parked = testId("supparked");
    const parked_id: []const u8 = &parked;
    const parked_cp = try seedUnjudgedPublish(
        &store,
        parked_id,
        "/srv/app/parked.bin",
        "/srv/app/parked.bin.part",
        "abc123",
    );
    try t.expectError(error.CheckpointNotSupersedable, locked(
        &store,
        Store.transfers.supersedeLocked,
        .{ &store, parked_cp, taker_id, 401 },
    ));
    try t.expectEqual(
        Store.transfers.State.indeterminate_publish,
        (try Store.transfers.get(&store, arena, parked_cp)).?.state,
    );

    // Published. There is no hold to release — a published row is not in the
    // index — and recording it as superseded would erase the one fact anybody
    // needs from it, that an artifact was put there.
    const done = testId("supdone");
    const done_id: []const u8 = &done;
    const done_cp = try seedCheckpoint(&store, done_id, "/srv/app/done.bin", "/srv/app/done.bin.part");
    var clock: i64 = 500;
    for ([_]Store.transfers.State{ .probing, .transferring, .verifying }) |step| {
        clock += 1;
        try Store.transfers.setState(&store, done_cp, done_id, step, null, clock);
    }
    try Store.transfers.recordVerifiedHash(&store, done_cp, done_id, "cccc", clock);
    try Store.transfers.setState(&store, done_cp, done_id, .publishing, null, clock + 1);
    try Store.transfers.setState(&store, done_cp, done_id, .published, null, clock + 2);
    try t.expectError(error.CheckpointNotSupersedable, locked(
        &store,
        Store.transfers.supersedeLocked,
        .{ &store, done_cp, taker_id, 402 },
    ));
    try t.expectEqual(
        Store.transfers.State.published,
        (try Store.transfers.get(&store, arena, done_cp)).?.state,
    );
}
