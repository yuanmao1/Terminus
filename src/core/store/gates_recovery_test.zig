//! Work whose owner is gone: abandonment, recovery, hand-over, and the barrier
//! that stops the ground moving underneath it.
//!
//! * **Abandoned mid-act.** A crash during verification does not wedge the
//!   checkpoint: it is recovered to `paused` and resumes, and a digest taken
//!   over bytes a resume may discard does not survive the pause. A crash
//!   mid-publish is recovered to `indeterminate_publish`, because that is what
//!   was true of it. A recovery that fails halfway leaves the row and both
//!   trails alone, and recovery is refused outright for a row that was not
//!   abandoned mid-act.
//! * **Hand-over.** A checkpoint changes hands only to an operation fit to run
//!   it, is taken only from an attempt that cannot still be running, does not
//!   move to another machine, and is recorded on both sides or on neither — a
//!   composite held together by `execution`, because nothing inside `store/` can
//!   hold the three writes at once.
//! * **The server barrier.** Deleting a server must not strand a transfer that
//!   still needs a hand-over, and is refused while an attempt is unsettled or a
//!   lease is held on it. The barrier check and the delete see one snapshot,
//!   proved by racing them.
//! * **Displacement.** An owner that lost its claim cannot keep writing to the
//!   checkpoint it lost.

const std = @import("std");
const Store = @import("Store.zig");
const op_state = @import("op_state.zig");
// The checkpoint hand-over is a composite: the row moves in `transfers` and
// both operations record it in `receipts`, in one transaction held by the
// layer above. Proving it lands as a whole or not at all means reaching for
// that layer from here — there is nothing inside `store/` that can hold the
// three writes together, which is the point.
const execution = @import("../execution.zig");

// The shared fixtures. Aliased under their own names so a gate reads the
// same here as it did when every gate was in one file.
const fixtures = @import("gates_fixtures.zig");
const Scratch = fixtures.Scratch;
const locked = fixtures.locked;
const testId = fixtures.testId;
const abandonOwner = fixtures.abandonOwner;
const seedCheckpoint = fixtures.seedCheckpoint;
const seedTransferOperation = fixtures.seedTransferOperation;
const countKind = fixtures.countKind;

test "gate: a crash during verification does not wedge the checkpoint" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_verify_unwedge");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    const rid = testId("wedge");
    const request_id: []const u8 = &rid;
    const id = try seedCheckpoint(&store, request_id, "/srv/app/out.bin", "/srv/app/out.bin.part");
    for ([_]Store.transfers.State{ .probing, .transferring }) |step|
        try Store.transfers.setState(&store, id, request_id, step, null, 110);
    try Store.transfers.confirmOffset(&store, id, request_id, 400, 400, "bbbb", 111);
    try Store.transfers.setState(&store, id, request_id, .verifying, null, 112);

    // While verifying, the row holds its destination but is not adoptable:
    // there is no offset left to resume from.
    try t.expectEqual(
        @as(?Store.transfers.Checkpoint, null),
        try Store.transfers.findResumable(&store, arena, .{ .server = 1 }, "/srv/app/out.bin"),
    );

    // `verifying → paused` is the edge that keeps that from being a trap. Only
    // `publishing` follows `verifying`, so without this a process killed
    // mid-hash leaves a row that can neither move nor be taken over, holding
    // its destination for good.
    //
    // This is the *owner* walking that edge, which is the case where an
    // interruption was clean: the verifier gave up and parked its own row. A
    // process that was killed cannot do this — every edge out of `verifying` is
    // keyed on the owning request id — and that case belongs to
    // `execution.recoverCheckpoint`, gated below.
    try Store.transfers.setState(&store, id, request_id, .paused, "verifier died", 113);

    const parked = (try Store.transfers.findResumable(&store, arena, .{ .server = 1 }, "/srv/app/out.bin")).?;
    try t.expectEqual(id, parked.id);
    try t.expectEqual(@as(i64, 400), parked.confirmed_offset);

    // And a resume can take it over from there, which is the whole point of
    // un-wedging it — once the attempt that was verifying is settled. That is
    // the reconcile the resume path costs: a checkpoint may only change hands
    // when somebody has recorded that the previous attempt is over.
    const heir = testId("wedgeheir");
    const heir_id: []const u8 = &heir;
    try Store.operations.create(&store, .{
        .request_id = heir_id,
        .server_id = 1,
        .server_name = "race",
        .kind = .transfer_push,
        .now = 200,
    });
    try abandonOwner(&store, request_id, "the verifier was killed", 200);
    try locked(&store, Store.transfers.adoptLocked, .{ &store, id, request_id, heir_id, 201 });
    try Store.transfers.setState(&store, id, heir_id, .probing, null, 202);
}

/// A transfer whose process was killed in the middle of an act.
///
/// The checkpoint is in `verifying` or `publishing` — the two states only a
/// running process can be in — and the operation is still `remote_started`,
/// which is what a `kill -9` really leaves behind: nothing writes a terminal on
/// the way out. Every gate below starts here and differs in what it does next.
fn seedAbandonedMidAct(
    store: *Store,
    request_id: []const u8,
    dest_path: []const u8,
    partial_path: []const u8,
    comptime stop_at: Store.transfers.State,
) !i64 {
    const id = try seedCheckpoint(store, request_id, dest_path, partial_path);
    // Declared before submission, because that is the only window there is; the
    // `publishing` route below needs it so `published` stays a live possibility
    // for the adjudication, and a row that could only ever fail would make the
    // verdict prove nothing.
    try Store.transfers.recordExpectedHash(store, id, request_id, "abc123", 101);
    try Store.operations.advance(store, request_id, .connecting, 102);
    try Store.operations.advance(store, request_id, .submitted, 103);
    try Store.operations.advance(store, request_id, .remote_started, 104);
    for ([_]Store.transfers.State{ .probing, .transferring }) |step|
        try Store.transfers.setState(store, id, request_id, step, null, 110);
    try Store.transfers.confirmOffset(store, id, request_id, 400, 400, "bbbb", 111);
    try Store.transfers.setState(store, id, request_id, .verifying, null, 112);
    if (stop_at == .publishing) {
        try Store.transfers.recordVerifiedHash(store, id, request_id, "abc123", 113);
        try Store.transfers.setState(store, id, request_id, .publishing, null, 114);
    }
    return id;
}

/// A recovery attempt, opened past the scope barrier the dead owner is still
/// holding.
///
/// `--force` is what an operator uses to get here, and it has to be: the
/// crashed attempt is unsettled, so it blocks the scope, and a recovery is
/// aimed at exactly that situation. What `--force` buys is the right to open an
/// operation — not the right to take a live attempt's partial, which is the
/// separate refusal the first gate below is about.
fn beginRecovery(store: *Store, arena: std.mem.Allocator, io: std.Io, now: i64) !execution.Execution {
    const start = try execution.begin(store, arena, io, .{
        .server_id = 1,
        .server_name = "race",
        .kind = .transfer_push,
        .owner_token = "gate",
        .force = true,
        .now = now,
    });
    return switch (start) {
        .ready => |e| e,
        .blocked => error.ScopeUnexpectedlyBlocked,
    };
}

/// Takes a transfer attempt out of the way of its scope, by the only route a
/// transfer has.
///
/// The gates that call this are about what may happen *once* the incumbent has
/// stopped blocking; how it stopped is fixture. They used to get there with
/// `.exited{1}` — a copier's exit status settling the transfer `failed` — and
/// `terminalDescribesKind` now refuses exactly that for every transfer kind,
/// along with `remote_deadline` and `remote_cancel_confirmed`. All three carry a
/// fact about a *process*, and a transfer is judged by the artifact at the
/// destination it declared before it sent anything: a copier that wrote to the
/// wrong path, or whose rename never ran, still exits 0. Even the attempt that
/// knows perfectly well it ran out of disk has no terminal for saying so —
/// what it knows is about itself, not about what is now at the destination.
///
/// So an attempt interrupted after submission has exactly one terminal left to
/// it, `indeterminate` — which blocks scope by design, and the price of the rule
/// is the reconcile below. `transfers` reads `resolved_status` beside `status`
/// (`ownerBlocksScope`, `incumbentBlocksScope`), so it is the resolution that
/// lifts the barrier, not the settlement.
///
/// The evidence is an override rather than a reading of the destination because
/// these checkpoints are not parked in `indeterminate_publish` at this point —
/// against a row in any other state a destination reading is refused with
/// `publish_not_in_question`, which is its own gate above. An operator who went
/// and looked is exactly who writes this one.
fn reconcileDeadTransfer(
    store: *Store,
    arena: std.mem.Allocator,
    request_id: []const u8,
    last_observed: op_state.Status,
    reason: []const u8,
    now: i64,
) !void {
    _ = try Store.receipts.settle(
        store,
        request_id,
        op_state.terminalForTransportLoss(last_observed, reason),
        .{},
        now,
    );
    const outcome = try Store.receipts.resolve(store, arena, request_id, .failed, .{
        .operator_override = .{ .reason = "checked by hand", .by = "gate" },
    }, now);
    if (outcome != .resolved) return error.ReconcileRefusedTheFixture;
}

test "gate: a checkpoint abandoned mid-verify is recovered to paused, and resumes" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_recover_verifying");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    const rid = testId("midverify");
    const request_id: []const u8 = &rid;
    const id = try seedAbandonedMidAct(
        &store,
        request_id,
        "/srv/app/mv.bin",
        "/srv/app/mv.bin.part",
        .verifying,
    );

    // Nothing can move this row. `verifying` is not adoptable, its only ordinary
    // exits are keyed on the owner that is gone, and it holds its destination
    // meanwhile — so before recovery existed this was a path claimed forever by
    // a process that no longer exists.
    try t.expectEqual(
        @as(?Store.transfers.Checkpoint, null),
        try Store.transfers.findResumable(&store, arena, .{ .server = 1 }, "/srv/app/mv.bin"),
    );

    var heir = try beginRecovery(&store, arena, scratch.io, 200);
    defer heir.deinit();

    // The incumbent is `remote_started`: as far as anything here knows it is
    // still hashing that partial. `--force` got the operation opened; it does
    // not get the checkpoint handed over, and nothing at all is written.
    try t.expectError(
        error.SurrenderingOperationMayStillBeRunning,
        heir.recoverCheckpoint(id, request_id),
    );
    const untouched = (try Store.transfers.get(&store, arena, id)).?;
    try t.expectEqual(Store.transfers.State.verifying, untouched.state);
    try t.expectEqualStrings(request_id, untouched.request_id);
    try t.expectEqual(@as(usize, 0), try countKind(&store, arena, request_id, "checkpoint"));
    try t.expectEqual(@as(usize, 0), try countKind(&store, arena, heir.id(), "checkpoint"));

    // Establishing what the dead attempt did is the price, and it is the one an
    // operator already pays for a resume. For a transfer that price is a
    // reconcile, not a scavenged exit status: `settle` refuses every
    // process-shaped terminal here, so the attempt goes `indeterminate` and
    // somebody has to say what became of the work.
    try reconcileDeadTransfer(&store, arena, request_id, .remote_started, "the attempt died without reporting", 210);

    const became = try heir.recoverCheckpoint(id, request_id);
    try t.expectEqual(Store.transfers.State.paused, became);

    // `paused` says what is true: nothing was published — `publishing` is the
    // only edge out of `verifying` and it was never taken — and the partial is
    // still exactly as long as the last offset anybody confirmed.
    const recovered = (try Store.transfers.get(&store, arena, id)).?;
    try t.expectEqual(Store.transfers.State.paused, recovered.state);
    try t.expectEqualStrings(heir.id(), recovered.request_id);
    try t.expectEqual(@as(i64, 400), recovered.confirmed_offset);
    try t.expectEqualStrings("bbbb", recovered.partial_sha256.?);

    // And it is resumable, which is the whole point of normalising it there.
    const parked = (try Store.transfers.findResumable(&store, arena, .{ .server = 1 }, "/srv/app/mv.bin")).?;
    try t.expectEqual(id, parked.id);
    try Store.transfers.setState(&store, id, heir.id(), .probing, null, 220);

    // Both operations recorded the hand-over, and both say what the row was
    // normalised into — a recovery that read as an ordinary adoption would let
    // a later reader think the offset had been re-confirmed since.
    try t.expectEqual(@as(usize, 1), try countKind(&store, arena, request_id, "checkpoint"));
    try t.expectEqual(@as(usize, 1), try countKind(&store, arena, heir.id(), "checkpoint"));
    const trail = try Store.receipts.list(&store, arena, request_id);
    const handover = trail[trail.len - 1].detail_json.?;
    try t.expect(std.mem.indexOf(u8, handover, "checkpoint_surrendered") != null);
    try t.expect(std.mem.indexOf(u8, handover, "\"normalisedTo\":\"paused\"") != null);
}

test "gate: a digest taken over bytes a resume may discard does not survive the pause" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_paused_digest");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    // A process hashes the staged partial, records the digest, and dies before
    // it can publish. Recovery normalises `verifying → paused`, and `paused`
    // means resumable: the resume is entitled to truncate back to
    // `confirmed_offset` and re-send from there, so the bytes the digest was
    // taken over need not exist a moment later.
    //
    // Left in the column, that digest is a claim about the current contents of
    // the partial that nothing keeps true — and `published` is guarded on
    // exactly that column. A resume that re-sent different bytes and reached
    // `publishing` could then be adjudicated `published` on the strength of a
    // hash of the bytes it replaced.
    const rid = testId("pausedig");
    const request_id: []const u8 = &rid;
    const id = try seedAbandonedMidAct(
        &store,
        request_id,
        "/srv/app/pd.bin",
        "/srv/app/pd.bin.part",
        .verifying,
    );
    try Store.transfers.recordVerifiedHash(&store, id, request_id, "abc123", 113);
    try t.expectEqualStrings("abc123", (try Store.transfers.get(&store, arena, id)).?.verified_sha256.?);
    try reconcileDeadTransfer(&store, arena, request_id, .remote_started, "the attempt died without reporting", 210);

    var heir = try beginRecovery(&store, arena, scratch.io, 200);
    defer heir.deinit();

    const became = try heir.recoverCheckpoint(id, request_id);
    try t.expectEqual(Store.transfers.State.paused, became);
    try t.expectEqual(
        @as(?[]const u8, null),
        (try Store.transfers.get(&store, arena, id)).?.verified_sha256,
    );

    // Cleared, not lost. Nothing else stored that reading, and it is a real
    // observation somebody made of real bytes — it has stopped being the working
    // record's and become history's, which is what the ledger is for. Both sides
    // of the hand-over carry it, because a reader holding either receipt has to
    // be able to see that a digest was discarded here rather than never taken.
    for ([_][]const u8{ request_id, heir.id() }) |who| {
        const trail = try Store.receipts.list(&store, arena, who);
        const handover = trail[trail.len - 1].detail_json.?;
        try t.expect(std.mem.indexOf(u8, handover, "\"normalisedTo\":\"paused\"") != null);
        try t.expect(std.mem.indexOf(u8, handover, "\"discardedVerifiedSha256\":\"abc123\"") != null);
    }

    // And the row is genuinely resumable with the column empty — the clearing is
    // not a cosmetic reset that leaves the transfer unable to finish. It re-hashes
    // whatever it ends up with, in `verifying`, where a digest may be written.
    const parked = (try Store.transfers.findResumable(&store, arena, .{ .server = 1 }, "/srv/app/pd.bin")).?;
    try t.expectEqual(id, parked.id);
    try Store.transfers.setState(&store, id, heir.id(), .probing, null, 220);
    try Store.transfers.setState(&store, id, heir.id(), .transferring, null, 221);
    try Store.transfers.setState(&store, id, heir.id(), .verifying, null, 222);
    try Store.transfers.recordVerifiedHash(&store, id, heir.id(), "abc123", 223);
}

test "gate: an operation that may still be running cannot have its destination taken" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_supersede_incumbent");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    // Supersession releases a failed transfer's destination so a later one may
    // claim it. The checkpoint's own settlement is checked — see the gate above
    // — but that is a statement about the *row*, and the thing that could still
    // be moving bytes is the *operation* that owns it.
    //
    // The window is real: a driver records `failed_transport` on its checkpoint
    // and is then killed, or loses its connection, before the operation is
    // settled. The row says failed; the process may be alive, holding the
    // partial open, mid-write. Superseding on the row alone hands that path to a
    // rival while the incumbent is still writing to it, and the two transfers
    // scribble over each other with no error anywhere — the second one's bytes
    // land under a name the first one is still renaming.
    const rid = testId("supinc");
    const request_id: []const u8 = &rid;
    const id = try seedCheckpoint(&store, request_id, "/srv/app/si.bin", "/srv/app/si.bin.part");
    try Store.operations.advance(&store, request_id, .connecting, 102);
    try Store.operations.advance(&store, request_id, .submitted, 103);
    try Store.operations.advance(&store, request_id, .remote_started, 104);
    for ([_]Store.transfers.State{ .probing, .transferring }) |step|
        try Store.transfers.setState(&store, id, request_id, step, null, 110);
    try Store.transfers.setState(&store, id, request_id, .failed_source_changed, "the source moved under us", 120);

    const heir_rid = testId("supheir");
    const heir_id: []const u8 = &heir_rid;
    try seedTransferOperation(&store, heir_id, .transfer_push, 1);

    try t.expectError(error.SurrenderingOperationMayStillBeRunning, locked(
        &store,
        Store.transfers.supersedeLocked,
        .{ &store, id, heir_id, 130 },
    ));
    // Nothing written: the row is still the incumbent's and still holds the path.
    const untouched = (try Store.transfers.get(&store, arena, id)).?;
    try t.expectEqual(Store.transfers.State.failed_source_changed, untouched.state);
    try t.expectEqualStrings(request_id, untouched.request_id);

    // Settling the operation is the price, and it is the same one every other
    // route out of a crashed attempt charges: establish what it did, then act.
    // For a transfer that means `indeterminate` and a reconcile — an exit status
    // is not a reading of the destination this row is still holding.
    try reconcileDeadTransfer(&store, arena, request_id, .remote_started, "the attempt died without reporting", 140);
    try locked(&store, Store.transfers.supersedeLocked, .{ &store, id, heir_id, 150 });
    try t.expectEqual(
        Store.transfers.State.superseded,
        (try Store.transfers.get(&store, arena, id)).?.state,
    );
    _ = try Store.transfers.create(&store, .{
        .request_id = heir_id,
        .direction = .push,
        .dest_side = .{ .server = 1 },
        .dest_path = "/srv/app/si.bin",
        .partial_path = "/srv/app/si.bin.heir",
        .source = .{ .local_file = .{ .path = "./out.bin" } },
        .chunk_size = 100,
        .now = 160,
    });
}

test "gate: a checkpoint is released by the same rule that lifts the scope barrier" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_incumbent_rule");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    // "Has this operation stopped being able to affect the host" is asked in two
    // places — `operations.unsettled_predicate`, which decides whether a new
    // request may run against the same scope, and the incumbent conjunct in
    // `supersede_sql`, which decides whether its destination may be handed to
    // somebody else. One question, and two answers is one answer too many: a
    // release that says yes where the barrier says no takes a path away from an
    // attempt the rest of the store is still protecting.
    //
    // The incumbent conjunct used to be `COALESCE(resolved_status, status) IN
    // (released)`, which reads a resolution as authoritative *whatever status it
    // sits beside*. The barrier deliberately does not: it subtracts
    // `indeterminate` explicitly and says so — "a safety barrier should not
    // depend on a rule held somewhere else". The row below is where the two
    // forms disagree.
    const rid = testId("rulepair");
    const request_id: []const u8 = &rid;
    const id = try seedCheckpoint(&store, request_id, "/srv/app/rp.bin", "/srv/app/rp.bin.part");
    try Store.operations.advance(&store, request_id, .connecting, 102);
    try Store.operations.advance(&store, request_id, .submitted, 103);
    try Store.operations.advance(&store, request_id, .remote_started, 104);
    for ([_]Store.transfers.State{ .probing, .transferring }) |step|
        try Store.transfers.setState(&store, id, request_id, step, null, 110);
    try Store.transfers.setState(&store, id, request_id, .failed_source_changed, "the source moved", 120);

    // Written straight into the column, because that is the situation the
    // barrier is defending against: `receipts.resolve` will not produce this
    // row, and the barrier is built not to trust that. A binary from another
    // version, a hand-edit, or a future writer is enough.
    {
        var stmt = try store.db.prepare(
            "UPDATE operations SET resolved_status = 'completed' WHERE request_id = ?1",
        );
        defer stmt.deinit();
        try stmt.bindText(1, request_id);
        _ = try stmt.step();
    }

    // The barrier still holds it: `remote_started` is a status that blocks, and
    // a resolution beside it resolves nothing.
    const still_blocking = try Store.operations.unsettled(&store, arena, 1);
    try t.expectEqual(@as(usize, 1), still_blocking.len);
    try t.expectEqualStrings(request_id, still_blocking[0].request_id);

    // So the destination is not available either. Same question, same answer.
    const heir_rid = testId("ruleheir");
    const heir_id: []const u8 = &heir_rid;
    try seedTransferOperation(&store, heir_id, .transfer_push, 1);
    try t.expectError(error.SurrenderingOperationMayStillBeRunning, locked(
        &store,
        Store.transfers.supersedeLocked,
        .{ &store, id, heir_id, 130 },
    ));
    try t.expectEqual(
        Store.transfers.State.failed_source_changed,
        (try Store.transfers.get(&store, arena, id)).?.state,
    );

    // And when the status *is* the one a resolution answers, both let go — so
    // this is a rule the two share, not merely a second refusal bolted on.
    {
        var stmt = try store.db.prepare(
            "UPDATE operations SET status = 'indeterminate' WHERE request_id = ?1",
        );
        defer stmt.deinit();
        try stmt.bindText(1, request_id);
        _ = try stmt.step();
    }
    try t.expectEqual(@as(usize, 0), (try Store.operations.unsettled(&store, arena, 1)).len);
    try locked(&store, Store.transfers.supersedeLocked, .{ &store, id, heir_id, 140 });
    try t.expectEqual(
        Store.transfers.State.superseded,
        (try Store.transfers.get(&store, arena, id)).?.state,
    );
}

/// `servers.remove`, for a gate that expects it to go through.
///
/// Names the two ways it can fail to, because "expected removed, got refused"
/// and "expected removed, got no-such-server" are different bugs and a bare
/// equality failure cannot say which.
fn mustRemove(store: *Store, name: []const u8, now: i64) !void {
    switch (try Store.servers.remove(store, name, now)) {
        .removed => {},
        .unknown_server => return error.ServerWasNotThereToRemove,
        .refused => return error.RemovalUnexpectedlyRefused,
    }
}

/// The barrier a removal refused over, for a gate that expects one.
fn refusalOf(store: *Store, name: []const u8, now: i64) !Store.servers.Barrier {
    return switch (try Store.servers.remove(store, name, now)) {
        .removed => error.RemovalWasNotRefused,
        .unknown_server => error.ServerWasNotThereToRemove,
        .refused => |barrier| barrier,
    };
}

test "gate: deleting a server does not strand a transfer that still needs a hand-over" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_server_rm_transfers");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    // `operations.server_id` is `ON DELETE SET NULL` and `transfer_checkpoints`
    // has no server column of its own, so removing the server row does not
    // remove the checkpoint — it removes the checkpoint's only link to a
    // machine. Every hand-over is guarded by a same-machine conjunct, so after
    // the delete an adoptable or recoverable row can never be taken over by
    // anybody, in any state, while going on holding its destination against
    // every later transfer. Nothing in the cascade counts said so: they covered
    // memories, facts, sessions, jobs and history — everything the delete would
    // *erase* — and were silent about the thing it would strand.
    const rid = testId("srvrm");
    const request_id: []const u8 = &rid;
    const id = try seedAbandonedMidAct(
        &store,
        request_id,
        "/srv/app/sr.bin",
        "/srv/app/sr.bin.part",
        .verifying,
    );
    try reconcileDeadTransfer(&store, arena, request_id, .remote_started, "the attempt died without reporting", 210);

    var heir = try beginRecovery(&store, arena, scratch.io, 200);
    defer heir.deinit();
    try t.expectEqual(Store.transfers.State.paused, try heir.recoverCheckpoint(id, request_id));

    // The count now comes back on the refusal itself rather than out of
    // `cascadeCounts`, and that is the point of this shape: a number a caller
    // has to remember to read before acting is a barrier held by convention,
    // and this one is decided in the same transaction as the DELETE.
    try t.expectEqual(
        Store.servers.Barrier{ .resumable_transfers = 1 },
        try refusalOf(&store, "race", 400),
    );
    // Refused means nothing went: the server is still there and so is the row.
    try t.expect((try Store.servers.getByName(&store, arena, "race")) != null);
    try t.expectEqual(
        Store.transfers.State.paused,
        (try Store.transfers.get(&store, arena, id)).?.state,
    );

    // The way out is the ordinary one — finish the transfer, or fail it and let
    // something supersede it — and then the delete goes through. Nothing here is
    // a `--force`: the two losses are not the same kind.
    //
    // "Fail it" is two acts rather than one, and that is the transfer contract
    // rather than an accident of this fixture. The *row* records what the copier
    // hit (`failed_no_space`); the *operation* cannot borrow that as its own
    // verdict, because a full disk is a fact about this end and the question is
    // what is now at the destination. So the attempt settles `indeterminate` and
    // a reconcile says the rest.
    try Store.transfers.setState(&store, id, heir.id(), .probing, null, 300);
    try Store.transfers.setState(&store, id, heir.id(), .failed_no_space, "the disk filled", 301);
    try Store.operations.advance(&store, heir.id(), .connecting, 302);
    try Store.operations.advance(&store, heir.id(), .submitted, 303);
    try reconcileDeadTransfer(&store, arena, heir.id(), .submitted, "the disk filled and the copier stopped", 304);

    const closer = testId("srvclose");
    const closer_id: []const u8 = &closer;
    try seedTransferOperation(&store, closer_id, .transfer_push, 1);
    try locked(&store, Store.transfers.supersedeLocked, .{ &store, id, closer_id, 310 });

    try mustRemove(&store, "race", 400);
}

test "gate: a server with an attempt still unsettled on it cannot be deleted" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_server_rm_unsettled");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    // The reachable-from-the-CLI half of the defect. `operations.server_id` is
    // `ON DELETE SET NULL`, and every guard filters `WHERE server_id …`, so
    // deleting a host used to un-scope every attempt on it in one statement:
    // an attempt that was blocking a same-scope mutation stopped blocking it,
    // and `request ls` stopped listing it, so the route by which anybody would
    // have found out what it did left with the row. Nothing warned, because
    // `history` has two writers left and a host driven only with exec/run/job
    // has zero rows in every counted table — the `--force` prompt was not even
    // reached.
    const rid = testId("srvunset");
    const request_id: []const u8 = &rid;
    try seedTransferOperation(&store, request_id, .exec, 1);
    try Store.operations.advance(&store, request_id, .submitted, 120);

    try t.expectEqual(
        Store.servers.Barrier{ .unsettled_operations = 1 },
        try refusalOf(&store, "race", 400),
    );
    try t.expect((try Store.servers.getByName(&store, arena, "race")) != null);

    // A read whose outcome is unknown is a barrier here even though it is not
    // one for the mutation guard, and the asymmetry is deliberate: the guard
    // asks whether a change can collide, and this asks whether deleting the row
    // destroys the only way to establish what happened. See
    // `operations.unsettledCountLocked`.
    {
        var stmt = try store.db.prepare("UPDATE operations SET mutating = 0 WHERE request_id = ?1");
        defer stmt.deinit();
        try stmt.bindText(1, request_id);
        _ = try stmt.step();
    }
    try t.expectEqual(@as(usize, 0), (try Store.operations.unsettledInScope(
        &store,
        arena,
        1,
        .{ .kind = .server },
    )).len);
    try t.expectEqual(
        Store.servers.Barrier{ .unsettled_operations = 1 },
        try refusalOf(&store, "race", 400),
    );

    // Establishing the outcome is what clears it — the ordinary route, and the
    // only one. There is no flag.
    _ = try Store.receipts.settle(&store, request_id, .{ .exited = .{ .exit_code = 0 } }, .{}, 130);
    try mustRemove(&store, "race", 400);

    // And the composition that makes the whole thing hold: `ON DELETE SET NULL`
    // moves every surviving attempt into the local realm, which since the fetch
    // fix is a realm with a barrier of its own. Because removal refuses while
    // anything is unsettled, what lands there can never be holding one — the
    // deleted host's leftovers cannot start blocking local work.
    try t.expectEqual(@as(usize, 0), (try Store.operations.unsettled(&store, arena, null)).len);
}

test "gate: a server with a lease still held on it cannot be deleted" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_server_rm_leases");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    const server_id = try Store.servers.add(&store, .{
        .name = "race",
        .host = "10.0.0.1",
        .port = 22,
        .username = "ubuntu",
        .now = 100,
    });

    // `leases.server_id` is `ON DELETE CASCADE`, so unlike operations these are
    // not un-scoped by the delete, they are destroyed — together with the
    // `superseded_by` chain that is the only record of who displaced whom. A
    // peer session mid-change would find its claim simply gone.
    const scope: Store.leases.Scope = .{ .kind = .path, .key = "/srv/app" };
    switch (try Store.leases.acquire(&store, arena, .{
        .server_id = server_id,
        .scope = scope,
        .owner_request_id = "01PEEEEEEER0123456789ABCDE",
        .profile_token = "peer-machine",
        .ttl_secs = 300,
        .now = 200,
    })) {
        .acquired => {},
        .renewed, .conflict => return error.LeaseDidNotTake,
    }

    try t.expectEqual(
        Store.servers.Barrier{ .active_leases = 1 },
        try refusalOf(&store, "race", 210),
    );
    try t.expect((try Store.servers.getByName(&store, arena, "race")) != null);

    // A lapsed lease is not a barrier, and cannot be: the owner may be a
    // process that died hours ago, and a row nobody will ever release would
    // turn this into a permanent refusal with no way out. The expiry pass runs
    // inside the same transaction, so "still held" means held *now*.
    try mustRemove(&store, "race", 600);
    try t.expect((try Store.servers.getByName(&store, arena, "race")) == null);
}

/// The probe `servers.between_check_and_delete` installs for the gate below.
///
/// A file-scope struct because the hook is a bare function pointer with nothing
/// to capture. The gate installs it, runs one removal and clears it, so no two
/// tests can see each other's state through this.
const RemovalRace = struct {
    /// A second connection to the same database, opened before the removal
    /// starts. Opened in advance deliberately: opening one *during* the
    /// removal would measure how `Store.open` behaves under a held write lock
    /// rather than whether the window exists.
    var peer: ?*Store = null;
    var result: Result = .not_run;
    var failure: ?anyerror = null;

    const Result = enum {
        /// The hook never fired — the implementation has no window at all to
        /// probe, which is not the same as having a closed one.
        not_run,
        /// The peer could not take the write lock, so there is no instant at
        /// which the barrier could have changed under the check.
        excluded,
        /// The peer wrote. Whatever the check concluded is now stale, and the
        /// DELETE that follows is acting on it.
        slipped_through,
    };

    fn reset() void {
        peer = null;
        result = .not_run;
        failure = null;
    }

    /// Tries to make a barrier true from another connection, in the window
    /// between the barrier check and the DELETE.
    fn makeBarrierTrue() void {
        const store = peer orelse {
            failure = error.NoPeerConnection;
            return;
        };
        // The question is whether the lock is held *now*, not whether it will
        // still be held in five seconds, so do not wait for it.
        store.db.exec("PRAGMA busy_timeout=0") catch |err| {
            failure = err;
            return;
        };
        store.db.exec("BEGIN IMMEDIATE") catch {
            // SQLite allows one writer; the removal is it.
            result = .excluded;
            return;
        };
        result = .slipped_through;
        submit(store) catch |err| {
            failure = err;
        };
        store.db.exec("COMMIT") catch |err| {
            failure = err;
        };
    }

    fn submit(store: *Store) !void {
        const rid = testId("racewin");
        const request_id: []const u8 = &rid;
        try Store.operations.create(store, .{
            .request_id = request_id,
            .server_id = 1,
            .server_name = "race",
            .kind = .exec,
            .now = 500,
        });
        try Store.operations.advanceLocked(store, request_id, .connecting, 501);
        try Store.operations.advanceLocked(store, request_id, .submitted, 502);
    }
};

test "gate: the barrier check and the delete see one snapshot" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_server_rm_snapshot");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    _ = try Store.servers.add(&store, .{
        .name = "race",
        .host = "10.0.0.1",
        .port = 22,
        .username = "ubuntu",
        .now = 100,
    });

    // What this gate proves, exactly: while the removal holds its transaction,
    // no other connection can write, so there is no instant between "no
    // barriers" and "row deleted" at which a barrier could come into being.
    // That is the whole of the concurrency claim, and it rests on SQLite
    // allowing a single writer — `BEGIN IMMEDIATE` takes that writer slot at
    // the start rather than on the first write, which is why the check is
    // inside it and not merely near it.
    //
    // What it does *not* prove: anything about two processes genuinely running
    // at once, or about a peer that only reads, or about what SQLite does under
    // a busy handler with a nonzero timeout — the probe sets it to zero so the
    // answer is about the lock rather than about how long it waited. It is a
    // statement about exclusion, not a stress test.
    var peer = try Store.open(scratch.path);
    defer peer.close();

    RemovalRace.reset();
    RemovalRace.peer = &peer;
    Store.servers.between_check_and_delete = RemovalRace.makeBarrierTrue;
    defer {
        Store.servers.between_check_and_delete = null;
        RemovalRace.reset();
    }

    try mustRemove(&store, "race", 400);

    if (RemovalRace.failure) |err| return err;
    // `not_run` fails here too, and on purpose: a removal that never reaches
    // the window has not been shown to close it.
    try t.expectEqual(RemovalRace.Result.excluded, RemovalRace.result);

    // And the ledger agrees. Had the peer written, the DELETE would have
    // un-scoped an attempt that reached `submitted` after the check said the
    // host was clear — the exact row nobody would ever be told about. `ON
    // DELETE SET NULL` would have left it in the local realm, so that is where
    // it would show up.
    try t.expectEqual(@as(usize, 0), (try Store.operations.unsettled(&store, arena, null)).len);
    try t.expectEqual(@as(usize, 0), (try Store.operations.unsettled(&store, arena, 1)).len);
}

test "gate: an attempt with no server is inside the barrier, not outside it" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_local_realm_barrier");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    // A `fetch` writes a local path, so it has no row in `servers` to point at
    // and its `server_id` is NULL. Every guard matched `server_id = ?1`, which
    // is never true of NULL, and both call sites reached the guard through
    // `if (self.server_id) |…|` — so such an attempt ran no barrier and
    // appeared in nobody else's. Two of them writing the same local path
    // neither blocked nor were blocked.
    const local: execution.Scope = .{ .kind = .path, .key = "/tmp/artifacts" };
    const first = try execution.begin(&store, arena, scratch.io, .{
        .server_id = null,
        .server_name = "local",
        .kind = .fetch,
        .scope = local,
        .owner_token = "agent-a",
        .now = 100,
    });
    var a = switch (first) {
        .ready => |e| e,
        .blocked => return error.ScopeUnexpectedlyBlocked,
    };
    defer a.deinit();

    // Opened while `a` is still `created`, which never blocks anybody — so this
    // one legitimately gets past `begin`, and the refusal below has to come
    // from `submitted`. That matters: `submitted` is where the guard binds, and
    // a gate that only exercised `begin` would pass with the guard restored to
    // running on server-bound work alone.
    const second = try execution.begin(&store, arena, scratch.io, .{
        .server_id = null,
        .server_name = "local",
        .kind = .fetch,
        .scope = local,
        .owner_token = "agent-b",
        .now = 101,
    });
    var b = switch (second) {
        .ready => |e| e,
        .blocked => return error.SecondAttemptBlockedTooEarly,
    };
    defer b.deinit();

    try a.connecting();
    switch (try a.submitted()) {
        .submitted => {},
        .refused => return error.FirstAttemptRefused,
    }

    try b.connecting();
    switch (try b.submitted()) {
        .submitted => return error.LocalWorkIsNotInsideTheBarrier,
        .refused => |blocker| try t.expectEqualStrings(a.id(), blocker.unsettled.request_id),
    }

    // The two realms still do not see each other, and that is the correct
    // reading rather than a leftover: work on a host and work in a local
    // directory cannot collide, so a barrier that made them block each other
    // would refuse changes for no reason. A whole-server scope is the widest
    // there is, and even that does not reach across — which is the assertion
    // that would fail if the fix had been to drop the server filter instead of
    // to make NULL match NULL.
    const hosted = testId("realmsep");
    const hosted_id: []const u8 = &hosted;
    try seedTransferOperation(&store, hosted_id, .exec, 1);
    try Store.operations.advance(&store, hosted_id, .submitted, 120);

    const whole_host: execution.Scope = .{ .kind = .server };
    const on_host = try Store.operations.unsettledInScope(&store, arena, 1, whole_host);
    try t.expectEqual(@as(usize, 1), on_host.len);
    try t.expectEqualStrings(hosted_id, on_host[0].request_id);

    const on_this_machine = try Store.operations.unsettledInScope(&store, arena, null, whole_host);
    try t.expectEqual(@as(usize, 1), on_this_machine.len);
    try t.expectEqualStrings(a.id(), on_this_machine[0].request_id);

    // The half that is *not* closed, pinned so it stays a known limit rather
    // than becoming a rediscovered hole: the local realm has one barrier, not
    // two. `leases.server_id` is `NOT NULL REFERENCES servers(id)`, so there is
    // no row shape for "the machine running this" and the database refuses to
    // invent one. Giving leases a nullable server is a foreign-key change.
    try t.expectError(error.Constraint, Store.leases.acquire(&store, arena, .{
        .server_id = 0,
        .scope = local,
        .owner_request_id = "01AGENTCCCC0123456789ABCDE",
        .profile_token = "one-shared-machine",
        .ttl_secs = 300,
        .now = 130,
    }));
}

test "gate: a checkpoint abandoned mid-publish is recovered to indeterminate_publish" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_recover_publishing");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    const rid = testId("midpub");
    const request_id: []const u8 = &rid;
    const id = try seedAbandonedMidAct(
        &store,
        request_id,
        "/srv/app/mp.bin",
        "/srv/app/mp.bin.part",
        .publishing,
    );
    try reconcileDeadTransfer(&store, arena, request_id, .remote_started, "the attempt died without reporting", 210);

    var heir = try beginRecovery(&store, arena, scratch.io, 200);
    defer heir.deinit();

    // `indeterminate_publish`, and not `paused`. The process entered
    // `publishing`, which means it had begun the rename; normalising to `paused`
    // would assert the rename did not happen, and a resume acting on that
    // assertion would overwrite an artifact that may already be at the
    // destination. "It may or may not have landed" is the one true thing here,
    // and it is a state this schema already has.
    const became = try heir.recoverCheckpoint(id, request_id);
    try t.expectEqual(Store.transfers.State.indeterminate_publish, became);

    const recovered = (try Store.transfers.get(&store, arena, id)).?;
    try t.expectEqual(Store.transfers.State.indeterminate_publish, recovered.state);
    try t.expectEqualStrings(heir.id(), recovered.request_id);

    // The digest survives, and the contrast with the `paused` recovery is the
    // point: those bytes were hashed and then handed to a rename. Nobody may
    // truncate them now, so the reading still describes the artifact and stays
    // where the adjudication will look for it. `paused` is the opposite case —
    // see the gate below.
    try t.expectEqualStrings("abc123", recovered.verified_sha256.?);
    const kept = try Store.receipts.list(&store, arena, request_id);
    try t.expect(std.mem.indexOf(
        u8,
        kept[kept.len - 1].detail_json.?,
        "\"discardedVerifiedSha256\":null",
    ) != null);

    // Not resumable, deliberately: nobody may append to a partial whose rename
    // may already have consumed it.
    try t.expectEqual(
        @as(?Store.transfers.Checkpoint, null),
        try Store.transfers.findResumable(&store, arena, .{ .server = 1 }, "/srv/app/mp.bin"),
    );
    // And still holding the path, for the same reason.
    const rival = testId("mprival");
    const rival_id: []const u8 = &rival;
    try seedTransferOperation(&store, rival_id, .transfer_push, 1);
    try t.expectError(error.DestinationHeld, Store.transfers.create(&store, .{
        .request_id = rival_id,
        .direction = .push,
        .dest_side = .{ .server = 1 },
        .dest_path = "/srv/app/mp.bin",
        .partial_path = "/srv/app/mp.bin.rival",
        .source = .{ .local_file = .{ .path = "./out.bin", .sha256 = "aaaa" } },
        .chunk_size = 100,
        .now = 230,
    }));

    // It is adjudicable, which is what "goes through adjudication like any
    // other parked publish" has to mean to be worth anything: the row is the
    // heir's now, so the heir's own resolution reaches it. The heir went and
    // looked, could not establish the outcome from the connection, and settled
    // `indeterminate` — the only state a resolution may annotate.
    try Store.operations.advance(&store, heir.id(), .connecting, 240);
    try Store.operations.advance(&store, heir.id(), .submitted, 241);
    heir.status = .submitted;
    _ = try heir.settleAttached(.{ .indeterminate = .{
        .reason = "the recovery connection dropped before it could read the destination",
        .last_observed = .submitted,
    } }, .{ .source = .reconcile });

    try t.expect((try Store.receipts.resolve(&store, arena, heir.id(), .failed, .{
        .destination_absent = .{
            .side = .remote,
            .path = "/srv/app/mp.bin",
            .verification_method = "stat => ENOENT",
        },
    }, 250)) == .resolved);
    try t.expectEqual(
        Store.transfers.State.failed_publish,
        (try Store.transfers.get(&store, arena, id)).?.state,
    );
}

test "gate: a recovery that fails halfway leaves the row and both trails alone" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_recover_atomic");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    const rid = testId("halfway");
    const request_id: []const u8 = &rid;
    const id = try seedAbandonedMidAct(
        &store,
        request_id,
        "/srv/app/hw.bin",
        "/srv/app/hw.bin.part",
        .publishing,
    );
    try reconcileDeadTransfer(&store, arena, request_id, .remote_started, "the attempt died without reporting", 210);

    var heir = try beginRecovery(&store, arena, scratch.io, 200);
    defer heir.deinit();

    // A failure after the row has changed hands *and* been rewritten *and* the
    // first receipt written. Ordering cannot undo any of that — only the
    // transaction can, which is why the state change has to be inside it. A
    // recovery that half-happened would leave a row in a state its own ledger
    // never explains, owned by an operation whose trail never mentions it.
    try store.db.exec(
        \\CREATE TRIGGER gate_block_recover_receipt
        \\BEFORE INSERT ON operation_events WHEN NEW.phase = 'adopted'
        \\BEGIN SELECT RAISE(ABORT, 'injected: the far half of the recovery fails'); END;
    );
    try t.expectError(error.Constraint, heir.recoverCheckpoint(id, request_id));
    try store.db.exec("DROP TRIGGER gate_block_recover_receipt");

    const untouched = (try Store.transfers.get(&store, arena, id)).?;
    if (untouched.state != .publishing) return error.NormalisationOutlivedTheFailedRecovery;
    if (!std.mem.eql(u8, untouched.request_id, request_id))
        return error.CheckpointChangedHandsOnAFailedRecovery;
    if (try countKind(&store, arena, request_id, "checkpoint") != 0)
        return error.SurrenderReceiptOutlivedTheFailedRecovery;
    if (try countKind(&store, arena, heir.id(), "checkpoint") != 0)
        return error.RecoverReceiptOutlivedTheFailedRecovery;

    // And the real one still works afterwards, so the gate above is not
    // satisfied by a recovery that never works at all.
    try t.expectEqual(
        Store.transfers.State.indeterminate_publish,
        try heir.recoverCheckpoint(id, request_id),
    );
}

test "gate: recovery is refused for a row that was not abandoned mid-act" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_recover_wrong_state");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    // An ordinary paused transfer whose owner is settled. It is adoptable, and
    // adoption is what it wants: recovery would rewrite a state nobody
    // interrupted. Refusing here is what keeps "recovered" from becoming a
    // second name for "adopted", with a state change nobody asked for attached.
    const rid = testId("notmidact");
    const request_id: []const u8 = &rid;
    const id = try seedCheckpoint(&store, request_id, "/srv/app/idle.bin", "/srv/app/idle.bin.part");
    try Store.transfers.setState(&store, id, request_id, .probing, null, 110);
    try abandonOwner(&store, request_id, "the caller walked away", 120);

    var heir = try beginRecovery(&store, arena, scratch.io, 200);
    defer heir.deinit();

    try t.expectError(error.CheckpointNotRecoverable, heir.recoverCheckpoint(id, request_id));
    try t.expectEqual(
        Store.transfers.State.probing,
        (try Store.transfers.get(&store, arena, id)).?.state,
    );
    try t.expectEqual(@as(usize, 0), try countKind(&store, arena, heir.id(), "checkpoint"));

    // The route that does fit it changes nothing but the owner.
    try heir.adoptCheckpoint(id, request_id);
    const adopted = (try Store.transfers.get(&store, arena, id)).?;
    try t.expectEqual(Store.transfers.State.probing, adopted.state);
    try t.expectEqualStrings(heir.id(), adopted.request_id);
}

test "gate: a checkpoint changes hands only to an operation fit to run it" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_adopt_eligibility");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    const rid = testId("adoptsrc");
    const request_id: []const u8 = &rid;
    const id = try seedCheckpoint(&store, request_id, "/srv/app/out.bin", "/srv/app/out.bin.part");
    // Settled up front so every refusal below is about the *heir*. An
    // unsettled incumbent is its own refusal, with its own name, and leaving
    // one here would make all four assertions pass without the heir clause
    // existing at all.
    try abandonOwner(&store, request_id, "the pusher was killed", 140);

    // An operation that has already ended cannot pick anything up: it has
    // nothing left to do and, if it was settled from evidence, it has already
    // committed to an outcome that these bytes would contradict. This is the
    // same window `recordExpectedHash` guards, reached from the other side.
    const settled = testId("adoptdead");
    const settled_id: []const u8 = &settled;
    try seedTransferOperation(&store, settled_id, .transfer_push, 1);
    _ = try Store.receipts.settle(&store, settled_id, .{
        .never_submitted = .{ .transport_error = "connection refused" },
    }, .{}, 150);
    try t.expectError(
        error.AdoptingOperationNotEligible,
        locked(&store, Store.transfers.adoptLocked, .{ &store, id, request_id, settled_id, 160 }),
    );

    // A job cannot inherit a push. Kind is what decides which evidence may
    // later settle the request, so an heir of the wrong kind would be judged
    // by rules written for other work.
    const wrong_kind = testId("adoptjob");
    const wrong_kind_id: []const u8 = &wrong_kind;
    try seedTransferOperation(&store, wrong_kind_id, .job, 1);
    try t.expectError(
        error.AdoptingOperationNotEligible,
        locked(&store, Store.transfers.adoptLocked, .{ &store, id, request_id, wrong_kind_id, 161 }),
    );

    // Nor may an operation bound to another machine: the partial and the
    // destination are on server 1, and nothing this heir could connect to has
    // either of them.
    const wrong_server = testId("adoptsrv2");
    const wrong_server_id: []const u8 = &wrong_server;
    try seedTransferOperation(&store, wrong_server_id, .transfer_push, 2);
    try t.expectError(
        error.AdoptingOperationNotEligible,
        locked(&store, Store.transfers.adoptLocked, .{ &store, id, request_id, wrong_server_id, 162 }),
    );

    // None of the three refusals moved it.
    try t.expectEqualStrings(
        request_id,
        (try Store.transfers.get(&store, arena, id)).?.request_id,
    );

    // A fit heir takes it...
    const heir = testId("adoptheir");
    const heir_id: []const u8 = &heir;
    try seedTransferOperation(&store, heir_id, .transfer_push, 1);
    try locked(&store, Store.transfers.adoptLocked, .{ &store, id, request_id, heir_id, 170 });
    try t.expectEqualStrings(
        heir_id,
        (try Store.transfers.get(&store, arena, id)).?.request_id,
    );

    // ...and the resume racing it finds the row already gone, under a name
    // that says so rather than one that says the heir was unfit.
    const loser = testId("adoptloser");
    const loser_id: []const u8 = &loser;
    try seedTransferOperation(&store, loser_id, .transfer_push, 1);
    try t.expectError(
        error.CheckpointOwnerChanged,
        locked(&store, Store.transfers.adoptLocked, .{ &store, id, request_id, loser_id, 171 }),
    );

    // The last of the three refusals, and the one that is easy to conflate
    // with the others: a perfectly fit heir asking for a checkpoint that has
    // moved past the last byte. Nothing is wrong with the heir, so telling it
    // it was ineligible would send it looking for a fault it does not have —
    // there is simply no offset left here for anyone to resume from.
    for ([_]Store.transfers.State{ .probing, .transferring, .verifying }) |step|
        try Store.transfers.setState(&store, id, heir_id, step, null, 180);
    // The new incumbent is settled first, for the same reason the original one
    // was at the top, and this sub-case is where it was missed. `heir_id` is
    // still at `connecting`, so the statement's incumbent conjunct refuses this
    // adopt on its own — and the classifier answers `isAdoptable` before it
    // asks about the incumbent, so the assertion below held whether or not
    // `adopt_sql` still constrained the state at all. Deleting that conjunct
    // left this gate green. With the incumbent settled, the state list is the
    // only conjunct left that can refuse the write.
    try abandonOwner(&store, heir_id, "the resumed pusher was killed too", 179);
    const late_heir = testId("adoptlate");
    const late_heir_id: []const u8 = &late_heir;
    try seedTransferOperation(&store, late_heir_id, .transfer_push, 1);
    try t.expectError(
        error.CheckpointNotResumable,
        locked(&store, Store.transfers.adoptLocked, .{ &store, id, heir_id, late_heir_id, 181 }),
    );
    try t.expectEqualStrings(
        heir_id,
        (try Store.transfers.get(&store, arena, id)).?.request_id,
    );
}

test "gate: a hand-over does not move a transfer to another machine" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_adopt_same_machine");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    // A pull, deliberately. `dest_side` pins the machine for a push and reads
    // `local` for a pull and a fetch, so the per-direction clause could only
    // ever catch the push — while a pull's *source* is a remote file whose only
    // record of which host it lives on is the owning operation's `server_id`.
    // Adopt is the one statement that changes that owner, so without a
    // same-machine conjunct this checkpoint would go on describing
    // `/data/x.bin` while naming a machine nobody compared it against.
    const rid = testId("pullsrc");
    const request_id: []const u8 = &rid;
    try seedTransferOperation(&store, request_id, .transfer_pull, 1);
    const id = try Store.transfers.create(&store, .{
        .request_id = request_id,
        .direction = .pull,
        .dest_side = .local,
        .dest_path = "/var/tmp/x.bin",
        .partial_path = "/var/tmp/x.bin.part",
        .source = .{ .remote_file = .{ .path = "/data/x.bin" } },
        .chunk_size = 100,
        .now = 110,
    });

    // Right kind, right destination side, not settled: everything the heir
    // clause used to look at says yes. It is bound to the wrong host.
    const stray = testId("pullstray");
    const stray_id: []const u8 = &stray;
    try seedTransferOperation(&store, stray_id, .transfer_pull, 2);
    // The incumbent is settled first so the refusal below is about the heir's
    // machine and not about the incumbent still being live.
    try abandonOwner(&store, request_id, "the puller was killed", 115);
    try t.expectError(
        error.AdoptingOperationNotEligible,
        locked(&store, Store.transfers.adoptLocked, .{ &store, id, request_id, stray_id, 120 }),
    );
    try t.expectEqualStrings(
        request_id,
        (try Store.transfers.get(&store, arena, id)).?.request_id,
    );

    // The same heir on the right host takes it, which is what keeps the
    // conjunct from being satisfied by refusing every pull.
    const heir = testId("pullheir");
    const heir_id: []const u8 = &heir;
    try seedTransferOperation(&store, heir_id, .transfer_pull, 1);
    try locked(&store, Store.transfers.adoptLocked, .{ &store, id, request_id, heir_id, 121 });
    try t.expectEqualStrings(
        heir_id,
        (try Store.transfers.get(&store, arena, id)).?.request_id,
    );
}

/// Settles a *transfer* `request_id` into `want`, by a route a transfer really
/// has.
///
/// Two of the five terminal statuses have no such route, and saying so out loud
/// is the point of this fixture rather than an inconvenience of it.
/// `terminalDescribesKind` refuses `exited`, `remote_deadline` and
/// `remote_cancel_confirmed` for every transfer kind — each carries a fact about
/// a process, and a transfer is judged by an artifact at a destination it
/// declared — so `completed` and `timed_out` cannot be settled at all until a
/// producer brings a terminal that carries what it read back off that
/// destination. They are returned as a named error instead of being approximated
/// with the nearest terminal that would compile, so a caller decides what to do
/// about a status its subject cannot reach rather than silently proving
/// something about a different one.
///
/// The three that remain each take their own route, from the state that route is
/// credible in (`op_state.canSettle`):
///
///  * `failed` — `never_submitted` from `connecting`: the transport proved the
///    first byte never left, which is the one failure a transfer can establish
///    without looking at a destination;
///  * `cancelled` — `local_abandon` from `connecting`: given up on before
///    anything was handed over, so there is nothing at the far end to have
///    claimed anything about;
///  * `indeterminate` — from `submitted`, and this is the state a killed
///    transfer is really left in.
///
/// Exhaustive over `Status`: a new terminal status has to be given a route here,
/// or refused here, rather than dropping out of the walk below unproven.
fn settleInto(store: *Store, request_id: []const u8, comptime want: op_state.Status, now: i64) !void {
    // Chosen before anything is advanced, so a refused status leaves the row
    // exactly where its caller left it.
    const terminal: op_state.Terminal = switch (want) {
        .completed, .timed_out => return error.TransferHasNoRouteToThisStatus,
        .failed => .{ .never_submitted = .{ .transport_error = "connection refused" } },
        .cancelled => .{ .local_abandon = .{ .reason = "the operator gave up before dialing" } },
        .indeterminate => .{ .indeterminate = .{
            .reason = "the connection dropped",
            .last_observed = .submitted,
        } },
        else => @compileError("not a terminal status: " ++ @tagName(want)),
    };
    try Store.operations.advance(store, request_id, .connecting, now);
    if (want == .indeterminate) try Store.operations.advance(store, request_id, .submitted, now);
    _ = try Store.receipts.settle(store, request_id, terminal, .{}, now);
}

/// Drives `request_id` to `want` by the route a real attempt takes to it.
///
/// Exhaustive over `Status` — through `settleInto` for the terminals — so a new
/// status has to be given a route rather than dropping silently out of the walk
/// below and leaving its cell unproven. Two of them come back refused rather
/// than driven; `settleInto` says which and why.
fn driveTo(store: *Store, request_id: []const u8, comptime want: op_state.Status, now: i64) !void {
    switch (want) {
        .created => {},
        .connecting => try Store.operations.advance(store, request_id, .connecting, now),
        .submitted, .remote_started => {
            try Store.operations.advance(store, request_id, .connecting, now);
            try Store.operations.advance(store, request_id, .submitted, now);
            if (want == .remote_started)
                try Store.operations.advance(store, request_id, .remote_started, now);
        },
        else => try settleInto(store, request_id, want, now),
    }
}

test "gate: a checkpoint is taken only from an attempt that cannot still be running" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_adopt_incumbent_settled");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    // Every status, one fresh checkpoint each, with the answer read off
    // `blocksScope` — the predicate the scope barrier itself is written in —
    // rather than transcribed. A fresh row per status because the accepting
    // cells really do move the checkpoint, and a shared row would end the walk
    // at the first one.
    //
    // The rule was `isTerminal`, and the gap was `indeterminate`: terminal, and
    // meaning precisely that nobody knows whether the remote process stopped.
    // An heir could take a partial away from an attempt that may still be
    // streaming into it — the exact failure the incumbent clause exists to
    // prevent, admitted by the predicate meant to prevent it.
    inline for (@typeInfo(op_state.Status).@"enum".fields) |field| {
        const status: op_state.Status = @enumFromInt(field.value);
        const owner = testId("own" ++ @tagName(status));
        const owner_id: []const u8 = &owner;
        const cp = try seedCheckpoint(
            &store,
            owner_id,
            "/srv/app/" ++ @tagName(status) ++ ".bin",
            "/srv/app/" ++ @tagName(status) ++ ".bin.part",
        );

        // Two statuses a transfer cannot be driven to at all, since
        // `terminalDescribesKind` stopped letting a process's fate settle an
        // artifact's: every terminal producing `completed` or `timed_out`
        // carries a fact about a process, and all three are refused for a
        // transfer kind. Asserted rather than skipped — the fixture has to
        // refuse *these two and only these two*, so a later change that hands a
        // transfer a route to one of them fails here instead of quietly
        // widening the walk.
        //
        // The walk still exercises both answers `blocksScope` can give: both of
        // the unreachable pair are non-blocking, and `failed` and `cancelled`
        // below reach that side of the predicate through `never_submitted` and
        // `local_abandon`.
        if (comptime status == .completed or status == .timed_out) {
            try t.expectError(
                error.TransferHasNoRouteToThisStatus,
                driveTo(&store, owner_id, status, 140),
            );
            try t.expect(!status.blocksScope());
            continue;
        }
        try driveTo(&store, owner_id, status, 140);

        const taker = testId("tak" ++ @tagName(status));
        const taker_id: []const u8 = &taker;
        try seedTransferOperation(&store, taker_id, .transfer_push, 1);

        if (comptime status.blocksScope()) {
            try t.expectError(
                error.SurrenderingOperationMayStillBeRunning,
                locked(&store, Store.transfers.adoptLocked, .{ &store, cp, owner_id, taker_id, 141 }),
            );
            // The refusal left ownership exactly where it was — a hand-over
            // that half-happened would be worse than one that did not happen.
            try t.expectEqualStrings(
                owner_id,
                (try Store.transfers.get(&store, arena, cp)).?.request_id,
            );
        } else {
            try locked(&store, Store.transfers.adoptLocked, .{ &store, cp, owner_id, taker_id, 141 });
            try t.expectEqualStrings(
                taker_id,
                (try Store.transfers.get(&store, arena, cp)).?.request_id,
            );
        }
    }

    // And the way out of the one refusal that would otherwise be permanent. A
    // hard-killed transfer settles `indeterminate`, which blocks — so the price
    // of the rule is `terminus request reconcile <id>`, and the price has to be
    // payable.
    //
    // `resolve` never overwrites `status`; it records the later-proven truth in
    // `resolved_status` beside it. So the incumbent below still reads
    // `indeterminate` in the column a naive guard would look at, and is
    // admitted anyway — which is the point: what the hand-over requires is
    // positive evidence, and `resolved_status` has exactly one writer, which
    // demands typed evidence before it writes there.
    const stuck = testId("reconciled");
    const stuck_id: []const u8 = &stuck;
    const stuck_cp = try seedCheckpoint(
        &store,
        stuck_id,
        "/srv/app/reconciled.bin",
        "/srv/app/reconciled.bin.part",
    );
    try driveTo(&store, stuck_id, .indeterminate, 200);

    const late = testId("lateheir");
    const late_id: []const u8 = &late;
    try seedTransferOperation(&store, late_id, .transfer_push, 1);
    try t.expectError(
        error.SurrenderingOperationMayStillBeRunning,
        locked(&store, Store.transfers.adoptLocked, .{ &store, stuck_cp, stuck_id, late_id, 201 }),
    );

    _ = try Store.receipts.resolve(&store, arena, stuck_id, .cancelled, .{
        .operator_override = .{ .reason = "the host was rebuilt; nothing of ours is left", .by = "czykl" },
    }, 210);
    try locked(&store, Store.transfers.adoptLocked, .{ &store, stuck_cp, stuck_id, late_id, 211 });
    try t.expectEqualStrings(
        late_id,
        (try Store.transfers.get(&store, arena, stuck_cp)).?.request_id,
    );

    // The observation was not rewritten to buy that. `status` is still what we
    // saw, and the hand-over cleared because the resolution is read beside it.
    const reconciled = (try Store.operations.get(&store, arena, stuck_id)).?;
    try t.expectEqual(op_state.Status.indeterminate, reconciled.status);
    try t.expectEqual(op_state.ResolvedStatus.cancelled, reconciled.resolved_status.?);
}

test "gate: a checkpoint hand-over is recorded on both sides or on neither" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_handover_atomic");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    const rid = testId("handover");
    const request_id: []const u8 = &rid;
    const id = try seedCheckpoint(&store, request_id, "/srv/app/out.bin", "/srv/app/out.bin.part");

    // The attempt that owned it never got its connection and was settled
    // `failed`. That is not an edge case: a checkpoint becomes adoptable
    // *because* the attempt holding it stopped, so the surrendering side is
    // normally settled by the time anyone comes for it.
    _ = try Store.receipts.settle(&store, request_id, .{
        .never_submitted = .{ .transport_error = "connection refused" },
    }, .{}, 150);

    const start = try execution.begin(&store, arena, scratch.io, .{
        .server_id = 1,
        .server_name = "race",
        .kind = .transfer_push,
        .owner_token = "gate",
        .now = 200,
    });
    var heir = switch (start) {
        .ready => |e| e,
        .blocked => return error.ScopeUnexpectedlyBlocked,
    };
    defer heir.deinit();

    // A hand-over the checkpoint refuses must leave no trace on either side.
    // This half proves *ordering* and only ordering: the refusable write is
    // first, so nothing had been attempted when it failed.
    try t.expectError(error.CheckpointOwnerChanged, heir.adoptCheckpoint(id, "01N0B0DY000000000000000000"));
    try t.expectEqual(@as(usize, 0), try countKind(&store, arena, request_id, "checkpoint"));
    try t.expectEqual(@as(usize, 0), try countKind(&store, arena, heir.id(), "checkpoint"));
    try t.expectEqualStrings(
        request_id,
        (try Store.transfers.get(&store, arena, id)).?.request_id,
    );

    // And this half is the one the transaction is actually for: a failure
    // *after* the row has changed hands and the first receipt is written. Only
    // a rollback can undo those; ordering cannot, because by then both have
    // happened. The trigger stands in for whatever really fails there — a disk
    // error, a killed process — because the three writes have no natural way to
    // fail in between, which is exactly why this was never proven before.
    try store.db.exec(
        \\CREATE TRIGGER gate_block_adopt_receipt
        \\BEFORE INSERT ON operation_events WHEN NEW.phase = 'adopted'
        \\BEGIN SELECT RAISE(ABORT, 'injected: the far half of the hand-over fails'); END;
    );
    try t.expectError(error.Constraint, heir.adoptCheckpoint(id, request_id));
    try store.db.exec("DROP TRIGGER gate_block_adopt_receipt");

    // The surrender receipt was written before the failure and must not have
    // survived it: an abandoned attempt's trail claiming it gave away a
    // checkpoint it still holds reads as a fact, not as an incomplete record.
    // Named rather than counted, because the two sides fail for different
    // reasons and a bare "expected 0, found 1" cannot say which half of the
    // hand-over leaked.
    if (try countKind(&store, arena, request_id, "checkpoint") != 0)
        return error.SurrenderReceiptOutlivedTheFailedHandover;
    if (try countKind(&store, arena, heir.id(), "checkpoint") != 0)
        return error.AdoptReceiptOutlivedTheFailedHandover;
    if (!std.mem.eql(u8, (try Store.transfers.get(&store, arena, id)).?.request_id, request_id))
        return error.CheckpointChangedHandsOnAFailedHandover;

    // The real one moves the row and records it on both operations at once.
    try heir.adoptCheckpoint(id, request_id);
    try t.expectEqual(@as(usize, 1), try countKind(&store, arena, request_id, "checkpoint"));
    try t.expectEqual(@as(usize, 1), try countKind(&store, arena, heir.id(), "checkpoint"));
    try t.expectEqualStrings(
        heir.id(),
        (try Store.transfers.get(&store, arena, id)).?.request_id,
    );

    // Each side names the other, so either trail alone answers "who took it"
    // without a join through a checkpoint that has since moved on again.
    const surrendered = (try Store.receipts.list(&store, arena, request_id));
    const surrender_detail = surrendered[surrendered.len - 1].detail_json.?;
    try t.expect(std.mem.indexOf(u8, surrender_detail, "checkpoint_surrendered") != null);
    try t.expect(std.mem.indexOf(u8, surrender_detail, heir.id()) != null);

    // And recording it did not revise the verdict of the attempt that lost it.
    // A `checkpoint` observation cannot carry a terminal status, which is what
    // makes writing one onto a settled operation honest rather than a second
    // opinion.
    try t.expectEqual(
        op_state.Status.failed,
        (try Store.operations.get(&store, arena, request_id)).?.status,
    );
}
