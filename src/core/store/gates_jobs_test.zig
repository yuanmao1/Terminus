//! The local `jobs` table: every write is a compare-and-swap, and the cached
//! terminal written beside the receipt.
//!
//! This table is a cache of what the ledger already knows, kept so `job ls` does
//! not have to reconstruct a status per row. That makes stale writes the whole
//! risk: a launch that lost its name must not finish the row that replaced it, a
//! settled row must not be overwritten by a second observer, a finish written
//! against a stale reading of the row is refused, and a cursor advance is a
//! compare-and-swap with no business touching the finish.
//!
//! Two rules are about who may delete: a relaunch may not delete a running row
//! and `job rm` may; and an unowned 0.1.x row is still writable while matching
//! no launch's expectation, because rows predating the owner column exist and
//! must not become unreachable.
//!
//! The last gate is the composite: the terminal and the cache row it describes
//! are written once, together, so no reader can see one without the other.

const std = @import("std");
const Store = @import("Store.zig");
const op_state = @import("op_state.zig");
const execution = @import("../execution.zig");

// The shared fixtures. Aliased under their own names so a gate reads the
// same here as it did when every gate was in one file.
const fixtures = @import("gates_fixtures.zig");
const Scratch = fixtures.Scratch;
const seedServer = fixtures.seedServer;
const mustApply = fixtures.mustApply;

fn jobRefusalOf(write: Store.jobs.Write) !Store.jobs.Conflict {
    return switch (write) {
        .applied => error.JobsWriteUnexpectedlyApplied,
        .refused => |conflict| conflict,
    };
}

/// A job row plus the attempt and operation behind it, as `run --name X`
/// leaves them.
const SeededJob = struct {
    request_id: []const u8,
    row: Store.jobs.Job,
};

fn seedJob(
    store: *Store,
    arena: std.mem.Allocator,
    io: std.Io,
    name: []const u8,
    sentinel: []const u8,
    now: i64,
) !SeededJob {
    const start = try execution.begin(store, arena, io, .{
        .server_id = 1,
        .server_name = "lease-host",
        .kind = .job,
        .scope = .{ .kind = .job, .key = name },
        .alias = name,
        .owner_token = "agent",
        .now = now,
    });
    var opened = switch (start) {
        .ready => |ready| ready,
        .blocked => return error.ScopeUnexpectedlyBlocked,
    };
    // A launch detaches rather than settling; nothing here is dropping an
    // undecided attempt on the floor.
    opened.settled = true;
    const request_id = try arena.dupe(u8, opened.id());
    _ = try Store.jobs.create(store, 1, name, "make things", sentinel, request_id, now);
    _ = try Store.job_attempts.create(store, .{
        .request_id = request_id,
        .server_id = 1,
        .server_name = "lease-host",
        .job_name = name,
        .attempt_no = 1,
        .sentinel = sentinel,
        .tmux_session = "job-x",
        .now = now,
    });
    return .{
        .request_id = request_id,
        .row = (try Store.jobs.getByName(store, arena, 1, name)).?,
    };
}

test "gate: a launch that lost its name cannot finish the row that replaced it" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_jobs_recycled_rowid");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    try seedServer(&store);

    // The v9 migration's own story, played out. A launcher reserves the name,
    // aborts, and its row is displaced by a successor that inherits the very
    // same rowid — sqlite hands the next INSERT the id of the row just
    // deleted. Both rows are `pending`, so nothing but the owner tells them
    // apart, which is exactly why the owner is in the statement.
    const first = try seedJob(&store, arena, scratch.io, "deploy", "__TERMINUS_JOB_1__", 1000);
    const stale = first.row.finishExpectation();
    try mustApply(try Store.jobs.remove(&store, first.row.removeExpectation(), .superseded_by_relaunch));

    const second = try seedJob(&store, arena, scratch.io, "deploy", "__TERMINUS_JOB_2__", 2000);
    try t.expectEqual(first.row.id, second.row.id); // the rowid really is recycled
    try t.expectEqual(Store.jobs.Status.pending, second.row.status);

    // The aborted launcher's observer now writes what it believes it saw. The
    // id matches and the status matches — only the owner does not, and that is
    // the whole difference between recording a fact and killing somebody
    // else's reservation.
    const conflict = try jobRefusalOf(try Store.jobs.markFinishedUnattached(&store, stale, .killed, null, 3000));
    switch (conflict) {
        .not_ours => |status| try t.expectEqual(Store.jobs.Status.pending, status),
        else => return error.WrongRefusal,
    }

    // And the successor is untouched: same status, same sentinel, same owner.
    const survivor = (try Store.jobs.getByName(&store, arena, 1, "deploy")).?;
    try t.expectEqual(Store.jobs.Status.pending, survivor.status);
    try t.expectEqualStrings("__TERMINUS_JOB_2__", survivor.sentinel);
    try t.expectEqualStrings(second.request_id, survivor.owner_request_id.?);

    // The control: the owner that really does hold the row can finish it. A
    // gate that only showed a refusal would also pass if the write had simply
    // stopped working.
    try mustApply(try Store.jobs.markFinishedUnattached(
        &store,
        survivor.finishExpectation(),
        .exited,
        0,
        3100,
    ));
    try t.expectEqual(
        Store.jobs.Status.exited,
        (try Store.jobs.getByName(&store, arena, 1, "deploy")).?.status,
    );
}

test "gate: a settled job row is not overwritten by a second observer" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_jobs_settled_once");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    try seedServer(&store);

    const seeded = try seedJob(&store, arena, scratch.io, "deploy", "__TERMINUS_JOB_1__", 1000);
    try t.expect(try Store.jobs.markStarted(&store, seeded.request_id));

    // `job kill` records that somebody stopped it.
    const running = (try Store.jobs.getByName(&store, arena, 1, "deploy")).?;
    try mustApply(try Store.jobs.markFinishedUnattached(
        &store,
        running.finishExpectation(),
        .killed,
        null,
        2000,
    ));

    // A second observer now reads the settled row and finds an exit status the
    // job happened to leave behind. Its snapshot is correct — it really did
    // read `killed` — so nothing but the transition rule stands between it and
    // rewriting the first observer's verdict. There was no transition rule
    // here at all, and `markFinished` would happily overwrite `killed` with
    // `exited`, on the row `run --name X` consults before it agrees to launch.
    const settled_row = (try Store.jobs.getByName(&store, arena, 1, "deploy")).?;
    const conflict = try jobRefusalOf(try Store.jobs.markFinishedUnattached(
        &store,
        settled_row.finishExpectation(),
        .exited,
        0,
        3000,
    ));
    switch (conflict) {
        .illegal_transition => |move| {
            try t.expectEqual(Store.jobs.Status.killed, move.from);
            try t.expectEqual(Store.jobs.Status.exited, move.to);
        },
        else => return error.WrongRefusal,
    }

    // The verdict and its columns are exactly as the first observer left them.
    const after = (try Store.jobs.getByName(&store, arena, 1, "deploy")).?;
    try t.expectEqual(Store.jobs.Status.killed, after.status);
    try t.expectEqual(@as(?i64, null), after.exit_code);
    try t.expectEqual(@as(?i64, 2000), after.finished_at);
}

test "gate: a finish written against a stale reading of the row is refused" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_jobs_stale_snapshot");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    try seedServer(&store);

    // An observer reads the row while it is still a reservation...
    const seeded = try seedJob(&store, arena, scratch.io, "deploy", "__TERMINUS_JOB_1__", 1000);
    const stale = seeded.row.finishExpectation();
    try t.expectEqual(Store.jobs.Status.pending, stale.status);

    // ...and the launcher reaches the remote shell in the meantime. Both
    // `pending → killed` and `running → killed` are legal moves, so the
    // transition rule cannot catch this one: what catches it is the snapshot,
    // which says the caller decided against a row that is no longer in that
    // state.
    try t.expect(try Store.jobs.markStarted(&store, seeded.request_id));

    const conflict = try jobRefusalOf(try Store.jobs.markFinishedUnattached(&store, stale, .killed, null, 2000));
    switch (conflict) {
        .status_moved => |moved| {
            try t.expectEqual(Store.jobs.Status.pending, moved.expected);
            try t.expectEqual(Store.jobs.Status.running, moved.found);
        },
        else => return error.WrongRefusal,
    }
    try t.expectEqual(
        Store.jobs.Status.running,
        (try Store.jobs.getByName(&store, arena, 1, "deploy")).?.status,
    );

    // Re-reading the row is the whole of the fix, which is what makes this a
    // refusal rather than a wall.
    const fresh = (try Store.jobs.getByName(&store, arena, 1, "deploy")).?;
    try mustApply(try Store.jobs.markFinishedUnattached(&store, fresh.finishExpectation(), .killed, null, 2100));
}

test "gate: a cursor advance is a compare-and-swap, and a finish is not one of its concerns" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_jobs_cursor");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    try seedServer(&store);

    const seeded = try seedJob(&store, arena, scratch.io, "deploy", "__TERMINUS_JOB_1__", 1000);
    try t.expect(try Store.jobs.markStarted(&store, seeded.request_id));

    // Two consumers both read from 0. The first records that it consumed 8192
    // bytes; the second, which read 4096 of the same bytes, has to find out
    // rather than move the position back under the first one's feet.
    const reader_a = (try Store.jobs.getByName(&store, arena, 1, "deploy")).?.cursorExpectation();
    const reader_b = reader_a;
    try mustApply(try Store.jobs.setCursor(&store, reader_a, 8192));
    const conflict = try jobRefusalOf(try Store.jobs.setCursor(&store, reader_b, 4096));
    switch (conflict) {
        .cursor_moved => |moved| {
            try t.expectEqual(@as(i64, 0), moved.expected);
            try t.expectEqual(@as(i64, 8192), moved.found);
        },
        else => return error.WrongRefusal,
    }
    try t.expectEqual(@as(i64, 8192), (try Store.jobs.getByName(&store, arena, 1, "deploy")).?.read_cursor);

    // The two snapshots are deliberately different sets. A job that finishes
    // while somebody is reading its log must not lose the advance, and a
    // consumer moving the cursor must not make a finish fail.
    const finish = (try Store.jobs.getByName(&store, arena, 1, "deploy")).?.finishExpectation();
    const reading = (try Store.jobs.getByName(&store, arena, 1, "deploy")).?.cursorExpectation();
    try mustApply(try Store.jobs.markFinishedUnattached(&store, finish, .exited, 0, 2000));
    // Read from a settled row: the log is still there and still being
    // consumed, so the advance lands.
    try mustApply(try Store.jobs.setCursor(&store, reading, 16384));
    const done = (try Store.jobs.getByName(&store, arena, 1, "deploy")).?;
    try t.expectEqual(@as(i64, 16384), done.read_cursor);
    try t.expectEqual(Store.jobs.Status.exited, done.status);
}

test "gate: a relaunch may not delete a running row, and 'job rm' may" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_jobs_removal_grounds");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    try seedServer(&store);

    const seeded = try seedJob(&store, arena, scratch.io, "deploy", "__TERMINUS_JOB_1__", 1000);
    try t.expect(try Store.jobs.markStarted(&store, seeded.request_id));
    const running = (try Store.jobs.getByName(&store, arena, 1, "deploy")).?;

    // `run --name deploy` decides in Zig whether the row it read is
    // displaceable, several statements before the DELETE. This is what makes
    // that decision binding: a peer promoting the reservation in between
    // cannot turn it into the deletion of a live row.
    const conflict = try jobRefusalOf(
        try Store.jobs.remove(&store, running.removeExpectation(), .superseded_by_relaunch),
    );
    switch (conflict) {
        .grounds_refuse => |refusal| {
            try t.expectEqual(Store.jobs.Status.running, refusal.found);
            try t.expectEqual(Store.jobs.RemovalGrounds.superseded_by_relaunch, refusal.grounds);
        },
        else => return error.WrongRefusal,
    }
    try t.expect((try Store.jobs.getByName(&store, arena, 1, "deploy")) != null);

    // `job rm` has been to the host and proved the session is gone, which is a
    // fact this column cannot hold, so it may forget the same row.
    //
    // It has to reach the delete the only way those grounds can now be reached:
    // `removeLocked`, inside a transaction its caller opened. `jobs.remove` will
    // not take them — `RemovalGrounds.warrant` says they need a claim re-read in
    // the destroying transaction, and passing them to the short route is a
    // compile error, not a refusal. In production the transaction is
    // `execution.commitDestruction`, which puts the terminal receipt in it too;
    // see `gates_authority_test.zig` for that composition. What is proved here
    // is the state list underneath it — that `running` really is removable on
    // these grounds and on no others.
    try store.db.exec("BEGIN IMMEDIATE");
    try mustApply(try Store.jobs.removeLocked(
        &store,
        running.removeExpectation(),
        .session_proven_gone,
    ));
    try store.db.exec("COMMIT");
    try t.expectEqual(@as(?Store.jobs.Job, null), try Store.jobs.getByName(&store, arena, 1, "deploy"));
}

test "gate: an unowned 0.1.x row is writable, and no launch's expectation matches one" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_jobs_legacy_owner");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    try seedServer(&store);

    // The shape 0.1.x left behind: a row with no owning launch. Nothing in
    // this binary can write one — `jobs.create` takes a non-optional owner —
    // so this has to be inserted by hand, and that fact is what makes
    // `(id, owner IS NULL)` a stable identity: a recycled rowid can only be
    // inherited by an owned row, which the NULL conjunct refuses.
    try store.db.exec(
        \\INSERT INTO jobs (id, server_id, name, command, sentinel, status, created_at)
        \\VALUES (7, 1, 'legacy', 'make old', '__TERMINUS_JOB_OLD__', 'running', 100)
    );
    const legacy = (try Store.jobs.getByName(&store, arena, 1, "legacy")).?;
    try t.expectEqual(@as(?[]const u8, null), legacy.owner_request_id);

    // A caller holding a request id can never write it. `owner_request_id = ?`
    // is NULL — and so never true — against this row, which is the half of the
    // policy that stops an owned expectation from sliding onto a legacy one.
    var impostor = legacy.finishExpectation();
    impostor.owner = .{ .launch = "01AAAAAAAA0123456789ABCDEF" };
    switch (try jobRefusalOf(try Store.jobs.markFinishedUnattached(&store, impostor, .exited, 0, 200))) {
        .not_ours => |status| try t.expectEqual(Store.jobs.Status.running, status),
        else => return error.WrongRefusal,
    }
    try t.expectEqual(
        Store.jobs.Status.running,
        (try Store.jobs.getByName(&store, arena, 1, "legacy")).?.status,
    );

    // And the other half: the row is not stranded. An observer that read it as
    // it is — unowned — can settle it, so a 0.1.x row stuck at `running` does
    // not refuse every later `run --name legacy` until somebody deletes it by
    // hand.
    try mustApply(try Store.jobs.markFinishedUnattached(&store, legacy.finishExpectation(), .exited, 3, 300));
    const settled = (try Store.jobs.getByName(&store, arena, 1, "legacy")).?;
    try t.expectEqual(Store.jobs.Status.exited, settled.status);
    try t.expectEqual(@as(?i64, 3), settled.exit_code);
}

/// The probe `execution.between_settle_and_cache` installs for the gate below.
///
/// Same shape and same reasoning as `RemovalRace` (`gates_recovery_test.zig`): a
/// file-scope struct because
/// the hook is a bare function pointer with nothing to capture, and one gate
/// installs it, runs one settlement and clears it.
const CacheRace = struct {
    /// Opened before the settlement starts, for the same reason `RemovalRace`
    /// does it: opening a connection while the write lock is held would
    /// measure `Store.open`, not the window.
    var peer: ?*Store = null;
    var result: Result = .not_run;
    var failure: ?anyerror = null;

    const Result = enum {
        /// The hook never fired. Either the settlement did not reach the
        /// window or nothing installed the probe — neither is evidence that
        /// the window is closed.
        not_run,
        /// The peer could not take the write lock, so there is no instant
        /// between the terminal and the cache row at which the row could
        /// change under the expectation that was already checked.
        excluded,
        /// The peer wrote. The receipt is committed and the cache row it
        /// describes has moved since, which is exactly the split this gate
        /// exists to forbid.
        slipped_through,
    };

    /// A state literal rendered from the Zig enum, for the same reason the
    /// writers render theirs: if `Status.killed` is ever renamed, this line
    /// must move with it rather than silently stop matching.
    const steal_sql = "UPDATE jobs SET status = '" ++
        @tagName(Store.jobs.Status.killed) ++ "' WHERE name = 'deploy'";

    fn reset() void {
        peer = null;
        result = .not_run;
        failure = null;
    }

    /// Tries to move the job row out from under the finish, in the window
    /// between the receipt and the cache write.
    fn moveTheRow() void {
        const store = peer orelse {
            failure = error.NoPeerConnection;
            return;
        };
        // Whether the lock is held *now* is the question; waiting for it would
        // answer a different one.
        store.db.exec("PRAGMA busy_timeout=0") catch |err| {
            failure = err;
            return;
        };
        store.db.exec("BEGIN IMMEDIATE") catch {
            // SQLite allows one writer, and the settlement is it.
            result = .excluded;
            return;
        };
        result = .slipped_through;
        store.db.exec(steal_sql) catch |err| {
            failure = err;
        };
        store.db.exec("COMMIT") catch |err| {
            failure = err;
        };
    }
};

test "gate: the terminal and the cache row it describes are written once, together" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_jobs_settle_atomic");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    try seedServer(&store);

    const seeded = try seedJob(&store, arena, scratch.io, "deploy", "__TERMINUS_JOB_1__", 1000);
    try Store.operations.advance(&store, seeded.request_id, .connecting, 1001);
    try Store.operations.advance(&store, seeded.request_id, .submitted, 1002);
    try t.expect(try Store.jobs.markStarted(&store, seeded.request_id));

    // What this gate proves: the receipt that decides the attempt and the job
    // row that caches it are one write. The expectation is read before the
    // transaction opens — that is unavoidable, the caller has to read a row to
    // form one — so the only thing standing between "checked" and "written" is
    // the transaction. If the two writes were split, the read would be stale
    // by an unbounded amount and the refusal it produces would be a routine
    // event rather than a real conflict.
    //
    // What it does not prove: anything about two processes truly running at
    // once, or about a reader. The probe sets `busy_timeout=0` so the answer
    // is about the lock rather than about how long it was willing to wait.
    var peer = try Store.open(scratch.path);
    defer peer.close();

    var exec = (try execution.attach(&store, arena, scratch.io, seeded.request_id)).?;
    defer exec.deinit();

    const row = (try Store.jobs.getByName(&store, arena, 1, "deploy")).?;
    try t.expectEqual(Store.jobs.Status.running, row.status);

    CacheRace.reset();
    CacheRace.peer = &peer;
    execution.between_settle_and_cache = CacheRace.moveTheRow;
    defer {
        execution.between_settle_and_cache = null;
        CacheRace.reset();
    }

    const done = try exec.settleAttachedAndSyncJob(
        .{ .exited = .{ .exit_code = 0 } },
        .{},
        .{ .finish = .{
            .expected = row.finishExpectation(),
            .status = .exited,
            .exit_code = 0,
            .at = 2000,
        } },
    );

    if (CacheRace.failure) |err| return err;
    // `not_run` fails here too: a settlement that never reaches the window has
    // not been shown to close it.
    try t.expectEqual(CacheRace.Result.excluded, CacheRace.result);

    // And the outcome agrees. Split in two, the peer would have moved the row
    // to `killed` between the receipt and the finish, and the finish would
    // have come back `status_moved` — a committed terminal with a cache row
    // that contradicts it.
    switch (done.cache) {
        .synced => {},
        else => return error.CacheNotSynced,
    }
    try t.expectEqual(op_state.Status.completed, done.status());

    const cached = (try Store.jobs.getByName(&store, arena, 1, "deploy")).?;
    try t.expectEqual(Store.jobs.Status.exited, cached.status);
    try t.expectEqual(@as(?i64, 0), cached.exit_code);
    try t.expectEqual(@as(?i64, 2000), cached.finished_at);
}
