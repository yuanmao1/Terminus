//! The destructive verbs, and the authority every one of them needs.
//!
//! Two halves.
//!
//! **`session rm`'s composite.** The terminal and the local delete are one
//! write. They used to be two, and both defects that shape allowed are about the
//! moment between them: a `--force` takeover landing in the window was never
//! re-checked, and a terminal written first left the ledger permanently
//! asserting a removal whose row was still on disk — which a frozen terminal
//! cannot take back.
//!
//! **The shared matrix.** `job kill`, `job rm` and `session rm` are the same act
//! with different nouns, so they must answer the same way to the same situation:
//! our claim held, lapsed or unreadable, crossed with a peer that is absent,
//! holds an unsettled operation, or holds a foreign lease. The matrix states the
//! expected answer for every cell once, and every path is driven through every
//! cell. A verb that answered one cell its own way would be a verb that had
//! grown its own idea of authority — which is the drift `src/core/control.zig`
//! exists to prevent.

const std = @import("std");
const Store = @import("Store.zig");
const Db = @import("Db.zig");
const ids = @import("ids.zig");
const op_state = @import("op_state.zig");
const execution = @import("../execution.zig");
const Control = @import("../control.zig");

// The shared fixtures. Aliased under their own names so a gate reads the
// same here as it did when every gate was in one file.
const fixtures = @import("gates_fixtures.zig");
const Scratch = fixtures.Scratch;
const testId = fixtures.testId;
const seedServer = fixtures.seedServer;

// --- `session rm`'s composite: the terminal and the local delete are one write --
//
// The contract `session rm` is held to is `job rm`'s, unchanged: aimed at a
// job's session it destroys the same three things in the same order with the
// same failure modes, so it owes the same proof before each step. That, and the
// F1/F2 review. `session rm` used to renew
// its lease, run a whole `execution.settle` transaction, and only then delete the
// local `sessions` row — whose delete cascades that session's memories. Two
// separate defects lived in that shape, and both are about a moment *between* two
// writes:
//
//  * a `--force` takeover landing in the window was never re-checked, so the
//    delete went ahead under a scope that had changed hands;
//  * the terminal came first, so a failed delete left the ledger permanently
//    asserting a removal whose row was still on disk — and a terminal is frozen,
//    so nothing could correct it.
//
// The three gates below prove the three halves of the fix: there is no instant
// between the check and the delete, a peer's claim at the door refuses the whole
// thing, and a delete that cannot happen leaves no terminal claiming it did.

/// A control operation over one session, at `submitted` and holding its scope.
///
/// `submitted` because `remote_cancel_confirmed` is only admissible from there
/// (`op_state.canSettle`), which is the honest shape: this terminal says a remote
/// session was stopped, and nothing that never reached the remote can say that.
const SeededRemoval = struct {
    execution: execution.Execution,
    session_id: i64,
    owner: []const u8,
};

fn seedSessionRemoval(
    store: *Store,
    arena: std.mem.Allocator,
    io: std.Io,
    session: []const u8,
) !SeededRemoval {
    return seedSessionRemovalAt(store, arena, io, session, try Store.leases.clockSeconds(store));
}

/// `seedSessionRemoval` with the lease acquired at a stated moment, so a gate can
/// seed a claim that has already run out. Nothing else about the fixture changes:
/// the operation is at `submitted` and the row and its memory are there either way.
fn seedSessionRemovalAt(
    store: *Store,
    arena: std.mem.Allocator,
    io: std.Io,
    session: []const u8,
    lease_taken_at: i64,
) !SeededRemoval {
    const session_id = try Store.sessions.ensure(store, 1, session, 1000);
    // The destruction no remote command can undo. A gate that only counted the
    // session row would pass over a cascade.
    _ = try Store.memories.add(
        store,
        .{ .server_id = 1, .session_id = session_id },
        .{ .key = "runbook", .content = "restart the queue first", .now = 1000 },
    );

    const start = try execution.begin(store, arena, io, .{
        .server_id = 1,
        .server_name = "lease-host",
        .kind = .control,
        .scope = .{ .kind = .job, .key = session },
        .alias = session,
        .owner_token = "one-machine",
        .now = 1000,
    });
    var exec = switch (start) {
        .ready => |e| e,
        .blocked => return error.SeedWasBlocked,
    };
    try exec.connecting();
    switch (try exec.submitted()) {
        .submitted => {},
        .refused => return error.SeedWasRefused,
    }

    const owner = try arena.dupe(u8, exec.id());
    switch (try Store.leases.acquire(store, arena, .{
        .server_id = 1,
        .scope = .{ .kind = .job, .key = session },
        .owner_request_id = owner,
        .profile_token = "one-machine",
        .owner_label = session,
        .ttl_secs = 120,
        .now = lease_taken_at,
    })) {
        .acquired => {},
        .renewed, .conflict => return error.SeedClaimDidNotTake,
    }
    return .{ .execution = exec, .session_id = session_id, .owner = owner };
}

/// The proven stop `cmd_session` writes, minus the prose it renders per session.
fn provenStop(verified_at: i64) op_state.Terminal {
    return .{ .remote_cancel_confirmed = .{
        .pid = null,
        .term_sent = true,
        .kill_sent = false,
        .absence_verified_at = verified_at,
        .verification_method = "tmux kill-session then has-session reported the session absent",
    } };
}

fn sessionMemories(store: *Store, arena: std.mem.Allocator, session_id: i64) !usize {
    const rows = try Store.memories.list(store, arena, .{ .server_id = 1, .session_id = session_id }, .{});
    var mine: usize = 0;
    for (rows) |row| if (row.scope == .session) {
        mine += 1;
    };
    return mine;
}

/// The probe `execution.between_ownership_and_removal` installs for the gate
/// below.
///
/// Same shape and same reasoning as `CacheRace` (`gates_jobs_test.zig`): the hook
/// is a bare function
/// pointer with nothing to capture, and one gate installs it, runs one removal and
/// clears it.
const TakeoverRace = struct {
    /// Opened before the removal starts, for the reason `CacheRace` gives:
    /// opening a connection while the write lock is held would measure
    /// `Store.open`, not the window.
    var peer: ?*Store = null;
    var result: Result = .not_run;
    var failure: ?anyerror = null;

    const Result = enum {
        /// The hook never fired. Either the removal did not reach the window or
        /// nothing installed the probe — neither is evidence that the window is
        /// closed.
        not_run,
        /// The peer could not take the write lock, so there is no instant between
        /// the ownership check and the delete at which the scope could change
        /// hands under a check that has already passed.
        excluded,
        /// The peer wrote. The check is committed evidence about a scope somebody
        /// else now holds, which is the split this gate exists to forbid.
        slipped_through,
    };

    /// A takeover, written as `leases.takeover` would: the incumbent is marked
    /// released and a new row appears. Rendered from the enum for the same reason
    /// `CacheRace.steal_sql` is — a renamed reason must move this line with it.
    const seize_sql = "UPDATE leases SET released_at = 2000, release_reason = '" ++
        @tagName(Store.leases.ReleaseReason.takeover) ++ "' WHERE released_at IS NULL";

    fn reset() void {
        peer = null;
        result = .not_run;
        failure = null;
    }

    fn seizeTheScope() void {
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
            // SQLite allows one writer, and the removal is it.
            result = .excluded;
            return;
        };
        result = .slipped_through;
        store.db.exec(seize_sql) catch |err| {
            failure = err;
        };
        store.db.exec("COMMIT") catch |err| {
            failure = err;
        };
    }
};

test "gate: nothing can take the scope between `session rm`'s ownership check and its delete" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_session_removal_atomic");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    try seedServer(&store);

    var seeded = try seedSessionRemoval(&store, arena, scratch.io, "shell");
    defer seeded.execution.deinit();

    // What this gate proves: the ownership check that licenses the delete and the
    // delete itself are one write, so a `--force` takeover cannot land between
    // them. The renewal before the last remote call is unavoidably outside the
    // transaction — the caller has to ask the host something — so the only thing
    // standing between "checked" and "deleted" is this transaction. Split in two,
    // the check would be stale by an unbounded amount and the takeover it exists
    // to catch would sail past it.
    //
    // What it does not prove: anything about two processes truly running at once,
    // or about a reader. The probe sets `busy_timeout=0`, so the answer is about
    // the lock rather than about how long it was willing to wait.
    var peer = try Store.open(scratch.path);
    defer peer.close();

    TakeoverRace.reset();
    TakeoverRace.peer = &peer;
    execution.between_ownership_and_removal = TakeoverRace.seizeTheScope;
    defer {
        execution.between_ownership_and_removal = null;
        TakeoverRace.reset();
    }

    var rollback: execution.Rollback = .none;
    const done = try seeded.execution.settleAndRemoveSession("shell", provenStop(2000), .{}, &rollback);

    if (TakeoverRace.failure) |err| return err;
    // `not_run` fails here too: a removal that never reaches the window has not
    // been shown to close it.
    try t.expectEqual(TakeoverRace.Result.excluded, TakeoverRace.result);

    // And the outcome agrees: the row is gone, its memories with it, and the
    // terminal is on record.
    switch (done) {
        .removed => |r| try t.expect(r.had_row),
        else => return error.RemovalDidNotHappen,
    }
    try t.expectEqual(@as(?i64, null), try Store.sessions.idByName(&store, 1, "shell"));
    try t.expectEqual(@as(usize, 0), try sessionMemories(&store, arena, seeded.session_id));
    try t.expectEqual(op_state.Status.cancelled, seeded.execution.status);
}

// The takeover the gate above excludes from the window, landing at the door
// instead: a peer holds an overlapping scope when the transaction opens.
//
// Everything is refused together. The local row stands, its memories stand, and —
// the part F2 is about — **no terminal is written at all**. The operation stays
// unsettled and goes on barring the scope, which is the fail-closed answer: a
// caller that cannot prove what it did must not leave a record saying it did it.
test "gate: a peer's claim refuses `session rm`'s composite whole, and writes no terminal" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_session_removal_refused");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    try seedServer(&store);

    var seeded = try seedSessionRemoval(&store, arena, scratch.io, "shell");
    defer seeded.execution.deinit();

    // The takeover, as `job kill --force` performs it: the incumbent's row is
    // released with a reason and the displacer's row is inserted. What the check
    // inside the transaction sees is the second one.
    const peer_owner = "01PEEEEEEER0123456789ABCDE";
    switch (try Store.leases.takeover(&store, arena, .{
        .server_id = 1,
        .scope = .{ .kind = .job, .key = "shell" },
        .owner_request_id = peer_owner,
        .profile_token = "the-other-machine",
        .owner_label = "shell",
        .ttl_secs = 120,
        .now = try Store.leases.clockSeconds(&store),
    })) {
        .taken => {},
        .acquired => return error.PeerDidNotSeize,
    }

    var rollback: execution.Rollback = .none;
    switch (try seeded.execution.settleAndRemoveSession("shell", provenStop(2000), .{}, &rollback)) {
        .refused => |blocker| switch (blocker) {
            .lease => |lease| try t.expectEqualStrings(peer_owner, lease.owner_request_id),
            .unsettled => return error.WrongBlocker,
        },
        else => return error.RemovalWasNotRefused,
    }

    // Nothing was destroyed.
    try t.expectEqual(@as(?i64, seeded.session_id), try Store.sessions.idByName(&store, 1, "shell"));
    try t.expectEqual(@as(usize, 1), try sessionMemories(&store, arena, seeded.session_id));

    // And nothing was claimed. No terminal receipt, and the operation is where it
    // was — still `submitted`, still barring the scope, still settleable by the
    // caller with a terminal that is honest about the partial state.
    try t.expectEqual(@as(?Store.receipts.TerminalRecord, null), try Store.receipts.terminalOf(&store, seeded.execution.id()));
    const op = (try Store.operations.get(&store, arena, seeded.execution.id())).?;
    try t.expectEqual(op_state.Status.submitted, op.status);
    try t.expect(op.status.blocksScope());
    try t.expect(!seeded.execution.settled);
}

// The other order defect, driven from the other end: the local delete fails and
// the terminal must not survive it.
//
// A `BEFORE DELETE` trigger is how the failure is arranged, and it is arranged
// rather than described because the shape is what matters: the delete is refused
// by the database, mid-transaction, after the terminal has already been inserted.
// Written the old way round — settle, commit, then delete — this is precisely the
// state that left a frozen `cancelled` receipt over a session row that is still on
// disk, with its memories, and possibly its pane log still on the host.
test "gate: a `session rm` whose local delete fails leaves no terminal claiming it" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_session_removal_delete_fails");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    try seedServer(&store);

    var seeded = try seedSessionRemoval(&store, arena, scratch.io, "shell");
    defer seeded.execution.deinit();

    try store.db.exec(
        \\CREATE TRIGGER refuse_session_delete BEFORE DELETE ON sessions
        \\BEGIN SELECT RAISE(ABORT, 'the local delete cannot happen'); END
    );

    var rollback: execution.Rollback = .none;
    try t.expectError(
        error.Constraint,
        seeded.execution.settleAndRemoveSession("shell", provenStop(2000), .{}, &rollback),
    );
    // The rollback happened and is *known* to have happened. `RAISE(ABORT)` aborts
    // the statement and leaves the transaction alive, so the `ROLLBACK` this call
    // issues has something to roll back and succeeds. That is what entitles the CLI
    // to report a known local state on this path; the sibling gate below is the
    // shape where it is not entitled to.
    try t.expectEqualStrings("confirmed", @tagName(rollback));

    // The whole transaction went back: no terminal, and the attempt is still
    // `submitted` rather than frozen at `cancelled`. That is the assertion — a
    // frozen terminal cannot be corrected, so the *only* safe answer to a delete
    // that will not happen is to write nothing.
    try t.expectEqual(@as(?Store.receipts.TerminalRecord, null), try Store.receipts.terminalOf(&store, seeded.execution.id()));
    const op = (try Store.operations.get(&store, arena, seeded.execution.id())).?;
    try t.expectEqual(op_state.Status.submitted, op.status);
    try t.expect(!seeded.execution.settled);

    // The row and its memories are where they were.
    try t.expectEqual(@as(?i64, seeded.session_id), try Store.sessions.idByName(&store, 1, "shell"));
    try t.expectEqual(@as(usize, 1), try sessionMemories(&store, arena, seeded.session_id));

    // The discriminating control: with the trigger gone the same call removes,
    // settles and reports the row it deleted — so none of the above passes because
    // the composite simply never works.
    try store.db.exec("DROP TRIGGER refuse_session_delete");
    switch (try seeded.execution.settleAndRemoveSession("shell", provenStop(2000), .{}, &rollback)) {
        .removed => |r| try t.expect(r.had_row),
        else => return error.RemovalDidNotHappen,
    }
    try t.expectEqual(@as(?i64, null), try Store.sessions.idByName(&store, 1, "shell"));
    try t.expectEqual(@as(usize, 0), try sessionMemories(&store, arena, seeded.session_id));
    try t.expectEqual(op_state.Status.cancelled, (try Store.operations.get(&store, arena, seeded.execution.id())).?.status);
}

// The hole the overlap check structurally could not see: **our own** lease.
//
// `blockerLocked` answers "has anything else claimed this scope", and that is a
// different question. If this command's lease runs out during the last remote
// round trip and *no successor takes it*, the expiry pass retires the row, the
// overlap check finds nothing to report — there genuinely is nothing — and the
// terminal plus the cascading delete used to commit anyway. A session's row and
// its memories, destroyed by a command holding nothing.
//
// Three legs, and the middle one is the fix's whole substance:
//
//  * the claim has lapsed and nobody has swept it: refused, reported `lapsed`;
//  * it has been swept, so the scope reads clear to every other barrier:
//    refused, reported `swept` — and the gate asks the overlap check directly to
//    show that it, on its own, would have let this through;
//  * a live claim on the same fixture still removes, so none of the above passes
//    because the composite has simply stopped working.
test "gate: `session rm`'s composite refuses when its own lease is no longer live" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_session_removal_claim_lost");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    try seedServer(&store);

    // A claim taken an hour ago with a two-minute TTL: the shape of a command
    // whose last round trip hung. Dated off the store's own clock rather than a
    // literal, so the composite's live `now()` really is past it.
    const long_ago = (try Store.leases.clockSeconds(&store)) - 3600;
    var seeded = try seedSessionRemovalAt(&store, arena, scratch.io, "shell", long_ago);
    defer seeded.execution.deinit();

    var rollback: execution.Rollback = .none;

    // Leg one. Nobody has run an expiry pass yet, so the row is still sitting
    // there unreleased and out of date, and that is what the caller is told.
    switch (try seeded.execution.settleAndRemoveSession("shell", provenStop(2000), .{}, &rollback)) {
        .claim_lost => |claim| try t.expectEqualStrings("lapsed", claim.code()),
        else => return error.RemovalWasNotRefused,
    }

    // Leg two. That refusal's own transaction ran the lazy expiry pass on its way
    // through — every barrier here does — so the row is now released as `expired`
    // with no successor. This is the state that used to pass.
    switch (try seeded.execution.settleAndRemoveSession("shell", provenStop(2000), .{}, &rollback)) {
        .claim_lost => |claim| try t.expectEqualStrings("swept", claim.code()),
        else => return error.RemovalWasNotRefused,
    }

    // …and the reason it used to pass, asked of the barrier itself: in exactly
    // this state the overlap check reports nothing, because there is nothing to
    // report. It is not wrong; it is answering a question that does not cover
    // this.
    try store.db.exec("BEGIN IMMEDIATE");
    const conflict = try Store.leases.conflictForLocked(
        &store,
        arena,
        1,
        .{ .kind = .job, .key = "shell" },
        seeded.owner,
        try Store.leases.clockSeconds(&store),
    );
    try store.db.exec("COMMIT");
    try t.expectEqual(@as(?Store.leases.Lease, null), conflict);

    // Nothing was destroyed on either leg, and nothing was claimed. The attempt is
    // where it was — still `submitted`, still barring the scope, still settleable
    // by the caller with a terminal that is honest about the partial state.
    try t.expectEqual(@as(?i64, seeded.session_id), try Store.sessions.idByName(&store, 1, "shell"));
    try t.expectEqual(@as(usize, 1), try sessionMemories(&store, arena, seeded.session_id));
    try t.expectEqual(@as(?Store.receipts.TerminalRecord, null), try Store.receipts.terminalOf(&store, seeded.execution.id()));
    const op = (try Store.operations.get(&store, arena, seeded.execution.id())).?;
    try t.expectEqual(op_state.Status.submitted, op.status);
    try t.expect(!seeded.execution.settled);

    // Leg three, the discriminating control: the same attempt, the same session,
    // a claim that is live. Without it every assertion above would hold just as
    // well against a composite that had started refusing everything.
    switch (try Store.leases.acquire(&store, arena, .{
        .server_id = 1,
        .scope = .{ .kind = .job, .key = "shell" },
        .owner_request_id = seeded.owner,
        .profile_token = "one-machine",
        .owner_label = "shell",
        .ttl_secs = 120,
        .now = try Store.leases.clockSeconds(&store),
    })) {
        .acquired => {},
        .renewed, .conflict => return error.SeedClaimDidNotTake,
    }
    switch (try seeded.execution.settleAndRemoveSession("shell", provenStop(2000), .{}, &rollback)) {
        .removed => |r| try t.expect(r.had_row),
        else => return error.RemovalDidNotHappen,
    }
    try t.expectEqual(@as(?i64, null), try Store.sessions.idByName(&store, 1, "shell"));
    try t.expectEqual(@as(usize, 0), try sessionMemories(&store, arena, seeded.session_id));
    try t.expectEqual(op_state.Status.cancelled, seeded.execution.status);
}

// A composite that could not commit *and* could not confirm its own rollback.
//
// The sibling of the `RAISE(ABORT)` gate above, and the difference between the two
// triggers is the entire point. `ABORT` ends the statement and leaves the
// transaction alive, so the `ROLLBACK` that follows has something to undo and
// succeeds — a proof that nothing was written, which is what lets the CLI report a
// known local state. `ROLLBACK` inside the trigger unwinds the transaction itself,
// so the explicit `ROLLBACK` afterwards finds none active and fails. Nothing about
// the local row is then established by this process, and the honest word is
// `unknown`.
//
// This is a real sqlite behaviour arranged, not a seam faked: the same shape arrives
// whenever the failure that killed a statement also killed the transaction under it.
test "gate: a `session rm` whose rollback cannot be confirmed says so instead of claiming the row is untouched" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_session_removal_rollback_unknown");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    try seedServer(&store);

    var seeded = try seedSessionRemoval(&store, arena, scratch.io, "shell");
    defer seeded.execution.deinit();

    try store.db.exec(
        \\CREATE TRIGGER unwind_on_session_delete BEFORE DELETE ON sessions
        \\BEGIN SELECT RAISE(ROLLBACK, 'the delete takes the transaction with it'); END
    );

    var rollback: execution.Rollback = .none;
    try t.expectError(
        error.Constraint,
        seeded.execution.settleAndRemoveSession("shell", provenStop(2000), .{}, &rollback),
    );

    // The assertion. `catch {}` — the shape this replaces — could only ever produce
    // silence here, and the caller reported "nothing local was deleted" off it.
    try t.expectEqualStrings("unconfirmed", @tagName(rollback));
    switch (rollback) {
        // Carries the cause, so an operator is not left with a bare word.
        .unconfirmed => |why| try t.expect(why.len > 0),
        .none, .confirmed => return error.RollbackWasConfirmed,
    }

    // What sqlite actually did is beside the point of the report and is asserted
    // anyway: this trigger really does unwind the transaction, so no terminal and
    // no delete survived. The *report* may not claim that, because the process
    // could not establish it — but a gate that did not check it would not know
    // whether it had arranged the shape it meant to.
    try t.expectEqual(@as(?Store.receipts.TerminalRecord, null), try Store.receipts.terminalOf(&store, seeded.execution.id()));
    try t.expectEqual(@as(?i64, seeded.session_id), try Store.sessions.idByName(&store, 1, "shell"));
    try t.expectEqual(@as(usize, 1), try sessionMemories(&store, arena, seeded.session_id));

    // The discriminating control, in the same store: with the trigger gone the same
    // call commits, and `Rollback` says `none` rather than reporting an unconfirmed
    // undo of a transaction that was never undone.
    try store.db.exec("DROP TRIGGER unwind_on_session_delete");
    switch (try seeded.execution.settleAndRemoveSession("shell", provenStop(2000), .{}, &rollback)) {
        .removed => |r| try t.expect(r.had_row),
        else => return error.RemovalDidNotHappen,
    }
    try t.expectEqualStrings("none", @tagName(rollback));
    try t.expectEqual(@as(?i64, null), try Store.sessions.idByName(&store, 1, "shell"));
}

// A refused attempt is recorded, and the record does not bar the next command.
//
// The end-to-end half is in `test/blackbox.zig`, which runs a second removal after
// the peer lets go and insists it succeeds. This is the store-side half, and it
// asks the two barriers directly rather than through a command: `blocksScope` and
// the guard's own query. Both have to say no, because they are two definitions of
// "this bars a change" and a refusal that satisfied one and not the other would be
// a trap that only showed up under one of them.
test "gate: a recorded `session rm` refusal is queryable and bars nothing" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_session_refusal_recorded");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    try seedServer(&store);

    const scope: execution.Scope = .{ .kind = .job, .key = "shell" };
    var minted: Store.ids.RequestId = undefined;
    const refusal = try execution.recordRefusal(&store, arena, scratch.io, .{
        .server_id = 1,
        .server_name = "lease-host",
        .kind = .control,
        .scope = scope,
        .alias = "shell",
        .owner_token = "one-machine",
        .now = 1000,
    }, "a peer holds an overlapping scope; nothing was sent to the host", &minted);

    // Queryable by request id, which is the property — an alias is a convenience
    // handle that names get reused under.
    const op = (try Store.operations.get(&store, arena, refusal.id())) orelse
        return error.RefusalIsNotQueryable;
    // What the function says it wrote is what the row holds. The caller reports
    // this word, so a returned status that drifted from the settlement would put
    // a wrong one in every refusal document.
    try t.expectEqual(op.status, refusal.status);
    try t.expectEqualStrings("control", op.kind);
    try t.expect(op.mutating);

    // Settled, in the same transaction that created it: a refusal left at
    // `created` would be a row somebody has to wonder about.
    try t.expectEqual(op_state.Status.cancelled, op.status);
    const terminal = (try Store.receipts.terminalOf(&store, refusal.id())) orelse
        return error.RefusalLeftNoTerminal;
    try t.expectEqual(op_state.Status.cancelled, terminal.status);

    // Both barriers: the predicate, and the query the mutation guard actually
    // runs. A refusal that blocked the scope it was refused by would be worse than
    // no record at all.
    try t.expect(!op.status.blocksScope());
    try t.expectEqual(
        @as(usize, 0),
        (try Store.operations.unsettledInScope(&store, arena, 1, scope)).len,
    );

    // The discriminating control, in the same store: an operation that *should*
    // bar the scope still does. Without it, a guard that had stopped returning
    // anything at all would satisfy the assertion above.
    const live = try execution.begin(&store, arena, scratch.io, .{
        .server_id = 1,
        .server_name = "lease-host",
        .kind = .control,
        .scope = scope,
        .alias = "shell",
        .owner_token = "one-machine",
        .now = 1001,
    });
    var running = switch (live) {
        .ready => |e| e,
        .blocked => return error.RefusalBarsTheNextCommand,
    };
    defer running.deinit();
    try running.connecting();
    switch (try running.submitted()) {
        .submitted => {},
        .refused => return error.RefusalBarsTheNextCommand,
    }
    try t.expectEqual(
        @as(usize, 1),
        (try Store.operations.unsettledInScope(&store, arena, 1, scope)).len,
    );
}

// --- The shared authority matrix ---------------------------------------------
//
// The reason the same defect kept coming back is that each verb was tested on its
// own. `session rm` grew a gate for the settle-then-act window; `job kill` grew a
// different one; `job rm`'s two standalone delete branches grew none at all, and
// went on calling `jobs.remove` — a `BEGIN IMMEDIATE` of their own with no
// terminal beside them and no authority check inside them.
//
// So one table, whose rows are the destructive paths and whose columns are the
// authority scenarios, driven against the real entry points. The finding it makes
// visible is that **the table has no per-path column**: `expectedCell` discards
// `path`, because every path now answers through `execution.commitDestruction`.
// The day one of them stops doing so, one row's cells start disagreeing with the
// other three and this fails naming the cell.
//
// Every cell is decided. The eight that cannot be reached say why, and the reason
// is a property of `leases.zig` rather than an inconvenience of the fixture — see
// `expectedCell`.
//
// What this does *not* cover, deliberately: `job kill`. It is not a row here
// because it commits no local destruction, and the gate below says so
// structurally rather than leaving a hole in the table.

/// The destructive paths, as rows.
const DestructivePath = enum {
    /// `session rm` — `Execution.settleAndRemoveSession`. Authority owner and
    /// target operation are the *same* value.
    session_rm,
    /// `job rm` with a live attempt to settle in the removal's transaction.
    /// Authority owner and target operation are two different values.
    job_rm_attached,
    /// `job rm` whose attempt is already terminal, so the removal writes no
    /// terminal of its own and defers to the one on record.
    job_rm_settled_attempt,
    /// `job rm` whose row names no attempt at all: nothing to settle, nothing to
    /// exempt from the peer check.
    job_rm_no_attempt,
};

/// What the authority owner's own claim is in when the transaction opens. The six
/// members of `leases.ClaimState`, by name — the gate below holds the two lists
/// against each other, so a claim state added there without a column here fails —
/// plus one that is not a state at all but a *moment*.
const ClaimScenario = enum {
    held,
    lapsed,
    swept,
    displaced,
    handed_back,
    never_taken,
    /// Live when the transaction asks for the write lock, out of date by the time
    /// it has it.
    ///
    /// Not a seventh `ClaimState` — it ends in `lapsed` like the second column
    /// does — and it is its own column because *when* the lapse happens is the
    /// thing being tested. `BEGIN IMMEDIATE` waits up to `Db.busy_timeout` for the
    /// lock, and a process suspend, a resumed VM or a forward clock jump can land
    /// in that wait: exactly the three deaths `execution.authorityLocked`
    /// documents. A clock sampled before the wait reports `held` about a claim
    /// that is gone by the time the guard evaluates it, and the destruction
    /// commits under it. Driven through `execution.between_lock_and_clock`,
    /// because time passing inside that window is not something a fixture can
    /// arrange from outside.
    lapses_under_the_lock,
};

/// The `leases.ClaimState` word this scenario ends in.
///
/// One line rather than `@tagName`, because the columns are no longer one-to-one
/// with the states: two of them arrive at `lapsed` and differ only in when.
fn claimCode(claim: ClaimScenario) []const u8 {
    return switch (claim) {
        .held => "held",
        .lapsed, .lapses_under_the_lock => "lapsed",
        .swept => "swept",
        .displaced => "displaced",
        .handed_back => "handed_back",
        .never_taken => "never_taken",
    };
}

test "gate: every claim state `leases` can report has a column in the authority matrix" {
    // The property the column list used to get by spelling `@tagName`: a state
    // added to `leases.ClaimState` and not answered here would leave a row of the
    // table untested and nothing would say so.
    inline for (@typeInfo(Store.leases.ClaimState).@"union".fields) |field| {
        if (!@hasField(ClaimScenario, field.name)) {
            std.debug.print("\nleases.ClaimState.{s} has no column in ClaimScenario\n", .{field.name});
            return error.ClaimStateHasNoColumn;
        }
    }
    // …and the mapping is onto: every column names a word `ClaimState.code` can
    // actually produce, so a cell cannot assert against a string nothing returns.
    for (std.enums.values(ClaimScenario)) |claim| {
        const want = claimCode(claim);
        var found = false;
        inline for (@typeInfo(Store.leases.ClaimState).@"union".fields) |field| {
            if (std.mem.eql(u8, field.name, want)) found = true;
        }
        if (!found) {
            std.debug.print("\nClaimScenario.{s} maps to \"{s}\", which is not a ClaimState\n", .{ @tagName(claim), want });
            return error.ColumnNamesNoClaimState;
        }
    }
}

/// What else claims the scope at the same moment.
///
/// Three and not two, because the two kinds of peer come from different tables and
/// a guard can be mis-keyed for one and not the other. An unsettled operation is
/// where the *target* would be mistaken for a peer; a foreign lease is where *our
/// own claim* would be.
const PeerScenario = enum { none, unsettled_operation, foreign_lease };

/// What the contract must answer for one cell.
const Expected = union(enum) {
    /// The destruction and the ledger write landed.
    committed,
    /// Declined over a peer, which the answer names.
    refused,
    /// Declined over the authority owner's own claim, which the answer reports the
    /// state of.
    claim_lost,
    /// The cell is not reachable, and this is why. A statement about coverage
    /// rather than a hole in the table.
    unreachable_because: []const u8,
};

/// The pinned table.
///
/// `path` is deliberately unused, and that is the whole point: one contract means
/// one answer per scenario, whatever is being destroyed. It is taken as a
/// parameter so the signature says what the table is indexed by.
fn expectedCell(path: DestructivePath, claim: ClaimScenario, peer: PeerScenario) Expected {
    _ = path;

    if (peer == .foreign_lease) switch (claim) {
        // `leases.acquire` refuses on any overlap and `leases.takeover` displaces
        // *every* overlap, so two unreleased leases on overlapping scopes cannot
        // coexist. A peer that ends up holding an overlapping lease has therefore
        // taken ours, and the state that leaves us in is `displaced` — never
        // `held`.
        .held => return .{ .unreachable_because = "no peer can hold an overlapping lease while ours is unreleased: acquire refuses an overlap and takeover displaces ours, which reads as `displaced`" },
        // Every lease writer runs the lazy expiry pass before it inserts, so a
        // peer acquiring over our lapsed row releases it as `expired` on the way
        // past and we read `swept`. A takeover instead reads `displaced`. Neither
        // leaves `lapsed` standing beside a live foreign lease.
        .lapsed => return .{ .unreachable_because = "a lease writer sweeps our lapsed row before it inserts, so a peer's overlapping lease leaves us `swept` (or `displaced`), never `lapsed`" },
        // This column's claim is *live* while the fixture is being built — that is
        // the whole shape of it — so it is unreachable for the reason `held` is,
        // and for no additional one.
        .lapses_under_the_lock => return .{ .unreachable_because = "this column's claim is live and unreleased when the peer would have to acquire, so it is refused exactly as it is under `held`" },
        .swept, .displaced, .handed_back, .never_taken => {},
    };

    // A peer outranks our own claim state: both refusals decline the identical
    // act, and a blocking request id is more use to an operator than "our lease is
    // not ours". See `execution.authorityLocked`.
    if (peer != .none) return .refused;

    return switch (claim) {
        .held => .committed,
        // `lapses_under_the_lock` sits with the rest deliberately. The contract has
        // one answer to "our claim is not live", and *when* it stopped being live
        // may not change it — a clock read before the lock is what made this column
        // answer `committed` instead.
        .lapsed, .swept, .displaced, .handed_back, .never_taken, .lapses_under_the_lock => .claim_lost,
    };
}

/// One seeded destructive act, with both of its identities named.
const MatrixSubject = struct {
    /// The live target attempt, for the paths that have one to settle.
    execution: ?execution.Execution = null,
    /// The target operation's request id, or null when the path has none.
    target: ?[]const u8 = null,
    /// Whose claim licenses the act.
    authority: []const u8,
    /// The `jobs` row, for the three job paths.
    job: ?Store.jobs.Job = null,
    /// The `sessions` row, for `session rm`.
    session_id: ?i64 = null,
};

const matrix_scope: execution.Scope = .{ .kind = .job, .key = "deploy" };

const matrix_name: []const u8 = "deploy";

const matrix_peer_owner: []const u8 = "01PEEEEEEER0123456789ABCDE";

const matrix_third_owner: []const u8 = "01THIRDDDDD123456789ABCDEF";

/// The control id `cmd_job.claimJobScope` mints per invocation: a lease owner that
/// backs no operation row and is not the attempt being acted on.
fn matrixAuthority(arena: std.mem.Allocator) ![]const u8 {
    const minted = testId("controlclaim");
    return arena.dupe(u8, &minted);
}

fn seedSubmittedOperation(
    store: *Store,
    arena: std.mem.Allocator,
    io: std.Io,
    kind: Store.operations.Kind,
    now: i64,
) !execution.Execution {
    const start = try execution.begin(store, arena, io, .{
        .server_id = 1,
        .server_name = "lease-host",
        .kind = kind,
        .scope = matrix_scope,
        .alias = matrix_name,
        .owner_token = "one-machine",
        .now = now,
    });
    var exec = switch (start) {
        .ready => |e| e,
        .blocked => return error.SeedWasBlocked,
    };
    try exec.connecting();
    switch (try exec.submitted()) {
        .submitted => {},
        .refused => return error.SeedWasRefused,
    }
    return exec;
}

fn seedMatrixJobRow(
    store: *Store,
    arena: std.mem.Allocator,
    owner_request_id: []const u8,
) !Store.jobs.Job {
    _ = try Store.jobs.create(store, 1, matrix_name, "./deploy.sh", "TERMINUS-SENTINEL-1", owner_request_id, 1000);
    if (!try Store.jobs.markStarted(store, owner_request_id)) return error.JobDidNotStart;
    return (try Store.jobs.getByName(store, arena, 1, matrix_name)) orelse error.JobRowMissing;
}

/// The subject, seeded before any claim exists.
///
/// The order matters and is the fixture's one subtlety: `execution.begin` and
/// `Execution.submitted` both run the lazy lease-expiry pass on their way through,
/// so a lapsed claim arranged before them would be swept and the `lapsed` column
/// would silently become the `swept` one.
fn seedMatrixSubject(
    store: *Store,
    arena: std.mem.Allocator,
    io: std.Io,
    path: DestructivePath,
    now: i64,
) !MatrixSubject {
    switch (path) {
        .session_rm => {
            const session_id = try Store.sessions.ensure(store, 1, matrix_name, 1000);
            // The destruction no remote command can undo. A gate that only
            // counted the session row would pass over a cascade.
            _ = try Store.memories.add(
                store,
                .{ .server_id = 1, .session_id = session_id },
                .{ .key = "runbook", .content = "restart the queue first", .now = 1000 },
            );
            const exec = try seedSubmittedOperation(store, arena, io, .control, now);
            const id = try arena.dupe(u8, exec.id());
            return .{ .execution = exec, .target = id, .authority = id, .session_id = session_id };
        },
        .job_rm_attached => {
            const exec = try seedSubmittedOperation(store, arena, io, .job, now);
            const id = try arena.dupe(u8, exec.id());
            const job = try seedMatrixJobRow(store, arena, id);
            return .{
                .execution = exec,
                .target = id,
                .authority = try matrixAuthority(arena),
                .job = job,
            };
        },
        .job_rm_settled_attempt => {
            var exec = try seedSubmittedOperation(store, arena, io, .job, now);
            const id = try arena.dupe(u8, exec.id());
            const job = try seedMatrixJobRow(store, arena, id);
            // An earlier observer already settled it, so `attach` would answer
            // null and this removal has no terminal of its own to write.
            _ = try exec.settle(.{ .indeterminate = .{
                .reason = "settled by an earlier observer",
                .last_observed = .submitted,
            } }, .{});
            return .{ .target = id, .authority = try matrixAuthority(arena), .job = job };
        },
        .job_rm_no_attempt => {
            // An owner with no operation row behind it: the 0.1.x shape, and the
            // shape a launcher that died before writing its attempt row leaves.
            const orphan = testId("orphanedowner");
            const job = try seedMatrixJobRow(store, arena, &orphan);
            return .{ .authority = try matrixAuthority(arena), .job = job };
        },
    }
}

/// A peer's unsettled, mutating operation on an overlapping scope.
///
/// Taken with `force`, because our own attempt already bars the scope by then and
/// that is exactly the state this peer has to arrive in. Deliberately never
/// settled and never `deinit`ed: an unsettled row is the whole of what it is for.
fn seedForcedPeerOperation(
    store: *Store,
    arena: std.mem.Allocator,
    io: std.Io,
    now: i64,
) !void {
    const start = try execution.begin(store, arena, io, .{
        .server_id = 1,
        .server_name = "lease-host",
        .kind = .control,
        .scope = matrix_scope,
        .alias = matrix_name,
        .owner_token = "the-other-machine",
        .force = true,
        .now = now,
    });
    var peer = switch (start) {
        .ready => |e| e,
        .blocked => return error.PeerSeedWasBlocked,
    };
    try peer.connecting();
    switch (try peer.submitted()) {
        .submitted => {},
        .refused => return error.PeerSeedWasRefused,
    }
    peer.settled = true; // not ours to settle; it is the blocker
}

fn mustAcquireMatrixClaim(
    store: *Store,
    arena: std.mem.Allocator,
    owner: []const u8,
    ttl_secs: i64,
    at: i64,
) !void {
    switch (try Store.leases.acquire(store, arena, .{
        .server_id = 1,
        .scope = matrix_scope,
        .owner_request_id = owner,
        .profile_token = "one-machine",
        .owner_label = matrix_name,
        .ttl_secs = ttl_secs,
        .now = at,
    })) {
        .acquired => {},
        .renewed, .conflict => return error.ClaimDidNotTake,
    }
}

/// Puts the authority owner's claim into the state the column names.
fn arrangeMatrixClaim(
    store: *Store,
    arena: std.mem.Allocator,
    owner: []const u8,
    claim: ClaimScenario,
    peer: PeerScenario,
    now: i64,
) !void {
    switch (claim) {
        // Nothing acquired. Not the same as a claim taken and lost, which is why
        // `ClaimState` keeps the two apart.
        .never_taken => {},
        // Both start as a plain live claim. What separates them is what happens
        // inside `commitDestruction`: `lapses_under_the_lock` installs a probe that
        // expires this row and waits for the wall clock to pass it, in the window
        // between taking the write lock and reading the clock.
        .held, .lapses_under_the_lock => try mustAcquireMatrixClaim(store, arena, owner, 600, now),
        // A claim taken an hour ago with a two-minute TTL: the shape of a command
        // whose last round trip hung. Nothing runs a lease writer afterwards, so
        // the row is still sitting there unreleased and out of date.
        .lapsed => try mustAcquireMatrixClaim(store, arena, owner, 120, now - 3600),
        .swept => {
            try mustAcquireMatrixClaim(store, arena, owner, 120, now - 3600);
            // Somebody's ordinary housekeeping: `active` runs the expiry pass, and
            // nobody takes the scope. This is the state in which every overlap
            // check reads clear.
            try std.testing.expectEqual(
                @as(usize, 0),
                (try Store.leases.active(store, arena, 1, now)).len,
            );
        },
        .displaced => {
            // A TTL that outlasts `now`, so the takeover below finds a live row to
            // displace. Dated in the past with a short TTL, the takeover's own
            // expiry pass would release it first — `expires_at <= now` is the
            // predicate, so even an expiry landing exactly on the boundary sweeps
            // it — and the takeover would answer `acquired`, leaving us `swept`
            // rather than `displaced`.
            try mustAcquireMatrixClaim(store, arena, owner, 10800, now - 7200);
            // The displacer is live only where the cell wants a peer to name. In
            // the other two columns it is dated so that it has itself lapsed by
            // now, which is what leaves the scope clear while our row still
            // records that somebody took it.
            const live = peer == .foreign_lease;
            switch (try Store.leases.takeover(store, arena, .{
                .server_id = 1,
                .scope = matrix_scope,
                .owner_request_id = matrix_peer_owner,
                .profile_token = "the-other-machine",
                .owner_label = matrix_name,
                .ttl_secs = if (live) 600 else 120,
                .now = if (live) now else now - 3600,
            })) {
                .taken => {},
                .acquired => return error.PeerDidNotSeize,
            }
        },
        .handed_back => {
            try mustAcquireMatrixClaim(store, arena, owner, 600, now);
            if (!try Store.leases.release(store, 1, matrix_scope, owner, .released, now))
                return error.ClaimWasNotOurs;
        },
    }
}

/// A third party's lease over the whole host, which overlaps the job scope
/// (`scope.Scope.overlaps`) without being the same key.
///
/// Only reachable once our own row is released — see `expectedCell` — which is why
/// it is seeded after the claim rather than before it.
fn seedForeignMatrixLease(store: *Store, arena: std.mem.Allocator, now: i64) !void {
    switch (try Store.leases.acquire(store, arena, .{
        .server_id = 1,
        .scope = .{ .kind = .server },
        .owner_request_id = matrix_third_owner,
        .profile_token = "a-third-machine",
        .ttl_secs = 600,
        .now = now,
    })) {
        .acquired => {},
        .renewed, .conflict => return error.ForeignLeaseDidNotTake,
    }
}

/// The probe `execution.between_lock_and_clock` installs for the
/// `lapses_under_the_lock` column.
///
/// It runs with the removal's own write lock held, on the removal's own
/// connection, and does two things in order:
///
///  1. expires the authority owner's claim, dated one second ahead of the clock's
///     *current* reading. Written as a bare `UPDATE` because no lease API expires
///     a live row in place, and the value is computed here rather than passed in
///     so the arithmetic is anchored to a reading taken strictly after the
///     transaction opened;
///  2. waits until the wall clock has passed that second.
///
/// Together those two make the column deterministic rather than a race. A clock
/// sampled before the lock was taken is necessarily at or below the reading in
/// step 1, so it is *below* the new expiry and reports `held`; a clock sampled
/// after step 2 is at or above it and reports `lapsed`. No fixture timing decides
/// which — the probe establishes both bounds itself.
///
/// The wait is bounded by the fraction of a second remaining, because the expiry
/// is one tick away rather than a fixed number of seconds.
const ClockCrossesTheTtl = struct {
    var store: ?*Store = null;
    var io: ?std.Io = null;
    var fired: bool = false;
    var failure: ?anyerror = null;

    fn reset() void {
        store = null;
        io = null;
        fired = false;
        failure = null;
    }

    fn expireAndWait() void {
        cross() catch |err| {
            failure = err;
            return;
        };
        fired = true;
    }

    fn cross() !void {
        const db = store orelse return error.NoStoreForTheClockProbe;
        const clock = io orelse return error.NoIoForTheClockProbe;
        const expires_at = (try Store.leases.clockSeconds(db)) + 1;
        var buf: [128]u8 = undefined;
        try db.db.exec(try std.fmt.bufPrintZ(
            &buf,
            "UPDATE leases SET expires_at = {d} WHERE released_at IS NULL",
            .{expires_at},
        ));
        while ((try Store.leases.clockSeconds(db)) < expires_at)
            std.Io.sleep(clock, .{ .nanoseconds = 2 * std.time.ns_per_ms }, .awake) catch {};
    }
};

fn expectPeerNamed(peer: PeerScenario, blocker: execution.Blocker) !void {
    switch (peer) {
        .unsettled_operation => switch (blocker) {
            .unsettled => {},
            .lease => return error.RefusedByTheWrongKindOfPeer,
        },
        .foreign_lease => switch (blocker) {
            .lease => {},
            .unsettled => return error.RefusedByTheWrongKindOfPeer,
        },
        .none => return error.RefusedWithNoPeerSeeded,
    }
}

fn matrixSubjectPresent(
    store: *Store,
    arena: std.mem.Allocator,
    path: DestructivePath,
) !bool {
    return switch (path) {
        .session_rm => (try Store.sessions.idByName(store, 1, matrix_name)) != null,
        .job_rm_attached, .job_rm_settled_attempt, .job_rm_no_attempt => (try Store.jobs.getByName(store, arena, 1, matrix_name)) != null,
    };
}

/// Seeds one cell, runs the path's real entry point, and asserts the answer.
fn runAuthorityCell(
    allocator: std.mem.Allocator,
    path: DestructivePath,
    claim: ClaimScenario,
    peer: PeerScenario,
    want: Expected,
) !void {
    const t = std.testing;
    var scratch = try Scratch.init(allocator, "gate_authority_matrix");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    try seedServer(&store);

    // The store's own clock, not a literal: the claim states below are decided by
    // comparing the row against the clock `commitDestruction` will read.
    const now = try Store.leases.clockSeconds(&store);

    var subject = try seedMatrixSubject(&store, arena, scratch.io, path, now);

    // **The identity model, asserted rather than described.** This is the
    // distinction four rounds of per-verb fixes conflated: for `session rm` the
    // authority owner and the target operation are one string, and for `job rm`
    // they are two. A fixture in which they were accidentally equal on the job
    // rows would make every cell below pass for the wrong reason.
    switch (path) {
        .session_rm => try t.expectEqualStrings(subject.authority, subject.target.?),
        .job_rm_attached, .job_rm_settled_attempt => try t.expect(
            !std.mem.eql(u8, subject.authority, subject.target.?),
        ),
        .job_rm_no_attempt => try t.expectEqual(@as(?[]const u8, null), subject.target),
    }

    // Before the claim: `begin` and `submitted` sweep lapsed leases on their way
    // through.
    if (peer == .unsettled_operation) try seedForcedPeerOperation(&store, arena, scratch.io, now);

    try arrangeMatrixClaim(&store, arena, subject.authority, claim, peer, now);

    // `displaced` seeds its own peer through the takeover that displaced us.
    if (peer == .foreign_lease and claim != .displaced)
        try seedForeignMatrixLease(&store, arena, now);

    // The one column whose arrangement is not a row on disk but a moment in time.
    // Installed last, so nothing in the seeding above can trip it.
    ClockCrossesTheTtl.reset();
    defer {
        execution.between_lock_and_clock = null;
        ClockCrossesTheTtl.reset();
    }
    if (claim == .lapses_under_the_lock) {
        ClockCrossesTheTtl.store = &store;
        ClockCrossesTheTtl.io = scratch.io;
        execution.between_lock_and_clock = ClockCrossesTheTtl.expireAndWait;
    }

    var rollback: execution.Rollback = .none;
    switch (path) {
        .session_rm => {
            const done = try subject.execution.?.settleAndRemoveSession(
                matrix_name,
                provenStop(now),
                .{},
                &rollback,
            );
            switch (want) {
                .committed => switch (done) {
                    .removed => |r| try t.expect(r.had_row),
                    else => return error.CellDidNotCommit,
                },
                .refused => switch (done) {
                    .refused => |blocker| try expectPeerNamed(peer, blocker),
                    else => return error.CellWasNotRefused,
                },
                .claim_lost => switch (done) {
                    .claim_lost => |state| try t.expectEqualStrings(claimCode(claim), state.code()),
                    else => return error.CellDidNotReportALostClaim,
                },
                .unreachable_because => return error.UnreachableCellWasRun,
            }
            // The cascade, which is the part no remote command can undo.
            try t.expectEqual(
                @as(usize, if (want == .committed) 0 else 1),
                try sessionMemories(&store, arena, subject.session_id.?),
            );
        },
        .job_rm_attached, .job_rm_settled_attempt, .job_rm_no_attempt => {
            const settlement: execution.JobSettlement = if (subject.execution) |*e| .{ .attempt = .{
                .execution = e,
                .terminal = .{ .indeterminate = .{
                    .reason = "job removed before its outcome was established",
                    .last_observed = .submitted,
                } },
                .extra = .{},
            } } else if (subject.target) |id|
                .{ .absent = .{ .already_on_record = id } }
            else
                .{ .absent = .no_operation };

            const done = try execution.settleAndForgetJob(
                &store,
                arena,
                scratch.io,
                1,
                matrix_scope,
                .{ .lease_owner_request_id = subject.authority },
                settlement,
                .{ .expected = subject.job.?.removeExpectation(), .grounds = .session_proven_gone },
                &rollback,
            );
            switch (want) {
                .committed => switch (done) {
                    // No write to read: a compare-and-swap that matched nothing
                    // leaves as `Refusal.row_moved`, and `matrixSubjectPresent`
                    // below is what says the row really went.
                    .forgotten => {},
                    else => return error.CellDidNotCommit,
                },
                // One refusal arm now, carrying which read declined it — so the
                // cell has to assert the *reason* as well as the refusal. A cell
                // that expected a peer and got a lost claim used to be two
                // different arms and is now one, and this is what keeps them apart.
                .refused => switch (done) {
                    .refused => |why| switch (why) {
                        .scope_taken => |blocker| try expectPeerNamed(peer, blocker),
                        .claim_lost, .row_moved => return error.CellWasNotRefused,
                    },
                    else => return error.CellWasNotRefused,
                },
                .claim_lost => switch (done) {
                    .refused => |why| switch (why) {
                        .claim_lost => |state| try t.expectEqualStrings(claimCode(claim), state.code()),
                        .scope_taken, .row_moved => return error.CellDidNotReportALostClaim,
                    },
                    else => return error.CellDidNotReportALostClaim,
                },
                .unreachable_because => return error.UnreachableCellWasRun,
            }
        },
    }

    // The probe fired if this column installed one, and did not fail while it was
    // in there. `not_run` fails too: a cell that never reached the window has not
    // been shown to close it.
    if (ClockCrossesTheTtl.failure) |err| return err;
    if (claim == .lapses_under_the_lock and !ClockCrossesTheTtl.fired)
        return error.TheClockProbeNeverRan;

    // The destruction, or its absence. A refusal that wrote no terminal and
    // deleted the row anyway would satisfy every assertion above.
    try t.expectEqual(want != .committed, try matrixSubjectPresent(&store, arena, path));

    // And the ledger. On a declined cell the target is left exactly as it was, so
    // the attempt stays unsettled and goes on barring the scope — the fail-closed
    // answer. Asserted only where this call was the one that would have written
    // the terminal: `job_rm_settled_attempt` has one on record already, and
    // `job_rm_no_attempt` has no operation to hold one.
    if (want != .committed) switch (path) {
        .session_rm, .job_rm_attached => {
            try t.expectEqual(
                @as(?Store.receipts.TerminalRecord, null),
                try Store.receipts.terminalOf(&store, subject.target.?),
            );
            try t.expect(!subject.execution.?.settled);
        },
        .job_rm_settled_attempt, .job_rm_no_attempt => {},
    };

    // Nothing failed, so nothing was rolled back. A cell that reported an undo
    // would mean the transaction never committed at all.
    try t.expectEqualStrings("none", @tagName(rollback));

    if (subject.execution) |*e| e.deinit();
}

test "gate: every destructive path answers every authority scenario the same way" {
    const t = std.testing;
    var decided: usize = 0;
    var stated_unreachable: usize = 0;
    for (std.enums.values(DestructivePath)) |path| {
        for (std.enums.values(ClaimScenario)) |claim| {
            for (std.enums.values(PeerScenario)) |peer| {
                const want = expectedCell(path, claim, peer);
                switch (want) {
                    .unreachable_because => |why| {
                        // A reason, not an empty arm: the point of the member is
                        // that the table states what it does not cover.
                        try t.expect(why.len > 0);
                        stated_unreachable += 1;
                        continue;
                    },
                    .committed, .refused, .claim_lost => {},
                }
                runAuthorityCell(t.allocator, path, claim, peer, want) catch |err| {
                    std.debug.print(
                        "\nauthority matrix cell failed: path={s} claim={s} peer={s} want={s}: {s}\n",
                        .{ @tagName(path), @tagName(claim), @tagName(peer), @tagName(want), @errorName(err) },
                    );
                    return err;
                };
                decided += 1;
            }
        }
    }

    // The counts, so a table that stopped covering something fails rather than
    // passing over an empty loop: four paths, seven claim scenarios, three peer
    // scenarios, less the three foreign-lease columns `leases.zig` makes
    // impossible.
    try t.expectEqual(@as(usize, 4 * 7 * 3), decided + stated_unreachable);
    try t.expectEqual(@as(usize, 4 * 3), stated_unreachable);
    try t.expectEqual(@as(usize, 72), decided);
}

// The destruction's own refusal, which is **not** a column in the matrix above and
// could not be one: that table's dimensions are authority scenarios, and this is a
// fact about the target row rather than about anybody's claim. It is also
// orthogonal to every one of those columns — the authority check refuses first in
// all six of the declining ones, so a compare-and-swap can only be reached in the
// `held`/`none` cell, where the matrix already asserts the opposite outcome.
//
// What it is about: `jobs.removeLocked` can answer `refused`, and that answer is a
// plain return value rather than an error. The contract stored it into `destroyed`
// and ran `COMMIT` regardless, so the terminal written two statements earlier
// landed over a row that is still on disk. On a non-exit-code terminal that
// receipt carries removal wording, and a terminal is frozen — nothing can correct
// it afterwards. Durable pseudo-success, in the ledger, which is the one thing this
// subsystem exists to prevent.
//
// Three legs: the refusal writes nothing and destroys nothing, its rollback is
// reported as the proof it is, and the same fixture with a matching expectation
// still removes — without which every assertion here would hold against a contract
// that had stopped removing anything.
test "gate: a `job rm` whose compare-and-swap is refused leaves no terminal claiming it" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_job_removal_cas_refused");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    try seedServer(&store);

    const now = try Store.leases.clockSeconds(&store);
    var subject = try seedMatrixSubject(&store, arena, scratch.io, .job_rm_attached, now);
    defer if (subject.execution) |*e| e.deinit();
    try arrangeMatrixClaim(&store, arena, subject.authority, .held, .none, now);

    const job = subject.job.?;
    // The row is `running`; this expectation says `pending`, which is the shape a
    // removal has when the row moved on between the read and the write — a
    // relaunch, a peer's kill, a name taken over. Built from the real row so only
    // the one field the CAS turns on differs.
    const stale: Store.jobs.RemoveExpectation = .{
        .id = job.removeExpectation().id,
        .owner = job.removeExpectation().owner,
        .status = .pending,
    };
    try t.expectEqual(Store.jobs.Status.running, job.status);

    const settlement: execution.JobSettlement = .{
        .attempt = .{
            .execution = &subject.execution.?,
            // The terminal that made this worth closing: `indeterminate`'s reason is
            // prose that opens with "job removed", and no later write can revise it.
            .terminal = .{ .indeterminate = .{
                .reason = "job removed before its outcome was established",
                .last_observed = .submitted,
            } },
            .extra = .{},
        },
    };

    var rollback: execution.Rollback = .none;
    switch (try execution.settleAndForgetJob(
        &store,
        arena,
        scratch.io,
        1,
        matrix_scope,
        .{ .lease_owner_request_id = subject.authority },
        settlement,
        .{ .expected = stale, .grounds = .session_proven_gone },
        &rollback,
    )) {
        .refused => |why| switch (why) {
            .row_moved => |conflict| switch (conflict) {
                .status_moved => |moved| {
                    try t.expectEqual(Store.jobs.Status.pending, moved.expected);
                    try t.expectEqual(Store.jobs.Status.running, moved.found);
                },
                else => return error.RefusedForTheWrongReason,
            },
            // The authority held: neither of these is what declined this call.
            .scope_taken, .claim_lost => return error.RefusedForTheWrongReason,
        },
        // This would mean the CAS answer reached a caller as something other than
        // a refusal — which is the defect.
        .forgotten => return error.RefusedRemovalWasNotReported,
    }

    // The assertion. No terminal, because the destruction did not happen; the
    // attempt is where it was, still `submitted`, still barring the scope, still
    // this command's to settle with something honest.
    try t.expectEqual(
        @as(?Store.receipts.TerminalRecord, null),
        try Store.receipts.terminalOf(&store, subject.target.?),
    );
    const op = (try Store.operations.get(&store, arena, subject.target.?)).?;
    try t.expectEqual(op_state.Status.submitted, op.status);
    try t.expect(op.status.blocksScope());
    try t.expect(!subject.execution.?.settled);

    // …and the row is still there, which is the other half of "neither or both".
    try t.expect((try Store.jobs.getByName(&store, arena, 1, matrix_name)) != null);

    // The undo is *reported*, not left to be inferred. A caller that could not tell
    // "the transaction went back" from "nothing needed undoing" would have nothing
    // to say about the row.
    try t.expectEqualStrings("confirmed", @tagName(rollback));

    // Leg three, the discriminating control: the same store, the same attempt, the
    // same claim, and the expectation the caller actually read. Without it every
    // assertion above is satisfied by a contract that refuses everything.
    const fresh = (try Store.jobs.getByName(&store, arena, 1, matrix_name)).?;
    switch (try execution.settleAndForgetJob(
        &store,
        arena,
        scratch.io,
        1,
        matrix_scope,
        .{ .lease_owner_request_id = subject.authority },
        settlement,
        .{ .expected = fresh.removeExpectation(), .grounds = .session_proven_gone },
        &rollback,
    )) {
        .forgotten => |done| switch (done.ledger) {
            .recorded => |record| try t.expectEqual(op_state.Status.indeterminate, record.status),
            .rival, .absent => return error.ControlWroteNoTerminal,
        },
        else => return error.ControlDidNotRemove,
    }
    try t.expectEqualStrings("none", @tagName(rollback));
    try t.expectEqual(
        @as(?Store.jobs.Job, null),
        try Store.jobs.getByName(&store, arena, 1, matrix_name),
    );
    try t.expect((try Store.receipts.terminalOf(&store, subject.target.?)) != null);
}

// `job kill` is the fifth destructive verb, and it is deliberately *not* a row in
// the matrix above. This is why, stated structurally rather than left as a hole.
//
// Its settlement goes through `Execution.settleAttachedAndSyncJob`, whose only
// local write is a `JobCacheSync` — and that type has no arm that destroys
// anything. So `job kill` cannot reach `commitDestruction`, and the authority
// question it has to answer is a different one: the kill has already gone out by
// the time it settles, so its terminal must be writable *precisely when the
// authority is lost* (`cmd_job.lostTerminal`, an `indeterminate` carrying
// `AUTHORITY_LOST`). An in-transaction refusal there would suppress the one record
// that says a pane was stopped and nobody can say what became of the work.
//
// What holds `job kill` instead is the renewal adjacency gate in `cmd_job.zig`,
// which proves there is nothing between the question and each `kill-session`.
//
// The assertion is on the shape of `JobCacheSync`, because that is the thing that
// would have to change for `job kill` to become a destruction: the `.forget` arm
// used to live there, which is exactly how `job rm`'s two standalone branches came
// to destroy rows through a route with no authority in it.
test "gate: the settlement `job kill` writes cannot express a destruction" {
    const t = std.testing;
    const fields = @typeInfo(execution.JobCacheSync).@"union".fields;
    try t.expectEqual(@as(usize, 2), fields.len);
    try t.expectEqualStrings("none", fields[0].name);
    try t.expectEqualStrings("finish", fields[1].name);

    // And the destructive contract's own vocabulary, for the other direction: two
    // destructions, both of which name a subject. A third arm added here without a
    // row in the matrix above fails this count.
    const destructions = @typeInfo(execution.Destruction).@"union".fields;
    try t.expectEqual(@as(usize, 2), destructions.len);
    try t.expectEqualStrings("session_row", destructions[0].name);
    try t.expectEqualStrings("job_row", destructions[1].name);
}

// --- A cascading delete has one writer, and one route to it ------------------
//
// **Two** DELETEs in this tree destroy more than the row they name, and one scan
// holds both. It used to hold one; the other was written down in `88f1d59`'s
// commit message as a follow-up, which is where a rule goes to be forgotten.
//
// The `sessions` delete cascades that session's memories — `memories.session_id
// ... ON DELETE CASCADE`, v1 — and memories are the one thing `session rm`
// destroys that no remote command can put back.
//
// The `servers` delete is wider: seven tables, which is the widest destruction
// here. That set is declared and held against the schema by
// `gates_schema_test.zig`'s `server_cascade`; what *this* gate holds is the other
// half — that the route to it stays the one route.
//
// (`jobs` is not in that class: nothing references `jobs(id)`, so a job delete
// takes exactly the row it names. Its route is held by a different mechanism; see
// `jobs.RemovalGrounds.warrant`.)
//
// **Why one implementation and not two.** The session half of this scan was
// copied nowhere and still drifted into being the only one, and a second copy for
// `servers` would have been the fourth place this session found the same rule
// written twice. So the counts are data — `CascadeRoute` — and the walk is
// written once. What the walk cannot be is a hand-list of files: a list cannot
// see a call in a file that did not exist when the list was written, which is
// precisely the regression — a new caller — that this exists to catch.
// `test/blackbox.zig` is deliberately out of the walk: it drives the built binary
// as a subprocess and cannot call a store function at all.
//
// **The needles are spelled in halves** so this file's own text does not satisfy
// the scan it drives. Skipping this file instead would have made the one file
// nobody scans the one place a call could hide. The same is why the prose above
// says "the `servers` DELETE" rather than writing the statement out: a mention in
// a comment is a mention, and the statement count does not care why the bytes are
// there.
//
// **The two routes are shaped differently, and the spec states the difference
// rather than the walk guessing at it.**
//
// `sessions.removeLocked` has one *cross-file* caller and no local one: its
// transaction-opening wrapper was deleted in `88f1d59` because it had zero
// callers, and the claim-backed contract in `execution.zig` is the only way in.
// So its file may name it exactly once — its own header — and a second local
// mention is the wrapper coming back under some name.
//
// `servers.removeLocked` is the mirror image: **zero** cross-file callers and one
// local one. Its wrapper `servers.remove` is the route, it has a production
// caller in `cmd_server.zig`, and it is not deletable — so this gate pins its
// caller count instead of arguing for its removal. That is also why the writer's
// own file may name the writer twice rather than once: the definition, and the
// wrapper's call to it.
//
// Four counts per route, each deliberate:
//
//   * the statement, **1**, because a second copy is a second route however it is
//     guarded;
//   * cross-file calls to the writer, checked against the one file and — where
//     there is one — the one *function* allowed to make them, via
//     `Control.bodyOf`, so a second function in the right file fails too;
//   * mentions of the writer inside its own file, which is the count a local
//     wrapper moves and the one three cross-file needles all miss;
//   * calls to the transaction-opening wrapper, against the files allowed to make
//     them.

/// One cascading DELETE, and the counts that hold its route.
const CascadeRoute = struct {
    /// What the failure messages call it.
    subject: []const u8,
    /// What the route protects, for a message that has to say why it matters.
    stakes: []const u8,
    /// The DELETE, spelled in halves.
    statement: []const u8,
    /// One. See the header.
    statement_count: usize,
    /// The file that owns the statement, relative to the walk root.
    writer_file: []const u8,
    /// The writer's name as an unqualified call, for counting where it is defined.
    writer_bare: []const u8,
    /// How many times that file may say it: its own header, plus the local
    /// callers this route is allowed to have.
    mentions_at_home: usize,
    /// The writer as a cross-file call.
    writer_call: []const u8,
    /// How many of those the tree may have.
    writer_call_count: usize,
    /// The one file allowed to make them, and the one function inside it. Null
    /// when the writer has no cross-file caller at all, in which case
    /// `writer_call_count` is zero and any call anywhere fails.
    caller: ?Caller,
    /// The transaction-opening wrapper beside the writer, as a call.
    wrapper_call: []const u8,
    /// How many of those the tree may have. Zero means the wrapper does not
    /// exist and may not come back.
    wrapper_call_count: usize,
    /// The files allowed to make them.
    wrapper_caller_files: []const []const u8,

    const Caller = struct {
        file: []const u8,
        /// Spelled as `Control.bodyOf` wants it.
        body: []const u8,
    };
};

/// `session rm`'s route: the claim-backed contract, and nothing else.
const session_cascade: CascadeRoute = .{
    .subject = "session",
    .stakes = "that session's memories, which no remote command can put back",
    .statement = "DELETE FROM " ++ "sessions",
    .statement_count = 1,
    .writer_file = "core/store/sessions.zig",
    .writer_bare = "removeLocked" ++ "(",
    // Its own header and nothing else. The deleted wrapper was a local call, so
    // this is the count that stops it coming back under any name.
    .mentions_at_home = 1,
    .writer_call = "sessions." ++ "removeLocked(",
    .writer_call_count = 1,
    .caller = .{
        .file = "core/execution.zig",
        .body = "\npub fn commitDestruction(",
    },
    .wrapper_call = "sessions." ++ "remove(",
    // Zero, forever, unless somebody argues for it out loud.
    .wrapper_call_count = 0,
    .wrapper_caller_files = &.{},
};

/// `server rm`'s route: the quiescence-backed contract, reached through the
/// wrapper that opens its transaction.
const server_cascade_route: CascadeRoute = .{
    .subject = "server",
    .stakes = "seven cascading tables, the widest destruction in this tree",
    .statement = "DELETE FROM " ++ "servers",
    .statement_count = 1,
    .writer_file = "core/store/servers.zig",
    .writer_bare = "removeLocked" ++ "(",
    // Two: the definition, and `remove`'s call to it. `remove` is the route, so
    // a third mention is a second local route.
    .mentions_at_home = 2,
    .writer_call = "servers." ++ "removeLocked(",
    // None. Everything that removes a server goes through `remove`, which opens
    // the `BEGIN IMMEDIATE` the three barriers are counted inside.
    .writer_call_count = 0,
    .caller = null,
    .wrapper_call = "servers." ++ "remove(",
    // One production caller in `cmd_server.zig`, plus the two helpers in the
    // recovery gate that drive it — `mustRemove` and `refusalOf`. Pinned rather
    // than reduced: unlike `sessions.remove` this wrapper is the route, so the
    // number is what a new caller has to move deliberately.
    .wrapper_call_count = 3,
    .wrapper_caller_files = &.{
        "cli/cmd_server.zig",
        "core/store/gates_recovery_test.zig",
    },
};

fn occurrences(haystack: []const u8, needle: []const u8) usize {
    var n: usize = 0;
    var from: usize = 0;
    while (std.mem.indexOfPos(u8, haystack, from, needle)) |at| : (from = at + needle.len) n += 1;
    return n;
}

fn allows(files: []const []const u8, path: []const u8) bool {
    for (files) |f| if (std.mem.eql(u8, f, path)) return true;
    return false;
}

/// Walks `src/` and holds one cascading delete to its route.
fn holdCascadeRoute(route: CascadeRoute) !void {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var threaded: std.Io.Threaded = .init(t.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var dir = try std.Io.Dir.cwd().openDir(io, "src", .{ .iterate = true });
    defer dir.close(io);
    var walker = try dir.walk(arena);
    defer walker.deinit();

    var statements: usize = 0;
    var writer_calls: usize = 0;
    var wrapper_calls: usize = 0;
    var mentions_at_home: ?usize = null;
    var caller_source: ?[]const u8 = null;

    while (try walker.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.basename, ".zig")) continue;
        const path = try arena.dupe(u8, entry.path);
        std.mem.replaceScalar(u8, path, '\\', '/');
        const text = try entry.dir.readFileAlloc(io, entry.basename, arena, .limited(8 << 20));
        const at_home = std.mem.eql(u8, path, route.writer_file);

        const here = occurrences(text, route.statement);
        if (here != 0 and !at_home) {
            std.debug.print(
                \\
                \\src/{s}: writes the {s} DELETE, whose cascade takes {s} with it.
                \\That statement belongs to src/{s} alone. If this is a *mention*
                \\in a comment rather than a statement, spell it in halves — the
                \\count reads bytes and cannot tell the difference.
                \\
            , .{ path, route.subject, route.stakes, route.writer_file });
            return error.CascadingDeleteOutsideItsWriter;
        }
        statements += here;

        const wraps = occurrences(text, route.wrapper_call);
        if (wraps != 0 and !allows(route.wrapper_caller_files, path)) {
            std.debug.print(
                \\
                \\src/{s}: calls the transaction-opening wrapper for the {s}
                \\cascade, and is not one of the files allowed to. The wrapper is
                \\a public route to a delete that takes {s}; a new caller is a new
                \\place that decision is made, so it goes in
                \\`wrapper_caller_files` beside a raised `wrapper_call_count` or
                \\it does not go in at all.
                \\
            , .{ path, route.subject, route.stakes });
            return error.CascadeWrapperCalledFromAnUnlistedFile;
        }
        wrapper_calls += wraps;

        // The writer's own file defines it; every other mention is a call.
        if (at_home) {
            mentions_at_home = occurrences(text, route.writer_bare);
            continue;
        }
        const calls = occurrences(text, route.writer_call);
        if (calls != 0 and !(route.caller != null and
            std.mem.eql(u8, path, route.caller.?.file)))
        {
            if (route.caller) |only| {
                std.debug.print(
                    \\
                    \\src/{s}: calls the {s}-cascade writer. Only src/{s} may: a
                    \\delete that takes {s} has to land in the same transaction as
                    \\the terminal that says it happened, or the ledger asserts a
                    \\removal whose rows are still on disk and no later command can
                    \\correct it.
                    \\
                , .{ path, route.subject, only.file, route.stakes });
            } else {
                std.debug.print(
                    \\
                    \\src/{s}: calls the {s}-cascade writer directly. Nothing
                    \\outside src/{s} may. The writer requires its caller's write
                    \\transaction and counts its barriers inside it; reaching it
                    \\from here means those barriers run inside a transaction this
                    \\file opened, over a delete that takes {s}. If that is really
                    \\what is wanted, it is a decision about the contract and not
                    \\a call site — say so and raise `writer_call_count`.
                    \\
                , .{ path, route.subject, route.writer_file, route.stakes });
            }
            return error.CascadingDeleteReachedOutsideItsRoute;
        }
        writer_calls += calls;
        if (calls != 0) caller_source = text;
    }

    // A walk that found nothing would have complained about nothing. The writer's
    // file has to have been read for any of the counts to mean anything.
    const home = mentions_at_home orelse {
        std.debug.print(
            \\
            \\the walk never read src/{s}, so every count below it is zero for
            \\the wrong reason. This gate reads the source tree from the build
            \\root; nothing here is evidence unless that file was seen.
            \\
        , .{route.writer_file});
        return error.CascadeWriterFileWasNotScanned;
    };
    if (home != route.mentions_at_home) {
        std.debug.print(
            \\
            \\src/{s} names the {s}-cascade writer {d} times; it may name it {d}.
            \\A mention over that budget is a local caller — a transaction-opening
            \\wrapper beside the writer, under whatever name — and that is a route
            \\to a delete that takes {s}, reached without whatever the sanctioned
            \\route establishes first.
            \\
        , .{ route.writer_file, route.subject, home, route.mentions_at_home, route.stakes });
        return error.CascadingDeleteHasAnExtraLocalRoute;
    }
    if (statements != route.statement_count) {
        std.debug.print(
            \\
            \\the tree writes the {s} DELETE {d} times; it may write it {d}.
            \\
        , .{ route.subject, statements, route.statement_count });
        return error.CascadingDeleteIsWrittenTwice;
    }
    if (writer_calls != route.writer_call_count) {
        std.debug.print(
            \\
            \\the {s}-cascade writer has {d} cross-file callers; it may have {d}.
            \\A caller changing this number is changing it deliberately or not at
            \\all.
            \\
        , .{ route.subject, writer_calls, route.writer_call_count });
        return error.CascadingDeleteCallerCountMoved;
    }
    if (wrapper_calls != route.wrapper_call_count) {
        std.debug.print(
            \\
            \\the {s} cascade's transaction-opening wrapper has {d} callers; it
            \\may have {d}.
            \\
        , .{ route.subject, wrapper_calls, route.wrapper_call_count });
        return error.CascadeWrapperCallerCountMoved;
    }

    // And the call is inside the one *function*, not merely inside its file. For
    // `session rm` that function is what re-reads the claim and writes the
    // terminal; a second function in `execution.zig` calling the writer would
    // satisfy every count above and have none of that.
    if (route.caller) |only| {
        const body = try Control.bodyOf(caller_source.?, only.body);
        try t.expectEqual(route.writer_call_count, occurrences(body, route.writer_call));
    } else {
        try t.expectEqual(@as(?[]const u8, null), caller_source);
    }
}

test "gate: the session cascade has one writer and the contract is its one caller" {
    try holdCascadeRoute(session_cascade);
}

test "gate: the server cascade has one writer and its wrapper is the one route" {
    try holdCascadeRoute(server_cascade_route);
}
