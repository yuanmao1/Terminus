//! Contention: the scope lease, and the one overlap rule it shares with the
//! operation guard.
//!
//! A lease is how two commands aimed at the same thing find out about each
//! other before either touches a host. The gates here hold that only one owner
//! wins a contended acquire; that renew, expiry and takeover leave an audit
//! chain a reader can follow; that a takeover displaces *every* overlapping
//! lease and links all of them rather than just the first; and that a job's
//! attempt rows survive both a same-name rerun and a `job rm`, because the
//! ledger outlives the row.
//!
//! Name reservation is here too. It is the same question one level up — two
//! launchers, one job name — answered by the same kind of race, so it is proved
//! the same way.
//!
//! The last gate is the seam: the operation guard and `leases` must agree on
//! what "overlapping" means. Two implementations of that predicate is two
//! answers to "may I act", and both directions of disagreement fail silently.

const std = @import("std");
const Store = @import("Store.zig");

// The shared fixtures. Aliased under their own names so a gate reads the
// same here as it did when every gate was in one file.
const fixtures = @import("gates_fixtures.zig");
const Scratch = fixtures.Scratch;
const testId = fixtures.testId;
const seedServer = fixtures.seedServer;
const mustApply = fixtures.mustApply;

const LeaseRaceCtx = struct {
    path: [:0]const u8,
    owner: []const u8,
    gate: *std.atomic.Value(bool),
    acquired: bool = false,
    conflicted: bool = false,
    err: ?anyerror = null,
};

fn acquireInThread(ctx: *LeaseRaceCtx) void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();

    while (!ctx.gate.load(.acquire)) std.atomic.spinLoopHint();
    var store = Store.open(ctx.path) catch |err| {
        ctx.err = err;
        return;
    };
    defer store.close();
    const outcome = Store.leases.acquire(&store, arena_state.allocator(), .{
        .server_id = 1,
        .scope = .{ .kind = .job, .key = "deploy" },
        .owner_request_id = ctx.owner,
        .profile_token = "one-shared-machine",
        .ttl_secs = 600,
        .now = 1000,
    }) catch |err| {
        ctx.err = err;
        return;
    };
    switch (outcome) {
        .acquired => ctx.acquired = true,
        .conflict => ctx.conflicted = true,
        .renewed => ctx.acquired = true,
    }
}

test "gate: only one owner wins a contended lease" {
    const t = std.testing;
    const owners = [_][]const u8{ "owner-a", "owner-b", "owner-c", "owner-d" };

    for (0..6) |round| {
        var name_buf: [40]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "gate_lease_race_{d}", .{round});
        var scratch = try Scratch.init(t.allocator, name);
        defer scratch.deinit();
        {
            var store = try Store.open(scratch.path);
            defer store.close();
            try seedServer(&store);
        }

        // Conflict detection lives inside BEGIN IMMEDIATE. A check-then-insert
        // outside a transaction would let several acquirers all see a free
        // scope and all believe they hold it.
        var gate: std.atomic.Value(bool) = .init(false);
        var ctxs: [owners.len]LeaseRaceCtx = undefined;
        var threads: [owners.len]std.Thread = undefined;
        for (&ctxs, 0..) |*ctx, i| {
            ctx.* = .{ .path = scratch.path, .owner = owners[i], .gate = &gate };
            threads[i] = try std.Thread.spawn(.{}, acquireInThread, .{ctx});
        }
        gate.store(true, .release);
        for (threads) |thread| thread.join();

        var winners: usize = 0;
        for (&ctxs) |*ctx| {
            if (ctx.err) |err| {
                std.debug.print("round {d} owner {s}: {s}\n", .{ round, ctx.owner, @errorName(err) });
                return err;
            }
            if (ctx.acquired) winners += 1;
        }
        try t.expectEqual(@as(usize, 1), winners);

        // And the database agrees: exactly one active row for the scope.
        var store = try Store.open(scratch.path);
        defer store.close();
        var stmt = try store.db.prepare(
            "SELECT COUNT(*) FROM leases WHERE released_at IS NULL AND scope_key = 'deploy'",
        );
        defer stmt.deinit();
        try t.expect(try stmt.step());
        try t.expectEqual(@as(i64, 1), stmt.columnInt(0));
    }
}

test "gate: lease lifecycle — renew, expire, takeover audit chain" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_lease_lifecycle");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    try seedServer(&store);

    // One machine, three attempts. The profile token is deliberately identical
    // on every acquisition below: until v12 it was what `acquire` compared, so
    // this whole gate would have read as one owner renewing its own lease over
    // and over and no line in it could have failed.
    const profile = "one-shared-machine";
    const attempt_a: []const u8 = "01AAAAAAAA0123456789ABCDEF";
    const attempt_b: []const u8 = "01BBBBBBBB0123456789ABCDEF";
    const attempt_c: []const u8 = "01CCCCCCCC0123456789ABCDEF";

    const job_scope: Store.leases.Scope = .{ .kind = .job, .key = "deploy" };
    const base: Store.leases.AcquireOptions = .{
        .server_id = 1,
        .scope = job_scope,
        .owner_request_id = attempt_a,
        .profile_token = profile,
        .ttl_secs = 100,
        .now = 1000,
    };

    // First acquisition.
    try t.expect((try Store.leases.acquire(&store, arena, base)).acquired.id > 0);

    // The same *attempt* asking again renews instead of piling up rows.
    var again = base;
    again.now = 1050;
    try t.expect((try Store.leases.acquire(&store, arena, again)) == .renewed);

    // A second attempt on the same machine is blocked, and learns which
    // attempt holds it. This is the line the defect lived on.
    var peer = base;
    peer.owner_request_id = attempt_b;
    peer.now = 1060;
    const blocked = try Store.leases.acquire(&store, arena, peer);
    try t.expectEqualStrings(attempt_a, blocked.conflict.owner_request_id);
    // ...and the profile is still recorded, as the audit subject it now is.
    try t.expectEqualStrings(profile, blocked.conflict.profile_token);

    // Exactly one row, so the renewal above really renewed.
    try t.expectEqual(@as(usize, 1), (try Store.leases.active(&store, arena, 1, 1060)).len);

    // A whole-server lease overlaps the job scope, so it is blocked too.
    var server_scope = peer;
    server_scope.scope = .{ .kind = .server };
    try t.expect((try Store.leases.acquire(&store, arena, server_scope)) == .conflict);

    // Past the TTL the lease lapses and the peer may take it (lazy expiry).
    peer.now = 5000;
    try t.expect((try Store.leases.acquire(&store, arena, peer)) == .acquired);

    // Losing a lease must be visible: the old owner's renew fails rather
    // than silently reviving it underneath the new holder.
    try t.expect(!try Store.leases.renew(&store, 1, job_scope, attempt_a, 100, 5010));

    // An owner that names nobody is refused before it can be compared: an
    // empty string matches every other empty string, which is the machine-wide
    // owner all over again.
    try t.expectError(
        error.EmptyLeaseOwner,
        Store.leases.renew(&store, 1, job_scope, "", 100, 5010),
    );
    try t.expectError(
        error.EmptyLeaseOwner,
        Store.leases.conflictFor(&store, arena, 1, job_scope, "", 5010),
    );

    // Takeover leaves an audit chain rather than overwriting.
    var thief = base;
    thief.owner_request_id = attempt_c;
    thief.now = 5020;
    const taken = try Store.leases.takeover(&store, arena, thief);
    try t.expectEqual(@as(usize, 1), taken.taken.from.len);
    try t.expectEqualStrings(attempt_b, taken.taken.from[0].owner_request_id);

    var stmt = try store.db.prepare(
        \\SELECT release_reason, superseded_by FROM leases
        \\ WHERE id = ?1
    );
    defer stmt.deinit();
    try stmt.bindInt(1, taken.taken.from[0].id);
    try t.expect(try stmt.step());
    try t.expectEqualStrings("takeover", stmt.columnText(0));
    try t.expectEqual(taken.taken.lease.id, stmt.columnInt(1));

    // The guard used by write operations sees the conflict for others only.
    try t.expect((try Store.leases.conflictFor(&store, arena, 1, job_scope, attempt_a, 5030)) != null);
    try t.expect((try Store.leases.conflictFor(&store, arena, 1, job_scope, attempt_c, 5030)) == null);
}

// A takeover displaces *every* overlapping lease, not the first one it finds.
//
// The state this gate exists to make unreachable is two active leases whose
// scopes overlap, which the schema cannot refuse: `idx_leases_active` is UNIQUE
// on `(server_id, scope_kind, scope_key)` exactly, so `path:/srv/app` sitting
// beside `path:/srv/app/build` is two distinct keys and commits clean. Nothing
// downstream would have objected either — `conflictFor` returns the *first*
// overlap it sees, so the surviving lease would have gone on blocking peers
// while its owner had been told nothing and the new holder believed the scope
// was theirs.
//
// The setup is ordinary rather than contrived: `acquire` refuses overlapping
// leases and permits everything else, so two sibling directories are exactly
// what a pair of cooperating sessions ends up holding.
test "gate: takeover displaces every overlapping lease and links all of them" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_lease_takeover_all");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    try seedServer(&store);

    const base: Store.leases.AcquireOptions = .{
        .server_id = 1,
        .scope = .{ .kind = .path, .key = "/srv/app/dist" },
        .owner_request_id = "01AAAAAAAA0123456789ABCDEF",
        .profile_token = "one-shared-machine",
        .ttl_secs = 1000,
        .now = 1000,
    };

    // Two leases that do not overlap each other. Both are legal, and the second
    // acquisition proves it rather than assuming it: if `acquire` ever started
    // refusing this pair, the hole below would stop being reachable and this
    // gate would be testing nothing.
    try t.expect((try Store.leases.acquire(&store, arena, base)) == .acquired);
    var sibling = base;
    sibling.scope = .{ .kind = .path, .key = "/srv/app/build" };
    sibling.owner_request_id = "01BBBBBBBB0123456789ABCDEF";
    sibling.now = 1010;
    try t.expect((try Store.leases.acquire(&store, arena, sibling)) == .acquired);

    // A third scope containing both.
    var thief = base;
    thief.scope = .{ .kind = .path, .key = "/srv/app" };
    thief.owner_request_id = "01CCCCCCCC0123456789ABCDEF";
    thief.now = 1100;
    const taken = try Store.leases.takeover(&store, arena, thief);

    // Both owners are reported. A caller told about one of them would notify
    // half the peers whose work it just seized.
    try t.expectEqual(@as(usize, 2), taken.taken.from.len);
    var saw_a = false;
    var saw_b = false;
    for (taken.taken.from) |old| {
        if (std.mem.eql(u8, old.owner_request_id, "01AAAAAAAA0123456789ABCDEF")) saw_a = true;
        if (std.mem.eql(u8, old.owner_request_id, "01BBBBBBBB0123456789ABCDEF")) saw_b = true;
    }
    try t.expect(saw_a and saw_b);

    // ...and the audit chain is complete for each: a displaced row with no
    // successor recorded reads as an expiry rather than as a seizure.
    for (taken.taken.from) |old| {
        var stmt = try store.db.prepare(
            "SELECT release_reason, superseded_by FROM leases WHERE id = ?1",
        );
        defer stmt.deinit();
        try stmt.bindInt(1, old.id);
        try t.expect(try stmt.step());
        try t.expectEqualStrings("takeover", stmt.columnText(0));
        try t.expectEqual(taken.taken.lease.id, stmt.columnInt(1));
    }

    // The invariant itself, read back off the table: one active lease on the
    // server, and it is the new one.
    const still_held = try Store.leases.active(&store, arena, 1, 1110);
    try t.expectEqual(@as(usize, 1), still_held.len);
    try t.expectEqualStrings("01CCCCCCCC0123456789ABCDEF", still_held[0].owner_request_id);

    // Both former owners are now blocked, and by the same lease. A survivor
    // would show up here as one of them still being free to write.
    for ([_][]const u8{ "01AAAAAAAA0123456789ABCDEF", "01BBBBBBBB0123456789ABCDEF" }) |owner| {
        const blocked = try Store.leases.conflictFor(
            &store,
            arena,
            1,
            .{ .kind = .path, .key = "/srv/app/dist" },
            owner,
            1110,
        );
        try t.expect(blocked != null);
        try t.expectEqual(taken.taken.lease.id, blocked.?.id);
    }
}

test "gate: job attempts survive a same-name rerun and job rm" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_job_attempts");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    try seedServer(&store);

    // Two runs of the same job name, as `run --name build` twice would do.
    for ([_][]const u8{ "01AAAAAAAA0123456789ABCDEF", "01BBBBBBBB0123456789ABCDEF" }, 0..) |request_id, i| {
        try Store.operations.create(&store, .{
            .request_id = request_id,
            .server_id = 1,
            .server_name = "lease-host",
            .kind = .job,
            .alias = "build",
            .now = @intCast(1000 + i),
        });
        const attempt_no = try Store.job_attempts.nextAttemptNo(&store, 1, "build");
        try t.expectEqual(@as(i64, @intCast(i + 1)), attempt_no);
        _ = try Store.job_attempts.create(&store, .{
            .request_id = request_id,
            .server_id = 1,
            .server_name = "lease-host",
            .job_name = "build",
            .attempt_no = attempt_no,
            .script_sha256 = if (i == 0) "hash-v1" else "hash-v2",
            .now = @intCast(1000 + i),
        });
    }

    // Both attempts remain, with their own script hashes — the point of an
    // immutable attempt: attempt 1 still says what it actually ran, even
    // though attempt 2 reused the name.
    const all = try Store.job_attempts.history(&store, arena, 1, "build");
    try t.expectEqual(@as(usize, 2), all.len);
    try t.expectEqualStrings("hash-v2", all[0].script_sha256.?);
    try t.expectEqualStrings("hash-v1", all[1].script_sha256.?);

    // Probe state is separate, so recording an observation cannot mutate the
    // attempt, and every reading carries when it was taken.
    try Store.job_attempts.recordProbe(&store, all[0].request_id, .{
        .probe_cursor = 4096,
        .latest_progress_json = "{\"phase\":\"download\"}",
        .session_alive = true,
        .now = 2000,
    });
    // A later probe that saw no new markers must not erase what we knew.
    try Store.job_attempts.recordProbe(&store, all[0].request_id, .{
        .probe_cursor = 8192,
        .session_alive = true,
        .now = 2100,
    });
    const probe = (try Store.job_attempts.probeState(&store, arena, all[0].request_id)).?;
    try t.expectEqual(@as(i64, 8192), probe.probe_cursor);
    try t.expectEqualStrings("{\"phase\":\"download\"}", probe.latest_progress_json.?);
    try t.expectEqual(@as(i64, 2100), probe.last_probed_at.?);
}

// The same rule as the test above, for the column it was not applied to.
//
// `parser_carry` holds the bytes a probe held back because a `__TERMINUS_PROGRESS__`
// line straddled its read window; the next probe is the only thing that can ever
// use them. It was the one of the four observation columns written unconditionally,
// and the single production caller (`cmd_job.zig`'s `refresh`) sets neither it nor
// two of its neighbours — so it bound the struct default `null` and every
// `job status` and every `job read` overwrote the column with NULL. A split marker
// could not survive a second look, which is the one thing this column exists for.
//
// Driven with the caller's own shape: the second `recordProbe` here sets exactly
// what `refresh` sets. That is what makes this the hot path and not a hypothetical.
test "gate: a second probe does not erase the carry the first one held back" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_probe_carry");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    try seedServer(&store);

    const request_id = "01CCCCCCCC0123456789ABCDEF";
    try Store.operations.create(&store, .{
        .request_id = request_id,
        .server_id = 1,
        .server_name = "lease-host",
        .kind = .job,
        .alias = "carry",
        .now = 3000,
    });
    _ = try Store.job_attempts.create(&store, .{
        .request_id = request_id,
        .server_id = 1,
        .server_name = "lease-host",
        .job_name = "carry",
        .attempt_no = 1,
        .now = 3000,
    });

    // A read that ended mid-marker. The tail is kept for the next one.
    const held_back = "__TERMINUS_PROG";
    try Store.job_attempts.recordProbe(&store, request_id, .{
        .probe_cursor = 1024,
        .parser_carry = held_back,
        .session_alive = true,
        .now = 3100,
    });
    try t.expectEqualStrings(
        held_back,
        (try Store.job_attempts.probeState(&store, arena, request_id)).?.parser_carry.?,
    );

    // …and the next probe, spelled exactly the way `refresh` spells it: a cursor,
    // a business result and liveness, and nothing about the carry.
    try Store.job_attempts.recordProbe(&store, request_id, .{
        .probe_cursor = 2048,
        .latest_business_result = "{\"ok\":true}",
        .session_alive = true,
        .now = 3200,
    });

    const after = (try Store.job_attempts.probeState(&store, arena, request_id)).?;
    if (after.parser_carry == null) {
        std.debug.print(
            \\
            \\the second probe erased `parser_carry`. It is the only one of the four
            \\observation columns whose UPDATE is not a `COALESCE`, and the one production
            \\caller does not set it — so the split marker the first probe held back is gone
            \\on every `job status` and every `job read`.
            \\
        , .{});
        return error.ProbeCarryErased;
    }
    try t.expectEqualStrings(held_back, after.parser_carry.?);
    // The columns that *were* meant to move, did. A COALESCE applied to the wrong
    // side would freeze the cursor instead, which is the opposite failure.
    try t.expectEqual(@as(i64, 2048), after.probe_cursor);
    try t.expectEqualStrings("{\"ok\":true}", after.latest_business_result.?);
}

/// One thread racing to claim a job name, the way `run --name deploy` does.
/// Each carries its own request id, because that is what owns the row.
const ReserveCtx = struct {
    path: [:0]const u8,
    request_id: []const u8,
    gate: *std.atomic.Value(bool),
    reserved: bool = false,
    taken: bool = false,
    err: ?anyerror = null,
};

fn reserveInThread(ctx: *ReserveCtx) void {
    while (!ctx.gate.load(.acquire)) std.atomic.spinLoopHint();
    var store = Store.open(ctx.path) catch |err| {
        ctx.err = err;
        return;
    };
    defer store.close();
    _ = Store.jobs.create(&store, 1, "deploy", "make deploy", "__TERMINUS_JOB_1__", ctx.request_id, 1000) catch |err| {
        switch (err) {
            error.NameTaken => ctx.taken = true,
            else => ctx.err = err,
        }
        return;
    };
    ctx.reserved = true;
}

const reserve_ids = [_][]const u8{
    "01AAAAAAAA0123456789ABCDEF",
    "01BBBBBBBB0123456789ABCDEF",
    "01CCCCCCCC0123456789ABCDEF",
    "01DDDDDDDD0123456789ABCDEF",
};

test "M2 gate: only one launcher may reserve a job name" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_job_reservation");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    {
        var store = try Store.open(scratch.path);
        defer store.close();
        try seedServer(&store);
    }

    var gate: std.atomic.Value(bool) = .init(false);
    var ctxs: [reserve_ids.len]ReserveCtx = undefined;
    var threads: [reserve_ids.len]std.Thread = undefined;
    for (&ctxs, 0..) |*c, i| {
        c.* = .{ .path = scratch.path, .request_id = reserve_ids[i], .gate = &gate };
        threads[i] = try std.Thread.spawn(.{}, reserveInThread, .{c});
    }
    gate.store(true, .release);
    for (threads) |th| th.join();

    var reserved: usize = 0;
    var taken: usize = 0;
    var winner: ?[]const u8 = null;
    for (ctxs) |c| {
        try t.expectEqual(@as(?anyerror, null), c.err);
        if (c.reserved) {
            reserved += 1;
            winner = c.request_id;
        }
        if (c.taken) taken += 1;
    }
    // Exactly one launcher owns the name, and the losers learned it from a
    // single indivisible insert rather than from a read that another thread
    // could invalidate a moment later.
    //
    // This is the gate behind an ordering rule in `cmd_job.runCmd`: the
    // reservation happens *before* the job's tmux session is torn down and
    // rebuilt. A loser that got as far as that teardown would be killing the
    // session the winner had already filled with real work.
    try t.expectEqual(@as(usize, 1), reserved);
    try t.expectEqual(@as(usize, reserve_ids.len - 1), taken);

    var store = try Store.open(scratch.path);
    defer store.close();
    const owner = winner.?;

    // The winner holds a *pending* row, not a running one. Nothing has been
    // typed into the remote shell yet, so claiming `running` would put a job
    // in `job ls` that provably never started — while still blocking the
    // name, which is what the reservation is for.
    const row = (try Store.jobs.getByName(&store, arena, 1, "deploy")).?;
    try t.expectEqual(Store.jobs.Status.pending, row.status);
    try t.expect(row.status.live());

    // A loser may not release the winner's row. It never owned it.
    for (ctxs) |c| {
        if (c.reserved) continue;
        try t.expect(!try Store.jobs.releaseReservation(&store, c.request_id));
    }
    try t.expect((try Store.jobs.getByName(&store, arena, 1, "deploy")) != null);

    // Only reaching the remote promotes it, and the promotion reports that it
    // found its row — the launcher needs to know, because by then the command
    // has already been sent.
    try t.expect(try Store.jobs.markStarted(&store, owner));
    try t.expectEqual(Store.jobs.Status.running, (try Store.jobs.getByName(&store, arena, 1, "deploy")).?.status);

    // Once promoted the row is no longer a reservation, so its own owner
    // cannot drop it either: it may name work running on the host.
    try t.expect(!try Store.jobs.releaseReservation(&store, owner));

    // A promotion arriving after somebody observed the job's end must not
    // walk it back: the settlement is the newer truth, and the launcher is
    // told it no longer owns the row.
    const running = (try Store.jobs.getByName(&store, arena, 1, "deploy")).?;
    try mustApply(try Store.jobs.markFinishedUnattached(
        &store,
        running.finishExpectation(),
        .exited,
        0,
        2000,
    ));
    try t.expect(!try Store.jobs.markStarted(&store, owner));
    try t.expectEqual(Store.jobs.Status.exited, (try Store.jobs.getByName(&store, arena, 1, "deploy")).?.status);

    // The takeover case, which is why ownership is the request id and not the
    // row id: sqlite hands the next INSERT the id of the row just deleted, so
    // a successor can and does inherit the aborted launcher's rowid.
    const stale_owner = owner;
    const settled = (try Store.jobs.getByName(&store, arena, 1, "deploy")).?;
    try mustApply(try Store.jobs.remove(&store, settled.removeExpectation(), .superseded_by_relaunch));
    const successor_owner: []const u8 = "01EEEEEEEE0123456789ABCDEF";
    const successor_id = try Store.jobs.create(&store, 1, "deploy", "make deploy", "__TERMINUS_JOB_2__", successor_owner, 3000);
    try t.expectEqual(row.id, successor_id); // the rowid really is recycled

    // The aborted launcher now fails and releases. It must not take the
    // successor's row with it — that row may already have a command running.
    try t.expect(!try Store.jobs.releaseReservation(&store, stale_owner));
    const survivor = (try Store.jobs.getByName(&store, arena, 1, "deploy")).?;
    try t.expectEqual(Store.jobs.Status.pending, survivor.status);
    try t.expectEqualStrings("__TERMINUS_JOB_2__", survivor.sentinel);

    // And the successor can still release its own.
    try t.expect(try Store.jobs.releaseReservation(&store, successor_owner));
    try t.expectEqual(@as(?Store.jobs.Job, null), try Store.jobs.getByName(&store, arena, 1, "deploy"));

    // An unreadable status is an error, not a guess. This row is the shape a
    // future version writing a state this binary does not know would leave
    // behind; the old `orelse .running` renamed it to a state it had no
    // evidence for and reported that in `job ls`.
    _ = try Store.jobs.create(&store, 1, "deploy", "make deploy", "__TERMINUS_JOB_3__", "01FFFFFFFF0123456789ABCDEF", 4000);
    try store.db.exec("UPDATE jobs SET status = 'quantum' WHERE name = 'deploy'");
    try t.expectError(error.UnknownStatus, Store.jobs.getByName(&store, arena, 1, "deploy"));
}

test "gate: the operation guard and leases share one overlap rule" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_scope_unified");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    try seedServer(&store);

    // An unsettled operation holding a narrow path.
    const dist = testId("dist");
    try Store.operations.create(&store, .{
        .request_id = &dist,
        .server_id = 1,
        .server_name = "lease-host",
        .kind = .transfer_push,
        .scope_kind = .path,
        .scope_key = "/srv/app/dist",
        .now = 100,
    });
    try Store.operations.advance(&store, &dist, .connecting, 101);
    try Store.operations.advance(&store, &dist, .submitted, 102);

    // SQL equality on (kind, key) missed all three of these.
    const parent: Store.operations.Scope = .{ .kind = .path, .key = "/srv/app" };
    try t.expectEqual(@as(usize, 1), (try Store.operations.unsettledInScope(&store, arena, 1, parent)).len);
    const whole_host: Store.operations.Scope = .{ .kind = .server };
    try t.expectEqual(@as(usize, 1), (try Store.operations.unsettledInScope(&store, arena, 1, whole_host)).len);
    const sibling: Store.operations.Scope = .{ .kind = .path, .key = "/srv/applied" };
    try t.expectEqual(@as(usize, 0), (try Store.operations.unsettledInScope(&store, arena, 1, sibling)).len);

    // An unsettled operation that never declared a scope must block
    // everything: we cannot bound what it is touching. `dist` still does not
    // match this sibling path, so the undeclared one is the only hit.
    const vague = testId("vague");
    try Store.operations.create(&store, .{
        .request_id = &vague,
        .server_id = 1,
        .server_name = "lease-host",
        .kind = .exec,
        .now = 200,
    });
    try Store.operations.advance(&store, &vague, .connecting, 201);
    try Store.operations.advance(&store, &vague, .submitted, 202);
    try t.expectEqual(@as(usize, 1), (try Store.operations.unsettledInScope(&store, arena, 1, sibling)).len);

    // Settling clears the barrier.
    _ = try Store.receipts.settle(&store, &vague, .{ .exited = .{ .exit_code = 0 } }, .{}, 300);
    try t.expectEqual(@as(usize, 0), (try Store.operations.unsettledInScope(&store, arena, 1, sibling)).len);
    // ...but the narrow path operation is still in flight for its own scope.
    try t.expectEqual(@as(usize, 1), (try Store.operations.unsettledInScope(&store, arena, 1, parent)).len);

    // The lease layer answers identically, because it is the same rule.
    try t.expect(Store.leases.Scope.overlaps(parent, .{ .kind = .path, .key = "/srv/app/dist" }));
    try t.expect(!Store.leases.Scope.overlaps(sibling, .{ .kind = .path, .key = "/srv/app/dist" }));
}
