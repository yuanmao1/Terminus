//! M1 release gates for the persistence layer.
//!
//! These are not smoke tests. Each one corresponds to a stated gate that
//! must pass before the operation ledger can be built on top:
//!
//! * a fresh database reaches the latest version
//! * every historical version upgrades in order, preserving its data
//! * reopening is idempotent
//! * a failing migration rolls back completely (no partial schema, no
//!   version bump)
//! * two connections racing the same first-open both succeed
//! * a terminal receipt is recorded exactly once under contention
//! * a transport failure after submission can never be recorded as `failed`
const std = @import("std");
const Store = @import("Store.zig");
const Db = @import("Db.zig");
const migrate = @import("migrate.zig");
const ids = @import("ids.zig");
const op_state = @import("op_state.zig");

/// Scratch database under .zig-cache so a crashed test leaves nothing in the
/// source tree. Returns a NUL-terminated path for sqlite.
const Scratch = struct {
    io: std.Io,
    threaded: *std.Io.Threaded,
    path: [:0]u8,
    allocator: std.mem.Allocator,

    const dir = ".zig-cache/tmp";

    fn init(allocator: std.mem.Allocator, name: []const u8) !Scratch {
        const threaded = try allocator.create(std.Io.Threaded);
        threaded.* = .init(allocator, .{});
        const io = threaded.io();
        std.Io.Dir.cwd().createDirPath(io, dir) catch {};
        const path = try std.fmt.allocPrintSentinel(allocator, "{s}/{s}.db", .{ dir, name }, 0);
        var s: Scratch = .{ .io = io, .threaded = threaded, .path = path, .allocator = allocator };
        s.removeFiles();
        return s;
    }

    /// WAL databases have sidecars; leaving one behind would make the next
    /// run read a mismatched log (a mistake that silently shows empty data).
    fn removeFiles(s: *Scratch) void {
        const cwd = std.Io.Dir.cwd();
        cwd.deleteFile(s.io, s.path) catch {};
        for ([_][]const u8{ "-wal", "-shm" }) |suffix| {
            const side = std.fmt.allocPrint(s.allocator, "{s}{s}", .{ s.path, suffix }) catch return;
            defer s.allocator.free(side);
            cwd.deleteFile(s.io, side) catch {};
        }
    }

    fn deinit(s: *Scratch) void {
        s.removeFiles();
        s.allocator.free(s.path);
        s.threaded.deinit();
        s.allocator.destroy(s.threaded);
    }
};

test "gate: fresh database reaches the latest schema version" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_fresh");
    defer scratch.deinit();

    var store = try Store.open(scratch.path);
    defer store.close();
    try t.expectEqual(@as(i64, migrate.latest_version), try migrate.userVersion(&store.db));
}

test "gate: reopening is idempotent" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_reopen");
    defer scratch.deinit();

    for (0..3) |_| {
        var store = try Store.open(scratch.path);
        defer store.close();
        try t.expectEqual(@as(i64, migrate.latest_version), try migrate.userVersion(&store.db));
    }
}

test "gate: every historical version upgrades in order" {
    const t = std.testing;
    var v: usize = 1;
    while (v <= migrate.latest_version) : (v += 1) {
        var name_buf: [32]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "gate_up_from_v{d}", .{v});
        var scratch = try Scratch.init(t.allocator, name);
        defer scratch.deinit();

        // Build a database that stopped at version v...
        {
            var db = try Db.open(scratch.path);
            defer db.close();
            try migrate.applyUpTo(&db, v);
            try t.expectEqual(@as(i64, @intCast(v)), try migrate.userVersion(&db));
        }
        // ...then let the normal open path carry it to the latest.
        var store = try Store.open(scratch.path);
        defer store.close();
        try t.expectEqual(@as(i64, migrate.latest_version), try migrate.userVersion(&store.db));
    }
}

test "gate: data written at v4 survives the upgrade to latest" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_readback");
    defer scratch.deinit();

    // Write through the v4 schema exactly as 0.1.x would have.
    {
        var db = try Db.open(scratch.path);
        defer db.close();
        try migrate.applyUpTo(&db, 4);
        try db.exec(
            \\INSERT INTO servers (id, name, host, port, username, created_at, updated_at)
            \\VALUES (1, 'legacy', '10.0.0.1', 22, 'ubuntu', 100, 100);
            \\INSERT INTO memories (server_id, key, content, created_at, updated_at)
            \\VALUES (1, 'services', 'nginx :80', 100, 100);
            \\INSERT INTO history (server_id, kind, detail, created_at)
            \\VALUES (1, 'exec', 'uname -a', 100);
            \\INSERT INTO facts (server_id, key, value, updated_at)
            \\VALUES (1, 'app_root', '/srv/app', 100);
        );
    }

    var store = try Store.open(scratch.path);
    defer store.close();
    try t.expectEqual(@as(i64, migrate.latest_version), try migrate.userVersion(&store.db));

    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const server = (try Store.servers.getByName(&store, arena, "legacy")).?;
    try t.expectEqualStrings("10.0.0.1", server.host);

    const mems = try Store.memories.list(&store, arena, .{ .server_id = server.id }, .{});
    try t.expectEqual(@as(usize, 1), mems.len);
    try t.expectEqualStrings("nginx :80", mems[0].content);

    const hist = try Store.history.list(&store, arena, server.id, 10);
    try t.expectEqual(@as(usize, 1), hist.len);
    try t.expectEqualStrings("uname -a", hist[0].detail);

    try t.expectEqualStrings("/srv/app", (try Store.facts.get(&store, arena, server.id, "app_root")).?);
}

test "gate: a failing migration rolls back and does not bump the version" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_rollback");
    defer scratch.deinit();

    var db = try Db.open(scratch.path);
    defer db.close();
    try migrate.applyUpTo(&db, migrate.latest_version);
    const before = try migrate.userVersion(&db);

    // A statement that creates a table and *then* fails: if the wrapper were
    // not transactional, `gate_partial` would survive and the version could
    // advance.
    try t.expectError(error.Sqlite, migrate.applyRawForTest(
        &db,
        "CREATE TABLE gate_partial (x INTEGER); SELECT this_function_does_not_exist();",
        99,
    ));
    try t.expectEqual(before, try migrate.userVersion(&db));

    var stmt = try db.prepare(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='gate_partial'",
    );
    defer stmt.deinit();
    try t.expect(try stmt.step());
    try t.expectEqual(@as(i64, 0), stmt.columnInt(0));
}

const RaceCtx = struct {
    path: [:0]const u8,
    /// Spin barrier: without it thread-spawn overhead serializes the opens
    /// and the test passes without ever exercising the race.
    gate: *std.atomic.Value(bool),
    err: ?anyerror = null,
    version: i64 = 0,
};

fn openInThread(ctx: *RaceCtx) void {
    while (!ctx.gate.load(.acquire)) std.atomic.spinLoopHint();
    var store = Store.open(ctx.path) catch |err| {
        ctx.err = err;
        return;
    };
    defer store.close();
    ctx.version = migrate.userVersion(&store.db) catch |err| {
        ctx.err = err;
        return;
    };
}

test "gate: concurrent first opens all succeed" {
    const t = std.testing;
    const thread_count = 4;
    // Repeat: a migration race is timing-dependent, so one attempt proves
    // little. Each round starts from a genuinely empty database.
    for (0..8) |round| {
        var name_buf: [40]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "gate_race_open_{d}", .{round});
        var scratch = try Scratch.init(t.allocator, name);
        defer scratch.deinit();

        // Separate Store.open calls mean separate sqlite connections, which
        // is the same locking path two OS processes take. With the old
        // deferred BEGIN both would read user_version 0 and then both try to
        // apply v1, so the loser failed with "table keys already exists".
        var gate: std.atomic.Value(bool) = .init(false);
        var ctxs: [thread_count]RaceCtx = undefined;
        var threads: [thread_count]std.Thread = undefined;
        for (&ctxs, 0..) |*ctx, i| {
            ctx.* = .{ .path = scratch.path, .gate = &gate };
            threads[i] = try std.Thread.spawn(.{}, openInThread, .{ctx});
        }
        gate.store(true, .release);
        for (threads) |thread| thread.join();

        for (&ctxs, 0..) |*ctx, i| {
            if (ctx.err) |err| {
                std.debug.print("round {d} connection {d} failed: {s}\n", .{ round, i, @errorName(err) });
                return err;
            }
            try t.expectEqual(@as(i64, migrate.latest_version), ctx.version);
        }
    }
}

/// Creates one operation ready to be settled.
fn seedOperation(store: *Store, request_id: []const u8) !void {
    try store.db.exec(
        \\INSERT INTO servers (id, name, host, port, username, created_at, updated_at)
        \\VALUES (1, 'race', '10.0.0.1', 22, 'ubuntu', 100, 100);
    );
    try Store.operations.create(store, .{
        .request_id = request_id,
        .server_id = 1,
        .server_name = "race",
        .kind = .exec,
        .now = 100,
    });
    try Store.operations.advance(store, request_id, .connecting, 101);
    try Store.operations.advance(store, request_id, .submitted, 102);
}

const SettleCtx = struct {
    path: [:0]const u8,
    request_id: []const u8,
    outcome: ?Store.receipts.SettleOutcome = null,
    err: ?anyerror = null,
};

fn settleInThread(ctx: *SettleCtx) void {
    var store = Store.open(ctx.path) catch |err| {
        ctx.err = err;
        return;
    };
    defer store.close();
    ctx.outcome = Store.receipts.settle(
        &store,
        ctx.request_id,
        .{ .exited = .{ .exit_code = 0 } },
        .{ .request_id = ctx.request_id, .kind = .terminal, .observed_at = 200 },
        200,
    ) catch |err| {
        ctx.err = err;
        return;
    };
}

test "gate: a terminal receipt is recorded exactly once under contention" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_terminal_once");
    defer scratch.deinit();

    const request_id = "01ABCDEFGH0123456789ABCDEF";
    {
        var store = try Store.open(scratch.path);
        defer store.close();
        try seedOperation(&store, request_id);
    }

    var a: SettleCtx = .{ .path = scratch.path, .request_id = request_id };
    var b: SettleCtx = .{ .path = scratch.path, .request_id = request_id };
    const ta = try std.Thread.spawn(.{}, settleInThread, .{&a});
    const tb = try std.Thread.spawn(.{}, settleInThread, .{&b});
    ta.join();
    tb.join();

    try t.expectEqual(@as(?anyerror, null), a.err);
    try t.expectEqual(@as(?anyerror, null), b.err);

    // Exactly one writer recorded it; the other was handed the winner.
    var recorded: usize = 0;
    var already: usize = 0;
    for ([_]?Store.receipts.SettleOutcome{ a.outcome, b.outcome }) |maybe| {
        switch (maybe.?) {
            .recorded => recorded += 1,
            .already_settled => already += 1,
        }
    }
    try t.expectEqual(@as(usize, 1), recorded);
    try t.expectEqual(@as(usize, 1), already);

    // And the ledger holds a single terminal row.
    var store = try Store.open(scratch.path);
    defer store.close();
    var stmt = try store.db.prepare(
        "SELECT COUNT(*) FROM operation_events WHERE request_id = ?1 AND is_terminal = 1",
    );
    defer stmt.deinit();
    try stmt.bindText(1, request_id);
    try t.expect(try stmt.step());
    try t.expectEqual(@as(i64, 1), stmt.columnInt(0));
}

test "gate: transport loss after submission records indeterminate, never failed" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_indeterminate");
    defer scratch.deinit();

    var store = try Store.open(scratch.path);
    defer store.close();
    const request_id = "01ZZZZZZZZ0123456789ABCDEF";
    try seedOperation(&store, request_id);

    // The only decision point for a dropped connection.
    const terminal = op_state.terminalForTransportLoss(.submitted, "channel eof");
    const outcome = try Store.receipts.settle(
        &store,
        request_id,
        terminal,
        .{ .request_id = request_id, .kind = .terminal, .observed_at = 300 },
        300,
    );
    try t.expectEqual(op_state.Status.indeterminate, outcome.recorded.status);

    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const op = (try Store.operations.get(&store, arena, request_id)).?;
    try t.expectEqual(op_state.Status.indeterminate, op.status);
    // Unsettled work must block a same-scope mutation until reconciled.
    try t.expect(op.status.blocksScope());

    // Reconciliation proves the truth without erasing the observation.
    try Store.operations.recordResolution(&store, request_id, .completed, "found exit 0 in job log", 400);
    const after = (try Store.operations.get(&store, arena, request_id)).?;
    try t.expectEqual(op_state.Status.indeterminate, after.status); // preserved
    try t.expectEqual(op_state.Status.completed, after.effectiveStatus());
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
    _ = try Store.receipts.settle(
        &store,
        request_id,
        .{ .exited = .{ .exit_code = 3 } },
        .{ .request_id = request_id, .kind = .terminal, .observed_at = 210 },
        210,
    );
    try t.expectError(error.IllegalTransition, Store.operations.advance(&store, request_id, .completed, 220));
}

fn seedServer(store: *Store) !void {
    try store.db.exec(
        \\INSERT INTO servers (id, name, host, port, username, created_at, updated_at)
        \\VALUES (1, 'lease-host', '10.0.0.1', 22, 'ubuntu', 100, 100);
    );
}

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
        .owner_token = ctx.owner,
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

    const job_scope: Store.leases.Scope = .{ .kind = .job, .key = "deploy" };
    const base: Store.leases.AcquireOptions = .{
        .server_id = 1,
        .scope = job_scope,
        .owner_token = "owner-a",
        .ttl_secs = 100,
        .now = 1000,
    };

    // First acquisition.
    try t.expect((try Store.leases.acquire(&store, arena, base)).acquired.id > 0);

    // The same owner asking again renews instead of piling up rows.
    var again = base;
    again.now = 1050;
    try t.expect((try Store.leases.acquire(&store, arena, again)) == .renewed);

    // A peer is blocked, and learns who holds it.
    var peer = base;
    peer.owner_token = "owner-b";
    peer.now = 1060;
    const blocked = try Store.leases.acquire(&store, arena, peer);
    try t.expectEqualStrings("owner-a", blocked.conflict.owner_token);

    // A whole-server lease overlaps the job scope, so it is blocked too.
    var server_scope = peer;
    server_scope.scope = .{ .kind = .server };
    try t.expect((try Store.leases.acquire(&store, arena, server_scope)) == .conflict);

    // Past the TTL the lease lapses and the peer may take it (lazy expiry).
    peer.now = 5000;
    try t.expect((try Store.leases.acquire(&store, arena, peer)) == .acquired);

    // Losing a lease must be visible: the old owner's renew fails rather
    // than silently reviving it underneath the new holder.
    try t.expect(!try Store.leases.renew(&store, 1, job_scope, "owner-a", 100, 5010));

    // Takeover leaves an audit chain rather than overwriting.
    var thief = base;
    thief.owner_token = "owner-c";
    thief.now = 5020;
    const taken = try Store.leases.takeover(&store, arena, thief);
    try t.expectEqualStrings("owner-b", taken.taken.from.owner_token);

    var stmt = try store.db.prepare(
        \\SELECT release_reason, superseded_by FROM leases
        \\ WHERE id = ?1
    );
    defer stmt.deinit();
    try stmt.bindInt(1, taken.taken.from.id);
    try t.expect(try stmt.step());
    try t.expectEqualStrings("takeover", stmt.columnText(0));
    try t.expectEqual(taken.taken.lease.id, stmt.columnInt(1));

    // The guard used by write operations sees the conflict for others only.
    try t.expect((try Store.leases.conflictFor(&store, arena, 1, job_scope, "owner-a", 5030)) != null);
    try t.expect((try Store.leases.conflictFor(&store, arena, 1, job_scope, "owner-c", 5030)) == null);
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

test "gate: owner token is stable across store reopens" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_owner_token");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var first_token: []const u8 = undefined;
    {
        var store = try Store.open(scratch.path);
        defer store.close();
        first_token = try Store.policy.ownerToken(&store, arena, scratch.io, 100);
        try Store.ids.validate(first_token);
    }
    // A lease is worthless if the owner identity changes every process: the
    // holder could never renew or release its own lease.
    var store = try Store.open(scratch.path);
    defer store.close();
    const second = try Store.policy.ownerToken(&store, arena, scratch.io, 200);
    try t.expectEqualStrings(first_token, second);
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

    // Nothing known yet.
    try t.expect((try Store.host_pins.verify(&store, arena, "h", 22, "ssh-ed25519", "SHA256:aaa")) == .unknown);

    _ = try Store.host_pins.record(&store, .{
        .host = "h",
        .port = 22,
        .key_type = "ssh-ed25519",
        .fingerprint_sha256 = "SHA256:aaa",
        .trust_source = .first_use,
        .now = 100,
    });
    try t.expect((try Store.host_pins.verify(&store, arena, "h", 22, "ssh-ed25519", "SHA256:aaa")) == .match);

    // A different key must surface as a mismatch the caller has to act on.
    const verdict = try Store.host_pins.verify(&store, arena, "h", 22, "ssh-ed25519", "SHA256:bbb");
    try t.expectEqualStrings("SHA256:aaa", verdict.mismatch.expected.fingerprint_sha256);

    // Verifying must not have quietly adopted the new key.
    try t.expect((try Store.host_pins.verify(&store, arena, "h", 22, "ssh-ed25519", "SHA256:aaa")) == .match);

    // Rotation is deliberate, keeps the old row, and links the two.
    _ = try Store.host_pins.rotate(&store, .{
        .host = "h",
        .port = 22,
        .key_type = "ssh-ed25519",
        .fingerprint_sha256 = "SHA256:bbb",
        .trust_source = .rotated,
        .now = 200,
    }, "server rebuilt");
    try t.expect((try Store.host_pins.verify(&store, arena, "h", 22, "ssh-ed25519", "SHA256:bbb")) == .match);
    try t.expectEqual(@as(usize, 1), (try Store.host_pins.list(&store, arena)).len);
}
