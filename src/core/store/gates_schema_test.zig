//! The store's own shape: how it is created, how it is opened, and the lists
//! that have to agree with it.
//!
//! * **Migration.** A fresh database reaches the latest version; every
//!   historical version upgrades in order and keeps its data; reopening is
//!   idempotent; a failing migration rolls back completely, leaving no partial
//!   schema and no version bump; two connections racing the same first open
//!   both succeed.
//! * **Refusal.** A database that is not ours, one written by a newer binary,
//!   and a pre-release schema are each detected and named rather than written
//!   into. The drift probe reads the shape sqlite actually stored, not just the
//!   column names, because a CHECK or an index can go missing without a column
//!   doing so.
//! * **Agreement.** Four gates exist only to stop a Zig list and a SQL list
//!   drifting apart: the statuses Zig calls scope-blocking against what the
//!   barrier query returns, the states Zig calls destination-holding against
//!   what the index covers, the statuses Zig knows against what the schema
//!   admits, and the tables Zig declares the `servers` DELETE destroys against
//!   what the foreign keys actually cascade. Each of those pairs is written out
//!   twice on purpose, and each stops being a gate the moment somebody derives
//!   one side from the other.
//! * **Transaction discipline.** Every `…Locked` writer refuses to run outside a
//!   transaction, which is what makes `fixtures.locked` an honest stand-in for
//!   the caller that would normally hold one, rather than a way around the
//!   guard.

const std = @import("std");
const Store = @import("Store.zig");
const Db = @import("Db.zig");
const migrate = @import("migrate.zig");
const ids = @import("ids.zig");
const op_state = @import("op_state.zig");

// The shared fixtures. Aliased under their own names so a gate reads the
// same here as it did when every gate was in one file.
const fixtures = @import("gates_fixtures.zig");
const Scratch = fixtures.Scratch;
const locked = fixtures.locked;
const testId = fixtures.testId;
const recordLaunchSentinel = fixtures.recordLaunchSentinel;
const seedServer = fixtures.seedServer;

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

test "gate: the statuses Zig calls scope-blocking are the ones the barrier query returns" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_blocks_scope_agreement");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    try store.db.exec(
        \\INSERT INTO servers (id, name, host, port, username, created_at, updated_at)
        \\VALUES (1, 'race', '10.0.0.1', 22, 'ubuntu', 100, 100);
    );

    // `unsettled()` is the scope barrier, and until now its status list was
    // typed out in SQL beside a Zig predicate that said the same thing. Nothing
    // compared them, which is the arrangement that already went wrong once for
    // the checkpoint states: the predicate gains a member, the string does not,
    // and a status that is supposed to block a same-scope mutation blocks
    // nothing. Every status is walked here, driven through the real writers, so
    // the two definitions cannot part company without this failing.
    inline for (@typeInfo(op_state.Status).@"enum".fields) |field| {
        const status: op_state.Status = @enumFromInt(field.value);
        const rid = testId("bs" ++ field.name);
        const request_id: []const u8 = &rid;
        try Store.operations.create(&store, .{
            .request_id = request_id,
            .server_id = 1,
            .server_name = "race",
            .kind = .exec,
            .now = 100,
        });
        // Reached the way production reaches it: `advance` for the live half,
        // and evidence through `settle` for the terminals. A fixture writing
        // the column directly would prove the query matches a string this test
        // chose, which is the thing being checked.
        switch (status) {
            .created => {},
            .connecting => try Store.operations.advance(&store, request_id, .connecting, 101),
            .submitted, .remote_started, .completed, .failed, .timed_out, .indeterminate => {
                try Store.operations.advance(&store, request_id, .connecting, 101);
                try Store.operations.advance(&store, request_id, .submitted, 102);
                switch (status) {
                    .remote_started => try Store.operations.advance(&store, request_id, .remote_started, 103),
                    .completed => _ = try Store.receipts.settle(&store, request_id, .{ .exited = .{ .exit_code = 0 } }, .{}, 104),
                    .failed => _ = try Store.receipts.settle(&store, request_id, .{ .exited = .{ .exit_code = 1 } }, .{}, 104),
                    .timed_out => _ = try Store.receipts.settle(&store, request_id, .{ .remote_deadline = .{ .after_ms = 10 } }, .{}, 104),
                    .indeterminate => _ = try Store.receipts.settle(&store, request_id, .{ .indeterminate = .{
                        .reason = "the connection dropped",
                        .last_observed = .submitted,
                    } }, .{}, 104),
                    else => {},
                }
            },
            // Abandoning is only credible before anything is handed over.
            .cancelled => _ = try Store.receipts.settle(
                &store,
                request_id,
                .{ .local_abandon = .{ .reason = "never started" } },
                .{},
                104,
            ),
        }

        try t.expectEqual(status, (try Store.operations.get(&store, arena, request_id)).?.status);
        var listed = false;
        for (try Store.operations.unsettled(&store, arena, 1)) |op| {
            if (std.mem.eql(u8, op.request_id, request_id)) listed = true;
        }
        try t.expectEqual(status.blocksScope(), listed);
    }

    // And the one status whose block a resolution can lift, which is why the
    // rendered list carries a subtraction rather than being used raw. The
    // observation stays `indeterminate` — `blocksScope()` still says true of it
    // — and the barrier drops anyway, because `resolved_status` is filled.
    const resolved_rid = testId("bsresolved");
    const resolved_id: []const u8 = &resolved_rid;
    try Store.operations.create(&store, .{
        .request_id = resolved_id,
        .server_id = 1,
        .server_name = "race",
        // A job, because the sentinel below is a job's evidence and nothing
        // else may be settled by one.
        .kind = .job,
        .now = 100,
    });
    try Store.operations.advance(&store, resolved_id, .connecting, 101);
    try Store.operations.advance(&store, resolved_id, .submitted, 102);
    try recordLaunchSentinel(&store, resolved_id, "race", "bsresolved", "__TERMINUS_JOB_1__", 100);
    _ = try Store.receipts.settle(
        &store,
        resolved_id,
        op_state.terminalForTransportLoss(.submitted, "eof"),
        .{},
        200,
    );
    try t.expect((try Store.receipts.resolve(&store, arena, resolved_id, .completed, .{
        .job_sentinel = .{ .sentinel = "__TERMINUS_JOB_1__", .exit_code = 0 },
    }, 210)) == .resolved);
    const resolved_op = (try Store.operations.get(&store, arena, resolved_id)).?;
    try t.expectEqual(op_state.Status.indeterminate, resolved_op.status);
    try t.expect(resolved_op.status.blocksScope());
    for (try Store.operations.unsettled(&store, arena, 1)) |op| {
        try t.expect(!std.mem.eql(u8, op.request_id, resolved_id));
    }
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

test "gate: a pre-release schema is detected instead of failing obscurely" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_drift");
    defer scratch.deinit();

    // Reproduce what the parent commit produced: v5+ reported, but the
    // evidence columns added afterwards are missing.
    {
        var db = try Db.open(scratch.path);
        defer db.close();
        try migrate.applyUpTo(&db, 4);
        try db.exec(
            \\CREATE TABLE operations (request_id TEXT PRIMARY KEY, status TEXT NOT NULL);
            \\CREATE TABLE operation_events (
            \\  id INTEGER PRIMARY KEY, request_id TEXT NOT NULL, seq INTEGER NOT NULL,
            \\  is_terminal INTEGER NOT NULL DEFAULT 0, observed_at INTEGER NOT NULL,
            \\  source TEXT NOT NULL
            \\);
            \\PRAGMA user_version = 8;
        );
    }
    try t.expectError(error.PreReleaseSchemaDrift, Store.open(scratch.path));
}

test "gate: pre-release drift is detected in the schema's shape, not just its columns" {
    const t = std.testing;

    // v11 has been amended three times since the first v11 databases existed,
    // and no amendment shows up in `pragma_table_info`. A store carrying an
    // earlier revision reports user_version 11 and has every column, so only
    // the DDL text can tell it apart.

    // (a) the destination-holding index, still on the narrow live-state
    //     predicate. A checkpoint that reached `verifying` would not be in the
    //     index, so a second transfer could claim the same path underneath it.
    {
        var scratch = try Scratch.init(t.allocator, "gate_drift_index");
        defer scratch.deinit();
        {
            var db = try Db.open(scratch.path);
            defer db.close();
            try migrate.applyUpTo(&db, migrate.latest_version);
            try db.exec(
                \\DROP INDEX idx_checkpoints_live_dest;
                \\CREATE UNIQUE INDEX idx_checkpoints_live_dest
                \\  ON transfer_checkpoints(dest_side, dest_path)
                \\  WHERE state IN ('planned','probing','transferring','paused');
            );
        }
        var refusal: migrate.Refusal = undefined;
        try t.expectError(
            error.PreReleaseSchemaDrift,
            Store.openDiagnosed(scratch.path, &refusal),
        );
        // Which object, not merely that something did not match. Three are
        // inspected at v11 and they fail for different reasons; a refusal that
        // cannot say which sends an operator to read all three.
        try t.expectEqualStrings(
            "idx_checkpoints_live_dest",
            refusal.pre_release_drift.probe,
        );
    }

    // (a2) The shape that opened the gate this rebuild exists for. The probe
    //      used to be three `LIKE '%needle%'` searches — `verifying`,
    //      `failed_hash_mismatch`, and the constraint's *name* — and this
    //      predicate satisfies all three while missing `paused`,
    //      `failed_no_space`, `failed_clobber_conflict` and `failed_publish`.
    //      On such a store a checkpoint parked in `paused` is not in the unique
    //      index at all, and the unique index is the only collision guard a
    //      locally-published transfer gets: a second `create` aimed at the same
    //      destination succeeds, and two drivers own one partial and one path.
    //      A needle can say a word is present; it can never say a list has not
    //      lost four of its members, which is what drift actually looks like.
    {
        var scratch = try Scratch.init(t.allocator, "gate_drift_index_v2");
        defer scratch.deinit();
        {
            var db = try Db.open(scratch.path);
            defer db.close();
            try migrate.applyUpTo(&db, migrate.latest_version);
            try db.exec(
                \\DROP INDEX idx_checkpoints_live_dest;
                \\CREATE UNIQUE INDEX idx_checkpoints_live_dest
                \\  ON transfer_checkpoints(dest_side, dest_path)
                \\  WHERE state IN ('planned','probing','transferring','verifying','publishing',
                \\                  'failed_source_changed','failed_remote_partial_mismatch',
                \\                  'failed_hash_mismatch','indeterminate_publish');
            );
        }
        var refusal: migrate.Refusal = undefined;
        try t.expectError(
            error.PreReleaseSchemaDrift,
            Store.openDiagnosed(scratch.path, &refusal),
        );
        try t.expectEqualStrings(
            "idx_checkpoints_live_dest",
            refusal.pre_release_drift.probe,
        );
    }

    // (b) a `transfer_checkpoints` without the named CHECK. The index is
    //     recreated with the *current* predicate on purpose: otherwise (a)
    //     would be what fails, and this case would pass without the table
    //     comparison existing at all. Generated from `holds_destination_sql` so
    //     that "current" stays true when the predicate next changes — a literal
    //     here would quietly go stale and hand this case back to probe (a).
    {
        var scratch = try Scratch.init(t.allocator, "gate_drift_check");
        defer scratch.deinit();
        {
            var db = try Db.open(scratch.path);
            defer db.close();
            try migrate.applyUpTo(&db, migrate.latest_version);
            try db.exec(std.fmt.comptimePrint(
                \\DROP TABLE transfer_checkpoints;
                \\CREATE TABLE transfer_checkpoints (
                \\  id               INTEGER PRIMARY KEY,
                \\  request_id       TEXT NOT NULL UNIQUE,
                \\  dest_side        TEXT NOT NULL,
                \\  dest_path        TEXT NOT NULL,
                \\  source_kind      TEXT NOT NULL,
                \\  source_sha256    TEXT,
                \\  confirmed_offset INTEGER NOT NULL DEFAULT 0,
                \\  state            TEXT NOT NULL
                \\);
                \\CREATE UNIQUE INDEX idx_checkpoints_live_dest
                \\  ON transfer_checkpoints(dest_side, dest_path)
                \\  WHERE state IN ({s});
            , .{Store.transfers.holds_destination_sql}));
        }
        var refusal: migrate.Refusal = undefined;
        try t.expectError(
            error.PreReleaseSchemaDrift,
            Store.openDiagnosed(scratch.path, &refusal),
        );
        try t.expectEqualStrings("transfer_checkpoints", refusal.pre_release_drift.probe);
    }

    // (b2) The constraint probe's own blind spot, which was the other half of
    //      the same lesson: the needle matched the CHECK's *name* while the
    //      property lives in its body. This table is the real v11 text with one
    //      conjunct of `offset_needs_source_identity` replaced — the name is
    //      still there, the column list is identical, and the constraint no
    //      longer requires a source digest for a non-zero offset. A row with
    //      bytes already sent and no way to re-identify their source is exactly
    //      what it exists to make impossible, and on this store it inserts.
    {
        var scratch = try Scratch.init(t.allocator, "gate_drift_check_body");
        defer scratch.deinit();
        {
            var db = try Db.open(scratch.path);
            defer db.close();
            try migrate.applyUpTo(&db, migrate.latest_version);
            var weakened: std.ArrayList(u8) = .empty;
            defer weakened.deinit(t.allocator);
            try weakened.appendSlice(t.allocator, "DROP TABLE transfer_checkpoints;\n");
            const want = "AND source_sha256 IS NOT NULL)";
            const cut = std.mem.indexOf(u8, migrate.checkpoints_table_ddl, want).?;
            try weakened.appendSlice(t.allocator, migrate.checkpoints_table_ddl[0..cut]);
            try weakened.appendSlice(t.allocator, "AND source_path IS NOT NULL)");
            try weakened.appendSlice(t.allocator, migrate.checkpoints_table_ddl[cut + want.len ..]);
            try weakened.appendSlice(t.allocator, ";\n");
            try weakened.appendSlice(t.allocator, migrate.checkpoints_index_ddl);
            try weakened.append(t.allocator, ';');
            const sql = try t.allocator.dupeZ(u8, weakened.items);
            defer t.allocator.free(sql);
            try db.exec(sql);
        }
        var refusal: migrate.Refusal = undefined;
        try t.expectError(
            error.PreReleaseSchemaDrift,
            Store.openDiagnosed(scratch.path, &refusal),
        );
        try t.expectEqualStrings("transfer_checkpoints", refusal.pre_release_drift.probe);
    }

    // (b3) The same lesson at v12, where the property is one clause wide. This
    //      store is at the current version and has a `leases` table that looks
    //      right — same name, same scope columns, an owner column — but the
    //      owner is `owner_token`, the machine-wide token v12 exists to stop
    //      deciding conflicts by. `user_version` cannot express a change
    //      *within* a version, and a column-name probe would not notice the swap
    //      either, so the stored text is again the only witness. A store like
    //      this decides every conflict the pre-v12 way while reporting itself as
    //      fixed.
    {
        var scratch = try Scratch.init(t.allocator, "gate_drift_lease_owner");
        defer scratch.deinit();
        {
            var db = try Db.open(scratch.path);
            defer db.close();
            try migrate.applyUpTo(&db, migrate.latest_version);
            try db.exec(
                \\DROP TABLE leases;
                \\CREATE TABLE leases (
                \\  id            INTEGER PRIMARY KEY,
                \\  server_id     INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
                \\  scope_kind    TEXT NOT NULL,
                \\  scope_key     TEXT NOT NULL,
                \\  owner_token   TEXT NOT NULL,
                \\  acquired_at   INTEGER NOT NULL,
                \\  renewed_at    INTEGER NOT NULL,
                \\  expires_at    INTEGER NOT NULL,
                \\  released_at   INTEGER
                \\);
                \\CREATE UNIQUE INDEX idx_leases_active
                \\  ON leases(server_id, scope_kind, scope_key) WHERE released_at IS NULL;
                \\CREATE INDEX idx_leases_owner ON leases(owner_token) WHERE released_at IS NULL;
            );
        }
        var refusal: migrate.Refusal = undefined;
        try t.expectError(
            error.PreReleaseSchemaDrift,
            Store.openDiagnosed(scratch.path, &refusal),
        );
        try t.expectEqualStrings("leases", refusal.pre_release_drift.probe);
    }

    // And the shape this binary actually writes satisfies every probe, so the
    // cases above are detecting drift rather than rejecting everything. This is
    // also what makes the comparison legitimate at all: it asserts that the
    // frozen text `frozenStatement` slices out is byte-for-byte what sqlite
    // stores when that same text is executed, which is the property the whole
    // probe rests on and would silently fail if a statement ever carried an
    // embedded `;` and got truncated.
    //
    // The probes are run again *directly*, against the freshly migrated file,
    // and that second call is not redundant. `Store.open` checks before it
    // applies, so on a brand new database the probes see version 0 and return
    // without looking at anything — opening cleanly proves nothing about the
    // shape `apply` went on to write.
    {
        var scratch = try Scratch.init(t.allocator, "gate_drift_current");
        defer scratch.deinit();
        var store = try Store.open(scratch.path);
        defer store.close();
        try t.expectEqual(@as(i64, migrate.latest_version), try migrate.userVersion(&store.db));
        try migrate.checkPreReleaseDrift(&store.db, null);

        // Said again as an equality, because `checkPreReleaseDrift` passing
        // could in principle mean the extraction and the storage are wrong in
        // the same direction. These read sqlite's copy directly.
        for ([_]struct { name: [:0]const u8, want: []const u8 }{
            .{ .name = "transfer_checkpoints", .want = migrate.checkpoints_table_ddl },
            .{ .name = "idx_checkpoints_live_dest", .want = migrate.checkpoints_index_ddl },
            .{ .name = "leases", .want = migrate.leases_table_ddl },
            .{ .name = "idx_leases_active", .want = migrate.leases_active_index_ddl },
            .{ .name = "idx_leases_owner", .want = migrate.leases_owner_index_ddl },
        }) |object| {
            var stmt = try store.db.prepare("SELECT sql FROM sqlite_master WHERE name = ?1");
            defer stmt.deinit();
            try stmt.bindText(1, object.name);
            try t.expect(try stmt.step());
            try t.expectEqualStrings(object.want, stmt.columnText(0));
        }
    }
}

test "gate: a database that is not ours is refused before a table is written into it" {
    const t = std.testing;

    // `user_version` defaults to 0, which is what essentially every SQLite file
    // in the world reports, and the gate had an upper bound on it and no lower
    // one. So `--db ~/some-other-app.db` ran the whole ladder into a stranger's
    // database — nineteen tables grafted in and its `user_version` overwritten
    // with 11, destroying the schema version of any application that uses that
    // field the idiomatic way.
    {
        var scratch = try Scratch.init(t.allocator, "gate_foreign_v0");
        defer scratch.deinit();
        {
            var db = try Db.open(scratch.path);
            defer db.close();
            try db.exec(
                \\CREATE TABLE their_widgets (id INTEGER PRIMARY KEY, name TEXT);
                \\INSERT INTO their_widgets (name) VALUES ('theirs');
            );
        }
        var refusal: migrate.Refusal = undefined;
        try t.expectError(
            error.NotATerminusStore,
            Store.openDiagnosed(scratch.path, &refusal),
        );
        try t.expectEqual(@as(i64, 0), refusal.foreign_database.version);

        // Nothing was written, and that is the whole point of refusing before
        // `apply`: their table is intact, their `user_version` is untouched,
        // and no table of ours exists. The journal mode is checked too — it
        // used to be switched to WAL inside `Db.open`, before the gate had
        // looked at the file at all, so the code refusing the database had
        // already rewritten its header and left `-wal`/`-shm` beside it.
        var db = try Db.open(scratch.path);
        defer db.close();
        try t.expectEqual(@as(i64, 0), try migrate.userVersion(&db));
        {
            var stmt = try db.prepare(
                "SELECT COUNT(*) FROM sqlite_master WHERE name IN ('keys','operations')",
            );
            defer stmt.deinit();
            try t.expect(try stmt.step());
            try t.expectEqual(@as(i64, 0), stmt.columnInt(0));
        }
        {
            var stmt = try db.prepare("SELECT COUNT(*) FROM their_widgets");
            defer stmt.deinit();
            try t.expect(try stmt.step());
            try t.expectEqual(@as(i64, 1), stmt.columnInt(0));
        }
        {
            var stmt = try db.prepare("PRAGMA journal_mode");
            defer stmt.deinit();
            try t.expect(try stmt.step());
            try t.expect(!std.ascii.eqlIgnoreCase(stmt.columnText(0), "wal"));
        }
    }

    // The quieter half: a foreign file that *does* use `user_version` for its
    // own migrations. At 4, `applyOne` skips v1–v4 — so the `CREATE TABLE keys`
    // collision that would have refused never happens — and v5 through v8 apply
    // cleanly, writing twelve tables, before v9's `ALTER TABLE jobs` fails and
    // the caller is told only "cannot open database". The file is left at
    // version 8 with our tables grafted in and nothing says so.
    {
        var scratch = try Scratch.init(t.allocator, "gate_foreign_v4");
        defer scratch.deinit();
        {
            var db = try Db.open(scratch.path);
            defer db.close();
            try db.exec(
                \\CREATE TABLE their_widgets (id INTEGER PRIMARY KEY);
                \\PRAGMA user_version = 4;
            );
        }
        var refusal: migrate.Refusal = undefined;
        try t.expectError(
            error.NotATerminusStore,
            Store.openDiagnosed(scratch.path, &refusal),
        );
        try t.expectEqual(@as(i64, 4), refusal.foreign_database.version);

        var db = try Db.open(scratch.path);
        defer db.close();
        try t.expectEqual(@as(i64, 4), try migrate.userVersion(&db));
        var stmt = try db.prepare(
            "SELECT COUNT(*) FROM sqlite_master WHERE name NOT LIKE 'their\\_%' ESCAPE '\\'",
        );
        defer stmt.deinit();
        try t.expect(try stmt.step());
        try t.expectEqual(@as(i64, 0), stmt.columnInt(0));
    }

    // And ours still opens: an empty file at version 0 is exactly what a brand
    // new store looks like, so the check has to admit it. Without this the two
    // cases above would pass on a gate that refused everything.
    {
        var scratch = try Scratch.init(t.allocator, "gate_foreign_ours");
        defer scratch.deinit();
        var store = try Store.open(scratch.path);
        defer store.close();
        try t.expectEqual(@as(i64, migrate.latest_version), try migrate.userVersion(&store.db));
    }
}

test "gate: checkpoint rows are never destroyed by the migration that recreates them" {
    const t = std.testing;

    // (a) A v10 store holding a real checkpoint row. v11 drops and recreates
    //     that table, so until the order was inverted `apply` destroyed the row
    //     and the check that exists to stop exactly that ran on the wreckage.
    //     The census behind v11 established that no such row exists outside
    //     test scratch — but a census recorded in a document is not a guard,
    //     and the code must not read a row it finds as disposable.
    {
        var scratch = try Scratch.init(t.allocator, "gate_preapply_rows");
        defer scratch.deinit();
        {
            var db = try Db.open(scratch.path);
            defer db.close();
            try migrate.applyUpTo(&db, 10);
            try db.exec(
                \\INSERT INTO operations
                \\  (request_id, schema_version, server_name, kind, status, created_at, updated_at)
                \\VALUES ('01LEGACYREQUEST0000000000', 1, 'legacy', 'transfer_push', 'created', 100, 100);
                \\INSERT INTO transfer_checkpoints
                \\  (request_id, schema_version, direction, remote_path, remote_partial_path,
                \\   chunk_size, confirmed_offset, state, created_at, updated_at)
                \\VALUES ('01LEGACYREQUEST0000000000', 1, 'push', '/srv/app/out.bin',
                \\        '/srv/app/out.bin.terminus-part', 1048576, 4096, 'paused', 100, 100);
            );
        }

        var refusal: migrate.Refusal = undefined;
        try t.expectError(
            error.CheckpointsWouldBeDropped,
            Store.openDiagnosed(scratch.path, &refusal),
        );
        // The numbers an operator would act on. Nothing prints them yet; the
        // point of carrying them is that the refusal is not reduced to "no".
        try t.expectEqual(@as(i64, 1), refusal.checkpoints_would_be_dropped.rows);
        try t.expectEqual(@as(i64, 10), refusal.checkpoints_would_be_dropped.version);

        // And the refusal is the whole action: the row is still there and the
        // version has not moved, which is what "before it writes" means.
        var db = try Db.open(scratch.path);
        defer db.close();
        try t.expectEqual(@as(i64, 10), try migrate.userVersion(&db));
        var count = try db.prepare("SELECT COUNT(*) FROM transfer_checkpoints");
        defer count.deinit();
        try t.expect(try count.step());
        try t.expectEqual(@as(i64, 1), count.columnInt(0));
    }

    // (b) The same v10 store with an empty `transfer_checkpoints` migrates as
    //     it always did. The gate refuses rows, not the table — without this
    //     the case above would pass on a gate that simply never opened a v10
    //     store at all.
    {
        var scratch = try Scratch.init(t.allocator, "gate_preapply_empty");
        defer scratch.deinit();
        {
            var db = try Db.open(scratch.path);
            defer db.close();
            try migrate.applyUpTo(&db, 10);
        }
        var store = try Store.open(scratch.path);
        defer store.close();
        try t.expectEqual(@as(i64, migrate.latest_version), try migrate.userVersion(&store.db));
    }
}

test "gate: a live pre-v12 lease stops the open rather than being voided" {
    const t = std.testing;

    // v12 recuts `leases` around `owner_request_id`. A v11 row's `owner_token`
    // is a machine profile, not a request id, and reading one as the other
    // would hand the row an owner that never existed — so no row can be
    // carried. Released rows are history and go with the table. A row nobody
    // has released is different in kind: it is somebody's claim on a scope
    // right now, and dropping it silently un-blocks whatever it was holding,
    // which is the one thing this table exists to prevent.
    {
        var scratch = try Scratch.init(t.allocator, "gate_preapply_live_lease");
        defer scratch.deinit();
        {
            var db = try Db.open(scratch.path);
            defer db.close();
            try migrate.applyUpTo(&db, 11);
            try db.exec(
                \\INSERT INTO servers (id, name, host, port, username, created_at, updated_at)
                \\VALUES (1, 'legacy', '10.0.0.1', 22, 'ubuntu', 100, 100);
                \\INSERT INTO leases
                \\  (server_id, scope_kind, scope_key, owner_token, acquired_at, renewed_at, expires_at)
                \\VALUES (1, 'job', 'deploy', '01MACHINEPROFILE000000000', 100, 100, 100000);
            );
        }

        var refusal: migrate.Refusal = undefined;
        try t.expectError(
            error.LiveLeasesCannotBeReowned,
            Store.openDiagnosed(scratch.path, &refusal),
        );
        try t.expectEqual(@as(i64, 1), refusal.live_leases_cannot_be_reowned.rows);
        try t.expectEqual(@as(i64, 11), refusal.live_leases_cannot_be_reowned.version);

        // Refusing is the whole action: the row is untouched and the version has
        // not moved, so the operator can still release it with the binary that
        // took it.
        var db = try Db.open(scratch.path);
        defer db.close();
        try t.expectEqual(@as(i64, 11), try migrate.userVersion(&db));
        var count = try db.prepare("SELECT COUNT(*) FROM leases WHERE owner_token IS NOT NULL");
        defer count.deinit();
        try t.expect(try count.step());
        try t.expectEqual(@as(i64, 1), count.columnInt(0));
    }

    // Released rows are not a barrier — otherwise every store that ever took a
    // lease would be unopenable forever, since expiry in this schema is lazy
    // and needs the store open to run. This half is also what stops the case
    // above passing on a gate that simply refuses any v11 store with a `leases`
    // table.
    {
        var scratch = try Scratch.init(t.allocator, "gate_preapply_dead_lease");
        defer scratch.deinit();
        {
            var db = try Db.open(scratch.path);
            defer db.close();
            try migrate.applyUpTo(&db, 11);
            try db.exec(
                \\INSERT INTO servers (id, name, host, port, username, created_at, updated_at)
                \\VALUES (1, 'legacy', '10.0.0.1', 22, 'ubuntu', 100, 100);
                \\INSERT INTO leases
                \\  (server_id, scope_kind, scope_key, owner_token, acquired_at, renewed_at,
                \\   expires_at, released_at, release_reason)
                \\VALUES (1, 'job', 'deploy', '01MACHINEPROFILE000000000', 100, 100, 200, 300, 'expired');
            );
        }
        var store = try Store.open(scratch.path);
        defer store.close();
        try t.expectEqual(@as(i64, migrate.latest_version), try migrate.userVersion(&store.db));

        // The table was recut, and the history went with it: `owner_token` is
        // gone and `owner_request_id` is what a lease is keyed on now. Said as
        // an emptiness rather than left implicit, because the alternative — a
        // carried row with an invented owner — is the failure this whole
        // version exists to avoid.
        var count = try store.db.prepare("SELECT COUNT(*) FROM leases");
        defer count.deinit();
        try t.expect(try count.step());
        try t.expectEqual(@as(i64, 0), count.columnInt(0));

        // And the new shape refuses an owner that names nobody, at the schema
        // level, where no caller can talk it round.
        try t.expectError(error.Constraint, store.db.exec(
            \\INSERT INTO leases
            \\  (server_id, scope_kind, scope_key, owner_request_id, profile_token,
            \\   acquired_at, renewed_at, expires_at)
            \\VALUES (1, 'job', 'deploy', '', 'machine', 100, 100, 200);
        ));
    }
}

test "gate: a database from a newer binary is refused, not opened" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_preapply_future");
    defer scratch.deinit();

    // Every statement in this program is written against a schema it knows, and
    // `apply`'s fast path returns immediately at a version above its own — so an
    // old binary used to open such a file in silence and then write through
    // columns, constraints and indexes it has never heard of.
    {
        var store = try Store.open(scratch.path);
        defer store.close();
        try store.db.exec(std.fmt.comptimePrint(
            "PRAGMA user_version = {d}",
            .{migrate.latest_version + 1},
        ));
    }

    var refusal: migrate.Refusal = undefined;
    try t.expectError(
        error.SchemaNewerThanBinary,
        Store.openDiagnosed(scratch.path, &refusal),
    );
    try t.expectEqual(@as(i64, migrate.latest_version + 1), refusal.future_version.found);
    try t.expectEqual(@as(i64, migrate.latest_version), refusal.future_version.known);

    // The version is read before any table is, because what shape a table has
    // is a function of the version: a probe of `transfer_checkpoints` on a file
    // from the future reads columns whose meaning it cannot vouch for. This
    // database's tables would satisfy every later probe, so the refusal above
    // can only have come from the version check, and only if it ran first.
    var db = try Db.open(scratch.path);
    defer db.close();
    try t.expectEqual(@as(i64, migrate.latest_version + 1), try migrate.userVersion(&db));
}

test "gate: the states Zig calls destination-holding are the ones the index covers" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_holds_dest_agreement");
    defer scratch.deinit();

    var store = try Store.open(scratch.path);
    defer store.close();

    // The drift this exists for already happened once: the index predicate
    // gained `verifying`, `publishing` and `indeterminate_publish` while five
    // hand-copied SQL literals in `transfers.zig` kept the old four, so a row
    // that reached `verifying` could never leave it and held its destination
    // for good. `transfers` now renders every one of those lists from
    // `State.holdsDestination` at comptime, which fixes the five — this fixes
    // the sixth copy, the one that lives in the schema and cannot be generated
    // from Zig because migrations are frozen text.
    var stmt = try store.db.prepare(
        "SELECT sql FROM sqlite_master WHERE name = 'idx_checkpoints_live_dest'",
    );
    defer stmt.deinit();
    try t.expect(try stmt.step());
    const ddl = stmt.columnText(0);

    const opened = std.mem.indexOf(u8, ddl, "state IN (").? + "state IN (".len;
    const closed = opened + std.mem.indexOfScalar(u8, ddl[opened..], ')').?;

    // The DDL wraps its list across lines to stay readable; the generated one
    // is a single line. Whitespace is the only difference allowed.
    var tight: std.ArrayList(u8) = .empty;
    defer tight.deinit(t.allocator);
    for (ddl[opened..closed]) |ch| {
        if (!std.ascii.isWhitespace(ch)) try tight.append(t.allocator, ch);
    }
    try t.expectEqualStrings(Store.transfers.holds_destination_sql, tight.items);
}

/// The `IN (...)` list a schema object constrains a column to, whitespace
/// removed.
///
/// The DDL wraps its lists across lines to stay readable and the generated ones
/// are single lines, so whitespace is the only difference allowed.
fn schemaInList(
    allocator: std.mem.Allocator,
    store: *Store,
    object: [:0]const u8,
    after: []const u8,
) ![]u8 {
    var stmt = try store.db.prepare("SELECT sql FROM sqlite_master WHERE name = ?1");
    defer stmt.deinit();
    try stmt.bindText(1, object);
    if (!try stmt.step()) return error.NoSuchSchemaObject;
    const ddl = stmt.columnText(0);

    const opened = (std.mem.indexOf(u8, ddl, after) orelse return error.NoSuchClause) + after.len;
    const closed = opened + (std.mem.indexOfScalar(u8, ddl[opened..], ')') orelse
        return error.UnterminatedClause);

    var tight: std.ArrayList(u8) = .empty;
    errdefer tight.deinit(allocator);
    for (ddl[opened..closed]) |ch| {
        if (!std.ascii.isWhitespace(ch)) try tight.append(allocator, ch);
    }
    return tight.toOwnedSlice(allocator);
}

test "gate: the statuses Zig knows are the ones the schema admits and the barrier indexes" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_status_vocab_agreement");
    defer scratch.deinit();

    var store = try Store.open(scratch.path);
    defer store.close();

    // The last hand-written vocabularies left in this store, and they are in the
    // schema for a reason that is not laziness: a migration is a record of what
    // was applied to databases that already exist, so rendering its text from a
    // live Zig predicate would rewrite history every time the predicate moved,
    // and an existing database would silently stop matching the statement that
    // supposedly created it.
    //
    // What that reasoning does *not* buy is permission to let the two drift. The
    // checkpoint index has been guarded this way since its own list drifted and
    // wedged every `verifying` row; these three are the same construction with
    // nothing watching them.
    //
    // The two CHECKs are equality. They are the schema's copy of the enum, and a
    // member `op_state` can produce that the column will not accept is a
    // constraint failure at the first write of a status nobody tested — while a
    // member the column accepts and Zig cannot name is a row `Status.parse`
    // refuses to read back.
    const admitted = try schemaInList(t.allocator, &store, "operations", "CHECK (status IN (");
    defer t.allocator.free(admitted);
    try t.expectEqualStrings(comptime Store.op_state.sqlList(everyStatus), admitted);

    const resolvable = try schemaInList(
        t.allocator,
        &store,
        "operations",
        "CHECK (resolved_status IS NULL OR resolved_status IN (",
    );
    defer t.allocator.free(resolvable);
    try t.expectEqualStrings(comptime resolvedStatusSqlList(), resolvable);

    // The index is containment, not equality, and the difference is worth being
    // exact about rather than tightening into a stricter-looking assertion that
    // would be false. `idx_operations_unsettled` is a *partial* index: it
    // constrains nothing, it only offers itself to queries whose `WHERE` sqlite
    // can prove is implied by the index's own. It covers `created` and
    // `connecting` as well, which `Status.blocksScope` deliberately does not —
    // an operation that never reached the remote blocks nothing.
    //
    // So a status added to `blocksScope` and missing here does not corrupt an
    // answer; it makes `operations.unsettled_predicate` unprovable against the
    // index, and the scope barrier quietly falls back to scanning `operations`
    // on every request. That is a performance cliff nobody would connect to the
    // enum member that caused it, and it is what this checks.
    const indexed = try schemaInList(
        t.allocator,
        &store,
        "idx_operations_unsettled",
        "status IN (",
    );
    defer t.allocator.free(indexed);
    // Split out of the rendered list rather than read from the enum, so this
    // asks about the string `unsettled_predicate` is actually built from.
    var blocking = std.mem.splitScalar(
        u8,
        comptime Store.op_state.sqlList(Store.op_state.Status.blocksScope),
        ',',
    );
    while (blocking.next()) |quoted| {
        if (std.mem.indexOf(u8, indexed, quoted) == null) {
            std.debug.print(
                "the scope barrier blocks on {s}, the partial index covers {s}\n",
                .{ quoted, indexed },
            );
            return error.ScopeBarrierPredicateIsNotCoveredByItsIndex;
        }
    }
}

fn everyStatus(_: Store.op_state.Status) bool {
    return true;
}

test "gate: the observation sources Zig can write are the ones the memories column admits" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_observed_source_vocab");
    defer scratch.deinit();

    var store = try Store.open(scratch.path);
    defer store.close();

    // v13's third hand-written vocabulary, held the way the other three are. The
    // column is a CHECK and the Zig side is `memories.observed_sources`, a subset
    // of `receipts.Source` — so this is equality against the subset and not
    // against the enum: a member the column accepts that Zig cannot name is a row
    // `list` refuses to read back with `error.UnknownObservedSource`, and a member
    // Zig writes that the column rejects is a constraint failure at the first
    // write of a source nobody tested.
    const admitted = try schemaInList(
        t.allocator,
        &store,
        "memories",
        "CHECK (observed_source IN (",
    );
    defer t.allocator.free(admitted);
    try t.expectEqualStrings(Store.memories.observed_sources_sql, admitted);
    try t.expectEqual(@as(usize, 4), Store.memories.observed_sources.len);

    // And the other direction, which is the one that needs a reason written down:
    // `receipts.Source` has a member `memories` deliberately does not carry.
    // Reconciliation adjudicates an operation whose outcome is unknown against
    // later evidence, and a memory has no ledger row and no outcome to adjudicate
    // — so `reconcile` is absent by decision. Asserting *which* member is absent,
    // rather than only how many, is what makes a new `Source` member land here as
    // a question instead of passing as one more exclusion.
    const source_fields = @typeInfo(Store.receipts.Source).@"enum".fields;
    try t.expectEqual(@as(usize, 5), source_fields.len);
    var excluded: usize = 0;
    inline for (source_fields) |field| {
        const source: Store.receipts.Source = @enumFromInt(field.value);
        var included = false;
        for (Store.memories.observed_sources) |member| {
            if (member == source) included = true;
        }
        if (!included) {
            excluded += 1;
            try t.expectEqual(Store.receipts.Source.reconcile, source);
        }
    }
    try t.expectEqual(@as(usize, 1), excluded);

    // The refusal itself, at the schema level, where no caller can talk it round.
    try store.db.exec(
        \\INSERT INTO servers (id, name, host, port, username, created_at, updated_at)
        \\VALUES (1, 'box', '10.0.0.1', 22, 'ubuntu', 100, 100);
        \\INSERT INTO memories (server_id, key, content, created_at, updated_at, observed_at, observed_source)
        \\VALUES (1, 'ok', 'x', 100, 100, 100, 'cache');
    );
    try t.expectError(error.Constraint, store.db.exec(
        "UPDATE memories SET observed_source = 'reconcile' WHERE key = 'ok'",
    ));
    try t.expectError(error.Constraint, store.db.exec(
        "UPDATE memories SET observed_source = 'verified' WHERE key = 'ok'",
    ));
}

test "gate: half a trust grant cannot be stored" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_grant_is_whole");
    defer scratch.deinit();

    var store = try Store.open(scratch.path);
    defer store.close();
    try store.db.exec(
        \\INSERT INTO servers (id, name, host, port, username, created_at, updated_at)
        \\VALUES (1, 'box', '10.0.0.1', 22, 'ubuntu', 100, 100);
        \\INSERT INTO memories
        \\  (server_id, key, content, created_at, updated_at, observed_at, observed_source, verify_cmd)
        \\VALUES (1, 'svc', 'nginx on :80', 100, 100, 100, 'cache', 'systemctl is-active nginx');
    );

    // A grant answers three questions — when, who, and what was authorised — and
    // a row answering two of them reads as authorised while the audit trail can
    // say nothing about why the command ran. Every combination is walked, because
    // a CHECK written with a bare `trusted_by <> ''` instead of an `IS NOT NULL`
    // would admit exactly the rows where the missing column makes the expression
    // NULL, and a NULL CHECK expression *passes*.
    const digest_64 = "a" ** 64;
    const partials = [_][:0]const u8{
        "UPDATE memories SET trusted_at = 200",
        "UPDATE memories SET trusted_by = 'ops'",
        "UPDATE memories SET trusted_cmd_sha256 = '" ++ digest_64 ++ "'",
        "UPDATE memories SET trusted_at = 200, trusted_by = 'ops'",
        "UPDATE memories SET trusted_at = 200, trusted_cmd_sha256 = '" ++ digest_64 ++ "'",
        "UPDATE memories SET trusted_by = 'ops', trusted_cmd_sha256 = '" ++ digest_64 ++ "'",
        // Present but naming nobody, which would match every other empty grantee
        // — v7's `owner_token` defect written in one character.
        "UPDATE memories SET trusted_at = 200, trusted_by = '', trusted_cmd_sha256 = '" ++ digest_64 ++ "'",
        // A digest that is not one cannot identify the text it authorised.
        "UPDATE memories SET trusted_at = 200, trusted_by = 'ops', trusted_cmd_sha256 = 'abc'",
    };
    var refused: usize = 0;
    for (partials) |sql| {
        store.db.exec(sql) catch |err| {
            try t.expectEqual(error.Constraint, err);
            refused += 1;
            continue;
        };
        std.debug.print("the schema accepted a partial grant: {s}\n", .{sql});
        return error.PartialTrustGrantWasStored;
    }
    // Counted, so a rewrite that dropped the loop body would fail here rather
    // than pass over an empty region.
    try t.expectEqual(partials.len, refused);
    try t.expectEqual(@as(usize, 8), refused);

    // And a whole grant is accepted, so the constraint is refusing halves rather
    // than everything.
    try store.db.exec(
        "UPDATE memories SET trusted_at = 200, trusted_by = 'ops', trusted_cmd_sha256 = '" ++
            digest_64 ++ "'",
    );
    var stmt = try store.db.prepare(
        "SELECT COUNT(*) FROM memories WHERE trusted_cmd_sha256 IS NOT NULL",
    );
    defer stmt.deinit();
    try t.expect(try stmt.step());
    try t.expectEqual(@as(i64, 1), stmt.columnInt(0));
}

test "gate: a memory written before v13 is backfilled and the row says it was" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_v13_backfill");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Written through the v4 schema, as 0.1.x would have: a note with a write
    // time and no notion of an observation. The two timestamps differ so the
    // backfill cannot be confirmed by coincidence.
    {
        var db = try Db.open(scratch.path);
        defer db.close();
        try migrate.applyUpTo(&db, 4);
        try db.exec(
            \\INSERT INTO servers (id, name, host, port, username, created_at, updated_at)
            \\VALUES (1, 'legacy', '10.0.0.1', 22, 'ubuntu', 100, 100);
            \\INSERT INTO memories (server_id, key, content, created_at, updated_at)
            \\VALUES (1, 'services', 'nginx :80', 100, 4242);
        );
    }

    var store = try Store.open(scratch.path);
    defer store.close();
    try t.expectEqual(@as(i64, migrate.latest_version), try migrate.userVersion(&store.db));

    const rows = try Store.memories.list(&store, arena, .{ .server_id = 1 }, .{});
    try t.expectEqual(@as(usize, 1), rows.len);
    const row = rows[0];

    // The timestamp came from `updated_at` — and the row says that is what it is.
    // A backfilled observation that read as an observation would be the exact
    // confusion v13 exists to remove: a write time in an observation's column,
    // with nothing to tell a reader which it is.
    try t.expectEqual(@as(?i64, 4242), row.observed_at);
    try t.expectEqual(@as(i64, 4242), row.updated_at);
    try t.expectEqual(Store.receipts.Source.backfill, row.observed_source);
    // And nothing was invented for the trust half: an old row is untrusted,
    // which is the same state an imported one lands in.
    try t.expectEqual(@as(?[]const u8, null), row.verify_cmd);
    try t.expect(row.grant == null);
    try t.expectEqual(Store.memories.TrustState.no_verify_cmd, Store.memories.trustState(row));

    // Read off the stored column as well, because the assertion above goes
    // through a Zig default that could in principle be supplying the word.
    var stmt = try store.db.prepare(
        "SELECT observed_source, observed_at FROM memories WHERE key = 'services'",
    );
    defer stmt.deinit();
    try t.expect(try stmt.step());
    try t.expectEqualStrings("backfill", stmt.columnText(0));
    try t.expectEqual(@as(i64, 4242), stmt.columnInt(1));
}

test "gate: a pre-release v13 missing a column is named rather than failing later" {
    const t = std.testing;

    // v13 adds its columns with `ALTER TABLE`, so the drift it can suffer is a
    // partial one: an intermediate revision that added the observation columns and
    // not the grant, or `observed_at` and not `observed_source`. Such a store
    // reports `user_version` 13 and then fails at the first read with a confusing
    // SQL error far from the cause.
    //
    // Both halves are probed and both are checked here, because a probe for one
    // half would let the other pass — which is how the v11 needle probes came to
    // open for the shape they were written to catch.
    //
    // Each store is built the way an intermediate revision would have built it:
    // a real v12 store, then *part* of v13's ALTER sequence, then the version
    // stamp. Not by dropping a column afterwards — sqlite refuses to drop one a
    // CHECK constraint mentions, and both columns probed here are in one.
    {
        var scratch = try Scratch.init(t.allocator, "gate_drift_v13_observed");
        defer scratch.deinit();
        {
            var db = try Db.open(scratch.path);
            defer db.close();
            try migrate.applyUpTo(&db, 12);
            try db.exec(
                \\ALTER TABLE memories ADD COLUMN observed_at INTEGER;
                \\PRAGMA user_version = 13;
            );
        }
        var refusal: migrate.Refusal = undefined;
        try t.expectError(
            error.PreReleaseSchemaDrift,
            Store.openDiagnosed(scratch.path, &refusal),
        );
        // Which column, not merely that something did not match: the two halves
        // of v13 send an operator to different places.
        try t.expectEqualStrings("memories.observed_source", refusal.pre_release_drift.probe);
    }

    // The trust half, on a store where the observation half is complete. Without
    // this case the probe above would be the only one that ever fired, and a
    // build that recorded observations while silently having nowhere to put a
    // grant would read as a finished v13.
    {
        var scratch = try Scratch.init(t.allocator, "gate_drift_v13_grant");
        defer scratch.deinit();
        {
            var db = try Db.open(scratch.path);
            defer db.close();
            try migrate.applyUpTo(&db, 12);
            try db.exec(
                \\ALTER TABLE memories ADD COLUMN observed_at INTEGER;
                \\ALTER TABLE memories ADD COLUMN observed_source TEXT NOT NULL DEFAULT 'backfill'
                \\  CHECK (observed_source IN ('live','cache','legacy_import','backfill'));
                \\ALTER TABLE memories ADD COLUMN verify_cmd TEXT;
                \\ALTER TABLE memories ADD COLUMN trusted_at INTEGER;
                \\ALTER TABLE memories ADD COLUMN trusted_by TEXT;
                \\PRAGMA user_version = 13;
            );
        }
        var refusal: migrate.Refusal = undefined;
        try t.expectError(
            error.PreReleaseSchemaDrift,
            Store.openDiagnosed(scratch.path, &refusal),
        );
        try t.expectEqualStrings("memories.trusted_cmd_sha256", refusal.pre_release_drift.probe);
    }
}

/// `ResolvedStatus` has no renderer of its own — it is a four-member subset
/// with no roles to slice it by — so the gate above builds its list here rather
/// than typing one out, which would be the seventh copy.
fn resolvedStatusSqlList() []const u8 {
    comptime {
        var out: []const u8 = "";
        for (@typeInfo(Store.op_state.ResolvedStatus).@"enum".fields, 0..) |f, i| {
            out = out ++ (if (i == 0) "" else ",") ++ "'" ++ f.name ++ "'";
        }
        return out;
    }
}

test "gate: a *Locked writer refuses to run outside a transaction" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_locked_needs_txn");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    try seedServer(&store);

    const rid = testId("txnguard");
    const request_id: []const u8 = &rid;

    // The suffix is a promise that the caller holds the write transaction, and
    // it used to be enforced by nothing: a forgotten `BEGIN` does not fail, it
    // succeeds one statement at a time and leaves half a hand-over behind,
    // reading as fact. Every argument below names something that does not
    // exist — the guard is the first thing each function does, so a refusal
    // here cannot be some later validation answering in its place.
    try t.expectError(
        error.NotInTransaction,
        Store.operations.statusOfLocked(&store, request_id),
    );
    try t.expectError(
        error.NotInTransaction,
        Store.operations.advanceLocked(&store, request_id, .submitted, 100),
    );
    try t.expectError(
        error.NotInTransaction,
        Store.receipts.nextSeqLocked(&store, request_id),
    );
    try t.expectError(error.NotInTransaction, Store.receipts.insertLocked(&store, .{
        .request_id = request_id,
        .kind = .audit,
        .observed_at = 100,
    }, 1));
    try t.expectError(error.NotInTransaction, Store.leases.conflictForLocked(
        &store,
        arena,
        1,
        .{ .kind = .server, .key = "" },
        "owner",
        100,
    ));
    try t.expectError(
        error.NotInTransaction,
        Store.transfers.adoptLocked(&store, 1, request_id, request_id, 100),
    );
    try t.expectError(
        error.NotInTransaction,
        Store.transfers.adjudicateLocked(&store, 1, request_id, .published, null, 100),
    );
    try t.expectError(
        error.NotInTransaction,
        Store.transfers.expectedEffectLocked(&store, arena, request_id),
    );
    try t.expectError(
        error.NotInTransaction,
        Store.transfers.pendingPublishLocked(&store, request_id),
    );
    try t.expectError(
        error.NotInTransaction,
        Store.transfers.supersedeLocked(&store, 1, request_id, 100),
    );
    // The third of `servers.removeLocked`'s three barriers. It is a reader
    // rather than a writer, which is why it went so long without the guard its
    // two siblings have — and why it needs one: a count taken outside the lock
    // describes a moment that has already passed by the time the DELETE runs,
    // so the barrier would be answering about a database nobody is holding
    // still. Its siblings `operations.unsettledCountLocked` and
    // `leases.activeCountLocked` both assert; this one did not.
    try t.expectError(
        error.NotInTransaction,
        Store.transfers.handoverBoundCountLocked(&store, 1),
    );

    // And inside one they run, so the guard is checking for a transaction
    // rather than refusing everything. All three readers answer "nothing
    // here", which is the right answer for a request that was never created
    // and a server with no transfers — what matters is that they got as far as
    // asking.
    try t.expectEqual(
        @as(?i64, null),
        try locked(&store, Store.transfers.pendingPublishLocked, .{ &store, request_id }),
    );
    try t.expectEqual(
        @as(i64, 1),
        try locked(&store, Store.receipts.nextSeqLocked, .{ &store, request_id }),
    );
    try t.expectEqual(
        @as(i64, 0),
        try locked(&store, Store.transfers.handoverBoundCountLocked, .{ &store, 1 }),
    );
}

// --- The server cascade set is declared, and the schema is held to it --------
//
// The `servers` DELETE is the widest destruction in this tree. It takes the
// server row and everything the foreign keys cascade off it, and until this gate
// existed that set was written down **nowhere**: not in a Zig list, not in a
// comment, not in a count. It existed only as `REFERENCES servers(id) ON DELETE
// CASCADE` scattered across eight migrations, so anybody adding a table with that
// clause silently joined the widest destruction in the tree and no gate, no
// review checklist and no message noticed.
//
// That is not a hypothetical. The set was hand-derived by grepping the schema
// text while this gate was being specified, and the hand-derivation was **wrong
// in three of ten entries**: it counted `keys` (the reference runs the other way
// — `servers.key_id REFERENCES keys(id)`, so a server delete leaves the key
// material alone), `host_pins` (no `server_id` column at all; it is keyed on
// host/port/key_type) and `job_probe_state` (it cascades off
// `operations(request_id)`, and `operations.server_id` is `ON DELETE SET NULL`,
// so a server delete never reaches it). A hand-list is exactly what this gate
// exists instead of.
//
// **Seven, and why it is seven.** Seven tables carry a `server_id` that cascades:
// five from v1–v4 when a server was just a host with notes on it (`sessions`,
// `memories`, `jobs`, `facts`, `history`), and two from v7 when servers gained
// coordination and policy (`leases`, `redaction_rules`). The transitive closure
// adds nothing: `memories` also cascades off `sessions`, but it is already in the
// set directly, and nothing references the other six.
//
// **The derivation is not a second list.** The actual set comes out of the schema
// a fresh store really has — `migrate.zig`'s text, applied — read back through
// `pragma_foreign_key_list` and closed transitively. A hand-list of tables to
// check could not see a table that did not exist when the list was written, which
// is precisely the regression this catches; and reading the applied schema rather
// than the source text means an `ALTER TABLE … REFERENCES` or a v-next re-cut is
// seen the same way a `CREATE TABLE` is.
//
// **What each of the seven is worth to an operator, stated per table.** The three
// barriers in `servers.removeLocked` count operations, leases and transfers; of
// those three tables only `leases` is in this cascade at all. `operations` is `ON
// DELETE SET NULL` and `transfer_checkpoints` has no server column, so two of the
// three barriers guard rows that survive the delete.
//
// **A barrier and a count are two facts, not two values of one.** This declaration
// used to carry a three-way `Guard` — barrier, volume warning, or nothing — which
// forced `leases` to pick one, and it picked the barrier. That reads as covered and
// is not: `leases.activeCountLocked` counts *live claims*, so a server whose leases
// have all been given back clears the barrier with its entire lease history still
// on disk, and the delete took every row of it without a number anywhere. So the
// two are recorded as two independent booleans, and `leases` has both.
//
// The other thing that change closed: `redaction_rules` was declared `.unwatched`
// — no barrier, no count, no message — and `.unwatched` was a legal thing to write
// down. It is not any more. Every one of the seven is now behind at least a count,
// the `.counted` column is held against `CascadeCounts`'s own fields in both
// directions, and an entry behind neither fails this gate rather than documenting
// itself.

/// One table that the `servers` DELETE destroys, and what stands between an
/// operator and that destruction.
const CascadedTable = struct {
    name: []const u8,

    /// One of `servers.removeLocked`'s three in-transaction barriers refuses the
    /// whole removal while a row here is live. `leases` is the only member, and
    /// only for *unreleased* rows — which is exactly why this is not a substitute
    /// for `counted`.
    barrier: bool,

    /// `servers.cascadeCounts` counts it, and `server rm` puts the number in the
    /// message `--force` answers. Advisory — it refuses nothing — and held
    /// against the struct that does the counting rather than asserted here.
    counted: bool,
};

/// The declared cascade set. Seven; see the header for why seven.
///
/// Adding a table here is the decision this gate exists to force: a new
/// `REFERENCES servers(id) ON DELETE CASCADE` fails the gate until somebody
/// writes the table down *and* says what guards it. Writing `false` in both
/// columns is not a way out — a table behind nothing fails too.
const server_cascade = [_]CascadedTable{
    .{ .name = "facts", .barrier = false, .counted = true },
    .{ .name = "history", .barrier = false, .counted = true },
    .{ .name = "jobs", .barrier = false, .counted = true },
    // Both, and the two are about different rows: the barrier refuses while a
    // claim is held, the count says how much lease history goes when none is.
    .{ .name = "leases", .barrier = true, .counted = true },
    .{ .name = "memories", .barrier = false, .counted = true },
    // Declared secret locations, so redaction does not depend on pattern
    // guessing alone (v7). Server-scoped rules go with the server, and until the
    // count named them nothing did.
    .{ .name = "redaction_rules", .barrier = false, .counted = true },
    .{ .name = "sessions", .barrier = false, .counted = true },
};

/// Stated separately from `server_cascade.len` so the number has to be edited
/// deliberately. A table added to the list without this moving is a table
/// somebody added without reading why the count is what it is.
const server_cascade_count = 7;

fn containsName(haystack: []const []const u8, needle: []const u8) bool {
    for (haystack) |name| if (std.mem.eql(u8, name, needle)) return true;
    return false;
}

/// Whether deleting a `parent` row cascades away `child` rows, as sqlite has it.
fn cascadesTo(store: *Store, child: []const u8, parent: []const u8) Db.Error!bool {
    var stmt = try store.db.prepare(
        \\SELECT 1 FROM pragma_foreign_key_list(?1)
        \\WHERE "table" = ?2 AND "on_delete" = 'CASCADE'
    );
    defer stmt.deinit();
    try stmt.bindText(1, child);
    try stmt.bindText(2, parent);
    return try stmt.step();
}

fn cascadesToAny(
    store: *Store,
    child: []const u8,
    root: []const u8,
    reached: []const []const u8,
) Db.Error!bool {
    if (try cascadesTo(store, child, root)) return true;
    for (reached) |mid| if (try cascadesTo(store, child, mid)) return true;
    return false;
}

/// Every table a `DELETE FROM <root>` destroys, transitively, as this database's
/// own foreign keys define it.
///
/// A fixpoint rather than a worklist: one pass per table at worst, and it needs
/// no mutable slice being iterated while it grows.
fn cascadeClosure(
    store: *Store,
    arena: std.mem.Allocator,
    root: []const u8,
) !std.ArrayList([]const u8) {
    var tables: std.ArrayList([]const u8) = .empty;
    {
        var stmt = try store.db.prepare(
            \\SELECT name FROM sqlite_master
            \\WHERE type = 'table' AND name NOT LIKE 'sqlite\_%' ESCAPE '\'
            \\ORDER BY name
        );
        defer stmt.deinit();
        while (try stmt.step()) try tables.append(arena, try arena.dupe(u8, stmt.columnText(0)));
    }

    var reached: std.ArrayList([]const u8) = .empty;
    var grew = true;
    while (grew) {
        grew = false;
        for (tables.items) |child| {
            if (std.mem.eql(u8, child, root)) continue;
            if (containsName(reached.items, child)) continue;
            if (!try cascadesToAny(store, child, root, reached.items)) continue;
            try reached.append(arena, child);
            grew = true;
        }
    }
    return reached;
}

test "gate: the server cascade set is declared and the schema is held to it" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_server_cascade_set");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    try t.expectEqual(@as(usize, server_cascade_count), server_cascade.len);

    const actual = try cascadeClosure(&store, arena, "servers");

    // A closure that found nothing would agree with nothing. `sessions` has
    // cascaded off `servers` since v1, so an empty answer means the derivation
    // is broken and every comparison below it is vacuous.
    if (!containsName(actual.items, "sessions")) {
        std.debug.print(
            \\
            \\the cascade derivation found {d} tables and `sessions` is not among
            \\them. `sessions.server_id` has been ON DELETE CASCADE since v1, so
            \\this is the derivation failing, not the schema changing — every
            \\comparison below would pass for the wrong reason.
            \\
        , .{actual.items.len});
        return error.ServerCascadeDerivationFoundNothing;
    }

    // The schema gained a cascading table nobody has decided about.
    for (actual.items) |table| {
        var declared = false;
        for (server_cascade) |entry| {
            if (std.mem.eql(u8, entry.name, table)) declared = true;
        }
        if (declared) continue;
        std.debug.print(
            \\
            \\`{s}` now cascades off `servers`, so `server rm` destroys its rows —
            \\and nothing in the tree says so. That delete is the widest
            \\destruction here; joining it is a decision, not a schema detail.
            \\
            \\Add `{s}` to `server_cascade` in this file, saying what guards it:
            \\
            \\  .barrier = true  a barrier in `servers.removeLocked` refuses the
            \\                   removal while a row here is live;
            \\  .counted = true  `servers.cascadeCounts` counts it and `server rm`
            \\                   puts the number in the message `--force` answers.
            \\
            \\At least one must be true. Both false is a table whose rows go with
            \\the server and nobody is told, and that is no longer something this
            \\declaration can express — add the `CascadeCounts` field.
            \\
            \\If `{s}` should not go with the server at all, its foreign key wants
            \\ON DELETE SET NULL — which is what `operations` and `job_attempts`
            \\already use — rather than a declaration here.
            \\
        , .{ table, table, table });
        return error.ServerCascadeGainedAnUndeclaredTable;
    }

    // And the declaration describes a table the schema still cascades.
    for (server_cascade) |entry| {
        if (containsName(actual.items, entry.name)) continue;
        std.debug.print(
            \\
            \\`server_cascade` declares `{s}`, and the `servers` DELETE no
            \\longer reaches it. Either its foreign key changed — in which case the
            \\entry and `server_cascade_count` go with it — or the table is gone.
            \\A declaration that outlives what it describes is how the next reader
            \\comes to trust a set that is no longer true.
            \\
        , .{entry.name});
        return error.ServerCascadeDeclaresATableTheSchemaDoesNot;
    }
    try t.expectEqual(server_cascade.len, actual.items.len);

    // Nothing in the cascade is behind nothing, and this is asked first because
    // it is the coarsest thing that can be wrong. There used to be an entry like
    // this: `redaction_rules` was `.unwatched` — no barrier, no count, no message
    // — its rows went with the server, and the declaration recorded that as a
    // decision somebody had made rather than a defect. Declared secret locations
    // are the worst of the seven to lose in silence, so both columns false is a
    // failure now and not a third guard.
    for (server_cascade) |entry| {
        if (entry.barrier or entry.counted) continue;
        std.debug.print(
            \\
            \\`{s}` cascades off `servers` with no barrier and no count: its rows
            \\go with the server and nothing refuses, nothing counts them and no
            \\message names them. Add the `CascadeCounts` field and set
            \\`.counted = true`; there is no third answer here.
            \\
        , .{entry.name});
        return error.ServerCascadeTableIsBehindNothing;
    }

    // The `.counted` column against the struct that does the counting, so "all
    // seven are behind a number" is read off `CascadeCounts` rather than asserted
    // here. Both directions: a field added there for a table that does not
    // cascade is counting something a removal does not destroy, and a cascading
    // table dropped from it goes from advisory to silent with nothing to notice.
    const counted = @typeInfo(Store.servers.CascadeCounts).@"struct".fields;
    inline for (counted) |field| {
        for (server_cascade) |entry| {
            if (!std.mem.eql(u8, entry.name, field.name)) continue;
            if (entry.counted) break;
            std.debug.print(
                \\
                \\`CascadeCounts` counts `{s}`, and this file declares it
                \\`.counted = false`. The struct is what `server rm` puts in front
                \\of `--force`, so it is the definition of that column — a barrier
                \\on the same table does not stand in for it, because a barrier is
                \\about rows somebody is holding and the count is about the rest.
                \\
            , .{field.name});
            return error.ServerCascadeGuardDisagreesWithTheVolumeWarning;
        } else {
            std.debug.print(
                \\
                \\`CascadeCounts` counts `{s}`, and the `servers` DELETE does
                \\not destroy it. The number `server rm` shows an operator is then
                \\about rows the removal leaves alone.
                \\
            , .{field.name});
            return error.VolumeWarningCountsATableTheCascadeDoesNotDestroy;
        }
    }
    for (server_cascade) |entry| {
        if (!entry.counted) continue;
        var in_struct = false;
        inline for (counted) |field| {
            if (std.mem.eql(u8, entry.name, field.name)) in_struct = true;
        }
        if (in_struct) continue;
        std.debug.print(
            \\
            \\`{s}` is declared `.counted = true` and `CascadeCounts` has no field
            \\for it, so nothing counts it. Add the field — dropping the claim
            \\instead leaves the table behind nothing, which the check below
            \\refuses.
            \\
        , .{entry.name});
        return error.VolumeWarningIsDeclaredForATableNothingCounts;
    }

    // And nothing in the cascade is behind nothing — asked above, before the
    // agreement checks, so that a table dropped out of `CascadeCounts` fails on
    // the coarse question rather than the fine one.

    // And the shape of the answer, so the header's numbers are checked rather
    // than written. One behind a barrier — `leases`, and `leases` alone, because
    // `operations` is SET NULL and `transfer_checkpoints` has no server column, so
    // two of the three barriers guard rows that outlive the delete. All seven
    // behind the advisory count, `leases` included: the barrier covers held
    // claims, the count covers the released history the barrier stops caring
    // about.
    var barriered: usize = 0;
    var counted_n: usize = 0;
    for (server_cascade) |entry| {
        if (entry.barrier) barriered += 1;
        if (entry.counted) counted_n += 1;
    }
    try t.expectEqual(@as(usize, 1), barriered);
    try t.expectEqual(@as(usize, server_cascade_count), counted_n);
    try t.expectEqual(@as(usize, server_cascade_count), counted.len);
    for (server_cascade) |entry| {
        if (!entry.barrier) continue;
        try t.expectEqualStrings("leases", entry.name);
    }
}
