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

    /// Scratch names must be unique per process: the gates are otherwise
    /// safe to run in parallel, and a shared filename turns that into a pile
    /// of false failures that look like real races.
    var counter: std.atomic.Value(u32) = .init(0);

    fn uniqueName(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
        const n = counter.fetchAdd(1, .monotonic);
        return std.fmt.allocPrint(allocator, "{s}_{d}_{d}", .{ name, std.Thread.getCurrentId(), n });
    }

    fn init(allocator: std.mem.Allocator, name: []const u8) !Scratch {
        const threaded = try allocator.create(std.Io.Threaded);
        threaded.* = .init(allocator, .{});
        const io = threaded.io();
        std.Io.Dir.cwd().createDirPath(io, dir) catch {};
        const unique = try uniqueName(allocator, name);
        defer allocator.free(unique);
        const path = try std.fmt.allocPrintSentinel(allocator, "{s}/{s}.db", .{ dir, unique }, 0);
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

/// Builds a syntactically valid request id from a readable label.
///
/// Crockford base32 omits I, L, O and U, so hand-written test ids are easy
/// to get wrong; this maps the confusable letters and pads to length.
fn testId(label: []const u8) [ids.len]u8 {
    var out: [ids.len]u8 = @splat('0');
    for (label, 0..) |ch, i| {
        if (i >= ids.len) break;
        out[i] = switch (std.ascii.toUpper(ch)) {
            'I', 'L' => '1',
            'O' => '0',
            'U' => 'V',
            '0'...'9', 'A'...'H', 'J', 'K', 'M', 'N', 'P'...'T', 'V'...'Z' => std.ascii.toUpper(ch),
            else => '0',
        };
    }
    return out;
}

test testId {
    const id = testId("guard");
    try ids.validate(&id);
    try std.testing.expectEqual(@as(usize, ids.len), id.len);
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
    try seedOperation(&store, request_id);

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
    try seedOperation(&store, request_id);
    _ = try Store.receipts.settle(
        &store,
        request_id,
        op_state.terminalForTransportLoss(.submitted, "eof"),
        .{},
        300,
    );

    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .completed, .{ .job_sentinel = .{ .sentinel = "__S__", .exit_code = 0 } }, 400)) == .resolved);

    // A second reconciler must not overwrite the first one's evidence.
    const second = try Store.receipts.resolve(&store, arena, request_id, .failed, .{ .supervisor_report = .{ .reported = .failed, .detail = "disagrees" } }, 500);
    try t.expectEqual(op_state.ResolvedStatus.completed, second.already_resolved);

    const op = (try Store.operations.get(&store, arena, request_id)).?;
    try t.expectEqual(op_state.ResolvedStatus.completed, op.resolved_status.?);
    try t.expect(std.mem.indexOf(u8, op.resolution_evidence.?, "job_sentinel") != null);

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

/// One thread racing to claim a job name, the way `run --name deploy` does.
const ReserveCtx = struct {
    path: [:0]const u8,
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
    _ = Store.jobs.create(&store, 1, "deploy", "make deploy", "__TERMINUS_JOB_1__", 1000) catch |err| {
        switch (err) {
            error.NameTaken => ctx.taken = true,
            else => ctx.err = err,
        }
        return;
    };
    ctx.reserved = true;
}

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

    const thread_count = 4;
    var gate: std.atomic.Value(bool) = .init(false);
    var ctxs: [thread_count]ReserveCtx = undefined;
    var threads: [thread_count]std.Thread = undefined;
    for (&ctxs, 0..) |*c, i| {
        c.* = .{ .path = scratch.path, .gate = &gate };
        threads[i] = try std.Thread.spawn(.{}, reserveInThread, .{c});
    }
    gate.store(true, .release);
    for (threads) |th| th.join();

    var reserved: usize = 0;
    var taken: usize = 0;
    for (ctxs) |c| {
        try t.expectEqual(@as(?anyerror, null), c.err);
        if (c.reserved) reserved += 1;
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
    try t.expectEqual(@as(usize, thread_count - 1), taken);

    var store = try Store.open(scratch.path);
    defer store.close();

    // The winner holds a *pending* row, not a running one. Nothing has been
    // typed into the remote shell yet, so claiming `running` would put a job
    // in `job ls` that provably never started — while still blocking the
    // name, which is what the reservation is for.
    const row = (try Store.jobs.getByName(&store, arena, 1, "deploy")).?;
    try t.expectEqual(Store.jobs.Status.pending, row.status);
    try t.expect(row.status.live());

    // Only reaching the remote promotes it.
    try Store.jobs.markStarted(&store, row.id);
    try t.expectEqual(Store.jobs.Status.running, (try Store.jobs.getByName(&store, arena, 1, "deploy")).?.status);

    // A promotion arriving after somebody observed the job's end must not
    // walk it back: the settlement is the newer truth.
    try Store.jobs.markFinished(&store, row.id, .exited, 0, 2000);
    try Store.jobs.markStarted(&store, row.id);
    try t.expectEqual(Store.jobs.Status.exited, (try Store.jobs.getByName(&store, arena, 1, "deploy")).?.status);

    // An unreadable status is an error, not a guess. This row is the shape a
    // future version writing a state this binary does not know would leave
    // behind; the old `orelse .running` renamed it to a state it had no
    // evidence for and reported that in `job ls`.
    try store.db.exec("UPDATE jobs SET status = 'quantum' WHERE name = 'deploy'");
    try t.expectError(error.UnknownStatus, Store.jobs.getByName(&store, arena, 1, "deploy"));
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
    const json = try probe.toJson(arena);
    try t.expect(std.mem.indexOf(u8, json, "\"mechanical\":true") != null);
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
    try seedOperation(&store, request_id);
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

    // The dangerous one: a process still *running* proves nothing, and must
    // not be able to release the mutation barrier by claiming completion.
    const alive = try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .process_probe = .{ .pid = 77, .alive = true },
    }, 401);
    try t.expect(alive == .evidence_does_not_support);

    // A dead process establishes absence, i.e. cancellation — not success.
    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .process_probe = .{ .pid = 77, .alive = false },
    }, 402)) == .evidence_does_not_support);

    // A published file hash says nothing about an arbitrary command.
    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .filesystem_effect = .{ .path = "/srv/app/out.bin", .sha256 = "abc" },
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

test "gate: a supervisor report cannot be repointed at another result" {
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
    // cannot be chosen independently.
    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .supervisor_report = .{ .reported = .timed_out, .detail = "deadline hit" },
    }, 400)) == .evidence_does_not_support);

    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .timed_out, .{
        .supervisor_report = .{ .reported = .timed_out, .detail = "deadline hit" },
    }, 401)) == .resolved);
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
