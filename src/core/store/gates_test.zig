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
    return seedOperationOfKind(store, request_id, .exec);
}

/// Same, for tests that care which kind of work the operation represents —
/// evidence is only admissible for the kind of operation that produces it.
fn seedOperationOfKind(store: *Store, request_id: []const u8, kind: Store.operations.Kind) !void {
    try store.db.exec(
        \\INSERT INTO servers (id, name, host, port, username, created_at, updated_at)
        \\VALUES (1, 'race', '10.0.0.1', 22, 'ubuntu', 100, 100);
    );
    try Store.operations.create(store, .{
        .request_id = request_id,
        .server_id = 1,
        .server_name = "race",
        .kind = kind,
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
    // A job: the reconciliation below is a job's exit sentinel, and evidence
    // is only admissible for the kind of operation that produces it.
    try seedOperationOfKind(&store, request_id, .job);

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
    try Store.jobs.markFinished(&store, row.id, .exited, 0, 2000);
    try t.expect(!try Store.jobs.markStarted(&store, owner));
    try t.expectEqual(Store.jobs.Status.exited, (try Store.jobs.getByName(&store, arena, 1, "deploy")).?.status);

    // The takeover case, which is why ownership is the request id and not the
    // row id: sqlite hands the next INSERT the id of the row just deleted, so
    // a successor can and does inherit the aborted launcher's rowid.
    const stale_owner = owner;
    _ = try Store.jobs.remove(&store, 1, "deploy");
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
    // A job, because the evidence under test is a job's exit sentinel: the
    // question here is whether the evidence entails the *result*, and it can
    // only get asked of an operation the evidence is allowed to speak about.
    try seedOperationOfKind(&store, request_id, .job);
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

test "gate: an operation kind too long to hold is refused, not truncated" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_kind_overlong");
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
    // may release the scope barrier — must not be handed a prefix of it.
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

    // Nothing was written, and the refusal did not leave a transaction open —
    // the next resolve would fail to BEGIN if it had.
    try t.expectEqual(
        @as(?op_state.ResolvedStatus, null),
        (try Store.operations.get(&store, arena, request_id)).?.resolved_status,
    );
    try store.db.exec("UPDATE operations SET kind = 'job'");
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
    try seedOperationOfKind(&store, request_id, .transfer_push);
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
    const undeclared = try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .filesystem_effect = .{ .side = .remote, .path = "/srv/app/out.bin", .sha256 = "abc" },
    }, 310);
    try t.expectEqual(
        @as(?Store.transfers.ExpectedEffect, null),
        undeclared.effect_hash_unproven.expected,
    );
    try t.expectEqualStrings("abc", undeclared.effect_hash_unproven.observed.sha256);

    const checkpoint = try Store.transfers.create(&store, .{
        .request_id = request_id,
        .direction = .push,
        .remote_path = "/srv/app/out.bin",
        .remote_partial_path = "/srv/app/out.bin.terminus-part",
        .chunk_size = 1 << 20,
        .expected_sha256 = "abc",
        .now = 200,
    });
    _ = checkpoint;

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

    // Declared and matching. This is the only pairing that settles.
    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .filesystem_effect = .{ .side = .remote, .path = "/srv/app/out.bin", .sha256 = "abc" },
    }, 314)) == .resolved);
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

/// A transfer operation parked at `connecting`, i.e. before anything has been
/// sent. `seedOperationOfKind` runs on to `submitted`, which is exactly the
/// state the digest-declaration gate needs to be *outside* of.
fn seedTransferBeforeSubmit(store: *Store, request_id: []const u8) !void {
    store.db.exec(
        \\INSERT INTO servers (id, name, host, port, username, created_at, updated_at)
        \\VALUES (1, 'race', '10.0.0.1', 22, 'ubuntu', 100, 100);
    ) catch |err| switch (err) {
        // The second call in a test shares the first call's server.
        error.Constraint => {},
        else => return err,
    };
    try Store.operations.create(store, .{
        .request_id = request_id,
        .server_id = 1,
        .server_name = "race",
        .kind = .transfer_push,
        .now = 100,
    });
    try Store.operations.advance(store, request_id, .connecting, 101);
}

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
        .remote_path = "/srv/app/out.bin",
        .remote_partial_path = "/srv/app/out.bin.terminus-part",
        .chunk_size = 1 << 20,
        .now = 100,
    });

    // Declaring it before the first byte leaves is the whole point, so that
    // one is allowed.
    try Store.transfers.recordExpectedHash(&store, checkpoint, "abc", 110);

    // A second declaration is refused even while the transfer is still early:
    // a digest that can be rewritten is a digest that can be made to match
    // whatever landed, which is the same as having none.
    try t.expectError(
        error.ExpectedHashLocked,
        Store.transfers.recordExpectedHash(&store, checkpoint, "def", 111),
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
        .remote_path = "/srv/app/late.bin",
        .remote_partial_path = "/srv/app/late.bin.terminus-part",
        .chunk_size = 1 << 20,
        .now = 100,
    });
    try Store.operations.advance(&store, late, .submitted, 102);
    try t.expectError(
        error.ExpectedHashLocked,
        Store.transfers.recordExpectedHash(&store, late_checkpoint, "abc", 112),
    );
    try t.expectEqual(
        @as(?[]const u8, null),
        (try Store.transfers.get(&store, arena, late_checkpoint)).?.expected_sha256,
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
    // exactly like "progress recorded".
    try t.expectError(
        error.CheckpointRowMissing,
        Store.transfers.confirmOffset(&store, 999, 4096, 4096, null, 100),
    );
    try t.expectError(
        error.CheckpointRowMissing,
        Store.transfers.setState(&store, 999, .transferring, null, 100),
    );
    try t.expectError(
        error.CheckpointRowMissing,
        Store.transfers.recordVerifiedHash(&store, 999, "abc", 100),
    );
}

test "gate: two declared digests for one request refuse to settle it" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_ambiguous_checkpoint");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    const rid = testId("ambig");
    const request_id: []const u8 = &rid;
    try seedOperationOfKind(&store, request_id, .transfer_push);
    _ = try Store.receipts.settle(
        &store,
        request_id,
        op_state.terminalForTransportLoss(.submitted, "eof"),
        .{},
        300,
    );

    for ([_][]const u8{ "abc", "def" }) |digest| {
        _ = try Store.transfers.create(&store, .{
            .request_id = request_id,
            .direction = .push,
            .remote_path = "/srv/app/out.bin",
            .remote_partial_path = "/srv/app/out.bin.terminus-part",
            .chunk_size = 1 << 20,
            .expected_sha256 = digest,
            .now = 200,
        });
    }

    // Two promises, both plausible. Picking one by `ORDER BY id DESC` would
    // make a scope-releasing decision out of insertion order, so this refuses
    // instead — and refuses as an error, because unlike a mismatch it is not
    // a fact about the transfer, it is a fact about our own bookkeeping.
    try t.expectError(error.AmbiguousCheckpoint, Store.receipts.resolve(
        &store,
        arena,
        request_id,
        .completed,
        .{ .filesystem_effect = .{ .side = .remote, .path = "/srv/app/out.bin", .sha256 = "abc" } },
        400,
    ));

    // The refusal left the ledger untouched — including the transaction it
    // had already opened.
    try t.expectEqual(
        @as(?op_state.ResolvedStatus, null),
        (try Store.operations.get(&store, arena, request_id)).?.resolved_status,
    );
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
