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
// The checkpoint hand-over is a composite: the row moves in `transfers` and
// both operations record it in `receipts`, in one transaction held by the
// layer above. Proving it lands as a whole or not at all means reaching for
// that layer from here — there is nothing inside `store/` that can hold the
// three writes together, which is the point.
const execution = @import("../execution.zig");

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

/// Calls a `pub fn …Locked` writer inside the transaction its name promises.
///
/// Every one of them now refuses outright when no transaction is open, so a
/// gate that called one directly would be exercising that guard instead of the
/// rule it came for. In production these calls sit inside a transaction their
/// caller opened around several writes — `execution.adoptCheckpoint`,
/// `receipts.resolve` — and this is the smallest honest stand-in: one writer,
/// one transaction, rolled back if it refuses.
fn locked(
    store: *Store,
    comptime f: anytype,
    args: anytype,
) @typeInfo(@TypeOf(f)).@"fn".return_type.? {
    try store.db.exec("BEGIN IMMEDIATE");
    errdefer store.db.exec("ROLLBACK") catch {};
    const result = try @call(.auto, f, args);
    try store.db.exec("COMMIT");
    return result;
}

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

/// Records the process identity a later probe will be checked against.
///
/// Written as an ordinary observation because that is how it is written for
/// real: `execution` reports the pid and start token the shell gave it for the
/// command it ran (`supervisor.Identity`). A gate that inserted the row by hand
/// would be proving something about a shape nothing produces.
fn recordProcess(
    store: *Store,
    request_id: []const u8,
    pid: i64,
    start_token: ?[]const u8,
    now: i64,
) !void {
    _ = try Store.receipts.append(store, .{
        .request_id = request_id,
        .kind = .remote_start,
        .observed_at = now,
        .remote_pid = pid,
        .remote_start_token = start_token,
    });
}

/// Records the launch a later `job_sentinel` resolution is checked against.
///
/// The counterpart of `recordProcess`, one evidence chain over, and written for
/// the same reason: `cmd_job` stores the sentinel it chose in `job_attempts`
/// before the launch line can reach the remote shell — `job_attempts.create` at
/// `cmd_job.zig:314`, some sixty lines ahead of `sendKeys` — so a sentinel that
/// could ever appear in a job's log is necessarily one this table already
/// carries. A gate that resolved from a sentinel with no attempt row behind it
/// would be proving something about a job that never launched.
///
/// The row has to match on all three of the things that make it this launch's:
/// the request id, the server, and the sentinel itself. A row that merely
/// exists would let the gate pass without the comparison ever having something
/// true to compare.
fn recordLaunchSentinel(
    store: *Store,
    request_id: []const u8,
    server_name: []const u8,
    job_name: []const u8,
    sentinel: []const u8,
    now: i64,
) !void {
    _ = try Store.job_attempts.create(store, .{
        .request_id = request_id,
        .server_id = 1,
        .server_name = server_name,
        .job_name = job_name,
        .attempt_no = try Store.job_attempts.nextAttemptNo(store, 1, job_name),
        .sentinel = sentinel,
        .now = now,
    });
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
    // ...and only for the operation that *recorded* it. See
    // `recordLaunchSentinel`.
    try recordLaunchSentinel(&store, request_id, "race", "migrate", "__TERMINUS_JOB_1__", 100);

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
    try recordLaunchSentinel(&store, request_id, "race", "once", "__S__", 100);
    _ = try Store.receipts.settle(
        &store,
        request_id,
        op_state.terminalForTransportLoss(.submitted, "eof"),
        .{},
        300,
    );

    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .completed, .{ .job_sentinel = .{ .sentinel = "__S__", .exit_code = 0 } }, 400)) == .resolved);
    // A second reconciler must not overwrite the first one's evidence. The
    // rival evidence has to be evidence this kind *admits*, or the refusal
    // comes back from `appliesToKind` a step earlier and this gate passes
    // without ever reaching the write-once rule it is about.
    const second = try Store.receipts.resolve(&store, arena, request_id, .failed, .{ .job_sentinel = .{ .sentinel = "__S__", .exit_code = 7 } }, 500);
    try t.expectEqual(op_state.ResolvedStatus.completed, second.already_resolved);

    const op = (try Store.operations.get(&store, arena, request_id)).?;
    try t.expectEqual(op_state.ResolvedStatus.completed, op.resolved_status.?);
    try t.expect(std.mem.indexOf(u8, op.resolution_evidence.?, "job_sentinel") != null);

    // An unknown request is answered before the evidence is examined at all,
    // which is why this may use a variant no kind admits: there is no kind to
    // check it against. The order matters — reporting "that evidence cannot
    // speak about a job" for a request that does not exist would send an
    // operator to look at the wrong thing.
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
    const json = try probe.toJson(arena, .pid_only, null);
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
    // The sentinel below has to be one this attempt actually launched with, or
    // it is refused as another job's log line and this gate never reaches the
    // entailment question it is about. See `recordLaunchSentinel`.
    try recordLaunchSentinel(&store, request_id, "race", "supports", "__S__", 100);
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

    // The probes below have to be readings of *this* attempt's process, or
    // they are refused one step earlier as readings of somebody else's and
    // this gate passes without ever reaching the question it is about.
    try recordProcess(&store, request_id, 77, "boot+77", 310);

    // The dangerous one: a process still *running* proves nothing, and must
    // not be able to release the mutation barrier by claiming completion.
    const alive = try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .process_probe = .{ .pid = 77, .start_token = "boot+77", .alive = true },
    }, 401);
    try t.expect(alive == .evidence_does_not_support);

    // A dead process establishes absence, i.e. cancellation — not success.
    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .process_probe = .{ .pid = 77, .start_token = "boot+77", .alive = false },
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

// The third identity binding, and the one that was missing.
//
// A sentinel names nothing. It is a string scanned out of a window of an
// append-only log that anything on the host can write to, so unlike a result
// document (which carries a request id) and unlike a probe (which carries a
// pid), it has no address of its own at all. What makes one *this* operation's
// is that this binary chose it and wrote it into `job_attempts` before the
// launch line could reach the shell. Until that was compared, `job_sentinel`
// was the only mechanical variant in the union with nothing tying it to the
// operation it settled — and `isMechanical` grades it `true`, which is the
// grade that releases the same-scope mutation barrier with no operator in the
// loop.
//
// All four readings are exercised, because the union has to keep them apart:
// a matching sentinel still settles, a foreign one is refused, an attempt that
// recorded no sentinel is refused, and a request with no attempt row at all is
// refused — and the last three are three different things to go and do.
test "gate: a job sentinel settles only the job that recorded it" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_sentinel_identity");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    const rid = testId("mysent");
    const request_id: []const u8 = &rid;
    try seedOperationOfKind(&store, request_id, .job);
    try recordLaunchSentinel(&store, request_id, "race", "deploy", "__TERMINUS_JOB_9__", 100);
    _ = try Store.receipts.settle(
        &store,
        request_id,
        .{ .indeterminate = .{ .reason = "caller walked away", .last_observed = .submitted } },
        .{},
        200,
    );

    // Somebody else's sentinel, carrying a perfectly good exit code. Admitting
    // it would settle this operation from another job's log line — the exact
    // shape the result-document check refuses one variant over, arriving
    // through the variant that had no check.
    const foreign = try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .job_sentinel = .{ .sentinel = "__TERMINUS_JOB_4__", .exit_code = 0 },
    }, 300);
    try t.expectEqualStrings("__TERMINUS_JOB_4__", foreign.evidence_wrong_sentinel.offered);
    try t.expectEqualStrings("__TERMINUS_JOB_9__", foreign.evidence_wrong_sentinel.recorded.sentinel);

    // Nothing was written by the refusal: no resolution, and no reconcile event
    // claiming one was considered.
    try t.expectEqual(
        @as(?op_state.ResolvedStatus, null),
        (try Store.operations.get(&store, arena, request_id)).?.resolved_status,
    );
    try t.expectEqual(@as(usize, 0), try countKind(&store, arena, request_id, "reconcile"));

    // An attempt that recorded no sentinel. Refused, and refused *distinctly*:
    // no amount of re-reading that job's log will produce a sentinel that can
    // be tied to it, which is a different instruction from "you read the wrong
    // line".
    const nrid = testId("nosent");
    const no_sentinel: []const u8 = &nrid;
    try Store.operations.create(&store, .{
        .request_id = no_sentinel,
        .server_id = 1,
        .server_name = "race",
        .kind = .job,
        .now = 100,
    });
    try Store.operations.advance(&store, no_sentinel, .connecting, 101);
    try Store.operations.advance(&store, no_sentinel, .submitted, 102);
    _ = try Store.job_attempts.create(&store, .{
        .request_id = no_sentinel,
        .server_id = 1,
        .server_name = "race",
        .job_name = "sentinel-less",
        .attempt_no = 1,
        .now = 100,
    });
    _ = try Store.receipts.settle(
        &store,
        no_sentinel,
        .{ .indeterminate = .{ .reason = "caller walked away", .last_observed = .submitted } },
        .{},
        200,
    );
    const unrecorded = try Store.receipts.resolve(&store, arena, no_sentinel, .completed, .{
        .job_sentinel = .{ .sentinel = "__TERMINUS_JOB_9__", .exit_code = 0 },
    }, 300);
    try t.expect(unrecorded.evidence_wrong_sentinel.recorded == .attempt_recorded_none);

    // A request no launch ever registered. Also refused, and also distinctly:
    // this one is evidence aimed at something that is not a job launch, not a
    // job whose launch forgot to write something down.
    const arid = testId("noatt");
    const no_attempt: []const u8 = &arid;
    try Store.operations.create(&store, .{
        .request_id = no_attempt,
        .server_id = 1,
        .server_name = "race",
        .kind = .job,
        .now = 100,
    });
    try Store.operations.advance(&store, no_attempt, .connecting, 101);
    try Store.operations.advance(&store, no_attempt, .submitted, 102);
    _ = try Store.receipts.settle(
        &store,
        no_attempt,
        .{ .indeterminate = .{ .reason = "caller walked away", .last_observed = .submitted } },
        .{},
        200,
    );
    const unlaunched = try Store.receipts.resolve(&store, arena, no_attempt, .completed, .{
        .job_sentinel = .{ .sentinel = "__TERMINUS_JOB_9__", .exit_code = 0 },
    }, 300);
    try t.expect(unlaunched.evidence_wrong_sentinel.recorded == .no_attempt);

    // And the binding is not a blanket refusal: this attempt's own sentinel
    // still settles it, which is what keeps the check from costing the job its
    // route. Last, so the three refusals above cannot have been the resolution
    // having already happened.
    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .job_sentinel = .{ .sentinel = "__TERMINUS_JOB_9__", .exit_code = 0 },
    }, 400)) == .resolved);
    try t.expectEqual(
        op_state.ResolvedStatus.completed,
        (try Store.operations.get(&store, arena, request_id)).?.resolved_status.?,
    );
}

// A settlement records what was sitting at its result-record address.
//
// The hole this closes: a job settles cleanly from the sentinel in its log
// while a document that is *not* usable sits at the address derived from that
// same request — most sharply a `foreign` one, which means the result directory
// is being reused or two request ids collided. The settlement is correct and
// the anomaly is a fact about the host, and the receipt — the one durable
// record — kept the verdict and dropped the contradiction standing next to it.
// The operator saw it on screen once and nothing kept it.
//
// Recorded in `detail_json` rather than in a column, so the schema is untouched
// and the versioned document carries it the way it carries `probeIdentity` and
// `declaredSha256` for a resolution.
test "gate: a terminal records what was at the job's result-record address" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_result_record_receipt");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    // Settles one job with `reading` at its result address and hands back the
    // terminal receipt's detail document.
    const settleWith = struct {
        fn f(
            s: *Store,
            a: std.mem.Allocator,
            request_id: []const u8,
            reading: Store.receipts.ResultRecordReading,
        ) ![]const u8 {
            try Store.operations.create(s, .{
                .request_id = request_id,
                .server_id = 1,
                .server_name = "race",
                .kind = .job,
                .now = 100,
            });
            try Store.operations.advance(s, request_id, .connecting, 101);
            try Store.operations.advance(s, request_id, .submitted, 102);
            _ = try Store.receipts.settle(s, request_id, .{ .exited = .{ .exit_code = 0 } }, .{
                .result_record = .{ .arena = a, .reading = reading },
            }, 200);
            for (try Store.receipts.list(s, a, request_id)) |row| {
                if (row.is_terminal) return row.detail_json orelse
                    error.TerminalRecordedNoResultRecord;
            }
            return error.NoTerminalRecorded;
        }
    }.f;

    try store.db.exec(
        \\INSERT INTO servers (id, name, host, port, username, created_at, updated_at)
        \\VALUES (1, 'race', '10.0.0.1', 22, 'ubuntu', 100, 100);
    );

    // The loud one. A document naming somebody else was found at this
    // request's own address, and the receipt has to carry *which* somebody —
    // the tag alone would say a collision happened while withholding the only
    // thing that identifies it.
    const frid = testId("rrforeign");
    const foreign = try settleWith(&store, arena, &frid, .{ .foreign = "01OTHEROTHER0123456789ABCD" });
    try t.expect(std.mem.indexOf(u8, foreign, "\"reading\":\"foreign\"") != null);
    try t.expect(std.mem.indexOf(u8, foreign, "01OTHEROTHER0123456789ABCD") != null);

    // The three unremarkable readings, and the reason the field is not just a
    // flag for anomalies: "we looked and there was nothing" and "we did not
    // look" are different facts, and a receipt that told them apart from
    // nothing would also fail to tell either of them from a settlement written
    // before this field existed.
    const arid = testId("rrabsent");
    const absent = try settleWith(&store, arena, &arid, .absent);
    try t.expect(std.mem.indexOf(u8, absent, "\"reading\":\"absent\"") != null);
    try t.expect(std.mem.indexOf(u8, absent, "\"claimedRequestId\":null") != null);

    const nrid = testId("rrnotreq");
    const not_requested = try settleWith(&store, arena, &nrid, .not_requested);
    try t.expect(std.mem.indexOf(u8, not_requested, "\"reading\":\"not_requested\"") != null);
    // The distinctness itself, asserted rather than implied: these two must
    // never render to the same document.
    try t.expect(!std.mem.eql(u8, absent, not_requested));

    const prid = testId("rrpresent");
    const present = try settleWith(&store, arena, &prid, .present);
    try t.expect(std.mem.indexOf(u8, present, "\"reading\":\"present\"") != null);

    // The two remaining defect readings, so all six names reach the ledger and
    // none of them collapses into a neighbour.
    const mrid = testId("rrmalform");
    const malformed = try settleWith(&store, arena, &mrid, .malformed);
    try t.expect(std.mem.indexOf(u8, malformed, "\"reading\":\"malformed\"") != null);

    const urid = testId("rrunkschema");
    const unknown = try settleWith(&store, arena, &urid, .unknown_schema);
    try t.expect(std.mem.indexOf(u8, unknown, "\"reading\":\"unknown_schema\"") != null);

    const xrid = testId("rroutrange");
    const out_of_range = try settleWith(&store, arena, &xrid, .exit_code_out_of_range);
    try t.expect(std.mem.indexOf(u8, out_of_range, "\"reading\":\"exit_code_out_of_range\"") != null);

    // Every document is versioned, for the reason the resolution document is:
    // this field was added to a shape that already had readers.
    try t.expect(std.mem.indexOf(u8, foreign, "\"schemaVersion\"") != null);

    // And a caller handing in both its own detail document and a reading is
    // refused rather than having one of the two silently dropped. Nothing
    // constructs this pair today; the refusal is what keeps it that way instead
    // of letting the next caller discover which one survives.
    const crid = testId("rrclash");
    const clash: []const u8 = &crid;
    try Store.operations.create(&store, .{
        .request_id = clash,
        .server_id = 1,
        .server_name = "race",
        .kind = .job,
        .now = 100,
    });
    try Store.operations.advance(&store, clash, .connecting, 101);
    try Store.operations.advance(&store, clash, .submitted, 102);
    try t.expectError(error.ConflictingTerminalDetail, Store.receipts.settle(
        &store,
        clash,
        .{ .exited = .{ .exit_code = 0 } },
        .{
            .detail_json = "{\"mine\":true}",
            .result_record = .{ .arena = arena, .reading = .absent },
        },
        200,
    ));
    // The refusal wrote nothing: no terminal, so the attempt is still settleable.
    try t.expect((try Store.receipts.terminalOf(&store, clash)) == null);
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

test "gate: an operation kind this binary cannot name admits nothing" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_kind_unknown");
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
    // may release the scope barrier — has no answer for it. Longer than any
    // kind that exists is the easy half.
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

    // The half that used to get through. A short unrecognised kind matched no
    // arm of a string comparison, fell into `else => true`, and admitted every
    // variant in the union — so an override settled an operation whose very
    // nature this binary could not read, and released its scope. The evidence
    // here is deliberately the one that is admissible for every kind that
    // exists: what refuses it is the kind being unreadable, nothing else.
    //
    // Checked to be unparseable rather than assumed: add a kind by this name
    // and the gate would go on passing while testing nothing.
    const not_a_kind = "jobs";
    try t.expectError(error.UnknownKind, Store.operations.Kind.parse(not_a_kind));
    try store.db.exec("UPDATE operations SET kind = '" ++ not_a_kind ++ "'");
    try t.expectError(error.UnknownOperationKind, Store.receipts.resolve(
        &store,
        arena,
        request_id,
        .completed,
        .{ .operator_override = .{ .reason = "checked by hand", .by = "tester" } },
        305,
    ));

    // Nothing was written by either refusal, and neither left a transaction
    // open — the next resolve would fail to BEGIN if it had.
    try t.expectEqual(
        @as(?op_state.ResolvedStatus, null),
        (try Store.operations.get(&store, arena, request_id)).?.resolved_status,
    );
    try t.expectEqual(@as(usize, 0), try countKind(&store, arena, request_id, "reconcile"));
    // Rendered from the enum: the control that proves the two refusals are not
    // just "resolve always fails here" has to write a kind this binary really
    // does know, and a rename must move it rather than break it silently.
    try store.db.exec("UPDATE operations SET kind = '" ++ @tagName(Store.operations.Kind.job) ++ "'");
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

    // The whole advance commitment is made before the attempt goes out, and it
    // has to be: `create` binds to an operation that has not submitted yet, and
    // `recordExpectedHash` refuses after that point too. This gate used to seed
    // a settled operation and hand `create` a digest directly, which was the
    // bypass in gate form — the same door the write-once rule exists to shut.
    try seedTransferBeforeSubmit(&store, request_id);
    const checkpoint = try Store.transfers.create(&store, .{
        .request_id = request_id,
        .direction = .push,
        .dest_side = .{ .server = 1 },
        .dest_path = "/srv/app/out.bin",
        .partial_path = "/srv/app/out.bin.terminus-part",
        .source = .{ .local_file = .{ .path = "./out.bin" } },
        .chunk_size = 1 << 20,
        .now = 102,
    });
    try Store.transfers.recordExpectedHash(&store, checkpoint, request_id, "abc", 103);
    try Store.operations.advance(&store, request_id, .submitted, 104);
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
    //
    // It takes a second request to say that now, because a digest has to be
    // declared before submission and one operation can no longer be both
    // "never declared" and "declared and matching". This one has a checkpoint
    // and no digest, which is the sharper claim anyway: a checkpoint existing
    // is not a declaration.
    const silent_rid = testId("undeclared");
    const silent: []const u8 = &silent_rid;
    try seedTransferBeforeSubmit(&store, silent);
    _ = try Store.transfers.create(&store, .{
        .request_id = silent,
        .direction = .push,
        .dest_side = .{ .server = 1 },
        .dest_path = "/srv/app/undeclared.bin",
        .partial_path = "/srv/app/undeclared.bin.terminus-part",
        .source = .{ .local_file = .{ .path = "./undeclared.bin" } },
        .chunk_size = 1 << 20,
        .now = 102,
    });
    try Store.operations.advance(&store, silent, .submitted, 104);
    _ = try Store.receipts.settle(
        &store,
        silent,
        op_state.terminalForTransportLoss(.submitted, "eof"),
        .{},
        200,
    );
    const undeclared = try Store.receipts.resolve(&store, arena, silent, .completed, .{
        .filesystem_effect = .{ .side = .remote, .path = "/srv/app/undeclared.bin", .sha256 = "abc" },
    }, 310);
    try t.expectEqual(
        @as(?Store.transfers.ExpectedEffect, null),
        undeclared.effect_hash_unproven.expected,
    );
    try t.expectEqualStrings("abc", undeclared.effect_hash_unproven.observed.sha256);

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

    // Declared and matching, against a checkpoint whose own record says the
    // rename landed. This is the only pairing that settles — and the second
    // half of it is not decoration: driven straight from `planned`, the same
    // reading was settling `completed` for a transfer that had never written a
    // byte, because the digest binds the reading to the declaration and nothing
    // asked whether this transfer had put anything there. See
    // `State.renameMayHaveLanded`.
    try driveToPublished(&store, checkpoint, request_id, "abc");
    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .filesystem_effect = .{ .side = .remote, .path = "/srv/app/out.bin", .sha256 = "abc" },
    }, 314)) == .resolved);
}

const EvidenceTag = std.meta.Tag(Store.receipts.ResolutionEvidence);

/// One legal value per evidence variant.
///
/// Exhaustive, so a new variant cannot exist without appearing in the matrix
/// below. The payloads do not matter to `appliesToKind` — it asks only what
/// class of claim this is — but they have to be *some* value the union admits.
fn sampleEvidence(tag: EvidenceTag) Store.receipts.ResolutionEvidence {
    return switch (tag) {
        .supervisor_report => .{ .supervisor_report = .{ .reported = .completed, .detail = "the wrapper reported an exit" } },
        .process_probe => .{ .process_probe = .{ .pid = 4242, .start_token = "boot+4242", .alive = false } },
        .job_sentinel => .{ .job_sentinel = .{ .sentinel = "__TERMINUS_JOB_1__", .exit_code = 0 } },
        .job_result => .{ .job_result = .{ .request_id = "01JQXW8ZK4N0RS7T3VYB2MCDEF", .exit_code = 0 } },
        .filesystem_effect => .{ .filesystem_effect = .{ .side = .remote, .path = "/srv/app/out.bin", .sha256 = "abc" } },
        .destination_absent => .{ .destination_absent = .{
            .side = .remote,
            .path = "/srv/app/out.bin",
            .verification_method = "stat => ENOENT",
        } },
        .destination_present_unverified => .{ .destination_present_unverified = .{
            .side = .remote,
            .path = "/srv/app/out.bin",
            .verification_method = "stat => 4096 bytes",
        } },
        .destination_present_contradicting => .{ .destination_present_contradicting = .{
            .side = .remote,
            .path = "/srv/app/out.bin",
            .sha256 = "0000ffff",
            .verification_method = "sha256sum => 0000ffff",
        } },
        .operator_override => .{ .operator_override = .{ .reason = "checked by hand", .by = "tester" } },
    };
}

/// The admissibility matrix, transcribed independently of the implementation.
///
/// That is the whole point of it: a second statement of the same table, so a
/// cell cannot be widened in `receipts.zig` alone. Both switches are exhaustive
/// and neither has a default arm, so a new `operations.Kind` or a new evidence
/// variant is a compile error in both places until somebody writes down what it
/// may settle.
///
/// Two rows of the table are refusals rather than routings, and they are the
/// ones a future change is most likely to undo by accident:
///
///  * `supervisor_report` is refused for **every** kind. It is the only
///    mechanical variant with no identity binding at all — a status and a
///    sentence, nothing tying either to the attempt it is handed to — while
///    `isMechanical` grades it mechanical, the grade that releases a scope
///    barrier with no operator in the loop. Nothing constructs one, so the
///    refusal costs no reachable route. `receipts.appliesToKind` names what a
///    producer must supply before any cell here may go back to `true`.
///  * `process_probe` is admitted for `exec` and refused for `job`. A job runs
///    in its own tmux session, so the pid on its trail is the *pane's*
///    (`Tmux.panePid`), not the job's process: a probe of it is a reading about
///    one process being used to settle another. A job has two evidence chains
///    addressed to it — `job_sentinel` and `job_result` — so nothing is lost.
fn pinnedCell(kind: Store.operations.Kind, tag: EvidenceTag) bool {
    return switch (kind) {
        // One supervised remote command, and the only kind that records the
        // pid and start token of the process that ran it. It has no job
        // wrapper and publishes no declared file.
        .exec => switch (tag) {
            .process_probe, .operator_override => true,
            .supervisor_report,
            .job_sentinel,
            .job_result,
            .filesystem_effect,
            .destination_absent,
            .destination_present_unverified,
            .destination_present_contradicting,
            => false,
        },
        // The two records the job wrapper writes, and nothing about a process:
        // the only pid a job ever recorded belongs to its pane.
        .job => switch (tag) {
            .job_sentinel, .job_result, .operator_override => true,
            .supervisor_report,
            .process_probe,
            .filesystem_effect,
            .destination_absent,
            .destination_present_unverified,
            .destination_present_contradicting,
            => false,
        },
        // A transfer's outcome is a fact about a file at a declared
        // destination — that it is there and right, that it is there and
        // wrong, that it is there and uncheckable, or that it is not there.
        // Every claim about a *process* is refused, however authoritative its
        // source: exit 0 from a copier that never renamed is still exit 0.
        .transfer_push, .transfer_pull, .fetch => switch (tag) {
            .filesystem_effect,
            .destination_absent,
            .destination_present_unverified,
            .destination_present_contradicting,
            .operator_override,
            => true,
            .supervisor_report, .process_probe, .job_sentinel, .job_result => false,
        },
        // Nothing creates these yet, so no mechanism produces evidence about
        // one. The operator route stays open so the first one is not born
        // stuck.
        .tunnel, .plan_phase, .audit, .cleanup => switch (tag) {
            .operator_override => true,
            .supervisor_report,
            .process_probe,
            .job_sentinel,
            .job_result,
            .filesystem_effect,
            .destination_absent,
            .destination_present_unverified,
            .destination_present_contradicting,
            => false,
        },
    };
}

test "gate: every kind × evidence cell is decided, and none of them by default" {
    const t = std.testing;

    // `appliesToKind` used to end in `else => true`: every kind it did not name
    // admitted every kind of evidence, and every kind added later inherited
    // that. Widening a cell is a decision about what may release the scope
    // barrier, so it has to be made twice, out loud — here and in the store.
    inline for (@typeInfo(Store.operations.Kind).@"enum".fields) |kind_field| {
        const kind: Store.operations.Kind = @field(Store.operations.Kind, kind_field.name);
        inline for (@typeInfo(EvidenceTag).@"enum".fields) |evidence_field| {
            const tag: EvidenceTag = @field(EvidenceTag, evidence_field.name);
            const got = sampleEvidence(tag).appliesToKind(kind);
            const pinned = pinnedCell(kind, tag);
            if (got != pinned) {
                std.debug.print(
                    "cell {s} x {s}: the store says {}, the pinned matrix says {}\n",
                    .{ kind_field.name, evidence_field.name, got, pinned },
                );
                return error.MatrixCellChanged;
            }
        }
    }

    // Six rules the two tables must not be able to agree to lose, stated a
    // third time and from the other direction — as a property of the kind
    // rather than as a row.
    for (std.enums.values(Store.operations.Kind)) |kind| {
        const publishes_a_declared_file = switch (kind) {
            .transfer_push, .transfer_pull, .fetch => true,
            else => false,
        };
        try t.expectEqual(publishes_a_declared_file, sampleEvidence(.filesystem_effect).appliesToKind(kind));
        // All three readings of a destination travel together: a kind that can
        // be told its artifact is there must be tellable that it is not and
        // that it is the wrong one, or some of its outcomes have no evidence
        // that can express them. That is not a tidiness rule — each of the
        // three was added because a parked publish with that answer had no
        // route out and held its destination forever.
        try t.expectEqual(publishes_a_declared_file, sampleEvidence(.destination_absent).appliesToKind(kind));
        try t.expectEqual(
            publishes_a_declared_file,
            sampleEvidence(.destination_present_unverified).appliesToKind(kind),
        );
        try t.expectEqual(
            publishes_a_declared_file,
            sampleEvidence(.destination_present_contradicting).appliesToKind(kind),
        );
        try t.expectEqual(kind == .job, sampleEvidence(.job_result).appliesToKind(kind));
        try t.expectEqual(kind == .job, sampleEvidence(.job_sentinel).appliesToKind(kind));
        // A probe is a reading of a pid, so it may only speak for a kind that
        // records the pid of the process that did the work. `exec` does; a job
        // records its *pane's* pid, which is a different process, and admitting
        // it there let "the pane is gone" mean "the job was cancelled" while a
        // daemonized child ran on.
        try t.expectEqual(kind == .exec, sampleEvidence(.process_probe).appliesToKind(kind));
        // A supervisor's report speaks for nothing at all until a producer
        // exists that binds it to the attempt it is offered against. It is the
        // only mechanical variant with no identity check in `resolve`, and
        // mechanical is the grade that releases a scope barrier unattended.
        try t.expect(!sampleEvidence(.supervisor_report).appliesToKind(kind));
        // Every kind keeps its escape hatch. A kind with no admissible
        // evidence at all would hold its scope forever with no way out, which
        // is the trap `request reconcile` exists to prevent — and with the two
        // refusals above, four of the nine kinds now have this as their only
        // admissible evidence.
        try t.expect(sampleEvidence(.operator_override).appliesToKind(kind));
    }
}

test "gate: a report about a process cannot settle a transfer" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_process_evidence_kind");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    const rid = testId("procpush");
    const request_id: []const u8 = &rid;

    try seedTransferBeforeSubmit(&store, request_id);
    const checkpoint = try Store.transfers.create(&store, .{
        .request_id = request_id,
        .direction = .push,
        .dest_side = .{ .server = 1 },
        .dest_path = "/srv/app/out.bin",
        .partial_path = "/srv/app/out.bin.terminus-part",
        .source = .{ .local_file = .{ .path = "./out.bin" } },
        .chunk_size = 1 << 20,
        .now = 102,
    });
    try Store.transfers.recordExpectedHash(&store, checkpoint, request_id, "abc", 103);
    try Store.operations.advance(&store, request_id, .submitted, 104);
    _ = try Store.receipts.settle(
        &store,
        request_id,
        op_state.terminalForTransportLoss(.submitted, "eof"),
        .{},
        200,
    );

    // The most dangerous cell in the matrix, back when it was a cell rather
    // than a blanket refusal. A supervisor report carries the status it
    // reports, so `supports` waves it straight through to `completed` — for a
    // transfer that would be a verdict of "the bytes landed" reached without
    // anybody reading the destination, past the digest comparison every other
    // route to that verdict has to pass. It is now refused for every kind (see
    // the gate on binding), and this assertion is kept because the transfer
    // reason is a different one and outlives it: even a report bound to its
    // attempt beyond doubt would still be a claim about a process.
    const by_report = try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .supervisor_report = .{ .reported = .completed, .detail = "the copier exited 0" },
    }, 300);
    try t.expectEqualStrings("transfer_push", by_report.evidence_wrong_kind.operation_kind);
    try t.expectEqualStrings("supervisor_report", by_report.evidence_wrong_kind.evidence_kind);

    // A probe is refused for the same reason one step further down: "it is no
    // longer running" is equally true of a copier that finished and one that
    // died halfway through its rename.
    //
    // The identity check runs before the kind check, so a transfer with no
    // recorded process would be refused as a reading of somebody else's and
    // this half of the gate would pass without testing the cell at all.
    // Nothing writes a process identity onto a transfer today; the gate writes
    // one so that the *kind* rule is what refuses — and so that the day a
    // transfer does record one, this is the cell that says no.
    try recordProcess(&store, request_id, 5150, "boot+5150", 301);
    const by_probe = try Store.receipts.resolve(&store, arena, request_id, .cancelled, .{
        .process_probe = .{ .pid = 5150, .start_token = "boot+5150", .alive = false },
    }, 302);
    try t.expectEqualStrings("transfer_push", by_probe.evidence_wrong_kind.operation_kind);
    try t.expectEqualStrings("process_probe", by_probe.evidence_wrong_kind.evidence_kind);

    // Neither refusal recorded anything.
    try t.expectEqual(
        @as(?op_state.ResolvedStatus, null),
        (try Store.operations.get(&store, arena, request_id)).?.resolved_status,
    );
    try t.expectEqual(@as(usize, 0), try countKind(&store, arena, request_id, "reconcile"));

    // The control that keeps the two refusals from being satisfied by refusing
    // everything: the evidence a transfer does produce still settles it.
    //
    // Driven to `published` first, and that is not scene-setting. A digest
    // match binds a reading to this transfer's *declaration* and says nothing
    // about whether this transfer ever put anything at that path, so
    // `filesystem_effect` also asks whether the checkpoint's own record leaves
    // room for it to have done — see `State.renameMayHaveLanded`. Against the
    // `planned` row this control used to use, the reading was settling
    // `completed` for a transfer that had not moved a byte.
    try driveToPublished(&store, checkpoint, request_id, "abc");
    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .filesystem_effect = .{ .side = .remote, .path = "/srv/app/out.bin", .sha256 = "abc" },
    }, 310)) == .resolved);
}

test "gate: a probe settles only the process the attempt recorded" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_probe_identity");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    const rid = testId("probe");
    const request_id: []const u8 = &rid;
    // An `exec`, because that is the only kind a probe may speak for at all:
    // it is the one that records the pid and start token of the process that
    // ran the command. Run against a `job` these calls are refused by kind
    // before the identity rules this gate is about are ever consulted.
    try seedOperationOfKind(&store, request_id, .exec);
    _ = try Store.receipts.settle(
        &store,
        request_id,
        op_state.terminalForTransportLoss(.submitted, "eof"),
        .{},
        200,
    );

    // Nothing may survive a refusal: not the resolution, and not a reconcile
    // event that would make the trail read as though one had been attempted and
    // judged. "Refused" has to mean nothing was recorded.
    const nothingRecorded = struct {
        fn check(s: *Store, a: std.mem.Allocator, id: []const u8) !void {
            try std.testing.expectEqual(
                @as(?op_state.ResolvedStatus, null),
                (try Store.operations.get(s, a, id)).?.resolved_status,
            );
            try std.testing.expectEqual(@as(usize, 0), try countKind(s, a, id, "reconcile"));
        }
    }.check;

    // An attempt that never recorded a process is one no probe can speak
    // about, exactly as a transfer with no declared digest is one no file hash
    // can speak about. Waving it through — there being nothing to contradict —
    // would make the check vacuous precisely where it matters: an attempt whose
    // process was never identified is the one nobody can go and look for.
    const unidentified = try Store.receipts.resolve(&store, arena, request_id, .cancelled, .{
        .process_probe = .{ .pid = 5150, .start_token = "boot+5150", .alive = false },
    }, 300);
    try t.expectEqual(@as(?Store.receipts.RecordedProcess, null), unidentified.evidence_wrong_process.recorded);
    try t.expectEqual(@as(i64, 5150), unidentified.evidence_wrong_process.probed_pid);
    try nothingRecorded(&store, arena, request_id);

    try recordProcess(&store, request_id, 5150, "boot+5150", 305);

    // A probe of some other process settles nothing here. Before this check
    // existed, any dead pid on any host released any operation's scope barrier.
    const other_pid = try Store.receipts.resolve(&store, arena, request_id, .cancelled, .{
        .process_probe = .{ .pid = 6001, .start_token = "boot+6001", .alive = false },
    }, 310);
    try t.expectEqual(@as(i64, 6001), other_pid.evidence_wrong_process.probed_pid);
    try t.expectEqual(@as(i64, 5150), other_pid.evidence_wrong_process.recorded.?.pid);
    try nothingRecorded(&store, arena, request_id);

    // The right pid and the wrong start token is the recycled-pid case, which
    // is the entire reason the token is recorded: the kernel handed 5150 to
    // something else, and that something else being dead says nothing about our
    // work.
    const recycled = try Store.receipts.resolve(&store, arena, request_id, .cancelled, .{
        .process_probe = .{ .pid = 5150, .start_token = "boot+9999", .alive = false },
    }, 311);
    try t.expectEqual(@as(i64, 5150), recycled.evidence_wrong_process.recorded.?.pid);
    try t.expectEqualStrings("boot+5150", recycled.evidence_wrong_process.recorded.?.start_token.?);
    try t.expectEqualStrings("boot+9999", recycled.evidence_wrong_process.probed_start_token.?);
    try nothingRecorded(&store, arena, request_id);

    // A probe that could not read a token at all is the same hole with the
    // evidence missing rather than wrong. Admitting it would leave the recorded
    // token as decoration: anyone who skipped reading it would be trusted.
    const tokenless = try Store.receipts.resolve(&store, arena, request_id, .cancelled, .{
        .process_probe = .{ .pid = 5150, .alive = false },
    }, 312);
    try t.expectEqual(@as(?[]const u8, null), tokenless.evidence_wrong_process.probed_start_token);
    try nothingRecorded(&store, arena, request_id);

    // And the arm that actually releases the barrier, which nothing exercised
    // before: this attempt's own pid, this attempt's own start token, and the
    // process is gone.
    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .cancelled, .{
        .process_probe = .{ .pid = 5150, .start_token = "boot+5150", .alive = false },
    }, 320)) == .resolved);
    const op = (try Store.operations.get(&store, arena, request_id)).?;
    try t.expectEqual(op_state.ResolvedStatus.cancelled, op.resolved_status.?);
    try t.expectEqual(op_state.Status.indeterminate, op.status); // the observation is kept
    try t.expect(!op.effectiveStatus().blocksScope());
    try t.expectEqual(@as(usize, 0), (try Store.operations.unsettled(&store, arena, 1)).len);
    try t.expectEqual(@as(usize, 1), try countKind(&store, arena, request_id, "reconcile"));
}

test "gate: an attempt that never read a start token is judged on its pid" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_probe_weak_identity");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    const rid = testId("weakid");
    const request_id: []const u8 = &rid;
    try seedOperationOfKind(&store, request_id, .exec);
    _ = try Store.receipts.settle(
        &store,
        request_id,
        op_state.terminalForTransportLoss(.submitted, "eof"),
        .{},
        200,
    );

    // Shell mode cannot always read a process start time, and records the pid
    // alone (`supervisor.Capability.pid_proof == .weak`). The pid is then the
    // whole of what this attempt ever knew about its own process, so it is the
    // whole of what a probe can be checked against — refusing every probe here
    // would make the weak supervisor unreconcilable by the only mechanical
    // route it has.
    //
    // The asymmetry is the point, and it is not symmetric by accident: a
    // recorded token the probe did not read is refused (above), because there
    // the attempt knew something the probe declined to check.
    try recordProcess(&store, request_id, 5150, null, 205);

    // With no recorded token there is nothing else left to refuse on, so this
    // is where the pid comparison is on its own. In the gate above a wrong pid
    // also carries a wrong token, and either conjunct alone would refuse it —
    // delete the pid comparison there and that gate still passes.
    const wrong_pid = try Store.receipts.resolve(&store, arena, request_id, .cancelled, .{
        .process_probe = .{ .pid = 6001, .alive = false },
    }, 210);
    try t.expectEqual(@as(i64, 6001), wrong_pid.evidence_wrong_process.probed_pid);
    try t.expectEqual(@as(i64, 5150), wrong_pid.evidence_wrong_process.recorded.?.pid);
    try t.expectEqual(@as(?[]const u8, null), wrong_pid.evidence_wrong_process.recorded.?.start_token);
    try t.expectEqual(
        @as(?op_state.ResolvedStatus, null),
        (try Store.operations.get(&store, arena, request_id)).?.resolved_status,
    );
    try t.expectEqual(@as(usize, 0), try countKind(&store, arena, request_id, "reconcile"));

    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .cancelled, .{
        .process_probe = .{ .pid = 5150, .start_token = "boot+5150", .alive = false },
    }, 300)) == .resolved);
    try t.expectEqual(
        op_state.ResolvedStatus.cancelled,
        (try Store.operations.get(&store, arena, request_id)).?.resolved_status.?,
    );

    // Admitted — and the receipt has to say on what. The probe volunteered a
    // token here and it was compared with nothing, because this attempt never
    // recorded one; grading the match by what the *probe* offered would let a
    // caller strengthen its own evidence by filling in a field. So the binding
    // is read off the recorded identity, and it is `pid_only`: a pid this
    // attempt used and the kernel is free to reissue.
    //
    // Without this the trail could not tell an admitted pid-only match from a
    // pid+token one, and the scope barrier is lifted on the strength of exactly
    // that difference.
    const trail = try Store.receipts.list(&store, arena, request_id);
    const reconcile = trail[trail.len - 1].detail_json.?;
    try t.expectEqualStrings("reconcile", trail[trail.len - 1].kind);
    try t.expect(std.mem.indexOf(u8, reconcile, "\"probeIdentity\":\"pid_only\"") != null);
}

test "gate: a probe backed by a recorded token is not filed as a pid-only match" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_probe_binding_strong");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    const rid = testId("strongid");
    const request_id: []const u8 = &rid;
    try seedOperationOfKind(&store, request_id, .exec);
    _ = try Store.receipts.settle(
        &store,
        request_id,
        op_state.terminalForTransportLoss(.submitted, "eof"),
        .{},
        200,
    );

    // The ordinary case on a host that can read a process start time:
    // `supervisor.wrapShell` reads it out of `/proc/<pid>/stat` or `ps -o
    // lstart=`, and `execution.remoteStarted` writes it onto the trail. The
    // field is not decoration — the pid-only reading above is the *fallback*,
    // not the norm — and the receipt has to distinguish the two or recording it
    // buys nothing.
    try recordProcess(&store, request_id, 5150, "boot+5150", 205);
    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .cancelled, .{
        .process_probe = .{ .pid = 5150, .start_token = "boot+5150", .alive = false },
    }, 210)) == .resolved);

    const trail = try Store.receipts.list(&store, arena, request_id);
    const reconcile = trail[trail.len - 1].detail_json.?;
    try t.expect(std.mem.indexOf(u8, reconcile, "\"probeIdentity\":\"pid_and_start_token\"") != null);
    try t.expect(std.mem.indexOf(u8, reconcile, "pid_only") == null);
}

test "gate: an identity the attempt proved cannot be forgotten by a later event" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_probe_identity_monotone");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    const rid = testId("keepsid");
    const request_id: []const u8 = &rid;
    try seedOperationOfKind(&store, request_id, .exec);
    _ = try Store.receipts.settle(
        &store,
        request_id,
        op_state.terminalForTransportLoss(.submitted, "eof"),
        .{},
        200,
    );

    // The attempt read a start time for its process, and then wrote a later
    // event about the same pid that did not carry one. `remote_pid` and
    // `remote_start_token` are independently optional on every writer — a
    // `remote_cancel_confirmed` fills each from `extra.x orelse c.x` on its own
    // — so this shape needs no misuse to occur, only a caller that had the pid
    // to hand and not the token.
    try recordProcess(&store, request_id, 5150, "boot+5150", 205);
    try recordProcess(&store, request_id, 5150, null, 206);

    // Reading the identity off the newest pid-bearing row alone would answer
    // "pid 5150, no token" here, and a probe that could not read a start time
    // would then be admitted — releasing the scope barrier on the strength of a
    // pid, for an attempt that had already demonstrated it could do better. The
    // token is read back for that pid instead, so the binding only ever
    // strengthens.
    const forgetful = try Store.receipts.resolve(&store, arena, request_id, .cancelled, .{
        .process_probe = .{ .pid = 5150, .alive = false },
    }, 210);
    // The tag first: reading the payload of a refusal that did not happen
    // panics on the union, and a regression here should say which outcome it
    // got rather than which field was active.
    try t.expectEqual(
        @as(std.meta.Tag(Store.receipts.ResolveOutcome), .evidence_wrong_process),
        std.meta.activeTag(forgetful),
    );
    try t.expectEqualStrings("boot+5150", forgetful.evidence_wrong_process.recorded.?.start_token.?);
    try t.expectEqual(@as(?[]const u8, null), forgetful.evidence_wrong_process.probed_start_token);
    try t.expectEqual(
        @as(?op_state.ResolvedStatus, null),
        (try Store.operations.get(&store, arena, request_id)).?.resolved_status,
    );
    try t.expectEqual(@as(usize, 0), try countKind(&store, arena, request_id, "reconcile"));

    // A token belonging to a *different* pid is still not this pid's. The
    // lookup is keyed on the pid it came back with, so an unrelated process on
    // the same trail cannot lend it one.
    try recordProcess(&store, request_id, 7000, "boot+7000", 211);
    const other = try Store.receipts.resolve(&store, arena, request_id, .cancelled, .{
        .process_probe = .{ .pid = 7000, .start_token = "boot+5150", .alive = false },
    }, 212);
    try t.expectEqualStrings("boot+7000", other.evidence_wrong_process.recorded.?.start_token.?);

    // And the probe that did read the right token still settles it.
    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .cancelled, .{
        .process_probe = .{ .pid = 7000, .start_token = "boot+7000", .alive = false },
    }, 213)) == .resolved);
}

test "gate: a supervisor report settles nothing until something binds it to an attempt" {
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
    // cannot be chosen independently. This half is about `supports`, which runs
    // before the kind check and is a property of the variant rather than of
    // where it is aimed, so it survives the refusal below unchanged.
    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .completed, .{
        .supervisor_report = .{ .reported = .timed_out, .detail = "deadline hit" },
    }, 400)) == .evidence_does_not_support);

    // And the pairing that used to settle it now does not, on the one kind that
    // was its strongest case: an `exec` is a single supervised remote command,
    // so its supervisor's report really is a statement about the whole of it.
    // It is refused anyway, because nothing ties *this* report to *this*
    // attempt. Every other mechanical variant carries something `resolve`
    // checks against a fact the store wrote down first — a request id in the
    // document, a pid and start token on the trail, a side, path and digest
    // committed to before submission — and this one carries a status and a
    // sentence. `isMechanical` grades it mechanical all the same, which is the
    // grade that releases the same-scope mutation barrier with no operator in
    // the loop, so until a producer exists that binds identity the cell is a
    // permit nobody can be held to.
    const unbound = try Store.receipts.resolve(&store, arena, request_id, .timed_out, .{
        .supervisor_report = .{ .reported = .timed_out, .detail = "deadline hit" },
    }, 401);
    try t.expectEqualStrings("exec", unbound.evidence_wrong_kind.operation_kind);
    try t.expectEqualStrings("supervisor_report", unbound.evidence_wrong_kind.evidence_kind);

    // Refused everywhere, not merely here. Stated as a property so a single
    // cell going back to `true` cannot be hidden behind a gate that only ever
    // looked at one kind.
    for (std.enums.values(Store.operations.Kind)) |kind| {
        const report: Store.receipts.ResolutionEvidence = .{
            .supervisor_report = .{ .reported = .completed, .detail = "the wrapper reported an exit" },
        };
        try t.expect(!report.appliesToKind(kind));
    }

    // The refusal recorded nothing, and the attempt is still settleable — by an
    // operator, which is the honest description of what an unbound report is
    // worth. Without this control the gate above would be satisfied by an
    // operation that refuses everything.
    try t.expectEqual(
        @as(?op_state.ResolvedStatus, null),
        (try Store.operations.get(&store, arena, request_id)).?.resolved_status,
    );
    try t.expectEqual(@as(usize, 0), try countKind(&store, arena, request_id, "reconcile"));
    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .timed_out, .{
        .operator_override = .{ .reason = "the wrapper's log says it hit the deadline", .by = "tester" },
    }, 402)) == .resolved);
}

test "gate: a job is not settled by a reading of its pane's process" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "gate_job_probe_refused");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    const rid = testId("panepid");
    const request_id: []const u8 = &rid;
    try seedOperationOfKind(&store, request_id, .job);
    // The launch record, for the same reason `recordProcess` below writes the
    // process identity: the closing assertion of this gate is that a job's
    // *other* evidence chain still settles it, and a sentinel no launch
    // recorded is not that chain — it is an unaddressed string. Seeding this is
    // what makes the last line prove the sentence the comment above it claims.
    try recordLaunchSentinel(&store, request_id, "race", "panepid", "__TERMINUS_JOB_1__", 100);
    _ = try Store.receipts.settle(
        &store,
        request_id,
        op_state.terminalForTransportLoss(.submitted, "eof"),
        .{},
        200,
    );

    // The identity a job actually records. `cmd_job` launches into a tmux
    // session and reports `Tmux.panePid` — the pane's pid, and no start token,
    // because a pane does not have one to read. Written the way `cmd_job`
    // writes it, so the gate is about the shape that exists rather than an
    // invented one.
    try recordProcess(&store, request_id, 4242, null, 210);

    // A probe of exactly that pid, correct in every way a probe can be checked:
    // it is the identity on the trail, so `evidence_wrong_process` does not
    // fire, and `supports` admits "gone therefore cancelled". While this cell
    // was open, that was enough — pane gone, `cancelled`, scope released, and a
    // command that daemonized or ran under `setsid` still running on the host.
    // The refusal is by *kind*, which is where it belongs: the pane is not the
    // job's process, so no reading of it is a reading of this operation however
    // carefully it is taken.
    const by_pane = try Store.receipts.resolve(&store, arena, request_id, .cancelled, .{
        .process_probe = .{ .pid = 4242, .alive = false },
    }, 220);
    try t.expectEqualStrings("job", by_pane.evidence_wrong_kind.operation_kind);
    try t.expectEqualStrings("process_probe", by_pane.evidence_wrong_kind.evidence_kind);
    try t.expectEqual(
        @as(?op_state.ResolvedStatus, null),
        (try Store.operations.get(&store, arena, request_id)).?.resolved_status,
    );
    try t.expectEqual(@as(usize, 0), try countKind(&store, arena, request_id, "reconcile"));

    // Nothing was taken away: a job has two evidence chains addressed to it,
    // and either still settles it. That is why refusing the probe costs the job
    // no route — unlike an `exec`, whose recorded pid *is* the command's.
    try t.expect((try Store.receipts.resolve(&store, arena, request_id, .failed, .{
        .job_sentinel = .{ .sentinel = "__TERMINUS_JOB_1__", .exit_code = 4 },
    }, 230)) == .resolved);
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

/// Settles the attempt that owns a checkpoint, which is what makes the
/// checkpoint adoptable at all.
///
/// `transfers.adoptLocked` refuses to take a checkpoint from an attempt that
/// may still be affecting the remote host: two live processes appending to one
/// partial is the failure that rule exists to stop. `local_abandon` is the
/// evidence that fits an attempt still at `created` or `connecting` — nothing
/// was handed over, so there is no remote absence to verify — and it settles
/// `cancelled`, which does not block scope.
fn abandonOwner(store: *Store, request_id: []const u8, reason: []const u8, now: i64) !void {
    _ = try Store.receipts.settle(
        store,
        request_id,
        .{ .local_abandon = .{ .reason = reason } },
        .{},
        now,
    );
}

/// A transfer operation and its checkpoint, aimed wherever the caller says.
///
/// The transition gates below all need the same three lines of setup and care
/// about nothing in it, so it lives here rather than five times over.
fn seedCheckpoint(
    store: *Store,
    request_id: []const u8,
    dest_path: []const u8,
    partial_path: []const u8,
) !i64 {
    store.db.exec(
        \\INSERT INTO servers (id, name, host, port, username, created_at, updated_at)
        \\VALUES (1, 'race', '10.0.0.1', 22, 'ubuntu', 100, 100);
    ) catch |err| switch (err) {
        // A test seeding a second operation shares the first one's server.
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
    return Store.transfers.create(store, .{
        .request_id = request_id,
        .direction = .push,
        .dest_side = .{ .server = 1 },
        .dest_path = dest_path,
        .partial_path = partial_path,
        // Carries a content hash so a confirmed offset is storable: from v11 a
        // non-zero offset may only be recorded against an identifiable source.
        .source = .{ .local_file = .{ .path = "./out.bin", .sha256 = "aaaa" } },
        .chunk_size = 100,
        .now = 100,
    });
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

/// Walks an existing checkpoint the whole legal way to `published`, hashing its
/// result on the way past.
///
/// For gates whose subject is something else and which need a transfer that
/// *did* deliver. A checkpoint left in `planned` is not that: nothing has moved,
/// the destination is still only a claim, and `filesystem_effect` is refused
/// there because a digest match proves the reading is of the promised artifact
/// and not that this transfer put it where it is.
fn driveToPublished(
    store: *Store,
    id: i64,
    request_id: []const u8,
    sha256: []const u8,
) !void {
    var clock: i64 = 150;
    for ([_]Store.transfers.State{ .probing, .transferring, .verifying }) |step| {
        clock += 1;
        try Store.transfers.setState(store, id, request_id, step, null, clock);
    }
    try Store.transfers.recordVerifiedHash(store, id, request_id, sha256, clock + 1);
    try Store.transfers.setState(store, id, request_id, .publishing, null, clock + 2);
    try Store.transfers.setState(store, id, request_id, .published, null, clock + 3);
}

/// A push whose rename was issued and never confirmed: the checkpoint is parked
/// in `indeterminate_publish` and its operation is `indeterminate`, which is
/// the only pairing `receipts.resolve` will look at.
/// The digest is declared before submission and read back while verifying,
/// because that is what a real transfer does and what `published` demands. A
/// checkpoint that never hashed its own result cannot be adjudicated published
/// however good the evidence about the rename is — adjudication is the last
/// word on whether the rename landed, not on what the bytes were.
fn seedUnjudgedPublish(
    store: *Store,
    request_id: []const u8,
    dest_path: []const u8,
    partial_path: []const u8,
    sha256: []const u8,
) !i64 {
    return seedUnjudgedPublishDigests(store, request_id, dest_path, partial_path, sha256, sha256);
}

/// `seedUnjudgedPublish` with the two digest columns chosen independently.
///
/// The difference between the three combinations is the entire subject of the
/// wedge gates below, and it is one column each time. A transfer walks the same
/// edges to `indeterminate_publish` whether or not it declared a digest and
/// whether or not it lived long enough to record one; what a reconciler may then
/// conclude about it is completely different in the three cases, and a seed that
/// always fills both columns can only ever exercise the easiest of them.
fn seedUnjudgedPublishDigests(
    store: *Store,
    request_id: []const u8,
    dest_path: []const u8,
    partial_path: []const u8,
    declared: ?[]const u8,
    verified: ?[]const u8,
) !i64 {
    try seedTransferOperation(store, request_id, .transfer_push, 1);
    const id = try Store.transfers.create(store, .{
        .request_id = request_id,
        .direction = .push,
        .dest_side = .{ .server = 1 },
        .dest_path = dest_path,
        .partial_path = partial_path,
        .source = .{ .local_file = .{ .path = "./out.bin" } },
        .chunk_size = 100,
        .now = 110,
    });
    if (declared) |sha| try Store.transfers.recordExpectedHash(store, id, request_id, sha, 111);
    try Store.operations.advance(store, request_id, .submitted, 112);
    var clock: i64 = 112;
    for ([_]Store.transfers.State{ .probing, .transferring, .verifying }) |step| {
        clock += 1;
        try Store.transfers.setState(store, id, request_id, step, null, clock);
    }
    if (verified) |sha| try Store.transfers.recordVerifiedHash(store, id, request_id, sha, 120);
    try Store.transfers.setState(store, id, request_id, .publishing, null, 121);
    try Store.transfers.setState(store, id, request_id, .indeterminate_publish, "the rename never reported", 122);
    _ = try Store.receipts.settle(store, request_id, .{ .indeterminate = .{
        .reason = "the connection dropped after the rename was issued",
        .last_observed = .submitted,
    } }, .{}, 123);
    return id;
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
    // operator already pays for a resume: `request reconcile --from-log` finds
    // the exit status the job left behind.
    _ = try Store.receipts.settle(&store, request_id, .{ .exited = .{ .exit_code = 1 } }, .{}, 210);

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
    _ = try Store.receipts.settle(&store, request_id, .{ .exited = .{ .exit_code = 1 } }, .{}, 210);

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
    _ = try Store.receipts.settle(&store, request_id, .{ .exited = .{ .exit_code = 1 } }, .{}, 140);
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
    _ = try Store.receipts.settle(&store, request_id, .{ .exited = .{ .exit_code = 1 } }, .{}, 210);

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
    try Store.transfers.setState(&store, id, heir.id(), .probing, null, 300);
    try Store.transfers.setState(&store, id, heir.id(), .failed_no_space, "the disk filled", 301);
    try Store.operations.advance(&store, heir.id(), .connecting, 302);
    try Store.operations.advance(&store, heir.id(), .submitted, 303);
    _ = try Store.receipts.settle(&store, heir.id(), .{ .exited = .{ .exit_code = 1 } }, .{}, 304);

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
    _ = try Store.receipts.settle(&store, request_id, .{ .exited = .{ .exit_code = 1 } }, .{}, 210);

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
    _ = try Store.receipts.settle(&store, request_id, .{ .exited = .{ .exit_code = 1 } }, .{}, 210);

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

/// A transfer-shaped operation parked at `connecting`, of whatever kind and on
/// whatever server the caller needs — including none, for a `fetch`.
///
/// Two servers exist so a gate can aim a checkpoint at a machine its operation
/// is not bound to, which is the mismatch that has no single-table constraint
/// to catch it. They are inserted one statement at a time: a gate that already
/// seeded server 1 through another helper would otherwise have its duplicate
/// tolerated and server 2 silently skipped along with it.
fn seedTransferOperation(
    store: *Store,
    request_id: []const u8,
    kind: Store.operations.Kind,
    server_id: ?i64,
) !void {
    for ([_][:0]const u8{
        \\INSERT INTO servers (id, name, host, port, username, created_at, updated_at)
        \\VALUES (1, 'race', '10.0.0.1', 22, 'ubuntu', 100, 100);
        ,
        \\INSERT INTO servers (id, name, host, port, username, created_at, updated_at)
        \\VALUES (2, 'race2', '10.0.0.2', 22, 'ubuntu', 100, 100);
        ,
    }) |sql| store.db.exec(sql) catch |err| switch (err) {
        // A test seeding a second operation shares the first one's servers.
        error.Constraint => {},
        else => return err,
    };
    try Store.operations.create(store, .{
        .request_id = request_id,
        .server_id = server_id,
        .server_name = if (server_id == null) "local" else "race",
        .kind = kind,
        .now = 100,
    });
    try Store.operations.advance(store, request_id, .connecting, 101);
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

/// Settles `request_id` into `want`, with evidence that legitimately produces
/// it.
///
/// All five terminals are reachable from `submitted`, which is also the state a
/// killed transfer is really left in, so one route serves them all. Exhaustive
/// over `Status`: a new terminal has to be given a route here rather than
/// quietly dropping out of the loop below and leaving its arm unproven.
fn settleInto(store: *Store, request_id: []const u8, comptime want: op_state.Status, now: i64) !void {
    try Store.operations.advance(store, request_id, .connecting, now);
    try Store.operations.advance(store, request_id, .submitted, now);
    const terminal: op_state.Terminal = switch (want) {
        .completed => .{ .exited = .{ .exit_code = 0 } },
        .failed => .{ .exited = .{ .exit_code = 1 } },
        .timed_out => .{ .remote_deadline = .{ .after_ms = 5 } },
        .cancelled => .{ .remote_cancel_confirmed = .{
            .term_sent = true,
            .kill_sent = false,
            .absence_verified_at = now,
            .verification_method = "kill -0 => ESRCH",
        } },
        .indeterminate => .{ .indeterminate = .{
            .reason = "the connection dropped",
            .last_observed = .submitted,
        } },
        else => @compileError("not a terminal status: " ++ @tagName(want)),
    };
    _ = try Store.receipts.settle(store, request_id, terminal, .{}, now);
}

/// Drives `request_id` to `want` by the route a real attempt takes to it.
///
/// Exhaustive over `Status` — through `settleInto` for the terminals — so a new
/// status has to be given a route rather than dropping silently out of the walk
/// below and leaving its cell unproven.
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

/// How many events of one kind the ledger holds for a request.
fn countKind(
    store: *Store,
    arena: std.mem.Allocator,
    request_id: []const u8,
    kind: []const u8,
) !usize {
    var n: usize = 0;
    for (try Store.receipts.list(store, arena, request_id)) |row| {
        if (std.mem.eql(u8, row.kind, kind)) n += 1;
    }
    return n;
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

/// The `jobs` writers return a refusal rather than an error, so a gate that
/// expected a write to land has to say so itself.
fn mustApply(write: Store.jobs.Write) !void {
    switch (write) {
        .applied => {},
        .refused => return error.JobsWriteRefused,
    }
}

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
    try mustApply(try Store.jobs.remove(&store, running.removeExpectation(), .session_proven_gone));
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
/// Same shape and same reasoning as `RemovalRace`: a file-scope struct because
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
