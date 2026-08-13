//! M2 release gates for the execution boundary.
//!
//! The milestone's acceptance criterion is a single claim: **no path turns a
//! transport failure into a verdict about the remote.** These tests inject a
//! disconnect at each of the four points where that temptation exists —
//! before submission, after submission but before any start confirmation,
//! after the process was confirmed running, and after it finished but before
//! the answer reached us — and assert what the ledger records.
//!
//! Only the first of those is a failure. The other three are `indeterminate`,
//! because the remote may have done the work, and a caller that retries on
//! "failed" would apply it twice.
const std = @import("std");
const Store = @import("store/Store.zig");
const operations = @import("store/operations.zig");
const receipts = @import("store/receipts.zig");
const op_state = @import("store/op_state.zig");
const scope_mod = @import("store/scope.zig");
const execution = @import("execution.zig");
const supervisor = @import("supervisor.zig");
const Scripted = @import("exec.zig").Scripted;

const Harness = struct {
    io: std.Io,
    threaded: *std.Io.Threaded,
    arena_state: *std.heap.ArenaAllocator,
    arena: std.mem.Allocator,
    path: [:0]u8,
    store: Store,
    allocator: std.mem.Allocator,

    const dir = ".zig-cache/tmp";

    fn init(allocator: std.mem.Allocator, name: []const u8) !Harness {
        const threaded = try allocator.create(std.Io.Threaded);
        threaded.* = .init(allocator, .{});
        const io = threaded.io();
        std.Io.Dir.cwd().createDirPath(io, dir) catch {};
        const path = try std.fmt.allocPrintSentinel(allocator, "{s}/{s}.db", .{ dir, name }, 0);

        // WAL sidecars must go with the database; a stale one silently shows
        // an empty view instead of failing.
        const cwd = std.Io.Dir.cwd();
        cwd.deleteFile(io, path) catch {};
        for ([_][]const u8{ "-wal", "-shm" }) |suffix| {
            const side = try std.fmt.allocPrint(allocator, "{s}{s}", .{ path, suffix });
            defer allocator.free(side);
            cwd.deleteFile(io, side) catch {};
        }

        const arena_state = try allocator.create(std.heap.ArenaAllocator);
        arena_state.* = std.heap.ArenaAllocator.init(allocator);

        var store = try Store.open(path);
        try store.db.exec(
            \\INSERT INTO servers (id, name, host, port, username, created_at, updated_at)
            \\VALUES (1, 'box', '10.0.0.1', 22, 'ubuntu', 100, 100);
        );

        return .{
            .io = io,
            .threaded = threaded,
            .arena_state = arena_state,
            .arena = arena_state.allocator(),
            .path = path,
            .store = store,
            .allocator = allocator,
        };
    }

    fn deinit(h: *Harness) void {
        h.store.close();
        const cwd = std.Io.Dir.cwd();
        cwd.deleteFile(h.io, h.path) catch {};
        for ([_][]const u8{ "-wal", "-shm" }) |suffix| {
            const side = std.fmt.allocPrint(h.allocator, "{s}{s}", .{ h.path, suffix }) catch continue;
            defer h.allocator.free(side);
            cwd.deleteFile(h.io, side) catch {};
        }
        h.arena_state.deinit();
        h.allocator.destroy(h.arena_state);
        h.allocator.free(h.path);
        h.threaded.deinit();
        h.allocator.destroy(h.threaded);
    }

    fn begin(h: *Harness, opts: anytype) !execution.Start {
        var options: execution.BeginOptions = .{
            .server_id = 1,
            .server_name = "box",
            .kind = .exec,
            .owner_token = "owner-a",
            .now = 1000,
        };
        inline for (@typeInfo(@TypeOf(opts)).@"struct".fields) |field| {
            @field(options, field.name) = @field(opts, field.name);
        }
        return execution.begin(&h.store, h.arena, h.io, options);
    }

    fn operationOf(h: *Harness, request_id: []const u8) !operations.Operation {
        return (try operations.get(&h.store, h.arena, request_id)).?;
    }

    fn terminalRow(h: *Harness, request_id: []const u8) !receipts.Row {
        const rows = try receipts.list(&h.store, h.arena, request_id);
        for (rows) |row| {
            if (row.is_terminal) return row;
        }
        return error.NoTerminalRecorded;
    }
};

/// Output a shell supervisor produces for a command that ran to completion.
fn completeOutput(arena: std.mem.Allocator, nonce: u64, body: []const u8, code: i32) ![]u8 {
    return std.fmt.allocPrint(
        arena,
        "__TERMINUS_START_{d}__ pid=4242 pgid=4242 token=99\n{s}__TERMINUS_EXIT_{d}__ code={d}\n",
        .{ nonce, body, nonce, code },
    );
}

test "M2 gate: disconnect before submission is a proven failure" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "m2_before_submit");
    defer h.deinit();

    const start = try h.begin(.{});
    var exec = start.ready;
    defer exec.deinit();

    // Dialing failed. Nothing left this machine, so the remote is untouched
    // and `failed` is the honest verdict — this is the *only* disconnect
    // that may be reported as a failure.
    try exec.connecting();
    _ = try exec.transportLoss("connection refused");

    const op = try h.operationOf(exec.id());
    try t.expectEqual(op_state.Status.failed, op.status);

    const terminal = try h.terminalRow(exec.id());
    try t.expectEqualStrings("connecting", terminal.last_observed.?);
    try t.expectEqualStrings("NEVER_SUBMITTED", terminal.error_code.?);
    try t.expectEqual(@as(?bool, false), terminal.remote_started);
    // `connecting` spans dialing and authenticating, so it cannot claim a
    // connection was established.
    try t.expectEqual(@as(?bool, null), terminal.connected);
}

test "M2 gate: disconnect after submission is indeterminate, not failed" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "m2_after_submit");
    defer h.deinit();

    const start = try h.begin(.{});
    var exec = start.ready;
    defer exec.deinit();
    try exec.connecting();

    // The command was handed over and then the channel broke. It may have
    // run. It may have run and finished. We cannot tell.
    var scripted = Scripted.init(h.arena, &.{.{ .transport_error = error.ExecFailed }});
    const outcome = try execution.runCommand(&exec, scripted.executor(), "systemctl restart api");

    try t.expectEqual(op_state.Status.indeterminate, outcome.status);
    try t.expectEqual(@as(?i32, null), outcome.exit_code);

    const op = try h.operationOf(exec.id());
    try t.expectEqual(op_state.Status.indeterminate, op.status);
    // It must keep blocking the scope: retrying a restart that may already
    // have happened is the failure mode this exists to prevent.
    try t.expect(op.status.blocksScope());
    try t.expectEqual(@as(usize, 1), (try operations.unsettled(&h.store, h.arena, 1)).len);

    const terminal = try h.terminalRow(exec.id());
    try t.expectEqualStrings("submitted", terminal.last_observed.?);
    try t.expectEqualStrings("INDETERMINATE", terminal.error_code.?);
}

test "M2 gate: disconnect after the process started is indeterminate" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "m2_after_start");
    defer h.deinit();

    const start = try h.begin(.{});
    var exec = start.ready;
    defer exec.deinit();
    try exec.connecting();

    // The supervisor reported a pid and some output, then the channel closed
    // without an exit marker.
    const truncated = try std.fmt.allocPrint(
        h.arena,
        "__TERMINUS_START_{d}__ pid=5150 pgid=5150 token=771\nmigrating rows",
        .{exec.nonce},
    );
    var scripted = Scripted.init(h.arena, &.{
        .{ .reply = .{ .exit_code = 0, .stdout = truncated, .stderr = "" } },
    });
    const outcome = try execution.runCommand(&exec, scripted.executor(), "./migrate.sh");

    // The channel's own exit code was 0. Reporting that as the command's
    // result is precisely the bug: the command never told us how it ended.
    try t.expectEqual(op_state.Status.indeterminate, outcome.status);
    try t.expectEqual(@as(?i32, null), outcome.exit_code);
    try t.expectEqual(@as(i64, 5150), outcome.identity.?.pid);
    try t.expectEqualStrings("migrating rows", outcome.stdout);

    const terminal = try h.terminalRow(exec.id());
    // We got far enough to see the process, and the trail says so.
    try t.expectEqualStrings("remote_started", terminal.last_observed.?);
    try t.expectEqual(@as(i64, 5150), terminal.remote_pid.?);
    try t.expectEqualStrings("771", terminal.remote_start_token.?);
}

test "M2 gate: a lost response is reconcilable, not guessable" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "m2_lost_response");
    defer h.deinit();

    const start = try h.begin(.{ .kind = .job, .alias = "migrate" });
    var exec = start.ready;
    defer exec.deinit();
    try exec.connecting();

    // The job finished on the remote; the answer never arrived. From here
    // this is indistinguishable from "still running", which is why it is
    // indeterminate rather than a guess in either direction.
    const truncated = try std.fmt.allocPrint(
        h.arena,
        "__TERMINUS_START_{d}__ pid=61 pgid=61 token=5\n",
        .{exec.nonce},
    );
    var scripted = Scripted.init(h.arena, &.{
        .{ .reply = .{ .exit_code = 0, .stdout = truncated, .stderr = "" } },
    });
    _ = try execution.runCommand(&exec, scripted.executor(), "./migrate.sh");
    try t.expectEqual(op_state.Status.indeterminate, (try h.operationOf(exec.id())).status);

    // Later, the durable job sentinel is found and settles the question.
    const resolved = try receipts.resolve(&h.store, h.arena, exec.id(), .completed, .{
        .job_sentinel = .{ .sentinel = "__TERMINUS_JOB_7__", .exit_code = 0 },
    }, 2000);
    try t.expect(resolved == .resolved);

    const op = try h.operationOf(exec.id());
    // The observation is preserved; the proven truth sits beside it.
    try t.expectEqual(op_state.Status.indeterminate, op.status);
    try t.expectEqual(op_state.Status.completed, op.effectiveStatus());
    try t.expect(!op.effectiveStatus().blocksScope());
    try t.expectEqual(@as(usize, 0), (try operations.unsettled(&h.store, h.arena, 1)).len);
}

test "M2 gate: no disconnect anywhere yields a failed verdict" {
    const t = std.testing;

    // Sweep the transport failure across every stage. Only the pre-submission
    // one may read as `failed`; a regression that starts guessing shows up
    // here regardless of which stage it guesses at.
    const stages = [_]op_state.Status{ .created, .connecting, .submitted, .remote_started };
    const expected = [_]op_state.Status{ .failed, .failed, .indeterminate, .indeterminate };

    for (stages, expected, 0..) |stage, want, i| {
        var name_buf: [40]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "m2_sweep_{d}", .{i});
        var h = try Harness.init(t.allocator, name);
        defer h.deinit();

        const start = try h.begin(.{});
        var exec = start.ready;
        defer exec.deinit();

        if (stage != .created) try exec.connecting();
        if (stage == .submitted or stage == .remote_started) try exec.submitted();
        if (stage == .remote_started) try exec.remoteStarted(.{ .pid = 7, .pgid = 7 });

        _ = try exec.transportLoss("channel eof");
        try t.expectEqual(want, (try h.operationOf(exec.id())).status);
    }
}

test "M2 gate: a clean run records identity and the real exit code" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "m2_clean_run");
    defer h.deinit();

    const start = try h.begin(.{});
    var exec = start.ready;
    defer exec.deinit();
    try exec.connecting();

    const stdout = try completeOutput(h.arena, exec.nonce, "ok\n", 3);
    var scripted = Scripted.init(h.arena, &.{
        .{ .reply = .{ .exit_code = 3, .stdout = stdout, .stderr = "" } },
    });
    const outcome = try execution.runCommand(&exec, scripted.executor(), "false");

    try t.expectEqual(op_state.Status.failed, outcome.status);
    try t.expectEqual(@as(i32, 3), outcome.exit_code.?);
    // Supervision markers do not leak into what the caller sees.
    try t.expectEqualStrings("ok\n", outcome.stdout);

    const terminal = try h.terminalRow(exec.id());
    try t.expectEqual(@as(i64, 3), terminal.exit_code.?);
    try t.expectEqualStrings("REMOTE_NONZERO_EXIT", terminal.error_code.?);
    try t.expectEqual(@as(i64, 4242), terminal.remote_pid.?);
    try t.expectEqual(@as(?bool, true), terminal.connected);
}

test "M2 gate: the capability of the supervisor is on the record" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "m2_capability");
    defer h.deinit();

    const start = try h.begin(.{});
    var exec = start.ready;
    defer exec.deinit();

    // A receipt that does not say how the work was supervised cannot be
    // audited: "exit 0" from a shell wrapper and from a real supervisor are
    // not the same claim.
    const op = try h.operationOf(exec.id());
    const capability = op.capability_json.?;
    try t.expect(std.mem.indexOf(u8, capability, "\"supervisor\":\"shell\"") != null);
    try t.expect(std.mem.indexOf(u8, capability, "\"pidProof\":\"weak\"") != null);
    try t.expect(std.mem.indexOf(u8, capability, "\"binaryFraming\":false") != null);
    try t.expect(std.mem.indexOf(u8, capability, "\"remoteDeadline\":false") != null);
}

test "M2 gate: an unsettled peer blocks a mutation but only warns a read" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "m2_scope_guard");
    defer h.deinit();

    // Leave one attempt unsettled on a job scope.
    const job_scope: scope_mod.Scope = .{ .kind = .job, .key = "deploy" };
    {
        const start = try h.begin(.{ .kind = .job, .scope = job_scope, .alias = "deploy" });
        var exec = start.ready;
        try exec.connecting();
        try exec.submitted();
        _ = try exec.transportLoss("eof"); // -> indeterminate
    }

    // A mutation on the same scope is refused, and told what is in the way.
    const blocked = try h.begin(.{ .kind = .job, .scope = job_scope, .mutating = true });
    try t.expectEqual(op_state.Status.indeterminate, blocked.blocked.unsettled.status);

    // Read-only work proceeds, but carries the advisory: refusing every
    // `exec` while one job is unsettled would make the guard unusable, and a
    // guard people switch off protects nothing.
    const read_start = try h.begin(.{ .kind = .exec, .scope = job_scope, .mutating = false });
    var read_exec = read_start.ready;
    defer read_exec.deinit();
    try t.expect(read_exec.advisory != null);

    // Forcing past the blocker is allowed and leaves an audit event.
    const forced_start = try h.begin(.{
        .kind = .job,
        .scope = job_scope,
        .mutating = true,
        .force = true,
    });
    var forced = forced_start.ready;
    defer forced.deinit();
    const rows = try receipts.list(&h.store, h.arena, forced.id());
    try t.expectEqualStrings("audit", rows[0].kind);
    try t.expect(std.mem.indexOf(u8, rows[0].detail_json.?, "forced_past_blocker") != null);
}

test "M2 gate: a dropped execution still records why nothing was decided" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "m2_dropped");
    defer h.deinit();

    var request_id_buf: [26]u8 = undefined;
    {
        const start = try h.begin(.{});
        var exec = start.ready;
        try exec.connecting();
        try exec.submitted();
        @memcpy(&request_id_buf, exec.id());
        // Falls out of scope without settling — a bug, but one that must not
        // leave an attempt that reached the remote silently unexplained.
        exec.deinit();
    }

    const op = try h.operationOf(&request_id_buf);
    try t.expectEqual(op_state.Status.indeterminate, op.status);
    const terminal = try h.terminalRow(&request_id_buf);
    try t.expect(std.mem.indexOf(u8, terminal.transport_error.?, "without recording an outcome") != null);
}

test "M2 gate: an execution abandoned before dialing touched nothing" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "m2_never_dialed");
    defer h.deinit();

    var request_id_buf: [26]u8 = undefined;
    {
        const start = try h.begin(.{});
        var exec = start.ready;
        @memcpy(&request_id_buf, exec.id());
        exec.deinit();
    }

    // Nothing was sent, so this is provably a failure rather than an unknown
    // — and it must not linger as a scope blocker.
    const op = try h.operationOf(&request_id_buf);
    try t.expectEqual(op_state.Status.failed, op.status);
    try t.expect(!op.status.blocksScope());
    try t.expectEqual(@as(usize, 0), (try operations.unsettled(&h.store, h.arena, 1)).len);
}
