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
const Proc = @import("proc.zig");
const Executor = @import("exec.zig").Executor;
const Scripted = @import("exec.zig").Scripted;

/// Submits, insisting the scope guard let it through.
///
/// Most gates here are about what happens *after* submission, so a refusal
/// would make them pass for the wrong reason — the attempt would have ended
/// before the thing under test ever happened.
fn mustSubmit(e: *execution.Execution) !void {
    switch (try e.submitted()) {
        .submitted => {},
        .refused => return error.UnexpectedlyRefused,
    }
}

fn mustRun(e: *execution.Execution, executor: Executor, command: []const u8) !execution.RunOutcome {
    return switch (try execution.runCommand(e, executor, command, null)) {
        .ran => |outcome| outcome,
        .refused => error.UnexpectedlyRefused,
    };
}

const Harness = struct {
    io: std.Io,
    threaded: *std.Io.Threaded,
    arena_state: *std.heap.ArenaAllocator,
    arena: std.mem.Allocator,
    path: [:0]u8,
    store: Store,
    allocator: std.mem.Allocator,

    const dir = ".zig-cache/tmp";

    /// Scratch names must be unique per process: the gates are otherwise
    /// safe to run in parallel, and a shared filename turns that into a pile
    /// of false failures that look like real races.
    var counter: std.atomic.Value(u32) = .init(0);

    fn uniqueName(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
        const n = counter.fetchAdd(1, .monotonic);
        return std.fmt.allocPrint(allocator, "{s}_{d}_{d}_{d}", .{ name, Proc.currentPid(), std.Thread.getCurrentId(), n });
    }

    fn init(allocator: std.mem.Allocator, name: []const u8) !Harness {
        const threaded = try allocator.create(std.Io.Threaded);
        threaded.* = .init(allocator, .{});
        const io = threaded.io();
        std.Io.Dir.cwd().createDirPath(io, dir) catch {};
        const unique = try uniqueName(allocator, name);
        defer allocator.free(unique);
        const path = try std.fmt.allocPrintSentinel(allocator, "{s}/{s}.db", .{ dir, unique }, 0);

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

    /// Records the launch a later `job_sentinel` resolution is checked against.
    ///
    /// `begin` creates the operation; it does not create the `job_attempts`
    /// row, because in production that row is `cmd_job`'s to write — it stores
    /// the sentinel it chose at `cmd_job.zig:314`, some sixty lines before
    /// `sendKeys` can put that sentinel into a remote log. So a job whose log
    /// could carry a sentinel always has this row, and a gate that resolved
    /// from one without it was modelling a job that never launched.
    ///
    /// It has to match on all three of the things that make the row this
    /// launch's — request id, server, and the sentinel itself — or the
    /// comparison in `receipts.resolve` passes with nothing true behind it.
    fn recordLaunch(h: *Harness, request_id: []const u8, job_name: []const u8, sentinel: []const u8) !void {
        _ = try Store.job_attempts.create(&h.store, .{
            .request_id = request_id,
            .server_id = 1,
            .server_name = "box",
            .job_name = job_name,
            .attempt_no = try Store.job_attempts.nextAttemptNo(&h.store, 1, job_name),
            .sentinel = sentinel,
            .now = 1000,
        });
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

    // Dialing failed. The command was never handed over, so `failed` is the
    // honest verdict — this is the *only* disconnect that may be reported as
    // a failure.
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
    const outcome = try mustRun(&exec, scripted.executor(), "systemctl restart api");

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
    const outcome = try mustRun(&exec, scripted.executor(), "./migrate.sh");

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
    // The launch record `cmd_job` writes before the command can reach the
    // shell. The sentinel resolution below is checked against it — see
    // `Harness.recordLaunch`.
    try h.recordLaunch(exec.id(), "migrate", "__TERMINUS_JOB_7__");

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
    _ = try mustRun(&exec, scripted.executor(), "./migrate.sh");
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
        if (stage == .submitted or stage == .remote_started) try mustSubmit(&exec);
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
    const outcome = try mustRun(&exec, scripted.executor(), "false");

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
        try mustSubmit(&exec);
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

test "M2e gate: an unsettled read holds no scope, before or after it is stored" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "m2e_readonly_scope");
    defer h.deinit();

    const job_scope: scope_mod.Scope = .{ .kind = .job, .key = "deploy" };

    // A read-only attempt that lost its connection after submission. Its
    // outcome is genuinely unknown — and irrelevant to anyone else, because
    // whatever it did or did not do, it did not change anything.
    var reader_id: [26]u8 = undefined;
    {
        const start = try h.begin(.{ .kind = .exec, .scope = job_scope, .mutating = false });
        var exec = start.ready;
        @memcpy(&reader_id, exec.id());
        try exec.connecting();
        try mustSubmit(&exec);
        _ = try exec.transportLoss("eof");
    }
    try t.expectEqual(op_state.Status.indeterminate, (try h.operationOf(&reader_id)).status);

    // It is still visible — an operator looking for loose ends must find it,
    // and a handoff has to carry it.
    const listed = try operations.unsettled(&h.store, h.arena, 1);
    try t.expectEqual(@as(usize, 1), listed.len);
    try t.expectEqualStrings(&reader_id, listed[0].request_id);

    // But it bars nothing. This is the half that used to be missing: the flag
    // lived only in memory, so once the attempt was stored the guard saw a
    // plain unsettled row and refused every later change on the scope —
    // asymmetric with the same attempt while it was running, which had been
    // allowed to proceed alongside a mutation.
    try t.expectEqual(@as(usize, 0), (try operations.unsettledInScope(&h.store, h.arena, 1, job_scope)).len);

    const after = try h.begin(.{ .kind = .job, .scope = job_scope, .mutating = true });
    var mutation = after.ready;
    defer mutation.deinit();
    try t.expectEqual(@as(?execution.Blocker, null), mutation.advisory);

    // And the writer that follows does hold it, so nothing was loosened
    // beyond the read.
    try mutation.connecting();
    try mustSubmit(&mutation);
    try t.expectEqual(@as(usize, 1), (try operations.unsettledInScope(&h.store, h.arena, 1, job_scope)).len);
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
        try mustSubmit(&exec);
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

test "M2b gate: a detached job stays in flight instead of inventing a verdict" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "m2b_detach");
    defer h.deinit();

    var request_id_buf: [26]u8 = undefined;
    {
        const start = try h.begin(.{ .kind = .job, .alias = "build", .mutating = true });
        var exec = start.ready;
        try exec.connecting();
        try mustSubmit(&exec);
        try exec.remoteStarted(.{ .pid = 900 });
        @memcpy(&request_id_buf, exec.id());
        // `run` exits here: the work continues in its tmux session.
        try exec.detach("job continues in its remote tmux session");
        exec.deinit(); // must not settle anything
    }

    const op = try h.operationOf(&request_id_buf);
    try t.expectEqual(op_state.Status.remote_started, op.status);
    // Detached is not finished: something really is running, so the scope
    // stays held until somebody establishes how it ended.
    try t.expect(op.status.blocksScope());
    try t.expect((try receipts.terminalOf(&h.store, &request_id_buf)) == null);
}

test "M2b gate: attaching to a running job cannot settle it by accident" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "m2b_attach_readonly");
    defer h.deinit();

    const start = try h.begin(.{ .kind = .job, .alias = "build", .mutating = true });
    var launcher = start.ready;
    try launcher.connecting();
    try mustSubmit(&launcher);
    try launcher.detach("running");

    // A later `job status` attaches. Merely looking must not produce a
    // terminal, even if the handle is dropped without deciding.
    {
        var attached = (try execution.attach(&h.store, h.arena, h.io, launcher.id())).?;
        attached.deinit();
    }
    try t.expect((try receipts.terminalOf(&h.store, launcher.id())) == null);
    try t.expectEqual(op_state.Status.submitted, (try h.operationOf(launcher.id())).status);

    // Recording a real outcome is explicit.
    var attached = (try execution.attach(&h.store, h.arena, h.io, launcher.id())).?;
    _ = try attached.settleAttached(.{ .exited = .{ .exit_code = 0 } }, .{});
    try t.expectEqual(op_state.Status.completed, (try h.operationOf(launcher.id())).status);

    // Once settled, a second observer gets the recorded terminal rather than
    // an opportunity to overwrite it.
    try t.expect((try execution.attach(&h.store, h.arena, h.io, launcher.id())) == null);
}

test "M2b gate: a vanished job session is unknown, not killed" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "m2b_vanished");
    defer h.deinit();

    const start = try h.begin(.{ .kind = .job, .alias = "migrate", .mutating = true });
    var launcher = start.ready;
    try launcher.connecting();
    try mustSubmit(&launcher);
    try launcher.remoteStarted(.{ .pid = 4242 });
    try launcher.detach("running");
    // The sentinel this launch chose. Recorded at launch and not at exit: the
    // string in `job_attempts` is the one `cmd_job` picked before the command
    // was sent, while the *line* below is what the remote wrapper echoes into
    // the log when the command ends. "No sentinel was ever written" in the
    // comment below is about the log, which is why both can be true at once.
    try h.recordLaunch(launcher.id(), "migrate", "__TERMINUS_JOB_1__");

    // The pane is gone and no sentinel was ever written. That happens when a
    // command finishes and the shell exits, when somebody kills it, and when
    // the host reboots mid-write — three different outcomes, none of which is
    // evidence for the others.
    var attached = (try execution.attach(&h.store, h.arena, h.io, launcher.id())).?;
    _ = try attached.settleAttached(.{ .indeterminate = .{
        .reason = "job session disappeared without reporting an exit status",
        .last_observed = attached.status,
    } }, .{});

    const op = try h.operationOf(launcher.id());
    try t.expectEqual(op_state.Status.indeterminate, op.status);
    try t.expect(op.status.blocksScope());

    // It can be resolved later by the durable log, which is the only thing
    // that actually knows.
    try t.expect((try receipts.resolve(&h.store, h.arena, launcher.id(), .completed, .{
        .job_sentinel = .{ .sentinel = "__TERMINUS_JOB_1__", .exit_code = 0 },
    }, 5000)) == .resolved);
    try t.expectEqual(op_state.Status.completed, (try h.operationOf(launcher.id())).effectiveStatus());
}

test "M2b gate: cancellation counts only when absence was verified" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "m2b_cancel");
    defer h.deinit();

    // Session confirmed gone -> a real cancellation.
    {
        const start = try h.begin(.{ .kind = .job, .alias = "a", .mutating = true });
        var e = start.ready;
        try e.connecting();
        try mustSubmit(&e);
        try e.detach("running");
        var attached = (try execution.attach(&h.store, h.arena, h.io, e.id())).?;
        _ = try attached.settleAttached(.{ .remote_cancel_confirmed = .{
            .term_sent = true,
            .kill_sent = true,
            .absence_verified_at = 4000,
            .verification_method = "tmux has-session reports the job session absent",
        } }, .{});
        const op = try h.operationOf(e.id());
        try t.expectEqual(op_state.Status.cancelled, op.status);
        try t.expect(!op.status.blocksScope());
    }

    // Kill issued but the session is still there -> unknown, and it keeps
    // holding the scope. Claiming `cancelled` here would release the barrier
    // on something still running.
    {
        const start = try h.begin(.{ .kind = .job, .alias = "b", .mutating = true });
        var e = start.ready;
        try e.connecting();
        try mustSubmit(&e);
        try e.detach("running");
        var attached = (try execution.attach(&h.store, h.arena, h.io, e.id())).?;
        _ = try attached.settleAttached(.{ .indeterminate = .{
            .reason = "kill issued but the job session is still present",
            .last_observed = attached.status,
        } }, .{});
        const op = try h.operationOf(e.id());
        try t.expectEqual(op_state.Status.indeterminate, op.status);
        try t.expect(op.status.blocksScope());
    }
}

test "M2b gate: relaunching a job whose fate is unknown is refused" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "m2b_relaunch");
    defer h.deinit();

    const scope: scope_mod.Scope = .{ .kind = .job, .key = "deploy" };
    const start = try h.begin(.{ .kind = .job, .scope = scope, .alias = "deploy", .mutating = true });
    var first = start.ready;
    try first.connecting();
    try mustSubmit(&first);
    try h.recordLaunch(first.id(), "deploy", "__S__");
    _ = try first.transportLoss("eof"); // indeterminate

    // The deploy may or may not have happened. Running it again could apply
    // it twice, so the launch is refused rather than left to judgement.
    const blocked = try h.begin(.{ .kind = .job, .scope = scope, .alias = "deploy", .mutating = true });
    try t.expectEqual(op_state.Status.indeterminate, blocked.blocked.unsettled.status);

    // Resolving the question unblocks it. The outcome is asserted rather than
    // discarded: this used to be `_ =`, so a resolution the ledger *refused*
    // showed up three lines below as a panic on the wrong union tag, with
    // nothing naming the refusal that caused it.
    try t.expect((try receipts.resolve(&h.store, h.arena, first.id(), .failed, .{
        .job_sentinel = .{ .sentinel = "__S__", .exit_code = 1 },
    }, 6000)) == .resolved);
    const allowed = try h.begin(.{ .kind = .job, .scope = scope, .alias = "deploy", .mutating = true });
    var second = allowed.ready;
    defer second.deinit();
    try t.expect(allowed == .ready);
}

const ConcurrentStart = struct {
    path: [:0]const u8,
    gate: *std.atomic.Value(bool),
    submitted: bool = false,
    refused: bool = false,
    err: ?anyerror = null,
};

/// One thread's worth of `terminus job run --name deploy`.
///
/// It runs the whole launch sequence, not just `begin`, because `begin` is not
/// where the race is decided. `begin` writes the row as `created`, which the
/// unsettled predicate deliberately does not count, so several threads can and
/// should get past it — a `created` row abandoned by a killed process must not
/// hold a scope forever. The single winner is picked at `submitted`, where the
/// conflict check and the write that makes this attempt visible to the next
/// caller happen in one transaction.
fn launchInThread(ctx: *ConcurrentStart) void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    var threaded: std.Io.Threaded = .init(std.heap.page_allocator, .{});
    defer threaded.deinit();

    while (!ctx.gate.load(.acquire)) std.atomic.spinLoopHint();
    var store = Store.open(ctx.path) catch |err| {
        ctx.err = err;
        return;
    };
    defer store.close();

    const start = execution.begin(&store, arena_state.allocator(), threaded.io(), .{
        .server_id = 1,
        .server_name = "box",
        .kind = .job,
        .scope = .{ .kind = .job, .key = "deploy" },
        .alias = "deploy",
        .mutating = true,
        .owner_token = "owner-a",
        .now = 1000,
    }) catch |err| {
        ctx.err = err;
        return;
    };

    var owned = switch (start) {
        .ready => |e| e,
        // Refused before dialing: a peer had already submitted.
        .blocked => {
            ctx.refused = true;
            return;
        },
    };
    // Whatever happens below, this attempt gets a terminal. A loser is settled
    // as a proven failure at `connecting` — nothing was sent — so it does not
    // become a blocker of its own.
    defer owned.deinit();

    owned.connecting() catch |err| {
        ctx.err = err;
        return;
    };
    const submit = owned.submitted() catch |err| {
        ctx.err = err;
        return;
    };
    switch (submit) {
        .submitted => {
            ctx.submitted = true;
            // The winner leaves it in flight, as `run` does.
            owned.detach("running") catch |err| {
                ctx.err = err;
            };
        },
        .refused => ctx.refused = true,
    }
}

test "M2 gate: concurrent launches on one scope produce exactly one submitter" {
    const t = std.testing;
    const thread_count = 4;

    for (0..6) |round| {
        var name_buf: [40]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "m2_concurrent_{d}", .{round});
        var h = try Harness.init(t.allocator, name);
        defer h.deinit();

        // Unless the conflict check and the transition to `submitted` land in
        // one write transaction, every thread sees an empty scope and every
        // thread sends — the exact double-application the guard exists to stop.
        var gate: std.atomic.Value(bool) = .init(false);
        var ctxs: [thread_count]ConcurrentStart = undefined;
        var threads: [thread_count]std.Thread = undefined;
        for (&ctxs, 0..) |*ctx, i| {
            ctx.* = .{ .path = h.path, .gate = &gate };
            threads[i] = try std.Thread.spawn(.{}, launchInThread, .{ctx});
        }
        gate.store(true, .release);
        for (threads) |thread| thread.join();

        var submitted: usize = 0;
        var refused: usize = 0;
        for (&ctxs) |*ctx| {
            if (ctx.err) |err| {
                std.debug.print("round {d}: {s}\n", .{ round, @errorName(err) });
                return err;
            }
            if (ctx.submitted) submitted += 1;
            if (ctx.refused) refused += 1;
        }
        try t.expectEqual(@as(usize, 1), submitted);
        try t.expectEqual(@as(usize, thread_count - 1), refused);

        // And the ledger agrees: exactly one attempt is holding the scope.
        try t.expectEqual(@as(usize, 1), (try operations.unsettled(&h.store, h.arena, 1)).len);
    }
}

test "M2 gate: an attempt that never dialed holds no scope" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "m2_created_no_trap");
    defer h.deinit();

    const scope: scope_mod.Scope = .{ .kind = .job, .key = "deploy" };

    // A process killed between `begin` and `submitted` leaves rows behind in
    // `created` and `connecting`. Neither may block the scope: nothing was
    // sent, so there is nothing to reconcile, and a permanent blocker with no
    // escape hatch is worse than no guard at all.
    var stranded = (try h.begin(.{ .kind = .job, .scope = scope, .alias = "deploy", .mutating = true })).ready;
    try t.expectEqual(op_state.Status.created, (try h.operationOf(stranded.id())).status);
    try t.expectEqual(@as(usize, 0), (try operations.unsettled(&h.store, h.arena, 1)).len);

    try stranded.connecting();
    try t.expectEqual(@as(usize, 0), (try operations.unsettled(&h.store, h.arena, 1)).len);

    // So the next launch goes through, all the way to the point of no return.
    var next = (try h.begin(.{ .kind = .job, .scope = scope, .alias = "deploy", .mutating = true })).ready;
    defer next.deinit();
    try next.connecting();
    try mustSubmit(&next);

    // Now that one really did send, and it does hold the scope.
    try t.expectEqual(@as(usize, 1), (try operations.unsettled(&h.store, h.arena, 1)).len);
    switch (try stranded.submitted()) {
        .submitted => return error.GuardLetASecondAttemptThrough,
        .refused => |blocker| try t.expectEqualStrings(next.id(), blocker.unsettled.request_id),
    }
    // Refused means nothing was sent, so the stranded attempt is still at
    // `connecting` and settles as a proven failure.
    stranded.deinit();
    try t.expectEqual(op_state.Status.failed, (try h.operationOf(stranded.id())).status);
}

test "M2 gate: a weak supervisor cannot claim a verified cancellation" {
    const t = std.testing;

    // The capability is not decoration: killing a tmux session does not prove
    // a daemonized or disowned child stopped, so shell mode must be unable to
    // record `cancelled` — which would release the scope while the work runs.
    try t.expect(!supervisor.Requirement.verified_cancellation.satisfiedBy(supervisor.shell_capability));

    const helper: supervisor.Capability = .{
        .supervisor = .helper,
        .pid_proof = .strong,
        .binary_framing = true,
        .remote_deadline = true,
        .audit_isolation = true,
    };
    try t.expect(supervisor.Requirement.verified_cancellation.satisfiedBy(helper));

    // And the state machine agrees about what the weaker outcome preserves.
    var h = try Harness.init(t.allocator, "m2_weak_cancel");
    defer h.deinit();
    const start = try h.begin(.{ .kind = .job, .alias = "svc", .mutating = true });
    var exec = start.ready;
    try exec.connecting();
    try mustSubmit(&exec);
    try exec.detach("running");

    var attached = (try execution.attach(&h.store, h.arena, h.io, exec.id())).?;
    _ = try attached.settleAttached(.{ .indeterminate = .{
        .reason = "job session killed, but this supervisor cannot prove the process tree stopped",
        .last_observed = attached.status,
    } }, .{});
    const op = try h.operationOf(exec.id());
    try t.expectEqual(op_state.Status.indeterminate, op.status);
    // Still held: a relaunch must not slip past an unproven cancellation.
    try t.expect(op.status.blocksScope());
}

test "M2 gate: a submitted attempt is findable even if the next local write fails" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "m2_submit_first");
    defer h.deinit();

    const start = try h.begin(.{ .kind = .job, .alias = "deploy", .mutating = true });
    var exec = start.ready;
    try exec.connecting();
    try mustSubmit(&exec);

    // Whatever happens locally after this point, the attempt exists and is
    // reachable by request id and by alias — which is what `status`, `kill`
    // and `reconcile` key off.
    const by_alias = (try Store.operations.latestByAlias(&h.store, h.arena, 1, "deploy")).?;
    try t.expectEqualStrings(exec.id(), by_alias.request_id);
    try t.expectEqual(op_state.Status.submitted, by_alias.status);
    try t.expectEqual(@as(usize, 1), (try Store.operations.unsettled(&h.store, h.arena, 1)).len);
}

test "M2 gate: reconciliation releases a scope only with evidence" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "m2_reconcile_gate");
    defer h.deinit();

    const scope: scope_mod.Scope = .{ .kind = .job, .key = "deploy" };
    const start = try h.begin(.{ .kind = .job, .scope = scope, .alias = "deploy", .mutating = true });
    var exec = start.ready;
    try exec.connecting();
    try mustSubmit(&exec);
    _ = try exec.transportLoss("eof");

    // An override needs a named owner and is marked as a decision, but it is
    // available — otherwise a forgotten job blocks its name forever, and the
    // guard becomes something people route around.
    try t.expect((try receipts.resolve(&h.store, h.arena, exec.id(), .failed, .{
        .operator_override = .{ .reason = "checked the host by hand; nothing ran", .by = "czykl" },
    }, 3000)) == .resolved);

    const op = try h.operationOf(exec.id());
    try t.expectEqual(op_state.Status.indeterminate, op.status); // observation kept
    try t.expect(!op.effectiveStatus().blocksScope()); // scope released
    try t.expect(std.mem.indexOf(u8, op.resolution_evidence.?, "\"mechanical\":false") != null);

    // And the scope is genuinely usable again.
    const again = try h.begin(.{ .kind = .job, .scope = scope, .alias = "deploy", .mutating = true });
    var second = again.ready;
    defer second.deinit();
    try t.expect(again == .ready);
}

test "M4 gate: a write holds its session's scope, in both directions" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "m4_write_scope");
    defer h.deinit();

    // `terminus write` names its scope the way `terminus exec
    // <server>:<session>` does (cmd_exec.zig:82). One vocabulary, so a write
    // and a run on the same session see each other; two would be a hole, not a
    // detail.
    const build: scope_mod.Scope = .{ .kind = .job, .key = "build" };
    const other: scope_mod.Scope = .{ .kind = .job, .key = "deploy" };

    // A run on that session whose outcome was lost.
    {
        const start = try h.begin(.{ .kind = .job, .scope = build, .alias = "build" });
        var exec = start.ready;
        try exec.connecting();
        try mustSubmit(&exec);
        _ = try exec.transportLoss("eof");
    }

    // The write is refused before it dials, and told what is in the way. This
    // is the whole point of routing it through the boundary: until now it
    // typed into the shell regardless and printed `ok`.
    const blocked = try h.begin(.{ .kind = .session_write, .scope = build, .alias = "build" });
    try t.expectEqual(op_state.Status.indeterminate, blocked.blocked.unsettled.status);

    // A write to a *different* session is unaffected — the barrier is the
    // session's, not the host's.
    const elsewhere = try h.begin(.{ .kind = .session_write, .scope = other, .alias = "deploy" });
    var elsewhere_exec = elsewhere.ready;
    defer elsewhere_exec.deinit();
    try t.expect(elsewhere == .ready);

    // And the write is subject to the barrier in the other direction too: an
    // unsettled write blocks a run on the same session, because bytes that may
    // be in a pane are exactly the case a second launch must not walk into.
    try elsewhere_exec.connecting();
    try mustSubmit(&elsewhere_exec);
    _ = try elsewhere_exec.transportLoss("eof");
    const run_blocked = try h.begin(.{ .kind = .job, .scope = other, .alias = "deploy" });
    try t.expectEqualStrings(elsewhere_exec.id(), run_blocked.blocked.unsettled.request_id);
}

test "M4 gate: a delivered write is a delivery, not an outcome" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "m4_write_terminal");
    defer h.deinit();

    const scope: scope_mod.Scope = .{ .kind = .job, .key = "build" };
    const start = try h.begin(.{ .kind = .session_write, .scope = scope, .alias = "build" });
    var exec = start.ready;
    defer exec.deinit();
    try exec.connecting();
    try mustSubmit(&exec);

    _ = try exec.settle(.{ .input_accepted = .{ .bytes = 9, .sha256 = "beef" } }, .{});

    const op = try h.operationOf(exec.id());
    try t.expectEqual(op_state.Status.completed, op.status);
    // Completed, and it releases the scope — which is correct and is the
    // reason the receipt has to be so careful about what it claims. The
    // operation ("hand these bytes to that terminal") really is over; the
    // input it delivered may run for an hour, and nothing in this ledger will
    // ever say how that went.
    try t.expect(!op.effectiveStatus().blocksScope());

    const row = try h.terminalRow(exec.id());
    try t.expectEqual(@as(?i64, null), row.exit_code);
    try t.expectEqual(@as(?[]const u8, null), row.error_code);
    try t.expectEqual(@as(?i64, 9), row.stdin_bytes);
    try t.expectEqualStrings("beef", row.stdin_sha256.?);
    // Nothing was read back out of the session, and the receipt says so by
    // carrying no output evidence at all rather than a zero.
    try t.expectEqual(@as(?i64, null), row.stdout_bytes);
    // `finished_at` answers "when did the remote work end". A delivery has no
    // such moment to report, and the time we looked is `observed_at`.
    try t.expectEqual(@as(?i64, null), row.finished_at);
}

test "M4 gate: a write whose answer was lost stays unknown, and holds its session" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "m4_write_lost");
    defer h.deinit();

    const scope: scope_mod.Scope = .{ .kind = .job, .key = "build" };
    const start = try h.begin(.{ .kind = .session_write, .scope = scope, .alias = "build" });
    var exec = start.ready;
    try exec.connecting();
    try mustSubmit(&exec);

    // The connection broke after the bytes were handed over. They may be in
    // the pane. `failed` here would tell an agent it is safe to type them
    // again, which is the one conclusion that is not available.
    _ = try exec.transportLoss("channel closed");
    const op = try h.operationOf(exec.id());
    try t.expectEqual(op_state.Status.indeterminate, op.status);
    try t.expect(op.effectiveStatus().blocksScope());

    // And a second write to the same session is refused rather than repeating
    // the input.
    const again = try h.begin(.{ .kind = .session_write, .scope = scope, .alias = "build" });
    try t.expectEqualStrings(exec.id(), again.blocked.unsettled.request_id);
}
