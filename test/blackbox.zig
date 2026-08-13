//! Black-box gates: the real binary, as a subprocess, judged only by its
//! stdout and its exit code.
//!
//! Everything else in this repo tests the ledger from the inside. That proves
//! the rules hold; it does not prove a caller can reach them. The contract an
//! agent actually depends on is narrower and entirely observable from out
//! here: which exit code came back, and whether the JSON said `ok`.
//!
//! The gate that matters most is the escape hatch. An attempt whose outcome is
//! unknown keeps blocking its scope on purpose, so `request reconcile` has to
//! be a real, reachable way out — not a string in an error message. It was
//! exactly that once, which is why it is checked from outside the process.
//!
//! What is *not* here: anything needing a remote host. Exit 75 on a lost
//! `sendKeys` response, and `--from-log` reading a real sentinel, both need an
//! SSH endpoint; they belong to the live end-to-end run, not to `zig build
//! test`, and pretending otherwise with a mock would gate on the mock.
const std = @import("std");
const build_options = @import("build_options");
const Terminus = @import("Terminus");
const Store = Terminus.Core.Store;

const exe_path = build_options.terminus_exe;

/// A scratch database seeded directly, then handed to the binary via `--db`.
///
/// Seeding through the library rather than through the CLI is deliberate: the
/// states worth testing (`submitted`, `indeterminate`) are only reachable by
/// talking to a remote host, and the point here is to test what the CLI does
/// once it finds one, not to test the seeding.
const Fixture = struct {
    io: std.Io,
    threaded: *std.Io.Threaded,
    dir: []u8,
    db: [:0]u8,
    allocator: std.mem.Allocator,

    var counter: std.atomic.Value(u32) = .init(0);

    fn init(allocator: std.mem.Allocator, name: []const u8) !Fixture {
        const threaded = try allocator.create(std.Io.Threaded);
        threaded.* = .init(allocator, .{});
        const io = threaded.io();

        const n = counter.fetchAdd(1, .monotonic);
        const dir = try std.fmt.allocPrint(
            allocator,
            ".zig-cache/tmp/bb_{s}_{d}_{d}",
            .{ name, std.Thread.getCurrentId(), n },
        );
        std.Io.Dir.cwd().createDirPath(io, dir) catch {};
        const db = try std.fmt.allocPrintSentinel(allocator, "{s}/terminus.db", .{dir}, 0);

        var f: Fixture = .{ .io = io, .threaded = threaded, .dir = dir, .db = db, .allocator = allocator };
        f.removeDbFiles();
        return f;
    }

    /// WAL leaves sidecars; a stale one makes the next open read a mismatched
    /// log, which shows up as empty data rather than as an error.
    fn removeDbFiles(f: *Fixture) void {
        const cwd = std.Io.Dir.cwd();
        cwd.deleteFile(f.io, f.db) catch {};
        for ([_][]const u8{ "-wal", "-shm" }) |suffix| {
            const side = std.fmt.allocPrint(f.allocator, "{s}{s}", .{ f.db, suffix }) catch return;
            defer f.allocator.free(side);
            cwd.deleteFile(f.io, side) catch {};
        }
    }

    fn deinit(f: *Fixture) void {
        f.removeDbFiles();
        std.Io.Dir.cwd().deleteDir(f.io, f.dir) catch {};
        f.allocator.free(f.dir);
        f.allocator.free(f.db);
        f.threaded.deinit();
        f.allocator.destroy(f.threaded);
    }

    fn open(f: *Fixture) !Store {
        return Store.open(f.db);
    }

    /// One server row pointing at a closed local port, so a command that gets
    /// past the local guards fails instantly at `connect` instead of hanging
    /// on an unroutable address.
    ///
    /// The stored key is a header and nothing else. Terminus sniffs the PEM
    /// banner before it will dial, so this is enough to get past that check
    /// and no use whatsoever to anyone who finds it — which is the point: no
    /// gate here is allowed to get far enough to need a real key.
    fn seedServer(f: *Fixture) !void {
        var store = try f.open();
        defer store.close();
        try store.db.exec(
            \\INSERT INTO keys (id, name, kind, private_pem, created_at)
            \\VALUES (1, 'placeholder', 'rsa',
            \\        '-----BEGIN RSA PRIVATE KEY-----
            \\not a key
            \\-----END RSA PRIVATE KEY-----
            \\', 100);
            \\INSERT INTO servers (id, name, host, port, username, key_id, created_at, updated_at)
            \\VALUES (1, 'box', '127.0.0.1', 1, 'ubuntu', 1, 100, 100);
        );
    }
};

/// What the binary did, from the caller's side of the process boundary.
const Run = struct {
    code: u8,
    stdout: []u8,
    stderr: []u8,

    fn deinit(r: Run, allocator: std.mem.Allocator) void {
        allocator.free(r.stdout);
        allocator.free(r.stderr);
    }

    fn expectCode(r: Run, want: u8) !void {
        std.testing.expectEqual(want, r.code) catch |err| {
            std.debug.print(
                "exit {d}, wanted {d}\n--- stdout ---\n{s}\n--- stderr ---\n{s}\n",
                .{ r.code, want, r.stdout, r.stderr },
            );
            return err;
        };
    }

    /// Substring match against whichever stream the message landed on: human
    /// mode writes to stderr, `--json` to stdout, and a gate on the wording
    /// should not also be a gate on which stream carried it.
    fn expectSays(r: Run, needle: []const u8) !void {
        if (std.mem.indexOf(u8, r.stdout, needle) != null) return;
        if (std.mem.indexOf(u8, r.stderr, needle) != null) return;
        std.debug.print(
            "missing {s}\n--- stdout ---\n{s}\n--- stderr ---\n{s}\n",
            .{ needle, r.stdout, r.stderr },
        );
        return error.OutputMissingText;
    }

    fn expectSaysNot(r: Run, needle: []const u8) !void {
        if (std.mem.indexOf(u8, r.stdout, needle) == null and
            std.mem.indexOf(u8, r.stderr, needle) == null) return;
        std.debug.print(
            "unexpected {s}\n--- stdout ---\n{s}\n--- stderr ---\n{s}\n",
            .{ needle, r.stdout, r.stderr },
        );
        return error.OutputHasText;
    }
};

fn run(f: *Fixture, argv: []const []const u8) !Run {
    const allocator = f.allocator;
    var full: std.ArrayList([]const u8) = .empty;
    defer full.deinit(allocator);
    try full.append(allocator, exe_path);
    try full.appendSlice(allocator, argv);

    const result = try std.process.run(allocator, f.io, .{
        .argv = full.items,
        .stdout_limit = .limited(1 << 20),
        .stderr_limit = .limited(1 << 20),
    });
    errdefer {
        allocator.free(result.stdout);
        allocator.free(result.stderr);
    }

    return .{
        .code = switch (result.term) {
            .exited => |c| c,
            // A crash is not one of the codes the contract defines, and
            // folding it into `failure` would let a segfault pass a gate that
            // only checks for "nonzero".
            else => return error.ProcessDidNotExitNormally,
        },
        .stdout = result.stdout,
        .stderr = result.stderr,
    };
}

/// An attempt parked in a live state, exactly as `run --name <alias>` leaves
/// one behind when the caller walks away.
fn seedInFlightJob(f: *Fixture, request_id: []const u8, alias: []const u8) !void {
    var store = try f.open();
    defer store.close();

    try Store.operations.create(&store, .{
        .request_id = request_id,
        .server_id = 1,
        .server_name = "box",
        .kind = .job,
        .scope_kind = .job,
        .scope_key = alias,
        .alias = alias,
        .now = 1000,
    });
    try Store.operations.advance(&store, request_id, .connecting, 1001);
    try Store.operations.advance(&store, request_id, .submitted, 1002);
    _ = try Store.job_attempts.create(&store, .{
        .request_id = request_id,
        .server_id = 1,
        .server_name = "box",
        .job_name = alias,
        .attempt_no = 1,
        .sentinel = "__TERMINUS_JOB_7__",
        .tmux_session = "job-deploy",
        .now = 1002,
    });
}

const in_flight_id = "01AAAAAAAA0123456789ABCDEF";

test "blackbox: the binary runs and reports a version" {
    const t = std.testing;
    var f = try Fixture.init(t.allocator, "version");
    defer f.deinit();
    var r = try run(&f, &.{"version"});
    defer r.deinit(f.allocator);
    try r.expectCode(0);
}

test "blackbox: an in-flight attempt is visible and says it blocks its scope" {
    const t = std.testing;
    var f = try Fixture.init(t.allocator, "inflight");
    defer f.deinit();
    try f.seedServer();
    try seedInFlightJob(&f, in_flight_id, "deploy");

    var ls = try run(&f, &.{ "request", "ls", "box", "--json", "--db", f.db });
    defer ls.deinit(f.allocator);
    try ls.expectCode(0);
    try ls.expectSays(in_flight_id);

    var show = try run(&f, &.{ "request", "show", in_flight_id, "--json", "--db", f.db });
    defer show.deinit(f.allocator);
    try show.expectCode(0);
    try show.expectSays("\"blocksScope\": true");
    try show.expectSays("\"status\": \"submitted\"");
}

test "blackbox: reconcile names the escape hatch instead of leaving a dead end" {
    const t = std.testing;
    var f = try Fixture.init(t.allocator, "hatch");
    defer f.deinit();
    try f.seedServer();
    try seedInFlightJob(&f, in_flight_id, "deploy");

    // Bare `reconcile` on a live attempt must not settle anything — the work
    // may be running right now — but it must say what *would* settle it.
    var bare = try run(&f, &.{ "request", "reconcile", in_flight_id, "--db", f.db });
    defer bare.deinit(f.allocator);
    try bare.expectCode(1);
    try bare.expectSays("--from-log");

    // Nor may a human assertion jump the queue: overriding a `submitted`
    // attempt would release the scope on top of a process nobody has looked
    // at. The refusal has to route to --from-log, not just say no.
    var override = try run(&f, &.{
        "request",     "reconcile", in_flight_id, "--override", "looks done to me",
        "--by",        "operator",  "--resolved", "completed",  "--db",
        f.db,
    });
    defer override.deinit(f.allocator);
    try override.expectCode(1);
    try override.expectSays("--from-log");

    // And nothing moved: a refusal that quietly advanced the ledger would be
    // worse than the dead end it replaced.
    var show = try run(&f, &.{ "request", "show", in_flight_id, "--json", "--db", f.db });
    defer show.deinit(f.allocator);
    try show.expectCode(0);
    try show.expectSays("\"status\": \"submitted\"");
    try show.expectSays("\"resolvedStatus\": null");
}

test "blackbox: an override releases an indeterminate scope and is marked as a decision" {
    const t = std.testing;
    var f = try Fixture.init(t.allocator, "override");
    defer f.deinit();
    try f.seedServer();
    try seedInFlightJob(&f, in_flight_id, "deploy");

    // Settle it the way a lost connection would: unknown, still blocking.
    {
        var store = try f.open();
        defer store.close();
        _ = try Store.receipts.settle(&store, in_flight_id, .{ .indeterminate = .{
            .reason = "connection lost after submission",
            .last_observed = .submitted,
        } }, .{}, 1100);
    }

    var blocked = try run(&f, &.{ "request", "show", in_flight_id, "--json", "--db", f.db });
    defer blocked.deinit(f.allocator);
    try blocked.expectSays("\"status\": \"indeterminate\"");
    try blocked.expectSays("\"blocksScope\": true");

    // An override needs an owner and a verdict, or it is not a decision.
    var no_owner = try run(&f, &.{
        "request", "reconcile", in_flight_id, "--override", "checked by hand", "--db", f.db,
    });
    defer no_owner.deinit(f.allocator);
    try no_owner.expectCode(1);
    try no_owner.expectSays("--by");

    var ok = try run(&f, &.{
        "request",  "reconcile",       in_flight_id, "--override", "ssh'd in; the deploy finished",
        "--by",     "czykl",           "--resolved", "completed",  "--json",
        "--db",     f.db,
    });
    defer ok.deinit(f.allocator);
    try ok.expectCode(0);
    // Recorded as a human decision. If this ever reads `"mechanical": true`
    // the ledger has started laundering assertions into proof.
    try ok.expectSays("\"mechanical\": false");

    var after = try run(&f, &.{ "request", "show", in_flight_id, "--json", "--db", f.db });
    defer after.deinit(f.allocator);
    try after.expectCode(0);
    // The observation is preserved beside the resolution, not overwritten.
    try after.expectSays("\"status\": \"indeterminate\"");
    try after.expectSays("\"resolvedStatus\": \"completed\"");
    try after.expectSays("\"blocksScope\": false");

    // Written once: a second override cannot redefine a settled history.
    var again = try run(&f, &.{
        "request", "reconcile", in_flight_id, "--override", "actually it failed",
        "--by",    "czykl",     "--resolved", "failed",     "--db",
        f.db,
    });
    defer again.deinit(f.allocator);
    try again.expectCode(1);
    try again.expectSays("written once");

    var final = try run(&f, &.{ "request", "show", in_flight_id, "--json", "--db", f.db });
    defer final.deinit(f.allocator);
    try final.expectSays("\"resolvedStatus\": \"completed\"");
}

test "blackbox: the scope guard refuses a second launch and says nothing was sent" {
    const t = std.testing;
    var f = try Fixture.init(t.allocator, "guard");
    defer f.deinit();
    try f.seedServer();
    try seedInFlightJob(&f, in_flight_id, "deploy");

    // Same job name, unknown predecessor. This has to be refused *before* the
    // network, and the message has to be unambiguous about it: an agent that
    // reads "refused" and retries is the failure mode the guard exists for.
    var again = try run(&f, &.{
        "run", "box", "--name", "deploy", "--cmd", "make deploy", "--db", f.db,
    });
    defer again.deinit(f.allocator);
    try again.expectCode(1);
    try again.expectSays("refused");
    try again.expectSays("the job was not started");
    try again.expectSays(in_flight_id);
    // The port is closed, so if this had gone as far as dialling we would be
    // looking at a connection error instead.
    try again.expectSaysNot("connect");

    // A non-overlapping scope is not blocked by it. (It fails at the network,
    // which is proof enough that the guard let it through.)
    var other = try run(&f, &.{
        "run", "box", "--name", "unrelated", "--cmd", "true", "--db", f.db,
    });
    defer other.deinit(f.allocator);
    try other.expectSaysNot("refused: request");
}

test "blackbox: a launch that never reached the host claims no job name" {
    const t = std.testing;
    var f = try Fixture.init(t.allocator, "reservation");
    defer f.deinit();
    try f.seedServer();

    // Closed port: the launch dies inside `connect`, after `begin` and before
    // anything reaches the remote.
    var attempt = try run(&f, &.{
        "run", "box", "--name", "deploy", "--cmd", "make deploy", "--db", f.db,
    });
    defer attempt.deinit(f.allocator);
    try attempt.expectCode(1);

    var store = try f.open();
    defer store.close();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();

    // The name is free. `jobs.create` is a reservation against the remote
    // setup that follows it, so it must not fire for a launch that never got
    // a connection — otherwise every unreachable host would leave a row that
    // makes the next launch report a job which never started.
    //
    // (The other half of that rule — releasing a reservation that *was* taken
    // and then hit a fatal during setup — needs a reachable host, so it lives
    // in the live end-to-end run rather than here.)
    try t.expectEqual(
        @as(?Store.jobs.Job, null),
        try Store.jobs.getByName(&store, arena_state.allocator(), 1, "deploy"),
    );

    // And the attempt was settled rather than left dangling: the connection
    // proved nothing was sent, so it must not hold the scope.
    const unsettled = try Store.operations.unsettled(&store, arena_state.allocator(), 1);
    try t.expectEqual(@as(usize, 0), unsettled.len);
}

test "blackbox: an unknown outcome is never reported as a plain failure" {
    const t = std.testing;
    var f = try Fixture.init(t.allocator, "exitcode");
    defer f.deinit();
    try f.seedServer();
    try seedInFlightJob(&f, in_flight_id, "deploy");

    {
        var store = try f.open();
        defer store.close();
        _ = try Store.receipts.settle(&store, in_flight_id, .{ .indeterminate = .{
            .reason = "connection lost after submission",
            .last_observed = .submitted,
        } }, .{}, 1100);
    }

    // `request ls` still surfaces it: an indeterminate attempt is exactly what
    // an operator needs to find, and dropping it from the list once it had a
    // terminal would hide the thing that is holding the scope.
    var ls = try run(&f, &.{ "request", "ls", "box", "--json", "--db", f.db });
    defer ls.deinit(f.allocator);
    try ls.expectCode(0);
    try ls.expectSays(in_flight_id);
    try ls.expectSays("\"blocksScope\": true");

    // The receipt trail is readable without a network, which is what makes an
    // after-the-fact audit possible at all.
    var receipt = try run(&f, &.{ "request", "receipt", in_flight_id, "--json", "--db", f.db });
    defer receipt.deinit(f.allocator);
    try receipt.expectCode(0);
    try receipt.expectSays("indeterminate");
}
