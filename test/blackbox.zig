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
//! What is *not* here: anything needing a real remote host. Exit 75 on a lost
//! `sendKeys` response, and `--from-log` reading a real sentinel, both need an
//! SSH endpoint; they belong to the live end-to-end run, not to `zig build
//! test`, and pretending otherwise with a mock would gate on the mock.
//!
//! The one exception is `FakeHost` below, and the line it does not cross is
//! worth stating: it stands in for the *transport*, never for a decision. Every
//! rule under test — which record may settle an operation, what the ledger ends
//! up holding, which exit code comes back, whether the scope is still barred —
//! is executed by the real binary against a real store. What the fake supplies
//! is the bytes a host would have sent, which is the one thing `zig build test`
//! cannot obtain and the one thing none of these gates is asserting about.
const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const Terminus = @import("Terminus");
const Store = Terminus.Core.Store;
const protocol = Terminus.Core.daemon_protocol;

const exe_path = build_options.terminus_exe;

/// The POSIX shell the two shell-execution gates below run their generated
/// text through. Resolved by the build: `-Dposix-sh=<path>`, else PATH, else
/// Git for Windows' own `sh.exe`.
const posix_sh = build_options.posix_sh;

/// Run a generated script through a real POSIX shell.
///
/// Reading generated shell text is not the same as knowing what it does, so
/// two gates here execute it. That makes a POSIX shell a prerequisite of
/// `zig build test` on Windows, and an absent one is reported as such.
///
/// It is not skipped. A skipped gate raises the pass count and checks
/// nothing, which is worse than having no gate at all: the number says the
/// wrapper's quoting rules were verified when they were not.
///
/// Only `FileNotFound` is translated, because only `FileNotFound` is
/// ambiguous — the script was just written by a `try` above and the scratch
/// directory exists, so at this point it means the shell. `IsDir`,
/// `AccessDenied` and `InvalidExe` already name their own cause and are
/// passed through untouched.
fn runPosixShell(
    arena: std.mem.Allocator,
    io: std.Io,
    script_path: []const u8,
    cwd: std.process.Child.Cwd,
) !std.process.RunResult {
    return std.process.run(arena, io, .{
        .argv = &.{ posix_sh, script_path },
        .cwd = cwd,
        .stdout_limit = .limited(1 << 16),
        .stderr_limit = .limited(1 << 16),
    }) catch |err| switch (err) {
        error.FileNotFound => {
            std.debug.print(
                \\
                \\this gate runs generated shell text through a real POSIX shell, and none
                \\was found at '{s}'. Install Git for Windows, or pass
                \\-Dposix-sh=<path-to-sh>.
                \\
                \\
            , .{posix_sh});
            return error.PosixShellNotFound;
        },
        else => return err,
    };
}

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
    return runWithEnvironment(f, argv, null);
}

fn runWithEnvironment(
    f: *Fixture,
    argv: []const []const u8,
    environ: ?*const std.process.Environ.Map,
) !Run {
    const allocator = f.allocator;
    var full: std.ArrayList([]const u8) = .empty;
    defer full.deinit(allocator);
    try full.append(allocator, exe_path);
    try full.appendSlice(allocator, argv);

    const result = try std.process.run(allocator, f.io, .{
        .argv = full.items,
        .environ_map = environ,
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
///
/// `kind` decides whether the resulting blocker is one a later launch will
/// spend a connection on: only a `job` leaves durable evidence on the host
/// (its result sidecar, its pane log), so only a `job` is worth going to read.
fn seedInFlight(
    f: *Fixture,
    request_id: []const u8,
    alias: []const u8,
    kind: Store.operations.Kind,
) !void {
    var store = try f.open();
    defer store.close();

    try Store.operations.create(&store, .{
        .request_id = request_id,
        .server_id = 1,
        .server_name = "box",
        .kind = kind,
        .scope_kind = .job,
        .scope_key = alias,
        .alias = alias,
        .now = 1000,
    });
    try Store.operations.advance(&store, request_id, .connecting, 1001);
    try Store.operations.advance(&store, request_id, .submitted, 1002);
    if (kind != .job) return;
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

fn seedInFlightJob(f: *Fixture, request_id: []const u8, alias: []const u8) !void {
    return seedInFlight(f, request_id, alias, .job);
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

test "blackbox: a bare `exit` cannot swallow the wrapper's exit marker" {
    const t = std.testing;
    var f = try Fixture.init(t.allocator, "wrapper");
    defer f.deinit();

    // Run the real supervision wrapper through a real POSIX shell. Every
    // other gate on this wrapper inspects the text it produces, which cannot
    // catch the failure mode: `exit 42` used to terminate the very shell that
    // was going to write the marker, so a command whose status was never in
    // doubt came back `indeterminate`.
    //
    // A missing `sh` fails this gate rather than skipping it. A shell-quoting
    // rule is not something to take on trust because the machine was awkward.
    const nonce: u64 = 987654321;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    for ([_][]const u8{ "exit 42", "sh -c 'exit 42'", "false; exit 42" }, 0..) |command, i| {
        const script = try Terminus.Core.supervisor.wrapShell(arena, command, nonce);

        // Via a file rather than `sh -c <text>`: the script is multi-line and
        // full of quotes, and this gate is about the wrapper, not about how
        // two layers of argument quoting survive a Windows command line.
        const path = try std.fmt.allocPrint(arena, "{s}/wrap_{d}.sh", .{ f.dir, i });
        try std.Io.Dir.cwd().writeFile(f.io, .{ .sub_path = path, .data = script });
        defer std.Io.Dir.cwd().deleteFile(f.io, path) catch {};

        const result = try runPosixShell(arena, f.io, path, .inherit);

        const observed = try Terminus.Core.supervisor.parseShell(arena, nonce, result.stdout, result.stderr);
        std.testing.expectEqual(@as(?i32, 42), observed.exit_code) catch |err| {
            std.debug.print("command {s} lost its marker\nstdout:\n{s}\n", .{ command, result.stdout });
            return err;
        };
    }
}

test "blackbox: a job records its exit status where later output cannot bury it" {
    const t = std.testing;
    var f = try Fixture.init(t.allocator, "sidecar");
    defer f.deinit();

    // Same reasoning as the wrapper gate above: the launch line is a single
    // line of shell holding a capture of `$?`, a printf format, a redirect and
    // a rename, and reading it is not the same as knowing it runs. Run it
    // through a real POSIX shell and look at what lands on disk.
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const request_id = "01JQXW8ZK4N0RS7T3VYB2MCDEF";
    const sentinel = "__TERMINUS_JOB_555__";

    const cases = [_]struct { command: []const u8, code: []const u8 }{
        .{ .command = "true", .code = "0" },
        .{ .command = "exit 3", .code = "3" },
        // The case the sidecar is for: a command that keeps the pane busy
        // long after it has answered. Its own output would push the sentinel
        // out of any tail window; the result file is unaffected.
        .{ .command = "(exit 7); i=0; while [ $i -lt 200 ]; do echo noise; i=$((i+1)); done; exit 7", .code = "7" },
    };

    for (cases, 0..) |case, i| {
        // `HOME=.` keeps `$HOME/.terminus/results` inside the scratch
        // directory: a test must never write into the real home.
        const line = try Terminus.Core.Tmux.jobLaunchLine(arena, case.command, null, sentinel, request_id);
        const script = try std.fmt.allocPrint(arena, "HOME=.\nexport HOME\n{s}\n", .{line});

        const path = try std.fmt.allocPrint(arena, "{s}/launch_{d}.sh", .{ f.dir, i });
        try std.Io.Dir.cwd().writeFile(f.io, .{ .sub_path = path, .data = script });
        defer std.Io.Dir.cwd().deleteFile(f.io, path) catch {};

        const result = try runPosixShell(
            arena,
            f.io,
            try std.fmt.allocPrint(arena, "launch_{d}.sh", .{i}),
            .{ .path = f.dir },
        );

        const doc_path = try std.fmt.allocPrint(arena, "{s}/.terminus/results/{s}.json", .{ f.dir, request_id });
        const doc = std.Io.Dir.cwd().readFileAlloc(f.io, doc_path, arena, .limited(4096)) catch |err| {
            std.debug.print("command '{s}' left no result document: {s}\nstdout:\n{s}\nstderr:\n{s}\n", .{ case.command, @errorName(err), result.stdout, result.stderr });
            return err;
        };

        const wanted_code = try std.fmt.allocPrint(arena, "\"exitCode\":{s}", .{case.code});
        std.testing.expect(std.mem.indexOf(u8, doc, wanted_code) != null) catch |err| {
            std.debug.print("command '{s}' recorded {s}, wanted {s}\n", .{ case.command, doc, wanted_code });
            return err;
        };
        try t.expect(std.mem.indexOf(u8, doc, request_id) != null);
        try t.expect(std.mem.indexOf(u8, doc, "\"v\":1") != null);

        // The document is published by rename, so a reader never sees the
        // partial write, and nothing is left behind pretending to be one.
        const part = try std.fmt.allocPrint(arena, "{s}.part", .{doc_path});
        try t.expectError(error.FileNotFound, std.Io.Dir.cwd().statFile(f.io, part, .{}));

        // The sentinel is still written: jobs whose result file is discarded
        // fall back to it, so it has to keep working.
        const marker = try std.fmt.allocPrint(arena, "{s}:{s}", .{ sentinel, case.code });
        try t.expect(std.mem.indexOf(u8, result.stdout, marker) != null);

        try std.Io.Dir.cwd().deleteFile(f.io, doc_path);
    }
}

/// A job-name reservation left behind by a launcher that did not finish,
/// with its owning attempt parked at `status`.
fn seedReservation(f: *Fixture, request_id: []const u8, name: []const u8, status: []const u8) !void {
    var store = try f.open();
    defer store.close();

    try Store.operations.create(&store, .{
        .request_id = request_id,
        .server_id = 1,
        .server_name = "box",
        .kind = .job,
        .scope_kind = .job,
        .scope_key = name,
        .alias = name,
        .mutating = true,
        .now = 1000,
    });
    try Store.operations.advance(&store, request_id, .connecting, 1001);
    if (std.mem.eql(u8, status, "submitted")) {
        try Store.operations.advance(&store, request_id, .submitted, 1002);
    }
    _ = try Store.jobs.create(&store, 1, name, "make deploy", "__TERMINUS_JOB_9__", request_id, 1002);
}

test "blackbox: a stranded reservation is reclaimed only when its launch never submitted" {
    const t = std.testing;
    var f = try Fixture.init(t.allocator, "reclaim");
    defer f.deinit();
    try f.seedServer();

    // Killed while still dialling. The attempt provably handed nothing over,
    // so the name it was holding is free — refusing forever would make every
    // crashed launch a manual cleanup, and deleting it on age would sooner or
    // later delete the row of a launcher that was merely slow.
    try seedReservation(&f, "01AAAAAAAA0123456789ABCDEF", "dialling", "connecting");
    var reclaimed = try run(&f, &.{
        "run", "box", "--name", "dialling", "--cmd", "make deploy", "--db", f.db,
    });
    defer reclaimed.deinit(f.allocator);
    try reclaimed.expectSaysNot("is pending");
    try reclaimed.expectSays("connect"); // got past the guard, died at the network

    // Killed after submitting. Something may be running under that name, so
    // the reservation stands and `--force` does not move it: forcing means "I
    // accept an unknown outcome", not "tear the name off a live job".
    try seedReservation(&f, "01BBBBBBBB0123456789ABCDEF", "sent", "submitted");
    var refused = try run(&f, &.{
        "run", "box", "--name", "sent", "--cmd", "make deploy", "--force", "--db", f.db,
    });
    defer refused.deinit(f.allocator);
    try refused.expectCode(1);
    try refused.expectSays("is pending");
    try refused.expectSays("nothing was sent");
    try refused.expectSaysNot("cannot connect");

    var store = try f.open();
    defer store.close();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const survivor = (try Store.jobs.getByName(&store, arena_state.allocator(), 1, "sent")).?;
    try t.expectEqualStrings("01BBBBBBBB0123456789ABCDEF", survivor.owner_request_id.?);
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
        "request", "reconcile", in_flight_id, "--override", "looks done to me",
        "--by",    "operator",  "--resolved", "completed",  "--db",
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
        "request", "reconcile", in_flight_id, "--override", "ssh'd in; the deploy finished",
        "--by",    "czykl",     "--resolved", "completed",  "--json",
        "--db",    f.db,
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

    // Same job name, unknown predecessor. The predecessor is a job, so the
    // launch is entitled to spend one connection finding out whether it has
    // already finished — the server here is a closed port, so it cannot. What
    // this gate pins is that failing to reach the host does not become the
    // command's answer: the refusal the guard already holds is the more useful
    // one, and an agent that reads "refused" and retries is the failure mode
    // the guard exists for.
    var again = try run(&f, &.{
        "run", "box", "--name", "deploy", "--cmd", "make deploy", "--db", f.db,
    });
    defer again.deinit(f.allocator);
    try again.expectCode(1);
    try again.expectSays("refused");
    try again.expectSays("the job was not started");
    try again.expectSays(in_flight_id);
    // It really did try, and said so — the probe is not silent about giving
    // up. Without this the gate would pass just as well with the probe
    // removed, which is how the previous version of it stopped meaning
    // anything when the probe was added.
    try again.expectSays("could not reach");

    // A non-overlapping scope is not blocked by it. (It fails at the network,
    // which is proof enough that the guard let it through.)
    var other = try run(&f, &.{
        "run", "box", "--name", "unrelated", "--cmd", "true", "--db", f.db,
    });
    defer other.deinit(f.allocator);
    try other.expectSaysNot("refused: request");
}

test "blackbox: a blocker with nothing to read is refused without dialling" {
    const t = std.testing;
    var f = try Fixture.init(t.allocator, "guard_no_dial");
    defer f.deinit();
    try f.seedServer();
    // An `exec` leaves no durable record on the host: no sidecar addressed by
    // its request id, no pane log, nothing a probe could read. Connecting to
    // ask about it would cost a round trip and learn nothing, so this blocker
    // must be refused where it stands.
    try seedInFlight(&f, in_flight_id, "deploy", .exec);

    var blocked = try run(&f, &.{
        "run", "box", "--name", "deploy", "--cmd", "make deploy", "--db", f.db,
    });
    defer blocked.deinit(f.allocator);
    try blocked.expectCode(1);
    try blocked.expectSays("refused");
    try blocked.expectSays(in_flight_id);
    // The whole point: no connection was attempted. The closed port would
    // have produced this line, so its absence is the evidence.
    try blocked.expectSaysNot("could not reach");
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

/// A stand-in for the local daemon, so a gate can put a chosen result record in
/// front of the real binary without a remote host.
///
/// The binary reaches a host in exactly two ways: the daemon socket, or a
/// direct SSH connection. The second cannot be produced under `zig build test`
/// — it needs a listening server and a real key — and the first is a documented
/// local protocol whose address is derived from the environment. So this binds
/// that address inside a scratch directory and answers the CLI's own protocol.
///
/// Deliberately *not* a way to test the probe's reasoning. The bytes below are
/// what a host sends; every conclusion drawn from them — the reading, the
/// refusal, the terminal written to the ledger, the exit code, the scope
/// barrier — is the binary's, computed by the same code an operator runs. That
/// is the whole reason these four facts are checked out here rather than in
/// process: an exit code reachable only through `std.process.exit` and a scope
/// barrier reachable only through a second command are exactly the two that go
/// untested from the inside.
const FakeHost = struct {
    /// One scripted answer, matched by a substring of the command the binary
    /// sends. Substrings rather than whole scripts because the scripts carry
    /// paths and byte counts that are none of a gate's business; what a gate
    /// means is "the probe" or "the kill".
    const Rule = struct {
        needle: []const u8,
        exit_code: i32 = 0,
        stdout: []const u8 = "",
        /// How many times this rule may answer before the next matching one
        /// takes over. The default answers forever; a bounded one is how a gate
        /// says "the host changed between these two looks", which is the whole
        /// shape of a job that reaches its own end during the round trip.
        uses: u32 = std.math.maxInt(u32),
    };

    io: std.Io,
    allocator: std.mem.Allocator,
    home: []u8,
    socket: []u8,
    server: std.Io.net.Server,
    rules: []Rule,
    thread: std.Thread,
    /// Set before the listener is touched, so the serve loop learns it is done
    /// from a value it owns rather than from a `Server` this thread has already
    /// invalidated. See `stop`.
    closing: std.atomic.Value(bool),
    /// Commands the rules did not cover. Never answered with a plausible
    /// success: a fake that quietly invents replies for calls nobody scripted
    /// turns a gate into a measurement of the fake.
    unscripted: std.atomic.Value(u32),

    fn start(f: *Fixture, rules: []Rule) !*FakeHost {
        const home = try std.fmt.allocPrint(f.allocator, "{s}/home", .{f.dir});
        errdefer f.allocator.free(home);
        const socket_dir = try std.fmt.allocPrint(f.allocator, "{s}/.terminus", .{home});
        defer f.allocator.free(socket_dir);
        try std.Io.Dir.cwd().createDirPath(f.io, socket_dir);
        const socket = try std.fmt.allocPrint(f.allocator, "{s}/daemon.sock", .{socket_dir});
        errdefer f.allocator.free(socket);
        std.Io.Dir.cwd().deleteFile(f.io, socket) catch {};

        const address = try std.Io.net.UnixAddress.init(socket);
        const host = try f.allocator.create(FakeHost);
        errdefer f.allocator.destroy(host);
        host.* = .{
            .io = f.io,
            .allocator = f.allocator,
            .home = home,
            .socket = socket,
            .server = try address.listen(f.io, .{}),
            .rules = rules,
            .thread = undefined,
            .closing = .init(false),
            .unscripted = .init(0),
        };
        host.thread = try std.Thread.spawn(.{}, serve, .{host});
        return host;
    }

    /// The child's environment: this process's own, with the home pointed at
    /// the scratch directory so the binary looks for its daemon socket there.
    ///
    /// A full copy rather than a two-entry map. The child is a real process on
    /// this machine, and stripping `SystemRoot`, `PATH` and the rest to isolate
    /// one variable would be gating on an environment nobody has.
    fn environment(host: *FakeHost) !std.process.Environ.Map {
        var map = switch (builtin.os.tag) {
            .windows => try (std.process.Environ{ .block = .global }).createMap(host.allocator),
            // Not quietly degraded to an empty environment. There is no
            // portable way to read this process's own environment without the
            // `std.process.Init` a test does not get, and running the binary
            // with nothing in its environment would gate on a machine that does
            // not exist. The daemon transport this stands in for is itself
            // Windows-only until M5.
            else => {
                std.debug.print(
                    \\
                    \\this gate points the binary's home at a scratch directory, which needs a
                    \\snapshot of this process's own environment; only the Windows path is
                    \\implemented, and the daemon transport it drives is Windows-only until M5.
                    \\
                    \\
                , .{});
                return error.ScratchHomeNeedsWindows;
            },
        };
        errdefer map.deinit();
        try map.put("USERPROFILE", host.home);
        try map.put("HOME", host.home);
        return map;
    }

    /// Asserts that every command the binary sent was one this gate scripted.
    ///
    /// Without it a gate can pass for the wrong reason. An unmatched command
    /// comes back as a transport failure, and a command that fails at the
    /// transport also exits nonzero and prints a refusal — which is precisely
    /// what several of these gates assert. So a gate that had drifted off the
    /// path it means to drive would still be green.
    fn expectFullyScripted(host: *FakeHost) !void {
        const missed = host.unscripted.load(.monotonic);
        std.testing.expectEqual(@as(u32, 0), missed) catch |err| {
            std.debug.print(
                "{d} command(s) reached the fake host with no rule to answer them\n",
                .{missed},
            );
            return err;
        };
    }

    fn stop(host: *FakeHost) void {
        host.closing.store(true, .release);
        // One throwaway connection, to return the blocked `accept`. Closing the
        // listener first instead is what the first version did, and it is a
        // data race with teeth: `Server.deinit` sets the value to `undefined`,
        // which in a debug build is a memory pattern, and the serve thread was
        // still inside `accept` reading the socket handle out of it.
        if (std.Io.net.UnixAddress.init(host.socket)) |address| {
            if (address.connect(host.io)) |stream| {
                var knock = stream;
                knock.close(host.io);
            } else |_| {}
        } else |_| {}
        host.thread.join();
        host.server.deinit(host.io);
        std.Io.Dir.cwd().deleteFile(host.io, host.socket) catch {};
        host.allocator.free(host.socket);
        host.allocator.free(host.home);
        host.allocator.destroy(host);
    }

    fn serve(host: *FakeHost) void {
        while (true) {
            var stream = host.server.accept(host.io) catch return;
            defer stream.close(host.io);
            if (host.closing.load(.acquire)) return;
            host.converse(&stream) catch {};
        }
    }

    fn converse(host: *FakeHost, stream: *std.Io.net.Stream) !void {
        var read_buffer: [1 << 16]u8 = undefined;
        var reader = stream.reader(host.io, &read_buffer);
        var write_buffer: [1 << 16]u8 = undefined;
        var writer = stream.writer(host.io, &write_buffer);

        var arena_state = std.heap.ArenaAllocator.init(host.allocator);
        defer arena_state.deinit();

        while (true) {
            // A peer reset here is the ordinary end of a conversation, not a
            // fault: the exit codes these gates exist to check are reached
            // through `std.process.exit`, which skips the CLI's own socket
            // close. Windows reports that as a status std does not map, so a
            // `zig build test` run prints its trace and returns the error to
            // this `catch`. Left unsuppressed — turning `std.options`'
            // unexpected-error tracing off for this binary would hide the whole
            // class to quieten one known member of it.
            const line = (reader.interface.takeDelimiter('\n') catch return) orelse return;
            if (line.len == 0) continue;
            const request = protocol.parseMessage(protocol.Request, arena_state.allocator(), line) catch {
                try protocol.writeMessage(&writer.interface, protocol.Response{
                    .v = protocol.version,
                    .ok = false,
                    .@"error" = "the gate's fake host could not parse that request",
                });
                continue;
            };
            const response: protocol.Response = switch (request.op) {
                .ping => .{ .v = protocol.version, .ok = true, .pid = 1 },
                .stop => .{ .v = protocol.version, .ok = true },
                .exec => host.replyTo(request.command),
            };
            try protocol.writeMessage(&writer.interface, response);
        }
    }

    fn replyTo(host: *FakeHost, command: []const u8) protocol.Response {
        for (host.rules) |*rule| {
            if (rule.uses == 0) continue;
            if (std.mem.indexOf(u8, command, rule.needle) != null) {
                if (rule.uses != std.math.maxInt(u32)) rule.uses -= 1;
                return .{
                    .v = protocol.version,
                    .ok = true,
                    .exitCode = rule.exit_code,
                    .stdout = rule.stdout,
                };
            }
        }
        _ = host.unscripted.fetchAdd(1, .monotonic);
        return .{
            .v = protocol.version,
            .ok = false,
            .@"error" = "the gate's fake host has no reply scripted for this command",
        };
    }
};

/// The remote wrapper's own framing, so a gate states what the host sent rather
/// than what the parser happens to want.
const probe_split = "__TERMINUS_PROBE_SPLIT__";

/// A job that reached the remote shell and is still recorded as running, with
/// the scope its name reserves held by its own operation.
fn seedRunningJob(f: *Fixture, request_id: []const u8, name: []const u8, sentinel: []const u8) !void {
    var store = try f.open();
    defer store.close();

    try Store.operations.create(&store, .{
        .request_id = request_id,
        .server_id = 1,
        .server_name = "box",
        .kind = .job,
        .scope_kind = .job,
        .scope_key = name,
        .alias = name,
        .mutating = true,
        .now = 1000,
    });
    try Store.operations.advance(&store, request_id, .connecting, 1001);
    try Store.operations.advance(&store, request_id, .submitted, 1002);
    try Store.operations.advance(&store, request_id, .remote_started, 1003);
    _ = try Store.jobs.create(&store, 1, name, "make deploy", sentinel, request_id, 1002);
    if (!try Store.jobs.markStarted(&store, request_id)) return error.RowWasNotReserved;
    const session = try std.fmt.allocPrint(f.allocator, "job-{s}", .{name});
    defer f.allocator.free(session);
    _ = try Store.job_attempts.create(&store, .{
        .request_id = request_id,
        .server_id = 1,
        .server_name = "box",
        .job_name = name,
        .attempt_no = 1,
        .sentinel = sentinel,
        .tmux_session = session,
        .now = 1003,
    });
}

test "blackbox: a defective result record ends `job kill` at 75 with the scope still barred" {
    const t = std.testing;
    var f = try Fixture.init(t.allocator, "defective_kill");
    defer f.deinit();
    try f.seedServer();

    const request_id = "01CCCCCCCC0123456789ABCDEF";
    const sentinel = "__TERMINUS_JOB_7__";
    try seedRunningJob(&f, request_id, "deploy", sentinel);

    // A document at this request's own address carrying an exit status no shell
    // produces, with the job's own sentinel still in the tail behind it. Both
    // records are present; the stronger one cannot be read, so the weaker one
    // cannot be checked against it and nothing here may settle.
    const probe_output = "{\"v\":1,\"requestId\":\"" ++ request_id ++ "\",\"exitCode\":9000,\"finishedAt\":1750}\n" ++
        probe_split ++ "\n20\nwork done\n" ++ sentinel ++ ":7\n";
    var rules = [_]FakeHost.Rule{
        .{ .needle = probe_split, .stdout = probe_output },
        // The kill goes ahead — the caller asked for the session to stop. What
        // is refused is reporting it as having established an outcome.
        .{ .needle = "kill-session", .exit_code = 0 },
        .{ .needle = "has-session", .exit_code = 0 },
    };
    var host = try FakeHost.start(&f, &rules);
    defer host.stop();
    var environ = try host.environment();
    defer environ.deinit();

    var killed = try runWithEnvironment(&f, &.{
        "job", "kill", "box", "deploy", "--json", "--db", f.db,
    }, &environ);
    defer killed.deinit(f.allocator);

    // The exit code, taken from the process. Every in-process gate on this rule
    // reads it off a function's return value; this is the only one that proves
    // the number leaves the binary, and 75 rather than 1 is what tells an agent
    // a retry is not available.
    try killed.expectCode(75);
    // …driven down the path this gate means to drive, rather than tripping over
    // a command the fake could not answer, which also exits nonzero.
    try host.expectFullyScripted();

    // The JSON shape: both keys, here and on every other `job kill` branch.
    // `resultRecord` is the machine enumeration a caller may branch on;
    // `resultRecordError` is prose it may not.
    try killed.expectSays("\"resultRecord\": \"exit_code_out_of_range\"");
    try killed.expectSays("\"resultRecordError\": \"");
    try killed.expectSays("\"cancellationProven\": false");
    try killed.expectSays("\"ok\": false");
    // The hint has to name a command that can actually succeed. `--from-log`
    // reads these same two records and refuses for the same reason, so pointing
    // at it would be a dead end wearing the shape of a next step.
    try killed.expectSays("--override");
    try killed.expectSaysNot("--from-log");

    // The ledger row, read out of the store rather than out of the report that
    // claimed it.
    {
        var store = try f.open();
        defer store.close();
        var arena_state = std.heap.ArenaAllocator.init(t.allocator);
        defer arena_state.deinit();
        const op = (try Store.operations.get(&store, arena_state.allocator(), request_id)).?;
        try t.expectEqualStrings("indeterminate", op.status.text());
    }

    // And the scope is still barred, which is the point of settling
    // `indeterminate` rather than `completed`: the name stays reserved until
    // somebody establishes what actually happened. Asserted through a second
    // command, because that is the only form the barrier takes for a caller.
    var relaunch = try runWithEnvironment(&f, &.{
        "run", "box", "--name", "deploy", "--cmd", "make deploy", "--db", f.db,
    }, &environ);
    defer relaunch.deinit(f.allocator);
    try relaunch.expectCode(1);
    try relaunch.expectSays("refused");
    try relaunch.expectSays(request_id);
}

test "blackbox: a job with no result record still settles, exits 0 and frees its scope" {
    const t = std.testing;
    var f = try Fixture.init(t.allocator, "absent_kill");
    defer f.deinit();
    try f.seedServer();

    const request_id = "01DDDDDDDD0123456789ABCDEF";
    const sentinel = "__TERMINUS_JOB_7__";
    try seedRunningJob(&f, request_id, "deploy", sentinel);

    // The control, and the half of the rule that is easy to lose: an absence is
    // not a defect. Same window, same sentinel, and nothing whatever at the
    // result record's address — a job launched before sidecars existed, or one
    // whose evidence was discarded. Without this the gate above would pass just
    // as happily against a binary that refused every reading there is.
    const probe_output = "\n" ++ probe_split ++ "\n20\nwork done\n" ++ sentinel ++ ":0\n";
    var rules = [_]FakeHost.Rule{
        .{ .needle = probe_split, .stdout = probe_output },
        .{ .needle = "kill-session", .exit_code = 0 },
        .{ .needle = "has-session", .exit_code = 0 },
    };
    var host = try FakeHost.start(&f, &rules);
    defer host.stop();
    var environ = try host.environment();
    defer environ.deinit();

    var killed = try runWithEnvironment(&f, &.{
        "job", "kill", "box", "deploy", "--json", "--db", f.db,
    }, &environ);
    defer killed.deinit(f.allocator);
    try killed.expectCode(0);
    try host.expectFullyScripted();
    try killed.expectSays("\"ok\": true");
    try killed.expectSays("\"exitCode\": 0");
    // The same two keys on a branch that found nothing wrong: `resultRecord`
    // names the reading even when the reading is "there was nothing there", and
    // `resultRecordError` is the JSON null saying there is no sentence to read.
    // A caller gets one key set out of `job kill --json`, not four.
    try killed.expectSays("\"resultRecord\": \"absent\"");
    try killed.expectSays("\"resultRecordError\": null");

    {
        var store = try f.open();
        defer store.close();
        var arena_state = std.heap.ArenaAllocator.init(t.allocator);
        defer arena_state.deinit();
        const op = (try Store.operations.get(&store, arena_state.allocator(), request_id)).?;
        try t.expectEqualStrings("completed", op.status.text());
        // Nothing left holding the job scope, which is what "released" means to
        // whoever launches next.
        const unsettled = try Store.operations.unsettled(&store, arena_state.allocator(), 1);
        try t.expectEqual(@as(usize, 0), unsettled.len);
    }

    // …and a relaunch is not turned away where it stands. It fails at the host
    // — the fake has no reply scripted for a launch — but it is not refused by
    // the scope guard, which is the difference this control draws.
    var relaunch = try runWithEnvironment(&f, &.{
        "run", "box", "--name", "deploy", "--cmd", "make deploy", "--db", f.db,
    }, &environ);
    defer relaunch.deinit(f.allocator);
    try relaunch.expectSaysNot("refused: request");
}

/// The race both mutating verbs have to survive: the job reaches its own end
/// during the SSH round trip, so the command's first probe sees work in
/// progress and its second — the one taken after the session is proven gone —
/// sees a document at this request's address that cannot be read.
///
/// Which probe happened to see the defect used to decide the exit code, because
/// the second look reported a refusal by returning nothing at all. `job rm` then
/// printed `{"action":"removed","ok":true}` and exit 0 with a hint naming a
/// `--from-log` reconcile that reads these same two records and refuses; `job
/// kill` exited 75 for an unrelated reason and wrote a receipt that never
/// mentioned the document. The receipt is the only record that outlives a
/// removal, so "never mentioned it" means nobody can ever find out.
fn defectArrivesDuringTheKill(fixture_name: []const u8, verb: []const u8) !void {
    const t = std.testing;
    var f = try Fixture.init(t.allocator, fixture_name);
    defer f.deinit();
    try f.seedServer();

    const request_id = "01EEEEEEEE0123456789ABCDEF";
    const sentinel = "__TERMINUS_JOB_7__";
    try seedRunningJob(&f, request_id, "deploy", sentinel);

    const defective = try std.fmt.allocPrint(
        f.allocator,
        "{{\"v\":1,\"requestId\":\"{s}\",\"exitCode\":9000,\"finishedAt\":1750}}\n{s}\n20\nwork done\n{s}:7\n",
        .{ request_id, probe_split, sentinel },
    );
    defer f.allocator.free(defective);

    var rules = [_]FakeHost.Rule{
        // The first look, once: nothing at the address, nothing in the log.
        .{ .needle = probe_split, .stdout = "\n" ++ probe_split ++ "\n12\nbuilding...\n", .uses = 1 },
        // Every look after it: the job finished while we were stopping it, and
        // what it left behind carries an exit status no shell produces.
        .{ .needle = probe_split, .stdout = defective },
        .{ .needle = "kill-session", .exit_code = 0 },
        .{ .needle = "has-session", .exit_code = 0 },
    };
    var host = try FakeHost.start(&f, &rules);
    defer host.stop();
    var environ = try host.environment();
    defer environ.deinit();

    var acted = try runWithEnvironment(&f, &.{
        "job", verb, "box", "deploy", "--json", "--db", f.db,
    }, &environ);
    defer acted.deinit(f.allocator);

    try acted.expectCode(75);
    try host.expectFullyScripted();
    try acted.expectSays("\"ok\": false");
    // The hint has to name a command that can succeed. `--from-log` reads the
    // same two records and refuses for the same reason, so offering it is a
    // dead end wearing the shape of a next step — and it is what `job rm`
    // offered, beside `ok: true`.
    try acted.expectSays("--override");
    try acted.expectSaysNot("--from-log");

    var store = try f.open();
    defer store.close();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const op = (try Store.operations.get(&store, arena, request_id)).?;
    try t.expectEqualStrings("indeterminate", op.status.text());

    // The receipt names both halves: the verdict that was declined, and the
    // reading that declined it. `job rm` deletes the local row, so this is the
    // only place either fact still exists afterwards.
    const rows = try Store.receipts.list(&store, arena, request_id);
    var terminal_reason: ?[]const u8 = null;
    var terminal_detail: ?[]const u8 = null;
    for (rows) |row| if (row.is_terminal) {
        terminal_reason = row.transport_error;
        terminal_detail = row.detail_json;
    };
    const reason = terminal_reason orelse return error.RemovalLeftNoTerminalReceipt;
    try t.expect(std.mem.indexOf(u8, reason, "exit 7") != null);
    try t.expect(std.mem.indexOf(u8, reason, "result record") != null);
    try t.expect(std.mem.indexOf(u8, terminal_detail.?, "exit_code_out_of_range") != null);
}

test "blackbox: `job kill` does not lose a result record that turned up during the kill" {
    try defectArrivesDuringTheKill("race_kill", "kill");
}

test "blackbox: `job rm` does not report a clean removal over a record it refused" {
    try defectArrivesDuringTheKill("race_rm", "rm");
}
