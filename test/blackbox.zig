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

test "blackbox: a result record the host cannot read is not a result record that is absent" {
    const t = std.testing;
    var f = try Fixture.init(t.allocator, "unreadable_sidecar");
    defer f.deinit();

    // The third script this file runs through a real POSIX shell, and for the
    // same reason as the other two: what `readResult`'s text does under a
    // failing `head` is the whole of its contract, and reading the text is not
    // knowing it.
    //
    // The text used to end `head -c N "$r" | tr -d '\n'`. A POSIX pipeline
    // exits with the status of its *last* command, so `tr` answered 0 for
    // every `head` that could not open the file — and the script's own
    // documentation says exit 0 with no output means the record is absent.
    // Absence is the one reading that lets the job's log sentinel settle the
    // operation by itself, so a defect at this attempt's own address was being
    // turned into a licence to settle from the weaker record.
    //
    // The failure is injected as a shell function, not as a broken file. What
    // has to be established is that `head`'s status reaches the script's
    // status; a `chmod` that Windows may not honour, or a directory (which
    // `[ -f ]` rejects before `head` is ever reached), would each test
    // something else. The shell is real and the script is the exact text the
    // binary sends.
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const request_id = "01JQXW8ZK4N0RS7T3VYB2MCDEF";
    const document = "{\"v\":1,\"requestId\":\"" ++ request_id ++ "\",\"exitCode\":3,\"finishedAt\":1750}";
    const script = try Terminus.Core.Tmux.resultReadScript(arena, request_id);

    // `HOME=.` keeps `$HOME/.terminus/results` inside the scratch directory: a
    // test must never read or write the real home.
    const preamble = "HOME=.\nexport HOME\n";
    const cases = [_]struct {
        what: []const u8,
        inject: []const u8,
        write_document: bool,
        code: u8,
        stdout: []const u8,
    }{
        // The bug. The file is there, `[ -f "$r" ]` passes, and the read of it
        // fails: the script has to say so in its exit status, because its only
        // other channel — stdout — is empty on this path and empty is taken to
        // mean the file was not there at all.
        .{ .what = "an unreadable record", .inject = "head() { return 1; }\n", .write_document = true, .code = 44, .stdout = "" },
        // The two controls, without which the gate would pass against a script
        // that refuses everything, or one that never runs.
        .{ .what = "a readable record", .inject = "", .write_document = true, .code = 0, .stdout = document },
        .{ .what = "no record at all", .inject = "", .write_document = false, .code = 0, .stdout = "" },
    };

    const results_dir = try std.fmt.allocPrint(arena, "{s}/.terminus/results", .{f.dir});
    try std.Io.Dir.cwd().createDirPath(f.io, results_dir);
    const doc_path = try std.fmt.allocPrint(arena, "{s}/{s}.json", .{ results_dir, request_id });

    for (cases, 0..) |case, i| {
        std.Io.Dir.cwd().deleteFile(f.io, doc_path) catch {};
        if (case.write_document)
            try std.Io.Dir.cwd().writeFile(f.io, .{ .sub_path = doc_path, .data = document });

        const name = try std.fmt.allocPrint(arena, "read_result_{d}.sh", .{i});
        const path = try std.fmt.allocPrint(arena, "{s}/{s}", .{ f.dir, name });
        try std.Io.Dir.cwd().writeFile(f.io, .{
            .sub_path = path,
            .data = try std.fmt.allocPrint(arena, "{s}{s}{s}\n", .{ preamble, case.inject, script }),
        });
        defer std.Io.Dir.cwd().deleteFile(f.io, path) catch {};

        const result = try runPosixShell(arena, f.io, name, .{ .path = f.dir });
        const code: u8 = switch (result.term) {
            .exited => |c| c,
            else => return error.ShellDidNotExitNormally,
        };
        std.testing.expectEqual(case.code, code) catch |err| {
            std.debug.print(
                "{s}: the sidecar read script exited {d}, wanted {d}\n--- script ---\n{s}\n--- stdout ---\n{s}\n--- stderr ---\n{s}\n",
                .{ case.what, code, case.code, script, result.stdout, result.stderr },
            );
            return err;
        };
        std.testing.expectEqualStrings(case.stdout, result.stdout) catch |err| {
            std.debug.print("{s}: unexpected stdout\n", .{case.what});
            return err;
        };
    }

    // The two answers a caller has to be able to tell apart both came back
    // with no output at all. Only the status separates them, which is exactly
    // what the pipeline was throwing away.
    try t.expectEqualStrings("", cases[0].stdout);
    try t.expectEqualStrings("", cases[2].stdout);
    try t.expect(cases[0].code != cases[2].code);

    // The same read, in the other reader. `probeTail` fetches the record and a
    // tail of the log in one round trip, so its sidecar read sits in the middle
    // of a script that goes on to print a marker, a byte count and a window —
    // and an `exit` that ended only a subshell would let all of that be printed
    // anyway, which is the pipeline's failure with an extra layer on it.
    const logs_dir = try std.fmt.allocPrint(arena, "{s}/.terminus/logs", .{f.dir});
    try std.Io.Dir.cwd().createDirPath(f.io, logs_dir);
    try std.Io.Dir.cwd().writeFile(f.io, .{
        .sub_path = try std.fmt.allocPrint(arena, "{s}/j.log", .{logs_dir}),
        .data = "work done\n",
    });
    try std.Io.Dir.cwd().writeFile(f.io, .{ .sub_path = doc_path, .data = document });

    const probe_script = try Terminus.Core.Tmux.probeScript(arena, "j", request_id, 4096);
    for ([_]struct { what: []const u8, inject: []const u8, code: u8, marker: bool }{
        .{ .what = "an unreadable record", .inject = "head() { return 1; }\n", .code = 44, .marker = false },
        .{ .what = "a readable record", .inject = "", .code = 0, .marker = true },
    }, 0..) |case, i| {
        const name = try std.fmt.allocPrint(arena, "probe_{d}.sh", .{i});
        try std.Io.Dir.cwd().writeFile(f.io, .{
            .sub_path = try std.fmt.allocPrint(arena, "{s}/{s}", .{ f.dir, name }),
            .data = try std.fmt.allocPrint(arena, "{s}{s}{s}\n", .{ preamble, case.inject, probe_script }),
        });
        const result = try runPosixShell(arena, f.io, name, .{ .path = f.dir });
        const code: u8 = switch (result.term) {
            .exited => |c| c,
            else => return error.ShellDidNotExitNormally,
        };
        std.testing.expectEqual(case.code, code) catch |err| {
            std.debug.print(
                "{s}: the probe script exited {d}, wanted {d}\n--- script ---\n{s}\n--- stdout ---\n{s}\n--- stderr ---\n{s}\n",
                .{ case.what, code, case.code, probe_script, result.stdout, result.stderr },
            );
            return err;
        };
        // The failing read must take the whole script with it. Reaching the
        // marker means the reader is handed a framed answer whose sidecar half
        // is empty — the absence this exists to stop the failure from becoming.
        const reached_marker = std.mem.indexOf(u8, result.stdout, probe_split) != null;
        std.testing.expectEqual(case.marker, reached_marker) catch |err| {
            std.debug.print(
                "{s}: the split marker was {s} in the probe's output\n--- stdout ---\n{s}\n",
                .{ case.what, if (reached_marker) "present" else "absent", result.stdout },
            );
            return err;
        };
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
        /// Take this job's scope lease away from the binary while it waits for
        /// this reply.
        ///
        /// The only deterministic way to reach the window the fail-closed steps
        /// exist for. The binary takes the lease before it dials and then runs a
        /// sequence of remote calls; a peer's `--force` landing *between* two of
        /// them cannot be arranged from outside, but the binary is blocked on
        /// this socket right now, and that is exactly the same instant.
        seize: bool = false,
        /// Renew the binary's *own* lease an hour into the future while it waits
        /// for this reply, so the release it makes on the way out cannot be dated
        /// and `leases.release` refuses it.
        ///
        /// The only deterministic way to reach `left_held` — a leaked lease — from
        /// outside the process. The three ways a release can fail are a store that
        /// cannot be reached, a clock that cannot be read, and a stamp that would
        /// contradict the row's own history; only the third can be arranged, and
        /// only by writing the row through the ordinary renewal with a stamp in
        /// the future. Every later renewal is refused for the same reason, which is
        /// why this belongs on the *last* remote call a branch makes if the report
        /// is to say `authority: held`.
        ///
        /// Not raw SQL where the ordinary writer would do — see `strandLease` for
        /// why no public lease writer can leave this row behind, and for what a
        /// real machine does to produce it.
        strand: bool = false,
    };

    /// The job whose scope a `seize` rule takes, and who takes it. Fixed rather
    /// than per-rule: every gate that uses this drives one job called `deploy`,
    /// and a second knob would be a knob nothing turns.
    const seized_job = "deploy";
    const seizing_peer = "01PEEEEEEER0123456789ABCDE";

    io: std.Io,
    allocator: std.mem.Allocator,
    home: []u8,
    socket: []u8,
    /// The fixture's database, borrowed. Only a `seize` rule touches it.
    db: [:0]const u8,
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
    /// Every command the binary sent, in order.
    ///
    /// `expectFullyScripted` answers "did anything arrive that we did not
    /// script"; it cannot answer "was the kill sent", because a `kill-session`
    /// script also contains `has-session` and would be answered by that rule.
    /// Only a record of the traffic can say what did *not* reach the host, which
    /// is the assertion a fail-closed step is worth anything for.
    seen: std.ArrayList([]u8),
    seen_lock: std.Io.Mutex,
    /// Commands that could not be recorded, and seizures that could not be
    /// performed. Both are reported as gate failures rather than swallowed: a
    /// dropped record makes `expectNeverSent` pass for the wrong reason, and a
    /// seizure that did not happen makes the whole window vanish.
    record_failures: std.atomic.Value(u32),
    seize_failures: std.atomic.Value(u32),
    /// What `Rule.strand` did: how many times it pushed the binary's own lease
    /// into the future, and how many times it could not. Both counted — a strand
    /// that never fired leaves the release perfectly datable, and the gate would
    /// then be asserting `left_held` on a command with nothing wrong with it.
    strands: std.atomic.Value(u32),
    strand_failures: std.atomic.Value(u32),
    /// Take the scope lease while answering the daemon *version handshake*,
    /// before any command has been sent.
    ///
    /// `Rule.seize` cannot reach this window, and the reason is structural: a
    /// rule fires when a command arrives, so by then that command has already
    /// been sent — which is exactly the fact the rule is used to assert about a
    /// kill. A verb whose *first* remote call is destructive therefore has no
    /// round trip on which "the scope moved before anything was sent" can be
    /// arranged, and `session rm` is that verb: there is nothing to probe, so
    /// `kill-session` goes out first.
    ///
    /// The handshake is the round trip that exists anyway. `DaemonClient.acquire`
    /// pings to check the protocol version before `cli.connect` returns, and the
    /// binary takes its operation and its lease *before* it dials — so a peer
    /// taking the scope here lands after the claim and before the first command,
    /// which is the window itself. Fires once: `acquire` pings once per
    /// connection, and a second seizure would displace the peer's own row and
    /// make the assertions afterwards about a different lease.
    seize_on_ping: bool,
    seized_on_ping: std.atomic.Value(bool),

    fn start(f: *Fixture, rules: []Rule) !*FakeHost {
        return startWith(f, rules, false);
    }

    /// `start`, plus a lease seizure on the version handshake. See
    /// `seize_on_ping`.
    fn startSeizingOnHandshake(f: *Fixture, rules: []Rule) !*FakeHost {
        return startWith(f, rules, true);
    }

    fn startWith(f: *Fixture, rules: []Rule, seize_on_ping: bool) !*FakeHost {
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
            .db = f.db,
            .server = try address.listen(f.io, .{}),
            .rules = rules,
            .thread = undefined,
            .closing = .init(false),
            .unscripted = .init(0),
            .seen = .empty,
            .seen_lock = .init,
            .record_failures = .init(0),
            .seize_failures = .init(0),
            .strands = .init(0),
            .strand_failures = .init(0),
            .seize_on_ping = seize_on_ping,
            .seized_on_ping = .init(false),
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

    /// Printed immediately before a traffic assertion's real message.
    ///
    /// The test runner groups whatever stderr arrives during a test into that
    /// test's block, so an assertion's own message can end up well below
    /// anything else the run printed. This says where it starts.
    ///
    /// It used to carry a disclaimer as well: every gate that drove the binary
    /// to `std.process.exit` left this thread blocked on a socket the child
    /// never closed, and std printed an `error.Unexpected NTSTATUS=0xc000020d
    /// (CONNECTION_RESET)` trace for the read that then failed — on green runs
    /// as much as failing ones, which is what made the disclaimer necessary and
    /// what made a real transport failure here unreadable. The binary closes
    /// that socket now, on every exit it has, so those traces are gone rather
    /// than excused. One appearing again is a finding, not the weather.
    fn banner(host: *FakeHost, comptime what: []const u8) void {
        _ = host;
        std.debug.print("\n--- FakeHost: the real failure follows.\n" ++ what ++ "\n", .{});
    }

    /// A read that failed rather than a conversation that ended.
    ///
    /// Reported, and named. Every conversation these gates drive now ends with
    /// the client closing its socket, so this cannot fire on a healthy run —
    /// which is exactly what makes printing it worth anything. The bare `catch
    /// return` it replaces left the fake unable to tell a conversation that
    /// broke from one that finished, and scored both as a clean end.
    fn conversationBroke(host: *FakeHost, err: anyerror) void {
        host.banner("--- the fake host's connection to the binary failed mid-conversation:");
        std.debug.print(
            "reading the next request failed with {s}: the binary did not close this " ++
                "connection, it broke. Whatever this gate asserts afterwards is about a " ++
                "conversation that never finished\n",
            .{@errorName(err)},
        );
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
            host.banner("--- unscripted traffic:");
            std.debug.print(
                "{d} command(s) reached the fake host with no rule to answer them\n",
                .{missed},
            );
            return err;
        };
    }

    /// Asserts that no command carrying `needle` ever reached the host.
    ///
    /// The positive form of a fail-closed step: "it refused" is an exit code,
    /// which a dozen other faults also produce, and only the traffic says the
    /// destructive command was never sent.
    fn expectNeverSent(host: *FakeHost, needle: []const u8) !void {
        const dropped = host.record_failures.load(.monotonic);
        std.testing.expectEqual(@as(u32, 0), dropped) catch |err| {
            host.banner("--- lost traffic records:");
            std.debug.print(
                "{d} command(s) reached the fake host and could not be recorded, so this assertion cannot be made\n",
                .{dropped},
            );
            return err;
        };
        host.seen_lock.lockUncancelable(host.io);
        defer host.seen_lock.unlock(host.io);
        for (host.seen.items) |command| {
            if (std.mem.indexOf(u8, command, needle) == null) continue;
            host.banner("--- a step this command was forbidden to take reached the host:");
            std.debug.print(
                "a command containing '{s}' reached the host:\n{s}\n",
                .{ needle, command },
            );
            return error.DestructiveCommandWasSent;
        }
    }

    /// Asserts that a command carrying `needle` did reach the host.
    ///
    /// The other half of `expectNeverSent`, and not decoration. A refusal gate
    /// asserts an absence, and an absence is what a binary that lost its way
    /// before the branch under test — or refused every kill unconditionally —
    /// also produces. Only a paired run that insists the same fixture *does*
    /// send the kill tells those two apart.
    fn expectSent(host: *FakeHost, needle: []const u8) !void {
        const dropped = host.record_failures.load(.monotonic);
        std.testing.expectEqual(@as(u32, 0), dropped) catch |err| {
            host.banner("--- lost traffic records:");
            std.debug.print(
                "{d} command(s) reached the fake host and could not be recorded, so this assertion cannot be made\n",
                .{dropped},
            );
            return err;
        };
        host.seen_lock.lockUncancelable(host.io);
        defer host.seen_lock.unlock(host.io);
        for (host.seen.items) |command| {
            if (std.mem.indexOf(u8, command, needle) != null) return;
        }
        host.banner("--- a step this command was supposed to take never reached the host:");
        std.debug.print(
            "no command containing '{s}' reached the host; {d} command(s) did\n",
            .{ needle, host.seen.items.len },
        );
        return error.ExpectedCommandWasNotSent;
    }

    /// Asserts that every `seize` rule that fired actually took the lease.
    fn expectSeized(host: *FakeHost) !void {
        const failed = host.seize_failures.load(.monotonic);
        std.testing.expectEqual(@as(u32, 0), failed) catch |err| {
            host.banner("--- the scripted lease seizure did not happen:");
            std.debug.print(
                "{d} scripted lease seizure(s) did not happen, so the window this gate drives never opened\n",
                .{failed},
            );
            return err;
        };
    }

    /// Asserts that a `strand` rule fired and did what it says.
    ///
    /// Both halves, unlike `expectSeized`: a strand that never fired leaves a
    /// release that dates perfectly well, so a gate asserting `left_held` over it
    /// would be measuring nothing at all rather than measuring the wrong thing.
    fn expectStranded(host: *FakeHost) !void {
        const failed = host.strand_failures.load(.monotonic);
        std.testing.expectEqual(@as(u32, 0), failed) catch |err| {
            host.banner("--- the scripted lease stranding did not happen:");
            std.debug.print(
                "{d} scripted lease stranding(s) failed, so the release this gate drives was never made undatable\n",
                .{failed},
            );
            return err;
        };
        const done = host.strands.load(.monotonic);
        std.testing.expect(done > 0) catch |err| {
            host.banner("--- the scripted lease stranding never fired:");
            std.debug.print(
                "no `strand` rule matched a command, so the binary's release was ordinary and `left_held` cannot mean anything here\n",
                .{},
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
        for (host.seen.items) |command| host.allocator.free(command);
        host.seen.deinit(host.allocator);
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
            // End of file is the ordinary end of a conversation: the client
            // finished and closed its socket, which every exit in the binary
            // now does — see `Cli.closeDaemonSocket`. Nothing to report.
            //
            // Anything else is a fault and says so. It used to be swallowed by
            // a bare `catch return`, because the client did *not* close its
            // socket: `std.process.exit` skipped the close, Windows delivered
            // the abrupt teardown here as a reset, and std printed a trace for
            // it — on green runs as much as failing ones, so the only way to
            // keep the run readable was to ignore the whole class. Now that a
            // finished client arrives as an EOF, a read that fails is a read
            // that failed, and reporting it is the difference between a gate
            // that noticed the conversation diverged and one that scored it as
            // complete.
            const line = (reader.interface.takeDelimiter('\n') catch |err| {
                host.conversationBroke(err);
                return err;
            }) orelse return;
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
                .ping => blk: {
                    // Before the reply, not after: the binary is blocked on this
                    // socket right now, and the whole point is that the scope
                    // changes hands while it waits.
                    if (host.seize_on_ping and !host.seized_on_ping.swap(true, .monotonic)) host.seize();
                    break :blk .{ .v = protocol.version, .ok = true, .pid = 1 };
                },
                .stop => .{ .v = protocol.version, .ok = true },
                .exec => host.replyTo(request.command),
            };
            try protocol.writeMessage(&writer.interface, response);
        }
    }

    fn replyTo(host: *FakeHost, command: []const u8) protocol.Response {
        host.record(command);
        for (host.rules) |*rule| {
            if (rule.uses == 0) continue;
            if (std.mem.indexOf(u8, command, rule.needle) != null) {
                if (rule.uses != std.math.maxInt(u32)) rule.uses -= 1;
                if (rule.seize) host.seize();
                if (rule.strand) host.strand();
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

    fn record(host: *FakeHost, command: []const u8) void {
        const copy = host.allocator.dupe(u8, command) catch {
            _ = host.record_failures.fetchAdd(1, .monotonic);
            return;
        };
        host.seen_lock.lockUncancelable(host.io);
        defer host.seen_lock.unlock(host.io);
        host.seen.append(host.allocator, copy) catch {
            host.allocator.free(copy);
            _ = host.record_failures.fetchAdd(1, .monotonic);
        };
    }

    /// Takes the job scope from the binary, from a second connection to the same
    /// database, while the binary waits for the reply this is attached to.
    fn seize(host: *FakeHost) void {
        host.seizeLease() catch |err| {
            _ = host.seize_failures.fetchAdd(1, .monotonic);
            std.debug.print(
                "the gate's fake host could not take the job lease: {s}\n",
                .{@errorName(err)},
            );
        };
    }

    fn seizeLease(host: *FakeHost) !void {
        var store = try Store.open(host.db);
        defer store.close();
        var arena_state = std.heap.ArenaAllocator.init(host.allocator);
        defer arena_state.deinit();
        switch (try Store.leases.takeover(&store, arena_state.allocator(), .{
            .server_id = 1,
            .scope = .{ .kind = .job, .key = seized_job },
            .owner_request_id = seizing_peer,
            .profile_token = "the-other-session",
            .owner_label = seized_job,
            .ttl_secs = 600,
            .now = try Store.leases.clockSeconds(&store),
        })) {
            .taken => {},
            // Nothing was there to displace, which means the binary was not
            // holding the scope when this fired — the window this exists to
            // create never opened, and every assertion after it would be about
            // a different command.
            .acquired => return error.NothingWasHoldingTheJobScope,
        }
    }

    /// Leaves the binary's own lease undatable, from a second connection to the
    /// same database, while the binary waits for the reply this is attached to.
    ///
    /// See `Rule.strand` for why this is the only reachable shape of the failure.
    fn strand(host: *FakeHost) void {
        host.strandLease() catch |err| {
            _ = host.strand_failures.fetchAdd(1, .monotonic);
            std.debug.print(
                "the gate's fake host could not strand the job lease: {s}\n",
                .{@errorName(err)},
            );
            return;
        };
        _ = host.strands.fetchAdd(1, .monotonic);
    }

    fn strandLease(host: *FakeHost) !void {
        var store = try Store.open(host.db);
        defer store.close();
        var arena_state = std.heap.ArenaAllocator.init(host.allocator);
        defer arena_state.deinit();
        const now = try Store.leases.clockSeconds(&store);
        const held = try Store.leases.active(&store, arena_state.allocator(), 1, now);
        // Exactly the binary's own claim, and nothing else. Anything else here
        // means this fired at a moment the gate did not mean to describe.
        if (held.len != 1) return error.OneLeaseWasNotHeldWhenTheStrandFired;
        const ours = held[0];
        // An hour ahead, and written straight onto the row: the shape a renewal
        // taken before this machine's clock was stepped backwards leaves behind.
        // `leases.renew` cannot be used for it — it matches only rows whose
        // `expires_at` is still ahead of the stamp it is writing, which a stamp an
        // hour out never is — and every other public writer runs the lazy expiry
        // pass with the stamp it is given, which would sweep this row instead of
        // dating it and turn the release into `not_ours`. The row stays live and
        // stays ours (`expires_at` moves out with it); the one thing that changes
        // is that no stamp from this machine's clock can now be written onto it
        // without contradicting what it already records. Exactly the state
        // `requireForwardStamp` exists to refuse, and `cli.zig`'s own gate builds
        // the same thing from the acquisition end.
        const ahead = now + 3600;
        var stmt = try store.db.prepare(
            "UPDATE leases SET renewed_at = ?1, expires_at = ?2 WHERE id = ?3",
        );
        defer stmt.deinit();
        try stmt.bindInt(1, ahead);
        try stmt.bindInt(2, ahead + ours.expires_at - ours.renewed_at);
        try stmt.bindInt(3, ours.id);
        _ = try stmt.step();
        if (store.db.changes() == 0) return error.LeaseVanishedBeforeItCouldBeStranded;
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

test "blackbox: a result record the host cannot read stops `job kill` and keeps the scope barred" {
    const t = std.testing;
    var f = try Fixture.init(t.allocator, "unreadable_kill");
    defer f.deinit();
    try f.seedServer();

    const request_id = "01FFFFFFFF0123456789ABCDEF";
    const sentinel = "__TERMINUS_JOB_7__";
    try seedRunningJob(&f, request_id, "deploy", sentinel);

    // Three commands against one host, and the only thing that changes between
    // the first two and the third is whether the result record could be read.
    // That is the whole discrimination this gate exists to make, and running it
    // on one fixture is what stops it from being two unrelated observations.
    //
    // The probe answers `result_unreadable_exit` twice: once for `job kill`,
    // once for the lazy read the refused relaunch does of its blocker. Then it
    // starts answering with an absent record and the job's own sentinel, which
    // is the reading a job launched before result records existed produces.
    const readable = "\n" ++ probe_split ++ "\n20\nwork done\n" ++ sentinel ++ ":0\n";
    var rules = [_]FakeHost.Rule{
        .{ .needle = probe_split, .exit_code = 44, .uses = 2 },
        .{ .needle = probe_split, .stdout = readable },
        .{ .needle = "kill-session", .exit_code = 0 },
        .{ .needle = "has-session", .exit_code = 0 },
    };
    var host = try FakeHost.start(&f, &rules);
    defer host.stop();
    var environ = try host.environment();
    defer environ.deinit();

    var stopped = try runWithEnvironment(&f, &.{
        "job", "kill", "box", "deploy", "--json", "--db", f.db,
    }, &environ);
    defer stopped.deinit(f.allocator);

    // Exit 1 and not 0. Under the old pipeline this same reply — a script that
    // exited without printing the document — reached the reader as exit 0 with
    // no output, which it reads as "there is no result record"; the sentinel in
    // the window then settled the job `completed` and freed its name.
    //
    // Exit 1 and not 75 for a reason worth stating: this probe runs before the
    // command has sent anything, so nothing about the job is newly unknown.
    // 75 is the code for "the remote effect may or may not have happened", and
    // claiming it here would forbid a retry that is perfectly safe.
    try stopped.expectCode(1);
    try host.expectFullyScripted();
    // The sentence has to send the operator to the file, not to tmux.
    try stopped.expectSays("result record");
    try stopped.expectSays(".terminus/results/" ++ request_id ++ ".json");
    try stopped.expectSays("could not read it");
    // …and it must not claim the record is gone. "Absent" is the reading this
    // whole change exists to stop the failure being mistaken for.
    try stopped.expectSaysNot("no result record");

    // Nothing was settled and nothing was sent: the ledger row is exactly where
    // the fixture left it, read out of the store rather than out of the report.
    {
        var store = try f.open();
        defer store.close();
        var arena_state = std.heap.ArenaAllocator.init(t.allocator);
        defer arena_state.deinit();
        const op = (try Store.operations.get(&store, arena_state.allocator(), request_id)).?;
        try t.expectEqualStrings("remote_started", op.status.text());
    }
    try host.expectNeverSent("kill-session");

    // The barrier, in the only form it takes for a caller. The blocker is still
    // unsettled, the lazy read that a launch does of it hits the same
    // unreadable record and declines to clear it, and the launch is refused.
    var relaunch = try runWithEnvironment(&f, &.{
        "run", "box", "--name", "deploy", "--cmd", "make deploy", "--db", f.db,
    }, &environ);
    defer relaunch.deinit(f.allocator);
    try relaunch.expectCode(1);
    try relaunch.expectSays("refused");
    try relaunch.expectSays(request_id);
    try host.expectFullyScripted();

    // The control, on the same fixture and the same verb: once the record can
    // be read and turns out to be genuinely absent, the sentinel settles the
    // job, the command exits 0 and the name is free again. Without this the
    // gate above would pass just as happily against a binary that refused every
    // sidecar there is.
    var settled = try runWithEnvironment(&f, &.{
        "job", "kill", "box", "deploy", "--json", "--db", f.db,
    }, &environ);
    defer settled.deinit(f.allocator);
    try settled.expectCode(0);
    try host.expectFullyScripted();
    try settled.expectSays("\"resultRecord\": \"absent\"");
    try settled.expectSays("\"exitCode\": 0");
    {
        var store = try f.open();
        defer store.close();
        var arena_state = std.heap.ArenaAllocator.init(t.allocator);
        defer arena_state.deinit();
        const op = (try Store.operations.get(&store, arena_state.allocator(), request_id)).?;
        try t.expectEqualStrings("completed", op.status.text());
        const unsettled = try Store.operations.unsettled(&store, arena_state.allocator(), 1);
        try t.expectEqual(@as(usize, 0), unsettled.len);
    }
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
    // The reading itself, named on both verbs and in the same words. `job rm`
    // carries this key for the same reason `job kill` does: `ok: false` says
    // something went wrong, and only this says a document was there and was
    // turned down — the one fact a removal's caller can no longer go and check.
    try acted.expectSays("\"resultRecord\": \"exit_code_out_of_range\"");

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

/// The read that fails *after* the kill, driven end to end for one verb.
///
/// `error.ResultUnreadable` exists because a `head` that cannot open a file the
/// script has just found came back as exit 0 with no output, which the parser
/// spells `absent` — and `absent` is the one reading that lets the log sentinel
/// settle a job on its own. `922f565` took that laundering out of `readResult`
/// and `probeTail`. It survived in `finalProbe`, the one look that runs after the
/// session has been stopped: a blanket `catch` printed the error to *stderr* with
/// `std.debug.print` — invisible to a `--json` consumer — and handed the caller
/// an empty second look, which reads as "there is nothing here to upgrade to".
///
/// So `job rm` printed `{"action":"removed","ok":true}` and exit 0 over a record
/// nobody could read, deleted the local row that was the last thing pointing at
/// the evidence, and offered a `--from-log` reconcile that reads this same
/// document through this same reader. `job rm --discard-evidence` deleted the
/// pane log and the result file *first* and then settled `indeterminate` for want
/// of them. `job kill` reached 75 only because no shipped supervisor can prove a
/// process tree is gone — it published `"resultRecord":"absent"` beside it, and
/// the day that supervisor exists it would have settled `remote_cancel_confirmed`
/// and freed the scope.
///
/// Every assertion below is read from the store or from the host's own traffic,
/// never from the report that is on trial.
fn readFailureAfterTheKill(
    fixture_name: []const u8,
    verb: []const u8,
    /// `--discard-evidence` on the one run that asks for it.
    extra_flag: ?[]const u8,
) !void {
    const t = std.testing;
    var f = try Fixture.init(t.allocator, fixture_name);
    defer f.deinit();
    try f.seedServer();

    const request_id = "01HHHHHHHH0123456789ABCDEF";
    const sentinel = "__TERMINUS_JOB_7__";
    try seedRunningJob(&f, request_id, "deploy", sentinel);

    // The discriminating control's job, seeded on the same fixture and driven
    // through the same verb, the same branch and the same code path. The one
    // difference is the reply to the look taken after the kill.
    //
    // A second job rather than a second run on `deploy`: the read failure
    // settles `deploy` `indeterminate` on purpose, and an attempt the ledger has
    // settled cannot be settled again by anything but a reconcile — so a repeat
    // run on that name would exit 75 for a reason that has nothing to do with
    // this rule, and prove nothing either way.
    const control_id = "01JJJJJJJJ0123456789ABCDEF";
    try seedRunningJob(&f, control_id, "release", sentinel);

    // …and the second half of the discrimination, because the control above
    // cannot make it on its own. `job kill` reaches "settles and exits 0" only
    // through the upgrade the second look hands back, and that return runs before
    // `final.unreadable` is ever read — so a `finalProbe` that called *every*
    // second look unreadable would still pass it. This job's second look is
    // readable and finds nothing at all: no document at the address, no sentinel
    // in the window. `skill/SKILL.md` says that changes nothing, and what it must
    // not turn into is a read failure.
    const quiet_id = "01KKKKKKKK0123456789ABCDEF";
    try seedRunningJob(&f, quiet_id, "verify", sentinel);

    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(f.allocator);
    try argv.appendSlice(f.allocator, &.{ "job", verb, "box", "deploy" });
    if (extra_flag) |flag| try argv.append(f.allocator, flag);
    try argv.appendSlice(f.allocator, &.{ "--json", "--db", f.db });

    var control_argv: std.ArrayList([]const u8) = .empty;
    defer control_argv.deinit(f.allocator);
    try control_argv.appendSlice(f.allocator, &.{ "job", verb, "box", "release" });
    if (extra_flag) |flag| try control_argv.append(f.allocator, flag);
    try control_argv.appendSlice(f.allocator, &.{ "--json", "--db", f.db });

    var quiet_argv: std.ArrayList([]const u8) = .empty;
    defer quiet_argv.deinit(f.allocator);
    try quiet_argv.appendSlice(f.allocator, &.{ "job", verb, "box", "verify" });
    if (extra_flag) |flag| try quiet_argv.append(f.allocator, flag);
    try quiet_argv.appendSlice(f.allocator, &.{ "--json", "--db", f.db });

    // A job still running when the command first looks, so there is nothing to
    // settle and the only next step is the kill.
    const running = "\n" ++ probe_split ++ "\n12\nbuilding...\n";
    // …and the control's second look: the address is readable and there is
    // genuinely nothing at it, with the job's own sentinel behind it.
    const settled_window = "\n" ++ probe_split ++ "\n20\nwork done\n" ++ sentinel ++ ":0\n";

    // Keyed by the log path each probe script carries, because both jobs' probes
    // contain the split marker and this gate needs the two answered differently
    // in one conversation. `rm -f` is first so a deletion is never answered by a
    // probe rule that happens to name the same log.
    var rules = [_]FakeHost.Rule{
        .{ .needle = "rm -f", .exit_code = 0 },
        .{ .needle = "job-deploy.log", .stdout = running, .uses = 1 },
        // Every look at `deploy` after that. `44` is the probe script's own
        // `result_unreadable_exit`: `[ -f "$r" ]` found a file at this attempt's
        // address and `head` could not obtain its bytes.
        //
        // Unbounded on purpose. Whether the refused relaunch below spends a
        // round trip lazily reading its blocker is not this gate's business, and
        // a bounded rule would make every assertion after it depend on that.
        .{ .needle = "job-deploy.log", .exit_code = 44 },
        .{ .needle = "job-release.log", .stdout = running, .uses = 1 },
        .{ .needle = "job-release.log", .stdout = settled_window },
        // `verify`, whose every look comes back readable and empty: no document
        // at the address, no sentinel in the window. Unbounded because both of
        // its looks say the same thing.
        .{ .needle = "job-verify.log", .stdout = running },
        .{ .needle = "kill-session", .exit_code = 0 },
        .{ .needle = "has-session", .exit_code = 0 },
    };
    var host = try FakeHost.start(&f, &rules);
    defer host.stop();
    var environ = try host.environment();
    defer environ.deinit();

    {
        var acted = try runWithEnvironment(&f, argv.items, &environ);
        defer acted.deinit(f.allocator);

        // The traffic first, so a regression names its cause. An exit code is
        // moved by a dozen other faults; only the host's record says the kill
        // did happen — this is not a command that stopped short of it — and that
        // neither deletion followed.
        try host.expectSent("kill-session");
        try host.expectNeverSent("rm -f");
        try host.expectFullyScripted();

        // 75 and not 1, from the process. The session was stopped and the
        // record that says what became of the work cannot be read, so the
        // outcome is genuinely unknown and a blind retry is not available.
        try acted.expectCode(75);

        // The machine-readable half of the finding, in the only place a `--json`
        // consumer can see it. `resultRecordError` is prose on every other
        // branch and this one stable token here.
        try acted.expectSays("\"resultRecordError\": \"read_error\"");
        try acted.expectSays("\"resultRecord\": \"read_error\"");
        // …and never the reading it used to publish. A read that failed is not
        // an absence, and `absent` is the one word that licenses the log
        // sentinel to settle this job by itself.
        try acted.expectSaysNot("\"resultRecord\": \"absent\"");
        try acted.expectSays("\"ok\": false");
        // The next step has to name a command that can succeed. `--from-log`
        // reads this same document through this same reader.
        try acted.expectSays("--override");
        try acted.expectSaysNot("--from-log");

        {
            var store = try f.open();
            defer store.close();
            var arena_state = std.heap.ArenaAllocator.init(t.allocator);
            defer arena_state.deinit();
            const arena = arena_state.allocator();

            // Out of the store, not parsed out of stdout.
            const op = (try Store.operations.get(&store, arena, request_id)).?;
            try t.expectEqualStrings("indeterminate", op.status.text());

            // The row survives on every one of the three verbs, including the
            // one that exists to delete it. It is the last thing pointing at the
            // log and the sidecar still sitting on the host, so forgetting it
            // strands them as surely as `rm -f` would have removed them.
            try t.expect((try Store.jobs.getByName(&store, arena, 1, "deploy")) != null);
        }

        // The scope, in the only form the bar takes for a caller: the next
        // command on this name is refused, and it names the request holding it.
        var relaunch = try runWithEnvironment(&f, &.{
            "run", "box", "--name", "deploy", "--cmd", "make deploy", "--db", f.db,
        }, &environ);
        defer relaunch.deinit(f.allocator);
        try relaunch.expectCode(1);
        try relaunch.expectSays("refused");
        try relaunch.expectSays(request_id);
        // Still nothing deleted, and still nothing off the scripted path. Both
        // asserted here, before the control run below sends the `rm -f` this
        // branch was forbidden.
        try host.expectNeverSent("rm -f");
        try host.expectFullyScripted();
    }

    // A second look that finds nothing is not a second look that failed. Both
    // verbs go on doing what they were already doing — the exit code differs by
    // verb and by `--discard-evidence`, so it is not what this leg is about —
    // and the reading stays the ordinary `absent` with no sentence beside it.
    //
    // This is the leg that fails if `read_error` ever becomes the answer to
    // something other than a read that failed.
    {
        var quiet = try runWithEnvironment(&f, quiet_argv.items, &environ);
        defer quiet.deinit(f.allocator);
        try host.expectFullyScripted();
        try quiet.expectSays("\"resultRecord\": \"absent\"");
        try quiet.expectSays("\"resultRecordError\": null");
        try quiet.expectSaysNot("read_error");
    }

    // The control. Same fixture, same verb, same branch — the first look finds
    // work in progress, the session is killed, and the second look is the one
    // that decides. Here it can read the address, finds nothing there, and the
    // job's own sentinel answers in its place: the attempt settles, the command
    // exits 0 and the name is free again.
    //
    // Without this every assertion above would hold just as well against a
    // binary that had started calling every outcome unknown.
    {
        var settled = try runWithEnvironment(&f, control_argv.items, &environ);
        defer settled.deinit(f.allocator);
        try host.expectFullyScripted();
        try settled.expectCode(0);
        try settled.expectSays("\"ok\": true");
        // The ordinary reading, under the ordinary key, with no sentence beside
        // it. `read_error` is reserved for a read that failed.
        try settled.expectSays("\"resultRecord\": \"absent\"");
        try settled.expectSays("\"resultRecordError\": null");

        {
            var store = try f.open();
            defer store.close();
            var arena_state = std.heap.ArenaAllocator.init(t.allocator);
            defer arena_state.deinit();
            const arena = arena_state.allocator();
            const op = (try Store.operations.get(&store, arena, control_id)).?;
            try t.expectEqualStrings("completed", op.status.text());
        }

        // …and the name is not turned away where it stands, which is what a
        // freed scope means to whoever launches next. It still fails at the host
        // — nothing here scripts a launch — but not at the scope guard.
        var relaunch = try runWithEnvironment(&f, &.{
            "run", "box", "--name", "release", "--cmd", "make release", "--db", f.db,
        }, &environ);
        defer relaunch.deinit(f.allocator);
        try relaunch.expectSaysNot("refused: request");
    }
}

test "blackbox: `job kill` will not report a cancellation over a record it could not read" {
    try readFailureAfterTheKill("read_error_kill", "kill", null);
}

test "blackbox: `job rm` keeps the row when the post-kill read of its record fails" {
    try readFailureAfterTheKill("read_error_rm", "rm", null);
}

test "blackbox: `job rm --discard-evidence` destroys nothing when the post-kill read fails" {
    try readFailureAfterTheKill("read_error_rm_discard", "rm", "--discard-evidence");
}

// The barrier `job rm` never had, reached through the only door a black-box
// fixture can open.
//
// `job rm` does not call `Execution.submitted`, so the unsettled-operation half of
// the scope guard never ran for it, and the two branches that deleted the row
// through `jobs.remove` opened a transaction of their own with no check in it at
// all. Now the delete runs under `execution.commitDestruction`, whose peer check is
// the same one `begin` and `submitted` use — keyed so that the attempt this removal
// is *settling* is not read as a peer blocking its own removal.
//
// A peer's unsettled attempt is what this seeds, and not a lease seizure, because
// a lease can only be lost across a round trip: `job rm`'s last renewal sits
// immediately above the commit with nothing between them, so a `FakeHost` seizure
// is caught by that renewal and never reaches the transaction. The claim-state half
// of the check is therefore only reachable in-process, and that is where it is
// gated — `gate: every destructive path answers every authority scenario the same
// way`, in `src/core/store/gates_test.zig`.
//
// Everything before the commit succeeds, and the assertions say so: the lease is
// acquired cleanly, every renewal answers `held`, and the kill goes out. What is
// refused is the deletion.
test "blackbox: `job rm` keeps the row when a peer's unsettled attempt claims the scope at the commit" {
    const t = std.testing;
    var f = try Fixture.init(t.allocator, "job_rm_peer_at_commit");
    defer f.deinit();
    try f.seedServer();

    const request_id = "01MMMMMMMM0123456789ABCDEF";
    const sentinel = "__TERMINUS_JOB_7__";
    try seedRunningJob(&f, request_id, "deploy", sentinel);

    // The peer: a second attempt, unsettled and mutating, on the *same* job scope
    // and holding no lease. Seeded through the store rather than by running a
    // second command, because a second command could not get here — our lease
    // refuses it at `submitted`. This is the shape a crashed `run --force` leaves.
    const peer_id = "01NNNNNNNN0123456789ABCDEF";
    {
        var store = try f.open();
        defer store.close();
        try Store.operations.create(&store, .{
            .request_id = peer_id,
            .server_id = 1,
            .server_name = "box",
            .kind = .job,
            .scope_kind = .job,
            .scope_key = "deploy",
            .alias = "deploy",
            .mutating = true,
            .now = 1100,
        });
        try Store.operations.advance(&store, peer_id, .connecting, 1101);
        try Store.operations.advance(&store, peer_id, .submitted, 1102);
    }

    // The discriminating control: the same fixture, the same verb, the same
    // branch, and no peer on its scope. Without it every assertion below would
    // hold just as well against a `job rm` that had stopped removing anything.
    const control_id = "01PPPPPPPP0123456789ABCDEF";
    try seedRunningJob(&f, control_id, "release", sentinel);

    const running = "\n" ++ probe_split ++ "\n12\nbuilding...\n";
    const finished = "\n" ++ probe_split ++ "\n20\nwork done\n" ++ sentinel ++ ":0\n";
    var rules = [_]FakeHost.Rule{
        .{ .needle = "job-deploy.log", .stdout = running, .uses = 1 },
        .{ .needle = "job-deploy.log", .stdout = finished },
        .{ .needle = "job-release.log", .stdout = running, .uses = 1 },
        .{ .needle = "job-release.log", .stdout = finished },
        .{ .needle = "kill-session", .exit_code = 0 },
        .{ .needle = "has-session", .exit_code = 0 },
    };
    var host = try FakeHost.start(&f, &rules);
    defer host.stop();
    var environ = try host.environment();
    defer environ.deinit();

    {
        var refused = try runWithEnvironment(&f, &.{
            "job", "rm", "box", "deploy", "--json", "--db", f.db,
        }, &environ);
        defer refused.deinit(f.allocator);

        // The traffic first, so a regression names its cause: the kill really did
        // go out — this is not a command that stopped short of it — and no
        // deletion followed.
        try host.expectSent("kill-session");
        try host.expectNeverSent("rm -f");
        try host.expectFullyScripted();

        // 1 and not 75: the second look read this attempt's own sentinel, so the
        // outcome is not in doubt. What failed is this command's standing to
        // delete a row, which is a plain failure.
        try refused.expectCode(1);
        try refused.expectSays("\"action\": \"not_removed\"");
        try refused.expectSays("\"rowRemoved\": false");
        try refused.expectSays("\"ok\": false");
        // An exit code read from a document at this attempt's own address is not
        // made false by a scope that moved, so the outcome stands and only the
        // deletion is refused.
        try refused.expectSays("\"outcomeProven\": true");
        // Every renewal answered truthfully about the moment it was asked. What
        // refused this is the read inside the transaction, and the code for it
        // travels in the sentence and in the receipt.
        try refused.expectSays("\"authority\": \"held\"");
        try refused.expectSays("SCOPE_TAKEN_BEFORE_COMMIT");
        try refused.expectSays(peer_id);
        // Nothing was discarded, and the report must not read as if it had been.
        try refused.expectSays("\"evidenceRetained\": true");
    }

    {
        var store = try f.open();
        defer store.close();
        var arena_state = std.heap.ArenaAllocator.init(t.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        // Out of the store, not parsed out of stdout: the row this removal was
        // about is still there.
        try t.expect((try Store.jobs.getByName(&store, arena, 1, "deploy")) != null);
        // …and the attempt is settled with the outcome the host reported, rather
        // than left unsettled to bar the scope with nothing saying why.
        const op = (try Store.operations.get(&store, arena, request_id)).?;
        try t.expectEqualStrings("completed", op.status.text());
    }

    {
        var removed = try runWithEnvironment(&f, &.{
            "job", "rm", "box", "release", "--json", "--db", f.db,
        }, &environ);
        defer removed.deinit(f.allocator);
        try host.expectFullyScripted();
        try removed.expectCode(0);
        try removed.expectSays("\"action\": \"removed\"");
        try removed.expectSays("\"rowRemoved\": true");

        var store = try f.open();
        defer store.close();
        var arena_state = std.heap.ArenaAllocator.init(t.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        try t.expectEqual(
            @as(?Store.jobs.Job, null),
            try Store.jobs.getByName(&store, arena, 1, "release"),
        );
        const op = (try Store.operations.get(&store, arena, control_id)).?;
        try t.expectEqualStrings("completed", op.status.text());
    }
}

/// How the look after the kill fails, when it fails without ever reading the
/// address.
///
/// Two, because they enter `probeTail` at different points and only one of them
/// is about the probe script at all. The second is the one a published sentence
/// rests on.
const PostKillFault = enum {
    /// The probe script itself reported failure — `probeTail` raises
    /// `error.RemoteFailed`. Any non-zero exit that is not `44` does it; `44` is
    /// the one code that means "the record is there and would not open" and is
    /// the *other* rule's business.
    remote_failed,
    /// The tail came back and then `tmux` was not runnable: `isAlive` raises
    /// `error.TmuxMissing` from inside the post-kill probe, after `killSession`
    /// has already answered. The only reachable window for it, and the one
    /// `skill/SKILL.md`'s "nothing is deleted on it" sentence was false about —
    /// `finalProbe` swallowed it and `job rm --discard-evidence` deleted both
    /// records anyway.
    tmux_missing,
};

/// The look after the kill that never happened at all, driven end to end for one
/// verb.
///
/// The sibling of `readFailureAfterTheKill`, and the distinction between them is
/// the point. There, the host answered and said a document is at this attempt's
/// own address and it would not open. Here the round trip broke, or the tool the
/// look needs stopped being runnable: nothing was read, nothing is known about
/// either record, and both are sitting on the host exactly as the job left them.
///
/// `job rm` treated the second as licence to finish: `finalProbe` printed the
/// error to *stderr* — invisible to a `--json` consumer — and handed back an
/// empty second look, which reads as "there is nothing here to upgrade to". So
/// the row was deleted, `{"action":"removed","ok":true}` and exit 0 came out over
/// a host nobody could reach, and `--discard-evidence` deleted the pane log and
/// the result file first. `job kill` is deliberately not part of that: it already
/// settles `indeterminate` and exits 75 here, and it deletes nothing on any path.
///
/// Every assertion below is read from the store or from the host's own traffic,
/// never from the report that is on trial.
fn probeFailureAfterTheKill(
    fixture_name: []const u8,
    verb: []const u8,
    /// `--discard-evidence` on the runs that ask for it.
    extra_flag: ?[]const u8,
    fault: PostKillFault,
) !void {
    const t = std.testing;
    var f = try Fixture.init(t.allocator, fixture_name);
    defer f.deinit();
    try f.seedServer();

    const request_id = "01QQQQQQQQ0123456789ABCDEF";
    const sentinel = "__TERMINUS_JOB_7__";
    try seedRunningJob(&f, request_id, "deploy", sentinel);

    // The discriminator this gate would be worthless without: the same fixture,
    // the same verb, the same branch, and a post-kill look that *did* reach the
    // address and could not read the document there. That is `read_error`, and it
    // must not have become `probe_error` — the two words carry different next
    // steps, and a change that collapsed them would pass every assertion about
    // `deploy` above.
    const unreadable_id = "01RRRRRRRR0123456789ABCDEF";
    try seedRunningJob(&f, unreadable_id, "salvage", sentinel);

    // The control for the arm next door. A second look that reaches the host and
    // finds nothing at all is `job rm`'s ordinary case, and it still removes the
    // row. If `probe_error` leaked into that arm, every unproven removal would
    // start keeping its row — which no assertion about a *failed* look can catch.
    const quiet_id = "01KKKKKKKK0123456789ABCDEF";
    try seedRunningJob(&f, quiet_id, "verify", sentinel);

    // …and the control that proves the binary still settles anything at all: this
    // job's second look is readable and its own sentinel answers, so the attempt
    // settles, the command exits 0 and the name is free again. It passes through
    // `finalProbe`'s upgrade arm, which is read *before* the failure arms — so it
    // cannot carry the discrimination on its own, and does not have to: the two
    // controls above cover the arms it skips.
    const control_id = "01JJJJJJJJ0123456789ABCDEF";
    try seedRunningJob(&f, control_id, "release", sentinel);

    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(f.allocator);
    try argv.appendSlice(f.allocator, &.{ "job", verb, "box", "deploy" });
    if (extra_flag) |flag| try argv.append(f.allocator, flag);
    try argv.appendSlice(f.allocator, &.{ "--json", "--db", f.db });

    var unreadable_argv: std.ArrayList([]const u8) = .empty;
    defer unreadable_argv.deinit(f.allocator);
    try unreadable_argv.appendSlice(f.allocator, &.{ "job", verb, "box", "salvage" });
    if (extra_flag) |flag| try unreadable_argv.append(f.allocator, flag);
    try unreadable_argv.appendSlice(f.allocator, &.{ "--json", "--db", f.db });

    var quiet_argv: std.ArrayList([]const u8) = .empty;
    defer quiet_argv.deinit(f.allocator);
    try quiet_argv.appendSlice(f.allocator, &.{ "job", verb, "box", "verify" });
    if (extra_flag) |flag| try quiet_argv.append(f.allocator, flag);
    try quiet_argv.appendSlice(f.allocator, &.{ "--json", "--db", f.db });

    var control_argv: std.ArrayList([]const u8) = .empty;
    defer control_argv.deinit(f.allocator);
    try control_argv.appendSlice(f.allocator, &.{ "job", verb, "box", "release" });
    if (extra_flag) |flag| try control_argv.append(f.allocator, flag);
    try control_argv.appendSlice(f.allocator, &.{ "--json", "--db", f.db });

    // A job still running when the command first looks, so there is nothing to
    // settle and the only next step is the kill.
    const running = "\n" ++ probe_split ++ "\n12\nbuilding...\n";
    // …and a second look that reaches the address, finds nothing at it, and has
    // the job's own sentinel behind it.
    const settled_window = "\n" ++ probe_split ++ "\n20\nwork done\n" ++ sentinel ++ ":0\n";

    // Keyed by the log path each probe script carries, because all four jobs'
    // probes contain the split marker and this gate needs them answered
    // differently in one conversation. `rm -f` is first so a deletion is never
    // answered by a probe rule that happens to name the same log, and
    // `kill-session` is next because that script carries `has-session` too.
    //
    // `deploy`'s second look is where the two faults differ. Here the probe
    // script reports failure, which is `error.RemoteFailed`, and the rule is
    // unbounded on purpose: whether the refused relaunch below spends a round
    // trip lazily reading its blocker is not this gate's business.
    var remote_rules = [_]FakeHost.Rule{
        .{ .needle = "rm -f", .exit_code = 0 },
        .{ .needle = "kill-session", .exit_code = 0 },
        .{ .needle = "job-deploy.log", .stdout = running, .uses = 1 },
        .{ .needle = "job-deploy.log", .exit_code = 2 },
        .{ .needle = "job-salvage.log", .stdout = running, .uses = 1 },
        // 44 is the probe script's own `result_unreadable_exit`: a file is at
        // this attempt's address and `head` could not obtain its bytes.
        .{ .needle = "job-salvage.log", .exit_code = 44 },
        .{ .needle = "job-verify.log", .stdout = running },
        .{ .needle = "job-release.log", .stdout = running, .uses = 1 },
        .{ .needle = "job-release.log", .stdout = settled_window },
        .{ .needle = "has-session", .exit_code = 0 },
    };
    // …and here the probe script answers and `tmux` is gone by the time the same
    // round trip asks whether the session is still there. Keyed to this job's own
    // target name, so the other three jobs' looks are unaffected: the tool going
    // missing for everything at once would make every assertion below depend on
    // which job the binary happened to touch first.
    var tmux_rules = [_]FakeHost.Rule{
        .{ .needle = "rm -f", .exit_code = 0 },
        .{ .needle = "kill-session", .exit_code = 0 },
        .{ .needle = "job-deploy.log", .stdout = running },
        // The pre-kill look, which has to succeed: a `tmux` already missing when
        // the command starts is the pre-kill probe's business, and it ends at
        // `fatalTmux` without stopping anything. This gate is about the window
        // *after* the kill.
        .{ .needle = "has-session -t =t-job-deploy", .exit_code = 0, .uses = 1 },
        // 41 is `isAlive`'s own `command -v tmux` exit.
        .{ .needle = "has-session -t =t-job-deploy", .exit_code = 41 },
        .{ .needle = "job-salvage.log", .stdout = running, .uses = 1 },
        .{ .needle = "job-salvage.log", .exit_code = 44 },
        .{ .needle = "job-verify.log", .stdout = running },
        .{ .needle = "job-release.log", .stdout = running, .uses = 1 },
        .{ .needle = "job-release.log", .stdout = settled_window },
        .{ .needle = "has-session", .exit_code = 0 },
    };
    const rules: []FakeHost.Rule = switch (fault) {
        .remote_failed => &remote_rules,
        .tmux_missing => &tmux_rules,
    };
    // The error's own name, in the report. Not decoration: `TmuxMissing` and a
    // remote failure send an operator to different places, and a hint that says
    // only "the look failed" sends it nowhere.
    const error_name = switch (fault) {
        .remote_failed => "RemoteFailed",
        .tmux_missing => "TmuxMissing",
    };
    // …asserted through the hint's own wording rather than the bare name.
    // `expectSays` reads stderr as well, and `finalProbe` prints the error there
    // too — so the bare name would be satisfied by a report that had dropped it.
    const hint_needle = switch (fault) {
        .remote_failed => "failed with RemoteFailed",
        .tmux_missing => "failed with TmuxMissing",
    };

    var host = try FakeHost.start(&f, rules);
    defer host.stop();
    var environ = try host.environment();
    defer environ.deinit();

    {
        var acted = try runWithEnvironment(&f, argv.items, &environ);
        defer acted.deinit(f.allocator);

        // The traffic first, so a regression names its cause rather than a
        // number. An exit code is moved by a dozen other faults; only the host's
        // record says the kill did happen — this is not a command that stopped
        // short of it — and that neither deletion followed.
        try host.expectSent("kill-session");
        try host.expectNeverSent("rm -f");
        try host.expectFullyScripted();

        // 75 and not 1, from the process. The session was stopped and the look
        // that had to follow it never happened, so the outcome is genuinely
        // unknown and a blind retry is not available.
        try acted.expectCode(75);

        // The machine-readable half of the finding, in the only place a `--json`
        // consumer can see it — `finalProbe` used to put it on stderr alone.
        try acted.expectSays("\"resultRecord\": \"probe_error\"");
        try acted.expectSays("\"resultRecordError\": \"probe_error\"");
        // …and never the *other* word. `read_error` means a document is at that
        // address and would not open, which is a claim this look cannot make.
        try acted.expectSaysNot("read_error");
        // …nor the reading it used to publish. `absent` is the one word that
        // licenses the log sentinel to settle this job by itself.
        try acted.expectSaysNot("\"resultRecord\": \"absent\"");
        try acted.expectSays("\"ok\": false");
        try acted.expectSays("\"action\": \"not_removed\"");
        try acted.expectSays("\"rowRemoved\": false");
        // What `--discard-evidence` was told to delete is still there, and the
        // key that reports it agrees with the traffic asserted above.
        try acted.expectSays("\"evidenceRetained\": true");
        // The next step, and it is `--from-log` rather than `--override`: both
        // records are intact, so the reconcile that reads them can succeed once
        // the host answers again. This is the other half of what the second
        // published word buys a caller.
        try acted.expectSays("--from-log");
        try acted.expectSays(hint_needle);

        {
            var store = try f.open();
            defer store.close();
            var arena_state = std.heap.ArenaAllocator.init(t.allocator);
            defer arena_state.deinit();
            const arena = arena_state.allocator();

            // Out of the store, not parsed out of stdout.
            const op = (try Store.operations.get(&store, arena, request_id)).?;
            try t.expectEqualStrings("indeterminate", op.status.text());

            // …and the ledger's own sentence names the fault. The receipt is what
            // an operator reads weeks later, and "the outcome is unknown" without
            // saying why sends them back to a host they cannot tell apart from a
            // host with a broken result file.
            const rows = try Store.receipts.list(&store, arena, request_id);
            var terminal_reason: ?[]const u8 = null;
            for (rows) |row| if (row.is_terminal) {
                terminal_reason = row.transport_error;
            };
            const reason = terminal_reason orelse return error.RemovalLeftNoTerminalReceipt;
            try t.expect(std.mem.indexOf(u8, reason, error_name) != null);
            // The claim this whole rule exists to make, in the one record that
            // outlives the command.
            try t.expect(std.mem.indexOf(u8, reason, "no evidence was deleted") != null);

            // The row survives on both verbs, including the one that exists to
            // delete it. It is the last thing pointing at the log and the sidecar
            // still sitting on the host, so forgetting it strands them as surely
            // as `rm -f` would have removed them.
            try t.expect((try Store.jobs.getByName(&store, arena, 1, "deploy")) != null);
        }

        // The scope, in the only form the bar takes for a caller: the next
        // command on this name is refused, and it names the request holding it.
        var relaunch = try runWithEnvironment(&f, &.{
            "run", "box", "--name", "deploy", "--cmd", "make deploy", "--db", f.db,
        }, &environ);
        defer relaunch.deinit(f.allocator);
        try relaunch.expectCode(1);
        try relaunch.expectSays("refused");
        try relaunch.expectSays(request_id);
        // Still nothing deleted, and still nothing off the scripted path. Both
        // asserted here, before the controls below send the `rm -f` this branch
        // was forbidden.
        try host.expectNeverSent("rm -f");
        try host.expectFullyScripted();
    }

    // The discriminator. Same fixture, same verb, same branch — and a post-kill
    // look that reached the address and could not read what is there. That is
    // still `read_error`, and if it has become `probe_error` the two findings
    // have collapsed into one word and a caller can no longer tell a file it must
    // repair from a wire it must retry.
    {
        var unreadable = try runWithEnvironment(&f, unreadable_argv.items, &environ);
        defer unreadable.deinit(f.allocator);
        try host.expectFullyScripted();
        try unreadable.expectCode(75);
        try unreadable.expectSays("\"resultRecord\": \"read_error\"");
        try unreadable.expectSays("\"resultRecordError\": \"read_error\"");
        try unreadable.expectSaysNot("probe_error");
    }

    // The arm next door, which has to keep behaving as it did. A second look that
    // reaches the host and finds nothing is not a second look that failed: the
    // removal goes through and the row is forgotten. The exit code differs by
    // `--discard-evidence`, so it is not what this leg asserts; the row is.
    {
        var quiet = try runWithEnvironment(&f, quiet_argv.items, &environ);
        defer quiet.deinit(f.allocator);
        try host.expectFullyScripted();
        try quiet.expectSays("\"resultRecord\": \"absent\"");
        try quiet.expectSays("\"resultRecordError\": null");
        try quiet.expectSaysNot("probe_error");
        try quiet.expectSays("\"rowRemoved\": true");
        try quiet.expectSays("\"action\": \"removed\"");
        // The ordinary lease answer on a removal that completed, and the control
        // for `job rm`'s leak gate below: this row went back.
        try quiet.expectSays("\"leaseRelease\": \"released\"");
        try quiet.expectSays("\"leaseReleaseError\": null");

        var store = try f.open();
        defer store.close();
        var arena_state = std.heap.ArenaAllocator.init(t.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        try t.expect((try Store.jobs.getByName(&store, arena, 1, "verify")) == null);
    }

    // The settling control: the second look reads the address, finds nothing
    // there, and the job's own sentinel answers in its place. The attempt
    // settles, the command exits 0 and the name is free again.
    //
    // Without it every assertion above would hold just as well against a binary
    // that had started calling every outcome unknown.
    {
        var settled = try runWithEnvironment(&f, control_argv.items, &environ);
        defer settled.deinit(f.allocator);
        try host.expectFullyScripted();
        try settled.expectCode(0);
        try settled.expectSays("\"ok\": true");
        try settled.expectSays("\"resultRecord\": \"absent\"");
        try settled.expectSays("\"resultRecordError\": null");

        {
            var store = try f.open();
            defer store.close();
            var arena_state = std.heap.ArenaAllocator.init(t.allocator);
            defer arena_state.deinit();
            const arena = arena_state.allocator();
            const op = (try Store.operations.get(&store, arena, control_id)).?;
            try t.expectEqualStrings("completed", op.status.text());
        }

        // …and the name is not turned away where it stands, which is what a freed
        // scope means to whoever launches next. It still fails at the host —
        // nothing here scripts a launch — but not at the scope guard.
        var relaunch = try runWithEnvironment(&f, &.{
            "run", "box", "--name", "release", "--cmd", "make release", "--db", f.db,
        }, &environ);
        defer relaunch.deinit(f.allocator);
        try relaunch.expectSaysNot("refused: request");
    }
}

test "blackbox: `job rm` keeps the row when the look after the kill never happens" {
    try probeFailureAfterTheKill("probe_error_rm", "rm", null, .remote_failed);
}

test "blackbox: `job rm --discard-evidence` destroys nothing when the look after the kill never happens" {
    try probeFailureAfterTheKill("probe_error_rm_discard", "rm", "--discard-evidence", .remote_failed);
}

test "blackbox: `job rm` keeps the row when tmux goes missing after the kill" {
    try probeFailureAfterTheKill("probe_tmux_rm", "rm", null, .tmux_missing);
}

// The one that makes a published sentence true. `skill/SKILL.md` says that if
// `tmux` is not runnable on the host, nothing is deleted on it — which held for
// the pre-kill probe (`fatalProbe` -> `fatalTmux`) and was false here:
// `isAlive` raises `TmuxMissing` inside the *post-kill* probe, `finalProbe`
// swallowed it, and this verb went on to delete the pane log and the result file.
test "blackbox: `job rm --discard-evidence` deletes nothing when tmux goes missing after the kill" {
    try probeFailureAfterTheKill("probe_tmux_rm_discard", "rm", "--discard-evidence", .tmux_missing);
}

// `job kill`'s half of the decision, which is that it does not change.
//
// The asymmetry this rule closes was in the verb, not the error set: `job kill`
// already settles `indeterminate` and exits 75 for every one of these faults, so
// giving it the second word would rename a transient network blip's settlement
// without fixing anything — while `job rm` was deleting a log, a result record
// and a local row over the same fault and reporting `ok: true`.
//
// So this gate asserts the *absence* of the new behaviour on this verb, and it
// asserts it where it would be visible: the published reading stays the pre-kill
// look's own answer, and the word `probe_error` never appears.
test "blackbox: `job kill` is unchanged when the look after the kill never happens" {
    const t = std.testing;
    var f = try Fixture.init(t.allocator, "probe_error_kill");
    defer f.deinit();
    try f.seedServer();

    const request_id = "01SSSSSSSS0123456789ABCDEF";
    const sentinel = "__TERMINUS_JOB_7__";
    try seedRunningJob(&f, request_id, "deploy", sentinel);

    const running = "\n" ++ probe_split ++ "\n12\nbuilding...\n";
    var rules = [_]FakeHost.Rule{
        .{ .needle = "kill-session", .exit_code = 0 },
        .{ .needle = "job-deploy.log", .stdout = running, .uses = 1 },
        .{ .needle = "job-deploy.log", .exit_code = 2 },
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
    try host.expectSent("kill-session");
    try host.expectFullyScripted();

    // The ordinary unprovable cancellation, which is where this fault already
    // landed: 75, and the reading the pre-kill look actually took.
    try killed.expectCode(75);
    try killed.expectSays("\"resultRecord\": \"absent\"");
    try killed.expectSays("\"resultRecordError\": null");
    // The word `job rm` publishes for this fault is not one of `job kill`'s.
    try killed.expectSaysNot("probe_error");
    try killed.expectSaysNot("read_error");

    var store = try f.open();
    defer store.close();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const op = (try Store.operations.get(&store, arena, request_id)).?;
    try t.expectEqualStrings("indeterminate", op.status.text());
}

// The ordering the arms of `removeJob`'s settlement are in, and the price it
// charges, pinned because it is decided rather than because it is obvious.
//
// The arms run `unreadable` -> `probe_error` -> `probe.exit_code` ->
// `!authority.holds()`. So a `job rm` on a job that had already reached its own
// end *before* the kill — the pre-kill look read its result record and holds a
// real exit status — settles `indeterminate` and exits 75 when the look after the
// kill breaks on the wire, rather than settling the code it read and exiting 0.
//
// The two arms above the exit code are above it for different reasons, and only
// one of them carries a contradiction. `unreadable` is two observations of a
// single document: one says it held an exit status, the other says the host cannot
// obtain its bytes, and nothing here can say which side of the kill was right.
// `probe_error` makes no claim about the document at all — the round trip broke —
// and it outranks the exit code because this verb's purpose is deletion. Every
// destructive step below the kill was declined, so the row, the log and the
// sidecar are all still there, and the arms beneath this one open with "job
// removed": a receipt saying so beside a surviving row would report a removal this
// command refused to perform. That is a choice, not a deduction, and the
// alternative — publish the exit code and report the broken look beside it — was
// the one the programmer rejected.
//
// The cost is real and deliberate: a caller who could have been told exit 7 is
// told "unknown" instead. It is not *lost*, and that is what the whole ordering
// rests on. Nothing was deleted, so both durable records are sitting on the host
// exactly as the job left them, and the hint names `reconcile --from-log` — the
// one reconcile that reads that same intact sidecar and settles the real code.
// `--override` is not offered, because nothing here needs a human's decision.
//
// Three legs on one fixture, one verb with one set of flags, differing only in
// what the host says to the look after the kill. Without the last two, every
// assertion below would hold just as well against a binary that had started
// calling every removal unknown, or one that had collapsed the two blind
// findings into a single word.
test "blackbox: `job rm` settles indeterminate over an exit code read before a post-kill look that failed" {
    const t = std.testing;
    var f = try Fixture.init(t.allocator, "finished_then_probe_failed");
    defer f.deinit();
    try f.seedServer();

    const sentinel = "__TERMINUS_JOB_7__";

    // The job this gate is about: over before the kill, and the look that had to
    // follow the kill fails at the transport.
    const deploy_id = "01TTTTTTTT0123456789ABCDEF";
    try seedRunningJob(&f, deploy_id, "deploy", sentinel);

    // Control one, for the arm directly above. The same already-finished job, and
    // a post-kill look that *did* reach the address and could not read what is at
    // it. That is still `read_error`, and it still sends the operator to
    // `--override` — `--from-log` reads the document that would not open. Collapse
    // the two words and the leg above is measuring one branch twice.
    const salvage_id = "01VVVVVVVV0123456789ABCDEF";
    try seedRunningJob(&f, salvage_id, "salvage", sentinel);

    // Control two, for the arm directly below, and the one that decides whether
    // this gate is about a failure path at all. The same already-finished job, and
    // a post-kill look that works: it reaches the address, finds nothing at it and
    // no sentinel in the window behind it, so it has nothing to hand back. The
    // exit status this removal settles can therefore only be the one the *pre-kill*
    // look read.
    //
    // Deliberately not a second look that carries the code again. That returns
    // through `finalProbe`'s upgrade arm, which is read before any failure arm and
    // replaces the pre-kill probe wholesale — so it would prove the post-kill
    // reading is honoured and say nothing about the one this gate is about. It is
    // the same trap `job kill`'s settling control fell into.
    const release_id = "01WWWWWWWW0123456789ABCDEF";
    try seedRunningJob(&f, release_id, "release", sentinel);

    // A first look that finds the job already over: its own result record, at its
    // own request id, reporting 7. Non-zero on purpose — `exited{0}` is what a
    // dropped exit code and half the defaults in the file look like, and 7 is
    // not — with no sentinel in the log window, so the record is the only thing
    // that established it.
    const finished_deploy = "{\"v\":1,\"requestId\":\"" ++ deploy_id ++
        "\",\"exitCode\":7,\"finishedAt\":1750}\n" ++ probe_split ++ "\n12\nbuilding...\n";
    const finished_salvage = "{\"v\":1,\"requestId\":\"" ++ salvage_id ++
        "\",\"exitCode\":7,\"finishedAt\":1750}\n" ++ probe_split ++ "\n12\nbuilding...\n";
    const finished_release = "{\"v\":1,\"requestId\":\"" ++ release_id ++
        "\",\"exitCode\":7,\"finishedAt\":1750}\n" ++ probe_split ++ "\n12\nbuilding...\n";
    // …and a look that reached the address and found nothing at it, with no
    // sentinel behind it either: readable, and with nothing to report.
    const nothing_there = "\n" ++ probe_split ++ "\n12\nbuilding...\n";

    // Keyed by the log path each probe script carries, because all three jobs'
    // probes contain the split marker and this gate needs them answered
    // differently in one conversation. `rm -f` is first so a deletion is never
    // answered by a probe rule that happens to name the same log — that is what
    // makes `expectNeverSent` an assertion about the binary rather than about the
    // fake — and `kill-session` is next because that script carries `has-session`
    // too.
    var rules = [_]FakeHost.Rule{
        .{ .needle = "rm -f", .exit_code = 0 },
        .{ .needle = "kill-session", .exit_code = 0 },
        // `deploy`: finished, then a probe script that reports failure, which is
        // `error.RemoteFailed`. Any non-zero status that is not `44` does it; `44`
        // is the one code that means "the record is there and would not open" and
        // is the next job's business. Unbounded on purpose — nothing after this
        // should depend on how many round trips the rest of the command spends.
        .{ .needle = "job-deploy.log", .stdout = finished_deploy, .uses = 1 },
        .{ .needle = "job-deploy.log", .exit_code = 2 },
        // `salvage`: finished, then `44` — a file is at this attempt's address and
        // `head` could not obtain its bytes.
        .{ .needle = "job-salvage.log", .stdout = finished_salvage, .uses = 1 },
        .{ .needle = "job-salvage.log", .exit_code = 44 },
        // `release`: finished, then a look that worked and found nothing.
        .{ .needle = "job-release.log", .stdout = finished_release, .uses = 1 },
        .{ .needle = "job-release.log", .stdout = nothing_there },
        .{ .needle = "has-session", .exit_code = 0 },
    };
    var host = try FakeHost.start(&f, &rules);
    defer host.stop();
    var environ = try host.environment();
    defer environ.deinit();

    // `--discard-evidence` on all three, so the two `expectNeverSent` calls below
    // are about a deletion this command was *asked* to perform and declined, and
    // so the third leg's `expectSent` is the same command doing it when it may.
    {
        var acted = try runWithEnvironment(&f, &.{
            "job", "rm", "box", "deploy", "--discard-evidence", "--json", "--db", f.db,
        }, &environ);
        defer acted.deinit(f.allocator);

        // The traffic first, and the forbidden command before any number: a
        // regression that starts destroying evidence here has to read as `rm -f`
        // reaching the host, not as an exit code that moved. The kill did go out —
        // this is not a command that stopped short of it.
        try host.expectSent("kill-session");
        try host.expectNeverSent("rm -f");
        try host.expectFullyScripted();

        // 75, and neither 0 nor 1. 0 is what the rejected ordering returns here,
        // and 1 would invite the blind retry an unknown outcome must not.
        try acted.expectCode(75);

        // The two words, in the only place a `--json` consumer can see them, and
        // never the pre-kill look's own reading: `present` here would say this
        // command knows what is at that address after the kill, which is exactly
        // what it does not.
        try acted.expectSays("\"resultRecord\": \"probe_error\"");
        try acted.expectSays("\"resultRecordError\": \"probe_error\"");
        try acted.expectSaysNot("\"resultRecord\": \"present\"");
        try acted.expectSaysNot("read_error");
        // Where the caller is sent, and it is the half of this rule that makes the
        // withheld exit code recoverable rather than lost: both records are intact,
        // so the reconcile that reads them settles the real 7 once the host answers
        // again. `--override` would be asking a human to decide something no human
        // has to.
        try acted.expectSays("--from-log");
        try acted.expectSaysNot("--override");
        try acted.expectSays("failed with RemoteFailed");

        var store = try f.open();
        defer store.close();
        var arena_state = std.heap.ArenaAllocator.init(t.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        // Out of the store, not parsed out of stdout. `indeterminate`, which is
        // what `exited{7}` is not: the rejected ordering settles this attempt
        // `failed`.
        const op = (try Store.operations.get(&store, arena, deploy_id)).?;
        try t.expectEqualStrings("indeterminate", op.status.text());

        // …and said again where it cannot be a coincidence of one enum tag. A
        // terminal receipt for `exited{7}` carries the code itself and
        // `REMOTE_NONZERO_EXIT`; this one carries neither.
        const rows = try Store.receipts.list(&store, arena, deploy_id);
        var terminal: ?Store.receipts.Row = null;
        for (rows) |row| if (row.is_terminal) {
            terminal = row;
        };
        const receipt = terminal orelse return error.RemovalLeftNoTerminalReceipt;
        try t.expectEqual(@as(?i64, null), receipt.exit_code);
        try t.expectEqualStrings("INDETERMINATE", receipt.error_code orelse
            return error.TerminalReceiptCarriedNoErrorCode);
        // The ledger's own sentence names the fault and the claim. The receipt is
        // what an operator reads weeks later, and "unknown" without saying why
        // sends them back to a host they cannot tell apart from a host with a
        // broken result file.
        const reason = receipt.transport_error orelse
            return error.TerminalReceiptCarriedNoReason;
        try t.expect(std.mem.indexOf(u8, reason, "RemoteFailed") != null);
        try t.expect(std.mem.indexOf(u8, reason, "no evidence was deleted") != null);

        // The row survives on the verb that exists to delete it. It is the last
        // thing pointing at the log and the sidecar still sitting on the host.
        try t.expect((try Store.jobs.getByName(&store, arena, 1, "deploy")) != null);
    }

    // Control one. Same fixture, same verb, same flags, same already-finished job —
    // and a post-kill look that reached the address and could not read the document
    // there. Two words, two next steps: if this has become `probe_error` a caller
    // can no longer tell a file it must repair from a wire it must retry.
    {
        var unreadable = try runWithEnvironment(&f, &.{
            "job", "rm", "box", "salvage", "--discard-evidence", "--json", "--db", f.db,
        }, &environ);
        defer unreadable.deinit(f.allocator);

        try host.expectNeverSent("rm -f");
        try host.expectFullyScripted();
        try unreadable.expectCode(75);
        try unreadable.expectSays("\"resultRecord\": \"read_error\"");
        try unreadable.expectSays("\"resultRecordError\": \"read_error\"");
        try unreadable.expectSaysNot("probe_error");
        try unreadable.expectSays("--override");
        try unreadable.expectSaysNot("--from-log");

        var store = try f.open();
        defer store.close();
        var arena_state = std.heap.ArenaAllocator.init(t.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const op = (try Store.operations.get(&store, arena, salvage_id)).?;
        try t.expectEqualStrings("indeterminate", op.status.text());
        try t.expect((try Store.jobs.getByName(&store, arena, 1, "salvage")) != null);
    }

    // Control two. The same already-finished job under the same command, with a
    // post-kill look that worked: the exit status the pre-kill look read is
    // published, the row is forgotten, the evidence this leg was told to discard is
    // discarded, and the command exits 0. This is what the leg above gives up, and
    // stating it here is the difference between a rule and a binary that stopped
    // settling anything.
    {
        var settled = try runWithEnvironment(&f, &.{
            "job", "rm", "box", "release", "--discard-evidence", "--json", "--db", f.db,
        }, &environ);
        defer settled.deinit(f.allocator);

        try host.expectFullyScripted();
        // The positive counterpart of the two absences above: this command really
        // does delete when it may, so their absence is a decision rather than a
        // binary that had stopped sending anything.
        try host.expectSent("rm -f");
        try settled.expectCode(0);
        try settled.expectSays("\"ok\": true");
        try settled.expectSays("\"outcomeProven\": true");
        try settled.expectSaysNot("probe_error");
        try settled.expectSaysNot("read_error");

        var store = try f.open();
        defer store.close();
        var arena_state = std.heap.ArenaAllocator.init(t.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        // `failed` is the status of `exited{7}`, and the receipt carries the code
        // itself — the same reading the leg above deliberately withholds.
        const op = (try Store.operations.get(&store, arena, release_id)).?;
        try t.expectEqualStrings("failed", op.status.text());
        const rows = try Store.receipts.list(&store, arena, release_id);
        var terminal: ?Store.receipts.Row = null;
        for (rows) |row| if (row.is_terminal) {
            terminal = row;
        };
        const receipt = terminal orelse return error.RemovalLeftNoTerminalReceipt;
        try t.expectEqual(@as(?i64, 7), receipt.exit_code);
        try t.expectEqualStrings("REMOTE_NONZERO_EXIT", receipt.error_code orelse
            return error.TerminalReceiptCarriedNoErrorCode);

        // …and the row really is gone, which is the other thing the leg above
        // refuses to do.
        try t.expect((try Store.jobs.getByName(&store, arena, 1, "release")) == null);
    }
}

// The window every fail-closed step exists for, driven end to end: the binary
// takes the job scope before it dials, and a peer forces it away while the
// binary is waiting for its first probe to come back.
//
// The renewal's *answer* is the whole of it. `holdClaim` used to return `void`
// and merely print on loss, so this path went on to `kill-session` exactly as
// if nothing had happened: the layer that exists to stop two sessions acting on
// one job could not stop anything, because nothing read what it said. The
// operator saw one line on stderr and a killed job.
//
// Asserted on the traffic and not on the exit code. A refusal exits non-zero,
// and so does a dozen other faults — a fake host with a missing rule among them.
// Only "no command containing `kill-session` reached the host" says the
// destructive step did not happen.
test "blackbox: `job kill` sends nothing to the host once the scope has moved" {
    const t = std.testing;
    var f = try Fixture.init(t.allocator, "kill_scope_moved");
    defer f.deinit();
    try f.seedServer();

    const request_id = "01FFFFFFFF0123456789ABCDEF";
    const sentinel = "__TERMINUS_JOB_7__";
    try seedRunningJob(&f, request_id, "deploy", sentinel);

    // A job still running: no result record, no sentinel in the window. There is
    // nothing here to settle, so this is the branch whose only next step is the
    // kill.
    const running = "\n" ++ probe_split ++ "\n12\nbuilding...\n";
    var rules = [_]FakeHost.Rule{
        // The first look, and the moment the scope changes hands. Bounded to one
        // use so a second probe cannot seize a second time and make the peer's
        // row a different row from the one this gate checks.
        .{ .needle = probe_split, .stdout = running, .uses = 1, .seize = true },
        .{ .needle = probe_split, .stdout = running },
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

    // The property, checked before anything else. Every other assertion here is
    // downstream of it, and an exit code checked first would report a gate
    // failure in terms of a number rather than in terms of the kill that was
    // sent.
    try host.expectSeized();
    try host.expectNeverSent("kill-session");
    try host.expectFullyScripted();
    // Exit 1 and not 75: this command changed nothing, so nothing about the
    // remote is unknown *because of it*, and re-running once the scope is free
    // is safe. That distinction is the whole contract of the two codes.
    try killed.expectCode(1);

    try killed.expectSays("\"action\": \"not_killed\"");
    try killed.expectSays("\"authority\": \"lapsed\"");
    try killed.expectSays("\"ok\": false");
    try killed.expectSays("\"sessionGone\": false");
    try killed.expectSays("\"cancellationProven\": false");
    // The keys the other five branches carry, on this one too: a caller gets one
    // reader for `job kill --json`, not six.
    try killed.expectSays("\"resultRecord\": ");
    try killed.expectSays("\"observedAt\": ");
    try killed.expectSays("\"sessionCleanedUp\": false");
    try killed.expectSays("--force");

    var store = try f.open();
    defer store.close();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // The ledger is exactly where the launch left it: this command settled
    // nothing, because a step it may not take is not a step it may record having
    // taken.
    const op = (try Store.operations.get(&store, arena, request_id)).?;
    try t.expectEqualStrings("remote_started", op.status.text());
    // …and so is the row.
    const row = (try Store.jobs.getByName(&store, arena, 1, "deploy")).?;
    try t.expectEqualStrings("running", @tagName(row.status));

    // The peer holds the scope and was never handed it back. `Cli.releaseClaim`
    // runs on this exit path too, and a release matching by scope alone would
    // have unlocked the winner's work on the loser's way out.
    const held = try Store.leases.active(&store, arena, 1, try Store.leases.clockSeconds(&store));
    try t.expectEqual(@as(usize, 1), held.len);
    try t.expectEqualStrings(FakeHost.seizing_peer, held[0].owner_request_id);
}

// The other half of the rule, on the verb that destroys things: the scope goes
// while the kill is in flight, so the loss is only discoverable *after* a remote
// mutation has already happened.
//
// Nothing can undo the kill. What can still be refused is everything after it,
// and `job rm --discard-evidence` has three such steps — delete the log, delete
// the result record, delete the local row. All three are forbidden here, and the
// attempt is settled `indeterminate` with `AUTHORITY_LOST` rather than with the
// `exited`, `cancelled` or clean removal this command set out to write.
test "blackbox: `job rm --discard-evidence` deletes nothing once the scope has moved" {
    const t = std.testing;
    var f = try Fixture.init(t.allocator, "rm_scope_moved");
    defer f.deinit();
    try f.seedServer();

    const request_id = "01GGGGGGGG0123456789ABCDEF";
    const sentinel = "__TERMINUS_JOB_7__";
    try seedRunningJob(&f, request_id, "deploy", sentinel);

    const running = "\n" ++ probe_split ++ "\n12\nbuilding...\n";
    var rules = [_]FakeHost.Rule{
        .{ .needle = probe_split, .stdout = running },
        // The kill goes out under a lease this command still holds — and comes
        // back after the scope has changed hands. Listed before `has-session`
        // because `killSession`'s script contains both words.
        .{ .needle = "kill-session", .exit_code = 0, .uses = 1, .seize = true },
        .{ .needle = "kill-session", .exit_code = 0 },
        .{ .needle = "has-session", .exit_code = 0 },
    };
    var host = try FakeHost.start(&f, &rules);
    defer host.stop();
    var environ = try host.environment();
    defer environ.deinit();

    var removed = try runWithEnvironment(&f, &.{
        "job", "rm", "box", "deploy", "--discard-evidence", "--json", "--db", f.db,
    }, &environ);
    defer removed.deinit(f.allocator);

    try host.expectSeized();
    // Both deletions are `rm -f` scripts. Neither was sent, and neither reached
    // the host under any other name: an unscripted command would have been
    // counted as well. Checked ahead of the exit code, which a dozen other
    // faults also move.
    try host.expectNeverSent("rm -f");
    try host.expectFullyScripted();

    try removed.expectSays("\"action\": \"not_removed\"");
    try removed.expectSays("\"rowRemoved\": false");
    // What actually happened to the evidence, not what `--discard-evidence`
    // asked for. Reporting the flag here would send an operator looking for a
    // log that is still sitting on the host.
    try removed.expectSays("\"evidenceRetained\": true");
    try removed.expectSays("\"authority\": \"lapsed\"");
    try removed.expectSays("\"ok\": false");
    try removed.expectSays("\"outcomeProven\": false");
    // The reading, on the branch that took nothing. `job rm` deletes the local
    // row, so this line and the receipt are the only places it survives — and
    // "there was no document" has to be tellable from "there was one and we
    // would not read it", which `outcomeProven` (false for both) cannot say.
    try removed.expectSays("\"resultRecord\": \"absent\"");
    try removed.expectCode(1);

    var store = try f.open();
    defer store.close();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // The row is still there, which is the local half of "forbid the deletion".
    try t.expect((try Store.jobs.getByName(&store, arena, 1, "deploy")) != null);

    // The attempt is settled, and settled as unknown. Not `cancelled`: the pane
    // went away, but with the scope in somebody else's hands since, "this
    // command stopped that work and it is gone" is exactly what cannot be said.
    const op = (try Store.operations.get(&store, arena, request_id)).?;
    try t.expectEqualStrings("indeterminate", op.status.text());

    // …and the receipt names why, in the code an auditor reads. Without it this
    // is indistinguishable from the four other ways a kill ends unknown.
    const rows = try Store.receipts.list(&store, arena, request_id);
    var terminal_code: ?[]const u8 = null;
    for (rows) |row| if (row.is_terminal) {
        terminal_code = row.error_code;
    };
    const code = terminal_code orelse return error.RemovalLeftNoTerminalReceipt;
    try t.expectEqualStrings("AUTHORITY_LOST", code);
}

// Authority and evidence are different things, and this is the gate that holds
// them apart on one path.
//
// Both arms lose the scope at the same instant — the reply to `kill-session`,
// the last moment at which nothing can be taken back. They differ in one thing
// only: whether the second look comes back holding the job's own exit status.
//
//   * with a code, the ledger records `exited{7}`. The reading came from a
//     document at this attempt's own request id, which no peer can write to
//     without starting a new attempt under a new id, so losing the lease cannot
//     have made it stale. What the loss costs is the right to *act*, not the
//     truth of what was already read.
//   * without one, there is nothing to stand on and the ledger records
//     `indeterminate` / `AUTHORITY_LOST`.
//
// And on both, every claim that rests on the kill having worked is gone:
// `cancellationProven` false, no `remote_cancel_confirmed`, `ok` false, a
// non-zero exit. An earlier version downgraded both arms; the point of running
// them together is that a rule which cannot tell them apart fails one or the
// other.
test "blackbox: a lost scope costs `job kill` and `job rm` their claims, not the exit status they read" {
    const t = std.testing;

    // Arm one: the job ended by itself while the kill was in flight, and left
    // its result record behind.
    {
        var f = try Fixture.init(t.allocator, "kill_lost_scope_with_code");
        defer f.deinit();
        try f.seedServer();

        const request_id = "01HHHHHHHH0123456789ABCDEF";
        const sentinel = "__TERMINUS_JOB_7__";
        try seedRunningJob(&f, request_id, "deploy", sentinel);

        const running = "\n" ++ probe_split ++ "\n12\nbuilding...\n";
        // The second look: a result record at this attempt's own id, saying 7.
        const finished = "{\"v\":1,\"requestId\":\"" ++ request_id ++
            "\",\"exitCode\":7,\"finishedAt\":1750}\n" ++ probe_split ++ "\n12\nbuilding...\n";
        var rules = [_]FakeHost.Rule{
            .{ .needle = probe_split, .stdout = running, .uses = 1 },
            // The kill goes out under a lease we hold and comes back after the
            // scope has moved. Before `has-session`: the kill script contains
            // both words.
            .{ .needle = "kill-session", .exit_code = 0, .uses = 1, .seize = true },
            .{ .needle = "kill-session", .exit_code = 0 },
            .{ .needle = probe_split, .stdout = finished },
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

        try host.expectSeized();
        // The kill did go out here — that is the premise. What must not have
        // gone out is anything that destroys evidence.
        try host.expectNeverSent("rm -f");
        try host.expectFullyScripted();

        try killed.expectSays("\"action\": \"finished_during_kill\"");
        // The half that survives.
        try killed.expectSays("\"exitCode\": 7");
        try killed.expectSays("\"outcomeProven\": true");
        // The half that does not.
        try killed.expectSays("\"cancellationProven\": false");
        try killed.expectSays("\"authority\": \"lapsed\"");
        try killed.expectSays("\"ok\": false");
        // Exit 1, not 75: the outcome is not in doubt, this command's standing
        // is. A caller that reads 75 goes and reconciles a settled operation.
        try killed.expectCode(1);

        var store = try f.open();
        defer store.close();
        var arena_state = std.heap.ArenaAllocator.init(t.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        const op = (try Store.operations.get(&store, arena, request_id)).?;
        try t.expectEqualStrings("failed", op.status.text());

        // The receipt says the job failed with a real code — not that the
        // authority went. Downgrading here is what threw the reading away.
        const rows = try Store.receipts.list(&store, arena, request_id);
        var terminal_code: ?[]const u8 = null;
        for (rows) |row| if (row.is_terminal) {
            terminal_code = row.error_code;
        };
        const code = terminal_code orelse return error.KillLeftNoTerminalReceipt;
        try t.expectEqualStrings("REMOTE_NONZERO_EXIT", code);

        // The row followed the ledger. Two records of one reading disagreeing
        // is the state this path exists to avoid.
        const row = (try Store.jobs.getByName(&store, arena, 1, "deploy")).?;
        try t.expectEqualStrings("exited", @tagName(row.status));
    }

    // Arm two: the same loss at the same instant, with nothing to stand on.
    {
        var f = try Fixture.init(t.allocator, "kill_lost_scope_no_code");
        defer f.deinit();
        try f.seedServer();

        const request_id = "01JJJJJJJJ0123456789ABCDEF";
        const sentinel = "__TERMINUS_JOB_7__";
        try seedRunningJob(&f, request_id, "deploy", sentinel);

        const running = "\n" ++ probe_split ++ "\n12\nbuilding...\n";
        var rules = [_]FakeHost.Rule{
            .{ .needle = probe_split, .stdout = running, .uses = 1 },
            .{ .needle = "kill-session", .exit_code = 0, .uses = 1, .seize = true },
            .{ .needle = "kill-session", .exit_code = 0 },
            // The second look finds what the first did: nothing.
            .{ .needle = probe_split, .stdout = running },
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

        try host.expectSeized();
        try host.expectNeverSent("rm -f");
        try host.expectFullyScripted();

        try killed.expectSays("\"authority\": \"lapsed\"");
        try killed.expectSays("\"cancellationProven\": false");
        try killed.expectSays("\"outcomeProven\": false");
        try killed.expectSays("\"exitCode\": null");
        try killed.expectSays("\"ok\": false");
        // 75 here, and 1 in the arm above. The pair is the contract: unknown
        // outcome versus known outcome under a command that may no longer act.
        try killed.expectCode(75);

        var store = try f.open();
        defer store.close();
        var arena_state = std.heap.ArenaAllocator.init(t.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        const op = (try Store.operations.get(&store, arena, request_id)).?;
        try t.expectEqualStrings("indeterminate", op.status.text());

        const rows = try Store.receipts.list(&store, arena, request_id);
        var terminal_code: ?[]const u8 = null;
        for (rows) |row| if (row.is_terminal) {
            terminal_code = row.error_code;
        };
        const code = terminal_code orelse return error.KillLeftNoTerminalReceipt;
        try t.expectEqualStrings("AUTHORITY_LOST", code);

        // The row records that the session was killed, which it was —
        // `killSession` proved the pane gone in the same round trip that lost
        // us the lease, and that reading is no staler than arm one's exit code.
        // The write is a compare-and-set on the row this command read, so a
        // peer that has already relaunched refuses it rather than losing it.
        //
        // What the row does *not* say, and what the ledger above refuses to
        // say, is that this command established an outcome. Those are the two
        // different questions the two records answer.
        const row = (try Store.jobs.getByName(&store, arena, 1, "deploy")).?;
        try t.expectEqualStrings("killed", @tagName(row.status));
    }

    // Arm three: the same rule on the verb that deletes things. `job rm
    // --discard-evidence` loses the scope on the kill's reply and then reads
    // the job's own exit status, so the two halves land on one command: the
    // outcome is recorded, and every destructive step it was about to take is
    // refused.
    {
        var f = try Fixture.init(t.allocator, "rm_lost_scope_with_code");
        defer f.deinit();
        try f.seedServer();

        const request_id = "01KKKKKKKK0123456789ABCDEF";
        const sentinel = "__TERMINUS_JOB_7__";
        try seedRunningJob(&f, request_id, "deploy", sentinel);

        const running = "\n" ++ probe_split ++ "\n12\nbuilding...\n";
        const finished = "{\"v\":1,\"requestId\":\"" ++ request_id ++
            "\",\"exitCode\":7,\"finishedAt\":1750}\n" ++ probe_split ++ "\n12\nbuilding...\n";
        var rules = [_]FakeHost.Rule{
            .{ .needle = probe_split, .stdout = running, .uses = 1 },
            .{ .needle = "kill-session", .exit_code = 0, .uses = 1, .seize = true },
            .{ .needle = "kill-session", .exit_code = 0 },
            .{ .needle = probe_split, .stdout = finished },
            .{ .needle = "has-session", .exit_code = 0 },
        };
        var host = try FakeHost.start(&f, &rules);
        defer host.stop();
        var environ = try host.environment();
        defer environ.deinit();

        var removed = try runWithEnvironment(&f, &.{
            "job", "rm", "box", "deploy", "--discard-evidence", "--json", "--db", f.db,
        }, &environ);
        defer removed.deinit(f.allocator);

        try host.expectSeized();
        try host.expectNeverSent("rm -f");
        try host.expectFullyScripted();

        // Refused as a removal…
        try removed.expectSays("\"action\": \"not_removed\"");
        try removed.expectSays("\"rowRemoved\": false");
        try removed.expectSays("\"evidenceRetained\": true");
        try removed.expectSays("\"authority\": \"lapsed\"");
        try removed.expectSays("\"ok\": false");
        // …and still holding the reading it took on the way. A removal that
        // refuses is not a removal that forgets what it saw.
        try removed.expectSays("\"outcomeProven\": true");
        try removed.expectSays("\"resultRecord\": \"present\"");
        try removed.expectCode(1);

        var store = try f.open();
        defer store.close();
        var arena_state = std.heap.ArenaAllocator.init(t.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        const op = (try Store.operations.get(&store, arena, request_id)).?;
        try t.expectEqualStrings("failed", op.status.text());

        const rows = try Store.receipts.list(&store, arena, request_id);
        var terminal_code: ?[]const u8 = null;
        for (rows) |row| if (row.is_terminal) {
            terminal_code = row.error_code;
        };
        const code = terminal_code orelse return error.RemovalLeftNoTerminalReceipt;
        try t.expectEqualStrings("REMOTE_NONZERO_EXIT", code);

        // The local half of "refused": the row this command was about to
        // forget is still there for the peer that now owns the name.
        try t.expect((try Store.jobs.getByName(&store, arena, 1, "deploy")) != null);
    }
}

/// One of the three `job kill` branches that write their settlement before they
/// clean the session up.
///
/// All three reach the host, read something the ledger can be told about — a
/// contradiction between the two durable records, a result record that is
/// present and unusable, or an exit status the job simply left behind — and
/// record it *before* sending `kill-session`, because the settlement describes
/// what the probe saw and nothing about it depends on the kill. That order is
/// why each of them carries two renewals rather than one: a store transaction
/// sits between the answer and the act, and a peer's `--force` landing inside
/// it would leave the command sending `kill-session` *by name* at a session the
/// new holder owns.
///
/// Each branch is driven twice on identical scripts, differing in one thing:
/// whether the scope is taken while the binary is blocked on the probe's reply.
/// The pair is the point — a gate that only ever refuses is green against a
/// binary that refuses every kill there is, and a gate that only ever kills is
/// green against the defect these exist for.
///
/// What the pair does *not* reach is the window between the settlement and the
/// kill. `FakeHost.Rule.seize` is deterministic only while the binary is
/// blocked on this socket, and between a renewal and the call it gates there
/// is, by construction, nothing to block on: no round trip, and therefore no
/// instant an outside agent can be scheduled into. The adjacency of those two
/// lines is held instead by a gate in `src/cli/cmd_job.zig` that reads the
/// source — see "every destructive remote call is renewed on the line above
/// it".
const KillBranch = struct {
    /// Names the two scratch fixtures this drives.
    name: []const u8,
    request_id: []const u8,
    /// The probe reply that puts `job kill` on this branch.
    probe: []const u8,
    /// A substring of the JSON that only this branch's reading produces.
    /// Asserted on both runs so three fixtures cannot silently collapse onto
    /// one branch and report it three times.
    marker: []const u8,
    /// What the run nobody interferes with calls what it did, and exits with.
    action: []const u8,
    code: u8,
    /// The ledger's own word for the attempt after that run, read out of the
    /// store rather than out of the report that claimed it.
    settled: []const u8,
};

const kill_branch_sentinel = "__TERMINUS_JOB_7__";

fn killBranchRefusesAScopeItHasLost(branch: KillBranch) !void {
    const t = std.testing;
    const fixture_name = try std.fmt.allocPrint(t.allocator, "{s}_seized", .{branch.name});
    defer t.allocator.free(fixture_name);
    var f = try Fixture.init(t.allocator, fixture_name);
    defer f.deinit();
    try f.seedServer();
    try seedRunningJob(&f, branch.request_id, "deploy", kill_branch_sentinel);

    var rules = [_]FakeHost.Rule{
        // The first look, and the moment the scope changes hands. Bounded to
        // one use so a second look cannot seize again and make the peer's row a
        // different row from the one this checks.
        .{ .needle = probe_split, .stdout = branch.probe, .uses = 1, .seize = true },
        .{ .needle = probe_split, .stdout = branch.probe },
        // No `kill-session` rule on purpose. One that was sent still gets
        // recorded, and `expectNeverSent` below reports it in those words
        // instead of as traffic the fake could not answer.
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

    // The property, ahead of everything downstream of it. An exit code checked
    // first would name a number; this names the kill.
    try host.expectSeized();
    try host.expectNeverSent("kill-session");
    try host.expectFullyScripted();
    // Exit 1 rather than 75: this command changed nothing, so nothing about the
    // remote is unknown because of it and a retry is safe once the scope frees.
    try killed.expectCode(1);

    try killed.expectSays("\"action\": \"not_killed\"");
    try killed.expectSays("\"authority\": \"lapsed\"");
    try killed.expectSays("\"ok\": false");
    try killed.expectSays("\"sessionGone\": false");
    try killed.expectSays("\"cancellationProven\": false");
    // The peer took our row, so there was nothing of ours left to hand back — and
    // that is neither a clean release nor a leak. One of three discriminating
    // values across these fixtures; see the two `left_held` gates below.
    try killed.expectSays("\"leaseRelease\": \"not_ours\"");
    // …on the branch this fixture means to drive, and not another one.
    try killed.expectSays(branch.marker);

    var store = try f.open();
    defer store.close();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Nothing was settled. A step this command may not take is not a step it
    // gets to record having taken, and every one of these branches was about to
    // write a terminal.
    const op = (try Store.operations.get(&store, arena, branch.request_id)).?;
    try t.expectEqualStrings("remote_started", op.status.text());
    const row = (try Store.jobs.getByName(&store, arena, 1, "deploy")).?;
    try t.expectEqualStrings("running", @tagName(row.status));

    // The peer still holds the scope: the loser's exit did not hand it back.
    const held = try Store.leases.active(&store, arena, 1, try Store.leases.clockSeconds(&store));
    try t.expectEqual(@as(usize, 1), held.len);
    try t.expectEqualStrings(FakeHost.seizing_peer, held[0].owner_request_id);
}

fn killBranchStillKillsWhatItHolds(branch: KillBranch) !void {
    const t = std.testing;
    const fixture_name = try std.fmt.allocPrint(t.allocator, "{s}_held", .{branch.name});
    defer t.allocator.free(fixture_name);
    var f = try Fixture.init(t.allocator, fixture_name);
    defer f.deinit();
    try f.seedServer();
    try seedRunningJob(&f, branch.request_id, "deploy", kill_branch_sentinel);

    var rules = [_]FakeHost.Rule{
        .{ .needle = probe_split, .stdout = branch.probe },
        // Before `has-session`: the kill's script contains both words.
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

    // The discriminating half: with nobody taking the scope, the second
    // renewal answers `held` and the kill goes out exactly as it did before.
    // A renewal that refused its own command would show up here and nowhere
    // else — the refusal gate above would still be green.
    try host.expectSent("kill-session");
    try host.expectFullyScripted();
    try killed.expectCode(branch.code);
    try killed.expectSays(branch.action);
    try killed.expectSays(branch.marker);
    try killed.expectSays("\"authority\": \"held\"");
    try killed.expectSays("\"authorityError\": null");
    try killed.expectSays("\"sessionGone\": true");
    // The ordinary answer, and the control that keeps the leak gates below honest:
    // a `leaseRelease` hard-coded to `left_held`, or a release that had stopped
    // happening at all, fails here on all three branches.
    try killed.expectSays("\"leaseRelease\": \"released\"");
    try killed.expectSays("\"leaseReleaseError\": null");

    var store = try f.open();
    defer store.close();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const op = (try Store.operations.get(&store, arena, branch.request_id)).?;
    try t.expectEqualStrings(branch.settled, op.status.text());

    // And the claim went back. Two renewals per branch push `expires_at`
    // further out than one did; what must not change is that the command still
    // gives the scope up when it is done with it.
    const still_held = try Store.leases.active(&store, arena, 1, try Store.leases.clockSeconds(&store));
    try t.expectEqual(@as(usize, 0), still_held.len);
}

fn killBranchSettlesThenCleansUp(branch: KillBranch) !void {
    try killBranchRefusesAScopeItHasLost(branch);
    try killBranchStillKillsWhatItHolds(branch);
}

test "blackbox: a kill that found the two records disagreeing settles, then needs the scope to clean up" {
    const request_id = "01MMMMMMMM0123456789ABCDEF";
    try killBranchSettlesThenCleansUp(.{
        .name = "kill_conflict",
        .request_id = request_id,
        // Both records readable, and they do not agree: the result file says 3,
        // the sentinel in the log says 7. One of them is wrong and nothing here
        // can say which, so the settlement is `indeterminate` and the kill is
        // the cleanup the caller asked for.
        .probe = "{\"v\":1,\"requestId\":\"" ++ request_id ++ "\",\"exitCode\":3,\"finishedAt\":1750}\n" ++
            probe_split ++ "\n20\nwork done\n" ++ kill_branch_sentinel ++ ":7\n",
        .marker = "\"resultExitCode\": 3",
        .action = "\"action\": \"killed\"",
        .code = 75,
        .settled = "indeterminate",
    });
}

test "blackbox: a kill over an unusable result record settles, then needs the scope to clean up" {
    const request_id = "01NNNNNNNN0123456789ABCDEF";
    try killBranchSettlesThenCleansUp(.{
        .name = "kill_refused",
        .request_id = request_id,
        // A document at this request's own address carrying an exit status no
        // shell produces, with the job's own sentinel behind it. The stronger
        // record is unusable, so the weaker one cannot be checked against it.
        .probe = "{\"v\":1,\"requestId\":\"" ++ request_id ++ "\",\"exitCode\":9000,\"finishedAt\":1750}\n" ++
            probe_split ++ "\n20\nwork done\n" ++ kill_branch_sentinel ++ ":7\n",
        .marker = "\"resultRecord\": \"exit_code_out_of_range\"",
        .action = "\"action\": \"killed\"",
        .code = 75,
        .settled = "indeterminate",
    });
}

test "blackbox: a kill on a job that already finished settles, then needs the scope to clean up" {
    try killBranchSettlesThenCleansUp(.{
        .name = "kill_finished",
        .request_id = "01PPPPPPPP0123456789ABCDEF",
        // Nothing at the result record's address and the job's own sentinel in
        // the tail: the outcome was there before this command was run, and the
        // kill is cleanup.
        .probe = "\n" ++ probe_split ++ "\n20\nwork done\n" ++ kill_branch_sentinel ++ ":0\n",
        .marker = "\"resultRecord\": \"absent\"",
        .action = "\"action\": \"already_finished\"",
        .code = 0,
        .settled = "completed",
    });
}

// --- The leaked lease, published rather than left on stderr -----------------
//
// `Cli.releaseClaim` returned `void`. On a clock-ordering violation or a store
// error it wrote a line to stderr and handed nothing back, so the caller went on
// to report `ok: true` over a lease that is still holding the job's scope — and
// the next `job kill`, `job rm` or `run --name` on that name is refused for the
// whole TTL, under a document that said the command succeeded. W1 closed that for
// `session rm`; the two gates below are the same shape on the two verbs that were
// left behind.
//
// The failure is *arranged*, not waited for: see `FakeHost.Rule.strand`. What each
// gate then asserts is three things a stdout match cannot establish on its own —
// that the document names the leak, that the store agrees the lease is still held,
// and that the scope really is barred, by running the next command and watching it
// be refused.
//
// The controls are in the fixtures above and below: `killBranchStillKillsWhatItHolds`
// asserts `released` on all three kill branches, `killBranchRefusesAScopeItHasLost`
// asserts `not_ours` on all three, and the `job rm` that completes asserts
// `released`. A binary that answered `left_held` unconditionally fails seven
// assertions before it reaches these two.

/// Asserts that one lease row is still held by the binary's own claim — not by a
/// peer, and not released — and that the scope it names is therefore barred.
///
/// Read from the store rather than believed from the report: `left_held` is a
/// claim about a row, and a report that printed the word over a row that had in
/// fact been handed back would be a new way of lying about the same thing.
fn expectScopeStillHeld(f: *Fixture, arena: std.mem.Allocator) !void {
    const t = std.testing;
    var store = try f.open();
    defer store.close();
    const now = try Store.leases.clockSeconds(&store);
    const held = try Store.leases.active(&store, arena, 1, now);
    try t.expectEqual(@as(usize, 1), held.len);
    // Not the fake host's peer: no takeover happened here, and a `not_ours` shaped
    // fixture would prove something else entirely.
    try t.expect(!std.mem.eql(u8, FakeHost.seizing_peer, held[0].owner_request_id));
    // …and it outlives this command by a long way, which is what makes the
    // refusal below the operator's real experience rather than a race.
    try t.expect(held[0].expires_at > now);
}

test "blackbox: a `job kill` that completed and could not give the scope back says so, and still exits 0" {
    const t = std.testing;
    var f = try Fixture.init(t.allocator, "kill_lease_left_held");
    defer f.deinit();
    try f.seedServer();
    const request_id = "01QQQQQQQQ0123456789ABCDEF";
    try seedRunningJob(&f, request_id, "deploy", kill_branch_sentinel);

    var rules = [_]FakeHost.Rule{
        // The job had already finished on its own: nothing at the result
        // record's address and its sentinel in the tail.
        .{ .needle = probe_split, .stdout = "\n" ++ probe_split ++ "\n20\nwork done\n" ++ kill_branch_sentinel ++ ":0\n" },
        // The kill, and the last remote call this branch makes. The strand rides
        // it because both of this branch's renewals are already behind us: the
        // report therefore says `authority: held` — the lease *was* ours the whole
        // time it mattered — and the only thing that failed is handing it back.
        // Before `has-session`: the kill's script contains both words.
        .{ .needle = "kill-session", .exit_code = 0, .strand = true },
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

    // The window really opened. Asserted before anything downstream, because a
    // strand that never fired makes every line below a statement about an
    // ordinary command.
    try host.expectStranded();
    try host.expectSent("kill-session");
    try host.expectFullyScripted();

    // **Exit 0, and that is the rule rather than an oversight.** The kill
    // completed and the outcome is durably recorded; a non-zero code would say
    // otherwise and send a caller into the retry this very lease would refuse.
    // The leak is reported in a field, not in the status code.
    try killed.expectCode(0);
    try killed.expectSays("\"ok\": true");
    try killed.expectSays("\"action\": \"already_finished\"");
    try killed.expectSays("\"outcomeProven\": true");
    // Two different questions, two different answers, and this is the pair that
    // says why both keys exist: the lease was ours for every step that needed it,
    // and the scope is not free now.
    try killed.expectSays("\"authority\": \"held\"");
    try killed.expectSays("\"authorityError\": null");
    try killed.expectSays("\"leaseRelease\": \"left_held\"");
    // Prose, and present. A code with no sentence beside it leaves an operator a
    // word and nothing to do about it.
    try killed.expectSaysNot("\"leaseReleaseError\": null");
    try killed.expectSays("will block further changes to that scope until its TTL lapses");

    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    {
        var store = try f.open();
        defer store.close();
        // The act really did complete, which is what makes exit 0 honest: the
        // ledger holds the outcome and the row carries it.
        const op = (try Store.operations.get(&store, arena, request_id)).?;
        try t.expectEqualStrings("completed", op.status.text());
        const row = (try Store.jobs.getByName(&store, arena, 1, "deploy")).?;
        try t.expectEqualStrings("exited", @tagName(row.status));
    }
    try expectScopeStillHeld(&f, arena);

    // And the consequence the report exists to warn about, performed. The next
    // command on this job is refused — before it dials, so the fake host sees
    // nothing new — which is exactly what a caller that read `ok: true` and
    // retried would have walked into with no explanation.
    var again = try runWithEnvironment(&f, &.{
        "job", "kill", "box", "deploy", "--json", "--db", f.db,
    }, &environ);
    defer again.deinit(f.allocator);
    try host.expectFullyScripted();
    try again.expectCode(1);
    try again.expectSays("holds a lease on an overlapping scope");
}

test "blackbox: a `job rm` that could not give the scope back keeps the row and names the leak" {
    const t = std.testing;
    var f = try Fixture.init(t.allocator, "rm_lease_left_held");
    defer f.deinit();
    try f.seedServer();
    const request_id = "01RRRRRRRR0123456789ABCDEF";
    try seedRunningJob(&f, request_id, "deploy", kill_branch_sentinel);

    // A job still running: no result record, no sentinel. So nothing here can
    // settle an outcome, and the removal's own steps are the whole story.
    const running = "\n" ++ probe_split ++ "\n20\nstill working\n";
    var rules = [_]FakeHost.Rule{
        // The look before the kill.
        .{ .needle = probe_split, .stdout = running, .uses = 1 },
        // Before `has-session`, as ever.
        .{ .needle = "kill-session", .exit_code = 0 },
        // The look after it — the last remote call `job rm` makes — and where the
        // strand rides. Unlike the kill gate above, the renewal that decides
        // whether the row may be deleted comes *after* this call, so it is refused
        // by the same contradiction: `authority` is `unreadable` and the row is
        // kept. That is the honest pair, and it is the shape of this verb rather
        // than a weaker fixture: there is no round trip between `job rm`'s last
        // renewal and its commit for a strand to land in.
        .{ .needle = probe_split, .stdout = running, .strand = true },
        .{ .needle = "has-session", .exit_code = 0 },
    };
    var host = try FakeHost.start(&f, &rules);
    defer host.stop();
    var environ = try host.environment();
    defer environ.deinit();

    var removed = try runWithEnvironment(&f, &.{
        "job", "rm", "box", "deploy", "--json", "--db", f.db,
    }, &environ);
    defer removed.deinit(f.allocator);

    try host.expectStranded();
    // The session was stopped — that much happened and the report must not deny
    // it — and nothing was deleted after it.
    try host.expectSent("kill-session");
    try host.expectNeverSent("rm -f");
    try host.expectFullyScripted();

    // Exit 1: the row survived and nothing remote is unknown because of it, so a
    // retry once the scope frees is safe. Not 75 — and not 0, which is what this
    // path reported before the renewal answered anything.
    try removed.expectCode(1);
    try removed.expectSays("\"ok\": false");
    try removed.expectSays("\"action\": \"not_removed\"");
    try removed.expectSays("\"rowRemoved\": false");
    try removed.expectSays("\"evidenceRetained\": true");
    try removed.expectSays("\"authority\": \"unreadable\"");
    try removed.expectSays("\"leaseRelease\": \"left_held\"");
    try removed.expectSaysNot("\"leaseReleaseError\": null");

    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    {
        var store = try f.open();
        defer store.close();
        // The row is the assertion: a removal that could not re-establish its
        // standing does not get to forget the name.
        try t.expect((try Store.jobs.getByName(&store, arena, 1, "deploy")) != null);
        const op = (try Store.operations.get(&store, arena, request_id)).?;
        try t.expectEqualStrings("indeterminate", op.status.text());
    }
    try expectScopeStillHeld(&f, arena);

    // …and the barrier is real here too. The row is still there, so this refusal
    // is the operator's next experience of the job, and `left_held` in the
    // document above is the only warning they were given.
    var again = try runWithEnvironment(&f, &.{
        "job", "rm", "box", "deploy", "--json", "--db", f.db,
    }, &environ);
    defer again.deinit(f.allocator);
    try host.expectFullyScripted();
    try again.expectCode(1);
    try again.expectSays("holds a lease on an overlapping scope");
}

// --- `session rm`: the destructive verb that had no authority at all --------
//
// `docs/m3b-job-control.md` §1.2. Until now this command killed a remote
// session, deleted its pane log and dropped the local row — cascading that
// session's memories — with no lease, no operation and no scope guard. The five
// gates below are the four questions §2.1 asks, driven through the real binary
// and asserted from the store and from the host's own traffic rather than from
// stdout.
//
// The traffic assertions come *first* in every one of them, before any exit
// code. A refusal exits non-zero and so does a dozen other faults — a missing
// rule among them — so only "no command containing `kill-session` reached the
// host" says the destructive step did not happen, and a gate that reported the
// number instead would name the wrong thing when it regressed.

/// A local metadata row for a session, as `session new` leaves one behind.
fn seedSessionRow(f: *Fixture, name: []const u8) !void {
    var store = try f.open();
    defer store.close();
    _ = try Store.sessions.ensure(&store, 1, name, 1000);
}

/// A session row *and* a memory attached to it.
///
/// The memory is the destruction no remote command can undo: `sessions.remove`
/// cascades it (`ON DELETE CASCADE` on `memories.session_id`), so a gate asserting
/// that a refused removal "kept the local row" has not asserted the thing that
/// matters until it counts the memories too. Returns the session id so a gate can
/// ask about the scope directly rather than by name.
fn seedSessionWithMemory(f: *Fixture, name: []const u8, content: []const u8) !i64 {
    var store = try f.open();
    defer store.close();
    const session_id = try Store.sessions.ensure(&store, 1, name, 1000);
    _ = try Store.memories.add(
        &store,
        .{ .server_id = 1, .session_id = session_id },
        .{ .key = "note", .content = content, .now = 1000 },
    );
    return session_id;
}

/// How many memories are attached to this session id.
fn sessionMemoryCount(store: *Store, arena: std.mem.Allocator, session_id: i64) !usize {
    const rows = try Store.memories.list(
        store,
        arena,
        .{ .server_id = 1, .session_id = session_id },
        .{},
    );
    var mine: usize = 0;
    for (rows) |row| if (row.scope == .session) {
        mine += 1;
    };
    return mine;
}

/// A peer's live claim on a scope, taken before the binary runs.
fn seedPeerLease(f: *Fixture, scope_key: []const u8, owner: []const u8) !void {
    var store = try f.open();
    defer store.close();
    var arena_state = std.heap.ArenaAllocator.init(f.allocator);
    defer arena_state.deinit();
    switch (try Store.leases.acquire(&store, arena_state.allocator(), .{
        .server_id = 1,
        .scope = .{ .kind = .job, .key = scope_key },
        .owner_request_id = owner,
        .profile_token = "the-other-session",
        .owner_label = scope_key,
        .ttl_secs = 600,
        .now = try Store.leases.clockSeconds(&store),
    })) {
        .acquired => {},
        .renewed, .conflict => return error.PeerLeaseDidNotTake,
    }
}

/// The terminal receipt's `error_code`, or null when nothing terminal was
/// written. Named rather than unwrapped: "no terminal at all" and "a terminal
/// with no code" are different findings, and a null unwrap ends the process so
/// every gate after it stops running too.
fn terminalErrorCode(
    store: *Store,
    arena: std.mem.Allocator,
    request_id: []const u8,
) !?[]const u8 {
    const rows = try Store.receipts.list(store, arena, request_id);
    for (rows) |row| if (row.is_terminal) return row.error_code orelse "";
    return null;
}

/// The terminal receipt's `detail_json`, same shape and same reasoning.
///
/// `session rm` settles two different partial shapes through one terminal variant
/// — `remote_cancel_confirmed`, whose whole claim is a verified absence — so what
/// tells a completed removal from one that stopped after the kill is the document
/// beside it. Read out of the store, not out of stdout: the ledger is what
/// survives the process.
fn terminalDetailJson(
    store: *Store,
    arena: std.mem.Allocator,
    request_id: []const u8,
) !?[]const u8 {
    const rows = try Store.receipts.list(store, arena, request_id);
    for (rows) |row| if (row.is_terminal) return row.detail_json;
    return null;
}

/// One substring, with the haystack printed when it is missing.
fn expectContains(hay: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, hay, needle) != null) return;
    std.debug.print("\nmissing \"{s}\" in:\n{s}\n", .{ needle, hay });
    return error.TextMissing;
}

// The discriminating control, and it is not decoration: every other gate here
// asserts an *absence*, and an absence is also what a binary that refused every
// removal unconditionally would produce. This one insists the same fixture still
// kills, still deletes, still exits 0 — and, the half that is new, that the act
// is now in the ledger.
test "blackbox: an uncontended `session rm` still removes, and now records a control operation" {
    const t = std.testing;
    var f = try Fixture.init(t.allocator, "session_rm_ok");
    defer f.deinit();
    try f.seedServer();
    try seedSessionRow(&f, "shell");

    var rules = [_]FakeHost.Rule{
        // `killSession`'s script carries both words, so the kill rule has to be
        // listed ahead of anything matching `has-session`.
        .{ .needle = "kill-session", .exit_code = 0 },
        .{ .needle = "rm -f", .exit_code = 0 },
    };
    var host = try FakeHost.start(&f, &rules);
    defer host.stop();
    var environ = try host.environment();
    defer environ.deinit();

    var removed = try runWithEnvironment(&f, &.{
        "session", "rm", "box", "shell", "--json", "--db", f.db,
    }, &environ);
    defer removed.deinit(f.allocator);

    // Both destructive steps really went out, in the order the proof requires:
    // the kill first, and the log only after it.
    try host.expectSent("kill-session");
    try host.expectSent("rm -f");
    try host.expectFullyScripted();
    try removed.expectCode(0);
    try removed.expectSays("\"action\": \"removed\"");
    try removed.expectSays("\"errorCode\": \"none\"");
    try removed.expectSays("\"sessionState\": \"gone\"");
    try removed.expectSays("\"logState\": \"deleted\"");
    try removed.expectSays("\"localRow\": \"removed\"");
    try removed.expectSays("\"authority\": \"held\"");
    try removed.expectSays("\"authorityError\": null");
    // The scope was handed back, and the document says so rather than leaving a
    // caller to infer it from the absence of a complaint on stderr.
    try removed.expectSays("\"leaseRelease\": \"released\"");
    try removed.expectSays("\"leaseReleaseError\": null");

    var store = try f.open();
    defer store.close();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // The ledger entry this verb never had. Found by the name it acted on, then
    // re-read by request id — because "queryable by request id" is the property,
    // and an alias is a convenience handle that names get reused under.
    const by_alias = (try Store.operations.latestByAlias(&store, arena, 1, "shell")) orelse
        return error.RemovalRecordedNoOperation;
    try t.expectEqualStrings("control", by_alias.kind);
    const op = (try Store.operations.get(&store, arena, by_alias.request_id)).?;

    // Settled, and settled as what was actually established: the host answered
    // that the session is gone. Not `completed` — no command of the caller's ran
    // and none was judged, and `terminalDescribesKind` refuses `exited` for this
    // kind so that no exit code can appear in the column an auditor reads first.
    try t.expectEqualStrings("cancelled", op.status.text());
    try t.expect(!op.status.blocksScope());
    const terminal = (try Store.receipts.terminalOf(&store, op.request_id)) orelse
        return error.RemovalLeftNoTerminalReceipt;
    try t.expectEqualStrings("cancelled", terminal.status.text());

    // The local row went with it, and the scope was handed back.
    try t.expectEqual(@as(?i64, null), try Store.sessions.idByName(&store, 1, "shell"));
    const held = try Store.leases.active(&store, arena, 1, try Store.leases.clockSeconds(&store));
    try t.expectEqual(@as(usize, 0), held.len);

    // The terminal says how far the removal got, in the one column that can carry
    // a fact `remote_cancel_confirmed` has no field for. Without it a completed
    // removal and one whose log deletion failed are the same `cancelled` row —
    // which is the ledger asserting a removal that did not happen.
    const detail = (try terminalDetailJson(&store, arena, op.request_id)) orelse
        return error.RemovalLeftNoTerminalDetail;
    try expectContains(detail, "\"logDeleted\":true");
    try expectContains(detail, "\"localRecordDropped\":true");
}

// Question 2 of §2.1, in its cheapest form: somebody else's claim is already on
// the scope when the command starts. `execution.begin` runs before the
// connection is opened, so this is refused without a socket ever being opened —
// the strongest form of "nothing was sent" available.
//
// **And the refusal is now recorded.** §8 says a `session rm` under a held claim
// "is refused and records the refusal", and it used to record nothing at all:
// `begin` returns `.blocked` having inserted no row, so the single most
// destructive verb in the tree left no trace of having been tried. Five questions
// had no answer — whether anybody tried, who, when, how often, what stopped them.
//
// The half that makes the record safe to write is asserted here too, because it
// is the half that could turn a fix into a trap: the row must not bar the next
// command. So the peer's lease is released and the same removal is run again, and
// it has to succeed. A refusal that blocked the scope it was refused by would be
// worse than no record.
test "blackbox: a `session rm` refused by a peer's claim is recorded and does not bar the next one" {
    const t = std.testing;
    var f = try Fixture.init(t.allocator, "session_rm_leased");
    defer f.deinit();
    try f.seedServer();
    try seedSessionRow(&f, "shell");
    const peer = "01QQQQQQQQ0123456789ABCDEF";
    try seedPeerLease(&f, "shell", peer);

    // Scripted anyway, so a regression that sent them is caught by
    // `expectNeverSent` naming the command rather than by the fake counting an
    // unscripted request.
    var rules = [_]FakeHost.Rule{
        .{ .needle = "kill-session", .exit_code = 0 },
        .{ .needle = "rm -f", .exit_code = 0 },
    };
    var host = try FakeHost.start(&f, &rules);
    defer host.stop();
    var environ = try host.environment();
    defer environ.deinit();

    var refused = try runWithEnvironment(&f, &.{
        "session", "rm", "box", "shell", "--json", "--db", f.db,
    }, &environ);
    defer refused.deinit(f.allocator);

    try host.expectNeverSent("kill-session");
    try host.expectNeverSent("rm -f");
    try refused.expectCode(1);
    try refused.expectSays(peer);
    try refused.expectSays("nothing was sent to the host");
    // The fixed key set, on the branch that used to emit `{ok, error}` and two
    // keys. A caller that hit this got no `requestId` at all, so it could neither
    // audit the attempt nor tell this refusal from any other failure.
    try refused.expectSays("\"errorCode\": \"SCOPE_HELD_BY_PEER\"");
    try refused.expectSays("\"sessionState\": \"not_attempted\"");
    try refused.expectSays("\"logState\": \"not_attempted\"");
    try refused.expectSays("\"localRow\": \"kept\"");
    try refused.expectSays("\"leaseRelease\": \"not_taken\"");

    {
        var store = try f.open();
        defer store.close();
        var arena_state = std.heap.ArenaAllocator.init(t.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        // The row is exactly where it was, and so are its memories.
        try t.expect((try Store.sessions.idByName(&store, 1, "shell")) != null);

        // The refusal is in the ledger, queryable by request id — the property,
        // as opposed to by alias, which is a convenience handle that names get
        // reused under.
        const by_alias = (try Store.operations.latestByAlias(&store, arena, 1, "shell")) orelse
            return error.RefusalRecordedNoOperation;
        try t.expectEqualStrings("control", by_alias.kind);
        const op = (try Store.operations.get(&store, arena, by_alias.request_id)).?;
        // Settled `cancelled` through `local_abandon` — "nothing had been handed
        // over, so there is nothing to stop", which is literally a refusal decided
        // before the connection opens. Not `never_submitted`, whose evidence is a
        // transport error: a peer's lease is not a transport failure.
        try t.expectEqualStrings("cancelled", op.status.text());
        try t.expect(op.status.isTerminal());

        // **The half that could have made this a trap.** Both barriers say the
        // recorded refusal does not bar anything: `blocksScope` is false for it,
        // and the guard's own query does not return it for the scope it was
        // refused on.
        try t.expect(!op.status.blocksScope());
        const barring = try Store.operations.unsettledInScope(
            &store,
            arena,
            1,
            .{ .kind = .job, .key = "shell" },
        );
        for (barring) |blocking| {
            if (std.mem.eql(u8, blocking.request_id, op.request_id))
                return error.RefusalBarsTheNextCommand;
        }

        // The peer's claim was neither displaced nor handed back on the way out: a
        // release matching by scope alone would unlock the winner's work on the
        // loser's exit.
        const held = try Store.leases.active(&store, arena, 1, try Store.leases.clockSeconds(&store));
        try t.expectEqual(@as(usize, 1), held.len);
        try t.expectEqualStrings(peer, held[0].owner_request_id);

        // Now hand the scope back, as the peer finishing would.
        try t.expect(try Store.leases.release(
            &store,
            1,
            .{ .kind = .job, .key = "shell" },
            peer,
            .released,
            try Store.leases.clockSeconds(&store),
        ));
    }

    // The discriminating control, and the assertion the recorded refusal exists
    // to be safe for: with nothing else claiming the scope, the very next removal
    // of the same session goes through.
    var second = try runWithEnvironment(&f, &.{
        "session", "rm", "box", "shell", "--json", "--db", f.db,
    }, &environ);
    defer second.deinit(f.allocator);

    try host.expectSent("kill-session");
    try host.expectSent("rm -f");
    try host.expectFullyScripted();
    try second.expectCode(0);
    try second.expectSays("\"action\": \"removed\"");
    try second.expectSays("\"localRow\": \"removed\"");

    var store = try f.open();
    defer store.close();
    try t.expectEqual(@as(?i64, null), try Store.sessions.idByName(&store, 1, "shell"));
}

// The scope moves *after* this command took it and *before* its first
// destructive call — the window the fail-closed renewal above the kill exists
// for. `session rm` has nothing to probe, so `kill-session` is its first remote
// command and no `Rule.seize` can land ahead of it; the seizure therefore rides
// the daemon version handshake, which is the one round trip between the claim
// and the kill. See `FakeHost.seize_on_ping`.
test "blackbox: `session rm` sends nothing once the scope has moved before the kill" {
    const t = std.testing;
    var f = try Fixture.init(t.allocator, "session_rm_moved_before");
    defer f.deinit();
    try f.seedServer();
    // Named for the scope the fake host's peer takes, so the seizure lands on
    // this command's own claim.
    try seedSessionRow(&f, FakeHost.seized_job);

    var rules = [_]FakeHost.Rule{
        .{ .needle = "kill-session", .exit_code = 0 },
        .{ .needle = "rm -f", .exit_code = 0 },
    };
    var host = try FakeHost.startSeizingOnHandshake(&f, &rules);
    defer host.stop();
    var environ = try host.environment();
    defer environ.deinit();

    var refused = try runWithEnvironment(&f, &.{
        "session", "rm", "box", FakeHost.seized_job, "--json", "--db", f.db,
    }, &environ);
    defer refused.deinit(f.allocator);

    // The window really opened, and then nothing destructive crossed it.
    try host.expectSeized();
    try host.expectNeverSent("kill-session");
    try host.expectNeverSent("rm -f");
    try host.expectFullyScripted();
    // Exit 1 and not 75: this command changed nothing, so nothing about the
    // remote is unknown *because of it*, and re-running once the scope is free
    // is safe. That distinction is the whole contract of the two codes.
    try refused.expectCode(1);
    try refused.expectSays("\"action\": \"not_removed\"");
    try refused.expectSays("\"errorCode\": \"AUTHORITY_LOST_BEFORE_KILL\"");
    try refused.expectSays("\"authority\": \"lapsed\"");
    try refused.expectSays("\"sessionState\": \"not_attempted\"");
    try refused.expectSays("\"logState\": \"not_attempted\"");
    try refused.expectSays("\"localRow\": \"kept\"");
    // The lease was taken by the peer, so there was nothing of ours to give back.
    // Reported as its own word: "not ours to release" is not "released", and a
    // caller that could not tell them apart could not tell a clean hand-back from
    // a displaced claim.
    try refused.expectSays("\"leaseRelease\": \"not_ours\"");

    var store = try f.open();
    defer store.close();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try t.expect((try Store.sessions.idByName(&store, 1, FakeHost.seized_job)) != null);

    // Settled `failed`, and that word is earned rather than convenient: the
    // renewal sits before `submitted`, so the attempt is still at `connecting`
    // when the loss is found and `never_submitted` — "the command the caller
    // asked for did not run" — is admissible. Had the renewal been on the far
    // side of `submitted`, the only terminal left would have been
    // `indeterminate`, which would have gone on blocking the scope over a kill
    // that was never sent.
    const op = (try Store.operations.latestByAlias(&store, arena, 1, FakeHost.seized_job)) orelse
        return error.RefusalRecordedNoOperation;
    try t.expectEqualStrings("control", op.kind);
    try t.expectEqualStrings("failed", op.status.text());
    try t.expect(!op.status.blocksScope());

    // And the peer still holds the scope.
    const held = try Store.leases.active(&store, arena, 1, try Store.leases.clockSeconds(&store));
    try t.expectEqual(@as(usize, 1), held.len);
    try t.expectEqualStrings(FakeHost.seizing_peer, held[0].owner_request_id);
}

// The other half of the rule: the scope goes while the kill is in flight, so the
// loss is only discoverable after a remote mutation has already happened.
//
// Nothing can undo the kill. What can still be refused is everything after it —
// the pane log, and the local row whose delete cascades this session's memories
// — and both are. The operation settles `indeterminate` carrying
// `AUTHORITY_LOST` rather than the proven cancellation it set out to write:
// `has-session` really did report the session absent, but the peer holding the
// lease has been free to create a session under that name ever since, so "it is
// gone" stopped being this command's to assert.
test "blackbox: `session rm` deletes nothing once the scope has moved after the kill" {
    const t = std.testing;
    var f = try Fixture.init(t.allocator, "session_rm_moved_after");
    defer f.deinit();
    try f.seedServer();
    try seedSessionRow(&f, FakeHost.seized_job);

    var rules = [_]FakeHost.Rule{
        // The kill goes out under a lease this command still holds — and comes
        // back after the scope has changed hands.
        .{ .needle = "kill-session", .exit_code = 0, .uses = 1, .seize = true },
        .{ .needle = "kill-session", .exit_code = 0 },
        .{ .needle = "rm -f", .exit_code = 0 },
    };
    var host = try FakeHost.start(&f, &rules);
    defer host.stop();
    var environ = try host.environment();
    defer environ.deinit();

    var refused = try runWithEnvironment(&f, &.{
        "session", "rm", "box", FakeHost.seized_job, "--json", "--db", f.db,
    }, &environ);
    defer refused.deinit(f.allocator);

    try host.expectSeized();
    // The kill happened; the deletion did not.
    try host.expectSent("kill-session");
    try host.expectNeverSent("rm -f");
    try host.expectFullyScripted();
    try refused.expectCode(1);
    try refused.expectSays("\"action\": \"not_removed\"");
    try refused.expectSays("\"errorCode\": \"AUTHORITY_LOST\"");
    try refused.expectSays("\"authority\": \"lapsed\"");
    try refused.expectSays("\"sessionState\": \"gone\"");
    try refused.expectSays("\"logState\": \"not_attempted\"");
    try refused.expectSays("\"localRow\": \"kept\"");

    var store = try f.open();
    defer store.close();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // The local half of "forbid the deletion": the row, and with it this
    // session's memories, are still there.
    try t.expect((try Store.sessions.idByName(&store, 1, FakeHost.seized_job)) != null);

    const op = (try Store.operations.latestByAlias(&store, arena, 1, FakeHost.seized_job)) orelse
        return error.RefusalRecordedNoOperation;
    try t.expectEqualStrings("control", op.kind);
    try t.expectEqualStrings("indeterminate", op.status.text());
    // …and the receipt names why, in the code an auditor reads. Without it this
    // is indistinguishable from every other way a removal ends unknown.
    const code = (try terminalErrorCode(&store, arena, op.request_id)) orelse
        return error.RemovalLeftNoTerminalReceipt;
    try t.expectEqualStrings("AUTHORITY_LOST", code);
}

// **The window F1 was about.** The scope survives the kill and goes during the
// *log deletion's* round trip, so the last thing in front of the command is the
// local row — and deleting that row cascades this session's memories away, which
// is the one destruction here that no remote command can be re-run to undo.
//
// It used to be caught by a third `stillOurs` and then acted on anyway: the
// renewal answered, `execution.settle` ran a whole transaction of its own, and
// `sessions.remove` ran after that. A takeover landing anywhere inside those two
// steps was never re-checked. Now the ownership question, the terminal and the
// delete are one `BEGIN IMMEDIATE` — so a peer's claim taken at any point before
// the commit is seen by the check inside it, and all three roll back together.
//
// What that costs is one word in the report: `authority` stays `held`, because the
// renewals were asked and answered truthfully, and the refusal is named by
// `SCOPE_TAKEN_BEFORE_COMMIT` instead. The two are worth telling apart — one says
// a renewal found the scope gone, the other says every renewal held and the atomic
// re-validation is what refused.
test "blackbox: `session rm` keeps the local row and its memories when the scope moves before the commit" {
    const t = std.testing;
    var f = try Fixture.init(t.allocator, "session_rm_moved_at_log");
    defer f.deinit();
    try f.seedServer();
    const session_id = try seedSessionWithMemory(&f, FakeHost.seized_job, "the deploy runbook");

    var rules = [_]FakeHost.Rule{
        .{ .needle = "kill-session", .exit_code = 0 },
        // The log deletion goes out under a lease this command still holds, and
        // comes back after the scope has changed hands.
        .{ .needle = "rm -f", .exit_code = 0, .uses = 1, .seize = true },
        .{ .needle = "rm -f", .exit_code = 0 },
    };
    var host = try FakeHost.start(&f, &rules);
    defer host.stop();
    var environ = try host.environment();
    defer environ.deinit();

    var refused = try runWithEnvironment(&f, &.{
        "session", "rm", "box", FakeHost.seized_job, "--json", "--db", f.db,
    }, &environ);
    defer refused.deinit(f.allocator);

    try host.expectSeized();
    // Both remote steps happened — this is not the "nothing was sent" case, and
    // the report must not read like it.
    try host.expectSent("kill-session");
    try host.expectSent("rm -f");
    try host.expectFullyScripted();
    try refused.expectCode(1);
    try refused.expectSays("\"action\": \"not_removed\"");
    try refused.expectSays("\"errorCode\": \"SCOPE_TAKEN_BEFORE_COMMIT\"");
    try refused.expectSays("\"sessionState\": \"gone\"");
    try refused.expectSays("\"logState\": \"deleted\"");
    try refused.expectSays("\"localRow\": \"kept\"");
    // The renewals all held; what refused is the check inside the transaction.
    try refused.expectSays("\"authority\": \"held\"");

    var store = try f.open();
    defer store.close();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // The row, and — the assertion this gate exists for — this session's memories
    // with it. A rollback that took the terminal back but let the delete stand
    // would satisfy every string assertion above.
    try t.expectEqual(@as(?i64, session_id), try Store.sessions.idByName(&store, 1, FakeHost.seized_job));
    try t.expectEqual(@as(usize, 1), try sessionMemoryCount(&store, arena, session_id));

    const op = (try Store.operations.latestByAlias(&store, arena, 1, FakeHost.seized_job)) orelse
        return error.RefusalRecordedNoOperation;
    try t.expectEqualStrings("indeterminate", op.status.text());
    const failure_code = (try terminalErrorCode(&store, arena, op.request_id)) orelse
        return error.RemovalLeftNoTerminalReceipt;
    try t.expectEqualStrings("SCOPE_TAKEN_BEFORE_COMMIT", failure_code);
    // And **not** the proven cancellation the command was about to write. That
    // terminal is the one F2 forbids here: it would have said the removal
    // happened, in the column an auditor reads first, over a row that is still on
    // disk.
    const detail = try terminalDetailJson(&store, arena, op.request_id);
    if (detail) |text| {
        if (std.mem.indexOf(u8, text, "session_stopped") != null)
            return error.RefusalClaimedACompletedRemoval;
    }
}

// The oldest rule in this verb, now that it has a ledger to record itself in:
// the kill is *proven* before anything is deleted. A local row dropped for a
// session still on the host orphans it — invisible to `session ls`'s local half,
// while `Tmux.ensure` treats the surviving session as ready — so the next
// command under that name lands in the shell this one claimed to have removed.
//
// The settlement is the new half. `remote_cancel_confirmed` is the one thing
// this outcome may not claim, and there is no proven-failure terminal for a
// control act after submission, so it records `indeterminate` — and says which
// unknown it is, in the code beside it.
test "blackbox: `session rm` deletes nothing when the session survives the kill" {
    const t = std.testing;
    var f = try Fixture.init(t.allocator, "session_rm_survived");
    defer f.deinit();
    try f.seedServer();
    try seedSessionRow(&f, "shell");

    var rules = [_]FakeHost.Rule{
        // `killSession`'s script exits 1 when `has-session` still finds it: the
        // host was asked, and answered that the session is still there.
        .{ .needle = "kill-session", .exit_code = 1 },
        .{ .needle = "rm -f", .exit_code = 0 },
    };
    var host = try FakeHost.start(&f, &rules);
    defer host.stop();
    var environ = try host.environment();
    defer environ.deinit();

    var refused = try runWithEnvironment(&f, &.{
        "session", "rm", "box", "shell", "--json", "--db", f.db,
    }, &environ);
    defer refused.deinit(f.allocator);

    // The kill was sent — this is not a refusal that withheld it — and the log
    // deletion was not.
    try host.expectSent("kill-session");
    try host.expectNeverSent("rm -f");
    try host.expectFullyScripted();
    // 75, not 1: the record now blocks this session's scope until it is
    // reconciled, so "plain failure, retry" would send a caller into a refusal.
    try refused.expectCode(75);
    try refused.expectSays("\"action\": \"not_removed\"");
    try refused.expectSays("\"errorCode\": \"SESSION_SURVIVED_KILL\"");
    try refused.expectSays("\"sessionState\": \"present\"");
    try refused.expectSays("\"logState\": \"not_attempted\"");
    try refused.expectSays("\"localRow\": \"kept\"");
    // The lease was never lost on this path; what stopped the command is the
    // host's answer, and the report must not blame the wrong barrier.
    try refused.expectSays("\"authority\": \"held\"");
    try refused.expectSays("\"leaseRelease\": \"released\"");

    var store = try f.open();
    defer store.close();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Neither the row nor its memories went anywhere.
    try t.expect((try Store.sessions.idByName(&store, 1, "shell")) != null);

    const op = (try Store.operations.latestByAlias(&store, arena, 1, "shell")) orelse
        return error.RefusalRecordedNoOperation;
    try t.expectEqualStrings("control", op.kind);
    try t.expectEqualStrings("indeterminate", op.status.text());
    // Its own code, so this is distinguishable from a lost lease — the two send
    // an operator to completely different places.
    const code = (try terminalErrorCode(&store, arena, op.request_id)) orelse
        return error.RemovalLeftNoTerminalReceipt;
    try t.expectEqualStrings("SESSION_SURVIVED_KILL", code);

    // And the scope was handed back even though the act failed: a claim held by
    // a process that has exited would lock the operator out for its whole TTL.
    const held = try Store.leases.active(&store, arena, 1, try Store.leases.clockSeconds(&store));
    try t.expectEqual(@as(usize, 0), held.len);
}

// **The gate this whole slice exists for** (§1.2). A job's tmux session is
// `job-<name>`, and `Tmux.list` strips the `t-` prefix, so a running job shows
// up in `session ls` as `job-deploy`. `session rm box job-deploy` is aimed at
// exactly the shell `job kill box deploy` is aimed at — and it used to take no
// lease, contend with nothing and write nothing, so it killed the job outright
// while the job's own barrier never saw it.
//
// It now contends. The job holds an unsettled writer on `.job:"deploy"`, the
// removal's contention key is the logical thing that session belongs to, and the
// two overlap — so the refusal happens before a socket is opened.
test "blackbox: `session rm` on a running job's session is refused and leaves the job intact" {
    const t = std.testing;
    var f = try Fixture.init(t.allocator, "session_rm_running_job");
    defer f.deinit();
    try f.seedServer();

    const request_id = "01JJJJJJJJ0123456789ABCDEF";
    const sentinel = "__TERMINUS_JOB_7__";
    try seedRunningJob(&f, request_id, "deploy", sentinel);

    var rules = [_]FakeHost.Rule{
        .{ .needle = "kill-session", .exit_code = 0 },
        .{ .needle = "rm -f", .exit_code = 0 },
    };
    var host = try FakeHost.start(&f, &rules);
    defer host.stop();
    var environ = try host.environment();
    defer environ.deinit();

    var refused = try runWithEnvironment(&f, &.{
        "session", "rm", "box", "job-deploy", "--json", "--db", f.db,
    }, &environ);
    defer refused.deinit(f.allocator);

    // The kill named first, and before the exit code: a regression here is "a
    // running job's shell was killed", not "the number was 0".
    try host.expectNeverSent("kill-session");
    // The job's pane log is the other thing `session rm` destroys, and it is the
    // record `reconcile --from-log` settles the job from.
    try host.expectNeverSent("rm -f");
    try host.expectFullyScripted();
    try refused.expectCode(1);
    try refused.expectSays(request_id);
    try refused.expectSays("nothing was sent to the host");
    try refused.expectSays("\"errorCode\": \"SCOPE_HELD_BY_PEER\"");

    var store = try f.open();
    defer store.close();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // The job's own row survived, still running.
    const row = (try Store.jobs.getByName(&store, arena, 1, "deploy")).?;
    try t.expectEqualStrings("running", @tagName(row.status));
    // …and so did its attempt: nothing settled it, and nothing here may. A
    // refusal that wrote onto the *target's* ledger would be the two-subjects
    // defect of §1.1, one verb over.
    const job_op = (try Store.operations.get(&store, arena, request_id)).?;
    try t.expectEqualStrings("remote_started", job_op.status.text());

    // The refusal has a row of its own, settled, and it is *not* the job's. Two
    // subjects, two operations — which is the whole shape §3.4 asks for.
    const refusal = (try Store.operations.latestByAlias(&store, arena, 1, "job-deploy")) orelse
        return error.RefusalRecordedNoOperation;
    try t.expectEqualStrings("control", refusal.kind);
    try t.expectEqualStrings("cancelled", refusal.status.text());
    try t.expect(!std.mem.eql(u8, refusal.request_id, request_id));
    // And it does not join the job in barring the scope: the job's `.job:"deploy"`
    // writer is the one blocker there, before and after.
    const barring = try Store.operations.unsettledInScope(
        &store,
        arena,
        1,
        .{ .kind = .job, .key = "deploy" },
    );
    try t.expectEqual(@as(usize, 1), barring.len);
    try t.expectEqualStrings(request_id, barring[0].request_id);
}

// The log deletion fails after the kill has landed and been proven. The session
// is gone, its pane log is still on the host with nothing left to recreate it, and
// this machine still holds the session's metadata row and its memories.
//
// This path used to settle the proven cancellation and then `fatal`, so a caller
// received `{ok:false, error:"..."}` — no request id, no `logState`, no
// `localRow` — and had to read English to learn that a shell had been stopped
// under it. Worse, the ledger's `cancelled` row was byte-identical to a completed
// removal's, so an auditor reading the status column could not tell that a log had
// been orphaned and a row left behind.
//
// **The terminal is still `remote_cancel_confirmed`, and that is the decision.**
// What the variant claims is a verified absence of the session, which is exactly
// what the host answered before this step was reached; a later deletion failing
// does not make an earlier reading unknown. Settling `indeterminate` instead would
// record a proof as an unknown *and* bar the scope, forcing a `request reconcile`
// before the re-run that would actually finish the job. What stops `cancelled`
// from reading as a completed removal is the document beside it.
test "blackbox: a `session rm` whose log deletion fails reports the partial and settles it honestly" {
    const t = std.testing;
    var f = try Fixture.init(t.allocator, "session_rm_log_failed");
    defer f.deinit();
    try f.seedServer();
    const session_id = try seedSessionWithMemory(&f, "shell", "the shell runbook");

    var rules = [_]FakeHost.Rule{
        .{ .needle = "kill-session", .exit_code = 0 },
        // The host refuses the deletion. `Tmux.removeLog` raises rather than
        // returning a bool, so this is the transport-shaped failure of that step.
        .{ .needle = "rm -f", .exit_code = 1 },
    };
    var host = try FakeHost.start(&f, &rules);
    defer host.stop();
    var environ = try host.environment();
    defer environ.deinit();

    var partial = try runWithEnvironment(&f, &.{
        "session", "rm", "box", "shell", "--json", "--db", f.db,
    }, &environ);
    defer partial.deinit(f.allocator);

    try host.expectSent("kill-session");
    try host.expectSent("rm -f");
    try host.expectFullyScripted();
    // Exit 1 and not 75: the record is settled, so the scope is free and this
    // command can simply be run again to finish. 75 would send a caller to
    // `request reconcile` for a state that needs no adjudication.
    try partial.expectCode(1);
    try partial.expectSays("\"action\": \"not_removed\"");
    try partial.expectSays("\"errorCode\": \"LOG_DELETE_FAILED\"");
    try partial.expectSays("\"sessionState\": \"gone\"");
    // The member a bool could not express. `not_attempted` here would say the step
    // was never reached, and an operator would not go looking for the orphan.
    try partial.expectSays("\"logState\": \"delete_failed\"");
    try partial.expectSays("\"localRow\": \"kept\"");
    try partial.expectSays("\"leaseRelease\": \"released\"");

    var store = try f.open();
    defer store.close();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Nothing local was destroyed, memories included.
    try t.expectEqual(@as(?i64, session_id), try Store.sessions.idByName(&store, 1, "shell"));
    try t.expectEqual(@as(usize, 1), try sessionMemoryCount(&store, arena, session_id));

    const op = (try Store.operations.latestByAlias(&store, arena, 1, "shell")) orelse
        return error.RemovalRecordedNoOperation;
    try t.expectEqualStrings("cancelled", op.status.text());
    // The scope is free, which is the point of not recording this as an unknown.
    try t.expect(!op.status.blocksScope());
    const held = try Store.leases.active(&store, arena, 1, try Store.leases.clockSeconds(&store));
    try t.expectEqual(@as(usize, 0), held.len);

    // And the ledger can tell this apart from a completed removal — the half that
    // makes `cancelled` admissible here at all.
    const detail = (try terminalDetailJson(&store, arena, op.request_id)) orelse
        return error.RemovalLeftNoTerminalDetail;
    try expectContains(detail, "\"logDeleted\":false");
    try expectContains(detail, "\"localRecordDropped\":false");
}

// --- The fixed key set, held against the document the binary actually emits ---
//
// `cmd_session.zig` holds `RemovalJson` against `skill/SKILL.md` at compile time,
// which proves the struct and the document agree. It cannot prove that a *branch*
// emits the struct: the hard-failure paths below reached shared helpers that emit
// `{ok, error}`, and compiled perfectly well doing it. So this reads the emitted
// document.
//
// It counts as well as names. The names catch a key that was renamed or dropped;
// the count catches one that was added — a check that only looked for sixteen
// literals it already knew would pass over a seventeenth nobody documented.
// `RemovalJson` is flat and `Output.json` indents by two, so every top-level key
// and only a top-level key appears as a newline, two spaces and a quote.
const removal_keys = [_][]const u8{
    "\n  \"ok\":",
    "\n  \"action\":",
    "\n  \"errorCode\":",
    "\n  \"session\":",
    "\n  \"server\":",
    "\n  \"requestId\":",
    "\n  \"status\":",
    "\n  \"sessionState\":",
    "\n  \"logState\":",
    "\n  \"localRow\":",
    "\n  \"authority\":",
    "\n  \"authorityError\":",
    "\n  \"leaseRelease\":",
    "\n  \"leaseReleaseError\":",
    "\n  \"reason\":",
    "\n  \"hint\":",
};

fn expectFixedRemovalDocument(r: Run) !void {
    for (removal_keys) |needle| try r.expectSays(needle);
    const found = std.mem.count(u8, r.stdout, "\n  \"");
    std.testing.expectEqual(removal_keys.len, found) catch |err| {
        std.debug.print(
            "the document has {d} top-level keys, wanted {d}\n--- stdout ---\n{s}\n",
            .{ found, removal_keys.len, r.stdout },
        );
        return err;
    };
}

/// How many operation rows the ledger holds.
///
/// Counted rather than looked up by alias, because "this command wrote no row" is a
/// statement about the whole table: an earlier leg of the same gate may legitimately
/// have left one under the same alias, and `latestByAlias` would hand that back and
/// read as a success.
fn operationCount(store: *Store) !i64 {
    var stmt = try store.db.prepare("SELECT COUNT(*) FROM operations");
    defer stmt.deinit();
    if (!try stmt.step()) return error.CountReturnedNothing;
    return stmt.columnInt(0);
}

// The kill went out and nothing came back to say what it did.
//
// This used to leave the process exiting **1** through `fatalTmux` → `Cli.fail`
// with `{ok, error}` — two keys — while the exit hook settled the submitted
// operation `indeterminate`. The ledger said "unknown" and the exit status said
// "plain failure", and 1 is what an agent reads as *nothing happened, retry is
// safe*. On the one call in this verb that cannot be taken back, that is the worst
// thing the two could disagree about.
//
// Arranged with exit 41 from the kill script, which is its `command -v tmux` guard
// failing — a real answer this verb can get from a real host, and the one shape
// that reaches `killSession`'s error path deterministically. `fatalTmux` itself is
// untouched and still serves `session new`, `session ls`, `exec`, `job` and
// `read`/`write`.
//
// Two legs on one fixture and one host. Without the second, every assertion here
// would hold against a binary that had started refusing every kill.
test "blackbox: `session rm` reports 75 and the full document when the kill gets no answer" {
    const t = std.testing;
    var f = try Fixture.init(t.allocator, "session_rm_kill_unanswered");
    defer f.deinit();
    try f.seedServer();
    const session_id = try seedSessionWithMemory(&f, "shell", "the shell runbook");
    try seedSessionRow(&f, "other");

    var rules = [_]FakeHost.Rule{
        // Keyed on the target, because both legs' kill scripts carry
        // `kill-session` and this gate needs them answered differently.
        .{ .needle = "kill-session -t =t-shell", .exit_code = 41 },
        .{ .needle = "kill-session -t =t-other", .exit_code = 0 },
        .{ .needle = "rm -f", .exit_code = 0 },
    };
    var host = try FakeHost.start(&f, &rules);
    defer host.stop();
    var environ = try host.environment();
    defer environ.deinit();

    var blind = try runWithEnvironment(&f, &.{
        "session", "rm", "box", "shell", "--json", "--db", f.db,
    }, &environ);
    defer blind.deinit(f.allocator);

    // The kill really was sent — this is not a withheld one — and nothing after it
    // was. Named before the exit code, because the regression that matters is "it
    // deleted the log anyway", not "the number was wrong".
    try host.expectSent("kill-session -t =t-shell");
    try host.expectNeverSent("rm -f");
    // 75, not 1: the ledger holds `indeterminate` and that bars this session's
    // scope, so "plain failure, retry" would walk a caller into a refusal.
    try blind.expectCode(75);
    try expectFixedRemovalDocument(blind);
    try blind.expectSays("\"action\": \"not_removed\"");
    try blind.expectSays("\"errorCode\": \"KILL_UNANSWERED\"");
    // The word that had to exist. `present` would report something the host never
    // said; `not_attempted` would deny a command that was sent.
    try blind.expectSays("\"sessionState\": \"unknown\"");
    try blind.expectSays("\"logState\": \"not_attempted\"");
    try blind.expectSays("\"localRow\": \"kept\"");
    // The lease was never lost on this path, and the report must not blame the
    // wrong barrier.
    try blind.expectSays("\"authority\": \"held\"");
    try blind.expectSays("\"leaseRelease\": \"released\"");
    // The error name reaches the operator, which is the one thing `fatalTmux`'s
    // per-error sentences carried that a fixed key set must not lose.
    try blind.expectSays("TmuxMissing");

    {
        var store = try f.open();
        defer store.close();
        var arena_state = std.heap.ArenaAllocator.init(t.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        // Nothing local was destroyed, memories included.
        try t.expectEqual(@as(?i64, session_id), try Store.sessions.idByName(&store, 1, "shell"));
        try t.expectEqual(@as(usize, 1), try sessionMemoryCount(&store, arena, session_id));

        const op = (try Store.operations.latestByAlias(&store, arena, 1, "shell")) orelse
            return error.RemovalRecordedNoOperation;
        try t.expectEqualStrings("control", op.kind);
        try t.expectEqualStrings("indeterminate", op.status.text());
        // Its own code on the receipt, so this is distinguishable from a survived
        // kill and from a lost lease — three unknowns that send an operator to
        // three different places.
        const recorded = (try terminalErrorCode(&store, arena, op.request_id)) orelse
            return error.RemovalLeftNoTerminalReceipt;
        try t.expectEqualStrings("KILL_UNANSWERED", recorded);

        // And the scope was handed back even though the act failed: a claim held by
        // a process that has exited would lock the operator out for its whole TTL.
        const held = try Store.leases.active(&store, arena, 1, try Store.leases.clockSeconds(&store));
        try t.expectEqual(@as(usize, 0), held.len);
    }

    // The discriminating control: the same fixture, the same host, a session whose
    // kill is answered. It still removes, still deletes the log, still exits 0.
    var fine = try runWithEnvironment(&f, &.{
        "session", "rm", "box", "other", "--json", "--db", f.db,
    }, &environ);
    defer fine.deinit(f.allocator);

    try host.expectSent("kill-session -t =t-other");
    try host.expectSent("rm -f");
    try host.expectFullyScripted();
    try fine.expectCode(0);
    try fine.expectSays("\"action\": \"removed\"");
    try fine.expectSays("\"errorCode\": \"none\"");
    try fine.expectSays("\"sessionState\": \"gone\"");
}

// A ledger write this command needs, and cannot make.
//
// Two shapes, and until now neither emitted this verb's document. The first went
// through `Cli.receiptFatal`, whose envelope is `{ok, error, errorCode, requestId,
// cause, remoteStatus, hint}` and whose cleanup is the `void` `releaseClaim()` — so
// a caller learned nothing about the session, the log or its local row, and a
// `left_held` lease that will refuse its next command for 120s reached stderr and
// nowhere else. The second went through `Cli.storeFatal` → `Cli.fail`: `{ok,
// error}` and **exit 1**, on the one branch where the record *is* the whole act.
//
// Both are arranged with a trigger on `operations`, which is a real refusal from
// the real store rather than a seam: `BEFORE UPDATE` catches the transition to
// `connecting`, `BEFORE INSERT` catches the refusal row a blocked removal writes.
// `receiptFatal` and `storeFatal` are untouched and still serve every other verb.
test "blackbox: a `session rm` that cannot write to the ledger reports the full document and exits 76" {
    const t = std.testing;
    var f = try Fixture.init(t.allocator, "session_rm_ledger_unwritable");
    defer f.deinit();
    try f.seedServer();
    const session_id = try seedSessionWithMemory(&f, "shell", "the shell runbook");

    var rules = [_]FakeHost.Rule{
        .{ .needle = "kill-session", .exit_code = 0 },
        .{ .needle = "rm -f", .exit_code = 0 },
    };
    var host = try FakeHost.start(&f, &rules);
    defer host.stop();
    var environ = try host.environment();
    defer environ.deinit();

    // Leg one: the step that records this attempt dialling cannot be written. It
    // runs before the socket is opened, so nothing reaches the host — and the lease
    // has already been taken, which is what makes `leaseRelease` worth asserting.
    var before_leg_two: i64 = 0;
    {
        var store = try f.open();
        defer store.close();
        try store.db.exec(
            \\CREATE TRIGGER refuse_operation_update BEFORE UPDATE ON operations
            \\BEGIN SELECT RAISE(ABORT, 'the ledger cannot be advanced'); END
        );
    }

    var unwritable = try runWithEnvironment(&f, &.{
        "session", "rm", "box", "shell", "--json", "--db", f.db,
    }, &environ);
    defer unwritable.deinit(f.allocator);

    try host.expectNeverSent("kill-session");
    try host.expectNeverSent("rm -f");
    // 76, not 1 and not 75: a write we needed did not happen. `receiptFatal`
    // already exited 76 here; what it did not do is say what is on the host.
    try unwritable.expectCode(76);
    try expectFixedRemovalDocument(unwritable);
    try unwritable.expectSays("\"errorCode\": \"RECEIPT_PERSIST_FAILED\"");
    try unwritable.expectSays("\"sessionState\": \"not_attempted\"");
    try unwritable.expectSays("\"logState\": \"not_attempted\"");
    try unwritable.expectSays("\"localRow\": \"kept\"");
    // The half `receiptFatal` threw away: the claim was taken, and what became of
    // it is in the document rather than only on stderr.
    try unwritable.expectSays("\"leaseRelease\": \"released\"");

    {
        var store = try f.open();
        defer store.close();
        var arena_state = std.heap.ArenaAllocator.init(t.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        try t.expectEqual(@as(?i64, session_id), try Store.sessions.idByName(&store, 1, "shell"));
        try t.expectEqual(@as(usize, 1), try sessionMemoryCount(&store, arena, session_id));
        // Reported as released, and actually released. A document that said so over
        // a row still holding the scope would be the same defect one layer up.
        const held = try Store.leases.active(&store, arena, 1, try Store.leases.clockSeconds(&store));
        try t.expectEqual(@as(usize, 0), held.len);

        try store.db.exec("DROP TRIGGER refuse_operation_update");
        // Leg two's arrangement: a peer's claim, so `begin` refuses before it
        // inserts anything, and a trigger that stops the refusal's own row from
        // being written.
        try store.db.exec(
            \\CREATE TRIGGER refuse_operation_insert BEFORE INSERT ON operations
            \\BEGIN SELECT RAISE(ABORT, 'the ledger cannot be written'); END
        );
        before_leg_two = try operationCount(&store);
    }
    try seedPeerLease(&f, "shell", "01QQQQQQQQ0123456789ABCDEF");

    var unrecordable = try runWithEnvironment(&f, &.{
        "session", "rm", "box", "shell", "--json", "--db", f.db,
    }, &environ);
    defer unrecordable.deinit(f.allocator);

    try host.expectNeverSent("kill-session");
    try host.expectNeverSent("rm -f");
    // Exit 1 before this change: "nothing happened, a retry is safe" — true of the
    // host and false of the ledger, which is now missing the only trace that
    // anybody tried to destroy this session.
    try unrecordable.expectCode(76);
    try expectFixedRemovalDocument(unrecordable);
    try unrecordable.expectSays("\"errorCode\": \"RECEIPT_PERSIST_FAILED\"");
    // No row exists, so there is no ledger word to read — and the document says
    // that rather than borrowing one.
    try unrecordable.expectSays("\"status\": \"unknown\"");
    // Never acquired: `not_taken` and not `released`, because "nothing was taken"
    // and "what was taken was handed back" are different facts about the scope.
    try unrecordable.expectSays("\"leaseRelease\": \"not_taken\"");
    try unrecordable.expectSays("\"localRow\": \"kept\"");

    {
        var store = try f.open();
        defer store.close();
        // The refusal really left no row, which is what the report is admitting.
        // Counted, because leg one legitimately left a `created` row under this
        // same alias and a lookup by alias would hand that one back.
        try t.expectEqual(before_leg_two, try operationCount(&store));

        try store.db.exec("DROP TRIGGER refuse_operation_insert");
        // The peer lets go, so the control leg is not measuring the blocker.
        try t.expect(try Store.leases.release(
            &store,
            1,
            .{ .kind = .job, .key = "shell" },
            "01QQQQQQQQ0123456789ABCDEF",
            .released,
            try Store.leases.clockSeconds(&store),
        ));
    }

    // The discriminating control: the same fixture with a writable ledger removes,
    // exits 0 and reports `none`. Without it, everything above is satisfied by a
    // binary that had started answering 76 to every removal.
    var fine = try runWithEnvironment(&f, &.{
        "session", "rm", "box", "shell", "--json", "--db", f.db,
    }, &environ);
    defer fine.deinit(f.allocator);

    try host.expectSent("kill-session");
    try host.expectSent("rm -f");
    try host.expectFullyScripted();
    try fine.expectCode(0);
    try expectFixedRemovalDocument(fine);
    try fine.expectSays("\"errorCode\": \"none\"");
    try fine.expectSays("\"localRow\": \"removed\"");

    {
        var store = try f.open();
        defer store.close();
        try t.expectEqual(@as(?i64, null), try Store.sessions.idByName(&store, 1, "shell"));
    }
}
