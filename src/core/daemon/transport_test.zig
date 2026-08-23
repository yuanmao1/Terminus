//! The daemon transport, end to end: a real unix socket, the real client, the
//! real ledger.
//!
//! **What is driven, and what is not.** There is no live server — the test
//! host's key lives only inside a database these tests may not touch — so the
//! thing on the far side of the socket runs a *fixture* where `Ssh.execRetained`
//! would run a channel. Everything between that fixture and the settled receipt
//! is production code: `protocol.execResponse` builds the reply, `writeMessage`
//! frames it, the bytes cross an actual `AF_UNIX` connection, `DaemonClient`
//! reads and decodes them, `Executor` dispatches on the daemon arm, and
//! `execution.runCommand` settles the row.
//!
//! What that leaves reviewed rather than proven is `Server.handleConnection`'s
//! dispatch — the stub below mirrors one iteration of it — and `Server.runOn`'s
//! one-line choice between `Ssh.exec` and `Ssh.execRetained`.
//!
//! This is the file that answers the question the change exists for: a command
//! that succeeds with more output than the old frame could carry settles with
//! its own exit code, and not `indeterminate`.
//!
//! See `Stub` for why the serving thread cannot outlive the gate that spawned
//! it, and cannot wait on the gate's own thread either. Two earlier versions of
//! it could, and both hung the suite.
const std = @import("std");
const protocol = @import("protocol.zig");
const DaemonClient = @import("Client.zig");
const Server = @import("Server.zig");
const Ssh = @import("../ssh/Client.zig");
const Core = @import("../core.zig");
const Proc = @import("../proc.zig");
const Store = Core.Store;
const wireOutput = @import("protocol_test.zig").wireOutput;

const scratch_dir = ".zig-cache/tmp";

/// A daemon that answers from a fixture instead of a channel.
///
/// **One connection, one wait for input, one reply, and then gone.** Each of
/// those is load-bearing, and each replaces a way this hung.
///
/// The first version looped for a second request, and that turned a wire
/// disagreement into a suite that never returned: the reply's header announced
/// 72 bytes more than the frame carried, so the client waited for a remainder
/// while the stub waited for another request, and `thread.join` waited for both.
/// `zig build test` sat there for seven minutes and was killed. A test that can
/// hang costs every later run a timeout and hides whatever else is failing
/// behind itself.
///
/// Serving exactly one request was not enough either, and the mutation run
/// proved it rather than an argument: with the header deliberately overstating
/// its payload by one byte, the *stub's* `readFrame` waited for a byte after the
/// request's terminator while the client waited for the reply. Both peers
/// waiting is not something the test can defer its way out of — the gate's own
/// thread is one of them, so no teardown ever runs.
///
/// So the shape is now this, and none of it assumes anything about the bytes:
///
///   * **There is exactly one wait on input, and it is for the request's first
///     bytes.** `peekGreedy` blocks until eight bytes are buffered and then
///     hands back everything that arrived; the frame is parsed out of *that*,
///     through a `.fixed` reader that cannot block. No byte sequence — no
///     header, no truncation, no desync — can make this stub wait for a second
///     piece of input. A request that does not fit what arrived fails the parse,
///     which ends the connection and fails the gate. Fail, never wait.
///   * **There is exactly one write, and then the socket closes.** So the
///     client's own read is bounded by the stub's close, whatever the reply's
///     header claimed.
///   * **The accept is always released.** `release` opens one throwaway
///     connection before it joins, so an `accept` that no client ever reached
///     still returns. That is `blackbox.FakeHost.stop`'s knock, and it is done
///     for the same documented reason: the listener may not be closed while a
///     thread is inside `accept` reading the handle out of it.
///   * **The peer's socket is closed before the join.** The client's `deinit` is
///     registered after `release`, so it runs first: a stub waiting on input
///     ends, and a stub blocked writing a multi-megabyte reply fails.
///
/// And the whole of it lives in a *block* inside each gate rather than beside the
/// assertions, so the thread is joined before a single expectation is evaluated.
/// Nothing below can read a field the stub is still writing, and no assertion
/// failure can skip the teardown.
const Stub = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    server: std.Io.net.Server,
    /// The listener's own path, for the knock in `release`.
    path: []const u8,
    /// The output the fixture "command" produced, as it came off the channel.
    raw: []u8,
    exit_code: i32,
    /// Set by the serving thread, so a gate can assert the daemon really was
    /// asked for a retained run and not a whole one. Read only after the join.
    seen_output: ?protocol.Request.Output = null,
    seen_command: []const u8 = "",

    fn serve(stub: *Stub) void {
        var stream = stub.server.accept(stub.io) catch return;
        defer stream.close(stub.io);

        // Wide enough for any request these gates send (a command, a host, and
        // auth material — the largest is around 525 bytes), because what arrives
        // in the single read below is all this stub will ever look at.
        var read_buffer: [1 << 13]u8 = undefined;
        var reader = stream.reader(stub.io, &read_buffer);
        var write_buffer: [1 << 16]u8 = undefined;
        var writer = stream.writer(stub.io, &write_buffer);

        // One request's worth, and the frame payload lives on it, so it must
        // outlive the parse.
        var request_arena = std.heap.ArenaAllocator.init(stub.gpa);
        defer request_arena.deinit();
        const arena = request_arena.allocator();

        // The one and only wait on input. See the type's comment: parsing the
        // frame out of what already arrived is what makes a desynced request a
        // failed gate instead of two peers waiting on each other.
        const arrived = reader.interface.peekGreedy(protocol.header_len) catch return;
        var framed: std.Io.Reader = .fixed(arrived);
        const payload = (protocol.readFrame(&framed, arena) catch return) orelse return;
        const request = protocol.parseMessage(protocol.Request, arena, payload) catch return;
        switch (request.op) {
            .ping => protocol.writeMessage(&writer.interface, protocol.Response{
                .v = protocol.version,
                .ok = true,
                .pid = 4242,
            }) catch return,
            .stop => return,
            .exec => {
                stub.seen_output = request.output;
                stub.seen_command = stub.gpa.dupe(u8, request.command) catch return;
                var retained: Ssh.Retained = .{};
                // The capture the daemon's own drain runs, in the channel's
                // read size — the fixture stands in for the channel, not for
                // the ceiling.
                const served = Ssh.retain(arena, .{
                    .exit_code = stub.exit_code,
                    .stdout = stub.raw,
                    .stderr = arena.alloc(u8, 0) catch return,
                }, &retained, Ssh.read_bytes) catch return;
                const response = protocol.execResponse(
                    served,
                    if (request.output == .retained) retained else null,
                );
                protocol.writeMessage(&writer.interface, response) catch return;
            },
        }
    }

    /// Returns the serving thread and joins it. See the type's comment for why
    /// the knock comes first and why the listener is not touched until after.
    fn release(stub: *Stub, thread: std.Thread) void {
        if (std.Io.net.UnixAddress.init(stub.path)) |address| {
            if (address.connect(stub.io)) |stream| {
                var knock = stream;
                knock.close(stub.io);
            } else |_| {}
        } else |_| {}
        thread.join();
    }

    fn deinit(stub: *Stub) void {
        stub.server.deinit(stub.io);
        if (stub.seen_command.len > 0) stub.gpa.free(stub.seen_command);
    }
};

const Harness = struct {
    io: std.Io,
    threaded: *std.Io.Threaded,
    arena_state: *std.heap.ArenaAllocator,
    arena: std.mem.Allocator,
    db_path: [:0]u8,
    sock_path: []u8,
    store: Store,
    allocator: std.mem.Allocator,

    var counter: std.atomic.Value(u32) = .init(0);

    fn init(allocator: std.mem.Allocator, name: []const u8) !Harness {
        const threaded = try allocator.create(std.Io.Threaded);
        threaded.* = .init(allocator, .{});
        const io = threaded.io();
        const cwd = std.Io.Dir.cwd();
        cwd.createDirPath(io, scratch_dir) catch {};
        const n = counter.fetchAdd(1, .monotonic);
        const db_path = try std.fmt.allocPrintSentinel(allocator, "{s}/{s}_{d}_{d}_{d}.db", .{
            scratch_dir, name, Proc.currentPid(), std.Thread.getCurrentId(), n,
        }, 0);
        const sock_path = try std.fmt.allocPrint(allocator, "{s}/{s}_{d}_{d}_{d}.sock", .{
            scratch_dir, name, Proc.currentPid(), std.Thread.getCurrentId(), n,
        });

        cwd.deleteFile(io, db_path) catch {};
        cwd.deleteFile(io, sock_path) catch {};
        for ([_][]const u8{ "-wal", "-shm" }) |suffix| {
            const side = try std.fmt.allocPrint(allocator, "{s}{s}", .{ db_path, suffix });
            defer allocator.free(side);
            cwd.deleteFile(io, side) catch {};
        }

        const arena_state = try allocator.create(std.heap.ArenaAllocator);
        arena_state.* = std.heap.ArenaAllocator.init(allocator);

        var store = try Store.open(db_path);
        try store.db.exec(
            \\INSERT INTO servers (id, name, host, port, username, created_at, updated_at)
            \\VALUES (1, 'box', '10.0.0.1', 22, 'ubuntu', 100, 100);
        );

        return .{
            .io = io,
            .threaded = threaded,
            .arena_state = arena_state,
            .arena = arena_state.allocator(),
            .db_path = db_path,
            .sock_path = sock_path,
            .store = store,
            .allocator = allocator,
        };
    }

    fn deinit(h: *Harness) void {
        h.store.close();
        const cwd = std.Io.Dir.cwd();
        cwd.deleteFile(h.io, h.db_path) catch {};
        cwd.deleteFile(h.io, h.sock_path) catch {};
        for ([_][]const u8{ "-wal", "-shm" }) |suffix| {
            const side = std.fmt.allocPrint(h.allocator, "{s}{s}", .{ h.db_path, suffix }) catch continue;
            defer h.allocator.free(side);
            cwd.deleteFile(h.io, side) catch {};
        }
        h.arena_state.deinit();
        h.allocator.destroy(h.arena_state);
        h.allocator.free(h.db_path);
        h.allocator.free(h.sock_path);
        h.threaded.deinit();
        h.allocator.destroy(h.threaded);
    }

    fn begin(h: *Harness) !Core.execution.Execution {
        const start = try Core.execution.begin(&h.store, h.arena, h.io, .{
            .server_id = 1,
            .server_name = "box",
            .kind = .exec,
            .owner_token = "owner-a",
            .now = 1000,
        });
        return start.ready;
    }

    fn terminalRow(h: *Harness, request_id: []const u8) !Store.receipts.Row {
        const rows = try Store.receipts.list(&h.store, h.arena, request_id);
        for (rows) |row| if (row.is_terminal) return row;
        return error.NoTerminalRecorded;
    }
};

test "gate: a large successful command over the daemon socket settles with its real exit code" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "daemon_large_reply");
    defer h.deinit();

    var execution = try h.begin();
    defer execution.deinit();
    try execution.connecting();

    // Exactly the ceiling, which is the largest output that keeps every byte:
    // the head takes the first 512 KiB, the ring the last 512 KiB, and nothing
    // is dropped. So the run is *not* truncated, and the frame is still far past
    // what the old transport could carry — base64 puts it near 1.4 MiB, and the
    // old newline-delimited line would have been over a megabyte of
    // JSON-escaped text against a 1 MiB reader buffer. That read failed with
    // `error.StreamTooLong`, which became `error.ExecFailed`, which `runCommand`
    // records as a transport loss: a command that had already succeeded settled
    // `indeterminate` on the default transport.
    const raw = try wireOutput(t.allocator, execution.nonce, Ssh.output_ceiling.total(), 7);
    defer t.allocator.free(raw);

    var stub: Stub = .{
        .io = h.io,
        .gpa = t.allocator,
        .server = try listen(h.io, h.sock_path),
        .path = h.sock_path,
        .raw = raw,
        .exit_code = 7,
    };
    defer stub.deinit();

    // The thread's whole life is this block: it is joined on the way out, before
    // any expectation below is evaluated. See `Stub`.
    const result = blk: {
        const thread = try std.Thread.spawn(.{}, Stub.serve, .{&stub});
        defer stub.release(thread);
        var client = try connectClient(h.io, h.arena, h.sock_path);
        defer client.deinit();

        break :blk try Core.execution.runCommand(
            &execution,
            .{ .daemon = &client },
            "print a lot",
            null,
        );
    };

    // The whole point, and it is the ledger's own word for it.
    try t.expect(result == .ran);
    try t.expect(result.ran.status != .indeterminate);
    try t.expectEqualStrings("failed", result.ran.status.text());
    try t.expectEqual(@as(?i32, 7), result.ran.exit_code);
    // A tail-only cap would lose this, and so would a lost reply.
    try t.expectEqual(@as(i64, 4242), result.ran.identity.?.pid);
    // Nothing was dropped, so no marker and no truncation flag.
    try t.expect(!result.ran.output.?.stdout.truncated);
    try t.expect(std.mem.indexOf(u8, result.ran.stdout, Ssh.gap_marker) == null);
    // And the daemon really was asked for the bounded discipline.
    try t.expectEqual(protocol.Request.Output.retained, stub.seen_output.?);
    try t.expect(std.mem.indexOf(u8, stub.seen_command, "print a lot") != null);

    const row = try h.terminalRow(execution.id());
    try t.expectEqualStrings("failed", row.status.?);
    try t.expectEqual(@as(?i64, 7), row.exit_code);
    try t.expectEqual(@as(?i64, @intCast(raw.len)), row.stdout_bytes);
    try t.expectEqualStrings(try hexOf(h.arena, raw), row.stdout_sha256.?);
    try t.expectEqual(@as(?bool, false), row.stdout_truncated);
}

test "gate: over the ceiling the daemon path settles the same way the direct one does" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "daemon_truncated_reply");
    defer h.deinit();

    var execution = try h.begin();
    defer execution.deinit();
    try execution.connecting();

    const raw = try wireOutput(t.allocator, execution.nonce, 4 * Ssh.output_ceiling.total(), 42);
    defer t.allocator.free(raw);

    var stub: Stub = .{
        .io = h.io,
        .gpa = t.allocator,
        .server = try listen(h.io, h.sock_path),
        .path = h.sock_path,
        .raw = raw,
        .exit_code = 42,
    };
    defer stub.deinit();

    const result = blk: {
        const thread = try std.Thread.spawn(.{}, Stub.serve, .{&stub});
        defer stub.release(thread);
        var client = try connectClient(h.io, h.arena, h.sock_path);
        defer client.deinit();

        break :blk try Core.execution.runCommand(
            &execution,
            .{ .daemon = &client },
            "print far too much",
            null,
        );
    };

    // The command's own answer, out of the tail the ceiling kept.
    try t.expect(result.ran.status != .indeterminate);
    try t.expectEqual(@as(?i32, 42), result.ran.exit_code);
    // The same in-band marker the direct transport writes, in the caller's
    // stdout and not merely in a field beside it.
    try t.expect(result.ran.output.?.stdout.truncated);
    try t.expect(std.mem.indexOf(u8, result.ran.stdout, Ssh.gap_marker) != null);
    try t.expect(result.ran.stdout.len < raw.len);

    // The same three numbers, and they describe every byte that passed on the
    // far side of the socket rather than the amount that came back.
    const row = try h.terminalRow(execution.id());
    try t.expectEqualStrings("failed", row.status.?);
    try t.expectEqual(@as(?i64, 42), row.exit_code);
    try t.expectEqual(@as(?i64, @intCast(raw.len)), row.stdout_bytes);
    try t.expect(row.stdout_bytes.? > @as(i64, @intCast(result.ran.stdout.len)));
    try t.expectEqualStrings(try hexOf(h.arena, raw), row.stdout_sha256.?);
    try t.expectEqual(@as(?bool, true), row.stdout_truncated);
    try t.expectEqual(@as(?i64, 0), row.stderr_bytes);
    try t.expectEqual(@as(?bool, false), row.stderr_truncated);
    try t.expectEqualStrings(Ssh.empty_sha256, row.stderr_sha256.?);
}

// --- gate: the fresh start ---------------------------------------------------
//
// **What is driven, and what is not.** The CLI auto-starts the daemon, so the
// first request of a session is the one that finds nothing on the other side.
// Every shape of "nothing came back" below is driven over a real `AF_UNIX`
// connection with the real `DaemonClient`: the socket that is not there, the
// socket file with nobody behind it, the peer that accepts and closes without
// writing, the reply that stops part-way, and the unframed answer an older
// build sends. The success shape is driven too — `acquire` finds a live peer
// through `Server.socketPath` and returns it without spawning anything.
//
// What is **not** driven here is `spawnDaemon` itself. It runs
// `std.process.executablePath` with `daemon run`, and from a test binary that is
// this suite re-entering itself as a subprocess. The spawn is driven end to end
// in `test/blackbox.zig` instead, against the real executable and a scratch
// home; what is left over from both is the five lines of `spawnDaemon`, which
// are reviewed.
//
// The one thing none of this can prove is the absence of a wait on a peer that
// writes a header and then neither writes nor closes. No shape below produces
// it — see the paragraph in `Client.zig`.

/// A listener that answers with **exactly the bytes it is given**, then closes.
///
/// Same discipline as `Stub`, and for the same reasons: one accept, one wait on
/// input, at most one write, then the socket closes. The wait is safe because
/// `roundTrip` writes and flushes its whole request before it reads a reply, and
/// nothing here parses that request — so no byte sequence can make this stub
/// wait for a second piece of input, and the client's own read is bounded by
/// this stub's close whatever the bytes said.
const Cut = struct {
    io: std.Io,
    server: std.Io.net.Server,
    path: []const u8,
    /// Empty means "accept, read the request, and close without writing" — the
    /// fresh-start EOF itself.
    reply: []const u8,

    fn serve(c: *Cut) void {
        var stream = c.server.accept(c.io) catch return;
        defer stream.close(c.io);
        var read_buffer: [1 << 13]u8 = undefined;
        var reader = stream.reader(c.io, &read_buffer);
        _ = reader.interface.peekGreedy(protocol.header_len) catch return;
        if (c.reply.len == 0) return;
        var write_buffer: [1 << 12]u8 = undefined;
        var writer = stream.writer(c.io, &write_buffer);
        writer.interface.writeAll(c.reply) catch return;
        writer.interface.flush() catch {};
    }

    /// The knock, then the join. See `Stub.release`.
    fn release(c: *Cut, thread: std.Thread) void {
        if (std.Io.net.UnixAddress.init(c.path)) |address| {
            if (address.connect(c.io)) |stream| {
                var knock = stream;
                knock.close(c.io);
            } else |_| {}
        } else |_| {}
        thread.join();
    }

    fn deinit(c: *Cut) void {
        c.server.deinit(c.io);
    }
};

/// One shape of "nothing came back", and the sentence it has to produce.
const FreshStart = struct {
    label: []const u8,
    reply: []const u8,
    /// `MalformedFrame` for bytes that are not a frame header, `FrameIncomplete`
    /// for a header whose frame did not arrive whole, and null when the stream
    /// simply ended between frames (a clean close, which is not an error).
    frame_error: ?protocol.FrameError,
    /// Whether `DaemonClient` must call this a version skew. Exactly one shape
    /// below may.
    skew: bool,
};

test "gate: a CLI that finds no daemon gets a named refusal, never a hang and never a wrong cause" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "daemon_fresh_start");
    defer h.deinit();

    const started = std.Io.Timestamp.now(h.io, .awake);
    var proven: usize = 0;

    // (1) No home, so no socket path. `acquire` names it and — this is the part
    // worth stating — returns before `spawnDaemon`, which from a test binary
    // would be this suite re-entering itself.
    {
        proven += 1;
        var bare: std.process.Environ.Map = .init(t.allocator);
        defer bare.deinit();
        const result = DaemonClient.acquire(h.io, h.arena, &bare, .{
            .v = protocol.version,
            .op = .exec,
        });
        try t.expectEqualStrings("no home directory for socket path", result.unavailable);
    }

    // (2) A home with no socket in it: the ordinary state of a machine whose
    // daemon has never run. `connectTo` checks for the file before it dials, so
    // this is a stated absence and not a Windows `error.Unexpected` with a
    // debug stack trace printed under it.
    //
    // The *stale* socket file — a plain file where the socket belongs, which an
    // unclean daemon exit leaves — is driven in `test/blackbox.zig` instead. It
    // has to be: on Windows a connect to one fails with a status std does not
    // map (`ConnectionRefused` is not in `UnixAddress.ConnectError`), so it
    // prints a trace, and out here that trace would land in this suite's own
    // output on every green run. Over there it lands in the child process's
    // captured stderr, where the assertion is about what the CLI *did* rather
    // than about std's noise. See that gate for the finding.
    {
        var environ: std.process.Environ.Map = .init(t.allocator);
        defer environ.deinit();
        const home = try std.fmt.allocPrint(h.arena, "{s}/fresh_home_{d}_{d}", .{ scratch_dir, Proc.currentPid(), std.Thread.getCurrentId() });
        try environ.put("USERPROFILE", home);
        const sock = try Server.socketPath(h.arena, &environ);
        std.Io.Dir.cwd().createDirPath(h.io, std.fs.path.dirname(sock).?) catch {};
        std.Io.Dir.cwd().deleteFile(h.io, sock) catch {};

        proven += 1;
        try t.expectEqual(@as(?u32, null), DaemonClient.pingDaemon(h.io, h.arena, &environ));
        try t.expectEqual(false, DaemonClient.stopDaemon(h.io, h.arena, &environ));
    }

    // (3) The five shapes a peer can produce once the connection is up. The
    // first is the EOF this gate is named for; the third and fourth are the
    // ones that used to be reported as a version skew.
    const header32 = "00000020";
    const shapes = [_]FreshStart{
        .{ .label = "accepted, then closed without writing", .reply = "", .frame_error = null, .skew = false },
        .{ .label = "half a header, then closed", .reply = "0000", .frame_error = null, .skew = false },
        .{ .label = "a header, then a payload cut short", .reply = header32 ++ "{\"v\":3,", .frame_error = error.FrameIncomplete, .skew = false },
        .{ .label = "a whole payload with no terminator", .reply = header32 ++ "{\"v\":3,\"ok\":true,\"pid\":9}!!!!!!!", .frame_error = error.FrameIncomplete, .skew = false },
        .{ .label = "an unframed line, as an older build sends", .reply = "{\"v\":2,\"ok\":false}\n", .frame_error = error.MalformedFrame, .skew = true },
    };

    for (shapes, 0..) |shape, i| {
        proven += 1;
        // The frame layer's own answer first, so the two names are pinned where
        // they are produced as well as where they are consumed. A shape that
        // ends between frames is a clean close and yields no error at all.
        var reader: std.Io.Reader = .fixed(shape.reply);
        if (shape.frame_error) |want| {
            try t.expectError(want, protocol.readFrame(&reader, h.arena));
        } else {
            try t.expectEqual(@as(?[]const u8, null), try protocol.readFrame(&reader, h.arena));
        }

        const path = try std.fmt.allocPrint(h.arena, "{s}_{d}", .{ h.sock_path, i });
        var cut: Cut = .{
            .io = h.io,
            .server = try listen(h.io, path),
            .path = path,
            .reply = shape.reply,
        };
        defer cut.deinit();
        defer std.Io.Dir.cwd().deleteFile(h.io, path) catch {};

        const message = blk: {
            const thread = try std.Thread.spawn(.{}, Cut.serve, .{&cut});
            defer cut.release(thread);
            var client = try connectClient(h.io, h.arena, path);
            defer client.deinit();
            try t.expectError(error.ExecFailed, client.exec(h.arena, "true"));
            break :blk client.errorMessage();
        };

        if (shape.skew) {
            // The one shape that really is another build's protocol, and the one
            // message allowed to say so — with the command that clears it.
            t.expect(std.mem.indexOf(u8, message, "another build") != null) catch |err| {
                std.debug.print("\n{s}: expected a version-skew sentence, got: {s}\n", .{ shape.label, message });
                return err;
            };
            try t.expect(std.mem.indexOf(u8, message, "daemon restart --force") != null);
        } else {
            // Nothing came back, and the sentence says that and nothing more.
            // A reply that stopped part-way used to land on the skew arm above:
            // it named a protocol version as the fault, sent the operator to
            // `daemon restart --force` for a daemon that had already gone, and
            // — because `acquire` does not spawn past a skew — kept the CLI on
            // direct SSH where a respawn would have worked.
            t.expectEqualStrings("daemon connection lost mid-request", message) catch |err| {
                std.debug.print("\n{s}: wrong diagnosis\n", .{shape.label});
                return err;
            };
            try t.expect(std.mem.indexOf(u8, message, "another build") == null);
        }
    }

    // (4) And the shape that is not a failure: a live peer at the path
    // `Server.socketPath` names, found and kept without anything being spawned.
    // Without this the gate would only prove that `acquire` gives up.
    {
        proven += 1;
        var environ: std.process.Environ.Map = .init(t.allocator);
        defer environ.deinit();
        const home = try std.fmt.allocPrint(h.arena, "{s}/live_home_{d}_{d}", .{ scratch_dir, Proc.currentPid(), std.Thread.getCurrentId() });
        try environ.put("USERPROFILE", home);
        const sock = try Server.socketPath(h.arena, &environ);
        std.Io.Dir.cwd().createDirPath(h.io, std.fs.path.dirname(sock).?) catch {};

        var stub: Stub = .{
            .io = h.io,
            .gpa = t.allocator,
            .server = try listen(h.io, sock),
            .path = sock,
            .raw = &.{},
            .exit_code = 0,
        };
        defer stub.deinit();
        defer std.Io.Dir.cwd().deleteFile(h.io, sock) catch {};

        const thread = try std.Thread.spawn(.{}, Stub.serve, .{&stub});
        defer stub.release(thread);
        switch (DaemonClient.acquire(h.io, h.arena, &environ, .{
            .v = protocol.version,
            .op = .exec,
            .host = "10.0.0.1",
            .username = "ubuntu",
        })) {
            .ok => |client| {
                var open = client;
                open.deinit();
            },
            .unavailable => |reason| {
                std.debug.print("\nacquire refused a live daemon: {s}\n", .{reason});
                return error.AcquireRefusedALiveDaemon;
            },
        }
    }

    try t.expectEqual(@as(usize, 8), proven);

    // Bounded, and asserted rather than assumed. Nothing above sleeps and
    // nothing retries, so this is generous by three orders of magnitude — what
    // it catches is a change that puts a wait or a retry loop on the read path,
    // which is the failure this gate is named for and the one an assertion on
    // messages alone cannot see.
    const elapsed = started.durationTo(std.Io.Timestamp.now(h.io, .awake)).nanoseconds;
    try t.expect(elapsed < 5 * std.time.ns_per_s);
}

fn listen(io: std.Io, path: []const u8) !std.Io.net.Server {
    std.Io.Dir.cwd().deleteFile(io, path) catch {};
    const address = try std.Io.net.UnixAddress.init(path);
    return address.listen(io, .{});
}

fn connectClient(io: std.Io, arena: std.mem.Allocator, path: []const u8) !DaemonClient {
    const address = try std.Io.net.UnixAddress.init(path);
    const stream = try address.connect(io);
    return .{
        .io = io,
        .arena = arena,
        .stream = stream,
        .request = .{ .v = protocol.version, .op = .exec, .host = "10.0.0.1", .username = "ubuntu" },
    };
}

fn hexOf(arena: std.mem.Allocator, bytes: []const u8) ![]const u8 {
    const out = try arena.alloc(u8, Core.digest.hex_len);
    return Core.digest.hex(bytes, out[0..Core.digest.hex_len]);
}
