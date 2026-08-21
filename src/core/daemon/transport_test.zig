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
const Ssh = @import("../ssh/Client.zig");
const Core = @import("../core.zig");
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
        const db_path = try std.fmt.allocPrintSentinel(allocator, "{s}/{s}_{d}_{d}.db", .{
            scratch_dir, name, std.Thread.getCurrentId(), n,
        }, 0);
        const sock_path = try std.fmt.allocPrint(allocator, "{s}/{s}_{d}_{d}.sock", .{
            scratch_dir, name, std.Thread.getCurrentId(), n,
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
