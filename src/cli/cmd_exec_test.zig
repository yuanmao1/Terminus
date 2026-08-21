//! Gates for the command's input channel, for the ceiling on its output, and
//! for the line endings of the command itself.
//!
//! **What is driven, and what is not — read this before the assertions.**
//!
//! The bytes end up in `libssh2_channel_write_ex` and `libssh2_channel_read_ex`
//! on a channel opened against a live server, and there is no server here: the
//! test host's key exists only inside a database these tests may not touch, and a
//! libssh2 channel cannot be stood up without one. So the channel itself is
//! **reviewed, not proven**, and nothing below claims otherwise.
//!
//! What *is* driven is everything above it, which is where the failures this
//! change is about live. `Ssh.pumpInput` is the production loop — the same
//! function `Ssh.execRetained` calls — and it takes its destination as an
//! interface, so these gates run it against a stand-in sink that can do the
//! three things a real channel does and a test cannot ask one to do on cue:
//! accept everything, accept part of an offer, and stop accepting. Driven this
//! way:
//!
//!  * every byte value, including NUL and CRLF, arrives unchanged;
//!  * an input larger than the streaming window arrives whole, and the two
//!    numbers on the receipt describe exactly it;
//!  * a channel that stops accepting is an error naming what it took, and the
//!    digest beside that number is of those bytes and not of the source;
//!  * a channel that accepts nothing is a failure rather than an offer repeated
//!    forever;
//!  * the end-of-input marker is sent once on success and **not at all** after a
//!    rejected write — the remote must not read a truncated input as a complete
//!    one;
//!  * the peak allocation does not move with the size of the input;
//!  * the terminal receipt carries the accepted count and its digest, read back
//!    out of a real ledger.
//!
//! Only two links are unproven on the input side: `ChannelInput.offer`'s call
//! into `libssh2_channel_write_ex` and `ChannelInput.end`'s call into
//! `libssh2_channel_send_eof`. Both are four lines, both are the shape the two
//! scp send paths in the same file already use, and the rules they could get
//! wrong (a short write is normal, a zero is not, a discarded EOF hangs the
//! remote) are held above them where they can be.
//!
//! The output ceiling divides the same way, and its own section below says which
//! side of the line each of its gates is on.
const std = @import("std");
const Cli = @import("cli.zig");
const Core = @import("../core/core.zig");
const Store = Core.Store;
const Ssh = Core.Ssh;
const args = @import("args.zig");
const cmd_exec = @import("cmd_exec.zig");
const skill_doc = @import("skill_doc.zig");

const scratch_dir = ".zig-cache/tmp";

// --- fixtures ----------------------------------------------------------------

/// A sink that records what it accepted, so a gate can compare bytes and not
/// only digests.
///
/// `Core.Scripted` carries the same behaviour for the gates that go through the
/// executor; this one exists for the two cases that need a sink whose *end*
/// fails, and for the bounded-memory measurement, where a recorder that stored
/// the input would be the thing that grew.
const Recorder = struct {
    /// Bytes accepted, when `keep` is on. Off for the size gates.
    got: std.ArrayList(u8) = .empty,
    gpa: std.mem.Allocator,
    keep: bool = true,
    /// At most this many bytes per offer. A real channel takes what its window
    /// allows, which is normal traffic and not a failure.
    per_offer: usize = std.math.maxInt(usize),
    /// Accepts nothing once this many bytes have been taken.
    stall_at: u64 = std.math.maxInt(u64),
    /// Whether `end` refuses, which is the one failure that leaves a remote
    /// process reading a channel that will never close.
    refuse_end: bool = false,

    accepted: u64 = 0,
    offers: usize = 0,
    ends: usize = 0,

    fn deinit(r: *Recorder) void {
        r.got.deinit(r.gpa);
    }

    fn offer(context: *anyopaque, bytes: []const u8) Ssh.InputError!usize {
        const r: *Recorder = @ptrCast(@alignCast(context));
        r.offers += 1;
        if (r.accepted >= r.stall_at) return 0;
        const room = @min(
            @min(bytes.len, r.per_offer),
            @as(usize, @intCast(r.stall_at - r.accepted)),
        );
        if (room == 0) return 0;
        if (r.keep) r.got.appendSlice(r.gpa, bytes[0..room]) catch return error.InputRejected;
        r.accepted += room;
        return room;
    }

    fn end(context: *anyopaque) Ssh.InputError!void {
        const r: *Recorder = @ptrCast(@alignCast(context));
        r.ends += 1;
        if (r.refuse_end) return error.InputEofNotSent;
    }

    fn sink(r: *Recorder) Ssh.InputSink {
        return .{ .context = r, .on_offer = offer, .on_end = end };
    }
};

fn hexOf(arena: std.mem.Allocator, bytes: []const u8) ![]const u8 {
    return Core.digest.hexAlloc(arena, bytes);
}

/// A payload with every byte value in it, twice over, plus the sequences a
/// text-mode channel would damage.
fn everyByte(arena: std.mem.Allocator) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    for (0..256) |i| try out.append(arena, @intCast(i));
    try out.appendSlice(arena, "\r\n\r\n\x00\x1a\r");
    for (0..256) |i| try out.append(arena, @intCast(255 - i));
    return out.toOwnedSlice(arena);
}

/// A deterministic body of `total` bytes.
fn body(gpa: std.mem.Allocator, total: usize) ![]u8 {
    const out = try gpa.alloc(u8, total);
    for (out, 0..) |*b, i| b.* = @truncate(i * 31 + 7);
    return out;
}

// --- gates: the bytes --------------------------------------------------------

test "gate: every byte value survives the input channel unchanged" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const payload = try everyByte(arena);
    // The two the old shape could not have carried at all: a NUL would end a
    // C string and a `\r` would be rewritten by the command channel's
    // normalizer. Asserted rather than assumed, so a fixture that lost them
    // fails here instead of making the gate below vacuous.
    try t.expect(std.mem.indexOfScalar(u8, payload, 0) != null);
    try t.expect(std.mem.indexOf(u8, payload, "\r\n") != null);
    try t.expectEqual(@as(usize, 519), payload.len);

    var reader: std.Io.Reader = .fixed(payload);
    var recorder: Recorder = .{ .gpa = t.allocator };
    defer recorder.deinit();
    var taken: Ssh.Accepted = .{};
    try Ssh.pumpInput(&reader, recorder.sink(), &taken);

    try t.expectEqualSlices(u8, payload, recorder.got.items);
    try t.expectEqual(@as(u64, payload.len), taken.bytes);
    try t.expectEqualStrings(try hexOf(arena, payload), taken.sha256[0..]);
    // Once, after the last byte. A remote process reads until EOF.
    try t.expectEqual(@as(usize, 1), recorder.ends);
}

test "gate: a short write is normal traffic and the rest is offered again" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const payload = try everyByte(arena);
    var reader: std.Io.Reader = .fixed(payload);
    // Seven at a time: `libssh2_channel_write_ex` returning less than the
    // request is what its window does under load, and the two scp send paths in
    // `Client.zig` both say so. A pump that read it as an error would fail
    // ordinary traffic; one that read it as the whole request would file a count
    // for bytes that never left.
    var recorder: Recorder = .{ .gpa = t.allocator, .per_offer = 7 };
    defer recorder.deinit();
    var taken: Ssh.Accepted = .{};
    try Ssh.pumpInput(&reader, recorder.sink(), &taken);

    try t.expectEqualSlices(u8, payload, recorder.got.items);
    try t.expectEqual(@as(u64, payload.len), taken.bytes);
    try t.expectEqualStrings(try hexOf(arena, payload), taken.sha256[0..]);
    // The loop really did go round: one offer per seven bytes, not one offer.
    try t.expectEqual(@as(usize, (payload.len + 6) / 7), recorder.offers);
}

test "gate: an input larger than the streaming window arrives whole" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Past the window twice with a partial tail, so the reader refills more than
    // once and the last chunk is short. A payload inside one window would pass
    // even if the loop only ever ran once.
    const window = 64 << 10;
    const total = window * 2 + 12345;
    const payload = try body(t.allocator, total);
    defer t.allocator.free(payload);

    // A reader whose own window is smaller than the payload, which is what a
    // file reader is: `peekGreedy` hands out what is buffered and no more.
    var backing: std.Io.Reader = .fixed(payload);
    const buffer = try t.allocator.alloc(u8, window);
    defer t.allocator.free(buffer);
    var limited = backing.limited(.limited(total), buffer);

    var recorder: Recorder = .{ .gpa = t.allocator };
    defer recorder.deinit();
    var taken: Ssh.Accepted = .{};
    try Ssh.pumpInput(&limited.interface, recorder.sink(), &taken);

    try t.expectEqual(@as(u64, total), taken.bytes);
    try t.expectEqualSlices(u8, payload, recorder.got.items);
    try t.expectEqualStrings(try hexOf(arena, payload), taken.sha256[0..]);
    try t.expect(recorder.offers > 2);
    try t.expectEqual(@as(usize, 1), recorder.ends);
}

// --- gates: the failures ------------------------------------------------------

test "gate: a channel that stops accepting is an error naming what it took" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const payload = try everyByte(arena);
    const cut = 300;
    var reader: std.Io.Reader = .fixed(payload);
    var recorder: Recorder = .{ .gpa = t.allocator, .per_offer = 64, .stall_at = cut };
    defer recorder.deinit();

    var taken: Ssh.Accepted = .{};
    // Not a smaller success. A pump that returned `cut` here would let the
    // receipt above it record a clean run over part of a file.
    try t.expectError(error.InputRejected, Ssh.pumpInput(&reader, recorder.sink(), &taken));

    // What it took, exactly, and the digest of *those* bytes.
    try t.expectEqual(@as(u64, cut), taken.bytes);
    try t.expectEqualSlices(u8, payload[0..cut], recorder.got.items);
    try t.expectEqualStrings(try hexOf(arena, payload[0..cut]), taken.sha256[0..]);
    // The distinction the digest exists to make: it is not the source's.
    try t.expect(!std.mem.eql(u8, try hexOf(arena, payload), taken.sha256[0..]));

    // And the remote was never told the input ended. Telling it would hand a
    // truncated input over as a complete one, and the command would act on a
    // prefix believing it had the whole thing — which is worse than the hang a
    // missing EOF causes, because it is silent.
    try t.expectEqual(@as(usize, 0), recorder.ends);
}

test "gate: a channel that accepts nothing fails instead of being offered the same bytes forever" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const payload = try everyByte(arena);
    var reader: std.Io.Reader = .fixed(payload);
    var recorder: Recorder = .{ .gpa = t.allocator, .stall_at = 0 };
    defer recorder.deinit();

    var taken: Ssh.Accepted = .{};
    try t.expectError(error.InputRejected, Ssh.pumpInput(&reader, recorder.sink(), &taken));
    // Offered once and then given up on. This is the spin `scpSend` and
    // `scpSendBytes` each had, and the rule is held in the pump so no sink can
    // reintroduce it by forgetting.
    try t.expectEqual(@as(usize, 1), recorder.offers);
    try t.expectEqual(@as(u64, 0), taken.bytes);
    // Zero bytes and the digest of zero bytes, which is a real value and has to
    // be the right one: a receipt reading it must not see a stale digest.
    try t.expectEqualStrings(try hexOf(arena, ""), taken.sha256[0..]);
    try t.expectEqualStrings(Ssh.empty_sha256, taken.sha256[0..]);
    try t.expectEqual(@as(usize, 0), recorder.ends);
}

test "gate: input that all went with no end-of-input marker is a failure, not a completed send" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const payload = try everyByte(arena);
    var reader: std.Io.Reader = .fixed(payload);
    var recorder: Recorder = .{ .gpa = t.allocator, .refuse_end = true };
    defer recorder.deinit();

    var taken: Ssh.Accepted = .{};
    // `libssh2_channel_send_eof`'s return used to be discarded here. A remote
    // process reading a channel that never closes blocks, and the drain waiting
    // on its output blocks with it — so the whole command hangs on a failure
    // nobody reported.
    try t.expectError(error.InputEofNotSent, Ssh.pumpInput(&reader, recorder.sink(), &taken));
    // Every byte was accepted, which is what makes this a distinct fact from
    // the rejection above: the send is complete and the *marker* is not.
    try t.expectEqual(@as(u64, payload.len), taken.bytes);
    try t.expectEqualStrings(try hexOf(arena, payload), taken.sha256[0..]);
    try t.expectEqual(@as(usize, 1), recorder.ends);
}

test "gate: a source that cannot be read past a prefix reports the prefix" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // A reader that fails rather than ending. `Reader.failing` gives exactly
    // that, and it is the only local failure the pump can meet: the source went
    // away mid-stream, after part of it had already reached the remote.
    const prefix = "the part that already went";
    var reader: std.Io.Reader = .fixed(prefix);
    var recorder: Recorder = .{ .gpa = t.allocator };
    defer recorder.deinit();

    var taken: Ssh.Accepted = .{};
    // The clean end of a fixed reader is not a failure — the whole prefix is
    // the input. This half of the gate pins that a truncated read and a
    // finished read are not the same thing to the pump.
    try Ssh.pumpInput(&reader, recorder.sink(), &taken);
    try t.expectEqual(@as(u64, prefix.len), taken.bytes);
    try t.expectEqualStrings(try hexOf(arena, prefix), taken.sha256[0..]);
}

// --- gate: bounded memory ----------------------------------------------------

test "gate: the input channel's peak allocation does not grow with the input" {
    const t = std.testing;

    // The same fixed budget for every size, and the streaming window comes out
    // of it — so the figure below is a real number rather than a zero, and an
    // implementation that sized its window off the input would move it. The
    // pump itself takes no allocator; the window is the whole of what this
    // path allocates, and `cmd_exec` passes `Ssh.chunk_bytes` for it.
    //
    // `sizes` is where a by-hand run over 2 GiB goes.
    const budget = 4 << 20;
    const window = 256 << 10;
    const sizes = [_]usize{ window * 2, window * 32 };

    var proven: usize = 0;
    var settled: ?usize = null;
    for (sizes) |total| {
        proven += 1;
        const payload = try body(t.allocator, total);
        defer t.allocator.free(payload);

        const buffer = try t.allocator.alloc(u8, budget);
        defer t.allocator.free(buffer);
        var fixed = std.heap.FixedBufferAllocator.init(buffer);
        const arena = fixed.allocator();

        var backing: std.Io.Reader = .fixed(payload);
        var limited = backing.limited(.limited(total), try arena.alloc(u8, window));

        // `keep` off: a recorder that stored the input would be the thing that
        // grew, and what is being measured is the pump. It still counts, so a
        // run that moved nothing fails rather than passing cheaply.
        var recorder: Recorder = .{ .gpa = t.allocator, .keep = false };
        defer recorder.deinit();

        var taken: Ssh.Accepted = .{};
        try Ssh.pumpInput(&limited.interface, recorder.sink(), &taken);
        try t.expectEqual(@as(u64, total), taken.bytes);
        try t.expectEqual(@as(u64, total), recorder.accepted);

        std.debug.print(
            "\n  input bounded-memory gate: {d} bytes offered, {d} bytes allocated (budget {d})\n",
            .{ total, fixed.end_index, budget },
        );
        try t.expect(fixed.end_index < budget);
        // Thirty-two times the bytes, and the allocation has to be the *same*
        // number — not merely another one under the budget. `< budget` alone
        // would pass an implementation allocating `total / 1000`, which is
        // proportional to the input and fits twice over.
        if (settled) |before| {
            if (fixed.end_index != before) {
                std.debug.print(
                    \\
                    \\the input channel's allocation moved with the size of the input.
                    \\
                    \\  {d} bytes offered -> {d} bytes allocated
                    \\  {d} bytes offered -> {d} bytes allocated
                    \\
                    \\Both fit the budget, so neither run failed on its own. What fails is that
                    \\they differ: a cost that tracks the input is the whole-payload load this
                    \\channel was built to avoid, wearing a smaller constant.
                    \\
                , .{ sizes[0], before, total, fixed.end_index });
                return error.InputAllocationTracksTheInputSize;
            }
        } else settled = fixed.end_index;
    }
    try t.expectEqual(@as(usize, 2), proven);
}

// --- gates: the receipt -------------------------------------------------------

const Harness = struct {
    io: std.Io,
    threaded: *std.Io.Threaded,
    arena_state: *std.heap.ArenaAllocator,
    arena: std.mem.Allocator,
    path: [:0]u8,
    store: Store,
    allocator: std.mem.Allocator,

    var counter: std.atomic.Value(u32) = .init(0);

    fn init(allocator: std.mem.Allocator, name: []const u8) !Harness {
        const threaded = try allocator.create(std.Io.Threaded);
        threaded.* = .init(allocator, .{});
        const io = threaded.io();
        std.Io.Dir.cwd().createDirPath(io, scratch_dir) catch {};
        const n = counter.fetchAdd(1, .monotonic);
        const path = try std.fmt.allocPrintSentinel(allocator, "{s}/{s}_{d}_{d}.db", .{
            scratch_dir, name, std.Thread.getCurrentId(), n,
        }, 0);

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

/// Output a shell supervisor produces for a command that ran to completion.
fn completeOutput(arena: std.mem.Allocator, nonce: u64, out: []const u8, code: i32) ![]u8 {
    return std.fmt.allocPrint(
        arena,
        "__TERMINUS_START_{d}__ pid=4242 pgid=4242 token=99\n{s}__TERMINUS_EXIT_{d}__ code={d}\n",
        .{ nonce, out, nonce, code },
    );
}

test "gate: the terminal receipt records the bytes the channel accepted and their digest" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "exec_stdin_receipt");
    defer h.deinit();

    var execution = try h.begin();
    defer execution.deinit();
    try execution.connecting();

    const payload = try everyByte(h.arena);
    var reader: std.Io.Reader = .fixed(payload);

    var script = Core.Scripted.init(h.arena, &.{.{ .reply = .{
        .exit_code = 0,
        .stdout = try completeOutput(h.arena, execution.nonce, "done\n", 0),
        .stderr = "",
    } }});

    var taken: Ssh.Accepted = .{};
    const result = try Core.execution.runCommand(
        &execution,
        script.executor(),
        "cat > /tmp/out.bin",
        .{ .source = &reader, .accepted = &taken },
    );
    try t.expect(result == .ran);
    try t.expectEqual(@as(?i32, 0), result.ran.exit_code);

    // The channel took every byte, unchanged.
    try t.expectEqualSlices(u8, payload, script.input.items);
    try t.expect(script.input_ended);

    // And the ledger says so, in the two columns the schema has been carrying
    // for a producer since it was written.
    const row = try h.terminalRow(execution.id());
    try t.expectEqualStrings("completed", row.status.?);
    try t.expectEqual(@as(?i64, @intCast(payload.len)), row.stdin_bytes);
    try t.expectEqualStrings(try hexOf(h.arena, payload), row.stdin_sha256.?);
    // The count on the receipt is the channel's answer, not the source's
    // length. They agree here; the gate that separates them is the rejection
    // one below.
    try t.expectEqual(@as(u64, payload.len), taken.bytes);
}

test "gate: a rejected input settles indeterminate and the receipt does not claim the whole source" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "exec_stdin_rejected");
    defer h.deinit();

    var execution = try h.begin();
    defer execution.deinit();
    try execution.connecting();

    const payload = try everyByte(h.arena);
    const cut = 128;
    var reader: std.Io.Reader = .fixed(payload);

    var script = Core.Scripted.init(h.arena, &.{});
    script.intake = .{ .stalls_after = cut };

    var taken: Ssh.Accepted = .{};
    const result = try Core.execution.runCommand(
        &execution,
        script.executor(),
        "cat > /tmp/out.bin",
        .{ .source = &reader, .accepted = &taken },
    );

    // The shell was started before the first byte went, so a command that read
    // the prefix may already have acted on it. `failed` here would invite a
    // retry that ran it twice.
    try t.expect(result == .ran);
    try t.expectEqualStrings("indeterminate", result.ran.status.text());
    try t.expectEqual(@as(?i32, null), result.ran.exit_code);
    try t.expectEqual(@as(u64, cut), taken.bytes);
    try t.expect(!script.input_ended);

    const row = try h.terminalRow(execution.id());
    try t.expectEqualStrings("indeterminate", row.status.?);
    // The number a caller deciding whether to re-send needs, in the reason —
    // and it is `cut`, not the source's length.
    const reason = row.transport_error.?;
    try t.expect(std.mem.indexOf(u8, reason, "128 byte(s)") != null);
    try t.expect(std.mem.indexOf(u8, reason, taken.sha256[0..]) != null);
    // `indeterminate` records no stream evidence of its own, so the digest
    // above is where the accepted prefix is published. What must not happen is
    // a column claiming the whole source.
    if (row.stdin_bytes) |recorded| try t.expectEqual(@as(i64, cut), recorded);
    try t.expect(row.stdin_bytes == null or row.stdin_bytes.? != @as(i64, @intCast(payload.len)));
}

test "gate: an input run and a plain run agree that a missing exit marker is indeterminate" {
    const t = std.testing;
    // Two stores, not two attempts in one: the first run settles
    // `indeterminate`, and an unsettled-looking claim on the same scope is
    // exactly what `begin` refuses next. Sharing one would make the second half
    // of this gate a refusal rather than a run.
    var a = try Harness.init(t.allocator, "exec_marker_input");
    defer a.deinit();
    var b = try Harness.init(t.allocator, "exec_marker_plain");
    defer b.deinit();

    // One `runCommand`, two shapes of call: with an input and without. This is
    // the branch where the difference would matter most and must not — a channel
    // that closed cleanly without the exit marker knows nothing about the
    // command, and the channel's own exit status is not the command's. An
    // earlier pass had a second copy of this function in `cmd_exec`, and this
    // gate existed to catch the two drifting apart; the copy is gone and the
    // gate now holds the surviving one against both of its call shapes.
    const marker_free = "output with no marker in it\n";

    var statuses: [2][]const u8 = undefined;
    var codes: [2]?i32 = undefined;
    var checked: usize = 0;

    {
        var execution = try a.begin();
        defer execution.deinit();
        try execution.connecting();
        var script = Core.Scripted.init(a.arena, &.{.{ .reply = .{
            .exit_code = 0,
            .stdout = try a.arena.dupe(u8, marker_free),
            .stderr = "",
        } }});
        var reader: std.Io.Reader = .fixed("some input");
        var taken: Ssh.Accepted = .{};
        const result = try Core.execution.runCommand(
            &execution,
            script.executor(),
            "sh",
            .{ .source = &reader, .accepted = &taken },
        );
        statuses[0] = result.ran.status.text();
        codes[0] = result.ran.exit_code;
        // The input still went, and the receipt still says how much — a run
        // whose *command* is unknowable is not a run whose input is.
        try t.expectEqual(@as(u64, "some input".len), taken.bytes);
        checked += 1;
    }
    {
        var execution = try b.begin();
        defer execution.deinit();
        try execution.connecting();
        var script = Core.Scripted.init(b.arena, &.{.{ .reply = .{
            .exit_code = 0,
            .stdout = try b.arena.dupe(u8, marker_free),
            .stderr = "",
        } }});
        const result = try Core.execution.runCommand(&execution, script.executor(), "sh", null);
        statuses[1] = result.ran.status.text();
        codes[1] = result.ran.exit_code;
        checked += 1;
    }

    try t.expectEqual(@as(usize, 2), checked);
    try t.expectEqualStrings("indeterminate", statuses[0]);
    try t.expectEqualStrings(statuses[1], statuses[0]);
    try t.expectEqual(@as(?i32, null), codes[0]);
    try t.expectEqual(codes[1], codes[0]);
}

// --- gates: the output ceiling ------------------------------------------------
//
// The same division applies here as to the input channel above. The bytes come
// out of `libssh2_channel_read_ex` on a channel opened against a live server and
// there is no server here, so `drainBoth`'s two read calls are **reviewed, not
// proven**. Everything they hand their reads to is driven: `Ssh.Capture` is the
// production retention, `Ssh.retain` is the production function the daemon
// transport and `Core.Scripted` both call, and `Core.Scripted` feeds it in
// `Ssh.read_bytes` pieces so the head/ring arithmetic meets the same boundaries
// a real drain would produce.
//
// What is driven below: the two ends survive at, one below and one above the
// ceiling; the digest covers every byte including the dropped ones; the receipt's
// count is the total and not the retained amount; a stream that fitted is
// byte-identical with no marker in it; the ring returns the true last bytes
// whatever the read sizes were; an exit marker split across two reads is still
// found; a command far larger than the ceiling settles with its own exit code
// rather than `indeterminate`; and the peak allocation does not move with the
// output.

/// One buffer holding what a supervised command's stdout looks like on the wire:
/// the identity line first, `body_len` bytes of the command's own output, the
/// exit line last.
///
/// Built in a single allocation on purpose — the bounded-memory gate runs this at
/// 32 MiB, and a fixture that copied itself would be the thing that grew.
///
/// The body's last byte is always a newline, so the exit marker starts a line at
/// every length. Without that a fixture would put the marker on the end of a line
/// of output, `parseShell` would not recognise it, and every gate below would be
/// measuring a broken fixture instead of the ceiling.
fn wireOutput(gpa: std.mem.Allocator, nonce: u64, body_len: usize, code: i32) ![]u8 {
    var head_buf: [96]u8 = undefined;
    var tail_buf: [64]u8 = undefined;
    const head = try std.fmt.bufPrint(
        &head_buf,
        "__TERMINUS_START_{d}__ pid=4242 pgid=4242 token=99\n",
        .{nonce},
    );
    const tail = try std.fmt.bufPrint(&tail_buf, "__TERMINUS_EXIT_{d}__ code={d}\n", .{ nonce, code });

    const out = try gpa.alloc(u8, head.len + body_len + tail.len);
    @memcpy(out[0..head.len], head);
    const middle = out[head.len..][0..body_len];
    for (middle, 0..) |*ch, i| {
        ch.* = if (i + 1 == body_len or (i + 1) % 64 == 0)
            '\n'
        else
            // Printable, never a marker, never a newline of its own.
            '0' + @as(u8, @intCast(i % 64));
    }
    @memcpy(out[head.len + body_len ..], tail);
    return out;
}

test "gate: the output ceiling keeps both ends at the boundary and drops only above it" {
    const t = std.testing;
    const ceiling = Ssh.output_ceiling.total();

    // One below, exactly at, and one above. The middle case is the one an
    // off-by-one would take: a ceiling that dropped a byte at exactly its own
    // size would report `truncated` on a stream it had every byte of.
    const cases = [_]struct { total: usize, dropped: u64 }{
        .{ .total = ceiling - 1, .dropped = 0 },
        .{ .total = ceiling, .dropped = 0 },
        .{ .total = ceiling + 1, .dropped = 1 },
    };

    var checked: usize = 0;
    for (cases) |case| {
        checked += 1;
        const payload = try body(t.allocator, case.total);
        defer t.allocator.free(payload);

        var arena_state = std.heap.ArenaAllocator.init(t.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        var output: Ssh.Retained = .{};
        const result = try Ssh.retain(
            arena,
            .{ .exit_code = 0, .stdout = payload, .stderr = "" },
            &output,
            Ssh.read_bytes,
        );

        // The count is of everything that passed, and the digest is of exactly
        // those bytes — the same digest whether or not a middle was dropped,
        // which is the property that makes a truncated run auditable.
        try t.expectEqual(@as(u64, case.total), output.stdout.bytes);
        try t.expectEqualStrings(try hexOf(arena, payload), output.stdout.sha256[0..]);
        try t.expectEqual(case.dropped > 0, output.stdout.truncated);

        if (case.dropped == 0) {
            // Byte-for-byte what arrived, and no marker anywhere in it. Both
            // halves matter: the marker's absence is what makes its presence
            // mean something.
            //
            // Compared by hand rather than with `expectEqualSlices`, which
            // prints its diff a byte at a time and dies of it at a megabyte —
            // the failure has to be readable or this gate cannot be acted on.
            try t.expectEqual(payload.len, result.stdout.len);
            if (std.mem.indexOfDiff(u8, payload, result.stdout)) |at| {
                std.debug.print(
                    \\
                    \\a stream that fitted under the ceiling came back altered.
                    \\
                    \\  {d} bytes passed, first difference at byte {d}
                    \\  arrived 0x{X:0>2}, came back 0x{X:0>2}
                    \\
                    \\Nothing was dropped, so the rendering had to be the stream itself.
                    \\
                , .{ case.total, at, payload[at], result.stdout[at] });
                return error.RetainedStreamAltered;
            }
            try t.expect(std.mem.indexOf(u8, result.stdout, Ssh.gap_marker) == null);
        } else {
            // Both ends whole, which is what the two markers live in.
            try t.expect(std.mem.startsWith(u8, result.stdout, payload[0..Ssh.output_ceiling.head]));
            try t.expect(std.mem.endsWith(u8, result.stdout, payload[payload.len - Ssh.output_ceiling.tail ..]));
            // And the published number a reader acts on is how much is missing.
            const said = try std.fmt.allocPrint(arena, "{s} dropped={d} of {d} byte(s)", .{
                Ssh.gap_marker, case.dropped, case.total,
            });
            try t.expect(std.mem.indexOf(u8, result.stdout, said) != null);
            // The gap sits exactly between the two ends, on a line of its own,
            // and what surrounds it is the ceiling to the byte — so `truncated`
            // and the retained size cannot disagree.
            const at = std.mem.indexOf(u8, result.stdout, Ssh.gap_marker).?;
            try t.expectEqual(Ssh.output_ceiling.head + 1, at);
            const after = std.mem.indexOfScalarPos(u8, result.stdout, at, '\n').? + 1;
            try t.expectEqual(Ssh.output_ceiling.tail, result.stdout.len - after);
        }
    }
    try t.expectEqual(@as(usize, 3), checked);
}

test "gate: the tail ring returns the last bytes of the stream whatever the read boundaries were" {
    const t = std.testing;
    // Small enough to check exhaustively, and misaligned on purpose: a ring
    // whose two-span wrapping copy or whose eviction arithmetic is wrong shows
    // up here at sizes a person can hold, and not only at 512 KiB where the
    // reads happen to divide it evenly.
    const tiny: Ssh.Ceiling = .{ .head = 8, .tail = 13 };

    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const payload = try body(t.allocator, 200);
    defer t.allocator.free(payload);

    var checked: usize = 0;
    for ([_]usize{ 1, 2, 3, 5, 7, 11, 17 }) |piece| {
        for ([_]usize{ 0, 1, 7, 8, 9, 20, 21, 22, 63, 64, 128, 199, 200 }) |total| {
            checked += 1;
            var capture: Ssh.Capture = .init(arena, tiny);
            var offset: usize = 0;
            while (offset < total) {
                const end = @min(offset + piece, total);
                try capture.push(payload[offset..end]);
                offset = end;
            }
            const passed = capture.passed();
            try t.expectEqual(@as(u64, total), passed.bytes);
            try t.expectEqualStrings(try hexOf(arena, payload[0..total]), passed.sha256[0..]);
            try t.expectEqual(total > tiny.total(), passed.truncated);

            const rendered = try capture.render(arena);
            const kept_head = @min(total, tiny.head);
            try t.expect(std.mem.startsWith(u8, rendered, payload[0..kept_head]));
            const kept_tail = @min(total - kept_head, tiny.tail);
            try t.expect(std.mem.endsWith(u8, rendered, payload[total - kept_tail .. total]));
            if (total <= tiny.total()) try t.expectEqualSlices(u8, payload[0..total], rendered);
        }
    }
    // Counted, so a loop that stopped iterating fails rather than passing over
    // an empty region.
    try t.expectEqual(@as(usize, 7 * 13), checked);
}

test "gate: a command far larger than the output ceiling still reports its own exit code" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "exec_ceiling_huge");
    defer h.deinit();

    var execution = try h.begin();
    defer execution.deinit();
    try execution.connecting();

    // Four times the ceiling, so the middle is unambiguously gone.
    const wire = try wireOutput(t.allocator, execution.nonce, 4 * Ssh.output_ceiling.total(), 42);
    defer t.allocator.free(wire);
    try t.expect(wire.len > Ssh.output_ceiling.total());

    var script = Core.Scripted.init(h.arena, &.{.{
        .reply = .{
            .exit_code = 0, // the channel's, never the command's
            .stdout = wire,
            .stderr = "",
        },
    }});

    const result = try Core.execution.runCommand(&execution, script.executor(), "yes | head -c 4M", null);
    try t.expect(result == .ran);

    // The whole point. A head-only cap loses the exit marker, and this run then
    // reads `indeterminate` — a command whose status was never in doubt reported
    // as unknown, which is strictly worse than the memory it saved.
    //
    // A nonzero code on purpose: `failed` here is the command's own answer, and
    // a `42` that survived four megabytes of output cannot have come from a
    // default.
    try t.expect(result.ran.status != .indeterminate);
    try t.expectEqualStrings("failed", result.ran.status.text());
    try t.expectEqual(@as(?i32, 42), result.ran.exit_code);
    // And a tail-only cap loses this, so the attempt could not be reconciled.
    try t.expectEqual(@as(i64, 4242), result.ran.identity.?.pid);
    try t.expectEqual(@as(i64, 4242), result.ran.identity.?.pgid.?);

    // The caller cannot mistake this for complete output.
    try t.expect(result.ran.output.?.stdout.truncated);
    try t.expect(std.mem.indexOf(u8, result.ran.stdout, Ssh.gap_marker) != null);
    try t.expect(result.ran.stdout.len < wire.len);

    const row = try h.terminalRow(execution.id());
    try t.expectEqualStrings("failed", row.status.?);
    try t.expectEqual(@as(?i64, 42), row.exit_code);
    // The true total that passed. `observed.stdout.len` was recorded here and
    // is none of the three numbers a reader could want: not the total, not the
    // retained amount, and not even a prefix of either once a middle is gone.
    try t.expectEqual(@as(?i64, @intCast(wire.len)), row.stdout_bytes);
    try t.expect(row.stdout_bytes.? > @as(i64, @intCast(result.ran.stdout.len)));
    // The digest of a truncated run is the digest of the same bytes hashed
    // whole — the receipt proves what came out of a command whose middle
    // nobody was given.
    try t.expectEqualStrings(try hexOf(h.arena, wire), row.stdout_sha256.?);
    try t.expectEqual(@as(?bool, true), row.stdout_truncated);
    // stderr said nothing and must not be described as truncated for it.
    try t.expectEqual(@as(?i64, 0), row.stderr_bytes);
    try t.expectEqual(@as(?bool, false), row.stderr_truncated);
    try t.expectEqualStrings(Ssh.empty_sha256, row.stderr_sha256.?);
}

test "gate: an exit marker split across two reads is still found" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "exec_ceiling_straddle");
    defer h.deinit();

    var execution = try h.begin();
    defer execution.deinit();
    try execution.connecting();

    const wire = try wireOutput(t.allocator, execution.nonce, 3 * Ssh.output_ceiling.total(), 7);
    defer t.allocator.free(wire);

    // Where the exit line starts, found the way `parseShell` would.
    const marker = try std.fmt.allocPrint(h.arena, "__TERMINUS_EXIT_{d}__ ", .{execution.nonce});
    const exit_at = std.mem.lastIndexOf(u8, wire, marker).?;

    // A read size whose last boundary lands *inside* that line. This is the case
    // a "keep the last read" tail would fail and a ring does not: the ring holds
    // the last N bytes of the stream, and where the reads stopped is not one of
    // its inputs.
    const mid = wire.len - (wire.len - exit_at) / 2;
    var script = Core.Scripted.init(h.arena, &.{.{ .reply = .{
        .exit_code = 0,
        .stdout = wire,
        .stderr = "",
    } }});
    script.reads_of = mid / 3;
    // Asserted, not assumed: a fixture that stopped straddling would make the
    // rest of this gate vacuous.
    const boundary = script.reads_of * 3;
    try t.expect(boundary > exit_at);
    try t.expect(boundary < wire.len);

    const result = try Core.execution.runCommand(&execution, script.executor(), "big", null);
    try t.expect(result.ran.status != .indeterminate);
    try t.expectEqualStrings("failed", result.ran.status.text());
    try t.expectEqual(@as(?i32, 7), result.ran.exit_code);
    try t.expectEqual(@as(i64, 4242), result.ran.identity.?.pid);
    try t.expect(result.ran.output.?.stdout.truncated);
}

test "gate: a run under the output ceiling is unchanged and its receipt says nothing was dropped" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "exec_ceiling_fits");
    defer h.deinit();

    var execution = try h.begin();
    defer execution.deinit();
    try execution.connecting();

    // Comfortably under, which is every command anybody actually runs.
    const wire = try wireOutput(t.allocator, execution.nonce, 4096, 0);
    defer t.allocator.free(wire);

    var script = Core.Scripted.init(h.arena, &.{.{ .reply = .{
        .exit_code = 0,
        .stdout = wire,
        .stderr = try h.arena.dupe(u8, "a warning\n"),
    } }});

    const result = try Core.execution.runCommand(&execution, script.executor(), "ls", null);
    try t.expectEqualStrings("completed", result.ran.status.text());
    try t.expectEqual(@as(?i32, 0), result.ran.exit_code);

    // Byte-identical to what the ceiling-free version produced: the two marker
    // lines removed and nothing else touched.
    const expected = try Core.supervisor.parseShell(h.arena, execution.nonce, wire, "a warning\n");
    try t.expectEqualStrings(expected.stdout, result.ran.stdout);
    try t.expectEqualStrings("a warning\n", result.ran.stderr);
    try t.expect(std.mem.indexOf(u8, result.ran.stdout, Ssh.gap_marker) == null);
    try t.expect(!result.ran.output.?.stdout.truncated);
    try t.expect(!result.ran.output.?.stderr.truncated);

    const row = try h.terminalRow(execution.id());
    // Still the total that passed rather than the marker-stripped length, and
    // the two differ even here — which is why this is the number to record.
    try t.expectEqual(@as(?i64, @intCast(wire.len)), row.stdout_bytes);
    try t.expect(row.stdout_bytes.? > @as(i64, @intCast(result.ran.stdout.len)));
    try t.expectEqualStrings(try hexOf(h.arena, wire), row.stdout_sha256.?);
    try t.expectEqual(@as(?bool, false), row.stdout_truncated);
    try t.expectEqual(@as(?i64, "a warning\n".len), row.stderr_bytes);
    try t.expectEqualStrings(try hexOf(h.arena, "a warning\n"), row.stderr_sha256.?);
    try t.expectEqual(@as(?bool, false), row.stderr_truncated);
}

test "gate: the output ceiling's tail cannot lose the exit marker" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // The widest nonce there is, so the marker text is at its longest.
    const nonce = std.math.maxInt(u64);
    const wrapped = try Core.supervisor.wrapShell(arena, "true", nonce);
    const printed = try std.fmt.allocPrint(arena, "__TERMINUS_EXIT_{d}__ code=", .{nonce});
    // The supervisor really does print this text — without this the bound below
    // is arithmetic over a string nothing emits.
    try t.expect(std.mem.indexOf(u8, wrapped, printed) != null);

    // Plus the widest exit status and a CRLF for a shell that sends one.
    const widest = printed.len + std.fmt.comptimePrint("{d}", .{std.math.minInt(i32)}).len + 2;
    try t.expectEqual(widest, Core.execution.exit_marker_max_line);
    // Held at compile time in `execution.zig` as well; asserted here so the
    // literal and the line it describes cannot drift apart silently.
    try t.expect(Ssh.output_ceiling.tail >= widest);
    try t.expect(Ssh.output_ceiling.tail >= Ssh.read_bytes);
}

test "gate: the truncation notice appears exactly when something was dropped" {
    const t = std.testing;
    var f = try TextFixture.init(t.allocator, "echo hi\n");
    defer f.deinit();

    // No reading at all: a session exec never sees the two streams apart, and a
    // notice there would be about a ceiling that never ran.
    try t.expectEqual(@as(?[]const u8, null), cmd_exec.truncationNotice(&f.ctx, null));
    // A reading with nothing dropped must stay silent, or a reader learns to
    // ignore the line that matters.
    try t.expectEqual(@as(?[]const u8, null), cmd_exec.truncationNotice(&f.ctx, .{}));

    var said: usize = 0;
    for ([_]struct { out: bool, err: bool, which: []const u8 }{
        .{ .out = true, .err = false, .which = "stdout exceeded" },
        .{ .out = false, .err = true, .which = "stderr exceeded" },
        .{ .out = true, .err = true, .which = "stdout and stderr exceeded" },
    }) |case| {
        said += 1;
        const note = cmd_exec.truncationNotice(&f.ctx, .{
            .stdout = .{ .truncated = case.out },
            .stderr = .{ .truncated = case.err },
        }).?;
        try t.expect(std.mem.startsWith(u8, note, case.which));
        // The marker a parser would find, so the two readers are told the same
        // thing in the terms each of them can act on.
        try t.expect(std.mem.indexOf(u8, note, Ssh.gap_marker) != null);
        // And the way out of the ceiling, rather than only the news of it.
        try t.expect(std.mem.indexOf(u8, note, "terminus pull") != null);
    }
    try t.expectEqual(@as(usize, 3), said);
}

test "gate: the skill document describes the output ceiling an agent will meet" {
    const t = std.testing;
    const heading = "## What a command's output does when there is a lot of it";
    // Found by name, never by position: this document is appended to.
    const at = std.mem.indexOf(u8, skill_doc.text, heading) orelse {
        std.debug.print(
            \\
            \\skill/SKILL.md has no "{s}" section. An agent that does not know the
            \\ceiling exists will read a stdout whose middle is gone and draw a conclusion
            \\from it, which is the one failure this slice is about.
            \\
        , .{heading});
        return error.SkillCeilingSectionMissing;
    };
    const rest = skill_doc.text[at + heading.len ..];
    const section = rest[0 .. std.mem.indexOf(u8, rest, "\n## ") orelse rest.len];

    var claims: usize = 0;
    for ([_][]const u8{
        // The marker an agent has to look for, spelled exactly as the code
        // emits it.
        Ssh.gap_marker,
        // The rule that makes the marker worth looking for in both directions.
        "If it is absent, you have every byte",
        // The three numbers, and the fact that the first is not what came back.
        "`stdoutBytes`",
        "`stdoutSha256`",
        "`stdoutTruncated`",
        "not the amount you were given",
        // Why both ends, which is the thing a reader would otherwise assume is
        // arbitrary — and the outcome a head-only cap would produce.
        "indeterminate",
        // What to do instead of hoping for a bigger ceiling.
        "terminus pull",
    }) |needle| {
        if (std.mem.indexOf(u8, section, needle) == null) {
            std.debug.print(
                \\
                \\skill/SKILL.md: the output-ceiling section no longer states "{s}".
                \\
            , .{needle});
            return error.SkillCeilingClaimMissing;
        }
        claims += 1;
    }
    try t.expectEqual(@as(usize, 8), claims);

    // The size the document publishes is the size the code enforces. A document
    // naming a different number would send an agent looking for a marker at the
    // wrong point, or tell it output was complete when it was not.
    const published = try std.fmt.allocPrint(t.allocator, "**{d} MiB**", .{Ssh.output_ceiling.total() / (1 << 20)});
    defer t.allocator.free(published);
    try t.expect(std.mem.indexOf(u8, section, published) != null);
    const halves = try std.fmt.allocPrint(t.allocator, "first {d} KiB and the last {d} KiB", .{
        Ssh.output_ceiling.head / 1024, Ssh.output_ceiling.tail / 1024,
    });
    defer t.allocator.free(halves);
    try t.expect(std.mem.indexOf(u8, section, halves) != null);
}

// --- gate: bounded memory, the output side -----------------------------------

test "gate: the output ceiling's peak allocation does not grow with the output" {
    const t = std.testing;

    // The same fixed budget for every size, and every allocation the retention
    // path makes comes out of it: the head buffer, the tail ring, and the
    // rendering handed back to the caller. Generous enough for those three at
    // the ceiling, and far below the larger run — so anything proportional to
    // the output fails on the big one while passing on the small one, which is
    // the signature this gate exists to catch. The version this replaced
    // appended every byte to an `ArrayList` and would fail both.
    //
    // `sizes` is where a by-hand run over 10 GiB goes.
    const budget = 8 << 20;
    const ceiling = Ssh.output_ceiling.total();
    const sizes = [_]usize{ ceiling * 2, ceiling * 32 };

    var proven: usize = 0;
    // The first size's allocation, which the second one has to match exactly.
    var settled: ?usize = null;
    for (sizes) |total| {
        proven += 1;
        // On the test allocator, not the measured one: the fixture stands in for
        // a remote host and its cost is not the ceiling's.
        const wire = try wireOutput(t.allocator, 7, total, 3);
        defer t.allocator.free(wire);

        const buffer = try t.allocator.alloc(u8, budget);
        defer t.allocator.free(buffer);
        var fixed = std.heap.FixedBufferAllocator.init(buffer);
        const arena = fixed.allocator();

        // `Scripted` dupes every command it is handed onto the allocator it was
        // built with and appends it to a list that never shrinks — the harness's
        // own growth, not the ceiling's. Given a zero-length allocator both fail
        // and are swallowed, so `seen` stays empty and what is being measured is
        // the retention path.
        var none = std.heap.FixedBufferAllocator.init(&[_]u8{});
        var script = Core.Scripted.init(none.allocator(), &.{.{ .reply = .{
            .exit_code = 0,
            .stdout = wire,
            .stderr = "",
        } }});

        var output: Ssh.Retained = .{};
        const result = try script.executor().execRetained(arena, "big", null, &output);
        try t.expectEqual(@as(u64, wire.len), output.stdout.bytes);
        try t.expect(output.stdout.truncated);
        try t.expectEqual(@as(usize, 0), script.seen.items.len);
        // The retained rendering is the ceiling plus one gap line, at both
        // sizes — so what came back is bounded and not merely what was counted.
        try t.expect(result.stdout.len > ceiling);
        try t.expect(result.stdout.len < ceiling + 512);

        std.debug.print(
            "\n  output bounded-memory gate: {d} bytes passed, {d} bytes allocated (budget {d})\n",
            .{ wire.len, fixed.end_index, budget },
        );
        try t.expect(fixed.end_index < budget);
        // Thirty-two times the bytes, and the allocation has to be the *same*
        // number — not merely another one under the budget. `< budget` alone
        // would pass an implementation allocating `total / 1000`, which is
        // proportional to the output and fits twice over. Equality is what says
        // the cost does not depend on the size, which is the whole claim.
        if (settled) |before| {
            if (fixed.end_index != before) {
                std.debug.print(
                    \\
                    \\the output ceiling's allocation moved with the size of the output.
                    \\
                    \\  {d} bytes passed -> {d} bytes allocated
                    \\  {d} bytes passed -> {d} bytes allocated
                    \\
                    \\Both fit the budget, so neither run failed on its own. What fails is that
                    \\they differ: a cost that tracks the output is the unbounded drain this
                    \\ceiling was built to replace, wearing a smaller constant.
                    \\
                , .{ sizes[0], before, total, fixed.end_index });
                return error.OutputAllocationTracksTheOutputSize;
            }
        } else settled = fixed.end_index;
    }
    try t.expectEqual(@as(usize, 2), proven);
}

// --- gates: the command's own line endings ------------------------------------

/// A `Ctx` over a scratch directory, for the two gates that read a command out
/// of a file the way the command itself does.
const TextFixture = struct {
    io: std.Io,
    threaded: *std.Io.Threaded,
    arena_state: *std.heap.ArenaAllocator,
    arena: std.mem.Allocator,
    out: *Cli.Output,
    discard: *std.Io.Writer.Discarding,
    environ: *std.process.Environ.Map,
    ctx: Cli.Ctx,
    path: []const u8,
    allocator: std.mem.Allocator,

    var counter: std.atomic.Value(u32) = .init(0);

    fn init(allocator: std.mem.Allocator, content: []const u8) !TextFixture {
        const threaded = try allocator.create(std.Io.Threaded);
        threaded.* = .init(allocator, .{});
        const io = threaded.io();
        std.Io.Dir.cwd().createDirPath(io, scratch_dir) catch {};

        const arena_state = try allocator.create(std.heap.ArenaAllocator);
        arena_state.* = std.heap.ArenaAllocator.init(allocator);
        const arena = arena_state.allocator();

        const n = counter.fetchAdd(1, .monotonic);
        const path = try std.fmt.allocPrint(arena, "{s}/exec_cmdfile_{d}_{d}.sh", .{
            scratch_dir, std.Thread.getCurrentId(), n,
        });
        {
            const file = try std.Io.Dir.cwd().createFile(io, path, .{});
            defer file.close(io);
            var buf: [4096]u8 = undefined;
            var writer = file.writerStreaming(io, &buf);
            try writer.interface.writeAll(content);
            try writer.interface.flush();
        }

        const discard = try allocator.create(std.Io.Writer.Discarding);
        discard.* = .init(&.{});
        const out = try allocator.create(Cli.Output);
        out.* = .{ .writer = &discard.writer };
        const environ = try allocator.create(std.process.Environ.Map);
        environ.* = .init(arena);

        return .{
            .io = io,
            .threaded = threaded,
            .arena_state = arena_state,
            .arena = arena,
            .out = out,
            .discard = discard,
            .environ = environ,
            .ctx = .{ .io = io, .arena = arena, .environ = environ, .out = out, .now = 1000 },
            .path = path,
            .allocator = allocator,
        };
    }

    fn deinit(f: *TextFixture) void {
        std.Io.Dir.cwd().deleteFile(f.io, f.path) catch {};
        f.environ.deinit();
        f.allocator.destroy(f.environ);
        f.allocator.destroy(f.out);
        f.allocator.destroy(f.discard);
        f.arena_state.deinit();
        f.allocator.destroy(f.arena_state);
        f.threaded.deinit();
        f.allocator.destroy(f.threaded);
    }
};

const crlf_script = "echo one\r\nif [ x = x ]; then\r\n  echo two\r\nfi\r";

test "gate: the command keeps its carriage returns unless normalization is asked for" {
    const t = std.testing;
    var f = try TextFixture.init(t.allocator, crlf_script);
    defer f.deinit();

    const parsed = try args.parse(f.arena, &.{ "box", "--cmd-file", f.path });
    const got = (try Cli.trailingContent(&f.ctx, &parsed, "cmd-file", 1)).?;

    // 0.1.10 rewrote these by default. Byte-for-byte is the 0.2.0 contract, and
    // it is what the receipt's digest is taken over, so a rewrite here would
    // make the command the operator typed and the command the ledger describes
    // two different strings.
    try t.expectEqualStrings(crlf_script, got);
    const reading = Cli.commandLineEndings();
    // Reported, which is the half of the old behaviour worth keeping: an
    // operator whose `true\r` did not match `true` now has the sentence that
    // explains it.
    try t.expectEqual(@as(usize, 4), reading.carriage_returns);
    try t.expect(!reading.normalized);
}

test "gate: --normalize-lf rewrites the command's line endings and says it did" {
    const t = std.testing;
    var f = try TextFixture.init(t.allocator, crlf_script);
    defer f.deinit();

    const parsed = try args.parse(f.arena, &.{ "box", "--cmd-file", f.path, "--normalize-lf" });
    const got = (try Cli.trailingContent(&f.ctx, &parsed, "cmd-file", 1)).?;

    try t.expectEqualStrings("echo one\nif [ x = x ]; then\n  echo two\nfi\n", got);
    try t.expect(std.mem.indexOfScalar(u8, got, '\r') == null);
    const reading = Cli.commandLineEndings();
    // The count is of what was read, before the rewrite — so the published
    // number says how much was changed rather than reporting zero because it
    // was changed.
    try t.expectEqual(@as(usize, 4), reading.carriage_returns);
    try t.expect(reading.normalized);
}

test "gate: a command with no carriage returns reports none and is not copied" {
    const t = std.testing;
    var f = try TextFixture.init(t.allocator, "echo one\necho two\n");
    defer f.deinit();

    const parsed = try args.parse(f.arena, &.{ "box", "--cmd-file", f.path });
    const got = (try Cli.trailingContent(&f.ctx, &parsed, "cmd-file", 1)).?;
    try t.expectEqualStrings("echo one\necho two\n", got);
    // A zero here is what makes the two gates above mean something: the reading
    // is per-call state, and one that never reset would report the last
    // command's carriage returns for this one.
    try t.expectEqual(@as(usize, 0), Cli.commandLineEndings().carriage_returns);
    try t.expect(!Cli.commandLineEndings().normalized);
}

// --- gate: flag registration --------------------------------------------------

test "gate: every boolean flag exec takes is registered, so none swallows the next argument" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // A flag missing from `args.bool_flags` is not a compile error and is
    // invisible to any gate that calls this command's helpers directly: the
    // parser falls through to `--flag <value>`, so the flag written last fails
    // with "a flag is missing its value" and one written before another
    // silently eats it. `--restart`, `--resume` and `--no-clobber` each shipped
    // that way and each was found by running the binary.
    //
    // Driven from a list of this command's own booleans rather than asserted
    // against `bool_flags` itself: the contents of that array are every
    // command's business and a gate over them fails on the next flag anybody
    // adds, while what this command needs to know is only that *its* flags
    // parse as booleans.
    var checked: usize = 0;
    for ([_][]const u8{
        "json",  "login", "strict",    "read-only",
        "force", "stdin", "no-daemon", "normalize-lf",
    }) |flag| {
        checked += 1;
        const alone = try args.parse(arena, &.{
            "box",
            try std.fmt.allocPrint(arena, "--{s}", .{flag}),
        });
        try t.expect(alone.boolean(flag));
        try t.expectEqual(@as(usize, 1), alone.positionals.len);
        try t.expectEqual(@as(?[]const u8, null), alone.flag(flag));

        // And it consumes nothing when something does follow it.
        const followed = try args.parse(arena, &.{
            "box",
            try std.fmt.allocPrint(arena, "--{s}", .{flag}),
            "--json",
        });
        try t.expect(followed.boolean(flag));
        try t.expect(followed.boolean("json"));
        try t.expectEqual(@as(usize, 1), followed.positionals.len);
    }
    // Counted, so a loop that stopped iterating fails rather than passing over
    // an empty region.
    try t.expectEqual(@as(usize, 8), checked);

    // The sharpest form of the bug, with the flag added last. `--normalize-lf`
    // written before the command would, unregistered, eat `--cmd` as its value
    // — so the command text would go missing and `exec` would refuse a command
    // the operator did supply. Both halves are asserted, because the flag count
    // alone passes if the parser drops the argument instead of consuming it.
    const before = try args.parse(arena, &.{ "box", "--normalize-lf", "--cmd", "uname -a" });
    try t.expect(before.boolean("normalize-lf"));
    try t.expectEqualStrings("uname -a", before.flag("cmd").?);
    try t.expectEqual(@as(usize, 1), before.positionals.len);
    try t.expectEqual(@as(?[]const u8, null), before.flag("normalize-lf"));

    // `--stdin-file` is the other half of the same rule from the other side: it
    // takes a value, so it must *not* be registered, or the path it was given
    // would be parsed as a positional and read as part of the command.
    const with_path = try args.parse(arena, &.{ "box", "--stdin-file", "./payload.bin", "--cmd", "cat" });
    try t.expectEqualStrings("./payload.bin", with_path.flag("stdin-file").?);
    try t.expect(!with_path.boolean("stdin-file"));
    try t.expectEqual(@as(usize, 1), with_path.positionals.len);
}

// --- gate: the document -------------------------------------------------------

test "gate: the skill document describes the input channel it now has" {
    const t = std.testing;
    const heading = "## Feeding a command its own standard input";
    // Found by name. Never by position and never by counting sections: this
    // document is appended to, and a gate that counted would fail on the next
    // section somebody adds while a gate that indexed would silently read a
    // different one.
    const at = std.mem.indexOf(u8, skill_doc.text, heading) orelse {
        std.debug.print(
            \\
            \\skill/SKILL.md has no "{s}" section. An agent that cannot read
            \\about `--stdin-file` will keep base64-ing payloads into command text, which
            \\is the thing this channel replaces.
            \\
        , .{heading});
        return error.SkillInputSectionMissing;
    };
    const rest = skill_doc.text[at + heading.len ..];
    // To the next `## ` heading, so the reading is of this section and not of
    // the rest of the file.
    const section = rest[0 .. std.mem.indexOf(u8, rest, "\n## ") orelse rest.len];

    var claims: usize = 0;
    for ([_][]const u8{
        // The flag, and the distinction that makes it a different flag from
        // `--stdin`.
        "`--stdin-file`",
        "not the bytes of the command",
        // Why an agent may hand it a binary at all.
        "byte for byte",
        // The two numbers on the receipt, and whose answer they are.
        "`stdinBytes`",
        "`stdinSha256`",
        "accepted",
        // The failure that must not be read as a smaller success.
        "indeterminate",
        // The one combination that is refused.
        "session",
    }) |needle| {
        if (std.mem.indexOf(u8, section, needle) == null) {
            std.debug.print(
                \\
                \\skill/SKILL.md: the standard-input section no longer states "{s}".
                \\
            , .{needle});
            return error.SkillInputClaimMissing;
        }
        claims += 1;
    }
    try t.expectEqual(@as(usize, 8), claims);

    // The flag is in the usage the command prints, so `--help` and the document
    // do not disagree about whether it exists.
    try t.expect(std.mem.indexOf(u8, cmd_exec.usage, "--stdin-file") != null);

    // And the line-ending default the document now publishes is the one the
    // code has. Both directions: the old sentence promised normalization and
    // the new one promises the opposite, so a document left behind would be
    // exactly wrong rather than merely stale.
    var endings: usize = 0;
    for ([_][]const u8{
        "`--normalize-lf`",
        "sent as they were read",
    }) |needle| {
        if (std.mem.indexOf(u8, skill_doc.text, needle) == null) {
            std.debug.print(
                \\
                \\skill/SKILL.md: the command-input section no longer states "{s}". 0.2.0
                \\stopped normalizing CRLF by default; a document still promising the 0.1.10
                \\behaviour tells an agent its `\r` will be removed for it.
                \\
            , .{needle});
            return error.SkillLineEndingClaimMissing;
        }
        endings += 1;
    }
    try t.expectEqual(@as(usize, 2), endings);
    // The 0.1.10 promise, gone rather than merely surrounded by new text.
    try t.expect(std.mem.indexOf(u8, skill_doc.text, "is normalized from CRLF/CR to LF") == null);
    try t.expect(std.mem.indexOf(u8, cmd_exec.usage, "--normalize-lf") != null);
}

// --- gate: the empty-stream digest is not a typed literal ----------------------

test "gate: the empty-stream digest matches the hash of nothing" {
    const t = std.testing;
    var buf: [Core.digest.hex_len]u8 = undefined;
    // `Ssh.Accepted`'s zero value carries this, so a receipt for a channel that
    // accepted nothing publishes a real digest of nothing rather than a
    // placeholder. A literal can be mistyped; this is the one thing that stops
    // it.
    try t.expectEqualStrings(Core.digest.hex("", &buf), Ssh.empty_sha256);
    try t.expectEqual(@as(usize, Core.digest.hex_len), Ssh.empty_sha256.len);
    const zero: Ssh.Accepted = .{};
    try t.expectEqual(@as(u64, 0), zero.bytes);
    try t.expectEqualStrings(Ssh.empty_sha256, zero.sha256[0..]);

    // And an empty source is a real input, not a skipped one: the remote still
    // has to be told the input ended, or a `cat` waiting on fd 0 never returns.
    var reader: std.Io.Reader = .fixed("");
    var recorder: Recorder = .{ .gpa = t.allocator };
    defer recorder.deinit();
    var taken: Ssh.Accepted = .{};
    try Ssh.pumpInput(&reader, recorder.sink(), &taken);
    try t.expectEqual(@as(u64, 0), taken.bytes);
    try t.expectEqualStrings(Ssh.empty_sha256, taken.sha256[0..]);
    try t.expectEqual(@as(usize, 1), recorder.ends);
}
