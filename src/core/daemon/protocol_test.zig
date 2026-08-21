//! Gates for the CLI↔daemon wire: the frame, the encoding inside it, and the
//! bound that says a reply cannot exceed it.
//!
//! **What is driven, and what is not.** There is no live server here — the test
//! host's key lives only inside a database these tests may not touch, and a
//! libssh2 channel cannot be stood up without one. So the daemon's *channel* is
//! reviewed, not proven, and the one-line choice in `Server.runOn` between
//! `Ssh.exec` and `Ssh.execRetained` is reviewed too.
//!
//! Everything else is driven for real, because the protocol needs no socket: a
//! `std.Io.Writer` over a buffer and a `std.Io.Reader` over the bytes it
//! produced are the same two interfaces the socket presents. Driven this way:
//!
//!  * a reply several times the old 1 MiB frame is written and read back whole;
//!  * a reply at exactly the frame limit, one byte under, and one byte over;
//!  * the header is the length of the payload that follows it — the one
//!    disagreement in this protocol that hangs a reader instead of failing it;
//!  * every byte value survives the wire unchanged, which is the property JSON
//!    escaping alone could not be relied on for;
//!  * output under the ceiling comes back byte-for-byte with no marker and no
//!    truncation flag;
//!  * output over the ceiling comes back with the same rendering and the same
//!    three numbers the direct transport produces for the same stream;
//!  * each stream's accounting comes back as its own, so a reply cannot carry
//!    one stream's digest for both;
//!  * the reply-building path's peak allocation does not move with the output;
//!  * a peer speaking another version is refused by name rather than misread,
//!    in both directions and without either side blocking.
//!
//! `transport_test.zig` carries the other half: the same protocol over a real
//! socket, into a real ledger.
const std = @import("std");
const protocol = @import("protocol.zig");
const Ssh = @import("../ssh/Client.zig");
const Core = @import("../core.zig");

// --- fixtures ----------------------------------------------------------------

/// Output a shell supervisor produces for a command that ran to completion,
/// padded out to `total` bytes. Shared with `transport_test.zig`.
///
/// The filler is broken into lines and always ends on one, because
/// `supervisor.parseShell` reads the exit status from the *last line* — a
/// fixture whose body ran into the exit marker would make every assertion about
/// an exit code vacuous.
pub fn wireOutput(allocator: std.mem.Allocator, nonce: u64, total: usize, code: i32) ![]u8 {
    const head = try std.fmt.allocPrint(
        allocator,
        "__TERMINUS_START_{d}__ pid=4242 pgid=4242 token=99\n",
        .{nonce},
    );
    defer allocator.free(head);
    const tail = try std.fmt.allocPrint(allocator, "__TERMINUS_EXIT_{d}__ code={d}\n", .{ nonce, code });
    defer allocator.free(tail);

    const out = try allocator.alloc(u8, @max(total, head.len + tail.len + 1));
    @memcpy(out[0..head.len], head);
    const body = out[head.len .. out.len - tail.len];
    for (body, 0..) |*b, i| {
        b.* = if (i + 1 == body.len or (i + 1) % 64 == 0)
            '\n'
        else
            // Printable, never a marker, never a newline of its own.
            '0' + @as(u8, @intCast(i % 64));
    }
    @memcpy(out[out.len - tail.len ..], tail);
    return out;
}

/// Writes one message and reads it straight back, through the real frame on
/// both sides. The reader's buffer is deliberately tiny: a frame no longer has
/// to fit the buffer that reads it, and a gate that handed it a large one would
/// not be testing that.
///
/// Every round trip here also checks that the frame is exactly its header, its
/// payload, and the terminator — nothing more. On a socket a header that
/// overstates its payload is not a failure, it is a reader waiting forever, so
/// the cheapest place to catch it is on every write this file makes.
fn roundTrip(arena: std.mem.Allocator, value: anytype) !struct {
    payload_len: usize,
    frame: []u8,
    response: protocol.Response,
} {
    var out: std.Io.Writer.Allocating = .init(arena);
    try protocol.writeMessage(&out.writer, value);
    const frame = out.written();

    var reader: std.Io.Reader = .fixed(frame);
    const payload = (try protocol.readFrame(&reader, arena)).?;
    if (frame.len != protocol.header_len + payload.len + 1)
        return error.FrameHeaderDisagreesWithPayload;
    return .{
        .payload_len = payload.len,
        .frame = frame,
        .response = try protocol.parseMessage(protocol.Response, arena, payload),
    };
}

// --- gate: the frame carries what the old one could not -----------------------

test "gate: a reply far larger than the old frame arrives whole with its exit code" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Under the ceiling, so nothing is dropped — and still more than twice the
    // 1 MiB stack buffer the client used to read replies through. This is the
    // command that used to settle `indeterminate`: it succeeded, and the
    // transport could not carry its answer.
    const raw = try wireOutput(arena, 77, 900 * 1024, 7);
    var retained: Ssh.Retained = .{};
    const rendered = try Ssh.retain(arena, .{
        .exit_code = 7,
        .stdout = raw,
        .stderr = try arena.alloc(u8, 0),
    }, &retained, Ssh.read_bytes);

    const trip = try roundTrip(arena, protocol.execResponse(rendered, retained));

    // The frame is past the old limit, so a reader that still needed the whole
    // line in a 1 MiB buffer would have failed here rather than passed quietly.
    try t.expect(trip.payload_len > 1 << 20);
    try t.expectEqual(@as(i32, 7), trip.response.exitCode);
    try t.expect(trip.response.ok);

    const stdout = trip.response.stdout.bytes;
    try t.expectEqualSlices(u8, raw, stdout);
    // The real exit code is still readable out of what came back, which is the
    // whole point: `supervisor.parseShell` reads it from the last line.
    const observed = try Core.supervisor.parseShell(arena, 77, stdout, "");
    try t.expectEqual(@as(?i32, 7), observed.exit_code);

    const passed = trip.response.passed.?;
    try t.expectEqual(@as(u64, raw.len), passed.stdout.bytes);
    try t.expect(!passed.stdout.truncated);
}

// --- gate: the frame boundary -------------------------------------------------

/// A response whose payload is exactly `want` bytes.
///
/// Padded through `error` rather than through an output stream, because `error`
/// is the one field of a reply that is a plain JSON string: an ASCII filler's
/// encoded width is its length, so `want` is an exact figure rather than one
/// rounded to a base64 group. What the padding rides on is beside the point —
/// the refusal below is `writeMessage`'s, and it does not care which field made
/// the frame too wide.
fn responseOfPayload(arena: std.mem.Allocator, want: usize) !protocol.Response {
    var response: protocol.Response = .{ .v = protocol.version, .ok = false, .@"error" = "" };
    const envelope = try protocol.payloadLen(response);
    const padding = try arena.alloc(u8, want - envelope);
    @memset(padding, 'e');
    response.@"error" = padding;
    return response;
}

test "gate: a reply at the frame limit passes, one byte over is refused by name" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var proven: usize = 0;
    for ([_]usize{ protocol.max_frame_bytes - 1, protocol.max_frame_bytes }) |want| {
        proven += 1;
        const response = try responseOfPayload(arena, want);
        // Asserted, not assumed: a fixture that missed the limit by a byte would
        // make the two runs below say nothing about the boundary.
        try t.expectEqual(@as(u64, want), try protocol.payloadLen(response));
        const trip = try roundTrip(arena, response);
        try t.expectEqual(want, trip.payload_len);
        try t.expectEqualStrings(response.@"error".?, trip.response.@"error".?);
    }

    // One byte over: refused, and *nothing written*. A frame half-emitted then
    // abandoned would leave the connection carrying a payload with no header.
    const over = try responseOfPayload(arena, protocol.max_frame_bytes + 1);
    var out: std.Io.Writer.Allocating = .init(arena);
    try t.expectError(error.FrameTooLarge, protocol.writeMessage(&out.writer, over));
    try t.expectEqual(@as(usize, 0), out.written().len);
    proven += 1;

    // And a peer that lies in the header is refused before it can make this
    // process allocate on its say-so.
    const lie = try std.fmt.allocPrint(arena, "{x:0>8}", .{protocol.max_frame_bytes + 1});
    var reader: std.Io.Reader = .fixed(lie);
    try t.expectError(error.FrameTooLarge, protocol.readFrame(&reader, arena));
    proven += 1;

    try t.expectEqual(@as(usize, 4), proven);
}

test "gate: the exec reply envelope fits the width the frame bound reserves for it" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Every non-payload field at its widest: the integers at their maxima, both
    // digests at full width, the error string at its cap. `max_exec_payload_bytes`
    // reserves `exec_envelope_bytes` for exactly this, and the comptime assertion
    // that a retained reply always fits a frame is only as true as that reserve.
    const wide_error = try arena.alloc(u8, protocol.max_error_bytes);
    @memset(wide_error, 'e');
    var sha: [Core.digest.hex_len]u8 = undefined;
    @memset(&sha, 'f');
    const widest: protocol.Response = .{
        .v = std.math.maxInt(u32),
        .ok = true,
        .@"error" = wide_error,
        .exitCode = std.math.minInt(i32),
        .passed = .{
            .stdout = .{ .bytes = std.math.maxInt(u64), .sha256 = sha, .truncated = true },
            .stderr = .{ .bytes = std.math.maxInt(u64), .sha256 = sha, .truncated = true },
        },
        .pid = std.math.maxInt(u32),
    };
    const width = try protocol.payloadLen(widest);
    // The reserve covers even this, which carries an error string a successful
    // reply never has.
    try t.expect(width <= protocol.exec_envelope_bytes);
    // And the derivation the comptime assertion rests on really is under the
    // frame, with the ceiling this build ships.
    try t.expect(protocol.max_exec_payload_bytes <= protocol.max_frame_bytes);
}

test "gate: the frame's header is the length of the payload that follows it" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // The one disagreement this protocol can produce that is a *hang* and not an
    // error. `writeMessage` settles the width with a counting pass and then
    // serialises a second time; if the two differ by a byte, a reader on a real
    // socket blocks forever on a remainder that was never sent, and no timeout
    // here rescues it. It did differ once — a field borrowed a digest from a
    // stack slot the two passes read at different depths — and the symptom was a
    // suite that never returned.
    //
    // Driven over the largest reply the retained path produces, because that is
    // the reply the accounting rides on and the widths in question are its.
    const raw = try wireOutput(arena, 13, Ssh.output_ceiling.total() * 2, 3);
    var retained: Ssh.Retained = .{};
    const rendered = try Ssh.retain(arena, .{
        .exit_code = 3,
        .stdout = raw,
        .stderr = try arena.dupe(u8, "e" ** 33),
    }, &retained, Ssh.read_bytes);
    const response = protocol.execResponse(rendered, retained);

    const announced = try protocol.payloadLen(response);
    var out: std.Io.Writer.Allocating = .init(arena);
    try protocol.writeMessage(&out.writer, response);

    // The frame is the header, exactly `announced` payload bytes, and one
    // terminator — measured on the bytes, not inferred from the writer.
    try t.expectEqual(
        @as(u64, protocol.header_len) + announced + 1,
        @as(u64, out.written().len),
    );
    // And the header really carries that number, so the reader and the writer
    // are reading the same figure rather than two that happen to agree in size.
    try t.expectEqual(
        announced,
        try std.fmt.parseInt(u64, out.written()[0..protocol.header_len], 16),
    );
}

test "gate: each stream's accounting comes back as its own, digest and all" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Two streams with different content, so their digests differ and a reply
    // that carried one of them twice cannot pass by coincidence. That is exactly
    // what a reply did: both digests were slices into one reused stack slot, so
    // stdout's receipt claimed stderr's hash — and on the daemon path that hash
    // is the only record of the bytes this process never saw.
    var retained: Ssh.Retained = .{};
    const rendered = try Ssh.retain(arena, .{
        .exit_code = 0,
        .stdout = try wireOutput(arena, 61, 8192, 0),
        .stderr = try arena.dupe(u8, "a warning, and a different one\n"),
    }, &retained, Ssh.read_bytes);

    const trip = try roundTrip(arena, protocol.execResponse(rendered, retained));
    const carried = trip.response.passed.?;
    const out_passed = try protocol.passedFrom(carried.stdout);
    const err_passed = try protocol.passedFrom(carried.stderr);

    try t.expectEqualSlices(u8, retained.stdout.sha256[0..], out_passed.sha256[0..]);
    try t.expectEqualSlices(u8, retained.stderr.sha256[0..], err_passed.sha256[0..]);
    try t.expect(!std.mem.eql(u8, out_passed.sha256[0..], err_passed.sha256[0..]));
    try t.expectEqual(retained.stdout.bytes, out_passed.bytes);
    try t.expectEqual(retained.stderr.bytes, err_passed.bytes);
}

// --- gate: what the two transports say about the same output ------------------

test "gate: output under the ceiling crosses the wire byte-for-byte" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const raw = try wireOutput(arena, 5, 4096, 0);
    var retained: Ssh.Retained = .{};
    const rendered = try Ssh.retain(arena, .{
        .exit_code = 0,
        .stdout = raw,
        .stderr = try arena.dupe(u8, "warn\n"),
    }, &retained, Ssh.read_bytes);

    const trip = try roundTrip(arena, protocol.execResponse(rendered, retained));
    const stdout = trip.response.stdout.bytes;
    const stderr = trip.response.stderr.bytes;

    try t.expectEqualSlices(u8, raw, stdout);
    try t.expectEqualStrings("warn\n", stderr);
    // No marker anywhere in it — its absence is what tells a caller nothing is
    // missing, so a wire that inserted one would be lying.
    try t.expect(std.mem.indexOf(u8, stdout, Ssh.gap_marker) == null);
    try t.expect(!trip.response.passed.?.stdout.truncated);
}

test "gate: every byte value crosses the wire unchanged" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // NUL, the newline the frame is terminated by, and every byte that is not
    // valid UTF-8. A command's output is bytes, not text, and this is the reason
    // the payload is base64 and not a JSON string of the output itself.
    var every: [256]u8 = undefined;
    for (&every, 0..) |*b, i| b.* = @intCast(i);

    var retained: Ssh.Retained = .{};
    const rendered = try Ssh.retain(arena, .{
        .exit_code = 0,
        .stdout = &every,
        .stderr = &every,
    }, &retained, Ssh.read_bytes);

    const trip = try roundTrip(arena, protocol.execResponse(rendered, retained));
    try t.expectEqualSlices(u8, &every, trip.response.stdout.bytes);
    try t.expectEqualSlices(u8, &every, trip.response.stderr.bytes);
    // The frame's own terminator is the last byte and appears nowhere else, so
    // an embedded newline cannot be read as the end of a frame.
    try t.expectEqual(@as(u8, '\n'), trip.frame[trip.frame.len - 1]);
    try t.expectEqual(
        @as(?usize, trip.frame.len - 1),
        std.mem.indexOfScalar(u8, trip.frame, '\n'),
    );
}

test "gate: over the ceiling, both transports say the same thing about the same output" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const raw = try wireOutput(arena, 31, Ssh.output_ceiling.total() * 3, 9);

    // The direct transport, through the stand-in the command path's own gates
    // use: `Scripted.execRetained` runs the same `Ssh.Capture` the channel
    // drain runs, in the channel's read size.
    var script = Core.Scripted.init(arena, &.{.{ .reply = .{
        .exit_code = 9,
        .stdout = raw,
        .stderr = "",
    } }});
    var direct_out: Ssh.Retained = .{};
    const direct = try script.executor().execRetained(arena, "big", null, &direct_out);

    // The daemon transport: the same capture on the far side of the socket, then
    // the whole wire — encode, frame, read, parse, decode.
    var daemon_out: Ssh.Retained = .{};
    const served = try Ssh.retain(arena, .{
        .exit_code = 9,
        .stdout = raw,
        .stderr = try arena.alloc(u8, 0),
    }, &daemon_out, Ssh.read_bytes);
    const trip = try roundTrip(arena, protocol.execResponse(served, daemon_out));
    const carried = trip.response.stdout.bytes;
    const passed = try protocol.passedFrom(trip.response.passed.?.stdout);

    // The same bytes, including the in-band marker at the same place.
    try t.expectEqualSlices(u8, direct.stdout, carried);
    try t.expect(std.mem.indexOf(u8, carried, Ssh.gap_marker) != null);
    // The same three numbers, meaning the same three things.
    try t.expectEqual(direct_out.stdout.bytes, passed.bytes);
    try t.expectEqualSlices(u8, direct_out.stdout.sha256[0..], passed.sha256[0..]);
    try t.expectEqual(direct_out.stdout.truncated, passed.truncated);
    try t.expectEqual(@as(u64, raw.len), passed.bytes);
    try t.expect(passed.truncated);
    // And the exit code is still readable out of the tail on both.
    try t.expectEqual(@as(i32, 9), trip.response.exitCode);
    const observed = try Core.supervisor.parseShell(arena, 31, carried, "");
    try t.expectEqual(@as(?i32, 9), observed.exit_code);
}

test "gate: a reply with no accounting is refused rather than read as zeros" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // What a `.whole` run produces: no ceiling was applied, so there is no
    // digest and no count, and the field is absent rather than zeroed.
    const whole = protocol.execResponse(.{
        .exit_code = 0,
        .stdout = try arena.dupe(u8, "hi"),
        .stderr = try arena.alloc(u8, 0),
    }, null);
    const trip = try roundTrip(arena, whole);
    try t.expect(trip.response.passed == null);

    // A digest that is not hex never becomes a row in the ledger claiming to be
    // a SHA-256.
    var not_hex: [Core.digest.hex_len]u8 = undefined;
    @memset(&not_hex, 'z');
    try t.expectError(error.MalformedMessage, protocol.passedFrom(.{
        .bytes = 1,
        .sha256 = not_hex,
        .truncated = false,
    }));

    // A digest of the wrong width never gets that far: it is the field's type,
    // so a peer that sends three characters fails the parse. Checked here rather
    // than in `passedFrom` because that is where it is now refused, and a test
    // asserting the old location would be asserting nothing.
    const short = try std.fmt.allocPrint(
        arena,
        "{{\"v\":{d},\"ok\":true,\"passed\":{{" ++
            "\"stdout\":{{\"bytes\":1,\"sha256\":\"abc\",\"truncated\":false}}," ++
            "\"stderr\":{{\"bytes\":0,\"sha256\":\"{s}\",\"truncated\":false}}}}}}",
        .{ protocol.version, "0" ** Core.digest.hex_len },
    );
    try t.expectError(
        error.MalformedMessage,
        protocol.parseMessage(protocol.Response, arena, short),
    );
    // The same payload with a full-width digest parses, so the refusal above is
    // the width and not something else in the fixture.
    const full = try std.fmt.allocPrint(
        arena,
        "{{\"v\":{d},\"ok\":true,\"passed\":{{" ++
            "\"stdout\":{{\"bytes\":1,\"sha256\":\"{s}\",\"truncated\":false}}," ++
            "\"stderr\":{{\"bytes\":0,\"sha256\":\"{s}\",\"truncated\":false}}}}}}",
        .{ protocol.version, "1" ** Core.digest.hex_len, "0" ** Core.digest.hex_len },
    );
    const parsed = try protocol.parseMessage(protocol.Response, arena, full);
    try t.expectEqual(@as(u64, 1), parsed.passed.?.stdout.bytes);
}

// --- gate: version skew -------------------------------------------------------

test "gate: a version skew is refused by name and hangs neither side" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var proven: usize = 0;

    // A daemon from an older build answers with a newline-delimited line and no
    // header. Read as a frame it fails on the header — it does *not* block
    // waiting for eight bytes that never come, and it is not mistaken for a
    // reply. This is the direction that used to be reported as "mismatch after
    // respawn".
    const v2_line = "{\"v\":2,\"ok\":false,\"error\":\"MalformedMessage\"}\n";
    var old_reply: std.Io.Reader = .fixed(v2_line);
    try t.expectError(error.MalformedFrame, protocol.readFrame(&old_reply, arena));
    proven += 1;

    // The other direction: an older client's unframed request, read by this
    // build's daemon. Same refusal, same absence of a wait.
    const v2_request = "{\"v\":2,\"op\":\"ping\"}\n";
    var old_request: std.Io.Reader = .fixed(v2_request);
    try t.expectError(error.MalformedFrame, protocol.readFrame(&old_request, arena));
    proven += 1;

    // And the reply this build sends an older client ends in the newline that
    // client delimits on, so it gets a complete line to fail on rather than
    // waiting for one.
    var out: std.Io.Writer.Allocating = .init(arena);
    try protocol.writeMessage(&out.writer, protocol.Response{
        .v = protocol.version,
        .ok = false,
        .@"error" = "MalformedFrame",
    });
    var old_side: std.Io.Reader = .fixed(out.written());
    const line = (try old_side.takeDelimiter('\n')).?;
    try t.expect(line.len > 0);
    try t.expectError(error.MalformedMessage, protocol.parseMessage(protocol.Response, arena, line));
    proven += 1;

    // A *future* daemon still frames, so its version can be read and named. This
    // is the case the message is allowed to be specific about.
    const future = try std.fmt.allocPrint(arena, "{{\"v\":{d},\"ok\":true,\"pid\":9}}", .{protocol.version + 1});
    const framed = try std.fmt.allocPrint(arena, "{x:0>8}{s}\n", .{ future.len, future });
    var ahead: std.Io.Reader = .fixed(framed);
    const payload = (try protocol.readFrame(&ahead, arena)).?;
    try t.expectError(
        error.VersionMismatch,
        protocol.parseMessage(protocol.Response, arena, payload),
    );
    try t.expectEqual(@as(?u32, protocol.version + 1), protocol.peerVersion(arena, payload));
    proven += 1;

    try t.expectEqual(@as(usize, 4), proven);
}

test "round trip and strictness" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var out: std.Io.Writer.Allocating = .init(arena);
    try protocol.writeMessage(&out.writer, protocol.Request{ .v = protocol.version, .op = .ping });
    var reader: std.Io.Reader = .fixed(out.written());
    const payload = (try protocol.readFrame(&reader, arena)).?;
    const parsed = try protocol.parseMessage(protocol.Request, arena, payload);
    try t.expectEqual(protocol.Op.ping, parsed.op);
    // A clean close between frames is not an error — the server loop ends on it.
    try t.expectEqual(@as(?[]const u8, null), try protocol.readFrame(&reader, arena));

    // Unknown field → hard failure.
    try t.expectError(error.MalformedMessage, protocol.parseMessage(protocol.Request, arena,
        \\{"v":3,"op":"ping","bogus":1}
    ));
    // Version mismatch → hard failure.
    try t.expectError(error.VersionMismatch, protocol.parseMessage(protocol.Request, arena,
        \\{"v":1,"op":"ping"}
    ));
    // Missing required field → hard failure.
    try t.expectError(error.MalformedMessage, protocol.parseMessage(protocol.Request, arena,
        \\{"v":3}
    ));
    // A payload that ends before the header said it would.
    var short: std.Io.Reader = .fixed("00000010{\"v\":3}");
    try t.expectError(error.MalformedFrame, protocol.readFrame(&short, arena));
}

// --- gate: bounded memory, the daemon's side ---------------------------------

test "gate: the daemon reply path's peak allocation does not grow with the output" {
    const t = std.testing;

    // Every allocation the daemon makes for a reply comes out of this budget:
    // the capture's head buffer, its tail ring, the retained rendering, and the
    // base64 the wire carries. Generous enough for those at the ceiling and far
    // below the larger run, so anything proportional to the output fails on the
    // big one while passing on the small one.
    //
    // What is measured is the same `Ssh.Capture` the daemon's `Ssh.execRetained`
    // drives, fed in the channel's own read size, plus the whole reply-building
    // path on top of it. The channel read loop itself needs a server and is
    // reviewed, not driven — but it allocates nothing of its own: the captures
    // are the only thing it hands bytes to.
    //
    // `sizes` is where a by-hand run over 10 GiB goes.
    const budget = 16 << 20;
    const ceiling = Ssh.output_ceiling.total();
    const sizes = [_]usize{ ceiling * 2, ceiling * 32 };

    var proven: usize = 0;
    var settled: ?usize = null;
    for (sizes) |total| {
        proven += 1;
        // On the test allocator, not the measured one: the fixture stands in for
        // a remote host and its cost is not the daemon's.
        const raw = try wireOutput(t.allocator, 3, total, 0);
        defer t.allocator.free(raw);

        const buffer = try t.allocator.alloc(u8, budget);
        defer t.allocator.free(buffer);
        var fixed = std.heap.FixedBufferAllocator.init(buffer);
        const arena = fixed.allocator();

        var retained: Ssh.Retained = .{};
        const served = try Ssh.retain(arena, .{
            .exit_code = 0,
            .stdout = raw,
            .stderr = try arena.alloc(u8, 0),
        }, &retained, Ssh.read_bytes);
        const response = protocol.execResponse(served, retained);
        // Written to a counting sink rather than a growing one: a buffer that
        // kept the frame would be the harness growing, and the daemon writes
        // straight into the socket.
        var sink: std.Io.Writer.Discarding = .init(&.{});
        try protocol.writeMessage(&sink.writer, response);

        try t.expectEqual(@as(u64, raw.len), retained.stdout.bytes);
        try t.expect(retained.stdout.truncated);
        try t.expect(sink.fullCount() > 0);

        std.debug.print(
            "\n  daemon reply bounded-memory gate: {d} bytes of output, {d} bytes allocated (budget {d})\n",
            .{ raw.len, fixed.end_index, budget },
        );
        try t.expect(fixed.end_index < budget);
        // Thirty-two times the output, and the allocation has to be the *same*
        // number — not merely another one under the budget. `< budget` alone
        // would pass an implementation allocating `total / 1000`, which is
        // proportional to the output and fits twice over. This is the figure
        // that used to grow without limit: the daemon held every byte.
        if (settled) |before| {
            if (fixed.end_index != before) {
                std.debug.print(
                    \\
                    \\the daemon's reply allocation moved with the size of the output.
                    \\
                    \\  {d} bytes of output -> {d} bytes allocated
                    \\  {d} bytes of output -> {d} bytes allocated
                    \\
                    \\Both fit the budget, so neither run failed on its own. What fails is that
                    \\they differ: a cost that tracks the output is the unbounded `Ssh.exec` the
                    \\daemon used to call, wearing a smaller constant.
                    \\
                , .{ sizes[0], before, total, fixed.end_index });
                return error.DaemonAllocationTracksTheOutputSize;
            }
        } else settled = fixed.end_index;
    }
    try t.expectEqual(@as(usize, 2), proven);
}
