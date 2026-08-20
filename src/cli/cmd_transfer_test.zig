//! Gates for the transfer producer's primitives.
//!
//! Five properties, and each one is a pseudo-success this pass removed rather
//! than a behaviour it added:
//!
//!  * a short transfer in either direction is an error that names what was
//!    expected and what arrived — it used to be a smaller byte count;
//!  * a failed transfer leaves the destination exactly as it was, in every
//!    failure mode, because the only thing that touches the destination is the
//!    rename and the rename is last;
//!  * a host that cannot hash ends `completed_unverified` and cannot reach
//!    `published`, and the two are mutually exclusive by the ledger's own
//!    construction;
//!  * a successful transfer walks the whole state path and leaves a confirmed
//!    prefix behind a prefix digest;
//!  * the peak memory of a transfer does not grow with the size of the file.
//!
//! **What is driven, and what is not.** The exec backend takes an `Executor`,
//! so `Scripted` drives the probe, the byte ranges, the verification and the
//! publish end to end against a fake host — including the failure injections a
//! real server cannot be made to produce on cue. The scp backend needs a live
//! libssh2 channel and is not reachable from here; the two paths share the
//! observer contract, the staging-then-rename shape and the state walk, and
//! those are what these gates are about.
const std = @import("std");
const Core = @import("../core/core.zig");
const Store = Core.Store;
const digest = Core.digest;
const transfers = Store.transfers;
const cmd_transfer = @import("cmd_transfer.zig");
const Cli = @import("cli.zig");
const skill_doc = @import("skill_doc.zig");
const args = @import("args.zig");

// --- fixtures ----------------------------------------------------------------

const scratch_dir = ".zig-cache/tmp";

/// A file with deterministic contents, under `.zig-cache/tmp`.
const Scratch = struct {
    io: std.Io,
    threaded: *std.Io.Threaded,
    allocator: std.mem.Allocator,
    paths: std.ArrayList([]u8) = .empty,

    var counter: std.atomic.Value(u32) = .init(0);

    fn init(allocator: std.mem.Allocator) !Scratch {
        const threaded = try allocator.create(std.Io.Threaded);
        threaded.* = .init(allocator, .{});
        const io = threaded.io();
        std.Io.Dir.cwd().createDirPath(io, scratch_dir) catch {};
        return .{ .io = io, .threaded = threaded, .allocator = allocator };
    }

    fn deinit(s: *Scratch) void {
        for (s.paths.items) |p| {
            std.Io.Dir.cwd().deleteFile(s.io, p) catch {};
            s.allocator.free(p);
        }
        s.paths.deinit(s.allocator);
        s.threaded.deinit();
        s.allocator.destroy(s.threaded);
    }

    /// A unique path this fixture will delete. Not created.
    fn path(s: *Scratch, label: []const u8) ![]const u8 {
        const n = counter.fetchAdd(1, .monotonic);
        const p = try std.fmt.allocPrint(s.allocator, "{s}/xfer_{s}_{d}_{d}", .{
            scratch_dir, label, std.Thread.getCurrentId(), n,
        });
        try s.paths.append(s.allocator, p);
        std.Io.Dir.cwd().deleteFile(s.io, p) catch {};
        return p;
    }

    fn write(s: *Scratch, label: []const u8, bytes: []const u8) ![]const u8 {
        const p = try s.path(label);
        const file = try std.Io.Dir.cwd().createFile(s.io, p, .{});
        defer file.close(s.io);
        var buf: [4096]u8 = undefined;
        var w = file.writerStreaming(s.io, &buf);
        try w.interface.writeAll(bytes);
        try w.interface.flush();
        return p;
    }

    fn read(s: *Scratch, arena: std.mem.Allocator, p: []const u8) ![]u8 {
        return std.Io.Dir.cwd().readFileAlloc(s.io, p, arena, .limited(1 << 24));
    }

    fn exists(s: *Scratch, p: []const u8) bool {
        const file = std.Io.Dir.cwd().openFile(s.io, p, .{}) catch return false;
        file.close(s.io);
        return true;
    }
};

/// `ExecResult` owns mutable buffers, and `Scripted` dupes whatever it is given
/// before handing it on — so a literal is never written through and the cast is
/// safe. It is here rather than at every call site so there is one place to
/// look at when asking whether that is still true.
fn reply(stdout: []const u8) Core.Scripted.Step {
    return replyCode(0, stdout);
}

fn replyCode(code: i32, stdout: []const u8) Core.Scripted.Step {
    return .{ .reply = .{
        .exit_code = code,
        .stdout = @constCast(stdout),
        .stderr = @constCast(@as([]const u8, "")),
    } };
}

/// The three lines `probeRemoteFile` parses: size, mtime, digest field. `-` in
/// either of the last two is the host stating that it cannot answer, which is
/// the shape the gates below turn on.
fn probeReply(arena: std.mem.Allocator, size: u64, mtime: []const u8, sha: []const u8) !Core.Scripted.Step {
    return reply(try std.fmt.allocPrint(arena, "{d}\n{s}\n{s}  -\n", .{ size, mtime, sha }));
}

/// One byte range, base64'd and wrapped at 76 columns the way `base64` does.
fn rangeReply(arena: std.mem.Allocator, bytes: []const u8) !Core.Scripted.Step {
    const encoder = std.base64.standard.Encoder;
    const raw = try arena.alloc(u8, encoder.calcSize(bytes.len));
    _ = encoder.encode(raw, bytes);
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < raw.len) : (i += 76) {
        try out.appendSlice(arena, raw[i..@min(i + 76, raw.len)]);
        try out.append(arena, '\n');
    }
    return reply(try out.toOwnedSlice(arena));
}

fn hexOf(arena: std.mem.Allocator, bytes: []const u8) ![]const u8 {
    return digest.hexAlloc(arena, bytes);
}

// --- gate: a short transfer is an error, not a smaller success ---------------

test "gate: a short pull is an error naming what was expected and what arrived" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var scratch = try Scratch.init(t.allocator);
    defer scratch.deinit();

    const partial = try scratch.path("shortpull");

    // The host announces 900 bytes and hands back 400. Under the shape this
    // replaces, `pullFile` returned 400 and the caller printed "400 bytes" as a
    // success — the staged partial was two fifths of a file and nothing said so.
    const body = "x" ** 400;
    var steps: std.ArrayList(Core.Scripted.Step) = .empty;
    try steps.append(arena, try rangeReply(arena, body));
    var script = Core.Scripted.init(arena, try steps.toOwnedSlice(arena));

    var moved: Core.Ssh.Moved = .{};
    const err = Core.transfer.pullFile(
        script.executor(),
        arena,
        scratch.io,
        "/srv/app/in.bin",
        partial,
        900,
        null,
        &moved,
    );
    try t.expectError(error.ShortReceive, err);

    // Both numbers, because the error set cannot carry them and this is the one
    // path where they are the whole of what the caller has to report.
    try t.expectEqual(@as(u64, 900), moved.expected);
    try t.expectEqual(@as(u64, 400), moved.arrived);

    // And the bytes that did arrive are on disk, flushed: the partial is the
    // resume material, so a short receive must not also lose the prefix.
    const staged = try scratch.read(arena, partial);
    try t.expectEqual(@as(usize, 400), staged.len);
}

test "gate: a short exec push is an error, and the count is not the answer" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var scratch = try Scratch.init(t.allocator);
    defer scratch.deinit();

    // A source whose length says one thing while the stream ends earlier is not
    // constructible from here without racing the filesystem, so the injection is
    // the *host* refusing a slice partway. Either way the property under test is
    // the same: the loop may not leave early and report the bytes it managed.
    const body = "y" ** (40 * 1024);
    const source = try scratch.write("shortpush", body);

    var steps = [_]Core.Scripted.Step{
        reply(""), // the init: truncate + chmod
        reply(""), // slice 1 lands
        replyCode(1, ""), // slice 2 is refused
    };
    var script = Core.Scripted.init(arena, &steps);

    var moved: Core.Ssh.Moved = .{};
    try t.expectError(error.RemoteWriteFailed, Core.transfer.pushFile(
        script.executor(),
        arena,
        scratch.io,
        source,
        "/srv/app/out.bin",
        0o644,
        null,
        &moved,
    ));
    // What was promised, and how far it got. `arrived` is one slice, not the
    // whole file, and not zero.
    try t.expectEqual(@as(u64, body.len), moved.expected);
    try t.expectEqual(@as(u64, Core.transfer.push_slice), moved.arrived);
}

// --- gate: the destination survives every failure mode -----------------------

test "gate: no failure mode touches the destination, because only the rename does" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var scratch = try Scratch.init(t.allocator);
    defer scratch.deinit();

    const previous = "the delivery that is already there, and must survive";

    // Three failure modes, one per column: the transfer stops mid-stream (the
    // stand-in for a full disk), the two ends disagree, and the publish itself
    // fails. Every one of them is driven to its end and the destination is read
    // back afterwards.
    var covered: usize = 0;

    // (1) mid-stream failure: the host refuses a byte range.
    {
        covered += 1;
        const dest = try scratch.write("survive_stream", previous);
        const partial = try std.fmt.allocPrint(arena, "{s}{s}", .{ dest, cmd_transfer.partial_suffix });
        var steps = [_]Core.Scripted.Step{replyCode(1, "")};
        var script = Core.Scripted.init(arena, &steps);
        var moved: Core.Ssh.Moved = .{};
        try t.expectError(error.RemoteReadFailed, Core.transfer.pullFile(
            script.executor(),
            arena,
            scratch.io,
            "/srv/app/in.bin",
            partial,
            4096,
            null,
            &moved,
        ));
        std.Io.Dir.cwd().deleteFile(scratch.io, partial) catch {};
        try t.expectEqualStrings(previous, try scratch.read(arena, dest));
    }

    // (2) the two ends disagree. The bytes are staged and the digests are
    // compared; nothing renames.
    {
        covered += 1;
        const dest = try scratch.write("survive_hash", previous);
        const partial = try std.fmt.allocPrint(arena, "{s}{s}", .{ dest, cmd_transfer.partial_suffix });
        const body = "these are not the bytes the host promised";
        var steps = [_]Core.Scripted.Step{try rangeReply(arena, body)};
        var script = Core.Scripted.init(arena, &steps);
        var moved: Core.Ssh.Moved = .{};
        _ = try Core.transfer.pullFile(
            script.executor(),
            arena,
            scratch.io,
            "/srv/app/in.bin",
            partial,
            body.len,
            null,
            &moved,
        );
        // The staged partial holds the wrong bytes, and the destination holds
        // what it held. This is the whole property: a mismatch is discovered
        // with the destination still intact, because staging is not publishing.
        try t.expectEqualStrings(body, try scratch.read(arena, partial));
        try t.expectEqualStrings(previous, try scratch.read(arena, dest));
        std.Io.Dir.cwd().deleteFile(scratch.io, partial) catch {};
    }

    // (3) the publish fails. The host's own answer is a refusal, so the
    // destination is untouched by definition — `mv` either replaces or does not.
    {
        covered += 1;
        var steps = [_]Core.Scripted.Step{replyCode(1, "")};
        var script = Core.Scripted.init(arena, &steps);
        try t.expectError(error.PublishFailed, Core.transfer.publishRemote(
            script.executor(),
            arena,
            "/srv/app/out.bin.terminus-part",
            "/srv/app/out.bin",
        ));
        // The command it would have run is the atomic one, and that is worth
        // pinning: a publish implemented as `cat partial > dest` would pass
        // every other assertion in this file and destroy the destination on a
        // failure halfway through.
        try t.expectEqual(@as(usize, 1), script.seen.items.len);
        try t.expect(std.mem.startsWith(u8, script.seen.items[0], "mv -f "));
    }

    // An empty region would otherwise pass this gate silently.
    try t.expectEqual(@as(usize, 3), covered);
}

test "gate: a pull stages beside the destination and never opens it" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var scratch = try Scratch.init(t.allocator);
    defer scratch.deinit();

    // The sharpest version: the destination does not exist, and must still not
    // exist after a failed pull. `createFile` defaults to `truncate = true`, so
    // a primitive handed the destination would have created an empty file
    // there — and an operator would find a zero-length artifact where there had
    // been nothing.
    const dest = try scratch.path("stage_only");
    const partial = try std.fmt.allocPrint(arena, "{s}{s}", .{ dest, cmd_transfer.partial_suffix });

    var steps = [_]Core.Scripted.Step{replyCode(1, "")};
    var script = Core.Scripted.init(arena, &steps);
    var moved: Core.Ssh.Moved = .{};
    try t.expectError(error.RemoteReadFailed, Core.transfer.pullFile(
        script.executor(),
        arena,
        scratch.io,
        "/srv/app/in.bin",
        partial,
        16,
        null,
        &moved,
    ));

    try t.expect(!scratch.exists(dest));
    // The partial *was* created, which is what makes the assertion above about
    // the destination rather than about nothing having happened.
    try t.expect(scratch.exists(partial));
    std.Io.Dir.cwd().deleteFile(scratch.io, partial) catch {};
}

// --- gate: no remote digest means completed_unverified, never published ------

test "gate: a host that cannot hash yields no declared digest, and published is then unreachable" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // `sha256sum` absent, `shasum` absent: the script's `else` arm prints `-`,
    // and `probeRemoteFile` reports the absence rather than a digest-shaped
    // string. A `-` mistaken for a digest is the failure this parses against:
    // it would be declared, compared against a real hash, and reported as a
    // mismatch — sending an operator to look for corruption on a host whose
    // only problem is a missing tool.
    var steps = [_]Core.Scripted.Step{try probeReply(arena, 4096, "1712345678", "-")};
    var script = Core.Scripted.init(arena, &steps);
    const reading = try Core.transfer.probeRemoteFile(script.executor(), arena, "/srv/app/in.bin");
    try t.expectEqual(@as(?[]const u8, null), reading.sha256);
    try t.expectEqual(@as(u64, 4096), reading.size);
    // The mtime is there, so this gate turns on the digest alone.
    try t.expectEqual(@as(?i128, 1712345678 * std.time.ns_per_s), reading.mtime_ns);

    // A host with no readable `stat` is the other half, and it costs something
    // different: the digest is there, so the transfer is still verifiable, and
    // what is lost is the *identity* — no offset may be stored against a source
    // nothing can re-identify, so this transfer cannot be resumed. Reported as
    // an absence rather than as a zero, which would be a timestamp nobody read.
    const want = try hexOf(arena, "abc");
    var no_stat_steps = [_]Core.Scripted.Step{try probeReply(arena, 4096, "-", want)};
    var no_stat_script = Core.Scripted.init(arena, &no_stat_steps);
    const no_stat = try Core.transfer.probeRemoteFile(no_stat_script.executor(), arena, "/srv/app/in.bin");
    try t.expectEqualStrings(want, no_stat.sha256.?);
    try t.expectEqual(@as(?i128, null), no_stat.mtime_ns);

    // `shasum -a 256` is asked for when `sha256sum` is missing, and its answer
    // is accepted. Without this the gate above would pass on a probe that had
    // simply stopped looking.
    var shasum_steps = [_]Core.Scripted.Step{try probeReply(arena, 4096, "1712345678", want)};
    var shasum_script = Core.Scripted.init(arena, &shasum_steps);
    const hashed = try Core.transfer.probeRemoteFile(shasum_script.executor(), arena, "/srv/app/in.bin");
    try t.expectEqualStrings(want, hashed.sha256.?);
    // And the command really does offer both tools, in that order, on stdin.
    const sent = shasum_script.seen.items[0];
    try t.expect(std.mem.indexOf(u8, sent, "sha256sum < ") != null);
    try t.expect(std.mem.indexOf(u8, sent, "shasum -a 256 < ") != null);
    try t.expect(std.mem.indexOf(u8, sent, "sha256sum <").? < std.mem.indexOf(u8, sent, "shasum -a 256 <").?);

    // A push asks a narrower question during its probe — *can* you hash — and
    // has to ask it before it declares anything. `remoteHashTool` is that
    // question, and it names the tool rather than answering yes/no so the
    // producer can say which one it is relying on.
    inline for (.{
        .{ "sha256sum\n", @as(?[]const u8, "sha256sum") },
        .{ "shasum\n", @as(?[]const u8, "shasum") },
        .{ "-\n", @as(?[]const u8, null) },
    }) |case| {
        var tool_steps = [_]Core.Scripted.Step{reply(case[0])};
        var tool_script = Core.Scripted.init(arena, &tool_steps);
        const got = try Core.transfer.remoteHashTool(tool_script.executor(), arena);
        if (case[1]) |expect_name| {
            try t.expectEqualStrings(expect_name, got.?);
        } else {
            try t.expectEqual(@as(?[]const u8, null), got);
        }
    }

    // Now the ledger half, which is what makes the absence *binding*: a
    // checkpoint that declared no digest and read none back cannot reach
    // `published`, and one that declared a digest cannot be recorded
    // `completed_unverified`. The two ends are mutually exclusive by
    // construction, which is why "no tool" cannot quietly become a success.
    var store_scratch = try StoreScratch.init(t.allocator, "unverified_gate");
    defer store_scratch.deinit();
    var store = try Store.open(store_scratch.path);
    defer store.close();

    const request_id = try seedTransfer(&store, arena, "unver");
    const cp = try transfers.create(&store, .{
        .request_id = request_id,
        .direction = .pull,
        .dest_side = .local,
        .dest_path = "/var/tmp/out.bin",
        .partial_path = "/var/tmp/out.bin.terminus-part",
        .source = .{ .remote_file = .{ .path = "/srv/app/in.bin" } },
        .chunk_size = Core.Ssh.chunk_bytes,
        .now = 100,
    });
    var clock: i64 = 110;
    for ([_]transfers.State{ .probing, .transferring, .verifying, .publishing }) |step| {
        clock += 1;
        try transfers.setState(&store, cp, request_id, step, null, clock);
    }
    try t.expectError(
        error.PublishNeedsVerifiedHash,
        transfers.setState(&store, cp, request_id, .published, null, clock + 1),
    );
    try transfers.setState(&store, cp, request_id, .completed_unverified, null, clock + 2);
    try t.expectEqual(
        transfers.State.completed_unverified,
        (try transfers.get(&store, arena, cp)).?.state,
    );

    // And the row the producer must never create: declared a digest, read none
    // back. It can reach *neither* end state — `published` wants the reading it
    // does not have, `completed_unverified` refuses the declaration it does —
    // so it has no legal end at all and holds its destination for good.
    //
    // This is why a push asks `remoteHashTool` before it declares. A push can
    // always hash its own source, so an unconditional declaration puts every
    // push to a host with no `sha256sum` and no `shasum` into exactly this row.
    const stranded_id = try seedTransfer(&store, arena, "stranded");
    const stranded = try transfers.create(&store, .{
        .request_id = stranded_id,
        .direction = .pull,
        .dest_side = .local,
        .dest_path = "/var/tmp/stranded.bin",
        .partial_path = "/var/tmp/stranded.bin.terminus-part",
        .source = .{ .remote_file = .{ .path = "/srv/app/in.bin" } },
        .chunk_size = Core.Ssh.chunk_bytes,
        .now = 100,
    });
    try transfers.setState(&store, stranded, stranded_id, .probing, null, 201);
    try transfers.recordExpectedHash(&store, stranded, stranded_id, try hexOf(arena, "promised"), 202);
    clock = 202;
    for ([_]transfers.State{ .transferring, .verifying, .publishing }) |step| {
        clock += 1;
        try transfers.setState(&store, stranded, stranded_id, step, null, clock);
    }
    try t.expectError(
        error.PublishNeedsVerifiedHash,
        transfers.setState(&store, stranded, stranded_id, .published, null, clock + 1),
    );
    try t.expectError(
        error.CompletedUnverifiedHasDeclaredHash,
        transfers.setState(&store, stranded, stranded_id, .completed_unverified, null, clock + 2),
    );
    // The way out this driver takes instead is one step earlier, from
    // `verifying`: park and publish nothing. Shown on a sibling row, because the
    // one above has already walked past it.
    const parked_id = try seedTransfer(&store, arena, "parkdecl");
    const parked = try transfers.create(&store, .{
        .request_id = parked_id,
        .direction = .pull,
        .dest_side = .local,
        .dest_path = "/var/tmp/parked.bin",
        .partial_path = "/var/tmp/parked.bin.terminus-part",
        .source = .{ .remote_file = .{ .path = "/srv/app/in.bin" } },
        .chunk_size = Core.Ssh.chunk_bytes,
        .now = 100,
    });
    try transfers.setState(&store, parked, parked_id, .probing, null, 301);
    try transfers.recordExpectedHash(&store, parked, parked_id, try hexOf(arena, "promised"), 302);
    for ([_]transfers.State{ .transferring, .verifying }) |step| {
        try transfers.setState(&store, parked, parked_id, step, null, 303);
    }
    try transfers.setState(&store, parked, parked_id, .paused, "declared and unread", 304);
    try t.expectEqual(
        transfers.State.paused,
        (try transfers.get(&store, arena, parked)).?.state,
    );
}

// --- gate: the successful walk, and the prefix it leaves behind --------------

test "gate: a verified pull walks planned to published and leaves a confirmed prefix" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var scratch = try Scratch.init(t.allocator);
    defer scratch.deinit();
    var store_scratch = try StoreScratch.init(t.allocator, "walk_gate");
    defer store_scratch.deinit();
    var store = try Store.open(store_scratch.path);
    defer store.close();

    // A body of three whole ranges plus a remainder, so the observer fires more
    // than once and the last call is a partial chunk.
    const total = Core.transfer.pull_slice * 2 + 777;
    const body = try arena.alloc(u8, total);
    for (body, 0..) |*b, i| b.* = @truncate(i * 31 + 7);
    const body_sha = try hexOf(arena, body);

    const dest = try scratch.path("walk_dest");
    const partial = try std.fmt.allocPrint(arena, "{s}{s}", .{ dest, cmd_transfer.partial_suffix });

    const request_id = try seedTransfer(&store, arena, "walk");
    const cp = try transfers.create(&store, .{
        .request_id = request_id,
        .direction = .pull,
        .dest_side = .local,
        .dest_path = dest,
        .partial_path = partial,
        .source = .{ .remote_file = .{ .path = "/srv/app/in.bin" } },
        .chunk_size = Core.Ssh.chunk_bytes,
        .total_bytes = total,
        .now = 100,
    });

    try transfers.setState(&store, cp, request_id, .probing, null, 101);
    // The probe's two writes, in the order the producer makes them: the source
    // is identified first (which is what licenses a non-zero offset at all) and
    // the digest the result will be judged by is declared second.
    try transfers.recordSourceIdentity(&store, cp, request_id, total, 1712345678 * std.time.ns_per_s, body_sha, 102);
    try transfers.recordExpectedHash(&store, cp, request_id, body_sha, 103);
    try Store.operations.advance(&store, request_id, .submitted, 104);
    try transfers.setState(&store, cp, request_id, .transferring, null, 105);

    // The stream, with the producer's observer contract: every chunk hashed,
    // and the offset confirmed behind a prefix digest of exactly those bytes.
    var confirms: usize = 0;
    const Recorder = struct {
        store: *Store,
        checkpoint: i64,
        request_id: []const u8,
        stream: digest.Running,
        confirms: *usize,
        failure: ?anyerror = null,

        fn onChunk(context: *anyopaque, chunk: []const u8, moved: u64, total_bytes: u64) Core.Ssh.ChunkError!void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.stream.update(chunk);
            var buf: [digest.hex_len]u8 = undefined;
            const prefix = self.stream.peekHex(&buf);
            transfers.confirmOffset(
                self.store,
                self.checkpoint,
                self.request_id,
                moved,
                moved,
                prefix,
                200 + @as(i64, @intCast(moved)),
            ) catch |err| {
                self.failure = err;
                return error.ObserverFailed;
            };
            self.confirms.* += 1;
            _ = total_bytes;
        }
    };
    var recorder: Recorder = .{
        .store = &store,
        .checkpoint = cp,
        .request_id = request_id,
        .stream = .init(),
        .confirms = &confirms,
    };

    var steps: std.ArrayList(Core.Scripted.Step) = .empty;
    var offset: usize = 0;
    while (offset < total) : (offset += Core.transfer.pull_slice) {
        try steps.append(arena, try rangeReply(arena, body[offset..@min(offset + Core.transfer.pull_slice, total)]));
    }
    var script = Core.Scripted.init(arena, try steps.toOwnedSlice(arena));

    var moved: Core.Ssh.Moved = .{};
    const received = try Core.transfer.pullFile(
        script.executor(),
        arena,
        scratch.io,
        "/srv/app/in.bin",
        partial,
        total,
        .{ .context = @ptrCast(&recorder), .on_chunk = Recorder.onChunk },
        &moved,
    );
    try t.expectEqual(@as(?anyerror, null), recorder.failure);
    try t.expectEqual(@as(u64, total), received);
    // Three ranges, three confirms. Asserted as a count so a loop that ran once
    // and reported the whole file would fail here.
    try t.expectEqual(@as(usize, 3), confirms);

    // The bytes on disk are the bytes the host sent, and the running digest of
    // the stream is the same digest — which is the comparison the producer's
    // `verifying` step makes.
    try t.expectEqualStrings(body, try scratch.read(arena, partial));
    var final_buf: [digest.hex_len]u8 = undefined;
    const observed = recorder.stream.finalHex(&final_buf);
    try t.expectEqualStrings(body_sha, observed);

    // The rest of the walk, exactly as the producer makes it.
    try transfers.setState(&store, cp, request_id, .verifying, null, 300);
    try transfers.recordVerifiedHash(&store, cp, request_id, observed, 301);
    try transfers.setState(&store, cp, request_id, .publishing, null, 302);
    const cwd = std.Io.Dir.cwd();
    try cwd.rename(partial, cwd, dest, scratch.io);
    try transfers.setState(&store, cp, request_id, .published, null, 303);

    const row = (try transfers.get(&store, arena, cp)).?;
    try t.expectEqual(transfers.State.published, row.state);
    // The confirmed prefix covers the whole file and carries the digest of
    // exactly those bytes — which is what a later resume would check against,
    // and the reason the offsets were written down at all.
    try t.expectEqual(@as(i64, total), row.confirmed_offset);
    try t.expectEqualStrings(body_sha, row.partial_sha256.?);
    try t.expectEqualStrings(body_sha, row.verified_sha256.?);
    try t.expectEqualStrings(body_sha, row.expected_sha256.?);
    // The artifact is at the destination and the staging file is gone.
    try t.expectEqualStrings(body, try scratch.read(arena, dest));
    try t.expect(!scratch.exists(partial));
}

// --- gate: bounded memory ----------------------------------------------------

test "gate: a transfer's peak allocation does not grow with the file" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator);
    defer scratch.deinit();

    // The same fixed budget for every size. It is generous enough for the
    // buffers `pullFile` allocates once (a base64 window, a decode window) and
    // far below the larger file — so anything proportional to the transfer fails
    // on the bigger run while passing on the smaller, which is exactly the
    // signature this gate exists to catch. The version this replaced allocated
    // the whole file and would fail both.
    //
    // Both sizes are exact multiples of the slice, so one wire reply serves
    // every range and the *fixture* stays constant too — otherwise the harness
    // would be the thing that grows and this gate could not be run at a size
    // worth running it at. `sizes` is where a by-hand run over 2 GiB goes.
    const budget = 4 << 20;
    const sizes = [_]usize{ Core.transfer.pull_slice * 4, Core.transfer.pull_slice * 64 };

    // One slice's worth of bytes, and its base64, built once.
    var wire_arena = std.heap.ArenaAllocator.init(t.allocator);
    defer wire_arena.deinit();
    const slice_body = try wire_arena.allocator().alloc(u8, Core.transfer.pull_slice);
    for (slice_body, 0..) |*b, i| b.* = @truncate(i * 17 + 5);
    const slice_reply = try rangeReply(wire_arena.allocator(), slice_body);

    var proven: usize = 0;
    // The first size's allocation, which the second one has to match exactly.
    var settled: ?usize = null;
    for (sizes) |total| {
        proven += 1;
        const buffer = try t.allocator.alloc(u8, budget);
        defer t.allocator.free(buffer);
        var fixed = std.heap.FixedBufferAllocator.init(buffer);
        const arena = fixed.allocator();

        const partial = try scratch.path("bounded");

        // Every step is the same reply. The steps list is the only part of the
        // fixture that scales, at one tagged union per range.
        const steps = try t.allocator.alloc(Core.Scripted.Step, total / Core.transfer.pull_slice);
        defer t.allocator.free(steps);
        @memset(steps, slice_reply);

        // `Scripted` dupes every command it is handed onto the allocator it was
        // built with, and appends it to a list that never shrinks — the
        // harness's own growth, not the transfer's. Given a zero-length
        // allocator both fail and are swallowed, so `seen` stays empty and what
        // is being measured is `pullFile`.
        var none = std.heap.FixedBufferAllocator.init(&[_]u8{});
        var script = Core.Scripted.init(none.allocator(), steps);

        var moved: Core.Ssh.Moved = .{};
        const received = try Core.transfer.pullFile(
            script.executor(),
            arena,
            scratch.io,
            "/srv/app/in.bin",
            partial,
            total,
            null,
            &moved,
        );
        try t.expectEqual(total, received);
        try t.expectEqual(@as(usize, 0), script.seen.items.len);
        // What the transfer actually took, reported so a regression that stays
        // inside the budget still shows up as a number that moved.
        std.debug.print(
            "\n  bounded-memory gate: {d} bytes moved, {d} bytes allocated (budget {d})\n",
            .{ total, fixed.end_index, budget },
        );
        // Sixteen times the bytes, and the allocation has to be the *same*
        // number — not merely another one under the budget.
        //
        // `< budget` alone was the assertion here and it is too weak to hold the
        // sentence above it: an implementation allocating `total / 1000` is
        // proportional to the file and still fits twice over, so it would pass
        // both runs. Equality is what says the transfer's cost does not depend on
        // the transfer's size, and it is the claim the release rule is about.
        try t.expect(fixed.end_index < budget);
        if (settled) |before| {
            if (fixed.end_index != before) {
                std.debug.print(
                    \\
                    \\a transfer's allocation moved with the size of the transfer.
                    \\
                    \\  {d} bytes moved -> {d} bytes allocated
                    \\  {d} bytes moved -> {d} bytes allocated
                    \\
                    \\Both fit the budget, so neither run failed on its own. What fails is that
                    \\they differ: a cost that tracks the file is the whole-file load this gate
                    \\replaced, wearing a smaller constant.
                    \\
                , .{ sizes[0], before, total, fixed.end_index });
                return error.TransferAllocationTracksTheFileSize;
            }
        } else settled = fixed.end_index;

        std.Io.Dir.cwd().deleteFile(scratch.io, partial) catch {};
    }
    try t.expectEqual(@as(usize, 2), proven);
}

test "gate: hashing a source does not grow with the source either" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator);
    defer scratch.deinit();

    // The probe is the half that carried the hard ceiling: it used to be
    // `readFileAlloc(…, .limited(1 << 31))`, so a file over 2 GiB could not be
    // hashed at all and one under it was held whole. `digest.readFile` takes no
    // allocator, which is the strongest form of this assertion available — there
    // is nowhere for a proportional allocation to live. What is checked here is
    // that it still produces the right answer across more than one buffer.
    const total = (1 << 20) * 2 + 4321;
    const body = try t.allocator.alloc(u8, total);
    defer t.allocator.free(body);
    for (body, 0..) |*b, i| b.* = @truncate(i * 11 + 2);
    const path = try scratch.write("probe_bounded", body);

    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const want = try hexOf(arena_state.allocator(), body);

    var out: [digest.hex_len]u8 = undefined;
    const reading = try digest.readFile(scratch.io, path, &out);
    try t.expectEqualStrings(want, reading.sha256);
    try t.expectEqual(@as(u64, total), reading.size);
}

// --- gate: how a transfer's operation is settled at all ---------------------

test "gate: a transfer settles indeterminate and is resolved by a reading of its destination" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var store_scratch = try StoreScratch.init(t.allocator, "settle_gate");
    defer store_scratch.deinit();
    var store = try Store.open(store_scratch.path);
    defer store.close();

    // The constraint that decides this whole shape: `operations.Kind.capabilities`
    // gives a transfer `publishes_declared_artifact` and nothing else, and
    // `receipts.terminalDescribes` refuses every terminal that carries a
    // verdict on the strength of that. So a transfer **cannot settle
    // `completed`** — its own module says "a transfer cannot reach `completed`
    // or `timed_out` through `settle` at all" — and the producer's success path
    // therefore has to be `indeterminate` plus a resolution over a reading of
    // the destination.
    //
    // Asserted here rather than trusted, because the producer's settle step is
    // built on it: if a later change admits a completing terminal for these
    // kinds, this is where that is noticed, and the producer should then settle
    // with it instead of going the long way round.
    const can = Store.operations.Kind.transfer_pull.capabilities();
    try t.expect(can.publishes_declared_artifact);
    try t.expect(!Store.receipts.terminalDescribes(.{ .exited = .{ .exit_code = 0 } }, can));
    try t.expect(!Store.receipts.terminalDescribes(
        .{ .proven_failure = .{ .observation = "read it", .error_code = "X" } },
        can,
    ));
    // ...and `indeterminate` is admitted, which is what makes the route exist.
    try t.expect(Store.receipts.terminalDescribes(
        .{ .indeterminate = .{ .reason = "r", .last_observed = .submitted } },
        can,
    ));

    const dest = "/var/tmp/settle_gate_out.bin";
    const body_sha = try hexOf(arena, "the artifact");
    const request_id = try seedTransfer(&store, arena, "settle");
    const cp = try transfers.create(&store, .{
        .request_id = request_id,
        .direction = .pull,
        .dest_side = .local,
        .dest_path = dest,
        .partial_path = dest ++ cmd_transfer.partial_suffix,
        .source = .{ .remote_file = .{ .path = "/srv/app/in.bin" } },
        .chunk_size = Core.Ssh.chunk_bytes,
        .now = 100,
    });
    try transfers.setState(&store, cp, request_id, .probing, null, 101);
    try transfers.recordExpectedHash(&store, cp, request_id, body_sha, 102);
    try Store.operations.advance(&store, request_id, .submitted, 103);
    var clock: i64 = 103;
    for ([_]transfers.State{ .transferring, .verifying }) |step| {
        clock += 1;
        try transfers.setState(&store, cp, request_id, step, null, clock);
    }
    try transfers.recordVerifiedHash(&store, cp, request_id, body_sha, 110);
    try transfers.setState(&store, cp, request_id, .publishing, null, 111);
    try transfers.setState(&store, cp, request_id, .published, null, 112);

    // The producer's two writes, in order.
    _ = try Store.receipts.settle(&store, request_id, .{ .indeterminate = .{
        .reason = "transfer ended published",
        .last_observed = .submitted,
    } }, .{}, 113);

    const resolution = try Store.receipts.resolve(
        &store,
        arena,
        request_id,
        .completed,
        cmd_transfer.publishedEffect(.pull, dest, body_sha),
        114,
    );
    try t.expect(std.meta.activeTag(resolution) == .resolved);

    const op = (try Store.operations.get(&store, arena, request_id)).?;
    try t.expectEqual(Store.op_state.Status.indeterminate, op.status);
    try t.expectEqual(Store.op_state.ResolvedStatus.completed, op.resolved_status.?);

    // And the reading has to be *this* transfer's. A digest that does not match
    // the one declared before the first byte is refused, which is what stops the
    // producer's own route from being a way to resolve anything it likes.
    const other_id = try seedTransfer(&store, arena, "settletwo");
    const other_dest = "/var/tmp/settle_gate_other.bin";
    const other_cp = try transfers.create(&store, .{
        .request_id = other_id,
        .direction = .pull,
        .dest_side = .local,
        .dest_path = other_dest,
        .partial_path = other_dest ++ cmd_transfer.partial_suffix,
        .source = .{ .remote_file = .{ .path = "/srv/app/in.bin" } },
        .chunk_size = Core.Ssh.chunk_bytes,
        .now = 100,
    });
    try transfers.setState(&store, other_cp, other_id, .probing, null, 121);
    try transfers.recordExpectedHash(&store, other_cp, other_id, body_sha, 122);
    try Store.operations.advance(&store, other_id, .submitted, 123);
    clock = 123;
    for ([_]transfers.State{ .transferring, .verifying }) |step| {
        clock += 1;
        try transfers.setState(&store, other_cp, other_id, step, null, clock);
    }
    try transfers.recordVerifiedHash(&store, other_cp, other_id, body_sha, 130);
    try transfers.setState(&store, other_cp, other_id, .publishing, null, 131);
    try transfers.setState(&store, other_cp, other_id, .published, null, 132);
    _ = try Store.receipts.settle(&store, other_id, .{ .indeterminate = .{
        .reason = "transfer ended published",
        .last_observed = .submitted,
    } }, .{}, 133);

    const wrong = try Store.receipts.resolve(
        &store,
        arena,
        other_id,
        .completed,
        cmd_transfer.publishedEffect(.pull, other_dest, try hexOf(arena, "some other bytes entirely")),
        134,
    );
    try t.expect(std.meta.activeTag(wrong) == .effect_hash_unproven);
    // Refused means nothing was written: the operation is still unresolved and
    // still barring its scope, which is the fail-closed half.
    const unresolved = (try Store.operations.get(&store, arena, other_id)).?;
    try t.expectEqual(@as(?Store.op_state.ResolvedStatus, null), unresolved.resolved_status);

    // And the side has to be the one the checkpoint recorded. A pull publishes
    // here, so offering the *host* as the place the artifact was read is a
    // reading of a machine this transfer never wrote to — `filesystem_effect`
    // carries `side` for exactly that, and `resolve` compares it against
    // `dest_side`. The digest is the right one, so nothing but the side can
    // refuse this.
    const wrong_side = try Store.receipts.resolve(
        &store,
        arena,
        other_id,
        .completed,
        cmd_transfer.publishedEffect(.push, other_dest, body_sha),
        135,
    );
    try t.expect(std.meta.activeTag(wrong_side) == .effect_hash_unproven);

    // The control, on the same row: the right side and the right digest resolve
    // it. Without this the two refusals above would pass on a `publishedEffect`
    // that had simply stopped producing anything usable.
    const right = try Store.receipts.resolve(
        &store,
        arena,
        other_id,
        .completed,
        cmd_transfer.publishedEffect(.pull, other_dest, body_sha),
        136,
    );
    try t.expect(std.meta.activeTag(right) == .resolved);
}

test "gate: what verifying concludes from the two readings it holds" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const a = try hexOf(arena, "the bytes we sent");
    const b = try hexOf(arena, "something else entirely");

    // All four rows, because the decision is what the command turns on and three
    // of the four are the ones that must not be confused. Counted, so a fifth
    // verdict added without a row here fails rather than passing unexamined.
    const cases = [_]struct {
        declared: ?[]const u8,
        ours: []const u8,
        far_end: ?[]const u8,
        want: cmd_transfer.Verdict,
    }{
        // Both ends agree. The only row that may publish as `published`.
        .{ .declared = a, .ours = a, .far_end = a, .want = .agreed },
        // Both ends have a reading and they differ. Not a publish.
        .{ .declared = a, .ours = a, .far_end = b, .want = .disagreed },
        // Neither end has anything. `completed_unverified` is legal here and
        // *only* here, because nothing was declared for it to contradict.
        .{ .declared = null, .ours = a, .far_end = null, .want = .unverifiable },
        // Declared, and the far end produced nothing. This is the row with no
        // legal end state, and the one a naive push creates on every host with
        // no `sha256sum` — see the gate that walks it into the corner.
        .{ .declared = a, .ours = a, .far_end = null, .want = .declared_but_unread },
        // Case sensitivity is not a mismatch: `sha256sum` prints lower case and
        // some tools print upper, and a transfer refused for that would be
        // reported as corruption.
        .{ .declared = a, .ours = a, .far_end = try std.ascii.allocUpperString(arena, a), .want = .agreed },
    };
    var checked: usize = 0;
    for (cases) |c| {
        checked += 1;
        try t.expectEqual(c.want, cmd_transfer.verdictFor(c.declared, c.ours, c.far_end));
    }
    try t.expectEqual(@as(usize, 5), checked);

    // Every verdict is reachable from the rows above, so none of them is dead.
    var seen: [4]bool = @splat(false);
    for (cases) |c| seen[@intFromEnum(c.want)] = true;
    for (seen) |hit| try t.expect(hit);
}

test "gate: completed_unverified is not success, and every outcome says what it proves" {
    const t = std.testing;

    // The difference a caller sees. `completed_unverified` delivered bytes and
    // established nothing about them, and the operation behind it is
    // `indeterminate` with no resolution — so `0` would tell a caller the ledger
    // agrees this worked when it does not, and `1` would tell them nothing
    // arrived when something did.
    try t.expect(!cmd_transfer.Outcome.completed_unverified.ok());
    try t.expectEqual(Cli.exit_code.indeterminate, cmd_transfer.Outcome.completed_unverified.exitCode());
    try t.expect(cmd_transfer.Outcome.published.ok());
    try t.expectEqual(Cli.exit_code.ok, cmd_transfer.Outcome.published.exitCode());
    // The proven failures are the only ones that exit `1`: they are the only
    // ones a caller may retry from without first reading the destination.
    try t.expectEqual(Cli.exit_code.failure, cmd_transfer.Outcome.failed_hash_mismatch.exitCode());
    try t.expectEqual(Cli.exit_code.failure, cmd_transfer.Outcome.failed_publish.exitCode());
    try t.expectEqual(Cli.exit_code.failure, cmd_transfer.Outcome.failed_source_changed.exitCode());
    // A rename whose answer was lost is never `1`.
    try t.expectEqual(Cli.exit_code.indeterminate, cmd_transfer.Outcome.indeterminate_publish.exitCode());
    try t.expectEqual(Cli.exit_code.indeterminate, cmd_transfer.Outcome.paused.exitCode());

    // Every outcome carries its own `proves` text, and only the clean one has no
    // hint. Counted, so an outcome added without either is not waved through.
    var seen: usize = 0;
    var texts: [16][]const u8 = undefined;
    inline for (@typeInfo(cmd_transfer.Outcome).@"enum".fields) |field| {
        const o: cmd_transfer.Outcome = @enumFromInt(field.value);
        try t.expect(o.proves().len > 0);
        try t.expectEqual(o == .published, o.hint() == null);
        for (texts[0..seen]) |prior| try t.expect(!std.mem.eql(u8, prior, o.proves()));
        texts[seen] = o.proves();
        seen += 1;
    }
    try t.expectEqual(@as(usize, 7), seen);
}

// --- gates: a held destination, and the one act that gets past it ------------
//
// A failed transfer keeps its destination (`State.holdsDestination` covers every
// failure) so the next `create` aimed there is refused until somebody says the
// leftovers may be discarded. `--restart` is where they say it, and these gates
// hold the four properties that make it safe to have:
//
//   * a held path is a refusal when nobody asked to release it;
//   * `--restart` over a settled failure releases the hold and puts a new
//     checkpoint on the path in one commit;
//   * `--restart` over a holder whose attempt may still be running is refused
//     and sent to `request reconcile`;
//   * a failure *after* the supersession leaves the path **held**, which is the
//     whole reason the three writes are one transaction.
//
// The last one is the one that has to be exercised rather than argued, so it is
// driven by making the replacement `create` fail for a real reason after the
// release has already landed inside the transaction.

/// The owner's settlement, which is half of whether a hold may be released.
///
/// Two arms and not a bool, because the words matter to the thing under test:
/// `settled` is an attempt that stopped blocking its scope, and `indeterminate`
/// is the terminal that means *nobody knows* — the one the driver above actually
/// writes for every transfer that gets past submission, and the one a rule
/// written against `isTerminal` would have waved through.
const OwnerEnd = enum { settled, indeterminate };

const Holding = struct {
    request_id: []const u8,
    checkpoint: i64,
};

/// A checkpoint standing on `dest` in `state`, with its owning attempt ended as
/// `owner` says. Walks the real transition graph to get there — no private edge,
/// so a state this fixture can reach is one the driver can reach.
fn seedHolder(
    store: *Store,
    arena: std.mem.Allocator,
    label: []const u8,
    dest: []const u8,
    state: transfers.State,
    owner: OwnerEnd,
) !Holding {
    const request_id = try seedTransfer(store, arena, label);
    const cp = try transfers.create(store, .{
        .request_id = request_id,
        .direction = .pull,
        .dest_side = .local,
        .dest_path = dest,
        .partial_path = try std.fmt.allocPrint(arena, "{s}{s}", .{ dest, cmd_transfer.partial_suffix }),
        .source = .{ .remote_file = .{ .path = "/srv/app/in.bin" } },
        .chunk_size = Core.Ssh.chunk_bytes,
        .now = 100,
    });

    // The route to each state, as the driver walks it. `failed_hash_mismatch`
    // comes out of `verifying`, `indeterminate_publish` out of `publishing`, and
    // `paused` out of `probing` — which is where every abort in the driver parks.
    const walk: []const transfers.State = switch (state) {
        .paused => &.{ .probing, .paused },
        .failed_hash_mismatch => &.{ .probing, .transferring, .verifying, .failed_hash_mismatch },
        .failed_publish => &.{ .probing, .transferring, .verifying, .publishing, .failed_publish },
        .indeterminate_publish => &.{ .probing, .transferring, .verifying, .publishing, .indeterminate_publish },
        .transferring => &.{ .probing, .transferring },
        else => return error.SeedHolderHasNoRouteToThatState,
    };
    var clock: i64 = 100;
    for (walk) |step| {
        clock += 1;
        try transfers.setState(store, cp, request_id, step, null, clock);
    }

    switch (owner) {
        // `local_abandon` settles `cancelled`, which does not block scope. It is
        // admitted for a transfer on positive grounds — "nothing had been handed
        // over, so there is nothing to stop" — and it is the evidence that fits
        // an owner still before submission.
        .settled => _ = try Store.receipts.settle(
            store,
            request_id,
            .{ .local_abandon = .{ .reason = "the fixture's attempt is over" } },
            .{},
            clock + 1,
        ),
        // What the driver really writes: after submission a transfer has exactly
        // one admissible terminal, and it is `indeterminate`. Unresolved, so the
        // effective status still blocks scope.
        .indeterminate => {
            try Store.operations.advance(store, request_id, .submitted, clock + 1);
            _ = try Store.receipts.settle(
                store,
                request_id,
                .{ .indeterminate = .{ .reason = "the answer never came back", .last_observed = .submitted } },
                .{},
                clock + 2,
            );
        },
    }

    return .{ .request_id = request_id, .checkpoint = cp };
}

fn countRows(store: *Store, sql: [:0]const u8) !i64 {
    var stmt = try store.db.prepare(sql);
    defer stmt.deinit();
    if (!try stmt.step()) return error.CountReturnedNoRow;
    return stmt.columnInt(0);
}

/// `BeginOptions` for a `transfer_pull` aimed at `dest`, which is what the CLI
/// builds for a pull.
fn pullBegin(dest: []const u8, kind: Store.operations.Kind) Core.execution.BeginOptions {
    return .{
        .server_id = 1,
        .server_name = "gate-host",
        .kind = kind,
        .scope = .{ .kind = .path, .key = dest },
        .mutating = true,
        .transport = "direct",
        .owner_token = "gate-profile",
        .now = 500,
    };
}

fn pullPlan(dest: []const u8, partial: []const u8, direction: transfers.Direction) transfers.CheckpointPlan {
    return .{
        .direction = direction,
        .dest_side = .local,
        .dest_path = dest,
        .partial_path = partial,
        .source = .{ .remote_file = .{ .path = "/srv/app/in.bin" } },
        .chunk_size = Core.Ssh.chunk_bytes,
    };
}

test "gate: a held destination refuses a fresh transfer and the refusal names the way through" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var store_scratch = try StoreScratch.init(t.allocator, "held_gate");
    defer store_scratch.deinit();
    var store = try Store.open(store_scratch.path);
    defer store.close();

    const dest = "/var/tmp/held_gate_out.bin";
    const held = try seedHolder(&store, arena, "heldone", dest, .failed_hash_mismatch, .settled);

    // The probe that words the refusal reads the same set the index refuses on,
    // so "nothing holds it" and "create is about to be refused" cannot disagree.
    const holder = (try transfers.findHolder(&store, arena, .local, dest)) orelse
        return error.NothingHoldsTheDestination;
    try t.expectEqual(held.checkpoint, holder.id);
    try t.expectEqualStrings(held.request_id, holder.request_id);
    try t.expectEqual(transfers.State.failed_hash_mismatch, holder.state);
    try t.expect(!holder.owner_may_be_running);
    try t.expect(holder.releasable());

    // And the refusal is real: a fresh request aimed at the same path is turned
    // away by the live-destination index, under the name an operator can act on.
    const rival = try seedTransfer(&store, arena, "heldtwo");
    try t.expectError(error.DestinationHeld, transfers.create(&store, .{
        .request_id = rival,
        .direction = .pull,
        .dest_side = .local,
        .dest_path = dest,
        .partial_path = dest ++ cmd_transfer.partial_suffix,
        .source = .{ .remote_file = .{ .path = "/srv/app/in.bin" } },
        .chunk_size = Core.Ssh.chunk_bytes,
        .now = 400,
    }));

    // Nothing was created for the rival, so the refusal really did decline the
    // insert rather than land a second row the index tolerated.
    try t.expectEqual(@as(i64, 1), try countRows(
        &store,
        "SELECT COUNT(*) FROM transfer_checkpoints WHERE dest_path = '/var/tmp/held_gate_out.bin'",
    ));

    // The message. It used to end at "it either has not finished or failed and
    // has not been released", which described a dead end and stopped. What it has
    // to carry now is the act that gets past it.
    const way = cmd_transfer.wayThrough(arena, holder);
    try t.expect(std.mem.indexOf(u8, way, "--restart") != null);
    // Not `reconcile`: this holder is settled, so sending an operator to
    // establish an outcome that is already established is a wrong instruction,
    // not a cautious one.
    try t.expectEqual(@as(?usize, null), std.mem.indexOf(u8, way, "reconcile"));
}

test "gate: --restart over a settled holder releases the path and the replacement owns it" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var store_scratch = try StoreScratch.init(t.allocator, "restart_gate");
    defer store_scratch.deinit();
    var store = try Store.open(store_scratch.path);
    defer store.close();

    const dest = "/var/tmp/restart_gate_out.bin";
    const partial = dest ++ cmd_transfer.partial_suffix;
    const held = try seedHolder(&store, arena, "restone", dest, .failed_hash_mismatch, .settled);

    const started = switch (try Core.execution.beginSupersedingCheckpoint(
        &store,
        arena,
        store_scratch.io,
        pullBegin(dest, .transfer_pull),
        held.checkpoint,
        pullPlan(dest, partial, .pull),
    )) {
        .ready => |s| s,
        .blocked => return error.RestartWasBlocked,
    };

    // The incumbent stopped claiming the path and kept everything else. That is
    // the whole of what supersession does: the row, its partial and its digests
    // stay, because the reason an operator was asked is that there is something
    // at that path worth knowing about.
    const before = (try transfers.get(&store, arena, held.checkpoint)).?;
    try t.expectEqual(transfers.State.superseded, before.state);
    try t.expect(!before.state.holdsDestination());
    try t.expectEqualStrings(partial, before.partial_path);
    // The provenance names the request that released it. Read here rather than
    // parsed anywhere real — `supersedeLocked` says not to parse this field —
    // but a gate is exactly where "it points at the right attempt" is checked.
    try t.expect(std.mem.indexOf(u8, before.failure_reason.?, started.execution.id()) != null);

    // And there is something on the way to the path again, owned by the new
    // attempt. This is the half a supersession alone would not have.
    const now_holding = (try transfers.findHolder(&store, arena, .local, dest)) orelse
        return error.NothingHoldsTheDestination;
    try t.expectEqual(started.checkpoint, now_holding.id);
    try t.expectEqualStrings(started.execution.id(), now_holding.request_id);
    try t.expectEqual(transfers.State.planned, now_holding.state);

    // Two rows on that destination and exactly one of them holds it — asserted as
    // counts, so a query that found nothing would fail here rather than passing
    // over an empty region.
    try t.expectEqual(@as(i64, 2), try countRows(
        &store,
        "SELECT COUNT(*) FROM transfer_checkpoints WHERE dest_path = '/var/tmp/restart_gate_out.bin'",
    ));
    try t.expectEqual(@as(i64, 1), try countRows(&store,
        \\SELECT COUNT(*) FROM transfer_checkpoints
        \\ WHERE dest_path = '/var/tmp/restart_gate_out.bin' AND state <> 'superseded'
    ));
}

test "gate: --restart over a holder that may still be running is refused and sent to reconcile" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var store_scratch = try StoreScratch.init(t.allocator, "unsettled_restart_gate");
    defer store_scratch.deinit();
    var store = try Store.open(store_scratch.path);
    defer store.close();

    const dest = "/var/tmp/unsettled_restart_out.bin";
    const held = try seedHolder(&store, arena, "vnsetone", dest, .failed_hash_mismatch, .indeterminate);

    // `failed_*` is a decision about the *transfer*, written by `setState`. It
    // says nothing about the operation that wrote it, which here is
    // `indeterminate` — a terminal that means nobody knows — so the remote copier
    // may still exist and may still be writing to the partial beside that path.
    const holder = (try transfers.findHolder(&store, arena, .local, dest)) orelse
        return error.NothingHoldsTheDestination;
    try t.expect(holder.state.isSupersedable());
    try t.expect(holder.owner_may_be_running);
    try t.expect(!holder.releasable());

    // The refusal an operator reads, and the one instruction that actually helps.
    const way = cmd_transfer.wayThrough(arena, holder);
    try t.expect(std.mem.indexOf(u8, way, "terminus request reconcile") != null);
    try t.expect(std.mem.indexOf(u8, way, holder.request_id) != null);

    // And the statement itself refuses, which is what makes the message a
    // description rather than a policy the CLI enforces on its own. Asked of
    // `supersedeLocked` directly: the guard is a conjunct of its UPDATE, so this
    // is the barrier, not a reading taken beside it.
    // The superseding request is minted before the transaction opens: every
    // seeding helper here runs a `BEGIN IMMEDIATE` of its own.
    const rival = try seedTransfer(&store, arena, "vnsettwo");
    try store.db.exec("BEGIN IMMEDIATE");
    try t.expectError(
        error.SurrenderingOperationMayStillBeRunning,
        transfers.supersedeLocked(&store, held.checkpoint, rival, 600),
    );
    try store.db.exec("ROLLBACK");

    // Nothing moved.
    try t.expectEqual(
        transfers.State.failed_hash_mismatch,
        (try transfers.get(&store, arena, held.checkpoint)).?.state,
    );
}

test "gate: a failure after the supersession leaves the destination held, not free" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var store_scratch = try StoreScratch.init(t.allocator, "restart_atomic_gate");
    defer store_scratch.deinit();
    var store = try Store.open(store_scratch.path);
    defer store.close();

    const dest = "/var/tmp/restart_atomic_out.bin";
    const partial = dest ++ cmd_transfer.partial_suffix;
    const held = try seedHolder(&store, arena, "atomone", dest, .failed_hash_mismatch, .settled);
    const operations_before = try countRows(&store, "SELECT COUNT(*) FROM operations");

    // The injection, and it is a real refusal rather than a seam: the operation
    // this mints is a `transfer_push` and the checkpoint it asks for is a `pull`,
    // so `create`'s `INSERT ... SELECT` matches no row and it returns
    // `CheckpointOperationMismatch`. That happens *after* `supersedeLocked` has
    // already released the path inside the same transaction, which is exactly the
    // window the transaction exists for.
    try t.expectError(error.CheckpointOperationMismatch, Core.execution.beginSupersedingCheckpoint(
        &store,
        arena,
        store_scratch.io,
        pullBegin(dest, .transfer_push),
        held.checkpoint,
        pullPlan(dest, partial, .pull),
    ));

    // The supersession went back with it. Under three separate writes this row
    // would read `superseded` — the path free, and nothing on the way to it, so
    // the next `create` aimed there walks straight onto the leftovers an operator
    // was supposed to be asked about.
    const after = (try transfers.get(&store, arena, held.checkpoint)).?;
    try t.expectEqual(transfers.State.failed_hash_mismatch, after.state);
    try t.expect(after.state.holdsDestination());

    // Read the other way round too, through the predicate the index enforces:
    // the path is still held, and still by the same checkpoint.
    const still = (try transfers.findHolder(&store, arena, .local, dest)) orelse
        return error.NothingHoldsTheDestination;
    try t.expectEqual(held.checkpoint, still.id);

    // The operation went back as well, so a supersession's provenance can never
    // point at an attempt that exists because of a restart that did not happen.
    try t.expectEqual(operations_before, try countRows(&store, "SELECT COUNT(*) FROM operations"));
    try t.expectEqual(@as(i64, 1), try countRows(
        &store,
        "SELECT COUNT(*) FROM transfer_checkpoints WHERE dest_path = '/var/tmp/restart_atomic_out.bin'",
    ));

    // And the transaction really is closed — the `errdefer` rolled back rather
    // than leaving the connection inside a `BEGIN` that the next writer inherits.
    try store.db.exec("BEGIN IMMEDIATE");
    try store.db.exec("ROLLBACK");
}

test "gate: --restart reaches three of the driver's outcomes and cannot reach paused" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var store_scratch = try StoreScratch.init(t.allocator, "restart_reach_gate");
    defer store_scratch.deinit();
    var store = try Store.open(store_scratch.path);
    defer store.close();

    // Every `Outcome` this driver can report names a checkpoint state, so the two
    // vocabularies can be held against each other rather than compared by eye.
    // An outcome whose name is not a state fails here, which is the only way to
    // be told the driver has grown a verdict the ledger has no row for.
    var outcomes: usize = 0;
    var holders: usize = 0;
    var releasable: usize = 0;
    inline for (@typeInfo(cmd_transfer.Outcome).@"enum".fields) |field| {
        outcomes += 1;
        const state = transfers.State.parse(field.name) catch
            return error.OutcomeNamesNoCheckpointState;
        if (state.holdsDestination()) {
            holders += 1;
            if (state.isSupersedable()) releasable += 1;
        }
    }
    try t.expectEqual(@as(usize, 7), outcomes);
    // Five of the seven leave the destination held: the three decided failures,
    // the unjudged publish, and `paused`.
    try t.expectEqual(@as(usize, 5), holders);
    // And `--restart` reaches three of those five. This is the number the slice
    // turns on: if it ever reads 5, `supersedeLocked` has been widened to accept
    // states that mean "this may still be resumed" and "nobody has judged the
    // rename", and both releases hand a path to a rival that must not have it.
    try t.expectEqual(@as(usize, 3), releasable);

    // The two it cannot reach, and why each is right to be out.
    //
    // `paused` is where **every abort in the driver parks** — the probe, the
    // stream, the verifier and a pre-submission refusal all land there — so this
    // is the commonest way a transfer comes to hold a path, and it is the one
    // `--restart` may not release. That is not an oversight to be patched by
    // widening `isSupersedable`: `paused` says the checkpoint is trustworthy and
    // *adoptable*, so releasing its path discards resume material that is still
    // good. The verb for it is a hand-over, and no CLI reaches one.
    try t.expect(transfers.State.paused.holdsDestination());
    try t.expect(transfers.State.paused.isAdoptable());
    try t.expect(!transfers.State.paused.isSupersedable());
    // `indeterminate_publish` is not settled but *unjudged*: the rename may
    // already have landed, so the artifact at that path may be one nobody has
    // looked at.
    try t.expect(!transfers.State.indeterminate_publish.isSupersedable());
    try t.expect(!transfers.State.indeterminate_publish.isAdoptable());

    // Now the same two facts as an operator meets them. A settled `paused`
    // holder — its attempt over, its checkpoint still resumable — is refused, and
    // the refusal does not offer `--restart`, because offering it would be an
    // instruction the statement below rejects.
    const paused_dest = "/var/tmp/restart_reach_paused.bin";
    const paused = try seedHolder(&store, arena, "reachone", paused_dest, .paused, .settled);
    const paused_holder = (try transfers.findHolder(&store, arena, .local, paused_dest)) orelse
        return error.NothingHoldsTheDestination;
    try t.expect(!paused_holder.owner_may_be_running);
    try t.expect(!paused_holder.releasable());
    const paused_way = cmd_transfer.wayThrough(arena, paused_holder);
    try t.expectEqual(@as(?usize, null), std.mem.indexOf(u8, paused_way, "--restart to release"));
    try t.expect(std.mem.indexOf(u8, paused_way, "stays held") != null);

    const paused_rival = try seedTransfer(&store, arena, "reachtwo");
    try store.db.exec("BEGIN IMMEDIATE");
    try t.expectError(
        error.CheckpointNotSupersedable,
        transfers.supersedeLocked(&store, paused.checkpoint, paused_rival, 700),
    );
    try store.db.exec("ROLLBACK");

    // The unjudged publish is refused by the same statement and sent somewhere
    // else entirely — adjudication, not release.
    const parked_dest = "/var/tmp/restart_reach_parked.bin";
    const parked = try seedHolder(&store, arena, "reachthree", parked_dest, .indeterminate_publish, .settled);
    const parked_holder = (try transfers.findHolder(&store, arena, .local, parked_dest)) orelse
        return error.NothingHoldsTheDestination;
    try t.expect(!parked_holder.releasable());
    const parked_way = cmd_transfer.wayThrough(arena, parked_holder);
    try t.expect(std.mem.indexOf(u8, parked_way, "terminus request reconcile") != null);
    try t.expect(std.mem.indexOf(u8, parked_way, "may already be at this path") != null);

    const parked_rival = try seedTransfer(&store, arena, "reachfovr");
    try store.db.exec("BEGIN IMMEDIATE");
    try t.expectError(
        error.CheckpointNotSupersedable,
        transfers.supersedeLocked(&store, parked.checkpoint, parked_rival, 701),
    );
    try store.db.exec("ROLLBACK");

    // A live checkpoint whose owner is gone is refused too, and the wording is
    // the `paused` one rather than the failure one — the two share a sentence
    // because they share a reason, and that is asserted rather than assumed.
    const live_dest = "/var/tmp/restart_reach_live.bin";
    _ = try seedHolder(&store, arena, "reachfive", live_dest, .transferring, .settled);
    const live_holder = (try transfers.findHolder(&store, arena, .local, live_dest)) orelse
        return error.NothingHoldsTheDestination;
    try t.expect(!live_holder.releasable());
    try t.expect(std.mem.indexOf(u8, cmd_transfer.wayThrough(arena, live_holder), "stays held") != null);
}

// --- gates: the agent-facing document, held against this file ---------------

/// The heading the two gates below read from, so a reflow that moved the section
/// fails once with a name rather than twice with a needle.
const transfer_section = "## File transfer: what a push or a pull leaves behind";

test "gate: SKILL.md publishes an exit code for every transfer outcome, and it is the one we exit with" {
    const t = std.testing;
    const section = try skill_doc.after(skill_doc.text, transfer_section, "the transfer outcome list");

    // A number in prose that no gate reads is how `session rm`'s survived-kill
    // bullet came to publish 75 for a branch that exits 1. These are the numbers
    // an agent is told to branch on, so they are read off the document and
    // compared with `Outcome.exitCode` rather than trusted.
    var documented: usize = 0;
    inline for (@typeInfo(cmd_transfer.Outcome).@"enum".fields) |field| {
        const bullet = "- `" ++ field.name ++ "` — exit **";
        const at = std.mem.indexOf(u8, section, bullet) orelse {
            std.debug.print(
                \\
                \\skill/SKILL.md: the transfer outcome list publishes no exit code for
                \\`{s}`.
                \\  looked for the literal: "{s}"
                \\Every `cmd_transfer.Outcome` has to appear there with the code it really
                \\exits with, because that list is what an agent branches on.
                \\
            , .{ field.name, bullet });
            return error.SkillTransferOutcomeMissing;
        };
        // Once. A second bullet for the same outcome would let the two disagree
        // and let this gate read whichever came first.
        try t.expectEqual(
            @as(?usize, null),
            std.mem.indexOfPos(u8, section, at + 1, bullet),
        );
        const rest = section[at + bullet.len ..];
        const close = std.mem.indexOf(u8, rest, "**") orelse return error.SkillTransferExitCodeUnterminated;
        const claimed = std.fmt.parseInt(u8, rest[0..close], 10) catch
            return error.SkillTransferExitCodeUnreadable;
        const outcome: cmd_transfer.Outcome = @enumFromInt(field.value);
        try t.expectEqual(outcome.exitCode(), claimed);
        documented += 1;
    }
    // Counted, so a section that lost its list fails here rather than passing
    // over an empty region.
    try t.expectEqual(@as(usize, 7), documented);
}

test "gate: SKILL.md publishes how many transfer verdicts --restart can release" {
    const t = std.testing;

    // The document tells an agent that `--restart` reaches three of the seven
    // verdicts. That number is not an opinion: it is how many of them name a
    // checkpoint state `State.isSupersedable` admits, and it is the number this
    // whole flag turns on. Widening `supersedeLocked` to accept `paused` — the
    // state every abort in the driver parks in — would make it 4 and would hand
    // a resumable transfer's path to a rival; this is where that is noticed.
    var releasable: usize = 0;
    inline for (@typeInfo(cmd_transfer.Outcome).@"enum".fields) |field| {
        const state = transfers.State.parse(field.name) catch
            return error.OutcomeNamesNoCheckpointState;
        if (state.holdsDestination() and state.isSupersedable()) releasable += 1;
    }

    const claim = try skill_doc.after(
        skill_doc.text,
        "It releases **",
        "the count of verdicts `--restart` can release",
    );
    const close = std.mem.indexOf(u8, claim, "**") orelse
        return error.SkillRestartCountUnterminated;
    const documented = std.fmt.parseInt(usize, claim[0..close], 10) catch
        return error.SkillRestartCountUnreadable;
    try t.expectEqual(releasable, documented);

    // And the sentence that says which three, so the number cannot be right
    // beside a description that is not.
    const section = try skill_doc.after(skill_doc.text, transfer_section, "the transfer outcome list");
    try t.expect(std.mem.indexOf(u8, section, "the three proven failures") != null);
    // The limit this slice could not remove, published rather than left for an
    // agent to discover by being refused.
    try t.expect(std.mem.indexOf(u8, section, "every abort parks at `paused`") != null);
}

test "gate: --restart is a boolean flag, so it does not swallow whatever follows it" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // A flag missing from `args.bool_flags` is not a compile error and is not
    // visible to any gate that exercises this command's helpers directly: the
    // parser simply treats it as `--flag <value>`, so `--restart` written last —
    // which is how it is documented and how it will be typed — fails with "a
    // flag is missing its value", and `--restart --json` eats the `--json`.
    // Found by running the binary, so it is asserted here.
    const trailing = try args.parse(arena, &.{ "smoke", "./local", "/srv/app/out.bin", "--restart" });
    try t.expect(trailing.boolean("restart"));
    try t.expectEqual(@as(usize, 3), trailing.positionals.len);
    try t.expectEqualStrings("/srv/app/out.bin", trailing.positional(2).?);

    // And it consumes nothing when something does follow it.
    const followed = try args.parse(arena, &.{ "smoke", "./local", "/srv/app/out.bin", "--restart", "--json" });
    try t.expect(followed.boolean("restart"));
    try t.expect(followed.boolean("json"));
    try t.expectEqual(@as(usize, 3), followed.positionals.len);
}

// --- store fixtures ---------------------------------------------------------

const StoreScratch = struct {
    io: std.Io,
    threaded: *std.Io.Threaded,
    path: [:0]u8,
    allocator: std.mem.Allocator,

    var counter: std.atomic.Value(u32) = .init(0);

    fn init(allocator: std.mem.Allocator, name: []const u8) !StoreScratch {
        const threaded = try allocator.create(std.Io.Threaded);
        threaded.* = .init(allocator, .{});
        const io = threaded.io();
        std.Io.Dir.cwd().createDirPath(io, scratch_dir) catch {};
        const n = counter.fetchAdd(1, .monotonic);
        const path = try std.fmt.allocPrintSentinel(allocator, "{s}/{s}_{d}_{d}.db", .{
            scratch_dir, name, std.Thread.getCurrentId(), n,
        }, 0);
        var s: StoreScratch = .{ .io = io, .threaded = threaded, .path = path, .allocator = allocator };
        s.removeFiles();
        return s;
    }

    fn removeFiles(s: *StoreScratch) void {
        const cwd = std.Io.Dir.cwd();
        cwd.deleteFile(s.io, s.path) catch {};
        for ([_][]const u8{ "-wal", "-shm" }) |suffix| {
            const side = std.fmt.allocPrint(s.allocator, "{s}{s}", .{ s.path, suffix }) catch return;
            defer s.allocator.free(side);
            cwd.deleteFile(s.io, side) catch {};
        }
    }

    fn deinit(s: *StoreScratch) void {
        s.removeFiles();
        s.allocator.free(s.path);
        s.threaded.deinit();
        s.allocator.destroy(s.threaded);
    }
};

/// A `transfer_pull` operation at `connecting`, which is the window
/// `transfers.create` and the probe's two writes require.
///
/// The id is built from a readable label the way the store's own gate fixtures
/// build theirs: Crockford base32 omits I, L, O and U, so a hand-written label
/// containing any of them is refused by `ids.validate` — which is a failure
/// about the fixture and not about the rule under test.
fn seedTransfer(store: *Store, arena: std.mem.Allocator, label: []const u8) ![]const u8 {
    store.db.exec(
        \\INSERT INTO servers (id, name, host, port, username, created_at, updated_at)
        \\VALUES (1, 'gate-host', '10.0.0.1', 22, 'ubuntu', 100, 100);
    ) catch |err| switch (err) {
        error.Constraint => {},
        else => return err,
    };
    var id: [26]u8 = @splat('0');
    for (label, 0..) |ch, i| {
        if (i >= id.len) break;
        id[i] = switch (std.ascii.toUpper(ch)) {
            'I', 'L' => '1',
            'O' => '0',
            'U' => 'V',
            '0'...'9', 'A'...'H', 'J', 'K', 'M', 'N', 'P'...'T', 'V'...'Z' => std.ascii.toUpper(ch),
            else => '0',
        };
    }
    const owned = try arena.dupe(u8, &id);
    try Store.operations.create(store, .{
        .request_id = owned,
        .server_id = 1,
        .server_name = "gate-host",
        .kind = .transfer_pull,
        .now = 100,
    });
    try Store.operations.advance(store, owned, .connecting, 101);
    return owned;
}
