//! Remote supervision: how a command is launched, identified and reaped.
//!
//! Two modes are planned (B3):
//!
//! * `helper` — an installed remote binary that forks the work itself, so it
//!   can prove a pid/pgid with a start token, frame binary streams, enforce
//!   its own deadline independently of the SSH link, and hold an audit
//!   allowlist on the far side.
//! * `shell` — no installation required. It can approximate identity and
//!   exit status, and nothing more.
//!
//! The point of `Capability` is that the difference is *declared*, on every
//! receipt, rather than assumed. Shell mode does not get to imply it can
//! prove a process is ours or that it can stop one; features that depend on
//! those guarantees refuse to run rather than degrading into something that
//! looks the same but is not.
const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Mode = enum { shell, helper };

/// How much the current supervisor can actually vouch for.
pub const Capability = struct {
    supervisor: Mode,
    /// `weak` means we have a pid the shell reported, with a start token we
    /// may or may not have been able to read — enough to *look* for the
    /// process later, not enough to prove one we find is ours.
    pid_proof: enum { none, weak, strong },
    /// Whether stdout/stderr survive byte-exact. Shell mode annotates the
    /// stream with markers, so it does not.
    binary_framing: bool,
    /// Whether a deadline is enforced on the remote, surviving a dropped
    /// connection.
    remote_deadline: bool,
    /// Whether a command allowlist is enforced on the far side rather than
    /// by local string inspection.
    audit_isolation: bool,

    pub fn toJson(c: Capability, arena: Allocator) Allocator.Error![]u8 {
        var writer: std.Io.Writer.Allocating = .init(arena);
        std.json.Stringify.value(.{
            .supervisor = @tagName(c.supervisor),
            .pidProof = @tagName(c.pid_proof),
            .binaryFraming = c.binary_framing,
            .remoteDeadline = c.remote_deadline,
            .auditIsolation = c.audit_isolation,
        }, .{}, &writer.writer) catch return error.OutOfMemory;
        return writer.toOwnedSlice();
    }
};

/// What a plain POSIX shell can honestly claim.
///
/// Note `pid_proof = .weak`, and what follows from it: a tmux session
/// disappearing does **not** establish that the work stopped. A command that
/// daemonized, called `disown`, or ran under `setsid` outlives the pane that
/// launched it. Shell mode can observe that the session is gone; it cannot
/// prove the process tree is.
pub const shell_capability: Capability = .{
    .supervisor = .shell,
    .pid_proof = .weak,
    .binary_framing = false,
    .remote_deadline = false,
    .audit_isolation = false,
};

/// The exact helper bytes built from `src/helper/main.zig` for this CLI.
pub const helper_executable = @embedFile("terminus_helper");
pub const helper_fact_key = "terminus.helper.sha256";

/// The installation surface will put the embedded binary here. Kept as one
/// production constant so installation and invocation cannot drift silently.
pub const remote_helper_command = "exec \"$HOME/.terminus/bin/terminus-helper\"";

/// Invocation used for every helper-backed execution. The digest check and
/// `exec` are one remote shell program, so a replaced helper is refused at the
/// last possible moment instead of being trusted from a stale local fact.
pub fn guardedRemoteHelperCommand(arena: Allocator) Allocator.Error![]const u8 {
    const digest = @import("digest.zig");
    var hex: [digest.hex_len]u8 = undefined;
    const want = digest.hex(helper_executable, &hex);
    return std.fmt.allocPrint(
        arena,
        "cd \"$HOME\" || exit 126; actual=$(sha256sum \"$HOME/.terminus/bin/terminus-helper\" 2>/dev/null | awk '{{print $1}}') || exit 126; " ++
            "[ \"$actual\" = \"{s}\" ] || exit 126; " ++ remote_helper_command,
        .{want},
    );
}

pub fn helperSha256(out: *[32]u8) void {
    std.crypto.hash.sha2.Sha256.hash(helper_executable, out, .{});
}

/// The helper's wire protocol, host side.
///
/// This lived in `test/blackbox.zig` — the nine gates that drive
/// `src/helper/main.zig` on a real Linux kernel had their own encoder and their
/// own frame loop. So those gates, and the nine mutation anchors pointing at
/// them, were proving that the *helper binary* is correct against a codec no
/// production path uses. Two implementations of one protocol, and the tested one
/// was the copy. Moving it here does not change what the helper does; it changes
/// which code the existing evidence covers.
///
/// Every constant below mirrors one in `src/helper/main.zig`, and a gate holds
/// the two in step rather than a comment asking the next reader to.
pub const wire = struct {
    /// A request larger than this is refused rather than truncated: a truncated
    /// argv is a different command. The helper refuses the same bound from the
    /// other side, so a request that gets past here cannot be rejected there for
    /// being too big.
    pub const max_frame = 1 << 20;
    pub const max_argv = 256;
    /// Room for argv strings plus their null terminators.
    pub const argv_bytes = 1 << 19;
    /// How much of a stream the helper carries in one frame.
    pub const pump_bytes = 32 * 1024;

    pub const Kind = struct {
        // host -> helper
        pub const run: u8 = 0x01;
        pub const query: u8 = 0x02;
        pub const cancel: u8 = 0x03;
        // helper -> host
        pub const started: u8 = 0x81;
        pub const stdout: u8 = 0x82;
        pub const stderr: u8 = 0x83;
        pub const exited: u8 = 0x84;
        pub const failed: u8 = 0x85;
        pub const state: u8 = 0x86;
    };

    /// How a command ended, as the helper measured it.
    ///
    /// The two timeout arms are distinct on the wire because they are distinct
    /// outcomes: `timed_out_killed` means the helper signalled and then confirmed
    /// the group was gone, and `timed_out_unconfirmed` means it signalled and the
    /// window closed with the group still there. The first is `timed_out`; the
    /// second is `indeterminate`. Collapsing them is exactly how a supervisor
    /// comes to report a command it could not account for as one it stopped.
    ///
    /// Non-exhaustive: a helper newer than this build must not be read as one of
    /// these by accident.
    pub const How = enum(u8) {
        exited = 0,
        signalled = 1,
        timed_out_killed = 2,
        timed_out_unconfirmed = 3,
        cancelled = 4,
        _,
    };

    pub const Started = struct { pid: i64, pgid: i64, token: u64 };
    pub const Ended = struct { how: How, status: i32 };

    pub const EncodeError = error{ TooManyArguments, ArgumentsTooLarge } || Allocator.Error;

    /// Encodes one `run` request.
    ///
    /// Refuses rather than truncating, and refuses *here* rather than letting the
    /// helper do it: a request that left this machine and was then rejected for
    /// its size is a submitted attempt with no result, which is `indeterminate`
    /// for a fault we could have named before sending a byte.
    pub fn encodeRun(
        arena: Allocator,
        argv: []const []const u8,
        deadline_ms: u64,
        grace_ms: u64,
    ) EncodeError![]u8 {
        return encodeRunFor(arena, "", argv, deadline_ms, grace_ms);
    }

    pub fn encodeRunFor(
        arena: Allocator,
        request_id: []const u8,
        argv: []const []const u8,
        deadline_ms: u64,
        grace_ms: u64,
    ) EncodeError![]u8 {
        if (request_id.len > 64) return error.ArgumentsTooLarge;
        if (argv.len > max_argv) return error.TooManyArguments;
        var total: usize = 0;
        for (argv) |a| total += a.len + 1;
        if (total > argv_bytes) return error.ArgumentsTooLarge;

        var body: std.ArrayList(u8) = .empty;
        var head: [8]u8 = undefined;
        try body.append(arena, @intCast(request_id.len));
        try body.appendSlice(arena, request_id);
        std.mem.writeInt(u64, &head, deadline_ms, .little);
        try body.appendSlice(arena, &head);
        std.mem.writeInt(u64, &head, grace_ms, .little);
        try body.appendSlice(arena, &head);
        std.mem.writeInt(u32, head[0..4], @intCast(argv.len), .little);
        try body.appendSlice(arena, head[0..4]);
        for (argv) |a| {
            std.mem.writeInt(u32, head[0..4], @intCast(a.len), .little);
            try body.appendSlice(arena, head[0..4]);
            try body.appendSlice(arena, a);
        }

        if (body.items.len + 1 > max_frame) return error.ArgumentsTooLarge;
        var frame: std.ArrayList(u8) = .empty;
        std.mem.writeInt(u32, head[0..4], @intCast(body.items.len + 1), .little);
        try frame.appendSlice(arena, head[0..4]);
        try frame.append(arena, Kind.run);
        try frame.appendSlice(arena, body.items);
        return frame.items;
    }

    pub fn encodeControl(
        arena: Allocator,
        kind: enum { query, cancel },
        request_id: []const u8,
        grace_ms: u64,
    ) EncodeError![]u8 {
        if (request_id.len == 0 or request_id.len > 64) return error.ArgumentsTooLarge;
        var body: std.ArrayList(u8) = .empty;
        try body.append(arena, @intCast(request_id.len));
        try body.appendSlice(arena, request_id);
        var word: [8]u8 = undefined;
        std.mem.writeInt(u64, &word, grace_ms, .little);
        try body.appendSlice(arena, &word);
        var frame: std.ArrayList(u8) = .empty;
        std.mem.writeInt(u32, word[0..4], @intCast(body.items.len + 1), .little);
        try frame.appendSlice(arena, word[0..4]);
        try frame.append(arena, if (kind == .query) Kind.query else Kind.cancel);
        try frame.appendSlice(arena, body.items);
        return frame.items;
    }

    /// Everything one reply stream said.
    ///
    /// `started` and `ended` are lists rather than options so a caller driving
    /// several runs through one invocation can assert about each, and so a helper
    /// that emitted two terminal frames is a fact the caller can see rather than
    /// one silently overwritten by the last.
    pub const Reply = struct {
        started: []const Started,
        ended: []const Ended,
        stdout: []const u8,
        stderr: []const u8,
        /// The `failed` frame's message, if the helper could not start the work.
        failed: ?[]const u8,
        /// Bytes after the last complete frame. Non-zero means the stream ended
        /// mid-frame — a helper that died while writing — which is not the same
        /// as a helper that reported nothing, and the caller must be able to tell
        /// them apart.
        trailing: usize,
    };

    pub const DecodeError = error{
        StartedFrameWrongSize,
        EndedFrameWrongSize,
        UnknownFrameKind,
        FrameTooLarge,
    } || Allocator.Error;

    /// Reads a reply stream.
    ///
    /// Sizes are checked rather than assumed: a frame whose declared length is
    /// wrong by one byte would otherwise slice out of bounds and panic, and a
    /// panicking decoder names the wrong defect — this is the layer that is
    /// supposed to notice.
    pub fn decode(arena: Allocator, bytes: []const u8) DecodeError!Reply {
        var started: std.ArrayList(Started) = .empty;
        var ended: std.ArrayList(Ended) = .empty;
        var out: std.ArrayList(u8) = .empty;
        var err_out: std.ArrayList(u8) = .empty;
        var failed: ?[]const u8 = null;

        var at: usize = 0;
        while (at + 4 <= bytes.len) {
            const n = std.mem.readInt(u32, bytes[at..][0..4], .little);
            if (n == 0) break;
            if (n > max_frame) return error.FrameTooLarge;
            if (at + 4 + n > bytes.len) break;
            const kind = bytes[at + 4];
            const payload = bytes[at + 5 ..][0 .. n - 1];
            at += 4 + n;
            switch (kind) {
                Kind.started => {
                    if (payload.len != 24) return error.StartedFrameWrongSize;
                    try started.append(arena, .{
                        .pid = std.mem.readInt(i64, payload[0..8], .little),
                        .pgid = std.mem.readInt(i64, payload[8..16], .little),
                        .token = std.mem.readInt(u64, payload[16..24], .little),
                    });
                },
                Kind.exited => {
                    if (payload.len != 5) return error.EndedFrameWrongSize;
                    try ended.append(arena, .{
                        .how = @enumFromInt(payload[0]),
                        .status = std.mem.readInt(i32, payload[1..5], .little),
                    });
                },
                Kind.stdout => try out.appendSlice(arena, payload),
                Kind.stderr => try err_out.appendSlice(arena, payload),
                Kind.failed => failed = payload,
                else => return error.UnknownFrameKind,
            }
        }

        return .{
            .started = started.items,
            .ended = ended.items,
            .stdout = out.items,
            .stderr = err_out.items,
            .failed = failed,
            .trailing = bytes.len - at,
        };
    }
};

/// What the helper can vouch for, and the one thing it cannot.
///
/// `audit_isolation` is **false**, and that is the helper's own statement rather
/// than a placeholder: `src/helper/main.zig` implements no allowlist and claims
/// none. Setting it true because a helper is present is how `audited_execution`
/// would come to run against a boundary that does not exist — the precise thing
/// the release rules forbid.
pub const helper_capability: Capability = .{
    .supervisor = .helper,
    .pid_proof = .strong,
    .binary_framing = true,
    .remote_deadline = true,
    .audit_isolation = false,
};

/// Granted only to the closed audit request path after the helper returns the
/// compiled policy manifest acknowledgement. Ordinary helper runs continue to
/// use `helper_capability` and cannot inherit this claim.
pub const audit_capability: Capability = .{
    .supervisor = .helper,
    .pid_proof = .strong,
    .binary_framing = true,
    .remote_deadline = true,
    .audit_isolation = true,
};

test "gate: the host's wire constants are the helper's own" {
    const t = std.testing;
    // The helper is a separate compilation unit for a different target, so its
    // constants cannot be imported — they are read out of its source. A comment
    // asking the next reader to keep two numbers in step is not a mechanism, and
    // a request the far side refuses for a bound this side thought was larger is
    // a submitted attempt with no result.
    //
    // Scoped per block rather than by indented text: `const exited: u8 =` occurs
    // in both `Kind` (0x84) and `How` (0), so a flat table cannot say which one
    // it is asserting about, and the first version of this gate did not.
    const source = @embedFile("../helper/main.zig");

    const Block = struct {
        fn of(src: []const u8, header: []const u8) ![]const u8 {
            const at = std.mem.indexOf(u8, src, header) orelse return error.HelperBlockGone;
            const rest = src[at + header.len ..];
            const close = std.mem.indexOf(u8, rest, "\n};") orelse return error.HelperBlockUnterminated;
            return rest[0..close];
        }

        fn value(block: []const u8, decl: []const u8) ![]const u8 {
            const at = std.mem.indexOf(u8, block, decl) orelse return error.HelperDeclarationGone;
            if (std.mem.indexOfPos(u8, block, at + decl.len, decl) != null)
                return error.HelperDeclarationRepeated;
            const rest = block[at + decl.len ..];
            const semi = std.mem.indexOfScalar(u8, rest, ';') orelse
                return error.HelperDeclarationUnterminated;
            return rest[0..semi];
        }
    };

    var checked: usize = 0;
    const kind = try Block.of(source, "const Kind = struct {");
    const how = try Block.of(source, "const How = struct {");

    const cases = [_]struct { block: []const u8, decl: []const u8, want: []const u8 }{
        .{ .block = source, .decl = "\nconst max_frame = ", .want = "1 << 20" },
        .{ .block = source, .decl = "\nconst max_argv = ", .want = "256" },
        .{ .block = source, .decl = "\nconst argv_bytes = ", .want = "1 << 19" },
        .{ .block = source, .decl = "\nconst pump_bytes = ", .want = "32 * 1024" },
        .{ .block = kind, .decl = "const run: u8 = ", .want = "0x01" },
        .{ .block = kind, .decl = "const query: u8 = ", .want = "0x02" },
        .{ .block = kind, .decl = "const cancel: u8 = ", .want = "0x03" },
        .{ .block = kind, .decl = "const started: u8 = ", .want = "0x81" },
        .{ .block = kind, .decl = "const stdout: u8 = ", .want = "0x82" },
        .{ .block = kind, .decl = "const stderr: u8 = ", .want = "0x83" },
        .{ .block = kind, .decl = "const exited: u8 = ", .want = "0x84" },
        .{ .block = kind, .decl = "const failed: u8 = ", .want = "0x85" },
        .{ .block = how, .decl = "const exited: u8 = ", .want = "0" },
        .{ .block = how, .decl = "const signalled: u8 = ", .want = "1" },
        .{ .block = how, .decl = "const timed_out_killed: u8 = ", .want = "2" },
        .{ .block = how, .decl = "const timed_out_unconfirmed: u8 = ", .want = "3" },
        .{ .block = how, .decl = "const cancelled: u8 = ", .want = "4" },
    };
    for (cases) |c| {
        const got = Block.value(c.block, c.decl) catch |err| {
            std.debug.print(
                "src/helper/main.zig and its host codec disagree about `{s}`: {s}\n",
                .{ c.decl, @errorName(err) },
            );
            return err;
        };
        t.expectEqualStrings(c.want, got) catch |err| {
            std.debug.print("`{s}` disagrees between the helper and its host codec\n", .{c.decl});
            return err;
        };
        checked += 1;
    }
    // Asserted so that deleting a row above — the way a rule stops being checked
    // without anything failing — is itself a failure.
    try t.expectEqual(@as(usize, 17), checked);

    // And the values the host actually uses, against the same numbers.
    try t.expectEqual(@as(usize, 1 << 20), wire.max_frame);
    try t.expectEqual(@as(usize, 256), wire.max_argv);
    try t.expectEqual(@as(usize, 1 << 19), wire.argv_bytes);
    try t.expectEqual(@as(usize, 32 * 1024), wire.pump_bytes);
    try t.expectEqual(@as(u8, 0x01), wire.Kind.run);
    try t.expectEqual(@as(u8, 0x02), wire.Kind.query);
    try t.expectEqual(@as(u8, 0x03), wire.Kind.cancel);
    try t.expectEqual(@as(u8, 0x85), wire.Kind.failed);
    try t.expectEqual(@as(u8, 2), @intFromEnum(wire.How.timed_out_killed));
    try t.expectEqual(@as(u8, 3), @intFromEnum(wire.How.timed_out_unconfirmed));
    try t.expectEqual(@as(u8, 4), @intFromEnum(wire.How.cancelled));
}

test "gate: a request too large for the helper is refused before it is sent" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Refused here, not there. A request the far side rejects for its size is a
    // submitted attempt with no result — `indeterminate` for a fault nameable
    // before a byte left.
    const many = try arena.alloc([]const u8, wire.max_argv + 1);
    for (many) |*a| a.* = "x";
    try t.expectError(error.TooManyArguments, wire.encodeRun(arena, many, 0, 0));

    const big = try arena.alloc(u8, wire.argv_bytes);
    @memset(big, 'x');
    try t.expectError(error.ArgumentsTooLarge, wire.encodeRun(arena, &.{big}, 0, 0));

    // And the boundary is not off by one in the permissive direction: exactly
    // `max_argv` arguments encode.
    const exact = try arena.alloc([]const u8, wire.max_argv);
    for (exact) |*a| a.* = "x";
    const frame = try wire.encodeRun(arena, exact, 0, 0);
    try t.expectEqual(wire.Kind.run, frame[4]);
}

test "gate: a reply that ends mid-frame is not a reply that said nothing" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // A helper killed while writing its terminal frame, and a helper that
    // reported nothing at all, are different outcomes. If `trailing` were not
    // reported the caller would see an empty `ended` list for both and could
    // only guess.
    var stream: std.ArrayList(u8) = .empty;
    var head: [4]u8 = undefined;
    std.mem.writeInt(u32, &head, 25, .little);
    try stream.appendSlice(arena, &head);
    try stream.append(arena, wire.Kind.started);
    try stream.appendSlice(arena, &[_]u8{0} ** 24);
    // Then a header promising five bytes, with two arriving.
    std.mem.writeInt(u32, &head, 6, .little);
    try stream.appendSlice(arena, &head);
    try stream.append(arena, wire.Kind.exited);
    try stream.appendSlice(arena, &[_]u8{ 0, 0 });

    const reply = try wire.decode(arena, stream.items);
    try t.expectEqual(@as(usize, 1), reply.started.len);
    try t.expectEqual(@as(usize, 0), reply.ended.len);
    try t.expectEqual(@as(usize, 7), reply.trailing);

    // A complete stream leaves nothing over, so the field cannot be read as
    // "always non-zero".
    var whole: std.ArrayList(u8) = .empty;
    std.mem.writeInt(u32, &head, 6, .little);
    try whole.appendSlice(arena, &head);
    try whole.append(arena, wire.Kind.exited);
    try whole.appendSlice(arena, &[_]u8{ 2, 0, 0, 0, 0 });
    const clean = try wire.decode(arena, whole.items);
    try t.expectEqual(@as(usize, 0), clean.trailing);
    try t.expectEqual(wire.How.timed_out_killed, clean.ended[0].how);
}

/// Features that must refuse rather than pretend under a weak supervisor.
pub const Requirement = enum {
    /// Killing a process tree and proving it is gone.
    verified_cancellation,
    /// Byte-exact stdin/stdout.
    binary_streams,
    /// A deadline that outlives the connection.
    remote_deadline,
    /// A command allowlist the remote enforces.
    audited_execution,

    pub fn satisfiedBy(r: Requirement, c: Capability) bool {
        return switch (r) {
            .verified_cancellation => c.pid_proof == .strong,
            .binary_streams => c.binary_framing,
            .remote_deadline => c.remote_deadline,
            .audited_execution => c.audit_isolation,
        };
    }

    pub fn explain(r: Requirement) []const u8 {
        return switch (r) {
            .verified_cancellation => "cancelling a running command requires a supervisor that can prove the process is gone; install the remote helper",
            .binary_streams => "byte-exact streams require the remote helper (shell mode annotates the stream with markers)",
            .remote_deadline => "a deadline that survives a dropped connection requires the remote helper",
            .audited_execution => "audit mode requires the remote helper to enforce the allowlist remotely; a local string check is not a boundary",
        };
    }
};

/// Identity the shell reported for the process running our command.
pub const Identity = struct {
    pid: i64,
    pgid: ?i64 = null,
    /// Process start time. Without it a recycled pid is indistinguishable
    /// from ours, which is why `pid_proof` is only `weak` when it is absent.
    start_token: ?[]const u8 = null,
};

/// How a command ended, in the terms the ledger settles on.
///
/// A tagged union and not `?i32`, because a number cannot hold what a real
/// supervisor measures. `waitid` separates a child that exited from one a signal
/// killed (`src/helper/main.zig` reports both), and a remote deadline has two
/// outcomes that settle differently: the supervisor stopped the group and
/// confirmed it gone, or it signalled and the window closed with the group still
/// there. The first is `timed_out`. The second is `indeterminate` — it claims
/// only that we asked.
///
/// The point of the union is that the wrong read cannot be written. With `?i32`
/// the caller unwraps a number and has no way to ask what kind of number it is,
/// which is how `128 + signal` comes to be reported as an exit status and how a
/// deadline we could not confirm comes to be reported as one we enforced.
pub const Ending = union(enum) {
    /// The command ran to completion; this is its status.
    exited: i32,
    /// A signal ended it. The number is the signal.
    signalled: i32,
    /// A remote deadline fired and the supervisor confirmed the group is gone.
    timed_out: Deadline,
    /// A remote deadline fired and the supervisor could not confirm the stop.
    timed_out_unconfirmed: Deadline,
    /// Nothing was established. The text says why, for the receipt.
    unknown: []const u8,

    pub const Deadline = struct {
        after_ms: i64,
        /// The signal the supervisor last sent, for the receipt to name.
        signal: i32,
    };

    /// The status a POSIX shell would report for this ending.
    ///
    /// `128 + signal` is the shell convention, and it is computed here rather
    /// than at each call site so that no caller has to remember it and none can
    /// disagree about it.
    pub fn shellStatus(e: Ending) ?i32 {
        return switch (e) {
            .exited => |code| code,
            .signalled => |sig| 128 + sig,
            .timed_out, .timed_out_unconfirmed, .unknown => null,
        };
    }
};

pub const Observed = struct {
    /// Present once the remote confirmed a running process.
    identity: ?Identity = null,
    /// How it ended, once it has.
    ending: Ending = .{ .unknown = "no outcome was reported" },
    /// Output with the supervision markers removed.
    stdout: []const u8,
    stderr: []const u8,
};

pub const HelperReplyError = wire.DecodeError || error{
    TruncatedFrame,
    HelperDidNotStart,
    HelperDidNotFinish,
    HelperReportedFailure,
    HelperReplyAmbiguous,
};

/// Converts the framed helper reply into the same `Observed` vocabulary the
/// shell supervisor feeds to the ledger. Exactly one start and one ending are
/// required; accepting the first of two would make process identity depend on
/// frame order after a protocol fault.
pub fn parseHelper(arena: Allocator, bytes: []const u8, deadline_ms: u64) HelperReplyError!Observed {
    const reply = try wire.decode(arena, bytes);
    if (reply.failed != null) return error.HelperReportedFailure;
    if (reply.trailing != 0) return error.TruncatedFrame;
    if (reply.started.len == 0) return error.HelperDidNotStart;
    if (reply.started.len != 1 or reply.ended.len > 1) return error.HelperReplyAmbiguous;
    if (reply.ended.len == 0) return error.HelperDidNotFinish;
    const started = reply.started[0];
    const ended = reply.ended[0];
    return .{
        .identity = .{
            .pid = started.pid,
            .pgid = started.pgid,
            .start_token = try std.fmt.allocPrint(arena, "{d}", .{started.token}),
        },
        .ending = switch (ended.how) {
            .exited => .{ .exited = ended.status },
            .signalled => .{ .signalled = ended.status },
            .timed_out_killed => .{ .timed_out = .{ .after_ms = @intCast(deadline_ms), .signal = ended.status } },
            .timed_out_unconfirmed => .{ .timed_out_unconfirmed = .{ .after_ms = @intCast(deadline_ms), .signal = ended.status } },
            .cancelled => .{ .unknown = "the remote helper reported an independent cancellation; query its durable request state to reconcile it" },
            _ => .{ .unknown = "the remote helper reported an ending this binary does not know" },
        },
        .stdout = reply.stdout,
        .stderr = reply.stderr,
    };
}

test "helper bytes, digest, capability and reply parser are wired into production" {
    const t = std.testing;
    try t.expect(helper_executable.len > 0);
    var digest: [32]u8 = undefined;
    helperSha256(&digest);
    var nonzero = false;
    for (digest) |b| nonzero = nonzero or b != 0;
    try t.expect(nonzero);
    try t.expect(Requirement.remote_deadline.satisfiedBy(helper_capability));
    try t.expect(Requirement.verified_cancellation.satisfiedBy(helper_capability));
    try t.expect(!Requirement.audited_execution.satisfiedBy(helper_capability));
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const guarded = try guardedRemoteHelperCommand(arena_state.allocator());
    var hex: [@import("digest.zig").hex_len]u8 = undefined;
    const want = @import("digest.zig").hex(helper_executable, &hex);
    try t.expect(std.mem.indexOf(u8, guarded, want) != null);
    try t.expect(std.mem.endsWith(u8, guarded, remote_helper_command));
}

/// Wraps a command so the shell reports the process identity before running
/// it and the exit status after.
///
/// `nonce` must be unique per attempt: the markers are stripped from the
/// output by prefix match, and a command that happens to print the same text
/// would otherwise have its output mangled.
///
/// The command runs in a subshell, and that is load-bearing rather than
/// stylistic. Run inline, a command ending in `exit 42` — or any script whose
/// last act is `exit` — terminates the very shell that was going to write the
/// exit marker. The marker never appears, the outcome reads as unknown, and
/// `terminus exec -- exit 42` comes back `indeterminate` for a command whose
/// status was never in doubt. The subshell absorbs the exit; `$?` then carries
/// it to the marker.
///
/// Note what this does *not* do. `$$` is the pid of the wrapper shell, which
/// is the parent of the subshell rather than the command itself; it shares the
/// process group, so it is usable for signalling but is not proof of anything
/// once the connection drops, and reading the start token is best-effort
/// across platforms. Hence `pid_proof = .weak`.
pub fn wrapShell(arena: Allocator, command: []const u8, nonce: u64) Allocator.Error![]u8 {
    return std.fmt.allocPrint(arena,
        \\__t_pid=$$
        \\__t_pgid=$(ps -o pgid= -p $__t_pid 2>/dev/null | tr -d ' ')
        \\__t_tok=$(awk '{{print $22}}' /proc/$__t_pid/stat 2>/dev/null || ps -o lstart= -p $__t_pid 2>/dev/null | tr -d ' \n')
        \\printf '__TERMINUS_START_{d}__ pid=%s pgid=%s token=%s\n' "$__t_pid" "$__t_pgid" "$__t_tok"
        \\(
        \\{s}
        \\)
        \\__t_rc=$?
        \\printf '__TERMINUS_EXIT_{d}__ code=%s\n' "$__t_rc"
    , .{ nonce, command, nonce });
}

fn powerShellEncoded(arena: Allocator, script: []const u8) Allocator.Error![]u8 {
    const utf16 = std.unicode.utf8ToUtf16LeAlloc(arena, script) catch return error.OutOfMemory;
    const bytes = std.mem.sliceAsBytes(utf16);
    const encoded = try arena.alloc(u8, std.base64.standard.Encoder.calcSize(bytes.len));
    _ = std.base64.standard.Encoder.encode(encoded, bytes);
    return encoded;
}

/// Supervises a native Windows PowerShell command without asking PowerShell to
/// parse caller text from a command-line quote.  Both the child command and
/// the fixed parent wrapper travel as UTF-16LE `-EncodedCommand` payloads.  The
/// parent survives `exit` in the child, publishes its wrapper PID/start token,
/// waits for it, then emits the same terminal marker `parseShell` consumes.
pub fn wrapPowerShell(arena: Allocator, command: []const u8, nonce: u64) Allocator.Error![]u8 {
    const child_script = try std.fmt.allocPrint(arena, "$ProgressPreference='SilentlyContinue'; {s}", .{command});
    const child = try powerShellEncoded(arena, child_script);
    const wrapper = try std.fmt.allocPrint(arena,
        \\$ErrorActionPreference = 'Stop'
        \\$ProgressPreference = 'SilentlyContinue'
        \\$__t_tok = (Get-Process -Id $PID).StartTime.ToFileTimeUtc()
        \\[Console]::Out.WriteLine(('__TERMINUS_START_{d}__ pid={{0}} pgid= token={{1}}' -f $PID,$__t_tok))
        \\& powershell.exe -NoLogo -NoProfile -NonInteractive -InputFormat Text -OutputFormat Text -EncodedCommand '{s}'
        \\$__t_rc = if ($null -eq $LASTEXITCODE) {{ 1 }} else {{ [int]$LASTEXITCODE }}
        \\[Console]::Out.WriteLine(('__TERMINUS_EXIT_{d}__ code={{0}}' -f $__t_rc))
        \\exit $__t_rc
    , .{ nonce, child, nonce });
    const encoded = try powerShellEncoded(arena, wrapper);
    return std.fmt.allocPrint(arena,
        "powershell.exe -NoLogo -NoProfile -NonInteractive -InputFormat Text -OutputFormat Text -ExecutionPolicy Bypass -EncodedCommand {s}",
        .{encoded},
    );
}

/// Splits the supervision markers back out of the captured output.
///
/// A missing exit marker is meaningful rather than an error: it means the
/// command's fate is unknown (the channel closed early, the shell was
/// killed), which is precisely the case that must become `indeterminate`
/// instead of being guessed at.
pub fn parseShell(arena: Allocator, nonce: u64, stdout: []const u8, stderr: []const u8) Allocator.Error!Observed {
    const start_marker = try std.fmt.allocPrint(arena, "__TERMINUS_START_{d}__ ", .{nonce});
    const exit_marker = try std.fmt.allocPrint(arena, "__TERMINUS_EXIT_{d}__ ", .{nonce});

    var kept: std.ArrayList(u8) = .empty;
    var identity: ?Identity = null;
    var exit_code: ?i32 = null;

    var lines = std.mem.splitScalar(u8, stdout, '\n');
    var first = true;
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (std.mem.startsWith(u8, line, start_marker)) {
            identity = parseIdentity(arena, line[start_marker.len..]) catch null;
            continue;
        }
        // A command is allowed to finish without printing a newline.  In that
        // case the shell appends our terminal marker to the command's last
        // output line.  Looking only at line prefixes would leave the marker
        // visible and, worse, report a proven exit as unknown.  The wrapper's
        // marker is terminal and nonce-bound, so consume its final occurrence
        // while preserving every byte before it.
        if (std.mem.lastIndexOf(u8, line, exit_marker)) |marker_at| {
            if (parseExit(line[marker_at + exit_marker.len ..])) |code| {
                if (!first) try kept.append(arena, '\n');
                if (marker_at != 0) {
                    try kept.appendSlice(arena, raw[0..marker_at]);
                    first = false;
                }
                exit_code = code;
                break;
            }
        }
        if (!first) try kept.append(arena, '\n');
        try kept.appendSlice(arena, raw);
        first = false;
    }

    return .{
        .identity = identity,
        .ending = if (exit_code) |code| .{ .exited = code } else .{
            .unknown = "remote closed the channel before reporting an exit status",
        },
        .stdout = kept.items,
        .stderr = stderr,
    };
}

fn parseIdentity(arena: Allocator, fields: []const u8) Allocator.Error!?Identity {
    var pid: ?i64 = null;
    var pgid: ?i64 = null;
    var token: ?[]const u8 = null;

    var it = std.mem.splitScalar(u8, fields, ' ');
    while (it.next()) |field| {
        const eq = std.mem.indexOfScalar(u8, field, '=') orelse continue;
        const key = field[0..eq];
        const value = std.mem.trim(u8, field[eq + 1 ..], " \t\r");
        if (value.len == 0) continue;
        if (std.mem.eql(u8, key, "pid")) {
            pid = std.fmt.parseInt(i64, value, 10) catch null;
        } else if (std.mem.eql(u8, key, "pgid")) {
            pgid = std.fmt.parseInt(i64, value, 10) catch null;
        } else if (std.mem.eql(u8, key, "token")) {
            token = try arena.dupe(u8, value);
        }
    }
    return if (pid) |p| .{ .pid = p, .pgid = pgid, .start_token = token } else null;
}

fn parseExit(fields: []const u8) ?i32 {
    const eq = std.mem.indexOfScalar(u8, fields, '=') orelse return null;
    const value = std.mem.trim(u8, fields[eq + 1 ..], " \t\r");
    return std.fmt.parseInt(i32, value, 10) catch null;
}

test "shell capability does not overstate itself" {
    const t = std.testing;
    // Every guarantee the helper exists to provide must read as absent here,
    // so a feature that needs one refuses instead of quietly degrading.
    try t.expect(!Requirement.verified_cancellation.satisfiedBy(shell_capability));
    try t.expect(!Requirement.binary_streams.satisfiedBy(shell_capability));
    try t.expect(!Requirement.remote_deadline.satisfiedBy(shell_capability));
    try t.expect(!Requirement.audited_execution.satisfiedBy(shell_capability));
}

test parseShell {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const out =
        "__TERMINUS_START_7__ pid=4242 pgid=4242 token=91823\n" ++
        "hello\nworld\n" ++
        "__TERMINUS_EXIT_7__ code=3\n";
    const observed = try parseShell(arena, 7, out, "");
    try t.expectEqual(@as(i64, 4242), observed.identity.?.pid);
    try t.expectEqual(@as(i64, 4242), observed.identity.?.pgid.?);
    try t.expectEqualStrings("91823", observed.identity.?.start_token.?);
    try t.expectEqual(Ending{ .exited = 3 }, observed.ending);
    try t.expectEqualStrings("hello\nworld\n", observed.stdout);
}

test "shell exit marker may follow output without a newline" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();

    const out =
        "__TERMINUS_START_17__ pid=4242 pgid=4242 token=91823\n" ++
        "no-newline__TERMINUS_EXIT_17__ code=0\n";
    const observed = try parseShell(arena_state.allocator(), 17, out, "");
    try t.expectEqual(Ending{ .exited = 0 }, observed.ending);
    try t.expectEqualStrings("no-newline", observed.stdout);
}

test "PowerShell wrapper survives child exit and publishes identity and terminal markers" {
    if (@import("builtin").os.tag != .windows) return;
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const wrapped = try wrapPowerShell(arena, "Write-Output 'powershell-wrapper-ok'; exit 7", 71);
    const encoded_at = std.mem.lastIndexOfScalar(u8, wrapped, ' ') orelse return error.InvalidWrapper;
    const result = try std.process.run(arena, t.io, .{
        .argv = &.{
            "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
            "-InputFormat", "Text", "-OutputFormat", "Text",
            "-ExecutionPolicy", "Bypass", "-EncodedCommand", wrapped[encoded_at + 1 ..],
        },
        .stdout_limit = .limited(1 << 16),
        .stderr_limit = .limited(1 << 16),
        .timeout = .{ .duration = .{ .raw = .fromMilliseconds(10_000), .clock = .awake } },
    });
    try t.expectEqual(@as(u8, 7), switch (result.term) {
        .exited => |code| code,
        else => return error.PowerShellWrapperDidNotExit,
    });
    const observed = try parseShell(arena, 71, result.stdout, result.stderr);
    try t.expect(observed.identity != null);
    try t.expect(observed.identity.?.pid > 0);
    try t.expect(observed.identity.?.start_token != null);
    try t.expectEqual(Ending{ .exited = 7 }, observed.ending);
    try t.expect(std.mem.indexOf(u8, observed.stdout, "powershell-wrapper-ok") != null);
}

test "a missing exit marker leaves the outcome unknown" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // The channel closed after the command started producing output. We know
    // it began; we do not know how it ended, and saying otherwise is the
    // whole class of bug this design exists to prevent.
    const truncated = "__TERMINUS_START_9__ pid=51 pgid=51 token=1\npartial outp";
    const observed = try parseShell(arena, 9, truncated, "");
    try t.expectEqual(@as(i64, 51), observed.identity.?.pid);
    try t.expectEqual(@as(?i32, null), observed.ending.shellStatus());
    try t.expectEqualStrings("partial outp", observed.stdout);
}

test "identity is optional when the shell could not report it" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // A shell without ps/procfs still reports a pid; the token is what goes
    // missing, and that is exactly why the proof is only weak.
    const out = "__TERMINUS_START_3__ pid=8 pgid= token=\nok\n__TERMINUS_EXIT_3__ code=0\n";
    const observed = try parseShell(arena, 3, out, "");
    try t.expectEqual(@as(i64, 8), observed.identity.?.pid);
    try t.expectEqual(@as(?i64, null), observed.identity.?.pgid);
    try t.expectEqual(@as(?[]const u8, null), observed.identity.?.start_token);
    try t.expectEqual(Ending{ .exited = 0 }, observed.ending);
    try t.expectEqualStrings("ok\n", observed.stdout);
}

test "command output resembling a marker is not stripped" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // A different nonce belongs to somebody else's attempt (or to the
    // command's own output) and must survive untouched.
    const out =
        "__TERMINUS_START_5__ pid=1 pgid=1 token=1\n" ++
        "__TERMINUS_EXIT_999__ code=0\n" ++
        "__TERMINUS_EXIT_5__ code=0\n";
    const observed = try parseShell(arena, 5, out, "");
    try t.expectEqual(Ending{ .exited = 0 }, observed.ending);
    try t.expectEqualStrings("__TERMINUS_EXIT_999__ code=0\n", observed.stdout);
}
