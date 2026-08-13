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
pub const shell_capability: Capability = .{
    .supervisor = .shell,
    .pid_proof = .weak,
    .binary_framing = false,
    .remote_deadline = false,
    .audit_isolation = false,
};

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

pub const Observed = struct {
    /// Present once the remote confirmed a running process.
    identity: ?Identity = null,
    /// Present once the command finished.
    exit_code: ?i32 = null,
    /// Output with the supervision markers removed.
    stdout: []const u8,
    stderr: []const u8,
};

/// Wraps a command so the shell reports the process identity before running
/// it and the exit status after.
///
/// `nonce` must be unique per attempt: the markers are stripped from the
/// output by prefix match, and a command that happens to print the same text
/// would otherwise have its output mangled.
///
/// Note what this does *not* do. `$$` is the pid of the shell that runs the
/// command, which is the right process for a simple exec but is not a proof
/// of anything after the connection drops, and reading the start token is
/// best-effort across platforms. Hence `pid_proof = .weak`.
pub fn wrapShell(arena: Allocator, command: []const u8, nonce: u64) Allocator.Error![]u8 {
    return std.fmt.allocPrint(arena,
        \\__t_pid=$$
        \\__t_pgid=$(ps -o pgid= -p $__t_pid 2>/dev/null | tr -d ' ')
        \\__t_tok=$(awk '{{print $22}}' /proc/$__t_pid/stat 2>/dev/null || ps -o lstart= -p $__t_pid 2>/dev/null | tr -d ' \n')
        \\printf '__TERMINUS_START_{d}__ pid=%s pgid=%s token=%s\n' "$__t_pid" "$__t_pgid" "$__t_tok"
        \\{s}
        \\__t_rc=$?
        \\printf '__TERMINUS_EXIT_{d}__ code=%s\n' "$__t_rc"
    , .{ nonce, command, nonce });
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
        if (std.mem.startsWith(u8, line, exit_marker)) {
            exit_code = parseExit(line[exit_marker.len..]);
            continue;
        }
        if (!first) try kept.append(arena, '\n');
        try kept.appendSlice(arena, raw);
        first = false;
    }

    return .{
        .identity = identity,
        .exit_code = exit_code,
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
    try t.expectEqual(@as(i32, 3), observed.exit_code.?);
    try t.expectEqualStrings("hello\nworld\n", observed.stdout);
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
    try t.expectEqual(@as(?i32, null), observed.exit_code);
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
    try t.expectEqual(@as(i32, 0), observed.exit_code.?);
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
    try t.expectEqual(@as(i32, 0), observed.exit_code.?);
    try t.expectEqualStrings("__TERMINUS_EXIT_999__ code=0\n", observed.stdout);
}
