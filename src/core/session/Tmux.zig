//! Remote tmux session management, built on Executor exec calls — works
//! identically over a direct SSH connection or the daemon's pooled one.
//!
//! Layout on the remote host:
//! * one tmux session per Terminus session, named `t-<name>`
//! * `tmux pipe-pane` mirrors all pane output into
//!   `~/.terminus/logs/<name>.log`, which is what cursor reads consume
//!
//! The local sqlite `sessions.cursor` is a byte offset into that log.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Ssh = @import("../ssh/Client.zig");
const Executor = @import("../exec.zig").Executor;

const log_dir = "$HOME/.terminus/logs";

pub const Error = Ssh.ExecError || error{
    TmuxMissing,
    SessionNotFound,
    /// The session disappeared while a command was running in it (the
    /// command likely terminated the shell, e.g. `exit`).
    SessionDied,
    RemoteFailed,
    CommandTimeout,
};

fn logPath(arena: Allocator, name: []const u8) Allocator.Error![]u8 {
    return std.fmt.allocPrint(arena, "{s}/{s}.log", .{ log_dir, name });
}

/// tmux session names get a `t-` prefix to keep Terminus-managed sessions
/// recognizable in `tmux ls` on the server.
fn tmuxName(arena: Allocator, name: []const u8) Allocator.Error![]u8 {
    return std.fmt.allocPrint(arena, "t-{s}", .{name});
}

/// Wraps `s` in single quotes for POSIX shells ('a'\''b' pattern).
fn shellQuote(arena: Allocator, s: []const u8) Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.append(arena, '\'');
    for (s) |ch| {
        if (ch == '\'') {
            try out.appendSlice(arena, "'\\''");
        } else {
            try out.append(arena, ch);
        }
    }
    try out.append(arena, '\'');
    return out.toOwnedSlice(arena);
}

fn run(executor: Executor, arena: Allocator, command: []const u8) Error!Ssh.ExecResult {
    return executor.exec(arena, command);
}

/// Creates the session if absent (idempotent) and starts output logging.
pub fn ensure(executor: Executor, arena: Allocator, name: []const u8) Error!void {
    const tname = try tmuxName(arena, name);
    // new-session and pipe-pane must be one tmux command sequence (';'):
    // as separate invocations the second can race a freshly (re)started
    // server and fail with "can't find pane".
    const script = try std.fmt.allocPrint(arena,
        \\command -v tmux >/dev/null || exit 41
        \\mkdir -p {s}
        \\tmux has-session -t ={s} 2>/dev/null && exit 0
        \\tmux new-session -d -s {s} ';' pipe-pane -o 'cat >> {s}/{s}.log' || exit 42
    , .{ log_dir, tname, tname, log_dir, name });
    const result = try run(executor, arena, script);
    switch (result.exit_code) {
        0 => {},
        41 => return error.TmuxMissing,
        else => return error.RemoteFailed,
    }
}

pub const RemoteSession = struct {
    name: []const u8, // Terminus name (prefix stripped)
    created: []const u8, // unix seconds, as reported by tmux
    attached: bool,
};

/// Sessions alive on the remote server right now (source of truth).
pub fn list(executor: Executor, arena: Allocator) Error![]RemoteSession {
    // Space-separated: tmux -F does not expand \t, and our validated
    // session names cannot contain spaces.
    const result = try run(executor, arena,
        \\command -v tmux >/dev/null || exit 41
        \\tmux ls -F '#{session_name} #{session_created} #{session_attached}' 2>/dev/null || true
    );
    if (result.exit_code == 41) return error.TmuxMissing;

    var out: std.ArrayList(RemoteSession) = .empty;
    var lines = std.mem.splitScalar(u8, result.stdout, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.splitScalar(u8, std.mem.trimEnd(u8, line, "\r"), ' ');
        const raw_name = fields.next() orelse continue;
        if (!std.mem.startsWith(u8, raw_name, "t-")) continue;
        try out.append(arena, .{
            .name = raw_name["t-".len..],
            .created = fields.next() orelse "",
            .attached = if (fields.next()) |a| !std.mem.eql(u8, a, "0") else false,
        });
    }
    return out.toOwnedSlice(arena);
}

/// Kills the remote tmux session and removes its log file.
pub fn kill(executor: Executor, arena: Allocator, name: []const u8) Error!void {
    const tname = try tmuxName(arena, name);
    const script = try std.fmt.allocPrint(arena,
        \\tmux kill-session -t ={s} 2>/dev/null; rm -f {s}/{s}.log
    , .{ tname, log_dir, name });
    _ = try run(executor, arena, script);
}

/// Types `input` into the session as if at the keyboard, plus Enter unless
/// `no_enter`. Does not wait for any output.
pub fn sendKeys(executor: Executor, arena: Allocator, name: []const u8, input: []const u8, no_enter: bool) Error!void {
    const tname = try tmuxName(arena, name);
    const quoted = try shellQuote(arena, input);
    // Pane targets need the trailing ':' (exact session, default window):
    // a bare '=name' is rejected as a pane target by some tmux versions.
    const script = try std.fmt.allocPrint(arena,
        \\tmux has-session -t ={s} 2>/dev/null || exit 43
        \\tmux send-keys -t ={s}: -l -- {s} || exit 42
        \\{s}
    , .{ tname, tname, quoted, if (no_enter) "" else try std.fmt.allocPrint(arena, "tmux send-keys -t ={s}: Enter", .{tname}) });
    const result = try run(executor, arena, script);
    switch (result.exit_code) {
        0 => {},
        43 => return error.SessionNotFound,
        else => return error.RemoteFailed,
    }
}

pub const ReadResult = struct {
    data: []const u8,
    /// Byte offset to continue from next time.
    next_cursor: i64,
    /// Total size of the remote log (cursor > size means log was truncated).
    log_size: i64,
};

/// Reads the session's output log from byte offset `cursor`, at most
/// `limit` bytes. Missing log file reads as empty.
pub fn readLog(executor: Executor, arena: Allocator, name: []const u8, cursor: i64, limit: i64) Error!ReadResult {
    const path = try logPath(arena, name);
    // First line of output is the log size, the rest is the data window.
    const script = try std.fmt.allocPrint(arena,
        \\f={s}
        \\[ -f "$f" ] || {{ echo 0; exit 0; }}
        \\wc -c < "$f"
        \\tail -c +{d} "$f" | head -c {d}
    , .{ path, cursor + 1, limit });
    const result = try run(executor, arena, script);
    if (result.exit_code != 0) return error.RemoteFailed;

    const newline = std.mem.indexOfScalar(u8, result.stdout, '\n') orelse
        return .{ .data = "", .next_cursor = cursor, .log_size = 0 };
    const size_text = std.mem.trim(u8, result.stdout[0..newline], " \t\r");
    const log_size = std.fmt.parseInt(i64, size_text, 10) catch return error.RemoteFailed;
    const data = result.stdout[newline + 1 ..];
    return .{
        .data = data,
        .next_cursor = @min(cursor + @as(i64, @intCast(data.len)), log_size),
        .log_size = log_size,
    };
}

pub const ExecInResult = struct {
    output: []const u8,
    exit_code: i32,
    /// Log offset after the command's output (new cursor for the caller).
    next_cursor: i64,
};

/// Runs a command inside the session's shell and waits for completion by
/// watching the output log for a sentinel line. Unlike plain `exec`, the
/// command inherits the session's cwd, env, and running state.
pub fn execIn(
    executor: Executor,
    arena: Allocator,
    io: std.Io,
    name: []const u8,
    command: []const u8,
    start_cursor: i64,
    timeout_ms: i64,
) Error!ExecInResult {
    // Nonce ties the sentinel to this invocation; derived from the wall
    // clock, which is plenty for a single-user CLI.
    const nonce: u64 = @intCast(@mod(std.Io.Timestamp.now(io, .real).nanoseconds, 1_000_000_007));
    const sentinel = try std.fmt.allocPrint(arena, "__TERMINUS_{d}__", .{nonce});

    // `; echo <sentinel>:$?` runs in the session shell after the command,
    // regardless of its exit status.
    const full = try std.fmt.allocPrint(arena, "{s}; echo {s}:$?", .{ command, sentinel });
    try sendKeys(executor, arena, name, full, false);

    // Poll the log until the sentinel shows up. Backoff keeps the SSH
    // round-trips reasonable for long commands.
    var cursor = start_cursor;
    var collected: std.ArrayList(u8) = .empty;
    var waited_ms: i64 = 0;
    var poll_ms: i64 = 150;
    while (true) {
        const chunk = try readLog(executor, arena, name, cursor, 1 << 20);
        cursor = chunk.next_cursor;
        try collected.appendSlice(arena, chunk.data);

        // Search the *stripped* text: escape sequences (bracketed paste,
        // OSC beacons) can precede the marker on the same raw line without
        // a newline, which would defeat a line-start match on raw bytes.
        const cleaned = try stripTerminalNoise(arena, collected.items);
        if (findSentinel(cleaned, sentinel)) |found| {
            // Echoed keystrokes also land in the log: the first line is the
            // typed command (containing the sentinel text); the real marker
            // is a line that *starts* with the sentinel.
            return .{
                .output = cleaned[found.output_start..found.output_end],
                .exit_code = found.exit_code,
                .next_cursor = cursor,
            };
        }

        if (waited_ms >= timeout_ms) return error.CommandTimeout;

        // The command may have killed the shell (e.g. `exit`), which
        // destroys the pane — the sentinel will never arrive.
        if (!try isAlive(executor, arena, name)) return error.SessionDied;

        std.Io.sleep(io, .{ .nanoseconds = poll_ms * std.time.ns_per_ms }, .awake) catch {};
        waited_ms += poll_ms;
        poll_ms = @min(poll_ms * 2, 2000);
    }
}

pub fn isAlive(executor: Executor, arena: Allocator, name: []const u8) Error!bool {
    const tname = try tmuxName(arena, name);
    const script = try std.fmt.allocPrint(arena, "tmux has-session -t ={s} 2>/dev/null", .{tname});
    const result = try run(executor, arena, script);
    return result.exit_code == 0;
}

pub const JobProbe = struct {
    /// New (cleaned) output since the given cursor.
    output: []const u8,
    next_cursor: i64,
    /// Set when the sentinel result line appeared: the job finished.
    exit_code: ?i32,
    session_alive: bool,
};

/// One SSH round to answer "how is this job doing": reads new log output,
/// looks for the sentinel result line, checks pane liveness. Used by both
/// `job status` and `job read`.
pub fn probeJob(
    executor: Executor,
    arena: Allocator,
    name: []const u8,
    sentinel: []const u8,
    cursor: i64,
    limit: i64,
) Error!JobProbe {
    const chunk = try readLog(executor, arena, name, cursor, limit);
    const cleaned = try stripTerminalNoise(arena, chunk.data);
    var exit_code: ?i32 = null;
    var output: []const u8 = cleaned;
    if (findSentinel(cleaned, sentinel)) |found| {
        exit_code = found.exit_code;
        output = cleaned[found.output_start..found.output_end];
    }
    return .{
        .output = output,
        .next_cursor = chunk.next_cursor,
        .exit_code = exit_code,
        .session_alive = try isAlive(executor, arena, name),
    };
}

/// The pipe-pane log is a raw terminal stream: it carries CSI/OSC escape
/// sequences (bracketed paste, shell integration beacons) and CR line
/// endings. Strip them so agents get plain text.
pub fn stripTerminalNoise(arena: Allocator, raw: []const u8) Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < raw.len) {
        const ch = raw[i];
        if (ch == 0x1b and i + 1 < raw.len) {
            const kind = raw[i + 1];
            if (kind == '[') {
                // CSI: ESC [ params... final-byte(0x40-0x7e)
                i += 2;
                while (i < raw.len and (raw[i] < 0x40 or raw[i] > 0x7e)) i += 1;
                if (i < raw.len) i += 1;
                continue;
            }
            if (kind == ']') {
                // OSC: ESC ] ... (BEL | ESC \)
                i += 2;
                while (i < raw.len) {
                    if (raw[i] == 0x07) {
                        i += 1;
                        break;
                    }
                    if (raw[i] == 0x1b and i + 1 < raw.len and raw[i + 1] == '\\') {
                        i += 2;
                        break;
                    }
                    i += 1;
                }
                continue;
            }
            // Two-byte escape (ESC c, ESC =, ...)
            i += 2;
            continue;
        }
        if (ch == '\r') {
            i += 1;
            continue;
        }
        try out.append(arena, ch);
        i += 1;
    }
    return out.toOwnedSlice(arena);
}

test stripTerminalNoise {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const cleaned = try stripTerminalNoise(
        arena_state.allocator(),
        "\x1b[?2004l\r\x1b]3008;start=abc\x07hello\r\n\x1b[0mworld\n",
    );
    try t.expectEqualStrings("hello\nworld\n", cleaned);
}

const SentinelHit = struct {
    output_start: usize,
    output_end: usize,
    exit_code: i32,
};

/// Locates the sentinel *result* line (line-start match), skipping the
/// echoed keystroke line. Output spans from after the echo line to the
/// marker line.
fn findSentinel(data: []const u8, sentinel: []const u8) ?SentinelHit {
    var search_from: usize = 0;
    var echo_end: ?usize = null;
    while (std.mem.indexOfPos(u8, data, search_from, sentinel)) |pos| {
        const line_start = if (std.mem.lastIndexOfScalar(u8, data[0..pos], '\n')) |nl| nl + 1 else 0;
        const line_end = std.mem.indexOfScalarPos(u8, data, pos, '\n') orelse data.len;
        if (line_start == pos) {
            // Result line: "<sentinel>:<code>"
            const after = data[pos + sentinel.len .. line_end];
            if (after.len >= 2 and after[0] == ':') {
                const code_text = std.mem.trim(u8, after[1..], " \r");
                if (std.fmt.parseInt(i32, code_text, 10)) |code| {
                    const start = echo_end orelse 0;
                    return .{ .output_start = @min(start, line_start), .output_end = line_start, .exit_code = code };
                } else |_| {}
            }
        } else {
            // Echoed keystrokes; real output starts on the next line.
            echo_end = @min(line_end + 1, data.len);
        }
        search_from = pos + sentinel.len;
    }
    return null;
}

test findSentinel {
    const t = std.testing;
    const data = "$ ls; echo __X__:$?\r\nfile1\r\nfile2\r\n__X__:0\r\n";
    const hit = findSentinel(data, "__X__").?;
    try t.expectEqualStrings("file1\r\nfile2\r\n", data[hit.output_start..hit.output_end]);
    try t.expectEqual(0, hit.exit_code);
    try t.expectEqual(null, findSentinel("$ ls; echo __X__:$?\r\npartial", "__X__"));
}
