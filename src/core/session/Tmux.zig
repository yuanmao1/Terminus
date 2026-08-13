//! Remote tmux session management, built on Executor exec calls — works
//! identically over a direct SSH connection or the daemon's pooled one.
//!
//! Layout on the remote host:
//! * one tmux session per Terminus session, named `t-<name>`
//! * `tmux pipe-pane` mirrors all pane output into
//!   `~/.terminus/logs/<name>.log`, which is what cursor reads consume
//! * a job additionally writes `~/.terminus/results/<request-id>.json` — its
//!   durable terminal result, keyed by the operation that launched it
//!
//! The local sqlite `sessions.cursor` is a byte offset into that log.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Ssh = @import("../ssh/Client.zig");
const Executor = @import("../exec.zig").Executor;

const log_dir = "$HOME/.terminus/logs";

/// Where job result sidecars live. Separate from the log directory because a
/// result must survive log rotation and `pipe-pane` restarts: the log is a
/// stream someone else owns, the result is a fact about one operation.
const result_dir = "$HOME/.terminus/results";

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
pub fn shellQuote(arena: Allocator, s: []const u8) Allocator.Error![]u8 {
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

/// A job's durable terminal result, as the remote wrapper recorded it.
pub const JobResult = struct {
    exit_code: i32,
    /// Unix seconds as the *remote* clock saw them, or 0 if `date` was
    /// unavailable. Never substituted with a local timestamp: a receipt that
    /// says when something finished must not be quoting a different machine.
    finished_at: i64,
};

/// Schema version of the sidecar document. Bump when a reader has to
/// understand something new; the reader rejects versions it does not know
/// rather than guessing at the fields it recognizes.
const result_schema_version: i64 = 1;

/// Builds the line typed into the job's shell.
///
/// Three things happen after the user's command, in this order:
///   1. its status is captured into `__t_rc`, before anything else can
///      clobber `$?`;
///   2. the result sidecar is written to a `.part` file and `mv`'d into
///      place, so a reader never sees a half-written document;
///   3. the log sentinel is echoed.
///
/// The sidecar exists because the sentinel alone is not durable evidence. It
/// is one line in an append-only log, and a job that keeps printing after it
/// finishes — a disowned child, a background tail — pushes it out of the tail
/// window a probe can afford to read. At that point the log can no longer
/// answer how the job ended, and neither could we. The sidecar is a fixed
/// location holding exactly one fact, so it stays answerable forever.
///
/// The sentinel is still written, and still read as a fallback: jobs launched
/// by an older build have no sidecar, and `--discard-evidence` may have taken
/// one away.
pub fn jobLaunchLine(
    arena: Allocator,
    command: []const u8,
    cwd: ?[]const u8,
    sentinel: []const u8,
    request_id: []const u8,
) Allocator.Error![]u8 {
    const body = if (cwd) |dir|
        try std.fmt.allocPrint(arena, "cd {s} && ({s})", .{ dir, command })
    else
        try std.fmt.allocPrint(arena, "({s})", .{command});

    // `date` is best-effort: a host without it still gets a valid document,
    // with finishedAt=0 meaning "the remote could not say".
    return std.fmt.allocPrint(
        arena,
        "mkdir -p {s} 2>/dev/null; {s}; __t_rc=$?; __t_res={s}/{s}.json; " ++
            "printf '{{\"v\":{d},\"requestId\":\"{s}\",\"exitCode\":%s,\"finishedAt\":%s}}' " ++
            "\"$__t_rc\" \"$(date +%s 2>/dev/null || echo 0)\" > \"$__t_res.part\" 2>/dev/null " ++
            "&& mv -f \"$__t_res.part\" \"$__t_res\" 2>/dev/null; echo {s}:$__t_rc",
        .{ result_dir, body, result_dir, request_id, result_schema_version, request_id, sentinel },
    );
}

/// Ceiling on how much of a sidecar we read. The document is one short line;
/// anything bigger is not ours, and reading it is how a probe turns into an
/// unbounded transfer.
const max_result_bytes: i64 = 4096;

/// Separates the sidecar document from the log window in a probe's output.
/// The sidecar is squeezed onto a single line by `tr -d '\n'`, so a
/// line-start match on this marker cannot land inside it.
const probe_split_marker = "__TERMINUS_PROBE_SPLIT__";

const ProbeHalves = struct {
    /// The sidecar document, or empty if there was none.
    result: []const u8,
    /// Everything after the marker line: the log size line and the window.
    rest: []const u8,
};

fn splitProbe(stdout: []const u8) ?ProbeHalves {
    var search: usize = 0;
    while (std.mem.indexOfPos(u8, stdout, search, probe_split_marker)) |pos| {
        const line_start = if (std.mem.lastIndexOfScalar(u8, stdout[0..pos], '\n')) |nl| nl + 1 else 0;
        const line_end = std.mem.indexOfScalarPos(u8, stdout, pos, '\n') orelse stdout.len;
        const tail = std.mem.trim(u8, stdout[pos + probe_split_marker.len .. line_end], " \t\r");
        if (line_start == pos and tail.len == 0) return .{
            .result = std.mem.trim(u8, stdout[0..line_start], " \t\r\n"),
            .rest = if (line_end < stdout.len) stdout[line_end + 1 ..] else "",
        };
        search = pos + probe_split_marker.len;
    }
    return null;
}

/// Reads back the sidecar document.
///
/// Returns null for "no usable result", which covers a missing file, a
/// truncated or malformed one, a schema version we do not know, and — the
/// case that matters — a document naming a *different* request. The whole
/// point of keying results by request id is that a leftover file from an
/// earlier attempt must not be read as this attempt's outcome, so a mismatch
/// is treated as no evidence at all rather than as evidence.
fn parseJobResult(arena: Allocator, text: []const u8, request_id: []const u8) ?JobResult {
    const trimmed = std.mem.trim(u8, text, " \t\r\n");
    if (trimmed.len == 0) return null;
    const Doc = struct {
        v: i64 = 0,
        requestId: []const u8 = "",
        exitCode: i64 = -1,
        finishedAt: i64 = 0,
    };
    const doc = std.json.parseFromSliceLeaky(Doc, arena, trimmed, .{
        .ignore_unknown_fields = true,
    }) catch return null;
    if (doc.v != result_schema_version) return null;
    if (!std.mem.eql(u8, doc.requestId, request_id)) return null;
    // Shell exit statuses are 0-255; anything else means the document was not
    // written by our wrapper, whatever it claims.
    if (doc.exitCode < 0 or doc.exitCode > 255) return null;
    return .{ .exit_code = @intCast(doc.exitCode), .finished_at = doc.finishedAt };
}

/// Deletes a job's result sidecar. Used only by `--discard-evidence`, which
/// is explicit about destroying what it destroys.
pub fn removeResult(executor: Executor, arena: Allocator, request_id: []const u8) Error!void {
    const script = try std.fmt.allocPrint(
        arena,
        "rm -f {s}/{s}.json {s}/{s}.json.part",
        .{ result_dir, request_id, result_dir, request_id },
    );
    const result = try run(executor, arena, script);
    if (result.exit_code != 0) return error.RemoteFailed;
}

/// One round trip for just the sidecar, for callers already reading the log
/// from a cursor and so unable to share `probeTail`'s window.
pub fn readResult(executor: Executor, arena: Allocator, request_id: []const u8) Error!?JobResult {
    const script = try std.fmt.allocPrint(arena,
        \\r={s}/{s}.json
        \\[ -f "$r" ] || exit 0
        \\head -c {d} "$r" | tr -d '\n'
    , .{ result_dir, request_id, max_result_bytes });
    const result = try run(executor, arena, script);
    if (result.exit_code != 0) return error.RemoteFailed;
    return parseJobResult(arena, result.stdout, request_id);
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
///
/// Destroys evidence: the log is the only durable record of how a job ended,
/// so anything that may still need reconciling should use `killKeepLog`.
pub fn kill(executor: Executor, arena: Allocator, name: []const u8) Error!void {
    _ = try killSession(executor, arena, name, true);
}

/// Kills the session but preserves the output log.
///
/// Returns whether the session is actually gone afterwards. The old
/// formulation (`tmux kill-session; rm -f log`) took its exit status from the
/// `rm`, so a failed kill reported success — and a surviving session is not a
/// cosmetic problem: `ensure` treats an existing session as ready, so the
/// next command would be typed into the previous job's shell.
pub fn killKeepLog(executor: Executor, arena: Allocator, name: []const u8) Error!bool {
    return killSession(executor, arena, name, false);
}

fn killSession(executor: Executor, arena: Allocator, name: []const u8, drop_log: bool) Error!bool {
    const tname = try tmuxName(arena, name);
    const script = if (drop_log)
        try std.fmt.allocPrint(arena,
            \\tmux kill-session -t ={s} 2>/dev/null
            \\rm -f {s}/{s}.log
            \\tmux has-session -t ={s} 2>/dev/null && exit 1
            \\exit 0
        , .{ tname, log_dir, name, tname })
    else
        try std.fmt.allocPrint(arena,
            \\tmux kill-session -t ={s} 2>/dev/null
            \\tmux has-session -t ={s} 2>/dev/null && exit 1
            \\exit 0
        , .{ tname, tname });
    const result = try run(executor, arena, script);
    return result.exit_code == 0;
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

/// State probe: reads the durable result sidecar and the *end* of the log,
/// in one round trip.
///
/// Detecting that a job finished is a different problem from streaming its
/// output, and conflating them is a bug: a reader that walks forward in 1 MiB
/// windows from the user's cursor never reaches the sentinel on a job that
/// produced 5 MiB, so the job stays "running" forever. Reading a tail window
/// instead finds a marker that is the last thing written, regardless of how
/// much came before.
///
/// But "the last thing written" is only true if the job stops printing when
/// it exits, and that is not something we control — a disowned child keeps
/// writing into the same pane long after the shell moved on. Then the
/// sentinel scrolls out of any window we are willing to read and the log
/// stops being able to answer the question at all. `request_id` names the
/// sidecar, which is one document in a fixed place holding one fact, so it
/// stays answerable however much noise follows. The sentinel scan remains as
/// the fallback for jobs launched before sidecars existed.
pub fn probeTail(
    executor: Executor,
    arena: Allocator,
    name: []const u8,
    sentinel: []const u8,
    request_id: ?[]const u8,
    tail_bytes: i64,
) Error!JobProbe {
    const path = try logPath(arena, name);
    // Empty `r` when there is no request to look up: `[ -f "" ]` is false, so
    // the framing stays identical and the parser has one shape to handle.
    const script = try std.fmt.allocPrint(arena,
        \\r={s}
        \\[ -f "$r" ] && head -c {d} "$r" | tr -d '\n'
        \\echo
        \\echo {s}
        \\f={s}
        \\[ -f "$f" ] || {{ echo 0; exit 0; }}
        \\wc -c < "$f"
        \\tail -c {d} "$f"
    , .{
        if (request_id) |id| try std.fmt.allocPrint(arena, "{s}/{s}.json", .{ result_dir, id }) else "",
        max_result_bytes,
        probe_split_marker,
        path,
        tail_bytes,
    });
    const result = try run(executor, arena, script);
    if (result.exit_code != 0) return error.RemoteFailed;

    var probe = try interpretTail(arena, result.stdout, sentinel, request_id);
    probe.session_alive = try isAlive(executor, arena, name);
    return probe;
}

/// Everything `probeTail` concludes from the bytes the remote sent back —
/// separated out because this, not the SSH call, is where the interesting
/// decision lives: which record gets to say how the job ended.
///
/// `session_alive` is left false; the caller fills it in.
fn interpretTail(
    arena: Allocator,
    stdout: []const u8,
    sentinel: []const u8,
    request_id: ?[]const u8,
) Error!JobProbe {
    const split = splitProbe(stdout) orelse return error.RemoteFailed;
    const sidecar = if (request_id) |id| parseJobResult(arena, split.result, id) else null;

    // No size line: the log file does not exist yet. The sidecar can still
    // have the answer — a job whose pane log was rotated away is exactly the
    // case it is there for.
    const newline = std.mem.indexOfScalar(u8, split.rest, '\n') orelse return .{
        .output = "",
        .next_cursor = 0,
        .exit_code = if (sidecar) |r| r.exit_code else null,
        .exit_source = if (sidecar != null) .result_file else .none,
        .finished_at = if (sidecar) |r| r.finished_at else null,
        .session_alive = false,
    };
    const size_text = std.mem.trim(u8, split.rest[0..newline], " \t\r");
    const log_size = std.fmt.parseInt(i64, size_text, 10) catch return error.RemoteFailed;
    const cleaned = try stripTerminalNoise(arena, split.rest[newline + 1 ..]);

    var exit_code: ?i32 = null;
    var exit_source: JobProbe.ExitSource = .none;
    var finished_at: ?i64 = null;
    if (sidecar) |r| {
        exit_code = r.exit_code;
        exit_source = .result_file;
        finished_at = r.finished_at;
    } else if (findSentinel(cleaned, sentinel)) |found| {
        exit_code = found.exit_code;
        exit_source = .log_sentinel;
    }

    return .{
        .output = cleaned,
        .next_cursor = log_size,
        .exit_code = exit_code,
        .exit_source = exit_source,
        .finished_at = finished_at,
        .session_alive = false,
        .business_result = try findBusinessResult(arena, cleaned),
    };
}

test "M2e gate: a buried sentinel does not cost a job its outcome" {
    const t = std.testing;
    var arena_state: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const rid = "01JQXW8ZK4N0RS7T3VYB2MCDEF";

    // What the remote sends back after a job that kept printing long past its
    // own sentinel: the tail window we can afford to read holds only trailing
    // noise, so the sentinel scan finds nothing. This is the case the sidecar
    // exists for.
    const buried = try std.fmt.allocPrint(arena,
        "{{\"v\":1,\"requestId\":\"{s}\",\"exitCode\":3,\"finishedAt\":1750000000}}\n" ++
        "{s}\n900000\nstill chattering\nand chattering\n", .{ rid, probe_split_marker });

    const found = try interpretTail(arena, buried, "__TERMINUS_JOB_9__", rid);
    try t.expectEqual(@as(?i32, 3), found.exit_code);
    try t.expectEqual(JobProbe.ExitSource.result_file, found.exit_source);
    try t.expectEqual(@as(?i64, 1750000000), found.finished_at);
    try t.expectEqual(@as(i64, 900000), found.next_cursor);

    // Same bytes, no sidecar: the honest answer is that we cannot say.
    const no_sidecar = try std.fmt.allocPrint(
        arena,
        "\n{s}\n900000\nstill chattering\nand chattering\n",
        .{probe_split_marker},
    );
    const unknown = try interpretTail(arena, no_sidecar, "__TERMINUS_JOB_9__", rid);
    try t.expectEqual(@as(?i32, null), unknown.exit_code);
    try t.expectEqual(JobProbe.ExitSource.none, unknown.exit_source);

    // A job launched before sidecars existed still settles from its log.
    const legacy = try std.fmt.allocPrint(
        arena,
        "\n{s}\n40\nwork done\n__TERMINUS_JOB_9__:7\n",
        .{probe_split_marker},
    );
    const from_log = try interpretTail(arena, legacy, "__TERMINUS_JOB_9__", rid);
    try t.expectEqual(@as(?i32, 7), from_log.exit_code);
    try t.expectEqual(JobProbe.ExitSource.log_sentinel, from_log.exit_source);
    try t.expectEqual(@as(?i64, null), from_log.finished_at);
}

test "M2e gate: a result belonging to another request is not evidence" {
    const t = std.testing;
    var arena_state: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const mine = "01JQXW8ZK4N0RS7T3VYB2MCDEF";
    const theirs = "01JQXW8ZK4N0RS7T3VYB2MCXYZ";

    // A leftover document from a different attempt in the same directory.
    // Reading it as ours would settle this operation from someone else's exit
    // code — the exact confusion request-keyed results are meant to prevent.
    const foreign = try std.fmt.allocPrint(arena,
        "{{\"v\":1,\"requestId\":\"{s}\",\"exitCode\":0,\"finishedAt\":1750000000}}\n{s}\n5\nhi\n",
        .{ theirs, probe_split_marker });
    const probe = try interpretTail(arena, foreign, "__S__", mine);
    try t.expectEqual(@as(?i32, null), probe.exit_code);
    try t.expectEqual(JobProbe.ExitSource.none, probe.exit_source);

    // Neither is a document from a schema we do not know, nor one whose exit
    // code is not a shell exit status, nor a truncated write.
    const rejects = [_][]const u8{
        "{\"v\":2,\"requestId\":\"01JQXW8ZK4N0RS7T3VYB2MCDEF\",\"exitCode\":0,\"finishedAt\":1}",
        "{\"v\":1,\"requestId\":\"01JQXW8ZK4N0RS7T3VYB2MCDEF\",\"exitCode\":9000,\"finishedAt\":1}",
        "{\"v\":1,\"requestId\":\"01JQXW8ZK4N0RS7T3VYB2M",
        "",
    };
    for (rejects) |doc| try t.expectEqual(@as(?JobResult, null), parseJobResult(arena, doc, mine));

    // And a good one is accepted, so the rejections above mean something.
    const good = parseJobResult(
        arena,
        "{\"v\":1,\"requestId\":\"01JQXW8ZK4N0RS7T3VYB2MCDEF\",\"exitCode\":255,\"finishedAt\":42}",
        mine,
    ) orelse return error.TestExpectedResult;
    try t.expectEqual(@as(i32, 255), good.exit_code);
    try t.expectEqual(@as(i64, 42), good.finished_at);
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

/// The pid of the session's pane process — the shell the job runs under, and
/// the head of its process group.
///
/// This is what identity a tmux-supervised job can offer. It is a real pid,
/// but nothing here proves a process later found under it is still ours,
/// which is why the recorded capability says `pidProof = weak`.
pub fn panePid(executor: Executor, arena: Allocator, name: []const u8) Error!?i64 {
    const tname = try tmuxName(arena, name);
    const script = try std.fmt.allocPrint(
        arena,
        "tmux list-panes -t ={s} -F '#{{pane_pid}}' 2>/dev/null | head -1",
        .{tname},
    );
    const result = try run(executor, arena, script);
    const text = std.mem.trim(u8, result.stdout, " \t\r\n");
    if (text.len == 0) return null;
    return std.fmt.parseInt(i64, text, 10) catch null;
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
    /// Set when the job's end was established: the durable result sidecar was
    /// there, or (failing that) the sentinel line was still in the window.
    exit_code: ?i32,
    /// Where `exit_code` came from. A caller writing a receipt has to say
    /// which one it was — "the wrapper's result file said 3" and "we found a
    /// line in a log that said 3" are not the same claim.
    exit_source: ExitSource = .none,
    /// Remote finish time, only ever from the sidecar. The log carries no
    /// timestamp, so a sentinel-only outcome has none.
    finished_at: ?i64 = null,
    session_alive: bool,
    /// Business-state marker: the value from the last `__TERMINUS_RESULT__:<v>`
    /// line the job printed, distinct from the process exit code (a job can
    /// exit 0 yet report a business failure). Null when the job printed none.
    business_result: ?[]const u8 = null,

    pub const ExitSource = enum {
        none,
        /// `~/.terminus/results/<request-id>.json`.
        result_file,
        /// The `<sentinel>:<code>` line in the pane log.
        log_sentinel,
    };
};

/// Jobs opt into business-state reporting by printing this marker; the
/// value after the colon becomes `businessResult` in status/read output.
pub const business_marker = "__TERMINUS_RESULT__";

/// Returns the value from the LAST `__TERMINUS_RESULT__:<value>` line in
/// `data` (line-start match), or null. Last wins so a job can update its
/// verdict as it progresses.
fn findBusinessResult(arena: Allocator, data: []const u8) Allocator.Error!?[]const u8 {
    var search_from: usize = 0;
    var last: ?[]const u8 = null;
    while (std.mem.indexOfPos(u8, data, search_from, business_marker)) |pos| {
        const line_start = if (std.mem.lastIndexOfScalar(u8, data[0..pos], '\n')) |nl| nl + 1 else 0;
        const line_end = std.mem.indexOfScalarPos(u8, data, pos, '\n') orelse data.len;
        if (line_start == pos) {
            const after = data[pos + business_marker.len .. line_end];
            if (after.len >= 1 and after[0] == ':') {
                last = std.mem.trim(u8, after[1..], " \t\r");
            }
        }
        search_from = pos + business_marker.len;
    }
    return if (last) |v| try arena.dupe(u8, v) else null;
}

/// Answers "how is this job doing": reads new log output from the caller's
/// cursor, establishes whether it ended, checks pane liveness. Used by
/// `job read`, which needs the output stream and so cannot share
/// `probeTail`'s tail window.
pub fn probeJob(
    executor: Executor,
    arena: Allocator,
    name: []const u8,
    sentinel: []const u8,
    request_id: ?[]const u8,
    cursor: i64,
    limit: i64,
) Error!JobProbe {
    const chunk = try readLog(executor, arena, name, cursor, limit);
    const cleaned = try stripTerminalNoise(arena, chunk.data);
    const sidecar = if (request_id) |id| try readResult(executor, arena, id) else null;

    var exit_code: ?i32 = null;
    var exit_source: JobProbe.ExitSource = .none;
    var output: []const u8 = cleaned;
    if (findSentinel(cleaned, sentinel)) |found| {
        exit_code = found.exit_code;
        exit_source = .log_sentinel;
        // Trim the marker out of what the caller shows the user; the window
        // happened to contain it, which is a property of where their cursor
        // was, not of how the job ended.
        output = cleaned[found.output_start..found.output_end];
    }
    if (sidecar) |r| {
        exit_code = r.exit_code;
        exit_source = .result_file;
    }
    return .{
        .output = output,
        .next_cursor = chunk.next_cursor,
        .exit_code = exit_code,
        .exit_source = exit_source,
        .finished_at = if (sidecar) |r| r.finished_at else null,
        .session_alive = try isAlive(executor, arena, name),
        .business_result = try findBusinessResult(arena, cleaned),
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
