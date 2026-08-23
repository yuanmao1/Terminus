//! The remote supervisor helper: a Linux binary that runs one command and
//! reports on it with syscall results rather than parsed text.
//!
//! This exists because a POSIX shell cannot honestly claim four of the five
//! things `Capability` describes, and the reasons are structural rather than a
//! matter of writing better shell:
//!
//! * **Strong pid proof.** In a subshell `$$` still expands to the *parent*
//!   shell's pid (POSIX XCU 2.5.2), so a shell-launched command cannot report
//!   its own identity. Backgrounding it — `( … ) & pid=$!` — does give the real
//!   pid, but then reading `/proc/$pid/stat` races the command: a fast command
//!   is reaped before the read, and the token comes back empty, which is the
//!   common case rather than the corner. Here the parent owns the reap, so the
//!   child is still a zombie with a readable `/proc` entry no matter how fast
//!   it exited. **That is the whole difference**: the race is not won, it is
//!   made impossible.
//! * **A deadline that outlives the link.** The timer is this process's, not
//!   the SSH connection's.
//! * **Cancellation that is proven.** `kill(-pgid, …)` then `kill(-pgid, 0)`
//!   returning `ESRCH` is a syscall answering "the group is gone". A shell can
//!   observe that a tmux pane vanished, which establishes nothing about a
//!   command that called `setsid` or `disown`.
//! * **Byte-exact streams.** Output is framed with an exact length, so no
//!   marker is embedded in it and no byte is special.
//!
//! Audit isolation is the fifth and is not implemented here yet; nothing in
//! this file claims it.
//!
//! Not wired into `build.zig` yet — built directly for `x86_64-linux-musl` and
//! driven under WSL. See `docs/v2.0-progress.md`.
//!
//! No allocator, and every buffer below is a fixed size with a stated bound:
//! this runs on somebody else's machine, and a supervisor that can fail to
//! allocate is a supervisor that can lose a child it has already forked.
const std = @import("std");
const linux = std.os.linux;

/// Wire limits. A request larger than this is refused rather than truncated —
/// a truncated argv is a different command.
const max_frame = 1 << 20;
const max_argv = 256;
/// Room for argv strings plus their null terminators.
const argv_bytes = 1 << 19;

const Kind = struct {
    // host -> helper
    const run: u8 = 0x01;
    // helper -> host
    const started: u8 = 0x81;
    const stdout: u8 = 0x82;
    const stderr: u8 = 0x83;
    const exited: u8 = 0x84;
    const failed: u8 = 0x85;
};

/// How a command ended. The two timeout arms are separate on the wire because
/// they are separate outcomes: one is `timed_out`, the other is
/// `indeterminate`, and collapsing them is how a supervisor reports a command
/// it could not account for as one it stopped.
const How = struct {
    const exited: u8 = 0;
    const signalled: u8 = 1;
    const timed_out_killed: u8 = 2;
    const timed_out_unconfirmed: u8 = 3;
};

/// How much of a stream is carried in one frame.
const pump_bytes = 32 * 1024;

var out_buf: [64 * 1024]u8 = undefined;

pub fn main() void {
    run() catch |err| {
        // A failure before the fork is reportable; after it, `supervise` owns
        // the reporting because a child exists and must be accounted for.
        failFrame(@errorName(err));
        exit(70);
    };
}

const Error = error{
    ShortRead,
    FrameTooLarge,
    BadFrame,
    TooManyArgs,
    ArgvTooLarge,
    PipeFailed,
    ForkFailed,
    WriteFailed,
};

fn run() Error!void {
    var frame: [max_frame]u8 = undefined;
    const body = try readFrame(&frame);
    if (body.len < 1 or body[0] != Kind.run) return error.BadFrame;

    var p = Parser{ .bytes = body[1..] };
    const deadline_ms = try p.u64le();
    const grace_ms = try p.u64le();
    const argc = try p.u32le();
    if (argc == 0 or argc > max_argv) return error.TooManyArgs;

    // argv for `execve`: null-terminated strings, null-terminated array.
    var strings: [argv_bytes]u8 = undefined;
    var used: usize = 0;
    var argv: [max_argv + 1]?[*:0]const u8 = undefined;
    for (0..argc) |i| {
        const len = try p.u32le();
        const s = try p.take(len);
        if (used + s.len + 1 > strings.len) return error.ArgvTooLarge;
        @memcpy(strings[used..][0..s.len], s);
        strings[used + s.len] = 0;
        argv[i] = @ptrCast(strings[used..].ptr);
        used += s.len + 1;
    }
    argv[argc] = null;

    var out_pipe: [2]i32 = undefined;
    var err_pipe: [2]i32 = undefined;
    var sync_pipe: [2]i32 = undefined;
    if (fail(linux.pipe2(&out_pipe, .{}))) return error.PipeFailed;
    if (fail(linux.pipe2(&err_pipe, .{}))) return error.PipeFailed;
    // Closed by `execve`, so the parent can tell "the child reached exec" from
    // "the child died first" without a second channel.
    if (fail(linux.pipe2(&sync_pipe, .{ .CLOEXEC = true }))) return error.PipeFailed;

    const rc = linux.fork();
    if (fail(rc)) return error.ForkFailed;
    const pid: i32 = @intCast(@as(isize, @bitCast(rc)));

    if (pid == 0) {
        // Child. `setsid` makes this process a session and process-group
        // leader, so `pgid == pid` and one `kill(-pgid, …)` reaches the whole
        // tree the command goes on to build. Nothing here can report a
        // failure over the wire — the parent owns the wire — so a failed
        // step exits with a code the parent turns into a status.
        if (fail(linux.syscall0(.setsid))) exit(71);
        // Announce that the new session exists. Until this byte is out, the
        // parent asking for our process group would get *its* group, and a
        // supervisor that signals its own group kills itself — or, worse, kills
        // whatever launched it. This ordering is the fix for that, and it is a
        // barrier rather than a retry because there is no bound on how long a
        // scheduler may leave a freshly forked child unrun.
        _ = linux.close(sync_pipe[0]);
        _ = linux.write(sync_pipe[1], "1", 1);
        _ = linux.close(out_pipe[0]);
        _ = linux.close(err_pipe[0]);
        if (fail(linux.dup2(out_pipe[1], 1))) exit(72);
        if (fail(linux.dup2(err_pipe[1], 2))) exit(72);
        _ = linux.close(out_pipe[1]);
        _ = linux.close(err_pipe[1]);
        _ = linux.execve(argv[0].?, @ptrCast(&argv), @ptrCast(&empty_env));
        // Only reachable if `execve` failed. 127 is the shell's convention for
        // "command not found" and the parent reports it as the command's.
        exit(127);
    }

    _ = linux.close(out_pipe[1]);
    _ = linux.close(err_pipe[1]);
    _ = linux.close(sync_pipe[1]);
    // Non-blocking on the parent's read ends only. The child keeps blocking
    // write ends — a non-blocking write end would make the *command's* own
    // `write` fail with `EAGAIN`, which is a corruption of the command rather
    // than a property of the supervisor.
    //
    // This is what makes every read below bounded. A blocking read on a pipe
    // that a grandchild still holds open never returns, and `cmd &` followed by
    // the parent exiting is an ordinary thing to write, not a corner.
    nonBlocking(out_pipe[0]);
    nonBlocking(err_pipe[0]);

    // Wait for the child's "my session exists" byte before anything asks about
    // its process group. Bounded, because a child that never gets there has
    // either died or failed `setsid`, and either way there is no group of ours
    // to signal; `readPgid` then answers 0 and `stopGroup` falls back to the pid.
    var ack: [1]u8 = undefined;
    var acked = false;
    if (readableWithin(sync_pipe[0], 5000)) {
        const n = linux.read(sync_pipe[0], &ack, 1);
        acked = !fail(n) and n == 1;
    }
    _ = linux.close(sync_pipe[0]);

    supervise(pid, out_pipe[0], err_pipe[0], deadline_ms, grace_ms, acked);
}

/// Whether `fd` becomes readable inside `ms`. EOF counts, so a child that died
/// before writing is not waited on for the full window.
fn readableWithin(fd: i32, ms: i32) bool {
    var pfd = [_]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN, .revents = 0 }};
    const rc = linux.poll(&pfd, 1, ms);
    return !fail(rc) and rc > 0 and pfd[0].revents != 0;
}

fn nonBlocking(fd: i32) void {
    const flags = linux.fcntl(fd, linux.F.GETFL, 0);
    if (fail(flags)) return;
    _ = linux.fcntl(fd, linux.F.SETFL, flags | @as(usize, 0o4000)); // O_NONBLOCK
}

var empty_env: [1]?[*:0]const u8 = .{null};

/// Reports the child's identity, pumps its output, enforces the deadline, and
/// reports how it ended.
fn supervise(pid: i32, out_fd: i32, err_fd: i32, deadline_ms: u64, grace_ms: u64, acked: bool) void {
    // Read the start token *before* reaping. The child may already have
    // exited; as a zombie its `/proc` entry is still there, which is why this
    // cannot come back empty for a fast command the way the shell's does.
    const token = startToken(pid);
    // `setsid` in the child makes this equal to `pid`, and it is still read back
    // rather than assumed — but only once the child has said the new session
    // exists.
    //
    // Asking earlier is not a slightly stale answer, it is the *wrong group*:
    // before `setsid` the child is still in ours, so `getpgid(child)` returns
    // our pgid and every later `kill(-pgid, …)` is aimed at this process and
    // whatever launched it. That is not theoretical — it is what this code did,
    // and it killed its own test harness eight times before the cause was clear.
    // Without the acknowledgement there is no group of ours to signal, so 0, and
    // `stopGroup` falls back to the pid.
    const pgid = if (acked) readPgid(pid) else 0;

    var started: [24]u8 = undefined;
    writeI64(started[0..8], pid);
    writeI64(started[8..16], pgid);
    writeU64(started[16..24], token);
    frameOut(Kind.started, &started);

    // A pidfd turns "has the child exited" into a pollable fd, so the deadline
    // and the output pump are one `poll` rather than a signal handler racing a
    // read. Requires Linux 5.3.
    const pidfd_rc = linux.syscall2(.pidfd_open, @intCast(pid), 0);
    const pidfd: i32 = if (fail(pidfd_rc)) -1 else @intCast(pidfd_rc);
    defer if (pidfd >= 0) {
        _ = linux.close(pidfd);
    };

    const deadline_at: ?u64 = if (deadline_ms == 0) null else nowMs() + deadline_ms;
    var timed_out = false;

    var out_open = true;
    var err_open = true;
    var child_exited = false;

    // A ceiling on the whole wait, armed once we have tried to stop the child.
    // An unbounded wait here is worse than an unwelcome answer: the caller's
    // channel stays open and nothing is ever reported, which is the one outcome
    // a supervisor must not produce.
    var give_up_at: ?u64 = null;

    // The command's own exit ends the report.
    //
    // Not "wait for the pipes to close": a command's children inherit its
    // stdout, so `cmd &`, `nohup`, or anything that daemonizes leaves the write
    // end open afterwards, and waiting for it is waiting on a process we were
    // never supervising, with no bound at all. Bytes already in the pipe are not
    // lost — the bounded drain below takes them.
    //
    // There was a two-second grace window here as well. A mutation that set it
    // to zero survived every gate, which is how it became clear it was doing
    // nothing: the child cannot exit until the pipe has taken its output, and
    // whatever is left is exactly what the drain reads.
    while (!child_exited) {
        if (give_up_at) |at| if (nowMs() >= at) break;

        var pfds: [3]linux.pollfd = undefined;
        var n: usize = 0;
        var out_i: ?usize = null;
        var err_i: ?usize = null;
        var pid_i: ?usize = null;
        if (out_open) {
            pfds[n] = .{ .fd = out_fd, .events = linux.POLL.IN, .revents = 0 };
            out_i = n;
            n += 1;
        }
        if (err_open) {
            pfds[n] = .{ .fd = err_fd, .events = linux.POLL.IN, .revents = 0 };
            err_i = n;
            n += 1;
        }
        if (!child_exited and pidfd >= 0) {
            pfds[n] = .{ .fd = pidfd, .events = linux.POLL.IN, .revents = 0 };
            pid_i = n;
            n += 1;
        }
        if (n == 0) break;

        // Wake at the deadline even when nothing is readable, and never block
        // forever when there is a deadline to enforce.
        const wait_ms: i32 = if (deadline_at) |at| blk: {
            const now = nowMs();
            if (now >= at) break :blk 0;
            break :blk @intCast(@min(at - now, 200));
        } else 200;

        const pr = linux.poll(&pfds, @intCast(n), wait_ms);
        if (fail(pr)) {
            // EINTR is the only expected one; anything else and we still owe a
            // terminal frame, so fall through to the deadline check.
            if (errno(pr) != .INTR) {}
        }

        if (out_i) |i| if (pfds[i].revents != 0) {
            if (!pump(out_fd, Kind.stdout)) out_open = false;
        };
        if (err_i) |i| if (pfds[i].revents != 0) {
            if (!pump(err_fd, Kind.stderr)) err_open = false;
        };
        if (pid_i) |i| if (pfds[i].revents != 0) {
            child_exited = true;
        };

        // Without a pidfd there is nothing to poll, so ask directly. `NOWAIT`
        // leaves the zombie reapable, so the real `waitid` below still gets the
        // status rather than `ECHILD`.
        if (!child_exited and pidfd < 0) {
            var peek: linux.siginfo_t = undefined;
            @memset(std.mem.asBytes(&peek), 0);
            const pk = linux.waitid(.PID, pid, &peek, linux.W.EXITED | linux.W.NOHANG | linux.W.NOWAIT, null);
            if (!fail(pk) and peek.code != 0) {
                child_exited = true;
            }
        }

        if (!timed_out) if (deadline_at) |at| if (nowMs() >= at and !child_exited) {
            timed_out = true;
            stopGroup(pgid, pid, grace_ms);
            // Not `break`: the pipes may still hold bytes the command wrote
            // before it died, and those bytes are part of its output.
            //
            // `stopGroup` has already spent its own bounded windows, so what
            // this allows for is the kernel finishing a reap we have asked for,
            // not another round of signalling.
            give_up_at = nowMs() + 1000;
        };
    }

    // Whatever is already buffered, and nothing more. The read ends are
    // non-blocking, so this cannot wait on a process still holding the pipe.
    if (out_open) while (pump(out_fd, Kind.stdout)) {
        if (!readable(out_fd)) break;
    };
    if (err_open) while (pump(err_fd, Kind.stderr)) {
        if (!readable(err_fd)) break;
    };
    _ = linux.close(out_fd);
    _ = linux.close(err_fd);

    if (!child_exited) {
        // We asked it to stop, the window closed, and it is still there. Saying
        // `timed_out_killed` here would be claiming a stop we did not observe.
        var unconfirmed: [5]u8 = undefined;
        unconfirmed[0] = How.timed_out_unconfirmed;
        writeI32(unconfirmed[1..5], 0);
        frameOut(Kind.exited, &unconfirmed);
        exit(0);
    }

    var info: linux.siginfo_t = undefined;
    @memset(std.mem.asBytes(&info), 0);
    // Non-blocking: the child has been observed to exit, so the status is
    // already waiting. A blocking call here would reintroduce the unbounded
    // wait the loop above exists to remove.
    const wr = linux.waitid(.PID, pid, &info, linux.W.EXITED | linux.W.NOHANG, null);

    var payload: [5]u8 = undefined;
    if (fail(wr)) {
        // We forked it and cannot say how it ended. That is not a failure of
        // the command, and reporting it as one would be the pseudo-result this
        // whole binary exists to avoid.
        payload[0] = How.timed_out_unconfirmed;
        writeI32(payload[1..5], 0);
        frameOut(Kind.exited, &payload);
        exit(0);
    }

    const code: linux.CLD = @enumFromInt(info.code);
    const status = info.fields.common.second.sigchld.status;

    payload[0] = if (timed_out)
        // The command was stopped by us, and `stopGroup` already established
        // whether the group is actually gone. `timed_out` claims a stop; the
        // unconfirmed arm claims only that we asked.
        (if (groupGone(pgid)) How.timed_out_killed else How.timed_out_unconfirmed)
    else switch (code) {
        .EXITED => How.exited,
        .KILLED, .DUMPED => How.signalled,
        else => How.exited,
    };
    writeI32(payload[1..5], status);
    frameOut(Kind.exited, &payload);
    exit(0);
}

/// TERM, then KILL after the grace period, then check.
///
/// Signals the *group* rather than the pid: a command that spawned children is
/// not stopped by stopping its shell, and the group is what `setsid` gave us to
/// make that one call.
fn stopGroup(pgid: i64, pid: i32, grace_ms: u64) void {
    const target: i32 = if (pgid > 0) @intCast(-pgid) else -pid;
    _ = linux.kill(target, linux.SIG.TERM);

    // Give it the grace period to leave on its own, polling rather than
    // sleeping the whole span, so a process that exits promptly is not held.
    const until = nowMs() + grace_ms;
    while (nowMs() < until) {
        if (groupGone(if (pgid > 0) pgid else pid)) return;
        sleepMs(10);
    }
    _ = linux.kill(target, linux.SIG.KILL);
    // KILL is not instantaneous either: the kernel still has to reap. Give it
    // a bounded window, then let the caller report unconfirmed.
    const hard = nowMs() + 500;
    while (nowMs() < hard) {
        if (groupGone(if (pgid > 0) pgid else pid)) return;
        sleepMs(10);
    }
}

/// Whether signalling the group would reach nobody.
///
/// `kill(-pgid, 0)` performs the permission and existence checks and delivers
/// nothing, so `ESRCH` is the kernel saying the group is empty. This is the
/// syscall behind `pid_proof = .strong`, and it is the claim shell mode cannot
/// make.
///
/// A zombie still counts as present, which is why the caller reaps before
/// asking.
fn groupGone(pgid: i64) bool {
    if (pgid <= 0) return false;
    // Signal 0 is the existence-and-permission probe; there is no `SIG` name
    // for it because it is not a signal.
    const rc = linux.kill(@intCast(-pgid), @enumFromInt(0));
    return fail(rc) and errno(rc) == .SRCH;
}

/// Field 22 of `/proc/<pid>/stat`: the process's start time in clock ticks
/// since boot. With it, a pid that has been recycled is distinguishable from
/// ours; without it, `pid_proof` can only ever be `weak`.
///
/// Parsed from the **last** `)` rather than by splitting on spaces: field 2 is
/// the executable name in parentheses and it may contain both spaces and
/// parentheses, so any left-to-right tokenisation reads the wrong field for a
/// command named `foo )bar(`. Returns 0 when unavailable, and 0 is a value the
/// host must treat as "no token" rather than as a token.
fn startToken(pid: i32) u64 {
    var path: [64]u8 = undefined;
    const p = std.fmt.bufPrint(&path, "/proc/{d}/stat\x00", .{pid}) catch return 0;
    const fd_rc = linux.open(@ptrCast(p.ptr), .{ .ACCMODE = .RDONLY }, 0);
    if (fail(fd_rc)) return 0;
    const fd: i32 = @intCast(fd_rc);
    defer _ = linux.close(fd);

    var buf: [1024]u8 = undefined;
    const n_rc = linux.read(fd, &buf, buf.len);
    if (fail(n_rc)) return 0;
    const text = buf[0..n_rc];

    const close_paren = std.mem.lastIndexOfScalar(u8, text, ')') orelse return 0;
    // After the `)` the next token is field 3, so field 22 is token 19.
    var it = std.mem.tokenizeScalar(u8, text[close_paren + 1 ..], ' ');
    var i: usize = 0;
    while (it.next()) |tok| : (i += 1) {
        if (i == 19) return std.fmt.parseInt(u64, std.mem.trim(u8, tok, " \n"), 10) catch 0;
    }
    return 0;
}

/// The child's process group, read back rather than assumed to be its pid.
fn readPgid(pid: i32) i64 {
    const rc = linux.syscall1(.getpgid, @intCast(pid));
    if (fail(rc)) return 0;
    return @intCast(@as(isize, @bitCast(rc)));
}

/// Whether this fd has something waiting, asked without blocking.
///
/// End-of-file counts as something: `pump` then returns false and the caller's
/// loop ends on the real reason rather than on a timeout.
fn readable(fd: i32) bool {
    var pfd = [_]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN, .revents = 0 }};
    const rc = linux.poll(&pfd, 1, 0);
    return !fail(rc) and rc > 0 and pfd[0].revents != 0;
}

/// Forwards one readable chunk. Returns false once the pipe is at EOF.
fn pump(fd: i32, kind: u8) bool {
    var buf: [pump_bytes]u8 = undefined;
    const rc = linux.read(fd, &buf, buf.len);
    if (fail(rc)) return errno(rc) == .AGAIN or errno(rc) == .INTR;
    if (rc == 0) return false;
    frameOut(kind, buf[0..rc]);
    return true;
}

// --- framing ---------------------------------------------------------------

/// Reads one length-prefixed frame into `into`, returning its body.
fn readFrame(into: []u8) Error![]const u8 {
    var head: [4]u8 = undefined;
    try readExact(&head);
    const len = std.mem.readInt(u32, &head, .little);
    if (len == 0 or len > into.len) return error.FrameTooLarge;
    try readExact(into[0..len]);
    return into[0..len];
}

fn readExact(into: []u8) Error!void {
    var off: usize = 0;
    while (off < into.len) {
        const rc = linux.read(0, into[off..].ptr, into.len - off);
        if (fail(rc)) {
            if (errno(rc) == .INTR) continue;
            return error.ShortRead;
        }
        if (rc == 0) return error.ShortRead;
        off += rc;
    }
}

/// One frame out, header and body in a single write where it fits, because two
/// writes can be interleaved by nothing here but would be by a future second
/// writer, and a split header is an unrecoverable stream.
fn frameOut(kind: u8, body: []const u8) void {
    // One frame, never a split. The loop that used to be here could not run:
    // the only large bodies come from `pump`, whose buffer is half this one, so
    // `chunk` was always `body.len` and the second iteration was unreachable. A
    // mutation aimed at its arithmetic survived, which is how that was found.
    //
    // Every body that reaches here is bounded by construction — 24 bytes for
    // `started`, 5 for `exited`, a short literal for `failed`, and at most
    // `pump_bytes` for the streams — so the bound is asserted at compile time
    // below rather than branched on at run time. A run-time arm here would be
    // the same unreachable code in a new place.
    std.mem.writeInt(u32, out_buf[0..4], @intCast(body.len + 1), .little);
    out_buf[4] = kind;
    @memcpy(out_buf[5..][0..body.len], body);
    writeAll(out_buf[0 .. 5 + body.len]);
}

comptime {
    // The premise of the paragraph above. Both sizes are named here so that
    // growing either one fails the build rather than the wire, where a body
    // longer than the buffer would put a wrong length in front of it and the
    // reader would take the next frame's header for payload.
    std.debug.assert(pump_bytes <= out_buf.len - 5);
}

fn failFrame(message: []const u8) void {
    frameOut(Kind.failed, message);
}

fn writeAll(bytes: []const u8) void {
    var off: usize = 0;
    while (off < bytes.len) {
        const rc = linux.write(1, bytes[off..].ptr, bytes.len - off);
        if (fail(rc)) {
            if (errno(rc) == .INTR) continue;
            return;
        }
        if (rc == 0) return;
        off += rc;
    }
}

const Parser = struct {
    bytes: []const u8,
    at: usize = 0,

    fn take(p: *Parser, n: usize) Error![]const u8 {
        if (p.at + n > p.bytes.len) return error.BadFrame;
        defer p.at += n;
        return p.bytes[p.at..][0..n];
    }

    fn u32le(p: *Parser) Error!u32 {
        const s = try p.take(4);
        return std.mem.readInt(u32, s[0..4], .little);
    }

    fn u64le(p: *Parser) Error!u64 {
        const s = try p.take(8);
        return std.mem.readInt(u64, s[0..8], .little);
    }
};

fn writeU64(into: *[8]u8, v: u64) void {
    std.mem.writeInt(u64, into, v, .little);
}
fn writeI64(into: *[8]u8, v: i64) void {
    std.mem.writeInt(i64, into, v, .little);
}
fn writeI32(into: *[4]u8, v: i32) void {
    std.mem.writeInt(i32, into, v, .little);
}

// --- syscall plumbing ------------------------------------------------------

fn fail(rc: usize) bool {
    return @as(isize, @bitCast(rc)) < 0;
}

fn errno(rc: usize) linux.E {
    return linux.errno(rc);
}

fn nowMs() u64 {
    var ts: linux.timespec = undefined;
    if (fail(linux.clock_gettime(.MONOTONIC, &ts))) return 0;
    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / 1_000_000;
}

fn sleepMs(ms: u64) void {
    var ts: linux.timespec = .{ .sec = @intCast(ms / 1000), .nsec = @intCast((ms % 1000) * 1_000_000) };
    _ = linux.nanosleep(&ts, null);
}

fn exit(code: u8) noreturn {
    linux.exit_group(code);
    unreachable;
}
