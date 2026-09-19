//! 交互会话的双向泵。
//!
//! 三件事在一个循环里轮流推进,任何一件都不许阻塞另外两件:
//! 本地输入 → PTY、PTY → 本地输出、窗口尺寸 → 远端 PTY。
//!
//! 本地输入来自 `InputQueue` 的后台线程,因为 Windows 上没有办法把控制台
//! 句柄和一个 socket 一起等;远端读写是 libssh2 非阻塞调用。两边都不阻塞,
//! 所以没有进展时才睡 1ms。

const std = @import("std");
const Ssh = @import("../ssh/Client.zig");
const Console = @import("Console.zig");
const Queue = @import("InputQueue.zig");

/// 尺寸轮询间隔。人感觉不到 200ms,而换来的是不必把事件读取和字节读取
/// 混在同一个句柄上 —— 输入线程在做阻塞 `ReadFile`,读不到窗口事件记录。
const resize_poll_ms: i64 = 200;

pub const Outcome = union(enum) {
    /// 远端结束了会话。真正的退出码由 `Pty.close` 取回。
    remote_exit,
    /// 本地 stdin 到了 EOF。
    local_eof,
    /// 传输中断;远端的下场不可知。
    transport_failed,
    /// 本地终端被关掉了(关窗口、Ctrl-Break)。远端没被通知,下场不可知。
    ///
    /// 和 `local_eof` 分开,因为它们要落的收据不同:stdin 到了 EOF 是一次
    /// 有序收尾,而窗口被关是人走了、没人再看着那一头。
    aborted,
};

pub const Error = error{
    InputThreadFailed,
    OutputWriteFailed,
};

/// 每个空闲 tick 调一次(与尺寸检查同一节拍,约 200ms)。
///
/// 返回 false 表示会话应当结束 —— 租约被别人接管时就是这样:继续打字会
/// 让两个所有者同时以为自己持有这个会话。
pub const Tick = struct {
    context: *anyopaque,
    call: *const fn (context: *anyopaque) bool,
};

/// 单调毫秒。
///
/// `.awake` 而不是 `.real`:这是一个间隔计时器,NTP 把墙钟往回拨一秒不该
/// 让尺寸轮询停上一秒。泵末尾的 `std.Io.sleep` 用的也是这个时钟。
fn nowMs(io: std.Io) i64 {
    const ts = std.Io.Timestamp.now(io, .awake);
    return @intCast(@divTrunc(ts.nanoseconds, std.time.ns_per_ms));
}

/// 读线程的队列,**进程级而不是栈上**。
///
/// 一个进程至多开一个交互会话,所以这是安全的;而它必须活得比 `run` 的
/// 栈帧长,理由见下面收尾处的注释:我们不等那个线程结束。
var session_queue: Queue.InputQueue = undefined;

pub fn run(io: std.Io, pty: *Ssh.Pty, tick: ?Tick) Error!Outcome {
    session_queue = Queue.InputQueue.init(io);
    const queue = &session_queue;
    var input_thread = std.Thread.spawn(.{}, Queue.inputPump, .{ queue, std.Io.File.stdin() }) catch
        return error.InputThreadFailed;
    var released = false;
    defer if (!released) release(queue, &input_thread);

    var out_buffer: [Queue.tunnel_buffer_bytes]u8 = undefined;
    var writer = std.Io.File.stdout().writerStreaming(io, &out_buffer);

    var last_size: ?Console.Size = Console.size();
    if (last_size) |s| pty.resize(s.cols, s.rows);
    var last_size_check = nowMs(io);

    var outcome: Outcome = .transport_failed;
    var input_buffer: [Queue.tunnel_buffer_bytes]u8 = undefined;
    var remote_buffer: [Queue.tunnel_buffer_bytes]u8 = undefined;

    loop: while (true) {
        // 每轮都问,不是每 200ms 问一次:关窗口时操作系统只给几秒,而这
        // 条循环在有数据时一轮只要几微秒。
        if (Console.abortRequested()) {
            outcome = .aborted;
            break :loop;
        }

        var progressed = false;

        // 本地 → 远端
        const queued = queue.peek(&input_buffer);
        if (queued != 0) {
            switch (pty.write(input_buffer[0..queued])) {
                .bytes => |n| {
                    queue.consume(n);
                    progressed = true;
                },
                .again => {},
                .failed => {
                    outcome = .transport_failed;
                    break :loop;
                },
            }
        } else {
            const state = queue.snapshot();
            if (state.done) {
                outcome = if (state.failed) .transport_failed else .local_eof;
                break :loop;
            }
        }

        // 远端 → 本地
        switch (pty.read(&remote_buffer)) {
            .bytes => |n| {
                writer.interface.writeAll(remote_buffer[0..n]) catch
                    return error.OutputWriteFailed;
                // 交互式输出必须立刻可见:一个没有换行的提示符不刷新
                // 就是一个看起来卡死的终端。
                writer.interface.flush() catch return error.OutputWriteFailed;
                progressed = true;
            },
            .again => {},
            .eof => {
                outcome = .remote_exit;
                break :loop;
            },
            .failed => {
                outcome = .transport_failed;
                break :loop;
            },
        }

        // 尺寸,以及挂在同一节拍上的空闲回调
        const now = nowMs(io);
        if (now - last_size_check >= resize_poll_ms) {
            last_size_check = now;
            if (Console.size()) |current| {
                const changed = last_size == null or
                    last_size.?.cols != current.cols or
                    last_size.?.rows != current.rows;
                if (changed) {
                    pty.resize(current.cols, current.rows);
                    last_size = current;
                }
            }
            if (tick) |t| {
                if (!t.call(t.context)) {
                    outcome = .remote_exit;
                    break :loop;
                }
            }
        }

        if (!progressed)
            std.Io.sleep(io, .{ .nanoseconds = std.time.ns_per_ms }, .awake) catch {};
    }

    writer.interface.flush() catch return error.OutputWriteFailed;
    release(queue, &input_thread);
    released = true;
    return outcome;
}

/// 放开读线程,**不等它**。
///
/// **为什么不 join。** `cancelInputRead` 是给管道写的 —— `tunnel` 的 stdin
/// 通常是管道,`NtCancelSynchronousIoFile` 在那上面管用。**控制台句柄上的
/// 同步读取消不掉**,所以 join 会一直阻塞到用户下一次按键。真机上的样子
/// 是:远端已经退出了,屏幕却卡住,要连按几次 Ctrl-C 才看到"会话结束"。
///
/// 取消仍然照发:它对管道有效(`tunnel` 走同一条路),对控制台无害。
///
/// 不 join 就意味着那个线程可能活过这个栈帧,所以队列是进程级的 ——
/// 它写进去的地方一直有效。进程随后就退出,线程被操作系统收掉。
fn release(queue: *Queue.InputQueue, thread: *std.Thread) void {
    queue.requestStop();
    Queue.cancelInputRead(thread);
    thread.detach();
}

test "the pump's body is analysed even before a caller exists" {
    // Zig analyses function bodies lazily, and `refAllDecls` is not recursive —
    // so without taking this address, `run` type checks for the first time
    // whenever some future commit happens to call it. Nothing here exercises the
    // loop (it needs a live channel and a real console); this only holds the
    // compiler to the signature and the body.
    _ = &run;
}
