//! 交互会话的双向泵。
//!
//! 三件事在一个循环里轮流推进,任何一件都不许阻塞另外两件:
//! 本地输入 → PTY、PTY → 本地输出、窗口尺寸 → 远端 PTY。
//!
//! 本地输入来自 `InputQueue` 的后台线程,因为 Windows 上没有办法把控制台
//! 句柄和一个 socket 一起等;远端读写是 libssh2 非阻塞调用。两边都不阻塞,
//! 所以没有进展时才睡 1ms。
//!
//! **本地终端是会话级的,PTY 通道不是。** 一次 `attach` 可能换好几条通道
//! (每次重连一条),但从头到尾只有一个终端和一个读它的线程。所以
//! `startLocal`/`stopLocal` 由调用方在整个会话的两端各调一次,`run` 只负责
//! 把一条通道泵到它结束为止。

const std = @import("std");
const Ssh = @import("../ssh/Client.zig");
const Console = @import("Console.zig");
const Queue = @import("InputQueue.zig");
const Escape = @import("escape.zig");

/// 尺寸轮询间隔。人感觉不到 200ms,而换来的是不必把事件读取和字节读取
/// 混在同一个句柄上 —— 输入线程在做阻塞 `ReadFile`,读不到窗口事件记录。
const resize_poll_ms: i64 = 200;

/// 重连等待期间多久看一次本地输入。比 `resize_poll_ms` 密,因为这段时间里
/// 本地输入的唯一用途就是让人打断,而一次"放弃"按下去要立刻有反应。
const abandon_poll_ms: i64 = 20;

/// 重连等待中读到它就是放弃。
///
/// 进了 raw 模式之后 `ENABLE_PROCESSED_INPUT` 已被清除,所以 Ctrl-C 到达
/// 时是字节 0x03 而不是信号。**这是整个会话期间 0x03 唯一一次不被送往
/// 远端** —— 此刻没有通道可送。
const abandon_key: u8 = 0x03;

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
    /// tick 说这个会话已经不归我们了(租约被接管)。
    lost,
    /// 人按了 `Ctrl-]` 加一个命令键。通道还好好的,调用方处理完这个动作
    /// 之后可以拿同一条通道再进来。
    escape: Escape.Action,
};

pub const Error = error{
    InputThreadFailed,
    OutputWriteFailed,
};

/// 每个空闲 tick 调一次(约 200ms),**包括重连等待期间**。
///
/// 返回 false 表示会话应当结束 —— 租约被别人接管时就是这样:继续打字会
/// 让两个所有者同时以为自己持有这个会话。
///
/// 停摆期间照调是必需的而不是顺便:租约 TTL 是 120s,而重连预算是 300s。
/// 不续租的话,一次三分钟的断线之后别人可以合法接管,而我们会带着一个
/// 已经失效的租约重连回去。
pub const Tick = struct {
    context: *anyopaque,
    call: *const fn (context: *anyopaque) bool,
};

/// 单调毫秒。
///
/// `.awake` 而不是 `.real`:这是一个间隔计时器,NTP 把墙钟往回拨一秒不该
/// 让尺寸轮询停上一秒。泵末尾的 `std.Io.sleep` 用的也是这个时钟。
pub fn nowMs(io: std.Io) i64 {
    const ts = std.Io.Timestamp.now(io, .awake);
    return @intCast(@divTrunc(ts.nanoseconds, std.time.ns_per_ms));
}

/// 读线程的队列,**进程级而不是栈上**。
///
/// 一个进程至多开一个交互会话,所以这是安全的;而它必须活得比任何一个
/// 栈帧长,理由见 `stopLocal`:我们不等那个线程结束。
var session_queue: Queue.InputQueue = undefined;

/// 这个进程有没有开过读线程。
///
/// **开过就再也不算清零**,因为 `stopLocal` 不等那个线程结束 —— 它此刻很
/// 可能正停在一次取消不掉的控制台读上。谁想结束这个进程,都得知道这件事:
/// 见 `Console.exitNow`。
var reader_started: bool = false;

pub fn hasOutstandingReader() bool {
    return reader_started;
}

/// 会话级的本地终端读取。整个会话开一次、关一次,跨重连不动。
pub const Local = struct {
    queue: *Queue.InputQueue,
    thread: std.Thread,
    /// 转义键状态机,**也是会话级的**。转义键和它后面那个命令键几乎不会
    /// 落在同一次读里,更不会落在同一条通道里 —— 断线重连换了通道之后,
    /// 它必须还记得自己在待命。
    escape: Escape.Machine = .{},
};

pub fn startLocal(io: std.Io) Error!Local {
    session_queue = Queue.InputQueue.init(io);
    const queue = &session_queue;
    const thread = std.Thread.spawn(.{}, Queue.inputPump, .{ queue, std.Io.File.stdin() }) catch
        return error.InputThreadFailed;
    reader_started = true;
    return .{ .queue = queue, .thread = thread };
}

/// 放开读线程,**不等它**。
///
/// **为什么不 join。** `cancelInputRead` 是给管道写的 —— `tunnel` 的 stdin
/// 通常是管道,`NtCancelSynchronousIoFile` 在那上面管用。**控制台句柄上的
/// 同步读取消不掉**,所以 join 会一直阻塞到用户下一次按键。真机上的样子
/// 是:远端已经退出了,屏幕却卡住,要连按几次 Ctrl-C 才看到"会话结束"。
///
/// **取消也不发,而这是被验收打回来的。** 这里曾经照发 `cancelInputRead`,
/// 理由是"对管道有效,对控制台无害"。后半句是错的:对一次进行中的控制台
/// 同步读发 `NtCancelSynchronousIoFile`,**这个调用本身**会阻塞到下一次
/// 输入 —— 于是远端已经退出、"会话结束"已经打出来,进程却停在这里,
/// 大约每两次就有一次。这里的 stdin 一定是控制台(`Console.enter` 已经
/// 拒绝了别的),所以那次取消在这里从来没有用处。管道上的取消是
/// `tunnel` 的事,它自己调。
///
/// 不 join 就意味着那个线程可能活过调用方的栈帧,所以队列是进程级的 ——
/// 它写进去的地方一直有效。进程随后就退出(`Console.exitNow`),线程被
/// 操作系统收掉。
pub fn stopLocal(local: *Local) void {
    local.queue.requestStop();
    local.thread.detach();
}

/// 把一条 PTY 通道泵到它结束为止。
///
/// 结束之后 `local` 仍然可用:传输中断时调用方会重连并拿一条新通道再进来。
pub fn run(io: std.Io, local: *Local, pty: *Ssh.Pty, tick: ?Tick) Error!Outcome {
    const queue = local.queue;

    var out_buffer: [Queue.tunnel_buffer_bytes]u8 = undefined;
    var writer = std.Io.File.stdout().writerStreaming(io, &out_buffer);

    var last_size: ?Console.Size = Console.size();
    if (last_size) |s| pty.resize(s.cols, s.rows);
    var last_size_check = nowMs(io);

    var outcome: Outcome = .transport_failed;
    var input_buffer: [Queue.tunnel_buffer_bytes]u8 = undefined;
    var remote_buffer: [Queue.tunnel_buffer_bytes]u8 = undefined;

    // 已经过了状态机、还没被通道收下的字节。
    //
    // 转发出去的字节永远不会比读进来的多(状态机只会吃掉字节,不会造出
    // 字节),所以和输入缓冲一样大就够。
    var pending: [Queue.tunnel_buffer_bytes]u8 = undefined;
    var pending_len: usize = 0;
    var pending_off: usize = 0;
    var fired: ?Escape.Action = null;

    loop: while (true) {
        // 每轮都问,不是每 200ms 问一次:关窗口时操作系统只给几秒,而这
        // 条循环在有数据时一轮只要几微秒。
        if (Console.abortRequested()) {
            outcome = .aborted;
            break :loop;
        }

        var progressed = false;

        // 本地 → 远端,**中间过一遍转义状态机**。
        //
        // 两段缓冲而不是把队列里的字节直接交给通道:状态机会吃掉一些字节
        // (转义键本身),于是"从队列消耗了多少"和"该往通道写多少"不再
        // 相等;而通道是非阻塞的,一次只肯收一部分。`pending` 就是这两个
        // 数字之间的那个缓冲。
        if (pending_off == pending_len) {
            // **动作要等到这一刻才交出去。** 人在按 `Ctrl-]` 之前打的字
            // 必须先真的到远端 —— 否则一次 detach 会顺手吞掉最后半行命令。
            if (fired) |action| {
                outcome = .{ .escape = action };
                break :loop;
            }
            pending_off = 0;
            pending_len = 0;
            const queued = queue.peek(&input_buffer);
            if (queued != 0) {
                var taken: usize = 0;
                for (input_buffer[0..queued]) |byte| {
                    taken += 1;
                    switch (local.escape.feed(byte)) {
                        .forward => |out| {
                            pending[pending_len] = out;
                            pending_len += 1;
                        },
                        .swallow => {},
                        .bell => {
                            writer.interface.writeAll("\x07") catch
                                return error.OutputWriteFailed;
                            writer.interface.flush() catch return error.OutputWriteFailed;
                        },
                        // 这一批剩下的字节留在队列里,下一轮再说 —— 动作
                        // 后面的按键属于动作处理完之后的那个会话。
                        .action => |action| {
                            fired = action;
                            break;
                        },
                    }
                }
                queue.consume(taken);
                progressed = true;
            } else {
                const state = queue.snapshot();
                if (state.done) {
                    outcome = if (state.failed) .transport_failed else .local_eof;
                    break :loop;
                }
            }
        }
        if (pending_off < pending_len) {
            switch (pty.write(pending[pending_off..pending_len])) {
                .bytes => |n| {
                    pending_off += n;
                    progressed = true;
                },
                .again => {},
                .failed => {
                    outcome = .transport_failed;
                    break :loop;
                },
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
                    outcome = .lost;
                    break :loop;
                }
            }
        }

        if (!progressed)
            std.Io.sleep(io, .{ .nanoseconds = std.time.ns_per_ms }, .awake) catch {};
    }

    writer.interface.flush() catch return error.OutputWriteFailed;
    return outcome;
}

/// 重连退避期间发生了什么。
pub const Wait = enum {
    /// 等满了,可以再试一次连接。
    elapsed,
    /// 用户按了 Ctrl-C。
    abandoned,
    /// 窗口被关了。
    aborted,
    /// 本地 stdin 结束了。
    local_eof,
    /// tick 说这个会话已经不归我们了。
    lost,
};

/// 等 `ms` 毫秒,期间盯着本地输入和关窗口。
///
/// **等待中必须排空输入队列**,而不只是看一眼:队列是有界的,塞满之后读
/// 线程会阻塞在 `put` 里,于是放弃键排在前面几千个字节后面永远轮不到。
/// 排空掉的字节直接丢弃 —— 此刻没有通道可以转发它们,而攒着它们等重连
/// 成功后再发,等于把断线期间的盲打送进一个已经换了上下文的 shell。
pub fn waitForRetry(io: std.Io, local: *Local, ms: i64, tick: ?Tick) Wait {
    const queue = local.queue;
    const started = nowMs(io);
    var last_tick = started;
    var drain: [Queue.tunnel_buffer_bytes]u8 = undefined;

    while (true) {
        if (Console.abortRequested()) return .aborted;

        const n = queue.peek(&drain);
        if (n != 0) {
            queue.consume(n);
            if (std.mem.indexOfScalar(u8, drain[0..n], abandon_key) != null) return .abandoned;
        } else if (queue.snapshot().done) {
            return .local_eof;
        }

        const now = nowMs(io);
        if (now - last_tick >= resize_poll_ms) {
            last_tick = now;
            if (tick) |t| {
                if (!t.call(t.context)) return .lost;
            }
        }
        if (now - started >= ms) return .elapsed;

        std.Io.sleep(io, .{ .nanoseconds = abandon_poll_ms * std.time.ns_per_ms }, .awake) catch {};
    }
}

/// 菜单要的一个按键。
pub const Key = union(enum) {
    byte: u8,
    aborted,
    local_eof,
    lost,
};

/// 取一个本地按键。菜单和提示行的输入原语。
///
/// **不过转义状态机**,而且这是对的:菜单开着的时候,按键属于菜单,不属于
/// 会话。设计里那个 `menu` 状态想表达的就是这件事 —— 这里用"根本不喂它"
/// 来表达,比用一条状态转移可靠。
///
/// **照调 tick。** 租约 TTL 是 120s,一个开着菜单去接电话的人会让它过期,
/// 和重连停摆期间同一个问题、同一个解法。
pub fn readKey(io: std.Io, local: *Local, tick: ?Tick) Key {
    const queue = local.queue;
    var one: [1]u8 = undefined;
    var last_tick = nowMs(io);
    while (true) {
        if (Console.abortRequested()) return .aborted;
        if (queue.peek(&one) != 0) {
            queue.consume(1);
            return .{ .byte = one[0] };
        }
        if (queue.snapshot().done) return .local_eof;

        const now = nowMs(io);
        if (now - last_tick >= resize_poll_ms) {
            last_tick = now;
            if (tick) |t| {
                if (!t.call(t.context)) return .lost;
            }
        }
        std.Io.sleep(io, .{ .nanoseconds = abandon_poll_ms * std.time.ns_per_ms }, .awake) catch {};
    }
}

/// 让远端把整屏重画一遍。
///
/// **本地没有办法把被覆盖的画面找回来。** 命令层在屏幕上打了几行字,而那
/// 几行可能正落在远端 `vim` 画的东西上;能修复它的只有 vim 自己。
///
/// 通用的触发器只有一个:改一下 PTY 尺寸再改回去。远端的前台进程组会收到
/// SIGWINCH,而 `vim`、`htop`、`less`、`tmux` 全都在那上面重画整屏。这不是
/// 取巧,这正是终端复用器自己用的办法。
///
/// **不用备用屏,而这是被真机打回来的。** 那个方案的假设是"进去再出来,
/// 终端把原样还回来" —— 但终端只有一块备用缓冲区,远端的 vim 早就在里面
/// 了。我们的进入是空操作,我们的退出把终端退回了主屏。
pub fn forceRedraw(pty: *Ssh.Pty) void {
    const size = Console.size() orelse return;
    // 尺寸必须真的变一下,否则有些程序会认出"没变"然后什么都不做。
    if (size.cols < 2) return;
    pty.resize(size.cols - 1, size.rows);
    pty.resize(size.cols, size.rows);
}

/// 丢掉此刻排在队列里的本地输入。
///
/// 给"按任意键返回"用的:一个 Alt-A 或者方向键是**两三个字节**,而那里
/// 只取走一个。剩下的会漏进会话,在远端变成一次莫名其妙的按键 —— 真机上
/// 的样子是 vim 忽然进了插入模式。
pub fn drainInput(local: *Local) void {
    const queue = local.queue;
    var scratch: [Queue.tunnel_buffer_bytes]u8 = undefined;
    while (true) {
        const n = queue.peek(&scratch);
        if (n == 0) return;
        queue.consume(n);
    }
}

test "the pump's body is analysed even before a caller exists" {
    // Zig analyses function bodies lazily, and `refAllDecls` is not recursive —
    // so without taking this address, `run` type checks for the first time
    // whenever some future commit happens to call it. Nothing here exercises the
    // loop (it needs a live channel and a real console); this only holds the
    // compiler to the signature and the body.
    _ = &run;
    _ = &waitForRetry;
    _ = &readKey;
    _ = &startLocal;
    _ = &stopLocal;
}

test "本地输入永远不会绕过转义状态机直接到远端" {
    // 源码契约。真行为要一个控制台夹具才测得到,而缺陷本身不需要那么重的
    // 东西就能锁住:它只是把队列缓冲直接交给了通道。那样写不会编译失败、
    // 也不会有任何测试变红 —— 只会让 `Ctrl-]` 一次也不触发,而远端收到
    // 一个它不认识的 0x1D。
    //
    // 扫描范围收敛到函数体,且上面这段散文刻意不拼出被检查的那个片段。
    const source = @embedFile("Pump.zig");
    const start = std.mem.indexOf(u8, source, "pub fn " ++ "run(io").?;
    const end = start + std.mem.indexOf(u8, source[start..], "\n}\n").?;
    const body = source[start..end];

    // 通道只从 `pending` 拿字节,而 `pending` 只有状态机填得进去。
    try std.testing.expect(std.mem.indexOf(u8, body, "pty.write(input" ++ "_buffer") == null);
    try std.testing.expect(std.mem.indexOf(u8, body, "pty.write(pend" ++ "ing[") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "local.escape." ++ "feed(") != null);
    // 范围真的收住了。
    try std.testing.expect(body.len < 6000);
}

test "放开读线程时不对控制台读发取消" {
    // 对进行中的控制台同步读发取消,这个调用自己会阻塞到下一次输入 ——
    // 进程停在"会话结束"之后不退,约每两次一次。ConPTY 实测。
    const source = @embedFile("Pump.zig");
    const start = std.mem.indexOf(u8, source, "pub fn " ++ "stopLocal(").?;
    const end = start + std.mem.indexOf(u8, source[start..], "\n}\n").?;
    const body = source[start..end];
    try std.testing.expect(std.mem.indexOf(u8, body, "cancel" ++ "InputRead") == null);
    try std.testing.expect(std.mem.indexOf(u8, body, "detach()") != null);
    try std.testing.expect(body.len < 400);
}

test "重连等待会把读到的字节丢掉,不会攒起来重放" {
    // 源码契约。真行为要一个管道夹具才测得到,而这里要锁住的是一个决定
    // 而不是一段算法:排空的字节必须被 `consume` 掉,并且这个函数体里
    // 不存在任何把它们送走的路径。
    //
    // 扫描范围收敛到函数体 —— 这棵树里"扫描器读到自己的散文"已经发生过
    // 七次。上面的散文刻意不拼出被检查的标识符。
    const source = @embedFile("Pump.zig");
    const start = std.mem.indexOf(u8, source, "pub fn wait" ++ "ForRetry").?;
    const end = start + std.mem.indexOf(u8, source[start..], "\n}\n").?;
    const body = source[start..end];

    try std.testing.expect(std.mem.indexOf(u8, body, "queue.con" ++ "sume") != null);
    // 没有任何一条写往远端的路径:那正是"此刻没有通道"的意思。
    try std.testing.expect(std.mem.indexOf(u8, body, "pty.") == null);
    try std.testing.expect(body.len < 1400);
}
