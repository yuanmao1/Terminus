//! `terminus shell <server>` 与 `terminus attach <server>[:<session>]`。
//!
//! 两个动词共用同一条管道(控制台 raw 模式 → PTY 通道 → 泵),只差远端
//! 启动什么:`shell` 启动登录 shell,`attach` 执行 `tmux attach`。
//!
//! 两者都用 `Cli.sshConnect` 而不是 `Cli.connect`:daemon 协议是长度前缀
//! 的 JSON 帧,载不动裸字节流;而热连接省下的一次握手对一个开几十分钟的
//! 会话没有意义。理由与 `cmd_tunnel.zig` 相同,那里也有一条同样的源码门禁。

const std = @import("std");
const Cli = @import("cli.zig");
const Core = @import("../core/core.zig");
const Store = Core.Store;
const Console = Core.tty.Console;
const Pump = Core.tty.Pump;
const Escape = Core.tty.escape;

const Control = @import("../core/control.zig");
const Claim = Control.Claim;
const Authority = Control.Authority;
const stillOurs = Control.stillOurs;

const fatal = Cli.fail;

/// 被挡住时说什么。
///
/// **两种挡法解法完全不同,所以不能共用一句话。** 未结的操作行要人去对账;
/// 活租约不需要,它自己会过期,而 `reconcile` 对它毫无作用 —— 那条把两者
/// 混为一谈的消息让人对着一个两分钟后自己消失的东西反复跑 reconcile。
fn refuseBlocked(ctx: *Cli.Ctx, blocker: Core.execution.Blocker) noreturn {
    switch (blocker) {
        .unsettled => |op| fatal(
            "交互会话被未结的 request {s} 挡住 —— 它可能还在远端跑着。" ++
                "确认之后对账掉它:\n" ++
                "  terminus request reconcile {s} --override \"<原因>\" --by <谁> --resolved cancelled",
            .{ op.request_id, op.request_id },
        ),
        .lease => |lease| {
            const left = lease.expires_at - Control.wallClockSeconds(ctx.io);
            fatal(
                "这个范围的租约被 request {s} 占着,还有 {d} 秒到期。\n" ++
                    "如果那是一个已经关掉的交互会话,等它过期就行 —— " ++
                    "reconcile 对租约没有作用。",
                .{ lease.owner_request_id, if (left > 0) left else 0 },
            );
        },
    }
}

pub const Mode = enum { shell, attach };

pub const shell_usage = "usage: terminus shell <server>\n" ++
    "\n打开远端登录 shell。本地终端进入 raw 模式,退出后自动还原。\n" ++
    "裸登录 shell 不持久:连接断开时远端进程随之结束。\n" ++
    "\n会话中按 Ctrl-] 再按 ? 看本地命令(detach / 传文件 / 强制断开)。\n";

pub const attach_usage = "usage: terminus attach <server>[:<session>]\n" ++
    "\n接入远端 tmux 会话。detach 后会话在远端继续存活,agent 可用\n" ++
    "'terminus read' 读到这期间的输出。不给会话名时列出现有会话。\n" ++
    "\n断线会自动重连(退避至多五分钟);会话在断线期间消失时不会替你新建。\n" ++
    "会话中按 Ctrl-] 再按 ? 看本地命令(detach / 传文件 / 强制断开)。\n" ++
    "\n需要远端已安装 tmux;用 'terminus doctor <server>' 确认。\n";

/// 续租的节拍器。
///
/// 泵每 200ms 调一次 tick,但续租是一次 store 写 —— 每秒五次写既无必要
/// 也会把 WAL 撑大。`Claim.ttl_secs` 是 120s,30s 续一次留了四倍余量。
const renew_every_ms: i64 = 30_000;

/// 单调毫秒,与 `Pump` 用同一个时钟。`.real` 会被 NTP 回拨,让间隔算成负数。
fn nowMs(io: std.Io) i64 {
    const ts = std.Io.Timestamp.now(io, .awake);
    return @intCast(@divTrunc(ts.nanoseconds, std.time.ns_per_ms));
}

/// 挂在泵空闲节拍上的租约续租。
const LeaseTick = struct {
    claim: Claim,
    io: std.Io,
    authority: Authority = .held,
    last_renewed_ms: i64,

    /// 返回 false 让泵结束会话。
    ///
    /// 续不上就停:租约被别人接管后继续打字,会让两个所有者同时以为自己
    /// 持有这个会话 —— 那正是这层屏障存在的理由。
    fn call(context: *anyopaque) bool {
        const self: *LeaseTick = @ptrCast(@alignCast(context));
        const now = nowMs(self.io);
        if (now - self.last_renewed_ms < renew_every_ms) return true;
        self.last_renewed_ms = now;
        return stillOurs(self.claim, self.io, &self.authority);
    }
};

/// 远端的 TERM。
///
/// 写死而不是读本地 `TERM`:Windows 控制台通常根本没有这个环境变量,而
/// 猜错会让远端的 ncurses 程序画出乱码。`xterm-256color` 是 Windows
/// Terminal 与 conhost(Win10 1703 起)都真正支持的那一档。
const remote_term = "xterm-256color";

/// 会话名 → 争用范围。与 `cmd_session.zig` 的 `contentionScope` 同一映射:
/// 一个 job 的会话就是那个 job 的 shell,接进去的人和 `job kill` 争的是
/// 同一个东西。
fn contentionScope(name: []const u8) Core.execution.Scope {
    const job_prefix = "job-";
    if (std.mem.startsWith(u8, name, job_prefix) and name.len > job_prefix.len)
        return .{ .kind = .job, .key = name[job_prefix.len..] };
    return .{ .kind = .job, .key = name };
}

/// 选出要接入的会话名(Terminus 名,不带 `t-` 前缀)。
///
/// 不给名字时:恰好一个就用它,多个则列出并要求指名,一个都没有则要求
/// 先 `terminus session new`。**不自动新建** —— 一个以为自己回到工作现场
/// 的人对着空 shell,比一句拒绝糟得多。
fn chooseSession(
    ctx: *Cli.Ctx,
    executor: Core.Executor,
    explicit: ?[]const u8,
) []const u8 {
    if (explicit) |name| return name;
    const sessions = Core.Tmux.list(executor, ctx.arena) catch |err| switch (err) {
        error.TmuxMissing => fatal(
            "远端没有 tmux;交互会话需要它。用 'terminus doctor <server>' 确认",
            .{},
        ),
        else => fatal("无法列出远端会话: {s}", .{@errorName(err)}),
    };
    if (sessions.len == 0) fatal(
        "该服务器上没有 Terminus 会话;先跑 'terminus session new <server> <name>'",
        .{},
    );
    if (sessions.len == 1) return sessions[0].name;

    var listing: std.ArrayList(u8) = .empty;
    for (sessions) |s| {
        listing.appendSlice(ctx.arena, "  ") catch {};
        listing.appendSlice(ctx.arena, s.name) catch {};
        listing.appendSlice(ctx.arena, "\n") catch {};
    }
    fatal("该服务器上有 {d} 个会话,指明要接哪个:\n{s}", .{ sessions.len, listing.items });
}

/// 会话是怎么结束的。
///
/// **两个变体的区别是"还有没有通道可关"**,这是类型在替收尾代码记的一件
/// 事:停摆期间结束的会话,它的连接早在决定重连时就被释放了,对它调
/// `pty.close()` 是访问已释放的内存。分成两支之后,收尾里那条关通道的路径
/// 在结构上就够不着它们。
const Ending = union(enum) {
    /// 通道还活着,按它的结局收尾。
    pump: Pump.Outcome,
    /// 停摆期间结束的,没有通道。
    outage: Outage,
    /// 人从 `Ctrl-]` 命令层结束了会话。通道还活着。
    local: LocalEnd,
};

const LocalEnd = enum {
    /// `Ctrl-] d` —— 干净地关掉通道,会话在远端继续。
    detached,
    /// `Ctrl-] .` —— 不等远端确认,直接走。
    force_disconnected,
};

const Outage = enum {
    /// 五分钟预算用尽,一直没连回去。
    exhausted,
    /// 连回去了,但那个 tmux 会话不在了。
    vanished,
    /// 连回去了,但远端已经没有 tmux。
    tmux_missing,
    /// 人在退避横幅上按了 Ctrl-C。
    abandoned,
    /// 退避期间窗口被关了。
    aborted,
    /// 退避期间本地 stdin 结束了。
    local_eof,
    /// 退避期间租约被别人接管了。
    lost,
};

/// 一轮重连的结果。
const Reconnected = union(enum) {
    /// 连回去了,这是新通道。
    pty: Core.Ssh.Pty,
    /// 没连回去,会话到此为止。
    over: Outage,
};

// --- `Ctrl-]` 命令层 ----------------------------------------------------------
//
// **就地打印,不抢屏,像 `ssh` 的 `~?`。** 设计第 6 节要求画在备用屏上,
// 理由是"这样在物理上不可能污染远端全屏程序的画面" —— 那句话是错的,而且
// 是被真机打回来的:终端只有一块备用缓冲区,远端的 `vim` 早就自己切进去
// 了,我们的退出把终端退回主屏,于是 vim 还在跑、画面却没了。
//
// 就地打印的代价是会盖住几行远端画面,而那个代价由 `Pump.forceRedraw`
// 付掉:返回会话时让远端重画整屏。顺带还有个好处 —— 在普通 shell 里
// (没人拥有屏幕)这些字就是正常滚上去的输出,你的历史一行都不丢。
//
// **菜单期间不读远端,也不需要缓冲。** 设计里那个 1 MiB 环形区加"丢弃了
// N 字节"的提示是在解决一个不存在的问题:SSH 通道自带窗口流控,我们不读,
// 窗口耗尽,远端就阻塞在写上,一个字节都不会丢。

/// 菜单做完之后,会话该怎么办。
const MenuEnd = enum {
    /// 回到会话。
    resume_session,
    /// 菜单期间窗口被关了。
    aborted,
    /// 菜单期间本地 stdin 结束了。
    local_eof,
    /// 菜单期间租约被别人接管了。
    lost,
};

/// 一次取键的三种去向。
fn menuEndFor(key: Pump.Key) ?MenuEnd {
    return switch (key) {
        .byte => null,
        .aborted => .aborted,
        .local_eof => .local_eof,
        .lost => .lost,
    };
}

/// `\r\n` 而不是 `\n`:raw 模式下 `DISABLE_NEWLINE_AUTO_RETURN` 开着,光标
/// 不会自己回到行首,只用 `\n` 画出来的东西会往右下角爬。
const help_screen =
    "\r\n" ++
    "── Terminus 会话命令 ─────────────────\r\n" ++
    "  Ctrl-] 之后按:\r\n" ++
    "    d        detach —— 断开,会话在远端继续\r\n" ++
    "    .        强制断开 —— 不等远端确认\r\n" ++
    "    p        推一个文件到远端\r\n" ++
    "    g        从远端拉一个文件\r\n" ++
    "    ?        这份键位表\r\n" ++
    "    Ctrl-]   给远端送一个字面的 Ctrl-]\r\n" ++
    "  其他键:响铃,而且那两个字节一个都不会送到远端\r\n" ++
    "──────────────────────────────────────\r\n" ++
    "按任意键返回会话\r\n";

fn showHelp(ctx: *Cli.Ctx, local: *Pump.Local, tick: ?Pump.Tick) MenuEnd {
    Console.writeDirect(ctx.io, help_screen);
    return menuEndFor(Pump.readKey(ctx.io, local, tick)) orelse .resume_session;
}

/// 打完一行之后发生了什么。行本身留在调用方的 `editor` 里。
const Typed = union(enum) {
    submitted,
    cancelled,
    ended: MenuEnd,
};

/// 就地读一行。回显、退格、Enter 提交、ESC 取消,没别的。
fn promptLine(
    ctx: *Cli.Ctx,
    local: *Pump.Local,
    tick: ?Pump.Tick,
    title: []const u8,
    hint: []const u8,
    editor: *Escape.LineEdit,
) Typed {
    Console.writeDirect(ctx.io, "\r\n── ");
    Console.writeDirect(ctx.io, title);
    Console.writeDirect(ctx.io, " ──\r\n  ");
    Console.writeDirect(ctx.io, hint);
    Console.writeDirect(ctx.io, "    (ESC 取消)\r\n> ");
    while (true) {
        const key = Pump.readKey(ctx.io, local, tick);
        if (menuEndFor(key)) |end| return .{ .ended = end };
        const byte = key.byte;
        switch (editor.feed(byte)) {
            .echo => Console.writeDirect(ctx.io, &[_]u8{byte}),
            // 退一格、擦掉、再退一格 —— 光标左移本身不删字符。
            .erase => Console.writeDirect(ctx.io, "\x08 \x08"),
            .bell => Console.writeDirect(ctx.io, "\x07"),
            .submit => return .submitted,
            .cancel => return .cancelled,
        }
    }
}

/// 从命令层回到会话:把远端的画面要回来,并丢掉命令层吃剩的字节。
///
/// 两件事都是被真机打回来的。
///
/// **重画**:命令层在屏幕上打了几行字,而那几行可能正落在远端 `vim` 画的
/// 东西上。本地没有办法把它找回来 —— 只有画它的那一头能。
///
/// **排空**:"按任意键"只取走一个字节,而 Alt-A、方向键这些是两三个字节
/// 的序列。剩下的会漏进会话,在远端变成一次莫名其妙的按键。
fn resumeSession(local: *Pump.Local, pty: *Core.Ssh.Pty) void {
    Pump.drainInput(local);
    Pump.forceRedraw(pty);
}

/// 等一个按键,给那些"看完再走"的提示用。
fn pause(ctx: *Cli.Ctx, local: *Pump.Local, tick: ?Pump.Tick) MenuEnd {
    Console.writeDirect(ctx.io, "\r\n按任意键继续\r\n");
    return menuEndFor(Pump.readKey(ctx.io, local, tick)) orelse .resume_session;
}

/// 本进程的可执行文件路径。
///
/// **`std.fs.selfExePath` 在 Zig 0.16 里整个被删了**(0.14 还有),所以这里
/// 直接问 Win32。走 PATH 找 `terminus` 不行:npm 装的那份可能是另一个版本,
/// 而这次传输必须由**正在跑的这个二进制**完成。
fn selfExePath(buf: []u8) ?[]const u8 {
    if (comptime @import("builtin").os.tag != .windows) return null;
    var wide: [std.os.windows.PATH_MAX_WIDE]u16 = undefined;
    const len = GetModuleFileNameW(null, &wide, wide.len);
    if (len == 0 or len >= wide.len) return null;
    const written = std.unicode.utf16LeToUtf8(buf, wide[0..len]) catch return null;
    return buf[0..written];
}

extern "kernel32" fn GetModuleFileNameW(
    hModule: ?std.os.windows.HMODULE,
    lpFilename: [*]u16,
    nSize: std.os.windows.DWORD,
) callconv(.winapi) std.os.windows.DWORD;

/// `p` 与 `g`:提示两个路径,然后**作为子进程**跑 `terminus push/pull`。
///
/// **子进程而不是进程内直接调那个传输命令,而这不是风格选择。**
/// `Cli.registerExecution` 写的是一个**单槽**进程级全局([cli.zig:259]);
/// 在会话里调它会把 attach 自己的登记覆盖掉,再在它的 defer 里清空,于是
/// 此后任何 `fatal` 都不会结清 attach 那条操作行 —— 正是 M1/M2 花了四轮
/// 才修好的那类缺陷。
///
/// 子进程还顺带给对了别的东西:传输拿到自己的 request id、自己的收据、
/// 自己的连接,和人在另一个窗口敲出来的完全一样。
///
/// (有一条门禁扫这个文件里有没有那个模块的名字,所以这段话不拼它。)
fn runTransfer(
    ctx: *Cli.Ctx,
    local: *Pump.Local,
    tick: ?Pump.Tick,
    server_name: []const u8,
    action: Escape.Action,
) MenuEnd {
    const pushing = action == .push;
    var editor: Escape.LineEdit = .{};
    switch (promptLine(
        ctx,
        local,
        tick,
        if (pushing) "推一个文件到远端" else "从远端拉一个文件",
        if (pushing) "<本地路径> <远端路径>" else "<远端路径> <本地路径>",
        &editor,
    )) {
        .cancelled => return .resume_session,
        .ended => |end| return end,
        .submitted => {},
    }

    const paths = Escape.splitPaths(editor.text()) orelse {
        Console.writeDirect(ctx.io, "\r\n\r\n要两个路径,中间一个空格。带空格的路径这里不支持。\r\n");
        return pause(ctx, local, tick);
    };

    var exe_buf: [std.fs.max_path_bytes]u8 = undefined;
    const exe = selfExePath(&exe_buf) orelse {
        Console.writeDirect(ctx.io, "\r\n\r\n找不到本程序的路径,无法启动传输。\r\n");
        return pause(ctx, local, tick);
    };
    const argv = [_][]const u8{
        exe,
        if (pushing) "push" else "pull",
        server_name,
        paths.first,
        paths.second,
    };

    // **把终端整个还给子进程。** 它是个普通命令,按行输出;在 raw 模式下
    // (`DISABLE_NEWLINE_AUTO_RETURN` 开着)它画出来的东西会往右下角爬。
    Console.restoreActive();

    var child = std.process.spawn(ctx.io, .{ .argv = &argv }) catch |err| {
        var msg: [160]u8 = undefined;
        Console.writeDirect(ctx.io, std.fmt.bufPrint(
            &msg,
            "无法启动传输子进程: {s}\r\n",
            .{@errorName(err)},
        ) catch "无法启动传输子进程\r\n");
        reenterOrDie(ctx);
        return pause(ctx, local, tick);
    };
    const term = child.wait(ctx.io) catch |err| {
        var msg: [160]u8 = undefined;
        Console.writeDirect(ctx.io, std.fmt.bufPrint(
            &msg,
            "等待传输子进程失败: {s}\r\n",
            .{@errorName(err)},
        ) catch "等待传输子进程失败\r\n");
        reenterOrDie(ctx);
        return pause(ctx, local, tick);
    };
    const code: u32 = switch (term) {
        .exited => |c| c,
        else => 1,
    };
    reenterOrDie(ctx);
    var line: [96]u8 = undefined;
    const text = std.fmt.bufPrint(
        &line,
        "\r\n传输结束(退出码 {d})\r\n",
        .{code},
    ) catch "\r\n传输结束\r\n";
    Console.writeDirect(ctx.io, text);
    return pause(ctx, local, tick);
}

/// 子进程跑完之后回到 raw 模式。
///
/// 回不去就必须停:一个回不到 raw 模式的会话,方向键会变成三个字符、
/// `Ctrl-C` 会杀掉 Terminus 而不是远端进程。带着这个继续,比停下糟。
fn reenterOrDie(ctx: *Cli.Ctx) void {
    _ = ctx;
    Console.enter() catch fatal(
        "传输结束后无法让终端回到 raw 模式;会话到此为止,远端会话未受影响",
        .{},
    );
}

/// 断线之后一直试到连回去、或者放弃为止。
///
/// 横幅就地打印,每次尝试一行 —— 于是它顺带成了一份可以往回翻的记录。
/// **不用备用屏**,理由和命令层完全相同(见那一段):远端的全屏程序可能
/// 已经占着那块缓冲区,我们退出时会把终端退回主屏。连回去之后
/// `tmux attach` 本来就会重画整屏,所以这里不需要 `forceRedraw`。
///
/// 进来时 `client` 里的那个连接已经被调用方 deinit 掉了(`client_live` 为
/// false);连回去时这里把新的写进去并置回 true。
fn reconnect(
    ctx: *Cli.Ctx,
    server: Store.servers.Server,
    auth: Core.Ssh.Auth,
    session: []const u8,
    start: Core.Ssh.PtyStart,
    local: *Pump.Local,
    tick: ?Pump.Tick,
    client: *Core.Ssh,
    client_live: *bool,
) Reconnected {
    var announced = false;
    const started = Pump.nowMs(ctx.io);
    var attempt: u32 = 1;
    while (true) : (attempt += 1) {
        const delay_ms = switch (Core.tty.reconnect.decide(attempt, Pump.nowMs(ctx.io) - started)) {
            .give_up => return .{ .over = .exhausted },
            .retry => |ms| ms,
        };

        if (!announced) {
            announced = true;
            var head: [192]u8 = undefined;
            Console.writeDirect(ctx.io, std.fmt.bufPrint(
                &head,
                "\r\n\r\n── 连接中断,正在重连 '{s}'(Ctrl-C 放弃)──\r\n",
                .{session},
            ) catch "\r\n\r\n── 连接中断,正在重连(Ctrl-C 放弃)──\r\n");
        }
        var line: [128]u8 = undefined;
        Console.writeDirect(ctx.io, std.fmt.bufPrint(
            &line,
            "  第 {d} 次尝试,{d}s 后\r\n",
            .{ attempt, @divTrunc(delay_ms, std.time.ms_per_s) },
        ) catch "  重试中\r\n");

        switch (Pump.waitForRetry(ctx.io, local, delay_ms, tick)) {
            .elapsed => {},
            .abandoned => return .{ .over = .abandoned },
            .aborted => return .{ .over = .aborted },
            .local_eof => return .{ .over = .local_eof },
            .lost => return .{ .over = .lost },
        }

        var fresh = Cli.sshReconnect(server, auth) orelse continue;

        // **会话还在不在,必须在拿 PTY 通道之前问。** 下面那一步会把 libssh2
        // session 置成非阻塞并留在那里,而这条普通 exec 通道要的是阻塞模式。
        //
        // (有一条门禁盯着这两步的先后,所以这段话里不拼出它们的名字 ——
        // 注释里的一个名字排在真正的调用之前,就足以让那条门禁读自己。)
        const executor: Core.Executor = .{ .direct = &fresh };
        const alive = Core.Tmux.isAlive(executor, ctx.arena, session) catch |err| switch (err) {
            // 会话没了和工具没了是两个答案,只有一个是证据 —— 那个函数的
            // 注释就是为这件事写的。
            error.TmuxMissing => {
                fresh.deinit();
                return .{ .over = .tmux_missing };
            },
            // 别的错误就是这一次没成:连接可能刚又断了,接着退避。
            else => {
                fresh.deinit();
                continue;
            },
        };
        if (!alive) {
            fresh.deinit();
            return .{ .over = .vanished };
        }

        const size = Console.size() orelse Console.Size{ .cols = 80, .rows = 24 };
        const fresh_pty = fresh.openPty(remote_term, size.cols, size.rows, start) catch {
            fresh.deinit();
            continue;
        };
        client.* = fresh;
        client_live.* = true;
        return .{ .pty = fresh_pty };
    }
}

pub fn run(ctx: *Cli.Ctx, mode: Mode, raw_args: []const []const u8) !void {
    const usage = switch (mode) {
        .shell => shell_usage,
        .attach => attach_usage,
    };
    const parsed = Cli.parseArgs(ctx, raw_args);
    if (parsed.boolean("json")) fatal(
        "交互会话的 stdout 是字节流,不能是 JSON;--json 在这里没有意义",
        .{},
    );
    const target_spec = parsed.positional(0) orelse fatal("{s}", .{usage});
    const target = Cli.Target.parse(target_spec);
    if (mode == .shell and target.session != null) fatal(
        "shell 的目标是服务器,不是会话;要接会话用 'terminus attach {s}'",
        .{target_spec},
    );

    var store = try Cli.openStore(ctx, &parsed);
    defer store.close();
    const resolved = Cli.resolveServer(ctx, &store, target.server);
    const owner_token = Store.policy.ownerToken(&store, ctx.arena, ctx.io, ctx.now) catch |err|
        Cli.storeFatal(&store, err);

    // 连接在进入 raw 模式之前:握手可能花几秒,而在那之前让终端保持正常,
    // 用户才看得到连接失败的句子。
    var client = Cli.sshConnect(resolved.server, resolved.auth);
    // 重连会把这个变量整个换掉,所以 defer 不能无条件跑:断线时旧连接在
    // 原地就释放了,退出时再释放一次是二次释放。
    var client_live = true;
    defer if (client_live) client.deinit();

    // 会话选择也在进入 raw 模式之前 —— 它可能 fatal,而在 raw 模式下那句话
    // 不会换行。
    var session_name: ?[]const u8 = null;
    const start: Core.Ssh.PtyStart = switch (mode) {
        .shell => .login_shell,
        .attach => blk: {
            // `Executor` 是个 union,直连客户端就是 `.direct` 那一支。这里
            // 没有 connection 包装可以问 `.executor()`。
            const executor: Core.Executor = .{ .direct = &client };
            const chosen = chooseSession(ctx, executor, target.session);
            session_name = chosen;
            const tname = try Core.Tmux.targetName(ctx.arena, chosen);
            // `-t '=<name>'` —— 两层意思,少一层都错。
            //
            // `=` 是 tmux 的精确匹配;不加它 tmux 做前缀匹配,`web` 会接上
            // `web-old`。
            //
            // **引号是给 zsh 的。** zsh 默认开着 `EQUALS` 选项,词首的
            // `=word` 会被展开成命令 `word` 的路径,于是 `-t =t-scratch`
            // 变成 `zsh:1: t-scratch not found`。远端脚本由用户的登录
            // shell 执行,而这台测试机的登录 shell 就是 zsh —— 这条让
            // `session new` 在 zsh 主机上完全不可用,实测确认。
            break :blk .{ .command = try std.fmt.allocPrint(
                ctx.arena,
                "tmux attach -t '={s}'",
                .{tname},
            ) };
        },
    };

    const start_ms = Core.control.wallClockSeconds(ctx.io) * std.time.ms_per_s;
    const begin_options: Core.execution.BeginOptions = .{
        .server_id = resolved.server.id,
        .server_name = resolved.server.name,
        .kind = .attach,
        .scope = switch (mode) {
            .shell => .{ .kind = .server },
            .attach => contentionScope(session_name.?),
        },
        // 一个人在里面敲命令,当然会改远端。声明成只读会让这条操作不参与
        // 同范围的互斥,而那正是 `attach` 要挡住 `job kill` 的理由。
        .mutating = true,
        .alias = session_name,
        .argv_redacted = switch (mode) {
            .shell => "interactive login shell",
            .attach => "interactive session",
        },
        .owner_token = owner_token,
        .now = ctx.now,
    };
    const begun = Core.execution.begin(&store, ctx.arena, ctx.io, begin_options) catch |err|
        Cli.storeFatal(&store, err);
    var execution = switch (begun) {
        .ready => |ready| ready,
        // 交互会话自己不再持有这道屏障(`Kind.holdsScopeWhileUnsettled`),
        // 所以挡在这里的一定是别的东西 —— 一条可能还在远端跑着的 exec、
        // 一个 job,或者别人的租约。那些该挡,而且只能由人来判断。
        .blocked => |blocker| refuseBlocked(ctx, blocker),
    };
    Cli.registerExecution(&execution);
    defer {
        Cli.clearExecution();
        execution.deinit();
    }
    execution.connecting() catch |err| Cli.receiptFatal(execution.id(), err, "created");

    if (mode == .attach) try ctx.out.print(
        "本会话输出会写入远端 pane 日志(agent 可读)\n",
        .{},
    );
    try ctx.out.flush();

    const size = Console.size() orelse Console.Size{ .cols = 80, .rows = 24 };
    Console.enter() catch |err| switch (err) {
        error.NotATerminal => fatal(
            "标准输入或输出不是终端;交互会话需要真终端,不能用管道或重定向",
            .{},
        ),
        error.ConsoleModeUnavailable => fatal(
            "控制台拒绝进入 raw 模式;这个终端可能不支持虚拟终端序列",
            .{},
        ),
    };
    defer Console.restoreActive();
    // 正常收尾时也要放 Ctrl 处理器走。它最多等三秒 `abortHandled` 才让进程
    // 死,而那三秒是为"关窗口时还来得及写收据"留的;会话已经结束之后再等
    // 三秒,只会让每一次 Ctrl-C 都先僵住。`fatal` 那些路径由 `refusalCleanup`
    // 说这一声。
    defer Console.abortHandled();

    switch (execution.submitted() catch |err|
        Cli.receiptFatal(execution.id(), err, "connecting")) {
        .submitted => {},
        .refused => fatal("交互会话在提交时被拒绝;对账 request {s}", .{execution.id()}),
    }

    // 租约,**只有 `attach` 取**,范围是会话的争用范围。
    //
    // 作用只有一个:人在会话里时 `session rm` 与 `job kill` 会被拒绝。
    //
    // **`shell` 不取,而且这是被真机打回来的。** 它一度也取,范围是整台
    // 服务器 —— 于是一个关掉窗口的 shell 会把那台机器上的一切挡住两分钟
    // (TTL),包括第二个 shell。裸登录 shell 不声明任何东西,它和 `ssh`
    // 一样,既不挡别人也不被别人挡。
    //
    // 租约会自己过期,这正是它相对未结操作行的好处:进程被硬杀之后,
    // 没有人需要做任何事 —— "the only thing a dead process can do"。
    var lease_tick: ?LeaseTick = null;
    if (session_name) |label| {
        const claim: Claim = .{
            .store = &store,
            .server_id = resolved.server.id,
            .scope = begin_options.scope,
            .owner_request_id = execution.id(),
            .subject = .{ .session = label },
        };
        // 活时钟,不是 `ctx.now`。`ctx.now` 是进程启动时间,用它计时的 TTL
        // 在 store 打开之前就开始走了 —— `cmd_session.zig` 的 `claimScope`
        // 记录了同一件事。
        const taken = Store.leases.acquire(&store, ctx.arena, .{
            .server_id = resolved.server.id,
            .scope = claim.scope,
            .owner_request_id = execution.id(),
            .profile_token = owner_token,
            .owner_label = label,
            .ttl_secs = Claim.ttl_secs,
            .now = Control.wallClockSeconds(ctx.io),
        }) catch |err| fatal("无法为 '{s}' 取得租约: {s}", .{ label, @errorName(err) });
        switch (taken) {
            .acquired, .renewed => {},
            .conflict => |peer| fatal(
                "'{s}' 的范围被 request {s} 持有;它结束后再来",
                .{ label, peer.owner_request_id },
            ),
        }
        lease_tick = .{
            .claim = claim,
            .io = ctx.io,
            .last_renewed_ms = nowMs(ctx.io),
        };
    }
    const tick: ?Pump.Tick = if (lease_tick) |*lt|
        .{ .context = lt, .call = LeaseTick.call }
    else
        null;

    // 本地终端的读取线程,**会话级**:一次 attach 可能用掉好几条通道(每断
    // 一次线换一条),但从头到尾只有一个终端。放在这里开、在函数出口关。
    var local = Pump.startLocal(ctx.io) catch |err| {
        _ = execution.abandon("the interactive session could not start its local input reader") catch {};
        Console.restoreActive();
        fatal("无法启动本地输入线程: {s}", .{@errorName(err)});
    };
    defer Pump.stopLocal(&local);

    var pty = client.openPty(remote_term, size.cols, size.rows, start) catch |err| fatal(
        "无法在 '{s}' 上打开伪终端: {s}",
        .{ target.server, @errorName(err) },
    );

    // --- 会话 -----------------------------------------------------------------
    //
    // **`shell` 不重连。** 裸登录 shell 的远端进程已经随连接死了,重连只会
    // 得到一个全新的 shell —— 把它当成原来那个是撒谎。所以这个循环对 `shell`
    // 恰好只转一圈。

    const ending: Ending = session: while (true) {
        const outcome = Pump.run(ctx.io, &local, &pty, tick) catch |err| {
            _ = execution.abandon("the interactive session's local pump failed") catch {};
            Console.abortHandled();
            Console.restoreActive();
            fatal("交互会话失败: {s}", .{@errorName(err)});
        };
        switch (outcome) {
            // 人按了 `Ctrl-]` 加一个命令键。
            .escape => |action| switch (action) {
                .detach => break :session .{ .local = .detached },
                .force_disconnect => break :session .{ .local = .force_disconnected },
                .help => switch (showHelp(ctx, &local, tick)) {
                    .resume_session => {
                        resumeSession(&local, &pty);
                        continue :session;
                    },
                    .aborted => break :session .{ .pump = .aborted },
                    .local_eof => break :session .{ .pump = .local_eof },
                    .lost => break :session .{ .pump = .lost },
                },
                .push, .pull => switch (runTransfer(
                    ctx,
                    &local,
                    tick,
                    resolved.server.name,
                    action,
                )) {
                    .resume_session => {
                        resumeSession(&local, &pty);
                        continue :session;
                    },
                    .aborted => break :session .{ .pump = .aborted },
                    .local_eof => break :session .{ .pump = .local_eof },
                    .lost => break :session .{ .pump = .lost },
                },
            },
            .transport_failed => {
                if (mode == .shell) break :session .{ .pump = outcome };

                // 传输没了。**这里不关通道** —— 等一个死连接的关闭确认就是
                // 干等到会话超时。整个连接就地释放,里面那条通道跟着一起走。
                client.deinit();
                client_live = false;

                switch (reconnect(
                    ctx,
                    resolved.server,
                    resolved.auth,
                    session_name.?,
                    start,
                    &local,
                    tick,
                    &client,
                    &client_live,
                )) {
                    .pty => |fresh| pty = fresh,
                    .over => |over| break :session .{ .outage = over },
                }
            },
            else => break :session .{ .pump = outcome },
        }
    };

    // --- 收尾 -----------------------------------------------------------------
    //
    // **收据先落盘,网络收尾在后。** 这个顺序是被真机打回来一次才写对的:
    // `pty.close()` 会调 `libssh2_channel_wait_closed` 等远端确认通道关闭,
    // 而关窗口时远端的 shell 还没退出,这一等就是几十秒(session 超时 30s)。
    // Ctrl 处理器只等三秒就放行让进程死 —— 于是收据永远写不成,那条操作行
    // 留在账本里挡住下一次 attach。
    //
    // 所以只有不赶时间的那几条路走「先关闭取退出码、再写收据」,而且它们
    // **必须排在中止分支之前** —— 那条门禁扫的就是中止分支之后的正文。

    // 断线停摆也算在会话时长里:从人打第一个字到他离开,中间那五分钟他
    // 确实在等着这个会话。(这一行原先在泵**之前**求值,于是每条收据的
    // 时长都是 0;重排之后顺带修好。)
    const duration = Core.control.wallClockSeconds(ctx.io) * std.time.ms_per_s - start_ms;

    switch (ending) {
        // **这一支排在最前面是有理由的。** 它里面有一次通道关闭,而下面那条
        // 门禁扫的是中止分支之后的正文 —— 不赶时间的关闭必须待在中止分支
        // 之前。
        //
        // 两种走法的区别就是要不要等远端确认,那正是 `.` 相对 `d` 的全部
        // 意思。
        .local => |how| switch (how) {
            .detached => {
                const status = pty.close();
                Console.restoreActive();
                _ = execution.settle(
                    .{ .exited = .{ .exit_code = status } },
                    .{ .connected = true, .duration_ms = duration },
                ) catch |err| Cli.receiptFatal(execution.id(), err, execution.status.text());
                switch (mode) {
                    .attach => try ctx.out.print(
                        "已 detach;会话 '{s}' 在远端继续运行\n",
                        .{session_name.?},
                    ),
                    .shell => try ctx.out.print("已断开(退出码 {d})\n", .{status}),
                }
                try ctx.out.flush();
            },
            .force_disconnected => {
                // 「强制」的全部意思就是不等,所以这里不做通道关闭:收据先
                // 落盘,然后放手让进程退出,操作系统会丢掉那个 socket。
                execution.abandon(
                    "the operator forced the connection down without waiting for the far end",
                ) catch |err| Cli.receiptFatal(execution.id(), err, execution.status.text());
                Console.restoreActive();
                switch (mode) {
                    .attach => try ctx.out.print(
                        "已强制断开;会话 '{s}' 仍在远端运行\n",
                        .{session_name.?},
                    ),
                    .shell => try ctx.out.print("已强制断开;远端登录 shell 的下场不可知\n", .{}),
                }
                try ctx.out.flush();
            },
        },
        .pump => |outcome| switch (outcome) {
            // `.escape` 到不了这里:会话循环把每一个都消化掉了。把它并进这
            // 一支而不是写 `unreachable` —— 一条不会说谎的收尾路径,好过一
            // 句关于控制流的断言。
            .remote_exit, .local_eof, .escape => {
                const status = pty.close();
                // 还原在写收据之前:下面的句子要能被读到。`restoreActive` 是
                // 幂等的,所以上面的 defer 再跑一次无害。
                Console.restoreActive();
                _ = execution.settle(
                    .{ .exited = .{ .exit_code = status } },
                    .{ .connected = true, .duration_ms = duration },
                ) catch |err| Cli.receiptFatal(execution.id(), err, execution.status.text());
                switch (outcome) {
                    .remote_exit => try ctx.out.print("会话结束(退出码 {d})\n", .{status}),
                    else => try ctx.out.print("本地输入结束,会话已关闭\n", .{}),
                }
                // **就地刷。** `Output.print` 只写进缓冲,而缓冲要到 `main`
                // 的最后才刷 —— 也就是排在连接与数据库的收尾之后。那几步
                // 慢一秒,这句话就晚一秒,而它正是用户在等的那一句。
                try ctx.out.flush();
            },
            .lost => {
                // 租约被别人接管了。这是我们**主动**收的尾,所以通道照关、
                // 退出码照取 —— 关掉通道对远端就是一次干净的 detach,tmux
                // 会话本身不受影响。
                const status = pty.close();
                Console.restoreActive();
                _ = execution.settle(
                    .{ .exited = .{ .exit_code = status } },
                    .{ .connected = true, .duration_ms = duration },
                ) catch |err| Cli.receiptFatal(execution.id(), err, execution.status.text());
                fatal(
                    "这个会话的租约已被别人接管,已自动 detach —— 两个人同时以为自己持有它是这道屏障要防的事",
                    .{},
                );
            },
            .aborted => {
                // 人关掉了窗口。远端没被通知过,所以这一侧不知道它现在怎么样 ——
                // `abandon` 会从当前状态挑出诚实的那个终态(`submitted` 之后是
                // `indeterminate`,因为 `local_abandon` 只从 `created`/`connecting`
                // 可达)。
                //
                // 这一步存在的全部理由:不结清的话,这条操作行会一直挡着,而
                // 下一次 attach 会撞上"被 request X 挡住"。对交互会话来说关
                // 窗口是人**正常**的离开方式,不是异常,所以让它需要人工对账
                // 是不可接受的。
                execution.abandon(
                    "the operator closed the terminal window; nothing watched the session to completion",
                ) catch |err| Cli.receiptFatal(execution.id(), err, execution.status.text());
                // 收据落盘了,放 Ctrl 处理器走 —— 它正在等这一声。
                //
                // **这里不做通道关闭。** 进程马上就要被结束,而关闭要等远端
                // 确认;在处理器的三秒钟里做这件事只有坏处。放手让进程退出,
                // 操作系统会丢掉那个 socket,远端自然读到 EOF。
                //
                // (下面那条门禁扫这一段,所以这里不能拼出那个函数名。)
                Console.abortHandled();
                Console.restoreActive();
                return;
            },
            .transport_failed => {
                // 只有 `shell` 到得了这里:`attach` 的断线全被上面的循环接走了。
                //
                // 远端的下场不可知 —— `local_abandon` 在 `submitted` 之后不可
                // 采纳(`op_state.canSettle`),而那恰好也是语义上对的:我们只
                // 知道自己不再看着它了。
                _ = execution.transportLoss(
                    "交互登录 shell 的连接中断,远端进程的下场不可知",
                ) catch |err|
                    Cli.receiptFatal(execution.id(), err, execution.status.text());
                Console.abortHandled();
                Console.restoreActive();
                fatal("连接中断;裸登录 shell 不持久,远端进程已经结束", .{});
            },
        },
        // 停摆期间结束的。**这一整段都没有通道可关** —— 连接在决定重连时
        // 就释放了,这正是 `Ending` 分两支的理由。
        .outage => |over| {
            const name = session_name.?;
            switch (over) {
                .aborted => {
                    execution.abandon(
                        "the operator closed the terminal window while the session was reconnecting",
                    ) catch |err| Cli.receiptFatal(execution.id(), err, execution.status.text());
                    Console.abortHandled();
                    Console.restoreActive();
                    return;
                },
                .vanished => {
                    execution.abandon(
                        "the tmux session was gone when the connection came back",
                    ) catch |err| Cli.receiptFatal(execution.id(), err, execution.status.text());
                    Console.restoreActive();
                    // **不静默新建。** 一个以为自己回到工作现场的人对着空
                    // shell,比一句拒绝糟得多。
                    fatal(
                        "重连上了,但会话 '{s}' 在断线期间消失了。没有替你新建 —— " ++
                            "要新开一个:terminus session new {s} {s}",
                        .{ name, target.server, name },
                    );
                },
                .tmux_missing => {
                    execution.abandon(
                        "tmux was gone from the host when the connection came back",
                    ) catch |err| Cli.receiptFatal(execution.id(), err, execution.status.text());
                    Console.restoreActive();
                    fatal("重连上了,但 '{s}' 上已经没有 tmux 了", .{target.server});
                },
                .lost => {
                    execution.abandon(
                        "another owner took the scope lease while the session was reconnecting",
                    ) catch |err| Cli.receiptFatal(execution.id(), err, execution.status.text());
                    Console.restoreActive();
                    fatal("断线期间 '{s}' 的租约被别人接管了,已停止重连", .{name});
                },
                .exhausted, .abandoned, .local_eof => {
                    const why = switch (over) {
                        .exhausted => "五分钟内没能重连上交互会话,远端 tmux 会话可能仍在运行",
                        .abandoned => "操作者放弃了重连,远端 tmux 会话可能仍在运行",
                        else => "断线期间本地输入结束,远端 tmux 会话可能仍在运行",
                    };
                    _ = execution.transportLoss(why) catch |err|
                        Cli.receiptFatal(execution.id(), err, execution.status.text());
                    Console.restoreActive();
                    const head = switch (over) {
                        .exhausted => "五分钟内没能重连上",
                        .abandoned => "已放弃重连",
                        else => "断线期间本地输入结束",
                    };
                    fatal(
                        "{s};会话 '{s}' 仍可能在远端运行,网络恢复后可再次 attach",
                        .{ head, name },
                    );
                },
            }
        },
    }
}
