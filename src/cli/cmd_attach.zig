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

const Control = @import("../core/control.zig");
const Claim = Control.Claim;
const Authority = Control.Authority;
const stillOurs = Control.stillOurs;

const fatal = Cli.fail;

pub const Mode = enum { shell, attach };

pub const shell_usage = "usage: terminus shell <server>\n" ++
    "\n打开远端登录 shell。本地终端进入 raw 模式,退出后自动还原。\n" ++
    "裸登录 shell 不持久:连接断开时远端进程随之结束。\n";

pub const attach_usage = "usage: terminus attach <server>[:<session>]\n" ++
    "\n接入远端 tmux 会话。detach 后会话在远端继续存活,agent 可用\n" ++
    "'terminus read' 读到这期间的输出。不给会话名时列出现有会话。\n" ++
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
    defer client.deinit();

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
            // `-t =<name>` 是精确匹配;不加 `=` 时 tmux 做前缀匹配,
            // `web` 会接上 `web-old`。
            break :blk .{ .command = try std.fmt.allocPrint(
                ctx.arena,
                "tmux attach -t ={s}",
                .{tname},
            ) };
        },
    };

    const start_ms = Core.control.wallClockSeconds(ctx.io) * std.time.ms_per_s;
    const begun = Core.execution.begin(&store, ctx.arena, ctx.io, .{
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
    }) catch |err| Cli.storeFatal(&store, err);
    var execution = switch (begun) {
        .ready => |ready| ready,
        .blocked => |blocker| fatal(
            "交互会话被 request {s} 挡住;先把它对账掉",
            .{switch (blocker) {
                .unsettled => |op| op.request_id,
                .lease => |lease| lease.owner_request_id,
            }},
        ),
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

    switch (execution.submitted() catch |err|
        Cli.receiptFatal(execution.id(), err, "connecting")) {
        .submitted => {},
        .refused => fatal("交互会话在提交时被拒绝;对账 request {s}", .{execution.id()}),
    }

    // 租约,在会话真正开始之前取得。`attach` 持它的效果是:人在里面时
    // `session rm` 与 `job kill` 会被拒绝。`--no-lease` 退出这个行为。
    var lease_tick: ?LeaseTick = null;
    if (mode == .attach and !parsed.boolean("no-lease")) {
        const name = session_name.?;
        const claim: Claim = .{
            .store = &store,
            .server_id = resolved.server.id,
            .scope = contentionScope(name),
            .owner_request_id = execution.id(),
            .subject = .{ .session = name },
        };
        // 活时钟,不是 `ctx.now`。`ctx.now` 是进程启动时间,用它计时的 TTL
        // 在 store 打开之前就开始走了 —— `cmd_session.zig` 的 `claimScope`
        // 记录了同一件事。
        const taken = Store.leases.acquire(&store, ctx.arena, .{
            .server_id = resolved.server.id,
            .scope = claim.scope,
            .owner_request_id = execution.id(),
            .profile_token = owner_token,
            .owner_label = name,
            .ttl_secs = Claim.ttl_secs,
            .now = Control.wallClockSeconds(ctx.io),
        }) catch |err| fatal("无法为会话 '{s}' 取得租约: {s}", .{ name, @errorName(err) });
        switch (taken) {
            .acquired, .renewed => {},
            .conflict => |peer| fatal(
                "会话 '{s}' 的范围被 request {s} 持有;它结束后再 attach",
                .{ name, peer.owner_request_id },
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

    var pty = client.openPty(remote_term, size.cols, size.rows, start) catch |err| fatal(
        "无法在 '{s}' 上打开伪终端: {s}",
        .{ target.server, @errorName(err) },
    );

    const outcome = Pump.run(ctx.io, &pty, tick) catch |err| {
        _ = pty.close();
        Console.restoreActive();
        fatal("交互会话失败: {s}", .{@errorName(err)});
    };
    const status = pty.close();
    // 还原**在写收据之前**:下面的句子要能被读到。`restoreActive` 是幂等的,
    // 所以上面的 defer 再跑一次无害。
    Console.restoreActive();

    const duration = Core.control.wallClockSeconds(ctx.io) * std.time.ms_per_s - start_ms;
    switch (outcome) {
        .remote_exit, .local_eof => {
            _ = execution.settle(
                .{ .exited = .{ .exit_code = status } },
                .{ .connected = true, .duration_ms = duration },
            ) catch |err| Cli.receiptFatal(execution.id(), err, execution.status.text());
            switch (outcome) {
                .remote_exit => try ctx.out.print("会话结束(退出码 {d})\n", .{status}),
                else => try ctx.out.print("本地输入结束,会话已关闭\n", .{}),
            }
        },
        .aborted => {
            // 人关掉了窗口。远端没被通知过,所以这一侧不知道它现在怎么样 ——
            // `abandon` 会从当前状态挑出诚实的那个终态(`submitted` 之后是
            // `indeterminate`,因为 `local_abandon` 只从 `created`/`connecting`
            // 可达)。
            //
            // 这一步存在的全部理由:不结清的话,这条操作行会以整台服务器为
            // 范围一直挡着,而下一次 attach 会撞上"被 request X 挡住"。对
            // 交互会话来说关窗口是人**正常**的离开方式,不是异常,所以让它
            // 需要人工对账是不可接受的。
            execution.abandon(
                "the operator closed the terminal window; nothing watched the session to completion",
            ) catch |err| Cli.receiptFatal(execution.id(), err, execution.status.text());
            // 收据落盘了,放 Ctrl 处理器走 —— 它正在等这一声,等满三秒就
            // 自己还原终端并让进程结束。
            Console.abortHandled();
            return;
        },
        .transport_failed => {
            // 连接没了,远端的下场不可知 —— `local_abandon` 在 `submitted`
            // 之后不可采纳(`op_state.canSettle`),而那恰好也是语义上对的:
            // 我们只知道自己不再看着它了。
            const why = switch (mode) {
                .shell => "交互登录 shell 的连接中断,远端进程的下场不可知",
                .attach => "交互会话的连接中断,远端 tmux 会话可能仍在运行",
            };
            _ = execution.transportLoss(why) catch |err|
                Cli.receiptFatal(execution.id(), err, execution.status.text());
            switch (mode) {
                .shell => fatal("连接中断;裸登录 shell 不持久,远端进程已经结束", .{}),
                .attach => fatal(
                    "连接中断;会话 '{s}' 仍在远端运行,重连后可再次 attach",
                    .{session_name.?},
                ),
            }
        },
    }
}
