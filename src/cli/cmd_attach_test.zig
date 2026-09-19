//! `cmd_attach.zig` 的源码契约。
//!
//! 这些断言的对象是**这个文件说了什么**,不是它做了什么 —— 因为它做的事
//! 需要一个真控制台和一条真连接,而那正是自动化测试到不了的地方。所以这里
//! 守的是三条一旦被"顺手统一"就会静默失效的性质。

const std = @import("std");

test "interactive verbs never take the daemon transport" {
    // spec 决策一:daemon 协议是长度前缀 JSON 帧,载不动裸字节流。
    // 这是源码层面的契约,和 cmd_tunnel.zig 的同名门禁同理 —— 一次
    // "顺手统一成 Cli.connect" 的重构会让会话在协议上无声地不可能。
    const source = @embedFile("cmd_attach.zig");
    const daemon_call = "Cli." ++ "connect(ctx";
    try std.testing.expect(std.mem.indexOf(u8, source, daemon_call) == null);
}

test "the console is restored on the way out" {
    // 还原必须在源码里出现至少三次:defer 一次,正常收尾一次,泵失败那条
    // 路径一次。只有 defer 的话,fail 路径全靠 refusalCleanup,而那条链
    // 断了没有任何测试会红。
    const source = @embedFile("cmd_attach.zig");
    const restore = "restore" ++ "Active()";
    try std.testing.expect(std.mem.count(u8, source, restore) >= 3);
}

test "attach matches the tmux session exactly" {
    // 两层都要:`=` 是 tmux 的精确匹配(没有它 `web` 会接上 `web-old`),
    // 引号是给 zsh 的(它默认把词首的 `=word` 展开成命令路径,于是
    // `-t =t-x` 变成 "t-x not found")。丢掉任何一层都会在真机上炸。
    const source = @embedFile("cmd_attach.zig");
    try std.testing.expect(std.mem.indexOf(u8, source, "tmux attach -t " ++ "'={s}'") != null);
}

test "nothing is drawn to the terminal after it enters raw mode and before it leaves" {
    // 进入 raw 模式之后,`ctx.out` 写出去的句子不会换行也不会回车 ——
    // 一条在那期间打印的诊断是一条用户读不到的诊断。所以这个文件里所有
    // 的 `ctx.out.print` 都必须排在 `Console.enter()` 之前,或者排在
    // `restoreActive()` 之后。
    //
    // 机械检查:第一个 `Console.enter()` 与其后第一个 `restoreActive()`
    // 之间不得出现 `ctx.out.print`。
    const source = @embedFile("cmd_attach.zig");
    const enter_at = std.mem.indexOf(u8, source, "Console.enter()").?;
    const restore = "restore" ++ "Active()";
    const restore_at = std.mem.indexOfPos(u8, source, enter_at, restore).?;
    const window = source[enter_at..restore_at];
    try std.testing.expect(std.mem.indexOf(u8, window, "ctx.out.print") == null);
}

test "the receipt is written before any network teardown on the paths that are racing a dying process" {
    // 被真机打回来一次才写对的顺序,所以钉住它。
    //
    // `pty.close()` 会等远端确认通道关闭。关窗口时远端的 shell 还没退出,
    // 那一等就是几十秒;而 Ctrl 处理器只等三秒就放行让进程死。收据排在
    // 它后面就永远写不成,于是一条以整台服务器为范围的操作行留在账本里,
    // 挡住下一次 attach —— 真的发生了两次。
    //
    // 正常收尾那条路不在此列:它要关闭的返回值当退出码,而且不赶时间。
    //
    // **被检查的名字不许出现在被扫描区域的散文里。** 第一版把两条分支注释
    // 里写出的那个名字读成了违规——这棵树里扫描器自证有罪的第七次。
    const source = @embedFile("cmd_attach.zig");
    const abort_at = std.mem.indexOf(u8, source, ".aborted => {").?;
    const tail = source[abort_at..];
    const settle_at = std.mem.indexOf(u8, tail, "execution.abandon(").?;
    // 中止分支之后不得再有通道关闭 —— 现在一次都没有。
    try std.testing.expect(std.mem.indexOf(u8, tail, "pty.close()") == null);
    // 而收据确实在这条分支里写。
    try std.testing.expect(settle_at < tail.len);
}
