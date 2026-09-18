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
    // `-t <name>` 是前缀匹配,`web` 会接上 `web-old`;`-t =<name>` 才是
    // 精确匹配。丢掉那个等号的后果是接错会话,而且看起来完全正常。
    const source = @embedFile("cmd_attach.zig");
    try std.testing.expect(std.mem.indexOf(u8, source, "tmux attach -t =") != null);
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
