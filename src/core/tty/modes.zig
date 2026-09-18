//! 本地 Windows 控制台模式的纯计算。
//!
//! 单独成模块,因为它是这个功能里唯一能被完整测试的部分:真正的
//! `SetConsoleMode` 需要一个真控制台,而控制台的行为无法在 CI 里断言。
//! 把决定压进纯函数,剩给 Win32 层的就只有"照着做"。
//!
//! 常量在这里自己声明:Zig 0.16 的 `std.os.windows` 一个控制台模式位都
//! 没有提供。数值取自 Win32 的 `wincon.h`。

const std = @import("std");

/// `SetConsoleMode` 对**输入**句柄的位。
pub const input = struct {
    /// 清除它,Ctrl-C 才会作为字节 0x03 进入输入流而不是变成本地信号。
    pub const processed: u32 = 0x0001;
    pub const line: u32 = 0x0002;
    pub const echo: u32 = 0x0004;
    pub const window: u32 = 0x0008;
    pub const virtual_terminal: u32 = 0x0200;
};

/// `SetConsoleMode` 对**输出**句柄的位。
pub const output = struct {
    pub const processed: u32 = 0x0001;
    pub const wrap_at_eol: u32 = 0x0002;
    pub const virtual_terminal: u32 = 0x0004;
    pub const no_auto_return: u32 = 0x0008;
};

pub const Pair = struct {
    in: u32,
    out: u32,
};

/// 给定控制台当前的模式,算出交互会话需要的模式。
///
/// 只增删指名的位,其余原样保留 —— 终端模拟器可能设置了我们不认识的位,
/// 把它们抹掉等于替用户改配置。
pub fn desired(saved: Pair) Pair {
    return .{
        .in = (saved.in & ~(input.processed | input.line | input.echo)) |
            input.virtual_terminal,
        .out = saved.out | output.processed | output.virtual_terminal |
            output.no_auto_return,
    };
}

test "raw input clears the three bits that make the console interpret keys" {
    const t = std.testing;
    const got = desired(.{ .in = input.processed | input.line | input.echo, .out = 0 });
    try t.expectEqual(@as(u32, 0), got.in & input.processed);
    try t.expectEqual(@as(u32, 0), got.in & input.line);
    try t.expectEqual(@as(u32, 0), got.in & input.echo);
}

test "clearing ENABLE_PROCESSED_INPUT is the whole mechanism for Ctrl-C reaching the remote" {
    // 单独一条,因为它是整个功能里最容易被"顺手简化掉"的一位:
    // 留着它,Ctrl-C 在本地触发 CTRL_C_EVENT 杀死 terminus;
    // 清掉它,Ctrl-C 以字节 0x03 进入输入流送往远端。
    const t = std.testing;
    const got = desired(.{ .in = 0xFFFF_FFFF, .out = 0 });
    try t.expectEqual(@as(u32, 0), got.in & input.processed);
}

test "virtual terminal input is requested and window input is not" {
    const t = std.testing;
    const got = desired(.{ .in = 0, .out = 0 });
    try t.expect(got.in & input.virtual_terminal != 0);
    // 输入线程用阻塞 ReadFile 读字节流,窗口事件记录会被丢弃而不是投递。
    // 设了也读不到,尺寸改用轮询。
    try t.expectEqual(@as(u32, 0), got.in & input.window);
}

test "output gains VT processing and keeps processed output" {
    const t = std.testing;
    const got = desired(.{ .in = 0, .out = output.processed });
    try t.expect(got.out & output.virtual_terminal != 0);
    try t.expect(got.out & output.no_auto_return != 0);
    try t.expect(got.out & output.processed != 0);
}

test "bits the console already had that we do not name are preserved" {
    const t = std.testing;
    const unrelated: u32 = 0x4000;
    const got = desired(.{ .in = unrelated, .out = unrelated });
    try t.expect(got.in & unrelated != 0);
    try t.expect(got.out & unrelated != 0);
}

test "desired is idempotent" {
    // 还原路径会重叠,进入路径也可能被重试;不幂等的话第二次调用会得到
    // 和第一次不同的模式,而那个差异只会在真终端上显形。
    const t = std.testing;
    const once = desired(.{ .in = 0x01FF, .out = 0x000F });
    const twice = desired(once);
    try t.expectEqual(once.in, twice.in);
    try t.expectEqual(once.out, twice.out);
}
