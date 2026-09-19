//! 重连策略,纯函数。
//!
//! 抽出来的理由和 `modes.zig` 一样:真正的重连要一根断掉的网线才试得出来,
//! 而"退避多久、什么时候放弃"是这里面唯一会算错的部分,把它变成纯函数就
//! 全部拿进了测试。
//!
//! **只有 `attach` 用这个。** 裸登录 shell 的远端进程已经随连接死了,重连
//! 只会得到一个全新的 shell;把它当成原来那个是撒谎。

const std = @import("std");

/// 从第一次断开算起,总共愿意花多久。
///
/// 五分钟是"泡杯咖啡回来还在"和"这条链路已经没救了"之间的分界。超过之后
/// 继续等的代价不是等待本身,而是一个以为自己还连着的人。
pub const budget_ms: i64 = 5 * 60 * std.time.ms_per_s;

/// 退避到此为止,之后恒定。
const max_delay_ms: i64 = 15 * std.time.ms_per_s;

pub const Decision = union(enum) {
    /// 等这么久,然后再试一次。
    retry: i64,
    /// 预算用尽。
    give_up,
};

/// 第 `attempt` 次重连该等多久。**`attempt` 从 1 开始** —— 横幅上写的
/// "第 N 次"就是这个 N,让它和人看到的数字是同一个。
///
/// 1s、2s、4s、8s,然后恒定 15s。指数段短,因为绝大多数断线是几秒钟的事;
/// 恒定段长,因为到了第五次就说明这不是抖动,再翻倍只会让恢复被自己的退避
/// 拖住。
pub fn delayFor(attempt: u32) i64 {
    std.debug.assert(attempt >= 1);
    if (attempt >= 5) return max_delay_ms;
    return @as(i64, std.time.ms_per_s) << @intCast(attempt - 1);
}

/// `elapsed_ms` 是从第一次断开到现在,不是这一轮的等待。
pub fn decide(attempt: u32, elapsed_ms: i64) Decision {
    if (elapsed_ms >= budget_ms) return .give_up;
    return .{ .retry = delayFor(attempt) };
}

test "退避序列是 1、2、4、8,然后恒定 15" {
    const t = std.testing;
    try t.expectEqual(@as(i64, 1000), delayFor(1));
    try t.expectEqual(@as(i64, 2000), delayFor(2));
    try t.expectEqual(@as(i64, 4000), delayFor(3));
    try t.expectEqual(@as(i64, 8000), delayFor(4));
    try t.expectEqual(@as(i64, 15000), delayFor(5));
    try t.expectEqual(@as(i64, 15000), delayFor(6));
    try t.expectEqual(@as(i64, 15000), delayFor(99));
}

test "恒定段不会再翻倍" {
    // 退化成指数的话第 20 次就是 500 多秒,比整个预算还长 —— 那等于
    // 预算被退避本身吃掉,而不是被重试吃掉。
    const t = std.testing;
    var attempt: u32 = 5;
    while (attempt < 40) : (attempt += 1)
        try t.expectEqual(@as(i64, 15000), delayFor(attempt));
}

test "预算用尽就放弃,不管才试到第几次" {
    const t = std.testing;
    try t.expectEqual(Decision.give_up, decide(1, budget_ms));
    try t.expectEqual(Decision.give_up, decide(1, budget_ms + 1));
    try t.expectEqual(Decision.give_up, decide(99, budget_ms));
}

test "预算之内照常退避" {
    const t = std.testing;
    try t.expectEqual(Decision{ .retry = 1000 }, decide(1, 0));
    try t.expectEqual(Decision{ .retry = 15000 }, decide(7, budget_ms - 1));
}

test "预算是五分钟,而退避永远够不到它" {
    // 这两条一起才有意义:恒定段 15s 意味着预算内至少还能试二十次,
    // 所以"放弃"永远是预算说了算,不是退避序列说了算。
    const t = std.testing;
    try t.expectEqual(@as(i64, 300_000), budget_ms);
    try t.expect(max_delay_ms * 20 <= budget_ms);
}
