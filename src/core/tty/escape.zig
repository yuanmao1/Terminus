//! 转义键的状态机与菜单的行编辑器,都是纯函数。
//!
//! 抽出来的理由和 `modes.zig`、`reconnect.zig` 一样:真正的交互要一个真
//! 控制台才试得出来,而"哪个字节该送去远端"是这里唯一会算错的东西 ——
//! 把它变成纯函数就全部拿进了测试。
//!
//! **状态机只有两个状态,不是设计里写的三个。** 设计把 `menu` 也算成一个
//! 状态,但那会让这个模块必须自己拿着行缓冲和输出环,它就不再是一个
//! `字节 → 步骤` 的函数了。菜单是调用方的模态子循环,那期间根本不往这里
//! 喂字节 —— 所以"菜单态不转发"是构造上成立的,不需要一条状态转移去保证。

const std = @import("std");

/// `Ctrl-]`。
///
/// telnet 的既有约定,而且 `bash`、`vim`、`tmux`、`htop`、`emacs` 默认都不
/// 绑定它。单字节,所以状态机只需要两个状态。
pub const escape_byte: u8 = 0x1D;

pub const Action = enum {
    /// 断开,但会话在远端继续。
    detach,
    /// 不等远端确认,直接走。
    force_disconnect,
    /// 键位表。
    help,
    /// 推文件到远端。
    push,
    /// 从远端拉文件。
    pull,
};

pub const Step = union(enum) {
    /// 这个字节照送远端。
    forward: u8,
    /// 吞掉。转义键本身就是这样。
    swallow,
    /// 本地响铃,**两个字节都不送**。
    bell,
    /// 执行一个本地动作。
    action: Action,
};

pub const Machine = struct {
    /// 上一个字节是转义键。
    armed: bool = false,

    pub fn feed(m: *Machine, byte: u8) Step {
        if (!m.armed) {
            if (byte == escape_byte) {
                m.armed = true;
                return .swallow;
            }
            return .{ .forward = byte };
        }
        m.armed = false;
        return switch (byte) {
            // 连按两下送一个字面的它。远端真要收这个字节时的唯一办法。
            escape_byte => .{ .forward = escape_byte },
            'd' => .{ .action = .detach },
            '.' => .{ .action = .force_disconnect },
            '?' => .{ .action = .help },
            'p' => .{ .action = .push },
            'g' => .{ .action = .pull },
            // **两个字节都不转发,这是明确的决定。** `ssh` 在无效命令时会把
            // 两个字符都发出去,我们不:不转发是可预测的,而转发会让一次误
            // 触变成远端收到两个随机字节 —— 那两个字节可能正落在一个等待
            // 确认的提示符上。
            else => .bell,
        };
    }
};

/// 菜单里那一行的编辑器。
///
/// **只有回显、退格、提交、取消。** 不做历史、补全、光标移动 —— 这一行的
/// 全部用途是打两个路径,而每加一个编辑功能就要多一套转义序列解析。
pub const LineEdit = struct {
    buf: [max_len]u8 = undefined,
    len: usize = 0,

    /// 两个路径加一个空格。超过这个长度的命令行不该从这里输入。
    pub const max_len = 512;

    pub const Edit = enum {
        /// 把这个字节回显出去。
        echo,
        /// 退一格(调用方写 `\x08 \x08`)。
        erase,
        /// 这一行完成了,拿 `text()`。
        submit,
        /// 放弃。
        cancel,
        /// 不认识,或者满了。
        bell,
    };

    pub fn feed(self: *LineEdit, byte: u8) Edit {
        return switch (byte) {
            // 回车和换行都算提交:raw 模式下 Enter 给的是 0x0D,但管道里
            // 是 0x0A,两个都认没有坏处。
            '\r', '\n' => .submit,
            0x1B => .cancel,
            // 两个退格码都要认:控制台给 0x08,多数终端给 0x7F。
            0x08, 0x7F => {
                if (self.len == 0) return .bell;
                self.len -= 1;
                return .erase;
            },
            else => {
                // 其余控制字符一律拒绝。让它们进这一行只会得到一个看不见
                // 的字符和一个"路径不存在"。
                if (byte < 0x20) return .bell;
                if (self.len == self.buf.len) return .bell;
                self.buf[self.len] = byte;
                self.len += 1;
                return .echo;
            },
        };
    }

    pub fn text(self: *const LineEdit) []const u8 {
        return self.buf[0..self.len];
    }

    pub fn reset(self: *LineEdit) void {
        self.len = 0;
    }
};

/// 把 `<本地路径> <远端路径>` 拆成两半。
///
/// 恰好两个词才算数。**不支持带空格的路径** —— 支持它就要一套引号规则,
/// 而这一行没有 shell 替我们做那件事;一个悄悄猜错引号的提示行比一句
/// "要两个路径"糟得多。
pub const Paths = struct {
    first: []const u8,
    second: []const u8,
};

pub fn splitPaths(line: []const u8) ?Paths {
    const trimmed = std.mem.trim(u8, line, " \t");
    var it = std.mem.tokenizeAny(u8, trimmed, " \t");
    const first = it.next() orelse return null;
    const second = it.next() orelse return null;
    if (it.next() != null) return null;
    return .{ .first = first, .second = second };
}

// --- 状态机 -------------------------------------------------------------------

test "普通字节原样转发,任何一个都不例外" {
    var m: Machine = .{};
    var byte: u16 = 0;
    while (byte <= 0xFF) : (byte += 1) {
        const b: u8 = @intCast(byte);
        if (b == escape_byte) continue;
        try std.testing.expectEqual(Step{ .forward = b }, m.feed(b));
        // 一个普通字节不该让状态机进入待命。
        try std.testing.expect(!m.armed);
    }
}

test "转义键本身不转发" {
    var m: Machine = .{};
    try std.testing.expectEqual(Step.swallow, m.feed(escape_byte));
    try std.testing.expect(m.armed);
}

test "连按两下送一个字面的转义键" {
    // 远端真要收到 0x1D 时的唯一办法,所以它必须存在,而且只能送一个。
    var m: Machine = .{};
    try std.testing.expectEqual(Step.swallow, m.feed(escape_byte));
    try std.testing.expectEqual(Step{ .forward = escape_byte }, m.feed(escape_byte));
    try std.testing.expect(!m.armed);
    // 第三下重新开始待命,不是第二个字面量。
    try std.testing.expectEqual(Step.swallow, m.feed(escape_byte));
}

test "每个命令键都映射到它的动作" {
    const cases = [_]struct { key: u8, action: Action }{
        .{ .key = 'd', .action = .detach },
        .{ .key = '.', .action = .force_disconnect },
        .{ .key = '?', .action = .help },
        .{ .key = 'p', .action = .push },
        .{ .key = 'g', .action = .pull },
    };
    for (cases) |c| {
        var m: Machine = .{};
        _ = m.feed(escape_byte);
        try std.testing.expectEqual(Step{ .action = c.action }, m.feed(c.key));
        try std.testing.expect(!m.armed);
    }
}

test "未知命令响铃,而且两个字节一个都不转发" {
    // `ssh` 在这里会把两个字符都发出去。我们不 —— 一次误触不该在远端
    // 那个正在等确认的提示符上留下两个随机字节。
    var m: Machine = .{};
    try std.testing.expectEqual(Step.swallow, m.feed(escape_byte));
    try std.testing.expectEqual(Step.bell, m.feed('x'));
    try std.testing.expect(!m.armed);
    // 下一个字节回到正常转发,不是被吞掉。
    try std.testing.expectEqual(Step{ .forward = 'y' }, m.feed('y'));
}

test "待命状态跨字节保持,而不是只在一次调用里" {
    // 输入是一个字节一个字节从队列里来的,转义键和命令键几乎不可能落在
    // 同一次读里。状态机记不住的话这个功能一次也不会触发。
    var m: Machine = .{};
    try std.testing.expectEqual(Step{ .forward = 'a' }, m.feed('a'));
    _ = m.feed(escape_byte);
    try std.testing.expect(m.armed);
    try std.testing.expectEqual(Step{ .action = .detach }, m.feed('d'));
}

test "大写的命令键不算命令" {
    // Shift 按住了不该变成另一个动作,也不该静默地什么都不做。
    var m: Machine = .{};
    _ = m.feed(escape_byte);
    try std.testing.expectEqual(Step.bell, m.feed('D'));
}

// --- 行编辑 -------------------------------------------------------------------

test "打字、退格、提交" {
    var e: LineEdit = .{};
    for ("abc") |b| try std.testing.expectEqual(LineEdit.Edit.echo, e.feed(b));
    try std.testing.expectEqualStrings("abc", e.text());
    try std.testing.expectEqual(LineEdit.Edit.erase, e.feed(0x08));
    try std.testing.expectEqualStrings("ab", e.text());
    try std.testing.expectEqual(LineEdit.Edit.erase, e.feed(0x7F));
    try std.testing.expectEqualStrings("a", e.text());
    try std.testing.expectEqual(LineEdit.Edit.submit, e.feed('\r'));
    try std.testing.expectEqualStrings("a", e.text());
}

test "空行上退格是响铃,不是下溢" {
    var e: LineEdit = .{};
    try std.testing.expectEqual(LineEdit.Edit.bell, e.feed(0x08));
    try std.testing.expectEqual(@as(usize, 0), e.text().len);
}

test "ESC 取消" {
    var e: LineEdit = .{};
    for ("/tmp/x") |b| _ = e.feed(b);
    try std.testing.expectEqual(LineEdit.Edit.cancel, e.feed(0x1B));
}

test "控制字符不进这一行" {
    // 进去了就是一个看不见的字符和一句"路径不存在"。
    var e: LineEdit = .{};
    try std.testing.expectEqual(LineEdit.Edit.bell, e.feed(0x01));
    try std.testing.expectEqual(LineEdit.Edit.bell, e.feed(0x09));
    try std.testing.expectEqual(@as(usize, 0), e.text().len);
}

test "满了就响铃,不是覆盖也不是溢出" {
    var e: LineEdit = .{};
    var i: usize = 0;
    while (i < LineEdit.max_len) : (i += 1)
        try std.testing.expectEqual(LineEdit.Edit.echo, e.feed('x'));
    try std.testing.expectEqual(LineEdit.Edit.bell, e.feed('x'));
    try std.testing.expectEqual(LineEdit.max_len, e.text().len);
}

test "UTF-8 能打进去" {
    // 中文路径不是边缘情况。多字节序列的每个字节都 >= 0x80,照单收下。
    var e: LineEdit = .{};
    for ("/tmp/文件") |b| try std.testing.expectEqual(LineEdit.Edit.echo, e.feed(b));
    try std.testing.expectEqualStrings("/tmp/文件", e.text());
}

// --- 路径拆分 -----------------------------------------------------------------

test "恰好两个词才算数" {
    const t = std.testing;
    const ok = splitPaths("a.txt /tmp/a.txt").?;
    try t.expectEqualStrings("a.txt", ok.first);
    try t.expectEqualStrings("/tmp/a.txt", ok.second);
    try t.expect(splitPaths("") == null);
    try t.expect(splitPaths("   ") == null);
    try t.expect(splitPaths("only-one") == null);
    try t.expect(splitPaths("a b c") == null);
}

test "多余的空白不算第三个词" {
    const got = splitPaths("  a.txt    /tmp/a.txt  ").?;
    try std.testing.expectEqualStrings("a.txt", got.first);
    try std.testing.expectEqualStrings("/tmp/a.txt", got.second);
}
