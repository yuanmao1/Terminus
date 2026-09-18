# 交互式终端 attach / shell 实现计划(M1 + M2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让 `terminus shell <server>` 打开远端 PTY 登录 shell,`terminus attach <server>[:<session>]` 接入远端 tmux 会话,两者都在本地 Windows 控制台的 raw 模式下运行并保证退出后终端完好。

**Architecture:** 三层。纯函数层(`modes.zig`)算出目标控制台模式,可完全单测;Win32 层(`Console.zig`)是仅有的几个系统调用,并通过进程级全局 + `SetConsoleCtrlHandler` 保证还原;泵层(`Pump.zig`)把本地输入队列、libssh2 PTY 通道和尺寸轮询装配成一个非阻塞循环。PTY 通道是 `Client.zig` 的新增能力,复用该文件既有的 `InputQueue`(本计划将其抽成独立模块)。

**Tech Stack:** Zig 0.16.0、libssh2(已 vendored)、Win32 console API(Zig std 不提供绑定,自行 `extern`)、既有的 execution ledger / scope lease。

---

## 范围

本计划覆盖 spec 的 **M1 与 M2**,交付两个可用动词。

以下**不在本计划内**,各自另立计划:

- **M3** vendored 静态 tmux 构建与安装 —— spec 明确它与 M1/M2 无依赖,且它是一个独立的构建系统 + C 供应链工程
- **M4** 断线重连
- **M5** `Ctrl-]` 转义命令层

因此本计划中 `attach` 要求远端**已有** tmux(`terminus doctor` 能看到);没有时给出明确拒绝,而不是尝试安装。

参考 spec:[docs/superpowers/specs/2026-09-19-interactive-tty-attach-design.md](../specs/2026-09-19-interactive-tty-attach-design.md)

---

## 文件结构

**新建**

| 文件 | 职责 |
|---|---|
| `src/core/tty/modes.zig` | 纯函数:已存控制台模式 → 目标模式。无 std 之外的依赖 |
| `src/core/tty/Console.zig` | 唯一碰 Win32 控制台的地方:进入 raw、还原、查尺寸、判断是否 TTY |
| `src/core/tty/InputQueue.zig` | 从 `Client.zig` 原样搬出的输入队列 + 取消原语 |
| `src/core/tty/Pump.zig` | 双向泵:输入队列 → PTY,PTY → stdout,尺寸轮询 |
| `src/cli/cmd_attach.zig` | `attach` 与 `shell` 两个动词 |
| `src/cli/cmd_attach_test.zig` | 该命令的门禁 |

**修改**

| 文件 | 改什么 |
|---|---|
| `src/core/ssh/Client.zig` | 删除搬走的 `InputQueue`/`inputPump`/`cancelInputRead`,改为引用新模块;新增 `Pty` 与 `openPty` |
| `src/core/core.zig` | 导出 `tty` 命名空间 |
| `src/core/store/operations.zig` | `Kind` 新增 `attach` |
| `src/core/store/receipts.zig` | 两张矩阵为 `attach` 补格 |
| `src/cli/dispatch.zig` | `TopCommand` 新增两个动词、usage、switch 分支、test 导入 |
| `src/cli/args.zig` | `bool_flags` 新增 `no-lease` |
| `build.zig` | 无需改动(新文件在既有模块树内) |

---

## 关键事实(实现前必读)

这些是写计划时逐条核实过的,不要再猜:

1. **Zig 0.16 的 `std.os.windows` 不提供任何控制台模式绑定。** `SetConsoleMode` / `GetConsoleMode` / `GetConsoleScreenBufferInfo` / `SetConsoleCtrlHandler` / `SetConsoleCP` 全都没有,必须自己 `extern "kernel32"` 声明。树里的既有风格见 [src/core/windows_supervisor.zig:138](../../../src/core/windows_supervisor.zig#L138)。
2. **`windows.UINT` 存在**(= `c_uint`),**`windows.COORD` 存在**(字段 `X`/`Y`,类型 `SHORT`),**`windows.SMALL_RECT` 不存在** —— 必须自己声明。
3. **新增 operation kind 不需要 schema 迁移。** `operations.kind` 是裸 `TEXT NOT NULL`。停住构建的**不是**那两张可采纳性矩阵 —— 它们刻意只按 `operations.Capabilities` 分支,`appliesTo` 的注释写明"a kind is **not in scope** while the rules are being decided",所以矩阵里写不出针对某个 kind 的例外。真正会停住构建的是 [operations.zig:86](../../../src/core/store/operations.zig#L86) 的 `Kind.capabilities()`,它对 `Kind` 穷举。回答那 8 条轴,矩阵自动得出结论。
4. **`libssh2_channel_shell` 和 `libssh2_channel_request_pty` 都是 C 宏**,translate-c 拿不到。用底层函数:`libssh2_channel_process_startup(ch, "shell", 5, null, 0)` 和 `libssh2_channel_request_pty_ex(ch, term, term_len, modes, modes_len, width, height, width_px, height_px)`。
5. **`std.Io.File` 有 `handle` 字段**,所以 `std.Io.File.stdin().handle` 就是控制台句柄,不需要 `GetStdHandle`(std 也没有它)。
6. **`op_state.canSettle` 不允许 `local_abandon` 从 `submitted`/`remote_started` 落** —— 见 [op_state.zig:473](../../../src/core/store/op_state.zig#L473)。交互会话中途失去连接只能落 `indeterminate`。
7. **`Cli.sshConnect` 是直连构造器**,签名 `fn sshConnect(server: Store.servers.Server, auth: Ssh.Auth) Ssh`。按 spec 决策一,两个动词都用它,不用 `Cli.connect`。

### 怎么跑测试

- 纯模块(无包依赖):`zig test src/core/tty/modes.zig` —— 秒级,TDD 循环用这个
- 全量:`zig build test` —— 较慢(冷编译约 90s),在每个 Task 的最后一步跑
- `zig` 可执行文件在 `C:/Program Files (x86)/zig/zig.exe`

---

# M1 — `terminus shell`

## Task 1:控制台模式的纯函数

**Files:**
- Create: `src/core/tty/modes.zig`

- [ ] **Step 1: 写下会失败的测试**

创建 `src/core/tty/modes.zig`,只放测试(实现留空,先让它编译失败):

```zig
const std = @import("std");

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
```

- [ ] **Step 2: 跑测试确认它失败**

Run: `"C:/Program Files (x86)/zig/zig.exe" test src/core/tty/modes.zig`
Expected: FAIL,报 `use of undeclared identifier 'desired'`(以及 `input`、`output`)

- [ ] **Step 3: 写最小实现**

在 `src/core/tty/modes.zig` 的测试**之前**插入:

```zig
//! 本地 Windows 控制台模式的纯计算。
//!
//! 单独成模块,因为它是这个功能里唯一能被完整测试的部分:真正的
//! `SetConsoleMode` 需要一个真控制台,而控制台的行为无法在 CI 里断言。
//! 把决定压进纯函数,剩给 Win32 层的就只有"照着做"。
//!
//! 常量在这里自己声明:Zig 0.16 的 `std.os.windows` 一个控制台模式位都
//! 没有提供。数值取自 Win32 的 `wincon.h`。

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
```

- [ ] **Step 4: 跑测试确认通过**

Run: `"C:/Program Files (x86)/zig/zig.exe" test src/core/tty/modes.zig`
Expected: `All 6 tests passed.`

- [ ] **Step 5: 提交**

```bash
git add src/core/tty/modes.zig
git commit -m "tty: 控制台模式计算抽成可测的纯函数"
```

---

## Task 2:把 InputQueue 从 Client.zig 搬出来

这是**纯搬移,不改任何行为**。搬完 `tunnel` 必须字节级等价地继续工作。

**Files:**
- Create: `src/core/tty/InputQueue.zig`
- Modify: `src/core/ssh/Client.zig`(删除 549-693 区间的队列代码,改为 import)

- [ ] **Step 1: 建立新模块**

创建 `src/core/tty/InputQueue.zig`,把 [Client.zig:549-693](../../../src/core/ssh/Client.zig#L549-L693) 中的 `tunnel_buffer_bytes`、`tunnel_queue_bytes`、`InputQueue`、`inputPump`、`cancelInputRead` **原样**移过来,只做三处机械改动:

1. 文件顶部补上 `const std = @import("std");` 和 `const builtin = @import("builtin");`
2. `InputQueue` 与其方法、`inputPump`、`cancelInputRead` 前加 `pub`
3. 加文件头注释:

```zig
//! 本地 stdin 的后台读取线程与它的有界环形队列。
//!
//! 从 `ssh/Client.zig` 搬出来的,因为现在有两个消费者:`tunnel` 的
//! direct-tcpip 泵和交互会话的 PTY 泵。两者都需要"主循环不能阻塞在本地
//! 读上",而 Windows 上唯一能打断一个同步 stdin 读的办法是
//! `NtCancelSynchronousIoFile`,所以取消原语必须和队列待在一起。
//!
//! 本次搬移不改任何行为。
```

- [ ] **Step 2: 改 Client.zig 引用它**

在 `Client.zig` 的 import 区加:

```zig
const InputQueueModule = @import("../tty/InputQueue.zig");
const InputQueue = InputQueueModule.InputQueue;
const inputPump = InputQueueModule.inputPump;
const cancelInputRead = InputQueueModule.cancelInputRead;
pub const tunnel_buffer_bytes = InputQueueModule.tunnel_buffer_bytes;
```

然后删掉原处的定义。`tunnel` 函数体一行不动。

- [ ] **Step 3: 跑全量测试确认零回归**

Run: `"C:/Program Files (x86)/zig/zig.exe" build test`
Expected: 与搬移前相同的通过数(基线 608)。任何数字变化都说明这不是一次纯搬移,回滚重做。

- [ ] **Step 4: 提交**

```bash
git add src/core/tty/InputQueue.zig src/core/ssh/Client.zig
git commit -m "tty: InputQueue 搬出 Client.zig，交互泵与 tunnel 共用一份"
```

---

## Task 3:Console.zig —— 唯一碰 Win32 的地方

**Files:**
- Create: `src/core/tty/Console.zig`

- [ ] **Step 1: 写下会失败的测试**

在 `src/core/tty/Console.zig` 末尾写:

```zig
test "entering raw mode refuses when the handle is not a console" {
    // `zig build test` 的 stdout 是重定向的,所以这条在 CI 里真的会走到
    // 拒绝分支 —— 这是本模块唯一能自动化的行为,也是最要紧的那条:
    // 不是终端时必须拒绝,不能降级成吐控制序列乱码。
    const t = std.testing;
    try t.expectError(error.NotATerminal, enter());
}

test "restoring without having entered is a no-op and does not crash" {
    // 还原路径有四条(defer、refusalCleanup、Ctrl 处理器、panic),它们会重叠。
    restoreActive();
    restoreActive();
}
```

- [ ] **Step 2: 跑测试确认它失败**

Run: `"C:/Program Files (x86)/zig/zig.exe" test src/core/tty/Console.zig`
Expected: FAIL,报 `use of undeclared identifier 'enter'`

- [ ] **Step 3: 写实现**

在测试之前写入:

```zig
//! 本地 Windows 控制台的 raw 模式,以及它的还原保证。
//!
//! **还原是这个模块存在的理由。** 本地终端被留在 raw 模式里是这个功能
//! 唯一不可接受的故障:用户的 shell 会变成一个不回显、不换行、Ctrl-C
//! 无效的东西,而且他不会知道是谁干的。
//!
//! 所以还原挂在四条路径上,和 `cli.zig` 的 `active_execution` 同构 ——
//! 那里的注释写得很清楚:`std.process.exit` 跳过 defer,所以必须用进程级
//! 全局。四条路径会重叠,因此 `restoreActive` 必须幂等。
//!
//! Zig 0.16 的 `std.os.windows` 不提供任何控制台绑定,下面的 `extern` 是
//! 自己声明的,风格照 `core/windows_supervisor.zig`。

const std = @import("std");
const builtin = @import("builtin");
const windows = std.os.windows;
const modes = @import("modes.zig");

pub const Error = error{
    /// stdin 或 stdout 不是控制台(被重定向了)。
    NotATerminal,
    /// 是控制台,但拒绝了我们要的模式。
    ConsoleModeUnavailable,
};

pub const Size = struct {
    cols: u16,
    rows: u16,
};

/// 进入前的全部状态。还原就是把这四项写回去。
pub const Saved = struct {
    in_handle: windows.HANDLE,
    out_handle: windows.HANDLE,
    in_mode: windows.DWORD,
    out_mode: windows.DWORD,
    in_cp: windows.UINT,
    out_cp: windows.UINT,
};

/// UTF-8。中文在这条链路上是默认要求,不是选项。
const utf8_code_page: windows.UINT = 65001;

/// 当前进程改过的控制台状态,没改过时为 null。
///
/// 进程级全局,理由与 `cli.zig:253` 的 `active_execution` 完全相同。
var active: ?Saved = null;
var handler_installed: bool = false;

/// 把控制台还原成进入前的样子。幂等:重复调用与未进入时调用都是空操作。
///
/// 每一步都忽略返回值并继续:这是唯一一条"失败了也必须往下走"的路径,
/// 在这里提前返回会因为输入模式没还原成功就放弃还原代码页。
pub fn restoreActive() void {
    if (comptime builtin.os.tag != .windows) return;
    const s = active orelse return;
    active = null; // 先清,保证并发的第二次调用是空操作
    _ = SetConsoleMode(s.in_handle, s.in_mode);
    _ = SetConsoleMode(s.out_handle, s.out_mode);
    _ = SetConsoleCP(s.in_cp);
    _ = SetConsoleOutputCP(s.out_cp);
}

/// Ctrl-Break、关窗口、注销、关机。
///
/// Ctrl-C **不**走这里:进入 raw 模式后 `ENABLE_PROCESSED_INPUT` 已被清除,
/// Ctrl-C 是字节 0x03,要原样送去远端。
///
/// 返回 FALSE 让默认处理器接着跑(它会结束进程),我们只负责在那之前把
/// 终端还原回去。
fn ctrlHandler(_: windows.DWORD) callconv(.winapi) windows.BOOL {
    restoreActive();
    return 0;
}

/// 进入 raw 模式,并登记还原状态。
pub fn enter() Error!void {
    if (comptime builtin.os.tag != .windows) return error.NotATerminal;
    const in_handle = std.Io.File.stdin().handle;
    const out_handle = std.Io.File.stdout().handle;

    var in_mode: windows.DWORD = 0;
    var out_mode: windows.DWORD = 0;
    // `GetConsoleMode` 对非控制台句柄失败,这就是 TTY 检测本身 ——
    // 不需要另一个 isatty。
    if (GetConsoleMode(in_handle, &in_mode) == 0) return error.NotATerminal;
    if (GetConsoleMode(out_handle, &out_mode) == 0) return error.NotATerminal;

    const saved: Saved = .{
        .in_handle = in_handle,
        .out_handle = out_handle,
        .in_mode = in_mode,
        .out_mode = out_mode,
        .in_cp = GetConsoleCP(),
        .out_cp = GetConsoleOutputCP(),
    };

    const want = modes.desired(.{ .in = in_mode, .out = out_mode });
    if (SetConsoleMode(in_handle, want.in) == 0) return error.ConsoleModeUnavailable;
    if (SetConsoleMode(out_handle, want.out) == 0) {
        _ = SetConsoleMode(in_handle, in_mode); // 半改的控制台比没改更糟
        return error.ConsoleModeUnavailable;
    }
    _ = SetConsoleCP(utf8_code_page);
    _ = SetConsoleOutputCP(utf8_code_page);

    active = saved;
    if (!handler_installed) {
        _ = SetConsoleCtrlHandler(ctrlHandler, 1);
        handler_installed = true;
    }
}

/// 当前窗口的字符尺寸,不可读时返回 null。
///
/// 取的是 `srWindow`(可见窗口)而不是 `dwSize`(缓冲区):远端 PTY 要的是
/// 用户看得见的那块,缓冲区通常比它高得多。
pub fn size() ?Size {
    if (comptime builtin.os.tag != .windows) return null;
    var info: ConsoleScreenBufferInfo = undefined;
    if (GetConsoleScreenBufferInfo(std.Io.File.stdout().handle, &info) == 0) return null;
    const cols = @as(i32, info.srWindow.Right) - info.srWindow.Left + 1;
    const rows = @as(i32, info.srWindow.Bottom) - info.srWindow.Top + 1;
    if (cols <= 0 or rows <= 0) return null;
    return .{ .cols = @intCast(cols), .rows = @intCast(rows) };
}

// --- Win32 -------------------------------------------------------------------
//
// `SMALL_RECT` 不在 `std.os.windows` 里,自己声明。`COORD` 在。

const SmallRect = extern struct {
    Left: windows.SHORT,
    Top: windows.SHORT,
    Right: windows.SHORT,
    Bottom: windows.SHORT,
};

const ConsoleScreenBufferInfo = extern struct {
    dwSize: windows.COORD,
    dwCursorPosition: windows.COORD,
    wAttributes: windows.WORD,
    srWindow: SmallRect,
    dwMaximumWindowSize: windows.COORD,
};

extern "kernel32" fn GetConsoleMode(
    hConsoleHandle: windows.HANDLE,
    lpMode: *windows.DWORD,
) callconv(.winapi) windows.BOOL;

extern "kernel32" fn SetConsoleMode(
    hConsoleHandle: windows.HANDLE,
    dwMode: windows.DWORD,
) callconv(.winapi) windows.BOOL;

extern "kernel32" fn GetConsoleCP() callconv(.winapi) windows.UINT;
extern "kernel32" fn SetConsoleCP(wCodePageID: windows.UINT) callconv(.winapi) windows.BOOL;
extern "kernel32" fn GetConsoleOutputCP() callconv(.winapi) windows.UINT;
extern "kernel32" fn SetConsoleOutputCP(wCodePageID: windows.UINT) callconv(.winapi) windows.BOOL;

extern "kernel32" fn GetConsoleScreenBufferInfo(
    hConsoleOutput: windows.HANDLE,
    lpConsoleScreenBufferInfo: *ConsoleScreenBufferInfo,
) callconv(.winapi) windows.BOOL;

extern "kernel32" fn SetConsoleCtrlHandler(
    HandlerRoutine: ?*const fn (windows.DWORD) callconv(.winapi) windows.BOOL,
    Add: windows.BOOL,
) callconv(.winapi) windows.BOOL;
```

- [ ] **Step 4: 跑测试确认通过**

Run: `"C:/Program Files (x86)/zig/zig.exe" test src/core/tty/Console.zig`
Expected: `All 2 tests passed.`

若 `windows.WORD` 或 `windows.SHORT` 报未定义,用 `u16` / `i16` 替换 —— 它们就是这两个类型。

- [ ] **Step 5: 提交**

```bash
git add src/core/tty/Console.zig
git commit -m "tty: Windows 控制台 raw 模式，还原挂在四条退出路径上"
```

---

## Task 4:把还原接进 `fail` 的清理链

没有这一步,任何一条 `Cli.fail` 都会留下一个 raw 模式的终端。

**Files:**
- Modify: `src/cli/cli.zig`(`refusalCleanup` 内)

- [ ] **Step 1: 找到清理函数**

Run: `grep -n "fn refusalCleanup" -A 12 src/cli/cli.zig`

- [ ] **Step 2: 在它最前面加一行还原**

在 `refusalCleanup` 函数体的**第一行**插入:

```zig
    // 终端先还原,再做其它清理:后面几步会往 stderr 写句子,而在 raw 模式
    // 下那些句子不会换行。这一行必须排在最前,不能挪到收据之后。
    Core.tty.Console.restoreActive();
```

- [ ] **Step 3: 在 `core.zig` 导出 tty**

在 `src/core/core.zig` 加:

```zig
pub const tty = struct {
    pub const modes = @import("tty/modes.zig");
    pub const Console = @import("tty/Console.zig");
    pub const InputQueue = @import("tty/InputQueue.zig");
    pub const Pump = @import("tty/Pump.zig");
};
```

注意 `Pump.zig` 此时还不存在,本步骤先只写 `modes` / `Console` / `InputQueue` 三行,Task 6 再补 `Pump`。

- [ ] **Step 4: 跑全量测试**

Run: `"C:/Program Files (x86)/zig/zig.exe" build test`
Expected: 通过数 = 608 + 8(Task 1 的 6 条 + Task 3 的 2 条)= 616

- [ ] **Step 5: 提交**

```bash
git add src/cli/cli.zig src/core/core.zig
git commit -m "tty: 控制台还原接进 refusalCleanup，fail 路径不再留下 raw 终端"
```

---

## Task 5:Client.zig 的 PTY 通道

**Files:**
- Modify: `src/core/ssh/Client.zig`(在 `tunnel` 之后、`exec` 之前插入)

- [ ] **Step 1: 写实现**

```zig
// --- the interactive channel -------------------------------------------------

pub const PtyError = error{
    ChannelOpenFailed,
    PtyRequestFailed,
    StartupFailed,
};

/// 一次读的结果。
///
/// 具名而不是用 `?usize` 或负数哨兵:调用方必须分辨"还没有数据"和"对端
/// 结束了",把它们混成同一个值正是把断线读成正常退出的那类错误。
pub const PtyRead = union(enum) {
    bytes: usize,
    /// 此刻没有数据,不是错误。
    again,
    /// 对端关闭了流。
    eof,
    failed,
};

pub const PtyWrite = union(enum) {
    bytes: usize,
    again,
    failed,
};

/// 远端要启动什么。
pub const PtyStart = union(enum) {
    /// 用户的登录 shell。
    login_shell,
    /// 一条命令,例如 `tmux attach -t =t-web`。
    command: []const u8,
};

/// 一条带伪终端的会话通道。
pub const Pty = struct {
    session: *c.LIBSSH2_SESSION,
    channel: *c.LIBSSH2_CHANNEL,

    /// 窗口尺寸变化。失败是无害的(远端只是继续用旧尺寸),所以不返回错误。
    pub fn resize(p: *Pty, cols: u16, rows: u16) void {
        _ = c.libssh2_channel_request_pty_size_ex(
            p.channel,
            @intCast(cols),
            @intCast(rows),
            0,
            0,
        );
    }

    pub fn read(p: *Pty, out: []u8) PtyRead {
        const n = c.libssh2_channel_read_ex(p.channel, 0, out.ptr, out.len);
        if (n > 0) return .{ .bytes = @intCast(n) };
        if (n == 0) return if (c.libssh2_channel_eof(p.channel) != 0) .eof else .again;
        if (n == c.LIBSSH2_ERROR_EAGAIN) return .again;
        return .failed;
    }

    pub fn write(p: *Pty, bytes: []const u8) PtyWrite {
        const n = c.libssh2_channel_write_ex(p.channel, 0, bytes.ptr, bytes.len);
        if (n > 0) return .{ .bytes = @intCast(n) };
        if (n == c.LIBSSH2_ERROR_EAGAIN) return .again;
        return .failed;
    }

    /// 关闭并交还退出码。
    ///
    /// 关闭前恢复阻塞模式:非阻塞下的 `wait_closed` 只会返回 EAGAIN,
    /// 让一次本来干净的收尾留下半开通道 —— `tunnel` 的收尾注释记录了
    /// 同一件事。
    pub fn close(p: *Pty) i32 {
        c.libssh2_session_set_blocking(p.session, 1);
        _ = c.libssh2_channel_close(p.channel);
        _ = c.libssh2_channel_wait_closed(p.channel);
        const status = c.libssh2_channel_get_exit_status(p.channel);
        _ = c.libssh2_channel_free(p.channel);
        return status;
    }
};

/// 开一条伪终端会话通道。
///
/// 会话被置为非阻塞并保持:交互泵必须能在没有远端数据时继续送本地输入。
/// 恢复阻塞是 `Pty.close` 的职责。
///
/// `libssh2_channel_request_pty` 与 `libssh2_channel_shell` 都是 C 宏,
/// translate-c 拿不到,所以这里调底层的 `_ex` / `process_startup`。
pub fn openPty(
    client: *Client,
    term: []const u8,
    cols: u16,
    rows: u16,
    start: PtyStart,
) PtyError!Pty {
    const channel = c.libssh2_channel_open_ex(
        client.session,
        "session",
        "session".len,
        c.LIBSSH2_CHANNEL_WINDOW_DEFAULT,
        c.LIBSSH2_CHANNEL_PACKET_DEFAULT,
        null,
        0,
    ) orelse return error.ChannelOpenFailed;
    errdefer _ = c.libssh2_channel_free(channel);

    if (c.libssh2_channel_request_pty_ex(
        channel,
        term.ptr,
        @intCast(term.len),
        null,
        0,
        @intCast(cols),
        @intCast(rows),
        0,
        0,
    ) != 0) return error.PtyRequestFailed;

    switch (start) {
        .login_shell => if (c.libssh2_channel_process_startup(
            channel,
            "shell",
            "shell".len,
            null,
            0,
        ) != 0) return error.StartupFailed,
        .command => |cmd| if (c.libssh2_channel_process_startup(
            channel,
            "exec",
            "exec".len,
            cmd.ptr,
            @intCast(cmd.len),
        ) != 0) return error.StartupFailed,
    }

    c.libssh2_session_set_blocking(client.session, 0);
    return .{ .session = client.session, .channel = channel };
}
```

- [ ] **Step 2: 确认编译**

Run: `"C:/Program Files (x86)/zig/zig.exe" build`
Expected: 成功。`refAllDecls` 非递归且 Zig 惰性分析函数体,所以只有真正被调用才会彻底检查 —— 下一个 Task 会调用它。

- [ ] **Step 3: 提交**

```bash
git add src/core/ssh/Client.zig
git commit -m "ssh: 伪终端会话通道（request_pty + shell/exec 启动）"
```

---

## Task 6:Pump.zig —— 会话循环

**Files:**
- Create: `src/core/tty/Pump.zig`
- Modify: `src/core/core.zig`(补上 `Pump` 那行)

- [ ] **Step 1: 写实现**

```zig
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
    /// 远端结束了会话,带回退出码。
    remote_exit: i32,
    /// 本地 stdin 到了 EOF。
    local_eof,
    /// 传输中断;远端的下场不可知。
    transport_failed,
};

pub const Error = error{
    InputThreadFailed,
    OutputWriteFailed,
};

pub fn run(io: std.Io, pty: *Ssh.Pty) Error!Outcome {
    var queue = Queue.InputQueue.init(io);
    var input_thread = std.Thread.spawn(.{}, Queue.inputPump, .{ &queue, std.Io.File.stdin() }) catch
        return error.InputThreadFailed;
    var joined = false;
    defer {
        if (!joined) {
            queue.requestStop();
            Queue.cancelInputRead(&input_thread);
            input_thread.join();
        }
    }

    var out_buffer: [Queue.tunnel_buffer_bytes]u8 = undefined;
    var writer = std.Io.File.stdout().writerStreaming(io, &out_buffer);

    var last_size: ?Console.Size = Console.size();
    if (last_size) |s| pty.resize(s.cols, s.rows);
    var last_size_check = std.time.milliTimestamp();

    var outcome: Outcome = .transport_failed;
    var input_buffer: [Queue.tunnel_buffer_bytes]u8 = undefined;
    var remote_buffer: [Queue.tunnel_buffer_bytes]u8 = undefined;

    loop: while (true) {
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
                outcome = .{ .remote_exit = 0 }; // 真退出码由 close 取回
                break :loop;
            },
            .failed => {
                outcome = .transport_failed;
                break :loop;
            },
        }

        // 尺寸
        const now = std.time.milliTimestamp();
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
        }

        if (!progressed)
            std.Io.sleep(io, .{ .nanoseconds = std.time.ns_per_ms }, .awake) catch {};
    }

    writer.interface.flush() catch return error.OutputWriteFailed;
    queue.requestStop();
    Queue.cancelInputRead(&input_thread);
    input_thread.join();
    joined = true;
    return outcome;
}
```

- [ ] **Step 2: 在 core.zig 补上导出**

把 Task 4 Step 3 里预留的那行加进 `tty` 结构:

```zig
    pub const Pump = @import("tty/Pump.zig");
```

- [ ] **Step 3: 确认编译**

Run: `"C:/Program Files (x86)/zig/zig.exe" build`
Expected: 成功

- [ ] **Step 4: 提交**

```bash
git add src/core/tty/Pump.zig src/core/core.zig
git commit -m "tty: 交互会话的双向泵，含尺寸轮询"
```

---

## Task 7:新增 operation kind `attach`

**Files:**
- Modify: `src/core/store/operations.zig`(两处:`Kind` 枚举和 `Kind.capabilities()`)

两张可采纳性矩阵**不需要修改** —— 它们只按 `Capabilities` 分支,不认识 kind。

- [ ] **Step 1: 加变体**

在 `src/core/store/operations.zig` 的 `Kind` 枚举里,`tunnel` 之后加:

```zig
    /// 一个人坐在远端的终端前面。
    ///
    /// 和 `exec` 的区别不是规模而是可观测性:`exec` 交出一条命令并收回它的
    /// 退出码,而这里交出去的是一条字节流,里面发生了什么这一侧永远不会
    /// 知道。所以 `argv_redacted` 记的是行为本身("interactive session"),
    /// 不假装知道内容。
    ///
    /// 加这个变体不需要迁移 —— `operations.kind` 是裸 TEXT,见 `control`
    /// 的注释。停住构建的是下面的 `capabilities()`。
    attach,
```

- [ ] **Step 2: 跑构建,让 `capabilities()` 停住它**

Run: `"C:/Program Files (x86)/zig/zig.exe" build`
Expected: **编译失败**,报 `capabilities` 的 switch 未覆盖 `.attach`。这正是要的。

- [ ] **Step 3: 回答那 8 条轴**

`.attach` 的答案与 `tunnel` / `plan_phase` / `cleanup` 逐条相同,所以加进它们那一条现成的分支即可。把:

```zig
            .tunnel, .plan_phase, .cleanup => .{
```

改成:

```zig
            // `attach` 和这三个同属"我们并不判断它做成了什么"的一类。
            //
            // `runs_our_command = false`:交出去的是一条字节流,人在那头敲
            // 什么我们没有命令可以指名。`tmux attach` 本身只是载具,不是这个
            // 操作的工作内容。
            //
            // `judgement_undeclared = true` 是让 `.exited` 仍然可采纳的那条 ——
            // `terminalDescribes` 里写的是
            // `.exited => can.runs_our_command or can.judgement_undeclared`,
            // 而注释解释了理由:"a kind nothing knows anything about must not be
            // born unsettleable"。正常 detach 要能落一个终态。
            //
            // `supervises_another_subject` 保持 false,尽管 `attach` 会在会话上
            // 持租约。持租约不是监管:它没有对那个会话做任何事。设成 true 会
            // 顺带让 `remote_cancel_confirmed` 可采纳,而**没有人能证明一个
            // 交互会话"被取消了"** —— 那正是这一位要挡住的收据。
            .tunnel, .plan_phase, .cleanup, .attach => .{
```

分支体一行不改。

- [ ] **Step 4: 跑全量测试**

Run: `"C:/Program Files (x86)/zig/zig.exe" build test`
Expected: 全绿。若 `gates_admissibility_test.zig` 报错,说明某条轴答错了 —— 它对每条轴做单轴翻转,会指出是哪一条。

- [ ] **Step 5: 提交**

```bash
git add src/core/store/operations.zig
git commit -m "ledger: 新增 attach operation kind，8 条能力轴逐条回答"
```

---

## Task 8:`terminus shell` 动词

**Files:**
- Create: `src/cli/cmd_attach.zig`
- Modify: `src/cli/dispatch.zig`

- [ ] **Step 1: 写命令**

创建 `src/cli/cmd_attach.zig`:

```zig
//! `terminus shell <server>` 与 `terminus attach <server>[:<session>]`。
//!
//! 两个动词共用同一条管道(控制台 raw 模式 → PTY 通道 → 泵),只差远端
//! 启动什么:`shell` 启动登录 shell,`attach` 执行 `tmux attach`。
//!
//! 两者都用 `Cli.sshConnect` 而不是 `Cli.connect`:daemon 协议是长度前缀
//! 的 JSON 帧,载不动裸字节流;而热连接省下的一次握手对一个开几十分钟的
//! 会话没有意义。理由与 `cmd_tunnel.zig` 相同。

const std = @import("std");
const Cli = @import("cli.zig");
const Core = @import("../core/core.zig");
const Store = Core.Store;
const Console = Core.tty.Console;
const Pump = Core.tty.Pump;

const fatal = Cli.fail;

pub const Mode = enum { shell, attach };

pub const shell_usage = "usage: terminus shell <server>\n" ++
    "\n打开远端登录 shell。本地终端进入 raw 模式,退出后自动还原。\n" ++
    "裸登录 shell 不持久:连接断开时远端进程随之结束。\n";

/// 远端的 TERM。
///
/// 写死而不是读本地 `TERM`:Windows 控制台通常根本没有这个环境变量,而
/// 猜错会让远端的 ncurses 程序画出乱码。`xterm-256color` 是 Windows
/// Terminal 与 conhost(Win10 1703 起)都真正支持的那一档。
const remote_term = "xterm-256color";

pub fn run(ctx: *Cli.Ctx, mode: Mode, raw_args: []const []const u8) !void {
    const parsed = Cli.parseArgs(ctx, raw_args);
    const target_spec = parsed.positional(0) orelse switch (mode) {
        .shell => fatal("{s}", .{shell_usage}),
        .attach => fatal("{s}", .{attach_usage}),
    };
    const target = Cli.Target.parse(target_spec);
    if (mode == .shell and target.session != null)
        fatal("shell 的目标是服务器,不是会话;要接会话用 'terminus attach {s}'", .{target_spec});

    var store = try Cli.openStore(ctx, &parsed);
    defer store.close();
    const resolved = Cli.resolveServer(ctx, &store, target.server);

    // 先占住控制台再连接:连接可能花几秒,而在那之前让终端保持正常,
    // 用户才能看到连接失败的句子。
    const size = Console.size() orelse Console.Size{ .cols = 80, .rows = 24 };

    var client = Cli.sshConnect(resolved.server, resolved.auth);
    defer client.deinit();

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

    var pty = client.openPty(remote_term, size.cols, size.rows, .login_shell) catch |err| fatal(
        "无法在 '{s}' 上打开伪终端: {s}",
        .{ target.server, @errorName(err) },
    );

    const outcome = Pump.run(ctx.io, &pty) catch |err| {
        _ = pty.close();
        fatal("交互会话失败: {s}", .{@errorName(err)});
    };
    const status = pty.close();
    Console.restoreActive();

    switch (outcome) {
        .remote_exit => try ctx.out.print("会话结束(退出码 {d})\n", .{status}),
        .local_eof => try ctx.out.print("本地输入结束,会话已关闭\n", .{}),
        .transport_failed => fatal(
            "连接中断;裸登录 shell 不持久,远端进程已经结束",
            .{},
        ),
    }
}
```

注意:`attach_usage` 与 `attach` 分支在 Task 10 加入;本 Task 先只让 `.shell` 分支可达,`attach_usage` 暂时写成与 `shell_usage` 相同的常量,Task 10 替换。

- [ ] **Step 2: 接进 dispatch**

在 `src/cli/dispatch.zig`:

1. `TopCommand` 枚举里 `tunnel` 之后加 `shell,`
2. `usage` 常量里 `tunnel` 那行之后加:
   ```
   \\  shell      open an interactive remote login shell
   ```
3. `dispatchCommand` 的 switch 里加:
   ```zig
   .shell => try @import("cmd_attach.zig").run(ctx, .shell, args[1..]),
   ```
4. 文件末尾的 `test` 块里加 `_ = @import("cmd_attach.zig");`

- [ ] **Step 3: 跑全量测试**

Run: `"C:/Program Files (x86)/zig/zig.exe" build test`
Expected: 全绿

- [ ] **Step 4: 提交**

```bash
git add src/cli/cmd_attach.zig src/cli/dispatch.zig
git commit -m "cli: terminus shell —— 远端交互式登录 shell"
```

---

## Task 9:M1 手工验收

自动化测试到此为止 —— 本地控制台 raw 模式的实际观感没有办法在 CI 里断言。这一步必须由人做。

**⚠ 跑本地构建前先重定向 `USERPROFILE` 和 `HOME`**:`zig-out/bin/Terminus.exe` 会用仓库的 `SKILL.md` 覆盖 `~/.claude/skills/terminus/SKILL.md` 和 `~/.codex/skills/terminus/SKILL.md`。

- [ ] **Step 1: 构建**

```bash
"C:/Program Files (x86)/zig/zig.exe" build -Doptimize=ReleaseSafe
```

- [ ] **Step 2: 逐项验收**

对一台已注册的服务器跑 `zig-out/bin/Terminus.exe shell <server>`,逐条确认:

| | 检查项 | 通过标准 |
|---|---|---|
| 1 | `vim` 方向键 | 光标移动,不出现 `^[[A` |
| 2 | `htop` | 正常刷新,颜色正确 |
| 3 | `Ctrl-C` | 中断**远端**进程,terminus 不退出 |
| 4 | 中文 | `echo 你好` 正确显示 |
| 5 | 拉伸窗口后 `tput cols` | 报出新宽度 |
| 6 | `exit` 退出 | 回到本地 shell,回显与换行正常 |
| 7 | 关闭窗口再开新终端 | 新终端正常(Ctrl 处理器还原生效) |
| 8 | `Ctrl-Break` | 退出且终端正常 |
| 9 | `echo x \| Terminus.exe shell <server>` | 明确拒绝,不吐乱码 |

- [ ] **Step 3: 把结果记进计划**

在本文件此处补一行实测结论(通过/哪条不通过)。任何一条不通过都是 M1 未完成,不要进入 M2。

---

# M2 — `terminus attach`

## Task 10:会话选择与 attach 动词

**Files:**
- Modify: `src/cli/cmd_attach.zig`
- Modify: `src/cli/dispatch.zig`

- [ ] **Step 1: 写会话解析**

在 `cmd_attach.zig` 加:

```zig
pub const attach_usage = "usage: terminus attach <server>[:<session>]\n" ++
    "\n接入远端 tmux 会话。detach 后会话在远端继续存活,agent 可用\n" ++
    "'terminus read' 读到这期间的输出。不给会话名时列出现有会话。\n" ++
    "\n需要远端已安装 tmux;用 'terminus doctor <server>' 确认。\n";

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
```

`RemoteSession` 的字段是 `name` / `created` / `attached`,见 [Tmux.zig:618](../../../src/core/session/Tmux.zig#L618);`list` 在远端没有 tmux 时返回 `error.TmuxMissing`([Tmux.zig:625](../../../src/core/session/Tmux.zig#L625) 的脚本用 exit 41 表示)。

- [ ] **Step 2: 在 run 里分出 attach 分支**

把 Task 8 中 `client.openPty(remote_term, size.cols, size.rows, .login_shell)` 那一句改成先算出 `start`:

```zig
    var session_name: ?[]const u8 = null;
    const start: Core.Ssh.PtyStart = switch (mode) {
        .shell => .login_shell,
        .attach => blk: {
            // `Executor` 是个 union,直连客户端就是 `.direct` 那一支 ——
            // 这里不能用 `conn.executor()`,我们拿的是 `Cli.sshConnect`
            // 返回的裸 `Ssh`,没有 connection 包装。
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

    var pty = client.openPty(remote_term, size.cols, size.rows, start) catch |err| fatal(
        "无法在 '{s}' 上打开伪终端: {s}",
        .{ target.server, @errorName(err) },
    );
```

注意 `chooseSession` 必须在 `Console.enter()` **之前**调用:它可能 `fatal`,而在 raw 模式下那句话不会换行。

并把 `.transport_failed` 分支按 mode 分开:

```zig
        .transport_failed => switch (mode) {
            .shell => fatal("连接中断;裸登录 shell 不持久,远端进程已经结束", .{}),
            .attach => fatal(
                "连接中断;会话 '{s}' 仍在远端运行,重连后可再次 attach",
                .{session_name.?},
            ),
        },
```

- [ ] **Step 3: 加 pane 日志提示**

在 `Console.enter()` **之前**(还没进 raw 模式,这行才会正常换行)插入:

```zig
    if (mode == .attach) try ctx.out.print(
        "本会话输出会写入远端 pane 日志(agent 可读)\n",
        .{},
    );
```

- [ ] **Step 4: 接进 dispatch**

`TopCommand` 加 `attach,`;usage 加:

```
\\  attach     attach to a remote tmux session   (persistent; agent-visible)
```

switch 加:

```zig
.attach => try @import("cmd_attach.zig").run(ctx, .attach, args[1..]),
```

- [ ] **Step 5: 跑全量测试**

Run: `"C:/Program Files (x86)/zig/zig.exe" build test`
Expected: 全绿

- [ ] **Step 6: 提交**

```bash
git add src/cli/cmd_attach.zig src/cli/dispatch.zig
git commit -m "cli: terminus attach —— 接入远端 tmux 会话，含会话选择"
```

---

## Task 11:会话租约与 `--no-lease`

**Files:**
- Modify: `src/cli/args.zig`
- Modify: `src/cli/cmd_attach.zig`
- Modify: `src/core/tty/Pump.zig`(加续租回调)

- [ ] **Step 1: 注册 flag**

在 `src/cli/args.zig` 的 `bool_flags` 末尾加 `"no-lease"`。

**同一个提交里必须有生产代码读它**,否则 [args.zig:147](../../../src/cli/args.zig#L147) 的双向门禁会红 —— 那条门禁存在的原因是漏登记不是编译错误,它会让读取永远为 `false` 并把后一个参数当成它的值吞掉。

- [ ] **Step 2: 给 Pump 加空闲回调**

在 `Pump.zig` 的 `Outcome` 之后加:

```zig
/// 每个空闲 tick 调一次(约 200ms 一轮尺寸检查的同一节拍)。
///
/// 返回 false 表示会话应当结束 —— 租约被别人接管时就是这样:继续打字会
/// 让两个所有者同时以为自己持有这个会话。
pub const Tick = struct {
    context: *anyopaque,
    call: *const fn (context: *anyopaque) bool,
};
```

`run` 的签名改成 `pub fn run(io: std.Io, pty: *Ssh.Pty, tick: ?Tick) Error!Outcome`,并在尺寸检查那个 `if (now - last_size_check >= resize_poll_ms)` 块的末尾加:

```zig
            if (tick) |t| {
                if (!t.call(t.context)) {
                    outcome = .{ .remote_exit = 0 };
                    break :loop;
                }
            }
```

Task 8 里 `Pump.run(ctx.io, &pty)` 的调用改成 `Pump.run(ctx.io, &pty, tick)`。

- [ ] **Step 3: 在 attach 里取租约并续租**

`attach` 的租约范围用与 `session rm` 相同的映射:一个会话的争用范围**就是 job 范围**。[cmd_session.zig:1774](../../../src/cli/cmd_session.zig#L1774) 的 `contentionScope` 把 `job-deploy` 映射成 `.{ .kind = .job, .key = "deploy" }`,并在它的测试里写明理由:"the session a running job lives in contends with the job, because it *is* the job's shell"。照抄这个映射,`attach` 就天然挡住 `job kill`,不需要第二套机制。

在 `cmd_attach.zig` 加:

```zig
const Control = @import("../core/control.zig");
const Claim = Control.Claim;
const Authority = Control.Authority;
const stillOurs = Control.stillOurs;

/// 会话名 → 争用范围。与 `cmd_session.zig` 的 `contentionScope` 同一映射:
/// 一个 job 的会话就是那个 job 的 shell,接进去的人和 `job kill` 争的是
/// 同一个东西。
fn contentionScope(name: []const u8) Core.execution.Scope {
    const job_prefix = "job-";
    if (std.mem.startsWith(u8, name, job_prefix) and name.len > job_prefix.len)
        return .{ .kind = .job, .key = name[job_prefix.len..] };
    return .{ .kind = .job, .key = name };
}

/// 续租的节拍器。
///
/// 泵每 200ms 调一次 tick,但续租是一次 store 写 —— 每秒五次写既无必要
/// 也会把 WAL 撑大。`Claim.ttl_secs` 是 120s,30s 续一次留了四倍余量。
const renew_every_ms: i64 = 30_000;

const LeaseTick = struct {
    claim: Claim,
    io: std.Io,
    authority: Authority = .held,
    last_renewed_ms: i64,

    fn call(context: *anyopaque) bool {
        const self: *LeaseTick = @ptrCast(@alignCast(context));
        const now = std.time.milliTimestamp();
        if (now - self.last_renewed_ms < renew_every_ms) return true;
        self.last_renewed_ms = now;
        // 续不上就结束会话:租约被别人接管后继续打字,会让两个所有者
        // 同时以为自己持有这个会话。
        return stillOurs(self.claim, self.io, &self.authority);
    }
};
```

在 `run` 中,`attach` 模式且未给 `--no-lease` 时取租约:

```zig
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
        _ = Store.leases.acquire(&store, ctx.arena, .{
            .server_id = resolved.server.id,
            .scope = claim.scope,
            .owner_request_id = execution.id(),
            .profile_token = owner_token,
            .owner_label = name,
            .ttl_secs = Claim.ttl_secs,
            // 活时钟,不是 `ctx.now`。`ctx.now` 是进程启动时间,用它计时的
            // TTL 在 store 打开之前就开始走了 —— `claimScope` 的注释记录了
            // 同一件事。
            .now = Control.wallClockSeconds(ctx.io),
        }) catch |err| fatal("无法为会话 '{s}' 取得租约: {s}", .{ name, @errorName(err) });

        lease_tick = .{
            .claim = claim,
            .io = ctx.io,
            .last_renewed_ms = std.time.milliTimestamp(),
        };
    }

    const tick: ?Pump.Tick = if (lease_tick) |*lt|
        .{ .context = lt, .call = LeaseTick.call }
    else
        null;
```

然后把 Task 6 的调用改成 `Pump.run(ctx.io, &pty, tick)`。

`owner_token` 由 `Store.policy.ownerToken(&store, ctx.arena, ctx.io, ctx.now)` 取得,用法见 [cmd_server.zig:284](../../../src/cli/cmd_server.zig#L284)。`execution` 是本命令自己的 operation(kind `.attach`),由 `Core.execution.begin` 建立 —— 同样参照 `cmd_server.zig` 中 `runHelperInstall` 的那一段,把 `.kind` 换成 `.attach`、`.scope` 换成 `contentionScope(name)`、`.argv_redacted` 换成 `"interactive session"`。

- [ ] **Step 4: 跑全量测试**

Run: `"C:/Program Files (x86)/zig/zig.exe" build test`
Expected: 全绿,且 `args.zig` 的双向门禁通过

- [ ] **Step 5: 提交**

```bash
git add src/cli/args.zig src/cli/cmd_attach.zig src/core/tty/Pump.zig
git commit -m "attach: 会话租约与续租，人在里面时 session rm / job kill 被挡住"
```

---

## Task 12:命令面的源码门禁

**Files:**
- Create: `src/cli/cmd_attach_test.zig`
- Modify: `src/cli/dispatch.zig`(test 块加导入)

- [ ] **Step 1: 写门禁**

```zig
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
    // 还原必须在源码里出现至少两次:一次 defer,一次正常路径的显式调用。
    // 只有 defer 的话,fail 路径依赖 refusalCleanup,而那条链断了没人会发现。
    const source = @embedFile("cmd_attach.zig");
    const restore = "restore" ++ "Active()";
    try std.testing.expect(std.mem.count(u8, source, restore) >= 2);
}

test "attach matches the tmux session exactly" {
    // `-t <name>` 是前缀匹配,`web` 会接上 `web-old`。
    const source = @embedFile("cmd_attach.zig");
    try std.testing.expect(std.mem.indexOf(u8, source, "tmux attach -t =") != null);
}
```

- [ ] **Step 2: 跑测试**

Run: `"C:/Program Files (x86)/zig/zig.exe" build test`
Expected: 全绿,新增 3 条

- [ ] **Step 3: 提交**

```bash
git add src/cli/cmd_attach_test.zig src/cli/dispatch.zig
git commit -m "attach: 命令面的三条源码门禁"
```

---

## Task 13:M2 手工验收

- [ ] **Step 1: 构建并验收**

同 Task 9 的环境隔离要求。逐条确认:

| | 检查项 | 通过标准 |
|---|---|---|
| 1 | `attach <server>` 无会话名、恰好一个会话 | 直接接入 |
| 2 | `attach <server>` 多个会话 | 列出并要求指名,不自动选 |
| 3 | `attach <server>:<name>` | 接入指定会话 |
| 4 | 在会话里跑东西,`Ctrl-B d` | detach 回本地,终端正常 |
| 5 | detach 后 `terminus read <server>:<name>` | 读得到刚才交互期间的输出 |
| 6 | attach 时另开窗口 `terminus session rm` | **被租约拒绝** |
| 7 | `--no-lease` 下重复第 6 条 | 不被拒绝 |
| 8 | 首次连接 | 打印 pane 日志提示 |
| 9 | 远端无 tmux | 明确拒绝并指向 `terminus doctor` |

- [ ] **Step 2: 记录结果**

在本文件此处补实测结论。

---

## 自查记录

写完后对照 spec 逐节核过:

- spec §3 命令面 —— Task 8(shell)、Task 10(attach + 选择器)。`--allow-tmux-install` 属 M3,本计划不含
- spec §5 控制台层 —— Task 1(模式)、Task 3(进出与还原)、Task 4(接进 fail 链)
- spec §6 转义层 —— **M5,不在本计划**
- spec §7 重连 —— **M4,不在本计划**。因此 Task 8/10 的 `.transport_failed` 分支是直接失败,M4 会把它替换成重连入口
- spec §8 错误处理 —— Task 8 覆盖非 TTY、模式不可用、传输中断;无 tmux 由 Task 10 的 `chooseSession` 覆盖
- spec §9 tmux 分发 —— **M3,不在本计划**
- spec §10 账本 —— Task 7(kind + 两张矩阵)、Task 11(租约)
- spec §11 pane 日志提示 —— Task 10 Step 3
- spec §12 测试 —— 可自动化部分在 Task 1/3/12;不可自动化部分是 Task 9 与 Task 13 的验收表

**一处已知的计划内欠账**:Task 8 先写一个与 `shell_usage` 相同的 `attach_usage` 占位,Task 10 替换它。这是为了让 Task 8 能独立编译通过并提交;Task 10 必须真的替换,不能留着。
