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

/// 进入前的全部状态。还原就是把这几项写回去。
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
/// 进程级全局,理由与 `cli.zig` 的 `active_execution` 完全相同。
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
    return .FALSE;
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
    if (!GetConsoleMode(in_handle, &in_mode).toBool()) return error.NotATerminal;
    if (!GetConsoleMode(out_handle, &out_mode).toBool()) return error.NotATerminal;

    const saved: Saved = .{
        .in_handle = in_handle,
        .out_handle = out_handle,
        .in_mode = in_mode,
        .out_mode = out_mode,
        .in_cp = GetConsoleCP(),
        .out_cp = GetConsoleOutputCP(),
    };

    const want = modes.desired(.{ .in = in_mode, .out = out_mode });
    if (!SetConsoleMode(in_handle, want.in).toBool()) return error.ConsoleModeUnavailable;
    if (!SetConsoleMode(out_handle, want.out).toBool()) {
        _ = SetConsoleMode(in_handle, in_mode); // 半改的控制台比没改更糟
        return error.ConsoleModeUnavailable;
    }
    _ = SetConsoleCP(utf8_code_page);
    _ = SetConsoleOutputCP(utf8_code_page);

    active = saved;
    if (!handler_installed) {
        _ = SetConsoleCtrlHandler(ctrlHandler, .fromBool(true));
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
    if (!GetConsoleScreenBufferInfo(std.Io.File.stdout().handle, &info).toBool()) return null;
    const cols = @as(i32, info.srWindow.Right) - info.srWindow.Left + 1;
    const rows = @as(i32, info.srWindow.Bottom) - info.srWindow.Top + 1;
    if (cols <= 0 or rows <= 0) return null;
    return .{ .cols = @intCast(cols), .rows = @intCast(rows) };
}

// --- Win32 -------------------------------------------------------------------
//
// `SMALL_RECT` 不在 `std.os.windows` 里,自己声明。`COORD` 在。

const SmallRect = extern struct {
    Left: i16,
    Top: i16,
    Right: i16,
    Bottom: i16,
};

const ConsoleScreenBufferInfo = extern struct {
    dwSize: windows.COORD,
    dwCursorPosition: windows.COORD,
    wAttributes: u16,
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
