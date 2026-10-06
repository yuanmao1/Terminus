//! 本地终端的 raw 模式,以及它的还原保证。Windows 走控制台 API,
//! Linux/macOS 走 termios。
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

const is_windows = builtin.os.tag == .windows;

/// 进入前的全部状态。还原就是把这几项写回去。
pub const Saved = if (is_windows) WindowsSaved else PosixSaved;

const PosixSaved = struct {
    fd: std.posix.fd_t,
    termios: std.posix.termios,
};

const WindowsSaved = struct {
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
    const s = active orelse return;
    active = null; // 先清,保证并发的第二次调用是空操作
    if (comptime !is_windows) {
        // tcsetattr 是 async-signal-safe 的,信号处理器里也走这里。
        std.posix.tcsetattr(s.fd, .FLUSH, s.termios) catch {};
        return;
    }
    _ = SetConsoleMode(s.in_handle, s.in_mode);
    _ = SetConsoleMode(s.out_handle, s.out_mode);
    _ = SetConsoleCP(s.in_cp);
    _ = SetConsoleOutputCP(s.out_cp);
}

/// 关窗口时,会话循环有没有收完尾。
///
/// 两个标志而不是一个:处理器要能分辨"还没轮到"和"已经收好了",否则它
/// 只能盲等满超时。
var abort_flag: std.atomic.Value(bool) = .init(false);
var abort_done: std.atomic.Value(bool) = .init(false);

/// 一个前台子进程正占着终端,Ctrl-C 归它。
///
/// 命令层的传输子进程跑的时候,控制台已经还原成普通模式,Ctrl-C 重新是
/// 信号,同时投给我们和子进程。那一下的意思是"取消这次传输",不是"关窗口";
/// 当成后者会让会话收不了尾就被结束。
var child_owns_ctrl_c: std.atomic.Value(bool) = .init(false);

pub fn setChildOwnsCtrlC(on: bool) void {
    child_owns_ctrl_c.store(on, .release);
}

const ctrl_c_event: windows.DWORD = 0;

/// 会话循环每轮问一次。
pub fn abortRequested() bool {
    return abort_flag.load(.acquire);
}

/// 会话循环收完尾之后说一声,放处理器走。
pub fn abortHandled() void {
    abort_done.store(true, .release);
}

/// Ctrl-Break、关窗口、注销、关机。
///
/// Ctrl-C **不**走这里:进入 raw 模式后 `ENABLE_PROCESSED_INPUT` 已被清除,
/// Ctrl-C 是字节 0x03,要原样送去远端。
///
/// **这里不碰数据库。** 处理器跑在操作系统注入的另一个线程上,而主线程
/// 可能正握着 store;在这里写收据是拿一个正确性问题换另一个。所以它只
/// 置标志,让会话循环自己结清那条操作行 —— 主线程本来就知道怎么做,而且
/// 它此刻只在泵字节,腾得出手。
///
/// 等待是有必要的:返回 FALSE 会让默认处理器结束进程。关窗口时 Windows
/// 大约给五秒,三秒在里面,而且足够一次 SQLite 写。等不到就还原终端走人 ——
/// 留下一条待对账的操作行,总好过留下一个 raw 模式的终端。
fn ctrlHandler(ctrl_type: windows.DWORD) callconv(.winapi) windows.BOOL {
    // 子进程自己会收到这一下并中断;我们这边什么都不做,会话照常。
    if (ctrl_type == ctrl_c_event and child_owns_ctrl_c.load(.acquire)) return .TRUE;
    abort_flag.store(true, .release);
    var waited: u32 = 0;
    while (waited < 3000 and !abort_done.load(.acquire)) {
        Sleep(10);
        waited += 10;
    }
    restoreActive();
    return .FALSE;
}

/// POSIX 上对应 `ctrlHandler` 的三个信号:SIGHUP(关窗口)、SIGTERM、
/// 以及 raw 模式以外的 SIGINT(raw 模式下 ISIG 已清,Ctrl-C 是字节 0x03)。
///
/// 和 Windows 不同,信号处理器打断的可能正是会话循环所在的线程,所以这里
/// **不能等** `abortHandled` —— 等就是自己等自己。第一次只置标志,会话循环
/// 收完尾后自己退出;第二次说明收尾没走通,还原终端后立刻结束进程。
fn signalHandler(sig: std.posix.SIG) callconv(.c) void {
    if (sig == .INT and child_owns_ctrl_c.load(.acquire)) return;
    if (abort_flag.swap(true, .acq_rel)) {
        restoreActive();
        std.c._exit(128 + @as(c_int, @intCast(@backingInt(sig))));
    }
}

fn enterPosix() Error!void {
    const in_fd = std.Io.File.stdin().handle;
    const out_fd = std.Io.File.stdout().handle;
    // tcgetattr 对非终端失败,这就是 TTY 检测本身。
    const original = std.posix.tcgetattr(in_fd) catch return error.NotATerminal;
    _ = std.posix.tcgetattr(out_fd) catch return error.NotATerminal;

    // cfmakeraw 的同一组位,和 OpenSSH 客户端进入交互会话时一样:回显、
    // 行编辑、信号键、输出加工都交给远端 PTY。
    var raw = original;
    raw.iflag.IGNBRK = false;
    raw.iflag.BRKINT = false;
    raw.iflag.PARMRK = false;
    raw.iflag.ISTRIP = false;
    raw.iflag.INLCR = false;
    raw.iflag.IGNCR = false;
    raw.iflag.ICRNL = false;
    raw.iflag.IXON = false;
    raw.oflag.OPOST = false;
    raw.lflag.ECHO = false;
    raw.lflag.ECHONL = false;
    raw.lflag.ICANON = false;
    raw.lflag.ISIG = false;
    raw.lflag.IEXTEN = false;
    raw.cflag.CSIZE = .CS8;
    raw.cflag.PARENB = false;
    raw.cc[@backingInt(std.posix.V.MIN)] = 1;
    raw.cc[@backingInt(std.posix.V.TIME)] = 0;
    std.posix.tcsetattr(in_fd, .FLUSH, raw) catch return error.ConsoleModeUnavailable;

    active = .{ .fd = in_fd, .termios = original };
    if (!handler_installed) {
        const action: std.posix.Sigaction = .{
            .handler = .{ .handler = signalHandler },
            .mask = std.posix.sigemptyset(),
            .flags = std.posix.SA.RESTART,
        };
        std.posix.sigaction(.HUP, &action, null);
        std.posix.sigaction(.TERM, &action, null);
        std.posix.sigaction(.INT, &action, null);
        handler_installed = true;
    }
}

/// 进入 raw 模式,并登记还原状态。
pub fn enter() Error!void {
    if (comptime !is_windows) return enterPosix();
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

// **这里没有备用屏常量,而这是被真机打回来的。**
//
// 一度有一对 `ESC[?1049h` / `ESC[?1049l`,菜单和重连横幅都画在备用屏上,
// 理由是"这样在物理上不可能污染远端全屏程序的画面"。那句话是错的:
// 终端只有**一块**备用缓冲区,而远端的 `vim` 早就自己切进去了。我们的
// 进入是空操作,我们的退出把终端退回**主屏** —— 于是 vim 还在远端跑着,
// 画面却换成了登录时的 MOTD。
//
// 备用屏不是栈,谁也没办法从本地知道自己是不是已经在里面。正确的做法在
// `Pump.forceRedraw`:让画那一屏的那一头重画。

/// 立刻结束进程,**不等任何线程**。
///
/// 普通的进程退出(`ExitProcess`,`std.c.exit` 最后走的也是它)会等其他线程
/// 结束。交互会话留下的读线程停在一次控制台读上,而那次读取消不掉 ——
/// `NtCancelSynchronousIoFile` 对管道有效,对控制台无效。于是进程一直不退,
/// 直到用户随手按了一个键把那次读喂饱。
///
/// **实测对照**:`exec`(不开读线程)立刻返回,`shell` 不返回,而两者的
/// 收尾代码完全相同 —— 差的只有那个线程。
///
/// 代价是跳过 CRT 的收尾(atexit、stdio flush),所以调用方必须自己先把
/// 该刷的都刷了。这条路径上要落的盘 —— 收据和数据库 —— 在更早就已经完成。
pub fn exitNow(code: u8) noreturn {
    // POSIX 的 exit 不等其他线程,读线程随进程一起消失。
    if (comptime !is_windows) std.process.exit(code);
    _ = TerminateProcess(GetCurrentProcess(), code);
    unreachable; // TerminateProcess 不会返回给自己
}

/// 直接写到 stdout,绕开 `Cli.Ctx.out`。
///
/// **在 raw 模式下不能用 `ctx.out`。** 那条路径按行缓冲、会自己补换行,而
/// 此刻 `DISABLE_NEWLINE_AUTO_RETURN` 是开着的 —— 它画出来的东西会呈阶梯状
/// 往右下角爬。`cmd_attach_test.zig` 有一条门禁盯着这件事。
///
/// 写失败就算了:这是画给人看的东西,为它中断一次重连是本末倒置。
pub fn writeDirect(io: std.Io, bytes: []const u8) void {
    var buf: [512]u8 = undefined;
    var w = std.Io.File.stdout().writerStreaming(io, &buf);
    w.interface.writeAll(bytes) catch return;
    w.interface.flush() catch return;
}

/// 当前窗口的字符尺寸,不可读时返回 null。
///
/// 取的是 `srWindow`(可见窗口)而不是 `dwSize`(缓冲区):远端 PTY 要的是
/// 用户看得见的那块,缓冲区通常比它高得多。
pub fn size() ?Size {
    if (comptime !is_windows) {
        var ws: std.posix.winsize = undefined;
        const request: c_int = @bitCast(@as(u32, @intCast(std.posix.T.IOCGWINSZ)));
        if (std.c.ioctl(std.Io.File.stdout().handle, request, &ws) != 0) return null;
        if (ws.col == 0 or ws.row == 0) return null;
        return .{ .cols = ws.col, .rows = ws.row };
    }
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

extern "kernel32" fn Sleep(dwMilliseconds: windows.DWORD) callconv(.winapi) void;

extern "kernel32" fn GetCurrentProcess() callconv(.winapi) windows.HANDLE;
extern "kernel32" fn TerminateProcess(
    hProcess: windows.HANDLE,
    uExitCode: windows.UINT,
) callconv(.winapi) windows.BOOL;

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
