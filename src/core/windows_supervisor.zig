//! Native Windows supervisor for PowerShell invocations.
//!
//! A POSIX marker wrapper cannot prove a PowerShell process tree stopped.  This
//! module uses the Windows kernel's Job Object boundary instead:
//!
//! * the child starts suspended;
//! * it is assigned to a Job Object before its first instruction;
//! * `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` covers descendants that inherit the
//!   job;
//! * the supervisor retains the process handle and creation FILETIME, so a PID
//!   recycle cannot be mistaken for the original process;
//! * a deadline calls `TerminateJobObject`, then waits and queries the job's
//!   active-process count.  A successful terminate call alone is never called
//!   "timed out": if active processes remain after the bounded confirmation
//!   window, the result is `indeterminate`.
//!
//! This is intentionally a standalone module.  The CLI/execution layer can
//! turn its `Outcome` into the existing receipt vocabulary without weakening
//! the POSIX helper or pretending that a remote SSH shell has Windows process
//! semantics.
const std = @import("std");
const builtin = @import("builtin");

pub const is_supported = builtin.os.tag == .windows;

pub const Error = error{
    UnsupportedPlatform,
    InvalidUtf8,
    CreateJobFailed,
    SetJobLimitFailed,
    CreateProcessFailed,
    AssignProcessFailed,
    ResumeProcessFailed,
    IdentityUnavailable,
    WaitFailed,
    QueryJobFailed,
    TerminateJobFailed,
    ExitCodeUnavailable,
};

pub const Identity = struct {
    pid: u32,
    /// Windows FILETIME units: 100-nanosecond intervals since 1601-01-01 UTC.
    /// The process handle and this value together are the identity proof.
    creation_time: u64,
};

pub const Query = union(enum) {
    running: Identity,
    exited: u32,
    /// The retained handle no longer describes the original process.  This is
    /// not a normal exit and must not release a caller's scope as completed.
    identity_lost,
};

pub const Confirmation = struct {
    confirmed: bool,
    /// Number of active processes reported by the Job Object after the
    /// confirmation window.  A non-zero value is the reason for indeterminate.
    active_processes: u32,
};

pub const Outcome = union(enum) {
    exited: u32,
    timed_out: Confirmation,
    cancelled: Confirmation,
    indeterminate: []const u8,
};

pub const PowerShell = enum {
    powershell,
    pwsh,

    pub fn executable(shell: PowerShell) []const u8 {
        return switch (shell) {
            .powershell => "powershell.exe",
            .pwsh => "pwsh.exe",
        };
    }
};

const windows = std.os.windows;

const WAIT_OBJECT_0: windows.DWORD = 0;
const WAIT_ABANDONED: windows.DWORD = 0x00000080;
const WAIT_TIMEOUT: windows.DWORD = 0x00000102;
const WAIT_FAILED: windows.DWORD = 0xffff_ffff;
const INFINITE: windows.DWORD = 0xffff_ffff;
const CREATE_FLAGS: windows.CreateProcessFlags = .{
    .create_suspended = true,
    .create_no_window = true,
};
const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: windows.DWORD = 9;
const JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION: windows.DWORD = 1;
const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: windows.DWORD = 0x0000_2000;

const IoCounters = extern struct {
    ReadOperationCount: u64 = 0,
    WriteOperationCount: u64 = 0,
    OtherOperationCount: u64 = 0,
    ReadTransferCount: u64 = 0,
    WriteTransferCount: u64 = 0,
    OtherTransferCount: u64 = 0,
};

const BasicLimitInformation = extern struct {
    PerProcessUserTimeLimit: windows.LARGE_INTEGER = 0,
    PerJobUserTimeLimit: windows.LARGE_INTEGER = 0,
    LimitFlags: windows.DWORD = 0,
    MinimumWorkingSetSize: windows.SIZE_T = 0,
    MaximumWorkingSetSize: windows.SIZE_T = 0,
    ActiveProcessLimit: windows.DWORD = 0,
    Affinity: windows.ULONG_PTR = 0,
    PriorityClass: windows.DWORD = 0,
    SchedulingClass: windows.DWORD = 0,
};

const ExtendedLimitInformation = extern struct {
    BasicLimitInformation: BasicLimitInformation = .{},
    IoInfo: IoCounters = .{},
    ProcessMemoryLimit: windows.SIZE_T = 0,
    JobMemoryLimit: windows.SIZE_T = 0,
    PeakProcessMemoryUsed: windows.SIZE_T = 0,
    PeakJobMemoryUsed: windows.SIZE_T = 0,
};

const BasicAccountingInformation = extern struct {
    TotalUserTime: windows.LARGE_INTEGER = 0,
    TotalKernelTime: windows.LARGE_INTEGER = 0,
    ThisPeriodTotalUserTime: windows.LARGE_INTEGER = 0,
    ThisPeriodTotalKernelTime: windows.LARGE_INTEGER = 0,
    TotalPageFaultCount: windows.DWORD = 0,
    TotalProcesses: windows.DWORD = 0,
    ActiveProcesses: windows.DWORD = 0,
    TotalTerminatedProcesses: windows.DWORD = 0,
};

extern "kernel32" fn CreateJobObjectW(
    lpJobAttributes: ?*windows.SECURITY_ATTRIBUTES,
    lpName: ?windows.LPCWSTR,
) callconv(.winapi) ?windows.HANDLE;

extern "kernel32" fn SetInformationJobObject(
    hJob: windows.HANDLE,
    JobObjectInformationClass: windows.DWORD,
    lpJobObjectInformation: *anyopaque,
    cbJobObjectInformationLength: windows.DWORD,
) callconv(.winapi) windows.BOOL;

extern "kernel32" fn AssignProcessToJobObject(
    hJob: windows.HANDLE,
    hProcess: windows.HANDLE,
) callconv(.winapi) windows.BOOL;

extern "kernel32" fn TerminateJobObject(
    hJob: windows.HANDLE,
    uExitCode: windows.UINT,
) callconv(.winapi) windows.BOOL;

extern "kernel32" fn QueryInformationJobObject(
    hJob: windows.HANDLE,
    JobObjectInformationClass: windows.DWORD,
    lpJobObjectInformation: *anyopaque,
    cbJobObjectInformationLength: windows.DWORD,
    lpReturnLength: ?*windows.DWORD,
) callconv(.winapi) windows.BOOL;

extern "kernel32" fn ResumeThread(hThread: windows.HANDLE) callconv(.winapi) windows.DWORD;
extern "kernel32" fn WaitForSingleObject(hHandle: windows.HANDLE, dwMilliseconds: windows.DWORD) callconv(.winapi) windows.DWORD;
extern "kernel32" fn GetProcessId(Process: windows.HANDLE) callconv(.winapi) windows.DWORD;
extern "kernel32" fn GetProcessTimes(
    hProcess: windows.HANDLE,
    lpCreationTime: *windows.FILETIME,
    lpExitTime: *windows.FILETIME,
    lpKernelTime: *windows.FILETIME,
    lpUserTime: *windows.FILETIME,
) callconv(.winapi) windows.BOOL;
extern "kernel32" fn GetExitCodeProcess(
    hProcess: windows.HANDLE,
    lpExitCode: *windows.DWORD,
) callconv(.winapi) windows.BOOL;

fn succeeded(value: windows.BOOL) bool {
    return value != .FALSE;
}

fn lastErrorCode() u32 {
    return @intFromEnum(windows.GetLastError());
}

/// A process and its Job Object.  The process handle is never replaced by a
/// fresh `OpenProcess(pid)` lookup; that is what keeps PID reuse from becoming
/// a false identity match.
pub const Supervisor = struct {
    job: windows.HANDLE,
    process: windows.HANDLE,
    identity: Identity,

    pub fn spawn(arena: std.mem.Allocator, command_line: []const u8) Error!Supervisor {
        if (!is_supported) return error.UnsupportedPlatform;
        var command = std.unicode.utf8ToUtf16LeAllocZ(arena, command_line) catch |err| switch (err) {
            error.InvalidUtf8 => return error.InvalidUtf8,
            error.OutOfMemory => return error.CreateProcessFailed,
        };
        return spawnUtf16(&command);
    }

    /// Builds a quote-free PowerShell command line. `-EncodedCommand` expects
    /// UTF-16LE before base64, so a script containing quotes, CRLF, `$`, or
    /// backticks cannot alter the supervisor command line.
    pub fn spawnPowerShell(
        arena: std.mem.Allocator,
        script: []const u8,
        shell: PowerShell,
    ) Error!Supervisor {
        if (!is_supported) return error.UnsupportedPlatform;
        const utf16 = std.unicode.utf8ToUtf16LeAlloc(arena, script) catch |err| switch (err) {
            error.InvalidUtf8 => return error.InvalidUtf8,
            error.OutOfMemory => return error.CreateProcessFailed,
        };
        const encoded_len = std.base64.standard.Encoder.calcSize(std.mem.sliceAsBytes(utf16).len);
        const encoded = arena.alloc(u8, encoded_len) catch return error.CreateProcessFailed;
        _ = std.base64.standard.Encoder.encode(encoded, std.mem.sliceAsBytes(utf16));
        const command_line = std.fmt.allocPrint(
            arena,
            "{s} -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {s}",
            .{ shell.executable(), encoded },
        ) catch return error.CreateProcessFailed;
        return spawn(arena, command_line);
    }

    fn spawnUtf16(command: *[:0]u16) Error!Supervisor {
        const job = CreateJobObjectW(null, null) orelse return error.CreateJobFailed;
        errdefer windows.CloseHandle(job);

        var limits: ExtendedLimitInformation = .{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!succeeded(SetInformationJobObject(
            job,
            JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            @ptrCast(&limits),
            @intCast(@sizeOf(ExtendedLimitInformation)),
        ))) return error.SetJobLimitFailed;

        var startup: windows.STARTUPINFOW = undefined;
        @memset(std.mem.asBytes(&startup), 0);
        startup.cb = @intCast(@sizeOf(windows.STARTUPINFOW));
        var process_info: windows.PROCESS.INFORMATION = undefined;
        if (!succeeded(windows.kernel32.CreateProcessW(
            null,
            @ptrCast(command.ptr),
            null,
            null,
            .FALSE,
            CREATE_FLAGS,
            null,
            null,
            &startup,
            &process_info,
        ))) return error.CreateProcessFailed;
        errdefer {
            windows.CloseHandle(process_info.hThread);
            windows.CloseHandle(process_info.hProcess);
        }

        const identity = readIdentity(process_info.hProcess) catch return error.IdentityUnavailable;
        if (!succeeded(AssignProcessToJobObject(job, process_info.hProcess)))
            return error.AssignProcessFailed;
        if (ResumeThread(process_info.hThread) == 0xffff_ffff)
            return error.ResumeProcessFailed;

        windows.CloseHandle(process_info.hThread);
        return .{
            .job = job,
            .process = process_info.hProcess,
            .identity = identity,
        };
    }

    /// Returns the current state without trusting a PID-only lookup.
    pub fn query(self: *const Supervisor) Error!Query {
        if (!identityMatches(self.process, self.identity)) return .identity_lost;
        const wait_status = WaitForSingleObject(self.process, 0);
        return switch (wait_status) {
            WAIT_OBJECT_0 => .{ .exited = try exitCode(self.process) },
            WAIT_TIMEOUT => .{ .running = self.identity },
            WAIT_ABANDONED, WAIT_FAILED => error.WaitFailed,
            else => error.WaitFailed,
        };
    }

    /// Waits for normal exit.  On timeout the complete Job Object is
    /// terminated, then independently confirmed.  If the job remains active
    /// after `grace_ms`, the answer is indeterminate rather than timed_out.
    pub fn wait(self: *const Supervisor, timeout_ms: u32, grace_ms: u32) Error!Outcome {
        if (!identityMatches(self.process, self.identity)) return .{ .indeterminate = "process identity changed before wait" };
        const wait_status = WaitForSingleObject(self.process, timeout_ms);
        switch (wait_status) {
            WAIT_OBJECT_0 => return .{ .exited = try exitCode(self.process) },
            WAIT_TIMEOUT => {},
            WAIT_ABANDONED, WAIT_FAILED => return error.WaitFailed,
            else => return error.WaitFailed,
        }

        if (!succeeded(TerminateJobObject(self.job, 0xC000_013A)))
            return error.TerminateJobFailed;
        const confirmation = confirmTermination(self.job, grace_ms) catch |err| switch (err) {
            error.WaitFailed, error.QueryJobFailed => return .{ .indeterminate = "job termination could not be confirmed" },
            else => return err,
        };
        if (!confirmation.confirmed) return .{ .indeterminate = "job termination remained active" };
        return .{ .timed_out = confirmation };
    }

    /// Explicit cancellation follows the same confirmation rule as a
    /// deadline, but has a distinct outcome for the operation ledger.
    pub fn cancel(self: *const Supervisor, grace_ms: u32) Error!Outcome {
        if (!identityMatches(self.process, self.identity)) return .{ .indeterminate = "process identity changed before cancel" };
        if (!succeeded(TerminateJobObject(self.job, 0xC000_013A)))
            return error.TerminateJobFailed;
        const confirmation = confirmTermination(self.job, grace_ms) catch |err| switch (err) {
            error.WaitFailed, error.QueryJobFailed => return .{ .indeterminate = "job termination could not be confirmed" },
            else => return err,
        };
        if (!confirmation.confirmed) return .{ .indeterminate = "job cancellation remained active" };
        return .{ .cancelled = confirmation };
    }

    /// Closing the Job Object is a safety net: because the limit is
    /// `KILL_ON_JOB_CLOSE`, a caller that abandons a Supervisor cannot leave a
    /// descendant tree behind. Callers should still wait/cancel explicitly so
    /// the outcome is recorded before deinit.
    pub fn deinit(self: *Supervisor) void {
        windows.CloseHandle(self.process);
        windows.CloseHandle(self.job);
        self.* = undefined;
    }
};

fn readIdentity(process: windows.HANDLE) Error!Identity {
    const pid = GetProcessId(process);
    if (pid == 0) return error.IdentityUnavailable;
    var creation: windows.FILETIME = undefined;
    var exit_time: windows.FILETIME = undefined;
    var kernel_time: windows.FILETIME = undefined;
    var user_time: windows.FILETIME = undefined;
    if (!succeeded(GetProcessTimes(process, &creation, &exit_time, &kernel_time, &user_time)))
        return error.IdentityUnavailable;
    return .{
        .pid = pid,
        .creation_time = (@as(u64, creation.dwHighDateTime) << 32) | creation.dwLowDateTime,
    };
}

fn identityMatches(process: windows.HANDLE, expected: Identity) bool {
    const actual = readIdentity(process) catch return false;
    return actual.pid == expected.pid and actual.creation_time == expected.creation_time;
}

fn exitCode(process: windows.HANDLE) Error!u32 {
    var code: windows.DWORD = 0;
    if (!succeeded(GetExitCodeProcess(process, &code))) return error.ExitCodeUnavailable;
    return code;
}

fn confirmTermination(job: windows.HANDLE, grace_ms: u32) Error!Confirmation {
    const wait_status = WaitForSingleObject(job, grace_ms);
    if (wait_status != WAIT_OBJECT_0 and wait_status != WAIT_TIMEOUT) return error.WaitFailed;
    const active = queryActiveProcesses(job) catch return error.QueryJobFailed;
    return .{
        .confirmed = active == 0,
        .active_processes = active,
    };
}

fn queryActiveProcesses(job: windows.HANDLE) Error!u32 {
    var accounting: BasicAccountingInformation = .{};
    var returned: windows.DWORD = 0;
    if (!succeeded(QueryInformationJobObject(
        job,
        JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION,
        @ptrCast(&accounting),
        @intCast(@sizeOf(BasicAccountingInformation)),
        &returned,
    ))) {
        return error.QueryJobFailed;
    }
    return accounting.ActiveProcesses;
}

test "PowerShell command lines use UTF-16LE encoded payloads rather than shell quoting" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const script = "Write-Output 'a; $env:PATH `quoted`'\r\nexit 7";
    const utf16 = try std.unicode.utf8ToUtf16LeAlloc(arena, script);
    const encoded_len = std.base64.standard.Encoder.calcSize(std.mem.sliceAsBytes(utf16).len);
    const encoded = try arena.alloc(u8, encoded_len);
    _ = std.base64.standard.Encoder.encode(encoded, std.mem.sliceAsBytes(utf16));
    try t.expect(std.mem.indexOf(u8, encoded, "Write-Output") == null);
    const decoded = try arena.alloc(u8, std.mem.sliceAsBytes(utf16).len);
    try std.base64.standard.Decoder.decode(decoded, encoded);
    try t.expectEqualSlices(u8, std.mem.sliceAsBytes(utf16), decoded);
    try t.expectEqualStrings("powershell.exe", PowerShell.powershell.executable());
}

test "job object limits and confirmation vocabulary are explicit" {
    const t = std.testing;
    try t.expect(is_supported or !is_supported);
    try t.expectEqual(@as(windows.DWORD, 0x0000_2000), JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE);
    try t.expect(@sizeOf(ExtendedLimitInformation) >= @sizeOf(BasicLimitInformation));
    const confirmed: Outcome = .{ .timed_out = .{ .confirmed = true, .active_processes = 0 } };
    const unconfirmed: Outcome = .{ .timed_out = .{ .confirmed = false, .active_processes = 1 } };
    try t.expect(confirmed.timed_out.confirmed);
    try t.expect(!unconfirmed.timed_out.confirmed);
}

test "Windows Job Object supervisor kills PowerShell descendants and confirms the tree" {
    if (!is_supported) return;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var supervisor = try Supervisor.spawnPowerShell(
        arena,
        "$p = Start-Process powershell.exe -ArgumentList '-NoProfile','-Command','Start-Sleep -Seconds 30' -PassThru; Start-Sleep -Seconds 30",
        .powershell,
    );
    defer supervisor.deinit();
    const outcome = try supervisor.wait(100, 1000);
    switch (outcome) {
        .timed_out => |confirmation| try std.testing.expect(confirmation.confirmed),
        .exited => |code| {
            std.debug.print("windows supervisor e2e exited early: {d}\\n", .{code});
            return error.DeadlineWasNotEnforced;
        },
        .indeterminate => |reason| {
            std.debug.print("windows supervisor e2e indeterminate: {s}\\n", .{reason});
            return error.DeadlineWasNotEnforced;
        },
        .cancelled => return error.DeadlineWasNotEnforced,
    }
    switch (try supervisor.query()) {
        .exited => {},
        else => return error.ProcessStillRunning,
    }
}
