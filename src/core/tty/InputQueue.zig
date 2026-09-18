//! 本地 stdin 的后台读取线程与它的有界环形队列。
//!
//! 从 `ssh/Client.zig` 搬出来的,因为现在有两个消费者:`tunnel` 的
//! direct-tcpip 泵和交互会话的 PTY 泵。两者都需要"主循环不能阻塞在本地
//! 读上",而 Windows 上唯一能打断一个同步 stdin 读的办法是
//! `NtCancelSynchronousIoFile`,所以取消原语必须和队列待在一起。
//!
//! 本次搬移不改任何行为。

const std = @import("std");
const builtin = @import("builtin");

pub const tunnel_buffer_bytes = 16 * 1024;
pub const tunnel_queue_bytes = 64 * 1024;

pub const InputQueue = struct {
    io: std.Io,
    mutex: std.Io.Mutex = .init,
    condition: std.Io.Condition = .init,
    storage: [tunnel_queue_bytes]u8 = undefined,
    head: usize = 0,
    tail: usize = 0,
    len: usize = 0,
    done: bool = false,
    failed: bool = false,
    stop: bool = false,

    pub const Snapshot = struct {
        len: usize,
        done: bool,
        failed: bool,
    };

    pub fn init(io: std.Io) InputQueue {
        return .{ .io = io };
    }

    pub fn snapshot(self: *InputQueue) Snapshot {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return .{ .len = self.len, .done = self.done, .failed = self.failed };
    }

    /// Copy into the bounded ring. Returns false when the pump was stopped.
    pub fn put(self: *InputQueue, bytes: []const u8) bool {
        var offset: usize = 0;
        while (offset < bytes.len) {
            self.mutex.lockUncancelable(self.io);
            while (self.len == self.storage.len and !self.stop)
                self.condition.waitUncancelable(self.io, &self.mutex);
            if (self.stop) {
                self.mutex.unlock(self.io);
                return false;
            }
            const room = self.storage.len - self.len;
            const n = @min(room, bytes.len - offset);
            const first = @min(n, self.storage.len - self.tail);
            @memcpy(self.storage[self.tail .. self.tail + first], bytes[offset .. offset + first]);
            const second = n - first;
            if (second != 0)
                @memcpy(self.storage[0..second], bytes[offset + first .. offset + n]);
            self.tail = (self.tail + n) % self.storage.len;
            self.len += n;
            offset += n;
            self.condition.signal(self.io);
            self.mutex.unlock(self.io);
        }
        return true;
    }

    /// Copy the current contiguous head without removing it. The caller may
    /// hand the returned bytes to libssh2 and then call `consume` with the
    /// number the channel accepted.
    pub fn peek(self: *InputQueue, out: []u8) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.len == 0) return 0;
        const n = @min(out.len, @min(self.len, self.storage.len - self.head));
        @memcpy(out[0..n], self.storage[self.head .. self.head + n]);
        return n;
    }

    pub fn consume(self: *InputQueue, n: usize) void {
        self.mutex.lockUncancelable(self.io);
        std.debug.assert(n <= self.len);
        self.head = (self.head + n) % self.storage.len;
        self.len -= n;
        self.condition.signal(self.io);
        self.mutex.unlock(self.io);
    }

    pub fn finish(self: *InputQueue, failed: bool) void {
        self.mutex.lockUncancelable(self.io);
        self.failed = failed;
        self.done = true;
        self.condition.broadcast(self.io);
        self.mutex.unlock(self.io);
    }

    pub fn requestStop(self: *InputQueue) void {
        self.mutex.lockUncancelable(self.io);
        self.stop = true;
        self.condition.broadcast(self.io);
        self.mutex.unlock(self.io);
    }
};

/// Move local stdin into the queue, one underlying read at a time.
///
/// **`readVec` and not `readSliceShort`, and the difference is the whole of
/// whether a human can type.** `readSliceShort` is documented to return short
/// "if and only if the stream reached the end" — it loops until the destination
/// is full. With a 16 KiB destination that means a keystroke sits in the buffer
/// until 16384 more arrive, so an interactive session renders the remote's
/// banner perfectly and then accepts nothing. `readVec` returns what one read
/// produced, which for a console is the keystroke.
///
/// `tunnel` had the same latency and nobody saw it: piped stdin reaches EOF,
/// and EOF is the other way `readSliceShort` returns.
///
/// The reader's own buffer and the destination are separate arrays on purpose.
/// They used to be the same one — the reader filled it and then copied it onto
/// itself.
pub fn inputPump(queue: *InputQueue, input: std.Io.File) void {
    var read_buffer: [tunnel_buffer_bytes]u8 = undefined;
    var chunk: [tunnel_buffer_bytes]u8 = undefined;
    var reader = input.readerStreaming(queue.io, &read_buffer);
    while (true) {
        var data: [1][]u8 = .{&chunk};
        const n = reader.interface.readVec(&data) catch |err| {
            // End of stream is an ordinary finish; anything else is a failure
            // the consumer has to be able to tell apart from it.
            queue.finish(err != error.EndOfStream);
            return;
        };
        if (n == 0) continue;
        if (!queue.put(chunk[0..n])) return;
    }
}

/// Interrupt a local synchronous stdin read before joining the input thread.
/// On Windows this is the same cancellation primitive used by the threaded IO
/// backend.  POSIX builds currently do not ship this libssh2 backend; retaining
/// the branch makes the intent explicit rather than pretending an arbitrary
/// detached thread is safe.
pub fn cancelInputRead(thread: *std.Thread) void {
    if (comptime builtin.os.tag == .windows) {
        var iosb: std.os.windows.IO_STATUS_BLOCK = undefined;
        _ = std.os.windows.ntdll.NtCancelSynchronousIoFile(thread.getHandle(), null, &iosb);
    }
}

test "the input pump never waits for a full buffer" {
    // 源码契约,不是行为测试 —— 说清它能证明什么:
    //
    // 这个队列真正的行为要一个管道夹具才测得到(std 没有 pipe API,要自己
    // extern `CreatePipe`),而缺陷本身不需要那么重的东西就能锁住:它只是
    // 用错了一个读函数。用错的那个会一直循环到把目的缓冲区填满,而目的
    // 缓冲区是 16 KiB —— 于是一次按键要等后面 16383 个字节才离开本地。
    // 在真终端上的样子是:远端 banner 一字不差地画出来,然后一个字也打
    // 不进去。
    //
    // **扫描范围必须收敛到函数体。** 第一版从函数开头一直看到文件末尾,
    // 于是它读到了这段解释里写出来的那个名字,并把自己报成了缺陷 ——
    // 这棵树里同类事故已经发生过五次,`args.zig` 的注释逐条记着。所以
    // 上面这段刻意不拼写任何一个被检查的标识符。
    const source = @embedFile("InputQueue.zig");
    const start = std.mem.indexOf(u8, source, "pub fn " ++ "inputPump").?;
    // 函数体在第一个顶格 `}` 处结束。
    const end = start + std.mem.indexOf(u8, source[start..], "\n}\n").?;
    const body = source[start..end];

    const forbidden = "readSlice" ++ "Short";
    const required = "read" ++ "Vec";
    try std.testing.expect(std.mem.indexOf(u8, body, forbidden) == null);
    try std.testing.expect(std.mem.indexOf(u8, body, required) != null);
    // 范围真的收住了:否则上面两条会在整份文件上求值,而那是无意义的。
    try std.testing.expect(body.len < 1200);
}
