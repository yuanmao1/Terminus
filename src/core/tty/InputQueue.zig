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

pub fn inputPump(queue: *InputQueue, input: std.Io.File) void {
    var buffer: [tunnel_buffer_bytes]u8 = undefined;
    var reader = input.readerStreaming(queue.io, &buffer);
    while (true) {
        const n = reader.interface.readSliceShort(&buffer) catch {
            queue.finish(true);
            return;
        };
        if (n == 0) {
            queue.finish(false);
            return;
        }
        if (!queue.put(buffer[0..n])) return;
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
