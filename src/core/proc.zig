//! Facts about this process itself.
//!
//! One definition, because there were two: `daemon/Server.zig` needed the pid
//! for its pid file and every test fixture needs it for a scratch path, and a
//! second copy of a three-line platform switch is a second place for it to be
//! wrong.
const std = @import("std");

/// This process's id.
///
/// Used for two unrelated things, and the second is the one worth explaining.
///
/// **Scratch paths.** Fixtures name their scratch files after the *thread* that
/// made them, which is unique inside one process and recycled across them. That
/// is not a theoretical gap: killing a test run leaves orphaned children holding
/// scratch files and a daemon socket, and a later run on a recycled thread id
/// collides with them. That produced a `test.exe` frozen for two hours with its
/// CPU time stopped, and a one-off crash in a suite that passed twice either
/// side of it. The pid makes a live run and a dead one's leftovers unable to
/// name the same path.
pub fn currentPid() u32 {
    return switch (@import("builtin").os.tag) {
        .windows => std.os.windows.GetCurrentProcessId(),
        else => @intCast(std.c.getpid()),
    };
}
