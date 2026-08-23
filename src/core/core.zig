pub const Store = @import("store/Store.zig");
pub const Ssh = @import("ssh/Client.zig");
pub const Tmux = @import("session/Tmux.zig");
pub const DaemonServer = @import("daemon/Server.zig");
pub const DaemonClient = @import("daemon/Client.zig");
pub const daemon_protocol = @import("daemon/protocol.zig");
pub const Executor = @import("exec.zig").Executor;
pub const script = @import("script.zig");
/// POSIX shell words: the one place a value spliced into a remote script
/// becomes an argument rather than syntax.
pub const shell = @import("shell.zig");
pub const transfer = @import("transfer.zig");
/// Incremental SHA-256: the digest a transfer is judged by, taken over a file
/// nobody can hold in memory.
pub const digest = @import("digest.zig");
pub const proc = @import("proc.zig");
pub const supervisor = @import("supervisor.zig");
/// The execution boundary: every remote side effect goes through it.
pub const execution = @import("execution.zig");
/// The lease-renewal barrier every destructive verb renews through.
pub const control = @import("control.zig");
pub const Scripted = @import("exec.zig").Scripted;

test {
    // Zig only compiles tests in files it actually analyzes. Without this,
    // a module that nothing references yet (execution.zig before the CLI is
    // rewired onto it) silently contributes zero tests.
    @import("std").testing.refAllDecls(@This());
}
