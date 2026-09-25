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
/// The static tmux `server tmux` installs.
pub const tmux_dist = @import("tmux_dist.zig");
/// The remote install script shared by the helper and tmux.
pub const embedded_install = @import("embedded_install.zig");
/// Native Windows process-tree supervisor for local PowerShell execution.
/// The module is kept separate so POSIX/remote paths cannot accidentally
/// claim Windows Job Object semantics.
pub const windows_supervisor = @import("windows_supervisor.zig");
/// Closed native-audit policy and helper wire contract. This module is shared
/// with the cross-compiled helper so the host cannot silently drift from the
/// remote allowlist.
pub const audit = @import("audit.zig");
/// The execution boundary: every remote side effect goes through it.
pub const execution = @import("execution.zig");
/// The lease-renewal barrier every destructive verb renews through.
pub const control = @import("control.zig");
/// The local terminal: raw mode, its restoration guarantee, and the pump that
/// carries an interactive session. Windows-only by construction — the console
/// half has no POSIX implementation in this tree.
pub const tty = struct {
    pub const modes = @import("tty/modes.zig");
    pub const Console = @import("tty/Console.zig");
    pub const InputQueue = @import("tty/InputQueue.zig");
    pub const Pump = @import("tty/Pump.zig");
    pub const reconnect = @import("tty/reconnect.zig");
    pub const escape = @import("tty/escape.zig");
};
pub const Scripted = @import("exec.zig").Scripted;

test {
    // Zig only compiles tests in files it actually analyzes. Without this,
    // a module that nothing references yet (execution.zig before the CLI is
    // rewired onto it) silently contributes zero tests.
    @import("std").testing.refAllDecls(@This());
    // `refAllDecls` is not recursive: it reaches `tty` the namespace and stops,
    // so the modules inside it would contribute zero tests until something
    // imported them by name. Named here for that reason.
    _ = tty.modes;
    _ = tty.Console;
    _ = tty.InputQueue;
    _ = tty.Pump;
    _ = tty.reconnect;
    _ = tty.escape;
}
