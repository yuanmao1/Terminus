//! Command execution abstraction: the tmux/session layer runs commands
//! through this, without caring whether they go over a direct SSH
//! connection or through the local daemon's pooled connection.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Ssh = @import("ssh/Client.zig");
const DaemonClient = @import("daemon/Client.zig");

pub const Executor = union(enum) {
    direct: *Ssh,
    daemon: *DaemonClient,

    pub fn exec(e: Executor, arena: Allocator, command: []const u8) Ssh.ExecError!Ssh.ExecResult {
        return switch (e) {
            .direct => |client| client.exec(arena, command),
            .daemon => |client| client.exec(arena, command),
        };
    }

    pub fn errorMessage(e: Executor) []const u8 {
        return switch (e) {
            .direct => |client| client.errorMessage(),
            .daemon => |client| client.errorMessage(),
        };
    }
};
