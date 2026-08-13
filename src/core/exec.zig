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
    /// A programmable stand-in, so the disconnect points that decide
    /// completed/failed/indeterminate can be exercised deterministically.
    /// Those decisions are the part of the system that must never guess, and
    /// they are unreachable from a real network without unplugging a cable
    /// at exactly the right microsecond.
    scripted: *Scripted,

    pub fn exec(e: Executor, arena: Allocator, command: []const u8) Ssh.ExecError!Ssh.ExecResult {
        return switch (e) {
            .direct => |client| client.exec(arena, command),
            .daemon => |client| client.exec(arena, command),
            .scripted => |client| client.exec(arena, command),
        };
    }

    pub fn errorMessage(e: Executor) []const u8 {
        return switch (e) {
            .direct => |client| client.errorMessage(),
            .daemon => |client| client.errorMessage(),
            .scripted => |client| client.errorMessage(),
        };
    }
};

/// Replays a fixed sequence of results, one per `exec` call.
pub const Scripted = struct {
    pub const Step = union(enum) {
        /// The remote answered.
        reply: Ssh.ExecResult,
        /// The transport broke. Which state the attempt was in when this
        /// happens is exactly what decides failed vs indeterminate.
        transport_error: Ssh.ExecError,
    };

    steps: []const Step,
    index: usize = 0,
    last_error: []const u8 = "scripted transport failure",
    /// Commands seen so far, so a test can assert what was actually sent.
    seen: std.ArrayList([]const u8) = .empty,
    arena: Allocator,

    pub fn init(arena: Allocator, steps: []const Step) Scripted {
        return .{ .steps = steps, .arena = arena };
    }

    pub fn executor(s: *Scripted) Executor {
        return .{ .scripted = s };
    }

    pub fn exec(s: *Scripted, arena: Allocator, command: []const u8) Ssh.ExecError!Ssh.ExecResult {
        s.seen.append(s.arena, s.arena.dupe(u8, command) catch command) catch {};
        if (s.index >= s.steps.len) return error.ExecFailed;
        const step = s.steps[s.index];
        s.index += 1;
        return switch (step) {
            .reply => |r| .{
                .exit_code = r.exit_code,
                .stdout = arena.dupe(u8, r.stdout) catch return error.OutOfMemory,
                .stderr = arena.dupe(u8, r.stderr) catch return error.OutOfMemory,
            },
            .transport_error => |err| err,
        };
    }

    pub fn errorMessage(s: *const Scripted) []const u8 {
        return s.last_error;
    }
};
