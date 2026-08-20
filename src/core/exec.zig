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

    /// `exec`, with local bytes streamed to the command's standard input.
    ///
    /// `taken` is filled whether this succeeds or fails: it is the count the
    /// channel accepted and the digest of exactly those bytes, and it is what
    /// the terminal receipt records.
    pub fn execWithStdin(
        e: Executor,
        arena: Allocator,
        command: []const u8,
        source: *std.Io.Reader,
        taken: *Ssh.Accepted,
    ) (Ssh.ExecError || Ssh.InputError)!Ssh.ExecResult {
        return switch (e) {
            .direct => |client| client.execWithStdin(arena, command, source, taken),
            // The daemon protocol carries a command and an answer and nothing
            // else — there is no third channel to stream into. Refused rather
            // than run without its input: a command that reads stdin and is
            // handed an immediate EOF reports success having done nothing. The
            // CLI keeps this unreachable by taking a direct connection when an
            // input source was named; this is the refusal behind that.
            .daemon => error.InputUnsupported,
            .scripted => |client| client.execWithStdin(arena, command, source, taken),
        };
    }

    pub fn errorMessage(e: Executor) []const u8 {
        return switch (e) {
            .direct => |client| client.errorMessage(),
            .daemon => |client| client.errorMessage(),
            .scripted => |client| client.errorMessage(),
        };
    }

    /// Whether this transport has a channel for the command's standard input.
    ///
    /// Asked *before* the scope guard binds, so a transport that cannot carry
    /// the input refuses with nothing sent rather than settling an attempt that
    /// never reached a host.
    pub fn carriesInput(e: Executor) bool {
        return switch (e) {
            .direct, .scripted => true,
            .daemon => false,
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

    /// How this channel treats offered input. The default takes everything;
    /// the other two are the shapes a real channel produces that no test can
    /// make a real one produce on cue.
    intake: Intake = .all,
    /// Input bytes this channel accepted, so a gate can assert they arrived
    /// unchanged rather than only that a digest matched.
    input: std.ArrayList(u8) = .empty,
    /// Whether the end-of-input marker was sent. A failing send must not send
    /// it: the remote would read a truncated input as a complete one.
    input_ended: bool = false,
    /// How many times bytes were offered, so a gate can tell a single write
    /// from a loop that re-offered what a short write left behind.
    offers: usize = 0,

    /// What the scripted channel does with offered input.
    pub const Intake = union(enum) {
        /// Takes every byte offered.
        all,
        /// Takes at most this many bytes per offer, which is what a real
        /// channel does when its window is smaller than the chunk. Normal
        /// traffic, not a failure.
        at_most: usize,
        /// Takes this many bytes in total and then accepts nothing further —
        /// the failure the pump must report as an error naming what it took,
        /// rather than round down to a smaller success.
        stalls_after: u64,
    };

    const Input = struct {
        owner: *Scripted,

        fn offer(context: *anyopaque, bytes: []const u8) Ssh.InputError!usize {
            const self: *Input = @ptrCast(@alignCast(context));
            const s = self.owner;
            s.offers += 1;
            const room: usize = switch (s.intake) {
                .all => bytes.len,
                .at_most => |n| @min(n, bytes.len),
                .stalls_after => |limit| blk: {
                    const already: u64 = s.input.items.len;
                    if (already >= limit) break :blk 0;
                    break :blk @min(bytes.len, @as(usize, @intCast(limit - already)));
                },
            };
            if (room == 0) return 0; // the pump owns the rule about zero
            // A harness that could not record what it took would leave a gate
            // asserting against a lie, so it fails the pump instead.
            s.input.appendSlice(s.arena, bytes[0..room]) catch return error.InputRejected;
            return room;
        }

        fn end(context: *anyopaque) Ssh.InputError!void {
            const self: *Input = @ptrCast(@alignCast(context));
            self.owner.input_ended = true;
        }

        fn sink(self: *Input) Ssh.InputSink {
            return .{ .context = self, .on_offer = offer, .on_end = end };
        }
    };

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

    /// `exec`, after streaming `source` into this channel.
    ///
    /// The input is pumped through the same `Ssh.pumpInput` the real channel
    /// uses, so what a gate drives here is the production loop with a
    /// stand-in for the one part of it a test cannot reach. A rejected input
    /// never reaches `exec`, which is the real ordering: the write happens
    /// before the output is drained.
    pub fn execWithStdin(
        s: *Scripted,
        arena: Allocator,
        command: []const u8,
        source: *std.Io.Reader,
        taken: *Ssh.Accepted,
    ) (Ssh.ExecError || Ssh.InputError)!Ssh.ExecResult {
        var input: Input = .{ .owner = s };
        try Ssh.pumpInput(source, input.sink(), taken);
        return s.exec(arena, command);
    }

    pub fn errorMessage(s: *const Scripted) []const u8 {
        return s.last_error;
    }
};
