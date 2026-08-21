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

    /// `exec` under a ceiling on what is kept from the command's output, with
    /// local bytes optionally streamed to its standard input.
    ///
    /// The command path's entry point, and the reason it is not `exec`: a
    /// command's output is as large as the user's command chooses to make it,
    /// while every other caller of `exec` asks a question with a bounded answer
    /// and one of them (`transfer.pullBytes`) must hold the whole reply to verify
    /// a digest over it. See `Ssh.exec` and `Ssh.Capture`.
    ///
    /// `input.accepted` is filled whether this succeeds or fails: it is the count
    /// the channel accepted and the digest of exactly those bytes. `output` is
    /// filled on every path too, and it is what the terminal receipt records
    /// about the streams that came back.
    pub fn execRetained(
        e: Executor,
        arena: Allocator,
        command: []const u8,
        input: ?Ssh.InputStream,
        output: *Ssh.Retained,
    ) (Ssh.ExecError || Ssh.InputError)!Ssh.ExecResult {
        return switch (e) {
            .direct => |client| client.execRetained(arena, command, input, output),
            // The daemon protocol carries a command and an answer and nothing
            // else — there is no third channel to stream into. Refused rather
            // than run without its input: a command that reads stdin and is
            // handed an immediate EOF reports success having done nothing. The
            // CLI keeps this unreachable by taking a direct connection when an
            // input source was named; this is the refusal behind that.
            //
            // Without an input it serves the command path like any other
            // transport, and under the same `Ssh.output_ceiling` — applied by
            // the daemon at the channel it drained, not here. A ceiling here
            // would bound nothing: by the time a reply is in hand every byte of
            // it has already been read, and the daemon would still have held all
            // of them. The accounting comes back on the wire because it is an
            // observation of bytes this process never saw.
            .daemon => |client| if (input != null)
                error.InputUnsupported
            else
                client.execRetained(arena, command, output),
            .scripted => |client| client.execRetained(arena, command, input, output),
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
    /// The size of the pieces a reply's output is handed to the ceiling in.
    /// Defaults to the real channel's read size, so a gate gets the same
    /// boundaries `drainBoth` produces unless it asks for different ones.
    reads_of: usize = Ssh.read_bytes,

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

    /// `exec`, after streaming `source` into this channel and under the same
    /// output ceiling the real channel applies.
    ///
    /// Two production loops run here with a stand-in for the one part of each a
    /// test cannot reach. The input is pumped through `Ssh.pumpInput`, and the
    /// output goes through `Ssh.Capture` in `reads_of`-sized pieces — the
    /// channel's own read size by default, so a gate drives the same head/ring
    /// arithmetic against the same boundaries `drainBoth` produces, including a
    /// read that stops in the middle of the exit-marker line. A rejected input
    /// never reaches the reply, which is the real ordering: the write happens
    /// before the output is drained.
    pub fn execRetained(
        s: *Scripted,
        arena: Allocator,
        command: []const u8,
        input: ?Ssh.InputStream,
        output: *Ssh.Retained,
    ) (Ssh.ExecError || Ssh.InputError)!Ssh.ExecResult {
        output.* = .{};
        if (input) |in| {
            var sink: Input = .{ .owner = s };
            try Ssh.pumpInput(in.source, sink.sink(), in.accepted);
        }
        s.seen.append(s.arena, s.arena.dupe(u8, command) catch command) catch {};
        if (s.index >= s.steps.len) return error.ExecFailed;
        const step = s.steps[s.index];
        s.index += 1;
        return switch (step) {
            // Not duped onto `arena` first: a harness that copied the whole
            // fixture before the ceiling saw it would be the thing that grew,
            // and the bounded-memory gate would be measuring the harness.
            .reply => |r| Ssh.retain(arena, r, output, s.reads_of),
            .transport_error => |err| err,
        };
    }

    pub fn errorMessage(s: *const Scripted) []const u8 {
        return s.last_error;
    }
};
