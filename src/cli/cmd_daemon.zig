//! `terminus daemon run/status/stop` — daemon lifecycle management.
//!
//! `run` is what the CLI spawns internally; it can also be launched by
//! hand for debugging (it stays in the foreground of that terminal).
const std = @import("std");
const fatal = Cli.fail;
const Cli = @import("cli.zig");
const Core = @import("../core/core.zig");

const usage =
    \\usage: terminus daemon <verb>
    \\
    \\  daemon status [--json]     is a daemon running? (pid)
    \\  daemon stop                ask the daemon to exit now (graceful)
    \\  daemon restart [--force]   stop then let the next call respawn; --force
    \\                             hard-kills a wedged daemon via its pidfile
    \\  daemon run                 serve in the foreground (internal; CLI spawns this)
    \\
;

pub fn run(ctx: *Cli.Ctx, raw_args: []const []const u8) !void {
    if (raw_args.len == 0) fatal("{s}", .{usage});
    const verb = raw_args[0];
    const parsed = Cli.parseArgs(ctx, raw_args[1..]);
    if (parsed.boolean("json")) ctx.out.format = .json;

    if (std.mem.eql(u8, verb, "run")) {
        // Blocks until idle-exit or stop. Any error just ends the process;
        // the CLI treats a missing daemon as "go direct".
        Core.DaemonServer.run(ctx.io, std.heap.smp_allocator, ctx.arena, ctx.environ) catch |err|
            fatal("daemon exited: {s}", .{@errorName(err)});
    } else if (std.mem.eql(u8, verb, "status")) {
        const pid = Core.DaemonClient.pingDaemon(ctx.io, ctx.arena, ctx.environ);
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .running = pid != null, .pid = pid }),
            .human => if (pid) |p|
                try ctx.out.print("daemon running (pid {d})\n", .{p})
            else
                try ctx.out.print("daemon not running\n", .{}),
        }
    } else if (std.mem.eql(u8, verb, "stop")) {
        const stopped = Core.DaemonClient.stopDaemon(ctx.io, ctx.arena, ctx.environ);
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .stopped = stopped }),
            .human => try ctx.out.print("{s}\n", .{if (stopped) "daemon stopped" else "daemon was not running"}),
        }
    } else if (std.mem.eql(u8, verb, "restart")) {
        // Graceful stop leaves respawn to the next SSH-bearing call (which
        // carries the auth material the daemon needs). --force hard-kills a
        // wedged daemon whose socket no longer answers.
        if (parsed.boolean("force")) {
            const result = Core.DaemonClient.forceKillDaemon(ctx.io, ctx.arena, ctx.environ);
            switch (ctx.out.format) {
                .json => try ctx.out.json(.{ .ok = true, .forced = true, .killed = result.killed, .pid = result.pid }),
                .human => if (result.killed)
                    try ctx.out.print("daemon force-killed (pid {?d}); next command respawns it\n", .{result.pid})
                else
                    try ctx.out.print("no daemon to kill; stale files cleared, next command respawns it\n", .{}),
            }
        } else {
            const stopped = Core.DaemonClient.stopDaemon(ctx.io, ctx.arena, ctx.environ);
            switch (ctx.out.format) {
                .json => try ctx.out.json(.{ .ok = true, .forced = false, .stopped = stopped }),
                .human => try ctx.out.print("{s}; next command respawns it\n", .{if (stopped) "daemon stopped" else "daemon was not running"}),
            }
        }
    } else {
        fatal("unknown verb 'daemon {s}'\n{s}", .{ verb, usage });
    }
}
