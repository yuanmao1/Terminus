//! `terminus push/pull` — file transfer over SCP.
//!
//! SCP over the existing libssh2 session: minimal protocol overhead,
//! 1 MiB streaming chunks. Always uses a direct SSH connection (the
//! daemon's line-based JSON protocol is unsuited to bulk binary data;
//! connection reuse matters less when the transfer itself dominates).
const std = @import("std");
const fatal = Cli.fail;
const Cli = @import("cli.zig");
const Core = @import("../core/core.zig");
const Store = Core.Store;

const usage =
    \\usage: terminus push <server> <local-path> <remote-path> [--mode 644] [--json]
    \\       terminus pull <server> <remote-path> <local-path> [--json]
    \\
;

pub const Verb = enum { push, pull };

pub fn run(ctx: *Cli.Ctx, verb: Verb, raw_args: []const []const u8) !void {
    const parsed = Cli.parseArgs(ctx, raw_args);
    if (parsed.boolean("json")) ctx.out.format = .json;

    const server_name = parsed.positional(0) orelse fatal("{s}", .{usage});
    const src = parsed.positional(1) orelse fatal("{s}", .{usage});
    const dst = parsed.positional(2) orelse fatal("{s}", .{usage});

    var store = try Cli.openStore(ctx, &parsed);
    defer store.close();
    const resolved = Cli.resolveServer(ctx, &store, server_name);

    var client = Cli.sshConnect(resolved.server, resolved.auth);
    defer client.deinit();

    const started = std.Io.Timestamp.now(ctx.io, .awake);
    var bytes: u64 = undefined;
    switch (verb) {
        .push => {
            const mode = if (parsed.flag("mode")) |m|
                std.fmt.parseInt(c_int, m, 8) catch fatal("invalid --mode '{s}' (octal, e.g. 644)", .{m})
            else
                0o644;
            const remote = try ctx.arena.dupeZ(u8, dst);
            bytes = client.scpSend(ctx.io, src, remote, mode, null) catch |err|
                fatalTransfer(err, &client, src, dst);
        },
        .pull => {
            const remote = try ctx.arena.dupeZ(u8, src);
            bytes = client.scpRecv(ctx.io, remote, dst, null) catch |err|
                fatalTransfer(err, &client, src, dst);
        },
    }

    const elapsed_ns = started.durationTo(std.Io.Timestamp.now(ctx.io, .awake)).nanoseconds;
    const duration_ms: i64 = @intCast(@divTrunc(elapsed_ns, std.time.ns_per_ms));
    const mib_s: f64 = if (elapsed_ns > 0)
        @as(f64, @floatFromInt(bytes)) / (1 << 20) / (@as(f64, @floatFromInt(elapsed_ns)) / std.time.ns_per_s)
    else
        0;

    Store.history.add(&store, resolved.server.id, .{
        .kind = @tagName(verb),
        .detail = try std.fmt.allocPrint(ctx.arena, "{s} -> {s}", .{ src, dst }),
        .exit_code = 0,
        .transport = "direct",
        .duration_ms = duration_ms,
    }, ctx.now) catch {};

    switch (ctx.out.format) {
        .json => try ctx.out.json(.{
            .ok = true,
            .action = @tagName(verb),
            .server = server_name,
            .source = src,
            .destination = dst,
            .bytes = bytes,
            .durationMs = duration_ms,
            .mibPerSec = mib_s,
        }),
        .human => try ctx.out.print("{t} {s} -> {s}: {Bi} in {d} ms ({d:.1} MiB/s)\n", .{
            verb, src, dst, bytes, duration_ms, mib_s,
        }),
    }
}

fn fatalTransfer(err: anyerror, client: *Core.Ssh, src: []const u8, dst: []const u8) noreturn {
    switch (err) {
        error.LocalFileFailed => fatal("cannot access local file ({s} -> {s})", .{ src, dst }),
        error.ChannelOpenFailed => fatal("remote refused the transfer: {s} (missing file or permission?)", .{client.errorMessage()}),
        else => fatal("transfer failed: {s} ({s})", .{ client.errorMessage(), @errorName(err) }),
    }
}
