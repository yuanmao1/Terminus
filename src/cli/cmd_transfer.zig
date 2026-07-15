//! `terminus push/pull` — file transfer.
//!
//! Two backends:
//! * scp  — libssh2 SCP, fastest, but runs the remote `scp` binary, which
//!          minimal images and OpenSSH 9+ servers may not have.
//! * exec — chunked base64 over the exec channel; needs only a POSIX
//!          shell + base64. ~4/3 slower plus round trips, works anywhere.
//!
//! Default: try scp, fall back to exec automatically (reported in the
//! output). `--via scp|exec` pins a backend. Always direct SSH (bulk data
//! doesn't fit the daemon's line-based JSON protocol).
const std = @import("std");
const fatal = Cli.fail;
const Cli = @import("cli.zig");
const Core = @import("../core/core.zig");
const Store = Core.Store;

const usage =
    \\usage: terminus push <server> <local-path> <remote-path> [--mode 644] [--via scp|exec] [--json]
    \\       terminus pull <server> <remote-path> <local-path> [--via scp|exec] [--json]
    \\
    \\Default backend is scp with automatic fallback to exec (base64 over
    \\the command channel) when the server has no scp binary.
    \\
;

pub const Verb = enum { push, pull };

pub fn run(ctx: *Cli.Ctx, verb: Verb, raw_args: []const []const u8) !void {
    const parsed = Cli.parseArgs(ctx, raw_args);
    if (parsed.boolean("json")) ctx.out.format = .json;

    const server_name = parsed.positional(0) orelse fatal("{s}", .{usage});
    const src = parsed.positional(1) orelse fatal("{s}", .{usage});
    const dst = parsed.positional(2) orelse fatal("{s}", .{usage});
    const via = parsed.flag("via");
    if (via != null and !std.mem.eql(u8, via.?, "scp") and !std.mem.eql(u8, via.?, "exec"))
        fatal("invalid --via '{s}' (scp|exec)", .{via.?});

    var store = try Cli.openStore(ctx, &parsed);
    defer store.close();
    const resolved = Cli.resolveServer(ctx, &store, server_name);

    var client = Cli.sshConnect(resolved.server, resolved.auth);
    defer client.deinit();

    const started = std.Io.Timestamp.now(ctx.io, .awake);
    var bytes: u64 = undefined;
    var backend: []const u8 = undefined;
    switch (verb) {
        .push => {
            const mode: u32 = if (parsed.flag("mode")) |m|
                std.fmt.parseInt(u32, m, 8) catch fatal("invalid --mode '{s}' (octal, e.g. 644)", .{m})
            else
                0o644;
            const data = std.Io.Dir.cwd().readFileAlloc(ctx.io, src, ctx.arena, .limited(1 << 31)) catch
                fatal("cannot read local file '{s}'", .{src});
            bytes = data.len;
            backend = pushData(ctx, &client, data, src, dst, mode, via);
        },
        .pull => {
            const result = pullData(ctx, &client, src, dst, via);
            bytes = result.bytes;
            backend = result.backend;
            std.Io.Dir.cwd().writeFile(ctx.io, .{ .sub_path = dst, .data = result.data }) catch |err|
                fatal("cannot write local file '{s}': {s}", .{ dst, @errorName(err) });
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
        .detail = try std.fmt.allocPrint(ctx.arena, "{s} -> {s} (via {s})", .{ src, dst, backend }),
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
            .backend = backend,
            .durationMs = duration_ms,
            .mibPerSec = mib_s,
        }),
        .human => try ctx.out.print("{t} {s} -> {s}: {Bi} in {d} ms ({d:.1} MiB/s, via {s})\n", .{
            verb, src, dst, bytes, duration_ms, mib_s, backend,
        }),
    }
}

/// Returns the backend that succeeded ("scp" or "exec").
fn pushData(
    ctx: *Cli.Ctx,
    client: *Core.Ssh,
    data: []const u8,
    src: []const u8,
    dst: []const u8,
    mode: u32,
    via: ?[]const u8,
) []const u8 {
    const dst_z = ctx.arena.dupeZ(u8, dst) catch fatal("out of memory", .{});
    const want_exec = via != null and std.mem.eql(u8, via.?, "exec");
    const pinned_scp = via != null and std.mem.eql(u8, via.?, "scp");

    if (!want_exec) {
        if (client.scpSendBytes(ctx.io, data, dst_z, @intCast(mode))) |_| {
            return "scp";
        } else |err| {
            if (pinned_scp)
                fatalTransfer(err, client, src, dst);
            // Fall through to exec (server likely has no scp binary).
        }
    }
    validateRemotePath(dst);
    Core.transfer.pushBytes(client, ctx.arena, data, dst, mode) catch |err|
        fatalExecTransfer(err, client, src, dst);
    return "exec";
}

const PullResult = struct {
    data: []u8,
    bytes: u64,
    backend: []const u8,
};

fn pullData(
    ctx: *Cli.Ctx,
    client: *Core.Ssh,
    src: []const u8,
    dst: []const u8,
    via: ?[]const u8,
) PullResult {
    const src_z = ctx.arena.dupeZ(u8, src) catch fatal("out of memory", .{});
    const want_exec = via != null and std.mem.eql(u8, via.?, "exec");
    const pinned_scp = via != null and std.mem.eql(u8, via.?, "scp");

    if (!want_exec) {
        if (client.scpRecvBytes(ctx.io, ctx.arena, src_z)) |data| {
            return .{ .data = data, .bytes = data.len, .backend = "scp" };
        } else |err| {
            if (pinned_scp)
                fatalTransfer(err, client, src, dst);
        }
    }
    validateRemotePath(src);
    const data = Core.transfer.pullBytes(client, ctx.arena, src) catch |err|
        fatalExecTransfer(err, client, src, dst);
    return .{ .data = data, .bytes = data.len, .backend = "exec" };
}

/// Exec-backend remote paths land inside single-quoted shell strings.
fn validateRemotePath(path: []const u8) void {
    if (path.len == 0 or std.mem.indexOfAny(u8, path, "'\"\n`$") != null)
        fatal("remote path must not contain quotes, backticks, '$' or newlines", .{});
}

fn fatalTransfer(err: anyerror, client: *Core.Ssh, src: []const u8, dst: []const u8) noreturn {
    switch (err) {
        error.LocalFileFailed => fatal("cannot access local file ({s} -> {s})", .{ src, dst }),
        error.ChannelOpenFailed => fatal("remote refused the transfer: {s} (missing file, permission, or no scp binary — try --via exec)", .{client.errorMessage()}),
        else => fatal("transfer failed: {s} ({s})", .{ client.errorMessage(), @errorName(err) }),
    }
}

fn fatalExecTransfer(err: anyerror, client: *Core.Ssh, src: []const u8, dst: []const u8) noreturn {
    switch (err) {
        error.RemoteFileMissing => fatal("remote file '{s}' does not exist", .{src}),
        error.RemoteWriteFailed => fatal("cannot write '{s}' on the remote (permission? disk full?)", .{dst}),
        error.RemoteToolMissing => fatal("remote lacks base64 for the exec transfer fallback", .{}),
        error.ChecksumMismatch => fatal("transfer corrupted (md5 mismatch) — retry", .{}),
        else => fatal("transfer failed: {s} ({s})", .{ client.errorMessage(), @errorName(err) }),
    }
}
