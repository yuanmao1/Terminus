//! `terminus sync push/pull` — recursive directory transfer.
//!
//! Implementation: tar the tree (std.tar locally, `tar` remotely), move
//! one archive over SCP, unpack on the other side, verify with a whole-
//! archive MD5. One archive beats per-file SCP round trips by orders of
//! magnitude on many-small-file trees, and `tar` exists on any remote
//! that has a shell.
//!
//!   terminus sync push <server> <local-dir> <remote-dir> [--exclude p1,p2] [--dry-run] [--delete]
//!   terminus sync pull <server> <remote-dir> <local-dir> [--exclude p1,p2] [--dry-run]
const std = @import("std");
const fatal = Cli.fail;
const Cli = @import("cli.zig");
const Core = @import("../core/core.zig");
const Store = Core.Store;

const usage =
    \\usage: terminus sync push <server> <local-dir> <remote-dir> [--exclude p1,p2] [--dry-run] [--delete] [--json]
    \\       terminus sync pull <server> <remote-dir> <local-dir> [--exclude p1,p2] [--dry-run] [--json]
    \\
    \\  --exclude   comma-separated substring patterns (e.g. node_modules,.git)
    \\  --dry-run   list what would transfer, change nothing
    \\  --delete    (push) remove remote files not present locally
    \\
;

pub fn run(ctx: *Cli.Ctx, raw_args: []const []const u8) !void {
    if (raw_args.len == 0) fatal("{s}", .{usage});
    const verb = raw_args[0];
    const parsed = Cli.parseArgs(ctx, raw_args[1..]);
    if (parsed.boolean("json")) ctx.out.format = .json;

    const server_name = parsed.positional(0) orelse fatal("{s}", .{usage});
    const src = parsed.positional(1) orelse fatal("{s}", .{usage});
    const dst = parsed.positional(2) orelse fatal("{s}", .{usage});
    const excludes = parseExcludes(ctx, parsed.flag("exclude"));
    const dry_run = parsed.boolean("dry-run");

    var store = try Cli.openStore(ctx, &parsed);
    defer store.close();
    const resolved = Cli.resolveServer(ctx, &store, server_name);

    const started = std.Io.Timestamp.now(ctx.io, .awake);
    var client = Cli.sshConnect(resolved.server, resolved.auth);
    defer client.deinit();

    var summary: Summary = undefined;
    if (std.mem.eql(u8, verb, "push")) {
        summary = try push(ctx, &client, src, dst, excludes, dry_run, parsed.boolean("delete"));
    } else if (std.mem.eql(u8, verb, "pull")) {
        summary = try pull(ctx, &client, src, dst, excludes, dry_run);
    } else {
        fatal("unknown verb 'sync {s}'\n{s}", .{ verb, usage });
    }

    const elapsed_ns = started.durationTo(std.Io.Timestamp.now(ctx.io, .awake)).nanoseconds;
    const duration_ms: i64 = @intCast(@divTrunc(elapsed_ns, std.time.ns_per_ms));

    Store.history.add(&store, resolved.server.id, .{
        .kind = "sync",
        .detail = try std.fmt.allocPrint(ctx.arena, "{s} {s} -> {s}{s}", .{
            verb, src, dst, if (dry_run) " (dry-run)" else "",
        }),
        .exit_code = 0,
        .transport = "direct",
        .duration_ms = duration_ms,
    }, ctx.now) catch {};

    switch (ctx.out.format) {
        .json => try ctx.out.json(.{
            .ok = true,
            .action = verb,
            .server = server_name,
            .source = src,
            .destination = dst,
            .files = summary.files,
            .bytes = summary.bytes,
            .dryRun = dry_run,
            .verified = summary.verified,
            .durationMs = duration_ms,
        }),
        .human => {
            if (dry_run) {
                try ctx.out.print("dry-run: {d} files ({Bi}) would sync {s} -> {s}\n", .{
                    summary.files, summary.bytes, src, dst,
                });
            } else {
                try ctx.out.print("synced {d} files ({Bi}) {s} -> {s} in {d} ms{s}\n", .{
                    summary.files, summary.bytes,          src, dst, duration_ms,
                    if (summary.verified) " [md5 verified]" else "",
                });
            }
        },
    }
}

const Summary = struct {
    files: u64,
    bytes: u64,
    verified: bool,
};

fn parseExcludes(ctx: *Cli.Ctx, flag: ?[]const u8) []const []const u8 {
    const text = flag orelse return &.{};
    var out: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, text, ',');
    while (it.next()) |p| {
        const trimmed = std.mem.trim(u8, p, " \t");
        if (trimmed.len > 0) out.append(ctx.arena, trimmed) catch fatal("out of memory", .{});
    }
    return out.toOwnedSlice(ctx.arena) catch fatal("out of memory", .{});
}

fn excluded(path: []const u8, excludes: []const []const u8) bool {
    for (excludes) |pattern| {
        if (std.mem.indexOf(u8, path, pattern) != null) return true;
    }
    return false;
}

/// Local tree → tar in memory → SCP → remote `tar -x` → md5 verify.
fn push(
    ctx: *Cli.Ctx,
    client: *Core.Ssh,
    local_dir: []const u8,
    remote_dir: []const u8,
    excludes: []const []const u8,
    dry_run: bool,
    delete: bool,
) !Summary {
    validateRemotePath(remote_dir);
    var dir = std.Io.Dir.cwd().openDir(ctx.io, local_dir, .{ .iterate = true }) catch
        fatal("cannot open local directory '{s}'", .{local_dir});
    defer dir.close(ctx.io);

    // Build the archive in memory (dev trees; not multi-GB datasets).
    var archive: std.Io.Writer.Allocating = .init(ctx.arena);
    var tar_writer: std.tar.Writer = .{ .underlying_writer = &archive.writer };

    var files: u64 = 0;
    var bytes: u64 = 0;
    var walker = try dir.walk(ctx.arena);
    defer walker.deinit();
    while (walker.next(ctx.io) catch |err| fatal("walk failed in '{s}': {s}", .{ local_dir, @errorName(err) })) |entry| {
        if (excluded(entry.path, excludes)) continue;
        if (entry.kind != .file) continue;
        files += 1;
        const posix_path = try ctx.arena.dupe(u8, entry.path);
        std.mem.replaceScalar(u8, posix_path, '\\', '/');
        if (dry_run) {
            const stat = entry.dir.statFile(ctx.io, entry.basename, .{}) catch continue;
            bytes += stat.size;
            continue;
        }
        const file = entry.dir.openFile(ctx.io, entry.basename, .{}) catch |err|
            fatal("cannot read {s}: {s}", .{ entry.path, @errorName(err) });
        defer file.close(ctx.io);
        var read_buffer: [1 << 16]u8 = undefined;
        var reader = file.reader(ctx.io, &read_buffer);
        tar_writer.writeFile(posix_path, &reader, 0) catch |err|
            fatal("tar write failed for {s}: {s}", .{ entry.path, @errorName(err) });
        bytes += reader.getSize() catch 0;
    }
    if (dry_run) return .{ .files = files, .bytes = bytes, .verified = false };

    tar_writer.finishPedantically() catch fatal("tar finish failed", .{});
    const tar_bytes = archive.writer.buffered();

    var md5: [16]u8 = undefined;
    std.crypto.hash.Md5.hash(tar_bytes, &md5, .{});
    const md5_hex = try std.fmt.allocPrint(ctx.arena, "{x}", .{&md5});

    // Stage the archive remotely (scp, or base64-over-exec when the
    // server has no scp binary), verify its checksum, then unpack.
    const remote_tmp = try std.fmt.allocPrint(ctx.arena, "/tmp/.terminus_sync_{d}.tar", .{ctx.now});
    const remote_tmp_z = try ctx.arena.dupeZ(u8, remote_tmp);
    _ = client.scpSendBytes(ctx.io, tar_bytes, remote_tmp_z, 0o600) catch {
        Core.transfer.pushBytes(client, ctx.arena, tar_bytes, remote_tmp, 0o600) catch |err|
            fatal("upload failed (scp and exec both): {s} ({s})", .{ client.errorMessage(), @errorName(err) });
    };

    const delete_clause = if (delete)
        try std.fmt.allocPrint(ctx.arena, "rm -rf '{s}' && ", .{remote_dir})
    else
        "";
    const script = try std.fmt.allocPrint(ctx.arena,
        \\set -e
        \\actual=$(md5sum {s} | cut -d' ' -f1)
        \\[ "$actual" = "{s}" ] || {{ echo "checksum mismatch: $actual"; rm -f {s}; exit 43; }}
        \\{s}mkdir -p '{s}'
        \\tar -xf {s} -C '{s}'
        \\rm -f {s}
    , .{ remote_tmp, md5_hex, remote_tmp, delete_clause, remote_dir, remote_tmp, remote_dir, remote_tmp });
    const result = client.exec(ctx.arena, script) catch |err|
        fatal("remote unpack failed: {s} ({s})", .{ client.errorMessage(), @errorName(err) });
    if (result.exit_code == 43) fatal("transfer corrupted (md5 mismatch): {s}", .{result.stdout});
    if (result.exit_code != 0) fatal("remote unpack failed (exit {d}): {s}", .{ result.exit_code, result.stderr });

    return .{ .files = files, .bytes = bytes, .verified = true };
}

/// Remote `tar -c` → SCP down → std.tar extract → md5 verify.
fn pull(
    ctx: *Cli.Ctx,
    client: *Core.Ssh,
    remote_dir: []const u8,
    local_dir: []const u8,
    excludes: []const []const u8,
    dry_run: bool,
) !Summary {
    validateRemotePath(remote_dir);
    var exclude_args: std.ArrayList(u8) = .empty;
    for (excludes) |pattern| {
        try exclude_args.appendSlice(ctx.arena, try std.fmt.allocPrint(ctx.arena, " --exclude='*{s}*'", .{pattern}));
    }

    if (dry_run) {
        const script = try std.fmt.allocPrint(ctx.arena,
            \\[ -d '{s}' ] || exit 44
            \\cd '{s}' && find . -type f {s} | wc -l && du -sb . | cut -f1
        , .{ remote_dir, remote_dir, "" });
        const result = client.exec(ctx.arena, script) catch |err|
            fatal("probe failed: {s} ({s})", .{ client.errorMessage(), @errorName(err) });
        if (result.exit_code == 44) fatal("remote directory '{s}' does not exist", .{remote_dir});
        var lines = std.mem.splitScalar(u8, std.mem.trim(u8, result.stdout, " \n\r"), '\n');
        const files = std.fmt.parseInt(u64, std.mem.trim(u8, lines.next() orelse "0", " \r"), 10) catch 0;
        const bytes = std.fmt.parseInt(u64, std.mem.trim(u8, lines.next() orelse "0", " \r"), 10) catch 0;
        return .{ .files = files, .bytes = bytes, .verified = false };
    }

    // Remote: tar to a temp file (SCP needs a real file), report its md5.
    const remote_tmp = try std.fmt.allocPrint(ctx.arena, "/tmp/.terminus_sync_{d}.tar", .{ctx.now});
    const script = try std.fmt.allocPrint(ctx.arena,
        \\set -e
        \\[ -d '{s}' ] || exit 44
        \\tar -cf {s} -C '{s}'{s} .
        \\md5sum {s} | cut -d' ' -f1
    , .{ remote_dir, remote_tmp, remote_dir, exclude_args.items, remote_tmp });
    const result = client.exec(ctx.arena, script) catch |err|
        fatal("remote tar failed: {s} ({s})", .{ client.errorMessage(), @errorName(err) });
    if (result.exit_code == 44) fatal("remote directory '{s}' does not exist", .{remote_dir});
    if (result.exit_code != 0) fatal("remote tar failed (exit {d}): {s}", .{ result.exit_code, result.stderr });
    const remote_md5 = std.mem.trim(u8, result.stdout, " \n\r");

    const remote_tmp_z = try ctx.arena.dupeZ(u8, remote_tmp);
    const tar_bytes = client.scpRecvBytes(ctx.io, ctx.arena, remote_tmp_z) catch
        Core.transfer.pullBytes(client, ctx.arena, remote_tmp) catch |err|
            fatal("download failed (scp and exec both): {s} ({s})", .{ client.errorMessage(), @errorName(err) });
    _ = client.exec(ctx.arena, try std.fmt.allocPrint(ctx.arena, "rm -f {s}", .{remote_tmp})) catch {};

    var md5: [16]u8 = undefined;
    std.crypto.hash.Md5.hash(tar_bytes, &md5, .{});
    const local_md5 = try std.fmt.allocPrint(ctx.arena, "{x}", .{&md5});
    const verified = std.mem.eql(u8, local_md5, remote_md5);
    if (!verified) fatal("transfer corrupted: remote md5 {s} != local {s}", .{ remote_md5, local_md5 });

    std.Io.Dir.cwd().createDirPath(ctx.io, local_dir) catch |err|
        fatal("cannot create '{s}': {s}", .{ local_dir, @errorName(err) });
    var dir = std.Io.Dir.cwd().openDir(ctx.io, local_dir, .{ .iterate = true }) catch
        fatal("cannot open '{s}'", .{local_dir});
    defer dir.close(ctx.io);

    var tar_reader = std.Io.Reader.fixed(tar_bytes);
    std.tar.extract(ctx.io, dir, &tar_reader, .{}) catch |err|
        fatal("extract failed: {s}", .{@errorName(err)});

    // Count what we extracted for the summary.
    var files: u64 = 0;
    var walker = try dir.walk(ctx.arena);
    defer walker.deinit();
    while (walker.next(ctx.io) catch null) |entry| {
        if (entry.kind == .file) files += 1;
    }
    return .{ .files = files, .bytes = tar_bytes.len, .verified = true };
}

/// Remote paths land inside single-quoted shell strings.
fn validateRemotePath(path: []const u8) void {
    if (path.len == 0 or std.mem.indexOfAny(u8, path, "'\"\n`$") != null)
        fatal("remote path must not contain quotes, backticks, '$' or newlines", .{});
}
