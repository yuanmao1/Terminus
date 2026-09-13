//! Manifest-based remote cleanup. A dry-run binds the normalized remote
//! observations into a SHA-256 plan; apply re-reads the same facts and refuses
//! unless the caller presents that exact hash.
const std = @import("std");
const Cli = @import("cli.zig");
const Core = @import("../core/core.zig");
const fatal = Cli.fail;

pub const usage =
    \\usage: terminus cleanup <server> --manifest <cleanup.json> --dry-run [--json]
    \\       terminus cleanup <server> --manifest <cleanup.json> --apply --plan-sha <sha256> [--json]
    \\
    \\manifest schema: {"version":1,"targets":[{"path":"/absolute/path"}]}
    \\Optional expectedType and expectedBytes fields make an additional assertion.
    \\Dry-run deletes nothing. Apply re-probes every target and requires the same
    \\plan hash before deleting any target.
    \\
;

const Manifest = struct {
    version: u32,
    targets: []const Target,
};

const Target = struct {
    path: []const u8,
    expectedType: ?[]const u8 = null,
    expectedBytes: ?u64 = null,
};

const Observed = struct {
    path: []const u8,
    kind: []const u8,
    bytes: u64,
    device: u64,
    inode: u64,
    mountRoot: bool,
    inUseCheck: []const u8 = "not-claimed",
};

fn observedBefore(_: void, a: Observed, b: Observed) bool {
    return std.mem.order(u8, a.path, b.path) == .lt;
}

fn pathRefusal(path: []const u8) ?[]const u8 {
    if (path.len < 2 or path[0] != '/') return "must be an absolute path below /";
    if (path[path.len - 1] == '/' or std.mem.indexOf(u8, path, "//") != null or
        std.mem.indexOf(u8, path, "/../") != null or std.mem.endsWith(u8, path, "/..") or
        std.mem.indexOf(u8, path, "/./") != null or std.mem.endsWith(u8, path, "/."))
        return "is not canonical";
    for (path) |c| if (c < 0x20 or c == 0x7f) return "contains a control character";
    const protected = [_][]const u8{
        "/bin",  "/boot", "/dev",  "/etc", "/home", "/lib", "/lib64", "/opt", "/proc",
        "/root", "/run",  "/sbin", "/srv", "/sys",  "/tmp", "/usr",   "/var",
    };
    for (protected) |root| if (std.mem.eql(u8, path, root)) return "is a protected system root; name a child path explicitly";
    return null;
}

fn validatePath(path: []const u8) void {
    if (pathRefusal(path)) |why| fatal("cleanup target '{s}' {s}", .{ path, why });
}

fn helperArgv(ctx: *Cli.Ctx, executor: Core.Executor, argv: []const []const u8, deadline_ms: u64) !Core.supervisor.Observed {
    const frame = Core.supervisor.wire.encodeRun(ctx.arena, argv, deadline_ms, 1_000) catch |err|
        fatal("cannot encode cleanup probe: {s}", .{@errorName(err)});
    var reader: std.Io.Reader = .fixed(frame);
    var accepted: Core.Ssh.Accepted = .{};
    var retained: Core.Ssh.Retained = .{};
    const result = executor.execRetained(
        ctx.arena,
        try Core.supervisor.guardedRemoteHelperCommand(ctx.arena),
        .{ .source = &reader, .accepted = &accepted },
        &retained,
    ) catch |err| fatal("cleanup probe transport failed after {d} request byte(s): {s} ({s})", .{
        accepted.bytes, executor.errorMessage(), @errorName(err),
    });
    const observed = Core.supervisor.parseHelper(ctx.arena, result.stdout, deadline_ms) catch |err|
        fatal("cleanup probe returned incomplete helper evidence: {s}", .{@errorName(err)});
    if (observed.ending.shellStatus() != 0)
        fatal("cleanup probe failed: {s}", .{observed.stderr});
    return observed;
}

fn oneLine(bytes: []const u8) []const u8 {
    return std.mem.trim(u8, bytes, " \t\r\n");
}

fn observeTarget(ctx: *Cli.Ctx, executor: Core.Executor, target: Target) !Observed {
    validatePath(target.path);
    const canonical_reply = try helperArgv(ctx, executor, &.{ "/usr/bin/readlink", "-f", "--", target.path }, 10_000);
    const canonical = oneLine(canonical_reply.stdout);
    if (!std.mem.eql(u8, canonical, target.path))
        fatal("cleanup target '{s}' resolves to '{s}'; symlinks and non-canonical paths are refused", .{ target.path, canonical });

    const stat_reply = try helperArgv(ctx, executor, &.{
        "/usr/bin/stat", "--printf=%d\\t%i\\t%s\\t%F\\n", "--", target.path,
    }, 10_000);
    var fields = std.mem.splitScalar(u8, oneLine(stat_reply.stdout), '\t');
    const device = std.fmt.parseInt(u64, fields.next() orelse fatal("stat omitted device for '{s}'", .{target.path}), 10) catch
        fatal("stat returned an invalid device for '{s}'", .{target.path});
    const inode = std.fmt.parseInt(u64, fields.next() orelse fatal("stat omitted inode for '{s}'", .{target.path}), 10) catch
        fatal("stat returned an invalid inode for '{s}'", .{target.path});
    const bytes = std.fmt.parseInt(u64, fields.next() orelse fatal("stat omitted size for '{s}'", .{target.path}), 10) catch
        fatal("stat returned an invalid size for '{s}'", .{target.path});
    const kind = fields.next() orelse fatal("stat omitted type for '{s}'", .{target.path});
    if (!std.mem.eql(u8, kind, "regular file") and !std.mem.eql(u8, kind, "directory"))
        fatal("cleanup refuses '{s}' because its type is '{s}', not a regular file or directory", .{ target.path, kind });
    if (target.expectedType) |expected| if (!std.mem.eql(u8, expected, kind))
        fatal("cleanup target '{s}' expected type '{s}' but observed '{s}'", .{ target.path, expected, kind });
    if (target.expectedBytes != null and !std.mem.eql(u8, kind, "regular file"))
        fatal("cleanup target '{s}' uses expectedBytes for a directory; directory stat size is not its recursive disk usage", .{target.path});
    if (target.expectedBytes) |expected| if (expected != bytes)
        fatal("cleanup target '{s}' expected {d} bytes but observed {d}", .{ target.path, expected, bytes });

    const mount_reply = try helperArgv(ctx, executor, &.{ "/usr/bin/findmnt", "-r", "-n", "-o", "TARGET" }, 10_000);
    var mounts = std.mem.splitScalar(u8, mount_reply.stdout, '\n');
    while (mounts.next()) |raw_mount| {
        const mount = oneLine(raw_mount);
        if (std.mem.eql(u8, mount, target.path) or
            (std.mem.startsWith(u8, mount, target.path) and mount.len > target.path.len and mount[target.path.len] == '/'))
            fatal("cleanup refuses '{s}' because mount point '{s}' is at or below it", .{ target.path, mount });
    }
    return .{ .path = target.path, .kind = kind, .bytes = bytes, .device = device, .inode = inode, .mountRoot = false };
}

fn planText(ctx: *Cli.Ctx, server: []const u8, observed: []const Observed) ![]const u8 {
    var writer: std.Io.Writer.Allocating = .init(ctx.arena);
    try writer.writer.print("terminus-cleanup-v1\nserver={s}\n", .{server});
    for (observed) |item| try writer.writer.print("{s}\t{d}\t{d}\t{d}\t{s}\n", .{
        item.path, item.device, item.inode, item.bytes, item.kind,
    });
    return writer.toOwnedSlice();
}

pub fn run(ctx: *Cli.Ctx, raw_args: []const []const u8) !void {
    const parsed = Cli.parseArgs(ctx, raw_args);
    if (parsed.boolean("json")) ctx.out.format = .json;
    const server_name = parsed.positional(0) orelse fatal("{s}", .{usage});
    const manifest_path = parsed.flag("manifest") orelse fatal("--manifest is required\n{s}", .{usage});
    const dry_run = parsed.boolean("dry-run");
    const apply = parsed.boolean("apply");
    if (dry_run == apply) fatal("choose exactly one of --dry-run or --apply", .{});
    const plan_sha = parsed.flag("plan-sha");
    if (apply and plan_sha == null) fatal("--apply requires the --plan-sha printed by a current dry-run", .{});
    if (dry_run and plan_sha != null) fatal("--plan-sha belongs to --apply, not --dry-run", .{});

    const raw = std.Io.Dir.cwd().readFileAlloc(ctx.io, manifest_path, ctx.arena, .limited(1 << 20)) catch
        fatal("cannot read cleanup manifest '{s}'", .{manifest_path});
    const manifest = std.json.parseFromSliceLeaky(Manifest, ctx.arena, raw, .{
        .ignore_unknown_fields = false,
        .allocate = .alloc_always,
    }) catch |err| fatal("invalid cleanup manifest: {s}", .{@errorName(err)});
    if (manifest.version != 1 or manifest.targets.len == 0 or manifest.targets.len > 100)
        fatal("cleanup manifest version must be 1 and targets must contain 1..100 entries", .{});

    var store = try Cli.openStore(ctx, &parsed);
    defer store.close();
    const resolved = Cli.resolveServer(ctx, &store, server_name);
    var conn = Cli.connectDirect(ctx, resolved.server, resolved.auth);
    defer conn.deinit();
    const executor = conn.executor();
    var observed: std.ArrayList(Observed) = .empty;
    for (manifest.targets) |target| try observed.append(ctx.arena, try observeTarget(ctx, executor, target));
    std.sort.heap(Observed, observed.items, {}, observedBefore);
    for (observed.items, 0..) |item, i| if (i > 0 and std.mem.eql(u8, observed.items[i - 1].path, item.path))
        fatal("cleanup manifest contains duplicate target '{s}'", .{item.path});
    const canonical = try planText(ctx, resolved.server.name, observed.items);
    const digest = try Core.digest.hexAlloc(ctx.arena, canonical);

    if (dry_run) return switch (ctx.out.format) {
        .json => try ctx.out.json(.{ .ok = true, .dryRun = true, .server = resolved.server.name, .planSha256 = digest, .targets = observed.items, .willDelete = false }),
        .human => {
            try ctx.out.print("dry-run plan {s} for {s}\n", .{ digest, resolved.server.name });
            for (observed.items) |item| try ctx.out.print("  {d:>12}  {s:<12}  {s}\n", .{ item.bytes, item.kind, item.path });
            try ctx.out.print("nothing deleted; apply only with --plan-sha {s}\n", .{digest});
        },
    };

    if (!std.mem.eql(u8, plan_sha.?, digest))
        fatal("cleanup plan changed or the supplied hash is wrong: expected current {s}, received {s}; nothing was deleted", .{ digest, plan_sha.? });

    var deleted: std.ArrayList([]const u8) = .empty;
    const owner = Core.Store.policy.ownerToken(&store, ctx.arena, ctx.io, ctx.now) catch |err| Cli.storeFatal(&store, err);
    for (observed.items) |item| {
        const begin = Core.execution.begin(&store, ctx.arena, ctx.io, .{
            .server_id = resolved.server.id,
            .server_name = resolved.server.name,
            .kind = .cleanup,
            .scope = .{ .kind = .path, .key = item.path },
            .mutating = true,
            .argv_redacted = try std.fmt.allocPrint(ctx.arena, "cleanup delete {s}", .{item.path}),
            .argv_sha256 = digest,
            .capability = Core.supervisor.helper_capability,
            .remote_deadline_ms = 120_000,
            .owner_token = owner,
            .now = ctx.now,
        }) catch |err| Cli.storeFatal(&store, err);
        var execution = switch (begin) {
            .ready => |ready| ready,
            .blocked => |blocker| fatal("cleanup target '{s}' is blocked by request {s}; nothing after it was attempted", .{ item.path, switch (blocker) {
                .unsettled => |op| op.request_id,
                .lease => |lease| lease.owner_request_id,
            } }),
        };
        defer execution.deinit();
        execution.connecting() catch |err| Cli.receiptFatal(execution.id(), err, "created");
        const command = try std.fmt.allocPrint(
            ctx.arena,
            "[ \"$(readlink -f -- {f})\" = {f} ] || exit 73; " ++
                "[ \"$(stat --printf='%d %i %s %F' -- {f})\" = {f} ] || exit 73; " ++
                "rm -rf -- {f}; rc=$?; [ $rc -eq 0 ] || exit $rc; [ ! -e {f} ] && [ ! -L {f} ]",
            .{
                Core.shell.word(item.path), Core.shell.word(item.path),
                Core.shell.word(item.path), Core.shell.word(try std.fmt.allocPrint(ctx.arena, "{d} {d} {d} {s}", .{ item.device, item.inode, item.bytes, item.kind })),
                Core.shell.word(item.path), Core.shell.word(item.path),
                Core.shell.word(item.path),
            },
        );
        const result = Core.execution.runCommand(&execution, executor, command, null) catch |err|
            Cli.receiptFatal(execution.id(), err, execution.status.text());
        const outcome = switch (result) {
            .ran => |ran| ran,
            .refused => fatal("cleanup target '{s}' lost its scope before submission", .{item.path}),
        };
        if (outcome.exit_code != 0 or outcome.status != .completed)
            fatal("cleanup target '{s}' was not proven deleted (request {s}, status {s}); later targets were not attempted", .{ item.path, execution.id(), outcome.status.text() });
        try deleted.append(ctx.arena, item.path);
    }
    switch (ctx.out.format) {
        .json => try ctx.out.json(.{ .ok = true, .server = resolved.server.name, .planSha256 = digest, .deleted = deleted.items }),
        .human => try ctx.out.print("deleted {d} target(s) from plan {s}\n", .{ deleted.items.len, digest }),
    }
}

test "cleanup path policy refuses roots, traversal and control bytes" {
    const t = std.testing;
    try t.expect(pathRefusal("/") != null);
    try t.expect(pathRefusal("/var") != null);
    try t.expect(pathRefusal("relative") != null);
    try t.expect(pathRefusal("/srv/app/../data") != null);
    try t.expect(pathRefusal("/srv/app\ncache") != null);
    try t.expect(pathRefusal("/srv/app/cache") == null);
}
