//! `terminus server add/ls/show/rm` — server resource management.
const std = @import("std");
const fatal = Cli.fail;
const Cli = @import("cli.zig");
const Core = @import("../core/core.zig");
const Store = Core.Store;

const usage =
    \\usage: terminus server <verb> [...]
    \\
    \\  server add    <name> --host <host> --user <user> [--port 22] [--key <keyname>] [--note ...]
    \\  server ls     [--json]
    \\  server show   <name> [--json]
    \\  server ping   <name> [--json]     connect+auth check, ~1 round trip
    \\  server rename <old-name> <new-name>
    \\  server set    <name> [--host H] [--port P] [--user U] [--key K] [--note ...]
    \\  server rm     <name> [--force]
    \\                --force confirms the cascade (memories/facts/sessions/
    \\                jobs/history). It does not, and cannot, cover an
    \\                unsettled attempt, a held lease or a resumable transfer.
    \\
;

pub fn run(ctx: *Cli.Ctx, raw_args: []const []const u8) !void {
    if (raw_args.len == 0) fatal("{s}", .{usage});
    const verb = raw_args[0];
    const parsed = Cli.parseArgs(ctx, raw_args[1..]);
    if (parsed.boolean("json")) ctx.out.format = .json;

    var store = try Cli.openStore(ctx, &parsed);
    defer store.close();

    if (std.mem.eql(u8, verb, "add")) {
        const name = parsed.positional(0) orelse fatal("{s}", .{usage});
        const host = parsed.flag("host") orelse fatal("--host is required", .{});
        const user = parsed.flag("user") orelse fatal("--user is required", .{});
        const port: u16 = if (parsed.flag("port")) |p|
            std.fmt.parseInt(u16, p, 10) catch fatal("invalid --port '{s}'", .{p})
        else
            22;
        _ = Store.servers.add(&store, .{
            .name = name,
            .host = host,
            .port = port,
            .username = user,
            .key = parsed.flag("key"),
            .note = parsed.flag("note"),
            .now = ctx.now,
        }) catch |err| switch (err) {
            error.NameTaken => fatal("server '{s}' already exists", .{name}),
            error.KeyNotFound => fatal("key '{s}' not found; add it with 'terminus key add'", .{parsed.flag("key").?}),
            else => Cli.storeFatal(&store, err),
        };
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .action = "added", .server = name }),
            .human => try ctx.out.print("added server '{s}' ({s}@{s}:{d})\n", .{ name, user, host, port }),
        }
    } else if (std.mem.eql(u8, verb, "ls")) {
        const list = Store.servers.list(&store, ctx.arena) catch |err| Cli.storeFatal(&store, err);
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .servers = list }),
            .human => {
                if (list.len == 0) return ctx.out.print("no servers. add one with 'terminus server add'\n", .{});
                for (list) |s| {
                    try ctx.out.print("{s}  {s}@{s}:{d}  key={s}  note={s}\n", .{
                        s.name, s.username, s.host, s.port, s.key orelse "-", s.note orelse "-",
                    });
                }
            },
        }
    } else if (std.mem.eql(u8, verb, "show")) {
        const name = parsed.positional(0) orelse fatal("{s}", .{usage});
        const server = (Store.servers.getByName(&store, ctx.arena, name) catch |err|
            Cli.storeFatal(&store, err)) orelse fatal("unknown server '{s}'", .{name});
        const mems = Store.memories.list(&store, ctx.arena, .{ .server_id = server.id }, .{}) catch |err|
            Cli.storeFatal(&store, err);
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .server = server, .memories = mems }),
            .human => {
                try ctx.out.print(
                    "name:  {s}\nhost:  {s}:{d}\nuser:  {s}\nkey:   {s}\nnote:  {s}\n",
                    .{ server.name, server.host, server.port, server.username, server.key orelse "-", server.note orelse "-" },
                );
                try ctx.out.print("memories: {d}\n", .{mems.len});
                for (mems) |m| {
                    try ctx.out.print("  [{d}] {s}: {s}\n", .{ m.id, m.key orelse "-", m.content });
                }
            },
        }
    } else if (std.mem.eql(u8, verb, "ping")) {
        const name = parsed.positional(0) orelse fatal("{s}", .{usage});
        const resolved = Cli.resolveServer(ctx, &store, name);
        const started = std.Io.Timestamp.now(ctx.io, .awake);
        var conn = Cli.connect(ctx, &parsed, resolved.server, resolved.auth);
        defer conn.deinit();
        const result = conn.executor().exec(ctx.arena, "true") catch |err|
            fatal("reachable but exec failed: {s} ({s})", .{ conn.executor().errorMessage(), @errorName(err) });
        const ms: i64 = @intCast(@divTrunc(
            started.durationTo(std.Io.Timestamp.now(ctx.io, .awake)).nanoseconds,
            std.time.ns_per_ms,
        ));
        _ = result;
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{
                .ok = true,
                .server = name,
                .reachable = true,
                .latencyMs = ms,
                .transport = conn.transport,
                .daemonError = conn.daemon_error,
            }),
            .human => try ctx.out.print("'{s}' is reachable ({d} ms via {s})\n", .{ name, ms, conn.transport }),
        }
    } else if (std.mem.eql(u8, verb, "rename")) {
        const old_name = parsed.positional(0) orelse fatal("{s}", .{usage});
        const new_name = parsed.positional(1) orelse fatal("{s}", .{usage});
        const server = (Store.servers.getByName(&store, ctx.arena, old_name) catch |err|
            Cli.storeFatal(&store, err)) orelse fatal("unknown server '{s}'", .{old_name});
        Store.servers.rename(&store, server.id, new_name, ctx.now) catch |err| switch (err) {
            error.NameTaken => fatal("server '{s}' already exists", .{new_name}),
            else => Cli.storeFatal(&store, err),
        };
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .action = "renamed", .from = old_name, .to = new_name }),
            .human => try ctx.out.print("renamed '{s}' -> '{s}' (memories/facts/jobs/history follow)\n", .{ old_name, new_name }),
        }
    } else if (std.mem.eql(u8, verb, "set")) {
        const name = parsed.positional(0) orelse fatal("{s}", .{usage});
        const server = (Store.servers.getByName(&store, ctx.arena, name) catch |err|
            Cli.storeFatal(&store, err)) orelse fatal("unknown server '{s}'", .{name});
        var changes: Store.servers.Update = .{
            .host = parsed.flag("host"),
            .username = parsed.flag("user"),
            .note = parsed.flag("note"),
        };
        if (parsed.flag("port")) |p|
            changes.port = std.fmt.parseInt(u16, p, 10) catch fatal("invalid --port '{s}'", .{p});
        if (parsed.flag("key")) |key_name| {
            changes.key_id = (Store.keys.idByName(&store, key_name) catch |err|
                Cli.storeFatal(&store, err)) orelse fatal("key '{s}' not found", .{key_name});
        }
        if (changes.host == null and changes.port == null and changes.username == null and
            changes.key_id == null and changes.note == null)
            fatal("nothing to change; pass at least one of --host/--port/--user/--key/--note", .{});
        Store.servers.update(&store, server.id, changes, ctx.now) catch |err| Cli.storeFatal(&store, err);
        const updated = (Store.servers.getByName(&store, ctx.arena, name) catch |err|
            Cli.storeFatal(&store, err)).?;
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .action = "updated", .server = updated }),
            .human => try ctx.out.print("updated '{s}': {s}@{s}:{d} key={s}\n", .{
                name, updated.username, updated.host, updated.port, updated.key orelse "-",
            }),
        }
    } else if (std.mem.eql(u8, verb, "rm")) {
        const name = parsed.positional(0) orelse fatal("{s}", .{usage});
        const server = (Store.servers.getByName(&store, ctx.arena, name) catch |err|
            Cli.storeFatal(&store, err)) orelse fatal("unknown server '{s}'", .{name});
        const outcome = removeServer(&store, server.id, name, parsed.boolean("force"), ctx.now) catch |err|
            Cli.storeFatal(&store, err);
        switch (outcome) {
            .removed => switch (ctx.out.format) {
                .json => try ctx.out.json(.{ .ok = true, .action = "removed", .server = name }),
                .human => try ctx.out.print("removed server '{s}'\n", .{name}),
            },
            .vanished => Cli.failWithCode(
                "SERVER_VANISHED",
                "server '{s}' was there when its barriers were checked and gone when the delete ran; the removal was abandoned and nothing was deleted",
                .{name},
            ),
            .needs_force => |counts| Cli.failWithCode(
                "SERVER_CASCADE_NOT_CONFIRMED",
                "removing '{s}' also deletes {d} memories, {d} facts, {d} sessions, {d} jobs, {d} history entries; re-run with --force",
                .{ name, counts.memories, counts.facts, counts.sessions, counts.jobs, counts.history },
            ),
            // One sentence per barrier, naming the count and the way past it.
            // `--force` is absent from all three on purpose and is not an
            // omission the operator should try to work around: see
            // `removeServer`.
            .refused => |barrier| switch (barrier) {
                .unsettled_operations => |n| Cli.failWithCode(
                    "SERVER_HAS_UNSETTLED_OPERATIONS",
                    "refused: {d} attempt(s) on '{s}' still have an unknown remote outcome, and nothing was deleted. " ++
                        "Deleting the server would un-scope every one of them and hide them from 'terminus request ls', " ++
                        "so establish what happened first: 'terminus request ls {s}', then " ++
                        "'terminus request reconcile <request-id>' for each",
                    .{ n, name, name },
                ),
                .active_leases => |n| Cli.failWithCode(
                    "SERVER_HAS_ACTIVE_LEASES",
                    "refused: {d} lease(s) on '{s}' are still held, and nothing was deleted. " ++
                        "Deleting the server destroys them outright, so a peer session mid-change would find its claim gone " ++
                        "with no record of where it went. Wait for them to lapse — every lease carries a TTL and is swept on the next check — " ++
                        "or have the owner release them",
                    .{ n, name },
                ),
                .resumable_transfers => |n| Cli.failWithCode(
                    "SERVER_HAS_RESUMABLE_TRANSFERS",
                    "refused: {d} transfer(s) on '{s}' still depend on a hand-over to go anywhere, and nothing was deleted. " ++
                        "Every hand-over is guarded by a same-machine conjunct, so without this server row they could never be " ++
                        "taken over by anybody while going on holding their destination. Finish them, or fail them and let " ++
                        "something supersede them, first",
                    .{ n, name },
                ),
            },
        }
    } else {
        fatal("unknown verb 'server {s}'\n{s}", .{ verb, usage });
    }
}

/// What `server rm` decided, before any of it is worded.
const RmOutcome = union(enum) {
    removed,
    /// The cascade *volume* warning: how much recorded knowledge about the host
    /// goes with it. `--force` covers this and only this.
    needs_force: Store.servers.CascadeCounts,
    /// A safety barrier. Nothing covers these.
    refused: Store.servers.Barrier,
    /// The name resolved a moment ago and did not resolve inside the removal's
    /// transaction. Not folded into a success: a caller told "removed" for a
    /// server that was never deleted has been told a falsehood.
    vanished,
};

/// The whole of `server rm` bar argument parsing and wording.
///
/// A named function rather than an inline block because one property has to be
/// provable and cannot be reached through `run`: **`force` is consulted for the
/// cascade volume warning and is never handed to the store.** The three
/// barriers are decided inside `servers.remove`'s write transaction, which
/// takes no flag and has no parameter that could carry one, so the only way a
/// flag could wave one through is if this function deleted the row itself.
/// The gate calls it with `force = true` against a live barrier and checks both
/// that it refuses and that the row survives — which is what makes the sentence
/// above a fact rather than a claim.
///
/// The two kinds of loss are genuinely different, which is why one is coverable
/// and the others are not. The cascade throws away records of a host nobody
/// wants any more. A barrier means something is still *live*: an attempt whose
/// remote outcome nobody knows, a claim somebody is holding, a transfer with a
/// legal move left. The way past each of those is to establish the fact it is
/// waiting on, and no flag supplies a fact.
fn removeServer(
    store: *Store,
    server_id: i64,
    name: []const u8,
    force: bool,
    now: i64,
) Store.servers.RemoveError!RmOutcome {
    // Advisory, and read outside any transaction on purpose: it is a volume
    // warning, so a row appearing between here and the delete changes nothing
    // that matters. The numbers that *do* matter are counted inside the
    // transaction that deletes.
    const counts = try Store.servers.cascadeCounts(store, server_id);
    const total = counts.sessions + counts.memories + counts.jobs + counts.facts + counts.history;
    if (total > 0 and !force) return .{ .needs_force = counts };

    return switch (try Store.servers.remove(store, name, now)) {
        .removed => .removed,
        .unknown_server => .vanished,
        .refused => |barrier| .{ .refused = barrier },
    };
}

/// A throwaway database for the gate below.
///
/// A local copy rather than a shared helper: the store's own gates keep theirs
/// in `gates_test.zig`, and reaching into a test file from the command layer to
/// share thirty lines would drag that file's whole suite into this build twice.
const Scratch = struct {
    io: std.Io,
    threaded: *std.Io.Threaded,
    path: [:0]u8,
    allocator: std.mem.Allocator,

    const dir = ".zig-cache/tmp";

    fn init(allocator: std.mem.Allocator, name: []const u8) !Scratch {
        const threaded = try allocator.create(std.Io.Threaded);
        threaded.* = .init(allocator, .{});
        const io = threaded.io();
        std.Io.Dir.cwd().createDirPath(io, dir) catch {};
        const path = try std.fmt.allocPrintSentinel(
            allocator,
            "{s}/{s}_{d}.db",
            .{ dir, name, std.Thread.getCurrentId() },
            0,
        );
        var s: Scratch = .{ .io = io, .threaded = threaded, .path = path, .allocator = allocator };
        s.removeFiles();
        return s;
    }

    /// WAL databases have sidecars; leaving one behind would make the next run
    /// read a mismatched log, which silently shows empty data.
    fn removeFiles(s: *Scratch) void {
        const cwd = std.Io.Dir.cwd();
        cwd.deleteFile(s.io, s.path) catch {};
        for ([_][]const u8{ "-wal", "-shm" }) |suffix| {
            const side = std.fmt.allocPrint(s.allocator, "{s}{s}", .{ s.path, suffix }) catch return;
            defer s.allocator.free(side);
            cwd.deleteFile(s.io, side) catch {};
        }
    }

    fn deinit(s: *Scratch) void {
        s.removeFiles();
        s.allocator.free(s.path);
        s.threaded.deinit();
        s.allocator.destroy(s.threaded);
    }
};

test "gate: --force covers the cascade and no barrier" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "cmd_server_force");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    const server_id = try Store.servers.add(&store, .{
        .name = "box",
        .host = "10.0.0.1",
        .port = 22,
        .username = "ubuntu",
        .now = 100,
    });

    // Something to warn about, so the two kinds of loss are both in play at
    // once and the gate is not quietly testing a server with nothing on it.
    _ = try Store.memories.add(&store, .{ .server_id = server_id }, .{
        .content = "the deploy user is ubuntu",
        .now = 100,
    });
    try t.expectEqual(
        @as(std.meta.Tag(RmOutcome), .needs_force),
        std.meta.activeTag(try removeServer(&store, server_id, "box", false, 200)),
    );

    // A lease is somebody's live claim. `--force` is the strongest thing the
    // operator can say and it does not touch this: the barrier is decided
    // inside `servers.remove`'s transaction, which takes no flag, and this
    // function does not delete anything itself.
    switch (try Store.leases.acquire(&store, arena, .{
        .server_id = server_id,
        .scope = .{ .kind = .path, .key = "/srv/app" },
        .owner_token = "peer",
        .ttl_secs = 300,
        .now = 200,
    })) {
        .acquired => {},
        .renewed, .conflict => return error.LeaseDidNotTake,
    }

    switch (try removeServer(&store, server_id, "box", true, 210)) {
        .refused => |barrier| try t.expectEqual(
            Store.servers.Barrier{ .active_leases = 1 },
            barrier,
        ),
        .removed => return error.ForceWavedThroughABarrier,
        .needs_force => return error.CascadeWarningSurvivedForce,
        .vanished => return error.ServerVanished,
    }
    // Refused means nothing went.
    try t.expect((try Store.servers.getByName(&store, arena, "box")) != null);

    // And the flag really does still do its job on the thing it is for: with
    // the barrier gone, the same forced call goes through and the cascade
    // warning it covers is not raised again. Without this half the gate would
    // also pass if `--force` had simply stopped working.
    _ = try Store.leases.release(
        &store,
        server_id,
        .{ .kind = .path, .key = "/srv/app" },
        "peer",
        .released,
        220,
    );
    try t.expectEqual(
        @as(std.meta.Tag(RmOutcome), .removed),
        std.meta.activeTag(try removeServer(&store, server_id, "box", true, 230)),
    );
    try t.expect((try Store.servers.getByName(&store, arena, "box")) == null);
}
