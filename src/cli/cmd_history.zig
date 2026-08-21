//! `terminus history <server>` — the local record of file transfers: which
//! `push` / `pull` / `sync` ran, with what exit code and transport, when.
//!
//! **This is not the audit trail, and it used to say it was.** `exec`, `run`,
//! `job` and `write` record to the operations ledger (`operations` +
//! `receipts`, read by `terminus request ls|show`) and write no history row at
//! all, so an agent that ran an `exec` and then read `history` was shown
//! nothing and told nothing about why. `Store.history.add` has exactly two
//! production call sites — `cmd_sync.zig` and `cmd_transfer.zig` — and the
//! gate at the bottom of this file counts them, so a third verb starting or
//! either one stopping has to move a number here on purpose.
const std = @import("std");
const fatal = Cli.fail;
const Cli = @import("cli.zig");
const Core = @import("../core/core.zig");
const Store = Core.Store;

const usage =
    \\usage: terminus history <server> [--limit N] [--json]
    \\
    \\Records push/pull/sync only. For exec/run/job/write, read the operations
    \\ledger: terminus request ls <server>
    \\
;

pub fn run(ctx: *Cli.Ctx, raw_args: []const []const u8) !void {
    const parsed = Cli.parseArgs(ctx, raw_args);
    if (parsed.boolean("json")) ctx.out.format = .json;

    const server_name = parsed.positional(0) orelse fatal("{s}", .{usage});
    const limit: i64 = if (parsed.flag("limit")) |l|
        std.fmt.parseInt(i64, l, 10) catch fatal("invalid --limit '{s}'", .{l})
    else
        50;

    var store = try Cli.openStore(ctx, &parsed);
    defer store.close();
    const server = (Store.servers.getByName(&store, ctx.arena, server_name) catch |err|
        Cli.storeFatal(&store, err)) orelse fatal("unknown server '{s}'", .{server_name});

    const entries = Store.history.list(&store, ctx.arena, server.id, limit) catch |err|
        Cli.storeFatal(&store, err);

    switch (ctx.out.format) {
        .json => try ctx.out.json(.{ .ok = true, .server = server_name, .history = entries }),
        .human => {
            // The empty case is where the old wording did its damage: a caller
            // who ran `exec` and read `history` saw a bare "no history" and had
            // no way to learn the record it wanted was somewhere else.
            if (entries.len == 0) return ctx.out.print(
                "no push/pull/sync history for '{s}' (exec/run/job/write record to the operations ledger: terminus request ls {s})\n",
                .{ server_name, server_name },
            );
            for (entries) |e| {
                try ctx.out.print("[{d}] {s}  exit={?d}  via={s}  {s}\n", .{
                    e.created_at, e.kind, e.exit_code, e.transport orelse "?", e.detail,
                });
            }
        },
    }
}

/// Files allowed to write a history row, and the total number of live call
/// sites across `src/`.
///
/// Two, and the identity of the two is the point rather than the arithmetic:
/// `history` is the record of transfers, and the help text in `dispatch.zig`,
/// this file's header and `store/history.zig`'s header all say so. A fifth
/// verb that started writing history would make those three sentences wrong
/// while every test still passed, which is exactly what happened when `exec`,
/// `run`, `job` and `write` moved to the operations ledger and the sentences
/// stayed behind.
const history_writers = [_][]const u8{
    "cli/cmd_sync.zig",
    "cli/cmd_transfer.zig",
};
const history_writer_calls: usize = 2;

/// Counts `needle` on lines that are not whole-line `//` comments.
///
/// Comment-stripping is load-bearing: `cli.zig` discusses a swallowed
/// `history.add` in prose, and a byte count cannot tell an explanation from a
/// call. The needle itself is spelled in halves at the call site below so that
/// this gate does not find its own source.
fn liveOccurrences(text: []const u8, needle: []const u8) usize {
    var n: usize = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trimStart(u8, raw, " \t\r");
        if (std.mem.startsWith(u8, line, "//")) continue;
        var from: usize = 0;
        while (std.mem.indexOfPos(u8, line, from, needle)) |at| : (from = at + needle.len) n += 1;
    }
    return n;
}

fn isAllowedWriter(path: []const u8) bool {
    for (history_writers) |f| if (std.mem.eql(u8, f, path)) return true;
    return false;
}

test "history has exactly the writers its help text claims" {
    const t = std.testing;
    // Split so the literal never appears contiguously in this file.
    const needle = "Store.history." ++ "add(";

    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var threaded: std.Io.Threaded = .init(t.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var dir = try std.Io.Dir.cwd().openDir(io, "src", .{ .iterate = true });
    defer dir.close(io);
    var walker = try dir.walk(arena);
    defer walker.deinit();

    var calls: usize = 0;
    while (try walker.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.basename, ".zig")) continue;
        const path = try arena.dupe(u8, entry.path);
        std.mem.replaceScalar(u8, path, '\\', '/');
        const text = try entry.dir.readFileAlloc(io, entry.basename, arena, .limited(8 << 20));

        const here = liveOccurrences(text, needle);
        if (here != 0 and !isAllowedWriter(path)) {
            std.debug.print(
                \\
                \\src/{s}: writes a `history` row, and is not one of the verbs the
                \\help text says `history` records.
                \\
                \\`terminus history` is documented in three places as the local
                \\record of push/pull/sync, with the operations ledger
                \\(`terminus request ls`) as the audit trail. A new writer makes
                \\all three wrong. Either record to the ledger through
                \\`execution.begin` instead, or add this file to
                \\`history_writers`, raise `history_writer_calls`, and correct
                \\`dispatch.zig`'s help line, `cmd_history.zig`'s header and
                \\`store/history.zig`'s header in the same change.
                \\
            , .{path});
            return error.UnexpectedHistoryWriter;
        }
        calls += here;
    }

    t.expectEqual(history_writer_calls, calls) catch {
        std.debug.print(
            \\
            \\`history` has {d} live writer call site(s) across src/, not {d}.
            \\
            \\Fewer means a verb stopped recording transfers and the three help
            \\texts now overstate what `terminus history` shows. More means a
            \\second call site appeared inside a file that is already allowed to
            \\write one. Either way the number moves here deliberately, with the
            \\wording moved beside it.
            \\
        , .{ calls, history_writer_calls });
        return error.HistoryWriterCountMoved;
    };
}
