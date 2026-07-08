//! `terminus read` / `terminus write` — cursor-based session output
//! reading and fire-and-forget input.
//!
//! `read --from-cursor` returns output since the stored cursor and
//! advances it. `--cursor N` reads from an explicit offset (does not move
//! the stored cursor). Default shows the last `--lines N` (default 50)
//! without moving the cursor, mirroring "peek at the terminal".
const std = @import("std");
const fatal = Cli.fail;
const Cli = @import("cli.zig");
const Core = @import("../core/core.zig");
const Store = Core.Store;
const Tmux = Core.Tmux;
const fatalTmux = @import("cmd_exec.zig").fatalTmux;

const read_usage =
    \\usage: terminus read <server>:<session> [--from-cursor | --cursor N] [--lines N] [--limit BYTES] [--raw] [--json]
    \\
;
const write_usage =
    \\usage: terminus write <server>:<session> [--no-enter] -- <input...>
    \\
;

const Verb = enum { read, write };

pub fn run(ctx: *Cli.Ctx, verb: Verb, raw_args: []const []const u8) !void {
    const parsed = Cli.parseArgs(ctx, raw_args);
    if (parsed.boolean("json")) ctx.out.format = .json;

    const spec = parsed.positional(0) orelse fatal("{s}", .{if (verb == .read) read_usage else write_usage});
    const target = Cli.Target.parse(spec);
    const session_name = target.session orelse fatal("target must be <server>:<session>", .{});

    var store = try Cli.openStore(ctx, &parsed);
    defer store.close();
    const resolved = Cli.resolveServer(ctx, &store, target.server);
    const session_id = (Store.sessions.idByName(&store, resolved.server.id, session_name) catch |err|
        Cli.storeFatal(&store, err)) orelse
        fatal("unknown session '{s}'; create it with 'terminus session new {s} {s}'", .{ spec, target.server, session_name });

    var conn = Cli.connect(ctx, &parsed, resolved.server, resolved.auth);
    defer conn.deinit();
    const executor = conn.executor();

    switch (verb) {
        .write => {
            const rest = parsed.rest orelse fatal("input goes after '--'\n{s}", .{write_usage});
            if (rest.len == 0) fatal("empty input", .{});
            const input = try std.mem.join(ctx.arena, " ", rest);
            Tmux.sendKeys(executor, ctx.arena, session_name, input, parsed.boolean("no-enter")) catch |err|
                fatalTmux(err, executor, session_name);
            Store.sessions.touch(&store, session_id, ctx.now) catch |err| Cli.storeFatal(&store, err);
            switch (ctx.out.format) {
                .json => try ctx.out.json(.{ .ok = true, .action = "wrote", .session = spec }),
                .human => try ctx.out.print("wrote to '{s}'\n", .{spec}),
            }
        },
        .read => {
            const limit: i64 = if (parsed.flag("limit")) |l|
                std.fmt.parseInt(i64, l, 10) catch fatal("invalid --limit '{s}'", .{l})
            else
                1 << 20;

            var from: i64 = undefined;
            var advance = false;
            if (parsed.boolean("from-cursor")) {
                from = Store.sessions.cursor(&store, session_id) catch |err| Cli.storeFatal(&store, err);
                advance = true;
            } else if (parsed.flag("cursor")) |c_text| {
                from = std.fmt.parseInt(i64, c_text, 10) catch fatal("invalid --cursor '{s}'", .{c_text});
            } else {
                from = -1; // tail mode, resolved below
            }

            var result: Tmux.ReadResult = undefined;
            if (from >= 0) {
                result = Tmux.readLog(executor, ctx.arena, session_name, from, limit) catch |err|
                    fatalTmux(err, executor, session_name);
                // Remote log shrank (rotated/删除): restart from the top
                // rather than returning silence forever.
                if (result.log_size < from) {
                    result = Tmux.readLog(executor, ctx.arena, session_name, 0, limit) catch |err|
                        fatalTmux(err, executor, session_name);
                    from = 0;
                }
            } else {
                // Tail mode: read the last chunk and keep the final N lines.
                const lines: usize = if (parsed.flag("lines")) |l|
                    std.fmt.parseInt(usize, l, 10) catch fatal("invalid --lines '{s}'", .{l})
                else
                    50;
                const probe = Tmux.readLog(executor, ctx.arena, session_name, 0, 0) catch |err|
                    fatalTmux(err, executor, session_name);
                const window: i64 = @min(probe.log_size, limit);
                from = probe.log_size - window;
                result = Tmux.readLog(executor, ctx.arena, session_name, from, window) catch |err|
                    fatalTmux(err, executor, session_name);
                result.data = lastLines(result.data, lines);
            }

            if (advance) {
                Store.sessions.setCursor(&store, session_id, result.next_cursor, ctx.now) catch |err|
                    Cli.storeFatal(&store, err);
            }

            // Cursors are raw-byte offsets; only the displayed data is
            // cleaned. --raw exposes the untouched terminal stream.
            const data = if (parsed.boolean("raw"))
                result.data
            else
                try Tmux.stripTerminalNoise(ctx.arena, result.data);

            switch (ctx.out.format) {
                .json => try ctx.out.json(.{
                    .ok = true,
                    .session = spec,
                    .from = from,
                    .to = result.next_cursor,
                    .logSize = result.log_size,
                    .data = data,
                    .cursorAdvanced = advance,
                }),
                .human => try ctx.out.print("{s}", .{data}),
            }
        },
    }
}

fn lastLines(data: []const u8, n: usize) []const u8 {
    if (n == 0) return "";
    var count: usize = 0;
    var i = data.len;
    while (i > 0) {
        i -= 1;
        if (data[i] == '\n') {
            count += 1;
            if (count > n) return data[i + 1 ..];
        }
    }
    return data;
}

test lastLines {
    const t = std.testing;
    try t.expectEqualStrings("c\nd\n", lastLines("a\nb\nc\nd\n", 2));
    try t.expectEqualStrings("a\nb\n", lastLines("a\nb\n", 5));
}
