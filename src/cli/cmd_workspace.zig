//! `terminus workspace` — per-server default working directory.
//!
//! The workspace is applied automatically by `exec <server>` (plain,
//! non-session) and `run` — through `shell.cdInto`, which renders it as exactly
//! one shell word. `set` therefore validates with `shell.cwdRefusal`, the same
//! predicate `exec` uses, rather than a character blacklist of its own.
//! Session targets keep their own live cwd.
const std = @import("std");
const fatal = Cli.fail;
const Cli = @import("cli.zig");
const Core = @import("../core/core.zig");
const Store = Core.Store;

const usage =
    \\usage: terminus workspace <verb> <server> [...]
    \\
    \\  workspace set   <server> <remote-dir>
    \\  workspace show  <server> [--json]
    \\  workspace clear <server>
    \\
;

pub fn run(ctx: *Cli.Ctx, raw_args: []const []const u8) !void {
    if (raw_args.len == 0) fatal("{s}", .{usage});
    const verb = raw_args[0];
    const parsed = Cli.parseArgs(ctx, raw_args[1..]);
    if (parsed.boolean("json")) ctx.out.format = .json;

    const server_name = parsed.positional(0) orelse fatal("{s}", .{usage});
    var store = try Cli.openStore(ctx, &parsed);
    defer store.close();
    const server = (Store.servers.getByName(&store, ctx.arena, server_name) catch |err|
        Cli.storeFatal(&store, err)) orelse fatal("unknown server '{s}'", .{server_name});

    if (std.mem.eql(u8, verb, "set")) {
        const dir = parsed.positional(1) orelse fatal("{s}", .{usage});
        // The same rule `exec` applies to `--cwd`, read from the same place.
        //
        // It used to be a blacklist of its own — `'`, `"` and newline — which
        // admitted `;`, a backtick, `$`, `|` and `&`, and every one of those
        // reached remote shell text as syntax through `cd {s}`. It is now the
        // inverse: `shell.cwd` renders any directory as one shell word, so an
        // apostrophe and a space are ordinary bytes here and no longer refused,
        // and what is refused is the narrow set that was relying on the remote
        // shell expanding it. Rejecting it at `set` means the store stops
        // accumulating values `exec` will later decline.
        if (Core.shell.cwdRefusal(dir)) |why| fatal(
            "workspace '{s}' cannot be used as a working directory: {s}. Pass an absolute path, or one starting '~/'",
            .{ dir, why },
        );
        Store.servers.setCwd(&store, server.id, dir, ctx.now) catch |err| Cli.storeFatal(&store, err);
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .server = server_name, .workspace = dir }),
            .human => try ctx.out.print("workspace for '{s}' set to {s}\n", .{ server_name, dir }),
        }
    } else if (std.mem.eql(u8, verb, "show")) {
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .server = server_name, .workspace = server.cwd }),
            .human => try ctx.out.print("{s}\n", .{server.cwd orelse "(not set)"}),
        }
    } else if (std.mem.eql(u8, verb, "clear")) {
        Store.servers.setCwd(&store, server.id, null, ctx.now) catch |err| Cli.storeFatal(&store, err);
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .server = server_name, .workspace = null }),
            .human => try ctx.out.print("workspace for '{s}' cleared\n", .{server_name}),
        }
    } else {
        fatal("unknown verb 'workspace {s}'\n{s}", .{ verb, usage });
    }
}
