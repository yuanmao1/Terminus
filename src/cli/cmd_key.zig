//! `terminus key add/ls/rm` — SSH key material management.
//! M1 stores bytes in plain form; encryption is milestone M4.
const std = @import("std");
const fatal = Cli.fail;
const Cli = @import("cli.zig");
const Core = @import("../core/core.zig");
const Store = Core.Store;

const usage =
    \\usage: terminus key <verb> [...]
    \\
    \\  key add    <name> --kind ed25519|rsa|password [--private-file <path>] [--public-file <path>] [--passphrase ...]
    \\  key ls     [--json]
    \\  key rename <old-name> <new-name>
    \\  key rm     <name>
    \\
;

const kinds = [_][]const u8{ "ed25519", "rsa", "password" };

pub fn run(ctx: *Cli.Ctx, raw_args: []const []const u8) !void {
    if (raw_args.len == 0) fatal("{s}", .{usage});
    const verb = raw_args[0];
    const parsed = Cli.parseArgs(ctx, raw_args[1..]);
    if (parsed.boolean("json")) ctx.out.format = .json;

    var store = try Cli.openStore(ctx, &parsed);
    defer store.close();

    if (std.mem.eql(u8, verb, "add")) {
        const name = parsed.positional(0) orelse fatal("{s}", .{usage});
        const kind = parsed.flag("kind") orelse fatal("--kind is required (ed25519|rsa|password)", .{});
        if (!validKind(kind)) fatal("invalid --kind '{s}' (ed25519|rsa|password)", .{kind});
        const passphrase = parsed.flag("passphrase");
        const private = try readFileFlag(ctx, &parsed, "private-file");
        const public = try readFileFlag(ctx, &parsed, "public-file");
        if (private == null and passphrase == null)
            fatal("provide --private-file (key auth) or --passphrase (password auth)", .{});
        // Reject unusable key formats at add time, not first connect: the
        // WinCNG backend wedges on OPENSSH-format keys instead of failing.
        if (private) |key_bytes| {
            const format = Core.Ssh.KeyFormat.detect(key_bytes);
            if (!format.supported())
                fatal("this private key cannot be used.\n{s}", .{Core.Ssh.KeyFormat.adviceFor(format)});
        }
        _ = Store.keys.add(&store, .{
            .name = name,
            .kind = kind,
            .private = private,
            .public = public,
            .passphrase = passphrase,
            .now = ctx.now,
        }) catch |err| switch (err) {
            error.NameTaken => fatal("key '{s}' already exists", .{name}),
            else => Cli.storeFatal(&store, err),
        };
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .action = "added", .key = name, .kind = kind }),
            .human => try ctx.out.print("added key '{s}' ({s})\n", .{ name, kind }),
        }
    } else if (std.mem.eql(u8, verb, "ls")) {
        const list = Store.keys.list(&store, ctx.arena) catch |err| Cli.storeFatal(&store, err);
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .keys = list }),
            .human => {
                if (list.len == 0) return ctx.out.print("no keys. add one with 'terminus key add'\n", .{});
                for (list) |k| {
                    try ctx.out.print("{s}  kind={s}  private={s}  passphrase={s}\n", .{
                        k.name,
                        k.kind,
                        if (k.has_private) "yes" else "no",
                        if (k.has_passphrase) "yes" else "no",
                    });
                }
            },
        }
    } else if (std.mem.eql(u8, verb, "rename")) {
        const old_name = parsed.positional(0) orelse fatal("{s}", .{usage});
        const new_name = parsed.positional(1) orelse fatal("{s}", .{usage});
        const renamed = Store.keys.rename(&store, old_name, new_name) catch |err| switch (err) {
            error.NameTaken => fatal("key '{s}' already exists", .{new_name}),
            else => Cli.storeFatal(&store, err),
        };
        if (!renamed) fatal("unknown key '{s}'", .{old_name});
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .action = "renamed", .from = old_name, .to = new_name }),
            .human => try ctx.out.print("renamed key '{s}' -> '{s}' (servers using it follow)\n", .{ old_name, new_name }),
        }
    } else if (std.mem.eql(u8, verb, "rm")) {
        const name = parsed.positional(0) orelse fatal("{s}", .{usage});
        const removed = Store.keys.remove(&store, name) catch |err| switch (err) {
            error.Constraint => fatal("key '{s}' is referenced by a server; remove the server first", .{name}),
            else => Cli.storeFatal(&store, err),
        };
        if (!removed) fatal("unknown key '{s}'", .{name});
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .action = "removed", .key = name }),
            .human => try ctx.out.print("removed key '{s}'\n", .{name}),
        }
    } else {
        fatal("unknown verb 'key {s}'\n{s}", .{ verb, usage });
    }
}

fn validKind(kind: []const u8) bool {
    for (kinds) |k| {
        if (std.mem.eql(u8, kind, k)) return true;
    }
    return false;
}

fn readFileFlag(ctx: *Cli.Ctx, parsed: *const Cli.Args.Parsed, flag: []const u8) !?[]u8 {
    const path = parsed.flag(flag) orelse return null;
    return std.Io.Dir.cwd().readFileAlloc(ctx.io, path, ctx.arena, .limited(1 << 20)) catch |err|
        fatal("cannot read {s}: {s}", .{ path, @errorName(err) });
}
