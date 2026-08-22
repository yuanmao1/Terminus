//! `terminus doctor <server>` — one-round environment capability probe.
//!
//! A single remote script gathers everything an agent needs to decide how
//! to work: shell, OS, tmux availability (sessions/jobs need it), paths,
//! disk space, writability. Structured output; one SSH round trip.
//!
//! **Why this verb opens no operation.** It makes a remote call and takes no
//! request id, which looks like the gap `sync` had and is not the same thing.
//! The ledger exists so a later session can establish whether a *change* was
//! applied — that is what `operations.zig` records and what
//! `BeginOptions.mutating` splits on — and this script applies none. It echoes
//! environment variables, asks `command -v` about eleven tools, and its only two
//! writes are zero-byte files at fixed terminus-named paths that the same shell
//! line removes. Every redirection in it goes to `/dev/null`. So there is no fact
//! about the host that a receipt would let anybody establish and that re-running
//! `doctor` would not, and no way for a second run to have a different effect
//! from the first.
//!
//! That argument is worth exactly as much as the script it is about, so the gate
//! at the bottom of this file holds the script to it: a `touch` that stopped being
//! undone, a redirection that went somewhere real, or any durable-write verb at
//! all fails the build. If this probe ever needs to change something, it needs an
//! operation first, and that gate is where the change will stop.
const std = @import("std");
const fatal = Cli.fail;
const Cli = @import("cli.zig");
const Core = @import("../core/core.zig");

const usage =
    \\usage: terminus doctor <server> [--json]
    \\
;

const probe_script =
    \\echo "shell=$SHELL"
    \\echo "os=$(uname -s 2>/dev/null || echo unknown)"
    \\echo "kernel=$(uname -r 2>/dev/null || echo unknown)"
    \\echo "distro=$(. /etc/os-release 2>/dev/null && echo $PRETTY_NAME || echo unknown)"
    \\echo "tmux=$(command -v tmux >/dev/null && tmux -V || echo missing)"
    \\echo "home=$HOME"
    \\echo "tmp_writable=$(touch /tmp/.terminus_probe 2>/dev/null && rm -f /tmp/.terminus_probe && echo yes || echo no)"
    \\echo "home_writable=$(touch $HOME/.terminus_probe 2>/dev/null && rm -f $HOME/.terminus_probe && echo yes || echo no)"
    \\echo "disk_home=$(df -h $HOME 2>/dev/null | tail -1 | awk '{print $4}' || echo unknown)"
    \\echo "nproc=$(nproc 2>/dev/null || echo unknown)"
    \\for t in node npm bun pm2 docker git python3 pip3 cargo scp base64; do
    \\  plain=$(command -v $t 2>/dev/null || echo -)
    \\  login=$(bash -ilc "command -v $t" 2>/dev/null | tail -1)
    \\  echo "tool=$t|$plain|${login:--}"
    \\done
;

pub fn run(ctx: *Cli.Ctx, raw_args: []const []const u8) !void {
    const parsed = Cli.parseArgs(ctx, raw_args);
    if (parsed.boolean("json")) ctx.out.format = .json;

    const server_name = parsed.positional(0) orelse fatal("{s}", .{usage});
    var store = try Cli.openStore(ctx, &parsed);
    const resolved = Cli.resolveServer(ctx, &store, server_name);
    const memory_keys = Core.Store.memories.keys(&store, ctx.arena, resolved.server.id) catch |err|
        Cli.storeFatal(&store, err);
    store.close();

    var conn = Cli.connect(ctx, &parsed, resolved.server, resolved.auth);
    defer conn.deinit();
    const executor = conn.executor();

    const result = executor.exec(ctx.arena, probe_script) catch |err|
        fatal("probe failed: {s} ({s})", .{ executor.errorMessage(), @errorName(err) });

    var facts: std.StringArrayHashMapUnmanaged([]const u8) = .empty;
    var tools: std.ArrayList(Tool) = .empty;
    var lines = std.mem.splitScalar(u8, result.stdout, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \r\t");
        const eq = std.mem.indexOfScalar(u8, trimmed, '=') orelse continue;
        if (std.mem.eql(u8, trimmed[0..eq], "tool")) {
            var fields = std.mem.splitScalar(u8, trimmed[eq + 1 ..], '|');
            const tool_name = fields.next() orelse continue;
            const plain = fields.next() orelse "-";
            const login = fields.next() orelse "-";
            try tools.append(ctx.arena, .{
                .name = tool_name,
                .plain = if (std.mem.eql(u8, plain, "-")) null else plain,
                .login = if (std.mem.eql(u8, login, "-")) null else login,
            });
            continue;
        }
        try facts.put(ctx.arena, trimmed[0..eq], trimmed[eq + 1 ..]);
    }

    // The single most common remote gotcha: a tool that exists for humans
    // but not for plain SSH exec. Surface it and the fix.
    var login_only: std.ArrayList([]const u8) = .empty;
    for (tools.items) |t| {
        if (t.plain == null and t.login != null) try login_only.append(ctx.arena, t.name);
    }

    const tmux_version = facts.get("tmux") orelse "missing";
    const has_tmux = !std.mem.eql(u8, tmux_version, "missing");

    switch (ctx.out.format) {
        .json => try ctx.out.json(.{
            .ok = true,
            .server = server_name,
            .workspace = resolved.server.cwd,
            .shell = facts.get("shell") orelse "unknown",
            .os = facts.get("os") orelse "unknown",
            .kernel = facts.get("kernel") orelse "unknown",
            .distro = facts.get("distro") orelse "unknown",
            .tmux = tmux_version,
            .home = facts.get("home") orelse "unknown",
            .tmpWritable = std.mem.eql(u8, facts.get("tmp_writable") orelse "no", "yes"),
            .homeWritable = std.mem.eql(u8, facts.get("home_writable") orelse "no", "yes"),
            .diskFreeHome = facts.get("disk_home") orelse "unknown",
            .nproc = facts.get("nproc") orelse "unknown",
            .tools = tools.items,
            .loginOnlyTools = login_only.items,
            .hint = if (login_only.items.len > 0)
                @as(?[]const u8, "some tools are only on the interactive-shell PATH; run them with 'terminus exec <server> --login ...'")
            else
                null,
            .capabilities = .{
                .exec = true, // we just proved it
                .sessions = has_tmux,
                .jobs = has_tmux,
                .push_pull = true, // SCP needs only sshd
            },
            .transport = conn.transport,
            .daemonError = conn.daemon_error,
            .memoryKeys = memory_keys,
        }),
        .human => {
            try ctx.out.print("server:    {s} ({s})\n", .{ server_name, facts.get("distro") orelse "?" });
            try ctx.out.print("shell:     {s}\n", .{facts.get("shell") orelse "?"});
            try ctx.out.print("tmux:      {s}\n", .{tmux_version});
            try ctx.out.print("workspace: {s}\n", .{resolved.server.cwd orelse "(not set)"});
            try ctx.out.print("disk free: {s} (home)   cores: {s}\n", .{ facts.get("disk_home") orelse "?", facts.get("nproc") orelse "?" });
            try ctx.out.print("capabilities: exec=yes sessions={s} jobs={s} push/pull=yes\n", .{
                if (has_tmux) "yes" else "NO (tmux missing)",
                if (has_tmux) "yes" else "NO (tmux missing)",
            });
            for (tools.items) |t| {
                if (t.plain != null or t.login != null) {
                    try ctx.out.print("tool {s}: {s}{s}\n", .{
                        t.name,
                        t.plain orelse "(login shell only)",
                        if (t.plain == null and t.login != null) "" else "",
                    });
                }
            }
            if (login_only.items.len > 0) {
                try ctx.out.print("hint: {d} tools only on login-shell PATH; use 'exec --login' for them\n", .{login_only.items.len});
            }
            try ctx.out.print("memories:  {d} keys\n", .{memory_keys.len});
        },
    }
}

const Tool = struct {
    name: []const u8,
    plain: ?[]const u8,
    login: ?[]const u8,
};

// The claim the file header makes, held against the script it is about.
//
// Three readings, because there are three ways this probe could stop being a
// read: a write that is no longer undone, a redirection that lands on a real
// path, and a verb that changes something outright. Each is checked over the
// script text itself, and each is counted so a scan that matched nothing fails
// rather than passing over an empty region.
test "gate: doctor's probe changes nothing, which is why it opens no operation" {
    const t = std.testing;

    // 1. Every write is undone in the line that made it. Per line rather than
    //    per script: a `touch` on one line and an `rm -f` twenty lines later is
    //    not the same guarantee, because everything between them can fail.
    var writes: usize = 0;
    var lines = std.mem.splitScalar(u8, probe_script, '\n');
    while (lines.next()) |line| {
        var i: usize = 0;
        while (std.mem.indexOfPos(u8, line, i, "touch ")) |at| : (i = at + 1) {
            writes += 1;
            const rest = line[at + "touch ".len ..];
            const path = rest[0 .. std.mem.indexOfScalar(u8, rest, ' ') orelse rest.len];
            const undo = try std.fmt.allocPrint(t.allocator, "rm -f {s}", .{path});
            defer t.allocator.free(undo);
            if (std.mem.indexOf(u8, line, undo) == null) {
                std.debug.print(
                    \\
                    \\doctor's probe writes {s} and does not remove it on the same line:
                    \\
                    \\  {s}
                    \\
                    \\The header of this file says this verb needs no operation row because it
                    \\leaves nothing behind. A write that outlives the command is a change, and a
                    \\change with no request id is the gap `sync` had.
                    \\
                , .{ path, line });
                return error.ProbeWriteNotUndone;
            }
        }
    }
    try t.expectEqual(@as(usize, 2), writes);
    // Both `rm -f`s are the two above, so nothing else in here removes anything.
    try t.expectEqual(@as(usize, 2), std.mem.count(u8, probe_script, "rm -f "));

    // 2. Every redirection goes to /dev/null. This is where a probe stops being
    //    one most quietly: `2>/dev/null` and `2>/tmp/log` differ by six
    //    characters and by whether the host is left changed.
    var redirects: usize = 0;
    var at: usize = 0;
    while (std.mem.indexOfScalarPos(u8, probe_script, at, '>')) |found| : (at = found + 1) {
        redirects += 1;
        if (!std.mem.startsWith(u8, probe_script[found + 1 ..], "/dev/null")) {
            std.debug.print(
                \\
                \\doctor's probe redirects somewhere other than /dev/null:
                \\
                \\  ...{s}...
                \\
            , .{probe_script[found -| 40..@min(probe_script.len, found + 20)]});
            return error.ProbeRedirectsSomewhereReal;
        }
    }
    try t.expectEqual(@as(usize, 10), redirects);

    // 3. No durable-write verb at all. Spelled with their separators where a
    //    bare name would collide — `scp base64` in the tool list contains "cp".
    var refused: usize = 0;
    for ([_][]const u8{
        "mkdir", " mv ",  " cp ",      " ln ",  "tee ",
        "chmod", "chown", "systemctl", "kill ", "sed -i",
        ">>",    " dd ",  "apt-get",   "curl",  "wget",
    }) |verb| {
        refused += 1;
        if (std.mem.indexOf(u8, probe_script, verb) != null) {
            std.debug.print(
                \\
                \\doctor's probe contains `{s}`, so it can change the host. Give it an
                \\operation row before it does — `cmd_sync.zig` has the shape.
                \\
            , .{verb});
            return error.ProbeChangesTheHost;
        }
    }
    try t.expectEqual(@as(usize, 15), refused);

    // And the probe really is the thing being read: a script trimmed down to
    // nothing would satisfy all three readings above.
    try t.expect(std.mem.indexOf(u8, probe_script, "command -v") != null);
    try t.expect(std.mem.indexOf(u8, probe_script, "tmp_writable=") != null);
    try t.expect(probe_script.len > 512);
}
