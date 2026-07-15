//! `terminus doctor <server>` — one-round environment capability probe.
//!
//! A single remote script gathers everything an agent needs to decide how
//! to work: shell, OS, tmux availability (sessions/jobs need it), paths,
//! disk space, writability. Structured output; one SSH round trip.
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
