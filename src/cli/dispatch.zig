//! Top-level subcommand routing.
const std = @import("std");
const Cli = @import("cli.zig");

pub const TopCommand = enum {
    server,
    key,
    memory,
    fact,
    workspace,
    session,
    exec,
    run,
    job,
    read,
    write,
    push,
    pull,
    sync,
    doctor,
    history,
    @"export",
    import,
    setup,
    daemon,
    help,
    version,
};

const usage =
    \\Terminus - agent-friendly persistent remote shell.
    \\
    \\usage: terminus <command> [...]
    \\
    \\  server     manage server resources           (add/ls/show/rm)
    \\  key        manage SSH keys                   (add/ls/rm)
    \\  memory     per-server/session agent memory   (add/ls/show/rm)
    \\  fact       machine-readable key/value facts  (set/get/ls/rm)
    \\  workspace  per-server default remote cwd     (set/show/clear)
    \\  session    manage remote tmux sessions       (new/ls/rm)
    \\  exec       run a remote command, wait for it (sync; <server> or <server>:<sess>)
    \\  run        start a tracked background job    (--name; needs tmux)
    \\  job        manage jobs                       (ls/status/read/kill/rm)
    \\  read       read session output by cursor
    \\  write      write input into a session
    \\  push       upload a file over SCP
    \\  pull       download a file over SCP
    \\  sync       recursive directory transfer      (push/pull; tar+md5)
    \\  doctor     probe remote environment capabilities
    \\  history    local audit trail of remote actions
    \\  export     dump all servers+memories+facts as JSON
    \\  import     merge an export (dry-run plan, conflict strategies)
    \\  setup      install the Terminus skill into coding agents
    \\  daemon     connection daemon lifecycle       (status/stop/run)
    \\
    \\Global flags (any position): --json (stable machine output), --db <path>.
    \\
;

pub fn dispatchCommand(ctx: *Cli.Ctx, args: []const []const u8) !void {
    if (args.len == 0) return ctx.out.print("{s}", .{usage});

    const command = std.meta.stringToEnum(TopCommand, args[0]) orelse
        Cli.fail("unknown command '{s}'; run 'terminus help'", .{args[0]});
    switch (command) {
        .version => switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .version = "0.1.6" }),
            .human => try ctx.out.print("terminus 0.1.6\n", .{}),
        },
        .help => try ctx.out.print("{s}", .{usage}),
        .server => try @import("cmd_server.zig").run(ctx, args[1..]),
        .key => try @import("cmd_key.zig").run(ctx, args[1..]),
        .memory => try @import("cmd_memory.zig").run(ctx, args[1..]),
        .fact => try @import("cmd_fact.zig").run(ctx, args[1..]),
        .workspace => try @import("cmd_workspace.zig").run(ctx, args[1..]),
        .exec => try @import("cmd_exec.zig").run(ctx, args[1..]),
        .run => try @import("cmd_job.zig").runCmd(ctx, args[1..]),
        .job => try @import("cmd_job.zig").jobCmd(ctx, args[1..]),
        .session => try @import("cmd_session.zig").run(ctx, args[1..]),
        .read => try @import("cmd_read_write.zig").run(ctx, .read, args[1..]),
        .write => try @import("cmd_read_write.zig").run(ctx, .write, args[1..]),
        .push => try @import("cmd_transfer.zig").run(ctx, .push, args[1..]),
        .pull => try @import("cmd_transfer.zig").run(ctx, .pull, args[1..]),
        .sync => try @import("cmd_sync.zig").run(ctx, args[1..]),
        .doctor => try @import("cmd_doctor.zig").run(ctx, args[1..]),
        .history => try @import("cmd_history.zig").run(ctx, args[1..]),
        .@"export" => try @import("cmd_export_import.zig").exportCmd(ctx, args[1..]),
        .import => try @import("cmd_export_import.zig").importCmd(ctx, args[1..]),
        .setup => try @import("cmd_setup.zig").run(ctx, args[1..]),
        .daemon => try @import("cmd_daemon.zig").run(ctx, args[1..]),
    }
}
