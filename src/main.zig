const std = @import("std");
const builtin = @import("builtin");

const Terminus = @import("Terminus");
const Cli = Terminus.Cli;

// Not exposed by std; needed to render UTF-8 (our own text and remote
// command output) correctly on consoles whose default codepage is not
// UTF-8 (e.g. GBK cp936 on Chinese Windows).
extern "kernel32" fn SetConsoleOutputCP(wCodePageID: c_uint) callconv(.winapi) c_int;

pub fn main(init: std.process.Init) !void {
    if (builtin.os.tag == .windows) {
        // Console-wide setting; affects only this console session. Redirected
        // output (pipes/files) is unaffected either way.
        _ = SetConsoleOutputCP(65001); // CP_UTF8
    }

    // Lives as long as the process; freed automatically on exit.
    const arena: std.mem.Allocator = init.arena.allocator();
    const raw_args = try init.minimal.args.toSlice(arena);
    const io = init.io;

    var stdout_buffer: [4096]u8 = undefined;
    // Streaming mode: stdout may be a pipe/console, which positional
    // writes would clobber from offset 0.
    var stdout_writer = std.Io.File.stdout().writerStreaming(io, &stdout_buffer);

    var out: Cli.Output = .{ .writer = &stdout_writer.interface };
    var ctx: Cli.Ctx = .{
        .io = io,
        .arena = arena,
        .environ = init.environ_map,
        .out = &out,
        .now = nowSeconds(io),
    };
    Cli.setActiveCtx(&ctx);

    // Keep installed agent skills in sync with this binary's embedded
    // copy (npm upgrades don't re-run `terminus setup`).
    Cli.Setup.autoRefresh(&ctx);

    // Global flags (--json, --db <path>) may appear anywhere; hoist them
    // out so both `terminus --json help` and `terminus help --json` work.
    var args: std.ArrayList([]const u8) = .empty;
    var i: usize = 1;
    var passthrough = false;
    while (i < raw_args.len) : (i += 1) {
        const arg = raw_args[i];
        if (!passthrough) {
            if (std.mem.eql(u8, arg, "--")) {
                passthrough = true;
            } else if (std.mem.eql(u8, arg, "--json")) {
                out.format = .json;
                continue;
            } else if (std.mem.eql(u8, arg, "--db")) {
                i += 1;
                if (i >= raw_args.len) Cli.fail("--db requires a path", .{});
                ctx.db_override = raw_args[i];
                continue;
            } else if (std.mem.startsWith(u8, arg, "--db=")) {
                ctx.db_override = arg["--db=".len..];
                continue;
            }
        }
        try args.append(arena, arg);
    }

    try Cli.Dispatch.dispatchCommand(&ctx, args.items);
    try out.flush();
}

fn nowSeconds(io: std.Io) i64 {
    const ts = std.Io.Timestamp.now(io, .real);
    return @intCast(@divTrunc(ts.nanoseconds, std.time.ns_per_s));
}
