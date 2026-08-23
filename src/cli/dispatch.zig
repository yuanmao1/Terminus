//! Top-level subcommand routing, and the one place this build learns its own
//! version.
const std = @import("std");
const Cli = @import("cli.zig");
const Setup = @import("cmd_setup.zig");

/// `npm/package.json`, verbatim.
///
/// **Why the manifest is the origin and this file derives.** The same number
/// used to be written by hand in three places — twice in the `version` arm
/// below, once in the manifest, and once as the minimum the agent-facing
/// document states — and copies like that drift because they are edited one at a
/// time. Exactly one of them cannot be derived: `npm publish` reads
/// `npm/package.json`, and nothing can make it read a Zig constant. So the
/// manifest is the origin, this is a read of it, and there is no second place to
/// edit.
///
/// `@embedFile` of an anonymous import rather than a path, for the reason
/// `skill_doc.zig` gives about the skill document: the file lives outside this
/// module's root, and `build.zig` wires it in.
const package_json = @embedFile("terminus_package_json");

/// A three-component version, ordered numerically.
///
/// **Why not `std.mem.order`.** `0.1.10` sorts *below* `0.1.9` as bytes — the
/// third character is `1` against `9` — so a `>=` written over strings reads the
/// newer build as the older one. That is not hypothetical in this tree:
/// `git tag -l | tail -5` hid `v0.1.10` for exactly that reason and produced a
/// reported claim that the release had never been tagged, in the same session
/// that had already used its commit. The gate in `version_test.zig` pins both
/// halves — that this ordering gets it right, and that the byte ordering gets it
/// wrong — so nobody can "simplify" one into the other.
pub const Version = struct {
    major: u32,
    minor: u32,
    patch: u32,

    /// One named error per way the text can fail to be a version, so a refusal
    /// says which reading broke rather than that "the version is wrong".
    pub const ParseError = error{
        VersionComponentEmpty,
        VersionComponentNotANumber,
        VersionComponentTooLarge,
        VersionNotThreeComponents,
    };

    /// `major.minor.patch`, decimal digits and nothing else.
    ///
    /// Deliberately narrow, and narrower than `std.fmt.parseInt`: that accepts a
    /// leading `+` and `_` digit separators, so it would read `1_0` as ten. A
    /// version silently read as a different number is worse than a refusal.
    ///
    /// A pre-release suffix (`0.2.0-rc.1`) is refused rather than ordered.
    /// Inventing an ordering for a shape this tree has never released would be
    /// inventing the answer to the question the caller asked; every release here
    /// has been a plain triple, and a build that stops being one should say so.
    pub fn parse(text: []const u8) ParseError!Version {
        var parts = std.mem.splitScalar(u8, text, '.');
        var out: [3]u32 = undefined;
        for (&out) |*slot| {
            slot.* = try component(parts.next() orelse return error.VersionNotThreeComponents);
        }
        if (parts.next() != null) return error.VersionNotThreeComponents;
        return .{ .major = out[0], .minor = out[1], .patch = out[2] };
    }

    fn component(text: []const u8) ParseError!u32 {
        if (text.len == 0) return error.VersionComponentEmpty;
        var n: u32 = 0;
        for (text) |c| {
            if (c < '0' or c > '9') return error.VersionComponentNotANumber;
            n = std.math.mul(u32, n, 10) catch return error.VersionComponentTooLarge;
            n = std.math.add(u32, n, c - '0') catch return error.VersionComponentTooLarge;
        }
        return n;
    }

    pub fn order(a: Version, b: Version) std.math.Order {
        if (a.major != b.major) return std.math.order(a.major, b.major);
        if (a.minor != b.minor) return std.math.order(a.minor, b.minor);
        return std.math.order(a.patch, b.patch);
    }

    /// Whether this version can honour a document that states `floor` as its
    /// minimum. Equal satisfies, and newer satisfies — a binary ahead of what a
    /// document asks for is the normal case, not a mismatch.
    pub fn atLeast(a: Version, floor: Version) bool {
        return a.order(floor) != .lt;
    }

    /// `{f}`, for the diagnostics that name a version they were handed rather
    /// than this build's own.
    pub fn format(v: Version, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("{d}.{d}.{d}", .{ v.major, v.minor, v.patch });
    }
};

/// The version this build reports, as the manifest spells it.
pub const version_string = packageVersion(package_json);

/// The same, ordered. A manifest whose version is not `major.minor.patch` fails
/// the build here rather than being reported as whatever it happens to be: there
/// is no useful runtime behaviour for "this binary does not know how old it is".
pub const version: Version = Version.parse(version_string) catch |err| @compileError(
    "npm/package.json's \"version\" is \"" ++ version_string ++
        "\", which is not major.minor.patch: " ++ @errorName(err),
);

/// The `"version"` string out of a package manifest, at compile time.
///
/// Not a JSON parse — `std.json` wants an allocator and the only field wanted is
/// one string. What it does insist on is that the file holds exactly *one*
/// `"version"` key: with two, which one is the origin would depend on byte
/// order, which is the failure this whole arrangement exists to remove.
fn packageVersion(comptime json: []const u8) []const u8 {
    comptime {
        @setEvalBranchQuota(200_000);
        const key = "\"version\"";
        const count = std.mem.count(u8, json, key);
        if (count != 1) @compileError(std.fmt.comptimePrint(
            "npm/package.json holds {d} \"version\" keys; the version origin has to be exactly one",
            .{count},
        ));
        var i = skipSpace(json, std.mem.indexOf(u8, json, key).? + key.len);
        if (i >= json.len or json[i] != ':')
            @compileError("npm/package.json: \"version\" is not followed by ':'");
        i = skipSpace(json, i + 1);
        if (i >= json.len or json[i] != '"')
            @compileError("npm/package.json: \"version\"'s value is not a string");
        const start = i + 1;
        const end = std.mem.indexOfScalarPos(u8, json, start, '"') orelse
            @compileError("npm/package.json: \"version\"'s string is never closed");
        return json[start..end];
    }
}

fn skipSpace(comptime s: []const u8, comptime from: usize) usize {
    var i = from;
    while (i < s.len and (s[i] == ' ' or s[i] == '\t' or s[i] == '\r' or s[i] == '\n')) i += 1;
    return i;
}

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
    docker,
    handoff,
    history,
    @"export",
    import,
    setup,
    request,
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
    \\  request    inspect and settle operations     (ls/show/receipt/reconcile)
    \\  read       read session output by cursor
    \\  write      write input into a session
    \\  push       upload a file over SCP
    \\  pull       download a file over SCP
    \\  sync       recursive directory transfer      (push/pull; tar+md5)
    \\  doctor     probe remote environment capabilities
    \\  docker     container state and health wait     (inspect/wait; typed, no prose)
    \\  handoff    everything in flight on a host     (offline; per-section source/observedAt)
    \\  history    local record of push/pull/sync    (audit trail: request ls)
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
            .json => try ctx.out.json(.{
                .ok = true,
                .version = version_string,
                .skillRequires = Setup.embedded_requirement_string,
                .skillSatisfied = Setup.embeddedSatisfied(),
            }),
            .human => {
                try ctx.out.print("terminus {s}\n", .{version_string});
                // The document tells its reader to run `terminus version` when a
                // flag it describes is rejected, so this is where that question
                // gets answered — and it is answered offline, which `doctor`
                // could not do: that verb needs a host before it can say
                // anything. Silent when the pair is fine, which is every
                // released build.
                if (!Setup.embeddedSatisfied()) try ctx.out.print(
                    "the agent skill document in this binary requires terminus >= {s}, " ++
                        "which this build is not; 'terminus setup' will refuse to install it\n",
                    .{Setup.embedded_requirement_string},
                );
            },
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
        .docker => try @import("cmd_docker.zig").run(ctx, args[1..]),
        .handoff => try @import("cmd_handoff.zig").run(ctx, args[1..]),
        .history => try @import("cmd_history.zig").run(ctx, args[1..]),
        .@"export" => try @import("cmd_export_import.zig").exportCmd(ctx, args[1..]),
        .import => try @import("cmd_export_import.zig").importCmd(ctx, args[1..]),
        .setup => try @import("cmd_setup.zig").run(ctx, args[1..]),
        .request => try @import("cmd_request.zig").run(ctx, args[1..]),
        .daemon => try @import("cmd_daemon.zig").run(ctx, args[1..]),
    }
}

test {
    // Every command module is imported inside a switch arm, and Zig only
    // compiles tests in files it actually analyzes — so without this, a test
    // written next to the code it covers silently never runs. That is worse
    // than having no test: the count goes up and nothing is checked.
    _ = @import("cmd_daemon.zig");
    _ = @import("cmd_docker.zig");
    _ = @import("cmd_doctor.zig");
    _ = @import("cmd_exec.zig");
    _ = @import("cmd_export_import.zig");
    _ = @import("cmd_fact.zig");
    _ = @import("cmd_handoff.zig");
    _ = @import("cmd_history.zig");
    _ = @import("cmd_job.zig");
    _ = @import("cmd_key.zig");
    _ = @import("cmd_memory.zig");
    _ = @import("cmd_read_write.zig");
    _ = @import("cmd_request.zig");
    _ = @import("cmd_server.zig");
    _ = @import("cmd_session.zig");
    _ = @import("cmd_setup.zig");
    _ = @import("cmd_sync.zig");
    _ = @import("cmd_transfer.zig");
    _ = @import("cmd_workspace.zig");
    _ = @import("version_test.zig");
}
