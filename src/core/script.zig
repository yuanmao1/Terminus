//! Script staging: multiline commands are written to a remote temp file
//! and executed as `<interpreter> <file>` instead of being inlined.
//!
//! Why: inlining multiline text into ssh exec or tmux send-keys goes
//! through one-or-more shell quoting layers, which breaks heredocs, only
//! reports the last line's exit code, and (in sessions) defeats the
//! sentinel output capture. A staged file is byte-exact — error line
//! numbers match the script, any interpreter works, and the executing
//! side sees exactly one command.
//!
//! Transport: the script travels base64-encoded inside a regular exec
//! (`printf '%s' <b64> | base64 -d > file`), so it works identically over
//! a direct connection or the daemon's pooled one, with no extra SSH
//! handshake. Linux ARG_MAX (~2 MiB) bounds the payload; scripts beyond
//! `max_inline_script` are rejected with advice to use push + exec.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Ssh = @import("ssh/Client.zig");
const Executor = @import("exec.zig").Executor;

const remote_dir = "/tmp/.terminus";

/// One SSH exec request caps near 32 KiB (libssh2/OpenSSH); chunk the
/// upload so scripts of any reasonable size stage correctly.
const stage_chunk = 20 * 1024;

/// Scripts beyond this are almost certainly data, not code; push+exec is
/// the right tool there.
pub const max_inline_script = 768 * 1024;

pub const Options = struct {
    /// Interpreter for the staged script (absolute or on PATH).
    interpreter: []const u8 = "bash",
    /// Prepend `set -euo pipefail` (bash/sh only): any failing line stops
    /// the script and its exit code becomes the result.
    strict: bool = false,
    /// Wrap execution in `bash -ilc` for the interactive PATH.
    login: bool = false,
};

pub const Staged = struct {
    /// The one-line command that runs the staged script.
    command: []const u8,
    /// Remote script path, for cleanup.
    remote_path: []const u8,
};

pub const StageError = Ssh.ExecError || Allocator.Error || error{ ScriptTooLarge, StagingFailed };

/// Content is worth staging when inlining would change its meaning.
pub fn shouldStage(content: []const u8) bool {
    return std.mem.indexOfScalar(u8, content, '\n') != null;
}

/// Writes `content` as an executable script on the remote host and
/// returns the command that runs it. `nonce` must be unique per call
/// (wall-clock nanoseconds are fine).
pub fn stage(
    executor: Executor,
    arena: Allocator,
    content: []const u8,
    options: Options,
    nonce: u64,
) StageError!Staged {
    if (content.len > max_inline_script) return error.ScriptTooLarge;
    const remote_path = try std.fmt.allocPrint(arena, "{s}/s{d}.sh", .{ remote_dir, nonce });

    var script: std.ArrayList(u8) = .empty;
    const is_shell = std.mem.endsWith(u8, options.interpreter, "bash") or
        std.mem.endsWith(u8, options.interpreter, "sh");
    if (options.strict and is_shell) {
        try script.appendSlice(arena, "set -euo pipefail\n");
    }
    try script.appendSlice(arena, content);
    if (content.len == 0 or content[content.len - 1] != '\n')
        try script.append(arena, '\n');

    const encoder = std.base64.standard.Encoder;

    // Truncate-create, then append chunk by chunk (one exec request caps
    // near 32 KiB, so big scripts can't travel in a single command).
    const init_cmd = try std.fmt.allocPrint(arena, "mkdir -p {s} && : > {s} && chmod 700 {s}", .{
        remote_dir, remote_path, remote_path,
    });
    const init_result = try executor.exec(arena, init_cmd);
    if (init_result.exit_code != 0) return error.StagingFailed;

    var offset: usize = 0;
    while (offset < script.items.len) {
        const end = @min(offset + stage_chunk, script.items.len);
        const chunk = script.items[offset..end];
        const encoded = try arena.alloc(u8, encoder.calcSize(chunk.len));
        _ = encoder.encode(encoded, chunk);
        const append = try std.fmt.allocPrint(arena,
            \\printf '%s' '{s}' | base64 -d >> {s}
        , .{ encoded, remote_path });
        const result = try executor.exec(arena, append);
        if (result.exit_code != 0) return error.StagingFailed;
        offset = end;
    }

    const base = try std.fmt.allocPrint(arena, "{s} {s}", .{ options.interpreter, remote_path });
    const command = if (options.login)
        try std.fmt.allocPrint(arena, "bash -ilc '{s}'", .{base})
    else
        base;
    return .{ .command = command, .remote_path = remote_path };
}

/// Best-effort removal of the staged script (also sweeps files older than
/// a day so an interrupted CLI never accumulates leftovers).
pub fn cleanup(executor: Executor, arena: Allocator, remote_path: []const u8) void {
    const script = std.fmt.allocPrint(
        arena,
        "rm -f {s}; find {s} -name 's*.sh' -mmin +1440 -delete 2>/dev/null; true",
        .{ remote_path, remote_dir },
    ) catch return;
    _ = executor.exec(arena, script) catch {};
}
