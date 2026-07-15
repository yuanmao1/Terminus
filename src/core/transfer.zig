//! Exec-channel file transfer: the SCP-free fallback.
//!
//! libssh2's SCP support runs the remote `scp` binary (`scp -f/-t`) over
//! an exec channel — servers without the scp binary installed (common on
//! minimal images; OpenSSH 9+ no longer ships it by default) fail. This
//! module needs only a POSIX shell, `base64`, and `dd`.
//!
//! Scope: the SCP-free path targets the common "no scp binary" case for
//! configs, scripts, keys, and modest build artifacts. Downloads are
//! capped at `pull_max` — a single libssh2 receive window's worth — since
//! reading past ~2 MiB on one blocking session deadlocks and reconnecting
//! mid-stream proved unreliable. Larger downloads need scp (or split the
//! file remotely first). Uploads have no such cap: each slice is a
//! separate small-output command.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Ssh = @import("ssh/Client.zig");

/// Raw push slice: base64 → ~24 KiB in the command string, safely under
/// the ~32 KiB exec-command ceiling.
const push_slice = 18 * 1024;
/// Raw pull slice: base64 → ~340 KiB of stdout, under the ~400 KiB
/// single-read ceiling.
const pull_slice = 256 * 1024;
/// Max exec-backend download: comfortably inside one 2 MiB receive window.
pub const pull_max = 1536 * 1024;

pub const Error = Ssh.ExecError || Allocator.Error || error{
    RemoteFileMissing,
    RemoteWriteFailed,
    ChecksumMismatch,
    RemoteToolMissing,
    FileTooLarge,
};

fn md5Hex(arena: Allocator, data: []const u8) ![]u8 {
    var digest: [16]u8 = undefined;
    std.crypto.hash.Md5.hash(data, &digest, .{});
    return std.fmt.allocPrint(arena, "{x}", .{&digest});
}

/// Uploads `data` to `remote_path`, one base64-in-command slice per exec.
pub fn pushBytes(
    client: *Ssh,
    arena: Allocator,
    data: []const u8,
    remote_path: []const u8,
    mode: u32,
) Error!void {
    const init = try std.fmt.allocPrint(arena,
        \\command -v base64 >/dev/null || exit 41
        \\: > '{s}' || exit 42
        \\chmod {o} '{s}'
    , .{ remote_path, mode, remote_path });
    const init_r = try client.exec(arena, init);
    switch (init_r.exit_code) {
        0 => {},
        41 => return error.RemoteToolMissing,
        else => return error.RemoteWriteFailed,
    }

    const encoder = std.base64.standard.Encoder;
    var offset: usize = 0;
    while (offset < data.len) {
        const end = @min(offset + push_slice, data.len);
        const chunk = data[offset..end];
        const encoded = try arena.alloc(u8, encoder.calcSize(chunk.len));
        _ = encoder.encode(encoded, chunk);
        const cmd = try std.fmt.allocPrint(arena, "printf '%s' '{s}' | base64 -d >> '{s}'", .{ encoded, remote_path });
        const r = try client.exec(arena, cmd);
        if (r.exit_code != 0) return error.RemoteWriteFailed;
        offset = end;
    }

    const local_md5 = try md5Hex(arena, data);
    const verify = try std.fmt.allocPrint(arena, "md5sum '{s}' | cut -d' ' -f1", .{remote_path});
    const r = try client.exec(arena, verify);
    if (r.exit_code != 0 or !std.mem.eql(u8, std.mem.trim(u8, r.stdout, " \r\n"), local_md5))
        return error.ChecksumMismatch;
}

/// Downloads `remote_path` (up to `pull_max`), one `dd | base64` slice
/// per exec, md5-verified.
pub fn pullBytes(
    client: *Ssh,
    arena: Allocator,
    remote_path: []const u8,
) Error![]u8 {
    const probe_cmd = try std.fmt.allocPrint(arena,
        \\command -v base64 >/dev/null || exit 41
        \\[ -f '{s}' ] || exit 44
        \\wc -c < '{s}'
        \\md5sum '{s}' | cut -d' ' -f1
    , .{ remote_path, remote_path, remote_path });
    const probe = try client.exec(arena, probe_cmd);
    switch (probe.exit_code) {
        0 => {},
        41 => return error.RemoteToolMissing,
        44 => return error.RemoteFileMissing,
        else => return error.RemoteWriteFailed,
    }
    var lines = std.mem.splitScalar(u8, std.mem.trim(u8, probe.stdout, " \r\n"), '\n');
    const size = std.fmt.parseInt(usize, std.mem.trim(u8, lines.next() orelse "0", " \r"), 10) catch
        return error.RemoteWriteFailed;
    const remote_md5 = std.mem.trim(u8, lines.next() orelse "", " \r");
    if (size > pull_max) return error.FileTooLarge;

    const decoder = std.base64.standard.Decoder;
    var out: std.ArrayList(u8) = .empty;
    var block: usize = 0;
    const total_blocks = if (size == 0) 0 else (size + pull_slice - 1) / pull_slice;
    while (block < total_blocks) : (block += 1) {
        const cmd = try std.fmt.allocPrint(
            arena,
            "dd if='{s}' bs={d} skip={d} count=1 2>/dev/null | base64 | tr -d '\\n'",
            .{ remote_path, pull_slice, block },
        );
        const r = try client.exec(arena, cmd);
        if (r.exit_code != 0) return error.RemoteWriteFailed;
        const encoded = std.mem.trim(u8, r.stdout, " \r\n");
        const dsize = decoder.calcSizeForSlice(encoded) catch return error.ChecksumMismatch;
        const buf = try arena.alloc(u8, dsize);
        decoder.decode(buf, encoded) catch return error.ChecksumMismatch;
        try out.appendSlice(arena, buf);
    }

    const data = out.items;
    if (!std.mem.eql(u8, try md5Hex(arena, data), remote_md5)) return error.ChecksumMismatch;
    return data;
}
