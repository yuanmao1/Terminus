//! Exec-channel file transfer: the SCP-free fallback.
//!
//! libssh2's SCP support runs the remote `scp` binary (`scp -f/-t`) over
//! an exec channel — servers without the scp binary installed (common on
//! minimal images; OpenSSH 9+ no longer ships it by default) fail. This
//! module needs only a POSIX shell + `base64`.
//!
//! push: bytes base64'd into per-slice commands, decoded and appended.
//! pull: one `base64 < file` command, decoded locally.
//! Both md5-verify. Download throughput is bounded by libssh2's read
//! speed (the bundled scp backend is no faster), so large downloads are
//! slow but correct; there is no size cap.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Ssh = @import("ssh/Client.zig");

/// Raw push slice: base64 → ~24 KiB in the command string, safely under
/// the ~32 KiB exec-command ceiling.
const push_slice = 18 * 1024;

pub const Error = Ssh.ExecError || Allocator.Error || error{
    RemoteFileMissing,
    RemoteWriteFailed,
    ChecksumMismatch,
    RemoteToolMissing,
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

/// Downloads `remote_path` in one `base64 < file` exec, md5-verified.
pub fn pullBytes(
    client: *Ssh,
    arena: Allocator,
    remote_path: []const u8,
) Error![]u8 {
    const md5_cmd = try std.fmt.allocPrint(arena,
        \\command -v base64 >/dev/null || exit 41
        \\[ -f '{s}' ] || exit 44
        \\md5sum '{s}' | cut -d' ' -f1
    , .{ remote_path, remote_path });
    const md5_r = try client.exec(arena, md5_cmd);
    switch (md5_r.exit_code) {
        0 => {},
        41 => return error.RemoteToolMissing,
        44 => return error.RemoteFileMissing,
        else => return error.RemoteWriteFailed,
    }
    const remote_md5 = std.mem.trim(u8, md5_r.stdout, " \r\n");

    const cmd = try std.fmt.allocPrint(arena, "base64 < '{s}'", .{remote_path});
    const r = try client.exec(arena, cmd);
    if (r.exit_code != 0) return error.RemoteWriteFailed;

    // base64 output wraps at 76 cols; strip whitespace before decoding.
    var compact: std.ArrayList(u8) = .empty;
    for (r.stdout) |ch| {
        if (ch != '\n' and ch != '\r' and ch != ' ') try compact.append(arena, ch);
    }
    const decoder = std.base64.standard.Decoder;
    const dsize = decoder.calcSizeForSlice(compact.items) catch return error.ChecksumMismatch;
    const data = try arena.alloc(u8, dsize);
    decoder.decode(data, compact.items) catch return error.ChecksumMismatch;

    if (!std.mem.eql(u8, try md5Hex(arena, data), remote_md5)) return error.ChecksumMismatch;
    return data;
}
