//! The tmux `terminus server tmux` installs: static x86_64-linux-musl, built
//! from `vendor/tmux_build.zig` at this commit, with terminfo for the common
//! terminals compiled in so a host without a terminfo database still starts a
//! session.
//!
//! It lands at `$HOME/.terminus/bin/tmux`, which `Tmux.path_prefix` puts ahead
//! of the system's on every remote tmux call — so once installed, it is the one
//! every verb uses.

/// The exact bytes built for this CLI.
pub const executable = @embedFile("terminus_tmux");

/// Per-server fact: the digest of the tmux this machine last installed there.
/// Named like the helper's (`supervisor.helper_fact_key`).
pub const fact_key = "terminus.tmux.sha256";

test "the embedded tmux is a static Linux executable" {
    const std = @import("std");
    try std.testing.expect(executable.len > 100_000);
    try std.testing.expectEqualSlices(u8, "\x7fELF", executable[0..4]);
}
