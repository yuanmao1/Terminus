//! By convention, root.zig is the root source file when making a package.
const std = @import("std");
pub const Cli = @import("cli/cli.zig");
pub const Core = @import("core/core.zig");

test {
    std.testing.refAllDecls(@This());
}
