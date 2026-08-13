//! By convention, root.zig is the root source file when making a package.
const std = @import("std");
pub const Cli = @import("cli/cli.zig");
pub const Core = @import("core/core.zig");
/// Referenced so `zig build test` compiles the command surface as well;
/// otherwise a broken cmd_*.zig only surfaces when building the exe.
pub const Dispatch = @import("cli/dispatch.zig");

test {
    std.testing.refAllDecls(@This());
}
