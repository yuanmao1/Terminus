//! `terminus tunnel <server> --to <host>:<port>` — a pinned, direct-only
//! stdio TCP tunnel.
//!
//! The tunnel's stdout is the remote byte stream and stdin is its input.  No
//! human banner or JSON envelope is written to stdout, because either would be
//! indistinguishable from payload to the program at the other end.  The SSH
//! session comes from `Cli.sshConnect`, which has already loaded the server's
//! pins and refuses before returning an authenticated client when the pin does
//! not match.  `sshConnect` is intentionally used instead of `Cli.connect`:
//! the daemon protocol has no channel for this byte stream and falling back
//! after an unauthorised daemon attempt would make the capability ambiguous.

const std = @import("std");
const Cli = @import("cli.zig");

const fatal = Cli.fail;

pub const usage = "usage: terminus tunnel <server> --to <host>:<port>\n" ++
    "\nOpens a host-pinned direct-tcpip channel. Local stdin and remote stdout " ++
    "are copied byte-for-byte with a fixed memory window. The tunnel is " ++
    "direct-only; --json is refused because stdout is the payload stream.\n" ++
    "\nUse [IPv6]:<port> for an IPv6 destination.\n";

pub const Destination = struct {
    host: []const u8,
    port: u16,
};

pub const DestinationError = error{
    Empty,
    MissingPort,
    InvalidPort,
    UnbracketedIpv6,
};

/// Parse the network endpoint without shell interpolation.  A destination is
/// carried as data to libssh2's direct-tcpip request; it is never rendered as
/// a remote command.
pub fn parseDestination(text: []const u8) DestinationError!Destination {
    if (text.len == 0) return error.Empty;

    var host: []const u8 = undefined;
    var port_text: []const u8 = undefined;
    if (text[0] == '[') {
        const close = std.mem.indexOfScalarPos(u8, text, 1, ']') orelse return error.MissingPort;
        if (close + 1 >= text.len or text[close + 1] != ':') return error.MissingPort;
        host = text[1..close];
        port_text = text[close + 2 ..];
    } else {
        const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse return error.MissingPort;
        host = text[0..colon];
        port_text = text[colon + 1 ..];
        // A bare IPv6 address has more than one colon and no unambiguous port;
        // require the bracketed spelling rather than guessing.
        if (std.mem.indexOfScalar(u8, host, ':') != null) return error.UnbracketedIpv6;
    }
    if (host.len == 0 or port_text.len == 0) return error.MissingPort;
    const port = std.fmt.parseInt(u16, port_text, 10) catch return error.InvalidPort;
    if (port == 0) return error.InvalidPort;
    return .{ .host = host, .port = port };
}

fn destinationOrFatal(text: []const u8) Destination {
    return parseDestination(text) catch |err| fatal(
        "invalid tunnel destination '{s}' ({s}); use <host>:<port> or [<ipv6>]:<port>",
        .{ text, @errorName(err) },
    );
}

pub fn run(ctx: *Cli.Ctx, raw_args: []const []const u8) !void {
    const parsed = Cli.parseArgs(ctx, raw_args);
    if (parsed.boolean("json")) fatal("tunnel stdout is a byte stream; --json is not available", .{});

    const target_spec = parsed.positional(0) orelse fatal("{s}", .{usage});
    const target = Cli.Target.parse(target_spec);
    if (target.session != null)
        fatal("tunnel target must be a server, not a session target", .{});
    if (parsed.positional(1) != null)
        fatal("tunnel destination must be passed with --to <host>:<port>", .{});
    const destination_text = parsed.flag("to") orelse fatal("{s}", .{usage});
    const destination = destinationOrFatal(destination_text);

    var store = try Cli.openStore(ctx, &parsed);
    defer store.close();
    const resolved = Cli.resolveServer(ctx, &store, target.server);

    // This is deliberately not `Cli.connect`: the daemon has no stdio tunnel
    // channel, and the operation must never silently change transport. The
    // direct constructor still performs the normal mandatory host-pin check.
    var client = Cli.sshConnect(resolved.server, resolved.auth);
    defer client.deinit();
    _ = client.tunnel(
        ctx.io,
        destination.host,
        destination.port,
        std.Io.File.stdin(),
        std.Io.File.stdout(),
    ) catch |err| fatal(
        "stdio tunnel to {s}:{d} failed: {s}; the byte stream was not reported as successful",
        .{ destination.host, destination.port, @errorName(err) },
    );
}

test "tunnel destination parser preserves host and requires a port" {
    const t = std.testing;
    const ipv4 = try parseDestination("127.0.0.1:8080");
    try t.expectEqualStrings("127.0.0.1", ipv4.host);
    try t.expectEqual(@as(u16, 8080), ipv4.port);

    const ipv6 = try parseDestination("[2001:db8::10]:443");
    try t.expectEqualStrings("2001:db8::10", ipv6.host);
    try t.expectEqual(@as(u16, 443), ipv6.port);

    try t.expectError(error.MissingPort, parseDestination("example.test"));
    try t.expectError(error.UnbracketedIpv6, parseDestination("2001:db8::1:443"));
    try t.expectError(error.InvalidPort, parseDestination("example.test:0"));
    try t.expectError(error.InvalidPort, parseDestination("example.test:not-a-port"));
}

test "tunnel module does not expose a command payload or private key option" {
    // This is a source-level contract for the command surface: authentication
    // is resolved by Cli, while the tunnel receives only its destination and
    // the two inherited stdio handles.
    const source = @embedFile("cmd_tunnel.zig");
    const command_flag = "--" ++ "cmd";
    const private_flag = "--" ++ "private";
    const daemon_call = "Cli." ++ "connect(ctx";
    try std.testing.expect(std.mem.indexOf(u8, source, command_flag) == null);
    try std.testing.expect(std.mem.indexOf(u8, source, private_flag) == null);
    try std.testing.expect(std.mem.indexOf(u8, source, daemon_call) == null);
}
