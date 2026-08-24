//! `terminus audit <server> <check>` — native, read-only host inspection.
//!
//! The command accepts a closed check vocabulary.  It deliberately has no
//! `--cmd`, `--argv-json`, shell, interpreter, stdin, or free-form arguments:
//! those would move the read-only decision back to the caller.  A future
//! execution path must send `Core.audit.Request` to the remote helper and must
//! require the helper's `audit_accepted` manifest acknowledgement before it
//! publishes `Capability.auditIsolation=true`.
//!
//! The helper acknowledges the compiled manifest before this path upgrades the
//! operation capability to `audit_isolation=true`; ordinary helper execution
//! continues to advertise false and cannot inherit the audit claim.
const std = @import("std");
const Cli = @import("cli.zig");
const Core = @import("../core/core.zig");
const Args = @import("args.zig");

const fatal = Cli.fail;

pub const usage =
    \\usage: terminus audit <server> <check> [--json]
    \\
    \\checks (closed allowlist, enforced by the remote helper):
    \\  host          kernel and host identity
    \\  filesystem    root filesystem capacity
    \\  processes     process inventory
    \\  services      running/failed system services
    \\  containers    container inventory
    \\  journal       last 200 journal lines through non-interactive sudo
    \\
    \\audit does not accept an arbitrary command or user-provided argv.
    \\
;

pub const Plan = struct {
    server: []const u8,
    check: Core.audit.Check,

    pub fn request(self: Plan, request_id: []const u8, deadline_ms: u64, grace_ms: u64) Core.audit.Request {
        return .{
            .request_id = request_id,
            .check = self.check,
            .use_sudo = self.check == .journal,
            .deadline_ms = deadline_ms,
            .grace_ms = grace_ms,
        };
    }

    /// Safe text for an operation row.  The actual argv is not part of the
    /// caller's input and is therefore not copied into the ledger.
    pub fn redacted(self: Plan, arena: std.mem.Allocator) ![]const u8 {
        return std.fmt.allocPrint(arena, "audit {s}", .{self.check.text()});
    }
};

pub const PlanError = error{
    MissingServer,
    MissingCheck,
    ExtraPositionals,
    FreeFormCommand,
    UnknownCheck,
};

/// Pure parser for the audit command.  Keeping this independent of `fatal`
/// makes every forbidden input testable without opening a store or a socket.
pub fn plan(parsed: *const Args.Parsed) PlanError!Plan {
    if (parsed.positional(0) == null) return error.MissingServer;
    const check_name = parsed.positional(1) orelse return error.MissingCheck;
    if (parsed.positional(2) != null or parsed.rest != null) return error.ExtraPositionals;
    // `audit` has no value-taking option at all.  Rejecting the complete map,
    // instead of naming today's free-form flags one by one, prevents a newly
    // registered CLI flag from silently becoming an audit escape hatch.
    if (parsed.flags.keys().len != 0) return error.FreeFormCommand;
    for (parsed.bools.keys()) |name| {
        if (!std.mem.eql(u8, name, "json")) return error.FreeFormCommand;
    }
    if (parsed.flag("cmd") != null or parsed.flag("argv-json") != null or
        parsed.flag("stdin-file") != null or parsed.flag("interpreter") != null or
        parsed.flag("shell") != null or parsed.flag("timeout") != null or
        parsed.boolean("stdin") or parsed.boolean("strict") or parsed.boolean("login"))
        return error.FreeFormCommand;
    const check = Core.audit.Check.parse(check_name) catch return error.UnknownCheck;
    return .{ .server = parsed.positional(0).?, .check = check };
}

pub fn run(ctx: *Cli.Ctx, raw_args: []const []const u8) !void {
    const parsed = Cli.parseArgs(ctx, raw_args);
    if (parsed.boolean("json")) ctx.out.format = .json;
    const selected = plan(&parsed) catch |err| switch (err) {
        error.MissingServer, error.MissingCheck, error.ExtraPositionals, error.FreeFormCommand, error.UnknownCheck => fatal("{s}", .{planRefusal(err)}),
    };

    var store = try Cli.openStore(ctx, &parsed);
    defer store.close();
    const resolved = Cli.resolveServer(ctx, &store, selected.server);
    const owner_token = Core.Store.policy.ownerToken(&store, ctx.arena, ctx.io, ctx.now) catch |err|
        Cli.storeFatal(&store, err);
    const begin = Core.execution.begin(&store, ctx.arena, ctx.io, .{
        .server_id = resolved.server.id,
        .server_name = resolved.server.name,
        .kind = .audit,
        .scope = .{ .kind = .server },
        .mutating = false,
        .argv_redacted = try selected.redacted(ctx.arena),
        // The stronger capability is persisted only after the helper's
        // acceptance frame verifies the compiled manifest below.
        .capability = Core.supervisor.helper_capability,
        .remote_deadline_ms = 30_000,
        .deadline_grace_ms = 1_000,
        .owner_token = owner_token,
        .now = ctx.now,
    }) catch |err| Cli.storeFatal(&store, err);
    var execution = switch (begin) {
        .ready => |ready| ready,
        .blocked => |blocker| fatal("audit was blocked by request {s}", .{switch (blocker) {
            .unsettled => |op| op.request_id,
            .lease => |lease| lease.owner_request_id,
        }}),
    };
    Cli.registerExecution(&execution);
    defer {
        Cli.clearExecution();
        execution.deinit();
    }
    execution.connecting() catch |err| Cli.receiptFatal(execution.id(), err, "created");
    var conn = Cli.connectDirect(ctx, resolved.server, resolved.auth);
    defer conn.deinit();
    const request = selected.request(execution.id(), 30_000, 1_000);
    const frame = Core.audit.wire.encodeRequest(ctx.arena, request) catch |err|
        fatal("cannot encode audit request: {s}", .{@errorName(err)});
    var reader: std.Io.Reader = .fixed(frame);
    var accepted: Core.Ssh.Accepted = .{};
    switch (execution.submitted() catch |err| Cli.receiptFatal(execution.id(), err, "connecting")) {
        .submitted => {},
        .refused => fatal("audit submission was refused; reconcile request {s}", .{execution.id()}),
    }
    var retained: Core.Ssh.Retained = .{};
    const executor = conn.executor();
    const result = executor.execRetained(
        ctx.arena,
        try Core.supervisor.guardedRemoteHelperCommand(ctx.arena),
        .{ .source = &reader, .accepted = &accepted },
        &retained,
    ) catch |err| {
        const why = try std.fmt.allocPrint(ctx.arena, "audit transport failed after accepting {d} byte(s): {s} ({s})", .{
            accepted.bytes, executor.errorMessage(), @errorName(err),
        });
        _ = execution.transportLoss(why) catch |receipt_err|
            Cli.receiptFatal(execution.id(), receipt_err, execution.status.text());
        Cli.failIndeterminateAfterOutput(execution.id());
    };
    _ = Core.audit.wire.decodeAcceptance(ctx.arena, result.stdout, request) catch |err| {
        const why = try std.fmt.allocPrint(ctx.arena, "remote audit policy acknowledgement failed: {s}", .{@errorName(err)});
        _ = execution.transportLoss(why) catch |receipt_err|
            Cli.receiptFatal(execution.id(), receipt_err, execution.status.text());
        Cli.failIndeterminateAfterOutput(execution.id());
    };
    const capability_json = try Core.supervisor.audit_capability.toJson(ctx.arena);
    Core.Store.operations.setCapability(&store, execution.id(), capability_json, ctx.now) catch |err|
        Cli.storeFatal(&store, err);
    execution.capability = Core.supervisor.audit_capability;

    const supervisor_reply = Core.audit.wire.supervisorReply(ctx.arena, result.stdout) catch |err| {
        const why = try std.fmt.allocPrint(ctx.arena, "remote audit helper reply framing was invalid: {s}", .{@errorName(err)});
        _ = execution.transportLoss(why) catch |receipt_err|
            Cli.receiptFatal(execution.id(), receipt_err, execution.status.text());
        Cli.failIndeterminateAfterOutput(execution.id());
    };
    const observed = Core.supervisor.parseHelper(ctx.arena, supervisor_reply, request.deadline_ms) catch |err| {
        const why = try std.fmt.allocPrint(ctx.arena, "remote audit helper reply was incomplete: {s}", .{@errorName(err)});
        _ = execution.transportLoss(why) catch |receipt_err|
            Cli.receiptFatal(execution.id(), receipt_err, execution.status.text());
        Cli.failIndeterminateAfterOutput(execution.id());
    };
    if (observed.identity) |identity| execution.remoteStarted(identity) catch |err|
        Cli.receiptFatal(execution.id(), err, execution.status.text());
    _ = execution.settle(Core.execution.terminalFor(observed.ending, execution.status), .{
        .connected = true,
        .stdin = .{ .bytes = @intCast(accepted.bytes), .sha256 = accepted.sha256[0..] },
        .stdout = .{ .bytes = @intCast(retained.stdout.bytes), .sha256 = retained.stdout.sha256[0..], .truncated = retained.stdout.truncated },
        .stderr = .{ .bytes = @intCast(retained.stderr.bytes), .sha256 = retained.stderr.sha256[0..], .truncated = retained.stderr.truncated },
        .remote_pid = if (observed.identity) |identity| identity.pid else null,
        .remote_pgid = if (observed.identity) |identity| identity.pgid else null,
        .remote_start_token = if (observed.identity) |identity| identity.start_token else null,
    }) catch |err| Cli.receiptFatal(execution.id(), err, execution.status.text());
    switch (ctx.out.format) {
        .json => try ctx.out.json(.{
            .ok = observed.ending.shellStatus() == 0,
            .requestId = execution.id(),
            .check = selected.check.text(),
            .exitCode = observed.ending.shellStatus(),
            .stdout = observed.stdout,
            .stderr = observed.stderr,
            .auditIsolation = true,
        }),
        .human => {
            try ctx.out.print("{s}", .{observed.stdout});
            if (observed.stderr.len != 0) try ctx.out.print("{s}", .{observed.stderr});
        },
    }
}

fn planRefusal(err: PlanError) []const u8 {
    return switch (err) {
        error.MissingServer => usage,
        error.MissingCheck => "audit needs a check name; see 'terminus audit --help'",
        error.ExtraPositionals => "audit accepts exactly <server> <check>; arbitrary command arguments are refused",
        error.FreeFormCommand => "audit accepts only a closed check id; --cmd/--argv-json/shell/stdin/interpreter options are refused",
        error.UnknownCheck => "unknown audit check; accepted: host, filesystem, processes, services, containers, journal",
    };
}

test "audit CLI accepts only closed check ids and never a free-form command" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var parsed = try Args.parse(arena, &.{ "srv", "host" });
    const host = try plan(&parsed);
    try t.expectEqual(Core.audit.Check.host, host.check);
    try t.expect(!host.request("01JQXW8ZK4N0RS7T3VYB2MCDEF", 5000, 1000).use_sudo);

    parsed = try Args.parse(arena, &.{ "srv", "journal" });
    const journal = try plan(&parsed);
    try t.expectEqual(Core.audit.Check.journal, journal.check);
    try t.expect(journal.request("01JQXW8ZK4N0RS7T3VYB2MCDEF", 5000, 1000).use_sudo);

    parsed = try Args.parse(arena, &.{ "srv", "host", "--", ";rm", "-rf", "/" });
    try t.expectError(error.ExtraPositionals, plan(&parsed));
    parsed = try Args.parse(arena, &.{ "srv", "host", "--cmd", "uname -a" });
    try t.expectError(error.FreeFormCommand, plan(&parsed));
    parsed = try Args.parse(arena, &.{ "srv", "host", "--argv-json", "[\"/bin/sh\"]" });
    try t.expectError(error.FreeFormCommand, plan(&parsed));
    parsed = try Args.parse(arena, &.{ "srv", "host", "--shell", "none" });
    try t.expectError(error.FreeFormCommand, plan(&parsed));
    parsed = try Args.parse(arena, &.{ "srv", "host", "--sudo", "1" });
    try t.expectError(error.FreeFormCommand, plan(&parsed));
    parsed = try Args.parse(arena, &.{ "srv", "host", "--force" });
    try t.expectError(error.FreeFormCommand, plan(&parsed));
    parsed = try Args.parse(arena, &.{ "srv", "sh -c id" });
    try t.expectError(error.UnknownCheck, plan(&parsed));
}

test "ordinary helper does not claim audit isolation" {
    const t = std.testing;
    try t.expect(!Core.supervisor.Requirement.audited_execution.satisfiedBy(Core.supervisor.helper_capability));
    const text = try (Plan{ .server = "srv", .check = .host }).redacted(std.testing.allocator);
    defer std.testing.allocator.free(text);
    try t.expectEqualStrings("audit host", text);
}
