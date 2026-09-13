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
    \\       terminus audit <server> disk --mounts [--json]
    \\       terminus audit <server> disk --containers [--json]
    \\       terminus audit <server> disk --largest N [--json]
    \\       terminus audit <server> disk --cleanup-candidates [--json]
    \\
    \\checks (closed allowlist, enforced by the remote helper):
    \\  host          kernel and host identity
    \\  filesystem    root filesystem capacity
    \\  processes     process inventory
    \\  services      running/failed system services
    \\  containers    container inventory
    \\  journal       last 200 journal lines through non-interactive sudo
    \\  disk          bounded disk mounts/usage/candidate views; never deletes
    \\
    \\audit does not accept an arbitrary command or user-provided argv.
    \\
;

pub const Plan = struct {
    server: []const u8,
    check: Core.audit.Check,
    view: enum { raw, mounts, containers, largest, cleanup_candidates } = .raw,
    limit: usize = 0,

    pub fn request(self: Plan, request_id: []const u8, deadline_ms: u64, grace_ms: u64) Core.audit.Request {
        return .{
            .request_id = request_id,
            .check = self.check,
            .use_sudo = self.check == .journal or self.check == .disk_usage,
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
    BadDiskOptions,
};

/// Pure parser for the audit command.  Keeping this independent of `fatal`
/// makes every forbidden input testable without opening a store or a socket.
pub fn plan(parsed: *const Args.Parsed) PlanError!Plan {
    if (parsed.positional(0) == null) return error.MissingServer;
    const check_name = parsed.positional(1) orelse return error.MissingCheck;
    if (parsed.positional(2) != null or parsed.rest != null) return error.ExtraPositionals;
    if (std.mem.eql(u8, check_name, "disk")) {
        if (parsed.positional(2) != null or parsed.rest != null) return error.ExtraPositionals;
        var modes: usize = 0;
        if (parsed.boolean("mounts")) modes += 1;
        if (parsed.boolean("containers")) modes += 1;
        if (parsed.boolean("cleanup-candidates")) modes += 1;
        if (parsed.flag("largest") != null) modes += 1;
        if (modes != 1) return error.BadDiskOptions;
        for (parsed.flags.keys()) |name| if (!std.mem.eql(u8, name, "largest")) return error.FreeFormCommand;
        for (parsed.bools.keys()) |name| if (!std.mem.eql(u8, name, "json") and
            !std.mem.eql(u8, name, "mounts") and !std.mem.eql(u8, name, "containers") and
            !std.mem.eql(u8, name, "cleanup-candidates"))
            return error.FreeFormCommand;
        if (parsed.boolean("mounts")) return .{ .server = parsed.positional(0).?, .check = .disk_mounts, .view = .mounts };
        if (parsed.boolean("containers")) return .{ .server = parsed.positional(0).?, .check = .disk_containers, .view = .containers };
        if (parsed.boolean("cleanup-candidates")) return .{ .server = parsed.positional(0).?, .check = .disk_usage, .view = .cleanup_candidates, .limit = 30 };
        const raw_limit = parsed.flag("largest").?;
        const limit = std.fmt.parseInt(usize, raw_limit, 10) catch return error.BadDiskOptions;
        if (limit == 0 or limit > 100) return error.BadDiskOptions;
        return .{ .server = parsed.positional(0).?, .check = .disk_usage, .view = .largest, .limit = limit };
    }
    // Ordinary audit checks have no value-taking option. Rejecting the complete map,
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
        error.MissingServer, error.MissingCheck, error.ExtraPositionals, error.FreeFormCommand, error.UnknownCheck, error.BadDiskOptions => fatal("{s}", .{planRefusal(err)}),
    };

    var store = try Cli.openStore(ctx, &parsed);
    defer store.close();
    const resolved = Cli.resolveServer(ctx, &store, selected.server);
    const owner_token = Core.Store.policy.ownerToken(&store, ctx.arena, ctx.io, ctx.now) catch |err|
        Cli.storeFatal(&store, err);
    const deadline_ms: u64 = if (selected.check == .disk_usage) 120_000 else 30_000;
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
        .remote_deadline_ms = deadline_ms,
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
    const request = selected.request(execution.id(), deadline_ms, 1_000);
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
    if (selected.view == .largest or selected.view == .cleanup_candidates)
        return renderDiskUsage(ctx, execution.id(), selected, observed);
    switch (ctx.out.format) {
        .json => try ctx.out.json(.{
            .ok = observed.ending.shellStatus() == 0,
            .complete = auditExitDisposition(observed.ending) == .ok,
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
    finishForEnding(ctx, execution.id(), observed.ending);
}

const ExitDisposition = union(enum) {
    ok,
    code: u8,
    indeterminate,
};

fn auditExitDisposition(ending: Core.supervisor.Ending) ExitDisposition {
    return switch (ending) {
        .exited => |code| if (code == 0)
            .ok
        else
            .{ .code = @intCast(std.math.clamp(code, 1, 255)) },
        .signalled => |signal| .{ .code = @intCast(std.math.clamp(@as(i64, signal) + 128, 1, 255)) },
        // A confirmed timeout is a definite failure. An unconfirmed timeout or
        // unknown ending must retain the distinct indeterminate exit code so a
        // caller cannot mistake it for a safe-to-retry audit failure.
        .timed_out => .{ .code = Cli.exit_code.failure },
        .timed_out_unconfirmed, .unknown => .indeterminate,
    };
}

fn finishForEnding(ctx: *Cli.Ctx, request_id: []const u8, ending: Core.supervisor.Ending) void {
    switch (auditExitDisposition(ending)) {
        .ok => return,
        .code => |code| {
            ctx.out.flush() catch {};
            Cli.clearExecution();
            Cli.exitNow(code);
        },
        .indeterminate => {
            ctx.out.flush() catch {};
            Cli.failIndeterminateAfterOutput(request_id);
        },
    }
}

const DiskEntry = struct {
    bytes: u64,
    path: []const u8,
    category: []const u8,
    confidence: []const u8,
    safeToDelete: bool = false,
};

fn diskCategory(path: []const u8) struct { category: []const u8, confidence: []const u8 } {
    if (std.mem.eql(u8, path, "/tmp") or std.mem.startsWith(u8, path, "/tmp/") or
        std.mem.eql(u8, path, "/var/tmp") or std.mem.startsWith(u8, path, "/var/tmp/"))
        return .{ .category = "temporary", .confidence = "medium" };
    if (std.mem.indexOf(u8, path, "/.cache") != null or std.mem.startsWith(u8, path, "/var/cache"))
        return .{ .category = "cache", .confidence = "medium" };
    if (std.mem.startsWith(u8, path, "/var/lib/docker"))
        return .{ .category = "docker-storage", .confidence = "high" };
    if (std.mem.startsWith(u8, path, "/var/backups") or std.mem.endsWith(u8, path, ".bak"))
        return .{ .category = "rollback-backup", .confidence = "medium" };
    return .{ .category = "unknown", .confidence = "low" };
}

fn diskEntryBefore(_: void, a: DiskEntry, b: DiskEntry) bool {
    return a.bytes > b.bytes;
}

fn renderDiskUsage(ctx: *Cli.Ctx, request_id: []const u8, selected: Plan, observed: Core.supervisor.Observed) !void {
    var entries: std.ArrayList(DiskEntry) = .empty;
    var lines = std.mem.splitScalar(u8, observed.stdout, '\n');
    while (lines.next()) |line| {
        const tab = std.mem.indexOfScalar(u8, line, '\t') orelse continue;
        const bytes = std.fmt.parseInt(u64, std.mem.trim(u8, line[0..tab], " "), 10) catch continue;
        const path = std.mem.trim(u8, line[tab + 1 ..], " \r");
        if (path.len == 0 or std.mem.eql(u8, path, "/")) continue;
        const label = diskCategory(path);
        if (selected.view == .cleanup_candidates and std.mem.eql(u8, label.category, "unknown")) continue;
        try entries.append(ctx.arena, .{
            .bytes = bytes,
            .path = path,
            .category = label.category,
            .confidence = label.confidence,
        });
    }
    std.sort.heap(DiskEntry, entries.items, {}, diskEntryBefore);
    const visible = entries.items[0..@min(entries.items.len, selected.limit)];
    const complete = auditExitDisposition(observed.ending) == .ok;
    switch (ctx.out.format) {
        .json => try ctx.out.json(.{
            .ok = complete,
            .complete = complete,
            .requestId = request_id,
            .check = if (selected.view == .largest) "disk-largest" else "disk-cleanup-candidates",
            .entries = visible,
            .safeCleanupClaimed = false,
            .note = if (complete)
                "categories are evidence-backed hints only; generate and review a cleanup manifest before deletion"
            else
                "partial scan only: the remote audit did not complete; do not treat these entries as a complete inventory or cleanup approval",
            .stderr = observed.stderr,
        }),
        .human => {
            for (visible) |entry| try ctx.out.print("{d:>14}  {s:<16}  {s}\n", .{ entry.bytes, entry.category, entry.path });
            if (complete)
                try ctx.out.print("candidates only; none is declared safe to delete. Review with a cleanup manifest.\n", .{})
            else
                try ctx.out.print("partial scan only; the remote audit did not complete. Do not use this as cleanup approval.\n", .{});
            if (observed.stderr.len != 0) try ctx.out.print("{s}", .{observed.stderr});
        },
    }
    finishForEnding(ctx, request_id, observed.ending);
}

fn planRefusal(err: PlanError) []const u8 {
    return switch (err) {
        error.MissingServer => usage,
        error.MissingCheck => "audit needs a check name; see 'terminus audit --help'",
        error.ExtraPositionals => "audit accepts exactly <server> <check>; arbitrary command arguments are refused",
        error.FreeFormCommand => "audit accepts only a closed check id; --cmd/--argv-json/shell/stdin/interpreter options are refused",
        error.UnknownCheck => "unknown audit check; accepted: host, filesystem, processes, services, containers, journal",
        error.BadDiskOptions => "disk audit requires exactly one of --mounts, --largest N (1..100), or --cleanup-candidates",
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

    parsed = try Args.parse(arena, &.{ "srv", "disk", "--largest", "30" });
    const largest = try plan(&parsed);
    try t.expectEqual(Core.audit.Check.disk_usage, largest.check);
    try t.expectEqual(@as(usize, 30), largest.limit);
    try t.expect(largest.request("01JQXW8ZK4N0RS7T3VYB2MCDEF", 120_000, 1000).use_sudo);
    parsed = try Args.parse(arena, &.{ "srv", "disk", "--containers" });
    try t.expectEqual(Core.audit.Check.disk_containers, (try plan(&parsed)).check);
    parsed = try Args.parse(arena, &.{ "srv", "disk", "--mounts", "--cleanup-candidates" });
    try t.expectError(error.BadDiskOptions, plan(&parsed));

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

test "audit endings preserve definite failure and indeterminate exits" {
    const t = std.testing;
    try t.expect(auditExitDisposition(.{ .exited = 0 }) == .ok);
    try t.expectEqual(@as(u8, 7), auditExitDisposition(.{ .exited = 7 }).code);
    try t.expectEqual(@as(u8, 143), auditExitDisposition(.{ .signalled = 15 }).code);
    try t.expectEqual(Cli.exit_code.failure, auditExitDisposition(.{ .timed_out = .{ .after_ms = 120_000, .signal = 15 } }).code);
    try t.expect(auditExitDisposition(.{ .timed_out_unconfirmed = .{ .after_ms = 120_000, .signal = 15 } }) == .indeterminate);
    try t.expect(auditExitDisposition(.{ .unknown = "no terminal frame" }) == .indeterminate);
}
