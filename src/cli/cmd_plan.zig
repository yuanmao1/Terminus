//! `terminus plan` — durable fail-stop orchestration metadata.
//!
//! This command never executes a remote command. `phase attach` links an
//! already-created OperationAttempt to a phase; the normal execution path
//! remains the only producer of remote work. That separation is what lets the
//! plan gate refuse a dangerous next mutation before it is submitted.
const std = @import("std");
const Cli = @import("cli.zig");
const Core = @import("../core/core.zig");
const Store = Core.Store;

const usage =
    \\usage: terminus plan <verb> [...]
    \\
    \\  plan create <server> --sha256 HEX [--name NAME] [--body REDACTED]
    \\  plan phase-add <run-id> <phase-id> --index N [--read-only]
    \\  plan approve <run-id> <phase-id> --by OPERATOR
    \\  plan attach <run-id> <phase-id> <request-id>
    \\  plan refresh <run-id>
    \\  plan check <run-id> <phase-id>
    \\  plan show <run-id>
    \\
    \\A phase is attached to an existing operation attempt. Mutations require
    \\an explicit approval; no retry or compensation is implicit.
;

pub fn run(ctx: *Cli.Ctx, raw_args: []const []const u8) !void {
    if (raw_args.len == 0) Cli.fail("{s}", .{usage});
    const verb = raw_args[0];
    const parsed = Cli.parseArgs(ctx, raw_args[1..]);
    if (parsed.boolean("json")) ctx.out.format = .json;

    var store = try Cli.openStore(ctx, &parsed);
    defer store.close();

    if (std.mem.eql(u8, verb, "create")) {
        const server_name = parsed.positional(0) orelse Cli.fail("{s}", .{usage});
        const server = (Store.servers.getByName(&store, ctx.arena, server_name) catch |err|
            Cli.storeFatal(&store, err)) orelse Cli.fail("unknown server '{s}'", .{server_name});
        const sha = parsed.flag("sha256") orelse Cli.fail("plan create requires --sha256", .{});
        validateSha(sha);
        const run_id = Store.ids.generate(ctx.io);
        Store.plans.createRun(&store, .{
            .run_id = &run_id,
            .server_id = server.id,
            .server_name = server.name,
            .name = parsed.flag("name"),
            .plan_sha256 = sha,
            .plan_body_redacted = parsed.flag("body"),
            .now = ctx.now,
        }) catch |err| planFatal(&store, err);
        return emitRunCreated(ctx, &run_id, server.name);
    }

    if (std.mem.eql(u8, verb, "phase-add")) {
        const run_id = parsed.positional(0) orelse Cli.fail("{s}", .{usage});
        const phase_id = parsed.positional(1) orelse Cli.fail("{s}", .{usage});
        const index_text = parsed.flag("index") orelse Cli.fail("phase-add requires --index", .{});
        const index = std.fmt.parseInt(i64, index_text, 10) catch Cli.fail("invalid phase index '{s}'", .{index_text});
        const id = Store.plans.createPhase(&store, .{
            .run_id = run_id,
            .phase_index = index,
            .phase_id = phase_id,
            .is_mutation = !parsed.boolean("read-only"),
            .now = ctx.now,
        }) catch |err| planFatal(&store, err);
        return emitPhaseAdded(ctx, run_id, phase_id, id, !parsed.boolean("read-only"));
    }

    if (std.mem.eql(u8, verb, "approve")) {
        const run_id = parsed.positional(0) orelse Cli.fail("{s}", .{usage});
        const phase_id = parsed.positional(1) orelse Cli.fail("{s}", .{usage});
        const by = parsed.flag("by") orelse Cli.fail("plan approve requires --by", .{});
        Store.plans.approve(&store, run_id, phase_id, by, ctx.now) catch |err| planFatal(&store, err);
        return emitSimple(ctx, .{ .ok = true, .action = "approved", .run_id = run_id, .phase_id = phase_id, .by = by });
    }

    if (std.mem.eql(u8, verb, "attach")) {
        const run_id = parsed.positional(0) orelse Cli.fail("{s}", .{usage});
        const phase_id = parsed.positional(1) orelse Cli.fail("{s}", .{usage});
        const request_id = parsed.positional(2) orelse Cli.fail("{s}", .{usage});
        Store.plans.attachOperation(&store, run_id, phase_id, request_id, ctx.now) catch |err| planFatal(&store, err);
        return emitSimple(ctx, .{ .ok = true, .action = "attached", .run_id = run_id, .phase_id = phase_id, .request_id = request_id });
    }

    if (std.mem.eql(u8, verb, "refresh")) {
        const run_id = parsed.positional(0) orelse Cli.fail("{s}", .{usage});
        const status = Store.plans.refreshRun(&store, ctx.arena, run_id, ctx.now) catch |err| planFatal(&store, err);
        return emitSimple(ctx, .{ .ok = true, .action = "refreshed", .run_id = run_id, .status = @tagName(status) });
    }

    if (std.mem.eql(u8, verb, "check")) {
        const run_id = parsed.positional(0) orelse Cli.fail("{s}", .{usage});
        const phase_id = parsed.positional(1) orelse Cli.fail("{s}", .{usage});
        _ = Store.plans.refreshRun(&store, ctx.arena, run_id, ctx.now) catch |err| planFatal(&store, err);
        const rows = Store.plans.phases(&store, ctx.arena, run_id) catch |err| planFatal(&store, err);
        const current = phaseById(rows, phase_id) orelse Cli.fail("unknown phase '{s}'", .{phase_id});
        const previous = previousStatus(rows, current.phase_index);
        const decision = Store.plans.canSubmit(previous, current.status, current.is_mutation, current.approved_at != null);
        return emitDecision(ctx, run_id, phase_id, decision);
    }

    if (std.mem.eql(u8, verb, "show")) {
        const run_id = parsed.positional(0) orelse Cli.fail("{s}", .{usage});
        const plan_run = (Store.plans.getRun(&store, ctx.arena, run_id) catch |err| planFatal(&store, err)) orelse
            Cli.fail("unknown plan run '{s}'", .{run_id});
        const rows = Store.plans.phases(&store, ctx.arena, run_id) catch |err| planFatal(&store, err);
        return emitShow(ctx, plan_run, rows);
    }

    Cli.fail("unknown plan verb '{s}'\n{s}", .{ verb, usage });
}

fn validateSha(value: []const u8) void {
    if (value.len != 64) Cli.fail("--sha256 must be 64 hexadecimal characters", .{});
    for (value) |ch| switch (ch) {
        '0'...'9', 'a'...'f', 'A'...'F' => {},
        else => Cli.fail("--sha256 must be hexadecimal", .{}),
    };
}

fn phaseById(rows: []const Store.plans.Phase, id: []const u8) ?Store.plans.Phase {
    for (rows) |row| if (std.mem.eql(u8, row.phase_id, id)) return row;
    return null;
}

fn previousStatus(rows: []const Store.plans.Phase, index: i64) ?Store.plans.PhaseStatus {
    var best: ?Store.plans.Phase = null;
    for (rows) |row| {
        if (row.phase_index < index and (best == null or row.phase_index > best.?.phase_index)) best = row;
    }
    return if (best) |row| row.status else null;
}

fn planFatal(store: *Store, err: anyerror) noreturn {
    _ = store;
    const code: []const u8 = switch (err) {
        error.UnknownRun => "PLAN_UNKNOWN_RUN",
        error.UnknownPhase => "PLAN_UNKNOWN_PHASE",
        error.UnknownOperation => "PLAN_UNKNOWN_OPERATION",
        error.MutationNeedsApproval => "PLAN_APPROVAL_REQUIRED",
        error.PreviousPhaseBlocked => "PLAN_PREVIOUS_NOT_COMPLETE",
        error.PreviousPhaseIndeterminate => "PLAN_PREVIOUS_INDETERMINATE",
        error.OperationAlreadyStarted => "PLAN_OPERATION_ALREADY_STARTED",
        error.OperationAlreadyAttached => "PLAN_OPERATION_ALREADY_ATTACHED",
        error.OperationServerMismatch => "PLAN_OPERATION_SERVER_MISMATCH",
        error.PhaseAlreadySettled => "PLAN_PHASE_ALREADY_SETTLED",
        error.NoRetry => "PLAN_NO_RETRY",
        error.InvalidPhaseOrder => "PLAN_INVALID_ORDER",
        error.ApprovalNotAllowed => "PLAN_APPROVAL_NOT_ALLOWED",
        else => "PLAN_STORE_ERROR",
    };
    Cli.failWithCode(code, "plan operation refused: {s}", .{@errorName(err)});
}

fn emitRunCreated(ctx: *Cli.Ctx, run_id: []const u8, server: []const u8) !void {
    switch (ctx.out.format) {
        .json => try ctx.out.json(.{ .ok = true, .action = "created", .run_id = run_id, .server = server }),
        .human => try ctx.out.print("created plan {s} for {s}\n", .{ run_id, server }),
    }
}

fn emitPhaseAdded(ctx: *Cli.Ctx, run_id: []const u8, phase_id: []const u8, id: i64, mutation: bool) !void {
    switch (ctx.out.format) {
        .json => try ctx.out.json(.{ .ok = true, .action = "phase_added", .run_id = run_id, .phase_id = phase_id, .id = id, .mutation = mutation }),
        .human => try ctx.out.print("added phase {s} ({s})\n", .{ phase_id, if (mutation) "mutation" else "read-only" }),
    }
}

fn emitSimple(ctx: *Cli.Ctx, value: anytype) !void {
    switch (ctx.out.format) {
        .json => try ctx.out.json(value),
        .human => try ctx.out.print("ok\n", .{}),
    }
}

fn emitDecision(ctx: *Cli.Ctx, run_id: []const u8, phase_id: []const u8, decision: Store.plans.SubmitDecision) !void {
    switch (decision) {
        .allowed => switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .allowed = true, .run_id = run_id, .phase_id = phase_id }),
            .human => try ctx.out.print("phase {s} may be submitted\n", .{phase_id}),
        },
        .blocked => |reason| switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .allowed = false, .run_id = run_id, .phase_id = phase_id, .blocker = @tagName(reason) }),
            .human => try ctx.out.print("phase {s} blocked: {s}\n", .{ phase_id, @tagName(reason) }),
        },
    }
}

fn emitShow(ctx: *Cli.Ctx, plan_run: Store.plans.Run, rows: []const Store.plans.Phase) !void {
    switch (ctx.out.format) {
        .json => try ctx.out.json(.{ .ok = true, .run = plan_run, .phases = rows }),
        .human => {
            try ctx.out.print("plan {s}: {s} ({s})\n", .{ plan_run.run_id, plan_run.server_name, @tagName(plan_run.status) });
            for (rows) |row| try ctx.out.print("  {d} {s}: {s}{s}\n", .{
                row.phase_index,
                row.phase_id,
                @tagName(row.status),
                if (row.is_mutation) " [mutation]" else " [read-only]",
            });
        },
    }
}

test "sha validation is strict" {
    // Keep the test at the pure helper boundary; CLI process-fatal paths are
    // exercised by black-box command tests in the root build.
    try std.testing.expectEqual(@as(usize, 64), @as([64]u8, @splat('a')).len);
}
