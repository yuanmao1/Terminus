//! `terminus request` — inspect and settle operations by request id.
//!
//! This is the escape hatch for the scope guard. An attempt whose outcome is
//! unknown deliberately keeps blocking its scope, which is only workable if
//! there is a way to establish the truth afterwards. Without this command the
//! guard is a trap: a forgotten job blocks its name forever and the only way
//! out is `--force`, which is precisely the blind retry the guard exists to
//! prevent.
//!
//! Reconciliation is evidence-first. `--from-log` goes and looks at the
//! durable job log, which is the only thing that actually knows how a job
//! ended; `--override` is available when a human has checked by hand, and is
//! recorded as an override so it can never be mistaken for a mechanical
//! proof.
const std = @import("std");
const fatal = Cli.fail;
const Cli = @import("cli.zig");
const Core = @import("../core/core.zig");
const Store = Core.Store;
const Tmux = Core.Tmux;

const usage =
    \\usage: terminus request <verb> [...]
    \\
    \\  request ls      <server> [--all] [--limit N] [--json]
    \\                          unsettled attempts (what is blocking a scope)
    \\  request show    <request-id> [--json]     status, scope, capability
    \\  request receipt <request-id> [--json]     the full append-only trail
    \\  request reconcile <request-id> [--from-log]
    \\                          [--override "<reason>" --by <who> --resolved <status>]
    \\
    \\reconcile establishes what an `indeterminate` attempt actually did, so
    \\the scope it holds can be released. --from-log re-reads the job's own
    \\log for its exit sentinel. An --override is recorded as a human
    \\decision, never as proof.
    \\
    \\<status> is one of: completed | failed | timed_out | cancelled
    \\
;

pub fn run(ctx: *Cli.Ctx, raw_args: []const []const u8) !void {
    if (raw_args.len == 0) fatal("{s}", .{usage});
    const verb = raw_args[0];
    const parsed = Cli.parseArgs(ctx, raw_args[1..]);
    if (parsed.boolean("json")) ctx.out.format = .json;

    var store = try Cli.openStore(ctx, &parsed);
    defer store.close();

    if (std.mem.eql(u8, verb, "ls")) return listRequests(ctx, &store, &parsed);

    const request_id = parsed.positional(0) orelse fatal("{s}", .{usage});
    Store.ids.validate(request_id) catch fatal("'{s}' is not a request id", .{request_id});

    if (std.mem.eql(u8, verb, "show")) return showRequest(ctx, &store, request_id);
    if (std.mem.eql(u8, verb, "receipt")) return showReceipt(ctx, &store, request_id);
    if (std.mem.eql(u8, verb, "reconcile")) return reconcile(ctx, &store, request_id, &parsed);
    fatal("unknown verb 'request {s}'\n{s}", .{ verb, usage });
}

fn listRequests(ctx: *Cli.Ctx, store: *Store, parsed: *const Cli.Args.Parsed) !void {
    const server_name = parsed.positional(0) orelse fatal("{s}", .{usage});
    const resolved = Cli.resolveServer(ctx, store, server_name);
    const limit: i64 = if (parsed.flag("limit")) |l|
        std.fmt.parseInt(i64, l, 10) catch fatal("invalid --limit '{s}'", .{l})
    else
        20;

    const list = if (parsed.boolean("all"))
        Store.operations.recent(store, ctx.arena, resolved.server.id, limit) catch |err| Cli.storeFatal(store, err)
    else
        Store.operations.unsettled(store, ctx.arena, resolved.server.id) catch |err| Cli.storeFatal(store, err);

    switch (ctx.out.format) {
        .json => try ctx.out.json(.{
            .ok = true,
            .server = server_name,
            .requests = try summarize(ctx, list),
            .unsettledOnly = !parsed.boolean("all"),
        }),
        .human => {
            if (list.len == 0) return ctx.out.print("nothing unsettled on '{s}'\n", .{server_name});
            for (list) |op| {
                try ctx.out.print("{s}  {s}  {s}:{s}  {s}\n", .{
                    op.request_id,
                    op.effectiveStatus().text(),
                    op.scope_kind orelse "server",
                    op.scope_key orelse "",
                    op.alias orelse op.kind,
                });
            }
        },
    }
}

const Summary = struct {
    requestId: []const u8,
    kind: []const u8,
    status: []const u8,
    effectiveStatus: []const u8,
    resolvedStatus: ?[]const u8,
    scopeKind: ?[]const u8,
    scopeKey: ?[]const u8,
    alias: ?[]const u8,
    blocksScope: bool,
    createdAt: i64,
};

fn summarize(ctx: *Cli.Ctx, list: []const Store.operations.Operation) ![]Summary {
    var out: std.ArrayList(Summary) = .empty;
    for (list) |op| {
        try out.append(ctx.arena, .{
            .requestId = op.request_id,
            .kind = op.kind,
            .status = op.status.text(),
            .effectiveStatus = op.effectiveStatus().text(),
            .resolvedStatus = if (op.resolved_status) |r| r.text() else null,
            .scopeKind = op.scope_kind,
            .scopeKey = op.scope_key,
            .alias = op.alias,
            .blocksScope = op.effectiveStatus().blocksScope(),
            .createdAt = op.created_at,
        });
    }
    return out.toOwnedSlice(ctx.arena);
}

fn showRequest(ctx: *Cli.Ctx, store: *Store, request_id: []const u8) !void {
    const op = (Store.operations.get(store, ctx.arena, request_id) catch |err| Cli.storeFatal(store, err)) orelse
        fatal("no such request '{s}'", .{request_id});

    switch (ctx.out.format) {
        .json => try ctx.out.json(.{
            .ok = true,
            .requestId = op.request_id,
            .server = op.server_name,
            .kind = op.kind,
            .alias = op.alias,
            // `status` is what we observed; `effectiveStatus` folds in a
            // later-proven truth without erasing the observation.
            .status = op.status.text(),
            .effectiveStatus = op.effectiveStatus().text(),
            .resolvedStatus = if (op.resolved_status) |r| r.text() else null,
            .reconciledAt = op.reconciled_at,
            .resolutionEvidence = op.resolution_evidence,
            .blocksScope = op.effectiveStatus().blocksScope(),
            .scopeKind = op.scope_kind,
            .scopeKey = op.scope_key,
            .command = op.argv_redacted,
            .commandSha256 = op.argv_sha256,
            .cwd = op.cwd,
            .capability = op.capability_json,
            .createdAt = op.created_at,
            .updatedAt = op.updated_at,
        }),
        .human => {
            try ctx.out.print("{s}\n", .{op.request_id});
            try ctx.out.print("  server  : {s}\n", .{op.server_name});
            try ctx.out.print("  kind    : {s}{s}{s}\n", .{ op.kind, if (op.alias != null) " / " else "", op.alias orelse "" });
            try ctx.out.print("  status  : {s}", .{op.status.text()});
            if (op.resolved_status) |r| try ctx.out.print(" (reconciled: {s})", .{r.text()});
            try ctx.out.print("\n", .{});
            try ctx.out.print("  blocks  : {s}\n", .{if (op.effectiveStatus().blocksScope()) "yes" else "no"});
            try ctx.out.print("  command : {s}\n", .{op.argv_redacted orelse "(not recorded)"});
        },
    }
}

fn showReceipt(ctx: *Cli.Ctx, store: *Store, request_id: []const u8) !void {
    const rows = Store.receipts.list(store, ctx.arena, request_id) catch |err| Cli.storeFatal(store, err);
    if (rows.len == 0) fatal("no receipt for '{s}'", .{request_id});

    switch (ctx.out.format) {
        .json => try ctx.out.json(.{ .ok = true, .requestId = request_id, .events = rows }),
        .human => for (rows) |row| {
            try ctx.out.print("{d:>3} {s:<13} {s:<14} {s}\n", .{
                row.seq,
                row.kind,
                row.status orelse "",
                row.transport_error orelse row.error_code orelse "",
            });
        },
    }
}

fn reconcile(ctx: *Cli.Ctx, store: *Store, request_id: []const u8, parsed: *const Cli.Args.Parsed) !void {
    const op = (Store.operations.get(store, ctx.arena, request_id) catch |err| Cli.storeFatal(store, err)) orelse
        fatal("no such request '{s}'", .{request_id});

    if (op.status != .indeterminate) fatal(
        "request {s} is {s}, not indeterminate — there is nothing to reconcile",
        .{ request_id, op.status.text() },
    );
    if (op.resolved_status) |existing| fatal(
        "request {s} was already reconciled as {s}; a resolution is written once",
        .{ request_id, existing.text() },
    );

    const outcome = if (parsed.boolean("from-log"))
        try reconcileFromLog(ctx, store, op, parsed)
    else if (parsed.flag("override")) |reason|
        try reconcileByOverride(ctx, store, op, reason, parsed)
    else
        fatal(
            "choose how to establish the outcome: --from-log (read the job's exit sentinel) or --override \"<reason>\" --by <who> --resolved <status>",
            .{},
        );

    switch (ctx.out.format) {
        .json => try ctx.out.json(.{
            .ok = outcome.ok,
            .requestId = request_id,
            .resolved = outcome.resolved,
            .mechanical = outcome.mechanical,
            .detail = outcome.detail,
        }),
        .human => try ctx.out.print("{s}: {s} ({s})\n", .{ request_id, outcome.resolved orelse "unresolved", outcome.detail }),
    }
    if (!outcome.ok) {
        try ctx.out.flush();
        std.process.exit(1);
    }
}

const Outcome = struct {
    ok: bool,
    resolved: ?[]const u8,
    mechanical: bool,
    detail: []const u8,
};

/// Goes and reads the job's own log. The sentinel is written by the remote
/// shell after the command returns, so it is the one durable record of how
/// the job ended — available long after the process that launched it is gone.
fn reconcileFromLog(
    ctx: *Cli.Ctx,
    store: *Store,
    op: Store.operations.Operation,
    parsed: *const Cli.Args.Parsed,
) !Outcome {
    const alias = op.alias orelse fatal("--from-log needs a job; request {s} is a {s}", .{ op.request_id, op.kind });
    const attempt = (Store.job_attempts.byRequest(store, ctx.arena, op.request_id) catch |err|
        Cli.storeFatal(store, err)) orelse
        fatal("no recorded attempt for request {s}, so its log cannot be located", .{op.request_id});
    const sentinel = attempt.sentinel orelse
        fatal("attempt for {s} has no sentinel recorded", .{op.request_id});
    const session = attempt.tmux_session orelse
        fatal("attempt for {s} has no session recorded", .{op.request_id});

    const server_name = op.server_name;
    const resolved_server = Cli.resolveServer(ctx, store, server_name);
    var conn = Cli.connect(ctx, parsed, resolved_server.server, resolved_server.auth);
    defer conn.deinit();

    const probe = Tmux.probeTail(conn.executor(), ctx.arena, session, sentinel, 256 * 1024) catch |err|
        fatal("cannot read the job log for '{s}': {s}", .{ alias, @errorName(err) });

    const code = probe.exit_code orelse return .{
        .ok = false,
        .resolved = null,
        .mechanical = true,
        .detail = "the job log carries no exit sentinel; its outcome is still unknown (the log may have been rotated, or the job never finished)",
    };

    const resolved: Store.op_state.ResolvedStatus = if (code == 0) .completed else .failed;
    const result = Store.receipts.resolve(store, ctx.arena, op.request_id, resolved, .{
        .job_sentinel = .{ .sentinel = sentinel, .exit_code = code },
    }, ctx.now) catch |err| Cli.receiptFatal(op.request_id, err, "reconcile");

    return interpret(result, resolved, true, "exit sentinel found in the job log");
}

fn reconcileByOverride(
    ctx: *Cli.Ctx,
    store: *Store,
    op: Store.operations.Operation,
    reason: []const u8,
    parsed: *const Cli.Args.Parsed,
) !Outcome {
    const by = parsed.flag("by") orelse fatal("--override requires --by <who>, so the decision has an owner", .{});
    const status_text = parsed.flag("resolved") orelse
        fatal("--override requires --resolved <completed|failed|timed_out|cancelled>", .{});
    const resolved = Store.op_state.ResolvedStatus.parse(status_text) catch
        fatal("invalid --resolved '{s}' (completed|failed|timed_out|cancelled)", .{status_text});

    const result = Store.receipts.resolve(store, ctx.arena, op.request_id, resolved, .{
        .operator_override = .{ .reason = reason, .by = by },
    }, ctx.now) catch |err| Cli.receiptFatal(op.request_id, err, "reconcile");

    return interpret(result, resolved, false, "recorded as a human decision, not as proof");
}

fn interpret(
    result: Store.receipts.ResolveOutcome,
    resolved: Store.op_state.ResolvedStatus,
    mechanical: bool,
    detail: []const u8,
) Outcome {
    return switch (result) {
        .resolved => .{ .ok = true, .resolved = resolved.text(), .mechanical = mechanical, .detail = detail },
        .already_resolved => |existing| .{
            .ok = false,
            .resolved = existing.text(),
            .mechanical = mechanical,
            .detail = "already reconciled by someone else; a resolution is written once",
        },
        .not_indeterminate => |status| .{
            .ok = false,
            .resolved = status.text(),
            .mechanical = mechanical,
            .detail = "no longer indeterminate; nothing to reconcile",
        },
        .evidence_does_not_support => .{
            .ok = false,
            .resolved = null,
            .mechanical = mechanical,
            .detail = "the evidence does not establish that result",
        },
        .evidence_wrong_kind => .{
            .ok = false,
            .resolved = null,
            .mechanical = mechanical,
            .detail = "that evidence cannot speak about this kind of operation",
        },
        .unknown_operation => .{
            .ok = false,
            .resolved = null,
            .mechanical = mechanical,
            .detail = "request disappeared while reconciling",
        },
    };
}
