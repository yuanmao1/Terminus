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
    \\reconcile establishes what an attempt actually did, so the scope it
    \\holds can be released.
    \\
    \\  --from-log   re-reads the job's own log. On an attempt still in
    \\               flight (a job whose caller walked away) this settles the
    \\               real outcome from the exit sentinel; if the session is
    \\               alive it reports that and settles nothing.
    \\  --override   for an `indeterminate` attempt a human has checked by
    \\               hand. Recorded as a decision, never as proof.
    \\
    \\<status> is one of: completed | failed | timed_out | cancelled
    \\
    \\Exit codes: 0 settled or still legitimately running, 75 the outcome is
    \\still unknown, 1 the request refused.
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

/// Establishes what an attempt did, from whichever state it is stuck in.
///
/// Two different states need reconciling, and they need different machinery:
///
///   * `indeterminate` — already settled as unknown. Its terminal is frozen,
///     so the truth is *annotated* beside it via `resolve`.
///   * `submitted` / `remote_started` — never settled at all. This is the
///     common case: `run` detaches, the caller walks away, and the attempt
///     holds its scope forever. Nothing has been recorded yet, so the log can
///     still produce a real terminal via `settle`.
///
/// Routing only the first one here (as this command originally did) left the
/// second with no way out but `--force`, which is the blind retry the guard
/// exists to prevent.
fn reconcile(ctx: *Cli.Ctx, store: *Store, request_id: []const u8, parsed: *const Cli.Args.Parsed) !void {
    const op = (Store.operations.get(store, ctx.arena, request_id) catch |err| Cli.storeFatal(store, err)) orelse
        fatal("no such request '{s}'", .{request_id});

    if (op.resolved_status) |existing| fatal(
        "request {s} was already reconciled as {s}; a resolution is written once",
        .{ request_id, existing.text() },
    );

    const outcome = switch (op.status) {
        .indeterminate => if (parsed.boolean("from-log"))
            try resolveFromLog(ctx, store, op, parsed)
        else if (parsed.flag("override")) |reason|
            try reconcileByOverride(ctx, store, op, reason, parsed)
        else
            fatal(
                "choose how to establish the outcome: --from-log (read the job's exit sentinel) or --override \"<reason>\" --by <who> --resolved <status>",
                .{},
            ),

        // Still in flight. An override may not settle this: the work might be
        // running right now, and a human assertion that it "completed" would
        // release the scope on top of a live process. --from-log is the only
        // route, and if it finds the session gone it records `indeterminate`
        // — which can then be overridden, in that order.
        .submitted, .remote_started => if (parsed.boolean("from-log"))
            try settleFromLog(ctx, store, op, parsed)
        else if (parsed.flag("override") != null)
            fatal(
                "request {s} is {s}: it was never settled, so there is nothing to override yet — the work may still be running. Run 'request reconcile {s} --from-log' first; it settles the real outcome from the job's log, or records indeterminate if the session is gone, and you can override that",
                .{ request_id, op.status.text(), request_id },
            )
        else
            fatal(
                "request {s} is {s} and still holds its scope; establish what happened with 'request reconcile {s} --from-log'",
                .{ request_id, op.status.text(), request_id },
            ),

        .created, .connecting => fatal(
            "request {s} is {s}: it was never handed to the remote, so there is nothing to establish (it does not block a scope either)",
            .{ request_id, op.status.text() },
        ),

        .completed, .failed, .timed_out, .cancelled => fatal(
            "request {s} is {s} — its outcome is already established",
            .{ request_id, op.status.text() },
        ),
    };

    switch (ctx.out.format) {
        .json => try ctx.out.json(.{
            .ok = outcome.ok,
            .requestId = request_id,
            .resolved = outcome.resolved,
            .status = outcome.status,
            .stillRunning = outcome.still_running,
            .mechanical = outcome.mechanical,
            .detail = outcome.detail,
        }),
        .human => try ctx.out.print("{s}: {s} ({s})\n", .{
            request_id,
            outcome.resolved orelse outcome.status,
            outcome.detail,
        }),
    }

    switch (outcome.exit) {
        .ok => {},
        .failure => {
            try ctx.out.flush();
            std.process.exit(1);
        },
        // Reconcile did its job and the answer is still "unknown". That is
        // not a failure of this command, and it must not read as one: an
        // agent that sees exit 1 here would treat the work as safe to retry.
        .indeterminate => {
            try ctx.out.flush();
            Cli.failIndeterminateAfterOutput(request_id);
        },
    }
}

const Outcome = struct {
    ok: bool,
    /// The outcome this call established, if it established one.
    resolved: ?[]const u8,
    mechanical: bool,
    /// The operation's status after this call.
    status: []const u8,
    /// The attempt is legitimately still in flight; nothing was settled.
    still_running: bool = false,
    detail: []const u8,
    exit: enum { ok, failure, indeterminate },
};

/// What the job's own log says, and whether its session is still there.
const LogEvidence = struct {
    alias: []const u8,
    sentinel: []const u8,
    exit_code: ?i32,
    session_alive: bool,
    output_bytes: usize,
};

/// Goes and reads the job's own log. The sentinel is written by the remote
/// shell after the command returns, so it is the one durable record of how
/// the job ended — available long after the process that launched it is gone.
fn readLog(
    ctx: *Cli.Ctx,
    store: *Store,
    op: Store.operations.Operation,
    parsed: *const Cli.Args.Parsed,
) !LogEvidence {
    const alias = op.alias orelse fatal("--from-log needs a job; request {s} is a {s}", .{ op.request_id, op.kind });
    const attempt = (Store.job_attempts.byRequest(store, ctx.arena, op.request_id) catch |err|
        Cli.storeFatal(store, err)) orelse
        fatal("no recorded attempt for request {s}, so its log cannot be located", .{op.request_id});
    const sentinel = attempt.sentinel orelse
        fatal("attempt for {s} has no sentinel recorded", .{op.request_id});
    const session = attempt.tmux_session orelse
        fatal("attempt for {s} has no session recorded", .{op.request_id});

    const resolved_server = Cli.resolveServer(ctx, store, op.server_name);
    var conn = Cli.connect(ctx, parsed, resolved_server.server, resolved_server.auth);
    defer conn.deinit();

    // Tail read: the sentinel is the last line, so one round trip finds it
    // however much output came before.
    const probe = Tmux.probeTail(conn.executor(), ctx.arena, session, sentinel, 256 * 1024) catch |err|
        fatal("cannot read the job log for '{s}': {s}", .{ alias, @errorName(err) });

    return .{
        .alias = alias,
        .sentinel = sentinel,
        .exit_code = probe.exit_code,
        .session_alive = probe.session_alive,
        .output_bytes = probe.output.len,
    };
}

/// Annotates an already-`indeterminate` attempt with what the log proves.
fn resolveFromLog(
    ctx: *Cli.Ctx,
    store: *Store,
    op: Store.operations.Operation,
    parsed: *const Cli.Args.Parsed,
) !Outcome {
    const evidence = try readLog(ctx, store, op, parsed);

    const code = evidence.exit_code orelse return .{
        .ok = false,
        .resolved = null,
        .mechanical = true,
        .status = op.status.text(),
        .detail = if (evidence.session_alive)
            "the job session is still alive and its log carries no exit sentinel; its outcome is not established yet"
        else
            "the job log carries no exit sentinel; its outcome is still unknown (the log may have been rotated, or the job never finished)",
        .exit = .indeterminate,
    };

    const resolved: Store.op_state.ResolvedStatus = if (code == 0) .completed else .failed;
    const result = Store.receipts.resolve(store, ctx.arena, op.request_id, resolved, .{
        .job_sentinel = .{ .sentinel = evidence.sentinel, .exit_code = code },
    }, ctx.now) catch |err| Cli.receiptFatal(op.request_id, err, "reconcile");

    return interpret(result, resolved, true, "exit sentinel found in the job log");
}

/// Settles an attempt that was never settled at all.
///
/// Three answers, kept strictly apart:
///
///   * sentinel present — the job ended and the log says how. Settled for
///     real, and the scope is released.
///   * no sentinel, session alive — the job is running. Nothing is settled;
///     the scope stays held because it *should* be held.
///   * no sentinel, session gone — something happened and the evidence is
///     gone with it. Settled `indeterminate`, which still blocks the scope.
///     An operator override can then release it, as an override.
fn settleFromLog(
    ctx: *Cli.Ctx,
    store: *Store,
    op: Store.operations.Operation,
    parsed: *const Cli.Args.Parsed,
) !Outcome {
    const evidence = try readLog(ctx, store, op, parsed);

    var execution = (Core.execution.attach(store, ctx.arena, ctx.io, op.request_id) catch |err|
        Cli.storeFatal(store, err)) orelse return .{
        .ok = false,
        .resolved = null,
        .mechanical = true,
        .status = op.status.text(),
        .detail = "the attempt was settled by someone else while we were reading its log; read it back with 'request show'",
        .exit = .failure,
    };

    if (evidence.exit_code) |code| {
        const settled = execution.settleAttached(.{ .exited = .{ .exit_code = code } }, .{
            .stdout = .{ .bytes = @intCast(evidence.output_bytes) },
            .source = .reconcile,
        }) catch |err| Cli.receiptFatal(op.request_id, err, op.status.text());
        const status = switch (settled) {
            .recorded => |r| r.status,
            .already_settled => |r| r.status,
        };
        return .{
            .ok = true,
            .resolved = status.text(),
            .mechanical = true,
            .status = status.text(),
            .detail = "exit sentinel found in the job log",
            .exit = .ok,
        };
    }

    if (evidence.session_alive) {
        // Nothing to settle: the job really is running. Recording that we
        // looked keeps the trail honest without inventing a verdict.
        _ = Store.receipts.append(store, .{
            .request_id = op.request_id,
            .kind = .checkpoint,
            .phase = "reconcile_probe",
            .observed_at = ctx.now,
            .detail_json = try probeJson(ctx.arena, true),
        }) catch |err| Cli.receiptFatal(op.request_id, err, op.status.text());
        return .{
            .ok = true,
            .resolved = null,
            .mechanical = true,
            .status = op.status.text(),
            .still_running = true,
            .detail = "still running: the job session is alive and has written no exit sentinel. Nothing to reconcile — poll it with 'job status'",
            .exit = .ok,
        };
    }

    _ = execution.settleAttached(.{ .indeterminate = .{
        .reason = "job session is gone and its log carries no exit sentinel",
        .last_observed = execution.status,
    } }, .{ .source = .reconcile }) catch |err| Cli.receiptFatal(op.request_id, err, op.status.text());

    return .{
        .ok = false,
        .resolved = null,
        .mechanical = true,
        .status = Store.op_state.Status.indeterminate.text(),
        .detail = "the job session is gone and left no exit sentinel; recorded as indeterminate, which keeps holding the scope. Release it with --override once you have checked the host by hand",
        .exit = .indeterminate,
    };
}

fn probeJson(arena: std.mem.Allocator, session_alive: bool) ![]u8 {
    var writer: std.Io.Writer.Allocating = .init(arena);
    std.json.Stringify.value(.{
        .schemaVersion = Store.receipts.schema_version,
        .event = "reconcile_probe",
        .sessionAlive = session_alive,
        .sentinelFound = false,
    }, .{}, &writer.writer) catch return error.OutOfMemory;
    return writer.toOwnedSlice();
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
        .resolved => .{
            .ok = true,
            .resolved = resolved.text(),
            .mechanical = mechanical,
            .status = Store.op_state.Status.indeterminate.text(),
            .detail = detail,
            .exit = .ok,
        },
        .already_resolved => |existing| .{
            .ok = false,
            .resolved = existing.text(),
            .mechanical = mechanical,
            .status = Store.op_state.Status.indeterminate.text(),
            .detail = "already reconciled by someone else; a resolution is written once",
            .exit = .failure,
        },
        .not_indeterminate => |status| .{
            .ok = false,
            .resolved = null,
            .mechanical = mechanical,
            .status = status.text(),
            .detail = "no longer indeterminate; nothing to reconcile",
            .exit = .failure,
        },
        .evidence_does_not_support => .{
            .ok = false,
            .resolved = null,
            .mechanical = mechanical,
            .status = Store.op_state.Status.indeterminate.text(),
            .detail = "the evidence does not establish that result",
            .exit = .failure,
        },
        .evidence_wrong_kind => .{
            .ok = false,
            .resolved = null,
            .mechanical = mechanical,
            .status = Store.op_state.Status.indeterminate.text(),
            .detail = "that evidence cannot speak about this kind of operation",
            .exit = .failure,
        },
        .unknown_operation => .{
            .ok = false,
            .resolved = null,
            .mechanical = mechanical,
            .status = "unknown",
            .detail = "request disappeared while reconciling",
            .exit = .failure,
        },
    };
}
