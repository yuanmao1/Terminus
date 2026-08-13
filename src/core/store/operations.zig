//! CRUD for `operations` — the immutable identity of every remote side
//! effect, plus its last *observed* status.
//!
//! Identity rule: `request_id` is authoritative. `alias` (a job or session
//! name) is a convenience handle only — names get reused and deleted, so an
//! audit trail can never be anchored on them.
//!
//! Status rule: this table records what we observed. Reconciliation writes
//! `resolved_status` and never rewrites `status`, so the ledger preserves
//! "we believed X, then proved Y". See `op_state.zig` for the contract.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Store = @import("Store.zig");
const Db = @import("Db.zig");
const ids = @import("ids.zig");
const op_state = @import("op_state.zig");

pub const Status = op_state.Status;
pub const ResolvedStatus = op_state.ResolvedStatus;
pub const Terminal = op_state.Terminal;

/// Bumped when the row layout gains meaning that a reader must understand.
pub const schema_version: i64 = 1;

pub const Kind = enum {
    exec,
    job,
    transfer_push,
    transfer_pull,
    fetch,
    tunnel,
    plan_phase,
    audit,
    cleanup,

    pub fn parse(text: []const u8) error{UnknownKind}!Kind {
        return std.meta.stringToEnum(Kind, text) orelse error.UnknownKind;
    }
};

pub const ScopeKind = enum {
    server,
    job,
    path,

    pub fn parse(text: []const u8) error{UnknownScopeKind}!ScopeKind {
        return std.meta.stringToEnum(ScopeKind, text) orelse error.UnknownScopeKind;
    }
};

/// Everything here except `status` is write-once.
pub const CreateOptions = struct {
    request_id: []const u8,
    server_id: ?i64,
    server_name: []const u8,
    kind: Kind,
    scope_kind: ?ScopeKind = null,
    scope_key: ?[]const u8 = null,
    alias: ?[]const u8 = null,
    /// Already redacted. Raw argv must never reach this table.
    argv_redacted: ?[]const u8 = null,
    /// SHA-256 of the RAW argv, for correlation without disclosure.
    argv_sha256: ?[]const u8 = null,
    cwd: ?[]const u8 = null,
    shell: ?[]const u8 = null,
    capability_json: ?[]const u8 = null,
    transport: ?[]const u8 = null,
    now: i64,
};

pub const Operation = struct {
    request_id: []const u8,
    schema_version: i64,
    server_id: ?i64,
    server_name: []const u8,
    kind: []const u8,
    scope_kind: ?[]const u8,
    scope_key: ?[]const u8,
    alias: ?[]const u8,
    status: Status,
    resolved_status: ?ResolvedStatus,
    reconciled_at: ?i64,
    resolution_evidence: ?[]const u8,
    argv_redacted: ?[]const u8,
    argv_sha256: ?[]const u8,
    cwd: ?[]const u8,
    shell: ?[]const u8,
    capability_json: ?[]const u8,
    transport: ?[]const u8,
    created_at: i64,
    updated_at: i64,

    /// What the caller should act on: the proven truth if we have one, else
    /// what we last observed.
    pub fn effectiveStatus(op: Operation) Status {
        if (op.resolved_status) |r| return switch (r) {
            .completed => .completed,
            .failed => .failed,
            .timed_out => .timed_out,
            .cancelled => .cancelled,
        };
        return op.status;
    }
};

pub const Error = Db.Error || error{ UnknownStatus, InvalidRequestId };

pub fn create(store: *Store, opts: CreateOptions) Error!void {
    try ids.validate(opts.request_id);
    var stmt = try store.db.prepare(
        \\INSERT INTO operations (
        \\  request_id, schema_version, server_id, server_name, kind,
        \\  scope_kind, scope_key, alias, status,
        \\  argv_redacted, argv_sha256, cwd, shell, capability_json, transport,
        \\  created_at, updated_at
        \\) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'created', ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?15)
    );
    defer stmt.deinit();
    try stmt.bindText(1, opts.request_id);
    try stmt.bindInt(2, schema_version);
    try stmt.bindOptInt(3, opts.server_id);
    try stmt.bindText(4, opts.server_name);
    try stmt.bindText(5, @tagName(opts.kind));
    try stmt.bindOptText(6, if (opts.scope_kind) |s| @tagName(s) else null);
    try stmt.bindOptText(7, opts.scope_key);
    try stmt.bindOptText(8, opts.alias);
    try stmt.bindOptText(9, opts.argv_redacted);
    try stmt.bindOptText(10, opts.argv_sha256);
    try stmt.bindOptText(11, opts.cwd);
    try stmt.bindOptText(12, opts.shell);
    try stmt.bindOptText(13, opts.capability_json);
    try stmt.bindOptText(14, opts.transport);
    try stmt.bindInt(15, opts.now);
    _ = try stmt.step();
}

const select_columns =
    \\SELECT request_id, schema_version, server_id, server_name, kind,
    \\       scope_kind, scope_key, alias, status, resolved_status,
    \\       reconciled_at, resolution_evidence, argv_redacted, argv_sha256,
    \\       cwd, shell, capability_json, transport, created_at, updated_at
    \\FROM operations
;

fn rowToOperation(arena: Allocator, stmt: *Db.Stmt) (Allocator.Error || error{UnknownStatus})!Operation {
    const dupOpt = struct {
        fn f(a: Allocator, v: ?[]const u8) Allocator.Error!?[]const u8 {
            return if (v) |value| try a.dupe(u8, value) else null;
        }
    }.f;
    return .{
        .request_id = try arena.dupe(u8, stmt.columnText(0)),
        .schema_version = stmt.columnInt(1),
        .server_id = stmt.columnOptInt(2),
        .server_name = try arena.dupe(u8, stmt.columnText(3)),
        .kind = try arena.dupe(u8, stmt.columnText(4)),
        .scope_kind = try dupOpt(arena, stmt.columnOptText(5)),
        .scope_key = try dupOpt(arena, stmt.columnOptText(6)),
        .alias = try dupOpt(arena, stmt.columnOptText(7)),
        // Strict: an unreadable status is an error, never a default.
        .status = try Status.parse(stmt.columnText(8)),
        .resolved_status = if (stmt.columnOptText(9)) |v| try ResolvedStatus.parse(v) else null,
        .reconciled_at = stmt.columnOptInt(10),
        .resolution_evidence = try dupOpt(arena, stmt.columnOptText(11)),
        .argv_redacted = try dupOpt(arena, stmt.columnOptText(12)),
        .argv_sha256 = try dupOpt(arena, stmt.columnOptText(13)),
        .cwd = try dupOpt(arena, stmt.columnOptText(14)),
        .shell = try dupOpt(arena, stmt.columnOptText(15)),
        .capability_json = try dupOpt(arena, stmt.columnOptText(16)),
        .transport = try dupOpt(arena, stmt.columnOptText(17)),
        .created_at = stmt.columnInt(18),
        .updated_at = stmt.columnInt(19),
    };
}

pub fn get(store: *Store, arena: Allocator, request_id: []const u8) (Error || Allocator.Error)!?Operation {
    var stmt = try store.db.prepare(select_columns ++ " WHERE request_id = ?1");
    defer stmt.deinit();
    try stmt.bindText(1, request_id);
    if (!try stmt.step()) return null;
    return try rowToOperation(arena, &stmt);
}

/// Advances a non-terminal status. Rejects any transition the state machine
/// does not allow, and refuses to move an already-terminal operation — a
/// caller that tries is buggy, and silently permitting it would let the
/// ledger record a state it cannot justify.
pub fn advance(store: *Store, request_id: []const u8, to: Status, now: i64) (Error || error{ IllegalTransition, UnknownOperation })!void {
    try store.db.exec("BEGIN IMMEDIATE");
    errdefer store.db.exec("ROLLBACK") catch {};

    const current = try statusOfLocked(store, request_id);
    if (!op_state.canTransition(current, to)) {
        store.db.exec("ROLLBACK") catch {};
        return error.IllegalTransition;
    }
    var stmt = try store.db.prepare(
        "UPDATE operations SET status = ?1, updated_at = ?2 WHERE request_id = ?3",
    );
    defer stmt.deinit();
    try stmt.bindText(1, to.text());
    try stmt.bindInt(2, now);
    try stmt.bindText(3, request_id);
    _ = try stmt.step();

    try store.db.exec("COMMIT");
}

/// Caller must hold the write transaction.
pub fn statusOfLocked(store: *Store, request_id: []const u8) (Error || error{UnknownOperation})!Status {
    var stmt = try store.db.prepare("SELECT status FROM operations WHERE request_id = ?1");
    defer stmt.deinit();
    try stmt.bindText(1, request_id);
    if (!try stmt.step()) return error.UnknownOperation;
    return try Status.parse(stmt.columnText(0));
}

/// Records the later-proven truth for an unsettled attempt. `status` keeps
/// the original observation; callers read `effectiveStatus()`.
pub fn recordResolution(
    store: *Store,
    request_id: []const u8,
    resolved: ResolvedStatus,
    evidence: []const u8,
    now: i64,
) Error!void {
    var stmt = try store.db.prepare(
        \\UPDATE operations
        \\   SET resolved_status = ?1, reconciled_at = ?2,
        \\       resolution_evidence = ?3, updated_at = ?2
        \\ WHERE request_id = ?4
    );
    defer stmt.deinit();
    try stmt.bindText(1, resolved.text());
    try stmt.bindInt(2, now);
    try stmt.bindText(3, evidence);
    try stmt.bindText(4, request_id);
    _ = try stmt.step();
}

/// Attempts that may still be touching the remote host. Used to block a
/// same-scope mutation (B7) and to fill the handoff package.
pub fn unsettled(store: *Store, arena: Allocator, server_id: i64) (Error || Allocator.Error)![]Operation {
    var out: std.ArrayList(Operation) = .empty;
    var stmt = try store.db.prepare(select_columns ++
        \\ WHERE server_id = ?1
        \\   AND resolved_status IS NULL
        \\   AND status IN ('submitted','remote_started','indeterminate')
        \\ ORDER BY created_at DESC
    );
    defer stmt.deinit();
    try stmt.bindInt(1, server_id);
    while (try stmt.step()) try out.append(arena, try rowToOperation(arena, &stmt));
    return out.toOwnedSlice(arena);
}

/// Unsettled attempts overlapping a scope, for the mutation guard.
pub fn unsettledInScope(
    store: *Store,
    arena: Allocator,
    server_id: i64,
    scope_kind: ScopeKind,
    scope_key: []const u8,
) (Error || Allocator.Error)![]Operation {
    var out: std.ArrayList(Operation) = .empty;
    var stmt = try store.db.prepare(select_columns ++
        \\ WHERE server_id = ?1
        \\   AND resolved_status IS NULL
        \\   AND status IN ('submitted','remote_started','indeterminate')
        \\   AND (scope_kind = 'server'
        \\        OR (scope_kind = ?2 AND scope_key = ?3))
        \\ ORDER BY created_at DESC
    );
    defer stmt.deinit();
    try stmt.bindInt(1, server_id);
    try stmt.bindText(2, @tagName(scope_kind));
    try stmt.bindText(3, scope_key);
    while (try stmt.step()) try out.append(arena, try rowToOperation(arena, &stmt));
    return out.toOwnedSlice(arena);
}

pub fn recent(store: *Store, arena: Allocator, server_id: i64, limit: i64) (Error || Allocator.Error)![]Operation {
    var out: std.ArrayList(Operation) = .empty;
    var stmt = try store.db.prepare(select_columns ++
        " WHERE server_id = ?1 ORDER BY created_at DESC LIMIT ?2");
    defer stmt.deinit();
    try stmt.bindInt(1, server_id);
    try stmt.bindInt(2, limit);
    while (try stmt.step()) try out.append(arena, try rowToOperation(arena, &stmt));
    return out.toOwnedSlice(arena);
}

/// Latest attempt carrying this alias (e.g. a job name), newest first.
pub fn latestByAlias(store: *Store, arena: Allocator, server_id: i64, alias: []const u8) (Error || Allocator.Error)!?Operation {
    var stmt = try store.db.prepare(select_columns ++
        " WHERE server_id = ?1 AND alias = ?2 ORDER BY created_at DESC LIMIT 1");
    defer stmt.deinit();
    try stmt.bindInt(1, server_id);
    try stmt.bindText(2, alias);
    if (!try stmt.step()) return null;
    return try rowToOperation(arena, &stmt);
}
