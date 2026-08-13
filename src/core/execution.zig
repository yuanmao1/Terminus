//! The execution boundary.
//!
//! Every call that can produce a remote side effect goes through an
//! `Execution`. It is not a convenience wrapper: it is the single place
//! where operation identity, the scope guard, leases, state transitions,
//! terminal receipts and receipt-persistence failures are joined, so that no
//! command can assemble its own version of those rules.
//!
//! The property that matters is what happens when things go wrong. An
//! `Execution` knows how far it got, so a dropped connection is classified
//! by the one function allowed to make that call
//! (`op_state.terminalForTransportLoss`): before submission it is a proven
//! failure, after submission it is `indeterminate`. No command is in a
//! position to guess, because no command sees the transport error directly —
//! it hands it here.
//!
//! An `Execution` that is dropped without a terminal is a bug, and is
//! recorded as `indeterminate` rather than quietly disappearing: an attempt
//! that reached the remote and left no verdict is exactly the case a later
//! session must not mistake for "nothing happened".
const std = @import("std");
const Allocator = std.mem.Allocator;
const Store = @import("store/Store.zig");
const operations = @import("store/operations.zig");
const receipts = @import("store/receipts.zig");
const leases = @import("store/leases.zig");
const op_state = @import("store/op_state.zig");
const scope_mod = @import("store/scope.zig");
const ids = @import("store/ids.zig");
const supervisor = @import("supervisor.zig");
const Executor = @import("exec.zig").Executor;
const Ssh = @import("ssh/Client.zig");

pub const Scope = scope_mod.Scope;
pub const Capability = supervisor.Capability;

pub const BeginOptions = struct {
    server_id: ?i64,
    server_name: []const u8,
    kind: operations.Kind,
    /// What this attempt may touch. An operation that cannot name its blast
    /// radius is treated as covering the whole server.
    scope: Scope = scope_mod.unknown,
    alias: ?[]const u8 = null,
    /// Whether this attempt changes remote state.
    ///
    /// Mutations are blocked by an unsettled writer on the same scope or by a
    /// foreign lease; read-only work is only warned about, because refusing
    /// every `exec` while one job is unsettled would make the guard unusable
    /// and get it switched off.
    ///
    /// Defaults to `true`, and the asymmetry of the two mistakes is why:
    /// wrongly treating a read as a mutation costs a refusal the caller can
    /// override, while wrongly treating a mutation as a read can apply a
    /// change twice. A caller that knows better says so.
    ///
    /// The value is persisted with the operation, so the guard can still tell
    /// which role an attempt claimed long after the caller is gone.
    mutating: bool = true,
    /// Already redacted. Raw argv must never reach the ledger.
    argv_redacted: ?[]const u8 = null,
    argv_sha256: ?[]const u8 = null,
    cwd: ?[]const u8 = null,
    shell: ?[]const u8 = null,
    transport: ?[]const u8 = null,
    capability: Capability = supervisor.shell_capability,
    owner_token: []const u8,
    /// Proceed despite a blocker, recording that the override happened.
    force: bool = false,
    now: i64,
};

/// Why a mutation was refused, or (for read-only work) what it is running
/// alongside.
pub const Blocker = union(enum) {
    /// A peer attempt may still be affecting this scope.
    unsettled: operations.Operation,
    /// Someone else holds an overlapping lease.
    lease: leases.Lease,
};

pub const Start = union(enum) {
    ready: Execution,
    blocked: Blocker,
};

/// The result of asking to submit.
///
/// `submitted` is the point of no return, so it is also the point the scope
/// guard has to be enforced at — see `Execution.submitted`.
pub const Submit = union(enum) {
    /// The attempt is now `submitted`. From here a transport failure proves
    /// nothing about the remote.
    submitted,
    /// Someone else holds the scope. Nothing was sent.
    refused: Blocker,
};

pub const Error = Store.Db.Error || receipts.Error || operations.Error ||
    Allocator.Error || error{ IllegalTransition, UnknownOperation, UnknownScopeKind };

/// Whether anything else is laying claim to `target`, as one definition.
///
/// Caller must hold the write transaction. A guard evaluated outside the
/// transaction that acts on it is not a guard: whatever it checked can become
/// false before the write lands.
fn blockerLocked(
    store: *Store,
    arena: Allocator,
    server_id: i64,
    target: Scope,
    owner_token: []const u8,
    exclude_request_id: ?[]const u8,
    now: i64,
) Error!?Blocker {
    var found: ?Blocker = null;

    const unsettled = try operations.unsettledInScope(store, arena, server_id, target);
    for (unsettled) |op| {
        if (exclude_request_id) |self_id| {
            if (std.mem.eql(u8, op.request_id, self_id)) continue;
        }
        found = .{ .unsettled = op };
        break;
    }

    // Run the lease check even when we already have a reason to refuse: it
    // expires stale leases on the way past, and that housekeeping should not
    // depend on the order the two checks happen to be in.
    if (try leases.conflictForLocked(store, arena, server_id, target, owner_token, now)) |lease| {
        if (found == null) found = .{ .lease = lease };
    }

    return found;
}

pub const Execution = struct {
    request_id: [ids.len]u8,
    /// The server this attempt is bound to, as resolved by `begin`.
    server_id: ?i64,
    store: *Store,
    arena: Allocator,
    io: std.Io,
    scope: Scope,
    capability: Capability,
    /// Whether this attempt changes remote state. Decides whether a claim on
    /// the same scope refuses it or merely warns. Safe default; see
    /// `BeginOptions.mutating`.
    mutating: bool = true,
    /// The caller chose to proceed past a blocker. Carried through to
    /// `submitted`, where the guard is actually binding.
    force: bool = false,
    /// Identifies who we are for lease purposes, so our own lease is not
    /// mistaken for someone else's.
    owner_token: []const u8 = "",
    /// Mirror of the persisted status, so transport failures can be
    /// classified without another read.
    status: op_state.Status = .created,
    settled: bool = false,
    /// Present for read-only work that is running alongside something
    /// unsettled; surfaced to the caller rather than acted on.
    advisory: ?Blocker = null,
    /// Unique per attempt, for supervision markers.
    nonce: u64,

    pub fn id(self: *const Execution) []const u8 {
        return &self.request_id;
    }

    fn now(self: *const Execution) i64 {
        const ts = std.Io.Timestamp.now(self.io, .real);
        return @intCast(@divTrunc(ts.nanoseconds, std.time.ns_per_s));
    }

    /// Moves to `connecting`. Call immediately before dialing.
    pub fn connecting(self: *Execution) Error!void {
        try operations.advance(self.store, self.id(), .connecting, self.now());
        self.status = .connecting;
        _ = try receipts.append(self.store, .{
            .request_id = self.id(),
            .kind = .connect,
            .status = .connecting,
            .observed_at = self.now(),
        });
    }

    /// Moves to `submitted`, enforcing the scope guard as it does so.
    ///
    /// This is where the guard actually binds, and it has to be here rather
    /// than at `begin`. `begin` commits the operation as `created`, which the
    /// unsettled predicate deliberately does not count — a `created` row left
    /// behind by a process that died before dialing provably never sent
    /// anything, and blocking a scope on it forever would be a trap with no
    /// escape. But that leaves a window: between `begin`'s COMMIT and this
    /// call the row is invisible to the guard, so two concurrent
    /// `run --name deploy` could each see a clear scope and each send. The
    /// check at `begin` is a courtesy that fails fast before we dial; this
    /// one is the real thing, because the check and the write that makes this
    /// attempt visible to the next caller land in a single transaction.
    ///
    /// Nothing has been sent when this returns `.refused`.
    pub fn submitted(self: *Execution) Error!Submit {
        const at = self.now();

        try self.store.db.exec("BEGIN IMMEDIATE");
        errdefer self.store.db.exec("ROLLBACK") catch {};

        if (self.server_id) |server_id| {
            if (try blockerLocked(self.store, self.arena, server_id, self.scope, self.owner_token, self.id(), at)) |blocker| {
                if (self.mutating and !self.force) {
                    // Nothing of ours was written, so committing only keeps
                    // the lease expiry pass that the check performed.
                    try self.store.db.exec("COMMIT");
                    return .{ .refused = blocker };
                }
                if (self.advisory == null) self.advisory = blocker;
                if (self.force) {
                    const audit_seq = try receipts.nextSeqLocked(self.store, self.id());
                    _ = try receipts.insertLocked(self.store, .{
                        .request_id = self.id(),
                        .kind = .audit,
                        .observed_at = at,
                        .detail_json = try forcedJson(self.arena, blocker),
                    }, audit_seq);
                }
            }
        }

        try operations.advanceLocked(self.store, self.id(), .submitted, at);
        const seq = try receipts.nextSeqLocked(self.store, self.id());
        _ = try receipts.insertLocked(self.store, .{
            .request_id = self.id(),
            .kind = .submit,
            .status = .submitted,
            .connected = true,
            .observed_at = at,
        }, seq);
        try self.store.db.exec("COMMIT");

        self.status = .submitted;
        return .submitted;
    }

    /// Records a confirmed remote process.
    pub fn remoteStarted(self: *Execution, identity: supervisor.Identity) Error!void {
        try operations.advance(self.store, self.id(), .remote_started, self.now());
        self.status = .remote_started;
        _ = try receipts.append(self.store, .{
            .request_id = self.id(),
            .kind = .remote_start,
            .status = .remote_started,
            .connected = true,
            .remote_started = true,
            .remote_pid = identity.pid,
            .remote_pgid = identity.pgid,
            .remote_start_token = identity.start_token,
            .observed_at = self.now(),
        });
    }

    /// Settles with explicit evidence.
    pub fn settle(
        self: *Execution,
        terminal: op_state.Terminal,
        extra: receipts.TerminalExtra,
    ) Error!receipts.SettleOutcome {
        const outcome = try receipts.settle(self.store, self.id(), terminal, extra, self.now());
        self.settled = true;
        self.status = switch (outcome) {
            .recorded => |r| r.status,
            .already_settled => |r| r.status,
        };
        return outcome;
    }

    /// Settles an attempt re-opened by `attach`.
    ///
    /// `attach` starts out marked as settled so that merely *looking* at a
    /// running job cannot invent a verdict for it. Recording a real outcome
    /// lifts that guard explicitly.
    pub fn settleAttached(
        self: *Execution,
        terminal: op_state.Terminal,
        extra: receipts.TerminalExtra,
    ) Error!receipts.SettleOutcome {
        self.settled = false;
        return self.settle(terminal, extra);
    }

    /// Classifies a transport failure against how far we got.
    ///
    /// This is the only route from an SSH/daemon error to a terminal, which
    /// is what keeps "the connection dropped" from ever being rendered as
    /// "the command failed".
    pub fn transportLoss(self: *Execution, detail: []const u8) Error!receipts.SettleOutcome {
        const terminal = op_state.terminalForTransportLoss(self.status, detail);
        return self.settle(terminal, .{});
    }

    /// Deliberately leaves the attempt in flight.
    ///
    /// A job outlives the process that launched it, so `run` must be able to
    /// exit without settling. That is *not* the same as losing track: it is
    /// recorded as a detach, and the attempt keeps blocking its scope because
    /// something really is still running there. Whoever next observes the
    /// job — `job status`, `job watch`, a handoff — settles it via `attach`.
    pub fn detach(self: *Execution, note: []const u8) Error!void {
        _ = try receipts.append(self.store, .{
            .request_id = self.id(),
            .kind = .checkpoint,
            .phase = "detached",
            .observed_at = self.now(),
            .detail_json = try detachJson(self.arena, note),
        });
        self.settled = true; // not "finished" — "not ours to finish here"
    }

    /// Settles an attempt we gave up on, classified by how far it got.
    ///
    /// Routes through the same function as a transport failure, so giving up
    /// before dialing is a proven failure while giving up after submission is
    /// `indeterminate`. Safe to call unconditionally; does nothing once
    /// settled.
    pub fn abandon(self: *Execution, reason: []const u8) Error!void {
        if (self.settled) return;
        _ = try self.settle(op_state.terminalForTransportLoss(self.status, reason), .{});
    }

    /// Last-resort settlement for a path that returned without deciding.
    ///
    /// Leaving the row unsettled would also be honest, but a terminal that
    /// says *why* nothing was decided is what a later reconcile can act on.
    /// A failure here cannot be propagated (this runs on the way out), so it
    /// is reported rather than swallowed.
    pub fn deinit(self: *Execution) void {
        if (self.settled) return;
        self.abandon("process exited without recording an outcome") catch |err|
            reportLostReceipt(self, err);
    }
};

fn reportLostReceipt(self: *Execution, err: anyerror) void {
    std.debug.print(
        "terminus: RECEIPT_PERSIST_FAILED for {s}: {s} (remote state unknown)\n",
        .{ self.id(), @errorName(err) },
    );
}

/// Opens an execution, applying the scope guard and lease check first.
///
/// This check is the fast path, not the binding one: it refuses before we
/// waste a connection on work that is already claimed. The operation it
/// creates is `created`, which the guard deliberately does not count, so the
/// authoritative check happens again in `Execution.submitted` — see there for
/// why the two cannot be collapsed into one.
pub fn begin(
    store: *Store,
    arena: Allocator,
    io: std.Io,
    opts: BeginOptions,
) Error!Start {
    const request_id = ids.generate(io);
    const capability_json = try opts.capability.toJson(arena);

    try store.db.exec("BEGIN IMMEDIATE");
    errdefer store.db.exec("ROLLBACK") catch {};

    var advisory: ?Blocker = null;
    if (opts.server_id) |server_id| {
        if (try blockerLocked(store, arena, server_id, opts.scope, opts.owner_token, null, opts.now)) |blocker| {
            if (opts.mutating and !opts.force) {
                // Nothing was inserted; the commit only keeps the lease
                // expiry pass the check performed on its way through.
                try store.db.exec("COMMIT");
                return .{ .blocked = blocker };
            }
            advisory = blocker;
        }
    }

    try operations.create(store, .{
        .request_id = &request_id,
        .server_id = opts.server_id,
        .server_name = opts.server_name,
        .kind = opts.kind,
        .scope_kind = opts.scope.kind,
        .scope_key = opts.scope.key,
        .alias = opts.alias,
        .argv_redacted = opts.argv_redacted,
        .argv_sha256 = opts.argv_sha256,
        .cwd = opts.cwd,
        .shell = opts.shell,
        .capability_json = capability_json,
        .transport = opts.transport,
        .mutating = opts.mutating,
        .now = opts.now,
    });

    // The override audit belongs to the same transaction as the operation.
    // Appending it afterwards meant a failure there left a `created`
    // operation behind with no Execution handed back — a blocker nobody
    // could settle, because reconcile only accepts `indeterminate`.
    if (opts.force and advisory != null) {
        const seq = try receipts.nextSeqLocked(store, &request_id);
        _ = try receipts.insertLocked(store, .{
            .request_id = &request_id,
            .kind = .audit,
            .observed_at = opts.now,
            .detail_json = try forcedJson(arena, advisory.?),
        }, seq);
    }

    try store.db.exec("COMMIT");

    const execution: Execution = .{
        .request_id = request_id,
        .server_id = opts.server_id,
        .store = store,
        .arena = arena,
        .io = io,
        .scope = opts.scope,
        .capability = opts.capability,
        .mutating = opts.mutating,
        .force = opts.force,
        .owner_token = opts.owner_token,
        .advisory = advisory,
        .nonce = nonceFrom(request_id),
    };

    return .{ .ready = execution };
}

fn nonceFrom(request_id: [ids.len]u8) u64 {
    // The random tail of the id is already unique per attempt; fold it into
    // an integer the shell can print.
    var value: u64 = 0;
    for (request_id[ids.len - 12 ..]) |ch| value = value *% 31 +% ch;
    return value;
}

fn detachJson(arena: Allocator, note: []const u8) Allocator.Error![]u8 {
    var writer: std.Io.Writer.Allocating = .init(arena);
    std.json.Stringify.value(.{
        .schemaVersion = receipts.schema_version,
        .event = "detached",
        .note = note,
    }, .{}, &writer.writer) catch return error.OutOfMemory;
    return writer.toOwnedSlice();
}

/// Re-opens an attempt that a previous process left in flight.
///
/// This is how a detached job gets settled: the launching command is long
/// gone, so the truth is established by whoever next looks. Returns null when
/// the attempt is already settled — the caller then reads the recorded
/// terminal rather than producing a second opinion.
pub fn attach(
    store: *Store,
    arena: Allocator,
    io: std.Io,
    request_id: []const u8,
) Error!?Execution {
    const op = (try operations.get(store, arena, request_id)) orelse return null;
    if (op.status.isTerminal()) return null;

    var buf: [ids.len]u8 = undefined;
    if (op.request_id.len != ids.len) return null;
    @memcpy(&buf, op.request_id);

    return .{
        .request_id = buf,
        .server_id = op.server_id,
        .store = store,
        .arena = arena,
        .io = io,
        .scope = op.scopeOf(),
        .capability = supervisor.shell_capability,
        .status = op.status,
        // Settling is the caller's job now; dropping this handle without
        // deciding must not invent a verdict for work that is still running.
        .settled = true,
        .nonce = nonceFrom(buf),
    };
}


fn forcedJson(arena: Allocator, blocker: Blocker) Allocator.Error![]u8 {
    var writer: std.Io.Writer.Allocating = .init(arena);
    switch (blocker) {
        .unsettled => |op| std.json.Stringify.value(.{
            .schemaVersion = receipts.schema_version,
            .event = "forced_past_blocker",
            .blocker = "unsettled_operation",
            .blockingRequestId = op.request_id,
            .blockingStatus = op.status.text(),
        }, .{}, &writer.writer) catch return error.OutOfMemory,
        .lease => |lease| std.json.Stringify.value(.{
            .schemaVersion = receipts.schema_version,
            .event = "forced_past_blocker",
            .blocker = "lease",
            .owner = lease.owner_token,
            .expiresAt = lease.expires_at,
        }, .{}, &writer.writer) catch return error.OutOfMemory,
    }
    return writer.toOwnedSlice();
}

/// Runs one command end to end under an already-opened execution.
///
/// Every exit from this function has recorded a terminal, including the ones
/// that do not know what happened.
pub const RunOutcome = struct {
    status: op_state.Status,
    exit_code: ?i32,
    stdout: []const u8,
    stderr: []const u8,
    identity: ?supervisor.Identity,
};

/// Either the command ran (however it ended), or the guard refused to let it
/// be sent. These are not the same thing and must not share a shape: a
/// refusal has no exit code, no output, and — crucially — no remote effect.
pub const RunResult = union(enum) {
    ran: RunOutcome,
    refused: Blocker,
};

pub fn runCommand(
    execution: *Execution,
    executor: Executor,
    command: []const u8,
) Error!RunResult {
    const wrapped = try supervisor.wrapShell(execution.arena, command, execution.nonce);

    switch (try execution.submitted()) {
        .submitted => {},
        .refused => |blocker| return .{ .refused = blocker },
    }

    const result = executor.exec(execution.arena, wrapped) catch |err| {
        // We do not know whether the remote ran it. Say so.
        _ = try execution.transportLoss(describe(executor, err));
        return .{ .ran = .{
            .status = execution.status,
            .exit_code = null,
            .stdout = "",
            .stderr = "",
            .identity = null,
        } };
    };

    const observed = try supervisor.parseShell(
        execution.arena,
        execution.nonce,
        result.stdout,
        result.stderr,
    );

    if (observed.identity) |identity| try execution.remoteStarted(identity);

    const stream_extra: receipts.TerminalExtra = .{
        .stdout = .{ .bytes = @intCast(observed.stdout.len) },
        .stderr = .{ .bytes = @intCast(observed.stderr.len) },
        .remote_pid = if (observed.identity) |i| i.pid else null,
        .remote_pgid = if (observed.identity) |i| i.pgid else null,
        .remote_start_token = if (observed.identity) |i| i.start_token else null,
    };

    if (observed.exit_code) |code| {
        _ = try execution.settle(.{ .exited = .{ .exit_code = code } }, stream_extra);
        return .{ .ran = .{
            .status = execution.status,
            .exit_code = code,
            .stdout = observed.stdout,
            .stderr = observed.stderr,
            .identity = observed.identity,
        } };
    }

    // The channel closed cleanly but the exit marker never arrived: the
    // command's fate is genuinely unknown. `result.exit_code` here is the
    // channel's, not the command's, and treating it as the command's is the
    // mistake this whole path exists to avoid.
    _ = try execution.settle(.{ .indeterminate = .{
        .reason = "remote closed the channel before reporting an exit status",
        .last_observed = execution.status,
    } }, stream_extra);
    return .{ .ran = .{
        .status = execution.status,
        .exit_code = null,
        .stdout = observed.stdout,
        .stderr = observed.stderr,
        .identity = observed.identity,
    } };
}

fn describe(executor: Executor, err: anyerror) []const u8 {
    const message = executor.errorMessage();
    return if (message.len > 0) message else @errorName(err);
}

comptime {
    // `Ssh.ExecError` is what `runCommand` classifies; keep the import used
    // so a future change to that error set surfaces here.
    _ = Ssh.ExecError;
}

test {
    _ = @import("execution_test.zig");
}
