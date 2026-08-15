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
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Store = @import("store/Store.zig");
const operations = @import("store/operations.zig");
const receipts = @import("store/receipts.zig");
const transfers = @import("store/transfers.zig");
const jobs = @import("store/jobs.zig");
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
    /// The machine profile this attempt is running as (`policy.ownerToken`).
    ///
    /// Audit subject, never identity. It used to be what the lease guard
    /// compared, which made every session on one machine the same lease owner;
    /// a lease is now held by an attempt's `request_id` and this token only
    /// records *which machine* forced its way past a barrier. See
    /// `leases.Lease.profile_token`.
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
    Allocator.Error || leases.Error ||
    error{ IllegalTransition, UnknownOperation, UnknownScopeKind };

/// What the `jobs` cache row must become when an attempt is settled, or why
/// there is none to write.
///
/// Passed in rather than derived here, because only the caller knows which row
/// it read and what it read there — and the whole point of the snapshot CAS in
/// `jobs` is that the write is checked against that reading. Deriving the
/// expectation inside this function would mean reading the row again, which is
/// the guess the CAS exists to replace.
pub const JobCacheSync = union(enum) {
    /// This settlement has no cache row behind it: the attempt is not a job,
    /// or its row has already been forgotten. Distinct from a refusal — the
    /// caller is stating a fact, not failing to write.
    none,
    /// Record how the job ended.
    finish: Finish,
    /// Destroy the row: `job rm`, which settles the attempt and forgets the
    /// name in the same breath.
    forget: Forget,

    pub const Finish = struct {
        expected: jobs.FinishExpectation,
        status: jobs.Settled,
        exit_code: ?i64,
        /// The remote's own clock when the host reported one, ours otherwise.
        /// The column mixes them by nature; the ledger is where the two are
        /// kept apart.
        at: i64,
    };

    pub const Forget = struct {
        expected: jobs.RemoveExpectation,
        grounds: jobs.RemovalGrounds,
    };
};

/// What happened to the cache row alongside the settlement.
///
/// Four answers rather than a bool, because they send a caller to four
/// different places and three of them are not success.
pub const CacheResult = union(enum) {
    /// The caller said there was no row to write.
    not_applicable,
    /// Written in the same transaction as the terminal.
    synced,
    /// Not written: the ledger already held a terminal recorded by somebody
    /// else, so this call established nothing to copy into the cache.
    ledger_already_settled,
    /// The row on disk is not the row the caller read. The settlement stands;
    /// the cache does not describe it.
    refused: jobs.Conflict,
};

pub const SettledWithCache = struct {
    outcome: receipts.SettleOutcome,
    cache: CacheResult,

    /// The status the *ledger* holds, which is not always the one the caller
    /// asked for: a peer may have settled the same attempt first.
    pub fn status(self: SettledWithCache) op_state.Status {
        return switch (self.outcome) {
            .recorded => |r| r.status,
            .already_settled => |r| r.status,
        };
    }
};

/// Called between the settlement and the cache write.
///
/// A test seam, and it exists because the property that matters cannot be
/// observed from outside: "the ledger and the cache row are written in one
/// transaction" is only falsifiable by trying to change the row in between,
/// from a connection that is not the one holding the transaction. The gate
/// installs a probe that attempts exactly that; under one `BEGIN IMMEDIATE`
/// the probe cannot take the write lock, and under two transactions it can.
///
/// `void` outside a test build — no storage, and the call site is behind
/// `comptime builtin.is_test`, so the shipped binary contains neither the
/// variable nor the branch.
pub var between_settle_and_cache: if (builtin.is_test) ?*const fn () void else void =
    if (builtin.is_test) null else {};

/// `jobs.removeLocked` takes its grounds at comptime — the statement's state
/// list is rendered from them — and a sync request carries them as a value.
/// One `inline else` is the whole of the conversion.
fn removeUnderGrounds(store: *Store, forget: JobCacheSync.Forget) jobs.WriteError!jobs.Write {
    return switch (forget.grounds) {
        inline else => |grounds| jobs.removeLocked(store, forget.expected, grounds),
    };
}

/// `adoptCheckpoint` is the only step here that *drives* the checkpoint table,
/// so it is the only one that can fail across its whole vocabulary. `Error`
/// already carries the adjudication subset — `receipts.resolve` writes to that
/// table now, to say what a resolution established about a rename nobody
/// watched — so `begin`, `settle` and `runCommand` do declare a handful of
/// checkpoint refusals they cannot themselves produce. That is the cost of
/// putting the two writes in one transaction, and it is bounded: the rest of
/// the table's refusals stay here, where the only function that can produce
/// them is.
pub const AdoptError = Error || transfers.Error;

/// Whether anything else is laying claim to `target`, as one definition.
///
/// `request_id` is this attempt's own identity, and it answers both halves at
/// once: an unsettled operation with that id is *us*, and a lease with that
/// owner is *ours*. Those used to be two parameters — the request id for the
/// operation half and `policy.ownerToken` for the lease half — and the second
/// was a token minted once per machine profile, so every agent on one machine
/// skipped every other agent's lease as if it were its own. One id means the
/// lease half can only ever exempt the attempt that actually took the lease.
///
/// `server_id` is optional and null is a real value here, not "skip the
/// check": it names the local realm, the set of attempts recorded against no
/// host. Until now this took a plain `i64` and both call sites reached it
/// through `if (self.server_id) |…|`, so an attempt with no server ran no guard
/// at all — and, because the guard queries matched `server_id = ?1`, was
/// invisible to everybody else's guard too. `fetch` is that shape (its
/// destination is this machine, so there is no host row to point at), so two
/// fetches writing the same local path would have neither blocked nor been
/// blocked. Stated as what the shape entails and not as something that
/// happened: nothing in this binary creates a `fetch` — it is a
/// `transfers.Direction` with no CLI verb — so the local realm has no producer
/// yet and the hole was never walked into. See `operations.Realm`.
///
/// Caller must hold the write transaction. A guard evaluated outside the
/// transaction that acts on it is not a guard: whatever it checked can become
/// false before the write lands.
fn blockerLocked(
    store: *Store,
    arena: Allocator,
    server_id: ?i64,
    target: Scope,
    request_id: []const u8,
    now: i64,
) Error!?Blocker {
    var found: ?Blocker = null;

    const unsettled = try operations.unsettledInScope(store, arena, server_id, target);
    for (unsettled) |op| {
        if (std.mem.eql(u8, op.request_id, request_id)) continue;
        found = .{ .unsettled = op };
        break;
    }

    // Leases cannot speak about the local realm at all: `leases.server_id` is
    // `NOT NULL REFERENCES servers(id)`, so there is no row shape for "the
    // machine running this" and none can be inserted. A NULL-server attempt
    // therefore observes the unsettled-operation barrier and only that one.
    //
    // Written as a real gap rather than left to be read off the `if`, because
    // it is one: closing it means giving leases a nullable server or a second
    // owner column, which is a foreign-key change and a persisted-shape
    // decision. Until then the local realm has one barrier, not two, and
    // saying so here is the difference between a known limit and a hole
    // somebody rediscovers.
    //
    // Run even when we already have a reason to refuse: it expires stale
    // leases on the way past, and that housekeeping should not depend on the
    // order the two checks happen to be in.
    if (server_id) |host| {
        if (try leases.conflictForLocked(store, arena, host, target, request_id, now)) |lease| {
            if (found == null) found = .{ .lease = lease };
        }
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
    /// The machine profile that opened this attempt, recorded on the override
    /// audit so it says *who* forced its way past a barrier. Null on a handle
    /// re-opened by `attach`: that is a later process observing somebody else's
    /// attempt, and naming its own profile there would attribute the act to the
    /// wrong machine. Never an identity — see `BeginOptions.owner_token`.
    owner_token: ?[]const u8 = null,
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

        // Unconditional in the server: `blockerLocked` takes the optional
        // directly, because a null server names the local realm and not "no
        // guard". A `fetch` writes a local path and used to skip this
        // entirely.
        if (try blockerLocked(self.store, self.arena, self.server_id, self.scope, self.id(), at)) |blocker| {
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
                    .detail_json = try forcedJson(self.arena, blocker, self.owner_token),
                }, audit_seq);
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

    /// Takes over a checkpoint an earlier attempt left behind.
    ///
    /// Three writes in one transaction: the checkpoint changes hands, and each
    /// of the two operations records that it did. They belong together because
    /// the ledger is how a later session works out which attempt owned which
    /// bytes, and half a hand-over — a surrender with no matching adoption, or
    /// the reverse — does not read as an incomplete record, it reads as a fact.
    /// `transfers.adoptLocked` is a bare statement precisely so this function
    /// can hold that transaction; the checkpoint module cannot write receipts
    /// itself without inverting the one-way dependency `receipts` declares.
    ///
    /// The surrendering operation is normally settled by the time it gets here,
    /// and the observation is written onto that settled attempt anyway. That is
    /// not leniency: the ordinary reason a checkpoint is up for adoption is that
    /// the attempt holding it stopped and was settled, so refusing to record
    /// the hand-over there would blank the event on exactly the side an auditor
    /// reading the abandoned attempt will look at. Nothing is revised by
    /// writing it — `checkpoint` observations cannot carry a terminal status
    /// and do not touch `operations.status`, so the settled attempt's verdict
    /// stands.
    ///
    /// What `transfers.adoptLocked` requires of that attempt is that its
    /// *effective* status does not block scope: either it never reached the
    /// remote, or it recorded an outcome that is not "unknown", or somebody
    /// reconciled the unknown one with evidence. It is not a liveness check and
    /// cannot be — a hard-killed process leaves no row — but it is the strongest
    /// claim this database can hold, and it is a claim about evidence rather
    /// than about paperwork. The route for a crashed attempt is `terminus
    /// request reconcile <id>`; there is no automatic sweep, so a resume costs
    /// one explicit reconcile first.
    ///
    /// This changes no state. A row whose owner died *mid-act* — `verifying` or
    /// `publishing` — cannot be continued as it stands and is refused here; see
    /// `recoverCheckpoint`.
    pub fn adoptCheckpoint(
        self: *Execution,
        checkpoint_id: i64,
        surrendered_by: []const u8,
    ) AdoptError!void {
        const at = self.now();

        try self.store.db.exec("BEGIN IMMEDIATE");
        errdefer self.store.db.exec("ROLLBACK") catch {};

        // First, because it is the write that can be refused. If the CAS is
        // lost or the heir is ineligible, the rollback leaves no observation
        // claiming a hand-over that did not happen.
        try transfers.adoptLocked(self.store, checkpoint_id, surrendered_by, self.id(), at);
        try self.recordHandover(checkpoint_id, surrendered_by, null, null, at);

        try self.store.db.exec("COMMIT");
    }

    /// Recovers a checkpoint whose owner stopped in the middle of an act.
    ///
    /// A sibling of `adoptCheckpoint` rather than a flag on it, because the two
    /// differ in the one thing a caller has to be sure of before it acts on the
    /// row. Adoption continues a transfer exactly as the row describes it;
    /// recovery *rewrites the state first*, because the state the row is in is
    /// one no reader can act on — `verifying` and `publishing` describe a
    /// process that is doing something, and there is no process.
    ///
    /// The composite, all of it inside one transaction and all of it refusable
    /// before a single ledger row is written:
    ///
    ///  1. the incumbent must not block scope, and the heir must be fit —
    ///     the same two clauses adoption is guarded by, in the same statement
    ///     as the CAS;
    ///  2. the ownership CAS;
    ///  3. the normalisation, `verifying → paused` or
    ///     `publishing → indeterminate_publish`, through the same transition
    ///     statement every other state change goes through;
    ///  4. a `checkpoint` observation on each side, naming the other and
    ///     saying what the row was normalised into.
    ///
    /// Steps 2 and 3 are in that order, and the reverse is not available: the
    /// normalisation is an ordinary transition keyed on whoever owns the row,
    /// so performing it first would mean writing as the dead attempt. Doing it
    /// through a statement of recovery's own is what the route partition in
    /// `transfers` exists to prevent — recovery would become a writer with
    /// edges nobody else has, which is how `setState` came to be able to
    /// adjudicate.
    ///
    /// Returns what the row became, because the two answers send the caller to
    /// different places: `paused` is resumable and this operation may go on to
    /// resume it, while `indeterminate_publish` is not — the rename may have
    /// landed, and only evidence about the destination can say.
    ///
    /// Recovery decides nothing about the transfer and releases nothing. In
    /// particular the destination stays held in both outcomes, which is correct
    /// in both: a paused transfer is still going to publish there, and an
    /// unjudged one may already have.
    pub fn recoverCheckpoint(
        self: *Execution,
        checkpoint_id: i64,
        abandoned_by: []const u8,
    ) AdoptError!transfers.State {
        const at = self.now();

        try self.store.db.exec("BEGIN IMMEDIATE");
        errdefer self.store.db.exec("ROLLBACK") catch {};

        // Read before the recovery, because `verifying → paused` clears the
        // column: a digest taken over the staged partial does not survive into
        // a state whose resume is entitled to truncate those bytes (see
        // `transfers.clearClause`). Nothing else stored it, so without this the
        // dead attempt's reading would be gone rather than merely no longer
        // authoritative, and the ledger is where a fact stops being the working
        // record's and becomes history's.
        const held = try transfers.verifiedHashLocked(self.store, self.arena, checkpoint_id);

        // Then the recovery, for the same reason adoption puts its refusable
        // write first: a rollback leaves no observation claiming a recovery
        // that did not happen.
        const normalised = try transfers.recoverLocked(
            self.store,
            checkpoint_id,
            abandoned_by,
            self.id(),
            at,
        );

        // Reported as discarded only when the normalisation actually discarded
        // it, which is a question about the state the row *became* and so
        // cannot be answered before the write. The other normalisation,
        // `publishing → indeterminate_publish`, keeps the digest — those bytes
        // went to a rename and nobody may truncate them now — and a receipt
        // announcing the loss of a digest still sitting in the row is a worse
        // record than no receipt at all.
        const discarded = if (transfers.discardsVerifiedHash(normalised)) held else null;
        try self.recordHandover(checkpoint_id, abandoned_by, normalised, discarded, at);

        try self.store.db.exec("COMMIT");
        return normalised;
    }

    /// The two observations a hand-over writes, one on each side.
    ///
    /// Shared by adoption and recovery because a trail that recorded one of
    /// them differently would make "who held this checkpoint when" answerable
    /// only by knowing which call had been made. `normalised_to` is the whole
    /// of the difference: null when the row was taken as it stood, and the new
    /// state when it was not.
    ///
    /// Caller must hold the transaction — both writes and whatever moved the
    /// checkpoint have to land together or not at all.
    fn recordHandover(
        self: *Execution,
        checkpoint_id: i64,
        counterparty: []const u8,
        normalised_to: ?transfers.State,
        discarded_verified_sha256: ?[]const u8,
        at: i64,
    ) Error!void {
        const gave_up_seq = try receipts.nextSeqLocked(self.store, counterparty);
        _ = try receipts.insertLocked(self.store, .{
            .request_id = counterparty,
            .kind = .checkpoint,
            .phase = "surrendered",
            .observed_at = at,
            .detail_json = try handoverJson(
                self.arena,
                "checkpoint_surrendered",
                checkpoint_id,
                self.id(),
                normalised_to,
                discarded_verified_sha256,
            ),
        }, gave_up_seq);

        const took_seq = try receipts.nextSeqLocked(self.store, self.id());
        _ = try receipts.insertLocked(self.store, .{
            .request_id = self.id(),
            .kind = .checkpoint,
            .phase = "adopted",
            .observed_at = at,
            .detail_json = try handoverJson(
                self.arena,
                "checkpoint_adopted",
                checkpoint_id,
                counterparty,
                normalised_to,
                discarded_verified_sha256,
            ),
        }, took_seq);
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

    /// `settleAttached`, for a caller that already holds the write
    /// transaction.
    ///
    /// The reason this exists rather than a flag on the one above: a
    /// settlement almost never travels alone. A job's outcome has to reach the
    /// ledger *and* the `jobs` cache row that the next `run --name X` consults,
    /// and those two used to be written in two transactions with an unbounded
    /// gap in between. See `settleAttachedAndSyncJob`, which is the only
    /// in-tree caller and the reason the primitive is public.
    pub fn settleAttachedLocked(
        self: *Execution,
        terminal: op_state.Terminal,
        extra: receipts.TerminalExtra,
    ) Error!receipts.SettleOutcome {
        const outcome = try receipts.settleLocked(
            self.store,
            self.id(),
            terminal,
            extra,
            self.now(),
        );
        self.settled = true;
        self.status = switch (outcome) {
            .recorded => |r| r.status,
            .already_settled => |r| r.status,
        };
        return outcome;
    }

    /// Settles an attached attempt and brings its `jobs` cache row into line
    /// with what the ledger now holds — one transaction, so the two cannot
    /// disagree about the same moment.
    ///
    /// This is the shape seven call sites were missing. Each of them settled
    /// the attempt and then wrote the cache as a separate statement outside
    /// any transaction of their own, so an observer arriving in between read a
    /// ledger that said the job was over and a row that said it was running —
    /// and the row is what `run --name X` checks *before* the scope guard, so
    /// the divergence was visible as a refusal the ledger could not explain.
    ///
    /// The cache is written only when *this* call recorded the terminal —
    /// except for `.forget`, which is written either way. `already_settled`
    /// means a peer got there first and the ledger holds their verdict, not
    /// ours; the cache's two settled words each assert something specific
    /// (`exited` carries an exit code, `killed` says somebody stopped it) and
    /// neither is a fact this call established. A removal asserts nothing about
    /// the outcome — it is the operator forgetting a name — so refusing to
    /// forget it because somebody else settled the attempt first would leave
    /// the row behind for good. The caller is told which happened and reports
    /// it: see `CacheResult`.
    ///
    /// A refused cache write does *not* roll the settlement back. The ledger is
    /// the record and it is now correct; what the refusal says is that the row
    /// the caller read is no longer the row on disk, which is a fact about the
    /// cache and not about the outcome. A database *error*, by contrast, takes
    /// the whole thing down: an all-or-nothing failure leaves both records
    /// where they were, which is the state a retry can act on.
    pub fn settleAttachedAndSyncJob(
        self: *Execution,
        terminal: op_state.Terminal,
        extra: receipts.TerminalExtra,
        sync: JobCacheSync,
    ) (Error || jobs.WriteError)!SettledWithCache {
        self.settled = false;

        try self.store.db.exec("BEGIN IMMEDIATE");
        errdefer self.store.db.exec("ROLLBACK") catch {};

        const outcome = try self.settleAttachedLocked(terminal, extra);

        if (comptime builtin.is_test) {
            if (between_settle_and_cache) |probe| probe();
        }

        const cache: CacheResult = switch (sync) {
            .none => .not_applicable,
            .finish => |f| switch (outcome) {
                .already_settled => .ledger_already_settled,
                .recorded => switch (try jobs.markFinishedLocked(
                    self.store,
                    f.expected,
                    f.status,
                    f.exit_code,
                    f.at,
                )) {
                    .applied => .synced,
                    .refused => |conflict| .{ .refused = conflict },
                },
            },
            .forget => |g| switch (try removeUnderGrounds(self.store, g)) {
                .applied => .synced,
                .refused => |conflict| .{ .refused = conflict },
            },
        };

        try self.store.db.exec("COMMIT");
        return .{ .outcome = outcome, .cache = cache };
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
    // Unconditional in the server, for the reason given at `blockerLocked`: a
    // null server is the local realm, not an excuse to skip the guard.
    //
    // The id passed is the one about to be created, which cannot yet own
    // anything: no operation row, and — because a lease is held by an attempt —
    // no lease either. So nothing is exempted here, which is correct for a
    // brand new attempt and is why this call needed no separate "exclude"
    // argument once the owner became the request id.
    if (try blockerLocked(store, arena, opts.server_id, opts.scope, &request_id, opts.now)) |blocker| {
        if (opts.mutating and !opts.force) {
            // Nothing was inserted; the commit only keeps the lease
            // expiry pass the check performed on its way through.
            try store.db.exec("COMMIT");
            return .{ .blocked = blocker };
        }
        advisory = blocker;
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
            .detail_json = try forcedJson(arena, advisory.?, opts.owner_token),
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

/// One side of a checkpoint hand-over, as the other side will need to read it.
///
/// Both rows name the counterparty, so either operation's trail alone answers
/// "who took it" or "who gave it up" without a join through the checkpoint —
/// which by then belongs to someone else and may have moved on again.
fn handoverJson(
    arena: Allocator,
    event: []const u8,
    checkpoint_id: i64,
    counterparty: []const u8,
    normalised_to: ?transfers.State,
    discarded_verified_sha256: ?[]const u8,
) Allocator.Error![]u8 {
    var writer: std.Io.Writer.Allocating = .init(arena);
    std.json.Stringify.value(.{
        .schemaVersion = receipts.schema_version,
        .event = event,
        .checkpointId = checkpoint_id,
        .counterparty = counterparty,
        // Null on an adoption, which took the row as it stood. Written even
        // then, because "this hand-over rewrote nothing" is the fact an auditor
        // reading a recovered row next door needs, and an absent key would
        // leave it to be inferred from the shape of the document.
        .normalisedTo = if (normalised_to) |s| s.text() else null,
        // The digest the recovered row stopped carrying, when there was one.
        // `verifying → paused` clears it because a resume may truncate the
        // bytes it covered, and this is the only other place it is written
        // down: an auditor asking what the dead attempt had hashed reads it
        // here, and a heir that later records a different one can be compared
        // against it. Null on an adoption and on a recovery of a row that never
        // had one.
        .discardedVerifiedSha256 = discarded_verified_sha256,
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

fn forcedJson(arena: Allocator, blocker: Blocker, forced_by_profile: ?[]const u8) Allocator.Error![]u8 {
    var writer: std.Io.Writer.Allocating = .init(arena);
    switch (blocker) {
        .unsettled => |op| std.json.Stringify.value(.{
            .schemaVersion = receipts.schema_version,
            .event = "forced_past_blocker",
            .blocker = "unsettled_operation",
            .blockingRequestId = op.request_id,
            .blockingStatus = op.status.text(),
            .forcedByProfile = forced_by_profile,
        }, .{}, &writer.writer) catch return error.OutOfMemory,
        .lease => |lease| std.json.Stringify.value(.{
            .schemaVersion = receipts.schema_version,
            .event = "forced_past_blocker",
            .blocker = "lease",
            // The attempt whose claim this displaced, and the machine it ran
            // on. Two fields, because they answer different questions and the
            // second one cannot answer the first: one machine profile covers
            // every session on that machine, which is exactly why it stopped
            // being what a lease is keyed on.
            .owner = lease.owner_request_id,
            .ownerProfile = lease.profile_token,
            .expiresAt = lease.expires_at,
            .forcedByProfile = forced_by_profile,
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

/// The best available text for a transport failure.
///
/// The connection's own message when it has one, the error name otherwise —
/// never both, and never an empty string standing in for "no reason given".
///
/// `pub` because `runCommand` is not the only caller that hands a transport
/// error to `transportLoss`: a command whose remote act is a single tmux
/// invocation (`terminus write`) drives the boundary step by step and reaches
/// the same decision point with the same two sources of text. Two copies of
/// "message, or else the error name" is how one of them comes to pass `""`.
pub fn describe(executor: Executor, err: anyerror) []const u8 {
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
