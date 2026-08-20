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
const sessions = @import("store/sessions.zig");
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
///
/// **Two arms, and there used to be a third.** `.forget` — `job rm` destroying
/// the row — lived here beside them, which made one function both a
/// non-destructive cache sync (used by `job status`, `job watch` and every
/// `job kill` branch, none of which need an authority) and a destructive commit
/// (which cannot happen without one). It now goes through `settleAndForgetJob`,
/// so the type no longer offers a caller a way to destroy a row without naming
/// whose claim licenses it.
pub const JobCacheSync = union(enum) {
    /// This settlement has no cache row behind it: the attempt is not a job,
    /// or its row has already been forgotten. Distinct from a refusal — the
    /// caller is stating a fact, not failing to write.
    none,
    /// Record how the job ended.
    finish: Finish,

    pub const Finish = struct {
        expected: jobs.FinishExpectation,
        status: jobs.Settled,
        exit_code: ?i64,
        /// The remote's own clock when the host reported one, ours otherwise.
        /// The column mixes them by nature; the ledger is where the two are
        /// kept apart.
        at: i64,
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

/// What `Execution.settleAndRemoveSession`'s one transaction did.
///
/// Four answers rather than a bool, because they send the caller to four
/// different reports and only one of them is a removal that happened.
pub const SessionRemoval = union(enum) {
    /// The terminal is written and the local row is gone. One commit, so neither
    /// of those can be true without the other.
    removed: struct {
        /// False means this machine had no metadata row for the session. Not a
        /// refusal — `sessions.removeLocked` has no owner, no expectation and no
        /// compare-and-swap — and an ordinary state for a session started
        /// outside Terminus. Reported rather than discarded, because "there was
        /// no row" and "the row is gone" are different facts and only one of
        /// them means a memory cascade happened.
        had_row: bool,
        recorded: receipts.TerminalRecord,
    },
    /// Something else was laying claim to the scope when the transaction opened.
    /// Nothing was deleted, no terminal was written, and the attempt is still
    /// unsettled — so the scope stays barred. The caller settles it with a
    /// terminal that is honest about the partial state it is actually in.
    refused: Blocker,
    /// This attempt's *own* lease is no longer live and ours, whatever anybody
    /// else is or is not claiming. Carries the state it read, because "it lapsed
    /// under us", "somebody swept it", "a peer took it" and "we never had it"
    /// are four different things to tell an operator.
    ///
    /// Separate from `refused` and not folded into it: that arm names a
    /// counterparty, and this one frequently has none. The state this exists for
    /// — `swept` — is precisely the one where there is nothing to find, which is
    /// why the overlap check passed it.
    ///
    /// Nothing was deleted and no terminal was written, exactly as `refused`.
    claim_lost: leases.ClaimState,
    /// The ledger already held a terminal for this attempt. The verdict on record
    /// is not the one this call was going to write, so the row is *not* deleted:
    /// a removal whose only durable record is somebody else's settlement is the
    /// pairing this whole transaction exists to forbid.
    ///
    /// Unreachable by construction today — a `session rm` settles its own
    /// operation once, and `Cli.settleActiveExecution` only fires on a path that
    /// never reaches here — which is why it is a value rather than an error: a
    /// caller that does reach it has to report what the ledger holds instead of
    /// inventing a verdict beside it.
    already_settled: receipts.TerminalRecord,
};

/// What became of a composite transaction that could not be committed.
///
/// Three answers, and the split that matters is between the two that are proofs
/// and the one that is not. `errdefer store.db.exec("ROLLBACK") catch {}` — the
/// shape this replaces — throws away the only evidence that the rollback
/// happened, and the caller then reported "nothing local was changed" on both
/// paths. On the second one that is a claim about a row nobody looked at: if the
/// `ROLLBACK` statement itself failed, the terminal and the delete may be on
/// disk and may not be, and the honest word for that is *unknown*.
///
/// Reported through an out-parameter rather than folded into the error, because
/// the two are independent: *why* the transaction failed and *whether it was
/// undone* are different questions, and collapsing them would cost the caller
/// the cause it needs to print.
pub const Rollback = union(enum) {
    /// Nothing needed rolling back: the transaction committed, or it never
    /// opened. Set before the transaction begins, so a failure on the way in
    /// reads as what it is.
    none,
    /// The transaction was undone and `ROLLBACK` succeeded. Nothing this call
    /// would have written is on disk — a proof, and the one the caller may report
    /// a known local state from.
    ///
    /// Two ways to arrive here, and both are the same fact about the disk: the
    /// transaction failed, or it was deliberately undone because the destruction
    /// it existed for was refused (`Committed.destruction_refused`). The second is
    /// not an error and comes back as a value, so a caller reading this beside a
    /// successful return is reading "the transaction went back", not "something
    /// broke".
    confirmed,
    /// `ROLLBACK` was issued and failed too, carrying `@errorName`.
    /// Whether the terminal and the local delete landed is genuinely not known.
    unconfirmed: []const u8,
};

/// Everything `settleAndRemoveSession` can answer with.
///
/// It carries `jobs.WriteError` through `DestructiveError`, which a session
/// removal cannot produce: one claim-backed destruction contract means one error
/// set, and `sessions.removeLocked` and `jobs.removeLocked` do not fail the same way. The
/// same trade `AdoptError` records, for the same reason — the alternative is two
/// copies of the transaction.
pub const SessionRemovalError = DestructiveError || ContractError || error{
    /// The attempt names no server, so there is no `sessions` row it could be
    /// about. Our defect, not an operator's: every control operation over a
    /// session is created with the host it resolved.
    SessionRemovalHasNoServer,
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

/// Called between the authority check and the local destruction of
/// `commitDestruction`.
///
/// A test seam, and the same one `between_settle_and_cache` is: "the authority
/// check, the terminal and the local destruction are one transaction" cannot be
/// observed from outside. The gate installs a probe that tries to take the scope
/// from another connection at exactly that instant; under one `BEGIN IMMEDIATE`
/// it cannot take the write lock, and under three separate writes it can.
///
/// One seam for every *claim-backed* destructive path, because there is now one
/// transaction: a per-verb hook would have been a second thing to remember to add
/// when a fourth verb arrives. It is not the only such seam in the tree, and the
/// other one is not a duplicate — `servers.between_check_and_delete` is the same
/// idea for the quiescence-backed contract, whose transaction this function is not
/// in and whose barriers are not the authority check this probes. See the header
/// above `commitDestruction`.
///
/// `void` outside a test build, so the shipped binary contains neither the
/// variable nor the branch.
pub var between_ownership_and_removal: if (builtin.is_test) ?*const fn () void else void =
    if (builtin.is_test) null else {};

/// Called after `commitDestruction` has the write lock and before it reads the
/// clock it evaluates authority against.
///
/// A test seam, and the property it exists for is one no fixture can arrange from
/// outside: *time passing between the two*. A process suspend, a VM resumed after
/// a pause and a forward clock jump are the three ways a live claim dies under a
/// command that believes its last renewal (see `authorityLocked`), and every one
/// of them lands in exactly this window — after the caller asked for the lock,
/// before the transaction that acts on it can read anything. The gate installs a
/// probe that expires the claim and then waits for the wall clock to pass it, so a
/// clock sampled ahead of the lock reports `held` about a claim that is gone.
///
/// `void` outside a test build, so the shipped binary contains neither the
/// variable nor the branch.
pub var between_lock_and_clock: if (builtin.is_test) ?*const fn () void else void =
    if (builtin.is_test) null else {};

/// `jobs.removeLocked` takes its grounds at comptime — the statement's state
/// list is rendered from them — and a destruction request carries them as a
/// value. One `inline else` is the whole of the conversion.
fn removeUnderGrounds(store: *Store, forget: JobForget) jobs.WriteError!jobs.Write {
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

// --- Who licenses a destructive act, and what it is about --------------------
//
// The tree conflated these two for four rounds of fixes, and every one of them
// was patched per-verb: the lease-renewal barrier, the settle-then-act window,
// the non-transactional composite, and the missing in-transaction ownership
// check. The reason a fix kept failing to generalise is that "the request id" is
// not one thing.
//
//   * `session rm` holds its lease under the request id of the control operation
//     it is about (`cmd_session.claimScope` passes `execution.id()`), so its
//     authority owner, its target operation and its own identity are the same
//     string.
//   * `job kill` / `job rm` hold theirs under a control id minted per invocation
//     (`cmd_job.claimJobScope`) that backs no operation row at all, while the
//     `Execution` they carry is the *target job attempt* — somebody else's
//     unsettled work.
//
// So a guard keyed on "the request id" asks the wrong question on two of the
// three verbs, and it does so confidently. Keyed the target's way round,
// `leases.claimStateLocked` answers `never_taken` about a lease that is live and
// ours, and `leases.conflictForLocked` reports our own lease as a peer's. Keyed
// the authority's way round for the operation half, the target attempt — which is
// unsettled and inside the scope, because that is exactly what makes it worth
// destroying — is reported as a peer blocking us from destroying it.
//
// Hence two types rather than two strings, with differently named fields so that
// an anonymous literal meant for one cannot coerce into the other.

/// Whose claim licenses a destructive act.
///
/// The owner of the lease this command took before it dialled —
/// `Control.Claim.owner_request_id`. This and only this may key a lease read:
/// `leases.claimStateLocked` answers *by owner*, and `leases.conflictForLocked`
/// exempts *by owner*.
///
/// Not the thing being acted on. `job kill` acts on somebody else's attempt and
/// holding the lease under that attempt's id would make two concurrent kills
/// renew each other — the defect one level down, which is why the id is minted
/// per invocation in the first place.
pub const AuthorityOwner = struct {
    /// The lease owner's request id.
    lease_owner_request_id: []const u8,
};

/// What a destructive act is about: the operation whose terminal it writes or
/// defers to, or the statement that there is none.
///
/// Never used to key a lease read — see `AuthorityOwner`. What it *is* used for
/// is the operation half of the peer check, where the target has to be exempted
/// or it is mistaken for a peer.
pub const TargetOperation = union(enum) {
    /// The attempt this act settles, or whose recorded terminal it defers to.
    attempt: []const u8,
    /// There is no operation behind this act at all: a `jobs` row whose attempt
    /// row is missing, so there is nothing to settle and nothing to exempt.
    /// Stated by the caller rather than reached by passing an empty string,
    /// which `leases.requireOwner` would refuse anyway and which the operation
    /// half would silently match against every other empty one.
    none,

    pub fn requestId(t: TargetOperation) ?[]const u8 {
        return switch (t) {
            .attempt => |id| id,
            .none => null,
        };
    }
};

/// The pair, as every guard in this file takes it.
pub const Identity = struct {
    authority: AuthorityOwner,
    target: TargetOperation,

    /// The shape where the two are the same value.
    ///
    /// `begin` and `submitted` — where the acting attempt is both the thing that
    /// would hold a lease and the thing being recorded — and `session rm`, whose
    /// control operation is its own lease owner. Named rather than left to two
    /// literals at each call site, because "these two are deliberately the same
    /// string here" is the fact a reader needs and a repeated literal does not
    /// state.
    pub fn coincident(request_id: []const u8) Identity {
        return .{
            .authority = .{ .lease_owner_request_id = request_id },
            .target = .{ .attempt = request_id },
        };
    }

    /// Whether an unsettled operation row is *not* a peer.
    ///
    /// Both ids, and each covers a case the other cannot. Exempting the target
    /// is what stops `job rm` from reading the very attempt it is settling as a
    /// blocker. Exempting the authority owner matters where the two coincide —
    /// `session rm`, `begin`, `submitted` — and is a no-op for the job verbs,
    /// whose minted control id backs no operation row; it is written
    /// unconditionally so that the day a verb holds its lease under a second
    /// *real* operation, that operation is not its own blocker either.
    fn exempts(self: Identity, request_id: []const u8) bool {
        if (std.mem.eql(u8, self.authority.lease_owner_request_id, request_id)) return true;
        if (self.target.requestId()) |target| return std.mem.eql(u8, target, request_id);
        return false;
    }
};

/// Whether anything else is laying claim to `target`, as one definition.
///
/// `identity` is who is asking, in both of the senses that matter: an unsettled
/// operation this identity exempts is *us or our subject*, and a lease whose
/// owner is its authority is *ours*. The lease half used to take
/// `policy.ownerToken` — a token minted once per machine profile — so every agent
/// on one machine skipped every other agent's lease as if it were its own; then
/// it took a single request id, which is right for `begin` and wrong for a verb
/// whose lease owner and subject are two values. See `Identity`.
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
    identity: Identity,
    now: i64,
) Error!?Blocker {
    var found: ?Blocker = null;

    const unsettled = try operations.unsettledInScope(store, arena, server_id, target);
    for (unsettled) |op| {
        if (identity.exempts(op.request_id)) continue;
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
        if (try leases.conflictForLocked(
            store,
            arena,
            host,
            target,
            identity.authority.lease_owner_request_id,
            now,
        )) |lease| {
            if (found == null) found = .{ .lease = lease };
        }
    }

    return found;
}

/// What the authority owner's claim, and any peer's, say about a destructive act
/// — read inside the caller's transaction.
///
/// Three answers and not a bool, because they send a caller to three different
/// reports and two of them are not the same refusal. `blocked` names a
/// counterparty; `claim_lost` frequently has none to name, and the state it
/// exists for is precisely the one where there is nothing to find.
pub const AuthorityVerdict = union(enum) {
    /// Nothing else claims an overlapping scope, and the authority owner's own
    /// claim is `held`. The only member that licenses a destructive commit.
    cleared,
    /// Something else was laying claim to the scope. Carries it, so the caller
    /// can name who.
    blocked: Blocker,
    /// The authority owner's *own* claim is not live and theirs, whatever anybody
    /// else is or is not claiming. Carries the state it read, because "it lapsed
    /// under us", "somebody swept it", "a peer took it", "we gave it back" and
    /// "we never had it" are five different things to tell an operator.
    claim_lost: leases.ClaimState,
};

/// The in-transaction authority check every claim-backed destructive commit runs,
/// expressed once.
///
/// **Two conjuncts, answering two questions neither can answer alone.**
///
/// `blockerLocked`, keyed on `identity`, answers *has anything else claimed this
/// scope* — the same definition `begin` and `submitted` use. A `--force` takeover
/// writes the incumbent's row `released` and inserts its own, so it is exactly
/// what this sees.
///
/// `leases.claimStateLocked`, keyed on the authority owner, answers *is our own
/// claim still live and ours*. Its absence was a hole rather than a rough edge: if
/// the authority's lease expires during the last remote round trip and **no
/// successor takes it**, the expiry pass sweeps the row, `blockerLocked` finds
/// nothing to report — there genuinely is nothing — and the destruction commits
/// anyway.
///
/// **The claim read comes first, and the refusal it drives comes second.** Reading
/// it first is forced: `blockerLocked` runs the lazy expiry pass on its way
/// through, which turns our own `lapsed` row into a `swept` one, so asking
/// afterwards could only ever report somebody's housekeeping — here, this
/// transaction's own — and never "we found it expired". Refusing on it *second* is
/// a separate choice: both refusals decline the identical act, so the order only
/// decides which fact the caller reports, and a peer's request id is more use than
/// "our lease is not ours". A `--force` takeover satisfies both readings at once
/// and is reported as the blocker it is.
///
/// **What can kill an authority between the last renewal and this check.**
/// `Db.busy_timeout` is 5 s, so ordinary lock contention cannot span the 120 s
/// `Control.Claim.ttl_secs`: waiting for the write lock is not a way to lose a
/// claim. What is: a peer's `--force` takeover (`leases.takeover`), the process
/// being suspended, a VM being resumed after a pause longer than the TTL, and a
/// forward jump of the wall clock — every one of which leaves the lease row
/// lapsed or displaced while this process believes its last renewal.
///
/// `server_id` is non-optional, unlike `blockerLocked`'s. `leases.server_id` is
/// `NOT NULL REFERENCES servers(id)`, so an attempt in the local realm cannot
/// hold a claim at all and there is no authority for this function to read. A
/// destructive verb with no host is therefore refused by its caller before it
/// gets here — see `SessionRemovalError.SessionRemovalHasNoServer` — rather than
/// being handed a null that would read as "no authority needed".
///
/// Caller must hold the write transaction. A guard evaluated outside the
/// transaction that acts on it is not a guard.
pub fn authorityLocked(
    store: *Store,
    arena: Allocator,
    server_id: i64,
    scope: Scope,
    identity: Identity,
    now: i64,
) Error!AuthorityVerdict {
    try store.db.requireTransaction();

    // Our own claim, read before the pass that would rewrite what it says.
    const claim = try leases.claimStateLocked(
        store,
        arena,
        server_id,
        scope,
        identity.authority.lease_owner_request_id,
        now,
    );

    // A peer, when there is one to name.
    if (try blockerLocked(store, arena, server_id, scope, identity, now)) |found|
        return .{ .blocked = found };

    // And our own claim when there is nobody to name, which is the state this
    // conjunct was added for: nothing else holds the scope, so the check above is
    // clear and correct, and the claim this command has been acting under stopped
    // being live anyway.
    if (!claim.holds()) return .{ .claim_lost = claim };

    return .cleared;
}

// --- The claim-backed destruction contract, expressed once -------------------
//
// **There are two destruction contracts in this tree, and they answer different
// questions.** Naming both is the point of this header: they were nearly folded
// into one, and folding them would have required inventing a lease so that the
// claim re-read below had something to read.
//
// This is the **claim-backed** contract. It is for a destructive act performed
// *under a lease*, and every commit that reaches it runs under the same four
// guarantees:
//
//   1. inside the transaction, the authority owner's own claim state is re-read
//      and the act is refused unless it is `held`;
//   2. inside the same transaction, a peer blocker is checked for, keyed so that
//      the target operation is never mistaken for a peer;
//   3. the terminal and the local destruction land in that same transaction, or
//      neither does;
//   4. a rollback that could not be confirmed reports the local state as unknown
//      rather than guessing.
//
// (1) is what makes it the right shape for these acts: `session rm` and `job rm`
// run for seconds against a remote host while holding a lease, and a lease can be
// lost mid-flight — swept on expiry, taken by a peer's `--force`. So the question
// it must answer at the moment of the delete is *is my claim still mine*, and only
// a re-read of that claim can answer it.
//
// Written once because it was written per-verb four times and drifted every time.
// `session rm` is the reference and reaches this through
// `Execution.settleAndRemoveSession`; `job rm` reaches it through
// `settleAndForgetJob`, including the two branches that used to call
// `jobs.remove` — a `BEGIN IMMEDIATE` of its own with no terminal beside it and
// no authority check at all.
//
// **The other contract is `servers.removeLocked`, and it must not be folded into
// this one.** `server rm` takes no lease and holds no claim, so (1) would have
// nothing to re-read and (2) no claim of ours to exempt from the peer check. What
// that act requires instead is **quiescence**: no unsettled operation, no active
// lease and no handover-bound transfer anywhere on the server, all three counted
// inside the same `BEGIN IMMEDIATE` as the DELETE. That is a stricter and
// categorically different question — *does nobody hold anything here at all*
// rather than *is my claim still mine* — and the strictness is exactly what lets
// it be asked by an actor holding nothing. Neither contract subsumes the other:
// this one licenses a destruction while peers are live elsewhere, and that one
// refuses while any peer is live at all. See the header above `servers.remove`.
//
// The price of one contract is one error set: `sessions.removeLocked` can fail
// with `Db.Error` and `jobs.removeLocked` with `jobs.WriteError`, so
// `DestructiveError` carries both and each caller declares a handful of refusals
// it cannot itself produce. That is the same trade `AdoptError` records, and it is
// bounded — the alternative is two copies of the transaction, which is what this
// replaces.

/// The local state a destructive commit destroys.
///
/// One arm per verb, and they are not interchangeable: the session delete has no
/// owner, no expectation and no compare-and-swap, while the job delete is a CAS
/// against the row the caller read and carries the grounds that entitle it.
pub const Destruction = union(enum) {
    /// `session rm`: the `sessions` row named here, whose delete cascades that
    /// session's memories away.
    session_row: []const u8,
    /// `job rm`: the `jobs` cache row, against the row the caller read.
    job_row: JobForget,
};

/// `job rm`'s destruction, as the compare-and-swap wants it.
///
/// Carries no authority of its own: the authority is named on
/// `DestructiveCommit`, once, beside the target — which is the whole point of
/// this pass. A `Forget` that carried its own owner would be a second place for
/// the two identities to disagree.
pub const JobForget = struct {
    expected: jobs.RemoveExpectation,
    grounds: jobs.RemovalGrounds,
};

/// What the destruction actually did.
pub const Destroyed = union(enum) {
    /// False means this machine had no metadata row for the session. Not a
    /// refusal — `sessions.removeLocked` has no expectation to lose — and an
    /// ordinary state for a session started outside Terminus. Reported rather
    /// than discarded, because "there was no row" and "the row is gone" are
    /// different facts and only one of them means a memory cascade happened.
    session_row: struct { had_row: bool },
    /// The `jobs` row is gone, and that is the only thing this arm can say.
    ///
    /// It used to carry `jobs.Write`, so a compare-and-swap that *refused* was a
    /// value handed back beside a committed terminal — a caller could ignore it,
    /// and the ledger then held a removal over a row still sitting on disk. A
    /// refusal now takes the transaction down with it and leaves as
    /// `Committed.destruction_refused`, so there is no answer here to ignore.
    job_row,
};

/// What a destructive commit writes to the ledger beside the destruction.
pub const Ledger = union(enum) {
    /// Settle the target in the same transaction as the destruction.
    settle: Settle,
    /// No terminal accompanies this destruction, and which of the two reasons
    /// applies is *stated* rather than inferred from a null.
    none: Absent,

    pub const Settle = struct {
        execution: *Execution,
        terminal: op_state.Terminal,
        extra: receipts.TerminalExtra,
        /// What to do when the ledger already holds a terminal for the target.
        on_rival: Rival,
    };

    /// The two answers to "a peer settled this attempt before we could", and the
    /// two verbs really do differ.
    pub const Rival = enum {
        /// Decline the destruction. `session rm`: the verdict on record is not
        /// the one this call was going to write, so a removal whose only durable
        /// record is somebody else's settlement is exactly the pairing this
        /// transaction exists to forbid.
        decline,
        /// Destroy anyway. `job rm`: forgetting a name asserts nothing about how
        /// the job ended — it is the operator forgetting a name — so declining
        /// because somebody else settled the attempt first would leave the row
        /// behind for good.
        destroy_anyway,
    };

    pub const Absent = union(enum) {
        /// There is no operation behind this destruction at all: a `jobs` row
        /// whose attempt row is missing.
        no_operation,
        /// The ledger already holds a terminal for this attempt, so there is
        /// nothing for this call to write. Carries the request id, because the
        /// attempt is still the *target* and still has to be exempted from the
        /// peer check.
        already_on_record: []const u8,
    };

    /// What the act is about — derived from the ledger rather than asked for
    /// separately, so a caller cannot name a target that disagrees with the
    /// attempt it is settling. That disagreement is the defect this whole pass
    /// is about; making it unexpressible is cheaper than checking for it.
    pub fn target(l: Ledger) TargetOperation {
        return switch (l) {
            .settle => |s| .{ .attempt = s.execution.id() },
            .none => |absent| switch (absent) {
                .no_operation => .none,
                .already_on_record => |id| .{ .attempt = id },
            },
        };
    }
};

/// One destructive act, named in full.
pub const DestructiveCommit = struct {
    /// The host the scope and the claim belong to. Non-optional; see
    /// `authorityLocked`.
    server_id: i64,
    scope: Scope,
    /// Whose claim licenses this. The lease owner, which for `job kill` / `job
    /// rm` is not the attempt being settled — see `AuthorityOwner`.
    authority: AuthorityOwner,
    /// What this writes to the ledger, and what it is about.
    ledger: Ledger,
    /// What it destroys locally.
    destroys: Destruction,

    fn identity(c: DestructiveCommit) Identity {
        return .{ .authority = c.authority, .target = c.ledger.target() };
    }
};

/// What the ledger half of a committed destruction did.
pub const LedgerResult = union(enum) {
    /// This call recorded the terminal.
    recorded: receipts.TerminalRecord,
    /// A terminal already stood for the target, this call wrote none, and the
    /// destruction went ahead regardless — `Ledger.Rival.destroy_anyway`. Named
    /// rather than folded into `recorded`, because the caller must report the
    /// verdict on record and not the one it asked for.
    rival: receipts.TerminalRecord,
    /// Nothing was written, for the reason the caller stated.
    absent: Ledger.Absent,
};

/// What one destructive transaction did.
pub const Committed = union(enum) {
    /// The destruction and the ledger write landed together. One commit, so
    /// neither can be true without the other.
    done: struct { destroyed: Destroyed, ledger: LedgerResult },
    /// Something else was laying claim to the scope when the transaction opened.
    /// Nothing was destroyed, no terminal was written, and the target is still
    /// unsettled — so the scope stays barred, which is the correct fail-closed
    /// outcome rather than a missing record.
    refused: Blocker,
    /// The authority owner's *own* claim is no longer live and theirs. Nothing
    /// was destroyed and no terminal was written, exactly as `refused`.
    claim_lost: leases.ClaimState,
    /// The ledger already held a terminal for the target and the caller asked to
    /// `decline` over one. Nothing was destroyed.
    already_settled: receipts.TerminalRecord,
    /// The local compare-and-swap did not match the row the caller read.
    ///
    /// The destruction did not happen, so the terminal that had already been
    /// written beside it in this transaction went back with it: the transaction is
    /// rolled back rather than committed, which is the one refusal here that
    /// cannot commit. The other three are refused *before* anything of ours is
    /// written and so commit the lazy lease-expiry pass on their way out; this one
    /// has a terminal on the wire already, and keeping the housekeeping would mean
    /// keeping that too — a durable receipt saying a row was removed, over a row
    /// that is still there. The expiry pass is housekeeping any later command
    /// redoes; a frozen terminal is not correctable at all.
    ///
    /// Only `Destruction.job_row` produces this: `sessions.removeLocked` has no
    /// owner, no expectation and no compare-and-swap to lose.
    destruction_refused: jobs.Conflict,
};

/// A wrapper read an arm of the contract's answer that its own request could not
/// have produced — a job's CAS answer off a session removal, or a recorded
/// terminal off a commit that stated there was none to write.
///
/// Named rather than left to `unreachable`, for the reason
/// `jobs.UnexplainedJobsRefusal` is: it means this file's own dispatch and its
/// wrappers have drifted apart, which is a bug here and not a state any caller
/// can act on.
pub const ContractError = error{ContractAnsweredAboutSomethingElse};

pub const DestructiveError = Error || jobs.WriteError;

/// Wall-clock seconds, from the `io` a call already has.
///
/// The one clock a destructive commit may use. `ctx.now` is read once at process
/// start, and a lease is the one thing in this tree that is *compared* against a
/// clock rather than merely stamped with one — so a claim check dated from process
/// start reports a lapsed lease as live, which is the guard answering yes about a
/// scope nobody holds. Taken from `io` rather than as a parameter precisely so no
/// caller can hand in the frozen stamp.
fn nowFrom(io: std.Io) i64 {
    const ts = std.Io.Timestamp.now(io, .real);
    return @intCast(@divTrunc(ts.nanoseconds, std.time.ns_per_s));
}

/// Runs one destructive act under the contract above.
///
/// The order inside the transaction is the substance:
///
///  1. the authority check, which can refuse before anything is written;
///  2. the terminal, because it is the next thing that can still be refused —
///     `canSettle`, `canTransition` and `terminalDescribesKind` all run inside
///     `receipts.settleLocked`;
///  3. the destruction, last, because it is the step nothing downstream can undo.
///
/// A refusal at (1) or (2) commits rather than rolls back, and that is deliberate:
/// nothing of ours was written, so the commit only keeps the lazy lease-expiry
/// pass the check performed on its way through — the same thing `begin` and
/// `submitted` commit on their refusal paths. A refusal at (3) is the one that
/// cannot: the terminal is already on the wire behind it, so the transaction goes
/// back whole. See `Committed.destruction_refused`.
///
/// **The clock is read after the lock, not before it.** `BEGIN IMMEDIATE` waits up
/// to `Db.busy_timeout` for the write lock, and a process suspend, a resumed VM or
/// a forward clock jump can land in that wait — the three things `authorityLocked`
/// names as the ways an authority dies. A stamp taken ahead of the wait is
/// evidence about a moment that has passed by the time the guard evaluates it, so
/// an expired lease reads `held` and the destruction commits under it. One reading
/// serves both uses inside the transaction, and deliberately: the second is the
/// terminal's `observed_at`, whose question is "when did we look", and this
/// transaction looked *here*. A separate earlier stamp there would date the
/// receipt before the check that licensed it and would answer for a moment nothing
/// in this function acted on.
///
/// A *failure* anywhere takes the whole thing down through the `errdefer`, and
/// whether that undo happened is reported through `rollback` rather than assumed:
/// a `ROLLBACK` whose own statement failed establishes nothing. See `Rollback`.
///
/// The in-memory `Execution` is updated only after the COMMIT. A handle marked
/// settled beside a transaction that rolled back would be a process believing a
/// terminal that is not on disk.
pub fn commitDestruction(
    store: *Store,
    arena: Allocator,
    io: std.Io,
    commit: DestructiveCommit,
    /// Whether the transaction was undone, when it could not be committed.
    /// Written on every path, before anything here can fail.
    rollback: *Rollback,
) DestructiveError!Committed {
    rollback.* = .none;

    // The `errdefer` below is declared after `BEGIN`, so a `BEGIN` that failed
    // leaves `rollback` at `.none` — which is the truth: no transaction opened, so
    // nothing needed undoing.
    try store.db.exec("BEGIN IMMEDIATE");
    errdefer {
        if (store.db.exec("ROLLBACK")) |_| {
            rollback.* = .confirmed;
        } else |err| {
            rollback.* = .{ .unconfirmed = @errorName(err) };
        }
    }
    if (comptime builtin.is_test) {
        if (between_lock_and_clock) |probe| probe();
    }
    const at = nowFrom(io);
    switch (try authorityLocked(store, arena, commit.server_id, commit.scope, commit.identity(), at)) {
        .cleared => {},
        .blocked => |found| {
            try store.db.exec("COMMIT");
            return .{ .refused = found };
        },
        .claim_lost => |claim| {
            try store.db.exec("COMMIT");
            return .{ .claim_lost = claim };
        },
    }

    if (comptime builtin.is_test) {
        if (between_ownership_and_removal) |probe| probe();
    }

    const ledger: LedgerResult = switch (commit.ledger) {
        .settle => |s| switch (try receipts.settleLocked(store, s.execution.id(), s.terminal, s.extra, at)) {
            .recorded => |record| .{ .recorded = record },
            .already_settled => |winner| switch (s.on_rival) {
                .decline => {
                    // Nothing was written by the settlement either — see
                    // `settleLocked`'s three non-writing exits — so this commits
                    // for the same reason the refusals above do.
                    try store.db.exec("COMMIT");
                    s.execution.settled = true;
                    s.execution.status = winner.status;
                    return .{ .already_settled = winner };
                },
                .destroy_anyway => .{ .rival = winner },
            },
        },
        .none => |absent| .{ .absent = absent },
    };

    // The destruction, last, and the only step here that can decline by value
    // rather than by error. When it does, the terminal above it has already been
    // written, so the transaction goes back whole: a `COMMIT` over a refused
    // compare-and-swap leaves a receipt saying this row was removed, over a row
    // still on disk, and a terminal is frozen — no later command can correct it.
    //
    // The `ROLLBACK` is issued here rather than left to the `errdefer` because
    // this is not an error: it is an answer, and the caller has to be handed the
    // conflict that refused it. A `ROLLBACK` that itself fails leaves through the
    // `errdefer`, which tries once more and reports `unconfirmed` — the honest
    // word for a transaction nobody could prove went back.
    const destroyed: Destroyed = switch (commit.destroys) {
        .session_row => |name| .{
            .session_row = .{ .had_row = try sessions.removeLocked(store, commit.server_id, name) },
        },
        .job_row => |forget| switch (try removeUnderGrounds(store, forget)) {
            .applied => .job_row,
            .refused => |conflict| {
                try store.db.exec("ROLLBACK");
                rollback.* = .confirmed;
                return .{ .destruction_refused = conflict };
            },
        },
    };

    try store.db.exec("COMMIT");

    switch (commit.ledger) {
        .settle => |s| switch (ledger) {
            .recorded => |record| {
                s.execution.settled = true;
                s.execution.status = record.status;
            },
            .rival => |winner| {
                s.execution.settled = true;
                s.execution.status = winner.status;
            },
            .absent => {},
        },
        .none => {},
    }

    return .{ .done = .{ .destroyed = destroyed, .ledger = ledger } };
}

/// What a `job rm`'s one transaction did.
///
/// A sibling of `SessionRemoval` rather than the same type: the destruction it
/// reports is a compare-and-swap against a row the caller read, and `had_row` is
/// not a thing a `jobs` delete can answer.
///
/// No `already_settled` arm, and that is a property rather than an omission:
/// `job rm` destroys either way (`Ledger.Rival.destroy_anyway`), and
/// `settleAndForgetJob` — not its caller — is what says so, so the state cannot
/// be asked for.
pub const JobRemoval = union(enum) {
    /// The row and the ledger write landed together.
    ///
    /// The row really is gone: a compare-and-swap that did not match leaves as
    /// `Refusal.row_moved`, so this arm carries no write for a caller to read a
    /// refusal off. It used to, and `job rm` then reported `not_removed` off a
    /// transaction that had already committed the terminal.
    forgotten: struct { ledger: LedgerResult },
    /// Nothing was destroyed and no terminal of this call's survives, and the
    /// value says which read declined it.
    refused: Refusal,
};

/// Why a destructive commit declined, as one value.
///
/// Three arms, and what refused the act is the difference. `scope_taken` names a
/// peer; `claim_lost` frequently has none to name — the state it exists for is a
/// lease that lapsed during the last round trip and was swept by somebody's
/// ordinary housekeeping, leaving the scope genuinely clear. That is exactly the
/// state the overlap check reads as "nothing is in your way", which is true, and
/// which used to be enough to delete a row. `row_moved` is about neither: the
/// authority held and the compare-and-swap still matched nothing, because the row
/// on disk is not the row the caller read.
///
/// One value rather than three sibling arms on `JobRemoval`, because the caller
/// was rebuilding exactly this union out of those arms to have something to
/// switch on. The three facts are this transaction's own, and so is the word for
/// each: a caller that had to name them itself is a caller that can name them
/// differently from the next one.
pub const Refusal = union(enum) {
    /// A peer's unsettled operation or lease covered the scope when the
    /// transaction opened.
    scope_taken: Blocker,
    /// The authority owner's *own* claim is no longer live and theirs.
    claim_lost: leases.ClaimState,
    /// The `jobs` row on disk is not the row the caller read, so the delete
    /// matched nothing. **Nothing was written**: the terminal went back with the
    /// transaction, the row is still there, and the attempt is still this
    /// command's to settle. Carries the conflict, because "somebody took the
    /// name", "it moved on" and "it is already gone" send an operator to three
    /// different places.
    row_moved: jobs.Conflict,

    /// The stable machine word for each, named here rather than at the report.
    ///
    /// The transaction is what knows which of the three refused it, so this is
    /// where the word for it belongs: a report that spelled them itself would be
    /// a second list to keep in step with this union, and `job rm` and
    /// `session rm` already publish the first two under the same names.
    pub const codes = struct {
        pub const scope_taken = "SCOPE_TAKEN_BEFORE_COMMIT";
        pub const claim_lost = "CLAIM_LOST_BEFORE_COMMIT";
        /// No session counterpart: a session delete has no expectation to lose.
        pub const row_moved = "ROW_MOVED_BEFORE_COMMIT";
    };

    pub fn errorCode(r: Refusal) []const u8 {
        return switch (r) {
            .scope_taken => codes.scope_taken,
            .claim_lost => codes.claim_lost,
            .row_moved => codes.row_moved,
        };
    }
};

/// `job rm`'s ledger half: the attempt to settle in the removal's transaction, or
/// the stated reason there is none.
///
/// Two of `job rm`'s three branches have no terminal to write — the `jobs` row
/// names no attempt, or the attempt is already terminal — and both of those used
/// to reach `jobs.remove` directly, which opened a `BEGIN IMMEDIATE` of its own
/// with no terminal beside it and no authority check in it. Stating *which* of the
/// two applies is what keeps "there is nothing to settle" from being expressed as
/// a null that also covers "we forgot to settle it".
pub const JobSettlement = union(enum) {
    /// Settle this attempt in the transaction that forgets the row.
    attempt: struct {
        execution: *Execution,
        terminal: op_state.Terminal,
        extra: receipts.TerminalExtra,
    },
    /// No terminal accompanies the removal.
    absent: Ledger.Absent,

    fn ledger(s: JobSettlement) Ledger {
        return switch (s) {
            .attempt => |a| .{
                .settle = .{
                    .execution = a.execution,
                    .terminal = a.terminal,
                    .extra = a.extra,
                    // Decided here rather than asked of the caller. `job rm` forgets
                    // a name, which asserts nothing about how the job ended, so a
                    // removal that declined because a peer settled the attempt first
                    // would leave the row behind for good. Fixing it here is also
                    // what makes `Committed.already_settled` unreachable from
                    // `settleAndForgetJob`, which is why `JobRemoval` has no arm for
                    // it.
                    .on_rival = .destroy_anyway,
                },
            },
            .absent => |absent| .{ .none = absent },
        };
    }
};

/// `job rm`'s destructive commit: settle the target attempt when there is one to
/// settle, and forget the cache row, in one transaction under the authority the
/// caller names.
///
/// A free function rather than a method, because two of `job rm`'s three branches
/// have no live `Execution` to hang it off — see `JobSettlement`.
///
/// `authority` is the lease owner minted by `cmd_job.claimJobScope`, which is
/// **not** `execution.id()`. Passing the attempt here would key the claim read on
/// an id that never took a lease — `never_taken`, every time — and hand the overlap
/// check an owner that does not match our own lease, so our own claim would be
/// reported as a peer's. Passing the lease owner to the *operation* half would
/// report the target attempt as a peer blocking its own removal. See
/// `AuthorityOwner`; this is the identity problem that made a copy of
/// `settleAndRemoveSession` the wrong answer here.
pub fn settleAndForgetJob(
    store: *Store,
    arena: Allocator,
    io: std.Io,
    server_id: i64,
    scope: Scope,
    authority: AuthorityOwner,
    settlement: JobSettlement,
    forget: JobForget,
    rollback: *Rollback,
) (DestructiveError || ContractError)!JobRemoval {
    switch (try commitDestruction(store, arena, io, .{
        .server_id = server_id,
        .scope = scope,
        .authority = authority,
        .ledger = settlement.ledger(),
        .destroys = .{ .job_row = forget },
    }, rollback)) {
        .refused => |blocker| return .{ .refused = .{ .scope_taken = blocker } },
        .claim_lost => |claim| return .{ .refused = .{ .claim_lost = claim } },
        // `JobSettlement.ledger` pins `on_rival` to `destroy_anyway`, which is the
        // only thing that can produce this arm, so reaching it means this file's
        // dispatch and its wrapper have drifted apart.
        .already_settled => return error.ContractAnsweredAboutSomethingElse,
        .destruction_refused => |conflict| return .{ .refused = .{ .row_moved = conflict } },
        .done => |done| switch (done.destroyed) {
            .job_row => return .{ .forgotten = .{ .ledger = done.ledger } },
            .session_row => return error.ContractAnsweredAboutSomethingElse,
        },
    }
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
        return nowFrom(self.io);
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
        //
        // `coincident`, because at this point the acting attempt is both the
        // thing that would hold a lease on this scope and the thing being
        // recorded. A destructive control verb is the shape where they part
        // company; see `Identity`.
        if (try blockerLocked(self.store, self.arena, self.server_id, self.scope, .coincident(self.id()), at)) |blocker| {
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
    /// The cache is written only when *this* call recorded the terminal.
    /// `already_settled` means a peer got there first and the ledger holds their
    /// verdict, not ours; the cache's two settled words each assert something
    /// specific (`exited` carries an exit code, `killed` says somebody stopped
    /// it) and neither is a fact this call established. The caller is told which
    /// happened and reports it: see `CacheResult`.
    ///
    /// The destructive counterpart — `job rm` forgetting the row — is *not*
    /// reachable here, and that is the point of the split. Destroying a row
    /// requires an authority to license it and this function has none to check;
    /// see `settleAndForgetJob`.
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
        };

        try self.store.db.exec("COMMIT");
        return .{ .outcome = outcome, .cache = cache };
    }

    /// Settles this attempt and deletes the local session row it names — one
    /// transaction, under the shared destructive contract.
    ///
    /// This is `session rm`'s last three acts, and they used to be three:
    /// `stillOurs` renewed the lease, then `execution.settle` ran a whole
    /// transaction of its own writing the proven cancellation, and only then the
    /// standalone `sessions.remove` wrapper — since deleted — dropped the row.
    /// Two defects fell out of that order.
    ///
    /// **The window.** A peer's takeover landing between the renewal and the
    /// delete was never re-checked, so the command went on to drop the row — and
    /// cascade that session's memories — under a scope that had changed hands.
    /// `1f47542` closed the same `renew → settle → act` window for `cmd_job`'s
    /// kill; this is its recurrence one verb over.
    ///
    /// **The order.** The terminal was written *first*. A failure in that delete
    /// afterwards left the durable ledger asserting a completed
    /// removal while the row, its memories and possibly the pane log were all
    /// still there — and a terminal is frozen, so nothing could correct it.
    ///
    /// Both are closed by `commitDestruction`, which this delegates to rather than
    /// reimplementing. It was the reference for that contract, and the copy that
    /// lived here was the fourth per-verb version of the same machinery; keeping
    /// the copy would have meant the next fix landing on one of the two.
    ///
    /// **The one identity decision this wrapper makes.** `session rm`'s authority
    /// owner and its target operation are the *same* value — `cmd_session.claimScope`
    /// holds the lease under `execution.id()`, and the operation being settled is
    /// that same control attempt — so `Identity.coincident` describes it. `job
    /// kill` and `job rm` are the shape where the two part company, which is
    /// exactly why a copy of this function on the job side would have looked up a
    /// lease no id ever took and read its own target attempt as a peer. See
    /// `AuthorityOwner`.
    ///
    /// `Ledger.Rival.decline` is the other: the verdict on record is not the one
    /// this call was going to write, so the row is deliberately kept rather than
    /// deleted against somebody else's terminal. `job rm` answers
    /// `destroy_anyway` to the same question, for the reason `Ledger.Rival` gives.
    pub fn settleAndRemoveSession(
        self: *Execution,
        session: []const u8,
        terminal: op_state.Terminal,
        extra: receipts.TerminalExtra,
        /// Whether the transaction was undone, when it could not be committed.
        /// Written on every path. See `Rollback` for why the caller needs it and
        /// why `catch {}` was not good enough.
        rollback: *Rollback,
    ) SessionRemovalError!SessionRemoval {
        // Before anything can fail, so a caller that got an error is reading an
        // answer rather than whatever was in the variable. Written again inside
        // `commitDestruction`; the duplication is deliberate, because the refusal
        // below returns without ever reaching it.
        rollback.* = .none;

        // A session row is keyed on a host (`sessions.server_id` is NOT NULL), so
        // an attempt with no server cannot name the row it is about. Refused
        // rather than defaulted: picking a server here would delete somebody
        // else's row. It is also what lets `authorityLocked` take a non-optional
        // `server_id`: there is no lease row shape for the local realm, so an
        // attempt with no host has no authority for it to read.
        const server_id = self.server_id orelse return error.SessionRemovalHasNoServer;

        switch (try commitDestruction(self.store, self.arena, self.io, .{
            .server_id = server_id,
            .scope = self.scope,
            // The one verb where the authority owner and the target operation are
            // the same value; see the doc comment above.
            .authority = .{ .lease_owner_request_id = self.id() },
            .ledger = .{ .settle = .{
                .execution = self,
                .terminal = terminal,
                .extra = extra,
                .on_rival = .decline,
            } },
            .destroys = .{ .session_row = session },
        }, rollback)) {
            .refused => |blocker| return .{ .refused = blocker },
            .claim_lost => |claim| return .{ .claim_lost = claim },
            .already_settled => |winner| return .{ .already_settled = winner },
            // A session delete has no owner, no expectation and no
            // compare-and-swap, so there is nothing for it to lose and nothing
            // this request could have asked for that produces this arm.
            .destruction_refused => return error.ContractAnsweredAboutSomethingElse,
            .done => |done| {
                const row = switch (done.destroyed) {
                    .session_row => |r| r,
                    .job_row => return error.ContractAnsweredAboutSomethingElse,
                };
                const record = switch (done.ledger) {
                    .recorded => |r| r,
                    // A `.settle` request with `on_rival = .decline` produces
                    // exactly one of `recorded` and `Committed.already_settled`,
                    // so neither of these is reachable from the request above.
                    .rival, .absent => return error.ContractAnsweredAboutSomethingElse,
                };
                return .{ .removed = .{ .had_row = row.had_row, .recorded = record } };
            },
        }
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

/// Inserts the operation row `opts` describes. Caller holds the transaction.
///
/// One field list, shared by `begin` and `recordRefusal`, because two copies of
/// it drift: a column added to one and not the other would make a refused
/// attempt describe itself differently from an accepted one, and the whole point
/// of recording the refusal is that the two are comparable.
fn createLocked(
    store: *Store,
    request_id: *const [ids.len]u8,
    capability_json: ?[]const u8,
    opts: BeginOptions,
) Error!void {
    try operations.create(store, .{
        .request_id = request_id,
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
}

/// A refusal that was written down, and what the ledger now holds for it.
///
/// The status travels with the id because the caller has to report it, and a
/// caller that spelled the word itself would be making a second, independently
/// drifting statement about what this function writes. There is one place that
/// decides a refusal settles `cancelled`, and it is the `local_abandon` below.
pub const RecordedRefusal = struct {
    request_id: [ids.len]u8,
    status: op_state.Status,

    pub fn id(r: *const RecordedRefusal) []const u8 {
        return &r.request_id;
    }
};

/// Records an attempt that a peer's claim refused before it could open.
///
/// `begin` returns `.blocked` having inserted nothing, and for most verbs that is
/// right: nothing happened to anything, so there is nothing to record. For a
/// destructive control act it is not. A `session rm` refused by a held claim has
/// to record the refusal, because a refusal with
/// no row leaves five questions with no answer: whether anybody tried to remove
/// this session, who, when, how often, and what stopped them.
///
/// One transaction: the row is created and settled together, so no refusal can be
/// left sitting at `created` because the process died between the two writes.
///
/// **The terminal is `local_abandon`, and that choice is the substance.** Its own
/// words are "nothing had been handed over, so there is nothing to stop", which is
/// literally this: the refusal is decided before the connection is opened. It
/// settles `cancelled`, and `cancelled` does not block scope
/// (`op_state.Status.blocksScope`) — which is the property that makes writing this
/// row safe at all. A record of a refusal that went on to refuse the next command
/// would be worse than no record.
///
/// Worth stating in full, because it is stronger than "we picked a safe terminal":
/// *no* admissible terminal here could bar the scope. `canSettle` admits only
/// `never_submitted` and `local_abandon` from `created`, they settle `failed` and
/// `cancelled`, and `created` itself does not block either — so every reachable
/// state of this row is non-blocking by construction rather than by choice.
///
/// Deliberately **not** `never_submitted`: that variant's evidence is a
/// `transport_error`, and a peer's lease is not a transport failure. Putting a
/// refusal's reason in that field would be the same category error as an exit code
/// on a write.
///
/// Returns the id it minted, so the refusal is queryable by request id the way
/// every other attempt is.
pub fn recordRefusal(
    store: *Store,
    arena: Allocator,
    io: std.Io,
    opts: BeginOptions,
    reason: []const u8,
    /// The id this refusal is minted under, written before anything here can
    /// fail.
    ///
    /// An out-parameter rather than part of the return value, because the caller
    /// needs it on precisely the path where there is no return value. A refused
    /// removal whose *record* could not be written is still a failure an operator
    /// has to be able to name, and a failure with no handle on it is one nobody
    /// can look up, correlate or report. Nothing was written under this id when
    /// that happens, and the caller has to say so — what it must not do is print
    /// no id at all.
    minted: *ids.RequestId,
) Error!RecordedRefusal {
    const request_id = ids.generate(io);
    minted.* = request_id;
    const capability_json = try opts.capability.toJson(arena);

    try store.db.exec("BEGIN IMMEDIATE");
    errdefer store.db.exec("ROLLBACK") catch {};

    try createLocked(store, &request_id, capability_json, opts);
    const recorded = switch (try receipts.settleLocked(
        store,
        &request_id,
        .{ .local_abandon = .{ .reason = reason } },
        .{},
        opts.now,
    )) {
        .recorded => |record| record,
        // The id was minted three statements ago and nothing else has ever seen
        // it, so a terminal already standing against it is not a race — it is a
        // generator collision, and a refusal recorded onto somebody else's
        // attempt would be worse than an unrecorded one.
        .already_settled => return error.IllegalTransition,
    };

    try store.db.exec("COMMIT");
    return .{ .request_id = request_id, .status = recorded.status };
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
    if (try blockerLocked(store, arena, opts.server_id, opts.scope, .coincident(&request_id), opts.now)) |blocker| {
        if (opts.mutating and !opts.force) {
            // Nothing was inserted; the commit only keeps the lease
            // expiry pass the check performed on its way through.
            try store.db.exec("COMMIT");
            return .{ .blocked = blocker };
        }
        advisory = blocker;
    }

    try createLocked(store, &request_id, capability_json, opts);

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
