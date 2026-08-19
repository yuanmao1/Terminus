//! `terminus session new/ls/rm` — remote tmux session lifecycle.
//!
//! `ls` reports live remote tmux state (source of truth) merged with the
//! local metadata rows (cursor, notes, memory counts).
//!
//! `rm` is the destructive one, and until now it was the only destructive
//! remote verb in the tree with **no authority of any kind**: no lease, no
//! operation row, no scope guard (`docs/m3b-job-control.md` §1.2). It killed a
//! remote session, deleted its pane log and dropped the local row — whose
//! delete cascades that session's memories — while contending with nothing and
//! recording nothing. Because a job's tmux session is `job-<name>` and
//! `session ls` shows it under that name, `session rm web job-deploy` would
//! stop a running job's shell with `job kill web deploy` holding a lease it
//! could not see.
//!
//! It now runs under a `control` operation and a scope lease, and renews that
//! lease immediately before every step that changes the host. What it already
//! got right is unchanged and is called out where it happens: the kill is
//! *proven* before anything is deleted, and the log is deleted only after that
//! proof.
//!
//! **Every exit reports the same document.** `RemovalJson` has no defaults, so a
//! branch that stops reporting a key does not compile — but a branch that never
//! emitted the struct at all did compile, and several did: a kill that got no
//! answer left through `fatalTmux` with `{ok, error}` and exit 1 while the ledger
//! recorded `indeterminate`, and every ledger-write failure left through
//! `Cli.receiptFatal` or `Cli.storeFatal`, whose envelopes say nothing about the
//! session, the log, the local row or a lease this command could not hand back.
//! Those paths are now this verb's own (`refuseKillUnanswered`,
//! `refuseLedgerUnrecordable`); the shared helpers are untouched and still serve
//! every other verb. The exits that remain outside the document are named in
//! `removeSession`.

const std = @import("std");
const fatal = Cli.fail;
const Cli = @import("cli.zig");
const Core = @import("../core/core.zig");
const Store = Core.Store;
const Tmux = Core.Tmux;
const fatalTmux = @import("cmd_exec.zig").fatalTmux;

// The lease-renewal barrier, named here and defined once in
// `src/core/control.zig`. These are aliases, not a second copy: `job kill`,
// `job rm` and `session rm` renew through the same `stillOurs`, latch on the
// same `Authority`, and read the same clock, so a fix to any of them reaches
// all three (`docs/m3b-job-control.md` §7.6).
const Control = @import("../core/control.zig");
const Claim = Control.Claim;
const Authority = Control.Authority;
const stillOurs = Control.stillOurs;
const wallClockSeconds = Control.wallClockSeconds;

const usage =
    \\usage: terminus session <verb> [...]
    \\
    \\  session new <server> <name>       create (or reattach) a remote tmux session
    \\  session ls  <server> [--json]     list live remote sessions
    \\  session rm  <server> <name>       kill remote session + local metadata/memories
    \\
;

pub fn run(ctx: *Cli.Ctx, raw_args: []const []const u8) !void {
    if (raw_args.len == 0) fatal("{s}", .{usage});
    const verb = raw_args[0];
    const parsed = Cli.parseArgs(ctx, raw_args[1..]);
    if (parsed.boolean("json")) ctx.out.format = .json;

    const server_name = parsed.positional(0) orelse fatal("{s}", .{usage});
    var store = try Cli.openStore(ctx, &parsed);
    defer store.close();
    const resolved = Cli.resolveServer(ctx, &store, server_name);

    // The connection is opened per verb rather than once up front, and that is
    // not tidying: `rm` has to be refusable *before* it dials, because the whole
    // point of a barrier it consults after opening a socket is that it no longer
    // proves "nothing was sent".
    if (std.mem.eql(u8, verb, "new")) {
        try newSession(ctx, &store, &parsed, resolved.server, resolved.auth, server_name);
    } else if (std.mem.eql(u8, verb, "ls")) {
        try listSessions(ctx, &store, &parsed, resolved.server, resolved.auth, server_name);
    } else if (std.mem.eql(u8, verb, "rm")) {
        try removeSession(ctx, &store, &parsed, resolved.server, resolved.auth, server_name);
    } else {
        fatal("unknown verb 'session {s}'\n{s}", .{ verb, usage });
    }
}

fn newSession(
    ctx: *Cli.Ctx,
    store: *Store,
    parsed: *const Cli.Args.Parsed,
    server: Store.servers.Server,
    auth: Core.Ssh.Auth,
    server_name: []const u8,
) !void {
    const name = parsed.positional(1) orelse fatal("{s}", .{usage});
    validateName(name);

    var conn = Cli.connect(ctx, parsed, server, auth);
    defer conn.deinit();
    const executor = conn.executor();

    Tmux.ensure(executor, ctx.arena, name) catch |err| fatalTmux(err, executor, name);
    _ = Store.sessions.ensure(store, server.id, name, ctx.now) catch |err|
        Cli.storeFatal(store, err);
    // Surface existing server-scope memories so an agent knows to read
    // them before starting work.
    const mems = Store.memories.list(store, ctx.arena, .{ .server_id = server.id }, .{}) catch |err|
        Cli.storeFatal(store, err);
    switch (ctx.out.format) {
        .json => try ctx.out.json(.{
            .ok = true,
            .action = "created",
            .session = name,
            .server = server_name,
            .serverMemories = mems.len,
        }),
        .human => {
            try ctx.out.print("session '{s}:{s}' is ready\n", .{ server_name, name });
            if (mems.len > 0)
                try ctx.out.print("hint: {d} server memories exist; read them with 'terminus memory ls {s}:{s}'\n", .{ mems.len, server_name, name });
        },
    }
}

fn listSessions(
    ctx: *Cli.Ctx,
    store: *Store,
    parsed: *const Cli.Args.Parsed,
    server: Store.servers.Server,
    auth: Core.Ssh.Auth,
    server_name: []const u8,
) !void {
    var conn = Cli.connect(ctx, parsed, server, auth);
    defer conn.deinit();
    const executor = conn.executor();

    const remote = Tmux.list(executor, ctx.arena) catch |err| fatalTmux(err, executor, "");
    const local = Store.sessions.list(store, ctx.arena, server.id) catch |err|
        Cli.storeFatal(store, err);
    const merged = try merge(ctx.arena, remote, local);
    switch (ctx.out.format) {
        .json => try ctx.out.json(.{ .ok = true, .server = server_name, .sessions = merged }),
        .human => {
            if (merged.len == 0) return ctx.out.print("no sessions on '{s}'\n", .{server_name});
            for (merged) |s| {
                try ctx.out.print("{s}:{s}  alive={s}  cursor={d}\n", .{
                    server_name, s.name, if (s.alive) "yes" else "no", s.cursor,
                });
            }
        },
    }
}

/// One reader for every branch of `session rm --json`.
///
/// Every key is present on every path, including the refusals, and — since the
/// four paths that used to fall through to the generic `{ok, error}` envelope
/// were brought in — including the ones that report a *partial destruction*. That
/// was the sharp defect: the initial blocker, the seized lease, a failed log
/// deletion and a failed local delete each emitted two keys, so a caller that had
/// just had a session stopped under it received none of `requestId`,
/// `sessionState`, `logState` or `localRow` — the four facts it needs to know
/// what is left on the host.
///
/// No defaults, so a branch that omits a key does not compile and a branch that
/// stops reporting one cannot be added. Where a branch has nothing to say it says
/// so with a word: the machine-readable enumerations are non-null everywhere and
/// each carries an explicit "we did not get that far" member, because a bool
/// cannot tell "the log is still there because we failed to delete it" from "the
/// log is still there because we never reached that step" — and those two leave
/// the host in different states.
///
/// `action` alone never says what survived. `sessionState`, `logState` and
/// `localRow` each report what actually happened to one thing, because a refusal
/// after the kill destroyed strictly more than one before it.
const RemovalJson = struct {
    ok: bool,
    /// `removed` | `not_removed`.
    action: []const u8,
    /// Why this command ended the way it did, as a stable token. **Never null and
    /// never absent**: `none` on the one branch that completed the removal. Branch
    /// on this; the prose fields below are not a protocol.
    errorCode: []const u8,
    session: []const u8,
    server: []const u8,
    /// The control operation's own id. Everything this command did is on its
    /// trail, and this is how to ask for it — on every branch, refusals included.
    ///
    /// One branch is the exception and says so in its own `reason`: when the write
    /// that would have *created* the row is what failed, this is the id the
    /// command minted for itself and nothing exists under it. Reported anyway,
    /// because a failure with no handle is one nobody can correlate — and stated
    /// in the sentence, because a caller that queried it and found nothing would
    /// otherwise conclude the ledger had lost a row.
    requestId: []const u8,
    /// What the ledger holds for that operation now, or `unknown` where the write
    /// that would have given it a word is the thing that failed.
    status: []const u8,
    /// `gone` | `present` | `unknown` | `not_attempted` — the host's own answer to
    /// "is that session there", that no answer came back, or that it was never
    /// asked.
    sessionState: []const u8,
    /// `deleted` | `delete_failed` | `not_attempted`. `delete_failed` means the
    /// pane log of a session that is *gone* is still on the host with nothing
    /// left to recreate it; `not_attempted` means the step was never reached.
    logState: []const u8,
    /// `removed` | `absent` | `kept` | `unknown`.
    ///
    /// Four words rather than a bool, because `sessions.remove` answering false
    /// is not a refusal — see the call site — and because a rollback nobody could
    /// confirm leaves the row's fate genuinely undecided rather than kept.
    localRow: []const u8,
    /// `held` | `lapsed` | `unreadable`: what this command's own renewals
    /// answered. Branch on this, never on the prose.
    authority: []const u8,
    authorityError: ?[]const u8,
    /// `not_taken` | `released` | `not_ours` | `left_held`: what became of the
    /// scope lease. `left_held` is a leak — the next command on this scope is
    /// refused until the lease lapses — and it used to be a line on stderr under
    /// a document that said `ok: true`.
    leaseRelease: []const u8,
    leaseReleaseError: ?[]const u8,
    /// What happened, in a sentence, and null on the branch where nothing went
    /// wrong. Prose — nothing may branch on it — but it is the only place a
    /// refusal's *counterparty* is named: the blocking request id, the machine
    /// that holds the lease, the host's own error text. That used to reach a JSON
    /// caller only because four branches fell through to `{ok, error}`, and
    /// bringing them into the fixed set would have dropped it.
    reason: ?[]const u8,
    hint: ?[]const u8,
};

/// The stable `errorCode` vocabulary, named once so the branches cannot spell it
/// two ways and `skill/SKILL.md` has something to be held against.
const code = struct {
    /// The removal completed. Present rather than null, for the reason
    /// `resultRecord` publishes `not_requested`: a caller must never have to
    /// decide whether a missing key means success or an older binary.
    pub const none = "none";
    /// A peer's unsettled writer or lease covers this session's scope. Nothing
    /// was sent.
    pub const scope_held = "SCOPE_HELD_BY_PEER";
    /// A renewal answered that the scope is no longer ours, before the kill.
    pub const authority_lost_before_kill = "AUTHORITY_LOST_BEFORE_KILL";
    /// A renewal answered that the scope is no longer ours, after it.
    pub const authority_lost = Authority.lost_code;
    /// Every renewal held, and the transaction that was to record the removal
    /// found a peer's claim on the scope. Distinct from `AUTHORITY_LOST`: there
    /// the renewal said so, here the renewals all passed and the atomic
    /// re-validation is what refused.
    pub const scope_taken_before_commit = "SCOPE_TAKEN_BEFORE_COMMIT";
    /// Every renewal held, and the transaction that was to record the removal
    /// found *this command's own* lease no longer live and ours.
    ///
    /// Distinct from `SCOPE_TAKEN_BEFORE_COMMIT`, which names a peer. The state
    /// this exists for has none: a lease that lapsed during the last round trip
    /// and was swept with nobody replacing it leaves the scope genuinely clear,
    /// which is exactly why the overlap check used to let it through.
    pub const claim_lost_before_commit = "CLAIM_LOST_BEFORE_COMMIT";
    /// The kill went out and the host still reports the session present.
    pub const survived = "SESSION_SURVIVED_KILL";
    /// The kill went out and no answer to it came back.
    pub const kill_unanswered = "KILL_UNANSWERED";
    /// The session is gone and its pane log could not be deleted.
    pub const log_delete_failed = "LOG_DELETE_FAILED";
    /// The ledger already held a terminal for this attempt, so this command did
    /// not write the one it had established and did not delete the local row.
    pub const already_settled = "LEDGER_ALREADY_SETTLED";
    /// The session was stopped, its log deleted, and the transaction carrying the
    /// terminal and the local delete could not be written. Nothing local changed.
    pub const ledger_write_failed = "LEDGER_WRITE_FAILED";
    /// A ledger write this command needed could not be made, at a step before the
    /// composite. The tree-wide code, reused rather than renamed: this is what
    /// `Cli.receiptFatal` publishes everywhere else, and an agent that already
    /// branches on it should not have to learn a second spelling for this verb.
    pub const receipt_persist_failed = "RECEIPT_PERSIST_FAILED";
    /// The id minted for this command already held a lease on the scope.
    pub const owner_collision = "OWNER_COLLISION";
};

/// The step vocabularies, for the same reason — one namespace per key.
///
/// Three namespaces rather than one flat list, and the split is what makes them
/// checkable. `skill/SKILL.md` publishes each key's values in its own
/// parenthetical, and a gate can only hold a documented list against the code's
/// list if the code *has* one list per key. Flat, `not_attempted` belonged to two
/// keys at once and the union of the three had a duplicate in it, so there was
/// nothing a documented list could be compared with — which is how a value could
/// be added to the document, or to the code, with no gate reading either.
///
/// Every member is `pub` because `@typeInfo(...).decls` lists public
/// declarations only, and the gate reads these off the type rather than off a
/// transcription of it.
const state = struct {
    /// `sessionState`: the host's own answer to "is that session there".
    const session = struct {
        pub const gone = "gone";
        pub const present = "present";
        /// The kill went out and nothing came back to say what it did. Neither
        /// `present` (nothing reported that) nor `not_attempted` (it *was*
        /// attempted) — the two words a three-value vocabulary would have forced
        /// this branch to pick between, both of them false.
        pub const unknown = "unknown";
        /// The host was never asked.
        pub const not_attempted = "not_attempted";
    };
    /// `logState`.
    const log = struct {
        pub const deleted = "deleted";
        pub const delete_failed = "delete_failed";
        /// The step was never reached. The member a bool cannot express.
        pub const not_attempted = "not_attempted";
    };
    /// `localRow`.
    const row = struct {
        pub const removed = "removed";
        pub const absent = "absent";
        pub const kept = "kept";
        /// The composite could not commit *and* its rollback could not be
        /// confirmed, so which way the row went is not known.
        ///
        /// **Never a default.** Every other branch can prove which side of the
        /// delete it is on, and `kept` is the word for the ones that can; see
        /// `localRowAfterFailedCommit`, which is the only producer.
        pub const unknown = "unknown";
    };
    /// `status`, on the one branch where there is no row to read the ledger's
    /// word off: the write that would have created it is what failed.
    const ledger = struct {
        pub const unknown = "unknown";
    };
};

/// The three step facts a report carries, travelling together.
///
/// Grouped because they are always decided together and always reported
/// together, and because the shared ledger-failure reporter below has to be
/// handed all three by a caller that knows how far it got — a reporter that
/// guessed any of them would be inventing the very thing this key set exists to
/// state.
const Facts = struct {
    session_state: []const u8,
    log_state: []const u8,
    local_row: []const u8,

    /// Nothing was sent to the host and nothing local was touched.
    const untouched: Facts = .{
        .session_state = state.session.not_attempted,
        .log_state = state.log.not_attempted,
        .local_row = state.row.kept,
    };
};

fn removeSession(
    ctx: *Cli.Ctx,
    store: *Store,
    parsed: *const Cli.Args.Parsed,
    server: Store.servers.Server,
    auth: Core.Ssh.Auth,
    server_name: []const u8,
) !void {
    const name = parsed.positional(1) orelse fatal("{s}", .{usage});
    validateName(name);

    // --- The exits that are deliberately *not* the fixed document ------------
    //
    // Four of them, all before this command can have established anything about
    // this session, and each one named rather than left to be found:
    //
    //  * the two above — a missing or malformed argument. There is no session and
    //    no attempt to report about.
    //  * `policy.ownerToken` and `execution.begin` below. Both fail before any
    //    operation row exists, so there is no `requestId` and no `status` to put
    //    in the document; `{ok, error}` and exit 1 are honest for "nothing
    //    happened, and we could not even start".
    //  * `leases.acquire` in `claimScope`. An operation row exists by then, and
    //    `Cli.fail`'s exit hook settles it — so the ledger is complete and exit 1
    //    is true of the host. What it does not carry is this verb's key set, and
    //    giving that branch a code of its own is a protocol addition rather than
    //    one of the failures this slice is about.
    //  * the two `fatal` calls in `provenCancellation` and `refuseSurvivedKill`,
    //    which are out of memory while formatting a receipt. That is the
    //    tree-wide OOM exit and it is not a state a document helps with.
    //
    // Every other exit — including every ledger-write failure and the kill that
    // got no answer — emits `RemovalJson`.
    const owner_token = Store.policy.ownerToken(store, ctx.arena, ctx.io, ctx.now) catch |err|
        Cli.storeFatal(store, err);

    // The ledger entry this verb never had. `control` is the kind for a
    // supervisory act on somebody else's session (§3.1); the target it acted on
    // travels in `alias`, which is already where a session name goes
    // (`cmd_exec.zig`'s `.alias = target.session`). The dedicated `target_*`
    // columns of §7.2 are v13 and are not this slice.
    //
    // `mutating` is left at its default `true` and it is worth saying why out
    // loud: this is the most destructive verb in the tree. It stops a shell,
    // deletes a log and cascades away a session's memories.
    //
    // Held in a value rather than written inline at the call, because the refusal
    // path below records an operation from the same description: a refused
    // attempt has to describe itself exactly as an accepted one does, or the two
    // are not comparable in the ledger.
    const opts: Core.execution.BeginOptions = .{
        .server_id = server.id,
        .server_name = server.name,
        .kind = .control,
        .scope = contentionScope(name),
        .alias = name,
        .owner_token = owner_token,
        .now = ctx.now,
    };
    const start = Core.execution.begin(store, ctx.arena, ctx.io, opts) catch |err|
        Cli.storeFatal(store, err);

    // Refused here means refused before the connection is opened: no socket, no
    // tmux command, nothing on the host to undo. This is the arm that closes
    // §1.2 — a running job holds an unsettled writer on the scope its session
    // belongs to, and it is now something `session rm` can see.
    var execution = switch (start) {
        .ready => |e| e,
        .blocked => |blocker| refuseBeforeOpening(ctx, store, opts, server_name, name, blocker),
    };
    Cli.registerExecution(&execution);
    defer {
        Cli.clearExecution();
        execution.deinit();
    }

    // The lease, owned by this command's own control operation. One identity
    // rather than two: `blockerLocked` exempts a lease whose owner is the
    // request id it was handed, so our own claim cannot refuse us, and a peer
    // arriving later sees a row that names the operation that took it.
    const claim = claimScope(ctx, store, &execution, opts, server_name, name);
    var authority: Authority = .held;

    execution.connecting() catch |err| refuseLedgerUnrecordable(
        ctx,
        execution.id(),
        server_name,
        name,
        execution.status.text(),
        authority,
        Facts.untouched,
        code.receipt_persist_failed,
        "the step that records this attempt dialling could not be written; nothing has been sent to the host",
        "nothing was sent, so the host is untouched; the attempt is left unsettled and bars this session's scope until it is reconciled",
        err,
    );

    var conn = Cli.connect(ctx, parsed, server, auth);
    defer conn.deinit();
    const executor = conn.executor();

    // The first renewal, and the only one that can still answer "nothing was
    // sent" in the ledger's own words. It sits *before* `submitted` on purpose:
    // a loss caught here leaves the attempt at `connecting`, where
    // `never_submitted` — "the command the caller asked for did not run" — is
    // admissible, and that is exactly what a withheld kill is. After
    // `submitted`, `op_state.canSettle` no longer admits it and the same loss
    // could only be recorded as `indeterminate`, which overstates a kill that
    // never left this machine.
    if (!stillOurs(claim, ctx.io, &authority)) refuseBeforeKill(ctx, &execution, server_name, name, authority);

    // The scope guard binds here rather than at `begin`, for the reason
    // `Execution.submitted` gives: the check and the write that makes this
    // attempt visible to the next caller have to be one transaction.
    const submit = execution.submitted() catch |err| refuseLedgerUnrecordable(
        ctx,
        execution.id(),
        server_name,
        name,
        execution.status.text(),
        authority,
        Facts.untouched,
        code.receipt_persist_failed,
        "the transaction that both re-checks the scope and records this attempt as submitted could not be written, so the kill was withheld; nothing has been sent to the host",
        "nothing was sent, so the host is untouched; the attempt is left unsettled and bars this session's scope until it is reconciled",
        err,
    );
    switch (submit) {
        .submitted => {},
        .refused => |blocker| {
            const reason = "another command claimed an overlapping scope between this one dialing and the kill; nothing was sent to the host";
            settleOrReportUnrecordable(ctx, &execution, server_name, name, authority, Facts.untouched, reason);
            refuseWithNothingSent(ctx, &execution, server_name, name, authority, code.scope_held, reason, blockerHint(ctx, blocker));
        },
    }

    // The kill has to be *proven* before anything else happens, and that rule
    // predates this change: deleting the local row for a session that is still
    // on the host leaves it orphaned — invisible to `session ls`'s local half,
    // and `ensure` treats an existing session as ready, so the next command
    // under this name would land in the shell we just claimed to have removed.
    //
    // The renewal the kill runs under, with nothing between it and the command
    // it gates — no store transaction, no probe, no second round trip. The one
    // above is on the far side of `submitted`'s transaction and answers about a
    // moment that has passed; a peer taking the lease inside it would leave this
    // command sending `kill-session` *by name* at a session the new holder may
    // already own. That window is narrowed, not closed: the host still acts some
    // interval after the renewal answered, and only a session identity the host
    // itself can check would close it (§2.4).
    if (!stillOurs(claim, ctx.io, &authority)) refuseBeforeKill(ctx, &execution, server_name, name, authority);
    const gone = Tmux.killSession(executor, ctx.arena, name) catch |err|
        refuseKillUnanswered(ctx, &execution, server_name, name, authority, executor, err);
    if (!gone) refuseSurvivedKill(ctx, &execution, server_name, name, authority);
    // When the host answered, so the receipt's `absence_verified_at` is the
    // moment of the reading rather than this process's start time.
    const verified_at = wallClockSeconds(ctx.io);

    // The kill cannot be taken back; every step after it can still be declined,
    // so the scope is asked for again. A loss here keeps the log *and* the local
    // row, and the receipt records that this command established nothing.
    //
    // On one line, and the adjacency gate below is why: it looks at the last line
    // of *code* before a destructive call, so a renewal wrapped across two lines
    // would put its own continuation there and read as if nothing had asked.
    if (!stillOurs(claim, ctx.io, &authority)) refuseAfterKill(ctx, &execution, server_name, name, authority, state.log.not_attempted, code.authority_lost);
    // Only now: a live pane recreates its log through `pipe-pane`, so a log
    // deleted under a surviving session quietly comes back holding a partial
    // history that starts mid-stream. `gone` above is what licenses this line,
    // which is why the proof comes first and the deletion second.
    Tmux.removeLog(executor, ctx.arena, name) catch |err|
        refuseLogUndeleted(ctx, &execution, server_name, name, authority, verified_at, executor, err);

    // The composite: re-validate the scope *and* this command's own claim, write
    // the terminal, drop the local row — one transaction, all four or none of
    // them.
    //
    // This used to be three separate steps in the other order: a renewal, then a
    // whole `execution.settle` transaction writing the proven cancellation, and
    // only then `sessions.remove`. Both halves of that were wrong. A `--force`
    // takeover landing inside the settlement was never re-checked, so the delete
    // — which cascades this session's memories — went ahead under a scope that
    // had changed hands; and because the terminal came first, a failed delete
    // left the ledger permanently asserting a removal whose row was still on
    // disk. See `Execution.settleAndRemoveSession`.
    const proven = provenCancellation(ctx, name, verified_at, true);
    var rollback: Core.execution.Rollback = .none;
    const removal = execution.settleAndRemoveSession(name, proven.terminal, proven.extra, &rollback) catch |err|
        refuseLedgerUnwritable(ctx, &execution, server_name, name, authority, rollback, err);

    const had_row = switch (removal) {
        // The bool is no longer discarded, and this is the one place in the CLI
        // where discarding it was not a swallowed refusal. `sessions.removeLocked`
        // has no owner, no expectation and no compare-and-swap: false means only
        // that this machine had no metadata row for the session, which `merge`
        // below documents as an ordinary state — a session started outside
        // Terminus is alive remotely with nothing local naming it. It is now
        // *reported* rather than merely justified (§2.2), because "there was no
        // row" and "the row is gone" are different facts about this machine and
        // only one of them means a cascade happened.
        .removed => |done| done.had_row,
        // The scope moved between the log deletion's round trip and the commit.
        // Nothing was deleted and no terminal was written, so the attempt is
        // still ours to settle — with the honest partial, not the clean removal
        // it was about to write.
        .refused => refuseAfterKill(
            ctx,
            &execution,
            server_name,
            name,
            authority,
            state.log.deleted,
            code.scope_taken_before_commit,
        ),
        // Our own lease stopped being live and ours during the log deletion's
        // round trip. Frequently with no peer involved at all, which is the whole
        // reason this arm is not the one above.
        .claim_lost => |claim_state| refuseClaimLost(ctx, &execution, server_name, name, authority, claim_state),
        .already_settled => |winner| refuseAlreadySettled(ctx, &execution, server_name, name, authority, winner),
    };
    const lease = Cli.releaseClaimReporting();

    switch (ctx.out.format) {
        .json => try ctx.out.json(RemovalJson{
            .ok = true,
            .action = "removed",
            .errorCode = code.none,
            .session = name,
            .server = server_name,
            .requestId = execution.id(),
            .status = execution.status.text(),
            .sessionState = state.session.gone,
            .logState = state.log.deleted,
            .localRow = if (had_row) state.row.removed else state.row.absent,
            .authority = authority.code(),
            .authorityError = authority.note(ctx.arena, .{ .session = name }),
            .leaseRelease = lease.code,
            .leaseReleaseError = lease.detail,
            .reason = null,
            .hint = null,
        }),
        .human => {
            try ctx.out.print("removed session '{s}:{s}'\n", .{ server_name, name });
            if (lease.detail) |text| try ctx.out.print("  note: {s}\n", .{text});
        },
    }
}

/// The terminal a proven session stop settles, plus the document that says how
/// far the removal actually got.
///
/// In one place because two sites write it and they must not disagree about what
/// was established — and, since the log-deletion failure became a reported
/// outcome rather than a `fatal`, because the two sites do not establish the same
/// thing and the difference has to survive into the ledger.
///
/// `remote_cancel_confirmed`, and the payload is where the honesty lives.
///
/// `pid = null`: no process was identified and none could be. This operation
/// names a *session*; the process in that pane belongs to whoever started it,
/// and recording its pid would be a reading about one thing offered as a verdict
/// on another — the mistake `operations.Kind.capabilities` leaves
/// `records_process_identity` false for a job and a control act over, and the
/// reason `appliesToKind` admits no `process_probe` for either.
///
/// `term_sent = true, kill_sent = false`: `tmux kill-session` hangs the pane up
/// on our behalf, and nothing here sends SIGKILL to anything. Written as what
/// happened rather than as two convenient trues. Note that neither flag reaches
/// the row: `receipts.terminalEvent`'s `remote_cancel_confirmed` arm writes
/// `cancel_method`, the pid pair and `finished_at`, and drops these two. Recorded
/// here as a known gap rather than as something this file can fix.
///
/// `verification_method` names both tmux commands, so a reader sees the
/// granularity of the proof beside the verdict. What was verified is that the
/// *session* is gone — this operation's whole subject — and not that anything it
/// had forked has stopped. A command that daemonized, called `disown` or ran
/// under `setsid` outlives the shell, and nothing on this receipt claims
/// otherwise.
///
/// **`detail_json` is what stops `cancelled` from meaning two things.** A
/// completed removal and a removal whose log deletion failed both settle
/// `cancelled` through this variant, because both really did stop the session and
/// that is the whole of what the variant claims. Read from the status column alone
/// they would be indistinguishable — which was half of F2: the ledger asserting a
/// removal while the log survived. So the settlement carries a versioned document
/// naming the two facts the variant has no field for, in the column `receipts`
/// documents for exactly this ("the document is versioned precisely so a new fact
/// does not need [a column]").
const ProvenStop = struct {
    terminal: Core.Store.op_state.Terminal,
    extra: Core.Store.receipts.TerminalExtra,
};

fn provenCancellation(
    ctx: *Cli.Ctx,
    session: []const u8,
    verified_at: i64,
    /// True only on the path that goes on to delete the local row in the same
    /// transaction as this terminal. The log deletion is the step before it, so
    /// this is also "the removal ran to the end".
    completed: bool,
) ProvenStop {
    const target = Tmux.targetName(ctx.arena, session) catch
        fatal("out of memory recording the removal of session '{s}'", .{session});
    return .{
        .terminal = .{ .remote_cancel_confirmed = .{
            .pid = null,
            .term_sent = true,
            .kill_sent = false,
            .absence_verified_at = verified_at,
            .verification_method = if (completed) std.fmt.allocPrint(
                ctx.arena,
                "tmux kill-session -t ={s} then has-session reported the session absent",
                .{target},
            ) catch "tmux kill-session then has-session reported the session absent" else std.fmt.allocPrint(
                ctx.arena,
                "tmux kill-session -t ={s} then has-session reported the session absent; the pane log was not deleted and the local record was kept",
                .{target},
            ) catch "tmux kill-session then has-session reported the session absent; the pane log was not deleted",
        } },
        .extra = .{ .detail_json = stopJson(ctx.arena, completed) catch
            fatal("out of memory recording the removal of session '{s}'", .{session}) },
    };
}

/// What the settlement establishes beyond the session's absence.
///
/// Two booleans and an event name, versioned like every other `detail_json`
/// document. `logDeleted` false with `localRecordDropped` false is the partial:
/// the session is gone, its pane log is still on the host with nothing left to
/// recreate it, and this machine still holds the session's metadata row and its
/// memories.
fn stopJson(arena: std.mem.Allocator, completed: bool) std.mem.Allocator.Error![]u8 {
    var writer: std.Io.Writer.Allocating = .init(arena);
    std.json.Stringify.value(.{
        .schemaVersion = Core.Store.receipts.schema_version,
        .event = "session_stopped",
        .logDeleted = completed,
        // Whether this terminal was committed in the same transaction as the
        // delete of the local `sessions` row. That delete may have matched no row
        // — an ordinary state — which is reported to the caller as
        // `localRow:"absent"`; what this says is that the removal reached it.
        .localRecordDropped = completed,
    }, .{}, &writer.writer) catch return error.OutOfMemory;
    return writer.toOwnedSlice();
}

/// The kill went out and the host says the session is still there.
///
/// Nothing is deleted — not the log, not the local row — and that rule predates
/// every part of this change: the local row for a session still on the host
/// would orphan it, and `Tmux.ensure` treats an existing session as ready, so
/// the next command under this name would land in the shell we just claimed to
/// have removed.
///
/// Settled `proven_failure`, and every word of that is earned. What the host
/// answered is that a session by this name is there *now*, and this command had
/// asked for it to be gone — so the act it exists to perform provably did not take
/// effect, and nothing was deleted on the strength of it. That is a failure, and a
/// failure is what the ledger says.
///
/// What it does **not** say is why. Something recreated the session, or tmux did
/// not do what it was asked, and this command cannot tell those apart; the receipt
/// carries the reading (`observation`) rather than a cause, which is the whole
/// reason `proven_failure` demands one. It also may not claim
/// `remote_cancel_confirmed`, whose content is a verified *absence*.
///
/// This used to be `indeterminate`, because `op_state.canSettle` admits
/// `never_submitted` only before submission and there was no other proven failure
/// after it. That was the conservative lie: "we could not establish what happened"
/// about something the host had just established, which barred this session's
/// scope until somebody reconciled a settled question. `failed` releases the
/// barrier, which is correct here rather than merely convenient — nothing was
/// deleted, the session is where it was, and the next removal has nothing to be
/// protected from.
///
/// So it exits **1**, not 75, and that inverts what this branch used to say for
/// the reason the inversion is now true: 1 means "it did not work, and a retry is
/// safe", and both halves hold. A caller re-running this walks into no refusal.
fn refuseSurvivedKill(
    ctx: *Cli.Ctx,
    execution: *Core.execution.Execution,
    server_name: []const u8,
    session: []const u8,
    authority: Authority,
) noreturn {
    const facts: Facts = .{
        .session_state = state.session.present,
        .log_state = state.log.not_attempted,
        .local_row = state.row.kept,
    };
    const target = Tmux.targetName(ctx.arena, session) catch
        fatal("out of memory reporting that session '{s}' survived the kill", .{session});
    const reason = std.fmt.allocPrint(
        ctx.arena,
        "the kill was sent for session '{s}' and the host still reports it present, so this removal provably did not happen; nothing was deleted — not the pane log, not the local row",
        .{session},
    ) catch "the kill was sent and the host still reports the session present, so this removal provably did not happen; nothing was deleted";
    // The observation, not the conclusion. `tmux has-session` after
    // `tmux kill-session` is the reading that establishes the failure, and it is
    // the reading a later operator gets to disagree with.
    const observation = std.fmt.allocPrint(
        ctx.arena,
        "tmux kill-session -t ={s} then has-session reported the session still present",
        .{target},
    ) catch "tmux kill-session then has-session reported the session still present";
    _ = execution.settle(.{ .proven_failure = .{
        .observation = observation,
        .error_code = code.survived,
    } }, .{}) catch |err| refuseLedgerUnrecordable(
        ctx,
        execution.id(),
        server_name,
        session,
        execution.status.text(),
        authority,
        facts,
        code.receipt_persist_failed,
        "the kill was sent, the host reported the session still present, and the record of that could not be written",
        "the session is still on the host and nothing was deleted; the attempt is left unsettled and bars this session's scope until it is reconciled",
        err,
    );
    // Before the report, so the answer can be in it. Every branch of this verb
    // says what became of the lease, because a leaked one refuses the next
    // command and used to do so under a document that never mentioned it.
    const lease = Cli.releaseClaimReporting();
    report(ctx, .{
        .ok = false,
        .action = "not_removed",
        .errorCode = code.survived,
        .session = session,
        .server = server_name,
        .requestId = execution.id(),
        .status = execution.status.text(),
        .sessionState = facts.session_state,
        .logState = facts.log_state,
        .localRow = facts.local_row,
        .authority = authority.code(),
        .authorityError = authority.note(ctx.arena, .{ .session = session }),
        .leaseRelease = lease.code,
        .leaseReleaseError = lease.detail,
        .reason = reason,
        .hint = std.fmt.allocPrint(
            ctx.arena,
            "nothing was deleted and this session's scope is free again; look at it with 'tmux attach -t {s}' on the host to find out why the kill did not take, then run the removal again",
            .{target},
        ) catch "nothing was deleted and the scope is free; inspect the session on the host, then run the removal again",
    });
    Cli.exitNow(Cli.exit_code.failure);
}

/// The kill was sent and nothing came back to say what it did.
///
/// A transport failure on that round trip, or a tmux error the host raised in
/// place of an answer. It used to go through `fatalTmux` → `Cli.fail`, which
/// emits `{ok, error}` and **exit 1** — while the process-exit hook settled the
/// submitted operation `indeterminate`. So the ledger said "unknown" and the exit
/// status said "plain failure", and 1 is what an agent reads as *nothing
/// happened, a retry is safe*. On the one call in this verb that cannot be taken
/// back, that is the most dangerous thing the two could disagree about: the kill
/// may well have landed.
///
/// So it emits the verb's own fixed structure and exits **75**, which is what
/// `indeterminate` exits everywhere else in the tree. `fatalTmux` itself is
/// untouched: `cmd_exec`, `cmd_job` and `cmd_read_write` share it and their
/// envelopes are not this verb's business.
///
/// `sessionState: "unknown"`, which is why that word had to exist. `present`
/// would report something the host never said and `not_attempted` would deny a
/// command that was sent.
///
/// **One imprecision, named rather than hidden, and now half-closed.**
/// `error.TmuxMissing` is the host answering that tmux is not installed, which
/// *proves* the kill did not run — and this still records `indeterminate`. The
/// missing piece is no longer the terminal: `op_state.Terminal.proven_failure`
/// exists, is admissible for a control act from `submitted`, and
/// `refuseSurvivedKill` writes it. What this branch would need is a published
/// **`errorCode` of its own**, because "the host gave no usable answer" and "the
/// host answered that it has no tmux" are different branches with different exit
/// codes — a proven failure exits 1 and a lost answer exits 75 — and one code
/// cannot carry both without lying to whichever caller branches on it. That code
/// would have to be added to `code` above *and* to the list `skill/SKILL.md`
/// publishes, which the gate below holds against each other, so it is a protocol
/// addition rather than an implementation detail. Until it is made, the error name
/// travels in `reason`, so an operator reading it is not left guessing; what the
/// ledger cannot do is say it in a column.
fn refuseKillUnanswered(
    ctx: *Cli.Ctx,
    execution: *Core.execution.Execution,
    server_name: []const u8,
    session: []const u8,
    authority: Authority,
    executor: Core.Executor,
    cause: anyerror,
) noreturn {
    const facts: Facts = .{
        .session_state = state.session.unknown,
        .log_state = state.log.not_attempted,
        .local_row = state.row.kept,
    };
    const reason = std.fmt.allocPrint(
        ctx.arena,
        "the kill for session '{s}:{s}' was sent and the host gave no usable answer to it: {s} ({s}); whether that session is still there cannot be established from here, and nothing was deleted — not the pane log, not the local row",
        .{ server_name, session, executor.errorMessage(), @errorName(cause) },
    ) catch "the kill was sent and the host gave no usable answer to it; nothing was deleted";
    _ = execution.settle(.{ .indeterminate = .{
        .reason = reason,
        .last_observed = execution.status,
        .error_code = code.kill_unanswered,
    } }, .{}) catch |err| refuseLedgerUnrecordable(
        ctx,
        execution.id(),
        server_name,
        session,
        execution.status.text(),
        authority,
        facts,
        code.receipt_persist_failed,
        "the kill was sent, no answer came back, and the record of that could not be written",
        "the kill may have landed and nothing was deleted; the attempt is left unsettled and bars this session's scope until it is reconciled",
        err,
    );
    const lease = Cli.releaseClaimReporting();
    report(ctx, .{
        .ok = false,
        .action = "not_removed",
        .errorCode = code.kill_unanswered,
        .session = session,
        .server = server_name,
        .requestId = execution.id(),
        .status = execution.status.text(),
        .sessionState = facts.session_state,
        .logState = facts.log_state,
        .localRow = facts.local_row,
        .authority = authority.code(),
        .authorityError = authority.note(ctx.arena, .{ .session = session }),
        .leaseRelease = lease.code,
        .leaseReleaseError = lease.detail,
        .reason = reason,
        .hint = "the kill may have landed; look at the host before re-running, then settle the record with 'terminus request reconcile <request-id>' — until it is settled this session's scope stays barred",
    });
    Cli.failIndeterminateAfterOutput(execution.id());
}

/// Refused before anything reached the host, by a renewal that answered "not
/// ours".
///
/// Settled through `Execution.abandon`, which routes to the one function allowed
/// to classify a give-up (`op_state.terminalForTransportLoss`): from
/// `connecting` that is `never_submitted`, whose whole claim is that the command
/// the caller asked for did not run. That is precisely a withheld kill, it
/// settles `failed`, and it is what §3.4 says a control operation that lost its
/// lease before sending anything records.
fn refuseBeforeKill(
    ctx: *Cli.Ctx,
    execution: *Core.execution.Execution,
    server_name: []const u8,
    session: []const u8,
    authority: Authority,
) noreturn {
    const reason = std.fmt.allocPrint(
        ctx.arena,
        "this command's scope lease for session '{s}' is no longer held ({s}), so the kill was never sent; nothing on the host and nothing in the local record was touched",
        .{ session, authority.code() },
    ) catch "the scope lease was lost before the kill was sent; nothing was touched";
    settleOrReportUnrecordable(ctx, execution, server_name, session, authority, Facts.untouched, reason);
    refuseWithNothingSent(
        ctx,
        execution,
        server_name,
        session,
        authority,
        code.authority_lost_before_kill,
        reason,
        "nothing was sent to the host, so re-running this once the scope is free is safe",
    );
}

/// Settles a give-up, and reports the verb's own document if even *that* could
/// not be written.
///
/// Every refusal below reaches its report through a settlement, and until now a
/// failure in the settlement fell out of the verb entirely: `Cli.receiptFatal`'s
/// envelope replaced this one and its `releaseClaim()` dropped the lease answer on
/// the floor. Shared, because there are five such sites and five copies of the
/// same three-line catch is how one of them comes to lose its `facts`.
///
/// Safe to call unconditionally — `Execution.abandon` does nothing once settled.
fn settleOrReportUnrecordable(
    ctx: *Cli.Ctx,
    execution: *Core.execution.Execution,
    server_name: []const u8,
    session: []const u8,
    authority: Authority,
    facts: Facts,
    reason: []const u8,
) void {
    execution.abandon(reason) catch |err| refuseLedgerUnrecordable(
        ctx,
        execution.id(),
        server_name,
        session,
        execution.status.text(),
        authority,
        facts,
        code.receipt_persist_failed,
        "this command gave up and the settlement recording why could not be written",
        "the attempt is left unsettled and bars this session's scope until it is reconciled",
        err,
    );
}

/// One report for every refusal that sent nothing and settled `failed`.
///
/// Shared because the three of them — a renewal that answered before the kill,
/// the scope guard binding at `submitted`, and a peer's claim arriving between
/// `begin` and the acquisition — differ in one code and one sentence and in
/// nothing else. Each already had a settled operation by the time it got here;
/// what this owns is the release, the document and the exit.
///
/// Exit 1, not 75. These commands changed nothing, so nothing about the remote is
/// unknown *because of them* — the distinction the two codes exist for.
fn refuseWithNothingSent(
    ctx: *Cli.Ctx,
    execution: *Core.execution.Execution,
    server_name: []const u8,
    session: []const u8,
    authority: Authority,
    error_code: []const u8,
    reason: []const u8,
    hint: ?[]const u8,
) noreturn {
    const lease = Cli.releaseClaimReporting();
    report(ctx, .{
        .ok = false,
        .action = "not_removed",
        .errorCode = error_code,
        .session = session,
        .server = server_name,
        .requestId = execution.id(),
        .status = execution.status.text(),
        .sessionState = Facts.untouched.session_state,
        .logState = Facts.untouched.log_state,
        .localRow = Facts.untouched.local_row,
        .authority = authority.code(),
        .authorityError = authority.note(ctx.arena, .{ .session = session }),
        .leaseRelease = lease.code,
        .leaseReleaseError = lease.detail,
        .reason = reason,
        .hint = hint,
    });
    Cli.exitNow(Cli.exit_code.failure);
}

/// Refused after the kill landed, with everything downstream of it declined.
///
/// The kill cannot be undone and this does not pretend otherwise; what it
/// refuses is the log deletion and the local row, and `log_state` says which
/// side of the log this loss fell on.
///
/// Settled `indeterminate`, and not `remote_cancel_confirmed`, even though
/// `has-session` really did report the session absent. The reading was true when
/// it was taken; what it can no longer support is a claim about *this name* now,
/// because the peer holding the scope has been free to create a session under it
/// ever since. `job kill` reached the same rule through `cancellationProvable`'s
/// `authority.holds()` conjunct.
///
/// Two codes reach this, and the difference is worth a caller's attention:
/// `AUTHORITY_LOST` means a renewal said the scope was gone, and
/// `SCOPE_TAKEN_BEFORE_COMMIT` means every renewal held and the transaction that
/// was to record the removal found a peer's claim. `authority` stays `held` in the
/// second case, because it reports what the renewals answered and they answered
/// truthfully.
fn refuseAfterKill(
    ctx: *Cli.Ctx,
    execution: *Core.execution.Execution,
    server_name: []const u8,
    session: []const u8,
    authority: Authority,
    log_state: []const u8,
    error_code: []const u8,
) noreturn {
    const reason = std.fmt.allocPrint(
        ctx.arena,
        "this command stopped session '{s}' and then found it no longer held the scope it took beforehand ({s}); another session may have created or acted on that name in between, so nothing here establishes what is there now",
        .{ session, error_code },
    ) catch "this command lost the scope for this session after stopping it";
    settleAfterKillOrReport(ctx, execution, server_name, session, authority, log_state, error_code, reason);
    const lease = Cli.releaseClaimReporting();
    report(ctx, .{
        .ok = false,
        .action = "not_removed",
        .errorCode = error_code,
        .session = session,
        .server = server_name,
        .requestId = execution.id(),
        .status = execution.status.text(),
        .sessionState = state.session.gone,
        .logState = log_state,
        .localRow = state.row.kept,
        .authority = authority.code(),
        .authorityError = authority.note(ctx.arena, .{ .session = session }),
        .leaseRelease = lease.code,
        .leaseReleaseError = lease.detail,
        .reason = reason,
        .hint = "the local row and this session's memories were kept; settle the record with 'terminus request reconcile <request-id>'",
    });
    Cli.exitNow(Cli.exit_code.failure);
}

/// This command's *own* lease stopped being live and ours between the log
/// deletion and the commit, and `settleAndRemoveSession` refused the whole
/// composite over it.
///
/// A sibling of `refuseAfterKill` rather than a sixth argument to it, because the
/// counterparty is the difference. `SCOPE_TAKEN_BEFORE_COMMIT` names a peer that
/// took the scope; this one frequently has none to name — the state it exists for
/// is a lease that lapsed during the last round trip and was swept away by
/// somebody's ordinary housekeeping, leaving the scope genuinely clear. That is
/// the state the overlap check reads as "nothing is in your way", which is true,
/// and which used to be enough to delete a session and cascade its memories.
///
/// `authority` stays whatever the renewals answered — `held`, on the path that
/// gets here — for the reason `refuseAfterKill` gives: it reports what the
/// renewals said, and they said it truthfully about the moments they were asked.
/// What refused this is the read inside the transaction, and `errorCode` is where
/// that is said.
fn refuseClaimLost(
    ctx: *Cli.Ctx,
    execution: *Core.execution.Execution,
    server_name: []const u8,
    session: []const u8,
    authority: Authority,
    claim: Core.Store.leases.ClaimState,
) noreturn {
    const reason = std.fmt.allocPrint(
        ctx.arena,
        "this command stopped session '{s}' and deleted its pane log, and the transaction that was to record that found this command's own lease on the scope no longer live and ours ({s}); nothing was deleted and no terminal was written, so the local row and this session's memories were kept",
        .{ session, claim.code() },
    ) catch "this command's own lease on this session's scope was no longer live when the removal was about to be recorded; nothing local was deleted";
    settleAfterKillOrReport(
        ctx,
        execution,
        server_name,
        session,
        authority,
        state.log.deleted,
        code.claim_lost_before_commit,
        reason,
    );
    const lease = Cli.releaseClaimReporting();
    report(ctx, .{
        .ok = false,
        .action = "not_removed",
        .errorCode = code.claim_lost_before_commit,
        .session = session,
        .server = server_name,
        .requestId = execution.id(),
        .status = execution.status.text(),
        .sessionState = state.session.gone,
        .logState = state.log.deleted,
        .localRow = state.row.kept,
        .authority = authority.code(),
        .authorityError = authority.note(ctx.arena, .{ .session = session }),
        .leaseRelease = lease.code,
        .leaseReleaseError = lease.detail,
        .reason = reason,
        .hint = "the local row and this session's memories were kept; settle the record with 'terminus request reconcile <request-id>', then re-run to finish the removal",
    });
    Cli.exitNow(Cli.exit_code.failure);
}

/// The `indeterminate` settlement the two post-kill refusals share, plus the
/// verb's own report if writing it fails.
fn settleAfterKillOrReport(
    ctx: *Cli.Ctx,
    execution: *Core.execution.Execution,
    server_name: []const u8,
    session: []const u8,
    authority: Authority,
    log_state: []const u8,
    error_code: []const u8,
    reason: []const u8,
) void {
    _ = execution.settle(.{ .indeterminate = .{
        .reason = reason,
        .last_observed = execution.status,
        .error_code = error_code,
    } }, .{}) catch |err| refuseLedgerUnrecordable(
        ctx,
        execution.id(),
        server_name,
        session,
        execution.status.text(),
        authority,
        .{
            .session_state = state.session.gone,
            .log_state = log_state,
            .local_row = state.row.kept,
        },
        code.receipt_persist_failed,
        "the session was stopped, the scope was then found not to be this command's, and the record of that could not be written",
        "nothing local was deleted; the attempt is left unsettled and bars this session's scope until it is reconciled",
        err,
    );
}

/// The session was stopped and its pane log could not be deleted.
///
/// This used to `fatal` after settling, so a caller that had just had a shell
/// stopped under it received `{ok:false, error:"..."}` and had to read English to
/// discover that a log was orphaned on the host and a local row was left behind.
///
/// **The terminal is `remote_cancel_confirmed`, and this is the partial shape
/// that had to be decided.** What the variant claims is a verified absence of the
/// session, and that is exactly what was established: the host answered before
/// this line was reached, and a later deletion failing does not make an earlier
/// reading unknown. `indeterminate` would be the mistake §7.5 rejected one level
/// up — recording a proof as an unknown, which additionally bars the scope and so
/// forces a `request reconcile` before the re-run that would actually finish the
/// job. Both remote steps are idempotent and the local row is still there, so a
/// re-run is the repair; `cancelled` releases the scope for it.
///
/// What stops `cancelled` from reading as a completed removal is the settlement's
/// own `detail_json` (`logDeleted:false`, `localRecordDropped:false`) and its
/// `cancel_method`, which names what was not done. See `provenCancellation`.
fn refuseLogUndeleted(
    ctx: *Cli.Ctx,
    execution: *Core.execution.Execution,
    server_name: []const u8,
    session: []const u8,
    authority: Authority,
    verified_at: i64,
    executor: Core.Executor,
    cause: anyerror,
) noreturn {
    const proven = provenCancellation(ctx, session, verified_at, false);
    const facts: Facts = .{
        .session_state = state.session.gone,
        .log_state = state.log.delete_failed,
        .local_row = state.row.kept,
    };
    _ = execution.settle(proven.terminal, proven.extra) catch |err| refuseLedgerUnrecordable(
        ctx,
        execution.id(),
        server_name,
        session,
        execution.status.text(),
        authority,
        facts,
        code.receipt_persist_failed,
        "the session was stopped, its pane log could not be deleted, and the record of that could not be written either",
        "the session is gone, its log is still on the host and nothing local was deleted; the attempt is left unsettled and bars this session's scope until it is reconciled",
        err,
    );
    const reason = std.fmt.allocPrint(
        ctx.arena,
        "session '{s}:{s}' was stopped and its pane log could not be deleted: {s} ({s}); the log is still on the host and the local record — with this session's memories — was kept",
        .{ server_name, session, executor.errorMessage(), @errorName(cause) },
    ) catch "the session was stopped and its pane log could not be deleted; the local record was kept";
    const lease = Cli.releaseClaimReporting();
    report(ctx, .{
        .ok = false,
        .action = "not_removed",
        .errorCode = code.log_delete_failed,
        .session = session,
        .server = server_name,
        .requestId = execution.id(),
        .status = execution.status.text(),
        .sessionState = facts.session_state,
        .logState = facts.log_state,
        .localRow = facts.local_row,
        .authority = authority.code(),
        .authorityError = authority.note(ctx.arena, .{ .session = session }),
        .leaseRelease = lease.code,
        .leaseReleaseError = lease.detail,
        .reason = reason,
        // Exit 1 and a re-run, not 75 and a reconcile: the record is settled, so
        // the scope is free and `session rm` can be run again to finish.
        .hint = "the session is gone; re-run this command once the host is reachable to delete the log and the local record",
    });
    Cli.exitNow(Cli.exit_code.failure);
}

/// Which side of the delete the local row is on, after a composite that could not
/// commit.
///
/// The whole content is the third arm. A `ROLLBACK` that succeeded is a proof that
/// nothing was written, and `kept` is the honest word for it; a `ROLLBACK` whose
/// own statement failed proves nothing at all, and the row may be gone with this
/// session's memories behind it. Reporting `kept` there — which the `catch {}` this
/// replaces left no way to avoid — is a claim about a row nobody looked at.
///
/// Exhaustive, with no `else`: a fourth `Rollback` arm has to be answered here
/// rather than defaulting into a word that says "we know".
fn localRowAfterFailedCommit(rollback: Core.execution.Rollback) []const u8 {
    return switch (rollback) {
        // No transaction was open, so nothing of this call's could have landed.
        .none => state.row.kept,
        .confirmed => state.row.kept,
        .unconfirmed => state.row.unknown,
    };
}

test localRowAfterFailedCommit {
    const t = std.testing;
    // The two proofs, and the one absence of a proof. `unknown` must not be
    // reachable from either of the first two: a branch that could prove the row
    // is where it was and said "unknown" anyway would be as wrong in the other
    // direction, and would send an operator hunting a cascade that never happened.
    try t.expectEqualStrings("kept", localRowAfterFailedCommit(.none));
    try t.expectEqualStrings("kept", localRowAfterFailedCommit(.confirmed));
    try t.expectEqualStrings("unknown", localRowAfterFailedCommit(.{ .unconfirmed = "Sqlite" }));
}

/// The one write that could not be made: the transaction carrying the terminal
/// and the local delete failed against the store.
///
/// The remote half already happened — the session is stopped, its pane log is
/// deleted — and the local half is decided by whether the rollback could be
/// confirmed: see `localRowAfterFailedCommit`. That distinction is the one this
/// used to get wrong. It reported `localRow:"kept"` unconditionally, on the
/// strength of an `errdefer store.db.exec("ROLLBACK") catch {}` whose answer was
/// thrown away — so a rollback that itself failed, leaving the delete and the
/// terminal in an unknown state, was reported as a known one.
///
/// It emits the verb's own fixed structure, and keeps the exit code the tree-wide
/// envelope uses. **76, not 1 and not 75.** The remote effect is real and the
/// ledger does not have it; that is exactly what `receipt_persist_failed` means,
/// and downgrading it to a plain failure would let a caller read "nothing
/// happened" off a destroyed session.
///
/// The operation is left unsettled deliberately. It goes on barring this session's
/// scope until somebody reconciles it, which is right: this command cannot write
/// what it established, so the next one must not proceed as if it had.
fn refuseLedgerUnwritable(
    ctx: *Cli.Ctx,
    execution: *Core.execution.Execution,
    server_name: []const u8,
    session: []const u8,
    authority: Authority,
    rollback: Core.execution.Rollback,
    cause: anyerror,
) noreturn {
    const local_row = localRowAfterFailedCommit(rollback);
    const unknown = std.mem.eql(u8, local_row, state.row.unknown);
    refuseLedgerUnrecordable(
        ctx,
        execution.id(),
        server_name,
        session,
        execution.status.text(),
        authority,
        .{
            .session_state = state.session.gone,
            .log_state = state.log.deleted,
            .local_row = local_row,
        },
        code.ledger_write_failed,
        if (unknown)
            "the session was stopped and its pane log deleted, and the transaction carrying the record of it and the delete of the local row could not be written — and the rollback of that transaction could not be confirmed either, so whether the local row and this session's memories are still here is not known"
        else
            "the session was stopped and its pane log deleted, and the transaction carrying the record of it and the delete of the local row could not be written; the whole transaction went back, so nothing local was deleted and no terminal was recorded",
        if (unknown)
            "the remote effect happened, the local ledger is incomplete and the local row's fate is unknown; read it with 'terminus session ls' before anything else, then settle the record with 'terminus request reconcile <request-id>'"
        else
            "the remote effect happened and the local ledger is incomplete; settle the record with 'terminus request reconcile <request-id>', then re-run to clear the local row",
        cause,
    );
}

/// A ledger write this command needed could not be made, on whichever step it was.
///
/// **Why this is not `Cli.receiptFatal`.** That is the tree-wide route and every
/// `session rm` step used to take it. Its envelope is `{ok, error, errorCode,
/// requestId, cause, remoteStatus, hint}`, so a caller that had just had a shell
/// stopped under it learned neither that the session was gone nor that its log had
/// been deleted nor what became of its local row — the four facts this verb exists
/// to publish. And it cleans up through the `void` `Cli.releaseClaim()`, which
/// drops the `ClaimRelease` answer: `left_held` — a leaked lease that refuses the
/// next command on this scope for its whole TTL — reached stderr and nothing else,
/// under a document that never mentioned a lease. `receiptFatal` is shared with
/// `cmd_exec`, `cmd_job` and `cmd_read_write`, whose envelopes are not this verb's
/// business, so this is a session-owned path and theirs are untouched.
///
/// **Exit 76 on every one of these.** `receiptFatal` already did that; the branch
/// that reached `Cli.storeFatal` did not, and exited 1 — a refused removal whose
/// *record* could not be written. 1 reads as "nothing happened, a retry is safe",
/// which is true of the host on that branch and false of the ledger, where the only
/// trace that anybody tried to destroy this session is now missing.
///
/// Nothing is settled here and nothing is retried. Where there is an attempt it is
/// left unsettled on purpose — it goes on barring this session's scope until
/// somebody reconciles it, because this command could not write what it knows.
fn refuseLedgerUnrecordable(
    ctx: *Cli.Ctx,
    request_id: []const u8,
    server_name: []const u8,
    session: []const u8,
    /// What the ledger holds for this attempt, or `state.ledger.unknown` where the
    /// write that would have given it a word is the one that failed.
    status: []const u8,
    authority: Authority,
    /// How far the command got. Taken from the caller rather than derived: only
    /// the step that failed knows what is on the host, and a reporter that
    /// guessed would be inventing the facts this key set exists to state.
    facts: Facts,
    /// `LEDGER_WRITE_FAILED` for the composite, which has its own published
    /// branch, and `RECEIPT_PERSIST_FAILED` for every other step. Two codes and
    /// not one, because the composite is the only one where the session is gone,
    /// its log is deleted and the removal was a single statement away.
    error_code: []const u8,
    /// Which write failed and what that leaves behind, in a sentence. Prose.
    stage: []const u8,
    hint: []const u8,
    cause: anyerror,
) noreturn {
    const reason = std.fmt.allocPrint(
        ctx.arena,
        "session '{s}:{s}': {s} ({s})",
        .{ server_name, session, stage, @errorName(cause) },
    ) catch stage;
    // Cleared before the report: the attempt is deliberately left unsettled, and
    // the process-exit hook must not invent a verdict for it on the way out.
    Cli.clearExecution();
    const lease = Cli.releaseClaimReporting();
    report(ctx, .{
        .ok = false,
        .action = "not_removed",
        .errorCode = error_code,
        .session = session,
        .server = server_name,
        .requestId = request_id,
        .status = status,
        .sessionState = facts.session_state,
        .logState = facts.log_state,
        .localRow = facts.local_row,
        .authority = authority.code(),
        .authorityError = authority.note(ctx.arena, .{ .session = session }),
        .leaseRelease = lease.code,
        .leaseReleaseError = lease.detail,
        .reason = reason,
        .hint = hint,
    });
    Cli.exitNow(Cli.exit_code.receipt_persist_failed);
}

/// The ledger already held a terminal for this attempt when the removal's
/// transaction tried to write one.
///
/// Unreachable by construction today — this command settles its own operation
/// once — and reported rather than asserted because if it ever is reached, the
/// row's verdict belongs to whoever wrote it and this command must not delete a
/// session against it. Nothing was deleted; the local row and its memories stand.
///
/// Exit 75: what the ledger holds is not what this command established, so
/// nothing here says what the record means.
fn refuseAlreadySettled(
    ctx: *Cli.Ctx,
    execution: *Core.execution.Execution,
    server_name: []const u8,
    session: []const u8,
    authority: Authority,
    winner: Core.Store.receipts.TerminalRecord,
) noreturn {
    const reason = std.fmt.allocPrint(
        ctx.arena,
        "session '{s}:{s}' was stopped and its log deleted, and the ledger already held a '{s}' terminal for this request written by somebody else — so this command wrote no verdict and deleted no local record",
        .{ server_name, session, winner.status.text() },
    ) catch "the ledger already held a terminal for this request; no local record was deleted";
    const lease = Cli.releaseClaimReporting();
    report(ctx, .{
        .ok = false,
        .action = "not_removed",
        .errorCode = code.already_settled,
        .session = session,
        .server = server_name,
        .requestId = execution.id(),
        .status = execution.status.text(),
        .sessionState = state.session.gone,
        .logState = state.log.deleted,
        .localRow = state.row.kept,
        .authority = authority.code(),
        .authorityError = authority.note(ctx.arena, .{ .session = session }),
        .leaseRelease = lease.code,
        .leaseReleaseError = lease.detail,
        .reason = reason,
        .hint = "read the recorded terminal with 'terminus request receipt <request-id>' before acting on this session again",
    });
    Cli.failIndeterminateAfterOutput(execution.id());
}

/// Writes one refusal, in whichever format the caller asked for.
///
/// Printed rather than raised through `fail`, so the request id reaches the
/// operator on every path: a refused removal is still a recorded attempt, and
/// auditing or reconciling it needs the id.
fn report(ctx: *Cli.Ctx, body: RemovalJson) void {
    switch (ctx.out.format) {
        .json => ctx.out.json(body) catch {},
        .human => {
            ctx.out.print("refused: {s}\n  request: {s}\n", .{ body.reason orelse "the removal did not complete", body.requestId }) catch {};
            if (body.hint) |text| ctx.out.print("  {s}\n", .{text}) catch {};
            if (body.leaseReleaseError) |text| ctx.out.print("  {s}\n", .{text}) catch {};
        },
    }
    ctx.out.flush() catch {};
}

/// Refuses a removal that a peer's claim makes unsafe, before `begin` has even
/// created a row — and records that the refusal happened.
///
/// `execution.begin` returns `.blocked` having inserted nothing, so until now a
/// refused `session rm` left no trace of any kind: `docs/m3b-job-control.md` §8
/// says a removal blocked by a held claim "is refused and records the refusal",
/// and it recorded nothing. Five questions had no answer — whether anybody tried,
/// who, when, how often, and what stopped them — for the single most destructive
/// verb in the tree.
///
/// So the row is written here, through `execution.recordRefusal`, which creates
/// and settles it in one transaction. The terminal is `local_abandon` and settles
/// `cancelled`, which **does not block scope** — the property that makes writing
/// it safe. A record of a refusal that went on to refuse the next command would be
/// worse than no record at all, so that is asserted by a gate rather than left to
/// this comment.
///
/// The refusal itself is unchanged: nothing was sent, no socket was opened, and
/// the peer's claim is neither displaced nor released.
///
/// **What changed is what happens when that write fails.** It used to reach
/// `Cli.storeFatal` → `Cli.fail`, which emits `{ok, error}` and **exit 1** — and
/// this is the one branch in the verb where the record *is* the whole act, so
/// losing it loses everything: the five questions above go back to having no
/// answer, and 1 tells a caller that nothing happened, which is true of the host
/// and false of the ledger. It now emits the verb's fixed document and exits 76,
/// like every other ledger write this command cannot make.
fn refuseBeforeOpening(
    ctx: *Cli.Ctx,
    store: *Store,
    opts: Core.execution.BeginOptions,
    server_name: []const u8,
    session: []const u8,
    blocker: Core.execution.Blocker,
) noreturn {
    const reason = blockerReason(ctx, blocker, server_name, session);
    // Written by `recordRefusal` before anything there can fail, so the branch
    // below can name the id it tried to record under. `undefined` is never read:
    // the only reader is that branch, and reaching it means the call ran.
    var minted: Store.ids.RequestId = undefined;
    const refusal = Core.execution.recordRefusal(store, ctx.arena, ctx.io, opts, reason, &minted) catch |err|
        refuseLedgerUnrecordable(
            ctx,
            &minted,
            server_name,
            session,
            // No row exists to read the ledger's word off — the write that would
            // have created it is the one that failed. The word for that is not a
            // status this command may borrow from somewhere else.
            state.ledger.unknown,
            .held,
            Facts.untouched,
            code.receipt_persist_failed,
            "a peer's claim refused this removal before anything was sent, and the record of that refusal could not be written — so nothing under the request id below exists, and there is no trace that this removal was attempted",
            "nothing was sent to the host and nothing local changed; the peer's claim still stands, and this attempt left no record — re-run once the scope is free",
            err,
        );
    // `not_taken`: this path never acquired a lease, and saying "released" would
    // claim a hand-back that never happened.
    report(ctx, .{
        .ok = false,
        .action = "not_removed",
        .errorCode = code.scope_held,
        .session = session,
        .server = server_name,
        .requestId = refusal.id(),
        // Read back off the settlement rather than spelled here: one place
        // decides what a refusal settles as, and it is `recordRefusal`.
        .status = refusal.status.text(),
        .sessionState = Facts.untouched.session_state,
        .logState = Facts.untouched.log_state,
        .localRow = Facts.untouched.local_row,
        .authority = Authority.code(.held),
        .authorityError = null,
        .leaseRelease = Cli.ClaimRelease.not_taken.code,
        .leaseReleaseError = Cli.ClaimRelease.not_taken.detail,
        .reason = reason,
        .hint = blockerHint(ctx, blocker),
    });
    Cli.exitNow(Cli.exit_code.failure);
}

/// The sentence naming whose claim refused this removal.
fn blockerReason(
    ctx: *Cli.Ctx,
    blocker: Core.execution.Blocker,
    server_name: []const u8,
    session: []const u8,
) []const u8 {
    return switch (blocker) {
        .unsettled => |op| std.fmt.allocPrint(
            ctx.arena,
            "request {s} is {s} on a scope that overlaps session '{s}:{s}', so removing it could destroy work that is still running; nothing was sent to the host",
            .{ op.request_id, op.status.text(), server_name, session },
        ) catch "an unsettled command holds a scope that overlaps this session; nothing was sent to the host",
        .lease => |lease| std.fmt.allocPrint(
            ctx.arena,
            "request {s} (on {s}) holds a lease on a scope that overlaps session '{s}:{s}' until {d}; nothing was sent to the host",
            .{ lease.owner_request_id, lease.profile_token, server_name, session, lease.expires_at },
        ) catch "another command holds a lease on a scope that overlaps this session; nothing was sent to the host",
    };
}

/// What to do about it. Prose; nothing branches on it.
fn blockerHint(ctx: *Cli.Ctx, blocker: Core.execution.Blocker) ?[]const u8 {
    return switch (blocker) {
        .unsettled => |op| std.fmt.allocPrint(
            ctx.arena,
            "reconcile it ('terminus request reconcile {s}') or wait for it to settle; for a job's session use 'terminus job kill' / 'terminus job rm', which are the verbs for a job",
            .{op.request_id},
        ) catch "reconcile the blocking request or wait for it to settle",
        .lease => "wait for that lease to lapse; there is no --force here, because a takeover would displace somebody's claim on a shell about to be destroyed along with its memories",
    };
}

/// The scope a command acting on session `name` contends on.
///
/// This is the line that closes §1.2, and the only place in this slice where a
/// name is taken apart.
///
/// A session called `job-<x>` is job `<x>`'s shell: `cmd_job` builds that name
/// (`jobSessionName`), and `Tmux.list` strips the `t-` prefix, so a running job
/// appears in `session ls` as `job-deploy`. `session rm web job-deploy` is
/// therefore aimed at the same shell `job kill web deploy` is aimed at — and
/// until now the two could not see each other. The job claims `.job:"deploy"`;
/// a lease keyed on the session name as typed would be `.job:"job-deploy"`,
/// which `Scope.overlaps` correctly reports as a different thing. Nothing
/// contended, and `session rm` killed running jobs.
///
/// So the *kill target* stays the physical session name and the *contention key*
/// is the logical thing that session belongs to — the split §4.3 states, applied
/// one verb early. The surgery lives here, at the call site that knows what it
/// is acting on, and never inside `Scope.overlaps`, which has to stay an
/// obviously correct key comparison (§7.10 rejected exactly that for this
/// reason).
///
/// Two limits, stated here rather than discovered later:
///
///  * a *user* session literally named `deploy` also maps to `.job:"deploy"` and
///    so now blocks against job `deploy`. That is §1.3's existing false
///    collision — `write` and `exec <server>:<session>` already spell a session
///    scope as `.job:<session name>` — widened by one verb rather than invented
///    here, and it is the safe direction: refusing once too often costs a wait,
///    refusing once too rarely destroys somebody's shell.
///  * `write web:job-deploy` claims `.job:"job-deploy"` and still does not
///    overlap this, so those two remain blind to each other. That is §1.3's
///    false *miss*, and it closes with the v13 `.session` scope — fixing it
///    *is* the scope-vocabulary change, and that is not this slice.
fn contentionScope(name: []const u8) Core.execution.Scope {
    const job_prefix = "job-";
    if (std.mem.startsWith(u8, name, job_prefix) and name.len > job_prefix.len)
        return .{ .kind = .job, .key = name[job_prefix.len..] };
    return .{ .kind = .job, .key = name };
}

test contentionScope {
    const t = std.testing;
    // The headline case: the session a running job lives in contends with the
    // job, because it *is* the job's shell.
    try t.expectEqualStrings("deploy", contentionScope("job-deploy").key);
    try t.expect(contentionScope("job-deploy").overlaps(.{ .kind = .job, .key = "deploy" }));
    // An ordinary session keeps the key `write` and `exec <server>:<session>`
    // already use for it.
    try t.expectEqualStrings("shell", contentionScope("shell").key);
    try t.expect(!contentionScope("shell").overlaps(.{ .kind = .job, .key = "deploy" }));
    // A session called exactly `job-` is not job ""; it is a session with an odd
    // name, and stripping the prefix would give it the empty key — which every
    // other empty-keyed `.job` scope would then collide with.
    try t.expectEqualStrings("job-", contentionScope("job-").key);
}

/// Takes the scope, after `begin` and before anything is sent.
///
/// The `Claim` this returns is `Control.Claim`: ownership is the control
/// operation's own `request_id`, minted by `execution.begin` before anything is
/// sent. That is deliberate on both sides — `blockerLocked` exempts a lease
/// whose owner is the request id it was handed, so this command's own claim can
/// never refuse it, and a peer reading the row finds the operation that took it
/// rather than a token naming this machine.
///
/// There is no `--force` here, and the omission is deliberate rather than
/// pending: a takeover displaces somebody else's claim on a session that is
/// about to be destroyed along with its memories, and nothing in this slice
/// establishes whose shell it is. Waiting out the TTL is the escape hatch.
///
/// Takes the execution rather than just its id because its two refusals are
/// branches of `session rm` like any other: they used to `fatal`, which emits the
/// generic `{ok, error}` envelope, so a caller that hit the one-in-a-thousand
/// window between `begin`'s check and this acquisition got two keys instead of the
/// verb's fixed set. Both settle the attempt and both report through
/// `refuseWithNothingSent`.
fn claimScope(
    ctx: *Cli.Ctx,
    store: *Store,
    execution: *Core.execution.Execution,
    opts: Core.execution.BeginOptions,
    server_name: []const u8,
    session: []const u8,
) Claim {
    const server_id = opts.server_id orelse
        fatal("internal: the control operation for session '{s}' names no server", .{session});
    const claim: Claim = .{
        .store = store,
        .server_id = server_id,
        .scope = contentionScope(session),
        .owner_request_id = execution.id(),
        .subject = .{ .session = session },
    };
    const outcome = Store.leases.acquire(store, ctx.arena, .{
        .server_id = server_id,
        .scope = claim.scope,
        .owner_request_id = execution.id(),
        // Audit subject: which machine did this. It decides nothing — that is
        // the point of the column — but a claim with no record of who took it
        // is not much of an audit trail.
        .profile_token = opts.owner_token,
        .owner_label = session,
        .ttl_secs = Claim.ttl_secs,
        // A live clock, not `ctx.now`. A lease is compared against a clock
        // rather than merely stamped with one, and `ctx.now` is this process's
        // start time — a TTL dated from it starts running before the store was
        // even opened.
        .now = wallClockSeconds(ctx.io),
    }) catch |err| Cli.storeFatal(store, err);

    switch (outcome) {
        .acquired => {
            Cli.registerClaim(store, server_id, claim.scope, execution.id(), session);
            return claim;
        },
        // The owner is a freshly minted request id, so it cannot already hold a
        // lease. Not folded into `acquired`: reaching this would mean two
        // commands are about to share an owner, which is the thing the whole
        // barrier exists to stop.
        .renewed => |lease| {
            const reason = std.fmt.allocPrint(
                ctx.arena,
                "internal: the id minted for this command ({s}) already held a lease on the scope for session '{s}'; refusing to share an owner with whatever took it — nothing was sent to the host",
                .{ lease.owner_request_id, session },
            ) catch "internal: the id minted for this command already held a lease on this session's scope; nothing was sent to the host";
            settleOrReportUnrecordable(ctx, execution, server_name, session, .held, Facts.untouched, reason);
            refuseWithNothingSent(
                ctx,
                execution,
                server_name,
                session,
                .held,
                code.owner_collision,
                reason,
                "this is a defect in Terminus, not a state you can clear; report the request id",
            );
        },
        // `begin` checked the same barrier a moment ago, so this is a peer that
        // arrived in between. Nothing has been sent.
        .conflict => |lease| {
            const reason = std.fmt.allocPrint(
                ctx.arena,
                "request {s} (on {s}) took a lease on a scope that overlaps session '{s}' until {d} while this command was starting; nothing was sent to the host",
                .{ lease.owner_request_id, lease.profile_token, session, lease.expires_at },
            ) catch "another command took a lease on a scope that overlaps this session while this one was starting; nothing was sent to the host";
            settleOrReportUnrecordable(ctx, execution, server_name, session, .held, Facts.untouched, reason);
            refuseWithNothingSent(
                ctx,
                execution,
                server_name,
                session,
                .held,
                code.scope_held,
                reason,
                "wait for that lease to lapse; there is no --force here, because a takeover would displace somebody's claim on a shell about to be destroyed along with its memories",
            );
        },
    }
}

// --- Adjacency, held against the source that has to have it -----------------
//
// "Renew before the step" is not a property of a function; it is a property of
// where the call sits. `stillOurs` cannot enforce it and no type can: a renewal
// three statements and a store transaction above a `kill-session` type checks
// exactly as well as one on the line above it, and answers a different question.
//
// The end-to-end gates cannot reach that window. A fake host's lease seizure is
// deterministic only while the binary is blocked on a socket, and between a
// renewal and the call it gates there is — by construction, and that is the
// point — no round trip to block on. So the adjacency is checked where it lives:
// in the text.
//
// The scan itself is `Control.renewalsAreAdjacent`, shared with `cmd_job.zig`,
// because two copies of a line walker and its failure message drift the same
// way two copies of the barrier would. So does the list of calls it looks for,
// which is now `Control.destructive_remote_calls` — it names one call
// (`Tmux.removeResult(`) that `removeSession` does not make today, which
// changes no count here and holds the rule for the day it does. What stays here
// is what only this file knows: which of its functions holds a claim, and how
// many destructive sites it has.

/// How many `Control.destructive_remote_calls` this file's claim-holding verb
/// makes. Asserted so a scan that found nothing — a renamed function, a body
/// delimiter that moved — fails instead of passing over an empty region.
const destructive_remote_call_count = 2;

/// The one function here that holds a `Claim` while it touches the host.
const claim_holding_bodies = [_][]const u8{"\nfn removeSession("};

test "gate: `session rm`'s destructive remote calls are renewed on the line above them" {
    const t = std.testing;
    const found = try Control.renewalsAreAdjacent(
        "src/cli/cmd_session.zig",
        @embedFile("cmd_session.zig"),
        &claim_holding_bodies,
    );
    // A scan that matched nothing would have reported nothing. Say how many
    // sites the rule is actually holding.
    try t.expectEqual(@as(usize, destructive_remote_call_count), found);
}

const MergedSession = struct {
    name: []const u8,
    alive: bool,
    cursor: i64,
    note: ?[]const u8,
};

/// Remote list ∪ local rows: a session may be alive remotely without local
/// metadata (created outside Terminus) or vice versa (server rebooted).
fn merge(
    arena: std.mem.Allocator,
    remote: []const Tmux.RemoteSession,
    local: []const Store.sessions.Session,
) ![]MergedSession {
    var out: std.ArrayList(MergedSession) = .empty;
    for (local) |l| {
        var alive = false;
        for (remote) |r| {
            if (std.mem.eql(u8, r.name, l.name)) {
                alive = true;
                break;
            }
        }
        try out.append(arena, .{ .name = l.name, .alive = alive, .cursor = l.cursor, .note = l.note });
    }
    for (remote) |r| {
        var known = false;
        for (local) |l| {
            if (std.mem.eql(u8, r.name, l.name)) {
                known = true;
                break;
            }
        }
        if (!known) try out.append(arena, .{ .name = r.name, .alive = true, .cursor = 0, .note = null });
    }
    return out.toOwnedSlice(arena);
}

/// Session names flow into tmux -t arguments and log file paths; keep them
/// to a safe charset instead of trying to quote for both contexts.
fn validateName(name: []const u8) void {
    if (name.len == 0 or name.len > 64) fatal("session name must be 1-64 chars", .{});
    for (name) |ch| {
        switch (ch) {
            'a'...'z', 'A'...'Z', '0'...'9', '-', '_', '.' => {},
            else => fatal("session name may only contain [a-zA-Z0-9._-]", .{}),
        }
    }
}

// --- The published key set, held against the struct that emits it -----------
//
// `RemovalJson` cannot drift from itself: it has no defaults, so a branch that
// omits a key does not compile. What can drift is the document. `skill/SKILL.md`
// publishes the key set as prose — a count, a never-null list and a nullable list
// — and prose does not fail to build when somebody adds a field, renames one, or
// takes a `?` off.
//
// It already drifted: the document said 11 keys for a struct with 12, and nothing
// caught it, because the `session rm` paragraph was the one key set with no gate
// reading it. `cmd_job.zig` has held `KillJson` and `RemovalJson` against their
// paragraphs since they were published; this is the same rule for this verb.
//
// Nullability is read from `@typeInfo` rather than from a list maintained beside
// it, because a list maintained beside it is one more thing to forget.
//
// The parse is a literal read of English and will break if that paragraph is
// reflowed. That is the trade, taken deliberately: a reformat that defeats the
// check fails the gate rather than quietly checking nothing. Every failure below
// prints the literal it was looking for, so the repair is to the document — or, if
// the wording genuinely moved on, to the needle here.
//
// The machinery is a second, smaller copy of `cmd_job.zig`'s. That is a real cost
// and it is stated rather than hidden: those helpers are file-private, and hoisting
// them into a module both files can reach is a module-boundary change, which is not
// this slice's to make.

/// The same text `terminus setup` ships, embedded rather than read: the gate runs
/// wherever the tests run, with no working directory to be wrong about.
const skill_md = @embedFile("terminus_skill");

const SkillError = error{
    SkillAnchorMissing,
    SkillCountUnreadable,
    SkillListUnterminated,
    SkillParensUnbalanced,
    SkillKeySetDrifted,
};

/// Whatever follows `needle`, or a loud failure naming it.
fn skillAfter(hay: []const u8, needle: []const u8, what: []const u8) SkillError![]const u8 {
    const at = std.mem.indexOf(u8, hay, needle) orelse {
        std.debug.print(
            \\
            \\skill/SKILL.md: cannot find {s}.
            \\  looked for the literal: "{s}"
            \\This gate parses that text to learn what the document claims about
            \\`session rm --json`'s key set. If the paragraph was reworded or reflowed,
            \\fix the needle in src/cli/cmd_session.zig; deleting the gate puts the
            \\document back to drifting from the struct unnoticed — which is how it came
            \\to publish 11 keys for a 12-field struct.
            \\
        , .{ what, needle });
        return error.SkillAnchorMissing;
    };
    return hay[at + needle.len ..];
}

/// The paragraph starting at `s`: up to its first blank line, or all of it. A line
/// of only spaces, tabs or `\r` is blank, so the parse does not depend on how the
/// checkout wrote its line endings.
fn skillParagraph(s: []const u8) []const u8 {
    var i: usize = 0;
    while (std.mem.indexOfScalarPos(u8, s, i, '\n')) |nl| {
        var j = nl + 1;
        while (j < s.len and (s[j] == ' ' or s[j] == '\t' or s[j] == '\r')) j += 1;
        if (j == s.len or s[j] == '\n') return s[0..nl];
        i = nl + 1;
    }
    return s;
}

/// Every `code span` after `label` that is not inside a parenthetical aside, up to
/// the first `.` outside both parentheses and code spans.
///
/// Parentheses are the reason this is not a plain search for the next period: the
/// document puts each enumeration's values in one (`gone` | `present` | ...), and
/// those are values, not keys.
fn skillKeys(
    gpa: std.mem.Allocator,
    para: []const u8,
    label: []const u8,
    what: []const u8,
) (SkillError || std.mem.Allocator.Error)![]const []const u8 {
    const rest = try skillAfter(para, label, what);
    var out: std.ArrayList([]const u8) = .empty;
    errdefer out.deinit(gpa);
    var depth: usize = 0;
    var i: usize = 0;
    var ended = false;
    while (i < rest.len) : (i += 1) {
        switch (rest[i]) {
            '(' => depth += 1,
            ')' => {
                if (depth == 0) {
                    std.debug.print(
                        \\
                        \\skill/SKILL.md: unbalanced parentheses in {s}, so the gate cannot tell
                        \\the keys from the values.
                        \\  text read: "{s}"
                        \\
                    , .{ what, rest });
                    return error.SkillParensUnbalanced;
                }
                depth -= 1;
            },
            '`' => {
                const close = std.mem.indexOfScalarPos(u8, rest, i + 1, '`') orelse {
                    std.debug.print(
                        \\
                        \\skill/SKILL.md: an unclosed `code span` in {s}.
                        \\  text read: "{s}"
                        \\
                    , .{ what, rest });
                    return error.SkillListUnterminated;
                };
                if (depth == 0) try out.append(gpa, rest[i + 1 .. close]);
                i = close;
            },
            '.' => if (depth == 0) {
                ended = true;
                break;
            },
            else => {},
        }
    }
    if (!ended or out.items.len == 0) {
        std.debug.print(
            \\
            \\skill/SKILL.md: {s} is empty or runs past the end of its sentence, so the
            \\gate would be checking nothing.
            \\  text read: "{s}"
            \\
        , .{ what, rest });
        return error.SkillListUnterminated;
    }
    return out.toOwnedSlice(gpa);
}

fn skillHas(list: []const []const u8, entry: []const u8) bool {
    for (list) |item| if (std.mem.eql(u8, item, entry)) return true;
    return false;
}

/// Every `code span` inside the parenthetical that follows `label`.
///
/// The other half of `skillKeys`, which deliberately *skips* those parentheticals
/// because they hold values rather than keys. Nothing was reading them, so a
/// value could be added to the document, or to the code, with no gate noticing —
/// which is exactly the shape the key-count drift took before a gate read that.
///
/// Stops at the first `)`, so it reads one key's list and not the rest of the
/// sentence.
fn skillValues(
    gpa: std.mem.Allocator,
    para: []const u8,
    label: []const u8,
    what: []const u8,
) (SkillError || std.mem.Allocator.Error)![]const []const u8 {
    const rest = try skillAfter(para, label, what);
    var out: std.ArrayList([]const u8) = .empty;
    errdefer out.deinit(gpa);
    var i: usize = 0;
    var closed = false;
    while (i < rest.len) : (i += 1) {
        switch (rest[i]) {
            ')' => {
                closed = true;
                break;
            },
            '`' => {
                const close = std.mem.indexOfScalarPos(u8, rest, i + 1, '`') orelse {
                    std.debug.print(
                        \\
                        \\skill/SKILL.md: an unclosed `code span` in {s}.
                        \\  text read: "{s}"
                        \\
                    , .{ what, rest });
                    return error.SkillListUnterminated;
                };
                try out.append(gpa, rest[i + 1 .. close]);
                i = close;
            },
            else => {},
        }
    }
    if (!closed or out.items.len == 0) {
        std.debug.print(
            \\
            \\skill/SKILL.md: {s} is empty or its parenthetical never closes, so the gate
            \\would be checking nothing.
            \\  text read: "{s}"
            \\
        , .{ what, rest });
        return error.SkillListUnterminated;
    }
    return out.toOwnedSlice(gpa);
}

/// One documented value list against the namespace the branches actually spell it
/// from.
fn expectSkillVocabulary(
    gpa: std.mem.Allocator,
    documented: []const []const u8,
    what: []const u8,
    comptime namespace: type,
) SkillError!void {
    var actual: std.ArrayList([]const u8) = .empty;
    defer actual.deinit(gpa);
    inline for (@typeInfo(namespace).@"struct".decls) |decl| {
        actual.append(gpa, @field(namespace, decl.name)) catch return error.SkillKeySetDrifted;
    }
    try expectSkillKeys(what, documented, actual.items);
}

/// One documented list against the one the code actually has, in both directions.
/// Both matter: an entry the document invented is as wrong as one it forgot, and a
/// field whose `?` came or went shows up as one of each.
fn expectSkillKeys(
    what: []const u8,
    documented: []const []const u8,
    actual: []const []const u8,
) SkillError!void {
    var drifted = false;
    for (documented) |entry| {
        if (!skillHas(actual, entry)) {
            std.debug.print(
                \\
                \\skill/SKILL.md lists `{s}` among {s}, and RemovalJson has nothing of that
                \\name there — it was removed, renamed, or moved to the other list.
                \\
            , .{ entry, what });
            drifted = true;
        }
    }
    for (actual) |entry| {
        if (!skillHas(documented, entry)) {
            std.debug.print(
                \\
                \\RemovalJson has `{s}` among {s}, and skill/SKILL.md does not list it there.
                \\
            , .{ entry, what });
            drifted = true;
        }
    }
    if (!drifted and documented.len != actual.len) {
        std.debug.print(
            \\
            \\skill/SKILL.md repeats an entry among {s}: {d} listed for {d} in the struct.
            \\
        , .{ what, documented.len, actual.len });
        drifted = true;
    }
    if (drifted) return error.SkillKeySetDrifted;
}

test "gate: SKILL.md's `session rm --json` key set is the one RemovalJson emits" {
    const gpa = std.testing.allocator;
    const fields = @typeInfo(RemovalJson).@"struct".fields;

    var never_null: std.ArrayList([]const u8) = .empty;
    defer never_null.deinit(gpa);
    var nullable: std.ArrayList([]const u8) = .empty;
    defer nullable.deinit(gpa);
    inline for (fields) |f| {
        // From the type. A hand-kept list of which keys are optional would be
        // exactly the drift this gate exists to catch.
        const bucket = if (@typeInfo(f.type) == .optional) &nullable else &never_null;
        try bucket.append(gpa, f.name);
    }

    const heading = "\n`session rm --json` — ";
    const para = skillParagraph(try skillAfter(skill_md, heading, "the key-set paragraph it opens"));

    const keys_at = std.mem.indexOf(u8, para, " keys,") orelse {
        std.debug.print(
            \\
            \\skill/SKILL.md: "`session rm --json` — " is not followed by "<n> keys,", so
            \\the gate cannot read the count the document claims.
            \\
        , .{});
        return error.SkillCountUnreadable;
    };
    const claimed = std.fmt.parseInt(usize, para[0..keys_at], 10) catch {
        std.debug.print(
            \\
            \\skill/SKILL.md: "`session rm --json` — " is followed by "{s} keys,", which is
            \\not a number.
            \\
        , .{para[0..keys_at]});
        return error.SkillCountUnreadable;
    };
    if (claimed != fields.len) {
        std.debug.print(
            \\
            \\skill/SKILL.md says "`session rm --json` — {d} keys,"; RemovalJson has {d}
            \\fields. This is the exact drift the gate was added for.
            \\
        , .{ claimed, fields.len });
        return error.SkillKeySetDrifted;
    }

    const documented_never_null = try skillKeys(gpa, para, "Never null: ", "`session rm`'s never-null keys");
    defer gpa.free(documented_never_null);
    const documented_nullable = try skillKeys(gpa, para, "Nullable: ", "`session rm`'s nullable keys");
    defer gpa.free(documented_nullable);

    // Both, before either is raised: a field that gained or lost its `?` is one
    // complaint from each list, and reporting half of that would send the reader
    // looking for a rename that never happened.
    const never_null_verdict = expectSkillKeys("`session rm`'s never-null keys", documented_never_null, never_null.items);
    const nullable_verdict = expectSkillKeys("`session rm`'s nullable keys", documented_nullable, nullable.items);
    try never_null_verdict;
    try nullable_verdict;
}

// `errorCode`'s vocabulary is published too, and a token the document invented
// would send an agent looking for a branch that cannot happen. Held against the
// `code` namespace rather than a transcription of it, so a renamed constant
// rewrites the check along with the code.
test "gate: SKILL.md publishes exactly `session rm`'s errorCode vocabulary" {
    const gpa = std.testing.allocator;
    const para = skillParagraph(try skillAfter(
        skill_md,
        "\n`session rm --json`'s `errorCode` is ",
        "the errorCode vocabulary paragraph",
    ));
    const documented = try skillKeys(gpa, para, "one of ", "`session rm`'s errorCode values");
    defer gpa.free(documented);

    var actual: std.ArrayList([]const u8) = .empty;
    defer actual.deinit(gpa);
    inline for (@typeInfo(code).@"struct".decls) |decl| {
        try actual.append(gpa, @field(code, decl.name));
    }
    try expectSkillKeys("`session rm`'s errorCode values", documented, actual.items);
}

// The step vocabularies are published too, and until now nothing read them. The
// key-set gate above deliberately skips every parenthetical — those hold values,
// not keys — so `sessionState` could gain a word in the code with the document
// still listing three, or the document could invent one the branches never emit,
// and both would pass. That is the same class of drift as the 11-keys-for-12-fields
// defect, one level down.
//
// Held against `state`'s three namespaces rather than a transcription of them, so a
// renamed or added member rewrites the check along with the code. The namespaces
// exist for this: flat, the union of the three had `not_attempted` in it twice and
// there was nothing a documented list could be compared with.
test "gate: SKILL.md publishes exactly `session rm`'s step-state vocabularies" {
    const gpa = std.testing.allocator;
    const heading = "\n`session rm --json` — ";
    const para = skillParagraph(try skillAfter(skill_md, heading, "the key-set paragraph it opens"));

    const session_values = try skillValues(gpa, para, "`sessionState` (", "`sessionState`'s values");
    defer gpa.free(session_values);
    const log_values = try skillValues(gpa, para, "`logState` (", "`logState`'s values");
    defer gpa.free(log_values);
    const row_values = try skillValues(gpa, para, "`localRow` (", "`localRow`'s values");
    defer gpa.free(row_values);

    // All three before any is raised, for the reason the key-set gate gives: a
    // value that moved from one key to another is one complaint from each list,
    // and reporting half of that sends the reader after a rename that never was.
    const session_verdict = expectSkillVocabulary(gpa, session_values, "`sessionState`'s values", state.session);
    const log_verdict = expectSkillVocabulary(gpa, log_values, "`logState`'s values", state.log);
    const row_verdict = expectSkillVocabulary(gpa, row_values, "`localRow`'s values", state.row);
    try session_verdict;
    try log_verdict;
    try row_verdict;
}

// `status` has no parenthetical to read, because its ordinary values are whatever
// the ledger holds — an open set this verb does not own. What it *does* own is the
// one word for "there is no row to read a word off", and a word documented in prose
// that no gate parses is the thing this file has already been caught doing.
test "gate: SKILL.md publishes the word `session rm` uses when the ledger has no row" {
    const gpa = std.testing.allocator;
    const para = skillParagraph(try skillAfter(
        skill_md,
        "\n`session rm --json`'s `status` is ",
        "the status paragraph",
    ));
    const documented = try skillKeys(gpa, para, "so it is ", "`session rm`'s no-row status word");
    defer gpa.free(documented);
    try expectSkillVocabulary(gpa, documented, "`session rm`'s no-row status word", state.ledger);
}
