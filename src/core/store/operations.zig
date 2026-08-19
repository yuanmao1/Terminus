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
const scope = @import("scope.zig");

pub const Status = op_state.Status;
pub const ResolvedStatus = op_state.ResolvedStatus;
pub const Terminal = op_state.Terminal;
/// Shared with leases, so both safety barriers use one overlap definition.
pub const ScopeKind = scope.Kind;
pub const Scope = scope.Scope;

/// Bumped when the row layout gains meaning that a reader must understand.
pub const schema_version: i64 = 1;

pub const Kind = enum {
    exec,
    job,
    /// Bytes typed into a live session's shell (`terminus write`).
    ///
    /// Named for the act rather than for its effect, because the effect is not
    /// knowable from here: the terminal takes the bytes and says nothing about
    /// what the shell then makes of them. Everything downstream of this name —
    /// the terminal receipt, what evidence may settle it — is built on that
    /// gap. See `op_state.Terminal.input_accepted`.
    session_write,
    /// A supervisory act on somebody else's session: stopping it, forgetting
    /// it, reclaiming it.
    ///
    /// `terminus session rm` is the first and, today, only producer. Until it
    /// had one of these, a command that killed a remote session, deleted its
    /// pane log and dropped its local row wrote **nothing** to the ledger —
    /// five questions with no answer: whether anyone tried, who, when, whether
    /// it worked, and whether this was the first attempt or the third.
    ///
    /// Adding the variant cost no migration: `operations.kind` is bare
    /// `TEXT NOT NULL` (`migrate.zig`), unlike `status` and `resolved_status`,
    /// which carry CHECKs. What it did cost is the two admissibility matrices
    /// below, which are exhaustive in both directions and so stopped the build
    /// until every cell for this kind was answered on purpose.
    ///
    /// Named for the class of act rather than for the verb, and both
    /// alternatives were considered. `job_control` was rejected because
    /// `session rm` is not a job. One variant per action — `kill_session`,
    /// `remove_session`, … — was rejected because it multiplies the two
    /// admissibility matrices in `receipts` by four and stops the action being
    /// a queryable column; what the operation acted on is carried by `alias`
    /// today and by dedicated target columns (kind, key, request) in v13.
    ///
    /// A control operation settles from **its own** evidence — lease held or
    /// lost, kill sent or withheld, the host's answer — and never from the
    /// target's. That separation is the whole point: one row used to carry two
    /// subjects, which is why `fdd1144` had to decide by hand whether a lost
    /// lease may overwrite a proven exit code (§3.4).
    control,
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

    /// What this kind of work *is*, in the terms both admissibility matrices in
    /// `receipts` are decided in. See `Capabilities`.
    ///
    /// Exhaustive with no `else`: a new kind stops the build here until somebody
    /// says what it does, which is the one question adding a kind should cost.
    pub fn capabilities(k: Kind) Capabilities {
        return switch (k) {
            // One supervised remote command of the caller's, judged by its exit
            // status, and the only kind that records the identity of the process
            // that ran it — `supervisor.Identity`, put on the trail by
            // `execution.remoteStarted`, which is a pid *and* a start token so a
            // recycled pid cannot masquerade as ours. It has no job wrapper, it
            // declares no destination, and it types nothing into anybody's shell.
            .exec => .{
                .runs_our_command = true,
                .supervised_deadline = true,
                .records_process_identity = true,
                .offers_input_bytes = false,
                .publishes_declared_artifact = false,
                .supervises_another_subject = false,
                .wrapper_documents_exit = false,
                .judgement_undeclared = false,
            },
            // Also one supervised remote command, and the launch line carries our
            // wrapper: it echoes a sentinel after the command and writes a result
            // sidecar at an address derived from the request id, which are the two
            // evidence chains addressed to a job.
            //
            // `records_process_identity` is **false**, and it is the one axis here
            // whose answer is not obvious. `cmd_job` launches into a tmux session
            // and reports `Tmux.panePid`, so the only identity on a job's trail is
            // the *pane's* pid, with no start token. `supervisor.zig` says what
            // that is worth: "a command that daemonized, called `disown`, or ran
            // under `setsid` outlives the pane". A probe of it is a reading about
            // one process offered as a verdict on another — pane gone,
            // `cancelled`, scope released, child still running — and `cmd_job`'s
            // own kill path already honours the distinction, writing
            // `remote_cancel_confirmed` only where `verified_cancellation` is
            // satisfied, which shell mode never is. If a launcher ever reports the
            // command's own pid and start token onto a job's trail, this is the
            // line that becomes `true`, and it should move in the same change that
            // makes it true rather than be held open in advance.
            //
            // `offers_input_bytes` is false for the reason it is worth writing
            // twice: `cmd_job` types its launch line into a tmux session exactly
            // as `write` types the operator's. The shared mechanism is not the
            // act. A job is judged by the wrapper's exit status, never by the
            // terminal's acceptance of the line that started it — and a receipt
            // carrying a byte count and no exit code would record a command as
            // having succeeded that nothing ever judged.
            .job => .{
                .runs_our_command = true,
                .supervised_deadline = true,
                .wrapper_documents_exit = true,
                .records_process_identity = false,
                .offers_input_bytes = false,
                .publishes_declared_artifact = false,
                .supervises_another_subject = false,
                .judgement_undeclared = false,
            },
            // Bytes typed into a shell somebody else is running, and the whole of
            // what the remote answers is whether the terminal took them.
            //
            // `runs_our_command = false` is the axis this kind exists to make
            // non-vacuous, and the tempting wrong answer is concrete rather than
            // hypothetical: `tmux send-keys` is itself a command with an exit
            // status, so a driver could settle the write with the tmux client's.
            // That is `input_accepted`/`input_refused` respelled as a verdict on a
            // command, and it loses the byte count and digest a write's receipt is
            // required by its own evidence type to carry. `7d0898a` split those
            // variants out of `exited` precisely so a receipt would not carry
            // `exit_code = 0`, in the column an auditor reads first, for an
            // operation in which no command was judged.
            //
            // Nothing else is true of it either. Nothing on the far side of
            // `send-keys` enforces a deadline or reports one, so `timed_out` is
            // not an outcome it can have — the local deadline waiting for the
            // answer is `indeterminate` (`op_state` rule 2), not a timeout. It
            // records no process, and there is no shape in which it could:
            // `Tmux.sendKeys` runs one tmux command and reports nothing about the
            // pane, let alone about whatever the shell then forks. The pane's pid
            // is not the input's process — that is the mistake `.job`'s
            // `records_process_identity` is false for. It has no wrapper: nothing
            // it types is obliged to echo anything, and an operator who typed a
            // wrapper of their own would be offering a document this binary never
            // asked any host to produce. And it declares no destination.
            .session_write => .{
                .offers_input_bytes = true,
                .runs_our_command = false,
                .supervised_deadline = false,
                .publishes_declared_artifact = false,
                .supervises_another_subject = false,
                .records_process_identity = false,
                .wrapper_documents_exit = false,
                .judgement_undeclared = false,
            },
            // A supervisory act whose subject is somebody else's work: `terminus
            // session rm` stops a remote session, deletes its pane log and forgets
            // its local row. `supervises_another_subject` is what that means on
            // both axes — the act is judged by whether the thing it named is
            // *gone*, read from the host's own answer (`tmux kill-session` then
            // `tmux has-session`), which is the session-granularity proof
            // `op_state.Terminal.remote_cancel_confirmed` documents its optional
            // `pid` for.
            //
            // Why the `.job` reservation does not transfer, which is the whole
            // question. A job's kill may only claim a verified cancellation when
            // the supervisor can prove the *process tree* is gone, because a job's
            // subject is the command in the pane and a disowned child outlives it.
            // A control act's subject is the **session itself**: "stop this shell,
            // delete its log, forget it". The gap that forces a job to
            // `indeterminate` — pane gone, work possibly alive — is not a gap in
            // this claim, because this claim never reached for the work.
            //
            // `runs_our_command = false`, and this is the same mistake as a
            // write's one step further on. `session rm` sends `tmux kill-session`,
            // `tmux has-session` and `rm -f`; each has an exit status of its own,
            // so the tempting wrong answer is three exit codes sitting in one
            // function, any of which a driver could hand to `settle`. A receipt
            // carrying `exit_code = 0` for a session removal would say, in the
            // column an auditor reads first, that a command the caller asked for
            // succeeded. None did; a session was stopped.
            //
            // `offers_input_bytes = false` is the trap §7.5 names by its commit
            // number: an act told "the session is gone" needs a terminal for that,
            // and `input_refused` is superficially close ("the remote answered,
            // and nothing of ours was touched") while its *name* is about input.
            // Nothing in a session removal offers bytes to a terminal, so there is
            // no answer about bytes to record.
            //
            // `records_process_identity = false`, one step sharper than a write's:
            // a control act has a process in *view* and it is somebody else's. The
            // pid in that pane belongs to whoever started the session, and the
            // only thing this operation ever wrote down about the host is the
            // session *name* (`alias`). Recording the pane's pid to make an
            // identity available would repeat `.job`'s mistake twice over — a
            // reading of one process settling a different operation, where the
            // operation is not even about a process.
            //
            // `wrapper_documents_exit = false` says out loud what "control and
            // target settle independently" (§3.4) means on the evidence axis. A
            // control act aimed at a job — `job kill`, `job rm`, `session rm`
            // pointed at `job-<name>` — is settled by what it itself did. The
            // job's wrapper documents belong to the job's own attempt, and that
            // row is where they settle it; a sidecar saying `exit 0` closing the
            // *supervisory* operation would report that the removal succeeded on
            // the strength of the removed job having finished. The two can
            // disagree — a kill that lost its lease over a job that had already
            // exited is exactly that case — and `fdd1144` is the commit that had
            // to untangle it by hand.
            //
            // It declares no destination: the pane log `session rm` deletes is not
            // one. Nothing said in advance that a file there would be what proved
            // the act, and that advance commitment is what the four readings of a
            // destination are compared against.
            .control => .{
                .supervises_another_subject = true,
                .runs_our_command = false,
                .supervised_deadline = false,
                .offers_input_bytes = false,
                .publishes_declared_artifact = false,
                .records_process_identity = false,
                .wrapper_documents_exit = false,
                .judgement_undeclared = false,
            },
            // Bytes to an address named before a byte moved, and the verdict is
            // what is at that address: `publishes_declared_artifact` is the whole
            // of what these three declare, and every process-shaped axis is false
            // on a positive argument rather than for want of a producer.
            //
            // A copier that wrote to the wrong path, or whose rename never ran,
            // still exits 0. So `runs_our_command` is false: an exit status is not
            // a reading of the destination and cannot be turned into one, and
            // admitting one would reach `completed` past every digest comparison
            // the resolve side is built to require. Nothing supervises a copier —
            // there is no `supervisor.Requirement.remote_deadline` on one, because
            // there is no copier — so no far side enforces a deadline, and a
            // transfer that really did run out of time still has to be settled by
            // looking at the path it declared. And "it is no longer running, its
            // absence verified" is equally true of a transfer that finished and one
            // that died mid-rename, which is why `supervises_another_subject` is
            // false too: admitting that reading would release the scope barrier on
            // the second while its checkpoint went on holding the destination
            // against everybody else.
            //
            // Decided while no producer exists, deliberately. **What is genuinely
            // gone until somebody writes one**: a transfer cannot reach
            // `completed` or `timed_out` through `settle` at all, and reaches
            // `failed` or `cancelled` only before submission. That is not a wedge —
            // `indeterminate` stays admissible from every in-flight state,
            // `transfers` reads `resolved_status` beside `status`
            // (`ownerBlocksScope`, `incumbentBlocksScope`), and `resolve` admits
            // four readings of a declared destination for exactly these kinds. A
            // producer that wants `completed` back must bring a terminal whose
            // content is the local effect it observed — the destination it wrote
            // and the digest it read back off it — not an exit status from the
            // process that was supposed to produce one.
            .transfer_push, .transfer_pull, .fetch => .{
                .publishes_declared_artifact = true,
                .runs_our_command = false,
                .supervised_deadline = false,
                .offers_input_bytes = false,
                .supervises_another_subject = false,
                .records_process_identity = false,
                .wrapper_documents_exit = false,
                .judgement_undeclared = false,
            },
            // Nothing in this binary constructs one, and — unlike a transfer —
            // nothing is known about what one would be judged by. `audit` is here
            // with the other three despite having two producers in `.kind = .audit`
            // form: what it lacks is not a row but a declared *verdict*, and this
            // field is about the second.
            //
            // `judgement_undeclared` is not a capability; it records the absence of
            // an answer, and it is a field rather than an inference because the two
            // matrices read it in **opposite directions**. On the settle side it
            // widens: refusing every terminal for a kind nothing knows anything
            // about means the first operation of that kind ever created is
            // unsettleable, holds its scope, and never reaches `indeterminate` for
            // a reconcile to act on — there is no operator variant in
            // `op_state.Terminal` to rescue it with. On the resolve side it is
            // ignored, and refusing costs nothing: `operator_override` is
            // admissible everywhere, so an operator route always remains.
            //
            // A change that builds a producer for one of these sets this false and
            // declares what it actually does. Half-states are refused: the gate in
            // `gates_admissibility_test.zig` holds that `judgement_undeclared` excludes every other
            // axis, so nobody can leave a kind claiming both that it publishes an
            // artifact and that nothing is known about it.
            .tunnel, .plan_phase, .audit, .cleanup => .{
                .judgement_undeclared = true,
                .runs_our_command = false,
                .supervised_deadline = false,
                .offers_input_bytes = false,
                .publishes_declared_artifact = false,
                .supervises_another_subject = false,
                .records_process_identity = false,
                .wrapper_documents_exit = false,
            },
        };
    }
};

/// What a kind of work *is*, in the terms the store's two admissibility
/// matrices are decided in.
///
/// Both matrices used to be written out cell by cell.
/// `receipts.terminalDescribesKind` is 8 terminals × 11 kinds and
/// `receipts.ResolutionEvidence.appliesToKind` is 9 evidence variants × 11
/// kinds — 187 hand-decided booleans, each with an independently-transcribed
/// mirror in `gates_admissibility_test.zig`, so 374 in total. Six of the eleven kinds are
/// constructed by nothing in this binary, and they accounted for 204 of them.
/// The bill came due as a refusal to spend it: one new `Terminal` variant cost
/// 22 answers, twelve about work that does not exist, and the variant a proven
/// post-submission failure needs — `op_state.Terminal.proven_failure` — was
/// deferred three times over.
///
/// What decides a cell was never the kind's *name*. It is whether the operation
/// ran a command of ours, so an exit status is its verdict; whether something on
/// the far side supervises that command and can hold it to a deadline; whether
/// it offers bytes to a terminal somebody else is running; whether it publishes
/// an artifact at an address it declared in advance; whether its subject is
/// somebody else's work; and what it wrote down about itself that a later
/// reading can be checked against. Those are the fields here, and both matrices
/// are rules over them — so a new kind declares what it is, and a new terminal
/// or evidence variant names the property it needs. One decision each, not
/// eleven.
///
/// **No field has a default and no cell has an exception.** Every field must be
/// written at every arm of `Kind.capabilities`, so a new axis stops the build
/// until all eleven kinds answer it, and the switch there has no `else`, so a
/// new kind stops it until it answers all eight. No cell in either matrix
/// departs from what these fields imply: there is no override table, because
/// nothing needed to be overridden, and an empty one would be a mechanism with
/// no user standing exactly where a future author looks for permission to make
/// an exception. The per-cell arguments the tables carried are not gone — the
/// ones about a *kind* are on the arms of `capabilities`, and the ones about a
/// *terminal or evidence variant* are on the rule that reads these fields.
pub const Capabilities = struct {
    /// This binary asks the host to run a command of the caller's, and that
    /// command's exit status is the operation's verdict.
    ///
    /// Read by two rules on the settle side, and the second is worth naming: a
    /// kind that runs a command of ours has a remote process, so there is
    /// something for a cancellation to have verified the absence of.
    runs_our_command: bool,
    /// Something on the far side supervises that command and may enforce and
    /// report a deadline on it — `supervisor.Requirement.remote_deadline`,
    /// satisfied only by the remote helper. A *local* deadline expiring is never
    /// this (`op_state` rule 2).
    supervised_deadline: bool,
    /// The act is offering the caller's bytes to a live terminal somebody else is
    /// running, and the remote's answer is whether the terminal took them.
    offers_input_bytes: bool,
    /// The verdict is an artifact at a destination declared before submission, so
    /// a reading of that address — present and right, present and wrong, present
    /// and uncheckable, or absent — is what speaks about it.
    publishes_declared_artifact: bool,
    /// The subject is somebody else's work, and the verdict is whether the thing
    /// this act named is gone, read from the host's own answer about it.
    supervises_another_subject: bool,
    /// The attempt records the identity of the process that did the work — a pid,
    /// and a start token where the host can read one — so a later probe can be
    /// checked against something this binary wrote down first.
    ///
    /// About the *recorded identity*, not about whether a process existed. A job
    /// runs one and records its pane's pid instead, which is why this is false
    /// there.
    records_process_identity: bool,
    /// The launch line carries our wrapper, which echoes a sentinel after the
    /// command and writes a result sidecar at an address derived from this
    /// operation's own id.
    wrapper_documents_exit: bool,
    /// Nothing constructs this kind and nothing is known about what one would be
    /// judged by. Not a capability — the absence of an answer, recorded so the
    /// two matrices can read it in opposite directions. See the arm that sets it.
    judgement_undeclared: bool,
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
    /// Whether this attempt claims its scope as a writer. Recorded, because
    /// the guard has to answer the same question later, when the caller that
    /// knew the answer is long gone.
    mutating: bool = true,
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
    mutating: bool,
    created_at: i64,
    updated_at: i64,

    /// The mutation scope this attempt claims. An attempt that never
    /// declared one is treated as covering the whole server: we cannot
    /// bound what it might be touching, so it must block rather than be
    /// assumed harmless.
    pub fn scopeOf(op: Operation) Scope {
        const kind_text = op.scope_kind orelse return scope.unknown;
        const kind = ScopeKind.parse(kind_text) catch return scope.unknown;
        return .{ .kind = kind, .key = op.scope_key orelse "" };
    }

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
    // The seed status is rendered from the enum for the same reason every other
    // status list in this store now is: a rename of the variant has to move the
    // statement with it rather than leave a row nothing can parse.
    var stmt = try store.db.prepare(comptime std.fmt.comptimePrint(
        \\INSERT INTO operations (
        \\  request_id, schema_version, server_id, server_name, kind,
        \\  scope_kind, scope_key, alias, status,
        \\  argv_redacted, argv_sha256, cwd, shell, capability_json, transport,
        \\  mutating, created_at, updated_at
        \\) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, '{s}', ?9, ?10, ?11, ?12, ?13, ?14, ?16, ?15, ?15)
    , .{@tagName(Status.created)}));
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
    try stmt.bindInt(16, @intFromBool(opts.mutating));
    _ = try stmt.step();
}

const select_columns =
    \\SELECT request_id, schema_version, server_id, server_name, kind,
    \\       scope_kind, scope_key, alias, status, resolved_status,
    \\       reconciled_at, resolution_evidence, argv_redacted, argv_sha256,
    \\       cwd, shell, capability_json, transport, mutating, created_at, updated_at
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
        .mutating = stmt.columnInt(18) != 0,
        .created_at = stmt.columnInt(19),
        .updated_at = stmt.columnInt(20),
    };
}

pub fn get(store: *Store, arena: Allocator, request_id: []const u8) (Error || Allocator.Error)!?Operation {
    var stmt = try store.db.prepare(select_columns ++ " WHERE request_id = ?1");
    defer stmt.deinit();
    try stmt.bindText(1, request_id);
    if (!try stmt.step()) return null;
    return try rowToOperation(arena, &stmt);
}

/// Advances a live (non-terminal) status.
///
/// The parameter type is `LiveStatus`, which has no terminal members, so
/// there is no way to reach `completed`/`failed`/`timed_out`/`cancelled`/
/// `indeterminate` through this function. Terminals belong to
/// `receipts.settle`, which demands evidence and writes the matching
/// terminal receipt in the same transaction.
pub fn advance(
    store: *Store,
    request_id: []const u8,
    to: op_state.LiveStatus,
    now: i64,
) (Error || error{ IllegalTransition, UnknownOperation })!void {
    try store.db.exec("BEGIN IMMEDIATE");
    errdefer store.db.exec("ROLLBACK") catch {};
    try advanceLocked(store, request_id, to, now);
    try store.db.exec("COMMIT");
}

/// The transition itself, for a caller that needs it to land atomically with
/// other writes.
///
/// `submitted` is the case that matters: the check for a conflicting attempt
/// and the write that makes *this* attempt visible as a conflict have to be
/// one indivisible step, or two callers each see a clear scope and both send.
/// Caller must hold the write transaction.
pub fn advanceLocked(
    store: *Store,
    request_id: []const u8,
    to: op_state.LiveStatus,
    now: i64,
) (Error || error{ IllegalTransition, UnknownOperation })!void {
    try store.db.requireTransaction();
    const current = try statusOfLocked(store, request_id);
    if (!op_state.canTransition(current, to.toStatus())) return error.IllegalTransition;

    var stmt = try store.db.prepare(
        "UPDATE operations SET status = ?1, updated_at = ?2 WHERE request_id = ?3",
    );
    defer stmt.deinit();
    try stmt.bindText(1, to.toStatus().text());
    try stmt.bindInt(2, now);
    try stmt.bindText(3, request_id);
    _ = try stmt.step();
}

/// Caller must hold the write transaction.
pub fn statusOfLocked(store: *Store, request_id: []const u8) (Error || error{UnknownOperation})!Status {
    try store.db.requireTransaction();
    var stmt = try store.db.prepare("SELECT status FROM operations WHERE request_id = ?1");
    defer stmt.deinit();
    try stmt.bindText(1, request_id);
    if (!try stmt.step()) return error.UnknownOperation;
    return try Status.parse(stmt.columnText(0));
}

/// Attempts that may still be touching the remote host. Used to block a
/// same-scope mutation (B7) and to fill the handoff package.
///
/// The predicate spells out "unsettled" directly rather than trusting that
/// `resolved_status` is only ever set on an `indeterminate` row. That
/// invariant is enforced in `receipts.resolve`, but a safety barrier should
/// not depend on a rule held somewhere else: a resolution written against a
/// still-running `submitted` attempt would otherwise silently lift the block.
///
/// The status list is rendered from `Status.blocksScope`, not typed out. It was
/// typed out until now — the last live copy of an operation-status list in this
/// store, and the barrier itself, so a member added to the predicate and not to
/// this string would have left the new status blocking nothing. `transfers` had
/// five copies of the checkpoint equivalent and one of them drifted; there is
/// no reason to keep the sixth here.
///
/// The exception is written as a subtraction because that is what it is: every
/// status in the list blocks, and exactly one of them stops blocking once
/// somebody has proved what really happened. Naming `indeterminate` once, next
/// to the column that resolves it, keeps the two halves of that sentence in one
/// place.
const unsettled_predicate = std.fmt.comptimePrint(
    \\ (status IN ({[blocking]s})
    \\  AND (status <> '{[resolvable]s}' OR resolved_status IS NULL))
, .{
    .blocking = op_state.sqlList(Status.blocksScope),
    .resolvable = @tagName(Status.indeterminate),
});

/// The scope barrier is held by writers only.
///
/// A read whose outcome is unknown is still worth surfacing — `request ls`
/// lists it, a handoff carries it — but it cannot make a later change unsafe,
/// because whatever it did or did not do, it did not change anything. Holding
/// the barrier for one would also be inconsistent with the same attempt while
/// it ran, which was allowed to proceed alongside a mutation.
const holds_scope_predicate = unsettled_predicate ++ " AND mutating = 1";

/// Which set of attempts a barrier query is about: one host, or — when null —
/// this machine.
///
/// `operations.server_id` is nullable, and until now every guard matched it
/// with `= ?1`, which is never true of NULL. An attempt with no server was
/// therefore invisible to every barrier in both directions: it saw nobody and
/// nobody saw it. `fetch` is exactly that shape — its destination is local, so
/// there is no row in `servers` to point at — so the one guard standing between
/// two commands writing the same place would silently not have applied to it.
/// Written in that mood deliberately: no command creates a `fetch`, so the
/// local realm is currently empty and this is a hole that was closed before
/// anything could fall into it.
///
/// `IS ?1` matches NULL against NULL, which turns "no server" into a realm of
/// its own rather than a hole. The two realms still do not see each other, and
/// that is the correct reading rather than a leftover: work on `web-01` and
/// work in a local directory cannot collide, so a barrier that made them block
/// each other would refuse changes for no reason. What changed is that two
/// pieces of *local* work now collide with each other.
///
/// Spelled `?i64` rather than a two-variant union because that is the type the
/// column, `BeginOptions.server_id` and every caller already carry; a union
/// would be clearer in isolation and would put a conversion at every call site
/// that has nothing to convert.
pub const Realm = ?i64;

pub fn unsettled(store: *Store, arena: Allocator, realm: Realm) (Error || Allocator.Error)![]Operation {
    return selectWhere(store, arena, realm, unsettled_predicate);
}

/// The subset of `unsettled` that actually bars a change: writers.
fn holdingScope(store: *Store, arena: Allocator, realm: Realm) (Error || Allocator.Error)![]Operation {
    return selectWhere(store, arena, realm, holds_scope_predicate);
}

fn selectWhere(
    store: *Store,
    arena: Allocator,
    realm: Realm,
    comptime predicate: []const u8,
) (Error || Allocator.Error)![]Operation {
    var out: std.ArrayList(Operation) = .empty;
    var stmt = try store.db.prepare(select_columns ++
        " WHERE server_id IS ?1 AND " ++ predicate ++ " ORDER BY created_at DESC");
    defer stmt.deinit();
    try stmt.bindOptInt(1, realm);
    while (try stmt.step()) try out.append(arena, try rowToOperation(arena, &stmt));
    return out.toOwnedSlice(arena);
}

/// How many attempts on this server still have an open remote outcome.
///
/// The barrier `servers.remove` refuses over, counted with the *same* rendered
/// predicate the mutation guard uses, so there is one definition of "still
/// unsettled" rather than two that can drift apart.
///
/// Deleting a server sets `operations.server_id` to NULL — the FK says so — and
/// that un-scopes every attempt on it at once: an unsettled writer stops
/// blocking the mutation it was blocking, and `request ls` (which filters by
/// server) stops listing any of them, so the route by which an operator would
/// have reconciled them leaves with the row.
///
/// It counts `unsettled` rather than the narrower `holds_scope` set, and the
/// difference is deliberate. The mutation guard asks "can this change collide",
/// which a read cannot; removal asks "does deleting this row destroy the only
/// way to find out what happened", which a read whose outcome is unknown is
/// just as exposed to. The wider predicate is also the safer mistake: refusing
/// once too often costs a reconcile, and refusing once too rarely releases a
/// barrier.
///
/// Caller must hold the write transaction. A count taken outside it describes a
/// moment that has already passed by the time the DELETE runs.
pub fn unsettledCountLocked(store: *Store, server_id: i64) Db.Error!i64 {
    try store.db.requireTransaction();
    var stmt = try store.db.prepare(
        "SELECT COUNT(*) FROM operations WHERE server_id IS ?1 AND " ++ unsettled_predicate,
    );
    defer stmt.deinit();
    try stmt.bindInt(1, server_id);
    if (!try stmt.step()) return error.Sqlite;
    return stmt.columnInt(0);
}

/// Unsettled *writers* overlapping a scope, for the mutation guard.
///
/// Overlap is decided in Zig using the shared `scope.Scope.overlaps` rules —
/// the same ones leases use. SQL equality on (kind, key) was not the same
/// thing: it missed `/srv/app` against `/srv/app/dist`, and a whole-server
/// mutation did not see a narrower path scope. One definition of "these two
/// touch the same thing" is the whole point; two nearly-identical ones is
/// how a hole appears.
///
/// An unsettled attempt that never declared a scope is treated as covering
/// the whole server: work that may still be running and whose blast radius
/// we cannot name has to block, rather than be assumed harmless. A read-only
/// attempt does not block at all — see `holds_scope_predicate`.
pub fn unsettledInScope(
    store: *Store,
    arena: Allocator,
    realm: Realm,
    target: scope.Scope,
) (Error || Allocator.Error)![]Operation {
    const candidates = try holdingScope(store, arena, realm);
    var out: std.ArrayList(Operation) = .empty;
    for (candidates) |op| {
        if (op.scopeOf().overlaps(target)) try out.append(arena, op);
    }
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
