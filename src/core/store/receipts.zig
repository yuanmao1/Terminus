//! Append-only receipt ledger (`operation_events`).
//!
//! This is the authoritative record of what happened, replacing the
//! best-effort `history` text log. Two invariants matter most:
//!
//! * **Append only.** Events are never updated or deleted.
//! * **Exactly one terminal per operation**, enforced by a partial unique
//!   index in the schema rather than by convention. Two racing writers
//!   cannot both settle a request: the loser gets `error.Constraint` and is
//!   handed the winner's terminal to reconcile against, never permitted to
//!   overwrite it.
//!
//! A failure to persist here must never be swallowed. `appendOrFail` is the
//! single door every write path goes through; see `Cli.receiptFatal`.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Store = @import("Store.zig");
const Db = @import("Db.zig");
const op_state = @import("op_state.zig");
const operations = @import("operations.zig");
// Read and written inside this module's own transaction: read to bind a
// published-file hash to the digest its transfer declared in advance, written
// to adjudicate a rename whose outcome the transfer never learned. Still
// one-way — `transfers` knows nothing about receipts — which is why
// `adjudicateLocked` is a bare statement and this module supplies the
// transaction. Keeping `transfers` the sole writer of its own table is the
// point: a second direct writer on one authoritative table is the entropy an
// audit has already flagged elsewhere in this store.
const transfers = @import("transfers.zig");
// Read inside this module's own transaction, to bind offered `job_sentinel`
// evidence to the sentinel this binary wrote down when it launched the job.
// One-way, like `transfers`: `job_attempts` imports only `std`, `Store` and
// `Db`, so it knows nothing about receipts and this edge closes no cycle.
const job_attempts = @import("job_attempts.zig");
const history = @import("history.zig");

pub const schema_version: i64 = 1;

pub const Kind = enum {
    /// Local record created; nothing sent.
    submit,
    connect,
    remote_start,
    progress,
    output,
    checkpoint,
    /// Settles the operation. At most one per request.
    terminal,
    reconcile,
    cleanup,
    audit,
    /// Lease acquire/release/takeover, for the coordination audit chain.
    lease,

    pub fn parse(text: []const u8) error{UnknownEventKind}!Kind {
        return std.meta.stringToEnum(Kind, text) orelse error.UnknownEventKind;
    }
};

/// Where an observation came from. `cache` readings must always travel with
/// their `observed_at` so a stale value cannot pass for a live one.
pub const Source = enum {
    live,
    cache,
    reconcile,
    legacy_import,
    backfill,

    pub fn parse(text: []const u8) error{UnknownSource}!Source {
        return std.meta.stringToEnum(Source, text) orelse error.UnknownSource;
    }
};

/// Byte-stream evidence: size and hash, never the payload itself.
pub const StreamEvidence = struct {
    bytes: ?i64 = null,
    sha256: ?[]const u8 = null,
    truncated: bool = false,
    /// Short, already-redacted human summary. Never raw output.
    digest: ?[]const u8 = null,
};

pub const Event = struct {
    request_id: []const u8,
    kind: Kind,
    observed_at: i64,
    source: Source = .live,

    phase: ?[]const u8 = null,
    status: ?op_state.Status = null,

    connected: ?bool = null,
    remote_started: ?bool = null,
    remote_pid: ?i64 = null,
    remote_pgid: ?i64 = null,
    /// Process start-time token. Without it a recycled pid could be
    /// mistaken for ours during reconcile.
    remote_start_token: ?[]const u8 = null,

    started_at: ?i64 = null,
    finished_at: ?i64 = null,
    duration_ms: ?i64 = null,
    exit_code: ?i64 = null,
    term_signal: ?i64 = null,
    timed_out: ?bool = null,

    transport_error: ?[]const u8 = null,
    error_code: ?[]const u8 = null,
    last_observed: ?[]const u8 = null,
    cancel_method: ?[]const u8 = null,

    stdin: StreamEvidence = .{},
    stdout: StreamEvidence = .{},
    stderr: StreamEvidence = .{},

    correlation_id: ?[]const u8 = null,
    /// Versioned, already-redacted structure for anything without a column.
    detail_json: ?[]const u8 = null,
};

/// What was found at a job's result-record address at the moment it settled.
///
/// A job can settle cleanly from the sentinel in its log while a document that
/// is *not* usable sits at the address derived from that same request — a
/// document naming a different request, one this build cannot parse, one from
/// a wrapper of another version, one reporting an exit code no shell produces.
/// The settlement is correct: the sentinel answered. But the anomaly is a fact
/// about the host — a result directory being reused, two request ids colliding,
/// a mismatched remote wrapper — and it was reaching the operator's screen and
/// then being dropped. The receipt, which is the one durable record, kept the
/// verdict and lost the contradiction standing next to it.
///
/// Deliberately *not* `Tmux.SidecarReading` itself. Nothing under `store/`
/// imports `session/`, and reversing that to reuse an enum would make the
/// persistence layer depend on the transport layer for the shape of a column's
/// contents. The tag names are identical on purpose — `SidecarReading.code()`
/// renders exactly these strings — and `cmd_job`'s mapping is an exhaustive
/// switch, so a reading added there is a compile error until it is named here.
///
/// `foreign` carries its claimed id in the type rather than in a sibling
/// optional field, so a `foreign` record without one cannot be constructed and
/// no other reading can carry one. That is the whole of the "half a fact"
/// problem: `foreign` is the reading whose entire content is *which other*
/// request the document named, and a receipt recording the tag alone would say
/// a collision happened while withholding the only thing that identifies it.
pub const ResultRecordReading = union(enum) {
    /// No request id was given, so no result record was looked for. Distinct
    /// from `absent`: one is "we did not ask", the other is "we asked and
    /// there is nothing there".
    not_requested,
    /// Looked, and the address is empty. Ordinary: the job predates result
    /// records, or its evidence was discarded.
    absent,
    /// Bytes are there and they are not a document this build can parse.
    malformed,
    /// Parsed, and declares a schema version this build does not know.
    unknown_schema,
    /// Parsed and ours, but the exit code is not a shell exit status.
    exit_code_out_of_range,
    /// Parsed, and names a different request. Carries the id it claimed.
    foreign: []const u8,
    /// A document we can read, at our address, naming us.
    present,

    /// The stable machine-readable name, derived from the tag so the receipt's
    /// vocabulary and this union cannot drift.
    pub fn code(r: ResultRecordReading) []const u8 {
        return @tagName(r);
    }
};

/// Supplementary facts a caller may attach to a terminal.
///
/// Deliberately narrow. Everything that the `Terminal` evidence itself
/// determines — status, exit code, signal, timed_out, transport error,
/// error code, cancel method, last observed state — is filled in by `settle`
/// and cannot be supplied here, so a caller cannot pair, say, a clean exit
/// with `timed_out = true`.
pub const TerminalExtra = struct {
    phase: ?[]const u8 = null,
    started_at: ?i64 = null,
    finished_at: ?i64 = null,
    duration_ms: ?i64 = null,
    /// What the transport actually observed, when it knows more than the
    /// state does — it can distinguish a refused TCP connect from a rejected
    /// key, both of which live in `connecting`. May not contradict work that
    /// was demonstrably handed over.
    connected: ?bool = null,
    remote_pid: ?i64 = null,
    remote_pgid: ?i64 = null,
    remote_start_token: ?[]const u8 = null,
    stdin: StreamEvidence = .{},
    stdout: StreamEvidence = .{},
    stderr: StreamEvidence = .{},
    correlation_id: ?[]const u8 = null,
    detail_json: ?[]const u8 = null,
    source: Source = .live,
    /// What was at this job's result-record address when it settled, and the
    /// arena to render it with.
    ///
    /// Null means the settlement recorded nothing about a result record, which
    /// is the ordinary case for everything that is not a job observation. It is
    /// *not* the same as `.not_requested`, which is a job observation that
    /// deliberately did not look — see `ResultRecordReading`.
    ///
    /// The arena travels inside the value rather than as a parameter on
    /// `settle` because `settle`, `settleLocked` and every wrapper over them in
    /// `execution` take no allocator, and threading one through would change
    /// four signatures to serve one annotation. It is required by the type
    /// whenever a reading is present, so there is no state where the store
    /// holds a reading it cannot write down.
    result_record: ?ResultRecord = null,

    pub const ResultRecord = struct {
        arena: Allocator,
        reading: ResultRecordReading,
    };
};

/// The ledger's own refusals, plus the ones `transfers.adjudicateLocked` can
/// hand back: `resolve` writes to the checkpoint table now, so it can fail in
/// that table's vocabulary. Only the adjudication subset is taken, not all of
/// `transfers.Error` — see `transfers.TransitionError` for why the split
/// exists.
pub const Error = Db.Error || transfers.AdjudicateError || error{
    UnknownEventKind,
    UnknownSource,
    UnknownStatus,
    /// A terminal event may only be written by `settle`.
    TerminalRequiresSettle,
    /// A reconcile event may only be written by `resolve`.
    ReconcileRequiresResolve,
    /// The requested terminal does not follow from the current status.
    IllegalTransition,
    /// The evidence contradicts the state the attempt was actually in (for
    /// example claiming nothing was submitted for an attempt already handed
    /// to the remote).
    EvidenceDoesNotFit,
    UnknownOperation,
    /// More than one checkpoint carrying a declared digest exists for one
    /// request. Choosing between them would make a scope-releasing decision
    /// by `ORDER BY`; see `transfers.expectedEffectLocked`.
    AmbiguousCheckpoint,
    /// A checkpoint's `dest_side` is not a value this binary writes. Like
    /// `UnknownOperationKind`, it means the row is not one we can reason
    /// about, so no admissibility decision may be made from it.
    UnknownDestSide,
    /// The `operations.kind` column holds something this binary cannot name.
    /// Not a business outcome: it means the row is not one we can reason
    /// about, so no admissibility decision may be made from it. Fires on any
    /// unparseable value, not only one too long to be a kind — a short
    /// unrecognised string used to slip past the text comparison this replaced
    /// and inherit the widest permit in `appliesToKind`.
    UnknownOperationKind,
    /// Supplementary fields contradict the evidence (e.g. a remote pid on a
    /// request whose command was provably never handed over).
    ContradictoryEvidence,
    /// The terminal offered does not describe work of this operation's *kind* —
    /// an exit status for a `session_write`, which runs no command; a terminal's
    /// acceptance of typed bytes for a `job`, which was judged by an exit status.
    ///
    /// A member of its own rather than another `EvidenceDoesNotFit`, because the
    /// two say different things to whoever reads them. `EvidenceDoesNotFit`
    /// means the evidence disagrees with the *state* the attempt was in, and
    /// sends a reader to look at a status; this means the evidence disagrees
    /// with the *work*, and the status is fine.
    ///
    /// Our defect, never an operator's. `settle` is reached only from the code
    /// that just did the work — every operation in this binary is created at one
    /// of three `execution.begin` sites and settled by the command that created
    /// it — so a pair this refuses is one this binary constructed wrongly. See
    /// `terminalDescribesKind`.
    TerminalDoesNotDescribeKind,
    /// A terminal carried both a caller-built `detail_json` and a
    /// result-record reading for this module to render into one.
    ///
    /// Our defect and not an operator's: the two would have to be merged, and
    /// merging a document whose shape this module does not control into one
    /// whose shape it promises is not something it can do correctly. Refused
    /// rather than resolved by dropping one, because either drop loses a fact
    /// that something went to the trouble of recording. Nothing constructs the
    /// combination today — every `detail_json` producer in the tree writes it
    /// on a `checkpoint` or an `audit` event.
    ConflictingTerminalDetail,
    /// The operation's transfer is parked in `indeterminate_publish` — its
    /// rename may or may not have landed — and the evidence offered cannot say
    /// which. The *whole* resolution is refused: resolving the operation and
    /// leaving the artifact unjudged would lift the scope barrier while the
    /// checkpoint goes on holding its destination against every later transfer.
    /// See `publishAdjudication` for what each evidence variant can establish.
    ///
    /// The cost of refusing the pair together, stated because it is not
    /// hypothetical: only a *reading of the destination* adjudicates. An
    /// operation in this position cannot be settled by an operator override, by
    /// a supervisor's report, or by a probe, so its scope barrier stays up until
    /// somebody goes and looks. What that costs the operator is one look; there
    /// is a reading for each of the four answers a look can produce —
    /// `filesystem_effect` when the artifact is there and hashes to the digest
    /// the transfer declared, `destination_present_contradicting` when it is
    /// there and hashes to something else, `destination_present_unverified` when
    /// it is there and no digest was ever declared, `destination_absent` when it
    /// is not — so the refusal is a requirement to say what was seen rather than
    /// a gap in the model.
    ///
    /// The fourth of those was the last hole, and it is worth recording that it
    /// was one: an artifact present at the committed destination whose digest
    /// *contradicts* the declaration used to be refused by every variant —
    /// `filesystem_effect` with `effect_hash_unproven`,
    /// `destination_present_unverified` because a digest was declared, and
    /// `destination_absent` because the file is demonstrably there — and the row
    /// stayed parked forever, holding its destination, with its operation
    /// unresolvable beside it. It now adjudicates to `failed_hash_mismatch`,
    /// whose literal meaning is what was proven. `effect_hash_unproven` is
    /// unchanged and still fires on every contradicting hash offered as a
    /// `filesystem_effect`: what closed the hole is a reading that says what it
    /// saw, not a relaxation of the one that says the bytes matched.
    ///
    /// An error rather than a `ResolveOutcome` variant, which is where it
    /// belongs: `interpret` in `cmd_request.zig` switches exhaustively on that
    /// union. `UnknownOperationKind` above is refused the same way for the same
    /// reason, and both are now classified by `cmd_request.semanticRefusal` so
    /// they are no longer reported as `RECEIPT_PERSIST_FAILED`.
    PublishAdjudicationUndetermined,
    OutOfMemory,
};

/// Rolls back a transaction on a path that is about to return a *business*
/// outcome rather than an error.
///
/// The failure is propagated instead of swallowed: if the rollback itself
/// fails the connection's transaction state is unknown, and handing back a
/// confident "already settled" while sitting on an open transaction would be
/// exactly the kind of quiet lie the ledger exists to prevent. (An `errdefer`
/// rollback is different — that path is already failing, so a secondary
/// cleanup failure has nothing to corrupt.)
fn rollback(store: *Store) Db.Error!void {
    return store.db.exec("ROLLBACK");
}

fn optBool(v: ?bool) ?i64 {
    return if (v) |b| @as(i64, if (b) 1 else 0) else null;
}

/// Appends one event, assigning the next sequence number. Caller must hold a
/// write transaction when ordering matters relative to other writes.
fn insert(store: *Store, event: Event, is_terminal: bool, seq: i64) Db.Error!i64 {
    var stmt = try store.db.prepare(
        \\INSERT INTO operation_events (
        \\  request_id, seq, schema_version, kind, phase, status, is_terminal,
        \\  connected, remote_started, remote_pid, remote_pgid, remote_start_token,
        \\  started_at, finished_at, duration_ms, exit_code, term_signal, timed_out,
        \\  transport_error, error_code, last_observed, cancel_method,
        \\  stdin_bytes, stdin_sha256,
        \\  stdout_bytes, stdout_sha256, stdout_truncated, stdout_digest,
        \\  stderr_bytes, stderr_sha256, stderr_truncated, stderr_digest,
        \\  observed_at, source, correlation_id, detail_json
        \\) VALUES (
        \\  ?1, ?2, ?3, ?4, ?5, ?6, ?7,
        \\  ?8, ?9, ?10, ?11, ?12,
        \\  ?13, ?14, ?15, ?16, ?17, ?18,
        \\  ?19, ?20, ?21, ?22,
        \\  ?23, ?24,
        \\  ?25, ?26, ?27, ?28,
        \\  ?29, ?30, ?31, ?32,
        \\  ?33, ?34, ?35, ?36
        \\)
    );
    defer stmt.deinit();
    try stmt.bindText(1, event.request_id);
    try stmt.bindInt(2, seq);
    try stmt.bindInt(3, schema_version);
    try stmt.bindText(4, @tagName(event.kind));
    try stmt.bindOptText(5, event.phase);
    try stmt.bindOptText(6, if (event.status) |s| s.text() else null);
    try stmt.bindInt(7, if (is_terminal) 1 else 0);
    try stmt.bindOptInt(8, optBool(event.connected));
    try stmt.bindOptInt(9, optBool(event.remote_started));
    try stmt.bindOptInt(10, event.remote_pid);
    try stmt.bindOptInt(11, event.remote_pgid);
    try stmt.bindOptText(12, event.remote_start_token);
    try stmt.bindOptInt(13, event.started_at);
    try stmt.bindOptInt(14, event.finished_at);
    try stmt.bindOptInt(15, event.duration_ms);
    try stmt.bindOptInt(16, event.exit_code);
    try stmt.bindOptInt(17, event.term_signal);
    try stmt.bindOptInt(18, optBool(event.timed_out));
    try stmt.bindOptText(19, event.transport_error);
    try stmt.bindOptText(20, event.error_code);
    try stmt.bindOptText(21, event.last_observed);
    try stmt.bindOptText(22, event.cancel_method);
    try stmt.bindOptInt(23, event.stdin.bytes);
    try stmt.bindOptText(24, event.stdin.sha256);
    try stmt.bindOptInt(25, event.stdout.bytes);
    try stmt.bindOptText(26, event.stdout.sha256);
    try stmt.bindOptInt(27, optBool(event.stdout.truncated));
    try stmt.bindOptText(28, event.stdout.digest);
    try stmt.bindOptInt(29, event.stderr.bytes);
    try stmt.bindOptText(30, event.stderr.sha256);
    try stmt.bindOptInt(31, optBool(event.stderr.truncated));
    try stmt.bindOptText(32, event.stderr.digest);
    try stmt.bindInt(33, event.observed_at);
    try stmt.bindText(34, @tagName(event.source));
    try stmt.bindOptText(35, event.correlation_id);
    try stmt.bindOptText(36, event.detail_json);
    _ = try stmt.step();
    return store.db.lastInsertRowId();
}

pub fn nextSeqLocked(store: *Store, request_id: []const u8) Db.Error!i64 {
    try store.db.requireTransaction();
    var stmt = try store.db.prepare(
        "SELECT IFNULL(MAX(seq), 0) + 1 FROM operation_events WHERE request_id = ?1",
    );
    defer stmt.deinit();
    try stmt.bindText(1, request_id);
    if (!try stmt.step()) return 1;
    return stmt.columnInt(0);
}

/// Event kinds a plain observation may carry.
///
/// `terminal` and `reconcile` are deliberately absent: they are the two
/// kinds that assert something authoritative about how an operation ended,
/// and each has exactly one writer (`settle` and `resolve`). Letting generic
/// `append` mint them would leave an audit trail where a forged entry is
/// indistinguishable from the real one.
pub const ObservationKind = enum {
    submit,
    connect,
    remote_start,
    progress,
    output,
    checkpoint,
    cleanup,
    audit,
    /// Lease acquire/release/takeover, for the coordination audit chain.
    lease,

    pub fn toKind(k: ObservationKind) Kind {
        return switch (k) {
            .submit => .submit,
            .connect => .connect,
            .remote_start => .remote_start,
            .progress => .progress,
            .output => .output,
            .checkpoint => .checkpoint,
            .cleanup => .cleanup,
            .audit => .audit,
            .lease => .lease,
        };
    }
};

/// A non-authoritative observation. Cannot describe an ending: `status` is
/// restricted to live states, so an appended row can never look like a
/// verdict.
pub const Observation = struct {
    request_id: []const u8,
    kind: ObservationKind,
    observed_at: i64,
    source: Source = .live,

    phase: ?[]const u8 = null,
    status: ?op_state.LiveStatus = null,

    connected: ?bool = null,
    remote_started: ?bool = null,
    remote_pid: ?i64 = null,
    remote_pgid: ?i64 = null,
    remote_start_token: ?[]const u8 = null,

    started_at: ?i64 = null,
    duration_ms: ?i64 = null,

    stdin: StreamEvidence = .{},
    stdout: StreamEvidence = .{},
    stderr: StreamEvidence = .{},

    correlation_id: ?[]const u8 = null,
    detail_json: ?[]const u8 = null,

    fn toEvent(o: Observation) Event {
        return .{
            .request_id = o.request_id,
            .kind = o.kind.toKind(),
            .observed_at = o.observed_at,
            .source = o.source,
            .phase = o.phase,
            .status = if (o.status) |s| s.toStatus() else null,
            .connected = o.connected,
            .remote_started = o.remote_started,
            .remote_pid = o.remote_pid,
            .remote_pgid = o.remote_pgid,
            .remote_start_token = o.remote_start_token,
            .started_at = o.started_at,
            .duration_ms = o.duration_ms,
            .stdin = o.stdin,
            .stdout = o.stdout,
            .stderr = o.stderr,
            .correlation_id = o.correlation_id,
            .detail_json = o.detail_json,
        };
    }
};

/// Appends an observation from inside a transaction the caller already holds.
///
/// Same restrictions as `append`; exists so a caller can make an event and
/// another write atomic (an override audit must land with the operation it
/// justifies, or not at all).
pub fn insertLocked(store: *Store, observation: Observation, seq: i64) Error!i64 {
    try store.db.requireTransaction();
    if (observation.source == .reconcile) return error.ReconcileRequiresResolve;
    return insert(store, observation.toEvent(), false, seq);
}

/// Appends a non-authoritative observation.
///
/// The parameter type cannot express a terminal or a reconcile, so those two
/// kinds have exactly one writer each. Relying on `std.debug.assert` here
/// would have been worse than useless: it vanishes in ReleaseFast, and a
/// terminal written this way would bypass both the transition check and the
/// `operations.status` update.
pub fn append(store: *Store, observation: Observation) Error!i64 {
    // `.reconcile` sources belong to `resolve`; a live observation claiming
    // to be one would make a forged resolution indistinguishable from a real
    // one in the trail.
    if (observation.source == .reconcile) return error.ReconcileRequiresResolve;
    try store.db.exec("BEGIN IMMEDIATE");
    errdefer store.db.exec("ROLLBACK") catch {};
    const seq = try nextSeqLocked(store, observation.request_id);
    const id = try insert(store, observation.toEvent(), false, seq);
    try store.db.exec("COMMIT");
    return id;
}

/// A recorded terminal, as read back from the ledger.
pub const TerminalRecord = struct {
    status: op_state.Status,
    observed_at: i64,
    seq: i64,
};

pub const SettleOutcome = union(enum) {
    /// This call recorded the terminal.
    recorded: TerminalRecord,
    /// A peer already settled it. Carries the winner's terminal so the
    /// caller reconciles against it rather than overwriting.
    already_settled: TerminalRecord,
};

/// What the operation's state tells us about the connection, as a three-state
/// observation.
///
/// `connecting` covers both dialing and authenticating, so it proves nothing:
/// an authentication failure would be reported with `connected = true` if we
/// derived it from the state alone. Unknown is recorded as unknown; the
/// transport layer can override with what it actually saw.
fn connectedAt(from: op_state.Status) ?bool {
    return switch (from) {
        .created => false, // nothing was dialed
        .connecting => null, // dialing or authenticating: not established
        .submitted, .remote_started => true, // work was handed over
        else => null,
    };
}

/// Builds the terminal event from evidence plus the state we were actually
/// in. Every field the evidence implies is set here, so a caller cannot
/// supply a contradictory combination, and `connected`/`remote_started`
/// describe what really happened rather than what the variant assumes.
fn terminalEvent(
    request_id: []const u8,
    from: op_state.Status,
    terminal: op_state.Terminal,
    extra: TerminalExtra,
    now: i64,
) Error!Event {
    // The transport layer may know more than the state does (it can tell a
    // refused TCP connect from a rejected key), but it may not contradict
    // work that was demonstrably handed over.
    const derived = connectedAt(from);
    if (extra.connected) |observed| {
        if (derived == true and observed == false) return error.ContradictoryEvidence;
    }
    const connected = extra.connected orelse derived;

    // The result-record annotation is a *store-derived* field on the receipt
    // document, the way `probeIdentity` and `declaredSha256` are on a
    // resolution's. It goes in `detail_json` rather than in a column of its own
    // because the document is versioned precisely so a new fact does not need
    // one, and because what it records is an observation about a settlement
    // rather than a property of the operation.
    //
    // A caller that supplied its own `detail_json` is refused rather than
    // merged or overwritten. No caller does today — every producer in the tree
    // writes `detail_json` on a `checkpoint` or `audit` event, never through
    // `TerminalExtra` — so this refuses a combination nothing constructs, and
    // refuses it because the alternatives are worse: silently dropping either
    // document loses a fact, and nesting one opaque string inside another would
    // put a document whose shape this module does not control inside one whose
    // shape it promises.
    const detail_json = if (extra.result_record) |record| blk: {
        if (extra.detail_json != null) return error.ConflictingTerminalDetail;
        var writer: std.Io.Writer.Allocating = .init(record.arena);
        std.json.Stringify.value(.{
            .schemaVersion = schema_version,
            .resultRecord = .{
                .reading = record.reading.code(),
                // Written as null rather than omitted for every reading but
                // `foreign`, for the reason `toJson` writes its corroboration
                // fields out as null: a reader must never have to decide
                // whether a missing key means "not that reading" or "written
                // before this was recorded".
                .claimedRequestId = switch (record.reading) {
                    .foreign => |claimed| claimed,
                    else => null,
                },
            },
        }, .{}, &writer.writer) catch return error.OutOfMemory;
        break :blk try writer.toOwnedSlice();
    } else extra.detail_json;

    var event: Event = .{
        .request_id = request_id,
        .kind = .terminal,
        .observed_at = now,
        .source = extra.source,
        .status = terminal.status(),
        .phase = extra.phase,
        .started_at = extra.started_at,
        // Never `orelse now`. `finished_at` answers "when did the remote work
        // end", and the only honest answer to that is one the remote gave us:
        // a sidecar's timestamp, a supervisor's report, a verified absence.
        // `now` answers "when did we look", which is `observed_at`, two lines
        // up and always present. Substituting one for the other made every
        // terminal receipt carry a finish time, most of them invented, and
        // buried the difference between a job that ended at 14:02 and one we
        // happened to notice at 14:02 after the connection came back.
        //
        // Null is the correct value for an outcome whose timing was never
        // established, and it is what the CLI already reports.
        .finished_at = extra.finished_at,
        .duration_ms = extra.duration_ms,
        .remote_pid = extra.remote_pid,
        .remote_pgid = extra.remote_pgid,
        .remote_start_token = extra.remote_start_token,
        .stdin = extra.stdin,
        .stdout = extra.stdout,
        .stderr = extra.stderr,
        .correlation_id = extra.correlation_id,
        .detail_json = detail_json,
        .error_code = terminal.errorCode(),
        .last_observed = from.text(),
        .connected = connected,
        .remote_started = from == .remote_started,
    };

    switch (terminal) {
        .exited => |e| {
            event.exit_code = e.exit_code;
            event.term_signal = if (e.term_signal) |s| @as(i64, s) else null;
            event.timed_out = false;
        },
        .never_submitted => |n| {
            // The claim is "the caller's command did not run", so any remote
            // process detail would contradict it. (Pre-submission setup may
            // still have reached the host; that is not a remote process.)
            if (extra.remote_pid != null or extra.remote_pgid != null or extra.remote_start_token != null)
                return error.ContradictoryEvidence;
            event.transport_error = n.transport_error;
            event.remote_started = false;
            event.timed_out = false;
        },
        .remote_deadline => |d| {
            event.timed_out = true;
            event.duration_ms = extra.duration_ms orelse d.after_ms;
        },
        .local_abandon => |a| {
            event.cancel_method = a.reason;
            event.remote_started = false;
            event.timed_out = false;
        },
        .remote_cancel_confirmed => |c| {
            event.cancel_method = c.verification_method;
            // Pid and token move together, from one source or the other, never
            // one from each. They used to be filled by two independent
            // `orelse`s, so a caller supplying only `extra.remote_pid` produced
            // a row carrying that pid beside the *evidence's* token — a pair
            // that never existed on any host, and one `recordedProcessLocked`
            // would hand to a later probe as a `pid_and_start_token` identity.
            // The effect runs both ways: the real process is refused because
            // its token does not match, and a probe quoting the fabricated pair
            // is admitted at the strongest binding grade there is.
            //
            // `remote_pid` is what decides, because the token is a property of
            // a pid and means nothing apart from one. A caller that wants to
            // correct the identity supplies both halves of the correction.
            if (extra.remote_pid) |pid| {
                event.remote_pid = pid;
                event.remote_start_token = extra.remote_start_token;
            } else {
                event.remote_pid = c.pid;
                event.remote_start_token = c.start_token;
            }
            event.finished_at = c.absence_verified_at;
            event.timed_out = false;
        },
        .indeterminate => |i| {
            event.transport_error = i.reason;
            event.timed_out = null;
        },
        .input_accepted => |a| {
            // What the terminal took, written from the evidence rather than
            // from `extra`. A caller supplying its own reading of the same
            // stream would leave the receipt holding two answers to the one
            // question this terminal exists to answer, so it is refused the
            // way `never_submitted` refuses a remote process.
            if (extra.stdin.bytes != null or extra.stdin.sha256 != null or
                extra.stdin.digest != null or extra.stdin.truncated)
                return error.ContradictoryEvidence;
            event.stdin = .{ .bytes = a.bytes, .sha256 = a.sha256 };
            // No exit code, and none may be inferred from the absence: this
            // operation delivered bytes, and nothing here judged a command.
            // `timed_out = false` because no deadline was involved either.
            event.timed_out = false;
        },
        .input_refused => |r| {
            // The claim is that the shell was never touched, so no stream
            // evidence may say bytes arrived and no remote process may be
            // named — the same contradiction `never_submitted` refuses, one
            // stage later.
            if (extra.stdin.bytes != null or extra.stdin.sha256 != null or
                extra.stdin.digest != null or extra.stdin.truncated)
                return error.ContradictoryEvidence;
            if (extra.remote_pid != null or extra.remote_pgid != null or extra.remote_start_token != null)
                return error.ContradictoryEvidence;
            // This column is the table's "what went wrong, in words" field —
            // `never_submitted` and `indeterminate` both use it for reasons
            // that are not always transport failures either. The machine-
            // readable half is `error_code`, filled from `terminal.errorCode()`
            // above.
            event.transport_error = r.reason;
            event.remote_started = false;
            event.timed_out = false;
        },
    }
    return event;
}

/// Settles an operation: validates the evidence against the state we were in,
/// writes the single terminal event and moves `operations.status`, all in one
/// transaction.
///
/// Five things make this the only way an operation can end:
///
/// * `terminal` is an evidence variant, so `failed` needs either a real
///   remote exit status or proof the command was never handed over. A
///   transport error after submission can only produce `indeterminate`.
/// * `canSettle` checks the evidence against the *source* state, not just the
///   target status. Several variants map onto `failed`, so a status-only
///   check would accept "submitted, and also never submitted".
/// * `terminalDescribesKind` checks it against the *kind of work*, which no
///   amount of looking at the status can tell you: `exited(0)` from
///   `submitted` is a perfectly legal settlement and a lie about an operation
///   that ran no command. The row's `kind` is read by the same statement as
///   its `status`, so the pair describes one moment.
/// * The check happens under the write lock, so a terminal receipt can never
///   disagree with the status it implies.
/// * The partial unique index means a peer racing us loses with
///   `error.Constraint` and is handed the winner's terminal instead of
///   overwriting it.
pub fn settle(
    store: *Store,
    request_id: []const u8,
    terminal: op_state.Terminal,
    extra: TerminalExtra,
    now: i64,
) Error!SettleOutcome {
    try store.db.exec("BEGIN IMMEDIATE");
    errdefer store.db.exec("ROLLBACK") catch {};
    const outcome = try settleLocked(store, request_id, terminal, extra, now);
    try store.db.exec("COMMIT");
    return outcome;
}

/// `settle`, for a caller that already holds the write transaction.
///
/// Split out so a settlement can be composed with the other writes that have
/// to land with it. The job cache is the case that forced it: seven callers
/// settled the ledger and then updated the `jobs` row in a second transaction,
/// and between the two the ledger said the attempt was over while the row that
/// gates the next `run --name X` still said `running`.
///
/// The three non-writing exits — already settled, illegal transition, evidence
/// that does not fit — no longer roll back, because the transaction is not
/// theirs to end. None of them has written anything by the time it is reached,
/// so a caller that goes on to COMMIT commits nothing, and a caller that
/// propagates the error rolls back through its own `errdefer`. Same for the
/// `Constraint` path: sqlite rolls back the failed *statement*, and the read
/// that follows it is a read.
///
/// Caller must hold the transaction. A settlement whose checks ran outside the
/// lock that carries them is not the "one way an operation can end" the doc
/// above claims it is — whatever `canSettle` looked at can change before the
/// insert lands.
pub fn settleLocked(
    store: *Store,
    request_id: []const u8,
    terminal: op_state.Terminal,
    extra: TerminalExtra,
    now: i64,
) Error!SettleOutcome {
    try store.db.requireTransaction();
    const status = terminal.status();

    const current = try currentStateLocked(store, request_id);

    // Asked first — before the already-settled branch, before both transition
    // checks — because it is the only one of the four that is not a question
    // about this moment. Whether a terminal can describe work of this kind is a
    // property of the pair alone, so answering it after the race would make a
    // programming error report itself only to the caller that *lost*, which is
    // the one way to have a defect nobody ever sees. Nothing has been written by
    // here, so refusing costs the transaction nothing.
    if (!terminalDescribesKind(terminal, current.kind)) {
        return error.TerminalDoesNotDescribeKind;
    }

    // Already settled by a peer? Hand them the winner rather than reporting
    // a bogus programming error.
    if (current.status.isTerminal()) {
        if (try terminalOfLocked(store, request_id)) |winner| {
            return .{ .already_settled = winner };
        }
        return error.IllegalTransition;
    }
    if (!op_state.canTransition(current.status, status)) {
        return error.IllegalTransition;
    }
    if (!op_state.canSettle(current.status, terminal)) {
        return error.EvidenceDoesNotFit;
    }

    const event = try terminalEvent(request_id, current.status, terminal, extra, now);
    const seq = try nextSeqLocked(store, request_id);
    _ = insert(store, event, true, seq) catch |err| switch (err) {
        // The partial unique index fired: a peer settled first.
        error.Constraint => {
            const winner = try terminalOfLocked(store, request_id);
            return .{ .already_settled = winner orelse return error.Sqlite };
        },
        else => return err,
    };

    var upd = try store.db.prepare(
        "UPDATE operations SET status = ?1, updated_at = ?2 WHERE request_id = ?3",
    );
    defer upd.deinit();
    try upd.bindText(1, status.text());
    try upd.bindInt(2, now);
    try upd.bindText(3, request_id);
    _ = try upd.step();

    return .{ .recorded = .{ .status = status, .observed_at = now, .seq = seq } };
}

/// What actually established the truth about an unsettled attempt.
///
/// Typed rather than a free-text note because a resolution lifts the
/// same-scope mutation barrier. "Someone typed a sentence" and "the remote
/// supervisor reported the exit status" must not be indistinguishable in the
/// audit trail — and an operator override has to be legible *as* an
/// override, never dressed up as a mechanical proof.
pub const ResolutionEvidence = union(enum) {
    /// The remote supervisor reported the final status. It carries the
    /// status it reported, so the claim and the conclusion are one fact
    /// rather than two independently-chosen ones.
    supervisor_report: struct {
        reported: op_state.ResolvedStatus,
        detail: []const u8,
    },
    /// A pid + start-token probe established whether the process survived.
    /// On its own this can only prove that something is *gone*, which is
    /// cancellation — never how it ended, and never that it succeeded.
    process_probe: struct {
        pid: i64,
        start_token: ?[]const u8 = null,
        alive: bool,
    },
    /// A durable job sentinel carried the exit code. The exit code is
    /// required: a sentinel without one proves the job ended, not how.
    job_sentinel: struct {
        sentinel: []const u8,
        exit_code: i64,
    },
    /// The job's result sidecar — the document the remote wrapper wrote to
    /// `~/.terminus/results/<request-id>.json` when the command returned.
    ///
    /// Kept distinct from `job_sentinel` even though both carry an exit code,
    /// because they are not the same claim. A sentinel is a line found by
    /// scanning a window of an append-only log that anything on the host can
    /// write to; a sidecar is a document at an address derived from this
    /// operation's own id, holding one fact. Collapsing them would make a
    /// receipt unable to say which one it had.
    job_result: struct {
        /// The request id the document itself names. Required to equal the
        /// operation being resolved — that equality is what makes this
        /// evidence *about* the operation rather than merely handed to it,
        /// and `resolve` refuses the pair when it does not hold.
        ///
        /// Must be filled from the parsed document
        /// (`Tmux.JobResult.claimed_request_id`), never from the operation
        /// being reconciled: sourcing both sides of the check from the same
        /// place makes it unfalsifiable.
        request_id: []const u8,
        exit_code: i64,
        /// Remote unix seconds, or null when the host could not report a
        /// clock. Optional rather than 0-means-absent so the ledger records
        /// "the remote could not say" as absence instead of as the epoch —
        /// the same reason `Tmux.JobResult.finished_at` is optional. Never
        /// substituted with a local clock.
        finished_at: ?i64 = null,
    },
    /// A verified side effect on the filesystem (published artifact hash).
    /// Only meaningful for transfers: a hash matching proves the bytes
    /// landed, which says nothing about an arbitrary command.
    ///
    /// All three fields are compared in `resolve` against what the transfer
    /// committed to *before* it submitted anything. Without every one of them
    /// this is the weakest evidence in the union pretending to be the
    /// strongest:
    ///
    /// * no hash, and "a file exists at this path" settles a transfer whose
    ///   bytes nobody checked — a stale file from an earlier run will do it;
    /// * no path, and the same content found *anywhere* settles it, so a copy
    ///   of the source still sitting in /tmp proves the destination was
    ///   written;
    /// * no side, and reading the local copy proves the remote one landed.
    filesystem_effect: struct {
        /// Which machine the file was read on. A push publishes on the host;
        /// a pull and a fetch publish here.
        side: transfers.Side,
        path: []const u8,
        sha256: []const u8,
    },
    /// The destination was inspected and does not carry the artifact.
    ///
    /// The negative counterpart of `filesystem_effect`, and the only evidence
    /// that can adjudicate a parked publish to `failed_publish`. Without it
    /// `publishAdjudication` mapped every variant but one to null, so a
    /// transfer whose artifact is *not* at the destination could never be
    /// judged at all: it stayed `indeterminate_publish` and went on holding its
    /// path against every later transfer. An escape hatch that only opens for
    /// one of the two possible answers is not an escape hatch.
    ///
    /// **What it proves and what it does not.** It records that at the moment
    /// of this reconcile, the destination this transfer committed to did not
    /// carry the artifact. It is *not* proof that the rename never ran —
    /// somebody could have removed the file afterwards, and nothing here can
    /// tell those two apart. So this is an observation with the reading
    /// attached, not a history, and what it is allowed to conclude is bounded
    /// accordingly: see `supports` for the operation's verdict and
    /// `publishAdjudication` for the checkpoint's.
    ///
    /// `side` and `path` are compared in `resolve` against the destination the
    /// transfer committed to at `create` — before it submitted anything — for
    /// the reason `filesystem_effect`'s three fields are compared: a reading
    /// taken somewhere else says nothing about this transfer, and without the
    /// comparison a reconciler could nominate whichever empty path it liked and
    /// call the transfer failed. There is no digest to compare because there is
    /// nothing to hash, which is also why the comparison is against the
    /// committed destination rather than against a declared digest — a transfer
    /// that never declared one is still judgeable this way.
    destination_absent: struct {
        side: transfers.Side,
        path: []const u8,
        /// How absence was established, e.g. `stat => ENOENT`.
        ///
        /// Required, for the reason `op_state.Terminal.remote_cancel_confirmed`
        /// requires one: "it is not there" is a conclusion, and a receipt
        /// carrying the conclusion with no reading behind it cannot be argued
        /// with afterwards by anyone who doubts it. `resolve` refuses an empty
        /// one — "required" said only by the type is a field a caller satisfies
        /// with `""`, which is the conclusion without the reading again.
        verification_method: []const u8,
    },
    /// The destination carries an artifact, and this transfer committed to no
    /// digest that could say whether it is the right one.
    ///
    /// The third reading of a destination, and the one that closes the last
    /// crash-shaped hole in `indeterminate_publish`. `completed_unverified`
    /// exists for a transfer where "no trustworthy hash or object validator was
    /// available" — so it declares none and records none, and both halves are
    /// conjuncts of the driver's own route out of `publishing` rather than
    /// prose here (see `transfers.evidenceClause`). Kill that driver mid-rename
    /// and the row normalises to `indeterminate_publish`, where every exit was
    /// closed: `filesystem_effect` is refused because there is no advance
    /// commitment to compare a hash against, `destination_absent` would be a lie
    /// because the artifact *is* there, an override cannot adjudicate, and the
    /// graph's `indeterminate_publish → completed_unverified` edge had no
    /// evidence that could reach it. The row held its destination against every
    /// later transfer, permanently, with no route but hand-editing sqlite.
    ///
    /// **Why it is not `filesystem_effect` with the digest check relaxed.**
    /// Relaxing that check would let any presence reading settle any transfer
    /// `completed`, which is the "weakest evidence in the union pretending to be
    /// the strongest" this whole comparison exists to stop. A separate variant
    /// keeps `filesystem_effect` exactly as strong as it is and makes the
    /// receipt say, on its face, that nothing was checked — an auditor reading
    /// the trail can tell a proven delivery from an unproven one without going
    /// to look at whether a commitment existed.
    ///
    /// **What `resolve` demands of it**, because on its own it is weak:
    ///
    ///  * side and path must match the destination the transfer committed to at
    ///    `create`, as for `destination_absent`;
    ///  * the checkpoint's publish must still be an open question. Anywhere else
    ///    this is a file at a path and says nothing about what this operation
    ///    did;
    ///  * the transfer must have declared **no** digest. If it declared one,
    ///    there is a stronger reading available for the same act of looking —
    ///    hash it and offer `filesystem_effect` — and admitting this would be a
    ///    way of skipping a check that was there to be made.
    ///
    /// What is left is the same claim the driver itself would have recorded had
    /// it survived: something is at the destination, and this transfer never had
    /// anything to check it against. A stale file from an earlier run satisfies
    /// it, and so would it have satisfied the driver.
    destination_present_unverified: struct {
        side: transfers.Side,
        path: []const u8,
        /// How presence was established, e.g. `stat => 4096 bytes`. Required
        /// and non-empty, for the reason `destination_absent`'s is.
        verification_method: []const u8,
    },
    /// The destination carries an artifact, and it is not the one this transfer
    /// promised: it hashes to something other than the digest declared before a
    /// byte moved.
    ///
    /// The fourth and last reading of a destination, and the only one whose
    /// verdict is `failed` on a *present* artifact. Until it existed this was the
    /// one `(crash point, state)` pair with no route at all: `filesystem_effect`
    /// refuses a hash that does not match the declaration (`effect_hash_unproven`
    /// — and it still does, everywhere, see below), `destination_present_unverified`
    /// refuses a transfer that declared a digest, `destination_absent` would be a
    /// lie about a file that is demonstrably there, and an override cannot
    /// adjudicate. A parked publish in that position held its destination against
    /// every later transfer for the life of the database, with its operation
    /// unresolvable alongside it.
    ///
    /// **Why the verdict is a failure and why that is safe.** The checkpoint
    /// lands on `failed_hash_mismatch`, whose literal meaning — the digest did
    /// not match — is precisely what was proven, and the operation resolves
    /// `failed`, because the artifact this transfer exists to deliver is not at
    /// the destination; something else is. That reads oddly next to a reading
    /// that says the file is *there*, so the reason it is not a hole is worth
    /// stating: a failure keeps its hold on the destination
    /// (`transfers.State.holdsDestination` covers every `failed_*`), so the wrong
    /// artifact is not silently clobbered by the next transfer aimed at that
    /// path — the rival `create` is refused `DestinationHeld`, and an operator
    /// releases it with `supersede` once they have decided what to do about the
    /// bytes that are actually there.
    ///
    /// **Why it is not `filesystem_effect` with the comparison inverted.** The
    /// two make opposite claims and `supports` has to be able to tell them apart
    /// before it has read anything: `filesystem_effect` proves `completed` and
    /// nothing else, and widening it to prove `failed` as well would let a
    /// *matching* digest justify `failed` on any path that never reaches the
    /// comparison. A separate variant keeps `filesystem_effect` exactly as strong
    /// as it is — `effect_hash_unproven` fires on a contradicting hash today in
    /// exactly the circumstances it fired in before this variant existed — and
    /// makes the receipt say on its face which of the two things was read.
    ///
    /// **What `resolve` demands of it**, all four things, because on its own an
    /// unmatched digest is just a number:
    ///
    ///  * a verification method, as for the other two readings;
    ///  * side and path matching the destination committed to at `create`;
    ///  * the checkpoint's publish still an open question. Anywhere else this is
    ///    a statement about a path and a hash, and re-deciding a settled publish
    ///    from one is what `publish_not_in_question` exists to refuse;
    ///  * a digest declared in advance that this reading actually *contradicts*.
    ///    Neither half is redundant: with nothing declared there is nothing to
    ///    contradict and the honest reading is `destination_present_unverified`,
    ///    and with a digest the reading *agrees* with, the honest reading is
    ///    `filesystem_effect` — admitting this one there would turn a delivered
    ///    artifact into a failure on the caller's choice of variant.
    destination_present_contradicting: struct {
        side: transfers.Side,
        path: []const u8,
        /// What the artifact at the destination actually hashes to. Compared
        /// against the transfer's advance commitment in `resolve`, and required
        /// to differ from it — see `contradiction_not_established`.
        sha256: []const u8,
        /// How the artifact was read and hashed, e.g.
        /// `sha256sum => 0000ffff`. Required and non-empty, for the reason
        /// `destination_absent`'s is.
        verification_method: []const u8,
    },
    /// A human decided, without mechanical proof.
    operator_override: struct {
        reason: []const u8,
        by: []const u8,
    },

    pub fn kindName(e: ResolutionEvidence) []const u8 {
        return @tagName(e);
    }

    /// Whether this rests on a reading rather than on somebody's say-so.
    ///
    /// Callers that need to distinguish "proved" from "asserted" ask this
    /// rather than parse the text, and `resolve` stamps the reconcile event
    /// `OPERATOR_OVERRIDE` when it is false.
    ///
    /// Exhaustive rather than `e != .operator_override`, so a new variant has to
    /// be classified out loud instead of inheriting "mechanical" from a
    /// negation nobody re-read. `destination_absent` is the one that makes that
    /// worth doing, because it is the first variant where the honest answer is
    /// arguable. It is mechanical: something looked at a path and reported what
    /// it found, the method is on the receipt, and another reader at that
    /// moment would have read the same thing. Its weakness is temporal — an
    /// absence read now is not an absence then — and that is a limit on what it
    /// may *conclude*, which is where it is enforced (`supports`,
    /// `publishAdjudication`). Demoting it to an assertion instead would file a
    /// reading alongside a human's opinion, and the trail would stop being able
    /// to tell those apart at all.
    pub fn isMechanical(e: ResolutionEvidence) bool {
        return switch (e) {
            .supervisor_report,
            .process_probe,
            .job_sentinel,
            .job_result,
            .filesystem_effect,
            .destination_absent,
            .destination_present_unverified,
            .destination_present_contradicting,
            => true,
            .operator_override => false,
        };
    }

    /// Whether this evidence actually entails `resolved`.
    ///
    /// Without this the two arguments of `resolve` are independent, so
    /// `failed` could be justified by a zero exit code, or — worse —
    /// `completed` by a probe showing the process still *running*, which
    /// would release the scope barrier on live work.
    pub fn supports(e: ResolutionEvidence, resolved: op_state.ResolvedStatus) bool {
        return switch (e) {
            .supervisor_report => |s| s.reported == resolved,
            .job_sentinel => |s| switch (resolved) {
                .completed => s.exit_code == 0,
                .failed => s.exit_code != 0,
                // A sentinel records how the command ended, which cannot
                // establish a timeout or a cancellation.
                .timed_out, .cancelled => false,
            },
            // Same reading rules as a sentinel: an exit status says how the
            // command ended, and nothing about a deadline or a cancellation.
            .job_result => |r| switch (resolved) {
                .completed => r.exit_code == 0,
                .failed => r.exit_code != 0,
                .timed_out, .cancelled => false,
            },
            // A live process proves nothing at all. A dead one proves only
            // that it is no longer running; pairing that with an outcome
            // needs the exit status, which this evidence does not carry.
            .process_probe => |p| !p.alive and resolved == .cancelled,
            .filesystem_effect => resolved == .completed,
            // The destination does not hold what this transfer promised, so the
            // transfer did not deliver it. Not `completed`, obviously; not
            // `timed_out`, which is a remote deadline this says nothing about;
            // not `cancelled`, which is a claim about a process rather than
            // about a file.
            //
            // The verdict is about the *effect*, and that is the whole of what
            // it claims: the artifact this operation exists to produce is not at
            // the destination, which is what was read. It stays true whether the
            // rename never ran or ran and was undone afterwards — telling those
            // apart would need a history nobody has, and `failed` does not
            // depend on which it was.
            .destination_absent => resolved == .failed,
            // Something is at the destination this transfer promised, and
            // nothing this transfer committed to can say whether it is the
            // right thing. `completed` is the verdict the driver itself would
            // have reached from the same position — bytes arrived, no digest
            // was ever available to check them — and it is the only one on
            // offer: `failed` is contradicted by the artifact being there,
            // `timed_out` is a claim about a deadline and `cancelled` one about
            // a process, and this reading is neither. The checkpoint records
            // the weakness that `ResolvedStatus` has no word for, in
            // `completed_unverified`.
            .destination_present_unverified => resolved == .completed,
            // Something is at the destination and it is provably not what this
            // transfer promised. `failed` is the only verdict the reading can
            // carry, and each of the other three is excluded by a different
            // thing: `completed` is contradicted by the digest, `timed_out` is a
            // claim about a deadline and `cancelled` one about a process, and a
            // hash of a file is neither.
            //
            // `completed` being excluded here rather than merely unlikely is the
            // whole reason this is a variant of its own: `filesystem_effect`
            // proves `completed` and nothing else, and had the contradicting
            // reading been folded into it, the union would have to admit one
            // variant proving two opposite outcomes with the comparison that
            // separates them living in `resolve` instead of here.
            .destination_present_contradicting => resolved == .failed,
            .operator_override => true,
        };
    }

    /// Kinds of operation this evidence can speak about.
    ///
    /// Evidence produced by one mechanism can only settle the operations that
    /// mechanism runs. Otherwise the strength of a record leaks across
    /// domains: a job wrapper's exit status would be allowed to close a
    /// transfer whose bytes nobody ever checked.
    ///
    /// Exhaustive in both directions, with no default arm anywhere, so adding
    /// an `operations.Kind` or a `ResolutionEvidence` variant is a compile
    /// error here until someone states what may settle what. The arm this
    /// replaced was `else => true`: every kind not named admitted every kind of
    /// evidence, and every kind added later inherited that — the widest
    /// possible permit, granted by omission, on the path that decides whether a
    /// resolution may lift the same-scope mutation barrier.
    ///
    /// Each cell answers "can evidence of this kind make a statement about work
    /// of this kind at all", not "could it be useful here". Where the answer is
    /// not clear the cell refuses and says why: a wrongly refused resolution is
    /// an operator inconvenience that names exactly what it refused, while a
    /// wrongly admitted one releases a safety barrier on a claim about
    /// something else.
    pub fn appliesToKind(e: ResolutionEvidence, kind: operations.Kind) bool {
        return switch (e) {
            // Refused for every kind, until something builds a producer that
            // binds a report to the attempt it is about.
            //
            // The variant is kept rather than deleted — the supervisor is
            // unbuilt work, not abandoned work — but nothing constructs one
            // today, and admitting it meanwhile grants the widest permit in the
            // union to the only mechanical variant with **no identity binding at
            // all**. Every other one has something tying the reading to this
            // operation, checked in `resolve`: `job_result` carries the request
            // id the document itself names, `process_probe` is matched against
            // the pid and start token the attempt recorded, `job_sentinel` is
            // matched against the sentinel the launch wrote down, and the four
            // readings of a destination are compared against the side, path and
            // digest the transfer committed to before it submitted. A
            // `supervisor_report` carries a status and a sentence. Any caller
            // holding any request id could hand one in and have it graded
            // mechanical (`isMechanical`), which is the grade that releases the
            // same-scope mutation barrier without an operator in the loop.
            //
            // **What a producer must supply for these cells to be reopened**,
            // written here because this is where a future author will come to
            // undo the refusal:
            //
            //  * a field on the variant naming what the report is *about*, in a
            //    form the report's own writer filled in and this binary can
            //    check against something it wrote down first. The three shapes
            //    that already work are `job_result`'s — the request id, read out
            //    of the document, compared against the operation being resolved
            //    — `process_probe`'s — a process identity, compared against
            //    the one the attempt recorded on its trail — and
            //    `job_sentinel`'s, a string compared against the one this binary
            //    chose at launch and stored in `job_attempts`. The wrapper in
            //    `supervisor.zig` already writes both a request id and a pid, so
            //    either is available; what is not acceptable is a field the
            //    caller fills from the operation it is resolving, which compares
            //    a value against itself and can never fire;
            //  * the check in `resolve`, next to the `job_result` and
            //    `process_probe` arms and before `supports`, refusing with
            //    `evidence_wrong_operation` (or `evidence_wrong_process`) rather
            //    than with a generic error;
            //  * then, and only then, a decision per cell here about which kinds
            //    that mechanism actually supervises — which is a narrower
            //    question than "which kinds run a remote process", and the
            //    reasons the old `exec, .job => true` cell gave for each group
            //    are kept below because they will still be the reasons.
            //
            // The old cell's reasoning, unchanged and still the starting point:
            // `exec` and `job` are one supervised remote command each, so what
            // the attempt did is what that command did and its supervisor's
            // report is a statement about the whole of it. A transfer's outcome
            // is whether the bytes are at the destination and hash to what was
            // promised in advance — a copier that wrote to the wrong path, or
            // whose rename never ran, still exits 0, and this variant would
            // carry that 0 straight to `completed` past the digest comparison
            // every other route to a transfer's verdict has to pass. Nothing in
            // this binary creates a `tunnel`, `plan_phase`, `audit` or `cleanup`
            // operation, so nothing supervises one either.
            //
            // Refusing everywhere costs nothing that is reachable: no command
            // constructs this variant, so no operator route disappears, and
            // `operator_override` remains admissible for every kind — nothing is
            // left with no way to be settled.
            .supervisor_report => switch (kind) {
                .exec,
                .job,
                .session_write,
                .transfer_push,
                .transfer_pull,
                .fetch,
                .tunnel,
                .plan_phase,
                .audit,
                .cleanup,
                => false,
            },
            // A pid and start-token reading of a process. `resolve` requires it
            // to be a reading of *this operation's own* recorded process, so
            // the kinds it may speak for are the ones a process identity is
            // recorded for.
            .process_probe => switch (kind) {
                // An `exec` records the pid and start token the shell reported
                // for the command it ran (`supervisor.Identity`, put on the
                // trail by `execution.remoteStarted`).
                .exec => true,
                // A `job` records neither of those things. `cmd_job` launches
                // into a tmux session and reports `Tmux.panePid`, so the identity
                // on a job's trail is the *pane's* pid with no start token — a
                // reading about one process, admitted to settle a different one.
                // `supervisor.zig` says outright what that is worth: "a command
                // that daemonized, called `disown`, or ran under `setsid`
                // outlives the pane". `cmd_job`'s own kill path honours that — it
                // writes `remote_cancel_confirmed` only when
                // `verified_cancellation` is satisfied, which shell mode never
                // satisfies — and while this cell was `true`, a probe arriving
                // here made the same claim with nothing asked of it: pane gone,
                // `cancelled`, scope released, child still running.
                //
                // It was left admissible once on the argument that the honest
                // rule is about the recorded *identity* rather than the kind, and
                // that narrowing the cell would encode today's job launcher into
                // the evidence contract. The argument is sound and the conclusion
                // was wrong: a job already has two evidence chains of its own
                // that are addressed to it — `job_sentinel` and `job_result` —
                // so refusing here removes no route, while admitting it keeps a
                // permit alive for a reading that is structurally about the
                // wrong process. If a launcher ever reports the command's own pid
                // and start token onto the job's trail, this cell is where that
                // becomes true again, and it should be reopened in the same
                // change that makes it true rather than held open in advance.
                .job => false,
                // A `session_write` records no process at all, and there is no
                // shape in which it could: `Tmux.sendKeys` runs one tmux
                // command and reports nothing about the pane, let alone about
                // whatever the shell went on to fork. So there is nothing for
                // a probe to be a reading *of* — `resolve` would find no
                // recorded identity and refuse with `evidence_wrong_process`
                // anyway, and this cell says why that is the permanent answer
                // rather than a gap somebody should fill by recording the
                // pane's pid. The pane's pid is not the input's process; that
                // mistake is the one the `.job` cell above was closed for.
                .session_write => false,
                // A transfer writes down a destination and a digest, not a
                // process. "It is no longer running" is equally true of a
                // transfer that finished and one that died mid-rename, and
                // `cancelled` — the only thing a dead process establishes —
                // would release the barrier on the second while its checkpoint
                // went on holding the path against everyone else.
                .transfer_push, .transfer_pull, .fetch => false,
                // As above: no such operation exists yet, so none of them
                // records a process a probe could be a reading of.
                .tunnel, .plan_phase, .audit, .cleanup => false,
            },
            // Both are exit statuses recorded by the job wrapper — the
            // sidecar it writes and the sentinel it echoes. Neither exists
            // for any other kind of operation, so one turning up against a
            // transfer or a fetch means the evidence was misrouted, not that
            // the operation is settled.
            //
            // A `session_write` is the case worth naming, because it is the
            // one kind that shares a mechanism with a job and still admits
            // neither: `cmd_job` types its launch line into a tmux session
            // exactly as `write` types the operator's, and the job's two
            // evidence chains come from the *wrapper* that line carries — a
            // sentinel echoed after the command, a sidecar written at an
            // address derived from the request id. A write carries no wrapper.
            // Nothing it types is obliged to echo anything, and an operator
            // who typed a wrapper of their own would be offering a document
            // this binary never asked any host to produce.
            .job_result, .job_sentinel => switch (kind) {
                .job => true,
                .exec,
                .session_write,
                .transfer_push,
                .transfer_pull,
                .fetch,
                .tunnel,
                .plan_phase,
                .audit,
                .cleanup,
                => false,
            },
            // A file read at a path and hashed. It can only mean anything for
            // work that said in advance which file would prove it — `resolve`
            // compares side, path and digest against that commitment, and no
            // other kind of operation makes one. A hash cannot say whether an
            // arbitrary command did what it was asked.
            .filesystem_effect => switch (kind) {
                .transfer_push, .transfer_pull, .fetch => true,
                .exec, .job, .session_write, .tunnel, .plan_phase, .audit, .cleanup => false,
            },
            // The same address, read and found empty. Only work that named a
            // destination in advance can be spoken about this way — `resolve`
            // compares side and path against that commitment — and only a
            // transfer names one. "Nothing is at /srv/app/out.bin" is not a
            // statement about what an arbitrary command did, however true it is.
            //
            // Its two positive twins are the same cell for the same reason: all
            // three are readings of an address, and only a transfer has one on
            // record. They travel together because a kind that can be told its
            // artifact is there must be tellable that it is not and that it is
            // the wrong one, or some of its outcomes have no evidence that can
            // express them at all — which is how the parked publish came to be
            // wedged in the first place.
            .destination_absent,
            .destination_present_unverified,
            .destination_present_contradicting,
            => switch (kind) {
                .transfer_push, .transfer_pull, .fetch => true,
                .exec, .job, .session_write, .tunnel, .plan_phase, .audit, .cleanup => false,
            },
            // A human's decision, and the only variant that is about the
            // *operation* rather than about some mechanism's output — so there
            // is no kind of work it cannot speak about. Admissible everywhere
            // on purpose: an attempt nothing mechanical can settle holds its
            // scope until somebody settles it, and a kind admitted no evidence
            // at all could never be settled by anyone. That is not hypothetical
            // any more — `supervisor_report` is now refused for every kind and
            // `process_probe` for every kind but `exec`, so for a `tunnel` or a
            // `plan_phase` this cell is the *only* admissible one. What keeps it
            // honest lives elsewhere — it is recorded as a decision
            // (`isMechanical`), and `publishAdjudication` refuses to let it
            // write an artifact fact nobody read.
            //
            // That refusal is also the limit of what this cell buys, and the
            // limit is real rather than theoretical: for a transfer parked in
            // `indeterminate_publish` an override is admitted here and then
            // fails the whole resolution with
            // `error.PublishAdjudicationUndetermined`, because the checkpoint
            // has to be judged in the same transaction and an override cannot
            // judge it. Such an operation is settleable by a reading of its
            // destination and by nothing else, and there is now one for each
            // answer a look can produce: `filesystem_effect` matching the digest
            // it declared, `destination_present_contradicting` when the artifact
            // is there and hashes to something else,
            // `destination_present_unverified` when it declared no digest at
            // all, or `destination_absent` at the path it committed to. All four
            // are available to the operator who checked by hand — that is the
            // same act with the reading attached — so the limit is a requirement
            // to say what was seen.
            //
            // `session_write` is the newest kind for which this is the *only*
            // admissible cell, and unlike a `tunnel` that is not because
            // nothing creates one — `terminus write` creates one every time it
            // runs. It is because a write's own terminal
            // (`op_state.Terminal.input_accepted`) settles it at the moment the
            // remote answers, so the only writes that reach a reconcile are the
            // ones whose answer was lost, and about *those* no mechanism on
            // this host or that one has anything to say. The bytes are either
            // in a pane or they are not; nothing recorded which.
            //
            // **What a future mechanical producer would have to bind itself
            // to**, written here for the reason `supervisor_report`'s refusal
            // is: an operator arriving to widen a cell should find the terms
            // rather than invent them. A write records exactly two things
            // about itself before it sends — the session it is aimed at
            // (`operations.alias`, and the scope key, which are the same
            // string) and the digest of the bytes it is about to type
            // (`operations.argv_sha256`). So evidence that could speak for a
            // `session_write` has to be a reading of *that pane* carrying
            // *that digest*, checked in `resolve` against those two columns
            // before `supports` runs, and refused with a named identity
            // outcome the way `evidence_wrong_sentinel` is. What would not do:
            // a reading of the pane alone — every write to a busy session
            // would match it, which is the "compares a value against itself"
            // shape — or a marker the *operator's own input* was asked to
            // echo, since nothing makes an operator type one and a write that
            // did not is exactly the write nobody can settle.
            .operator_override => switch (kind) {
                .exec,
                .job,
                .session_write,
                .transfer_push,
                .transfer_pull,
                .fetch,
                .tunnel,
                .plan_phase,
                .audit,
                .cleanup,
                => true,
            },
        };
    }

    /// Versioned JSON, matching the documented contract of `detail_json`.
    ///
    /// Free-text fields pass through the same redaction as the audit trail:
    /// `detail_json` promises already-redacted content, and a reconciler
    /// pasting a command line into `detail` must not be how a token reaches
    /// the ledger.
    ///
    /// Two of the fields are *corroboration*: facts only `resolve` can know,
    /// because the evidence carries what it read and what it had to match is in
    /// the store. Both are written out as null rather than omitted, so a reader
    /// never has to decide whether a missing key means "not that kind of
    /// evidence" or "written before this was recorded".
    ///
    ///  * `binding` — how strongly a `process_probe` was tied to this attempt.
    ///    See `ProbeBinding`.
    ///  * `declared_sha256` — the digest the transfer committed to before it
    ///    sent a byte, for the readings that are judged against one. It exists
    ///    for `destination_present_contradicting`: that receipt's whole content
    ///    is that two digests disagree, and one of them written down alone is
    ///    half a fact. It cannot come from the caller — the caller would be
    ///    echoing back a value it read out of this same database, which compares
    ///    a number with itself — so it is read here, off the checkpoint, in the
    ///    transaction that judges it.
    pub fn toJson(
        e: ResolutionEvidence,
        arena: std.mem.Allocator,
        binding: ?ProbeBinding,
        declared_sha256: ?[]const u8,
    ) std.mem.Allocator.Error![]u8 {
        const redacted: ResolutionEvidence = switch (e) {
            .supervisor_report => |s| .{ .supervisor_report = .{
                .reported = s.reported,
                .detail = try redact(arena, s.detail),
            } },
            .job_sentinel => |s| .{ .job_sentinel = .{
                .sentinel = try redact(arena, s.sentinel),
                .exit_code = s.exit_code,
            } },
            .filesystem_effect => |f| .{ .filesystem_effect = .{
                .side = f.side,
                .path = try redact(arena, f.path),
                .sha256 = f.sha256,
            } },
            .destination_absent => |a| .{ .destination_absent = .{
                .side = a.side,
                .path = try redact(arena, a.path),
                .verification_method = try redact(arena, a.verification_method),
            } },
            .destination_present_unverified => |p| .{ .destination_present_unverified = .{
                .side = p.side,
                .path = try redact(arena, p.path),
                .verification_method = try redact(arena, p.verification_method),
            } },
            .destination_present_contradicting => |c| .{ .destination_present_contradicting = .{
                .side = c.side,
                .path = try redact(arena, c.path),
                .sha256 = c.sha256,
                .verification_method = try redact(arena, c.verification_method),
            } },
            .operator_override => |o| .{ .operator_override = .{
                .reason = try redact(arena, o.reason),
                .by = try redact(arena, o.by),
            } },
            .process_probe => e, // numeric and opaque; nothing to redact
            .job_result => e, // a request id and numbers; nothing to redact
        };

        var writer: std.Io.Writer.Allocating = .init(arena);
        std.json.Stringify.value(.{
            .schemaVersion = schema_version,
            .kind = e.kindName(),
            .mechanical = e.isMechanical(),
            .probeIdentity = if (binding) |b| @tagName(b) else null,
            .declaredSha256 = declared_sha256,
            .evidence = redacted,
        }, .{}, &writer.writer) catch return error.OutOfMemory;
        return writer.toOwnedSlice();
    }
};

/// Whether this terminal can describe work of this kind at all.
///
/// The settle-side counterpart of `ResolutionEvidence.appliesToKind` above, and
/// deliberately next to it: these are the store's only two admissibility
/// matrices, and a change to one is usually a question about the other. It lives
/// here rather than on `op_state.Terminal` because `op_state.zig` imports only
/// `std` and `operations.zig` imports *it* — the matrix there would close an
/// import cycle in the store's leaf module.
///
/// The two are not symmetric, and the asymmetry is why this one did not exist
/// until now. `resolve` accepts evidence about work the caller did not perform,
/// so it must ask whether a reading is even addressed to this domain. `settle`
/// is reached only from the code that just did the work: three `execution.begin`
/// sites construct every operation this binary creates — `cmd_exec` (`.exec`),
/// `cmd_job` (`.job`), `cmd_read_write` (`.session_write`) — and each settles its
/// own, while the two routes that settle an operation their caller did not create
/// (`request reconcile --from-log`, `Cli.settleProvableBlocker`) both require a
/// `job_attempts` row, which only `job run` writes, on a `.job` operation. So no
/// wrong pair is produced today. This exists to keep that true, not to correct it.
///
/// What made the question non-vacuous is `session_write`. While `exec` and `job`
/// were the only kinds, every terminal described both and the table said nothing.
/// A write runs no command, so `exited` — whose entire content is an exit status
/// — acquired a kind it must not speak for, and `input_accepted` acquired nine.
///
/// **A refusal here is not the same shape of refusal as `appliesToKind`'s**, and
/// saying why is what decides most of the cells below. A refused *resolution* is
/// recoverable: the operator brings a different reading, and `operator_override`
/// is admissible for every kind precisely so nothing is left with no way out. A
/// refused *settlement* is not. `settle` is the sole terminal writer, there is no
/// operator variant in `op_state.Terminal`, and none is proposed here — so a kind
/// whose only route to an outcome is refused cannot reach that outcome at all.
/// The attempt stays live, goes on blocking its scope, and `resolve` cannot
/// rescue it either, because `resolve` acts only on `indeterminate` and the
/// operation never got there. Refusing on this side deletes an outcome from a
/// kind's vocabulary; refusing on the other side only narrows what may prove one.
///
/// So the test for a cell here is not "would this be useful" but "can this kind
/// perform the act the terminal describes, and does refusing still leave it able
/// to say what happened to it".
///
/// Exhaustive in both directions with no `else` anywhere, for the reason
/// `appliesToKind` has none: a new terminal or a new kind must stop the build
/// until somebody answers the question for it, rather than inheriting whichever
/// answer the previous author happened to write last. `gates_test` states the
/// same table a second time from the other direction, kind by kind.
pub fn terminalDescribesKind(terminal: op_state.Terminal, kind: operations.Kind) bool {
    return switch (terminal) {
        // Three of the eight describe the *attempt* rather than the work, and
        // each is admitted for every kind — not by default, but for a reason
        // that is checked per kind below and is the same reason in each case:
        // the fact they carry is about this host's side of the exchange, and
        // every kind of work has one of those.
        //
        // `never_submitted` says the connection layer proved the caller's
        // command did not leave this machine. Per kind: an `exec`'s command, a
        // `job`'s launch line, a `session_write`'s bytes, a transfer's first
        // byte, and whatever a `tunnel`, `plan_phase`, `audit` or `cleanup`
        // would send are all things this binary hands over, and every one of
        // them can fail to be handed over. There is no kind for which "it never
        // left" is either meaningless or false by construction.
        //
        // Refusing any cell would also break the give-up path rather than narrow
        // it. `op_state.terminalForTransportLoss` builds this variant from
        // `created`/`connecting` without being told the kind, and
        // `Execution.abandon` — and through it `Execution.deinit`, the last
        // resort for a process that returned without deciding — calls it for
        // every operation there is. A refused cell would turn "the process
        // exited without recording an outcome" into a lost receipt for whichever
        // kind refused it.
        .never_submitted => switch (kind) {
            .exec,
            .job,
            .session_write,
            .transfer_push,
            .transfer_pull,
            .fetch,
            .tunnel,
            .plan_phase,
            .audit,
            .cleanup,
            => true,
        },
        // "Nothing had been handed over, so there is nothing to stop." Also
        // about the attempt: it records a decision made on this side, in the
        // window before anything was sent, and what was going to be sent does
        // not enter into it. Per kind, the sentence is true of all ten for the
        // same reason `never_submitted`'s is — each is created, each dials, and
        // each can be given up on before it dials.
        //
        // Not interchangeable with `never_submitted`, which is why refusing a
        // cell here would cost something even though that variant stays open:
        // one claims the transport *proved* the bytes did not leave, the other
        // records that we chose to stop. A kind refused here would have to
        // either claim a transport failure that did not happen or stay live.
        // The in-tree users are the transfer fixtures — a checkpoint can only be
        // adopted from an owner that has stopped blocking scope, and this is the
        // evidence that fits an owner still at `created`.
        .local_abandon => switch (kind) {
            .exec,
            .job,
            .session_write,
            .transfer_push,
            .transfer_pull,
            .fetch,
            .tunnel,
            .plan_phase,
            .audit,
            .cleanup,
            => true,
        },
        // The terminal of last resort, and the one cell-by-cell argument that is
        // really an argument about all ten at once: "we cannot establish the
        // remote outcome" is a statement about *our knowledge*, and every kind
        // can be in that position — the answer is lost for an exec, a job, a
        // write, a transfer, or anything later kinds turn out to do. A kind
        // refused here would be a kind obliged to guess, which is the single
        // thing this whole module exists to prevent (`op_state` rule 3).
        //
        // Like `never_submitted` it is produced kind-blindly by
        // `terminalForTransportLoss`, on the same universal give-up path.
        .indeterminate => switch (kind) {
            .exec,
            .job,
            .session_write,
            .transfer_push,
            .transfer_pull,
            .fetch,
            .tunnel,
            .plan_phase,
            .audit,
            .cleanup,
            => true,
        },
        // A real exit status, reported by something that ran a command.
        .exited => switch (kind) {
            // One supervised remote command each, judged by exactly this. The
            // producers are `cmd_exec`'s run path and `cmd_job`'s attach/finish
            // paths, plus the two routes that settle a job somebody else
            // launched.
            .exec, .job => true,
            // A write types bytes into a shell somebody else is running. It runs
            // no command, so there is no exit status anywhere in the operation,
            // and this cell is what makes `input_accepted` binding rather than
            // merely available: `op_state` split that variant out so a receipt
            // would not carry `exit_code = 0` in the column an auditor reads
            // first, for an operation in which no command was judged. Nothing
            // stopped the wrong answer being written beside the right one until
            // here.
            //
            // The tempting wrong answer is concrete rather than hypothetical:
            // `tmux send-keys` is itself a command with an exit status, and a
            // driver could settle the write with the tmux client's. That is
            // `input_accepted`/`input_refused` respelled as a verdict on a
            // command, and it loses the byte count and digest a write's receipt
            // is required by its own evidence type to carry.
            //
            // Refusing costs the kind no outcome: `completed` and `failed` stay
            // reachable through the two variants built to carry what a write
            // actually establishes.
            .session_write => false,
            // Open, and a deliberate blank rather than a decision. Nothing in
            // this binary creates a transfer operation — `transfers` is
            // store-side work with no CLI producer — so there is no evidence
            // chain to answer from, and the honest arguments point both ways: a
            // transfer's verdict is a digest at a destination it declared in
            // advance, not an exit code (the argument `appliesToKind` uses to
            // refuse `supervisor_report` for these kinds), yet the code that
            // will settle one is the code that will *perform* it, which is not
            // the same situation as importing a copier's exit status as proof.
            //
            // What decides it meanwhile is the cost of being wrong in each
            // direction. `exited` is the only terminal yielding `completed` for
            // anything that is not a `session_write`, so a refusal here would
            // not narrow how a transfer may be settled — it would mean a
            // transfer can never complete, while `transfers`' own state machine
            // requires the owning operation to settle before a checkpoint can be
            // adopted or published. That is a wedged subsystem, not a narrowed
            // one. Left open for the change that writes the producer to answer.
            .transfer_push, .transfer_pull, .fetch => true,
            // Open for the same reason with less to say: nothing creates one of
            // these, nothing settles one, and there is no mechanism to reason
            // from. A deliberate blank, and specifically *not* the free refusal
            // it would be in `appliesToKind` — refusing every terminal for a
            // producerless kind means the first operation of that kind ever
            // created is unsettleable, holds its scope, and never reaches
            // `indeterminate` for a reconcile to act on.
            .tunnel, .plan_phase, .audit, .cleanup => true,
        },
        // A deadline the *remote* enforced and reported.
        .remote_deadline => switch (kind) {
            // Both declare it as a capability they may have —
            // `supervisor.Requirement.remote_deadline`, satisfied only by the
            // remote helper — which is what makes a report of one a statement
            // about their own work rather than about the local clock.
            .exec, .job => true,
            // A write hands one tmux invocation over and reads its answer.
            // Nothing on the far side of `send-keys` enforces a deadline or
            // reports one, and `timed_out` is not an outcome the operation can
            // have: the bytes were taken or they were not.
            //
            // The tempting wrong answer is the *local* deadline waiting for that
            // answer, which `op_state` rule 2 already names — a local deadline
            // expiring while the remote is unreachable is not a timeout — and
            // which `terminalForTransportLoss` routes to `indeterminate`. This
            // is the one refusal in the table that removes a status from a
            // kind's vocabulary entirely, and it removes one the kind could
            // never have reached honestly.
            .session_write => false,
            // Deliberate blanks, as for `exited`: no producer, and refusing
            // would delete `timed_out` outright from kinds whose remote work has
            // not been written yet.
            .transfer_push, .transfer_pull, .fetch => true,
            .tunnel, .plan_phase, .audit, .cleanup => true,
        },
        // A remote process was signalled and its absence verified.
        .remote_cancel_confirmed => switch (kind) {
            // An `exec` records the pid and start token of the process that ran
            // its command (`supervisor.Identity`, put on the trail by
            // `execution.remoteStarted`), so there is a process to signal and an
            // identity to verify absence against — the same fact that makes
            // `process_probe` admissible for `exec` and only `exec` in
            // `appliesToKind`.
            .exec => true,
            // The producer is `cmd_job`'s kill path, which constructs this only
            // when the operation's recorded capability satisfies
            // `verified_cancellation`; shell mode never does, and gets
            // `indeterminate` instead.
            .job => true,
            // A write starts no remote process, so there is nothing for a
            // cancellation to have confirmed the absence of. `Tmux.sendKeys`
            // runs one tmux command and reports nothing about the pane, and the
            // pane's process belongs to whoever started the session — killing it
            // does not cancel a write, it kills somebody else's work. That is
            // the mistake `appliesToKind`'s `process_probe` × `job` cell was
            // closed for, one axis over.
            //
            // The tempting wrong answer is the operator interrupting `terminus
            // write`: nothing local un-sends bytes already handed to tmux, and
            // after submission the honest terminal is `indeterminate`, which is
            // what `cmd_read_write` writes. `cancelled` is not lost — before
            // submission it is still reachable through `local_abandon`, and
            // before submission is the only window in which a write has anything
            // to abandon.
            .session_write => false,
            // Deliberate blanks. Not empty ones: `gates_test`'s own fixture
            // records that this is the state a killed transfer is really left
            // in, so the first producer has somewhere to start. Refusing would
            // delete post-submission `cancelled` from these kinds meanwhile.
            .transfer_push, .transfer_pull, .fetch => true,
            .tunnel, .plan_phase, .audit, .cleanup => true,
        },
        // A live terminal's answer about bytes it was offered, positive or
        // negative. `terminus write` performs that act and nothing else does.
        .input_accepted, .input_refused => switch (kind) {
            .session_write => true,
            // An `exec` or a `job` runs a command and is judged by its exit
            // status. `input_accepted` would settle one `completed` carrying a
            // byte count and no exit code — a command recorded as having
            // succeeded that nothing ever judged — and `input_refused` would say
            // the shell was never touched, which for a job is false in the most
            // literal way available: `cmd_job` types its launch line into a tmux
            // session exactly as `write` types the operator's. That shared
            // mechanism is precisely why the cell is written out rather than
            // assumed; `appliesToKind` names the same pair for the same reason
            // in its `job_result` row.
            //
            // Refusing costs neither kind an outcome — `exited` carries both of
            // theirs — so this is a refusal, not a blank.
            .exec, .job => false,
            // A transfer's completion is a file at a destination it declared,
            // with the digest it promised. "A terminal took some bytes" is not a
            // reading of a destination and cannot be turned into one. A refusal
            // rather than a blank, because the act is simply not theirs, and it
            // deletes nothing: `exited` stays open above.
            .transfer_push, .transfer_pull, .fetch => false,
            // Refused rather than left blank for the same reason, and the
            // refusal is free: whatever these turn out to do, none of them is
            // "type bytes into somebody else's shell", which is the only act
            // this pair describes — and each keeps `exited` and all three
            // attempt-level terminals.
            .tunnel, .plan_phase, .audit, .cleanup => false,
        },
    };
}

/// What a `process_probe` was actually matched against.
///
/// A probe names no request. What ties it to an operation is the process
/// identity that operation recorded while it ran, and that identity comes in
/// two strengths — which is a fact about the *host*, not about the probe:
/// `supervisor.wrapShell` reads the start time out of `/proc/<pid>/stat` or
/// `ps -o lstart=`, and a host that can do neither reports a pid alone
/// (`supervisor.Capability.pid_proof == .weak`).
///
/// The contract, written here because it had none and two readings of the
/// missing token were both defensible:
///
///  * A recorded token the probe did not read is a **mismatch**. The attempt
///    knew something and the probe declined to check it.
///  * A recorded token the probe read differently is a **mismatch**. That is
///    the recycled pid the token exists to catch.
///  * No recorded token is **admitted, as `pid_only`**. Refusing would leave
///    every attempt on such a host with no mechanical route to resolution at
///    all, and the pid really is the whole of what that attempt ever knew about
///    its own process. What is *not* acceptable is admitting it silently: pids
///    are recycled, so a pid-only match is a weaker claim than a pid+token one
///    and the receipt has to say which it was. That is the whole reason this
///    enum exists rather than a bool inside `resolve`.
///  * A token the probe read against an attempt that recorded none is still
///    `pid_only`. Nothing here was compared with anything — a token nobody
///    wrote down cannot corroborate a match — and grading the binding by what
///    the *probe* volunteered would let a caller strengthen its own evidence by
///    supplying a field.
pub const ProbeBinding = enum {
    /// The attempt recorded a start token and the probe read the same one.
    pid_and_start_token,
    /// The attempt never recorded a start token, so the pid is the whole of
    /// the match. A different process may since have been given that pid.
    pid_only,
};

fn redact(arena: std.mem.Allocator, text: []const u8) std.mem.Allocator.Error![]const u8 {
    return history.redactSecrets(arena, text);
}

/// The process identity an operation recorded for itself, read back off its
/// event trail.
pub const RecordedProcess = struct {
    pid: i64,
    /// Null when the shell could not read a start time. `pid_proof` is only
    /// `weak` then (see `supervisor.Capability`), and the pid is the whole of
    /// what a later probe can be checked against.
    start_token: ?[]const u8,
};

pub const ResolveOutcome = union(enum) {
    resolved,
    /// The evidence does not entail the claimed result (a zero exit code
    /// cannot prove `failed`; a live process cannot prove anything).
    evidence_does_not_support: struct {
        resolved: op_state.ResolvedStatus,
        evidence_kind: []const u8,
    },
    /// The evidence cannot speak about this kind of operation (a published
    /// file hash says nothing about an arbitrary command).
    evidence_wrong_kind: struct {
        operation_kind: []const u8,
        evidence_kind: []const u8,
    },
    /// The evidence is about a *different* operation: it carries a request id
    /// of its own, and it is not this one. Distinct from `evidence_wrong_kind`
    /// because the mismatch is identity, not category — the evidence could be
    /// perfectly valid, just not here.
    evidence_wrong_operation: struct {
        /// The request id the evidence itself names.
        evidence_request_id: []const u8,
        /// The request id being resolved.
        request_id: []const u8,
    },
    /// A process probe was offered for an operation whose process it is not a
    /// reading of. The identity analogue of `evidence_wrong_operation`, one
    /// domain over: a probe is addressed by pid rather than by request id, so
    /// what binds it to this operation is the pid and start token the attempt
    /// recorded while it ran.
    ///
    /// Carries both sides because they send an operator to three different
    /// places — another process, a recycled pid, or an attempt that never had a
    /// process at all — and only the payload knows which.
    evidence_wrong_process: struct {
        probed_pid: i64,
        probed_start_token: ?[]const u8,
        /// What this operation recorded, or null when it never recorded a
        /// process identity at all.
        recorded: ?RecordedProcess,
    },
    /// A job sentinel was offered for an operation whose sentinel it is not.
    ///
    /// The third identity refusal, and the one that was missing. A sentinel
    /// names no request — it is a line scanned out of a window of an append-only
    /// log that anything on the host can write to — so what ties it to this
    /// operation is the sentinel `cmd_job` wrote down when it launched the
    /// attempt. Until that was compared, `job_sentinel` was the only mechanical
    /// variant in the union with **no identity binding at all**: its `sentinel`
    /// field was carried into the receipt and never checked against anything,
    /// while `isMechanical` graded it `true` — the grade that settles an
    /// operation and releases the same-scope mutation barrier with no operator
    /// in the loop. Any caller holding any request id could hand in any string
    /// with an exit code attached.
    ///
    /// Carries both sides, for the reason `evidence_wrong_process` does: the
    /// three cases in `RecordedSentinel` send an operator three different ways,
    /// and only the payload knows which one this is. Refusing when nothing was
    /// recorded is the correct direction and not an over-reach — absence of a
    /// recording is not permission, and waving it through would make the check
    /// vacuous exactly on the attempts nobody can go and verify.
    evidence_wrong_sentinel: struct {
        /// The sentinel the evidence carried.
        offered: []const u8,
        /// What the launch wrote down, or why there is nothing to compare with.
        recorded: job_attempts.RecordedSentinel,
    },
    /// A published-file hash was offered for an operation that never declared
    /// what would count, or whose declaration it does not match. Separate from
    /// `evidence_does_not_support` because the evidence *kind* is right and
    /// the claim is the right shape — what is missing is the advance
    /// commitment that makes the observation mean anything.
    effect_hash_unproven: struct {
        /// What the caller says it read, and where.
        observed: Observed,
        /// What the transfer committed to before submitting, if anything.
        expected: ?transfers.ExpectedEffect,

        pub const Observed = struct {
            side: transfers.Side,
            path: []const u8,
            sha256: []const u8,
        };
    },
    /// An absence reading was offered for a destination this transfer never
    /// committed to, or for a request that has no checkpoint at all. Separate
    /// from `effect_hash_unproven` because there is no digest in the question:
    /// what does not line up is the address, and printing a hash comparison for
    /// it would send an operator to look at bytes.
    absence_wrong_destination: struct {
        /// Where the caller says it looked.
        observed: transfers.Destination,
        /// Where the transfer said it would publish, if it has a checkpoint.
        committed: ?transfers.Destination,
    },
    /// A reading of the destination was offered for a transfer whose publish is
    /// not an open question.
    ///
    /// A destination reading settles what became of a *rename nobody watched*,
    /// which is the one thing `indeterminate_publish` records. Anywhere else it
    /// is a statement about a path, and the two are not interchangeable: a
    /// transfer that published and verified, then lost its reply and settled
    /// `indeterminate`, could otherwise be resolved `failed` from an absence
    /// read after a rotation removed the file — leaving the ledger holding
    /// `resolved_status = failed` and a receipt saying the artifact was never
    /// delivered, next to a checkpoint that says `published`. The next transfer
    /// aimed there would then repeat a delivery the store's own record
    /// contradicts.
    ///
    /// Carries the state so the refusal can say which way the question was
    /// already answered.
    publish_not_in_question: struct {
        observed: transfers.Destination,
        /// What the checkpoint records about that destination now.
        state: []const u8,
    },
    /// A "present, nothing to check it against" reading was offered for a
    /// transfer that *did* declare a digest.
    ///
    /// The reading is not wrong, it is weaker than the one available for the
    /// same act of looking: the file is there and the transfer said in advance
    /// what it should hash to, so hashing it settles the question properly.
    /// Admitting the unverified form here would be a way of skipping a check
    /// that exists, on the path that decides whether an artifact is recorded as
    /// delivered.
    unverified_reading_when_digest_declared: struct {
        observed: transfers.Destination,
        /// What the transfer committed to, so the caller knows what to compare
        /// its hash against.
        expected_sha256: []const u8,
    },
    /// A "the artifact here is the wrong artifact" reading that does not
    /// actually contradict anything.
    ///
    /// Two situations wearing one name, told apart by `declared`, and they send
    /// the caller to two different readings:
    ///
    ///  * `declared == null` — the transfer never said what its artifact would
    ///    hash to, so there is nothing for this digest to disagree with and no
    ///    reading of the bytes can be judged at all. What the look established
    ///    is that *something* is there, which is
    ///    `destination_present_unverified`.
    ///  * `declared` equals what was read — the artifact is the one that was
    ///    promised. That is a delivery, not a failure, and the reading for it is
    ///    `filesystem_effect`.
    ///
    /// Refused rather than quietly redirected, because the two verdicts are
    /// opposite: admitting the second would let a caller turn a correctly
    /// delivered artifact into `failed` and `failed_hash_mismatch` by choosing a
    /// variant, on the path that decides whether a scope barrier is released.
    contradiction_not_established: struct {
        observed: transfers.Destination,
        /// The digest the caller says it read off the destination.
        observed_sha256: []const u8,
        /// What the transfer committed to in advance, or null if it committed
        /// to nothing.
        declared: ?[]const u8,
    },
    /// A destination reading arrived with no account of how it was read. The
    /// method is what makes it a reading rather than a conclusion — see
    /// `ResolutionEvidence.destination_absent.verification_method`.
    reading_has_no_method: struct { evidence_kind: []const u8 },
    /// A published-file hash matched this transfer's declaration, against a
    /// checkpoint whose own record says the transfer never got as far as
    /// putting an artifact there.
    ///
    /// The sibling of `publish_not_in_question`, one variant over and in the
    /// opposite direction. That one refuses a reading of a destination whose
    /// question is already answered; this one refuses a reading whose answer
    /// contradicts what the transfer recorded about itself. A digest match binds
    /// the reading to the *declaration* and to nothing else, so on a row that
    /// records a failure — most reachably `failed_clobber_conflict`, whose
    /// ordinary cause is the previous delivery of the very same artifact still
    /// sitting at the path — it would settle the operation `completed` and lift
    /// the scope barrier while the checkpoint went on saying no byte was ever
    /// written and holding the destination.
    ///
    /// Not folded into `effect_hash_unproven`: the hash *was* proven, and
    /// telling an operator their digest did not match would send them to
    /// re-hash a file that is exactly what they said it was. What is wrong is
    /// the conclusion drawn from it, so the refusal carries the state instead of
    /// the digests.
    effect_reading_against_recorded_outcome: struct {
        observed: transfers.Destination,
        /// What the checkpoint records about that destination now.
        state: []const u8,
    },
    /// Only an `indeterminate` attempt can be resolved. Carries what the
    /// status actually is, so the caller can say why it refused.
    not_indeterminate: op_state.Status,
    /// `resolved_status` is write-once; a second reconciler must not
    /// overwrite the first one's evidence.
    already_resolved: op_state.ResolvedStatus,
    unknown_operation,
};

/// The newest process identity this operation recorded, or null if it never
/// recorded one.
///
/// Newest wins because one attempt can report a pid more than once — the start
/// marker, then the terminal — and the last process we saw running is the one a
/// later probe is a reading of.
///
/// The token is then read back **for that pid**, newest first, rather than off
/// whichever row supplied the pid. Two things follow, and both are the point:
/// a token can never be checked against a pid it did not belong to, and an
/// identity cannot be *downgraded*. The columns are independently optional at
/// every writer (`Observation` and `TerminalExtra` both expose them as free
/// optionals), so a later event carrying the pid without the token would
/// otherwise take the operation from pid+token binding to pid-only — turning a
/// probe that could not read a start time from refused into admitted, on an
/// attempt that had already proved it could read one.
///
/// The first of those two is a property of *this* statement only across rows.
/// Within one row it is the writer's, and one writer used to be able to break
/// it: `terminalEvent`'s `remote_cancel_confirmed` arm filled pid and token
/// from two independent `orelse`s, so a caller correcting only the pid produced
/// a row pairing it with the evidence's token — a pair no host ever reported,
/// read back here as a `pid_and_start_token` identity. That arm now takes both
/// halves from one source. Saying "that is a property of the callers, not of
/// the table" was true and was not a reason to leave the caller wrong.
///
/// A row that never carried a token leaves this null. `pid_proof` is only
/// `weak` then (see `supervisor.Capability`) and the pid is the whole of the
/// identity — see `startTokenFits` for what that admits and `ProbeBinding` for
/// what the receipt is then allowed to claim about it.
///
/// Both statements walk this request's own events newest-first over
/// `UNIQUE(request_id, seq)` and stop at the first hit, so together they read at
/// most one operation's trail. Caller must hold the write transaction.
fn recordedProcessLocked(store: *Store, arena: Allocator, request_id: []const u8) Error!?RecordedProcess {
    const pid = blk: {
        var stmt = try store.db.prepare(
            \\SELECT remote_pid
            \\  FROM operation_events
            \\ WHERE request_id = ?1 AND remote_pid IS NOT NULL
            \\ ORDER BY seq DESC LIMIT 1
        );
        defer stmt.deinit();
        try stmt.bindText(1, request_id);
        if (!try stmt.step()) return null;
        break :blk stmt.columnInt(0);
    };

    var stmt = try store.db.prepare(
        \\SELECT remote_start_token
        \\  FROM operation_events
        \\ WHERE request_id = ?1 AND remote_pid = ?2 AND remote_start_token IS NOT NULL
        \\ ORDER BY seq DESC LIMIT 1
    );
    defer stmt.deinit();
    try stmt.bindText(1, request_id);
    try stmt.bindInt(2, pid);
    return .{
        .pid = pid,
        // Duped: the statement is finalized before this is read, and the value
        // travels out of `resolve` inside the refusal.
        .start_token = if (try stmt.step()) try arena.dupe(u8, stmt.columnText(0)) else null,
    };
}

/// Whether a probe's start token clears the identity the operation recorded.
///
/// Half of the contract in `ProbeBinding`, and the half that decides admission:
/// a recorded token the probe did not read, or read differently, is a mismatch
/// and not a pass. The token is the only thing separating our process from
/// whatever the kernel handed that pid next, which is the entire reason it is
/// recorded; a probe that could not read one has not ruled that out.
///
/// A probe that *did* read one for an attempt that recorded none is not a
/// mismatch — there is nothing here to contradict it, and the pid is all this
/// operation ever knew about its own process. It is not a stronger match
/// either: `bindingFor` grades that case `pid_only`, because the token was
/// compared with nothing.
fn startTokenFits(recorded: ?[]const u8, probed: ?[]const u8) bool {
    const want = recorded orelse return true;
    const got = probed orelse return false;
    return std.mem.eql(u8, want, got);
}

/// How strong the match was, given what the attempt had written down.
///
/// Read off the *recorded* identity alone. `startTokenFits` has already said
/// the probe is admissible; this says how much that admission is worth, and it
/// goes on the receipt so the claim there is no stronger than the evidence
/// behind it.
fn bindingFor(recorded: RecordedProcess) ProbeBinding {
    return if (recorded.start_token == null) .pid_only else .pid_and_start_token;
}

/// What a resolution's evidence forces on a checkpoint parked in
/// `indeterminate_publish`, or null when it forces nothing.
///
/// A narrower question than the one `supports` answers. `supports` asks what
/// the evidence proves about the *operation*; this asks what it proves about a
/// rename that may or may not have run — and `indeterminate_publish` is
/// recorded precisely when the process's own fate stopped answering that. Every
/// arm has to justify itself, because a null refuses a whole resolution and a
/// wrong non-null writes a fabricated fact about a file on someone's disk.
///
/// `reading` travels with the verdict because for the two verdicts that have one
/// the reading and the verdict are one fact: for `published` the digest that
/// proved the artifact is the digest the checkpoint then records as its own, and
/// for `failed_hash_mismatch` the digest that disproved it is what the state is
/// *about*. See `transfers.adjudicateLocked` for why the row cannot supply
/// either and why carrying them here is not a weakening.
///
/// Exhaustive over the union so a new evidence variant has to say what it can
/// establish about a destination before it can be used at all.
const PublishVerdict = struct {
    to: transfers.State,
    /// The digest read off the destination, for the two verdicts that turn on
    /// one.
    reading: ?[]const u8 = null,
};

/// Whether this evidence can say what became of a rename nobody watched.
///
/// The same question `publishAdjudication` answers, exposed as a bool so the
/// operator-facing text that has to enumerate these readings is checked against
/// the set rather than against a hand-kept list. A refusal that tells an
/// operator to offer a reading has to name every reading that would work, and
/// the last time that list was maintained by hand it went stale the moment a
/// fourth reading landed — leaving a transfer whose only route was the reading
/// the sentence did not mention.
pub fn adjudicatesParkedPublish(e: ResolutionEvidence) bool {
    return publishAdjudication(e) != null;
}

fn publishAdjudication(e: ResolutionEvidence) ?PublishVerdict {
    return switch (e) {
        // The one variant that reads the destination *and* has something to
        // check it against. By the time this is asked, `resolve` has compared
        // all three halves — side, path and digest — against what the transfer
        // committed to before it sent anything, so the artifact is at the
        // destination and hashes to what was promised. That is what `published`
        // means, and the reading goes with it: a row whose owner was killed
        // before it could hash its own result has no `verified_sha256`, and
        // this reading is that column's honest content.
        .filesystem_effect => |fx| .{ .to = .published, .reading = fx.sha256 },
        // The artifact is there and this transfer never declared anything that
        // could say it is the right artifact. `completed_unverified` is the
        // state for exactly that, and no reading accompanies it — the digest
        // conjunct on that target requires the column to stay null, which is
        // what "unverified" means.
        .destination_present_unverified => .{ .to = .completed_unverified },
        // The artifact is there and it is provably the wrong artifact. By the
        // time this is asked, `resolve` has compared side and path against the
        // committed destination, established that the transfer declared a digest
        // in advance, and established that this reading is not that digest.
        //
        // `failed_hash_mismatch` says the digest did not match, which is exactly
        // what was proven — the state's literal meaning, not the nearest legal
        // answer. It is a *failure* verdict reached from a *present* artifact,
        // and that only reads oddly until the hold is taken into account: every
        // `failed_*` keeps its destination (`transfers.State.holdsDestination`),
        // so the wrong bytes are not silently clobbered by the next transfer
        // aimed there, and the operator's exit is `supersede` once they have
        // decided what to do about them.
        //
        // The reading travels with the verdict, and it has to. A parked row can
        // already carry a digest — the driver hashed the staged bytes while
        // verifying, then died mid-rename, and the normalisation to
        // `indeterminate_publish` deliberately keeps it — and that digest is of
        // the bytes *before* the rename while this one is of what is at the
        // destination *after* it. The state records the second, so the column
        // has to hold the second. Leaving the first in place produced a
        // `failed_hash_mismatch` whose columns said the digest agreed;
        // `transfers.evidenceClause` now refuses that row outright, so a verdict
        // carrying no reading could not reach the state at all.
        .destination_present_contradicting => |reading| .{
            .to = .failed_hash_mismatch,
            .reading = reading.sha256,
        },

        // The other reading of the same destination, and the only thing that
        // can produce `failed_publish`. By the time this is asked, `resolve`
        // has compared side and path against what the transfer committed to at
        // `create`, so what was inspected is this transfer's destination and it
        // does not carry the artifact.
        //
        // `failed_publish` says the publish did not put the artifact at the
        // path — which is what was read — and deliberately does not say the
        // rename never ran, because an absence now cannot distinguish a rename
        // that never happened from one that happened and was undone. Nothing
        // downstream needs that distinction: the row keeps holding its
        // destination either way (`State.holdsDestination` covers every
        // failure), so the next transfer aimed there still has to be let
        // through by an operator rather than walking into the leftovers.
        .destination_absent => .{ .to = .failed_publish },
        // A report about how the *process* ended, from a supervisor that does
        // not speak about files. Exit 0 is compatible with a rename that landed
        // and with one whose reply was the thing that got lost; a non-zero one
        // is compatible with a rename that had already succeeded. Reading
        // either as a fact about the destination is the guess this refuses.
        .supervisor_report => null,
        // Weaker still: a dead process proves it is no longer running, and
        // nothing whatever about what it left behind.
        .process_probe => null,
        // A human's decision about the operation, carrying no reading of the
        // destination. Recording `published` from it would put an artifact fact
        // in the checkpoint table with nothing marking it as asserted rather
        // than observed, while `resolve` keeps an override legible as an
        // override everywhere else.
        //
        // That reasoning used to hold in one direction only: the operator's
        // route was to hash the file and offer `filesystem_effect`, and there
        // was no route for the negative case or for a transfer that never
        // declared a digest, so refusing here left both wedged. It now holds in
        // all four — an operator who looked reports what they saw, and there is
        // a variant for each thing there is to see. The refusal is a requirement
        // to say what was seen.
        .operator_override => null,
        .job_result, .job_sentinel => null,
        // Five of the nine arms above no longer reach this point at all:
        // `appliesToKind` admits only the four destination readings and
        // `operator_override` for the three transfer kinds, and only a transfer
        // has a checkpoint. They are answered rather than asserted
        // `unreachable` because the guard that makes them dead lives in another
        // function — a null costs one refusal if that ever changes, a wrong
        // `unreachable` costs the process. Their reasons are kept because they
        // are why those cells are refused a step earlier, not leftovers.
    };
}

/// Records the later-proven truth for an unsettled attempt.
///
/// Guarded because a resolution lifts the same-scope mutation barrier: writing
/// one against a still-running attempt would let a peer start a conflicting
/// change while the remote command is alive. Hence
///
/// * only `indeterminate` may be resolved (a `submitted` attempt is not
///   unknown, it is *in progress* — wait for it or reconcile it properly);
/// * `resolved_status` is write-once, enforced by a conditional UPDATE whose
///   row count is checked;
/// * evidence is typed, so an operator override stays legible as one instead
///   of passing for a mechanical proof;
/// * evidence that names a request must name *this* one, a probe must be a
///   reading of the process this attempt recorded, and evidence must suit the
///   kind of operation it is offered for — a barrier that trusts its callers to
///   aim correctly is not a barrier;
/// * a transfer whose rename was never observed is adjudicated here too, in
///   this transaction, so the operation's verdict and the artifact's fate land
///   together or not at all;
/// * the resolution and its append-only reconcile event commit together, so
///   a resolution can never exist without evidence explaining it.
pub fn resolve(
    store: *Store,
    arena: std.mem.Allocator,
    request_id: []const u8,
    resolved: op_state.ResolvedStatus,
    evidence: ResolutionEvidence,
    now: i64,
) Error!ResolveOutcome {
    try store.db.exec("BEGIN IMMEDIATE");
    errdefer store.db.exec("ROLLBACK") catch {};

    // Each statement is scoped so it is finalized *before* any rollback: a
    // live statement can make ROLLBACK fail with SQLITE_BUSY, and we do not
    // want a cleanup path that depends on statement lifetime.
    var found = false;
    var current_status: op_state.Status = undefined;
    var current_resolution: ?op_state.ResolvedStatus = null;
    var kind: operations.Kind = undefined;
    {
        var stmt = try store.db.prepare(
            "SELECT status, resolved_status, kind FROM operations WHERE request_id = ?1",
        );
        defer stmt.deinit();
        try stmt.bindText(1, request_id);
        if (try stmt.step()) {
            found = true;
            current_status = try op_state.Status.parse(stmt.columnText(0));
            current_resolution = if (stmt.columnOptText(1)) |v| try op_state.ResolvedStatus.parse(v) else null;
            // `kind` carries no CHECK constraint, so a future version, a manual
            // edit or a corrupted row can leave anything in it. Whatever it
            // holds, a kind this binary cannot name is one it cannot reason
            // about, and `appliesToKind` — which decides whether evidence may
            // release the scope barrier — only has answers for the kinds it
            // knows. Parse or refuse; there is no third option that is honest.
            //
            // Parsing is also what closes the hole underneath: the column used
            // to be copied into a buffer and compared as text, so an
            // unrecognised *short* kind matched nothing, fell through the old
            // `else => true`, and admitted every variant in the union.
            kind = operations.Kind.parse(stmt.columnText(2)) catch return error.UnknownOperationKind;
        }
    }

    if (!found) {
        try rollback(store);
        return .unknown_operation;
    }
    // Identity before content: ask whether the evidence is about this
    // operation at all before asking what it says. A sidecar is addressed by
    // the request id it was written for and carries that id inside it, so a
    // pair that disagrees is either a misrouted document or a caller that
    // wired the wrong id in — and settling one operation from another's exit
    // status is exactly what request-keyed results exist to prevent.
    //
    // `Tmux.parseJobResult` already refuses to hand back a document naming
    // another request, and this check stays anyway. They are not the same
    // check: the parser stops a foreign document from becoming a reading at
    // all, this stops a genuine reading from being aimed at the wrong
    // operation — which no parser can see, because by then the reading is
    // just a value a caller is passing. Two independent checks on a
    // scope-releasing path is the point. It only holds while the evidence's
    // `request_id` comes from the document (see its doc comment); filled from
    // the operation being resolved, this compares a value against itself and
    // can never fire.
    //
    // A probe is the same question addressed differently. It names no request,
    // so what ties it to this operation is the process identity the attempt
    // recorded while it ran — and until that was read, a probe of any process
    // on any host settled any operation, releasing its barrier on a claim about
    // an unrelated pid. It is asked here, with the other identity check and
    // before `supports`, because "a live process proves nothing" is a true
    // sentence about *some* process: printed for a probe of somebody else's,
    // it sends an operator to look at the wrong one.
    // How firmly a probe was tied to this attempt, filled by the check below
    // and carried into the receipt. Null for every other kind of evidence, and
    // for a probe that never got past the check — nothing is written then.
    var probe_binding: ?ProbeBinding = null;
    switch (evidence) {
        .job_result => |r| if (!std.mem.eql(u8, r.request_id, request_id)) {
            try rollback(store);
            return .{ .evidence_wrong_operation = .{
                .evidence_request_id = r.request_id,
                .request_id = request_id,
            } };
        },
        .process_probe => |probe| {
            const recorded = try recordedProcessLocked(store, arena, request_id);
            // An attempt that never recorded a process is one a probe cannot
            // speak about — the same shape as a transfer that never declared a
            // digest, and refused for the same reason. Waving it through
            // because there is nothing to contradict would make the check
            // vacuous exactly where it is needed: an attempt whose process we
            // never identified is the one nobody can go and look for.
            const fits = if (recorded) |had|
                had.pid == probe.pid and startTokenFits(had.start_token, probe.start_token)
            else
                false;
            if (!fits) {
                try rollback(store);
                return .{ .evidence_wrong_process = .{
                    .probed_pid = probe.pid,
                    .probed_start_token = probe.start_token,
                    .recorded = recorded,
                } };
            }
            // Admitted — and how strongly, because the two are not the same
            // claim and only this function knows which one it just made. See
            // `ProbeBinding`: a pid-only match is admitted deliberately, and a
            // receipt that did not say so would read as a pid+token match on a
            // number the kernel is free to reissue.
            probe_binding = bindingFor(recorded.?);
        },
        else => {},
    }
    // Check what the evidence can actually establish before anything else:
    // a resolution lifts the mutation barrier, so an unsupported one must
    // never reach the ledger at all.
    if (!evidence.supports(resolved)) {
        try rollback(store);
        return .{ .evidence_does_not_support = .{
            .resolved = resolved,
            .evidence_kind = evidence.kindName(),
        } };
    }
    if (!evidence.appliesToKind(kind)) {
        try rollback(store);
        // `@tagName` rather than the column's text: the two fields answer two
        // different questions — what refused, and what was offered — and
        // reporting the evidence's kind in both told a caller nothing about
        // which pairing was rejected.
        return .{ .evidence_wrong_kind = .{
            .operation_kind = @tagName(kind),
            .evidence_kind = evidence.kindName(),
        } };
    }
    // The same idea as the `job_result` check above, one domain over, and it
    // runs here because it is the *narrowest* of the three: by now we know the
    // evidence supports the claim and may speak about this kind of operation,
    // so what is left is whether it speaks about this particular one.
    //
    // A job's evidence is addressed by request id. A transfer's is addressed
    // by content, so what binds it to this operation is the digest the
    // transfer wrote down *before* it sent anything. A digest recorded
    // afterwards would just be the hash of whatever is there now, and
    // comparing that against itself is how a hash check becomes decoration.
    //
    // No declared digest means no proof is possible — not that any digest will
    // do. Without this, `filesystem_effect` was the weakest evidence in the
    // union behaving like the strongest: a stale file left at the right path
    // by an earlier run would settle an indeterminate transfer `completed`.
    //
    // The digest a transfer committed to, filled by the one arm below whose
    // verdict is *about* that digest, and carried into the receipt beside the
    // reading that contradicts it. Null everywhere else, including for
    // `filesystem_effect`, whose receipt records a digest that agreed and needs
    // no second copy of it.
    var declared_sha256: ?[]const u8 = null;
    switch (evidence) {
        // A sentinel is the third address the identity question is asked at, and
        // the only one that has to wait until here to ask it. It names no
        // request and no process — it is a string scanned out of a window of an
        // append-only log that anything on the host can write to — so what ties
        // it to this operation is the sentinel this binary chose and wrote into
        // `job_attempts` before the launch line ever reached the shell
        // (`cmd_job`, which records it before `sendKeys`; so a sentinel that
        // could be in a log is necessarily one that is in that table).
        //
        // It sits *after* `appliesToKind` rather than beside the `job_result`
        // and `process_probe` checks above, and the reason is that the question
        // is unaskable before it. Only a job has an attempt row, so "no attempt
        // recorded this sentinel" is true of every transfer and every fetch as
        // well — asked first, it answers a `job_sentinel` offered for a transfer
        // with an identity refusal, sending an operator to look for a launch
        // record for work that never had one and hiding the fact that sentinels
        // cannot speak about transfers at all. The category error is the larger
        // fact and `evidence_wrong_kind` is where it is named. By the time this
        // runs the operation is known to be a job, and what is left is whether
        // this is *that* job's sentinel — which is exactly the position the
        // transfer commitment checks below occupy for their own evidence.
        //
        // Both absences refuse. An attempt that recorded no sentinel is one no
        // sentinel can speak for, exactly as an attempt that recorded no process
        // is one no probe can speak for; admitting it because there is nothing
        // to contradict would make the check vacuous on precisely the rows that
        // need it most.
        .job_sentinel => |s| {
            const recorded = try job_attempts.sentinelForLocked(store, arena, request_id);
            const fits = switch (recorded) {
                .sentinel => |had| std.mem.eql(u8, had, s.sentinel),
                .attempt_recorded_none, .no_attempt => false,
            };
            if (!fits) {
                try rollback(store);
                return .{ .evidence_wrong_sentinel = .{
                    .offered = s.sentinel,
                    .recorded = recorded,
                } };
            }
        },
        .filesystem_effect => |fx| {
            const expected = try transfers.expectedEffectLocked(store, arena, request_id);
            const matches = if (expected) |want|
                want.side == fx.side and
                    std.mem.eql(u8, want.path, fx.path) and
                    std.mem.eql(u8, want.sha256, fx.sha256)
            else
                false;
            if (!matches) {
                try rollback(store);
                return .{ .effect_hash_unproven = .{
                    .observed = .{ .side = fx.side, .path = fx.path, .sha256 = fx.sha256 },
                    .expected = expected,
                } };
            }
            // The digest binds the reading to this transfer's *declaration*. It
            // does not say this transfer ever put anything at that path, and
            // that second question has an answer sitting in the same row — the
            // checkpoint's state. The three destination readings below ask it
            // (`publish_not_in_question`); this arm did not, and was the only
            // way a reading could overrule a recorded verdict rather than fill
            // in a missing one. See `State.renameMayHaveLanded` for the
            // clobber-conflict sequence that walks through the digest check
            // with the hash of somebody else's artifact.
            if (!expected.?.state.renameMayHaveLanded()) {
                try rollback(store);
                return .{ .effect_reading_against_recorded_outcome = .{
                    .observed = .{ .side = fx.side, .path = fx.path },
                    .state = expected.?.state.text(),
                } };
            }
        },
        // The same question with nothing to hash, or with a hash that has to
        // disagree, for the three readings that report an address. Five things
        // are asked, and each closes a way of settling a transfer from a look at
        // the wrong thing:
        //
        //  * the method must be there. It is what makes this a reading rather
        //    than a conclusion, and a field that is "required" only by its type
        //    is one a caller satisfies with `""`.
        //  * side and path must match the destination the transfer committed to
        //    at `create`, before it submitted. Without the path a reconciler
        //    could report any empty path it liked; without the side, looking at
        //    the local copy of a push would prove the host's destination empty.
        //  * the checkpoint's publish must still be an open question. See
        //    `publish_not_in_question`: a reading of a destination answers what
        //    became of a rename nobody watched, and against a row that already
        //    records what became of it, it is a statement about a path with a
        //    verdict attached.
        //  * for the unverified positive reading only, the transfer must have
        //    declared no digest. If it declared one there is a stronger reading
        //    to be had from the same look.
        //  * for the contradicting positive reading only, the mirror of that:
        //    the transfer must have declared a digest *and* the reading must
        //    disagree with it. Either half missing and the reading contradicts
        //    nothing — see `contradiction_not_established`, which names the two
        //    cases apart because they send the caller to two different readings
        //    with opposite verdicts.
        //
        // The commitment read here is deliberately *not* `expectedEffectLocked`.
        // That one is null unless a digest was declared, and the first three
        // claims need no digest — a transfer that never declared one still
        // promised a path, and requiring a digest would leave its parked publish
        // unjudgeable, which is the wedge these variants exist to open. A
        // request with no checkpoint at all has committed to nothing and is
        // refused: there is no address to have looked at. The digest is read
        // separately, by the two arms whose rules turn on whether one exists.
        // The three arms are one arm with `inline`, because their payloads are
        // distinct anonymous struct types that happen to share the three fields
        // read here — the rules above are identical for all three and a second
        // copy of them is a second thing to keep in step.
        inline .destination_absent,
        .destination_present_unverified,
        .destination_present_contradicting,
        => |reading| {
            if (reading.verification_method.len == 0) {
                try rollback(store);
                return .{ .reading_has_no_method = .{ .evidence_kind = evidence.kindName() } };
            }
            const observed: transfers.Destination = .{
                .side = reading.side,
                .path = reading.path,
            };
            const committed = try transfers.committedDestinationLocked(store, arena, request_id);
            const same_place = if (committed) |want|
                want.side == observed.side and std.mem.eql(u8, want.path, observed.path)
            else
                false;
            if (!same_place) {
                try rollback(store);
                return .{ .absence_wrong_destination = .{
                    .observed = observed,
                    .committed = if (committed) |c| c.address() else null,
                } };
            }
            if (committed.?.state != .indeterminate_publish) {
                try rollback(store);
                return .{ .publish_not_in_question = .{
                    .observed = observed,
                    .state = committed.?.state.text(),
                } };
            }
            if (evidence == .destination_present_unverified) {
                if (try transfers.expectedEffectLocked(store, arena, request_id)) |declared| {
                    try rollback(store);
                    return .{ .unverified_reading_when_digest_declared = .{
                        .observed = observed,
                        .expected_sha256 = declared.sha256,
                    } };
                }
            }
            if (evidence == .destination_present_contradicting) {
                const read_back = evidence.destination_present_contradicting.sha256;
                const declared = try transfers.expectedEffectLocked(store, arena, request_id);
                // A contradiction needs two sides. Nothing declared and there is
                // no promise to have broken; the same digest and the promise was
                // kept. In both cases the honest reading is a different variant
                // with a different verdict, so this is refused rather than
                // resolved to the nearest thing — the difference between them is
                // `completed` and `failed`.
                const contradicts = if (declared) |want|
                    !std.mem.eql(u8, want.sha256, read_back)
                else
                    false;
                if (!contradicts) {
                    try rollback(store);
                    return .{ .contradiction_not_established = .{
                        .observed = observed,
                        .observed_sha256 = read_back,
                        .declared = if (declared) |d| d.sha256 else null,
                    } };
                }
                // Kept for the receipt. The reading alone says "the artifact
                // hashes to X"; what makes it a *contradiction* is the digest
                // this transfer committed to before it sent a byte, and a
                // receipt holding only one of the two is half the fact. It is
                // read here, off the checkpoint, rather than taken from the
                // caller — a caller echoing back a value out of this database
                // would be comparing a number with itself. See `toJson`.
                declared_sha256 = declared.?.sha256;
            }
        },
        else => {},
    }
    if (current_resolution) |existing| {
        try rollback(store);
        return .{ .already_resolved = existing };
    }
    if (current_status != .indeterminate) {
        try rollback(store);
        return .{ .not_indeterminate = current_status };
    }

    // Whether this resolution also has to say what became of an artifact, and
    // what it says. Decided before anything is written, because the two answers
    // are not both recoverable afterwards: an evidence variant that cannot
    // settle the rename must leave the ledger exactly as it found it rather
    // than resolve the operation — lifting the scope barrier — and abandon a
    // checkpoint that goes on holding its destination against everyone.
    //
    // A null id is the ordinary case and is not an error: the operation is not
    // a transfer, or its transfer never reached a rename, or the rename's
    // outcome was observed at the time and the row already records it. Nothing
    // to adjudicate is nothing to do.
    //
    // The refusal returns an error and lets the `errdefer` roll back, the way
    // `UnknownOperationKind` above does; the explicit `rollback` calls are for
    // paths that hand back a *business outcome*, where there is no error for
    // the deferred one to fire on.
    const Adjudication = struct { checkpoint_id: i64, verdict: PublishVerdict };
    var adjudication: ?Adjudication = null;
    if (try transfers.pendingPublishLocked(store, request_id)) |checkpoint_id| {
        adjudication = .{
            .checkpoint_id = checkpoint_id,
            .verdict = publishAdjudication(evidence) orelse
                return error.PublishAdjudicationUndetermined,
        };
    }

    // Serialised here rather than on the way in, because until the probe check
    // above has run there is no honest answer for `probeIdentity` — the
    // document would have to claim a binding strength before anything had been
    // compared. The same is true of `declaredSha256`, which is read off the
    // checkpoint by the contradiction check. Every refusal before this point
    // writes nothing at all, so nothing is lost by not having it earlier.
    const evidence_json = try evidence.toJson(arena, probe_binding, declared_sha256);

    var updated: i64 = 0;
    {
        // Conditional update, then verify it matched: two reconcilers racing
        // must not both believe they wrote the resolution. The status is
        // rendered from the enum rather than typed out, so renaming the variant
        // moves this guard with it instead of quietly matching no row.
        var stmt = try store.db.prepare(comptime std.fmt.comptimePrint(
            \\UPDATE operations
            \\   SET resolved_status = ?1, reconciled_at = ?2,
            \\       resolution_evidence = ?3, updated_at = ?2
            \\ WHERE request_id = ?4
            \\   AND status = '{s}'
            \\   AND resolved_status IS NULL
        , .{@tagName(op_state.Status.indeterminate)}));
        defer stmt.deinit();
        try stmt.bindText(1, resolved.text());
        try stmt.bindInt(2, now);
        try stmt.bindText(3, evidence_json);
        try stmt.bindText(4, request_id);
        _ = try stmt.step();
        updated = store.db.changes();
    }
    if (updated == 0) {
        try rollback(store);
        return .{ .already_resolved = resolved };
    }

    // `transfers` stays the sole writer of its own table; this calls its writer
    // rather than reaching into the table, so every rule that statement carries
    // — ownership, the transition list, and the evidence `published` demands —
    // applies to a resolution exactly as it applies to the transfer itself. A
    // refusal here propagates and the `errdefer` rolls the resolution back with
    // it, which is the point of doing both inside one transaction.
    if (adjudication) |verdict| try transfers.adjudicateLocked(
        store,
        verdict.checkpoint_id,
        request_id,
        verdict.verdict.to,
        verdict.verdict.reading,
        now,
    );

    const seq = try nextSeqLocked(store, request_id);
    _ = try insert(store, .{
        .request_id = request_id,
        .kind = .reconcile,
        .observed_at = now,
        .source = .reconcile,
        .status = resolved.toStatus(),
        .last_observed = op_state.Status.indeterminate.text(),
        .error_code = if (evidence.isMechanical()) null else "OPERATOR_OVERRIDE",
        .detail_json = evidence_json,
    }, false, seq);

    try store.db.exec("COMMIT");
    return .resolved;
}

/// The two columns a settlement is judged against, read in one statement.
///
/// `status` and `kind` come back together on purpose. Two statements would be
/// two readings of one row, and the pair they produced would describe no moment
/// that ever existed — a status read before a peer's terminal landed beside a
/// kind read after it. `kind` is write-once, so today only the first half can
/// move; "only one of them can change" is exactly the sort of true-for-now this
/// module refuses to build a check on, and widening the SELECT that already runs
/// costs one column.
const CurrentState = struct {
    status: op_state.Status,
    /// Parsed, never compared as text. The column carries no CHECK constraint,
    /// so a future version, a hand edit or a corrupt row can leave anything in
    /// it, and a kind this binary cannot name is one it cannot decide a matrix
    /// cell for. `resolve` refuses the same value for the same reason, and the
    /// note on its own SELECT records what text comparison cost there: an
    /// unrecognised short string matched nothing and inherited the widest permit
    /// in the table.
    kind: operations.Kind,
};

fn currentStateLocked(store: *Store, request_id: []const u8) Error!CurrentState {
    var stmt = try store.db.prepare("SELECT status, kind FROM operations WHERE request_id = ?1");
    defer stmt.deinit();
    try stmt.bindText(1, request_id);
    if (!try stmt.step()) return error.UnknownOperation;
    return .{
        .status = try op_state.Status.parse(stmt.columnText(0)),
        .kind = operations.Kind.parse(stmt.columnText(1)) catch return error.UnknownOperationKind,
    };
}

fn terminalOfLocked(store: *Store, request_id: []const u8) Error!?TerminalRecord {
    var stmt = try store.db.prepare(
        "SELECT status, observed_at, seq FROM operation_events WHERE request_id = ?1 AND is_terminal = 1",
    );
    defer stmt.deinit();
    try stmt.bindText(1, request_id);
    if (!try stmt.step()) return null;
    return .{
        .status = try op_state.Status.parse(stmt.columnText(0)),
        .observed_at = stmt.columnInt(1),
        .seq = stmt.columnInt(2),
    };
}

/// The terminal event's status/time, if the operation is settled.
pub fn terminalOf(store: *Store, request_id: []const u8) Error!?TerminalRecord {
    return terminalOfLocked(store, request_id);
}

/// Full trail for `request receipt` / `job receipt`, oldest first.
///
/// Mirrors every stored column: evidence that reaches the database but not
/// this struct is evidence a caller cannot act on, which defeats the point
/// of recording it.
pub const Row = struct {
    seq: i64,
    kind: []const u8,
    phase: ?[]const u8,
    status: ?[]const u8,
    is_terminal: bool,
    connected: ?bool,
    remote_started: ?bool,
    remote_pid: ?i64,
    remote_pgid: ?i64,
    remote_start_token: ?[]const u8,
    started_at: ?i64,
    finished_at: ?i64,
    duration_ms: ?i64,
    exit_code: ?i64,
    term_signal: ?i64,
    timed_out: ?bool,
    transport_error: ?[]const u8,
    error_code: ?[]const u8,
    /// The state the attempt was in when this event was recorded — what a
    /// reconciler navigates by.
    last_observed: ?[]const u8,
    cancel_method: ?[]const u8,
    stdin_bytes: ?i64,
    stdin_sha256: ?[]const u8,
    stdout_bytes: ?i64,
    stdout_sha256: ?[]const u8,
    stdout_truncated: ?bool,
    stdout_digest: ?[]const u8,
    stderr_bytes: ?i64,
    stderr_sha256: ?[]const u8,
    stderr_truncated: ?bool,
    stderr_digest: ?[]const u8,
    observed_at: i64,
    source: []const u8,
    correlation_id: ?[]const u8,
    detail_json: ?[]const u8,
};

pub fn list(store: *Store, arena: Allocator, request_id: []const u8) (Error || Allocator.Error)![]Row {
    var out: std.ArrayList(Row) = .empty;
    var stmt = try store.db.prepare(
        \\SELECT seq, kind, phase, status, is_terminal, connected, remote_started,
        \\       remote_pid, remote_pgid, remote_start_token,
        \\       started_at, finished_at, duration_ms, exit_code, term_signal,
        \\       timed_out, transport_error, error_code, last_observed, cancel_method,
        \\       stdin_bytes, stdin_sha256,
        \\       stdout_bytes, stdout_sha256, stdout_truncated, stdout_digest,
        \\       stderr_bytes, stderr_sha256, stderr_truncated, stderr_digest,
        \\       observed_at, source, correlation_id, detail_json
        \\FROM operation_events WHERE request_id = ?1 ORDER BY seq
    );
    defer stmt.deinit();
    try stmt.bindText(1, request_id);
    const dupOpt = struct {
        fn f(a: Allocator, v: ?[]const u8) Allocator.Error!?[]const u8 {
            return if (v) |value| try a.dupe(u8, value) else null;
        }
    }.f;
    const optFlag = struct {
        fn f(v: ?i64) ?bool {
            return if (v) |value| value != 0 else null;
        }
    }.f;
    while (try stmt.step()) {
        try out.append(arena, .{
            .seq = stmt.columnInt(0),
            .kind = try arena.dupe(u8, stmt.columnText(1)),
            .phase = try dupOpt(arena, stmt.columnOptText(2)),
            .status = try dupOpt(arena, stmt.columnOptText(3)),
            .is_terminal = stmt.columnInt(4) != 0,
            .connected = optFlag(stmt.columnOptInt(5)),
            .remote_started = optFlag(stmt.columnOptInt(6)),
            .remote_pid = stmt.columnOptInt(7),
            .remote_pgid = stmt.columnOptInt(8),
            .remote_start_token = try dupOpt(arena, stmt.columnOptText(9)),
            .started_at = stmt.columnOptInt(10),
            .finished_at = stmt.columnOptInt(11),
            .duration_ms = stmt.columnOptInt(12),
            .exit_code = stmt.columnOptInt(13),
            .term_signal = stmt.columnOptInt(14),
            .timed_out = optFlag(stmt.columnOptInt(15)),
            .transport_error = try dupOpt(arena, stmt.columnOptText(16)),
            .error_code = try dupOpt(arena, stmt.columnOptText(17)),
            .last_observed = try dupOpt(arena, stmt.columnOptText(18)),
            .cancel_method = try dupOpt(arena, stmt.columnOptText(19)),
            .stdin_bytes = stmt.columnOptInt(20),
            .stdin_sha256 = try dupOpt(arena, stmt.columnOptText(21)),
            .stdout_bytes = stmt.columnOptInt(22),
            .stdout_sha256 = try dupOpt(arena, stmt.columnOptText(23)),
            .stdout_truncated = optFlag(stmt.columnOptInt(24)),
            .stdout_digest = try dupOpt(arena, stmt.columnOptText(25)),
            .stderr_bytes = stmt.columnOptInt(26),
            .stderr_sha256 = try dupOpt(arena, stmt.columnOptText(27)),
            .stderr_truncated = optFlag(stmt.columnOptInt(28)),
            .stderr_digest = try dupOpt(arena, stmt.columnOptText(29)),
            .observed_at = stmt.columnInt(30),
            .source = try arena.dupe(u8, stmt.columnText(31)),
            .correlation_id = try dupOpt(arena, stmt.columnOptText(32)),
            .detail_json = try dupOpt(arena, stmt.columnOptText(33)),
        });
    }
    return out.toOwnedSlice(arena);
}
