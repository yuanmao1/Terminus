//! `terminus handoff <server>` — everything this machine knows about work in
//! flight on one host, with each section's own provenance attached to it.
//!
//! **The shape carries the epistemics, not just the data.** An agent picking up
//! somebody else's work has to be able to tell what it actually knows, so:
//!
//!  * `complete` is false whenever any section failed, and every failure is in
//!    `errors[]` naming the section and what the reader loses by not having it.
//!    A section that could not be read is never silently omitted from a document
//!    still claiming to be complete.
//!  * `observedAt` is **per section**, because a memory written last week and a
//!    lease renewed a second ago are not equally fresh and a single document
//!    timestamp would let a reader treat them as if they were. It names when the
//!    *freshest fact in that section* was established — not when this process
//!    read the store, which is the same instant for all six and therefore says
//!    nothing.
//!  * `source` is a `Store.receipts.Source` word, never a vocabulary of this
//!    file's own, and it is the source of the fact `observedAt` names. See
//!    `Freshest`, which makes that pairing mechanical rather than a claim.
//!
//! **Why this verb needs no host, and what that costs.** Every section is read
//! out of the local store. Five of the six describe the remote host and every
//! one of them is `cache` — a stored reading that may be stale, which is exactly
//! the arm `receipts.Source` documents as having to travel with its
//! `observed_at`. The exception is a ledger row somebody has reconciled: its
//! status was *proven* against the host, so it is `reconcile`. Nothing here is
//! ever `live` about the host, because nothing here asks the host anything.
//!
//! That is not a limitation dressed up as a design. It is what makes a handoff
//! usable at the moment it is most needed — the host is down, the session that
//! was working on it is gone, and somebody has to find out what was in flight.
//! A fully offline handoff therefore answers all six sections and **nothing
//! degrades**: there is no round trip to lose. `complete` goes false for a
//! different reason, and a real one — a store read that failed, or a row
//! carrying a word this build refuses to guess at (`error.UnknownStatus`,
//! `error.UnknownTransferState`, `error.UnknownReleaseReason`). Those refusals
//! exist all over this store precisely so a bad row cannot become a plausible
//! one, and a handoff is where they surface.
//!
//! The section that *would* degrade if this verb ever grew a round trip is
//! `jobs`: a local row saying `running` is only a claim about the past, and
//! asking the host would make it a claim about now. It is deliberately not done
//! here. `terminus job status` is that probe, it already exists, and putting it
//! in a handoff would trade the offline guarantee — the one property that makes
//! this verb worth having — for a fact one command away.
//!
//! **Why no operation row, no lease, no receipt.** A handoff reads. It sends
//! nothing anywhere: there is no executor in this file, no connection, and no
//! script. `terminus doctor` and `terminus docker` reach the same conclusion on
//! the same grounds — the ledger exists so a later session can establish whether
//! a *change* was applied, and this applies none — and a handoff is a stronger
//! case than either of them, because both of those at least make a remote call.
//! The gate at the bottom of this file holds that: this module reaches no
//! transport at all.
//!
//! The one write it does make is `leases.active`'s lazy expiry of rows whose TTL
//! has already lapsed. That is not this verb's act — it is the pass every lease
//! reader in the tree runs, and reporting a lapsed lease as held would be the
//! wrong answer rather than a conservative one.
//!
//! **Secrets.** This is a release blocker (`docs/v2.0文档.md` line 170), so it is
//! established field by field rather than asserted. Every string that enters the
//! document goes through `scrub`, which is `Store.history.redactSecrets` — the
//! sole redactor in this tree, the one that writes `operations.argv_redacted` and
//! the one extended to cover `Cookie`-style headers. Two columns are refused
//! outright rather than redacted:
//!
//!   * `jobs.command` holds the **raw** command (`cmd_job.zig` binds
//!     `raw_command` straight into `jobs.create`). `JobEntry` has no key for it.
//!     What a handoff publishes instead is `job_attempts.script_body_redacted`,
//!     which is the column that exists for this and carries the digest of the
//!     raw text beside it.
//!   * the `keys` table holds private material, and it is not merely unread —
//!     it is out of reach. This file never calls `Cli.resolveServer`, which
//!     loads key material to build an `Ssh.Auth`; it reads the server row
//!     directly through `Store.servers.getByName`, so no private byte is ever
//!     in this process's memory on account of this verb.
const std = @import("std");
const Allocator = std.mem.Allocator;
const fatal = Cli.fail;
const Cli = @import("cli.zig");
const Core = @import("../core/core.zig");
const Store = Core.Store;

/// Where an observation came from. The ledger's own vocabulary, imported rather
/// than restated: `live`, `cache`, `reconcile`, `legacy_import`, `backfill`.
const Source = Store.receipts.Source;

/// The document's own version.
///
/// **What changing it would mean.** Bumping this says a reader that understood
/// version N cannot be trusted to read version N+1 correctly — a key removed, a
/// key whose meaning moved, a section that stopped meaning what it did. Adding a
/// key does not require it, because a reader that ignores unknown keys still
/// reads every fact it knew about correctly; *renaming or reordering* one does,
/// and the key-set gate is what stops either happening silently. It is this
/// document's version and nothing else's: the store's schema version, the
/// operations ledger's `schema_version` and this number move independently, and
/// a reader must not infer one from another.
pub const schema_version: i64 = 1;

/// How many ledger rows a handoff reads, and therefore how far back the
/// `transfers` section can see. See `readTransfers`.
pub const default_limit: i64 = 50;

pub const usage =
    \\usage: terminus handoff <server> [--limit N] [--json]
    \\
    \\Everything this machine knows about work in flight on <server>: the
    \\operations ledger, jobs, transfer checkpoints, leases and memories, each
    \\with its own `source` and `observedAt`, plus the argv a caller can run to
    \\pick each item up.
    \\
    \\Reads only. No host is contacted, so a handoff works with the server down —
    \\that is the point of it. Every section that describes the host is therefore
    \\`cache`: a stored reading, dated, never a claim about right now.
    \\
    \\`complete` is false when any section could not be read; the reason is in
    \\`errors[]` under that section's name and the other sections are still
    \\carried. An incomplete handoff exits 1.
    \\
    \\--limit bounds the ledger window (default 50, newest first). The transfers
    \\section is enumerated from that window, so a narrower limit can hide an
    \\older checkpoint.
    \\
;

// --- The six sections ---------------------------------------------------------

/// The six things a handoff aggregates, as the goal names them: the ledger,
/// jobs, transfer checkpoints, leases, memories and errors.
///
/// An enum so the published section names and the code cannot drift, and so
/// `Sections` can be held against it field for field. `errors` is one of the six
/// rather than an afterthought: whether this document is trustworthy is a fact
/// about the handoff, it has a provenance of its own, and it is the only section
/// whose facts were observed by this process.
pub const Section = enum {
    ledger,
    jobs,
    transfers,
    leases,
    memories,
    errors,

    /// What a reader loses when this section could not be read. One sentence
    /// each, never a shared "a section failed": which one it is decides whether
    /// the reader may act at all.
    pub fn cost(s: Section) []const u8 {
        return switch (s) {
            .ledger => "the operations ledger could not be read, so nothing here can say which attempts are unsettled — and an unsettled writer is exactly what makes a retry unsafe. Do not act on this host until 'terminus request ls' answers",
            .jobs => "the job rows could not be read, so this document cannot say whether a background job is still live on the host. 'terminus job ls' is the same read",
            .transfers => "the transfer checkpoints could not be read, so a resumable or destination-holding transfer may exist that this document does not list. A push or pull aimed at that path will be refused rather than silently collide",
            .leases => "the leases could not be read, so this document cannot say whether a peer holds a scope. A mutation may be refused for a reason this handoff does not show",
            .memories => "the memories could not be read, so the accumulated knowledge about this host is missing from this handoff. 'terminus memory ls' is the same read",
            .errors => "the error list itself could not be assembled, which means this document cannot be trusted to report its own gaps",
        };
    }
};

/// One section's provenance.
///
/// Four fields, and `answered` is the one the other three are read through: a
/// section that could not be read has no source, no timestamp and no rows, and
/// saying so is different from being empty.
pub const Reading = struct {
    /// Whether this section was read. False means the arrays below are empty
    /// *because of a failure*, and the failure is in `errors[]`.
    answered: bool,
    /// How the fact `observedAt` names was obtained — a `Store.receipts.Source`
    /// word. Null exactly when `answered` is false: a section nobody could read
    /// has no provenance, and naming one would be an invention.
    source: ?[]const u8,
    /// When the freshest fact in this section was established. Null when the
    /// section is empty and null when it failed; `answered` tells those apart.
    observedAt: ?i64,
    count: usize,
};

/// A section that could not be read. Not a default — the only constructor for a
/// `Reading` with no provenance, so a populated section cannot accidentally
/// claim one.
const unread: Reading = .{ .answered = false, .source = null, .observedAt = null, .count = 0 };

/// The freshest fact seen so far, and where it came from.
///
/// The pairing rule the header states, as code: `source` always describes the
/// fact `observedAt` names. Two separate accumulators would let a section report
/// the timestamp of one row beside the provenance of another, which is the
/// quietest possible way to make a document lie about its own freshness.
const Freshest = struct {
    at: ?i64 = null,
    source: Source = .cache,

    fn see(f: *Freshest, at: ?i64, source: Source) void {
        const when = at orelse return;
        if (f.at == null or when > f.at.?) {
            f.at = when;
            f.source = source;
        }
    }

    fn reading(f: Freshest, count: usize) Reading {
        return .{
            .answered = true,
            .source = @tagName(f.source),
            .observedAt = f.at,
            .count = count,
        };
    }
};

/// Every section's provenance. Field for field the members of `Section`, held
/// so by the gate at the bottom of this file.
pub const Sections = struct {
    ledger: Reading,
    jobs: Reading,
    transfers: Reading,
    leases: Reading,
    memories: Reading,
    errors: Reading,
};

// --- The rows ------------------------------------------------------------------

pub const LedgerEntry = struct {
    requestId: []const u8,
    kind: []const u8,
    status: []const u8,
    resolvedStatus: ?[]const u8,
    /// What to act on: the proven truth if there is one, else what we observed.
    effectiveStatus: []const u8,
    /// Whether this attempt may still be affecting the host, so a same-scope
    /// change is unsafe without reconciling it first.
    blocksScope: bool,
    mutating: bool,
    scopeKind: ?[]const u8,
    scopeKey: ?[]const u8,
    alias: ?[]const u8,
    argvRedacted: ?[]const u8,
    argvSha256: ?[]const u8,
    cwd: ?[]const u8,
    shell: ?[]const u8,
    transport: ?[]const u8,
    createdAt: i64,
    updatedAt: i64,
    reconciledAt: ?i64,
};

/// One job, as the local store last recorded it.
///
/// **There is no `command` key and that is deliberate.** `jobs.command` holds
/// the raw command text; the redacted form lives on the attempt and is
/// `scriptRedacted` below, with `scriptSha256` beside it so "was this the script
/// that ran" still has an answer.
pub const JobEntry = struct {
    name: []const u8,
    status: []const u8,
    /// Whether this row may still correspond to something on the host.
    live: bool,
    exitCode: ?i64,
    readCursor: i64,
    ownerRequestId: ?[]const u8,
    attemptNo: ?i64,
    scriptRedacted: ?[]const u8,
    scriptSha256: ?[]const u8,
    tmuxSession: ?[]const u8,
    cwd: ?[]const u8,
    latestPhase: ?[]const u8,
    latestBusinessResult: ?[]const u8,
    sessionAlive: ?bool,
    probeCursor: ?i64,
    /// When the host was last asked about this job. Null means never — the row
    /// says what the launch said and nothing has checked it since.
    lastProbedAt: ?i64,
    createdAt: i64,
    finishedAt: ?i64,
};

pub const TransferEntry = struct {
    requestId: []const u8,
    direction: []const u8,
    state: []const u8,
    /// Whether this checkpoint still occupies its destination, so the next
    /// transfer aimed there is refused.
    holdsDestination: bool,
    /// Whether a resume can pick it up from its confirmed offset.
    resumable: bool,
    destSide: []const u8,
    destPath: []const u8,
    partialPath: []const u8,
    partialLen: i64,
    confirmedOffset: i64,
    totalBytes: ?i64,
    chunkSize: i64,
    expectedSha256: ?[]const u8,
    verifiedSha256: ?[]const u8,
    partialSha256: ?[]const u8,
    noClobber: bool,
    sourceKind: []const u8,
    /// The source's path, or an http source's url. Null for a source kind with
    /// neither, which nothing in this binary constructs today.
    sourceRef: ?[]const u8,
    failureReason: ?[]const u8,
    createdAt: i64,
    updatedAt: i64,
};

pub const LeaseEntry = struct {
    scopeKind: []const u8,
    scopeKey: []const u8,
    /// The attempt that holds it. This — and only this — is what a conflict is
    /// decided by.
    ownerRequestId: []const u8,
    /// Which machine profile the holder ran as. Audit subject only, never
    /// compared: two attempts on one machine share it.
    profileToken: []const u8,
    ownerLabel: ?[]const u8,
    note: ?[]const u8,
    acquiredAt: i64,
    renewedAt: i64,
    expiresAt: i64,
};

pub const MemoryEntry = struct {
    /// The session this memory belongs to, or null for a server-scope one.
    session: ?[]const u8,
    key: ?[]const u8,
    content: []const u8,
    tags: ?[]const u8,
    updatedAt: i64,
};

/// A section this handoff could not read.
pub const ErrorEntry = struct {
    /// A `Section` name, so a reader can match the failure to the empty section.
    section: []const u8,
    /// The refusal's own name. A word from the store's error sets, never a
    /// sentence to be parsed.
    code: []const u8,
    /// What the reader loses. `Section.cost`, so the sentence lives next to the
    /// section rather than at the throw site.
    detail: []const u8,
};

/// One thing a caller can pick up, and the argv that picks it up.
pub const ResumeEntry = struct {
    section: []const u8,
    /// What this entry is about: a request id, a job name, a destination path.
    subject: []const u8,
    /// A command line a caller can actually run, element by element. **Null
    /// means no argv here can be made honest** — and `why` says what would have
    /// to be decided by a human first. Never a plausible-looking command that
    /// would do the wrong thing.
    argv: ?[]const []const u8,
    why: []const u8,
};

// --- The document --------------------------------------------------------------

/// The published document. No defaults, so a branch that omits a key does not
/// compile — the rule `ReceiptFatalJson` states in `cli.zig`.
pub const HandoffJson = struct {
    ok: bool,
    schemaVersion: i64,
    /// False when any section failed. Never true over a section that was
    /// dropped: that is the pseudo-success this verb exists not to be.
    complete: bool,
    server: []const u8,
    workspace: ?[]const u8,
    /// The ledger window this document was built from. Published because the
    /// `transfers` section is enumerated from it.
    limit: i64,
    sections: Sections,
    ledger: []const LedgerEntry,
    jobs: []const JobEntry,
    transfers: []const TransferEntry,
    leases: []const LeaseEntry,
    memories: []const MemoryEntry,
    errors: []const ErrorEntry,
    @"resume": []const ResumeEntry,
};

/// Everything gathered, before it becomes a document.
pub const Package = struct {
    sections: Sections,
    ledger: []const LedgerEntry,
    jobs: []const JobEntry,
    transfers: []const TransferEntry,
    leases: []const LeaseEntry,
    memories: []const MemoryEntry,
    errors: []const ErrorEntry,
    resume_argv: []const ResumeEntry,

    /// Whether every section was read.
    ///
    /// Derived from the readings rather than tracked alongside them, and
    /// exhaustive over the struct's fields — so a seventh section cannot be
    /// added without this answering for it.
    pub fn complete(p: Package) bool {
        inline for (@typeInfo(Sections).@"struct".fields) |f| {
            if (!@field(p.sections, f.name).answered) return false;
        }
        return true;
    }
};

pub fn document(p: Package, server: Store.servers.Server, workspace: ?[]const u8, limit: i64) HandoffJson {
    const whole = p.complete();
    return .{
        .ok = whole,
        .schemaVersion = schema_version,
        .complete = whole,
        .server = server.name,
        .workspace = workspace,
        .limit = limit,
        .sections = p.sections,
        .ledger = p.ledger,
        .jobs = p.jobs,
        .transfers = p.transfers,
        .leases = p.leases,
        .memories = p.memories,
        .errors = p.errors,
        .@"resume" = p.resume_argv,
    };
}

// --- Redaction -----------------------------------------------------------------

/// Every string that enters the document goes through here.
///
/// `Store.history.redactSecrets` is the sole redactor in this tree: it is what
/// writes `operations.argv_redacted`, and it is the one that was extended to
/// mask `Cookie`-style headers. Applied at this boundary even to columns whose
/// writer already redacted them, and that is not distrust dressed up as defence:
/// `argv_redacted` has many writers, a handoff is a release blocker, and one
/// choke point that can be driven end to end by a gate is worth more than a rule
/// every future writer has to remember.
///
/// **What it does not do**, stated because a security claim with an unstated
/// boundary is worse than none. It is conservative and pattern-based: `NAME=…`
/// for secret-ish names, the builtin secret headers, `Bearer …`, bare `sk-…`. A
/// credential written as English prose in a memory — "the root password is
/// hunter2" — matches no pattern and is carried. That exposure is not new here
/// (`terminus memory ls` and `terminus export` print the same bytes) and it is
/// not one a redactor can close; what this verb must not do is *add* a leak, and
/// the two columns that would have been new ones are refused outright rather
/// than redacted. See the file header.
fn scrub(arena: Allocator, text: []const u8) Allocator.Error![]const u8 {
    return Store.history.redactSecrets(arena, text);
}

fn scrubOpt(arena: Allocator, text: ?[]const u8) Allocator.Error!?[]const u8 {
    return if (text) |value| try scrub(arena, value) else null;
}

// --- Gathering ------------------------------------------------------------------

const Errors = std.ArrayList(ErrorEntry);

fn note(errors: *Errors, arena: Allocator, section: Section, err: anyerror) Allocator.Error!void {
    try errors.append(arena, .{
        .section = @tagName(section),
        .code = @errorName(err),
        .detail = section.cost(),
    });
}

/// The ledger: the newest `limit` attempts on this host.
///
/// `source` is `reconcile` when the freshest fact in the section is a
/// reconciliation and `cache` otherwise, and that distinction is the one real
/// use of the vocabulary's third arm here: a reconciled row's status was proven
/// against the host, which is a different standing from what we happened to
/// believe when we last wrote the row.
fn readLedger(
    store: *Store,
    arena: Allocator,
    server_id: i64,
    limit: i64,
) !struct { entries: []const LedgerEntry, reading: Reading, rows: []Store.operations.Operation } {
    const rows = try Store.operations.recent(store, arena, server_id, limit);
    var out: std.ArrayList(LedgerEntry) = .empty;
    var fresh: Freshest = .{};
    for (rows) |op| {
        // The reconciliation is offered first when it is the newer of the two,
        // which `Freshest.see` decides by comparing them rather than by trusting
        // an ordering nothing enforces.
        fresh.see(op.updated_at, .cache);
        fresh.see(op.reconciled_at, .reconcile);
        try out.append(arena, .{
            .requestId = op.request_id,
            .kind = op.kind,
            .status = op.status.text(),
            .resolvedStatus = if (op.resolved_status) |r| @tagName(r) else null,
            .effectiveStatus = op.effectiveStatus().text(),
            .blocksScope = op.status.blocksScope() and op.resolved_status == null,
            .mutating = op.mutating,
            .scopeKind = op.scope_kind,
            .scopeKey = try scrubOpt(arena, op.scope_key),
            .alias = try scrubOpt(arena, op.alias),
            .argvRedacted = try scrubOpt(arena, op.argv_redacted),
            .argvSha256 = op.argv_sha256,
            .cwd = try scrubOpt(arena, op.cwd),
            .shell = try scrubOpt(arena, op.shell),
            .transport = op.transport,
            .createdAt = op.created_at,
            .updatedAt = op.updated_at,
            .reconciledAt = op.reconciled_at,
        });
    }
    const entries = try out.toOwnedSlice(arena);
    return .{ .entries = entries, .reading = fresh.reading(entries.len), .rows = rows };
}

/// The jobs, each with the probe that last looked at it.
///
/// `observedAt` comes from `job_probe_state.last_probed_at` — the column the
/// schema puts there for exactly this reader ("`job ls` and offline handoff read,
/// always alongside last_probed_at so a stale reading can never be mistaken for
/// a live one"). A job that has never been probed contributes its own row's
/// timestamp instead, because that is genuinely when what we know about it was
/// established: the launch said so and nothing has checked since.
fn readJobs(
    store: *Store,
    arena: Allocator,
    server_id: i64,
) !struct { entries: []const JobEntry, reading: Reading } {
    const rows = try Store.jobs.list(store, arena, server_id);
    var out: std.ArrayList(JobEntry) = .empty;
    var fresh: Freshest = .{};
    for (rows) |job| {
        var attempt: ?Store.job_attempts.Attempt = null;
        var probe: ?Store.job_attempts.ProbeState = null;
        if (job.owner_request_id) |owner| {
            attempt = try Store.job_attempts.byRequest(store, arena, owner);
            probe = try Store.job_attempts.probeState(store, arena, owner);
        }
        const probed: ?i64 = if (probe) |p| p.last_probed_at else null;
        fresh.see(probed orelse job.finished_at orelse job.created_at, .cache);
        try out.append(arena, .{
            .name = try scrub(arena, job.name),
            .status = job.status.text(),
            .live = job.status.live(),
            .exitCode = job.exit_code,
            .readCursor = job.read_cursor,
            .ownerRequestId = job.owner_request_id,
            .attemptNo = if (attempt) |a| a.attempt_no else null,
            .scriptRedacted = if (attempt) |a| try scrubOpt(arena, a.script_body_redacted) else null,
            .scriptSha256 = if (attempt) |a| a.script_sha256 else null,
            .tmuxSession = if (attempt) |a| try scrubOpt(arena, a.tmux_session) else null,
            .cwd = if (attempt) |a| try scrubOpt(arena, a.cwd) else null,
            .latestPhase = if (probe) |p| try scrubOpt(arena, p.latest_phase) else null,
            .latestBusinessResult = if (probe) |p| try scrubOpt(arena, p.latest_business_result) else null,
            .sessionAlive = if (probe) |p| p.session_alive else null,
            .probeCursor = if (probe) |p| p.probe_cursor else null,
            .lastProbedAt = probed,
            .createdAt = job.created_at,
            .finishedAt = job.finished_at,
        });
    }
    const entries = try out.toOwnedSlice(arena);
    return .{ .entries = entries, .reading = fresh.reading(entries.len) };
}

/// The transfer checkpoints belonging to the ledger rows already read.
///
/// `transfers` is keyed by request and by destination; there is no
/// list-by-server read, and this file may not add one. So the checkpoints are
/// looked up through the attempts that own them, which means **this section sees
/// only checkpoints whose operation is inside the ledger window**. That bound is
/// published — `limit` is a key of the document — rather than left for a reader
/// to discover by missing a checkpoint.
fn readTransfers(
    store: *Store,
    arena: Allocator,
    rows: []Store.operations.Operation,
) !struct { entries: []const TransferEntry, reading: Reading } {
    var out: std.ArrayList(TransferEntry) = .empty;
    var fresh: Freshest = .{};
    for (rows) |op| {
        const kind = Store.operations.Kind.parse(op.kind) catch continue;
        if (!kind.capabilities().publishes_declared_artifact) continue;
        const cp = (try Store.transfers.byRequest(store, arena, op.request_id)) orelse continue;
        fresh.see(cp.updated_at, .cache);
        var side_buf: [Store.transfers.dest_side_buf_len]u8 = undefined;
        try out.append(arena, .{
            .requestId = cp.request_id,
            .direction = @tagName(cp.direction),
            .state = cp.state.text(),
            .holdsDestination = cp.state.holdsDestination(),
            .resumable = cp.state.isAdoptable(),
            .destSide = try arena.dupe(u8, cp.dest_side.text(&side_buf)),
            .destPath = try scrub(arena, cp.dest_path),
            .partialPath = try scrub(arena, cp.partial_path),
            .partialLen = cp.partial_len,
            .confirmedOffset = cp.confirmed_offset,
            .totalBytes = cp.total_bytes,
            .chunkSize = cp.chunk_size,
            .expectedSha256 = cp.expected_sha256,
            .verifiedSha256 = cp.verified_sha256,
            .partialSha256 = cp.partial_sha256,
            .noClobber = cp.no_clobber,
            .sourceKind = cp.source.kindName(),
            .sourceRef = try scrubOpt(arena, sourceRefOf(cp.source)),
            .failureReason = try scrubOpt(arena, cp.failure_reason),
            .createdAt = cp.created_at,
            .updatedAt = cp.updated_at,
        });
    }
    const entries = try out.toOwnedSlice(arena);
    return .{ .entries = entries, .reading = fresh.reading(entries.len) };
}

/// A source's path, or an http source's url. Exhaustive with no `else`, so a
/// fourth source kind has to be answered for rather than silently reported as
/// having no reference at all.
fn sourceRefOf(source: Store.transfers.SourceIdentity) ?[]const u8 {
    return switch (source) {
        .local_file, .remote_file => |f| f.path,
        .http => |h| h.url,
    };
}

/// The leases still held, after the lazy expiry pass every lease reader runs.
///
/// `observedAt` is the newest `renewed_at`: a lease's holder proves it is still
/// there by renewing, so that timestamp is when the claim was last established.
/// `acquired_at` would date the claim's beginning, which says nothing about
/// whether anybody is still behind it.
fn readLeases(
    store: *Store,
    arena: Allocator,
    server_id: i64,
    now: i64,
) !struct { entries: []const LeaseEntry, reading: Reading } {
    const held = try Store.leases.active(store, arena, server_id, now);
    var out: std.ArrayList(LeaseEntry) = .empty;
    var fresh: Freshest = .{};
    for (held) |lease| {
        fresh.see(lease.renewed_at, .cache);
        try out.append(arena, .{
            .scopeKind = @tagName(lease.scope_kind),
            .scopeKey = try scrub(arena, lease.scope_key),
            .ownerRequestId = lease.owner_request_id,
            .profileToken = lease.profile_token,
            .ownerLabel = try scrubOpt(arena, lease.owner_label),
            .note = try scrubOpt(arena, lease.note),
            .acquiredAt = lease.acquired_at,
            .renewedAt = lease.renewed_at,
            .expiresAt = lease.expires_at,
        });
    }
    const entries = try out.toOwnedSlice(arena);
    return .{ .entries = entries, .reading = fresh.reading(entries.len) };
}

/// Every memory on this host, session-scoped ones included.
///
/// `exportAll` rather than `list`, because a session-scoped memory is knowledge
/// about this host too and the session it belongs to is what tells the reader how
/// to weigh it.
///
/// **Freshness in the goal-11 sense is not here, and no field pretends it is.**
/// The `memories` table has `created_at` and `updated_at` and nothing else: no
/// verified-at column, no `verify_cmd`. So `observedAt` is the newest
/// `updated_at` — when the note was last *written*, which is honestly all this
/// store knows — and a reader must not read it as "checked against the host
/// then". A handoff reads; it does not get to invent the column that would make
/// that claim true.
fn readMemories(
    store: *Store,
    arena: Allocator,
    server_id: i64,
) !struct { entries: []const MemoryEntry, reading: Reading } {
    const rows = try Store.memories.exportAll(store, arena, server_id);
    var out: std.ArrayList(MemoryEntry) = .empty;
    var fresh: Freshest = .{};
    for (rows) |m| {
        fresh.see(m.updated_at, .cache);
        try out.append(arena, .{
            .session = try scrubOpt(arena, m.session),
            .key = try scrubOpt(arena, m.key),
            .content = try scrub(arena, m.content),
            .tags = try scrubOpt(arena, m.tags),
            .updatedAt = m.updated_at,
        });
    }
    const entries = try out.toOwnedSlice(arena);
    return .{ .entries = entries, .reading = fresh.reading(entries.len) };
}

// --- Resume ---------------------------------------------------------------------

/// The argv a caller runs to pick each item up.
///
/// Every entry is either a command line that runs as written, or a null argv
/// with a sentence saying what a human has to decide first. There is no third
/// option, and in particular no argv that looks plausible and would do the wrong
/// thing — the two places that would have produced one are named on their arms.
fn buildResume(
    arena: Allocator,
    server: []const u8,
    ledger: []const LedgerEntry,
    jobs: []const JobEntry,
    transfers: []const TransferEntry,
    leases: []const LeaseEntry,
) Allocator.Error![]const ResumeEntry {
    var out: std.ArrayList(ResumeEntry) = .empty;

    for (ledger) |op| {
        if (!op.blocksScope) continue;
        try out.append(arena, .{
            .section = @tagName(Section.ledger),
            .subject = op.requestId,
            .argv = try argv(arena, &.{ "terminus", "request", "reconcile", op.requestId }),
            .why = "this attempt may still be affecting the host and nothing has established what it did. Until it is settled it bars a same-scope change, and a blind retry of it can apply a remote effect twice",
        });
    }

    for (jobs) |job| {
        if (!job.live) continue;
        try out.append(arena, .{
            .section = @tagName(Section.jobs),
            .subject = job.name,
            .argv = try argv(arena, &.{ "terminus", "job", "status", server, job.name }),
            .why = "the local row still calls this job live. That is a reading of the past — see lastProbedAt — and this asks the host what is true now",
        });
    }

    for (transfers) |cp| {
        if (cp.resumable) {
            // A resume needs the source and the destination in the order the
            // verb takes them, and the direction decides which is which.
            const push = std.mem.eql(u8, cp.direction, @tagName(Store.transfers.Direction.push));
            const pull = std.mem.eql(u8, cp.direction, @tagName(Store.transfers.Direction.pull));
            if ((push or pull) and cp.sourceRef != null) {
                const verb = if (push) "push" else "pull";
                // push takes <local> <remote>, pull takes <remote> <local>; in
                // both the source comes first, which is what makes one line
                // serve both.
                try out.append(arena, .{
                    .section = @tagName(Section.transfers),
                    .subject = cp.destPath,
                    .argv = try argv(arena, &.{
                        "terminus", verb, server, cp.sourceRef.?, cp.destPath, "--resume",
                    }),
                    .why = "an interrupted transfer whose checkpoint is trustworthy. --resume continues from the confirmed offset and discards nothing",
                });
                continue;
            }
            // A `fetch` is adoptable in the same states and nothing in this
            // binary constructs one, so there is no verb to name. Reported
            // rather than dropped: the checkpoint still holds the destination.
            try out.append(arena, .{
                .section = @tagName(Section.transfers),
                .subject = cp.destPath,
                .argv = null,
                .why = "this checkpoint is resumable but no command in this binary produces its direction, so there is no argv to offer. It still holds the destination",
            });
            continue;
        }
        if (!cp.holdsDestination) continue;
        if (std.mem.eql(u8, cp.state, @tagName(Store.transfers.State.indeterminate_publish))) {
            try out.append(arena, .{
                .section = @tagName(Section.transfers),
                .subject = cp.destPath,
                .argv = try argv(arena, &.{ "terminus", "request", "reconcile", cp.requestId }),
                .why = "the rename may or may not have landed, so the destination may already hold an artifact nobody has judged. This is settled by reading what is at that address, never by sending the bytes again",
            });
            continue;
        }
        // A settled failure standing on its destination. `--restart` is what
        // releases it, and it discards the partial — so this document names the
        // decision and refuses to make it.
        try out.append(arena, .{
            .section = @tagName(Section.transfers),
            .subject = cp.destPath,
            .argv = null,
            .why = "a settled failure still holds this destination, and the next transfer aimed there will be refused. Releasing it is 'terminus push|pull ... --restart', which starts over and discards the partial beside the destination; no argv is offered because that is a decision about somebody's leftovers",
        });
    }

    for (leases) |lease| {
        try out.append(arena, .{
            .section = @tagName(Section.leases),
            .subject = lease.scopeKey,
            .argv = null,
            .why = "a peer holds this scope. There is no argv that resumes work by taking somebody's live claim: --force and a takeover both override the holder, and emitting one here would be this document telling a reader to do that on the strength of a lease it read out of a cache",
        });
    }

    return out.toOwnedSlice(arena);
}

fn argv(arena: Allocator, parts: []const []const u8) Allocator.Error![]const []const u8 {
    const out = try arena.alloc([]const u8, parts.len);
    for (parts, 0..) |part, i| out[i] = try scrub(arena, part);
    return out;
}

/// Reads all six sections, letting each fail on its own.
///
/// Every section is attempted whatever the others did, and a failure lands in
/// `errors[]` with the section's name rather than removing a key from the
/// document. `transfers` is the one dependency: it is enumerated from the ledger
/// window, so a ledger that could not be read takes it down too — and it says so
/// under its own name instead of quietly reporting zero checkpoints.
pub fn gather(
    store: *Store,
    arena: Allocator,
    server_id: i64,
    server_name: []const u8,
    limit: i64,
    now: i64,
) Allocator.Error!Package {
    var errors: Errors = .empty;
    var sections: Sections = .{
        .ledger = unread,
        .jobs = unread,
        .transfers = unread,
        .leases = unread,
        .memories = unread,
        .errors = unread,
    };
    var ledger: []const LedgerEntry = &.{};
    var jobs: []const JobEntry = &.{};
    var transfers: []const TransferEntry = &.{};
    var leases: []const LeaseEntry = &.{};
    var memories: []const MemoryEntry = &.{};

    var rows: ?[]Store.operations.Operation = null;
    if (readLedger(store, arena, server_id, limit)) |got| {
        ledger = got.entries;
        sections.ledger = got.reading;
        rows = got.rows;
    } else |err| try note(&errors, arena, .ledger, err);

    if (readJobs(store, arena, server_id)) |got| {
        jobs = got.entries;
        sections.jobs = got.reading;
    } else |err| try note(&errors, arena, .jobs, err);

    if (rows) |ledger_rows| {
        if (readTransfers(store, arena, ledger_rows)) |got| {
            transfers = got.entries;
            sections.transfers = got.reading;
        } else |err| try note(&errors, arena, .transfers, err);
    } else {
        // Not silently zero. The checkpoints are reached through the attempts
        // that own them, and there are no attempts to walk.
        try note(&errors, arena, .transfers, error.LedgerWindowUnavailable);
    }

    if (readLeases(store, arena, server_id, now)) |got| {
        leases = got.entries;
        sections.leases = got.reading;
    } else |err| try note(&errors, arena, .leases, err);

    if (readMemories(store, arena, server_id)) |got| {
        memories = got.entries;
        sections.memories = got.reading;
    } else |err| try note(&errors, arena, .memories, err);

    const found = try errors.toOwnedSlice(arena);
    // The one section whose facts this process observed itself, so the one
    // section that is `live` — and `observedAt` is now, because "which sections
    // could not be read" is a fact about this run and about nothing else.
    sections.errors = .{
        .answered = true,
        .source = @tagName(Source.live),
        .observedAt = now,
        .count = found.len,
    };

    return .{
        .sections = sections,
        .ledger = ledger,
        .jobs = jobs,
        .transfers = transfers,
        .leases = leases,
        .memories = memories,
        .errors = found,
        .resume_argv = try buildResume(arena, server_name, ledger, jobs, transfers, leases),
    };
}

// --- The verb --------------------------------------------------------------------

pub fn run(ctx: *Cli.Ctx, raw_args: []const []const u8) !void {
    const parsed = Cli.parseArgs(ctx, raw_args);
    if (parsed.boolean("json")) ctx.out.format = .json;

    const server_name = parsed.positional(0) orelse fatal("{s}", .{usage});
    const limit = if (parsed.flag("limit")) |text|
        std.fmt.parseInt(i64, text, 10) catch
            fatal("invalid --limit '{s}'; it takes a whole number of ledger rows", .{text})
    else
        default_limit;
    if (limit <= 0) fatal("--limit must be at least 1; a handoff over no ledger rows would report an empty host", .{});

    var store = try Cli.openStore(ctx, &parsed);
    defer store.close();
    // `Store.servers.getByName`, not `Cli.resolveServer`: that one loads the
    // private key material to build an `Ssh.Auth`, and this verb never dials.
    // See the file header.
    const server = (Store.servers.getByName(&store, ctx.arena, server_name) catch |err|
        Cli.storeFatal(&store, err)) orelse fatal("unknown server '{s}'", .{server_name});

    const package = try gather(&store, ctx.arena, server.id, server.name, limit, ctx.now);
    const doc = document(package, server, try scrubOpt(ctx.arena, server.cwd), limit);

    switch (ctx.out.format) {
        .json => try ctx.out.json(doc),
        .human => try printHandoff(ctx, doc),
    }
    if (!doc.complete) {
        try ctx.out.flush();
        Cli.exitNow(Cli.exit_code.failure);
    }
}

fn printHandoff(ctx: *Cli.Ctx, d: HandoffJson) !void {
    try ctx.out.print("handoff:   {s} (schema {d}, complete={s})\n", .{
        d.server, d.schemaVersion, if (d.complete) "yes" else "NO",
    });
    if (d.workspace) |cwd| try ctx.out.print("workspace: {s}\n", .{cwd});
    inline for (@typeInfo(Sections).@"struct".fields) |f| {
        const r = @field(d.sections, f.name);
        if (r.answered) {
            try ctx.out.print("  {s}: {d} row(s), source {s}, observed {?d}\n", .{
                f.name, r.count, r.source orelse "-", r.observedAt,
            });
        } else {
            try ctx.out.print("  {s}: UNREAD (see errors)\n", .{f.name});
        }
    }
    for (d.errors) |e| try ctx.out.print("error [{s}] {s}: {s}\n", .{ e.section, e.code, e.detail });
    for (d.@"resume") |r| {
        if (r.argv) |line| {
            try ctx.out.print("resume [{s}] {s}:", .{ r.section, r.subject });
            for (line) |word| try ctx.out.print(" {s}", .{word});
            try ctx.out.print("\n", .{});
        } else {
            try ctx.out.print("resume [{s}] {s}: no argv — {s}\n", .{ r.section, r.subject, r.why });
        }
    }
}

test {
    _ = @import("cmd_handoff_test.zig");
}
