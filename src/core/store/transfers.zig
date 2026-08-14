//! Resumable transfer checkpoints (`transfer_checkpoints`).
//!
//! A checkpoint records *what* was being transferred, not just *where* it got
//! to. That distinction is the whole point: a partial file identified only by
//! its destination path can silently become the head of a different source.
//! Before continuing, `verifyResume` insists that
//!
//! * the source still has the identity it had — for a file, the same size,
//!   mtime and content hash; for an HTTP object, the same strong validator —
//!   and
//! * the staging partial is exactly as long as the offset we last confirmed,
//!   and its prefix hashes to what we recorded.
//!
//! Anything else fails loudly rather than restarting from zero behind the
//! caller's back — a silent restart of a 9 GiB upload is not a kindness.
//!
//! Everything here is written in *roles*, not sides: `dest_*` is wherever the
//! artifact will be published and `partial_*` is the staging file next to it,
//! which is the host for a push and this machine for a pull or a fetch. The
//! v6 table called them `remote_*`, which was true of a push and an active lie
//! about everything else — and `remote_path NOT NULL` made a locally
//! published transfer impossible to record at all.
//!
//! Offsets only ever advance to a *confirmed* position. For parallel chunked
//! transfers that means the contiguous completed prefix, never the highest
//! finished chunk: chunks 5, 6 and 7 may finish while 4 is still in flight,
//! and resuming from 8 would leave a hole. (The idea is borrowed from
//! RingIO's `SlotMarks.contiguousEnd`; the authoritative record has to live
//! here in sqlite because an in-memory mark set dies with the process.)
const std = @import("std");
const Allocator = std.mem.Allocator;
const Store = @import("Store.zig");
const Db = @import("Db.zig");

pub const schema_version: i64 = 1;

pub const Direction = enum {
    push,
    pull,
    fetch,

    pub fn parse(raw: []const u8) error{UnknownDirection}!Direction {
        return std.meta.stringToEnum(Direction, raw) orelse error.UnknownDirection;
    }
};

pub const State = enum {
    planned,
    probing,
    transferring,
    /// Interrupted but resumable: the checkpoint is trustworthy.
    paused,
    verifying,
    publishing,
    published,
    /// Bytes arrived and matched their length, but no trustworthy hash or
    /// object validator was available to prove they are the right bytes.
    /// Deliberately not `published`: size alone is not verification.
    completed_unverified,
    failed_source_changed,
    failed_remote_partial_mismatch,
    failed_hash_mismatch,
    failed_no_space,
    failed_clobber_conflict,
    failed_publish,
    /// The rename may or may not have happened. Never report this as failed.
    indeterminate_publish,

    pub fn parse(raw: []const u8) error{UnknownTransferState}!State {
        return std.meta.stringToEnum(State, raw) orelse error.UnknownTransferState;
    }

    pub fn text(s: State) []const u8 {
        return @tagName(s);
    }

    /// Live states: the transfer is still going somewhere. These are exactly
    /// the states the partial unique index in the schema covers, and the only
    /// ones `confirmOffset` will write into. Kept as one list here so the two
    /// cannot drift apart silently.
    pub fn isLive(s: State) bool {
        return switch (s) {
            .planned, .probing, .transferring, .paused => true,
            else => false,
        };
    }

    /// A settled state, from which nothing may go back to being live.
    pub fn isTerminal(s: State) bool {
        return !s.isLive();
    }

    pub fn isResumable(s: State) bool {
        return s.isLive();
    }

    pub fn isFailure(s: State) bool {
        return switch (s) {
            .failed_source_changed,
            .failed_remote_partial_mismatch,
            .failed_hash_mismatch,
            .failed_no_space,
            .failed_clobber_conflict,
            .failed_publish,
            => true,
            else => false,
        };
    }
};

/// Which machine the artifact is published on.
///
/// Not a bool and not just "remote": two pulls from *different* servers into
/// one local path are a genuine collision, and two pushes to the same path on
/// different servers are not. The server id is what tells those apart, and the
/// live-destination unique index is keyed on this text.
pub const DestSide = union(enum) {
    local,
    server: i64,

    /// Stored form: `local` or `server:<id>`. The schema CHECKs this shape.
    pub fn text(d: DestSide, buf: []u8) []const u8 {
        return switch (d) {
            .local => "local",
            .server => |id| std.fmt.bufPrint(buf, "server:{d}", .{id}) catch
                // `buf` is `dest_side_buf_len`, sized for the widest i64.
                unreachable,
        };
    }

    pub fn parse(raw: []const u8) error{UnknownDestSide}!DestSide {
        if (std.mem.eql(u8, raw, "local")) return .local;
        const prefix = "server:";
        if (!std.mem.startsWith(u8, raw, prefix)) return error.UnknownDestSide;
        const id = std.fmt.parseInt(i64, raw[prefix.len..], 10) catch
            return error.UnknownDestSide;
        return .{ .server = id };
    }

    /// Which machine a verifier has to read to see this artifact.
    ///
    /// The evidence side is coarser than the destination on purpose: an
    /// operation is bound to one server, so within a single request "remote"
    /// names exactly one machine and carrying its id again would be a second
    /// copy of a fact the operation row already holds.
    pub fn evidenceSide(d: DestSide) Side {
        return switch (d) {
            .local => .local,
            .server => .remote,
        };
    }
};

/// `server:` plus the widest i64.
pub const dest_side_buf_len = 7 + 20;

/// Identity of a file being read, captured when the transfer started.
///
/// The optional fields are what could be learned cheaply. `size` and
/// `mtime_ns` come from a stat; `sha256` is filled in while streaming, so it
/// costs nothing extra on the first pass but is absent on a checkpoint written
/// before the first byte was read.
pub const FileIdentity = struct {
    path: []const u8,
    size: ?u64 = null,
    mtime_ns: ?i128 = null,
    sha256: ?[]const u8 = null,
};

/// Identity of an HTTP source, for `fetch`. A strong validator is what makes
/// a ranged resume safe: without it the object may have changed between
/// requests and the chunks would not belong to the same file.
pub const HttpIdentity = struct {
    url: []const u8,
    etag: ?[]const u8 = null,
    last_modified: ?[]const u8 = null,
    size: ?u64 = null,
};

/// Where the bytes come from, as an exhaustive union.
///
/// It replaces `if (checkpoint.local_path != null)`, which let a remote source
/// skip the identity check entirely by having a null in the column a push
/// happens to use. A switch cannot be fallen through by being null.
pub const SourceIdentity = union(enum) {
    /// A file on this machine (a push).
    local_file: FileIdentity,
    /// A file on the host (a pull).
    remote_file: FileIdentity,
    /// An HTTP object (a fetch; not constructible until M3b).
    http: HttpIdentity,

    pub fn kindName(s: SourceIdentity) []const u8 {
        return @tagName(s);
    }

    pub fn file(s: SourceIdentity) ?FileIdentity {
        return switch (s) {
            .local_file, .remote_file => |f| f,
            .http => null,
        };
    }
};

pub const Checkpoint = struct {
    id: i64,
    request_id: []const u8,
    direction: Direction,

    dest_side: DestSide,
    dest_path: []const u8,
    partial_path: []const u8,
    partial_len: i64,
    /// Hash of the first `confirmed_offset` bytes of the partial, as we last
    /// recorded them. The schema requires it whenever the offset is non-zero.
    partial_sha256: ?[]const u8,

    source: SourceIdentity,

    chunk_size: i64,
    confirmed_offset: i64,
    total_bytes: ?i64,
    expected_sha256: ?[]const u8,
    verified_sha256: ?[]const u8,
    no_clobber: bool,
    state: State,
    failure_reason: ?[]const u8,
    created_at: i64,
    updated_at: i64,
};

pub const Error = Db.Error || error{
    UnknownDirection,
    UnknownTransferState,
    UnknownDestSide,
    /// A stored row's `source_kind` is not one this binary knows, or its
    /// columns do not carry the family that kind requires. The schema CHECKs
    /// both, so this means the row was written by something else.
    UnknownSourceKind,
    /// An mtime in nanoseconds that does not fit the column. Real only past
    /// the year 2262 — but narrowing it silently would make a source that
    /// changed look unchanged.
    MtimeOutOfRange,
    OutOfMemory,
    /// An UPDATE addressed by primary key matched no row. See `requireOneRow`.
    CheckpointRowMissing,
    /// `recordExpectedHash` was called on a transfer that had already declared
    /// a digest, or that had already started. Both mean the value it wants to
    /// write can no longer be an *advance* commitment.
    ExpectedHashLocked,
    /// `adopt` was asked to re-point a checkpoint that is no longer resumable.
    CheckpointNotResumable,
};

pub const CreateOptions = struct {
    request_id: []const u8,
    direction: Direction,
    dest_side: DestSide,
    dest_path: []const u8,
    partial_path: []const u8,
    source: SourceIdentity,
    chunk_size: i64,
    total_bytes: ?u64 = null,
    expected_sha256: ?[]const u8 = null,
    no_clobber: bool = false,
    now: i64,
};

fn narrowMtime(mtime_ns: ?i128) Error!?i64 {
    const v = mtime_ns orelse return null;
    return std.math.cast(i64, v) orelse error.MtimeOutOfRange;
}

fn optU64(v: ?u64) Error!?i64 {
    const value = v orelse return null;
    return std.math.cast(i64, value) orelse error.MtimeOutOfRange;
}

pub fn create(store: *Store, opts: CreateOptions) Error!i64 {
    var stmt = try store.db.prepare(
        \\INSERT INTO transfer_checkpoints (
        \\  request_id, schema_version, direction,
        \\  dest_side, dest_path, partial_path, partial_len,
        \\  source_kind, source_path, source_size, source_mtime_ns, source_sha256,
        \\  source_url, source_etag, source_last_modified,
        \\  chunk_size, confirmed_offset, total_bytes, expected_sha256,
        \\  no_clobber, state, created_at, updated_at
        \\) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0,
        \\          ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
        \\          ?15, 0, ?16, ?17, ?18, 'planned', ?19, ?19)
    );
    defer stmt.deinit();
    var side_buf: [dest_side_buf_len]u8 = undefined;
    try stmt.bindText(1, opts.request_id);
    try stmt.bindInt(2, schema_version);
    try stmt.bindText(3, @tagName(opts.direction));
    try stmt.bindText(4, opts.dest_side.text(&side_buf));
    try stmt.bindText(5, opts.dest_path);
    try stmt.bindText(6, opts.partial_path);
    try stmt.bindText(7, opts.source.kindName());
    switch (opts.source) {
        .local_file, .remote_file => |f| {
            try stmt.bindText(8, f.path);
            try stmt.bindOptInt(9, try optU64(f.size));
            try stmt.bindOptInt(10, try narrowMtime(f.mtime_ns));
            try stmt.bindOptText(11, f.sha256);
            try stmt.bindOptText(12, null);
            try stmt.bindOptText(13, null);
            try stmt.bindOptText(14, null);
        },
        .http => |h| {
            try stmt.bindOptText(8, null);
            try stmt.bindOptInt(9, try optU64(h.size));
            try stmt.bindOptInt(10, null);
            try stmt.bindOptText(11, null);
            try stmt.bindText(12, h.url);
            try stmt.bindOptText(13, h.etag);
            try stmt.bindOptText(14, h.last_modified);
        },
    }
    try stmt.bindInt(15, opts.chunk_size);
    try stmt.bindOptInt(16, try optU64(opts.total_bytes));
    try stmt.bindOptText(17, opts.expected_sha256);
    try stmt.bindInt(18, if (opts.no_clobber) 1 else 0);
    try stmt.bindInt(19, opts.now);
    _ = try stmt.step();
    return store.db.lastInsertRowId();
}

const select_columns =
    \\SELECT id, request_id, direction, dest_side, dest_path,
    \\       partial_path, partial_len, partial_sha256,
    \\       source_kind, source_path, source_size, source_mtime_ns, source_sha256,
    \\       source_url, source_etag, source_last_modified,
    \\       chunk_size, confirmed_offset, total_bytes,
    \\       expected_sha256, verified_sha256, no_clobber, state,
    \\       failure_reason, created_at, updated_at
    \\FROM transfer_checkpoints
;

fn dupOpt(a: Allocator, v: ?[]const u8) Allocator.Error!?[]const u8 {
    return if (v) |value| try a.dupe(u8, value) else null;
}

fn rowToCheckpoint(arena: Allocator, stmt: *Db.Stmt) Error!Checkpoint {
    const source: SourceIdentity = blk: {
        const kind = stmt.columnText(8);
        if (std.mem.eql(u8, kind, "http")) break :blk .{ .http = .{
            .url = try arena.dupe(u8, stmt.columnOptText(13) orelse return error.UnknownSourceKind),
            .etag = try dupOpt(arena, stmt.columnOptText(14)),
            .last_modified = try dupOpt(arena, stmt.columnOptText(15)),
            .size = if (stmt.columnOptInt(10)) |v| @intCast(v) else null,
        } };
        const file: FileIdentity = .{
            .path = try arena.dupe(u8, stmt.columnOptText(9) orelse return error.UnknownSourceKind),
            .size = if (stmt.columnOptInt(10)) |v| @intCast(v) else null,
            .mtime_ns = if (stmt.columnOptInt(11)) |v| @as(i128, v) else null,
            .sha256 = try dupOpt(arena, stmt.columnOptText(12)),
        };
        if (std.mem.eql(u8, kind, "local_file")) break :blk .{ .local_file = file };
        if (std.mem.eql(u8, kind, "remote_file")) break :blk .{ .remote_file = file };
        return error.UnknownSourceKind;
    };
    return .{
        .id = stmt.columnInt(0),
        .request_id = try arena.dupe(u8, stmt.columnText(1)),
        .direction = try Direction.parse(stmt.columnText(2)),
        .dest_side = try DestSide.parse(stmt.columnText(3)),
        .dest_path = try arena.dupe(u8, stmt.columnText(4)),
        .partial_path = try arena.dupe(u8, stmt.columnText(5)),
        .partial_len = stmt.columnInt(6),
        .partial_sha256 = try dupOpt(arena, stmt.columnOptText(7)),
        .source = source,
        .chunk_size = stmt.columnInt(16),
        .confirmed_offset = stmt.columnInt(17),
        .total_bytes = stmt.columnOptInt(18),
        .expected_sha256 = try dupOpt(arena, stmt.columnOptText(19)),
        .verified_sha256 = try dupOpt(arena, stmt.columnOptText(20)),
        .no_clobber = stmt.columnInt(21) != 0,
        .state = try State.parse(stmt.columnText(22)),
        .failure_reason = try dupOpt(arena, stmt.columnOptText(23)),
        .created_at = stmt.columnInt(24),
        .updated_at = stmt.columnInt(25),
    };
}

pub fn get(store: *Store, arena: Allocator, id: i64) Error!?Checkpoint {
    var stmt = try store.db.prepare(select_columns ++ " WHERE id = ?1");
    defer stmt.deinit();
    try stmt.bindInt(1, id);
    if (!try stmt.step()) return null;
    return try rowToCheckpoint(arena, &stmt);
}

/// The checkpoint for one request. At most one exists: `UNIQUE(request_id)`
/// in the schema, which is what lets this return a value rather than a choice.
pub fn byRequest(store: *Store, arena: Allocator, request_id: []const u8) Error!?Checkpoint {
    var stmt = try store.db.prepare(select_columns ++ " WHERE request_id = ?1");
    defer stmt.deinit();
    try stmt.bindText(1, request_id);
    if (!try stmt.step()) return null;
    return try rowToCheckpoint(arena, &stmt);
}

/// The live checkpoint for a destination, if any.
///
/// At most one can exist — the partial unique index over live states enforces
/// it — so this is a lookup, not a pick. Keyed on both halves of the
/// destination because a path alone does not name one: `/srv/app/out.bin` on
/// two different servers is two destinations, and `/srv/app/out.bin` here is a
/// third.
pub fn findResumable(
    store: *Store,
    arena: Allocator,
    dest_side: DestSide,
    dest_path: []const u8,
) Error!?Checkpoint {
    var stmt = try store.db.prepare(select_columns ++
        \\ WHERE dest_side = ?1 AND dest_path = ?2
        \\   AND state IN ('planned','probing','transferring','paused')
    );
    defer stmt.deinit();
    var side_buf: [dest_side_buf_len]u8 = undefined;
    try stmt.bindText(1, dest_side.text(&side_buf));
    try stmt.bindText(2, dest_path);
    if (!try stmt.step()) return null;
    return try rowToCheckpoint(arena, &stmt);
}

/// Observed state of the staging partial, as probed before resuming.
pub const PartialObservation = struct {
    exists: bool,
    len: u64 = 0,
    /// Hash of the first `confirmed_offset` bytes, when we asked for it.
    prefix_sha256: ?[]const u8 = null,
};

pub const ResumeVerdict = union(enum) {
    /// Safe to continue from this offset, and the partial is already exactly
    /// this long.
    resume_from: u64,
    /// Safe to continue from `offset`, but the partial is longer than that and
    /// must be truncated back to it first. The extra bytes were written and
    /// never confirmed — normal after a cut mid-write — and they are not
    /// evidence of anything, so they are discarded rather than counted.
    /// Truncating before the prefix is proven would destroy the only thing
    /// that could have proven it, hence the order: prove, then cut.
    truncate_then_resume: struct {
        offset: u64,
        /// What the partial is now, for the message when the truncate fails.
        partial_len: u64,
    },
    /// Nothing usable at the destination; start over (not an error).
    start_over,
    /// The source is not the one this checkpoint describes.
    source_changed: []const u8,
    /// The staging partial does not match what we confirmed.
    partial_mismatch: []const u8,
};

/// Decides whether a checkpoint may be resumed. Pure, so the rules are
/// testable without a network or a filesystem.
pub fn verifyResume(
    checkpoint: Checkpoint,
    observed_source: ?SourceIdentity,
    partial: PartialObservation,
) ResumeVerdict {
    if (sourceChanged(checkpoint.source, observed_source)) |why|
        return .{ .source_changed = why };

    const confirmed: u64 = @intCast(@max(checkpoint.confirmed_offset, 0));

    // Nothing staged: a fresh start is correct, and only correct because we
    // just proved the source is unchanged.
    if (!partial.exists) return if (confirmed == 0) .start_over else .{
        .partial_mismatch = "the staging partial disappeared after bytes were confirmed",
    };

    // Shorter than our confirmed offset means bytes we had counted are gone —
    // nothing there can be trusted as a prefix of what we sent.
    if (partial.len < confirmed) return .{ .partial_mismatch = "the staging partial is shorter than the confirmed offset" };

    // Length is not content. Any resume from a non-zero offset appends to
    // bytes we are about to stop looking at, so those bytes must be proven,
    // not counted: a partial of exactly the right length can be a different
    // file, a half-written retry, or another writer's work. Both the recorded
    // hash and the observed one must exist and agree — an equal length with
    // no hash used to be enough, which meant the strictness below only ever
    // applied to the interrupted case and never to the clean-looking one.
    if (confirmed > 0) {
        const recorded = checkpoint.partial_sha256 orelse
            return .{ .partial_mismatch = "no prefix hash was recorded for the bytes already confirmed, so they cannot be proven to be ours" };
        const observed = partial.prefix_sha256 orelse
            return .{ .partial_mismatch = "the partial's prefix hash was not read back for comparison" };
        if (!std.mem.eql(u8, recorded, observed))
            return .{ .partial_mismatch = "the staging partial's content does not match the checkpoint" };
    }

    // Longer is the *normal* shape of an interruption, not a fault: the writer
    // confirms an offset only after the far side acknowledges it, so a cut
    // mid-write leaves bytes there that were never confirmed. Rejecting this
    // outright — as this function used to — made resume unreachable in exactly
    // the case resume exists for.
    //
    // Those unconfirmed bytes still prove nothing, so they are not counted and
    // not trusted; the head was proven just above, and only that licenses
    // cutting the tail away. Proving first is the whole ordering.
    if (partial.len > confirmed) return .{ .truncate_then_resume = .{
        .offset = confirmed,
        .partial_len = partial.len,
    } };
    return .{ .resume_from = confirmed };
}

/// Why the source is not the one the checkpoint was written against, or null.
///
/// Exhaustive over the source union and over the *pairing*: a checkpoint that
/// recorded a local file cannot be re-proved by observing a remote one, even
/// at the same path, because the two are different machines' idea of that
/// path.
fn sourceChanged(recorded: SourceIdentity, observed_opt: ?SourceIdentity) ?[]const u8 {
    const observed = observed_opt orelse return "the source is gone";
    if (std.meta.activeTag(recorded) != std.meta.activeTag(observed))
        return "the source is a different kind of thing than the checkpoint recorded";

    switch (recorded) {
        .local_file, .remote_file => {
            const was = recorded.file().?;
            const now = observed.file().?;
            if (!std.mem.eql(u8, was.path, now.path)) return "the source path changed";
            if (was.size) |recorded_size| {
                const current = now.size orelse return "the source size is unavailable for comparison";
                if (current != recorded_size) return "the source size changed";
            }
            if (was.mtime_ns) |recorded_mtime| {
                const current = now.mtime_ns orelse return "the source mtime is unavailable for comparison";
                if (current != recorded_mtime) return "the source mtime changed";
            }
            if (was.sha256) |recorded_hash| {
                const current = now.sha256 orelse return "the source hash is unavailable for comparison";
                if (!std.mem.eql(u8, recorded_hash, current)) return "the source content changed";
            }
            return null;
        },
        .http => |was| {
            const now = observed.http;
            if (!std.mem.eql(u8, was.url, now.url)) return "the source URL changed";
            // A ranged resume splices bytes fetched at two different moments
            // into one file. Only a strong validator says those moments saw
            // the same object; a matching size says the second one is the same
            // length, which is not the same claim.
            const recorded_tag = was.etag orelse was.last_modified orelse
                return "the source offered no validator when the transfer started, so a ranged resume cannot be proven safe";
            const current_tag = now.etag orelse now.last_modified orelse
                return "the source no longer offers a validator";
            if (!std.mem.eql(u8, recorded_tag, current_tag)) return "the source validator changed";
            return null;
        },
    }
}

/// Advances the confirmed offset. `offset` must be the end of the contiguous
/// completed prefix, never the highest finished chunk.
///
/// Three guards, each of which used to be the caller's problem:
///
/// * `?1 >= confirmed_offset` — a regressing offset matches no row. A late
///   reply from an earlier chunk could otherwise walk the durable offset
///   backwards, and the next resume would re-send bytes it had confirmed, or
///   worse, trust a prefix hash taken at the higher offset.
/// * the live-state list — a settled checkpoint cannot be advanced. Writing
///   progress into a failed or published row would make it resumable again.
/// * `requireOneRow` — a zero-row match is a refusal, not a shrug.
///
/// The prefix hash is a plain assignment, not a `COALESCE`. Under COALESCE, a
/// caller passing null kept the *previous* offset's hash while the offset
/// moved on, so the pair stopped describing the same bytes — and that pair is
/// exactly what `verifyResume` compares. The schema now refuses the null
/// outright whenever the offset is non-zero.
pub fn confirmOffset(
    store: *Store,
    id: i64,
    offset: u64,
    partial_len: u64,
    prefix_sha256: ?[]const u8,
    now: i64,
) Error!void {
    var stmt = try store.db.prepare(
        \\UPDATE transfer_checkpoints
        \\   SET confirmed_offset = ?1, partial_len = ?2,
        \\       partial_sha256 = ?3, updated_at = ?4
        \\ WHERE id = ?5 AND ?1 >= confirmed_offset
        \\   AND state IN ('planned','probing','transferring','paused')
    );
    defer stmt.deinit();
    try stmt.bindInt(1, @intCast(offset));
    try stmt.bindInt(2, @intCast(partial_len));
    try stmt.bindOptText(3, prefix_sha256);
    try stmt.bindInt(4, now);
    try stmt.bindInt(5, id);
    _ = try stmt.step();
    try requireOneRow(store, "confirmOffset");
}

/// Moves a checkpoint to a new state.
///
/// A terminal state is final: `state IN (...)` admits only the live states as
/// a *starting* point, so nothing can bring a published, failed or
/// indeterminate checkpoint back to life. That matters because the live states
/// are what the destination unique index covers — reviving a settled row would
/// silently re-enter the set that is supposed to hold one transfer per
/// destination, and could collide with the transfer that replaced it.
///
/// Re-entering the same live state is allowed: the probe → transferring →
/// paused walk revisits states, and a caller that has to remember whether a
/// transition is a repeat is a caller that will get it wrong.
pub fn setState(store: *Store, id: i64, state: State, failure_reason: ?[]const u8, now: i64) Error!void {
    var stmt = try store.db.prepare(
        \\UPDATE transfer_checkpoints
        \\   SET state = ?1, failure_reason = ?2, updated_at = ?3
        \\ WHERE id = ?4
        \\   AND state IN ('planned','probing','transferring','paused')
    );
    defer stmt.deinit();
    try stmt.bindText(1, state.text());
    try stmt.bindOptText(2, failure_reason);
    try stmt.bindInt(3, now);
    try stmt.bindInt(4, id);
    _ = try stmt.step();
    try requireOneRow(store, "setState");
}

/// Re-points a resumable checkpoint at the operation that is resuming it.
///
/// A resume is a new operation with a new `request_id`, and `UNIQUE(request_id)`
/// means the row cannot simply be copied. The checkpoint is a mutable working
/// record — it tracks where the bytes got to — while the ledger is the audit
/// trail, so moving it is correct and losing the trail would not be: the
/// caller writes a `checkpoint` observation on both operations naming the
/// other.
///
/// Refuses a settled checkpoint. Adopting one would hand a new operation an
/// offset into a partial that the failure already declared untrustworthy.
pub fn adopt(store: *Store, id: i64, new_request_id: []const u8, now: i64) Error!void {
    var stmt = try store.db.prepare(
        \\UPDATE transfer_checkpoints
        \\   SET request_id = ?1, updated_at = ?2
        \\ WHERE id = ?3
        \\   AND state IN ('planned','probing','transferring','paused')
    );
    defer stmt.deinit();
    try stmt.bindText(1, new_request_id);
    try stmt.bindInt(2, now);
    try stmt.bindInt(3, id);
    _ = try stmt.step();
    if (store.db.changes() == 0) return error.CheckpointNotResumable;
}

/// Which side of the connection a transfer's destination is on.
///
/// A push lands on the host; a pull and a fetch land here. The distinction
/// matters to whoever verifies the result — reading `/srv/app/out.bin` locally
/// to prove a push would prove nothing about the host.
pub const Side = enum { local, remote };

/// What a published-file hash has to match to settle this transfer.
pub const ExpectedEffect = struct {
    side: Side,
    path: []const u8,
    sha256: []const u8,
};

/// The commitment this transfer made before it sent anything.
///
/// Read by `receipts.resolve`, inside that module's transaction, to decide
/// whether a published-file hash may settle this operation. Null means the
/// transfer never declared one — in which case no observed digest can prove
/// anything, because there is nothing it could have been checked against.
///
/// Refuses to choose when a request somehow has more than one checkpoint
/// carrying a digest. `UNIQUE(request_id)` makes that unreachable from v11
/// onwards; the check stays because taking the newest would mean a
/// scope-releasing decision made by `ORDER BY id DESC`, and a constraint the
/// code silently relies on is worth restating where the reliance is.
pub fn expectedEffectLocked(
    store: *Store,
    arena: Allocator,
    request_id: []const u8,
) (Db.Error || Allocator.Error || error{ AmbiguousCheckpoint, UnknownDestSide })!?ExpectedEffect {
    var stmt = try store.db.prepare(
        \\SELECT dest_side, dest_path, expected_sha256
        \\  FROM transfer_checkpoints
        \\ WHERE request_id = ?1 AND expected_sha256 IS NOT NULL
    );
    defer stmt.deinit();
    try stmt.bindText(1, request_id);
    if (!try stmt.step()) return null;

    const dest = try DestSide.parse(stmt.columnText(0));
    const found: ExpectedEffect = .{
        .side = dest.evidenceSide(),
        .path = try arena.dupe(u8, stmt.columnText(1)),
        .sha256 = try arena.dupe(u8, stmt.columnText(2)),
    };
    if (try stmt.step()) return error.AmbiguousCheckpoint;
    return found;
}

/// Declares, in advance, which digest would prove this transfer landed.
///
/// Write-once, and only before the operation submits — both enforced here, in
/// one statement, rather than left to the caller's ordering. A comment saying
/// "call this first" is not a guarantee: with a plain UPDATE this could be
/// written after `submitted`, after `indeterminate`, or over an existing
/// value, and each of those reopens the laundering hole it exists to close.
/// The dangerous one is the last: read the destination file, write its hash in
/// as the "advance commitment", then present that same hash as proof. The
/// comparison would pass and mean nothing.
///
/// `created` and `connecting` are the two states in which nothing has been
/// sent, so a digest recorded then cannot have been derived from the result.
/// A caller that gets `error.ExpectedHashLocked` has either already declared
/// one or has already started, and neither is retryable by trying harder.
pub fn recordExpectedHash(store: *Store, id: i64, sha256: []const u8, now: i64) Error!void {
    var stmt = try store.db.prepare(
        \\UPDATE transfer_checkpoints
        \\   SET expected_sha256 = ?1, updated_at = ?2
        \\ WHERE id = ?3
        \\   AND expected_sha256 IS NULL
        \\   AND request_id IN (
        \\         SELECT request_id FROM operations
        \\          WHERE status IN ('created','connecting')
        \\       )
    );
    defer stmt.deinit();
    try stmt.bindText(1, sha256);
    try stmt.bindInt(2, now);
    try stmt.bindInt(3, id);
    _ = try stmt.step();
    if (store.db.changes() == 0) return error.ExpectedHashLocked;
}

/// Fails when an UPDATE matched nothing.
///
/// Every write here is addressed by a primary key the caller is holding, so a
/// zero-row UPDATE means the row is gone, the id is wrong, or a guard in the
/// WHERE clause rejected the write. All three are real failures, and all three
/// used to return success: `_ = try stmt.step()` reports that the statement
/// ran, not that it changed anything. On a durable checkpoint that silence is
/// the difference between "the offset advanced" and "we believe the offset
/// advanced" — and the second one resumes from the wrong place.
fn requireOneRow(store: *Store, what: []const u8) Error!void {
    if (store.db.changes() == 0) {
        std.debug.print("terminus: checkpoint write '{s}' matched no row\n", .{what});
        return error.CheckpointRowMissing;
    }
}

pub fn recordVerifiedHash(store: *Store, id: i64, sha256: []const u8, now: i64) Error!void {
    var stmt = try store.db.prepare(
        "UPDATE transfer_checkpoints SET verified_sha256 = ?1, updated_at = ?2 WHERE id = ?3",
    );
    defer stmt.deinit();
    try stmt.bindText(1, sha256);
    try stmt.bindInt(2, now);
    try stmt.bindInt(3, id);
    _ = try stmt.step();
    try requireOneRow(store, "recordVerifiedHash");
}

/// End of the contiguous completed prefix, given which chunks finished.
///
/// Parallel chunks complete out of order, so the durable offset may only
/// advance past chunk N once every chunk before it is done. Returning the
/// highest completed chunk instead would leave a hole that a later resume
/// would skip.
pub fn contiguousPrefix(done: []const bool, chunk_size: u64, total: u64) u64 {
    var complete: u64 = 0;
    for (done) |finished| {
        if (!finished) break;
        complete += 1;
    }
    return @min(complete * chunk_size, total);
}

test contiguousPrefix {
    const t = std.testing;
    // Chunks 0,1 done; 2 still running; 3,4 finished early.
    const done = [_]bool{ true, true, false, true, true };
    // Offset stops at the gap, not at the highest finished chunk.
    try t.expectEqual(@as(u64, 200), contiguousPrefix(&done, 100, 500));

    try t.expectEqual(@as(u64, 0), contiguousPrefix(&[_]bool{ false, true }, 100, 200));
    try t.expectEqual(@as(u64, 500), contiguousPrefix(&[_]bool{ true, true, true, true, true }, 100, 500));
    // A short final chunk must not push the offset past the real length.
    try t.expectEqual(@as(u64, 250), contiguousPrefix(&[_]bool{ true, true, true }, 100, 250));
}

test "DestSide round-trips, and refuses anything it did not write" {
    const t = std.testing;
    var buf: [dest_side_buf_len]u8 = undefined;
    try t.expectEqualStrings("local", DestSide.text(.local, &buf));
    try t.expectEqualStrings("server:12", DestSide.text(.{ .server = 12 }, &buf));
    try t.expectEqual(DestSide.local, try DestSide.parse("local"));
    try t.expectEqual(@as(i64, 12), (try DestSide.parse("server:12")).server);
    // The widest id still fits the buffer `text` promises is enough.
    try t.expectEqualStrings(
        "server:-9223372036854775808",
        DestSide.text(.{ .server = std.math.minInt(i64) }, &buf),
    );
    try t.expectError(error.UnknownDestSide, DestSide.parse("remote"));
    try t.expectError(error.UnknownDestSide, DestSide.parse("server:"));
    try t.expectError(error.UnknownDestSide, DestSide.parse("server:abc"));

    // A push is proved on the host, a pull and a fetch here.
    try t.expectEqual(Side.remote, DestSide.evidenceSide(.{ .server = 3 }));
    try t.expectEqual(Side.local, DestSide.evidenceSide(.local));
}

fn testCheckpoint() Checkpoint {
    return .{
        .id = 1,
        .request_id = "01ABCDEFGH0123456789ABCDEF",
        .direction = .push,
        .dest_side = .{ .server = 1 },
        .dest_path = "/srv/big.bin",
        .partial_path = "/srv/big.bin.terminus-part",
        .partial_len = 400,
        .partial_sha256 = "bbbb",
        .source = .{ .local_file = .{
            .path = "./big.bin",
            .size = 1000,
            .mtime_ns = 42,
            .sha256 = "aaaa",
        } },
        .chunk_size = 100,
        .confirmed_offset = 400,
        .total_bytes = 1000,
        .expected_sha256 = "aaaa",
        .verified_sha256 = null,
        .no_clobber = false,
        .state = .paused,
        .failure_reason = null,
        .created_at = 1,
        .updated_at = 2,
    };
}

fn unchangedSource() SourceIdentity {
    return .{ .local_file = .{
        .path = "./big.bin",
        .size = 1000,
        .mtime_ns = 42,
        .sha256 = "aaaa",
    } };
}

test "verifyResume accepts an unchanged source and matching partial" {
    const t = std.testing;
    const verdict = verifyResume(
        testCheckpoint(),
        unchangedSource(),
        .{ .exists = true, .len = 400, .prefix_sha256 = "bbbb" },
    );
    try t.expectEqual(@as(u64, 400), verdict.resume_from);
}

test "verifyResume refuses a changed source" {
    const t = std.testing;

    // Same size and mtime, different content: caught by the hash.
    try t.expect(verifyResume(testCheckpoint(), .{ .local_file = .{
        .path = "./big.bin",
        .size = 1000,
        .mtime_ns = 42,
        .sha256 = "zzzz",
    } }, .{ .exists = true, .len = 400, .prefix_sha256 = "bbbb" }) == .source_changed);

    // Rewritten in place: mtime moves.
    try t.expect(verifyResume(testCheckpoint(), .{ .local_file = .{
        .path = "./big.bin",
        .size = 1000,
        .mtime_ns = 99,
        .sha256 = "aaaa",
    } }, .{ .exists = true, .len = 400, .prefix_sha256 = "bbbb" }) == .source_changed);

    // Truncated or appended.
    try t.expect(verifyResume(testCheckpoint(), .{ .local_file = .{
        .path = "./big.bin",
        .size = 900,
        .mtime_ns = 42,
        .sha256 = "aaaa",
    } }, .{ .exists = true, .len = 400, .prefix_sha256 = "bbbb" }) == .source_changed);

    // A different path entirely, offered under the same identity.
    try t.expect(verifyResume(testCheckpoint(), .{ .local_file = .{
        .path = "./other.bin",
        .size = 1000,
        .mtime_ns = 42,
        .sha256 = "aaaa",
    } }, .{ .exists = true, .len = 400, .prefix_sha256 = "bbbb" }) == .source_changed);

    // The same path on the *other* machine. Identical bytes would still be a
    // different file, and the old `local_path != null` gate let this through
    // by not being a check at all.
    try t.expect(verifyResume(testCheckpoint(), .{ .remote_file = .{
        .path = "./big.bin",
        .size = 1000,
        .mtime_ns = 42,
        .sha256 = "aaaa",
    } }, .{ .exists = true, .len = 400, .prefix_sha256 = "bbbb" }) == .source_changed);

    // Observed, but with nothing to compare against: silence is not a match.
    try t.expect(verifyResume(testCheckpoint(), .{ .local_file = .{
        .path = "./big.bin",
    } }, .{ .exists = true, .len = 400, .prefix_sha256 = "bbbb" }) == .source_changed);

    // Source gone entirely.
    try t.expect(verifyResume(testCheckpoint(), null, .{ .exists = true, .len = 400 }) == .source_changed);
}

test "verifyResume will not resume an HTTP source without a stable validator" {
    const t = std.testing;
    var checkpoint = testCheckpoint();
    checkpoint.direction = .fetch;
    checkpoint.dest_side = .local;

    // Recorded with a strong validator, and it still holds.
    checkpoint.source = .{ .http = .{ .url = "https://h/f.bin", .etag = "W1" } };
    try t.expectEqual(@as(u64, 400), verifyResume(
        checkpoint,
        .{ .http = .{ .url = "https://h/f.bin", .etag = "W1" } },
        .{ .exists = true, .len = 400, .prefix_sha256 = "bbbb" },
    ).resume_from);

    // The object moved on.
    try t.expect(verifyResume(
        checkpoint,
        .{ .http = .{ .url = "https://h/f.bin", .etag = "W2" } },
        .{ .exists = true, .len = 400, .prefix_sha256 = "bbbb" },
    ) == .source_changed);

    // Same size, no validator either then or now. Size is not identity: a
    // ranged resume splices two moments together, and only a validator says
    // they saw the same object.
    checkpoint.source = .{ .http = .{ .url = "https://h/f.bin", .size = 1000 } };
    try t.expect(verifyResume(
        checkpoint,
        .{ .http = .{ .url = "https://h/f.bin", .size = 1000 } },
        .{ .exists = true, .len = 400, .prefix_sha256 = "bbbb" },
    ) == .source_changed);
}

test "verifyResume refuses a mismatched partial" {
    const t = std.testing;
    const source = unchangedSource();

    // The far side lost bytes we had counted.
    try t.expect(verifyResume(testCheckpoint(), source, .{ .exists = true, .len = 300, .prefix_sha256 = "bbbb" }) == .partial_mismatch);
    // Right length, wrong content.
    try t.expect(verifyResume(testCheckpoint(), source, .{ .exists = true, .len = 400, .prefix_sha256 = "cccc" }) == .partial_mismatch);
    // Longer than confirmed AND the confirmed head does not check out: the
    // tail cannot be discarded on the strength of a head we just disproved.
    try t.expect(verifyResume(testCheckpoint(), source, .{ .exists = true, .len = 500, .prefix_sha256 = "cccc" }) == .partial_mismatch);
    // Nothing recorded to check the head against, at either length. Length is
    // not content: a partial of exactly the confirmed size can be a different
    // file or a half-written retry, and appending to it would splice two
    // sources together into something whose hash matches neither.
    var no_hash = testCheckpoint();
    no_hash.partial_sha256 = null;
    try t.expect(verifyResume(no_hash, source, .{ .exists = true, .len = 500, .prefix_sha256 = "bbbb" }) == .partial_mismatch);
    try t.expect(verifyResume(no_hash, source, .{ .exists = true, .len = 400, .prefix_sha256 = "bbbb" }) == .partial_mismatch);
    // Recorded but not observed: we asked and the far side did not tell us.
    try t.expect(verifyResume(testCheckpoint(), source, .{ .exists = true, .len = 400, .prefix_sha256 = null }) == .partial_mismatch);
    // Partial vanished after we had confirmed progress: not a clean restart.
    try t.expect(verifyResume(testCheckpoint(), source, .{ .exists = false }) == .partial_mismatch);
}

test "verifyResume resumes past unconfirmed bytes, after proving the head" {
    const t = std.testing;
    const source = unchangedSource();

    // The ordinary shape of an interruption: the writer confirms an offset
    // only once the far side acknowledges it, so a cut mid-write leaves more
    // bytes there than were ever confirmed. Refusing this outright — which
    // this function used to do — made resume unreachable in the one case it
    // exists for, and every real resume would have restarted at zero.
    const verdict = verifyResume(testCheckpoint(), source, .{
        .exists = true,
        .len = 500,
        .prefix_sha256 = "bbbb",
    });
    try t.expectEqual(@as(u64, 400), verdict.truncate_then_resume.offset);
    try t.expectEqual(@as(u64, 500), verdict.truncate_then_resume.partial_len);

    // Exactly as long as confirmed needs no truncation at all.
    try t.expectEqual(@as(u64, 400), verifyResume(testCheckpoint(), source, .{
        .exists = true,
        .len = 400,
        .prefix_sha256 = "bbbb",
    }).resume_from);
}

test "verifyResume allows a clean start when nothing was confirmed yet" {
    const t = std.testing;
    var checkpoint = testCheckpoint();
    checkpoint.confirmed_offset = 0;
    checkpoint.partial_len = 0;
    checkpoint.partial_sha256 = null;
    const verdict = verifyResume(checkpoint, unchangedSource(), .{ .exists = false });
    try t.expect(verdict == .start_over);
}
