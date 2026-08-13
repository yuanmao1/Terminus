//! Resumable transfer checkpoints (`transfer_checkpoints`).
//!
//! A checkpoint records *what* was being transferred, not just *where* it got
//! to. That distinction is the whole point: a partial file identified only by
//! its destination path can silently become the head of a different source.
//! Before continuing, `verifyResume` insists that
//!
//! * the local source still has the same size, mtime and content hash, and
//! * the remote partial is exactly as long as the offset we last confirmed,
//!   and its prefix hashes to what we recorded.
//!
//! Anything else fails loudly rather than restarting from zero behind the
//! caller's back — a silent restart of a 9 GiB upload is not a kindness.
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

    pub fn isResumable(s: State) bool {
        return switch (s) {
            .planned, .probing, .transferring, .paused => true,
            else => false,
        };
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

/// Identity of a local source file, captured when the transfer started.
pub const LocalIdentity = struct {
    path: []const u8,
    size: u64,
    mtime_ns: i128,
    /// Whole-file hash. Computed incrementally while streaming, so it costs
    /// nothing extra on the first pass.
    sha256: ?[]const u8 = null,
};

/// Identity of an HTTP source, for `fetch`. A strong validator is what makes
/// a ranged resume safe: without it the object may have changed between
/// requests and the chunks would not belong to the same file.
pub const RemoteSourceIdentity = struct {
    url: []const u8,
    etag: ?[]const u8 = null,
    last_modified: ?[]const u8 = null,
    size: ?u64 = null,
};

pub const Checkpoint = struct {
    id: i64,
    request_id: []const u8,
    direction: Direction,
    local_path: ?[]const u8,
    local_size: ?i64,
    local_mtime_ns: ?i64,
    local_sha256: ?[]const u8,
    source_url: ?[]const u8,
    source_etag: ?[]const u8,
    source_last_modified: ?[]const u8,
    source_size: ?i64,
    remote_path: []const u8,
    remote_partial_path: []const u8,
    remote_partial_len: i64,
    remote_partial_sha256: ?[]const u8,
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

pub const Error = Db.Error || error{ UnknownDirection, UnknownTransferState, OutOfMemory };

pub const CreateOptions = struct {
    request_id: []const u8,
    direction: Direction,
    remote_path: []const u8,
    remote_partial_path: []const u8,
    chunk_size: i64,
    total_bytes: ?u64 = null,
    expected_sha256: ?[]const u8 = null,
    no_clobber: bool = false,
    local: ?LocalIdentity = null,
    source: ?RemoteSourceIdentity = null,
    now: i64,
};

pub fn create(store: *Store, opts: CreateOptions) Error!i64 {
    var stmt = try store.db.prepare(
        \\INSERT INTO transfer_checkpoints (
        \\  request_id, schema_version, direction,
        \\  local_path, local_size, local_mtime_ns, local_sha256,
        \\  source_url, source_etag, source_last_modified, source_size,
        \\  remote_path, remote_partial_path, remote_partial_len,
        \\  chunk_size, confirmed_offset, total_bytes, expected_sha256,
        \\  no_clobber, state, created_at, updated_at
        \\) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
        \\          ?12, ?13, 0, ?14, 0, ?15, ?16, ?17, 'planned', ?18, ?18)
    );
    defer stmt.deinit();
    try stmt.bindText(1, opts.request_id);
    try stmt.bindInt(2, schema_version);
    try stmt.bindText(3, @tagName(opts.direction));
    try stmt.bindOptText(4, if (opts.local) |l| l.path else null);
    try stmt.bindOptInt(5, if (opts.local) |l| @as(i64, @intCast(l.size)) else null);
    try stmt.bindOptInt(6, if (opts.local) |l| @as(i64, @intCast(@divTrunc(l.mtime_ns, 1))) else null);
    try stmt.bindOptText(7, if (opts.local) |l| l.sha256 else null);
    try stmt.bindOptText(8, if (opts.source) |s| s.url else null);
    try stmt.bindOptText(9, if (opts.source) |s| s.etag else null);
    try stmt.bindOptText(10, if (opts.source) |s| s.last_modified else null);
    try stmt.bindOptInt(11, if (opts.source) |s| (if (s.size) |v| @as(i64, @intCast(v)) else null) else null);
    try stmt.bindText(12, opts.remote_path);
    try stmt.bindText(13, opts.remote_partial_path);
    try stmt.bindInt(14, opts.chunk_size);
    try stmt.bindOptInt(15, if (opts.total_bytes) |v| @as(i64, @intCast(v)) else null);
    try stmt.bindOptText(16, opts.expected_sha256);
    try stmt.bindInt(17, if (opts.no_clobber) 1 else 0);
    try stmt.bindInt(18, opts.now);
    _ = try stmt.step();
    return store.db.lastInsertRowId();
}

const select_columns =
    \\SELECT id, request_id, direction, local_path, local_size, local_mtime_ns,
    \\       local_sha256, source_url, source_etag, source_last_modified,
    \\       source_size, remote_path, remote_partial_path, remote_partial_len,
    \\       remote_partial_sha256, chunk_size, confirmed_offset, total_bytes,
    \\       expected_sha256, verified_sha256, no_clobber, state,
    \\       failure_reason, created_at, updated_at
    \\FROM transfer_checkpoints
;

fn rowToCheckpoint(arena: Allocator, stmt: *Db.Stmt) Error!Checkpoint {
    const dupOpt = struct {
        fn f(a: Allocator, v: ?[]const u8) Allocator.Error!?[]const u8 {
            return if (v) |value| try a.dupe(u8, value) else null;
        }
    }.f;
    return .{
        .id = stmt.columnInt(0),
        .request_id = try arena.dupe(u8, stmt.columnText(1)),
        .direction = try Direction.parse(stmt.columnText(2)),
        .local_path = try dupOpt(arena, stmt.columnOptText(3)),
        .local_size = stmt.columnOptInt(4),
        .local_mtime_ns = stmt.columnOptInt(5),
        .local_sha256 = try dupOpt(arena, stmt.columnOptText(6)),
        .source_url = try dupOpt(arena, stmt.columnOptText(7)),
        .source_etag = try dupOpt(arena, stmt.columnOptText(8)),
        .source_last_modified = try dupOpt(arena, stmt.columnOptText(9)),
        .source_size = stmt.columnOptInt(10),
        .remote_path = try arena.dupe(u8, stmt.columnText(11)),
        .remote_partial_path = try arena.dupe(u8, stmt.columnText(12)),
        .remote_partial_len = stmt.columnInt(13),
        .remote_partial_sha256 = try dupOpt(arena, stmt.columnOptText(14)),
        .chunk_size = stmt.columnInt(15),
        .confirmed_offset = stmt.columnInt(16),
        .total_bytes = stmt.columnOptInt(17),
        .expected_sha256 = try dupOpt(arena, stmt.columnOptText(18)),
        .verified_sha256 = try dupOpt(arena, stmt.columnOptText(19)),
        .no_clobber = stmt.columnInt(20) != 0,
        .state = try State.parse(stmt.columnText(21)),
        .failure_reason = try dupOpt(arena, stmt.columnOptText(22)),
        .created_at = stmt.columnInt(23),
        .updated_at = stmt.columnInt(24),
    };
}

pub fn get(store: *Store, arena: Allocator, id: i64) Error!?Checkpoint {
    var stmt = try store.db.prepare(select_columns ++ " WHERE id = ?1");
    defer stmt.deinit();
    try stmt.bindInt(1, id);
    if (!try stmt.step()) return null;
    return try rowToCheckpoint(arena, &stmt);
}

pub fn byRequest(store: *Store, arena: Allocator, request_id: []const u8) Error!?Checkpoint {
    var stmt = try store.db.prepare(select_columns ++ " WHERE request_id = ?1 ORDER BY id DESC LIMIT 1");
    defer stmt.deinit();
    try stmt.bindText(1, request_id);
    if (!try stmt.step()) return null;
    return try rowToCheckpoint(arena, &stmt);
}

/// The newest resumable checkpoint for a destination, if any.
pub fn findResumable(store: *Store, arena: Allocator, remote_path: []const u8) Error!?Checkpoint {
    var stmt = try store.db.prepare(select_columns ++
        \\ WHERE remote_path = ?1
        \\   AND state IN ('planned','probing','transferring','paused')
        \\ ORDER BY updated_at DESC LIMIT 1
    );
    defer stmt.deinit();
    try stmt.bindText(1, remote_path);
    if (!try stmt.step()) return null;
    return try rowToCheckpoint(arena, &stmt);
}

/// Observed state of the remote partial file, as probed before resuming.
pub const RemotePartial = struct {
    exists: bool,
    len: u64 = 0,
    /// Hash of the first `confirmed_offset` bytes, when we asked for it.
    prefix_sha256: ?[]const u8 = null,
};

pub const ResumeVerdict = union(enum) {
    /// Safe to continue from this offset.
    resume_from: u64,
    /// Nothing usable on the remote; start over (not an error).
    start_over,
    /// The local file is not the one this checkpoint describes.
    source_changed: []const u8,
    /// The remote partial does not match what we confirmed.
    partial_mismatch: []const u8,
};

/// Decides whether a checkpoint may be resumed. Pure, so the rules are
/// testable without a network or a filesystem.
pub fn verifyResume(
    checkpoint: Checkpoint,
    local_now: ?LocalIdentity,
    remote: RemotePartial,
) ResumeVerdict {
    // Local source identity: size, mtime and (when known) content hash must
    // all still match. Any change means the bytes already on the remote came
    // from a different file.
    if (checkpoint.local_path != null) {
        const current = local_now orelse
            return .{ .source_changed = "local source file is gone" };
        if (checkpoint.local_size) |recorded| {
            if (@as(i64, @intCast(current.size)) != recorded)
                return .{ .source_changed = "local source size changed" };
        }
        if (checkpoint.local_mtime_ns) |recorded| {
            if (@as(i64, @intCast(current.mtime_ns)) != recorded)
                return .{ .source_changed = "local source mtime changed" };
        }
        if (checkpoint.local_sha256) |recorded| {
            const now_hash = current.sha256 orelse
                return .{ .source_changed = "local source hash unavailable for comparison" };
            if (!std.mem.eql(u8, recorded, now_hash))
                return .{ .source_changed = "local source content changed" };
        }
    }

    const confirmed: u64 = @intCast(@max(checkpoint.confirmed_offset, 0));

    // Nothing on the remote: a fresh start is correct, and only correct
    // because we just proved the source is unchanged.
    if (!remote.exists) return if (confirmed == 0) .start_over else .{
        .partial_mismatch = "remote partial disappeared after bytes were confirmed",
    };

    // A partial shorter than our confirmed offset means the remote lost data
    // we had counted; longer means bytes we never confirmed (another writer,
    // or a crash mid-append). Neither may be trusted as a prefix.
    if (remote.len < confirmed) return .{ .partial_mismatch = "remote partial is shorter than the confirmed offset" };
    if (remote.len > confirmed) return .{ .partial_mismatch = "remote partial is longer than the confirmed offset" };

    if (checkpoint.remote_partial_sha256) |recorded| {
        const observed = remote.prefix_sha256 orelse
            return .{ .partial_mismatch = "remote partial hash unavailable for comparison" };
        if (!std.mem.eql(u8, recorded, observed))
            return .{ .partial_mismatch = "remote partial content does not match the checkpoint" };
    }

    return .{ .resume_from = confirmed };
}

/// Advances the confirmed offset. `offset` must be the end of the contiguous
/// completed prefix, never the highest finished chunk.
pub fn confirmOffset(
    store: *Store,
    id: i64,
    offset: u64,
    remote_partial_len: u64,
    prefix_sha256: ?[]const u8,
    now: i64,
) Error!void {
    var stmt = try store.db.prepare(
        \\UPDATE transfer_checkpoints
        \\   SET confirmed_offset = ?1, remote_partial_len = ?2,
        \\       remote_partial_sha256 = COALESCE(?3, remote_partial_sha256),
        \\       state = 'transferring', updated_at = ?4
        \\ WHERE id = ?5 AND ?1 >= confirmed_offset
    );
    defer stmt.deinit();
    try stmt.bindInt(1, @intCast(offset));
    try stmt.bindInt(2, @intCast(remote_partial_len));
    try stmt.bindOptText(3, prefix_sha256);
    try stmt.bindInt(4, now);
    try stmt.bindInt(5, id);
    _ = try stmt.step();
}

pub fn setState(store: *Store, id: i64, state: State, failure_reason: ?[]const u8, now: i64) Error!void {
    var stmt = try store.db.prepare(
        \\UPDATE transfer_checkpoints
        \\   SET state = ?1, failure_reason = ?2, updated_at = ?3
        \\ WHERE id = ?4
    );
    defer stmt.deinit();
    try stmt.bindText(1, state.text());
    try stmt.bindOptText(2, failure_reason);
    try stmt.bindInt(3, now);
    try stmt.bindInt(4, id);
    _ = try stmt.step();
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

fn testCheckpoint() Checkpoint {
    return .{
        .id = 1,
        .request_id = "01ABCDEFGH0123456789ABCDEF",
        .direction = .push,
        .local_path = "./big.bin",
        .local_size = 1000,
        .local_mtime_ns = 42,
        .local_sha256 = "aaaa",
        .source_url = null,
        .source_etag = null,
        .source_last_modified = null,
        .source_size = null,
        .remote_path = "/srv/big.bin",
        .remote_partial_path = "/srv/big.bin.terminus-part",
        .remote_partial_len = 400,
        .remote_partial_sha256 = "bbbb",
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

test "verifyResume accepts an unchanged source and matching partial" {
    const t = std.testing;
    const verdict = verifyResume(
        testCheckpoint(),
        .{ .path = "./big.bin", .size = 1000, .mtime_ns = 42, .sha256 = "aaaa" },
        .{ .exists = true, .len = 400, .prefix_sha256 = "bbbb" },
    );
    try t.expectEqual(@as(u64, 400), verdict.resume_from);
}

test "verifyResume refuses a changed local source" {
    const t = std.testing;
    // Same size and mtime, different content: caught by the hash.
    const changed_content = verifyResume(
        testCheckpoint(),
        .{ .path = "./big.bin", .size = 1000, .mtime_ns = 42, .sha256 = "zzzz" },
        .{ .exists = true, .len = 400, .prefix_sha256 = "bbbb" },
    );
    try t.expect(changed_content == .source_changed);

    // Rewritten in place: mtime moves.
    const changed_mtime = verifyResume(
        testCheckpoint(),
        .{ .path = "./big.bin", .size = 1000, .mtime_ns = 99, .sha256 = "aaaa" },
        .{ .exists = true, .len = 400, .prefix_sha256 = "bbbb" },
    );
    try t.expect(changed_mtime == .source_changed);

    // Truncated or appended.
    const changed_size = verifyResume(
        testCheckpoint(),
        .{ .path = "./big.bin", .size = 900, .mtime_ns = 42, .sha256 = "aaaa" },
        .{ .exists = true, .len = 400, .prefix_sha256 = "bbbb" },
    );
    try t.expect(changed_size == .source_changed);

    // Source gone entirely.
    const gone = verifyResume(testCheckpoint(), null, .{ .exists = true, .len = 400 });
    try t.expect(gone == .source_changed);
}

test "verifyResume refuses a mismatched remote partial" {
    const t = std.testing;
    const local: LocalIdentity = .{ .path = "./big.bin", .size = 1000, .mtime_ns = 42, .sha256 = "aaaa" };

    // Remote lost bytes we had counted.
    try t.expect(verifyResume(testCheckpoint(), local, .{ .exists = true, .len = 300, .prefix_sha256 = "bbbb" }) == .partial_mismatch);
    // Remote has bytes we never confirmed (another writer, or a torn append).
    try t.expect(verifyResume(testCheckpoint(), local, .{ .exists = true, .len = 500, .prefix_sha256 = "bbbb" }) == .partial_mismatch);
    // Right length, wrong content.
    try t.expect(verifyResume(testCheckpoint(), local, .{ .exists = true, .len = 400, .prefix_sha256 = "cccc" }) == .partial_mismatch);
    // Partial vanished after we had confirmed progress: not a clean restart.
    try t.expect(verifyResume(testCheckpoint(), local, .{ .exists = false }) == .partial_mismatch);
}

test "verifyResume allows a clean start when nothing was confirmed yet" {
    const t = std.testing;
    var checkpoint = testCheckpoint();
    checkpoint.confirmed_offset = 0;
    checkpoint.remote_partial_len = 0;
    checkpoint.remote_partial_sha256 = null;
    const verdict = verifyResume(
        checkpoint,
        .{ .path = "./big.bin", .size = 1000, .mtime_ns = 42, .sha256 = "aaaa" },
        .{ .exists = false },
    );
    try t.expect(verdict == .start_over);
}
