//! Exec-channel file transfer: the SCP-free fallback, plus the remote readings
//! every transfer needs whichever backend moves the bytes.
//!
//! libssh2's SCP support runs the remote `scp` binary (`scp -f/-t`) over an exec
//! channel — servers without the scp binary installed (common on minimal images;
//! OpenSSH 9+ no longer ships it by default) fail. This module needs only a
//! POSIX shell + `base64`.
//!
//! **Nothing here holds a file.** `pushFile` reads its source a slice at a time
//! and `pullFile` asks for one byte range at a time, so the peak is the slice
//! buffers and not the transfer. The version this replaces base64'd one whole
//! buffer into per-slice commands and hashed the whole buffer again afterwards,
//! which put two copies of the file in memory and capped a transfer at whatever
//! the caller could allocate.
//!
//! **The digest is SHA-256, at both ends.** It was MD5, on both sides of every
//! comparison in this file. MD5 collisions are constructible, so "the bytes
//! that arrived are the bytes we sent" was a claim an adversary could satisfy
//! with different bytes; and the ledger's `expected_sha256` / `verified_sha256`
//! columns name the algorithm they store, so an MD5 reading could not be
//! recorded there at all.
//!
//! **Everything takes an `Executor`.** The exec channel is the only thing this
//! module needs, and taking the abstraction rather than a live `*Ssh` is what
//! lets the probe, the verification and the publish be driven by `Scripted`
//! against a fake host — which is the only way any of it is provable without a
//! server. The two `*Ssh` entry points are wrappers, kept because `cmd_sync`
//! calls them with a client.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Ssh = @import("ssh/Client.zig");
const Executor = @import("exec.zig").Executor;
const digest = @import("digest.zig");

/// Raw push slice: base64 → ~24 KiB in the command string, safely under the
/// ~32 KiB exec-command ceiling.
pub const push_slice = 18 * 1024;

/// Raw pull slice. `Ssh.drainBoth` warns that a single command's stdout should
/// stay "under a few hundred KiB" before libssh2's blocking reader can wedge on
/// window bookkeeping, and 128 KiB of file is ~174 KiB of base64 — inside that
/// budget with room to spare.
pub const pull_slice = 128 * 1024;

const encoder = std.base64.standard.Encoder;
const decoder = std.base64.standard.Decoder;

pub const Error = Ssh.ExecError || Allocator.Error || error{
    RemoteFileMissing,
    RemoteWriteFailed,
    ChecksumMismatch,
    RemoteToolMissing,
    /// The remote path is long enough that a slice command would not fit under
    /// the exec-command ceiling. Named rather than truncated: a truncated path
    /// is a write to a different file.
    RemotePathTooLong,
    /// The remote answered, and its answer is not in the shape this module
    /// asked for. Never defaulted past — a missing size or a malformed digest
    /// line is exactly the input that would otherwise become a confident zero.
    RemoteReplyMalformed,
    /// A read of the remote (its size, its bytes) reported failure.
    RemoteReadFailed,
    /// The remote produced fewer bytes for a byte range than the range asked
    /// for, before the end of the file. The staged partial is short.
    ShortReceive,
    /// The local staging file could not be created, written or flushed.
    LocalFileFailed,
    /// The caller's per-chunk observer refused. Its reason is in its own
    /// context; see `Ssh.ChunkError`.
    ObserverFailed,
    /// The rename that publishes a staged partial did not report success.
    PublishFailed,
    /// A resume was asked to start past the end of its own source. Named rather
    /// than clamped: a clamp would publish a shorter file and call it the one
    /// that was asked for.
    ResumeOffsetPastSource,
    /// The truncate that cuts a remote partial back to a confirmed offset did
    /// not leave the length it was asked for. Never assumed — a `dd` that did
    /// nothing looks exactly like one that worked until the next append lands
    /// in the wrong place.
    RemoteTruncateFailed,
    /// At append time the remote staging partial is not the length the resume
    /// was licensed for. Somebody else wrote to it between the verification and
    /// the first slice, and appending now would splice at the wrong offset.
    RemotePartialLengthChanged,
    /// The local staging partial is shorter than the offset a resume was told to
    /// continue from. Extending it would fill the gap with zeroes.
    LocalPartialTooShort,
};

// --- Remote readings ---------------------------------------------------------

/// What the host says about one file.
///
/// Three fields and two of them optional, because the host may genuinely be
/// unable to answer and each absence costs something different:
///
///  * no `sha256` and the transfer cannot be verified at all — it may reach
///    `completed_unverified` and never `published`;
///  * no `mtime_ns` and the source cannot be *identified*, so no confirmed
///    offset may be stored against it (the schema's
///    `offset_needs_source_identity`) and a later resume has nothing to check a
///    prefix against. Verification is unaffected.
///
/// Neither is defaulted. A zero mtime and an empty digest are both values that
/// read as answers, and the whole point of asking is to find out.
pub const RemoteReading = struct {
    size: u64,
    mtime_ns: ?i128,
    sha256: ?[]const u8,
};

/// The probe script: size, mtime and digest of one file, one line each.
///
/// **`sha256sum`, then `shasum -a 256`, then neither.** GNU coreutils ships
/// `sha256sum`; the BSDs and macOS ship `shasum` (a perl script) and no
/// `sha256sum`; a busybox image may have one, the other, or neither. Asking for
/// both is the difference between verifying a transfer to a Mac and not. When
/// neither is there the line is `-`, which is a stated absence — the caller then
/// has to choose `completed_unverified`, and cannot mistake a missing tool for a
/// digest that agreed.
///
/// Both are fed on **stdin** (`< 'path'`) rather than given the path as an
/// argument, so a filename is never parsed as an option and the two tools'
/// different `--` support stops mattering. The cost is that the output's second
/// field is `-` instead of the name, which nothing here reads.
///
/// `stat` is asked twice, GNU form then BSD form, and `-` when neither answers.
/// There is no third portable spelling; a host with neither simply cannot have
/// its files identified, which is a smaller loss than a fabricated timestamp.
const probe_script =
    \\[ -f '{[path]s}' ] || exit 44
    \\wc -c < '{[path]s}' || exit 45
    \\stat -c %Y '{[path]s}' 2>/dev/null || stat -f %m '{[path]s}' 2>/dev/null || echo -
    \\if command -v sha256sum >/dev/null 2>&1; then sha256sum < '{[path]s}'
    \\elif command -v shasum >/dev/null 2>&1; then shasum -a 256 < '{[path]s}'
    \\else echo -
    \\fi
;

/// Reads size, mtime and digest of `remote_path` in one round trip.
pub fn probeRemoteFile(
    executor: Executor,
    arena: Allocator,
    remote_path: []const u8,
) Error!RemoteReading {
    const cmd = try std.fmt.allocPrint(arena, probe_script, .{ .path = remote_path });
    const r = try executor.exec(arena, cmd);
    switch (r.exit_code) {
        0 => {},
        44 => return error.RemoteFileMissing,
        else => return error.RemoteReadFailed,
    }

    var lines = std.mem.splitScalar(u8, std.mem.trim(u8, r.stdout, "\r\n"), '\n');
    const size_text = std.mem.trim(u8, lines.next() orelse return error.RemoteReplyMalformed, " \t\r");
    const mtime_text = std.mem.trim(u8, lines.next() orelse return error.RemoteReplyMalformed, " \t\r");
    const digest_line = std.mem.trim(u8, lines.next() orelse return error.RemoteReplyMalformed, " \t\r");

    return .{
        .size = std.fmt.parseInt(u64, size_text, 10) catch return error.RemoteReplyMalformed,
        .mtime_ns = parseMtimeNs(mtime_text),
        .sha256 = try parseDigest(arena, digest_line),
    };
}

/// Seconds since the epoch as the ledger's nanoseconds, or null for the stated
/// absence. A value that is present but unparseable is also null: the host said
/// something this code cannot read, which is the same amount of knowledge as
/// nothing, and guessing would file a timestamp nobody observed.
fn parseMtimeNs(text: []const u8) ?i128 {
    const secs = std.fmt.parseInt(i64, text, 10) catch return null;
    return @as(i128, secs) * std.time.ns_per_s;
}

/// The first field of a `sha256sum` line, validated as 64 hex digits, or null
/// for the stated absence.
///
/// Validated rather than trusted, because everything downstream compares this
/// against a digest we took ourselves and a comparison of two strings cannot
/// tell "the tool printed an error onto stdout" from "the file hashed
/// differently". The first is a broken host and the second is a corrupted
/// transfer, and they send an operator to different places.
fn parseDigest(arena: Allocator, line: []const u8) Allocator.Error!?[]const u8 {
    var fields = std.mem.tokenizeAny(u8, line, " \t");
    const first = fields.next() orelse return null;
    if (first.len != digest.hex_len) return null;
    for (first) |ch| switch (ch) {
        '0'...'9', 'a'...'f', 'A'...'F' => {},
        else => return null,
    };
    return try arena.dupe(u8, first);
}

/// The remote's own SHA-256 of one file, or null when the host has no tool that
/// can produce one.
///
/// The narrow form of `probeRemoteFile`, for the second reading a transfer takes
/// — the digest of the staged partial after the bytes have gone out. Size and
/// mtime are not asked for there because nothing compares them: what is being
/// checked is whether the bytes that arrived hash to the bytes that left.
pub fn remoteDigest(
    executor: Executor,
    arena: Allocator,
    remote_path: []const u8,
) Error!?[]const u8 {
    const cmd = try std.fmt.allocPrint(arena,
        \\[ -f '{[path]s}' ] || exit 44
        \\if command -v sha256sum >/dev/null 2>&1; then sha256sum < '{[path]s}'
        \\elif command -v shasum >/dev/null 2>&1; then shasum -a 256 < '{[path]s}'
        \\else echo -
        \\fi
    , .{ .path = remote_path });
    const r = try executor.exec(arena, cmd);
    switch (r.exit_code) {
        0 => {},
        44 => return error.RemoteFileMissing,
        else => return error.RemoteWriteFailed,
    }
    return parseDigest(arena, std.mem.trim(u8, r.stdout, " \t\r\n"));
}

/// Which SHA-256 tool the host has, or null for neither.
///
/// Asked during a **push's** probe, before it declares anything, and the reason
/// is a hole in the state machine rather than a nicety. A push can always hash
/// its own source, so it would otherwise declare a digest unconditionally — and
/// if the host then turns out to have no way to hash the staged partial, the row
/// has *no legal end state at all*: `published` needs a reading it cannot get,
/// `completed_unverified` refuses a row that declared a digest
/// (`CompletedUnverifiedHasDeclaredHash`), and `failed_hash_mismatch` needs a
/// reading that disagrees. Asking first is what keeps that row from being
/// created; a pull cannot reach it, because a pull's declaration *is* the host's
/// reading and the two are absent together.
///
/// Returns the tool's name rather than a bool so the caller can say which one it
/// is relying on. Same two candidates and same order as `probe_script`.
pub fn remoteHashTool(executor: Executor, arena: Allocator) Error!?[]const u8 {
    const r = try executor.exec(arena,
        \\if command -v sha256sum >/dev/null 2>&1; then echo sha256sum
        \\elif command -v shasum >/dev/null 2>&1; then echo shasum
        \\else echo -
        \\fi
    );
    if (r.exit_code != 0) return error.RemoteReadFailed;
    const name = std.mem.trim(u8, r.stdout, " \t\r\n");
    if (std.mem.eql(u8, name, "sha256sum") or std.mem.eql(u8, name, "shasum"))
        return try arena.dupe(u8, name);
    return null;
}

// --- Resume readings ---------------------------------------------------------
//
// A resume splices bytes fetched now onto bytes fetched earlier, so before it
// moves anything it has to prove two things: that the source is still the one
// the checkpoint recorded, and that the staging partial's confirmed prefix is
// still the bytes we counted. `transfers.verifyResume` is the rule; these are
// the two readings it is asked about, and which side each is taken on follows
// from where the partial lives — on the host for a push, on this machine for a
// pull.
//
// **Both readings double as the SHA-256 state a resume needs.** A digest cannot
// be resumed from its output: the hasher state at byte N is not recoverable from
// the prefix digest recorded at N. So a resumed transfer would either have to
// re-read the prefix to rebuild that state — a whole extra pass, every resume —
// or stop advancing the confirmed offset, which takes resume with it. Neither is
// necessary, because the pass that *licenses* the resume is a pass over exactly
// those bytes: `readLocalFile` hands back the running hasher as it stood at the
// mark alongside the digest it was asked for. The prefix is read once, for the
// proof, and the hasher comes free with it.

/// One pass over a local file: its whole identity, and the digest state at a
/// mark.
///
/// `mark` is the offset a resume would continue from. `at_mark` and
/// `prefix_sha256` are both null when the file ended before it — which is a
/// finding (`verifyResume` calls it a short partial), not a reason to report a
/// zero.
pub const LocalPass = struct {
    /// Digest of the whole file, as read.
    sha256: []const u8,
    /// Bytes actually read, which is the length on disk.
    size: u64,
    mtime_ns: i128,
    /// The hasher after exactly `mark` bytes, for a caller that is about to feed
    /// it the rest of the file.
    at_mark: ?digest.Running,
    /// The hex digest of the first `mark` bytes. Null at `mark == 0`, because a
    /// digest of nothing is not a prefix proof and must not be offered as one.
    prefix_sha256: ?[]const u8,
};

/// Reads `path` once, hashing as it goes, and snapshots the hasher at `mark`.
///
/// The same walk `digest.readFile` makes, with the snapshot added — chunks are
/// split at the mark so the state is taken at exactly that byte and not at
/// whichever buffer boundary happened to straddle it. Null when there is no such
/// file, which is a finding rather than an error; see the `FileNotFound` arm.
pub fn readLocalFile(
    io: std.Io,
    arena: Allocator,
    path: []const u8,
    mark: u64,
) Error!?LocalPass {
    const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch |err| switch (err) {
        // A stated absence. The two callers mean different things by it — a
        // push's source is gone, a pull's staging partial was never written —
        // and both are findings `verifyResume` has words for, so neither may be
        // flattened into "unreadable".
        error.FileNotFound => return null,
        else => return error.LocalFileFailed,
    };
    defer file.close(io);
    const info = file.stat(io) catch return error.LocalFileFailed;

    var buffer: [1 << 20]u8 = undefined;
    var reader = file.reader(io, &buffer);
    var running: digest.Running = .init();
    var at_mark: ?digest.Running = if (mark == 0) running else null;
    var prefix: ?[]const u8 = null;
    var read: u64 = 0;
    while (true) {
        const available = reader.interface.peekGreedy(1) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return error.LocalFileFailed,
        };
        // Split at the mark, so the snapshot is of exactly `mark` bytes.
        const chunk = if (read < mark and read + available.len > mark)
            available[0..@intCast(mark - read)]
        else
            available;
        running.update(chunk);
        reader.interface.toss(chunk.len);
        read += chunk.len;
        if (read == mark and at_mark == null) {
            at_mark = running;
            var buf: [digest.hex_len]u8 = undefined;
            prefix = try arena.dupe(u8, running.peekHex(&buf));
        }
    }

    var out: [digest.hex_len]u8 = undefined;
    return .{
        .sha256 = try arena.dupe(u8, running.finalHex(&out)),
        .size = read,
        .mtime_ns = info.mtime.nanoseconds,
        .at_mark = at_mark,
        .prefix_sha256 = prefix,
    };
}

/// What the host says about a staging partial a resume is about to append to.
///
/// The shape `transfers.PartialObservation` is built from. A local type rather
/// than that one because the dependency runs the other way: nothing in this
/// module knows about the checkpoint table, and importing it to borrow a
/// three-field struct would put the ledger underneath the transport.
pub const PartialReading = struct {
    exists: bool,
    len: u64 = 0,
    prefix_sha256: ?[]const u8 = null,
};

/// The host's length and ranged prefix digest for one staging partial.
///
/// `head -c N` and not `dd`, for the reason `fetchRange` gives: `dd`'s block
/// semantics can return short for a full block, and here a short read would
/// produce the digest of fewer bytes than were asked about — a prefix proof over
/// the wrong range, which is worse than no proof.
pub fn remotePartial(
    executor: Executor,
    arena: Allocator,
    remote_path: []const u8,
    prefix_len: u64,
) Error!PartialReading {
    const cmd = try std.fmt.allocPrint(arena,
        \\[ -f '{[path]s}' ] || exit 44
        \\wc -c < '{[path]s}' || exit 45
        \\head -c {[len]d} < '{[path]s}' | if command -v sha256sum >/dev/null 2>&1; then sha256sum
        \\elif command -v shasum >/dev/null 2>&1; then shasum -a 256
        \\else echo -
        \\fi
    , .{ .path = remote_path, .len = prefix_len });
    const r = try executor.exec(arena, cmd);
    switch (r.exit_code) {
        0 => {},
        44 => return .{ .exists = false },
        else => return error.RemoteReadFailed,
    }

    var lines = std.mem.splitScalar(u8, std.mem.trim(u8, r.stdout, "\r\n"), '\n');
    const size_text = std.mem.trim(u8, lines.next() orelse return error.RemoteReplyMalformed, " \t\r");
    const digest_line = std.mem.trim(u8, lines.next() orelse return error.RemoteReplyMalformed, " \t\r");
    return .{
        .exists = true,
        .len = std.fmt.parseInt(u64, size_text, 10) catch return error.RemoteReplyMalformed,
        // At zero there is no prefix. The host will have hashed an empty stream
        // and produced a perfectly valid digest of nothing; offering it as a
        // prefix proof is the one thing that must not happen here.
        .prefix_sha256 = if (prefix_len == 0) null else try parseDigest(arena, digest_line),
    };
}

/// Cuts a remote staging partial back to `len` bytes, in place.
///
/// The bytes above `len` were written and never confirmed — the ordinary shape
/// of an interruption — and they prove nothing, so a resume discards them. It
/// discards them only *after* the prefix below `len` has been proven, which is
/// the order `transfers.ResumeVerdict.truncate_then_resume` exists to state:
/// truncating first would destroy the only thing that could have proven it.
///
/// `dd if=/dev/null of=… seek=N` rather than `truncate -s N`: `truncate` is
/// GNU/BSD and is absent from macOS, while this form works on GNU coreutils,
/// the BSDs and busybox. The length is read back and compared rather than
/// assumed, because a `dd` that did nothing is indistinguishable from one that
/// worked until the next append lands in the wrong place.
pub fn truncateRemote(
    executor: Executor,
    arena: Allocator,
    remote_path: []const u8,
    len: u64,
) Error!void {
    const cmd = try std.fmt.allocPrint(arena,
        \\[ -f '{[path]s}' ] || exit 44
        \\dd if=/dev/null of='{[path]s}' bs=1 seek={[len]d} 2>/dev/null || exit 42
        \\wc -c < '{[path]s}' || exit 45
    , .{ .path = remote_path, .len = len });
    const r = try executor.exec(arena, cmd);
    switch (r.exit_code) {
        0 => {},
        44 => return error.RemoteFileMissing,
        else => return error.RemoteTruncateFailed,
    }
    const now = std.fmt.parseInt(
        u64,
        std.mem.trim(u8, r.stdout, " \t\r\n"),
        10,
    ) catch return error.RemoteReplyMalformed;
    if (now != len) return error.RemoteTruncateFailed;
}

/// Renames a staged partial over its destination on the host.
///
/// `mv -f` is POSIX `rename(2)` within one filesystem: the destination is
/// replaced whole or not at all, and a failure leaves what was there. That is
/// what makes it the publish step — every byte before it went to the partial, so
/// until this runs the destination is untouched by construction rather than by
/// care.
pub fn publishRemote(
    executor: Executor,
    arena: Allocator,
    partial_path: []const u8,
    dest_path: []const u8,
) Error!void {
    const cmd = try std.fmt.allocPrint(
        arena,
        "mv -f '{s}' '{s}'",
        .{ partial_path, dest_path },
    );
    const r = try executor.exec(arena, cmd);
    if (r.exit_code != 0) return error.PublishFailed;
}

// --- Push --------------------------------------------------------------------

/// Truncates (or creates) the remote staging file and sets its mode.
fn beginRemoteFile(
    executor: Executor,
    arena: Allocator,
    remote_path: []const u8,
    mode: u32,
) Error!void {
    const init = try std.fmt.allocPrint(arena,
        \\command -v base64 >/dev/null || exit 41
        \\: > '{[path]s}' || exit 42
        \\chmod {[mode]o} '{[path]s}'
    , .{ .path = remote_path, .mode = mode });
    const r = try executor.exec(arena, init);
    switch (r.exit_code) {
        0 => {},
        41 => return error.RemoteToolMissing,
        else => return error.RemoteWriteFailed,
    }
}

/// The resuming counterpart of `beginRemoteFile`: **it does not truncate.**
///
/// That absence is the whole function. `beginRemoteFile` opens with `: >`, which
/// empties the partial — correct for a fresh push and the one thing a resume
/// must never do to the bytes it is about to append to. So the two are separate
/// entry points rather than one with a flag: a flag defaulting the wrong way, or
/// read the wrong way once, silently turns every resume into a restart that
/// reports itself as a resume.
///
/// What it checks instead is that the partial is *exactly* `offset` bytes now.
/// The caller has already proven that prefix and, if the partial was longer,
/// cut it back; a different length at this point means somebody else wrote to it
/// in between, and appending would splice at the wrong offset. `chmod` is not
/// repeated — the mode was set when the partial was created, and re-applying it
/// would be this function's only write to a file it exists not to write to.
fn resumeRemoteFile(
    executor: Executor,
    arena: Allocator,
    remote_path: []const u8,
    offset: u64,
) Error!void {
    const cmd = try std.fmt.allocPrint(arena,
        \\command -v base64 >/dev/null || exit 41
        \\[ -f '{[path]s}' ] || exit 44
        \\wc -c < '{[path]s}' || exit 45
    , .{ .path = remote_path });
    const r = try executor.exec(arena, cmd);
    switch (r.exit_code) {
        0 => {},
        41 => return error.RemoteToolMissing,
        44 => return error.RemoteFileMissing,
        else => return error.RemoteReadFailed,
    }
    const now = std.fmt.parseInt(
        u64,
        std.mem.trim(u8, r.stdout, " \t\r\n"),
        10,
    ) catch return error.RemoteReplyMalformed;
    if (now != offset) return error.RemotePartialLengthChanged;
}

/// The fixed buffers one push loop needs, allocated once.
///
/// Once, and not per slice: the loop runs 116 000 times for a 2 GiB file, and a
/// per-slice `arena.alloc` is how a constant-memory transfer becomes a transfer
/// that allocates as much as it moves. That is the exact shape this module used
/// to have.
const PushBuffers = struct {
    encoded: []u8,
    command: []u8,

    fn init(arena: Allocator, remote_path: []const u8) Error!PushBuffers {
        const encoded_max = encoder.calcSize(push_slice);
        // `printf '%s' '<encoded>' | base64 -d >> '<path>'` plus slack for the
        // literal text. Checked rather than assumed: `bufPrint` returns
        // `NoSpaceLeft` and this module turns that into a named refusal.
        const command_max = encoded_max + remote_path.len + 64;
        return .{
            .encoded = try arena.alloc(u8, encoded_max),
            .command = try arena.alloc(u8, command_max),
        };
    }
};

/// Appends one raw slice to the remote file.
fn appendSlice(
    executor: Executor,
    scratch: *std.heap.ArenaAllocator,
    buffers: PushBuffers,
    chunk: []const u8,
    remote_path: []const u8,
) Error!void {
    const encoded = buffers.encoded[0..encoder.calcSize(chunk.len)];
    _ = encoder.encode(encoded, chunk);
    const cmd = std.fmt.bufPrint(
        buffers.command,
        "printf '%s' '{s}' | base64 -d >> '{s}'",
        .{ encoded, remote_path },
    ) catch return error.RemotePathTooLong;

    // The exec's own stdout/stderr allocations go here and are handed back
    // before the next slice. Retaining capacity means the peak is one slice's
    // worth however many slices there are.
    _ = scratch.reset(.retain_capacity);
    const r = try executor.exec(scratch.allocator(), cmd);
    if (r.exit_code != 0) return error.RemoteWriteFailed;
}

/// Uploads `local_path` to `remote_path` a slice at a time, in bounded memory.
///
/// `observer` sees every slice as it goes out — the same contract
/// `Ssh.scpSend`'s does, so a driver hashes and records progress identically
/// whichever backend moved the bytes. `moved` counts absolutely: on a resume the
/// first slice arrives at `start_offset + its length`, because what a caller
/// records against a checkpoint is a position in the artifact and not a count of
/// this run's work.
///
/// `start_offset` is where the remote partial already ends. At zero the partial
/// is created and truncated as before; above zero **nothing truncates it** — see
/// `resumeRemoteFile`.
///
/// Verifies nothing. The digest comparison belongs to the driver, which is the
/// only thing that knows what was declared before the first byte and which is
/// the only thing that may record the answer. Two verification implementations
/// is how one of them comes to compare the wrong pair.
pub fn pushFile(
    executor: Executor,
    arena: Allocator,
    io: std.Io,
    local_path: []const u8,
    remote_path: []const u8,
    start_offset: u64,
    mode: u32,
    observer: ?Ssh.Observer,
    moved: *Ssh.Moved,
) Error!u64 {
    moved.* = .{};
    const file = std.Io.Dir.cwd().openFile(io, local_path, .{}) catch return error.LocalFileFailed;
    defer file.close(io);
    const total = file.length(io) catch return error.LocalFileFailed;
    moved.expected = total;
    if (start_offset > total) return error.ResumeOffsetPastSource;
    moved.arrived = start_offset;

    if (start_offset == 0)
        try beginRemoteFile(executor, arena, remote_path, mode)
    else
        try resumeRemoteFile(executor, arena, remote_path, start_offset);

    const buffers = try PushBuffers.init(arena, remote_path);
    var scratch = std.heap.ArenaAllocator.init(arena);
    defer scratch.deinit();

    var read_buffer: [push_slice]u8 = undefined;
    var reader = file.reader(io, &read_buffer);
    // Positional by default, so the first read comes from `start_offset` rather
    // than from the head of the file.
    reader.pos = start_offset;
    var sent: u64 = start_offset;
    while (sent < total) {
        const available = reader.interface.peekGreedy(1) catch |err| switch (err) {
            // The file ended before its own reported length. Nothing here can
            // publish what it promised, and a shorter success is the answer
            // this module exists to stop giving.
            error.EndOfStream => {
                moved.arrived = sent;
                return error.ShortReceive;
            },
            else => return error.LocalFileFailed,
        };
        const chunk = available[0..@min(available.len, @as(usize, @intCast(total - sent)))];
        try appendSlice(executor, &scratch, buffers, chunk, remote_path);
        reader.interface.toss(chunk.len);
        sent += chunk.len;
        moved.arrived = sent;
        if (observer) |o| try o.offer(chunk, sent, total);
    }
    return sent;
}

/// Uploads an in-memory buffer, SHA-256 verified against the remote's own
/// reading.
///
/// The shape `cmd_sync` needs for a tar archive it already holds. It verifies
/// where `pushFile` does not, because its caller has no checkpoint to record a
/// comparison against and no state machine to record it in — the answer has to
/// be the return value or nothing.
pub fn pushBytes(
    client: *Ssh,
    arena: Allocator,
    data: []const u8,
    remote_path: []const u8,
    mode: u32,
) Error!void {
    const executor: Executor = .{ .direct = client };
    try beginRemoteFile(executor, arena, remote_path, mode);

    const buffers = try PushBuffers.init(arena, remote_path);
    var scratch = std.heap.ArenaAllocator.init(arena);
    defer scratch.deinit();

    var offset: usize = 0;
    while (offset < data.len) {
        const end = @min(offset + push_slice, data.len);
        try appendSlice(executor, &scratch, buffers, data[offset..end], remote_path);
        offset = end;
    }

    var local: [digest.hex_len]u8 = undefined;
    const want = digest.hex(data, &local);
    const got = (try remoteDigest(executor, arena, remote_path)) orelse
        return error.RemoteToolMissing;
    if (!std.ascii.eqlIgnoreCase(want, got)) return error.ChecksumMismatch;
}

// --- Pull --------------------------------------------------------------------

/// The fixed buffers one pull loop needs, allocated once, for the reason
/// `PushBuffers` is.
const PullBuffers = struct {
    /// Whitespace-stripped base64, straight out of the remote's stdout.
    compact: []u8,
    /// The decoded slice.
    raw: []u8,

    fn init(arena: Allocator) Error!PullBuffers {
        return .{
            .compact = try arena.alloc(u8, encoder.calcSize(pull_slice)),
            .raw = try arena.alloc(u8, pull_slice),
        };
    }
};

/// Asks for one byte range and decodes it into `buffers.raw`.
///
/// `tail -c +N | head -c M` rather than `dd bs=… skip=…`: `dd`'s block
/// semantics let it return a short read for a full block, which would silently
/// shorten a slice in the middle of a file, and the byte-exact `iflag=`
/// spellings that fix it are GNU-only. Both of these are POSIX and both count
/// in bytes.
fn fetchRange(
    executor: Executor,
    scratch: *std.heap.ArenaAllocator,
    buffers: PullBuffers,
    remote_path: []const u8,
    offset: u64,
    want: usize,
) Error![]const u8 {
    _ = scratch.reset(.retain_capacity);
    const alloc = scratch.allocator();
    const cmd = try std.fmt.allocPrint(
        alloc,
        "tail -c +{d} '{s}' | head -c {d} | base64",
        .{ offset + 1, remote_path, want },
    );
    const r = try executor.exec(alloc, cmd);
    if (r.exit_code != 0) return error.RemoteReadFailed;

    // base64 output wraps at 76 cols; strip whitespace before decoding. Into a
    // fixed buffer, because the growable list this replaced was an allocation
    // proportional to the file.
    var n: usize = 0;
    for (r.stdout) |ch| {
        switch (ch) {
            '\n', '\r', ' ', '\t' => continue,
            else => {},
        }
        if (n == buffers.compact.len) return error.RemoteReplyMalformed;
        buffers.compact[n] = ch;
        n += 1;
    }
    const compact = buffers.compact[0..n];
    const size = decoder.calcSizeForSlice(compact) catch return error.RemoteReplyMalformed;
    if (size > buffers.raw.len) return error.RemoteReplyMalformed;
    decoder.decode(buffers.raw[0..size], compact) catch return error.RemoteReplyMalformed;
    return buffers.raw[0..size];
}

/// Downloads `remote_path` into `partial_path` a byte range at a time, in
/// bounded memory.
///
/// **`partial_path` must be a staging path, never the caller's destination.**
/// At `start_offset == 0` the file is created truncating, exactly as
/// `Ssh.scpRecv` does and for the same reason: a pull that fails halfway must
/// not already have emptied what the operator had.
///
/// Above zero it opens without truncating and cuts the file back to
/// `start_offset` — the unconfirmed tail an interruption left, which proves
/// nothing and is therefore not counted. It refuses a partial that is *shorter*
/// than the offset rather than extending it, because extending would fill the
/// gap with zeroes and then hash them as if they had arrived.
///
/// `total` is the whole file and `moved` counts absolutely, so a resumed pull
/// reports its position in the artifact rather than this run's share of it.
///
/// Verifies nothing, for the reason `pushFile` does not.
pub fn pullFile(
    executor: Executor,
    arena: Allocator,
    io: std.Io,
    remote_path: []const u8,
    partial_path: []const u8,
    start_offset: u64,
    total: u64,
    observer: ?Ssh.Observer,
    moved: *Ssh.Moved,
) Error!u64 {
    moved.* = .{ .expected = total };
    if (start_offset > total) return error.ResumeOffsetPastSource;
    moved.arrived = start_offset;

    const buffers = try PullBuffers.init(arena);
    var scratch = std.heap.ArenaAllocator.init(arena);
    defer scratch.deinit();

    const file = (if (start_offset == 0)
        std.Io.Dir.cwd().createFile(io, partial_path, .{})
    else
        // Read access as well as write, and not for reading: a resume has to ask
        // the file how long it is before it appends, and a write-only handle
        // cannot be statted on Windows. The fresh path keeps the handle it had.
        std.Io.Dir.cwd().createFile(io, partial_path, .{
            .truncate = false,
            .read = true,
        })) catch return error.LocalFileFailed;
    defer file.close(io);
    if (start_offset > 0) {
        const on_disk = file.length(io) catch return error.LocalFileFailed;
        if (on_disk < start_offset) return error.LocalPartialTooShort;
        if (on_disk > start_offset)
            file.setLength(io, start_offset) catch return error.LocalFileFailed;
    }
    var write_buffer: [1 << 16]u8 = undefined;
    // Positional, with the cursor set where the confirmed prefix ends. A
    // streaming writer would start at zero and overwrite the bytes this resume
    // exists to keep.
    var writer = file.writer(io, &write_buffer);
    writer.pos = start_offset;

    var received: u64 = start_offset;
    while (received < total) {
        const want: usize = @intCast(@min(@as(u64, pull_slice), total - received));
        const chunk = try fetchRange(executor, &scratch, buffers, remote_path, received, want);
        // Short of the range asked for, before the end of the file: the source
        // shrank, or the host truncated the pipe. Either way the partial is not
        // the file, and reporting the smaller number is the pseudo-success this
        // whole pass is about.
        if (chunk.len == 0 or chunk.len > want) {
            moved.arrived = received;
            return error.ShortReceive;
        }
        writer.interface.writeAll(chunk) catch return error.LocalFileFailed;
        received += chunk.len;
        moved.arrived = received;
        if (observer) |o| try o.offer(chunk, received, total);
        if (chunk.len < want) {
            writer.interface.flush() catch return error.LocalFileFailed;
            return error.ShortReceive;
        }
    }
    writer.interface.flush() catch return error.LocalFileFailed;
    return received;
}

/// Downloads `remote_path` in one `base64 < file` exec, SHA-256 verified.
///
/// The shape `cmd_sync` needs for a tar archive it is about to unpack in
/// memory. It holds the whole object by construction, which is why the streaming
/// `pullFile` exists beside it rather than replacing it.
pub fn pullBytes(
    client: *Ssh,
    arena: Allocator,
    remote_path: []const u8,
) Error![]u8 {
    const executor: Executor = .{ .direct = client };
    const reading = try probeRemoteFile(executor, arena, remote_path);
    const remote_sha = reading.sha256 orelse return error.RemoteToolMissing;

    const cmd = try std.fmt.allocPrint(arena,
        \\command -v base64 >/dev/null || exit 41
        \\base64 < '{s}'
    , .{remote_path});
    const r = try executor.exec(arena, cmd);
    switch (r.exit_code) {
        0 => {},
        41 => return error.RemoteToolMissing,
        else => return error.RemoteReadFailed,
    }

    var compact: std.ArrayList(u8) = .empty;
    for (r.stdout) |ch| {
        if (ch != '\n' and ch != '\r' and ch != ' ') try compact.append(arena, ch);
    }
    const dsize = decoder.calcSizeForSlice(compact.items) catch return error.RemoteReplyMalformed;
    const data = try arena.alloc(u8, dsize);
    decoder.decode(data, compact.items) catch return error.RemoteReplyMalformed;

    var local: [digest.hex_len]u8 = undefined;
    if (!std.ascii.eqlIgnoreCase(digest.hex(data, &local), remote_sha))
        return error.ChecksumMismatch;
    return data;
}
