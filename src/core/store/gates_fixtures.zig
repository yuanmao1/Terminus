//! The scratch store, and the seeds the gate files share.
//!
//! One home, deliberately. These fixtures decide what a gate is looking at
//! before it looks — which operation kind, which checkpoint state, which digest
//! columns are filled — so a second copy is not a convenience: it is two gates
//! quietly proving different things while appearing to read the same. Anything
//! used from more than one gate file belongs here; anything used from one
//! belongs beside its gate.
//!
//! Nothing here asserts a product rule. The one test in this file pins a
//! property of a fixture itself, because a seed that silently stopped producing
//! distinct ids would weaken every gate downstream of it without failing.

const std = @import("std");
const Store = @import("Store.zig");
const ids = @import("ids.zig");
const execution = @import("../execution.zig");
const Proc = @import("../proc.zig");

/// Scratch database under .zig-cache so a crashed test leaves nothing in the
/// source tree. Returns a NUL-terminated path for sqlite.
pub const Scratch = struct {
    io: std.Io,
    threaded: *std.Io.Threaded,
    path: [:0]u8,
    allocator: std.mem.Allocator,

    const dir = ".zig-cache/tmp";

    /// Scratch names must be unique per process: the gates are otherwise
    /// safe to run in parallel, and a shared filename turns that into a pile
    /// of false failures that look like real races.
    var counter: std.atomic.Value(u32) = .init(0);

    fn uniqueName(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
        const n = counter.fetchAdd(1, .monotonic);
        return std.fmt.allocPrint(allocator, "{s}_{d}_{d}_{d}", .{ name, Proc.currentPid(), std.Thread.getCurrentId(), n });
    }

    pub fn init(allocator: std.mem.Allocator, name: []const u8) !Scratch {
        const threaded = try allocator.create(std.Io.Threaded);
        threaded.* = .init(allocator, .{});
        const io = threaded.io();
        std.Io.Dir.cwd().createDirPath(io, dir) catch {};
        const unique = try uniqueName(allocator, name);
        defer allocator.free(unique);
        const path = try std.fmt.allocPrintSentinel(allocator, "{s}/{s}.db", .{ dir, unique }, 0);
        var s: Scratch = .{ .io = io, .threaded = threaded, .path = path, .allocator = allocator };
        s.removeFiles();
        return s;
    }

    /// WAL databases have sidecars; leaving one behind would make the next
    /// run read a mismatched log (a mistake that silently shows empty data).
    fn removeFiles(s: *Scratch) void {
        const cwd = std.Io.Dir.cwd();
        cwd.deleteFile(s.io, s.path) catch {};
        for ([_][]const u8{ "-wal", "-shm" }) |suffix| {
            const side = std.fmt.allocPrint(s.allocator, "{s}{s}", .{ s.path, suffix }) catch return;
            defer s.allocator.free(side);
            cwd.deleteFile(s.io, side) catch {};
        }
    }

    pub fn deinit(s: *Scratch) void {
        s.removeFiles();
        s.allocator.free(s.path);
        s.threaded.deinit();
        s.allocator.destroy(s.threaded);
    }
};

/// Calls a `pub fn …Locked` writer inside the transaction its name promises.
///
/// Every one of them now refuses outright when no transaction is open, so a
/// gate that called one directly would be exercising that guard instead of the
/// rule it came for. In production these calls sit inside a transaction their
/// caller opened around several writes — `execution.adoptCheckpoint`,
/// `receipts.resolve` — and this is the smallest honest stand-in: one writer,
/// one transaction, rolled back if it refuses.
pub fn locked(
    store: *Store,
    comptime f: anytype,
    args: anytype,
) @typeInfo(@TypeOf(f)).@"fn".return_type.? {
    try store.db.exec("BEGIN IMMEDIATE");
    errdefer store.db.exec("ROLLBACK") catch {};
    const result = try @call(.auto, f, args);
    try store.db.exec("COMMIT");
    return result;
}

/// Builds a syntactically valid request id from a readable label.
///
/// Crockford base32 omits I, L, O and U, so hand-written test ids are easy
/// to get wrong; this maps the confusable letters and pads to length.
pub fn testId(label: []const u8) [ids.len]u8 {
    var out: [ids.len]u8 = @splat('0');
    for (label, 0..) |ch, i| {
        if (i >= ids.len) break;
        out[i] = switch (std.ascii.toUpper(ch)) {
            'I', 'L' => '1',
            'O' => '0',
            'U' => 'V',
            '0'...'9', 'A'...'H', 'J', 'K', 'M', 'N', 'P'...'T', 'V'...'Z' => std.ascii.toUpper(ch),
            else => '0',
        };
    }
    return out;
}

test testId {
    const id = testId("guard");
    try ids.validate(&id);
    try std.testing.expectEqual(@as(usize, ids.len), id.len);
}

/// Creates one operation ready to be settled.
pub fn seedOperation(store: *Store, request_id: []const u8) !void {
    return seedOperationOfKind(store, request_id, .exec);
}

/// Same, for tests that care which kind of work the operation represents —
/// evidence is only admissible for the kind of operation that produces it.
pub fn seedOperationOfKind(store: *Store, request_id: []const u8, kind: Store.operations.Kind) !void {
    try store.db.exec(
        \\INSERT INTO servers (id, name, host, port, username, created_at, updated_at)
        \\VALUES (1, 'race', '10.0.0.1', 22, 'ubuntu', 100, 100);
    );
    try Store.operations.create(store, .{
        .request_id = request_id,
        .server_id = 1,
        .server_name = "race",
        .kind = kind,
        .now = 100,
    });
    try Store.operations.advance(store, request_id, .connecting, 101);
    try Store.operations.advance(store, request_id, .submitted, 102);
}

/// Records the process identity a later probe will be checked against.
///
/// Written as an ordinary observation because that is how it is written for
/// real: `execution` reports the pid and start token the shell gave it for the
/// command it ran (`supervisor.Identity`). A gate that inserted the row by hand
/// would be proving something about a shape nothing produces.
pub fn recordProcess(
    store: *Store,
    request_id: []const u8,
    pid: i64,
    start_token: ?[]const u8,
    now: i64,
) !void {
    _ = try Store.receipts.append(store, .{
        .request_id = request_id,
        .kind = .remote_start,
        .observed_at = now,
        .remote_pid = pid,
        .remote_start_token = start_token,
    });
}

/// Records the launch a later `job_sentinel` resolution is checked against.
///
/// The counterpart of `recordProcess`, one evidence chain over, and written for
/// the same reason: `cmd_job` stores the sentinel it chose in `job_attempts`
/// before the launch line can reach the remote shell — `job_attempts.create` at
/// `cmd_job.zig:314`, some sixty lines ahead of `sendKeys` — so a sentinel that
/// could ever appear in a job's log is necessarily one this table already
/// carries. A gate that resolved from a sentinel with no attempt row behind it
/// would be proving something about a job that never launched.
///
/// The row has to match on all three of the things that make it this launch's:
/// the request id, the server, and the sentinel itself. A row that merely
/// exists would let the gate pass without the comparison ever having something
/// true to compare.
pub fn recordLaunchSentinel(
    store: *Store,
    request_id: []const u8,
    server_name: []const u8,
    job_name: []const u8,
    sentinel: []const u8,
    now: i64,
) !void {
    _ = try Store.job_attempts.create(store, .{
        .request_id = request_id,
        .server_id = 1,
        .server_name = server_name,
        .job_name = job_name,
        .attempt_no = try Store.job_attempts.nextAttemptNo(store, 1, job_name),
        .sentinel = sentinel,
        .now = now,
    });
}

pub fn seedServer(store: *Store) !void {
    try store.db.exec(
        \\INSERT INTO servers (id, name, host, port, username, created_at, updated_at)
        \\VALUES (1, 'lease-host', '10.0.0.1', 22, 'ubuntu', 100, 100);
    );
}

/// A transfer operation parked at `connecting`, i.e. before anything has been
/// sent. `seedOperationOfKind` runs on to `submitted`, which is exactly the
/// state the digest-declaration gate needs to be *outside* of.
pub fn seedTransferBeforeSubmit(store: *Store, request_id: []const u8) !void {
    store.db.exec(
        \\INSERT INTO servers (id, name, host, port, username, created_at, updated_at)
        \\VALUES (1, 'race', '10.0.0.1', 22, 'ubuntu', 100, 100);
    ) catch |err| switch (err) {
        // The second call in a test shares the first call's server.
        error.Constraint => {},
        else => return err,
    };
    try Store.operations.create(store, .{
        .request_id = request_id,
        .server_id = 1,
        .server_name = "race",
        .kind = .transfer_push,
        .now = 100,
    });
    try Store.operations.advance(store, request_id, .connecting, 101);
}

/// Settles the attempt that owns a checkpoint, which is what makes the
/// checkpoint adoptable at all.
///
/// `transfers.adoptLocked` refuses to take a checkpoint from an attempt that
/// may still be affecting the remote host: two live processes appending to one
/// partial is the failure that rule exists to stop. `local_abandon` is the
/// evidence that fits an attempt still at `created` or `connecting` — nothing
/// was handed over, so there is no remote absence to verify — and it settles
/// `cancelled`, which does not block scope.
pub fn abandonOwner(store: *Store, request_id: []const u8, reason: []const u8, now: i64) !void {
    _ = try Store.receipts.settle(
        store,
        request_id,
        .{ .local_abandon = .{ .reason = reason } },
        .{},
        now,
    );
}

/// A transfer operation and its checkpoint, aimed wherever the caller says.
///
/// The transition gates below all need the same three lines of setup and care
/// about nothing in it, so it lives here rather than five times over.
pub fn seedCheckpoint(
    store: *Store,
    request_id: []const u8,
    dest_path: []const u8,
    partial_path: []const u8,
) !i64 {
    store.db.exec(
        \\INSERT INTO servers (id, name, host, port, username, created_at, updated_at)
        \\VALUES (1, 'race', '10.0.0.1', 22, 'ubuntu', 100, 100);
    ) catch |err| switch (err) {
        // A test seeding a second operation shares the first one's server.
        error.Constraint => {},
        else => return err,
    };
    try Store.operations.create(store, .{
        .request_id = request_id,
        .server_id = 1,
        .server_name = "race",
        .kind = .transfer_push,
        .now = 100,
    });
    return Store.transfers.create(store, .{
        .request_id = request_id,
        .direction = .push,
        .dest_side = .{ .server = 1 },
        .dest_path = dest_path,
        .partial_path = partial_path,
        // Carries a content hash so a confirmed offset is storable: from v11 a
        // non-zero offset may only be recorded against an identifiable source.
        .source = .{ .local_file = .{ .path = "./out.bin", .sha256 = "aaaa" } },
        .chunk_size = 100,
        .now = 100,
    });
}

/// Walks an existing checkpoint the whole legal way to `published`, hashing its
/// result on the way past.
///
/// For gates whose subject is something else and which need a transfer that
/// *did* deliver. A checkpoint left in `planned` is not that: nothing has moved,
/// the destination is still only a claim, and `filesystem_effect` is refused
/// there because a digest match proves the reading is of the promised artifact
/// and not that this transfer put it where it is.
pub fn driveToPublished(
    store: *Store,
    id: i64,
    request_id: []const u8,
    sha256: []const u8,
) !void {
    var clock: i64 = 150;
    for ([_]Store.transfers.State{ .probing, .transferring, .verifying }) |step| {
        clock += 1;
        try Store.transfers.setState(store, id, request_id, step, null, clock);
    }
    try Store.transfers.recordVerifiedHash(store, id, request_id, sha256, clock + 1);
    try Store.transfers.setState(store, id, request_id, .publishing, null, clock + 2);
    try Store.transfers.setState(store, id, request_id, .published, null, clock + 3);
}

/// A push whose rename was issued and never confirmed: the checkpoint is parked
/// in `indeterminate_publish` and its operation is `indeterminate`, which is
/// the only pairing `receipts.resolve` will look at.
/// The digest is declared before submission and read back while verifying,
/// because that is what a real transfer does and what `published` demands. A
/// checkpoint that never hashed its own result cannot be adjudicated published
/// however good the evidence about the rename is — adjudication is the last
/// word on whether the rename landed, not on what the bytes were.
pub fn seedUnjudgedPublish(
    store: *Store,
    request_id: []const u8,
    dest_path: []const u8,
    partial_path: []const u8,
    sha256: []const u8,
) !i64 {
    return seedUnjudgedPublishDigests(store, request_id, dest_path, partial_path, sha256, sha256);
}

/// `seedUnjudgedPublish` with the two digest columns chosen independently.
///
/// The difference between the three combinations is the entire subject of the
/// wedge gates below, and it is one column each time. A transfer walks the same
/// edges to `indeterminate_publish` whether or not it declared a digest and
/// whether or not it lived long enough to record one; what a reconciler may then
/// conclude about it is completely different in the three cases, and a seed that
/// always fills both columns can only ever exercise the easiest of them.
pub fn seedUnjudgedPublishDigests(
    store: *Store,
    request_id: []const u8,
    dest_path: []const u8,
    partial_path: []const u8,
    declared: ?[]const u8,
    verified: ?[]const u8,
) !i64 {
    try seedTransferOperation(store, request_id, .transfer_push, 1);
    const id = try Store.transfers.create(store, .{
        .request_id = request_id,
        .direction = .push,
        .dest_side = .{ .server = 1 },
        .dest_path = dest_path,
        .partial_path = partial_path,
        .source = .{ .local_file = .{ .path = "./out.bin" } },
        .chunk_size = 100,
        .now = 110,
    });
    if (declared) |sha| try Store.transfers.recordExpectedHash(store, id, request_id, sha, 111);
    try Store.operations.advance(store, request_id, .submitted, 112);
    var clock: i64 = 112;
    for ([_]Store.transfers.State{ .probing, .transferring, .verifying }) |step| {
        clock += 1;
        try Store.transfers.setState(store, id, request_id, step, null, clock);
    }
    if (verified) |sha| try Store.transfers.recordVerifiedHash(store, id, request_id, sha, 120);
    try Store.transfers.setState(store, id, request_id, .publishing, null, 121);
    try Store.transfers.setState(store, id, request_id, .indeterminate_publish, "the rename never reported", 122);
    _ = try Store.receipts.settle(store, request_id, .{ .indeterminate = .{
        .reason = "the connection dropped after the rename was issued",
        .last_observed = .submitted,
    } }, .{}, 123);
    return id;
}

/// A transfer-shaped operation parked at `connecting`, of whatever kind and on
/// whatever server the caller needs — including none, for a `fetch`.
///
/// Two servers exist so a gate can aim a checkpoint at a machine its operation
/// is not bound to, which is the mismatch that has no single-table constraint
/// to catch it. They are inserted one statement at a time: a gate that already
/// seeded server 1 through another helper would otherwise have its duplicate
/// tolerated and server 2 silently skipped along with it.
pub fn seedTransferOperation(
    store: *Store,
    request_id: []const u8,
    kind: Store.operations.Kind,
    server_id: ?i64,
) !void {
    for ([_][:0]const u8{
        \\INSERT INTO servers (id, name, host, port, username, created_at, updated_at)
        \\VALUES (1, 'race', '10.0.0.1', 22, 'ubuntu', 100, 100);
        ,
        \\INSERT INTO servers (id, name, host, port, username, created_at, updated_at)
        \\VALUES (2, 'race2', '10.0.0.2', 22, 'ubuntu', 100, 100);
        ,
    }) |sql| store.db.exec(sql) catch |err| switch (err) {
        // A test seeding a second operation shares the first one's servers.
        error.Constraint => {},
        else => return err,
    };
    try Store.operations.create(store, .{
        .request_id = request_id,
        .server_id = server_id,
        .server_name = if (server_id == null) "local" else "race",
        .kind = kind,
        .now = 100,
    });
    try Store.operations.advance(store, request_id, .connecting, 101);
}

/// How many events of one kind the ledger holds for a request.
pub fn countKind(
    store: *Store,
    arena: std.mem.Allocator,
    request_id: []const u8,
    kind: []const u8,
) !usize {
    var n: usize = 0;
    for (try Store.receipts.list(store, arena, request_id)) |row| {
        if (std.mem.eql(u8, row.kind, kind)) n += 1;
    }
    return n;
}

/// The `jobs` writers return a refusal rather than an error, so a gate that
/// expected a write to land has to say so itself.
pub fn mustApply(write: Store.jobs.Write) !void {
    switch (write) {
        .applied => {},
        .refused => return error.JobsWriteRefused,
    }
}
