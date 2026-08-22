//! Gates for `terminus handoff`.
//!
//! **What is driven, and what is not — read this before the assertions.**
//!
//! All of it is driven. That is unusual in this tree and it is the point of the
//! verb: a handoff makes no remote call, so there is nothing here that needs a
//! host and nothing that has to be reviewed rather than proven. Every gate below
//! runs `gather` against a real sqlite store on disk under `.zig-cache/tmp`,
//! seeded through the store's own writers, and reads back the document a real
//! invocation would print.
//!
//! The one thing **reviewed rather than proven** is the human-readable rendering
//! (`printHandoff`), which needs a `Cli.Ctx` and a live writer. Every fact it
//! prints is read out of the same `HandoffJson` the gates hold, so a wrong value
//! there would be a formatting bug and not a wrong claim.
//!
//! What these gates establish:
//!
//!  * every section is answered, and each carries its **own** `observedAt` —
//!    asserted as five distinct timestamps, so a single document-wide clock
//!    would fail;
//!  * exactly one section reports `live`, and it is `errors`. No section that
//!    describes the host claims a live reading, which is what makes the offline
//!    guarantee structural rather than a promise;
//!  * a row this build refuses to interpret takes its own section down,
//!    `complete` goes false, `errors[]` names that section, and every other
//!    section is still carried;
//!  * a recognisable secret written into every column this verb can reach
//!    appears nowhere in the rendered document — including `jobs.command`, which
//!    holds raw command text and which this verb has no key for;
//!  * every `resume` argv names a real top-level command, and the two states
//!    where no argv can be honest carry none.
const std = @import("std");
const Cli = @import("cli.zig");
const Core = @import("../core/core.zig");
const Store = Core.Store;
const handoff = @import("cmd_handoff.zig");
const docker = @import("cmd_docker.zig");
const skill_doc = @import("skill_doc.zig");

const scratch_dir = ".zig-cache/tmp";

/// The module's own text, for the two rules that are about what it does *not*
/// contain. `@embedFile` on a sibling source file, the way `skill_doc` reaches
/// `SKILL.md`.
const module_source = @embedFile("cmd_handoff.zig");

// --- fixtures ----------------------------------------------------------------

/// A real store on disk under `.zig-cache/tmp`, with one server in it.
///
/// Never `%APPDATA%\terminus\terminus.db`: every path is built from
/// `scratch_dir` and the file is deleted on the way out, `-wal` and `-shm` too.
const Harness = struct {
    io: std.Io,
    threaded: *std.Io.Threaded,
    arena_state: *std.heap.ArenaAllocator,
    arena: std.mem.Allocator,
    path: [:0]u8,
    store: Store,
    allocator: std.mem.Allocator,

    var counter: std.atomic.Value(u32) = .init(0);

    fn init(allocator: std.mem.Allocator, name: []const u8) !Harness {
        const threaded = try allocator.create(std.Io.Threaded);
        threaded.* = .init(allocator, .{});
        const io = threaded.io();
        std.Io.Dir.cwd().createDirPath(io, scratch_dir) catch {};
        const n = counter.fetchAdd(1, .monotonic);
        const path = try std.fmt.allocPrintSentinel(allocator, "{s}/{s}_{d}_{d}.db", .{
            scratch_dir, name, std.Thread.getCurrentId(), n,
        }, 0);

        const cwd = std.Io.Dir.cwd();
        cwd.deleteFile(io, path) catch {};
        for ([_][]const u8{ "-wal", "-shm" }) |suffix| {
            const side = try std.fmt.allocPrint(allocator, "{s}{s}", .{ path, suffix });
            defer allocator.free(side);
            cwd.deleteFile(io, side) catch {};
        }

        const arena_state = try allocator.create(std.heap.ArenaAllocator);
        arena_state.* = std.heap.ArenaAllocator.init(allocator);

        var store = try Store.open(path);
        try store.db.exec(
            \\INSERT INTO servers (id, name, host, port, username, cwd, created_at, updated_at)
            \\VALUES (1, 'box', '10.0.0.1', 22, 'ubuntu', '/srv/app', 100, 100);
        );

        return .{
            .io = io,
            .threaded = threaded,
            .arena_state = arena_state,
            .arena = arena_state.allocator(),
            .path = path,
            .store = store,
            .allocator = allocator,
        };
    }

    fn deinit(h: *Harness) void {
        h.store.close();
        const cwd = std.Io.Dir.cwd();
        cwd.deleteFile(h.io, h.path) catch {};
        for ([_][]const u8{ "-wal", "-shm" }) |suffix| {
            const side = std.fmt.allocPrint(h.allocator, "{s}{s}", .{ h.path, suffix }) catch continue;
            defer h.allocator.free(side);
            cwd.deleteFile(h.io, side) catch {};
        }
        h.arena_state.deinit();
        h.allocator.destroy(h.arena_state);
        h.allocator.free(h.path);
        h.threaded.deinit();
        h.allocator.destroy(h.threaded);
    }

    fn gather(h: *Harness, now: i64) !handoff.Package {
        return handoff.gather(&h.store, h.arena, 1, "box", handoff.default_limit, now);
    }

    /// The document a real `--json` run would print.
    fn document(h: *Harness, now: i64) !handoff.HandoffJson {
        const package = try h.gather(now);
        const server = (try Store.servers.getByName(&h.store, h.arena, "box")).?;
        const workspace = if (server.cwd) |cwd|
            try Store.history.redactSecrets(h.arena, cwd)
        else
            null;
        return handoff.document(package, server, workspace, handoff.default_limit);
    }
};

/// A syntactically valid request id from a readable label.
///
/// Crockford base32 omits I, L, O and U, so a hand-written id is easy to get
/// wrong; this maps the confusable letters and pads to length. The shape
/// `gates_fixtures.testId` uses, local because that file is in `store/`.
fn testId(label: []const u8) [Store.ids.len]u8 {
    var out: [Store.ids.len]u8 = @splat('0');
    for (label, 0..) |ch, i| {
        if (i >= Store.ids.len) break;
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

/// The moment each section's freshest fact is seeded at.
///
/// Five *different* numbers, and that is the whole reason this exists: a
/// document reporting one clock for all six sections would satisfy every other
/// assertion in this file.
const seeded = struct {
    const memory: i64 = 1_000;
    const ledger: i64 = 2_100;
    const transfer: i64 = 2_500;
    const probe: i64 = 3_500;
    const lease: i64 = 4_200;
    /// When the handoff is taken. Later than every fact above, so a section that
    /// reported the read time instead of its fact's time is caught.
    const now: i64 = 9_000;
};

/// One exec attempt, submitted and never settled — the shape that bars a scope,
/// and the ledger's most important row for a handoff.
///
/// Its `updated_at` is `seeded.ledger`, which is deliberately later than every
/// other operation any fixture here creates: the ledger's `observedAt` is the
/// newest fact in the section, so it has to be *this* row's.
fn seedUnsettledExec(h: *Harness, id: []const u8, opts: struct {
    scope_key: []const u8 = "/srv/app",
    alias: []const u8 = "deploy",
    argv_redacted: []const u8 = "bash deploy.sh",
    cwd: []const u8 = "/srv/app",
    shell: []const u8 = "bash",
}) !void {
    try Store.operations.create(&h.store, .{
        .request_id = id,
        .server_id = 1,
        .server_name = "box",
        .kind = .exec,
        .scope_kind = .path,
        .scope_key = opts.scope_key,
        .alias = opts.alias,
        .argv_redacted = opts.argv_redacted,
        .argv_sha256 = "abc123",
        .cwd = opts.cwd,
        .shell = opts.shell,
        .transport = "direct",
        .now = seeded.ledger - 100,
    });
    try Store.operations.advance(&h.store, id, .connecting, seeded.ledger - 50);
    try Store.operations.advance(&h.store, id, .submitted, seeded.ledger);
}

/// A push checkpoint walked along the state graph to wherever the caller needs.
///
/// The walk is real: `setState` guards every edge against the graph in
/// `transfers.zig`, so a fixture that named an impossible sequence would refuse
/// rather than produce a row nothing can reach.
fn seedPush(
    h: *Harness,
    id: []const u8,
    dest: []const u8,
    steps: []const Store.transfers.State,
    last_at: i64,
) !i64 {
    try Store.operations.create(&h.store, .{
        .request_id = id,
        .server_id = 1,
        .server_name = "box",
        .kind = .transfer_push,
        .now = 100,
    });
    const cp = try Store.transfers.create(&h.store, .{
        .request_id = id,
        .direction = .push,
        .dest_side = .{ .server = 1 },
        .dest_path = dest,
        .partial_path = "/srv/app/out.bin.partial",
        .source = .{ .local_file = .{ .path = "./out.bin", .sha256 = "aaaa" } },
        .chunk_size = 100,
        .now = 110,
    });
    try Store.operations.advance(&h.store, id, .connecting, 111);
    try Store.operations.advance(&h.store, id, .submitted, 112);
    var clock: i64 = 120;
    for (steps, 0..) |step, i| {
        const at = if (i + 1 == steps.len) last_at else blk: {
            clock += 10;
            break :blk clock;
        };
        const reason: ?[]const u8 = switch (step) {
            .failed_no_space => "the device is full",
            .indeterminate_publish => "the rename never reported",
            else => null,
        };
        try Store.transfers.setState(&h.store, cp, id, step, reason, at);
    }
    return cp;
}

const paused_walk = [_]Store.transfers.State{ .probing, .transferring, .paused };
const failed_walk = [_]Store.transfers.State{ .probing, .transferring, .failed_no_space };
const unjudged_walk = [_]Store.transfers.State{
    .probing, .transferring, .verifying, .publishing, .indeterminate_publish,
};

/// A job with an attempt and a probe behind it.
///
/// Its operation is stamped well before `seeded.ledger` so the ledger's
/// `observedAt` stays the unsettled exec's; the *job* section's freshness comes
/// from the probe, which is the whole distinction under test.
fn seedJob(h: *Harness, id: []const u8, name: []const u8, command: []const u8, opts: struct {
    script_redacted: []const u8 = "bash migrate.sh",
    tmux_session: []const u8 = "job-migrate",
    cwd: []const u8 = "/srv/app",
    phase: []const u8 = "migrating",
    business_result: []const u8 = "rows=12",
}) !void {
    try Store.operations.create(&h.store, .{
        .request_id = id,
        .server_id = 1,
        .server_name = "box",
        .kind = .job,
        .alias = name,
        .now = 1_500,
    });
    _ = try Store.jobs.create(&h.store, 1, name, command, "SENT1NEL", id, 1_600);
    _ = try Store.job_attempts.create(&h.store, .{
        .request_id = id,
        .server_id = 1,
        .server_name = "box",
        .job_name = name,
        .attempt_no = try Store.job_attempts.nextAttemptNo(&h.store, 1, name),
        .sentinel = "SENT1NEL",
        .tmux_session = opts.tmux_session,
        .cwd = opts.cwd,
        .script_body_redacted = opts.script_redacted,
        .script_sha256 = "def456",
        .now = 1_700,
    });
    try Store.job_attempts.recordProbe(&h.store, id, .{
        .probe_cursor = 4096,
        .latest_phase = opts.phase,
        .latest_business_result = opts.business_result,
        .session_alive = true,
        .now = seeded.probe,
    });
}

fn seedLease(h: *Harness, owner: []const u8, opts: struct {
    scope_key: []const u8 = "/srv/app",
    owner_label: []const u8 = "agent-one",
    note: []const u8 = "mid-deploy",
}) !void {
    const outcome = try Store.leases.acquire(&h.store, h.arena, .{
        .server_id = 1,
        .scope = .{ .kind = .path, .key = opts.scope_key },
        .owner_request_id = owner,
        .profile_token = "profile-a",
        .owner_label = opts.owner_label,
        .note = opts.note,
        .ttl_secs = 100_000,
        .now = seeded.lease,
    });
    if (outcome != .acquired) return error.LeaseNotAcquired;
}

fn seedMemory(h: *Harness, key: []const u8, content: []const u8) !void {
    const result = try Store.memories.add(&h.store, .{ .server_id = 1 }, .{
        .key = key,
        .content = content,
        .tags = "deploy",
        .now = seeded.memory,
    });
    if (result != .inserted) return error.MemoryNotInserted;
}

/// Every section seeded, each at its own timestamp.
fn seedEverything(h: *Harness) !void {
    const exec_id = testId("handoffexec");
    const push_id = testId("handoffpush");
    const job_id = testId("handoffjob");
    try seedUnsettledExec(h, &exec_id, .{});
    _ = try seedPush(h, &push_id, "/srv/app/out.bin", &paused_walk, seeded.transfer);
    try seedJob(h, &job_id, "migrate", "bash migrate.sh", .{});
    try seedLease(h, &exec_id, .{});
    try seedMemory(h, "deploy-notes", "restart nginx after every push");
}

/// The document, rendered exactly as `--json` prints it.
fn render(arena: std.mem.Allocator, doc: handoff.HandoffJson) ![]u8 {
    var writer: std.Io.Writer.Allocating = .init(arena);
    try std.json.Stringify.value(doc, .{ .whitespace = .indent_2 }, &writer.writer);
    return writer.toOwnedSlice();
}

// --- gate: every section answered, with its own observedAt --------------------

test "gate: every section is answered with its own observedAt, and only errors is live" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "handoff_complete");
    defer h.deinit();
    try seedEverything(&h);

    const doc = try h.document(seeded.now);

    // Complete, and complete because every section was read — not because
    // nothing was attempted.
    try t.expect(doc.complete);
    try t.expect(doc.ok);
    try t.expectEqual(@as(usize, 0), doc.errors.len);
    try t.expectEqual(handoff.schema_version, doc.schemaVersion);
    try t.expectEqualStrings("box", doc.server);

    // Every section answered, counted so a section that silently vanished fails
    // here rather than being passed over.
    var answered: usize = 0;
    inline for (@typeInfo(handoff.Sections).@"struct".fields) |f| {
        const reading = @field(doc.sections, f.name);
        if (!reading.answered) {
            std.debug.print("\nsection `{s}` was not answered\n", .{f.name});
            return error.SectionUnanswered;
        }
        if (reading.source == null) {
            std.debug.print("\nsection `{s}` is answered with no source\n", .{f.name});
            return error.AnsweredSectionHasNoSource;
        }
        answered += 1;
    }
    try t.expectEqual(@as(usize, 6), answered);

    // The rows are really there, so nothing below is a test of five empty
    // sections agreeing about their emptiness.
    try t.expectEqual(@as(usize, 3), doc.sections.ledger.count);
    try t.expectEqual(@as(usize, 3), doc.ledger.len);
    try t.expectEqual(@as(usize, 1), doc.jobs.len);
    try t.expectEqual(@as(usize, 1), doc.transfers.len);
    try t.expectEqual(@as(usize, 1), doc.leases.len);
    try t.expectEqual(@as(usize, 1), doc.memories.len);

    // **The property this gate exists for.** Five facts established at five
    // different moments, reported as five different timestamps.
    try t.expectEqual(@as(?i64, seeded.ledger), doc.sections.ledger.observedAt);
    try t.expectEqual(@as(?i64, seeded.probe), doc.sections.jobs.observedAt);
    try t.expectEqual(@as(?i64, seeded.transfer), doc.sections.transfers.observedAt);
    try t.expectEqual(@as(?i64, seeded.lease), doc.sections.leases.observedAt);
    try t.expectEqual(@as(?i64, seeded.memory), doc.sections.memories.observedAt);
    // And none of them is the moment we looked, which is what a lazier
    // implementation would have reported for all five.
    inline for (.{ "ledger", "jobs", "transfers", "leases", "memories" }) |name| {
        if (@field(doc.sections, name).observedAt.? == seeded.now) {
            std.debug.print(
                \\
                \\section `{s}` dated its facts to the moment the handoff was taken. That is
                \\when we read the store, which is the same instant for all six sections and
                \\therefore says nothing about how stale this one is.
                \\
            , .{name});
            return error.SectionReportedReadTime;
        }
    }

    // **Exactly one section is `live`, and it is the one about this run.** No
    // section describing the host claims a live reading, because none of them
    // asked the host anything — the offline guarantee as a property of the
    // document rather than a promise in a comment.
    var live: usize = 0;
    inline for (@typeInfo(handoff.Sections).@"struct".fields) |f| {
        if (std.mem.eql(u8, @field(doc.sections, f.name).source.?, "live")) {
            live += 1;
            try t.expectEqualStrings("errors", f.name);
        }
    }
    try t.expectEqual(@as(usize, 1), live);
    try t.expectEqual(@as(?i64, seeded.now), doc.sections.errors.observedAt);

    // The five host-describing sections are `cache` — the arm `receipts.Source`
    // documents as having to travel with its `observed_at`, which is exactly
    // what the assertions above hold.
    inline for (.{ "ledger", "jobs", "transfers", "leases", "memories" }) |name| {
        try t.expectEqualStrings("cache", @field(doc.sections, name).source.?);
    }

    // Every source word is one of the ledger's own, never a vocabulary this file
    // invented.
    var vocabulary: usize = 0;
    inline for (@typeInfo(handoff.Sections).@"struct".fields) |f| {
        const word = @field(doc.sections, f.name).source.?;
        if (std.meta.stringToEnum(Store.receipts.Source, word) == null) {
            std.debug.print(
                "\nsection `{s}` reports source `{s}`, which is not a receipts.Source\n",
                .{ f.name, word },
            );
            return error.SourceOutsideVocabulary;
        }
        vocabulary += 1;
    }
    try t.expectEqual(@as(usize, 6), vocabulary);

    // The rows a handoff exists to surface: attempts that may still be touching
    // the host. Two of the three, and the third is a job launch still at
    // `created`, which has sent nothing.
    var blocking: usize = 0;
    for (doc.ledger) |op| {
        if (op.blocksScope) blocking += 1;
    }
    try t.expectEqual(@as(usize, 2), blocking);

    // The job's freshness is the probe's, and the probe is where the schema puts
    // it ("`job ls` and offline handoff read, always alongside last_probed_at").
    try t.expectEqual(@as(?i64, seeded.probe), doc.jobs[0].lastProbedAt);
    try t.expect(doc.jobs[0].live);
    try t.expectEqualStrings("migrating", doc.jobs[0].latestPhase.?);
    try t.expectEqualStrings("bash migrate.sh", doc.jobs[0].scriptRedacted.?);

    // A checkpoint that is resumable and still standing on its destination.
    try t.expectEqualStrings("paused", doc.transfers[0].state);
    try t.expect(doc.transfers[0].resumable);
    try t.expect(doc.transfers[0].holdsDestination);
    try t.expectEqualStrings("server:1", doc.transfers[0].destSide);
    try t.expectEqualStrings("./out.bin", doc.transfers[0].sourceRef.?);

    // The lease is somebody's live claim, reported with the owner a conflict is
    // actually decided by.
    try t.expectEqualStrings("/srv/app", doc.leases[0].scopeKey);
    try t.expectEqual(@as(i64, seeded.lease), doc.leases[0].renewedAt);
}

test "gate: a reconciled ledger row is reported as reconcile, not as cache" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "handoff_reconciled");
    defer h.deinit();

    const id = testId("handoffrecon");
    try seedUnsettledExec(&h, &id, .{});
    // The shape `receipts.resolve` leaves: the observed status is kept and the
    // proven one recorded beside it, dated. Written directly because what is
    // under test is how a handoff *reads* those two columns.
    try h.store.db.exec(
        \\UPDATE operations SET resolved_status = 'completed', reconciled_at = 2900
        \\WHERE status = 'submitted';
    );

    const doc = try h.document(seeded.now);

    try t.expect(doc.complete);
    try t.expectEqual(@as(usize, 1), doc.ledger.len);
    // The freshest fact in the section is the reconciliation, so that is what
    // `observedAt` names and what `source` describes. A status proven against
    // the host has a different standing from one we merely last believed, and
    // this is where the third arm of the vocabulary earns its keep.
    try t.expectEqualStrings("reconcile", doc.sections.ledger.source.?);
    try t.expectEqual(@as(?i64, 2900), doc.sections.ledger.observedAt);
    // And the original observation is still there, unrewritten.
    try t.expectEqualStrings("submitted", doc.ledger[0].status);
    try t.expectEqualStrings("completed", doc.ledger[0].resolvedStatus.?);
    try t.expectEqualStrings("completed", doc.ledger[0].effectiveStatus);
    // A resolved attempt no longer bars a change, and so is offered no
    // reconcile argv.
    try t.expect(!doc.ledger[0].blocksScope);
    for (doc.@"resume") |entry| {
        if (std.mem.eql(u8, entry.section, "ledger")) return error.SettledAttemptOfferedAReconcile;
    }
}

// --- gate: one section fails, the rest survive --------------------------------

test "gate: a section this build refuses to read leaves complete false and names itself" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "handoff_partial");
    defer h.deinit();
    try seedEverything(&h);

    // `jobs.status` is bare `TEXT NOT NULL` in the schema, so a row can carry a
    // word this build's vocabulary does not have. `jobs.Status.parse` refuses it
    // rather than guessing — that refusal is the realistic way a section fails,
    // and a handoff is where it surfaces.
    try h.store.db.exec("UPDATE jobs SET status = 'probably-fine' WHERE name = 'migrate';");

    const doc = try h.document(seeded.now);

    // Not complete, and not ok. A document that dropped the jobs section and
    // still said `complete: true` is the pseudo-success this verb exists not to
    // be.
    try t.expect(!doc.complete);
    try t.expect(!doc.ok);

    // The failure names its section and its refusal, with something to act on.
    try t.expectEqual(@as(usize, 1), doc.errors.len);
    try t.expectEqualStrings("jobs", doc.errors[0].section);
    try t.expectEqualStrings("UnknownStatus", doc.errors[0].code);
    try t.expect(std.mem.indexOf(u8, doc.errors[0].detail, "terminus job ls") != null);

    // The section says it was not read, and says it with no provenance rather
    // than with a plausible one.
    try t.expect(!doc.sections.jobs.answered);
    try t.expectEqual(@as(?[]const u8, null), doc.sections.jobs.source);
    try t.expectEqual(@as(?i64, null), doc.sections.jobs.observedAt);
    try t.expectEqual(@as(usize, 0), doc.sections.jobs.count);
    try t.expectEqual(@as(usize, 0), doc.jobs.len);

    // **And every other section is still carried.** A handoff that gave up
    // wholesale over one bad row would be useless at the moment it is needed.
    var survivors: usize = 0;
    inline for (.{ "ledger", "transfers", "leases", "memories", "errors" }) |name| {
        if (!@field(doc.sections, name).answered) {
            std.debug.print("\nsection `{s}` was dropped along with `jobs`\n", .{name});
            return error.UnrelatedSectionDropped;
        }
        survivors += 1;
    }
    try t.expectEqual(@as(usize, 5), survivors);
    try t.expectEqual(@as(usize, 3), doc.ledger.len);
    try t.expectEqual(@as(usize, 1), doc.transfers.len);
    try t.expectEqual(@as(usize, 1), doc.leases.len);
    try t.expectEqual(@as(usize, 1), doc.memories.len);

    // The errors section is itself answered and counts what it holds, so the
    // document reports its own gaps rather than merely having them.
    try t.expect(doc.sections.errors.answered);
    try t.expectEqual(@as(usize, 1), doc.sections.errors.count);

    // The jobs resume entry is gone with its section: a live job nobody could
    // read must not produce an argv aimed at it.
    for (doc.@"resume") |entry| {
        if (std.mem.eql(u8, entry.section, "jobs")) return error.ResumeOfferedForUnreadSection;
    }

    // Every `Section` has its own cost sentence: which one failed decides what
    // the reader may still do, so a shared sentence would lose that.
    const names = @typeInfo(handoff.Section).@"enum".fields;
    try t.expectEqual(@as(usize, 6), names.len);
    var pairs: usize = 0;
    inline for (names, 0..) |a, i| {
        inline for (names, 0..) |b, j| {
            if (i >= j) continue;
            pairs += 1;
            const first: handoff.Section = @enumFromInt(a.value);
            const second: handoff.Section = @enumFromInt(b.value);
            if (std.mem.eql(u8, first.cost(), second.cost())) {
                std.debug.print("\n`{s}` and `{s}` share one cost sentence\n", .{ a.name, b.name });
                return error.SharedSectionCost;
            }
        }
    }
    try t.expectEqual(@as(usize, 15), pairs);
}

test "gate: a ledger that cannot be read takes transfers with it, under its own name" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "handoff_ledger_gone");
    defer h.deinit();
    try seedEverything(&h);

    // The transfers section is enumerated through the attempts that own the
    // checkpoints, so it genuinely depends on the ledger window. The rename is
    // legacy-mode so the references in other tables are left alone: what breaks
    // is the ledger read and nothing else.
    try h.store.db.exec(
        \\PRAGMA legacy_alter_table = ON;
        \\ALTER TABLE operations RENAME TO operations_gone;
    );

    const doc = try h.document(seeded.now);

    try t.expect(!doc.complete);
    // Two failures, not one, and neither hides behind the other: the ledger
    // could not be read, and *therefore* the checkpoints could not be
    // enumerated. Reporting zero transfers would have been the wrong answer.
    try t.expectEqual(@as(usize, 2), doc.errors.len);
    var named: usize = 0;
    for (doc.errors) |e| {
        if (std.mem.eql(u8, e.section, "ledger")) named += 1;
        if (std.mem.eql(u8, e.section, "transfers")) {
            named += 1;
            try t.expectEqualStrings("LedgerWindowUnavailable", e.code);
        }
    }
    try t.expectEqual(@as(usize, 2), named);
    try t.expect(!doc.sections.ledger.answered);
    try t.expect(!doc.sections.transfers.answered);

    // The sections that do not go through the ledger are unaffected.
    try t.expect(doc.sections.leases.answered);
    try t.expect(doc.sections.memories.answered);
    try t.expectEqual(@as(usize, 1), doc.memories.len);
    try t.expectEqual(@as(usize, 1), doc.leases.len);
}

// --- gate: offline ------------------------------------------------------------

test "gate: a handoff reaches no host, so an offline one answers every section" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "handoff_offline");
    defer h.deinit();
    try seedEverything(&h);

    // There is no host in this test and no way to reach one, so a handoff cannot
    // degrade for want of a connection. The document proves it by being
    // complete, with every section carrying rows.
    const doc = try h.document(seeded.now);
    try t.expect(doc.complete);
    try t.expectEqual(@as(usize, 0), doc.errors.len);
    var populated: usize = 0;
    inline for (.{ "ledger", "jobs", "transfers", "leases", "memories" }) |name| {
        if (@field(doc.sections, name).count == 0) {
            std.debug.print("\nsection `{s}` is empty, so this gate proves nothing about it\n", .{name});
            return error.OfflineGateOverAnEmptySection;
        }
        populated += 1;
    }
    try t.expectEqual(@as(usize, 5), populated);

    // `gather`'s signature is the structural half of the claim: a store, an
    // arena, a server id, a server name, a window and a clock. No executor, no
    // connection, no `std.Io` — a round trip cannot be added without changing
    // this list, and this is where that change stops.
    const params = @typeInfo(@TypeOf(handoff.gather)).@"fn".params;
    try t.expectEqual(@as(usize, 6), params.len);
    var scanned: usize = 0;
    inline for (params) |p| {
        scanned += 1;
        const T = p.type.?;
        const carries_transport = T == Core.Executor or T == Core.Ssh or
            T == *Core.Ssh or T == std.Io;
        if (carries_transport) {
            std.debug.print("\nhandoff.gather takes a transport in position {d}\n", .{scanned});
            return error.GatherTookATransport;
        }
    }
    try t.expectEqual(@as(usize, 6), scanned);

    // And the module's *code* names no transport at all. A text rule rather than
    // a type rule because the way this would really happen is a helper added
    // later that dials on the side, and such a helper would not appear in the
    // signature above.
    //
    // Over the code and not the comments, which is not a convenience: the header
    // of `cmd_handoff.zig` explains at length why the file never calls
    // `Cli.resolveServer`, and a rule that read prose would be failed by its own
    // documentation.
    const code = try codeOnly(h.arena);
    var refused: usize = 0;
    for ([_][]const u8{
        "Core.Executor",
        "Core.Ssh",
        "Cli.connect",
        "Cli.resolveServer",
        ".executor()",
        "Store.keys",
        "sshConnect",
    }) |needle| {
        refused += 1;
        if (std.mem.indexOf(u8, code, needle) != null) {
            std.debug.print(
                \\
                \\cmd_handoff.zig calls `{s}`. A handoff that dials is one that stops working
                \\when the host is down, which is the one situation it exists for — and
                \\resolving a server in particular loads private key material.
                \\
            , .{needle});
            return error.HandoffReachesForATransport;
        }
    }
    try t.expectEqual(@as(usize, 7), refused);

    // The scan really is over the module's code: a source that failed to embed,
    // or a stripper that removed everything, would satisfy every absence above.
    try t.expect(std.mem.indexOf(u8, code, "pub fn gather(") != null);
    try t.expect(std.mem.indexOf(u8, code, "Store.servers.getByName") != null);
    try t.expect(code.len > 1024);
    try t.expect(code.len < module_source.len);
    // And the comments really were the thing removed, so the rule above is not
    // quietly reading the whole file after all.
    try t.expect(std.mem.indexOf(u8, module_source, "Cli.resolveServer") != null);
    try t.expect(module_source.len > 4096);
}

/// `cmd_handoff.zig` with its comment lines removed.
///
/// So the two absence rules above are about what the module *does* rather than
/// about what it says. Every rule in this tree that greps source text has this
/// problem; here it is not hypothetical, because the file's header names three of
/// the seven forbidden symbols in order to explain why it does not use them.
fn codeOnly(arena: std.mem.Allocator) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var lines = std.mem.splitScalar(u8, module_source, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trimStart(u8, line, " \t");
        // `//`, `///` and `//!` all start the same way, and all three are prose.
        if (std.mem.startsWith(u8, trimmed, "//")) continue;
        try out.appendSlice(arena, line);
        try out.append(arena, '\n');
    }
    return out.toOwnedSlice(arena);
}

// --- gate: secrets ------------------------------------------------------------

test "gate: a secret in every reachable column reaches no field of the document" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "handoff_secret");
    defer h.deinit();

    // Three recognisable shapes, because `redactSecrets` recognises shapes and
    // not strings: an env assignment, a bare API key, and a header value — the
    // last being what the redactor was extended for in the previous commit.
    // Every seeded value is one of these three, so a field that reached the
    // document unmasked shows up as the needle.
    const env_secret = "AWS_SECRET_ACCESS_KEY=hunter2trombonestaple";
    const bare_secret = "sk-ant-hunter2trombonestaple";
    const header_secret = "curl -H 'Cookie: session=hunter2trombonestaple' https://api";
    const needle = "hunter2trombonestaple";
    // In the `keys` table, which this verb must not be able to reach at all. It
    // matches no redaction pattern, which is exactly what makes it a canary: if
    // it ever appeared, no redactor would have masked it.
    const key_material = "-----BEGIN OPENSSH PRIVATE KEY-----hunter2trombonestaple";

    const exec_id = testId("secretexec");
    const push_id = testId("secretpush");
    const job_id = testId("secretjob");

    // Seeded through the store's own writers where they take the field, then the
    // columns those writers do not expose are set directly. Counted, so a
    // fixture that stopped seeding a field cannot make this gate pass over an
    // absence.
    var fields: usize = 0;

    try seedUnsettledExec(&h, &exec_id, .{
        .scope_key = env_secret,
        .alias = bare_secret,
        // Deliberately *not* redacted, standing in for a writer that failed to
        // redact. The column's contract says it is already masked; this verb
        // does not take that on trust.
        .argv_redacted = header_secret,
        .cwd = env_secret,
        .shell = bare_secret,
    });
    fields += 5;

    // `jobs.command` holds the RAW command — `cmd_job` binds `raw_command`
    // straight into `jobs.create`. This is the column a handoff must have no key
    // for, and the one new leak this verb could have introduced.
    try seedJob(&h, &job_id, "deploy", header_secret, .{
        .script_redacted = header_secret,
        .tmux_session = bare_secret,
        .cwd = env_secret,
        .phase = env_secret,
        .business_result = bare_secret,
    });
    fields += 6;

    _ = try seedPush(&h, &push_id, "/srv/app/out.bin", &failed_walk, seeded.transfer);
    try h.store.db.exec(
        \\UPDATE transfer_checkpoints
        \\SET dest_path = 'AWS_SECRET_ACCESS_KEY=hunter2trombonestaple',
        \\    partial_path = 'sk-ant-hunter2trombonestaple',
        \\    source_path = 'AWS_SECRET_ACCESS_KEY=hunter2trombonestaple',
        \\    failure_reason = 'sk-ant-hunter2trombonestaple';
    );
    fields += 4;

    try seedLease(&h, &exec_id, .{
        .scope_key = env_secret,
        .owner_label = bare_secret,
        .note = header_secret,
    });
    fields += 3;

    try seedMemory(&h, env_secret, header_secret);
    try h.store.db.exec("UPDATE memories SET tags = 'sk-ant-hunter2trombonestaple';");
    fields += 3;

    // The `keys` table, which must not be within reach of this verb at all.
    try h.store.db.exec(
        \\INSERT INTO keys (name, kind, private_pem, created_at)
        \\VALUES ('box-key', 'ssh', '-----BEGIN OPENSSH PRIVATE KEY-----hunter2trombonestaple', 100);
    );
    fields += 1;

    // The server's own workspace, which travels into the document as a key.
    try h.store.db.exec(
        \\UPDATE servers SET cwd = 'AWS_SECRET_ACCESS_KEY=hunter2trombonestaple' WHERE id = 1;
    );
    fields += 1;

    try t.expectEqual(@as(usize, 23), fields);

    const doc = try h.document(seeded.now);
    const rendered = try render(h.arena, doc);

    // Complete, so the scan below is over a document that really has all six
    // sections in it. An incomplete handoff would trivially carry no secret.
    try t.expect(doc.complete);
    try t.expect(rendered.len > 1024);

    // **The whole point.** Not one occurrence, anywhere in the rendered
    // document, in any of the three shapes.
    if (std.mem.indexOf(u8, rendered, needle)) |at| {
        std.debug.print(
            \\
            \\a secret reached the handoff document at byte {d}:
            \\
            \\  ...{s}...
            \\
            \\`docs/v2.0文档.md` line 170: a secret entering a handoff blocks the release.
            \\Every string in this document goes through `scrub`; something bypassed it.
            \\
        , .{ at, rendered[at -| 120..@min(rendered.len, at + 80)] });
        return error.SecretReachedTheHandoff;
    }

    // The raw command is not merely masked, it is absent: `JobEntry` has no key
    // for it. Held both ways — the shape of the struct, and the text of the
    // rendered document.
    var command_keys: usize = 0;
    inline for (@typeInfo(handoff.JobEntry).@"struct".fields) |f| {
        if (comptime std.mem.eql(u8, f.name, "command")) command_keys += 1;
    }
    try t.expectEqual(@as(usize, 0), command_keys);
    try t.expect(std.mem.indexOf(u8, rendered, "\"command\"") == null);

    // The key material is absent, and this gate would have caught it: the same
    // needle is inside it.
    try t.expect(std.mem.indexOf(u8, rendered, "BEGIN OPENSSH") == null);
    try t.expect(std.mem.indexOf(u8, key_material, needle) != null);

    // And the redactor really ran, rather than the document happening to carry
    // none of these fields. Counted: one masked value would not tell us the
    // whole document was scanned.
    const masked = std.mem.count(u8, rendered, "[REDACTED]");
    if (masked < 15) {
        std.debug.print(
            \\
            \\only {d} value(s) in the handoff were masked. The fixture seeds a secret into
            \\every column this verb reads, so a document with almost none masked is one
            \\that is not carrying those columns at all — and this gate would then be
            \\proving nothing.
            \\
        , .{masked});
        return error.DocumentCarriesTooLittleToProveAnything;
    }

    // The columns really did keep the secret, so the absence above is redaction
    // and not a store that never stored it.
    var stored: i64 = 0;
    var stmt = try h.store.db.prepare(
        "SELECT COUNT(*) FROM jobs WHERE command LIKE '%hunter2trombonestaple%'",
    );
    defer stmt.deinit();
    if (try stmt.step()) stored = stmt.columnInt(0);
    try t.expectEqual(@as(i64, 1), stored);
}

// --- gate: the key set -------------------------------------------------------

test "gate: the published key set is exactly this, and the section names are the vocabulary" {
    const t = std.testing;

    // Line 107 of the goal document names five of these by hand: schemaVersion,
    // complete, errors, source/observedAt (per section) and resume argv. All
    // five are here, and pinned in order so a key cannot be added, renamed or
    // reordered silently.
    const document_keys = [_][]const u8{
        "ok",     "schemaVersion", "complete", "server", "workspace",
        "limit",  "sections",      "ledger",   "jobs",   "transfers",
        "leases", "memories",      "errors",   "resume",
    };
    const section_keys = [_][]const u8{ "ledger", "jobs", "transfers", "leases", "memories", "errors" };
    const reading_keys = [_][]const u8{ "answered", "source", "observedAt", "count" };
    const ledger_keys = [_][]const u8{
        "requestId",    "kind",       "status",       "resolvedStatus", "effectiveStatus",
        "blocksScope",  "mutating",   "scopeKind",    "scopeKey",       "alias",
        "argvRedacted", "argvSha256", "cwd",          "shell",          "transport",
        "createdAt",    "updatedAt",  "reconciledAt",
    };
    const job_keys = [_][]const u8{
        "name",                 "status",         "live",        "exitCode",
        "readCursor",           "ownerRequestId", "attemptNo",   "scriptRedacted",
        "scriptSha256",         "tmuxSession",    "cwd",         "latestPhase",
        "latestBusinessResult", "sessionAlive",   "probeCursor", "lastProbedAt",
        "createdAt",            "finishedAt",
    };
    const transfer_keys = [_][]const u8{
        "requestId",      "direction",       "state",         "holdsDestination",
        "resumable",      "destSide",        "destPath",      "partialPath",
        "partialLen",     "confirmedOffset", "totalBytes",    "chunkSize",
        "expectedSha256", "verifiedSha256",  "partialSha256", "noClobber",
        "sourceKind",     "sourceRef",       "failureReason", "createdAt",
        "updatedAt",
    };
    const lease_keys = [_][]const u8{
        "scopeKind", "scopeKey",   "ownerRequestId", "profileToken", "ownerLabel",
        "note",      "acquiredAt", "renewedAt",      "expiresAt",
    };
    const memory_keys = [_][]const u8{ "session", "key", "content", "tags", "updatedAt" };
    const error_keys = [_][]const u8{ "section", "code", "detail" };
    const resume_keys = [_][]const u8{ "section", "subject", "argv", "why" };

    const cases = .{
        .{ handoff.HandoffJson, &document_keys },
        .{ handoff.Sections, &section_keys },
        .{ handoff.Reading, &reading_keys },
        .{ handoff.LedgerEntry, &ledger_keys },
        .{ handoff.JobEntry, &job_keys },
        .{ handoff.TransferEntry, &transfer_keys },
        .{ handoff.LeaseEntry, &lease_keys },
        .{ handoff.MemoryEntry, &memory_keys },
        .{ handoff.ErrorEntry, &error_keys },
        .{ handoff.ResumeEntry, &resume_keys },
    };

    var pinned: usize = 0;
    inline for (cases) |case| {
        const struct_fields = @typeInfo(case[0]).@"struct".fields;
        const expected: []const []const u8 = case[1];
        // A count first, so a key added or dropped fails here rather than being
        // missed by a loop that only checks the ones it knows about.
        try t.expectEqual(expected.len, struct_fields.len);
        inline for (struct_fields, 0..) |f, i| {
            // `resume` is a Zig keyword, so the field is `@"resume"` and the
            // published key is `resume`. Compared against the published name.
            try t.expectEqualStrings(expected[i], f.name);
        }
        pinned += struct_fields.len;
    }
    try t.expectEqual(@as(usize, 10), cases.len);
    try t.expectEqual(@as(usize, 102), pinned);

    // `Sections` is the `Section` enum, field for field and in order. Two lists
    // that could drift is how a section ends up with a name nothing reports
    // under.
    const members = @typeInfo(handoff.Section).@"enum".fields;
    const section_fields = @typeInfo(handoff.Sections).@"struct".fields;
    try t.expectEqual(members.len, section_fields.len);
    inline for (members, section_fields) |m, f| try t.expectEqualStrings(m.name, f.name);
    try t.expectEqual(@as(usize, 6), members.len);

    // The no-defaults rule this document follows is held for all thirteen
    // published documents by `gate: no published document has a field with a
    // default`, below. It used to be checked here, for this struct alone.
}

// --- gate: the no-defaults rule, over every published document ---------------
//
// Every `*Json` document in this tree is a struct with **no defaults**, so a
// branch that omits a key does not compile. `ReceiptFatalJson` in `cli.zig`
// states the rule and twelve other structs cite it, and every key-set gate in
// this tree rests on it: a key set says which keys exist and says nothing about
// whether a branch had to supply them. A field that gains a default keeps its
// name, is still emitted on the branches that fill it, and passes every one of
// those gates while a branch that omits it starts compiling.
//
// It was enforced for exactly one of the thirteen — `HandoffJson`, three lines
// above this comment — which is what this replaces.
//
// **Why a text scan and not `@typeInfo`.** Ten of the thirteen are private to
// their command's module, and `@typeInfo` cannot reach a decl that is not `pub`.
// Making six modules' documents public to be testable would widen six surfaces
// for a rule that is a property of their text. So the source is read — the way
// `skill_doc` reads `SKILL.md` and `Control.bodyOf` reads a function body — and
// the three that *are* reachable are then held against the compiler, field name
// for field name and default for default. That cross-check is what says the
// scanner sees what `@typeInfo` sees; without it a scan that silently matched
// nothing would report the rule as kept.
//
// It lives in this file because this is where the rule's only enforcement
// already lived. None of the six files below is this one, so the needle can be
// spelled whole here — a scanner that lived inside its own subject would find
// itself.

/// Every source that declares a published document, embedded so the rule can be
/// held against the text that has to have it.
const document_sources = [_]struct { name: []const u8, text: []const u8 }{
    .{ .name = "cli.zig", .text = @embedFile("cli.zig") },
    .{ .name = "cmd_docker.zig", .text = @embedFile("cmd_docker.zig") },
    .{ .name = "cmd_handoff.zig", .text = module_source },
    .{ .name = "cmd_job.zig", .text = @embedFile("cmd_job.zig") },
    .{ .name = "cmd_memory.zig", .text = @embedFile("cmd_memory.zig") },
    .{ .name = "cmd_session.zig", .text = @embedFile("cmd_session.zig") },
};

/// How many document structs those six files declare between them, and how many
/// fields they carry. Both asserted, because a scan that has stopped covering a
/// file — a renamed struct, a moved terminator, a body that grew a method above
/// its fields — walks an empty region and reports success.
const document_struct_count = 13;
const document_field_count = 173;

/// One document struct as the text has it.
const DocumentStruct = struct {
    file: []const u8,
    name: []const u8,
    /// Field lines, trimmed, in declaration order.
    fields: []const []const u8,
};

/// The field name a declaration line carries, `@"…"` unwrapped so it is the key
/// that gets published rather than the Zig spelling of it.
fn documentFieldName(line: []const u8) []const u8 {
    const colon = std.mem.indexOfScalar(u8, line, ':') orelse return line;
    var name = std.mem.trim(u8, line[0..colon], " \t");
    if (std.mem.startsWith(u8, name, "@\"") and std.mem.endsWith(u8, name, "\""))
        name = name[2 .. name.len - 1];
    return name;
}

fn scanDocumentStructs(
    arena: std.mem.Allocator,
    out: *std.ArrayList(DocumentStruct),
) !void {
    const opener = "Json = struct {";
    for (document_sources) |source| {
        var from: usize = 0;
        while (std.mem.indexOfPos(u8, source.text, from, opener)) |at| {
            from = at + 1;
            const line_start = if (std.mem.lastIndexOfScalar(u8, source.text[0..at], '\n')) |nl| nl + 1 else 0;
            const decl = source.text[line_start .. at + opener.len];
            // A top-level `const Name = struct {`. A nested or indented one
            // would close with something other than `};` in column zero, so the
            // body walk below would be reading the wrong region — refused rather
            // than guessed at.
            const keyword = std.mem.indexOf(u8, decl, "const ") orelse {
                std.debug.print("\n{s}: a document struct is declared as `{s}`, which this scan cannot delimit\n", .{ source.name, decl });
                return error.DocumentStructIsNotAConstDeclaration;
            };
            if (keyword != 0 and !std.mem.startsWith(u8, decl, "pub const ")) {
                std.debug.print("\n{s}: a document struct is not a top-level declaration: `{s}`\n", .{ source.name, decl });
                return error.DocumentStructIsNotTopLevel;
            }
            const name_start = keyword + "const ".len;
            const name_end = std.mem.indexOfScalarPos(u8, decl, name_start, ' ') orelse decl.len;
            const body_start = std.mem.indexOfScalarPos(u8, source.text, at, '\n').? + 1;
            const body_end = std.mem.indexOfPos(u8, source.text, body_start, "\n};\n") orelse {
                std.debug.print("\n{s}: `{s}` has no `}};` in column zero to end it\n", .{ source.name, decl });
                return error.DocumentStructUnterminated;
            };

            var fields: std.ArrayList([]const u8) = .empty;
            var lines = std.mem.splitScalar(u8, source.text[body_start..body_end], '\n');
            while (lines.next()) |raw| {
                const line = std.mem.trim(u8, raw, " \t\r");
                if (line.len == 0 or std.mem.startsWith(u8, line, "//")) continue;
                // The fields come first in all thirteen. The first method or
                // nested declaration ends the region; the asserted counts above
                // are what catch a struct that ever stops being written that way.
                if (std.mem.startsWith(u8, line, "fn ") or
                    std.mem.startsWith(u8, line, "pub fn ") or
                    std.mem.startsWith(u8, line, "const ") or
                    std.mem.startsWith(u8, line, "pub const ") or
                    // Spelled in halves on purpose. `tools/mutate.py` derives
                    // every gate name it can resolve by matching `test "…"`
                    // against the source, so this literal written whole makes
                    // that regex swallow the opening quote of the next real test
                    // in this file — and the anchor for the gate below then
                    // reports UNRESOLVED. It did exactly that once.
                    std.mem.startsWith(u8, line, "tes" ++ "t ")) break;
                try fields.append(arena, line);
            }
            try out.append(arena, .{
                .file = source.name,
                .name = decl[name_start..name_end],
                .fields = try fields.toOwnedSlice(arena),
            });
        }
    }
}

test "gate: no published document has a field with a default, in any of the six modules" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var found: std.ArrayList(DocumentStruct) = .empty;
    try scanDocumentStructs(arena, &found);
    try t.expectEqual(@as(usize, document_struct_count), found.items.len);

    var fields: usize = 0;
    for (found.items) |doc| {
        if (doc.fields.len == 0) {
            std.debug.print("\n{s}: `{s}` scanned as having no fields at all\n", .{ doc.file, doc.name });
            return error.DocumentStructHasNoFields;
        }
        fields += doc.fields.len;
        for (doc.fields) |line| {
            if (std.mem.indexOfScalar(u8, line, '=') == null) continue;
            std.debug.print(
                \\
                \\{s}: `{s}.{s}` carries a default.
                \\
                \\  {s}
                \\
                \\Every published document in this tree is a struct with no defaults, so that a
                \\branch which omits a key does not compile — the rule `ReceiptFatalJson` states
                \\in `cli.zig`. A field with a default keeps its name and is still emitted by the
                \\branches that fill it, so every key-set gate in this tree goes on passing while
                \\a branch that says nothing about it starts compiling. What an agent then reads
                \\is a key whose presence no longer means anybody looked.
                \\
                \\If the value really is the same on every branch, it is not a default: state it
                \\at each site, or compute it in the function that builds the document.
                \\
            , .{ doc.file, doc.name, documentFieldName(line), line });
            return error.PublishedDocumentFieldHasADefault;
        }
    }
    try t.expectEqual(@as(usize, document_field_count), fields);

    // The scanner against the compiler, on the three documents that are `pub`.
    // Same names, same order, same count — and the compiler's own answer to the
    // question the scan just answered from text.
    const reachable = .{
        .{ "InspectJson", docker.InspectJson },
        .{ "WaitJson", docker.WaitJson },
        .{ "HandoffJson", handoff.HandoffJson },
    };
    var cross_checked: usize = 0;
    inline for (reachable) |pair| {
        const doc = for (found.items) |d| {
            if (std.mem.eql(u8, d.name, pair[0])) break d;
        } else {
            std.debug.print("\n`{s}` is reachable from here and the scan did not find it\n", .{pair[0]});
            return error.ReachableDocumentWasNotScanned;
        };
        const compiled = @typeInfo(pair[1]).@"struct".fields;
        try t.expectEqual(compiled.len, doc.fields.len);
        inline for (compiled, 0..) |f, i| {
            try t.expectEqualStrings(f.name, documentFieldName(doc.fields[i]));
            try t.expect(f.default_value_ptr == null);
        }
        cross_checked += 1;
    }
    try t.expectEqual(@as(usize, 3), cross_checked);
}

// --- gate: resume argv -------------------------------------------------------

test "gate: every resume argv runs as written, and the dishonest ones carry none" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "handoff_resume");
    defer h.deinit();
    try seedEverything(&h);

    // A second push, settled failed and still standing on its destination: the
    // state where a resume cannot be honest.
    const failed_id = testId("resumefailed");
    _ = try seedPush(&h, &failed_id, "/srv/app/other.bin", &failed_walk, seeded.transfer + 10);

    const doc = try h.document(seeded.now);
    try t.expect(doc.complete);

    // **Every argv that exists is runnable.** Its first word is the binary and
    // its second is a real top-level command, resolved against the dispatch
    // table rather than against a list transcribed here — so an argv naming a
    // verb this build does not have fails against the build's own router.
    var runnable: usize = 0;
    var refusals: usize = 0;
    for (doc.@"resume") |entry| {
        try t.expect(entry.why.len > 0);
        try t.expect(std.meta.stringToEnum(handoff.Section, entry.section) != null);
        const line = entry.argv orelse {
            refusals += 1;
            continue;
        };
        runnable += 1;
        try t.expect(line.len >= 3);
        try t.expectEqualStrings("terminus", line[0]);
        if (std.meta.stringToEnum(Cli.Dispatch.TopCommand, line[1]) == null) {
            std.debug.print(
                \\
                \\a resume argv names `{s}`, which is not a terminus command. The whole
                \\requirement is that a caller can run these lines; one naming a verb this
                \\binary does not have is worse than no argv at all.
                \\
            , .{line[1]});
            return error.ResumeArgvNamesNoCommand;
        }
    }
    // Three unsettled writers, one live job and one resumable checkpoint: five
    // runnable lines. Two refusals: the peer's lease and the settled failure
    // standing on its destination.
    try t.expectEqual(@as(usize, 5), runnable);
    try t.expectEqual(@as(usize, 2), refusals);

    var found_reconcile: usize = 0;
    var found_job: usize = 0;
    var found_push: usize = 0;
    var found_restart_refusal: usize = 0;
    var found_lease_refusal: usize = 0;
    for (doc.@"resume") |entry| {
        if (entry.argv) |line| {
            if (std.mem.eql(u8, entry.section, "ledger")) {
                try t.expectEqualStrings("request", line[1]);
                try t.expectEqualStrings("reconcile", line[2]);
                try t.expectEqualStrings(entry.subject, line[3]);
                try t.expectEqual(@as(usize, 4), line.len);
                found_reconcile += 1;
            }
            if (std.mem.eql(u8, entry.section, "jobs")) {
                try t.expectEqualStrings("job", line[1]);
                try t.expectEqualStrings("status", line[2]);
                try t.expectEqualStrings("box", line[3]);
                try t.expectEqualStrings("migrate", line[4]);
                found_job += 1;
            }
            if (std.mem.eql(u8, entry.section, "transfers")) {
                // Source then destination, in the order the verb takes them, and
                // `--resume` rather than `--restart`: a resume continues from the
                // confirmed offset and discards nothing.
                try t.expectEqualStrings("push", line[1]);
                try t.expectEqualStrings("box", line[2]);
                try t.expectEqualStrings("./out.bin", line[3]);
                try t.expectEqualStrings("/srv/app/out.bin", line[4]);
                try t.expectEqualStrings("--resume", line[5]);
                try t.expectEqual(@as(usize, 6), line.len);
                found_push += 1;
            }
        } else {
            if (std.mem.eql(u8, entry.section, "transfers")) {
                // The settled failure. No argv, and the sentence names the flag
                // that would release it and says what that costs.
                try t.expectEqualStrings("/srv/app/other.bin", entry.subject);
                try t.expect(std.mem.indexOf(u8, entry.why, "--restart") != null);
                try t.expect(std.mem.indexOf(u8, entry.why, "discards the partial") != null);
                found_restart_refusal += 1;
            }
            if (std.mem.eql(u8, entry.section, "leases")) {
                // A peer's live claim. There is no argv that resumes work by
                // taking one, and the refusal says so rather than emitting
                // `--force`.
                try t.expect(std.mem.indexOf(u8, entry.why, "--force") != null);
                try t.expect(std.mem.indexOf(u8, entry.why, "live claim") != null);
                found_lease_refusal += 1;
            }
        }
    }
    // Three ledger rows bar their scope — the unsettled exec and both submitted
    // pushes — so the reconcile route is offered for each of them. A transfer's
    // *operation* being unsettled and its *checkpoint* needing a decision are
    // two different facts, and both get an entry.
    try t.expectEqual(@as(usize, 3), found_reconcile);
    try t.expectEqual(@as(usize, 1), found_job);
    try t.expectEqual(@as(usize, 1), found_push);
    try t.expectEqual(@as(usize, 1), found_restart_refusal);
    try t.expectEqual(@as(usize, 1), found_lease_refusal);

    // No argv anywhere carries `--force` or `--restart`. Both override somebody
    // else's state, and this document does not tell a reader to do that.
    for (doc.@"resume") |entry| {
        const line = entry.argv orelse continue;
        for (line) |word| {
            if (std.mem.eql(u8, word, "--force") or std.mem.eql(u8, word, "--restart")) {
                std.debug.print("\na resume argv carries `{s}`\n", .{word});
                return error.ResumeArgvOverridesSomebodyElse;
            }
        }
    }

    // The flags the argvs lean on are in the verbs' own usage text, so a handoff
    // and `--help` cannot disagree about whether they exist.
    try t.expect(std.mem.indexOf(u8, @import("cmd_transfer.zig").usage, "--resume") != null);
    try t.expect(std.mem.indexOf(u8, handoff.usage, "--limit") != null);
}

test "gate: an unjudged publish is reconciled, never sent again" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "handoff_unjudged");
    defer h.deinit();

    // A rename that was issued and never confirmed. The destination may already
    // hold an artifact nobody has judged, so sending the bytes again is the one
    // thing a handoff must not suggest.
    const id = testId("unjudgedpub");
    _ = try seedPush(&h, &id, "/srv/app/out.bin", &unjudged_walk, seeded.transfer);

    const doc = try h.document(seeded.now);
    try t.expect(doc.complete);
    try t.expectEqual(@as(usize, 1), doc.transfers.len);
    try t.expectEqualStrings("indeterminate_publish", doc.transfers[0].state);
    try t.expect(!doc.transfers[0].resumable);
    try t.expect(doc.transfers[0].holdsDestination);

    var checked: usize = 0;
    for (doc.@"resume") |entry| {
        if (!std.mem.eql(u8, entry.section, "transfers")) continue;
        checked += 1;
        const line = entry.argv orelse return error.UnjudgedPublishOfferedNoRoute;
        // Reconciled, by the request that owns the checkpoint.
        try t.expectEqualStrings("request", line[1]);
        try t.expectEqualStrings("reconcile", line[2]);
        try t.expectEqualStrings(&id, line[3]);
        for (line) |word| {
            if (std.mem.eql(u8, word, "push") or std.mem.eql(u8, word, "pull")) {
                std.debug.print(
                    \\
                    \\a checkpoint in `indeterminate_publish` was offered a transfer to run
                    \\again. The rename may already have landed, so this would overwrite a
                    \\result nobody has judged — that destination is read, never re-sent.
                    \\
                , .{});
                return error.UnjudgedPublishOfferedARetry;
            }
        }
    }
    try t.expectEqual(@as(usize, 1), checked);
}

// --- gate: the document ------------------------------------------------------

test "gate: the skill document says what a handoff knows and how stale it may be" {
    const t = std.testing;
    const heading = "## Picking up somebody else's work: `terminus handoff`";
    // Found by name, never by position: this document is appended to.
    const at = std.mem.indexOf(u8, skill_doc.text, heading) orelse {
        std.debug.print(
            \\
            \\skill/SKILL.md has no "{s}" section. An agent that does not know a handoff
            \\exists will start work on a host without finding out what is already in
            \\flight on it — and one that does not know every section is a dated cache will
            \\read a three-day-old `running` as a fact about right now.
            \\
        , .{heading});
        return error.SkillHandoffSectionMissing;
    };
    const rest = skill_doc.text[at + heading.len ..];
    const section = rest[0 .. std.mem.indexOf(u8, rest, "\n## ") orelse rest.len];

    var claims: usize = 0;
    for ([_][]const u8{
        // The keys line 107 of the goal document names.
        "schemaVersion",
        "complete",
        "errors",
        "observedAt",
        "resume",
        // The epistemics, in the words the document uses.
        "cache",
        "per section",
        // What makes it worth running: it needs no host.
        "offline",
        // What an incomplete one means, and how it exits.
        "exits 1",
        // The thing it will not tell you to do.
        "--force",
    }) |needle| {
        if (std.mem.indexOf(u8, section, needle) == null) {
            std.debug.print(
                \\
                \\skill/SKILL.md: the handoff section no longer states "{s}".
                \\
            , .{needle});
            return error.SkillHandoffClaimMissing;
        }
        claims += 1;
    }
    try t.expectEqual(@as(usize, 10), claims);

    // The flags the document leans on are in the usage the command prints.
    try t.expect(std.mem.indexOf(u8, handoff.usage, "--json") != null);
    try t.expect(std.mem.indexOf(u8, handoff.usage, "--limit") != null);
}
