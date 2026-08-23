//! Gates for the ledger row `sync` did not have.
//!
//! **What is driven, and what is not — read this before the assertions.**
//!
//! There is no server here: the test host's key exists only inside a database
//! these tests may not touch, and a libssh2 channel cannot be stood up without
//! one. So the two byte-moving halves of this verb are **reviewed, not proven** —
//! `Ssh.scpSendBytes`/`scpRecvBytes` and the `Core.transfer.pushBytes`/`pullBytes`
//! fallbacks both take an `*Ssh` and cannot be handed a stand-in. They are also
//! not what this slice is about: they are staging, they happen before submission,
//! and a failure in either provably never unpacked anything.
//!
//! What *is* driven is everything the ledger is made of. `Core.execution.begin`,
//! `runCommand`, `settle` and the scope guard run against a real store on disk and
//! a `Core.Scripted` host, so these gates read back the rows a real run would
//! leave:
//!
//!  * a sync that unpacks cleanly leaves exactly one operation, of the kind and
//!    scope this verb declares, with one terminal carrying the host's own status,
//!    findable by the request id a `terminus request` verb is given;
//!  * a host that answered with a nonzero status settles `failed` and is never
//!    read as success — including the `exit 43` the script uses for a digest it
//!    could not match;
//!  * a channel that broke after the script went out, and a channel that closed
//!    cleanly without the supervisor's exit marker, both settle `indeterminate`
//!    and never `failed`;
//!  * a submitted push holds its remote directory against an overlapping sync and
//!    against a `terminus push` aimed inside it, and against neither a sibling
//!    that merely shares a prefix nor a read-only pull;
//!  * `--dry-run` records a read-only attempt that bars nobody, settled by the
//!    terminal that says nothing was handed over.
const std = @import("std");
const Cli = @import("cli.zig");
const Core = @import("../core/core.zig");
const Store = Core.Store;
const cmd_sync = @import("cmd_sync.zig");
const skill_doc = @import("skill_doc.zig");
/// The shared source reader the text-level gates in this tree use.
const Control = @import("../core/control.zig");
const Proc = @import("../core/proc.zig");

const scratch_dir = ".zig-cache/tmp";

// --- fixtures ----------------------------------------------------------------

/// A real store on disk, under `.zig-cache/tmp`, with one server in it.
///
/// Never `%APPDATA%\terminus\terminus.db`: every path here is built from
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
        const path = try std.fmt.allocPrintSentinel(allocator, "{s}/{s}_{d}_{d}_{d}.db", .{
            scratch_dir, name, Proc.currentPid(), std.Thread.getCurrentId(), n,
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
            \\INSERT INTO servers (id, name, host, port, username, created_at, updated_at)
            \\VALUES (1, 'box', '10.0.0.1', 22, 'ubuntu', 100, 100);
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

    /// `begin`, with the kind, scope and mutating flag this verb declares — read
    /// off `cmd_sync` rather than transcribed, so a gate cannot pass against a
    /// scope the command does not actually take.
    fn start(
        h: *Harness,
        verb: cmd_sync.Verb,
        remote_dir: []const u8,
        dry_run: bool,
    ) !Core.execution.Start {
        return Core.execution.begin(&h.store, h.arena, h.io, .{
            .server_id = 1,
            .server_name = "box",
            .kind = cmd_sync.kind,
            .scope = cmd_sync.scopeOf(remote_dir),
            .mutating = cmd_sync.mutates(verb, dry_run),
            .owner_token = "owner-a",
            .now = 1000,
        });
    }

    fn begin(h: *Harness, verb: cmd_sync.Verb, remote_dir: []const u8, dry_run: bool) !Core.execution.Execution {
        return (try h.start(verb, remote_dir, dry_run)).ready;
    }

    /// A neighbour of some other kind claiming a path — `terminus push`'s shape.
    fn startForeign(
        h: *Harness,
        kind: Store.operations.Kind,
        path: []const u8,
    ) !Core.execution.Start {
        return Core.execution.begin(&h.store, h.arena, h.io, .{
            .server_id = 1,
            .server_name = "box",
            .kind = kind,
            .scope = .{ .kind = .path, .key = path },
            .owner_token = "owner-b",
            .now = 1000,
        });
    }

    fn operation(h: *Harness, request_id: []const u8) !Store.operations.Operation {
        return (try Store.operations.get(&h.store, h.arena, request_id)) orelse
            error.OperationNotRecorded;
    }

    fn terminalRow(h: *Harness, request_id: []const u8) !Store.receipts.Row {
        const rows = try Store.receipts.list(&h.store, h.arena, request_id);
        var found: ?Store.receipts.Row = null;
        var terminals: usize = 0;
        for (rows) |row| {
            if (!row.is_terminal) continue;
            terminals += 1;
            found = row;
        }
        // Exactly one, never "the first one": two terminals on an attempt would
        // mean the ledger recorded two verdicts for a single remote act.
        if (terminals != 1) return error.NotExactlyOneTerminal;
        return found.?;
    }
};

/// What a supervised script's stdout looks like on the wire: the identity line,
/// the script's own output, the exit line.
fn wire(arena: std.mem.Allocator, nonce: u64, out: []const u8, code: i32) ![]u8 {
    return std.fmt.allocPrint(
        arena,
        "__TERMINUS_START_{d}__ pid=4242 pgid=4242 token=99\n{s}__TERMINUS_EXIT_{d}__ code={d}\n",
        .{ nonce, out, nonce, code },
    );
}

/// `ExecResult` owns mutable buffers and `Scripted` dupes what it is handed
/// before passing it on, so a literal is never written through.
fn replyOf(stdout: []const u8) Core.Scripted.Step {
    return .{
        .reply = .{
            .exit_code = 0, // the channel's, never the script's
            .stdout = @constCast(stdout),
            .stderr = @constCast(@as([]const u8, "")),
        },
    };
}

const staged_tar = "/tmp/.terminus_sync_01JQXW8ZK4N0RS7T3VYB2MCDEF.tar";
const staged_md5 = "d41d8cd98f00b204e9800998ecf8427e";

// --- gates: the row a sync leaves ---------------------------------------------

test "gate: a sync that unpacks cleanly leaves one operation with a terminal and a findable id" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "sync_push_ok");
    defer h.deinit();

    const remote_dir = "/srv/app";
    var execution = try h.begin(.push, remote_dir, false);
    defer execution.deinit();
    try execution.connecting();
    const request_id = try h.arena.dupe(u8, execution.id());

    const script = try cmd_sync.unpackScript(h.arena, staged_tar, staged_md5, remote_dir, true);
    // Asserted rather than assumed: a fixture that stopped naming the
    // destructive verbs would make everything below a test of an empty string.
    try t.expect(std.mem.indexOf(u8, script, "tar -xf") != null);
    try t.expect(std.mem.indexOf(u8, script, "rm -rf '/srv/app'") != null);

    var scripted = Core.Scripted.init(h.arena, &.{replyOf(try wire(h.arena, execution.nonce, "", 0))});
    const act = cmd_sync.remoteAct(&execution, scripted.executor(), script);
    try t.expect(act == .ran);
    try t.expect(act.ran == .completed);

    // One operation on this server, and it is this one. Not "at least one": a
    // verb that opened a second attempt per run would pass every assertion below
    // while filing two rows for one act.
    const ops = try Store.operations.recent(&h.store, h.arena, 1, 10);
    try t.expectEqual(@as(usize, 1), ops.len);
    try t.expectEqualStrings(request_id, ops[0].request_id);

    // The kind and the scope this verb declares, read back off the row rather
    // than off the constants that produced it.
    try t.expectEqualStrings("exec", ops[0].kind);
    try t.expectEqualStrings(@tagName(cmd_sync.kind), ops[0].kind);
    try t.expectEqualStrings("path", ops[0].scope_kind.?);
    try t.expectEqualStrings(remote_dir, ops[0].scope_key.?);
    try t.expect(ops[0].mutating);
    try t.expectEqualStrings("completed", ops[0].status.text());

    // Findable by the handle a `terminus request` verb is given. This is the
    // half of goal 2 the audit row never provided: `history` is keyed by server
    // and time, and nothing in it can be reconciled.
    const found = try h.operation(request_id);
    try t.expectEqualStrings(request_id, found.request_id);
    try t.expectEqualStrings("completed", found.effectiveStatus().text());

    // Exactly one terminal, carrying the host's own status.
    const terminal = try h.terminalRow(request_id);
    try t.expectEqualStrings("completed", terminal.status.?);
    try t.expectEqual(@as(?i64, 0), terminal.exit_code);

    // The supervisor wrapper really went out, which is what puts the remote pid
    // and start token on the trail for a later `request reconcile` to probe.
    try t.expectEqual(@as(usize, 1), scripted.seen.items.len);
    const sent = scripted.seen.items[0];
    try t.expect(std.mem.indexOf(u8, sent, "__TERMINUS_EXIT_") != null);
    try t.expect(std.mem.indexOf(u8, sent, "tar -xf") != null);
    try t.expectEqual(@as(?i64, 4242), terminal.remote_pid);

    // The archive is staged at an address derived from this request, so a temp
    // file left behind by an attempt that died names the attempt that left it.
    const staging = try cmd_sync.stagingPath(h.arena, request_id);
    try t.expect(std.mem.indexOf(u8, staging, request_id) != null);
}

test "gate: a remote extract the host refused settles a failure and is never read as success" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "sync_push_refused");
    defer h.deinit();

    // Both of the script's own answers: the digest it could not match, and an
    // ordinary `tar` failure. A `failed` attempt does not block scope, so the
    // two runs can share a store and a path.
    const cases = [_]struct { code: i32, what: []const u8 }{
        .{ .code = cmd_sync.corrupt_exit, .what = "checksum mismatch: 00\n" },
        .{ .code = 2, .what = "" },
    };

    var checked: usize = 0;
    for (cases) |case| {
        checked += 1;
        var execution = try h.begin(.push, "/srv/app", false);
        defer execution.deinit();
        try execution.connecting();
        const request_id = try h.arena.dupe(u8, execution.id());

        var scripted = Core.Scripted.init(
            h.arena,
            &.{replyOf(try wire(h.arena, execution.nonce, case.what, case.code))},
        );
        const script = try cmd_sync.unpackScript(h.arena, staged_tar, staged_md5, "/srv/app", false);
        const act = cmd_sync.remoteAct(&execution, scripted.executor(), script);

        try t.expect(act == .ran);
        const verdict = act.ran;
        if (verdict != .nonzero) {
            std.debug.print(
                \\
                \\a remote unpack that exited {d} was not read as the host's own refusal.
                \\A sync that reports `ok: true` over an extract the host declined is the
                \\defect this whole slice is about.
                \\
            , .{case.code});
            return error.RefusalReadAsSuccess;
        }
        try t.expectEqual(case.code, verdict.nonzero.exit_code);

        const op = try h.operation(request_id);
        try t.expectEqualStrings("failed", op.status.text());
        const terminal = try h.terminalRow(request_id);
        try t.expectEqualStrings("failed", terminal.status.?);
        try t.expectEqual(@as(?i64, case.code), terminal.exit_code);
        // The stage it reached is on the row: submitted, then a real status back.
        try t.expectEqualStrings("REMOTE_NONZERO_EXIT", terminal.error_code.?);
    }
    try t.expectEqual(@as(usize, 2), checked);
}

test "gate: a sync whose answer never arrived settles indeterminate, never failed" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "sync_push_unknown");
    defer h.deinit();

    // Two ways of not being told, and they must agree. The first is the wire
    // breaking after the script went out; the second is the one this verb used
    // to get wrong on its own — a channel that closed cleanly with no exit
    // marker, whose `exit_code` is the *channel's* zero and not the script's.
    //
    // An `indeterminate` attempt blocks its scope, so the two runs take
    // non-overlapping paths rather than sharing one.
    const cases = [_]struct {
        path: []const u8,
        step: Core.Scripted.Step,
        says: []const u8,
    }{
        .{
            .path = "/srv/one",
            .step = .{ .transport_error = error.ExecFailed },
            .says = "the transport broke after the script went out",
        },
        .{
            .path = "/srv/two",
            .step = replyOf("output with no marker in it\n"),
            .says = "the channel closed without an exit marker",
        },
    };

    var checked: usize = 0;
    for (cases) |case| {
        checked += 1;
        var execution = try h.begin(.push, case.path, false);
        defer execution.deinit();
        try execution.connecting();
        const request_id = try h.arena.dupe(u8, execution.id());

        var scripted = Core.Scripted.init(h.arena, &.{case.step});
        const script = try cmd_sync.unpackScript(h.arena, staged_tar, staged_md5, case.path, true);
        const act = cmd_sync.remoteAct(&execution, scripted.executor(), script);

        try t.expect(act == .ran);
        if (act.ran != .unknown) {
            std.debug.print(
                \\
                \\{s}, and the sync claimed to know how it ended. The script had already been
                \\submitted, so the remote may have run `rm -rf` and unpacked over the
                \\directory — an agent told `failed` retries that, and an agent told
                \\`completed` believes a tree it never saw.
                \\
            , .{case.says});
            return error.UnknownReadAsAnAnswer;
        }

        const op = try h.operation(request_id);
        try t.expectEqualStrings("indeterminate", op.status.text());
        // Both directions, because the two wrong answers are wrong differently.
        try t.expect(op.status != .failed);
        try t.expect(op.status != .completed);

        const terminal = try h.terminalRow(request_id);
        try t.expectEqualStrings("indeterminate", terminal.status.?);
        try t.expectEqualStrings("INDETERMINATE", terminal.error_code.?);
        // The stage it reached, which is what a reconcile navigates by.
        try t.expectEqualStrings("submitted", terminal.last_observed.?);
    }
    try t.expectEqual(@as(usize, 2), checked);
}

// --- gate: the scope ----------------------------------------------------------

test "gate: a submitted sync push holds its remote directory, and a read-only pull does not" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "sync_scope");
    defer h.deinit();

    // The overlap rule itself, before anything is written: this is the existing
    // `.path` arm of `scope.Scope.overlaps`, and the point of the gate is that
    // `sync` needed nothing added to it.
    const held = cmd_sync.scopeOf("/srv/app");
    try t.expect(held.overlaps(.{ .kind = .path, .key = "/srv/app/dist" }));
    try t.expect(held.overlaps(.{ .kind = .path, .key = "/srv/app/config.json" }));
    try t.expect(!held.overlaps(.{ .kind = .path, .key = "/srv/applied" }));

    var incumbent = try h.begin(.push, "/srv/app", false);
    defer incumbent.deinit();
    try incumbent.connecting();
    // `created` deliberately does not block; the barrier binds at submission.
    try t.expect((try incumbent.submitted()) == .submitted);

    var checked: usize = 0;

    // A second sync into a directory inside the one being replaced.
    checked += 1;
    switch (try h.start(.push, "/srv/app/dist", false)) {
        .blocked => |blocker| try t.expect(blocker == .unsettled),
        .ready => return error.OverlappingSyncNotRefused,
    }

    // A `terminus push` aimed at a file inside it. Different kind, same scope
    // vocabulary — which is the whole reason `sync` uses `.path` rather than
    // inventing a scope of its own.
    checked += 1;
    switch (try h.startForeign(.transfer_push, "/srv/app/config.json")) {
        .blocked => |blocker| try t.expect(blocker == .unsettled),
        .ready => return error.OverlappingTransferNotRefused,
    }

    // A sibling that merely shares a prefix is not inside it, and refusing it
    // would be a barrier nobody could work with.
    checked += 1;
    switch (try h.start(.push, "/srv/applied", false)) {
        .ready => |e| {
            var sibling = e;
            sibling.deinit();
        },
        .blocked => return error.UnrelatedPathRefused,
    }

    // A pull of the very same directory is read-only, so it proceeds — and is
    // told what it is running alongside rather than being waved through blind.
    checked += 1;
    switch (try h.start(.pull, "/srv/app", false)) {
        .ready => |e| {
            var reader = e;
            defer reader.deinit();
            try t.expect(reader.advisory != null);
            try t.expect(!reader.mutating);
        },
        .blocked => return error.ReadOnlyPullRefused,
    }

    try t.expectEqual(@as(usize, 4), checked);
}

// --- gate: --dry-run ----------------------------------------------------------

test "gate: --dry-run records a read-only attempt, settles it, and bars nobody" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "sync_dry_run");
    defer h.deinit();

    // The rule, stated once and read from the command: a push changes the remote
    // directory, a pull reads it, and a dry-run of either changes nothing.
    try t.expect(cmd_sync.mutates(.push, false));
    try t.expect(!cmd_sync.mutates(.push, true));
    try t.expect(!cmd_sync.mutates(.pull, false));
    try t.expect(!cmd_sync.mutates(.pull, true));

    // A `push --dry-run` makes no remote call at all.
    var dry = try h.begin(.push, "/srv/app", true);
    defer dry.deinit();
    try dry.connecting();
    const dry_id = try h.arena.dupe(u8, dry.id());
    cmd_sync.settleDryRun(&dry);

    const op = try h.operation(dry_id);
    try t.expect(!op.mutating);
    try t.expectEqualStrings("cancelled", op.status.text());
    const terminal = try h.terminalRow(dry_id);
    try t.expectEqualStrings("cancelled", terminal.status.?);
    // Not `failed`, which is what `never_submitted` would have recorded for a
    // run that did exactly what it was asked to.
    try t.expect(op.status != .failed);
    // The sentence the ledger carries is the command's own, not this gate's —
    // `local_abandon` files its reason in `cancel_method`.
    try t.expectEqualStrings(cmd_sync.dry_run_reason, terminal.cancel_method.?);
    try t.expect(std.mem.indexOf(u8, cmd_sync.dry_run_reason, "dry-run") != null);

    // And the real run behind it is not refused by it. A dry-run that barred the
    // command it exists to preview is a guard that gets switched off.
    switch (try h.start(.push, "/srv/app", false)) {
        .ready => |e| {
            var real = e;
            real.deinit();
        },
        .blocked => return error.DryRunBarredTheRealRun,
    }

    // A `pull --dry-run` does ask the host something, so it goes out through the
    // same act every other run does and is settled by the probe's own status.
    var probe = try h.begin(.pull, "/srv/logs", true);
    defer probe.deinit();
    try probe.connecting();
    const probe_id = try h.arena.dupe(u8, probe.id());

    const script = try cmd_sync.probeScript(h.arena, "/srv/logs");
    // The probe counts and measures; it must not be able to write. Held here
    // because that is the whole reason a dry-run is read-only.
    var refused: usize = 0;
    for ([_][]const u8{ "tar", "rm ", "mkdir", ">", "touch" }) |verb| {
        refused += 1;
        if (std.mem.indexOf(u8, script, verb) != null) {
            std.debug.print("\nthe pull dry-run probe contains `{s}`\n", .{verb});
            return error.DryRunProbeWrites;
        }
    }
    try t.expectEqual(@as(usize, 5), refused);

    var scripted = Core.Scripted.init(
        h.arena,
        &.{replyOf(try wire(h.arena, probe.nonce, "12\n34567\n", 0))},
    );
    const act = cmd_sync.remoteAct(&probe, scripted.executor(), script);
    try t.expect(act == .ran);
    try t.expectEqualStrings("12\n34567\n", act.ran.completed);

    const probe_op = try h.operation(probe_id);
    try t.expect(!probe_op.mutating);
    try t.expectEqualStrings("completed", probe_op.status.text());
    try t.expectEqualStrings("path", probe_op.scope_kind.?);
    try t.expectEqualStrings("/srv/logs", probe_op.scope_key.?);
}

// --- gates: the scripts and the reading of them --------------------------------

test "gate: the unpack script proves the digest before it destroys anything" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const script = try cmd_sync.unpackScript(arena, staged_tar, staged_md5, "/srv/app", true);
    try t.expect(std.mem.startsWith(u8, script, "set -e"));

    const refusal = try std.fmt.allocPrint(arena, "exit {d}", .{cmd_sync.corrupt_exit});
    const md5_at = std.mem.indexOf(u8, script, "md5sum") orelse return error.ScriptDoesNotHash;
    const refuse_at = std.mem.indexOf(u8, script, refusal) orelse return error.ScriptDoesNotRefuse;
    const rm_at = std.mem.indexOf(u8, script, "rm -rf") orelse return error.ScriptDoesNotDelete;
    const tar_at = std.mem.indexOf(u8, script, "tar -xf") orelse return error.ScriptDoesNotExtract;

    // The order is the whole safety property: the host reads the archive's
    // digest, refuses on a mismatch with nothing applied, and only then removes
    // the directory it is about to replace.
    try t.expect(md5_at < refuse_at);
    try t.expect(refuse_at < rm_at);
    try t.expect(rm_at < tar_at);

    // A refusal code of zero would be the failure wearing a different hat: the
    // host would print "checksum mismatch" and exit 0, and a clean unpack is
    // exactly what that reads as.
    try t.expect(cmd_sync.corrupt_exit != 0);
    try t.expect(cmd_sync.missing_dir_exit != 0);
    try t.expect(cmd_sync.corrupt_exit != cmd_sync.missing_dir_exit);

    // And the destructive clause is absent unless `--delete` asked for it.
    const kept = try cmd_sync.unpackScript(arena, staged_tar, staged_md5, "/srv/app", false);
    try t.expect(std.mem.indexOf(u8, kept, "rm -rf") == null);
    try t.expect(std.mem.indexOf(u8, kept, "tar -xf") != null);
    try t.expect(std.mem.indexOf(u8, kept, refusal) != null);
}

test "gate: verdictOf never turns an outcome nobody reported into an answer" {
    const t = std.testing;

    const cases = [_]struct {
        outcome: Core.execution.RunOutcome,
        want: std.meta.Tag(cmd_sync.Verdict),
        why: []const u8,
    }{
        .{
            .outcome = .{ .status = .completed, .exit_code = 0, .stdout = "", .stderr = "", .identity = null },
            .want = .completed,
            .why = "the host reported zero",
        },
        .{
            .outcome = .{ .status = .failed, .exit_code = 1, .stdout = "", .stderr = "", .identity = null },
            .want = .nonzero,
            .why = "the host reported a failure",
        },
        .{
            .outcome = .{ .status = .failed, .exit_code = cmd_sync.corrupt_exit, .stdout = "", .stderr = "", .identity = null },
            .want = .nonzero,
            .why = "the host refused on a digest mismatch",
        },
        .{
            .outcome = .{ .status = .indeterminate, .exit_code = null, .stdout = "", .stderr = "", .identity = null },
            .want = .unknown,
            .why = "nothing came back at all",
        },
        .{
            // The trap. A settled-`indeterminate` run whose outcome still
            // carries a zero is exactly what a channel that closed early looks
            // like from one field down, and reading the number instead of the
            // status is how a lost answer becomes a clean sync.
            .outcome = .{ .status = .indeterminate, .exit_code = 0, .stdout = "", .stderr = "", .identity = null },
            .want = .unknown,
            .why = "the status says unknown even though a zero is sitting beside it",
        },
        .{
            .outcome = .{ .status = .completed, .exit_code = null, .stdout = "", .stderr = "", .identity = null },
            .want = .unknown,
            .why = "no status was reported, whatever the row says",
        },
    };

    var checked: usize = 0;
    for (cases) |case| {
        checked += 1;
        const got = std.meta.activeTag(cmd_sync.verdictOf(case.outcome));
        if (got != case.want) {
            std.debug.print(
                \\
                \\verdictOf read {s} as `{s}`, and it must be `{s}` — {s}.
                \\
            , .{ @tagName(case.outcome.status), @tagName(got), @tagName(case.want), case.why });
            return error.VerdictMisread;
        }
    }
    try t.expectEqual(@as(usize, 6), checked);
}

// --- gate: the document -------------------------------------------------------

test "gate: the skill document describes the receipt a sync now leaves" {
    const t = std.testing;
    const heading = "## What a sync records, and what it does when the answer is unknown";
    // Found by name, never by position: this document is appended to.
    const at = std.mem.indexOf(u8, skill_doc.text, heading) orelse {
        std.debug.print(
            \\
            \\skill/SKILL.md has no "{s}" section. An agent that does not know a sync now
            \\mints a request id will keep treating a non-zero exit from it as "try again",
            \\which for a push means running `rm -rf` on the destination a second time.
            \\
        , .{heading});
        return error.SkillSyncSectionMissing;
    };
    const rest = skill_doc.text[at + heading.len ..];
    const section = rest[0 .. std.mem.indexOf(u8, rest, "\n## ") orelse rest.len];

    var claims: usize = 0;
    for ([_][]const u8{
        // The handle, and the verb that can act on it.
        "`requestId`",
        "terminus request reconcile",
        // The answer that is not a failure, and the exit code that carries it.
        "indeterminate",
        "75",
        // What the attempt contends on, in the words the guard uses.
        "remote directory",
        "--force",
        // Why a retry is not free.
        "rm -rf",
        // The read-only side, which is the reason a dry-run bars nobody.
        "--dry-run",
    }) |needle| {
        if (std.mem.indexOf(u8, section, needle) == null) {
            std.debug.print(
                \\
                \\skill/SKILL.md: the sync-receipt section no longer states "{s}".
                \\
            , .{needle});
            return error.SkillSyncClaimMissing;
        }
        claims += 1;
    }
    try t.expectEqual(@as(usize, 8), claims);

    // The flags the document leans on are in the usage the command prints, so
    // `--help` and the document do not disagree about whether they exist.
    try t.expect(std.mem.indexOf(u8, cmd_sync.usage, "--force") != null);
    try t.expect(std.mem.indexOf(u8, cmd_sync.usage, "--dry-run") != null);
}

// --- gates: --exclude, which was the unvalidated half of a validated template -

test "gate: every --exclude pattern is one shell word, and the archive script proves it" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Six patterns, and every one of them is a byte `parseExcludes` accepts:
    // it trims whitespace and keeps the rest. They used to be spliced into
    // `" --exclude='*{s}*'"` — quotes owned by the template, escaping nothing —
    // in the same file, on the same `tar` command line, whose *other* argument
    // has been validated since an earlier audit.
    const patterns = [_][]const u8{
        "node_modules",
        "John's cache",
        "a b",
        "x'; rm -rf /tmp/y; '",
        "$HOME",
        "`id`",
    };
    // What each one has to come back out of the script as: `tar`'s own globbing
    // stays in the word, because `--exclude` takes a pattern and not a path.
    var expected: std.ArrayList([]const u8) = .empty;
    for (patterns) |p| {
        try expected.append(arena, try std.mem.concat(arena, u8, &.{ "--exclude=*", p, "*" }));
    }

    var exclude_args: std.ArrayList(u8) = .empty;
    for (patterns) |p| {
        try exclude_args.append(arena, ' ');
        try exclude_args.appendSlice(arena, try cmd_sync.excludeArg(arena, p));
    }

    const script = try cmd_sync.archiveScript(arena, "/srv/app", exclude_args.items, staged_tar);
    // Asserted rather than assumed: a fixture that stopped naming `tar` would
    // make everything below a test of an empty string.
    try t.expect(std.mem.indexOf(u8, script, "tar -cf") != null);

    // The `tar` line, split the way the host would split it. This is the whole
    // gate: not "the bytes look quoted" but "the words the shell produces are
    // the words that went in".
    const tar_at = std.mem.indexOf(u8, script, "tar -cf") orelse return error.ScriptDoesNotArchive;
    const stop = std.mem.indexOfScalarPos(u8, script, tar_at, '\n') orelse script.len;
    const got = try Core.shell.words(arena, script[tar_at..stop]);

    // `tar`, `-cf`, the archive, `-C`, the directory, then one word per
    // pattern, then `.`. Element for element, so an extra word or a lost one is
    // a failure either way.
    try t.expectEqual(@as(usize, 5 + patterns.len + 1), got.len);
    try t.expectEqualStrings("tar", got[0]);
    try t.expectEqualStrings("-cf", got[1]);
    try t.expectEqualStrings(staged_tar, got[2]);
    try t.expectEqualStrings("-C", got[3]);
    try t.expectEqualStrings("/srv/app", got[4]);
    try t.expectEqualStrings(".", got[got.len - 1]);

    var matched: usize = 0;
    for (expected.items, got[5 .. 5 + patterns.len]) |want, have| {
        if (!std.mem.eql(u8, want, have)) {
            std.debug.print(
                \\
                \\an --exclude argument did not survive as one word.
                \\  wanted: {s}
                \\  got:    {s}
                \\
                \\`--exclude='*<pattern>*'` put the operator's pattern inside quotes the
                \\template owned, so an apostrophe in it ended the word and everything after
                \\it became syntax in the middle of a `tar` command line on somebody's host.
                \\
            , .{ want, have });
            return error.ExcludePatternNotOneWord;
        }
        matched += 1;
    }
    try t.expectEqual(@as(usize, 6), matched);

    // And the apostrophe case specifically, because it is the one that used to
    // end the word: the pattern is intact, and nothing after it became a
    // separate argument.
    try t.expect(std.mem.indexOf(u8, got[6], "John's cache") != null);

    // The old spelling, for the contrast. A shell cannot even read it: the
    // apostrophe inside opens a quote that never closes.
    const old = try std.fmt.allocPrint(arena, " --exclude='*{s}*'", .{"John's cache"});
    try t.expectError(error.UnbalancedQuote, Core.shell.words(arena, old));

    // No excludes at all is no words at all — the `tar` line must not grow an
    // empty argument, which `tar` would read as the current directory.
    const bare = try cmd_sync.archiveScript(arena, "/srv/app", "", staged_tar);
    const bare_at = std.mem.indexOf(u8, bare, "tar -cf").?;
    const bare_stop = std.mem.indexOfScalarPos(u8, bare, bare_at, '\n') orelse bare.len;
    try t.expectEqual(@as(usize, 6), (try Core.shell.words(arena, bare[bare_at..bare_stop])).len);
}

test "gate: the remote directory survives every script as one word" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // `validateRemotePath` refuses quotes, backticks, `$` and newlines, and
    // admits everything else — a space, a `;`, a `|`, a `&`. Those were safe
    // only because of the template's own quotes, which is the arrangement that
    // has failed in this project seven times. They are safe here because they
    // are quoted by `shell.word`, which is a property of the renderer and not
    // of the validator.
    const dir = "/srv/two words; rm -rf ~ | tee &";

    // Every line of every script that names the directory, split as the host
    // would. `unpackScript` double-quotes `$actual` for the digest comparison,
    // which `words` refuses to model — so the lines are taken one at a time and
    // only the ones carrying the directory are read.
    const scripts = [_][]const u8{
        try cmd_sync.unpackScript(arena, staged_tar, staged_md5, dir, true),
        try cmd_sync.unpackScript(arena, staged_tar, staged_md5, dir, false),
        try cmd_sync.archiveScript(arena, dir, "", staged_tar),
        try cmd_sync.probeScript(arena, dir),
    };

    var found_lines: usize = 0;
    for (scripts) |script| {
        var lines = std.mem.splitScalar(u8, script, '\n');
        while (lines.next()) |line| {
            if (std.mem.indexOf(u8, line, "two words") == null) continue;
            if (std.mem.indexOfScalar(u8, line, '"') != null) continue;
            found_lines += 1;
            const got = try Core.shell.words(arena, line);
            var carried: usize = 0;
            for (got) |w| {
                if (std.mem.eql(u8, w, dir)) carried += 1;
            }
            if (carried == 0) {
                std.debug.print(
                    \\
                    \\this line does not carry the remote directory as one word:
                    \\
                    \\  {s}
                    \\
                    \\It is a `rm -rf`, a `mkdir -p`, a `tar -C` or a `cd` on somebody's host.
                    \\
                , .{line});
                return error.RemoteDirectoryNotOneWord;
            }
            carried = 0;
        }
    }
    // `rm -rf`, `mkdir -p`, `tar -xf -C` (twice over the two unpack variants,
    // minus the delete clause the second does not have), `[ -d ]`, `tar -cf -C`,
    // `[ -d ]` and `cd --`. Counted, so a scan that found nothing fails.
    try t.expectEqual(@as(usize, 8), found_lines);

    // The `cd` in the dry-run probe carries `--` for the same reason
    // `shell.cdInto` does: quoting does not stop `cd` reading `-P` as an option.
    try t.expect(std.mem.indexOf(u8, scripts[3], "cd -- ") != null);
}

// --- gate: the history row's exit code ---------------------------------------

test "gate: the sync history row reports no exit code when nothing answered" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "sync_history_code");
    defer h.deinit();

    // The row is written on both of the two paths that reach it, and the only
    // difference between them is whether the host ever answered. It used to
    // carry a hardcoded `.exit_code = 0` on both: `push`'s `.unknown` arm
    // *returns* rather than fatals, so the row was written and only then did the
    // verb exit 75 — and `terminus history --json` showed `"exit_code": 0` for a
    // sync that may or may not have run `rm -rf` on the destination.
    //
    // The whole status vocabulary, not only the two that occur: `completed` is
    // the one and only zero, and every other status is the absence of an answer
    // rather than a number standing in for one.
    var mapped: usize = 0;
    for (std.enums.values(Store.op_state.Status)) |status| {
        mapped += 1;
        const got = cmd_sync.historyExitCode(status);
        const want: ?i64 = if (status == .completed) 0 else null;
        if (!std.meta.eql(got, want)) {
            std.debug.print(
                \\
                \\a `{s}` sync would write exit_code={?d} to its history row, and it must
                \\write {?d}. A caller told `0` is told the ledger agrees that this worked;
                \\for anything but `completed` it does not, and for `indeterminate` the
                \\remote may have replaced a directory.
                \\
            , .{ @tagName(status), got, want });
            return error.HistoryExitCodeDishonest;
        }
    }
    // Nine statuses. Counted, so a status added to `op_state` without a
    // decision here fails rather than falling into an `else`.
    try t.expectEqual(@as(usize, 9), mapped);

    // The column can hold the absence, which is why null is available at all.
    try t.expect(@typeInfo(@FieldType(Store.history.Record, "exit_code")) == .optional);

    // And a run that really was left unanswered maps to null through the same
    // function, off a status the ledger produced rather than one this gate named.
    var execution = try h.begin(.push, "/srv/silent", false);
    defer execution.deinit();
    try execution.connecting();
    var scripted = Core.Scripted.init(h.arena, &.{.{ .transport_error = error.ExecFailed }});
    const script = try cmd_sync.unpackScript(h.arena, staged_tar, staged_md5, "/srv/silent", true);
    const act = cmd_sync.remoteAct(&execution, scripted.executor(), script);
    try t.expect(act.ran == .unknown);
    try t.expectEqualStrings("indeterminate", execution.status.text());
    try t.expectEqual(@as(?i64, null), cmd_sync.historyExitCode(execution.status));

    // And the command really does read the status rather than hardcoding a zero.
    // The write is in `run`, so the statement is read from there.
    const body = try Control.bodyOf(@embedFile("cmd_sync.zig"), "\npub fn run(");
    const call = "Store.history" ++ ".add(";
    const at = std.mem.indexOf(u8, body, call) orelse return error.AuditWriteNotFound;
    const end = std.mem.indexOfScalarPos(u8, body, at, ';') orelse return error.AuditWriteUnterminated;
    const statement = body[at .. end + 1];
    if (std.mem.indexOf(u8, statement, ".exit_code = historyExitCode(execution.status),") == null) {
        std.debug.print(
            \\
            \\cmd_sync's history write no longer takes its exit code from the attempt's own
            \\status:
            \\
            \\  {s}
            \\
            \\A literal here is a claim about a remote act this process may never have been
            \\told the outcome of.
            \\
        , .{statement});
        return error.HistoryExitCodeHardcoded;
    }
}
