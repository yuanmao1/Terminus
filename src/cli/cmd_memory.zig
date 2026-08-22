//! `terminus memory add/ls/show/rm/trust/verify` — persistent per-server /
//! per-session memory for agents.
//!
//! Target syntax: `<server>` for server scope, `<server>:<session>` for
//! session scope. Session-scope reads merge server-scope entries.
//!
//! **Freshness.** A memory carries when its *fact* was observed, not only when
//! its row was written. `add` records the write moment as the observation unless
//! `--observed-at` says otherwise, and `verify` replaces it with a live reading by
//! running the memory's own `--verify-cmd` on the host.
//!
//! **Trust.** That verify command is an arbitrary line executing on a host, and
//! memories arrive by `terminus import` from documents anybody can hand over. So
//! it never runs until somebody has granted it by name with `memory trust`, and
//! the refusal says so rather than running it "just to check". See `verify` below
//! for why the connection is a seam and not a call.
const std = @import("std");
const fatal = Cli.fail;
const Cli = @import("cli.zig");
const Core = @import("../core/core.zig");
const Store = Core.Store;

const usage =
    \\usage: terminus memory <verb> <server>[:<session>] [...]
    \\
    \\  memory add    <target> [--key K] [--tags t1,t2] [--append]
    \\                         [--verify-cmd C] [--observed-at UNIX] <content input>
    \\  memory ls     <target> [--tags t] [--json]
    \\  memory show   <target> --key K | --id N [--json]
    \\  memory rm     <target> --key K | --id N
    \\  memory trust  <target> --key K | --id N [--by WHO] [--json]
    \\  memory verify <target> --key K | --id N [--json]
    \\  memory export <server>            all memories+facts as JSON (backup/migration)
    \\
    \\content input, most quote-proof first (PowerShell mangles ';' '*' in bare args):
    \\  --stdin                    read from standard input
    \\  --content-file <path>      read from a local file
    \\  --content "<text>"         a single flag value
    \\  -- <text...>               everything after --
    \\
    \\add semantics: --key upserts (same key replaces content; shown as
    \\"updated" with the previous value). --append appends a line instead.
    \\
    \\freshness: --observed-at says when the fact was *seen*, which may be long
    \\before it was written down. Without it, writing is the observation.
    \\
    \\trust: --verify-cmd stores a command; it does not authorise it. 'memory
    \\verify' refuses to run an unauthorised command and names the grant. A grant
    \\covers the exact text it was given, so rewriting --verify-cmd revokes it.
    \\
;

pub fn run(ctx: *Cli.Ctx, raw_args: []const []const u8) !void {
    if (raw_args.len == 0) fatal("{s}", .{usage});
    const verb = raw_args[0];
    const parsed = Cli.parseArgs(ctx, raw_args[1..]);
    if (parsed.boolean("json")) ctx.out.format = .json;

    var store = try Cli.openStore(ctx, &parsed);
    defer store.close();

    const target = Cli.Target.parse(parsed.positional(0) orelse fatal("{s}", .{usage}));
    const server = (Store.servers.getByName(&store, ctx.arena, target.server) catch |err|
        Cli.storeFatal(&store, err)) orelse fatal("unknown server '{s}'", .{target.server});

    // Export ignores session targets: it dumps the server's full knowledge
    // (all memories incl. session-scoped, plus facts) as one JSON document.
    if (std.mem.eql(u8, verb, "export")) {
        ctx.out.format = .json;
        const all_memories = Store.memories.exportAll(&store, ctx.arena, server.id) catch |err|
            Cli.storeFatal(&store, err);
        const all_facts = Store.facts.list(&store, ctx.arena, server.id) catch |err|
            Cli.storeFatal(&store, err);
        try ctx.out.json(.{
            .ok = true,
            .server = server.name,
            .host = server.host,
            .exportedAt = ctx.now,
            .memories = all_memories,
            .facts = all_facts,
        });
        return;
    }

    // `add` creates the session metadata row on demand; read/delete verbs
    // on an unknown session fail loudly instead of silently narrowing to
    // server scope.
    var scope: Store.memories.Scope = .{ .server_id = server.id };
    if (target.session) |session_name| {
        if (std.mem.eql(u8, verb, "add")) {
            scope.session_id = Store.sessions.ensure(&store, server.id, session_name, ctx.now) catch |err|
                Cli.storeFatal(&store, err);
        } else {
            scope.session_id = (Store.sessions.idByName(&store, server.id, session_name) catch |err|
                Cli.storeFatal(&store, err)) orelse
                fatal("unknown session '{s}'; for server-scope memories use 'terminus memory {s} {s}'", .{
                    targetName(parsed), verb, target.server,
                });
        }
    }

    if (std.mem.eql(u8, verb, "add")) {
        var content = (try Cli.trailingContent(ctx, &parsed, "content-file", 1)) orelse
            fatal("no memory content given (use --stdin, --content-file, --content, or '-- <content>')\n{s}", .{usage});

        // Transparency: report exactly what an existing key held before this
        // write, and support append instead of replace.
        var previous: ?[]const u8 = null;
        if (parsed.flag("key")) |key| {
            if (Store.memories.find(&store, ctx.arena, scope, .{ .key = key }) catch |err|
                Cli.storeFatal(&store, err)) |existing|
            {
                // find() falls back to server scope for session targets;
                // only treat it as "existing" when scopes actually match.
                const same_scope = (scope.session_id == null) == (existing.scope == .server);
                if (same_scope) {
                    previous = existing.content;
                    if (parsed.boolean("append"))
                        content = try std.fmt.allocPrint(ctx.arena, "{s}\n{s}", .{ existing.content, content });
                }
            }
        }

        const result = Store.memories.add(&store, scope, .{
            .key = parsed.flag("key"),
            .content = content,
            .tags = parsed.flag("tags"),
            .now = ctx.now,
            .observed = observationFlag(&parsed, ctx.now),
            // A written note is a stored reading, not a live one: nothing was
            // asked of the host. `memory verify` is the only thing that produces
            // `live`.
            .observed_source = .cache,
            .verify_cmd = parsed.flag("verify-cmd"),
        }) catch |err| Cli.storeFatal(&store, err);
        const action: []const u8 = if (result == .inserted)
            "inserted"
        else if (parsed.boolean("append"))
            "appended"
        else
            "replaced";
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{
                .ok = true,
                .action = action,
                .target = targetName(parsed),
                .key = parsed.flag("key"),
                .content = content,
                .previous = previous,
            }),
            .human => try ctx.out.print("{s} memory for '{s}'{s}\n", .{
                action,                                                                                     targetName(parsed),
                if (previous != null and !parsed.boolean("append")) " (previous content replaced)" else "",
            }),
        }
    } else if (std.mem.eql(u8, verb, "ls")) {
        const list = Store.memories.list(&store, ctx.arena, scope, .{
            .tag = parsed.flag("tags"),
        }) catch |err| Cli.storeFatal(&store, err);
        switch (ctx.out.format) {
            .json => {
                var views: std.ArrayList(MemoryJson) = .empty;
                for (list) |m| try views.append(ctx.arena, memoryJson(m));
                try ctx.out.json(.{ .ok = true, .target = targetName(parsed), .memories = views.items });
            },
            .human => {
                if (list.len == 0) return ctx.out.print("no memories for '{s}'\n", .{targetName(parsed)});
                for (list) |m| {
                    try ctx.out.print("[{d}] ({t}) {s}: {s}{s}{s}\n", .{
                        m.id,      m.scope,                           m.key orelse "-",
                        m.content, if (m.tags != null) "  #" else "", m.tags orelse "",
                    });
                    try printFreshness(ctx, m);
                }
            },
        }
    } else if (std.mem.eql(u8, verb, "show")) {
        const memory = (Store.memories.find(&store, ctx.arena, scope, selector(&parsed)) catch |err|
            Cli.storeFatal(&store, err)) orelse fatal("no matching memory in '{s}'", .{targetName(parsed)});
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{
                .ok = true,
                .target = targetName(parsed),
                .memory = memoryJson(memory),
            }),
            .human => {
                try ctx.out.print("[{d}] ({t}) {s}: {s}\n", .{
                    memory.id, memory.scope, memory.key orelse "-", memory.content,
                });
                try printFreshness(ctx, memory);
            },
        }
    } else if (std.mem.eql(u8, verb, "rm")) {
        const removed = Store.memories.remove(&store, scope, selector(&parsed)) catch |err|
            Cli.storeFatal(&store, err);
        if (!removed) fatal("no matching memory in '{s}'", .{targetName(parsed)});
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .action = "removed", .target = targetName(parsed) }),
            .human => try ctx.out.print("removed memory from '{s}'\n", .{targetName(parsed)}),
        }
    } else if (std.mem.eql(u8, verb, "trust")) {
        try runTrust(ctx, &store, scope, &parsed);
    } else if (std.mem.eql(u8, verb, "verify")) {
        try runVerify(ctx, &store, scope, &parsed);
    } else {
        fatal("unknown verb 'memory {s}'\n{s}", .{ verb, usage });
    }
}

// --- freshness output ---------------------------------------------------------

/// What `memory ls --json` and `memory show --json` publish for one row.
///
/// A view rather than the store's `Memory`, for one reason that matters: the row
/// carries `trusted_cmd_sha256`, and the useful answer is not the digest but
/// whether the grant still covers the command — which is `trust`, below. Printing
/// the digest instead would leave every reader to recompute the comparison, and a
/// reader that got it wrong would get it wrong in the permissive direction.
///
/// Field names stay in the shape `memory ls` already published (`created_at`,
/// not `createdAt`), because an agent parsing this output today should keep
/// working.
const MemoryJson = struct {
    id: i64,
    scope: []const u8,
    key: ?[]const u8,
    content: []const u8,
    tags: ?[]const u8,
    created_at: i64,
    updated_at: i64,
    /// When the *fact* was observed. Null means nobody knows — which is the
    /// honest answer for a memory imported from a document that said nothing.
    /// Never silently equal to `updated_at`: `observed_source` says which.
    observed_at: ?i64,
    /// `live` | `cache` | `legacy_import` | `backfill`. `backfill` means the
    /// timestamp is a write time standing in for an observation.
    observed_source: []const u8,
    verify_cmd: ?[]const u8,
    /// `no_verify_cmd` | `untrusted` | `stale_grant` | `trusted`. Only `trusted`
    /// may run.
    trust: []const u8,
    trusted_at: ?i64,
    trusted_by: ?[]const u8,
};

fn memoryJson(m: Store.memories.Memory) MemoryJson {
    return .{
        .id = m.id,
        .scope = @tagName(m.scope),
        .key = m.key,
        .content = m.content,
        .tags = m.tags,
        .created_at = m.created_at,
        .updated_at = m.updated_at,
        .observed_at = m.observed_at,
        .observed_source = @tagName(m.observed_source),
        .verify_cmd = m.verify_cmd,
        .trust = @tagName(Store.memories.trustState(m)),
        .trusted_at = if (m.grant) |g| g.at else null,
        .trusted_by = if (m.grant) |g| g.by else null,
    };
}

/// The human line under a memory, printed only when there is something to say.
///
/// A backfilled observation is named as one. That is the whole point of the
/// column: a row whose `observed_at` is really its write time must not read like
/// a row somebody checked.
fn printFreshness(ctx: *Cli.Ctx, m: Store.memories.Memory) !void {
    const state = Store.memories.trustState(m);
    if (m.observed_source == .backfill) {
        try ctx.out.print("    observed: unknown (backfilled from the write time)\n", .{});
    } else if (m.observed_at) |at| {
        try ctx.out.print("    observed: {d} ({t})\n", .{ at, m.observed_source });
    } else {
        try ctx.out.print("    observed: unknown\n", .{});
    }
    if (m.verify_cmd) |command| {
        try ctx.out.print("    verify: {s} [{t}]\n", .{ command, state });
    }
}

// --- trust --------------------------------------------------------------------

fn runTrust(
    ctx: *Cli.Ctx,
    store: *Store,
    scope: Store.memories.Scope,
    parsed: *const Cli.Args.Parsed,
) !void {
    // Who granted it. `--by` when a human wants to sign their own name;
    // otherwise this machine's audit identity, which is the tree's existing
    // answer to "who was this" and is stable across processes.
    const by = parsed.flag("by") orelse
        (Store.policy.ownerToken(store, ctx.arena, ctx.io, ctx.now) catch |err|
            Cli.storeFatal(store, err));
    if (by.len == 0)
        fatal("--by names who is granting this trust; an empty name records nobody", .{});

    const result = Store.memories.grantTrust(
        store,
        ctx.arena,
        scope,
        selector(parsed),
        by,
        ctx.now,
    ) catch |err| Cli.storeFatal(store, err);

    switch (result) {
        .no_such_memory => fatal("no matching memory in '{s}'", .{targetName(parsed.*)}),
        .nothing_to_trust => fatal(
            "that memory has no --verify-cmd, so there is nothing to authorise. " ++
                "Store the command first with 'terminus memory add', then trust it — " ++
                "a grant recorded against no command would pre-authorise whatever text arrived next.",
            .{},
        ),
        .granted => |grant| switch (ctx.out.format) {
            .json => try ctx.out.json(.{
                .ok = true,
                .action = "trusted",
                .target = targetName(parsed.*),
                .trustedAt = grant.at,
                .trustedBy = grant.by,
                .trustedCmdSha256 = grant.cmd_sha256,
            }),
            .human => try ctx.out.print(
                "trusted the verify command for '{s}' (by {s} at {d})\n" ++
                    "the grant covers this exact text; rewriting --verify-cmd revokes it\n",
                .{ targetName(parsed.*), grant.by, grant.at },
            ),
        },
    }
}

// --- verify -------------------------------------------------------------------

/// How a verification reaches the host.
///
/// A seam rather than a `Cli.connect` inside `verify`, and the reason is the
/// property this whole slice exists for: an unauthorised command must be refused
/// with **nothing opened**, not merely with nothing sent. If `verify` held a
/// connection it would already have dialled by the time it read the grant, and
/// "we refused" would be a claim about what was sent rather than about what was
/// done. Because the connection is something `verify` asks for, a gate can count
/// the asks and get zero.
pub const Dial = struct {
    context: *anyopaque,
    open: *const fn (context: *anyopaque) Core.Executor,
};

pub const VerifyOutcome = union(enum) {
    no_such_memory,
    /// The memory carries no command, so there is nothing to run.
    no_verify_cmd,
    /// A command that is not authorised. `grant` is the exact command line that
    /// would authorise it — a refusal that cannot say what to do next is a
    /// refusal an operator can only obey.
    refused: struct {
        trust: Store.memories.TrustState,
        command: []const u8,
        grant: []const u8,
    },
    /// The command ran and agreed. The fact is now observed as of `at`, `live`.
    observed: struct { at: i64, command: []const u8 },
    /// The command ran and disagreed. Nothing is recorded: a failed check is not
    /// an observation, and writing `observed_at` here would make a contradicted
    /// memory look freshly confirmed.
    disagreed: struct { exit_code: i32, stderr: []const u8 },
    /// The transport failed. Whether the command ran is unknown, so nothing is
    /// recorded either.
    transport_failed: struct { reason: []const u8 },
};

/// Re-observes one memory by running its `verify_cmd`, if it is allowed to.
///
/// The order is the security boundary and it is the first thing this function
/// does: the row is read, its trust state is decided, and only a `trusted` state
/// reaches `dial.open`. Every other state returns before a connection exists.
pub fn verify(
    store: *Store,
    arena: std.mem.Allocator,
    scope: Store.memories.Scope,
    sel: Store.memories.Selector,
    target: []const u8,
    dial: Dial,
    now: i64,
) (Store.memories.Error || std.mem.Allocator.Error)!VerifyOutcome {
    const found = (try Store.memories.find(store, arena, scope, sel)) orelse return .no_such_memory;
    const state = Store.memories.trustState(found);
    switch (state) {
        .no_verify_cmd => return .no_verify_cmd,
        .untrusted, .stale_grant => return .{ .refused = .{
            .trust = state,
            .command = found.verify_cmd.?,
            .grant = try grantCommandLine(arena, target, found),
        } },
        // Exhaustive on purpose: a new trust state has to be classified here
        // rather than falling into whichever arm happens to be last.
        .trusted => {},
    }

    const command = found.verify_cmd.?;
    const executor = dial.open(dial.context);
    const result = executor.exec(arena, command) catch |err|
        return .{ .transport_failed = .{ .reason = @errorName(err) } };
    if (result.exit_code != 0) return .{ .disagreed = .{
        .exit_code = result.exit_code,
        .stderr = result.stderr,
    } };
    if (!try Store.memories.recordObservation(store, scope.server_id, found.id, now, .live))
        return .no_such_memory;
    return .{ .observed = .{ .at = now, .command = command } };
}

/// The command line that would authorise this memory's verify command.
///
/// By `--key` when the row has one, by `--id` when it does not, because those are
/// the two selectors `memory trust` accepts and an argv naming neither would be a
/// suggestion that fails.
fn grantCommandLine(
    arena: std.mem.Allocator,
    target: []const u8,
    m: Store.memories.Memory,
) std.mem.Allocator.Error![]const u8 {
    if (m.key) |key|
        return std.fmt.allocPrint(arena, "terminus memory trust {s} --key {s}", .{ target, key });
    return std.fmt.allocPrint(arena, "terminus memory trust {s} --id {d}", .{ target, m.id });
}

/// Holds the connection `verify` asks for, and resolves the server's auth only
/// at that moment.
///
/// Resolving earlier would fatal on a keyless server *before* the trust refusal —
/// so an operator with an untrusted command on an unconfigured host would be told
/// about the key and never about the grant. The refusal paths never construct
/// auth material at all.
const CliDial = struct {
    ctx: *Cli.Ctx,
    parsed: *const Cli.Args.Parsed,
    store: *Store,
    server_name: []const u8,
    connection: ?Cli.Connection = null,

    fn open(context: *anyopaque) Core.Executor {
        const self: *CliDial = @ptrCast(@alignCast(context));
        const resolved = Cli.resolveServer(self.ctx, self.store, self.server_name);
        self.connection = Cli.connect(self.ctx, self.parsed, resolved.server, resolved.auth);
        return self.connection.?.executor();
    }

    fn dial(self: *CliDial) Dial {
        return .{ .context = self, .open = open };
    }

    fn deinit(self: *CliDial) void {
        if (self.connection) |*conn| conn.deinit();
        self.connection = null;
    }
};

fn runVerify(
    ctx: *Cli.Ctx,
    store: *Store,
    scope: Store.memories.Scope,
    parsed: *const Cli.Args.Parsed,
) !void {
    const target = Cli.Target.parse(parsed.positionals[0]);
    var slot: CliDial = .{
        .ctx = ctx,
        .parsed = parsed,
        .store = store,
        .server_name = target.server,
    };
    defer slot.deinit();

    const outcome = verify(
        store,
        ctx.arena,
        scope,
        selector(parsed),
        targetName(parsed.*),
        slot.dial(),
        ctx.now,
    ) catch |err| Cli.storeFatal(store, err);

    switch (outcome) {
        .no_such_memory => fatal("no matching memory in '{s}'", .{targetName(parsed.*)}),
        .no_verify_cmd => fatal(
            "that memory has no --verify-cmd, so there is nothing to run. " ++
                "Store one with 'terminus memory add --key <k> --verify-cmd <command>'.",
            .{},
        ),
        .refused => |r| switch (ctx.out.format) {
            .json => try ctx.out.json(.{
                .ok = false,
                .errorCode = "VERIFY_CMD_UNTRUSTED",
                .target = targetName(parsed.*),
                .trust = @tagName(r.trust),
                .verifyCmd = r.command,
                .grant = r.grant,
            }),
            .human => try ctx.out.print(
                "refused to run the verify command for '{s}': it is {t}.\n" ++
                    "  command: {s}\n" ++
                    "Read that command, then authorise it:\n  {s}\n",
                .{ targetName(parsed.*), r.trust, r.command, r.grant },
            ),
        },
        .observed => |o| switch (ctx.out.format) {
            .json => try ctx.out.json(.{
                .ok = true,
                .action = "observed",
                .target = targetName(parsed.*),
                .observedAt = o.at,
                .observedSource = "live",
                .verifyCmd = o.command,
            }),
            .human => try ctx.out.print("verified '{s}' at {d} (live)\n", .{ targetName(parsed.*), o.at }),
        },
        .disagreed => |d| switch (ctx.out.format) {
            .json => try ctx.out.json(.{
                .ok = false,
                .errorCode = "VERIFY_CMD_DISAGREED",
                .target = targetName(parsed.*),
                .exitCode = d.exit_code,
                .stderr = d.stderr,
            }),
            .human => try ctx.out.print(
                "the verify command for '{s}' exited {d}; the memory's observation is left as it was\n{s}",
                .{ targetName(parsed.*), d.exit_code, d.stderr },
            ),
        },
        .transport_failed => |f| switch (ctx.out.format) {
            .json => try ctx.out.json(.{
                .ok = false,
                .errorCode = "VERIFY_CMD_TRANSPORT_FAILED",
                .target = targetName(parsed.*),
                .reason = f.reason,
            }),
            .human => try ctx.out.print(
                "could not verify '{s}': {s}; nothing was recorded\n",
                .{ targetName(parsed.*), f.reason },
            ),
        },
    }
}

fn targetName(parsed: Cli.Args.Parsed) []const u8 {
    return parsed.positionals[0];
}

/// When the fact was observed, as `add`'s flags say it.
///
/// Absent means "writing it down is the observation", which is what an operator
/// typing a note is doing. `--observed-at` is for the other case: a fact seen a
/// while ago and only now being recorded.
fn observationFlag(parsed: *const Cli.Args.Parsed, now: i64) Store.memories.Observation {
    const text = parsed.flag("observed-at") orelse return .now;
    const at = std.fmt.parseInt(i64, text, 10) catch
        fatal("invalid --observed-at '{s}' (unix seconds)", .{text});
    if (at > now)
        fatal("--observed-at {d} is in the future (now is {d}); a fact cannot have been seen yet", .{ at, now });
    return .{ .at = at };
}

fn selector(parsed: *const Cli.Args.Parsed) Store.memories.Selector {
    if (parsed.flag("key")) |key| return .{ .key = key };
    if (parsed.flag("id")) |id_text| {
        const id = std.fmt.parseInt(i64, id_text, 10) catch fatal("invalid --id '{s}'", .{id_text});
        return .{ .id = id };
    }
    fatal("select a memory with --key K or --id N", .{});
}

test {
    _ = @import("cmd_memory_test.zig");
}
