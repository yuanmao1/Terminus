//! `terminus server add/ls/show/rm` — server resource management.
//!
//! **Why `ping` opens no operation.** It is the one verb here that reaches a
//! host, and the whole of what it sends is the word below. `true` is the POSIX
//! no-op: it takes no arguments, reads nothing, writes nothing, and cannot have a
//! different effect the second time. The operation ledger exists so a later
//! session can establish whether a *change* was applied (`operations.zig`,
//! `BeginOptions.mutating`); there is no such fact here for a receipt to carry,
//! and a row per reachability check would be noise in the one table an operator
//! reads to find work that may still be in flight. `cmd_sync.zig`'s header has
//! the other side of that argument, for a verb whose remote call really does
//! change something.
//!
//! The claim is only as strong as the word, so the gate at the bottom of this
//! file holds both halves of it: the command is exactly `true`, and it is the
//! only remote call this file makes.
const std = @import("std");
const fatal = Cli.fail;
const Cli = @import("cli.zig");
const Core = @import("../core/core.zig");
const Store = Core.Store;

/// Everything `server ping` sends. See the file header for why it may stay that
/// way without a request id, and the gate at the bottom for what enforces it.
pub const ping_command = "true";

const usage =
    \\usage: terminus server <verb> [...]
    \\
    \\  server add    <name> --host <host> --user <user> [--port 22] [--key <keyname>] [--note ...]
    \\  server ls     [--json]
    \\  server show   <name> [--json]
    \\  server ping   <name> [--json]     connect+auth check, ~1 round trip
    \\  server pin    <name> [--json]     what this machine trusts for the host
    \\                <name> --key-type <t> --fingerprint <fp>
    \\                       record a pin you checked somewhere other than this
    \\                       connection. Every later connection is compared to it.
    \\                <name> --trust-on-first-use
    \\                       connect once and record whatever answers. Protects
    \\                       every connection after this one, and nothing else.
    \\                <name> --rotate --key-type <t> --fingerprint <fp> [--reason ...]
    \\                       the host's key really changed. The new fingerprint is
    \\                       required: this command does not decide what to trust.
    \\                <name> --revoke --key-type <t> [--reason ...]
    \\                       stop trusting a key without naming a replacement.
    \\  server rename <old-name> <new-name>
    \\  server set    <name> [--host H] [--port P] [--user U] [--key K] [--note ...]
    \\  server rm     <name> [--force]
    \\                --force confirms the cascade (memories/facts/sessions/
    \\                jobs/history/leases/redaction rules). It does not, and
    \\                cannot, cover an unsettled attempt, a held lease or a
    \\                resumable transfer. The server's private key is not
    \\                deleted; a successful removal names it if nothing else
    \\                references it any more.
    \\
;

pub fn run(ctx: *Cli.Ctx, raw_args: []const []const u8) !void {
    if (raw_args.len == 0) fatal("{s}", .{usage});
    const verb = raw_args[0];
    const parsed = Cli.parseArgs(ctx, raw_args[1..]);
    if (parsed.boolean("json")) ctx.out.format = .json;

    var store = try Cli.openStore(ctx, &parsed);
    defer store.close();

    if (std.mem.eql(u8, verb, "add")) {
        const name = parsed.positional(0) orelse fatal("{s}", .{usage});
        const host = parsed.flag("host") orelse fatal("--host is required", .{});
        const user = parsed.flag("user") orelse fatal("--user is required", .{});
        const port: u16 = if (parsed.flag("port")) |p|
            std.fmt.parseInt(u16, p, 10) catch fatal("invalid --port '{s}'", .{p})
        else
            22;
        _ = Store.servers.add(&store, .{
            .name = name,
            .host = host,
            .port = port,
            .username = user,
            .key = parsed.flag("key"),
            .note = parsed.flag("note"),
            .now = ctx.now,
        }) catch |err| switch (err) {
            error.NameTaken => fatal("server '{s}' already exists", .{name}),
            error.KeyNotFound => fatal("key '{s}' not found; add it with 'terminus key add'", .{parsed.flag("key").?}),
            else => Cli.storeFatal(&store, err),
        };
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .action = "added", .server = name }),
            .human => try ctx.out.print("added server '{s}' ({s}@{s}:{d})\n", .{ name, user, host, port }),
        }
    } else if (std.mem.eql(u8, verb, "ls")) {
        const list = Store.servers.list(&store, ctx.arena) catch |err| Cli.storeFatal(&store, err);
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .servers = list }),
            .human => {
                if (list.len == 0) return ctx.out.print("no servers. add one with 'terminus server add'\n", .{});
                for (list) |s| {
                    try ctx.out.print("{s}  {s}@{s}:{d}  key={s}  note={s}\n", .{
                        s.name, s.username, s.host, s.port, s.key orelse "-", s.note orelse "-",
                    });
                }
            },
        }
    } else if (std.mem.eql(u8, verb, "show")) {
        const name = parsed.positional(0) orelse fatal("{s}", .{usage});
        const server = (Store.servers.getByName(&store, ctx.arena, name) catch |err|
            Cli.storeFatal(&store, err)) orelse fatal("unknown server '{s}'", .{name});
        const mems = Store.memories.list(&store, ctx.arena, .{ .server_id = server.id }, .{}) catch |err|
            Cli.storeFatal(&store, err);
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .server = server, .memories = mems }),
            .human => {
                try ctx.out.print(
                    "name:  {s}\nhost:  {s}:{d}\nuser:  {s}\nkey:   {s}\nnote:  {s}\n",
                    .{ server.name, server.host, server.port, server.username, server.key orelse "-", server.note orelse "-" },
                );
                try ctx.out.print("memories: {d}\n", .{mems.len});
                for (mems) |m| {
                    try ctx.out.print("  [{d}] {s}: {s}\n", .{ m.id, m.key orelse "-", m.content });
                }
            },
        }
    } else if (std.mem.eql(u8, verb, "ping")) {
        const name = parsed.positional(0) orelse fatal("{s}", .{usage});
        const resolved = Cli.resolveServer(ctx, &store, name);
        const started = std.Io.Timestamp.now(ctx.io, .awake);
        var conn = Cli.connect(ctx, &parsed, resolved.server, resolved.auth);
        defer conn.deinit();
        const result = conn.executor().exec(ctx.arena, ping_command) catch |err|
            fatal("reachable but exec failed: {s} ({s})", .{ conn.executor().errorMessage(), @errorName(err) });
        const ms: i64 = @intCast(@divTrunc(
            started.durationTo(std.Io.Timestamp.now(ctx.io, .awake)).nanoseconds,
            std.time.ns_per_ms,
        ));
        _ = result;
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{
                .ok = true,
                .server = name,
                .reachable = true,
                .latencyMs = ms,
                .transport = conn.transport,
                .daemonError = conn.daemon_error,
            }),
            .human => try ctx.out.print("'{s}' is reachable ({d} ms via {s})\n", .{ name, ms, conn.transport }),
        }
    } else if (std.mem.eql(u8, verb, "pin")) {
        try runPin(ctx, &store, &parsed);
    } else if (std.mem.eql(u8, verb, "rename")) {
        const old_name = parsed.positional(0) orelse fatal("{s}", .{usage});
        const new_name = parsed.positional(1) orelse fatal("{s}", .{usage});
        const server = (Store.servers.getByName(&store, ctx.arena, old_name) catch |err|
            Cli.storeFatal(&store, err)) orelse fatal("unknown server '{s}'", .{old_name});
        Store.servers.rename(&store, server.id, new_name, ctx.now) catch |err| switch (err) {
            error.NameTaken => fatal("server '{s}' already exists", .{new_name}),
            else => Cli.storeFatal(&store, err),
        };
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .action = "renamed", .from = old_name, .to = new_name }),
            .human => try ctx.out.print("renamed '{s}' -> '{s}' (memories/facts/jobs/history follow)\n", .{ old_name, new_name }),
        }
    } else if (std.mem.eql(u8, verb, "set")) {
        const name = parsed.positional(0) orelse fatal("{s}", .{usage});
        const server = (Store.servers.getByName(&store, ctx.arena, name) catch |err|
            Cli.storeFatal(&store, err)) orelse fatal("unknown server '{s}'", .{name});
        var changes: Store.servers.Update = .{
            .host = parsed.flag("host"),
            .username = parsed.flag("user"),
            .note = parsed.flag("note"),
        };
        if (parsed.flag("port")) |p|
            changes.port = std.fmt.parseInt(u16, p, 10) catch fatal("invalid --port '{s}'", .{p});
        if (parsed.flag("key")) |key_name| {
            changes.key_id = (Store.keys.idByName(&store, key_name) catch |err|
                Cli.storeFatal(&store, err)) orelse fatal("key '{s}' not found", .{key_name});
        }
        if (changes.host == null and changes.port == null and changes.username == null and
            changes.key_id == null and changes.note == null)
            fatal("nothing to change; pass at least one of --host/--port/--user/--key/--note", .{});
        Store.servers.update(&store, server.id, changes, ctx.now) catch |err| Cli.storeFatal(&store, err);
        const updated = (Store.servers.getByName(&store, ctx.arena, name) catch |err|
            Cli.storeFatal(&store, err)).?;
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{ .ok = true, .action = "updated", .server = updated }),
            .human => try ctx.out.print("updated '{s}': {s}@{s}:{d} key={s}\n", .{
                name, updated.username, updated.host, updated.port, updated.key orelse "-",
            }),
        }
    } else if (std.mem.eql(u8, verb, "rm")) {
        const name = parsed.positional(0) orelse fatal("{s}", .{usage});
        const server = (Store.servers.getByName(&store, ctx.arena, name) catch |err|
            Cli.storeFatal(&store, err)) orelse fatal("unknown server '{s}'", .{name});
        const outcome = removeServer(&store, server.id, name, server.key, parsed.boolean("force"), ctx.now) catch |err|
            Cli.storeFatal(&store, err);
        switch (outcome) {
            .removed => |orphaned| try reportRemoved(ctx.out, name, orphaned),
            .vanished => Cli.failWithCode(
                "SERVER_VANISHED",
                "server '{s}' was there when its barriers were checked and gone when the delete ran; the removal was abandoned and nothing was deleted",
                .{name},
            ),
            .needs_force => |counts| Cli.failWithCode(
                "SERVER_CASCADE_NOT_CONFIRMED",
                cascade_not_confirmed,
                .{
                    name,        counts.memories, counts.facts,  counts.sessions,
                    counts.jobs, counts.history,  counts.leases, counts.redaction_rules,
                },
            ),
            // One sentence per barrier, naming the count and the way past it.
            // `--force` is absent from all three on purpose and is not an
            // omission the operator should try to work around: see
            // `removeServer`.
            .refused => |barrier| switch (barrier) {
                .unsettled_operations => |n| Cli.failWithCode(
                    "SERVER_HAS_UNSETTLED_OPERATIONS",
                    "refused: {d} attempt(s) on '{s}' still have an unknown remote outcome, and nothing was deleted. " ++
                        "Deleting the server would un-scope every one of them and hide them from 'terminus request ls', " ++
                        "so establish what happened first: 'terminus request ls {s}', then " ++
                        "'terminus request reconcile <request-id>' for each",
                    .{ n, name, name },
                ),
                .active_leases => |n| Cli.failWithCode(
                    "SERVER_HAS_ACTIVE_LEASES",
                    "refused: {d} lease(s) on '{s}' are still held, and nothing was deleted. " ++
                        "Deleting the server destroys them outright, so a peer session mid-change would find its claim gone " ++
                        "with no record of where it went. Wait for them to lapse — every lease carries a TTL and is swept on the next check — " ++
                        "or have the owner release them",
                    .{ n, name },
                ),
                .resumable_transfers => |n| Cli.failWithCode(
                    "SERVER_HAS_RESUMABLE_TRANSFERS",
                    "refused: {d} transfer(s) on '{s}' still depend on a hand-over to go anywhere, and nothing was deleted. " ++
                        "Every hand-over is guarded by a same-machine conjunct, so without this server row they could never be " ++
                        "taken over by anybody while going on holding their destination. Finish them, or fail them and let " ++
                        "something supersede them, first",
                    .{ n, name },
                ),
            },
        }
    } else {
        fatal("unknown verb 'server {s}'\n{s}", .{ verb, usage });
    }
}

// --- `server pin` -------------------------------------------------------------
//
// The operator's whole interface to the trust root. Four verbs share one
// command because they are four answers to one question — what does this
// machine trust for this host — and because the contract they implement is one
// sentence per flag:
//
//   * an explicit pin is the default, and `--fingerprint` is how it arrives;
//   * trust-on-first-use is never implied, so it has its own flag and its own
//     `trust_source` in the ledger;
//   * rotation needs the new fingerprint supplied, so `--rotate` without one is
//     refused rather than filled in from whatever the host is offering today;
//   * a key can be stopped without a replacement, which is `--revoke`.
//
// With no flags it prints, and printing is the only one of the five with no
// effect at all — which is why it is the default rather than something an
// operator has to remember a subcommand for.
//
// A pin is keyed on `(host, port, key_type)` and a server row names a host and
// a port, so two servers on one box share a pin and a server whose address is
// changed has none at the new one. See `host_pins.zig`'s header.

/// A pin identified the way the schema keys one, with the fingerprint that goes
/// in it.
const Keyed = struct {
    key_type: []const u8,
    fingerprint: []const u8,
};

/// What `server pin`'s flags asked for.
const PinPlan = union(enum) {
    /// No flags: print what is recorded, change nothing.
    show,
    /// Record a pin for a key type that has none.
    record: Keyed,
    /// Replace the active pin, keeping the old row as evidence.
    rotate: Keyed,
    /// Stop trusting the active pin without naming a replacement.
    revoke: []const u8,
    /// Connect once and record whatever answers.
    first_use,
};

/// Every way the flags can fail to describe one of the five plans.
///
/// Named members rather than a message, so `pinPlanRefusal` is total over them
/// and the gate below can walk the set: a seventh way to ask for something
/// impossible cannot be added without a sentence for it.
const PinPlanError = error{
    /// More than one of `--trust-on-first-use` / `--rotate` / `--revoke`, or a
    /// fingerprint handed to one of the two that does not take one.
    ConflictingModes,
    /// `--rotate` with no `--fingerprint`. The contract's third rule: "the key
    /// changed, record the new one" is not something this decides.
    RotationNeedsAFingerprint,
    /// `--revoke` with no `--key-type`. A host can have several pins and this
    /// will not guess which one to withdraw.
    RevocationNeedsAKeyType,
    /// A fingerprint with nothing saying which key it belongs to. The schema
    /// keys on the type, so a pin without one has no address.
    FingerprintNeedsAKeyType,
    /// A key type on its own, which describes no action.
    KeyTypeNeedsAFingerprint,
    /// A fingerprint that could never match anything this build computes — an
    /// MD5 one, a bare hex digest, a padded base64 one. Refused here rather
    /// than stored, because stored it would refuse every connection to the host
    /// for ever and report a key mismatch while doing it.
    FingerprintNotCanonical,
};

/// The flags, as a plan or as the reason there is none.
///
/// A pure function over the five inputs, so the whole of this command's
/// argument contract is drivable from a gate without a process, a store or a
/// host. `run` does the parsing and the wording; this does the deciding.
fn pinPlan(opts: struct {
    key_type: ?[]const u8,
    fingerprint: ?[]const u8,
    trust_on_first_use: bool,
    rotate: bool,
    revoke: bool,
}) PinPlanError!PinPlan {
    const modes = @as(u8, @intFromBool(opts.trust_on_first_use)) +
        @intFromBool(opts.rotate) + @intFromBool(opts.revoke);
    if (modes > 1) return error.ConflictingModes;

    if (opts.fingerprint) |fp| {
        if (opts.trust_on_first_use or opts.revoke) return error.ConflictingModes;
        if (!Core.Ssh.isCanonicalFingerprint(fp)) return error.FingerprintNotCanonical;
        const key_type = opts.key_type orelse return error.FingerprintNeedsAKeyType;
        const keyed: Keyed = .{ .key_type = key_type, .fingerprint = fp };
        return if (opts.rotate) .{ .rotate = keyed } else .{ .record = keyed };
    }

    if (opts.rotate) return error.RotationNeedsAFingerprint;
    if (opts.revoke) return .{ .revoke = opts.key_type orelse return error.RevocationNeedsAKeyType };
    if (opts.trust_on_first_use) return .first_use;
    if (opts.key_type != null) return error.KeyTypeNeedsAFingerprint;
    return .show;
}

/// One sentence per refusal, and each one names the flag that fixes it.
fn pinPlanRefusal(err: PinPlanError) []const u8 {
    return switch (err) {
        error.ConflictingModes => "--trust-on-first-use, --rotate and --revoke are three different answers and only one may be given; " ++
            "--trust-on-first-use and --revoke take no --fingerprint",
        error.RotationNeedsAFingerprint => "--rotate needs the new fingerprint: 'server pin <name> --rotate --key-type <t> --fingerprint <fp>'. " ++
            "Recording whatever the host is offering today would make the tool decide what to trust, which is " ++
            "exactly what a pin exists to stop",
        error.RevocationNeedsAKeyType => "--revoke needs --key-type: a host can have a pin per key type and this will not guess which one to withdraw. " ++
            "'server pin <name>' lists them",
        error.FingerprintNeedsAKeyType => "--fingerprint needs --key-type (ssh-ed25519, ssh-rsa, ecdsa-sha2-nistp256, ...): a pin is keyed on the " ++
            "key's type as well as the host, so without one it has no address",
        error.KeyTypeNeedsAFingerprint => "--key-type on its own describes no action; add --fingerprint <fp> to record one, --revoke to withdraw one, " ++
            "or drop it to list what is recorded",
        error.FingerprintNotCanonical => "--fingerprint was not given a fingerprint this build can ever match. It must be exactly what " ++
            "'ssh-keyscan' prints: 'SHA256:' followed by 43 unpadded base64 characters. Stored as given it would " ++
            "refuse every connection to the host and report a key mismatch while doing it",
    };
}

fn runPin(ctx: *Cli.Ctx, store: *Store, parsed: *const Cli.Args.Parsed) !void {
    const name = parsed.positional(0) orelse fatal("{s}", .{usage});
    const server = (Store.servers.getByName(store, ctx.arena, name) catch |err|
        Cli.storeFatal(store, err)) orelse fatal("unknown server '{s}'", .{name});

    const plan = pinPlan(.{
        .key_type = parsed.flag("key-type"),
        .fingerprint = parsed.flag("fingerprint"),
        .trust_on_first_use = parsed.boolean("trust-on-first-use"),
        .rotate = parsed.boolean("rotate"),
        .revoke = parsed.boolean("revoke"),
    }) catch |err| fatal("{s}", .{pinPlanRefusal(err)});

    const reason = parsed.flag("reason");
    switch (plan) {
        .show => {
            const pins = Store.host_pins.forEndpoint(store, ctx.arena, server.host, server.port) catch |err|
                Cli.storeFatal(store, err);
            try reportPins(ctx.out, name, server.host, server.port, pins);
        },
        .record => |keyed| {
            _ = Store.host_pins.record(store, .{
                .host = server.host,
                .port = server.port,
                .key_type = keyed.key_type,
                .fingerprint_sha256 = keyed.fingerprint,
                .trust_source = .explicit_pin,
                .note = parsed.flag("note"),
                .now = ctx.now,
            }) catch |err| switch (err) {
                // The schema's partial unique index, not a race: one active pin
                // per (host, port, key type). Replacing it is a rotation, which
                // says so out loud and keeps the old row.
                error.Constraint => fatal(
                    "a {s} pin is already active for {s}:{d}. If the host's key really changed, " ++
                        "record it deliberately: 'terminus server pin {s} --rotate --key-type {s} --fingerprint <fp>'",
                    .{ keyed.key_type, server.host, server.port, name, keyed.key_type },
                ),
                else => Cli.storeFatal(store, err),
            };
            try reportPinned(ctx.out, "pinned", name, server.host, server.port, keyed, .explicit_pin);
        },
        .rotate => |keyed| {
            _ = Store.host_pins.rotate(store, .{
                .host = server.host,
                .port = server.port,
                .key_type = keyed.key_type,
                .fingerprint_sha256 = keyed.fingerprint,
                .trust_source = .rotated,
                .note = parsed.flag("note"),
                .now = ctx.now,
            }, reason orelse "rotated by operator") catch |err| Cli.storeFatal(store, err);
            try reportPinned(ctx.out, "rotated", name, server.host, server.port, keyed, .rotated);
        },
        .revoke => |key_type| {
            const active = (Store.host_pins.active(store, ctx.arena, server.host, server.port, key_type) catch |err|
                Cli.storeFatal(store, err)) orelse fatal(
                "no active {s} pin for {s}:{d}, so there is nothing to withdraw",
                .{ key_type, server.host, server.port },
            );
            const withdrawn = Store.host_pins.revoke(
                store,
                active.id,
                reason orelse "revoked by operator",
                ctx.now,
            ) catch |err| Cli.storeFatal(store, err);
            if (!withdrawn) fatal(
                "the {s} pin for {s}:{d} was active when it was read and was not when the withdrawal ran; nothing was changed",
                .{ key_type, server.host, server.port },
            );
            switch (ctx.out.format) {
                .json => try ctx.out.json(.{
                    .ok = true,
                    .action = "revoked",
                    .server = name,
                    .keyType = key_type,
                    .fingerprint = active.fingerprint_sha256,
                }),
                .human => try ctx.out.print(
                    "revoked the {s} pin for {s}:{d} ({s}). Connections to '{s}' are refused until a pin is recorded again\n",
                    .{ key_type, server.host, server.port, active.fingerprint_sha256, name },
                ),
            }
        },
        .first_use => switch (Cli.observeHostKey(store, ctx.arena, server)) {
            .refused => |sentence| fatal("{s}", .{sentence}),
            .already_pinned => |key| switch (ctx.out.format) {
                .json => try ctx.out.json(.{
                    .ok = true,
                    .action = "unchanged",
                    .server = name,
                    .keyType = key.key_type,
                    .fingerprint = key.text(),
                }),
                .human => try ctx.out.print(
                    "'{s}' ({s}:{d}) already has a matching {s} pin ({s}); nothing was recorded\n",
                    .{ name, server.host, server.port, key.key_type, key.text() },
                ),
            },
            .observed => |key| {
                const keyed: Keyed = .{ .key_type = key.key_type, .fingerprint = key.text() };
                _ = Store.host_pins.record(store, .{
                    .host = server.host,
                    .port = server.port,
                    .key_type = keyed.key_type,
                    .fingerprint_sha256 = keyed.fingerprint,
                    .trust_source = .first_use,
                    .note = parsed.flag("note"),
                    .now = ctx.now,
                }) catch |err| Cli.storeFatal(store, err);
                try reportPinned(ctx.out, "trusted-on-first-use", name, server.host, server.port, keyed, .first_use);
            },
        },
    }
}

/// A recorded pin, in both formats.
///
/// The `trust_source` is published rather than implied, and in the human line
/// as well as the JSON: an operator reading back what they did needs to see
/// which of the two kinds of trust this row carries, because one of them was
/// checked against something and the other was not.
fn reportPinned(
    out: *Cli.Output,
    action: []const u8,
    name: []const u8,
    host: []const u8,
    port: u16,
    keyed: Keyed,
    source: Store.host_pins.TrustSource,
) !void {
    switch (out.format) {
        .json => try out.json(.{
            .ok = true,
            .action = action,
            .server = name,
            .keyType = keyed.key_type,
            .fingerprint = keyed.fingerprint,
            .trustSource = source.text(),
        }),
        .human => switch (source) {
            .first_use => try out.print(
                "recorded the {s} key {s} answered with: {s}\n" ++
                    "trust_source=first_use — nothing checked it, so it protects every connection after this one and not this one\n",
                .{ keyed.key_type, host, keyed.fingerprint },
            ),
            else => try out.print(
                "{s} {s} for {s}:{d}: {s} ({s})\n",
                .{ action, keyed.key_type, host, port, keyed.fingerprint, source.text() },
            ),
        },
    }
}

/// What this machine has ever trusted for one endpoint.
///
/// Revoked and superseded rows are shown, not filtered: somebody reading this
/// after a refusal needs to see the key that used to be trusted, and an empty
/// list is the answer that explains why every connection is being refused.
fn reportPins(
    out: *Cli.Output,
    name: []const u8,
    host: []const u8,
    port: u16,
    pins: []const Store.host_pins.Pin,
) !void {
    switch (out.format) {
        .json => try out.json(.{ .ok = true, .server = name, .host = host, .port = port, .pins = pins }),
        .human => {
            if (pins.len == 0) return out.print(
                "no host key is pinned for '{s}' ({s}:{d}), so every connection to it is refused.\n" ++
                    "  terminus server pin {s} --key-type <t> --fingerprint <fp>   a key you checked elsewhere\n" ++
                    "  terminus server pin {s} --trust-on-first-use                whatever answers now\n",
                .{ name, host, port, name, name },
            );
            try out.print("pins for '{s}' ({s}:{d}):\n", .{ name, host, port });
            for (pins) |p| {
                try out.print("  {s}  {s}  {s}{s}\n", .{
                    p.key_type,
                    p.fingerprint_sha256,
                    p.trust_source.text(),
                    if (p.revoked_at != null) "  [no longer active]" else "  [active]",
                });
            }
        },
    }
}

// The whole of `server pin`'s argument contract, as a gate.
//
// Drives `pinPlan` rather than the process: the flags are where three of the
// contract's four rules are actually enforced — first use is asked for by
// name, rotation needs the new fingerprint supplied, and a fingerprint that
// could never match is refused at the point of entry — and all three are
// decisions about five values with no store, host or process in them.
test "gate: `server pin`'s flags decide one of five things or refuse by name" {
    const t = std.testing;
    const fp = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU";

    // Every plan is reachable, and the count is held against the union so a
    // sixth cannot be added without a case here.
    try t.expectEqual(@as(std.meta.Tag(PinPlan), .show), std.meta.activeTag(try pinPlan(.{
        .key_type = null,
        .fingerprint = null,
        .trust_on_first_use = false,
        .rotate = false,
        .revoke = false,
    })));
    try t.expectEqual(@as(std.meta.Tag(PinPlan), .first_use), std.meta.activeTag(try pinPlan(.{
        .key_type = null,
        .fingerprint = null,
        .trust_on_first_use = true,
        .rotate = false,
        .revoke = false,
    })));
    const recorded = try pinPlan(.{
        .key_type = "ssh-ed25519",
        .fingerprint = fp,
        .trust_on_first_use = false,
        .rotate = false,
        .revoke = false,
    });
    try t.expectEqualStrings(fp, recorded.record.fingerprint);
    try t.expectEqualStrings("ssh-ed25519", recorded.record.key_type);
    const rotated = try pinPlan(.{
        .key_type = "ssh-ed25519",
        .fingerprint = fp,
        .trust_on_first_use = false,
        .rotate = true,
        .revoke = false,
    });
    try t.expectEqualStrings(fp, rotated.rotate.fingerprint);
    const revoked = try pinPlan(.{
        .key_type = "ssh-rsa",
        .fingerprint = null,
        .trust_on_first_use = false,
        .rotate = false,
        .revoke = true,
    });
    try t.expectEqualStrings("ssh-rsa", revoked.revoke);
    try t.expectEqual(@as(usize, 5), @typeInfo(PinPlan).@"union".fields.len);

    // **Rotation without a supplied fingerprint is refused.** The contract's
    // third rule, and the one a helpful implementation breaks first: taking the
    // key the host is offering today would make the tool decide what to trust,
    // which is the whole thing a pin exists to stop.
    try t.expectError(error.RotationNeedsAFingerprint, pinPlan(.{
        .key_type = "ssh-ed25519",
        .fingerprint = null,
        .trust_on_first_use = false,
        .rotate = true,
        .revoke = false,
    }));
    // Not even with a key type and a reason, which is what the shape of a
    // rotation otherwise looks like.
    try t.expectError(error.RotationNeedsAFingerprint, pinPlan(.{
        .key_type = "ssh-rsa",
        .fingerprint = null,
        .trust_on_first_use = false,
        .rotate = true,
        .revoke = false,
    }));

    // First use and an explicit fingerprint are two different answers to one
    // question, so asking for both is refused rather than one of them silently
    // winning — and a `first_use` row carrying a fingerprint somebody checked,
    // or an `explicit_pin` row carrying one nobody did, are both lies in the
    // ledger.
    try t.expectError(error.ConflictingModes, pinPlan(.{
        .key_type = "ssh-ed25519",
        .fingerprint = fp,
        .trust_on_first_use = true,
        .rotate = false,
        .revoke = false,
    }));
    try t.expectError(error.ConflictingModes, pinPlan(.{
        .key_type = "ssh-ed25519",
        .fingerprint = fp,
        .trust_on_first_use = false,
        .rotate = false,
        .revoke = true,
    }));
    try t.expectError(error.ConflictingModes, pinPlan(.{
        .key_type = null,
        .fingerprint = null,
        .trust_on_first_use = true,
        .rotate = true,
        .revoke = false,
    }));

    // A pin is keyed on the type as well as the endpoint, so neither half of
    // that key may be guessed.
    try t.expectError(error.FingerprintNeedsAKeyType, pinPlan(.{
        .key_type = null,
        .fingerprint = fp,
        .trust_on_first_use = false,
        .rotate = false,
        .revoke = false,
    }));
    try t.expectError(error.RevocationNeedsAKeyType, pinPlan(.{
        .key_type = null,
        .fingerprint = null,
        .trust_on_first_use = false,
        .rotate = false,
        .revoke = true,
    }));
    try t.expectError(error.KeyTypeNeedsAFingerprint, pinPlan(.{
        .key_type = "ssh-ed25519",
        .fingerprint = null,
        .trust_on_first_use = false,
        .rotate = false,
        .revoke = false,
    }));

    // A fingerprint that cannot match is refused here rather than stored.
    try t.expectError(error.FingerprintNotCanonical, pinPlan(.{
        .key_type = "ssh-ed25519",
        .fingerprint = "MD5:ab:cd:ef",
        .trust_on_first_use = false,
        .rotate = false,
        .revoke = false,
    }));
    try t.expectError(error.FingerprintNotCanonical, pinPlan(.{
        .key_type = "ssh-ed25519",
        .fingerprint = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        .trust_on_first_use = false,
        .rotate = false,
        .revoke = false,
    }));

    // Every refusal has a sentence, and each sentence names a flag. A member
    // added to the error set without one would print an empty line.
    var worded: usize = 0;
    inline for (@typeInfo(PinPlanError).error_set.?) |e| {
        worded += 1;
        const sentence = pinPlanRefusal(@field(PinPlanError, e.name));
        if (sentence.len < 40 or std.mem.indexOf(u8, sentence, "--") == null) {
            std.debug.print("\n`{s}`'s refusal names no flag: \"{s}\"\n", .{ e.name, sentence });
            return error.PinRefusalNamesNoFlag;
        }
    }
    try t.expectEqual(@as(usize, 6), worded);
}

/// A successful removal, in both formats and in one place.
///
/// Extracted from `run` so a gate can drive it: "the key is published in the JSON
/// *and* in the human line" is a property of two arms that would otherwise only be
/// checkable by reading them, and the arm most likely to be forgotten is the one a
/// human never looks at.
///
/// `orphanedKey` is present on every success and null when nothing was orphaned,
/// rather than absent. An agent branches on one key either way; an absent key would
/// make it distinguish "nothing was left behind" from "this build does not report
/// it", which is a question about the binary and not about the removal.
fn reportRemoved(out: *Cli.Output, name: []const u8, orphaned: ?[]const u8) !void {
    switch (out.format) {
        .json => try out.json(.{
            .ok = true,
            .action = "removed",
            .server = name,
            .orphanedKey = orphaned,
        }),
        // The key is named, not merely reported to exist: an operator told "a
        // key is now unreferenced" cannot act on it without going to look up
        // which one.
        .human => if (orphaned) |key| try out.print(
            "removed server '{s}'; its private key '{s}' was not deleted and is now referenced by nothing — " ++
                "'terminus key rm {s}' would destroy material that cannot be regenerated\n",
            .{ name, key, key },
        ) else try out.print("removed server '{s}'\n", .{name}),
    }
}

/// The `SERVER_CASCADE_NOT_CONFIRMED` sentence, named so a gate can count its
/// slots.
///
/// One `{d}` per counted table, plus the `{s}` for the server. `leases` is named
/// as well as barriered because the two answer different questions — the barrier
/// refuses over live claims, this counts the released history that goes when there
/// are none — and `redaction_rules` is named because destroying a declared secret
/// location in silence is the worst of the seven.
///
/// **What the gate below holds, and what it deliberately does not.** It holds the
/// number of slots against the number of `CascadeCounts` fields, because that is
/// the failure an eighth cascading table produces today: every other joint of the
/// chain moves, and the operator is handed a sentence that names seven of eight.
/// It does not hold the *order*. The sentence leads with the two an operator is
/// most likely to regret and the argument list is written to match, so an order
/// check would be a check on a wording decision rather than on drift — and the one
/// thing an order check would catch, two counts swapped, is not made more likely by
/// adding a table.
const cascade_not_confirmed =
    "removing '{s}' also deletes {d} memories, {d} facts, {d} sessions, {d} jobs, {d} history entries, " ++
    "{d} lease records and {d} redaction rules. The lease records are the history of who held what on " ++
    "this host and how it was given back, which the lease barrier stops covering the moment nothing is " ++
    "held; the redaction rules are declared secret locations, so losing them puts what they hid back on " ++
    "pattern guessing. Re-run with --force";

test "gate: the cascade refusal has a slot for every counted table" {
    const fields = @typeInfo(Store.servers.CascadeCounts).@"struct".fields;
    const slots = std.mem.count(u8, cascade_not_confirmed, "{d}");
    if (slots != fields.len) {
        std.debug.print(
            \\
            \\`cascade_not_confirmed` has {d} `{{d}}` slot(s) and `CascadeCounts` has {d} field(s).
            \\A table in the cascade and out of this sentence is deleted without ever being
            \\named: `--force` is asked for on the strength of a total that now includes it,
            \\and the operator is shown the other {d}.
            \\
        , .{ slots, fields.len, slots });
        return error.CascadeSentenceIncomplete;
    }
}

/// What `server rm` decided, before any of it is worded.
const RmOutcome = union(enum) {
    /// The server is gone, and the payload is the private key the removal left
    /// behind with nothing referencing it — `null` when there was no key, and
    /// when another server still points at the same one, for which the removal
    /// changed nothing and saying so would be false.
    ///
    /// A key name and not a flag, because the sentence has to name the key: an
    /// operator told "a key is now unreferenced" has been given a fact they
    /// cannot act on without going to look it up.
    removed: ?[]const u8,
    /// The cascade *volume* warning: how much recorded knowledge about the host
    /// goes with it. `--force` covers this and only this.
    needs_force: Store.servers.CascadeCounts,
    /// A safety barrier. Nothing covers these.
    refused: Store.servers.Barrier,
    /// The name resolved a moment ago and did not resolve inside the removal's
    /// transaction. Not folded into a success: a caller told "removed" for a
    /// server that was never deleted has been told a falsehood.
    vanished,
};

/// The whole of `server rm` bar argument parsing and wording.
///
/// A named function rather than an inline block because one property has to be
/// provable and cannot be reached through `run`: **`force` is consulted for the
/// cascade volume warning and is never handed to the store.** The three
/// barriers are decided inside `servers.remove`'s write transaction, which
/// takes no flag and has no parameter that could carry one, so the only way a
/// flag could wave one through is if this function deleted the row itself.
/// The gate calls it with `force = true` against a live barrier and checks both
/// that it refuses and that the row survives — which is what makes the sentence
/// above a fact rather than a claim.
///
/// The two kinds of loss are genuinely different, which is why one is coverable
/// and the others are not. The cascade throws away records of a host nobody
/// wants any more. A barrier means something is still *live*: an attempt whose
/// remote outcome nobody knows, a claim somebody is holding, a transfer with a
/// legal move left. The way past each of those is to establish the fact it is
/// waiting on, and no flag supplies a fact.
///
/// `key_name` is the third kind, and it is neither a loss nor a barrier: the
/// removal leaves the private key exactly where it was and only stops referencing
/// it. It arrives as a parameter rather than being read here because it has to be
/// read from the `servers`→`keys` join while the server row still exists — see
/// the header above `Store.servers.KeyAfterRemoval` for what the store decides
/// and what this passes through.
fn removeServer(
    store: *Store,
    server_id: i64,
    name: []const u8,
    key_name: ?[]const u8,
    force: bool,
    now: i64,
) Store.servers.RemoveError!RmOutcome {
    // Advisory, and read outside any transaction on purpose: it is a volume
    // warning, so a row appearing between here and the delete changes nothing
    // that matters. The numbers that *do* matter are counted inside the
    // transaction that deletes.
    const counts = try Store.servers.cascadeCounts(store, server_id);
    // Every field, derived. This was seven terms added up by hand against a
    // seven-field struct with nothing tying the two together — the one link of
    // this chain that was not held, and the one an eighth cascading table would
    // have walked straight through: schema gate, declaration, field and
    // assignment all move, and the sum went on adding seven. See
    // `servers.cascadeTotal`.
    const total = Store.servers.cascadeTotal(counts);
    if (total > 0 and !force) return .{ .needs_force = counts };

    return switch (try Store.servers.remove(store, name, now)) {
        // The name is the one read from the `servers`→`keys` join before the
        // removal opened its transaction; whether it is now unreferenced was
        // decided inside it. See `RmOutcome.removed`.
        .removed => |key_after| .{
            .removed = if (key_after == .left_unreferenced) key_name else null,
        },
        .unknown_server => .vanished,
        .refused => |barrier| .{ .refused = barrier },
    };
}

/// A throwaway database for the gate below.
///
/// A local copy rather than a shared helper: the store's own gates keep theirs
/// in `gates_test.zig`, and reaching into a test file from the command layer to
/// share thirty lines would drag that file's whole suite into this build twice.
const Scratch = struct {
    io: std.Io,
    threaded: *std.Io.Threaded,
    path: [:0]u8,
    allocator: std.mem.Allocator,

    const dir = ".zig-cache/tmp";

    fn init(allocator: std.mem.Allocator, name: []const u8) !Scratch {
        const threaded = try allocator.create(std.Io.Threaded);
        threaded.* = .init(allocator, .{});
        const io = threaded.io();
        std.Io.Dir.cwd().createDirPath(io, dir) catch {};
        const path = try std.fmt.allocPrintSentinel(
            allocator,
            "{s}/{s}_{d}.db",
            .{ dir, name, std.Thread.getCurrentId() },
            0,
        );
        var s: Scratch = .{ .io = io, .threaded = threaded, .path = path, .allocator = allocator };
        s.removeFiles();
        return s;
    }

    /// WAL databases have sidecars; leaving one behind would make the next run
    /// read a mismatched log, which silently shows empty data.
    fn removeFiles(s: *Scratch) void {
        const cwd = std.Io.Dir.cwd();
        cwd.deleteFile(s.io, s.path) catch {};
        for ([_][]const u8{ "-wal", "-shm" }) |suffix| {
            const side = std.fmt.allocPrint(s.allocator, "{s}{s}", .{ s.path, suffix }) catch return;
            defer s.allocator.free(side);
            cwd.deleteFile(s.io, side) catch {};
        }
    }

    fn deinit(s: *Scratch) void {
        s.removeFiles();
        s.allocator.free(s.path);
        s.threaded.deinit();
        s.allocator.destroy(s.threaded);
    }
};

test "gate: --force covers the cascade and no barrier" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "cmd_server_force");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    const server_id = try Store.servers.add(&store, .{
        .name = "box",
        .host = "10.0.0.1",
        .port = 22,
        .username = "ubuntu",
        .now = 100,
    });

    // Something to warn about, so the two kinds of loss are both in play at
    // once and the gate is not quietly testing a server with nothing on it.
    _ = try Store.memories.add(&store, .{ .server_id = server_id }, .{
        .content = "the deploy user is ubuntu",
        .now = 100,
    });
    try t.expectEqual(
        @as(std.meta.Tag(RmOutcome), .needs_force),
        std.meta.activeTag(try removeServer(&store, server_id, "box", null, false, 200)),
    );

    // A lease is somebody's live claim. `--force` is the strongest thing the
    // operator can say and it does not touch this: the barrier is decided
    // inside `servers.remove`'s transaction, which takes no flag, and this
    // function does not delete anything itself.
    switch (try Store.leases.acquire(&store, arena, .{
        .server_id = server_id,
        .scope = .{ .kind = .path, .key = "/srv/app" },
        .owner_request_id = "01PEEEEEEER0123456789ABCDE",
        .profile_token = "peer-machine",
        .ttl_secs = 300,
        .now = 200,
    })) {
        .acquired => {},
        .renewed, .conflict => return error.LeaseDidNotTake,
    }

    switch (try removeServer(&store, server_id, "box", null, true, 210)) {
        .refused => |barrier| try t.expectEqual(
            Store.servers.Barrier{ .active_leases = 1 },
            barrier,
        ),
        .removed => return error.ForceWavedThroughABarrier,
        .needs_force => return error.CascadeWarningSurvivedForce,
        .vanished => return error.ServerVanished,
    }
    // Refused means nothing went.
    try t.expect((try Store.servers.getByName(&store, arena, "box")) != null);

    // And the flag really does still do its job on the thing it is for: with
    // the barrier gone, the same forced call goes through and the cascade
    // warning it covers is not raised again. Without this half the gate would
    // also pass if `--force` had simply stopped working.
    _ = try Store.leases.release(
        &store,
        server_id,
        .{ .kind = .path, .key = "/srv/app" },
        "01PEEEEEEER0123456789ABCDE",
        .released,
        220,
    );
    try t.expectEqual(
        @as(std.meta.Tag(RmOutcome), .removed),
        std.meta.activeTag(try removeServer(&store, server_id, "box", null, true, 230)),
    );
    try t.expect((try Store.servers.getByName(&store, arena, "box")) == null);
}

/// Removes a server through the whole of `server rm` bar wording, and answers
/// what it said about the key.
///
/// `force = false` on purpose: these servers are meant to have nothing on them,
/// so a cascade warning here is the fixture having grown rows nobody intended
/// rather than something to wave through.
fn removeAndReportKey(
    store: *Store,
    arena: std.mem.Allocator,
    name: []const u8,
    now: i64,
) !?[]const u8 {
    const server = (try Store.servers.getByName(store, arena, name)) orelse
        return error.ServerWasNotThereToRemove;
    return switch (try removeServer(store, server.id, name, server.key, false, now)) {
        .removed => |orphaned| orphaned,
        .needs_force => error.CascadeWarningBlockedTheRemoval,
        .refused => error.RemovalUnexpectedlyRefused,
        .vanished => error.ServerVanished,
    };
}

/// The private material behind a key name, or an error if the row is not there.
///
/// An error and not a `null` a caller can ignore: every use below is asserting
/// that `server rm` left the key alone, and a lookup that quietly finds nothing
/// would turn "the key survived" into "we did not look".
fn survivingPrivateKey(store: *Store, arena: std.mem.Allocator, name: []const u8) ![]const u8 {
    const material = (try Store.keys.material(store, arena, name)) orelse
        return error.KeyRowWasDestroyedByTheServerRemoval;
    return material.private orelse error.KeyRowSurvivedWithoutItsPrivateMaterial;
}

/// `removeAndReportKey` for a removal that is supposed to name a key.
///
/// A named error rather than `.?`: unwrapping a null here panics, and a gate
/// whose failure is a panic tells the next reader that something crashed rather
/// than which of the three readings stopped being true.
fn orphanedKeyOf(
    store: *Store,
    arena: std.mem.Allocator,
    name: []const u8,
    now: i64,
) ![]const u8 {
    return (try removeAndReportKey(store, arena, name, now)) orelse
        error.RemovalDidNotNameTheKeyItLeftUnreferenced;
}

fn wordedRemoval(
    arena: std.mem.Allocator,
    format: Cli.Output.Format,
    name: []const u8,
    orphaned: ?[]const u8,
) ![]const u8 {
    var buffer: std.Io.Writer.Allocating = .init(arena);
    var out: Cli.Output = .{ .writer = &buffer.writer, .format = format };
    try reportRemoved(&out, name, orphaned);
    return buffer.toOwnedSlice();
}

test "gate: a successful removal names the private key it leaves unreferenced" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "cmd_server_orphan_key");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    // Two keys with real private material, and three shapes of server pointing
    // at them: one sole referrer, two sharing one key, and one with no key at
    // all. All three readings of the sentence are in this one store.
    _ = try Store.keys.add(&store, .{
        .name = "solo-key",
        .kind = "ed25519",
        .private = "-----BEGIN PRIVATE KEY-----solo",
        .now = 100,
    });
    _ = try Store.keys.add(&store, .{
        .name = "shared-key",
        .kind = "ed25519",
        .private = "-----BEGIN PRIVATE KEY-----shared",
        .now = 100,
    });
    for ([_]struct { name: []const u8, key: ?[]const u8 }{
        .{ .name = "solo", .key = "solo-key" },
        .{ .name = "twin-a", .key = "shared-key" },
        .{ .name = "twin-b", .key = "shared-key" },
        .{ .name = "bare", .key = null },
    }) |spec| {
        _ = try Store.servers.add(&store, .{
            .name = spec.name,
            .host = "10.0.0.1",
            .port = 22,
            .username = "ubuntu",
            .key = spec.key,
            .now = 100,
        });
    }
    // The fixture is the evidence, so it is counted before anything is removed:
    // four servers and two keys, or every silence below is a server that was
    // never there.
    try t.expectEqual(@as(usize, 4), (try Store.servers.list(&store, arena)).len);
    try t.expectEqual(@as(usize, 2), (try Store.keys.list(&store, arena)).len);

    // (1) Correctly silent, and silent for a *reason*: `shared-key` is still
    //     referenced by `twin-b`, so nothing about that key changed and a
    //     sentence claiming it had been left unreferenced would be false.
    try t.expectEqual(@as(?[]const u8, null), try removeAndReportKey(&store, arena, "twin-a", 200));

    // (2) Reported. Same key, one removal later, and now the last reference to
    //     it is gone. This pair is the whole point: if the answer were "the
    //     server had a key" rather than "the key is now unreferenced", (1) and
    //     (2) would read the same and only one of them would be true.
    try t.expectEqualStrings(
        "shared-key",
        try orphanedKeyOf(&store, arena, "twin-b", 210),
    );

    // (3) Not malformed. No key at all, so there is no name to put in a
    //     sentence and the plain line is the whole output — no empty quotes, no
    //     dangling clause.
    try t.expectEqual(@as(?[]const u8, null), try removeAndReportKey(&store, arena, "bare", 220));
    try t.expectEqualStrings(
        "removed server 'bare'\n",
        try wordedRemoval(arena, .human, "bare", null),
    );

    // (4) The sole referrer, reported the same way, so (2) is not an artefact
    //     of a key that once had two servers.
    try t.expectEqualStrings(
        "solo-key",
        try orphanedKeyOf(&store, arena, "solo", 230),
    );

    // Nothing is left to remove, and both key rows outlived every one of those
    // removals with their private material intact. `servers.key_id` points *at*
    // `keys` and is `NO ACTION`: the removal ends the reference, never the
    // material, which is exactly why the sentence has to be said — `key rm`
    // will now go through over bytes nobody can regenerate.
    try t.expectEqual(@as(usize, 0), (try Store.servers.list(&store, arena)).len);
    try t.expectEqual(@as(usize, 2), (try Store.keys.list(&store, arena)).len);
    try t.expectEqualStrings(
        "-----BEGIN PRIVATE KEY-----solo",
        try survivingPrivateKey(&store, arena, "solo-key"),
    );
    try t.expectEqualStrings(
        "-----BEGIN PRIVATE KEY-----shared",
        try survivingPrivateKey(&store, arena, "shared-key"),
    );

    // And the answer reaches both published formats. The JSON arm is the one a
    // human never reads, so it is the one that would go missing; the key is
    // present either way and null is the "nothing was orphaned" answer, so an
    // agent branches on one key rather than on its absence.
    try t.expectEqualStrings(
        \\{
        \\  "ok": true,
        \\  "action": "removed",
        \\  "server": "solo",
        \\  "orphanedKey": "solo-key"
        \\}
        \\
    , try wordedRemoval(arena, .json, "solo", "solo-key"));
    try t.expectEqualStrings(
        \\{
        \\  "ok": true,
        \\  "action": "removed",
        \\  "server": "bare",
        \\  "orphanedKey": null
        \\}
        \\
    , try wordedRemoval(arena, .json, "bare", null));

    // The human line names the key and says what is now possible over it. Held
    // as substrings rather than the whole sentence: the wording is allowed to
    // improve, the two facts in it are not allowed to leave.
    const line = try wordedRemoval(arena, .human, "solo", "solo-key");
    for ([_][]const u8{ "solo-key", "referenced by nothing", "key rm solo-key" }) |needle| {
        if (std.mem.indexOf(u8, line, needle) == null) {
            std.debug.print(
                \\
                \\the human line for a removal that orphaned a key does not contain
                \\`{s}`. It read:
                \\
                \\  {s}
                \\
            , .{ needle, line });
            return error.OrphanedKeyIsNotInTheHumanLine;
        }
    }
}

// The file header's claim about `ping`, held against the code it is about.
//
// Two halves, because dropping either one would let the verb start changing a
// host with no request id: the word it sends, and the fact that it is the only
// remote call in here. The second is read over the source rather than asserted
// from memory — a second `exec` added anywhere in this file fails this gate,
// which is where the question "does that one need an operation?" gets asked.
test "gate: `server ping` sends a command that cannot change the host" {
    const t = std.testing;

    // `true` and nothing else. Not "starts with", not "contains": an argument
    // appended here would be a command with an effect, and the argument for this
    // verb having no ledger row is that there is no effect to record.
    try t.expectEqualStrings("true", ping_command);

    // Assembled so this gate's own text is not one of the sites it counts.
    const needle = ".exec" ++ "(";
    const source = @embedFile("cmd_server.zig");

    var calls: usize = 0;
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, source, i, needle)) |at| : (i = at + 1) calls += 1;
    if (calls != 1) {
        std.debug.print(
            \\
            \\cmd_server.zig makes {d} exec calls. It may have exactly one — `ping`'s — and
            \\the reason this verb has no operation row is that the one it has sends a word
            \\with no effect. A second one is a remote call nothing in the ledger describes;
            \\give it an execution (`cmd_sync.zig` has the shape) rather than widening this
            \\count.
            \\
        , .{calls});
        return error.MoreThanOneRemoteCall;
    }

    // And the one call is passed the constant, not a literal beside it.
    try t.expect(std.mem.indexOf(u8, source, needle ++ "ctx.arena, ping_command)") != null);
}
