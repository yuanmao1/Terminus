//! Host key pinning, gated at the layer that can actually be gated.
//!
//! **What is proven here and what is not.** There is no SSH server in this
//! repository: the one host whose key this machine has lives only inside the
//! operator's real database, which no test may open, so a real libssh2
//! handshake is unreachable from a gate. Two libssh2 calls are therefore
//! *reviewed* rather than proven — `libssh2_session_hostkey`, which hands back
//! the key blob and its type, and the `Sha256` over that blob in
//! `Ssh.presentedKey`. Everything that decides anything is above them and is
//! driven here against real sqlite stores: the store lookup, the comparison,
//! the mapping from verdict to refusal, the sentence the operator reads, and
//! the argument contract of the command that records a pin.
//!
//! That boundary is stated plainly on purpose. This is the one area of the tree
//! where a false claim of coverage would itself be the security problem.
const std = @import("std");
const Cli = @import("cli.zig");
const Core = @import("../core/core.zig");
const Ssh = Core.Ssh;
const Store = Core.Store;

/// A throwaway database. A local copy for the reason `cmd_server.zig` keeps
/// one: reaching into another file's test helpers to share thirty lines drags
/// that file's whole suite into this build a second time.
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

/// A presented key built the way `Ssh.presentedKey` builds one: a type name and
/// the canonical text of a SHA-256.
fn presented(key_type: []const u8, material: []const u8) Ssh.HostKey {
    var sha: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(material, &sha, .{});
    var key: Ssh.HostKey = .{ .key_type = key_type, .fingerprint = undefined };
    Ssh.formatFingerprint(&key.fingerprint, sha);
    return key;
}

// --- the decision -------------------------------------------------------------

test "gate: a presented key is judged against the pin recorded for its own type" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "host_key_judge");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();

    const real = presented("ssh-ed25519", "the host's real key");
    const impostor = presented("ssh-ed25519", "somebody else's key");
    const other_type = presented("ssh-rsa", "the host's real key");

    // Every case below is `(what is in the store) x (what was presented) x
    // (was first use asked for)`, and the count is asserted at the end so a
    // future edit cannot quietly delete one and leave a green gate.
    var checked: usize = 0;

    // (1) The state every existing store is in. Nothing before this slice
    //     recorded a host key anywhere, so there is no pin and no observation
    //     a migration could have promoted into one. The default is refusal.
    var lookup = Cli.pinsOf(&store, arena, "10.0.0.1", 22);
    try t.expectEqual(Ssh.Verdict.not_pinned, Ssh.judge(lookup.trustRoot(false), real));
    checked += 1;

    // (2) ...and the absence of a pin does not become permission when nobody
    //     asked for first use. Same state, same answer, twice, because this is
    //     the single most important line in the file.
    try t.expectEqual(Ssh.Verdict.not_pinned, Ssh.judge(lookup.trustRoot(false), impostor));
    checked += 1;

    // (3) First use is asked for by name, and only then is an unpinned key
    //     admitted — as `first_use`, a distinct verdict, because the caller has
    //     to record something and a `matches_pin` would tell it there was
    //     nothing to do.
    try t.expectEqual(Ssh.Verdict.first_use, Ssh.judge(lookup.trustRoot(true), real));
    checked += 1;

    _ = try Store.host_pins.record(&store, .{
        .host = "10.0.0.1",
        .port = 22,
        .key_type = "ssh-ed25519",
        .fingerprint_sha256 = real.text(),
        .trust_source = .explicit_pin,
        .now = 100,
    });

    // (4) The pinned key connects.
    try t.expectEqual(Ssh.Verdict.matches_pin, Ssh.judge(lookup.trustRoot(false), real));
    checked += 1;

    // (5) Any other key is a mismatch. Not a warning, not a prompt.
    try t.expectEqual(Ssh.Verdict.mismatch, Ssh.judge(lookup.trustRoot(false), impostor));
    checked += 1;

    // (6) **First use does not override a pin.** `--trust-on-first-use` means
    //     "record a host nothing is known about"; if it also replaced a
    //     recorded key it would be a way to turn the check off, and the flag an
    //     operator used once during setup would silently disarm every later
    //     connection.
    try t.expectEqual(Ssh.Verdict.mismatch, Ssh.judge(lookup.trustRoot(true), impostor));
    checked += 1;
    try t.expectEqual(Ssh.Verdict.matches_pin, Ssh.judge(lookup.trustRoot(true), real));
    checked += 1;

    // (7) The pin is keyed on the key type as well as the endpoint, so a key of
    //     another type is unpinned rather than compared against this one. That
    //     is what stops a machine in the path from offering a type nobody has
    //     vouched for and being measured against the pin for a different one.
    try t.expectEqual(Ssh.Verdict.not_pinned, Ssh.judge(lookup.trustRoot(false), other_type));
    checked += 1;

    // (8) A different port is a different endpoint. Two servers on one host at
    //     one port share this pin; the same host at another port does not have
    //     it, and neither does a server row whose address was changed.
    var other_port = Cli.pinsOf(&store, arena, "10.0.0.1", 2222);
    try t.expectEqual(Ssh.Verdict.not_pinned, Ssh.judge(other_port.trustRoot(false), real));
    checked += 1;
    var other_host = Cli.pinsOf(&store, arena, "10.0.0.2", 22);
    try t.expectEqual(Ssh.Verdict.not_pinned, Ssh.judge(other_host.trustRoot(false), real));
    checked += 1;

    // (9) A second server row on the same host:port really does share it — the
    //     pin describes the machine, not the login.
    var same_box = Cli.pinsOf(&store, arena, "10.0.0.1", 22);
    try t.expectEqual(Ssh.Verdict.matches_pin, Ssh.judge(same_box.trustRoot(false), real));
    checked += 1;

    // (10) Revocation. `host_pins.revoke` had no caller at all before this
    //      slice, so this is also the first thing that establishes what a
    //      withdrawn pin does: `active` stops answering, the verdict falls back
    //      to the default, and the connection is refused. The contract needs
    //      this verb because its other three cannot do it — a mismatch changes
    //      no row, and rotation needs a replacement fingerprint that an
    //      operator who has just learned a key was stolen does not have.
    const pin = (try Store.host_pins.active(&store, arena, "10.0.0.1", 22, "ssh-ed25519")).?;
    try t.expect(try Store.host_pins.revoke(&store, pin.id, "key was on a stolen backup", 200));
    var after = Cli.pinsOf(&store, arena, "10.0.0.1", 22);
    try t.expectEqual(Ssh.Verdict.not_pinned, Ssh.judge(after.trustRoot(false), real));
    checked += 1;
    // And a revoked pin is not resurrected by asking with first use on: that
    // would make revocation undoable by the same flag it was meant to survive.
    // It records a *new* pin instead, which is a deliberate act with its own
    // row and its own `trust_source`.
    try t.expectEqual(Ssh.Verdict.first_use, Ssh.judge(after.trustRoot(true), real));
    checked += 1;

    try t.expectEqual(@as(usize, 13), checked);
}

test "gate: every verdict that is not a match refuses the connection" {
    const t = std.testing;

    // Exhaustive over the enum rather than over a list somebody maintains: a
    // sixth verdict added without a refusal fails here.
    const fields = @typeInfo(Ssh.Verdict).@"enum".fields;
    try t.expectEqual(@as(usize, 5), fields.len);

    var admitted: usize = 0;
    var refused: usize = 0;
    inline for (fields) |f| {
        const v: Ssh.Verdict = @field(Ssh.Verdict, f.name);
        // The two answers have to agree: `admits` is what the prose says and
        // `refusalFor` is what `connect` obeys, and a verdict where they parted
        // would be a session opened over a refusal or the reverse.
        if (v.admits()) {
            admitted += 1;
            if (Ssh.refusalFor(v) != null) {
                std.debug.print("\nverdict `{s}` admits a session and also refuses one\n", .{f.name});
                return error.VerdictDisagreesWithItself;
            }
        } else {
            refused += 1;
            if (Ssh.refusalFor(v) == null) {
                std.debug.print(
                    \\
                    \\verdict `{s}` refuses a session and `refusalFor` has no error for it, so
                    \\`connect` would return a live `Client` over it.
                    \\
                , .{f.name});
                return error.RefusedVerdictOpensASession;
            }
        }
    }
    try t.expectEqual(@as(usize, 2), admitted);
    try t.expectEqual(@as(usize, 3), refused);

    // And each refusal is its own error, because the operator's next move is
    // different for each: record a pin, investigate an impersonation, or use a
    // transport that has a trust store.
    try t.expectEqual(@as(?anyerror, error.HostKeyNotPinned), Ssh.refusalFor(.not_pinned));
    try t.expectEqual(@as(?anyerror, error.HostKeyMismatch), Ssh.refusalFor(.mismatch));
    try t.expectEqual(@as(?anyerror, error.NoTrustRoot), Ssh.refusalFor(.no_trust_root));
}

test "gate: the trust root has no member that opens a session without a pin" {
    const t = std.testing;

    // Two members, and that is the structural claim: one checks, the other
    // refuses. A third — a `.trust_anything`, an `.insecure`, a
    // `.skip_verification` — fails this gate before it can be used anywhere.
    const members = @typeInfo(Ssh.TrustRoot).@"union".fields;
    try t.expectEqual(@as(usize, 2), members.len);
    var named: usize = 0;
    inline for (members) |m| {
        named += 1;
        const known = std.mem.eql(u8, m.name, "pins") or std.mem.eql(u8, m.name, "none");
        if (!known) {
            std.debug.print(
                \\
                \\`Ssh.TrustRoot` has a member `{s}`. The two that exist are `pins`, which is
                \\compared against a store, and `none`, which refuses before it dials. A third
                \\is a way to open a session nothing checked; give it a `Verdict` and a refusal
                \\rather than widening this gate.
                \\
            , .{m.name});
            return error.TrustRootGrewAMember;
        }
    }
    try t.expectEqual(@as(usize, 2), named);

    // `.none` refuses whatever it is shown.
    try t.expectEqual(Ssh.Verdict.no_trust_root, Ssh.judge(.none, presented("ssh-ed25519", "anything")));
    try t.expectEqual(Ssh.Verdict.no_trust_root, Ssh.judge(.none, presented("ssh-rsa", "anything else")));

    // First use is off unless somebody sets it. A default of `true` here would
    // turn every connection in the tree into trust-on-first-use while every
    // call site went on looking correct.
    //
    // Three fields and no more, for the same reason the union has two members:
    // a fourth would be another dial on the one thing that can widen the check.
    try t.expectEqual(@as(usize, 3), @typeInfo(Ssh.TrustRoot.Pins).@"struct".fields.len);
    const tofu = std.meta.fieldInfo(Ssh.TrustRoot.Pins, .trust_on_first_use);
    const default = tofu.default_value_ptr orelse return error.FirstUseHasNoDefault;
    try t.expectEqual(false, @as(*const bool, @ptrCast(default)).*);

    // **The lookup cannot see what it will be compared against.** This is what
    // makes "every session goes through the check" a property of the types
    // rather than of a list of call sites: the strongest thing a wrong or
    // hostile lookup can do is refuse a connection that should have been
    // allowed, because it is never handed the presented fingerprint and so
    // cannot be arranged to agree with it. A second parameter of type
    // `HostKey`, or a `[32]u8`, or the fingerprint text, would end that.
    const recorded = @typeInfo(@typeInfo(std.meta.fieldInfo(Ssh.TrustRoot.Pins, .recorded).type).pointer.child).@"fn";
    try t.expectEqual(@as(usize, 2), recorded.params.len);
    try t.expectEqual(@as(?type, *anyopaque), recorded.params[0].type);
    try t.expectEqual(@as(?type, []const u8), recorded.params[1].type);
    try t.expectEqual(@as(?type, ?[]const u8), recorded.return_type);
}

// --- where the check sits -----------------------------------------------------

/// A module's source with its comment lines removed, so the rules below are
/// about what the code does rather than about what it says. Not a convenience:
/// both files scanned here explain the pinning rules at length in prose, and a
/// rule that read the prose would be satisfied by its own documentation.
fn codeOnly(arena: std.mem.Allocator, source: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var lines = std.mem.splitScalar(u8, source, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trimStart(u8, line, " \t");
        // `//`, `///` and `//!` all start the same way, and all three are prose.
        if (std.mem.startsWith(u8, trimmed, "//")) continue;
        try out.appendSlice(arena, line);
        try out.append(arena, '\n');
    }
    return out.toOwnedSlice(arena);
}

fn occurrences(haystack: []const u8, needle: []const u8) usize {
    var n: usize = 0;
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, haystack, i, needle)) |at| : (i = at + 1) n += 1;
    return n;
}

test "gate: no session is constructed without naming a trust root" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // The type-level half, and the one that covers sites nobody has written
    // yet: `connect` takes the trust root as a required argument. There is no
    // default, no second entry point, and no overload — so a new caller cannot
    // open a session without deciding what it is checked against, and the only
    // two things it can decide are "this store" and "refuse".
    const params = @typeInfo(@TypeOf(Ssh.connect)).@"fn".params;
    try t.expectEqual(@as(usize, 4), params.len);
    try t.expectEqual(@as(?type, Ssh.TrustRoot), params[2].type);
    try t.expectEqual(@as(?type, *?Ssh.HostKey), params[3].type);

    // The census half. Two sites exist in this tree and the gate says which,
    // because "two" on its own would also be satisfied by two copies in one
    // file while a third slipped into another.
    const needle = "Ssh.connect(";
    const cli = try codeOnly(arena, @embedFile("cli.zig"));
    const daemon = try codeOnly(arena, @embedFile("../core/daemon/Server.zig"));

    // Two in the CLI: the one every command dials through, and the one
    // `server pin --trust-on-first-use` uses to read a key and hang up.
    try t.expectEqual(@as(usize, 2), occurrences(cli, needle));
    try t.expectEqual(@as(usize, 1), occurrences(daemon, needle));

    // The daemon's site passes the trust root the *request* carried, and the
    // property underneath that is what this checks: the daemon has no store.
    //
    // This assertion used to read `..., .none,` — a proxy for "it has nothing to
    // read a pin from", which stopped being true when the authority started
    // travelling with the request. The proxy is replaced by the thing it stood
    // for, which survives the change: a daemon that opened the default database
    // would authorise a `--db <other>` CLI's connections from a trust root the
    // operator never recorded in, and a background process would open the user's
    // real store.
    try t.expect(std.mem.indexOf(u8, daemon, needle ++ "request.host, request.port, lookup.trustRoot(), &observed") != null);
    for ([_][]const u8{ "Store" ++ ".open", "host" ++ "_pins", "db" ++ "Path", "sqlite" }) |forbidden| {
        std.testing.expectEqual(@as(usize, 0), occurrences(daemon, forbidden)) catch |err| {
            std.debug.print("the daemon reaches for '{s}', so it has a store after all\n", .{forbidden});
            return err;
        };
    }

    // The scans really did read code: a failed embed or an over-eager stripper
    // would satisfy every count above.
    try t.expect(std.mem.indexOf(u8, cli, "pub fn observeHostKey(") != null);
    try t.expect(std.mem.indexOf(u8, daemon, "fn connectFor(") != null);
    try t.expect(cli.len > 4096);
    try t.expect(daemon.len > 2048);
}

test "gate: connect judges the key it read before it hands back a session" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // The one line no gate can reach by running it: `connect` needs a socket, a
    // handshake and a server, and there is none here. So the wiring is held as
    // a rule over the source instead, and the rule is about order — the two
    // `errdefer`s above it are what make a refusal free the session and close
    // the socket, and the language guarantees they run for *any* error return
    // between them and the end of the function. What has to be true is that the
    // judgment happens on that side of the `return`.
    const body = try @import("../core/control.zig").bodyOf(
        try codeOnly(arena, @embedFile("../core/ssh/Client.zig")),
        "\npub fn connect(",
    );

    // One judgment, and it is the composition: `judge` deciding and `refusalFor`
    // turning that into the error. Split into two statements with a `null` check
    // in between, or replaced by a bare `judge` whose answer is discarded, this
    // count changes.
    try t.expectEqual(@as(usize, 1), occurrences(body, "refusalFor(judge("));

    const judged = std.mem.indexOf(u8, body, "refusalFor(judge(").?;
    const handed_back = std.mem.indexOf(u8, body, "return .{ .socket = socket").?;
    if (judged > handed_back) {
        std.debug.print(
            \\
            \\`Ssh.connect` returns a `Client` before it judges the host key. Everything after
            \\that return happens with a live session in the caller's hands.
            \\
        , .{});
        return error.SessionHandedBackBeforeTheCheck;
    }

    // And the two `errdefer`s really are above it, so the refusal below them
    // frees the session and closes the socket rather than leaking both.
    const frees = std.mem.indexOf(u8, body, "errdefer _ = c.libssh2_session_free(session);").?;
    const closes = std.mem.indexOf(u8, body, "errdefer _ = c.closesocket(socket);").?;
    try t.expect(frees < judged);
    try t.expect(closes < judged);

    // The trust root is consulted with the key that was *read*, not with one
    // built from anything else in scope, and the observation is published before
    // the refusal so the sentence can name the fingerprint that was rejected.
    const observed_at = std.mem.indexOf(u8, body, "observed.* = key;").?;
    try t.expect(observed_at < judged);
    try t.expect(std.mem.indexOf(u8, body, "presentedKey(session) orelse return error.HostKeyUnreadable") != null);
}

test "gate: trust-on-first-use is turned on in exactly one place" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // The one escape from "a pin must already exist" is the boolean on
    // `TrustRoot.Pins`, and every dial in the tree goes through
    // `PinLookup.trustRoot`, which takes it as its only argument. So the whole
    // of "first use is never implied" is these two counts: one site asks for
    // it — `observeHostKey`, which is what `server pin --trust-on-first-use`
    // calls — and one site refuses it, which is every other connection.
    const cli = try codeOnly(arena, @embedFile("cli.zig"));
    try t.expectEqual(@as(usize, 1), occurrences(cli, "trustRoot(true)"));
    try t.expectEqual(@as(usize, 1), occurrences(cli, "trustRoot(false)"));

    // And nothing sets the field directly, going around the pair above.
    try t.expectEqual(@as(usize, 0), occurrences(cli, ".trust_on_first_use = true"));
    const server = try codeOnly(arena, @embedFile("../core/daemon/Server.zig"));
    try t.expectEqual(@as(usize, 0), occurrences(server, "trust_on_first_use"));
}

// --- what the operator is told ------------------------------------------------

test "gate: a refused connection names the command that records the pin" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const key = presented("ssh-ed25519", "the host's real key");
    const facts: Cli.HostKeyRefusal = .{
        .server = "prod-web",
        .host = "10.0.0.1",
        .port = 22,
        .observed = key,
        .recorded = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    };

    // (1) The transition sentence. Every existing store has no pins, so this is
    //     what the first command after this build prints, and it has to be the
    //     sentence that gets somebody moving: the command, this server's own
    //     name, and both ways of recording a pin named as the two different
    //     things they are.
    const not_pinned = (try Cli.hostKeyRefusalText(arena, error.HostKeyNotPinned, facts)).?;
    for ([_][]const u8{
        "terminus server pin prod-web",
        "--trust-on-first-use",
        "--key-type ssh-ed25519",
        "--fingerprint",
        "ssh-keyscan",
        "10.0.0.1",
    }) |needle| {
        if (std.mem.indexOf(u8, not_pinned, needle) == null) {
            std.debug.print(
                \\
                \\the refusal for an unpinned host does not contain `{s}`. It read:
                \\
                \\{s}
                \\
            , .{ needle, not_pinned });
            return error.RefusalDoesNotNameTheWayOut;
        }
    }
    // It shows what was presented, as information...
    try t.expect(std.mem.indexOf(u8, not_pinned, key.text()) != null);
    // ...and never as the value to paste after `--fingerprint`. Pasting back
    // the key we were just handed is trust-on-first-use wearing the other
    // flag's clothes, and it would land in the ledger as `explicit_pin` — a row
    // claiming somebody checked something nobody checked.
    try t.expect(std.mem.indexOf(u8, not_pinned, "--fingerprint SHA256:") == null);

    // (2) The mismatch. It names both fingerprints, refuses to decide, and the
    //     command it offers is the rotation — with a placeholder, for the same
    //     reason as above.
    const mismatch = (try Cli.hostKeyRefusalText(arena, error.HostKeyMismatch, facts)).?;
    for ([_][]const u8{
        "terminus server pin prod-web --rotate",
        "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "ssh-keyscan",
        "nothing was sent",
    }) |needle| {
        if (std.mem.indexOf(u8, mismatch, needle) == null) {
            std.debug.print("\nthe mismatch refusal does not contain `{s}`. It read:\n\n{s}\n", .{ needle, mismatch });
            return error.MismatchRefusalIsIncomplete;
        }
    }
    try t.expect(std.mem.indexOf(u8, mismatch, key.text()) != null);
    try t.expect(std.mem.indexOf(u8, mismatch, "--fingerprint SHA256:") == null);

    // (3) A store that could not be read is not a missing pin, and must not be
    //     answered with "record one" — the operator would record a pin they
    //     already have and be refused again.
    var broken = facts;
    broken.store_error = "DatabaseBusy";
    const unreadable = (try Cli.hostKeyRefusalText(arena, error.HostKeyNotPinned, broken)).?;
    try t.expect(std.mem.indexOf(u8, unreadable, "DatabaseBusy") != null);
    try t.expect(std.mem.indexOf(u8, unreadable, "terminus server pin") == null);

    // (4) The other two host key errors have sentences too, so no refusal
    //      reaches an operator as a bare error name.
    try t.expect((try Cli.hostKeyRefusalText(arena, error.HostKeyUnreadable, facts)) != null);
    try t.expect((try Cli.hostKeyRefusalText(arena, error.NoTrustRoot, facts)) != null);

    // (5) And it answers null for everything that is not about the host key, so
    //     `sshOpen` keeps its own reachability wording — a mismatch reported as
    //     "could not reach" would send somebody to look at the network.
    try t.expect((try Cli.hostKeyRefusalText(arena, error.ConnectFailed, facts)) == null);
    try t.expect((try Cli.hostKeyRefusalText(arena, error.HandshakeFailed, facts)) == null);
}

test "gate: a fingerprint is the text ssh-keyscan prints, and nothing else is stored" {
    const t = std.testing;

    var sha: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("terminus", &sha, .{});
    var buffer: [Ssh.fingerprint_text_len]u8 = undefined;
    Ssh.formatFingerprint(&buffer, sha);

    try t.expect(std.mem.startsWith(u8, &buffer, "SHA256:"));
    // OpenSSH prints unpadded base64; a trailing '=' would not match anything
    // an operator can read off `ssh-keyscan`.
    try t.expect(std.mem.indexOfScalar(u8, &buffer, '=') == null);
    try t.expectEqual(@as(usize, "SHA256:".len + 43), buffer.len);
    // What this build writes is what this build will accept back.
    try t.expect(Ssh.isCanonicalFingerprint(&buffer));

    // The shapes an operator plausibly pastes, and every one of them refused at
    // the point of entry rather than stored. Stored, each would refuse every
    // connection to the host for ever and report a key mismatch while doing it.
    var rejected: usize = 0;
    for ([_][]const u8{
        "", // nothing
        "SHA256:", // the prefix alone
        "MD5:ab:cd:ef", // the old fingerprint format
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // a bare hex digest
        "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", // padded base64
        "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuF", // one character short
        "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFUU", // one too long
        "sha256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU", // wrong case in the prefix
        "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuF!", // not a base64 character
    }) |bad| {
        rejected += 1;
        if (Ssh.isCanonicalFingerprint(bad)) {
            std.debug.print("\n`{s}` was accepted as a fingerprint and can never match one\n", .{bad});
            return error.UnmatchableFingerprintAccepted;
        }
    }
    try t.expectEqual(@as(usize, 9), rejected);

    // Every key type this build can name round-trips to a stable string, since
    // that string is a third of a pin's primary key. An unnamed type is refused
    // rather than pinned under a number.
    var named: usize = 0;
    for ([_][]const u8{
        "ssh-rsa",             "ssh-dss",             "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-ed25519",
    }) |expected| {
        named += 1;
        try t.expectEqualStrings(expected, Ssh.keyTypeName(@intCast(named)).?);
    }
    try t.expectEqual(@as(usize, 6), named);
    try t.expect(Ssh.keyTypeName(0) == null);
    try t.expect(Ssh.keyTypeName(7) == null);
}
