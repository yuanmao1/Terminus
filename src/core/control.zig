//! The lease-renewal barrier, owned once.
//!
//! A destructive remote verb takes a scope lease before it dials, renews that
//! lease immediately before every step that changes the host or the local
//! record, and reads the renewal's *answer* — a step taken after a renewal
//! said "not ours" is a step taken on somebody else's session.
//!
//! That machinery was written for `job kill` / `job rm` (`1f42477`) and then
//! written a second time, privately, for `session rm` (`d3bef52`): two
//! `Claim`s, two `Authority`s, two `holdClaim`s, two `stillOurs`s, two clock
//! readers, two source-scanning adjacency gates. Two copies of a barrier is
//! the shape that drifts, and the drift is invisible — a fix applied to one
//! copy and not the other shows up as a lost scope, which is the failure the
//! barrier exists to prevent. `job kill`, `job rm`, `session new`, `run`'s
//! stale cleanup and `write --force` are all queued to need the same thing,
//! so this is where it lives (`docs/m3b-job-control.md` §2.3, §7.6).
//!
//! **What is shared here is the machinery, not the words.** The two verbs that
//! use it today say different things in their diagnostics, and this file
//! preserves both wordings verbatim rather than picking one — see `Subject`.
//! Nothing here decides *when* a verb renews: that is the call site's business,
//! and `renewalsAreAdjacent` is what holds it to it.
const std = @import("std");
const Store = @import("store/Store.zig");
const execution = @import("execution.zig");

/// The thing a claim is over, and the noun its diagnostics use for it.
///
/// One tag per verb family, because the two families word the same fact
/// differently and always have: `job kill` says "job 'deploy'", `session rm`
/// says "the scope for session 'web'" in some sentences and "session 'web'" in
/// others, and their fallback prose differs again. Those texts reach an
/// operator — `authorityError` in JSON, stderr in the log — so this extraction
/// keeps them byte for byte instead of unifying them. Which of the two
/// wordings a third verb should adopt, or whether they should converge at all,
/// is a decision for the programmer and not for a refactor.
///
/// Prose only. `Authority.code` is the machine-readable value, and nothing
/// branches on which tag this is except the sentences below.
pub const Subject = union(enum) {
    job: []const u8,
    session: []const u8,

    /// The bare name, for callers that need it without the noun.
    pub fn name(s: Subject) []const u8 {
        return switch (s) {
            .job, .session => |n| n,
        };
    }
};

/// The scope lease a destructive verb holds from before its first remote call
/// until the last thing it changes is changed.
///
/// Ownership is a `request_id` minted per invocation, never the machine's
/// profile token: two commands on one machine are two owners, and the token is
/// an audit subject that decides nothing. `job kill`'s `--force` is an audited
/// `takeover` that displaces the incumbent and records it; `session rm` has no
/// override at all. Both hold the claim across every step and release it at
/// settle, from `Cli.releaseClaim` on every process-ending path, or by TTL if
/// the process is killed outright.
pub const Claim = struct {
    store: *Store,
    server_id: i64,
    scope: execution.Scope,
    /// This invocation's identity. Not the thing being acted on: `job kill`
    /// acts *on* somebody else's attempt, and holding the lease under that id
    /// would make two concurrent kills renew each other — the defect one level
    /// down.
    owner_request_id: []const u8,
    subject: Subject,

    /// Long enough that probe → kill → settle (`job kill`) and kill → log →
    /// settle (`session rm`) never renew in practice, short enough that a
    /// hard-killed command does not lock the operator out of its own job or
    /// session for long. A claim that outlives its holder is released by
    /// lapsing, which is the only thing a dead process can do.
    pub const ttl_secs: i64 = 120;

    /// What a peer's live claim did to this command.
    ///
    /// `job kill` / `job rm` consume all three. `session rm` refuses inline and
    /// never builds one, because it has no `--force` to seize with.
    pub const Outcome = union(enum) {
        held: Claim,
        /// Somebody else holds an overlapping scope. Nothing remote has been
        /// touched, because this runs before the connection is opened.
        blocked: Store.leases.Lease,
        /// `--force`: the incumbents were displaced and each one's row records
        /// it — `release_reason = 'takeover'` and `superseded_by` pointing at
        /// this claim.
        seized: struct { claim: Claim, displaced: []const Store.leases.Lease },
    };
};

/// Whether a command still holds the scope it took before it reached the host.
///
/// Three answers and not a bool, because the two failures are different facts
/// and the report says which one it got. `lapsed` is an answer — the row is not
/// ours, so another session may be acting on this name right now. `unreadable`
/// is the absence of one: the store could not be asked, so the question stands
/// open. Neither is `held`, and that is the whole of the rule every destructive
/// step runs under: **a question we could not ask is not a yes.**
pub const Authority = union(enum) {
    held,
    /// `leases.renew` matched no row: the lease lapsed, or a peer displaced it
    /// (`job kill --force` is the only thing that can, today).
    lapsed,
    /// `leases.renew` could not be performed. Carries `@errorName`, which is
    /// diagnostic prose and not something a caller may branch on — `code` is.
    unreadable: []const u8,

    /// The `error_code` a settlement written after the authority was lost
    /// carries, inside the ordinary `indeterminate` terminal.
    ///
    /// Not a terminal of its own. `op_state.Terminal` already has the variant
    /// for "we cannot establish the remote outcome", and that is exactly what
    /// this is: the kill went out, and whether anything else has since acted on
    /// the same name is precisely what we no longer know. The code is what lets
    /// a reader tell this cause apart from the others in the receipt.
    pub const lost_code = "AUTHORITY_LOST";

    pub fn holds(a: Authority) bool {
        return switch (a) {
            .held => true,
            .lapsed, .unreadable => false,
        };
    }

    /// The machine-readable value, present on every branch of every verb that
    /// holds a claim.
    pub fn code(a: Authority) []const u8 {
        return switch (a) {
            .held => "held",
            .lapsed => "lapsed",
            .unreadable => "unreadable",
        };
    }

    /// The sentence beside it, or null while the claim is still ours.
    ///
    /// Prose: nothing branches on it, which is what `code` is for. The two
    /// subjects word it differently and each wording is the one that verb
    /// shipped — see `Subject`.
    pub fn note(a: Authority, arena: std.mem.Allocator, subject: Subject) ?[]const u8 {
        return switch (a) {
            .held => null,
            .lapsed => switch (subject) {
                .job => |n| std.fmt.allocPrint(
                    arena,
                    "this command's lease on job '{s}' is no longer held — it lapsed, or another session took it over while the host was being contacted",
                    .{n},
                ) catch "this command's lease on this job is no longer held",
                .session => |n| std.fmt.allocPrint(
                    arena,
                    "this command's lease on the scope for session '{s}' is no longer held — it lapsed, or another session took it over while the host was being contacted",
                    .{n},
                ) catch "this command's lease on this session's scope is no longer held",
            },
            .unreadable => |err_name| switch (subject) {
                .job => |n| std.fmt.allocPrint(
                    arena,
                    "this command's lease on job '{s}' could not be renewed ({s}), so whether the scope is still ours could not be established",
                    .{ n, err_name },
                ) catch "this command's lease on this job could not be renewed",
                .session => |n| std.fmt.allocPrint(
                    arena,
                    "this command's lease on the scope for session '{s}' could not be renewed ({s}), so whether the scope is still ours could not be established",
                    .{ n, err_name },
                ) catch "this command's lease on this session's scope could not be renewed",
            },
        };
    }
};

/// Wall-clock seconds, as opposed to the `ctx.now` every other row a command
/// writes is stamped with — that one is read once at process start.
///
/// A lease is the one thing *compared* against a clock rather than merely
/// stamped with one: `expires_at` is what decides whether a peer may take the
/// scope, and `leases.renew` refuses a lease that has already lapsed. Renewing
/// with `ctx.now` would write back the expiry the acquisition already set, so a
/// command that outran its TTL would extend nothing while reporting that it had
/// — a call that always succeeds and never does anything.
///
/// Every writer of a lease row reads this, not just the renewal: the
/// acquisition and the takeover stamp from it too, and the release reads the
/// equivalent clock through the store. That is not tidiness — the ordering
/// guard in `leases.zig` compares those stamps against each other, so a single
/// writer left on the frozen `ctx.now` is a writer that can be refused by the
/// row it is writing.
pub fn wallClockSeconds(io: std.Io) i64 {
    const ts = std.Io.Timestamp.now(io, .real);
    return @intCast(@divTrunc(ts.nanoseconds, std.time.ns_per_s));
}

/// Keeps the claim alive across the remote work, and says whether it is still
/// ours.
///
/// The answer is the point. This used to return `void` and merely print on
/// loss, so every caller renewed and then went on to kill, delete and settle
/// exactly as if the renewal had succeeded — the layer that exists to stop two
/// sessions acting on one name could not stop anything, because nothing
/// consumed what it said. It is read by `stillOurs`, which is what each
/// destructive step is gated on.
///
/// The diagnostic stays: it names the subject on the way past, where a caller
/// that only reports the machine-readable `Authority.code` still leaves a line
/// in the log saying what it was about.
pub fn holdClaim(claim: Claim, now: i64) Authority {
    const still_ours = Store.leases.renew(
        claim.store,
        claim.server_id,
        claim.scope,
        claim.owner_request_id,
        Claim.ttl_secs,
        now,
    ) catch |err| {
        switch (claim.subject) {
            .job => |n| std.debug.print(
                "terminus: could not renew the scope lease for job '{s}': {s}; " ++
                    "this command will not take any step that changes the host or the local record\n",
                .{ n, @errorName(err) },
            ),
            .session => |n| std.debug.print(
                "terminus: could not renew the scope lease for session '{s}': {s}; " ++
                    "this command will not take any step that changes the host or the local record\n",
                .{ n, @errorName(err) },
            ),
        }
        return .{ .unreadable = @errorName(err) };
    };
    if (still_ours) return .held;
    switch (claim.subject) {
        .job => |n| std.debug.print(
            "terminus: this command's lease on job '{s}' is no longer held — it lapsed or was taken over " ++
                "while the host was being contacted, so another session may be acting on the same job\n",
            .{n},
        ),
        .session => |n| std.debug.print(
            "terminus: this command's lease on the scope for session '{s}' is no longer held — it lapsed or was " ++
                "taken over while the host was being contacted, so another session may be acting on the same name\n",
            .{n},
        ),
    }
    return .lapsed;
}

/// Renews the claim immediately before the next step, and says whether that
/// step may go ahead.
///
/// One renewal per step, not one per command. A single renewal at the top
/// covers the moment it ran and nothing after it: `job rm --discard-evidence`
/// sends four remote commands and can spend a minute doing it, and the lease it
/// checked before the first one says nothing about who owns the scope by the
/// fourth.
///
/// `authority` only ever moves one way. Once a renewal has answered that the
/// scope is not ours the steps after it are forbidden, so there is nothing left
/// to renew — and asking again would let a later answer overwrite the first
/// loss, which is the one the report is built from.
pub fn stillOurs(claim: Claim, io: std.Io, authority: *Authority) bool {
    if (!authority.holds()) return false;
    authority.* = holdClaim(claim, wallClockSeconds(io));
    return authority.holds();
}

// --- Adjacency, held against the source that has to have it -----------------
//
// "Renew before the step" is not a property of a function; it is a property of
// where the call sits. `stillOurs` cannot enforce it, and no type can: a
// renewal three statements and a store transaction above a `kill-session` type
// checks exactly as well as one on the line above it, and answers a different
// question. That was the defect — three branches renewed, settled, and then
// killed on an answer a whole transaction old, so a peer's `--force` landing
// inside the transaction left the command sending `kill-session` *by name* at a
// session the new holder may already own.
//
// The end-to-end gates cannot reach that window. A fake host's lease seizure is
// deterministic only while the binary is blocked on the socket, and between a
// renewal and the call it gates there is — by construction, and that is the
// point — no round trip to block on. So the adjacency is checked where it
// lives: in the text.
//
// The *scan* is here, once, because it was the duplicated part: two copies of a
// line walker, a comment-skipping look-back and a failure message is exactly
// the drift this file exists to remove. What stays with each verb is what only
// that verb knows — which of its functions hold a claim, which calls are
// destructive in it, and how many such sites it has — so each caller keeps its
// own gate, its own asserted count, and its own name in a failure report.
//
// This does not replace the traffic gates. They prove the refusal is real and
// reports honestly; this proves there is nothing between the question and the
// act.

/// A top-level function's text, from its `fn` line to the `}` in column zero
/// that closes it.
///
/// Textual and deliberately simple, with the fragility stated rather than
/// papered over: it ends the body at the first `\n}\n`, and on CRLF input it
/// finds none and fails with `FunctionUnterminated`. `.gitattributes` pins
/// every text file to LF, which is what keeps that from happening; loosening
/// the scan to tolerate CRLF would trade a loud failure for a scan that can
/// quietly stop covering half a function.
pub fn bodyOf(source: []const u8, header: []const u8) error{ FunctionMissing, FunctionUnterminated }![]const u8 {
    const start = std.mem.indexOf(u8, source, header) orelse return error.FunctionMissing;
    const rest = source[start + 1 ..];
    const end = std.mem.indexOf(u8, rest, "\n}\n") orelse return error.FunctionUnterminated;
    return rest[0 .. end + 1];
}

/// Checks that every destructive call in `bodies` is preceded, with nothing but
/// comments in between, by a `stillOurs(...)` renewal — and returns how many
/// such calls it saw.
///
/// The count is returned rather than asserted here so that each caller states
/// its own, next to the functions it is about. A scan that matched nothing
/// would otherwise report nothing at all, which is worse than having no gate:
/// a renamed function or a moved body delimiter would pass silently over an
/// empty region.
pub fn renewalsAreAdjacent(
    file: []const u8,
    source: []const u8,
    bodies: []const []const u8,
    calls: []const []const u8,
) error{ FunctionMissing, FunctionUnterminated, DestructiveCallIsNotAdjacentToItsRenewal }!usize {
    var found: usize = 0;
    for (bodies) |header| {
        const body = try bodyOf(source, header);
        var lines = std.mem.splitScalar(u8, body, '\n');
        // Every code line seen so far, so the check can look back past the
        // comments that explain each site — and only past those.
        var last_code: []const u8 = "";
        var number: usize = 0;
        while (lines.next()) |raw| {
            number += 1;
            const line = std.mem.trim(u8, raw, " \t\r");
            const destructive = for (calls) |call| {
                if (std.mem.indexOf(u8, line, call) != null) break call;
            } else null;
            if (destructive) |call| {
                found += 1;
                if (std.mem.indexOf(u8, last_code, "stillOurs(") == null) {
                    std.debug.print(
                        \\
                        \\{s}: a destructive remote call is not gated on a renewal
                        \\taken immediately before it.
                        \\
                        \\  in:               {s}
                        \\  line {d} of it:    {s}
                        \\  the code above it: {s}
                        \\
                        \\Every call that changes the host must be preceded — with nothing but
                        \\comments in between — by a `stillOurs(...)` gate, so that no store
                        \\transaction, probe or second round trip can sit between the question
                        \\"is the scope still ours" and the act it authorises. A renewal on the
                        \\far side of a settlement answers about a moment that has passed, and
                        \\the peer that took the lease in between now owns the session this
                        \\`{s}` names.
                        \\
                    , .{ file, header[1..], number, line, last_code, call });
                    return error.DestructiveCallIsNotAdjacentToItsRenewal;
                }
            }
            if (line.len == 0 or std.mem.startsWith(u8, line, "//")) continue;
            last_code = line;
        }
    }
    return found;
}
