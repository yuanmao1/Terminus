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
//! so this is where it lives.
//!
//! **Why a module, and not one of the two cheaper homes.** Renaming the
//! `Authority` that `cmd_job.zig` already defined and leaving the barrier there
//! is no module move at all — and it is the shape that produced the second copy,
//! because `cmd_session.zig` cannot reach into a sibling command. Lifting the
//! *type* alone into `src/core/` would let both verbs hold one value, and still
//! leaves every call site writing out its own renew/check/act sequence. A module
//! under `src/core/` that owns the whole barrier is the largest of the three and
//! the only one that makes the duplication impossible rather than merely
//! discouraged. That is a module boundary, so it was the programmer's call.
//!
//! **Only the renewal half is owned here.** The act itself is not: each verb
//! still writes its own renew/kill/consume sequence inline, and `run`'s cleanup
//! still kills with no claim at all. A `stopSession(authority, incarnation)`
//! primitive that all four call sites shared would finish the job; it does not
//! exist yet, and nothing here pretends otherwise.
//!
//! **What is shared here is the machinery and, since the wordings were
//! reconciled, the words as well.** Every sentence the two verbs print names
//! *the scope for* the subject rather than the subject itself, because for
//! `session rm` those are not the same string — see `Subject`.
//! Nothing here decides *when* a verb renews: that is the call site's business,
//! and `renewalsAreAdjacent` is what holds it to it.
const std = @import("std");
const Store = @import("store/Store.zig");
const execution = @import("execution.zig");

/// The thing a claim is over, and the noun its diagnostics use for it.
///
/// One tag per verb family, because the noun differs — `job kill` is about a
/// job, `session rm` about a session — and nothing else about the sentences
/// does. Every one of them names *the scope for* the subject rather than the
/// subject itself.
///
/// That is truthfulness rather than tidiness. `session rm`'s contention key is
/// *derived*: `contentionScope` maps a session named `job-deploy` onto the
/// scope `.job:deploy`, so a message that says "session 'job-deploy'" can name
/// a different string from the one actually locked. Naming the scope is
/// accurate for both verbs; naming the subject is accurate for jobs by
/// coincidence. The two families used to word this differently — "job
/// 'deploy'" against "the scope for session 'web'", and `session rm` was not
/// even consistent with itself across its three sentences — and this file
/// preserved both verbatim until the choice was made. This is that choice.
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
    /// Prose: nothing branches on it, which is what `code` is for. Both
    /// subjects word it the same way apart from the noun, and both name the
    /// scope rather than the thing that was typed — see `Subject`.
    pub fn note(a: Authority, arena: std.mem.Allocator, subject: Subject) ?[]const u8 {
        return switch (a) {
            .held => null,
            .lapsed => switch (subject) {
                .job => |n| std.fmt.allocPrint(
                    arena,
                    "this command's lease on the scope for job '{s}' is no longer held — it lapsed, or another session took it over while the host was being contacted",
                    .{n},
                ) catch "this command's lease on this job's scope is no longer held",
                .session => |n| std.fmt.allocPrint(
                    arena,
                    "this command's lease on the scope for session '{s}' is no longer held — it lapsed, or another session took it over while the host was being contacted",
                    .{n},
                ) catch "this command's lease on this session's scope is no longer held",
            },
            .unreadable => |err_name| switch (subject) {
                .job => |n| std.fmt.allocPrint(
                    arena,
                    "this command's lease on the scope for job '{s}' could not be renewed ({s}), so whether the scope is still ours could not be established",
                    .{ n, err_name },
                ) catch "this command's lease on this job's scope could not be renewed",
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
                "terminus: could not renew the lease on the scope for job '{s}': {s}; " ++
                    "this command will not take any step that changes the host or the local record\n",
                .{ n, @errorName(err) },
            ),
            .session => |n| std.debug.print(
                "terminus: could not renew the lease on the scope for session '{s}': {s}; " ++
                    "this command will not take any step that changes the host or the local record\n",
                .{ n, @errorName(err) },
            ),
        }
        return .{ .unreadable = @errorName(err) };
    };
    if (still_ours) return .held;
    switch (claim.subject) {
        .job => |n| std.debug.print(
            "terminus: this command's lease on the scope for job '{s}' is no longer held — it lapsed or was " ++
                "taken over while the host was being contacted, so another session may be acting on the same scope\n",
            .{n},
        ),
        .session => |n| std.debug.print(
            "terminus: this command's lease on the scope for session '{s}' is no longer held — it lapsed or was " ++
                "taken over while the host was being contacted, so another session may be acting on the same scope\n",
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
// the drift this file exists to remove. So is the vocabulary of destructive
// calls it scans for. What stays with each verb is what only that verb knows —
// which of its functions hold a claim, and how many such sites it has — so each
// caller keeps its own gate, its own asserted count, and its own name in a
// failure report.
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

/// The calls that change a host, spelled as they are written.
///
/// One list, for every verb that holds a claim. There used to be two: this one,
/// which lived in `cmd_job.zig`, and a copy in `cmd_session.zig` without
/// `Tmux.removeResult(` — kept apart on the grounds that merging them would
/// silently widen what the session gate covered. Widening it is the point:
/// `removeSession` makes no `Tmux.removeResult(` call today, so one list
/// changes neither asserted count, and the day that verb grows one the rule is
/// already holding it. A vocabulary each file keeps privately is the drift this
/// file exists to remove.
pub const destructive_remote_calls = [_][]const u8{
    "Tmux.killSession(",
    "Tmux.removeLog(",
    "Tmux.removeResult(",
};

/// Checks that every `destructive_remote_calls` call in `bodies` is preceded,
/// with nothing but comments in between, by a `stillOurs(...)` renewal — and
/// returns how many such calls it saw.
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
            const destructive = for (destructive_remote_calls) |call| {
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

// --- The other dangerous call: the one that writes the terminal -------------
//
// `renewalsAreAdjacent` covers the calls that change the *host*. It does not
// cover the call that changes the *ledger*, and that was the gap: the renewal
// standing between a lost scope and a terminal is spelled
// `_ = stillOurs(claim, ctx.io, &authority);` — a discard, three tokens of
// visible effect, the easiest line in a 680-line function to read as a no-op and
// delete. Deleting one left the suite green. The command then chooses its
// terminal from a stale `authority` and publishes `authority: held` on a branch
// where the scope was already gone.
//
// The rule is not adjacency. A terminal is not one call, it is a derivation —
// load the attempt, read the last observed status, decide what the evidence
// proves — and code between the renewal and the write is normal. What may not
// sit in that gap is a *round trip*. A renewal answers about the moment it was
// taken; local statements do not move that moment, and a call to the host does.
// So: a renewal must have happened, and nothing since it may have gone to the
// host.
//
// Two kinds of terminal write, and only one needs the rule
// --------------------------------------------------------
// `settleObserved(` writes the terminal from `authority` alone. Nothing re-asks
// the store, so the text is the only thing that can say the answer was fresh.
//
// `settleAndForgetJob(` and `settleAndRemoveSession(` go through
// `execution.commitDestruction`, which re-reads the acting party's own claim
// *inside* the transaction that writes the terminal. That is strictly stronger
// than any textual rule — there is no gap left to police, because the question
// and the write are one commit. `removeSession` is why this distinction has to
// be stated rather than assumed: it renews, then makes a `Tmux.removeLog(`
// round trip, then settles. Under a single rule that is a violation; it is in
// fact the safest of the eight sites, and a rule that cannot tell the two apart
// would have to be weakened for all of them.
//
// So both are counted and each caller asserts both. The counts are the load
// bearing part, not the pass: a verb that swapped `settleAndRemoveSession(` for
// a bare `settleObserved(` would still satisfy the adjacency rule, and the pair
// moving from `(0, 1)` to `(1, 0)` is what says the in-transaction re-read was
// dropped. Downgrading from the contract to a bare settle is the change this
// gate exists to make unwritable.

/// A call that goes to the host, spelled as it is written.
///
/// A superset of `destructive_remote_calls` — every call in that list is one of
/// these — because this rule is about elapsed time rather than about damage. A
/// probe changes nothing and is just as good a window for a peer's `--force` to
/// land in.
pub const remote_round_trips = [_][]const u8{
    "Tmux.killSession(",
    "Tmux.removeLog(",
    "Tmux.removeResult(",
    "Tmux.probeTail(",
    "Tmux.isAlive(",
    "Tmux.readLog(",
    "finalProbe(",
};

/// Terminal writes that take the ledger's word from `authority` and nothing else.
pub const bare_terminal_writes = [_][]const u8{"settleObserved("};

/// Terminal writes that re-read the claim inside their own transaction.
///
/// Listed so they can be *counted*, not so they can be checked: what protects
/// them is `commitDestruction`, and no arrangement of text could add to it.
pub const contract_backed_terminal_writes = [_][]const u8{
    "settleAndForgetJob(",
    "settleAndRemoveSession(",
};

/// How each body settled: how many terminals it wrote on its own authority, and
/// how many it wrote through the claim-backed contract.
pub const LedgerWrites = struct { bare: usize, contract_backed: usize };

/// Every top-level function in `source` whose body renews a claim, as the
/// `\nfn name(` headers `bodyOf` takes.
///
/// Derived rather than declared, because the hand-written lists diverged. Both
/// rules in this file need "which functions hold a claim", and `cmd_job.zig`
/// answered it twice: `claim_reporting_bodies` named seven — including
/// `reportFinishedDuringKill` — and `claim_holding_bodies` named two, leaving
/// that function's renewal and its `settleObserved` unscanned by the renewal
/// rules while the release rule covered it. Neither list was wrong about its own
/// question; the drift is that the answer was written down twice.
///
/// A function that renews is holding a claim — that is what renewing is — so the
/// membership is a property of the text and is read off it. Callers still assert
/// the count, because a scan that finds nothing must fail rather than pass over
/// an empty region.
///
/// Comment lines are stripped before the search: a paragraph that explains
/// `stillOurs` is not a renewal, and this file's own prose is full of them.
pub fn claimHoldingBodies(
    source: []const u8,
    out: [][]const u8,
) error{ FunctionUnterminated, TooManyClaimHoldingBodies }![]const []const u8 {
    var count: usize = 0;
    for ([_][]const u8{ "\nfn ", "\npub fn " }) |opener| {
        var from: usize = 0;
        while (std.mem.indexOfPos(u8, source, from, opener)) |at| {
            from = at + 1;
            const paren = std.mem.indexOfPos(u8, source, at, "(") orelse continue;
            const header = source[at .. paren + 1];
            // `\nfn ` is a prefix of nothing else, but `\npub fn ` bodies are
            // also found by neither — a header whose body has no `\n}\n` is a
            // scan that has stopped covering the function, and that is the one
            // thing this must not do quietly.
            const body = bodyOf(source, header) catch |err| switch (err) {
                error.FunctionMissing => continue,
                error.FunctionUnterminated => return error.FunctionUnterminated,
            };
            var lines = std.mem.splitScalar(u8, body, '\n');
            const renews = while (lines.next()) |raw| {
                const line = std.mem.trim(u8, raw, " \t\r");
                if (std.mem.startsWith(u8, line, "//")) continue;
                if (std.mem.indexOf(u8, line, "stillOurs(") != null) break true;
            } else false;
            if (!renews) continue;
            if (count == out.len) return error.TooManyClaimHoldingBodies;
            out[count] = header;
            count += 1;
        }
    }
    return out[0..count];
}

/// Checks that every `bare_terminal_writes` call in `bodies` follows a
/// `stillOurs(...)` renewal with no `remote_round_trips` call in between — and
/// returns how many writes of each kind it saw.
///
/// Both counts are returned rather than asserted here for the reason
/// `renewalsAreAdjacent` returns its one: a scan over a renamed function walks
/// an empty region and reports success. A caller with no bare writes at all —
/// `cmd_session.zig` is one — has nothing else to prove it looked, which is
/// exactly when the contract-backed count is doing the work.
pub fn renewalsPrecedeTerminalWrites(
    file: []const u8,
    source: []const u8,
    bodies: []const []const u8,
) error{
    FunctionMissing,
    FunctionUnterminated,
    TerminalWrittenWithoutARenewal,
    TerminalWrittenAfterARoundTrip,
}!LedgerWrites {
    var seen: LedgerWrites = .{ .bare = 0, .contract_backed = 0 };
    for (bodies) |header| {
        const body = try bodyOf(source, header);
        var lines = std.mem.splitScalar(u8, body, '\n');
        var renewed_at: ?usize = null;
        // The first round trip since that renewal, kept with its line so the
        // failure can name the call that opened the gap rather than just
        // asserting one exists.
        var trip: ?struct { number: usize, call: []const u8 } = null;
        var number: usize = 0;
        while (lines.next()) |raw| {
            number += 1;
            const line = std.mem.trim(u8, raw, " \t\r");
            // Prose that spells a call is not a call. Skipped before any of the
            // three questions below, so the paragraphs that explain each site
            // cannot trip the rule they explain.
            if (line.len == 0 or std.mem.startsWith(u8, line, "//")) continue;

            if (std.mem.indexOf(u8, line, "stillOurs(") != null) {
                renewed_at = number;
                trip = null;
            }

            for (contract_backed_terminal_writes) |write| {
                if (std.mem.indexOf(u8, line, write) != null) {
                    seen.contract_backed += 1;
                    break;
                }
            }

            for (bare_terminal_writes) |write| {
                if (std.mem.indexOf(u8, line, write) == null) continue;
                seen.bare += 1;
                const renewal = renewed_at orelse {
                    std.debug.print(
                        \\
                        \\{s}: a terminal is written on an authority this body never renewed.
                        \\
                        \\  in:            {s}
                        \\  line {d} of it: {s}
                        \\
                        \\`{s}` writes the terminal from `authority` and re-asks nothing. A body
                        \\that holds a claim must renew before it settles, because the renewal is
                        \\what decides which terminal this command is entitled to write — and a
                        \\command that lost the scope is not entitled to record a cancellation of
                        \\work it no longer speaks for.
                        \\
                    , .{ file, header[1..], number, line, write });
                    return error.TerminalWrittenWithoutARenewal;
                };
                if (trip) |made| {
                    std.debug.print(
                        \\
                        \\{s}: a terminal is written on a renewal that a round trip has outlived.
                        \\
                        \\  in:              {s}
                        \\  renewed on line: {d}
                        \\  round trip on:   {d}  ({s})
                        \\  settled on line: {d}  {s}
                        \\
                        \\`{s}` takes the ledger's word from `authority`, so the renewal above it is
                        \\the whole of what says the scope was still ours. A call to the host in
                        \\between is time a peer's `--force` can land in, and the terminal that
                        \\follows would be written on an answer that has since stopped being true.
                        \\
                        \\Renew again after the round trip, or settle through
                        \\`execution.commitDestruction` — it re-reads the claim inside the
                        \\transaction that writes the terminal, which closes the gap rather than
                        \\shortening it.
                        \\
                    , .{ file, header[1..], renewal, made.number, made.call, number, line, write });
                    return error.TerminalWrittenAfterARoundTrip;
                }
                break;
            }

            if (trip == null) {
                for (remote_round_trips) |call| {
                    if (std.mem.indexOf(u8, line, call) != null) {
                        trip = .{ .number = number, .call = call };
                        break;
                    }
                }
            }
        }
    }
    return seen;
}

// Compile-checks every declaration in *this* module.
//
// Nothing here is exercised by a test of its own: the behaviour is proved end to
// end (`test/blackbox.zig`) and by each caller's own adjacency gate
// (`cmd_job.zig`, `cmd_session.zig`), which reach this file only through the
// decls they alias. A decl nothing aliases is never analysed, so a future
// addition here — a third `Subject` arm's `note` sentence, a helper added ahead
// of its call site — could stop compiling and no test would say so. This
// references them all, which is the whole of what it claims to do: it does not
// assert behaviour and it does not run anything.
//
// `refAllDecls`, not a recursive variant: this Zig standard library has no
// `refAllDeclsRecursive` (`std/testing.zig` defines `refAllDecls` only), and a
// single level is the gap that matters here — the modules this file imports have
// their own tests.
test "every decl in this module is compile-checked" {
    std.testing.refAllDecls(@This());
}
