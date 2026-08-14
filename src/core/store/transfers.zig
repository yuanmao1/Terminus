//! Resumable transfer checkpoints (`transfer_checkpoints`).
//!
//! A checkpoint records *what* was being transferred, not just *where* it got
//! to. That distinction is the whole point: a partial file identified only by
//! its destination path can silently become the head of a different source.
//! Before continuing, `verifyResume` insists that
//!
//! * the source still has the identity it had — for a file, the same size,
//!   mtime and content hash; for an HTTP object, the same strong validator —
//!   and
//! * the staging partial is exactly as long as the offset we last confirmed,
//!   and its prefix hashes to what we recorded.
//!
//! Anything else fails loudly rather than restarting from zero behind the
//! caller's back — a silent restart of a 9 GiB upload is not a kindness.
//!
//! Everything here is written in *roles*, not sides: `dest_*` is wherever the
//! artifact will be published and `partial_*` is the staging file next to it,
//! which is the host for a push and this machine for a pull or a fetch. The
//! v6 table called them `remote_*`, which was true of a push and an active lie
//! about everything else — and `remote_path NOT NULL` made a locally
//! published transfer impossible to record at all.
//!
//! Offsets only ever advance to a *confirmed* position. For parallel chunked
//! transfers that means the contiguous completed prefix, never the highest
//! finished chunk: chunks 5, 6 and 7 may finish while 4 is still in flight,
//! and resuming from 8 would leave a hole. (The idea is borrowed from
//! RingIO's `SlotMarks.contiguousEnd`; the authoritative record has to live
//! here in sqlite because an in-memory mark set dies with the process.)
const std = @import("std");
const Allocator = std.mem.Allocator;
const Store = @import("Store.zig");
const Db = @import("Db.zig");
// Imported for its status vocabulary only, and only at comptime: three
// statements here constrain `operations.status`, and rendering those lists from
// the module that owns the enum is what keeps them from being three hand-typed
// copies. The dependency is one-way and cannot close a loop — `op_state`
// imports nothing but `std`.
const op_state = @import("op_state.zig");

pub const schema_version: i64 = 1;

pub const Direction = enum {
    push,
    pull,
    fetch,

    pub fn parse(raw: []const u8) error{UnknownDirection}!Direction {
        return std.meta.stringToEnum(Direction, raw) orelse error.UnknownDirection;
    }
};

pub const State = enum {
    planned,
    probing,
    transferring,
    /// Interrupted but resumable: the checkpoint is trustworthy.
    paused,
    verifying,
    publishing,
    published,
    /// Bytes arrived and matched their length, but no trustworthy hash or
    /// object validator was available to prove they are the right bytes.
    /// Deliberately not `published`: size alone is not verification.
    completed_unverified,
    failed_source_changed,
    failed_remote_partial_mismatch,
    failed_hash_mismatch,
    failed_no_space,
    failed_clobber_conflict,
    failed_publish,
    /// The rename may or may not have happened. Never report this as failed.
    indeterminate_publish,
    /// An operator decided this attempt is over and released its destination.
    ///
    /// The one way out of the hold every settled-but-unpublished state keeps —
    /// see `holdsDestination`. Written only by `supersedeLocked`, and only over
    /// a `failed_*` state; the row, its partial and its digests all stay
    /// exactly as they were, because the point is to stop claiming the path,
    /// not to forget what happened on it.
    superseded,

    pub fn parse(raw: []const u8) error{UnknownTransferState}!State {
        return std.meta.stringToEnum(State, raw) orelse error.UnknownTransferState;
    }

    pub fn text(s: State) []const u8 {
        return @tagName(s);
    }

    /// Whether a checkpoint in this state still occupies its destination path.
    ///
    /// This is the predicate behind `idx_checkpoints_live_dest`, which is the
    /// only collision guard a locally-published transfer gets: `unsettledInScope`
    /// filters by `server_id`, so two pulls from different servers into one
    /// local path both clear the scope barrier, and a fetch has no server at
    /// all.
    ///
    /// Everything holds except `published` and `completed_unverified`. Those two
    /// are the only states in which the path stopped being a *claim* and became
    /// the artifact: the transfer put what it came to put there, and the next
    /// transfer aimed at that path is an ordinary overwrite, not a collision
    /// with somebody's unfinished work.
    ///
    /// Every failure holds, and keeps holding until something explicitly
    /// supersedes it. A failed run leaves a partial next to the destination and
    /// a half-told story about what is at it, and the next `create` walking
    /// straight into that is precisely what an operator has to be given the
    /// chance to refuse — with `--restart`, which reaches `supersedeLocked`.
    /// Releasing on failure made that requirement a thing the documentation
    /// asked for and nothing enforced.
    ///
    /// A failure during `probing` — before a byte reached the destination —
    /// holds too, and that is deliberate rather than an oversight. The rule is
    /// about what an operator must acknowledge, not about which bytes exist:
    /// nothing here can tell whether a `failed_no_space` at probe time left a
    /// zero-length partial, and a rule with per-failure exceptions is one
    /// nobody can state, predict, or check against the index that enforces it.
    ///
    /// `indeterminate_publish` holds for a different reason worth keeping
    /// separate: there the rename may already have landed, so the path may
    /// already hold an artifact awaiting adjudication, and handing it to a rival
    /// would let the rival overwrite a result nobody has judged yet. That wait
    /// ends at `adjudicateLocked`, which is the only writer of the four edges
    /// out.
    ///
    /// Exhaustive with no `else`, so a new variant has to be classified rather
    /// than defaulting into whichever answer the author happened to write last.
    pub fn holdsDestination(s: State) bool {
        return switch (s) {
            .planned,
            .probing,
            .transferring,
            .paused,
            .verifying,
            .publishing,
            .failed_source_changed,
            .failed_remote_partial_mismatch,
            .failed_hash_mismatch,
            .failed_no_space,
            .failed_clobber_conflict,
            .failed_publish,
            .indeterminate_publish,
            => true,
            .published,
            .completed_unverified,
            .superseded,
            => false,
        };
    }

    /// Whether this transfer's own record leaves room for its artifact to be at
    /// the destination.
    ///
    /// Asked by `receipts.resolve` of a `filesystem_effect` reading, which is
    /// the one piece of evidence that claims "the artifact this transfer
    /// promised is at the destination, hashing to what was declared" and
    /// resolves the operation `completed` on the strength of it.
    ///
    /// The digest comparison alone does not make that claim safe, and this is
    /// the hole it left: the comparison binds the reading to *this transfer's
    /// declaration*, and says nothing about whether this transfer ever got as
    /// far as putting anything there. A push that declared a digest, found the
    /// destination occupied by the previous delivery of the same artifact —
    /// which is the ordinary reason a re-push hits a clobber conflict — and was
    /// recorded `failed_clobber_conflict` before its connection dropped, would
    /// match a hash of that destination on all three halves. The operation
    /// resolved `completed`, the scope barrier lifted, and the receipt said the
    /// artifact had been delivered, beside a checkpoint saying the transfer
    /// never wrote a byte to it and still holding the path.
    ///
    /// The three admissible states are the three in which the transfer's own
    /// record says the rename either landed or may have landed, so a later
    /// reading of the destination corroborates rather than overrules:
    ///
    ///  * `published` — the driver watched the rename and hashed the result;
    ///    the operation went `indeterminate` only because the reply was lost;
    ///  * `completed_unverified` — the rename landed and nothing hashed it.
    ///    (In combination with `evidenceClause` such a row can never carry a
    ///    declared digest, so `expectedEffectLocked` returns null for it and the
    ///    reading is refused a step earlier. It is admitted here because of what
    ///    the state means, not because the pair is reachable.)
    ///  * `indeterminate_publish` — the rename was never observed. This is the
    ///    case that adjudicates.
    ///
    /// Every other state is an answer this reading must not re-decide: the live
    /// states say the transfer had not reached a rename, every `failed_*` says
    /// somebody recorded that it would not, and `superseded` says an operator
    /// released it. In all of them a matching hash at the destination is the
    /// hash of somebody else's artifact.
    ///
    /// Exhaustive with no `else`, so a new variant has to be classified rather
    /// than defaulting into whichever answer the author happened to write last.
    pub fn renameMayHaveLanded(s: State) bool {
        return switch (s) {
            .published,
            .completed_unverified,
            .indeterminate_publish,
            => true,
            .planned,
            .probing,
            .transferring,
            .paused,
            .verifying,
            .publishing,
            .failed_source_changed,
            .failed_remote_partial_mismatch,
            .failed_hash_mismatch,
            .failed_no_space,
            .failed_clobber_conflict,
            .failed_publish,
            .superseded,
            => false,
        };
    }

    /// Whether `supersedeLocked` may release this state's hold on its
    /// destination.
    ///
    /// The six failures, and nothing else. Each is a decision somebody already
    /// recorded — the attempt is over and it did not publish — so the only
    /// question left is whether its leftovers may be discarded, which is the
    /// question supersession answers.
    ///
    /// The four groups it excludes, and why each would be wrong:
    ///
    /// * The live states, `planned` through `publishing`. Nobody has decided
    ///   the attempt is over, and a process may still be appending to the
    ///   partial; releasing the path would hand it to a rival while the first
    ///   writer is still using it. Stopping a live transfer is a different
    ///   operation, and it has to happen before this one.
    /// * `indeterminate_publish`. Not settled — *unjudged*. Superseding it
    ///   would throw away the open question of whether the rename landed and
    ///   let a rival overwrite an artifact nobody has looked at.
    ///   `adjudicateLocked` is its way out, and it needs evidence. Note that
    ///   the way out may be `failed_hash_mismatch`, which *is* supersedable —
    ///   the sequence is not a loophole but the intended two-step: a reading
    ///   establishes that the wrong bytes are at the destination, and only then
    ///   is there a decided failure for an operator to release.
    /// * `published` and `completed_unverified`. They do not hold the
    ///   destination, so there is nothing to release, and overwriting either
    ///   with `superseded` would erase the record that an artifact was
    ///   published there.
    /// * `superseded` itself. Already released; a second supersession would
    ///   only overwrite the first one's provenance with a later request's.
    pub fn isSupersedable(s: State) bool {
        return switch (s) {
            .failed_source_changed,
            .failed_remote_partial_mismatch,
            .failed_hash_mismatch,
            .failed_no_space,
            .failed_clobber_conflict,
            .failed_publish,
            => true,
            .planned,
            .probing,
            .transferring,
            .paused,
            .verifying,
            .publishing,
            .published,
            .completed_unverified,
            .indeterminate_publish,
            .superseded,
            => false,
        };
    }

    /// Whether a new operation may take this checkpoint over and continue it.
    ///
    /// Strictly narrower than `holdsDestination`, and the gap is the point.
    /// `verifying` and `publishing` are past the last byte: there is no offset
    /// left to resume from, so adopting one would hand a new operation a
    /// complete partial and a state machine with nowhere useful to go. They
    /// still hold the destination, because a rival writing to that path would
    /// still collide. Occupying a path and being resumable are two different
    /// claims that happen to agree on four states today.
    ///
    /// `transferring` is in the set, and it is worth being clear about what
    /// that does and does not mean. It is here because a process killed
    /// mid-stream has no chance to park the row in `paused`, and a
    /// `transferring` row nobody may adopt is a checkpoint wedged against its
    /// own destination for good — the trap `verifying → paused` was added to
    /// avoid, in the state where it is likeliest. It is *not* a claim that
    /// nobody is writing: no row proves a process died. What stands between an
    /// heir and a live writer is the incumbent conjunct of the hand-over
    /// statement, and what that is worth is written out at `handoverSql`.
    pub fn isAdoptable(s: State) bool {
        return switch (s) {
            .planned, .probing, .transferring, .paused => true,
            .verifying,
            .publishing,
            .published,
            .completed_unverified,
            .failed_source_changed,
            .failed_remote_partial_mismatch,
            .failed_hash_mismatch,
            .failed_no_space,
            .failed_clobber_conflict,
            .failed_publish,
            .indeterminate_publish,
            .superseded,
            => false,
        };
    }

    /// Where a row left in this state belongs once its owner is gone, or null
    /// when nothing here was abandoned in the middle of an act.
    ///
    /// `verifying` and `publishing` are the two states only a running process
    /// can be in and only that process can leave: every edge out of them is a
    /// compare-and-swap keyed on the owning `request_id`, and a process killed
    /// mid-hash or mid-rename never writes anything again. Both hold their
    /// destination and neither is adoptable, so before this existed a crash
    /// inside either one left a row that could not move, could not be taken
    /// over, and went on refusing every later `create` aimed at that path. The
    /// `verifying` case had a nominal way out — `verifying → paused` — which
    /// only the dead owner could walk.
    ///
    /// Where each one goes is a claim about the world, not a convenience:
    ///
    /// * `verifying → paused`. Nothing was published: `publishing` is the only
    ///   edge onward and it was never taken. The partial is still beside the
    ///   destination and its confirmed offset is as durable as it ever was, so
    ///   `paused` — where a resumable transfer waits — says exactly what is
    ///   true.
    /// * `publishing → indeterminate_publish`. The rename was issued and its
    ///   outcome was never observed, which is that state's whole meaning. The
    ///   row then goes to `adjudicateLocked` like any other parked publish.
    ///   Normalising it to `paused` would assert the rename did *not* land, and
    ///   a resume acting on that assertion would overwrite an artifact that may
    ///   already be at the destination — the one outcome nobody here can rule
    ///   out.
    ///
    /// Both targets are ordinary edges of `predecessors`, walked by the ordinary
    /// transition statement on the ordinary route. Recovery gets no private edge
    /// and no private writer, so a normalisation cannot reach anywhere a driver
    /// could not.
    ///
    /// Exhaustive with no `else`, so a new state has to say whether an abandoned
    /// row in it can be normalised, and to what.
    pub fn abandonedNormalisation(s: State) ?State {
        return switch (s) {
            .verifying => .paused,
            .publishing => .indeterminate_publish,
            // Live, but not mid-act. Every one of these is already reachable by
            // an heir through `adoptLocked`, which moves ownership and changes
            // no state at all, because there is nothing here to normalise: the
            // row already describes a transfer that can be picked up where it
            // stands.
            .planned,
            .probing,
            .transferring,
            .paused,
            => null,
            // Settled, unjudged, or released. Nothing was interrupted — the row
            // already records what became of the transfer, and rewriting that
            // because its owner is gone would be inventing a second verdict out
            // of the fact that nobody is watching. `indeterminate_publish` in
            // particular is not stuck: `adjudicateLocked` is its way out and it
            // needs evidence, which recovery does not have.
            .published,
            .completed_unverified,
            .failed_source_changed,
            .failed_remote_partial_mismatch,
            .failed_hash_mismatch,
            .failed_no_space,
            .failed_clobber_conflict,
            .failed_publish,
            .indeterminate_publish,
            .superseded,
            => null,
        };
    }

    /// Whether an abandoned row in this state can be recovered.
    ///
    /// The domain of `abandonedNormalisation`, as a predicate, so the SQL guard
    /// on the hand-over and the mapping that follows it cannot come apart: a
    /// state the statement admits but the mapping cannot place would take a
    /// checkpoint away from its owner and then have nowhere to put it.
    pub fn isRecoverable(s: State) bool {
        return s.abandonedNormalisation() != null;
    }

    /// Whether `confirmOffset` may write progress into this state.
    ///
    /// The same four states, for a third reason: an offset is a claim that the
    /// bytes below it are on disk and provable, and only a transfer that is
    /// still sending bytes can make it. Advancing a `verifying` row would move
    /// the goalposts under the digest being checked, and advancing a settled
    /// one would make it look resumable again.
    pub fn acceptsOffset(s: State) bool {
        return switch (s) {
            .planned, .probing, .transferring, .paused => true,
            .verifying,
            .publishing,
            .published,
            .completed_unverified,
            .failed_source_changed,
            .failed_remote_partial_mismatch,
            .failed_hash_mismatch,
            .failed_no_space,
            .failed_clobber_conflict,
            .failed_publish,
            .indeterminate_publish,
            .superseded,
            => false,
        };
    }

    /// Whether the transfer has yet to put a byte on the wire.
    ///
    /// The narrowest window, and one predicate for two writers because they
    /// enforce a single rule: a commitment made *in advance* has to be made
    /// before the thing it commits about happens.
    ///
    /// * `recordSourceIdentity` says what the source is. A digest recorded
    ///   mid-transfer is read from the source at one moment and attached to
    ///   bytes taken out of it at another — the exact splice `verifyResume`
    ///   exists to refuse, except performed by us and stamped as proof of the
    ///   opposite.
    /// * `recordExpectedHash` says which digest would prove the transfer
    ///   landed. One declared after the bytes are gone is indistinguishable
    ///   from a reading of whatever landed.
    ///
    /// They shared a *set* before they shared a predicate, and the second
    /// writer expressed it as "the operation has not submitted yet" instead —
    /// which is a fact about the operation, not about the transfer, and
    /// `adoptLocked` re-points the row at a fresh operation whose clock has not
    /// started. A checkpoint fact survives a hand-over; an operation fact is
    /// reset by one.
    ///
    /// `planned` and `probing` are the two states in which nothing has been
    /// sent. Strictly narrower than `acceptsOffset`, and the two states in the
    /// gap are why it is a separate predicate rather than a reuse:
    /// `transferring` and `paused` may still take progress, and must not still
    /// take a commitment about what that progress will mean.
    pub fn beforeFirstByte(s: State) bool {
        return switch (s) {
            .planned, .probing => true,
            .transferring,
            .paused,
            .verifying,
            .publishing,
            .published,
            .completed_unverified,
            .failed_source_changed,
            .failed_remote_partial_mismatch,
            .failed_hash_mismatch,
            .failed_no_space,
            .failed_clobber_conflict,
            .failed_publish,
            .indeterminate_publish,
            .superseded,
            => false,
        };
    }

    /// Whether `recordVerifiedHash` may record a digest read back off the
    /// result.
    ///
    /// The mirror of `beforeFirstByte`, and disjoint from it: a verified digest
    /// claims that something hashed what landed, so it may only be written
    /// while something is doing that. `verifying` hashes the staged bytes and
    /// `publishing` can still find them wrong — which is exactly why those two
    /// are the predecessors of `failed_hash_mismatch`.
    ///
    /// Outside them the write is a claim with no act behind it, and both ends
    /// are reachable without this guard: on a `planned` row it records that a
    /// transfer which has sent nothing was checked, and on
    /// `failed_hash_mismatch` it records that the digest agreed on a row whose
    /// entire content is that it did not. Nothing reads `verified_sha256` yet,
    /// which is the window in which the guard is free to add — the first reader
    /// will assume the column means what its name says.
    pub fn acceptsVerifiedHash(s: State) bool {
        return switch (s) {
            .verifying, .publishing => true,
            .planned,
            .probing,
            .transferring,
            .paused,
            .published,
            .completed_unverified,
            .failed_source_changed,
            .failed_remote_partial_mismatch,
            .failed_hash_mismatch,
            .failed_no_space,
            .failed_clobber_conflict,
            .failed_publish,
            .indeterminate_publish,
            .superseded,
            => false,
        };
    }
};

/// The predecessors of `superseded`, as a value.
///
/// Derived from `State.isSupersedable` so that classifying a new failure state
/// there is the whole of adding it to the graph. Bound to a constant rather
/// than called inline in `predecessors`, because `canTransition` calls that
/// function at runtime and `membersWhere` only exists at comptime.
const supersedable_states = membersWhere(State, State.isSupersedable);

/// Legal predecessors of each checkpoint state — the whole transition graph,
/// in one place.
///
/// Written target-first because that is the direction the SQL needs: every
/// mutator guards its UPDATE with `state IN (<predecessors of its target>)`,
/// and those lists are rendered from this function at comptime rather than
/// typed out. Five hand-copied copies of a state list is how the Zig side and
/// the schema's index predicate came to disagree in the first place, and a
/// sixth copy is the failure this shape exists to make unavailable.
///
/// The edges that carry weight:
///
///  * `published` and `completed_unverified` are reachable only from
///    `publishing` or from adjudication. A plain "not settled yet" guard would
///    have admitted `planned → published`: an artifact recorded as published
///    without a byte of it ever having been hashed. Order is not the whole of
///    it, though, and this table is not where the rest lives: the two end
///    states are told apart by the *evidence* conjuncts `setStateSql` adds —
///    `published` needs a verified digest that does not contradict the declared
///    one, `completed_unverified` needs the absence of one — so a walk that
///    confirmed no bytes and read back no digest reaches the second and is
///    refused by the first.
///  * `indeterminate_publish → published | completed_unverified |
///    failed_publish | failed_hash_mismatch`. This is the one state that looks
///    terminal and is not: the rename may have landed, so the row keeps its
///    destination until something can say which way it went. Those four edges
///    are the only way out, and `adjudicateLocked` is their only writer.
///    Without them the checkpoint holds its path for good — it is not
///    adoptable, and nothing deletes these rows — so every later `create` aimed
///    there is refused with `DestinationHeld` forever.
///  * `verifying → paused`. Without it a crash during verification wedges the
///    row: nothing follows `verifying` except `publishing`, and `verifying` is
///    not adoptable, so the checkpoint could neither move nor be taken over
///    while still holding its destination forever.
///  * `planned` has no predecessors at all. `create` is its only writer, so a
///    `setState` aiming there is refused rather than quietly given an edge
///    nobody designed.
///  * every `failed_* → superseded`. The one way a failed transfer stops
///    holding its destination, written only by `supersedeLocked` — the graph
///    has the edges, the route partition below says who may walk them. The
///    predecessor list is rendered from `isSupersedable` rather than typed out,
///    so a seventh failure state joins it by being classified there.
///
/// Exhaustive on purpose: a new `State` variant fails to compile here, which
/// is the only reliable way to be told the graph has a hole.
fn predecessors(to: State) []const State {
    return switch (to) {
        .planned => &[_]State{},
        .probing => &[_]State{ .planned, .paused },
        .transferring => &[_]State{.probing},
        // A clean interruption at any point where bytes or a digest are still
        // in flight parks here, verification included.
        .paused => &[_]State{ .probing, .transferring, .verifying },
        .verifying => &[_]State{.transferring},
        .publishing => &[_]State{.verifying},
        // Either the rename was watched to completion, or it was adjudicated
        // afterwards by whoever established what the operation had done.
        .published => &[_]State{ .publishing, .indeterminate_publish },
        .completed_unverified => &[_]State{ .publishing, .indeterminate_publish },
        // Source identity is compared while reading the source, so only the
        // two states that read it can find it changed.
        .failed_source_changed => &[_]State{ .probing, .transferring },
        // The far side's leftover partial is inspected once, during the probe.
        .failed_remote_partial_mismatch => &[_]State{.probing},
        .failed_no_space => &[_]State{ .probing, .transferring },
        // Either the probe found the destination occupied, or the rename did.
        .failed_clobber_conflict => &[_]State{ .probing, .publishing },
        // A digest cannot disagree before something has hashed it — by the
        // transfer's own machinery while `verifying` or `publishing`, or by a
        // reconciler who hashed the artifact sitting at the destination of a
        // parked publish and found it is not what was promised. The third case
        // is a *failure* verdict reached from a *present* artifact, which reads
        // oddly until the hold is taken into account: `holdsDestination` covers
        // every failure, so the row goes on claiming its path and the wrong
        // artifact is not silently clobbered by the next transfer. The operator's
        // exit from there is `supersedeLocked`, the same as for any other
        // failure. See `receipts.publishAdjudication`.
        .failed_hash_mismatch => &[_]State{ .verifying, .publishing, .indeterminate_publish },
        .failed_publish => &[_]State{ .publishing, .indeterminate_publish },
        .indeterminate_publish => &[_]State{.publishing},
        .superseded => supersedable_states,
    };
}

/// Whether `from → to` is an edge of the graph above.
///
/// For callers and tests that need to ask the question in Zig. The mutators
/// deliberately do *not* consult it: asking here and writing in SQL is two
/// decisions that can disagree under a concurrent writer, so they guard on the
/// rendered list instead and let the check happen inside the same statement as
/// the write.
pub fn canTransition(from: State, to: State) bool {
    for (predecessors(to)) |allowed| if (allowed == from) return true;
    return false;
}

/// Renders enum members as a SQL `IN` list: `'probing','transferring'`.
///
/// Generic over the enum because three vocabularies in this file need the same
/// treatment — checkpoint states, source kinds, and (through `op_state`'s own
/// copy) operation statuses — and a renderer per vocabulary is the duplication
/// this shape exists to prevent, one level up.
///
/// The empty set becomes `NULL`, because `state IN ()` is a syntax error while
/// `state IN (NULL)` is never true — which is exactly what "this target has no
/// legal predecessor" means. `planned` is the only such target, and a
/// `setState` aiming at it therefore matches no row and is classified as an
/// illegal transition, which is what it is.
fn sqlList(comptime E: type, comptime members: []const E) []const u8 {
    comptime {
        if (members.len == 0) return "NULL";
        var out: []const u8 = "";
        for (members, 0..) |m, i| {
            out = out ++ (if (i == 0) "" else ",") ++ "'" ++ @tagName(m) ++ "'";
        }
        return out;
    }
}

/// Which of the three writers a transition statement is being rendered for.
///
/// The graph says which moves exist; this says who may make them. They are not
/// the same question, and treating them as one is how `setState` came to be
/// able to adjudicate: `published`, `completed_unverified`, `failed_publish` and
/// `failed_hash_mismatch` each list `indeterminate_publish` among their
/// predecessors, so the statement rendered for `setState` accepted a parked row
/// as readily as a `publishing` one. A transfer driver holding the owning
/// `request_id` — which it must, to write anything — could therefore record a
/// rename as published with no evidence at all, on the one row that exists
/// *because* nobody saw the rename. That is the fact
/// `receipts.publishAdjudication` refuses an operator override permission to
/// write, available one module down with nothing asked of it.
///
/// Supersession is the same argument in the other direction. Its edges leave a
/// settled row and release a destination; the writer that walks them does not
/// own the checkpoint — it *is* the rival — so it cannot be `setState`, whose
/// every statement is keyed on the owning request id. Left in the driver's
/// route, a failed attempt could clear its own path and start again with
/// nothing having asked whether the leftover partial may be discarded.
const Route = enum {
    /// `setState`: a driver reporting on a transfer it is running.
    transition,
    /// `adjudicateLocked`: a resolution saying what became of a rename nobody
    /// watched.
    adjudication,
    /// `supersedeLocked`: an operator releasing a failed attempt's destination.
    supersession,
};

/// Which writer owns the edge `from → to`.
///
/// A total function over the edges, which is what makes `sourcesFor` a
/// partition rather than three filters that happen not to overlap today. Read
/// target-first, because that is the stronger claim: everything into
/// `superseded` is a supersession whatever it came from, and among the rest
/// everything out of the unjudged state is an adjudication.
fn ownerOf(comptime to: State, from: State) Route {
    if (to == .superseded) return .supersession;
    if (from == .indeterminate_publish) return .adjudication;
    return .transition;
}

/// The predecessors of `to` that `route` may move.
///
/// A partition of `predecessors(to)` by `ownerOf`. Every edge belongs to exactly
/// one route — asserted by a test, because a split that quietly dropped an edge
/// would make a state unreachable and one that shared an edge would put the
/// rule back.
fn sourcesFor(comptime to: State, comptime route: Route) []const State {
    comptime {
        var out: []const State = &[_]State{};
        for (predecessors(to)) |from| {
            if (ownerOf(to, from) == route) out = out ++ &[_]State{from};
        }
        return out;
    }
}

/// Whether `route` may walk `from → to`. The Zig side of `sourcesFor`, used
/// only to word a refusal that has already happened.
fn routeAllows(comptime route: Route, from: State, comptime to: State) bool {
    inline for (comptime sourcesFor(to, route)) |allowed| if (allowed == from) return true;
    return false;
}

fn predecessorList(comptime to: State, comptime route: Route) []const u8 {
    return sqlList(State, sourcesFor(to, route));
}

/// The members of `E` satisfying one of the role predicates, in declaration
/// order.
fn membersWhere(comptime E: type, comptime role: fn (E) bool) []const E {
    comptime {
        var out: []const E = &[_]E{};
        for (@typeInfo(E).@"enum".fields) |field| {
            const member: E = @enumFromInt(field.value);
            if (role(member)) out = out ++ &[_]E{member};
        }
        return out;
    }
}

/// SQL `IN` lists for the role predicates, generated from the Zig predicates so
/// a state added to one of them reaches every statement that enforces it
/// without anyone editing SQL.
///
/// `holds_destination_sql` is public because it is the one list that also has
/// to agree with something outside this file — the schema's partial unique
/// index — and `gates_test` compares it against the DDL sqlite actually stored.
pub const holds_destination_sql = sqlList(State, membersWhere(State, State.holdsDestination));
const adoptable_sql = sqlList(State, membersWhere(State, State.isAdoptable));
const recoverable_sql = sqlList(State, membersWhere(State, State.isRecoverable));
const accepts_offset_sql = sqlList(State, membersWhere(State, State.acceptsOffset));
const before_first_byte_sql = sqlList(State, membersWhere(State, State.beforeFirstByte));
const accepts_verified_hash_sql = sqlList(State, membersWhere(State, State.acceptsVerifiedHash));

/// The complement of `op_state.Status.blocksScope`, written as a predicate so
/// the list below can be a positive `IN`.
///
/// The negation lives here, once, rather than as a `NOT IN` in the statement.
/// `NOT IN` would be a list of the statuses that *refuse* a hand-over, and a
/// status this binary cannot name — a newer schema, a hand-edited row — is not
/// in it, so it would pass. A positive list refuses anything it does not
/// recognise, which is the answer a hand-over deserves when it cannot tell
/// whether the attempt it is displacing is still running.
fn statusReleasesScope(s: op_state.Status) bool {
    return !s.blocksScope();
}

/// The same question of a `resolved_status`, which is a narrower vocabulary.
///
/// Every member of it releases today, so the rendered list is all four. It is
/// generated rather than written out for the case where that stops being true:
/// a fifth resolution that still blocked would have to be excluded here, and a
/// hand-coded list would silently admit it.
fn resolvedReleasesScope(s: op_state.ResolvedStatus) bool {
    return statusReleasesScope(s.toStatus());
}

/// The lists this file needs from the *operation* vocabulary, rendered by the
/// modules that own them. Two of them used to be typed out inside the
/// statements — three copies of `('created','connecting')` that no predicate
/// could reach.
const op_before_submission_sql = op_state.sqlList(op_state.Status.beforeSubmission);
const op_releases_scope_sql = op_state.sqlList(statusReleasesScope);
const resolution_releases_scope_sql = sqlList(
    op_state.ResolvedStatus,
    membersWhere(op_state.ResolvedStatus, resolvedReleasesScope),
);

/// Whether an attempt in this status pair may still be affecting the remote
/// host, as the SQL conjunct that decides it.
///
/// `<alias>` is the operations row to read. Rendered once and used by both
/// writers that displace or release somebody else's work, because "is the
/// incumbent still running" is one question and a second copy of the answer is
/// a second thing to keep in step.
///
/// It is written the way `operations.unsettled_predicate` is written, and
/// deliberately *not* as `COALESCE(resolved_status, status)`. The COALESCE form
/// answers a question about one column pair by folding it into one value, and
/// the fold is only sound while `resolved_status` is set on `indeterminate`
/// rows and nowhere else. `receipts.resolve` enforces that; the schema does not
/// CHECK it. A barrier that depends on a rule held in another module is a
/// barrier one bug away from opening, and `operations` refused that trade for
/// the scope guard — so the two statements over the same fact now say the same
/// thing rather than disagreeing on any row where the rule was broken.
///
/// Both halves are positive `IN` lists for the reason `statusReleasesScope`
/// exists: a status this binary cannot name is not evidence that anything
/// stopped.
fn releasesScopeSql(comptime alias: []const u8) []const u8 {
    return std.fmt.comptimePrint(
        \\({[a]s}.status IN ({[released]s})
        \\         OR ({[a]s}.status = '{[unknown]s}'
        \\             AND {[a]s}.resolved_status IN ({[resolved]s})))
    , .{
        .a = alias,
        .released = op_releases_scope_sql,
        .unknown = @tagName(op_state.Status.indeterminate),
        .resolved = resolution_releases_scope_sql,
    });
}

/// Which machine the artifact is published on.
///
/// Not a bool and not just "remote": two pulls from *different* servers into
/// one local path are a genuine collision, and two pushes to the same path on
/// different servers are not. The server id is what tells those apart, and the
/// live-destination unique index is keyed on this text.
pub const DestSide = union(enum) {
    local,
    server: i64,

    /// Stored form: `local` or `server:<id>`. The schema CHECKs this shape.
    pub fn text(d: DestSide, buf: []u8) []const u8 {
        return switch (d) {
            .local => "local",
            .server => |id| std.fmt.bufPrint(buf, "server:{d}", .{id}) catch
                // `buf` is `dest_side_buf_len`, sized for the widest i64.
                unreachable,
        };
    }

    pub fn parse(raw: []const u8) error{UnknownDestSide}!DestSide {
        if (std.mem.eql(u8, raw, "local")) return .local;
        const prefix = "server:";
        if (!std.mem.startsWith(u8, raw, prefix)) return error.UnknownDestSide;
        const id = std.fmt.parseInt(i64, raw[prefix.len..], 10) catch
            return error.UnknownDestSide;
        return .{ .server = id };
    }

    /// Which machine a verifier has to read to see this artifact.
    ///
    /// The evidence side is coarser than the destination on purpose: an
    /// operation is bound to one server, so within a single request "remote"
    /// names exactly one machine and carrying its id again would be a second
    /// copy of a fact the operation row already holds.
    pub fn evidenceSide(d: DestSide) Side {
        return switch (d) {
            .local => .local,
            .server => .remote,
        };
    }
};

/// `server:` plus the widest i64.
pub const dest_side_buf_len = 7 + 20;

/// Identity of a file being read, captured when the transfer started.
///
/// `size` and `mtime_ns` come from a stat, so `create` can have them for the
/// asking. `sha256` cannot be had that cheaply — it means reading the whole
/// file — so a checkpoint written before its source has been read carries
/// none, and `recordSourceIdentity` writes all three once the probe has read
/// it. That ordering matters because the digest is the only one of the three a
/// rewrite cannot reproduce: size and mtime can both be restored by hand, so
/// they are corroboration and not identity. Hence a non-zero confirmed offset
/// may not exist without the digest, enforced twice — by the schema
/// (`offset_needs_source_identity`) and again in `verifyResume`, which is pure
/// and so cannot assume the schema vetted the struct it was handed.
pub const FileIdentity = struct {
    path: []const u8,
    size: ?u64 = null,
    mtime_ns: ?i128 = null,
    sha256: ?[]const u8 = null,
};

/// Identity of an HTTP source, for `fetch`. A strong validator is what makes
/// a ranged resume safe: without it the object may have changed between
/// requests and the chunks would not belong to the same file.
pub const HttpIdentity = struct {
    url: []const u8,
    etag: ?[]const u8 = null,
    last_modified: ?[]const u8 = null,
    size: ?u64 = null,
};

/// Where the bytes come from, as an exhaustive union.
///
/// It replaces `if (checkpoint.local_path != null)`, which let a remote source
/// skip the identity check entirely by having a null in the column a push
/// happens to use. A switch cannot be fallen through by being null.
pub const SourceIdentity = union(enum) {
    /// A file on this machine (a push).
    local_file: FileIdentity,
    /// A file on the host (a pull).
    remote_file: FileIdentity,
    /// An HTTP object (a fetch; not constructible until M3b).
    http: HttpIdentity,

    pub fn kindName(s: SourceIdentity) []const u8 {
        return @tagName(s);
    }

    pub fn file(s: SourceIdentity) ?FileIdentity {
        return switch (s) {
            .local_file, .remote_file => |f| f,
            .http => null,
        };
    }
};

/// The stored `source_kind` vocabulary, which is this union's tag. The schema
/// CHECKs the same three names.
pub const SourceKind = std.meta.Tag(SourceIdentity);

/// Whether a source of this kind is a file, and so has the size, mtime and
/// content digest that `recordSourceIdentity` writes.
///
/// An `http` source has none of the three: its identity is a strong validator,
/// which arrives with the response and is stored in different columns
/// altogether. The predicate exists so that statement can say which rows it
/// applies to without a hand-typed list — see `record_source_identity_sql`.
///
/// Exhaustive with no `else`: a fourth source kind has to be classified here
/// rather than silently inheriting whichever answer it was written next to.
fn isFileSource(k: SourceKind) bool {
    return switch (k) {
        .local_file, .remote_file => true,
        .http => false,
    };
}

const file_source_sql = sqlList(SourceKind, membersWhere(SourceKind, isFileSource));

pub const Checkpoint = struct {
    id: i64,
    request_id: []const u8,
    direction: Direction,

    dest_side: DestSide,
    dest_path: []const u8,
    partial_path: []const u8,
    partial_len: i64,
    /// Hash of the first `confirmed_offset` bytes of the partial, as we last
    /// recorded them. The schema requires it whenever the offset is non-zero.
    partial_sha256: ?[]const u8,

    source: SourceIdentity,

    chunk_size: i64,
    confirmed_offset: i64,
    total_bytes: ?i64,
    expected_sha256: ?[]const u8,
    verified_sha256: ?[]const u8,
    no_clobber: bool,
    state: State,
    failure_reason: ?[]const u8,
    created_at: i64,
    updated_at: i64,
};

/// What a guarded state change can refuse with.
///
/// Split out of `Error` so `receipts` can call `adjudicateLocked` without
/// taking the whole checkpoint vocabulary into the ledger's error set — and,
/// through it, into the execution boundary's. `Error` is built from this one,
/// so the containment is structural rather than a claim in a comment.
pub const TransitionError = Db.Error || error{
    UnknownTransferState,
    /// There is no checkpoint with that id. Only that — see `ownedRow`, which
    /// exists so the other refusals stopped hiding behind this one.
    CheckpointRowMissing,
    /// The row is there, but `request_id` names a different operation. A resume
    /// adopted it away while we were still holding its id.
    CheckpointNotOurs,
    /// The row is there and it is ours, but the target state is not reachable
    /// from the state it is in.
    IllegalCheckpointTransition,
    /// `setState` was aimed at a row parked in `indeterminate_publish`. The
    /// graph has that edge; this writer does not have it. Separate from
    /// `IllegalCheckpointTransition` because the answer is different: the move
    /// is not impossible, it is somebody else's to make, and what the caller
    /// has to do is stop and let `receipts.resolve` judge the rename from
    /// evidence rather than record a verdict it does not have. See `Route`.
    CheckpointAwaitingAdjudication,
    /// `adjudicateLocked` was aimed at a row that is not parked. A resolution
    /// only adjudicates what `pendingPublishLocked` hands it, so this means the
    /// id came from somewhere else — a driver's ordinary state change wearing a
    /// resolution's authority.
    CheckpointNotAwaitingAdjudication,
    /// `setState` was aimed at `superseded`. The graph has those edges; this
    /// writer does not have them. Releasing a failed attempt's destination is
    /// not something the failed attempt gets to do to itself — see
    /// `supersedeLocked`, which is keyed on the *superseding* request instead
    /// of the owning one for exactly that reason.
    SupersessionIsNotATransition,
    /// `published` was asked for on a row that never read a digest back off
    /// the result. Distinct from the transition refusal on purpose: the walk
    /// was legal and the evidence was not, and one name for both sends a
    /// caller to the transition table for a problem that is in the digest.
    /// `completed_unverified` is the state that names this outcome honestly.
    PublishNeedsVerifiedHash,
    /// `published` was asked for on a row whose verified digest disagrees with
    /// the one the transfer declared before it sent anything. The right bytes
    /// are not there; `failed_hash_mismatch` is the state for it.
    PublishHashContradictsDeclared,
    /// `completed_unverified` was asked for on a row that *does* carry a
    /// verified digest. The two end states are mutually exclusive by
    /// construction — that is what makes "unverified" mean something — so a
    /// transfer that checked its result must be recorded as having checked it.
    CompletedUnverifiedHasVerifiedHash,
    /// `completed_unverified` was asked for on a row that declared, before it
    /// sent anything, what its result would hash to.
    ///
    /// "Unverified" means the transfer had nothing to check its result against.
    /// A transfer that named a digest in advance had something, and recording
    /// it unverified would put an artifact at the destination, release the
    /// hold `holdsDestination` keeps on every unpublished state, and settle the
    /// operation `completed` — all without the declared digest ever having been
    /// compared with anything. The resolution route one function over already
    /// refuses exactly this shape (`unverified_reading_when_digest_declared`);
    /// the driver's own route did not, so the same act was refused when reached
    /// through a crash and admitted when reached through the happy path.
    CompletedUnverifiedHasDeclaredHash,
    /// `failed_hash_mismatch` was asked for on a row whose columns say the
    /// digest agreed: `verified_sha256` equals the `expected_sha256` declared
    /// in advance.
    ///
    /// The state's whole content is that the digest did not match, so a row in
    /// it holding a reading that matches is a row contradicting itself — and
    /// this file says so in three places (`acceptsVerifiedHash`,
    /// `recordVerifiedHash`, `adjudicateLocked`) while nothing enforced it. The
    /// reachable way in was the adjudication route: a driver hashes the staged
    /// bytes while `verifying`, dies mid-rename, the row normalises to
    /// `indeterminate_publish` *keeping* that digest, and a reconciler then
    /// reads the destination and finds different bytes. `adjudicateLocked`
    /// replaces the column with the reading it was given for exactly that
    /// reason, so this fires only on an adjudication that supplied none, or on
    /// a driver claiming a mismatch it has not recorded.
    HashMismatchWithAgreeingDigest,
};

/// The refusals `adjudicateLocked` adds to those.
pub const AdjudicateError = TransitionError || error{
    /// `adjudicateLocked` was aimed at a state that is not one of the four
    /// outcomes of a rename nobody observed. Checked at runtime rather than in
    /// the type because the target is *derived* from evidence — see
    /// `receipts.resolve` — so a four-member enum would move the decision one
    /// function earlier without removing it.
    NotAnAdjudicationTarget,
};

pub const Error = AdjudicateError || error{
    UnknownDirection,
    UnknownDestSide,
    /// A stored row's `source_kind` is not one this binary knows, or its
    /// columns do not carry the family that kind requires. The schema CHECKs
    /// both, so this means the row was written by something else.
    UnknownSourceKind,
    /// A stored `operations.status` — or `resolved_status` — is not one this
    /// binary knows. Read only to name a refusal, see `incumbentBlocksScope`,
    /// and refused rather than read as "not blocking", because a status we
    /// cannot interpret is not evidence of anything.
    UnknownStatus,
    /// An mtime in nanoseconds that does not fit the column. Real only past
    /// the year 2262 — but narrowing it silently would make a source that
    /// changed look unchanged.
    MtimeOutOfRange,
    OutOfMemory,
    /// A re-confirm at the *same* offset carried a different prefix digest.
    /// One of the two readings of those bytes is wrong and we cannot tell
    /// which, so neither is written.
    PrefixHashConflict,
    /// `confirmOffset` was handed an offset below the one already durable — a
    /// late reply from an earlier chunk trying to walk progress backwards.
    CheckpointNotAdvanced,
    /// `recordExpectedHash` was called on a transfer that had already declared
    /// a digest, or that had already started. Both mean the value it wants to
    /// write can no longer be an *advance* commitment. "Already started" is
    /// read off the checkpoint — its state and its offset — because that is the
    /// fact a hand-over carries with it.
    ExpectedHashLocked,
    /// `recordVerifiedHash` was called on a transfer that had already recorded
    /// a verification digest, or on one in a state where nothing could have
    /// hashed the result. Either way the value would be a claim with no act
    /// behind it.
    VerifiedHashLocked,
    /// `adopt` was asked to re-point a checkpoint that is no longer resumable.
    CheckpointNotResumable,
    /// `recover` was asked to take over a checkpoint that was not left in the
    /// middle of an act. Only `verifying` and `publishing` can be — see
    /// `State.abandonedNormalisation`. A row that is merely idle is adopted,
    /// not recovered, and a settled one is neither.
    CheckpointNotRecoverable,
    /// The operation named by `request_id` does not agree with the checkpoint
    /// `create` was asked to write: there is no such operation, it has already
    /// submitted, or its kind, source family or server contradicts the
    /// direction and destination given. Refused rather than reconciled — see
    /// `create` for why quietly adopting the operation's answer would be worse.
    CheckpointOperationMismatch,
    /// `recordSourceIdentity` was called on a source that had already been
    /// identified, on a transfer past the point where a fresh reading of the
    /// source could describe the bytes it has been sending, or on a row whose
    /// source is an HTTP object and therefore has no file identity to record.
    SourceIdentityLocked,
    /// `adoptLocked` lost its compare-and-swap: another resume took the
    /// checkpoint over first. Distinct from `CheckpointNotOurs`, which tells a
    /// *writer* to stop; this tells a would-be heir it lost a race and may
    /// re-read and decide again.
    CheckpointOwnerChanged,
    /// The checkpoint may move, but the operation asked to take it could not
    /// run it: already settled, the wrong kind for the direction, bound to a
    /// different machine than the destination, or bound to a different machine
    /// than the operation surrendering it.
    AdoptingOperationNotEligible,
    /// The operation *giving up* the checkpoint may still be affecting the
    /// remote host: it has not reached the remote's answer, or it reached
    /// `indeterminate` and nobody has reconciled that. Either way it may still
    /// be appending to the same partial. Its own name because the caller's
    /// response is the opposite of `AdoptingOperationNotEligible`'s: nothing is
    /// wrong with the heir, and the fix is to establish what the incumbent did
    /// — `terminus request reconcile <id>` — before taking anything from it.
    ///
    /// The predicate is `op_state.Status.blocksScope` over the *effective*
    /// status, not `isTerminal`: `indeterminate` is a terminal that means
    /// nobody knows, and a rule satisfied by it would let an heir take a
    /// partial away from a process that may still be streaming into it.
    SurrenderingOperationMayStillBeRunning,
    /// The checkpoint names an operation that does not exist. `request_id` is
    /// a foreign key into `operations` and foreign keys are on, so this means
    /// the database is not the shape this binary was built against — reported,
    /// never read as "not settled".
    SurrenderingOperationMissing,
    /// `create` was asked for a second checkpoint on a request that already has
    /// one. The caller's own bookkeeping is what is wrong — it is holding an id
    /// it forgot about — which is a different thing to be told than that some
    /// other transfer is in the way.
    CheckpointAlreadyExists,
    /// Another transfer still holds this destination. Not a caller bug but a
    /// real conflict over a path, which an operator can resolve and a caller
    /// cannot. Split out of the bare `error.Constraint` these two used to share
    /// because they demand opposite responses.
    DestinationHeld,
    /// `supersedeLocked` was aimed at a checkpoint that is not settled with a
    /// failure. A live transfer may still be writing to the partial, an
    /// unjudged one is waiting on `adjudicateLocked`, and a published one has
    /// no hold to release — see `State.isSupersedable`.
    CheckpointNotSupersedable,
    /// `supersedeLocked` was given a `superseded_by_request_id` naming no
    /// operation. The whole product of a supersession is a record of who
    /// released the path; a record pointing at nothing is worse than none,
    /// because it reads as provenance.
    SupersedingOperationMissing,
};

pub const CreateOptions = struct {
    request_id: []const u8,
    direction: Direction,
    dest_side: DestSide,
    dest_path: []const u8,
    partial_path: []const u8,
    source: SourceIdentity,
    chunk_size: i64,
    total_bytes: ?u64 = null,
    no_clobber: bool = false,
    now: i64,
};

fn narrowMtime(mtime_ns: ?i128) Error!?i64 {
    const v = mtime_ns orelse return null;
    return std.math.cast(i64, v) orelse error.MtimeOutOfRange;
}

fn optU64(v: ?u64) Error!?i64 {
    const value = v orelse return null;
    return std.math.cast(i64, value) orelse error.MtimeOutOfRange;
}

/// Records a new checkpoint, bound to the operation that is going to run it.
///
/// The insert is a `SELECT` over `operations` because a checkpoint is a claim
/// about work some operation is doing, and nothing used to check that the two
/// described the same work. A push aimed at server 2 could be recorded under
/// an operation bound to server 1, and every later reader — the scope guard,
/// the live-destination index, `receipts.resolve` deciding whether a published
/// hash may settle the request — would then be reasoning about a pairing that
/// never existed. Putting the agreement in the `WHERE` clause makes it part of
/// the same statement as the write, so it cannot be checked and then go stale.
///
/// Four things have to line up: the operation exists and has not submitted
/// yet, its kind matches the direction, the source family matches the
/// direction, and the machine the artifact lands on is the one the operation
/// is bound to. The status window is the same one `recordExpectedHash` uses,
/// and for the same reason: a checkpoint minted after the bytes are in flight
/// describes a transfer nobody planned.
///
/// A mismatch is refused, never repaired. Deriving `dest_side` from the
/// operation instead would turn "publish this on server 2" into a silent push
/// to server 1 — a correction the caller never asked for and cannot see.
///
/// Two schema constraints can still refuse an insert whose operation agrees
/// with it: this request already has a checkpoint, or the destination is held
/// by a live transfer. `createConflict` names which, because they are the same
/// `error.Constraint` to sqlite and opposite instructions to a caller.
pub fn create(store: *Store, opts: CreateOptions) Error!i64 {
    var stmt = try store.db.prepare(create_sql);
    defer stmt.deinit();
    var side_buf: [dest_side_buf_len]u8 = undefined;
    try stmt.bindText(1, opts.request_id);
    try stmt.bindInt(2, schema_version);
    try stmt.bindText(3, @tagName(opts.direction));
    try stmt.bindText(4, opts.dest_side.text(&side_buf));
    try stmt.bindText(5, opts.dest_path);
    try stmt.bindText(6, opts.partial_path);
    try stmt.bindText(7, opts.source.kindName());
    switch (opts.source) {
        .local_file, .remote_file => |f| {
            try stmt.bindText(8, f.path);
            try stmt.bindOptInt(9, try optU64(f.size));
            try stmt.bindOptInt(10, try narrowMtime(f.mtime_ns));
            try stmt.bindOptText(11, f.sha256);
            try stmt.bindOptText(12, null);
            try stmt.bindOptText(13, null);
            try stmt.bindOptText(14, null);
        },
        .http => |h| {
            try stmt.bindOptText(8, null);
            try stmt.bindOptInt(9, try optU64(h.size));
            try stmt.bindOptInt(10, null);
            try stmt.bindOptText(11, null);
            try stmt.bindText(12, h.url);
            try stmt.bindOptText(13, h.etag);
            try stmt.bindOptText(14, h.last_modified);
        },
    }
    try stmt.bindInt(15, opts.chunk_size);
    try stmt.bindOptInt(16, try optU64(opts.total_bytes));
    try stmt.bindInt(17, if (opts.no_clobber) 1 else 0);
    try stmt.bindInt(18, opts.now);
    // The destination's server id as a number, so the statement can compare it
    // against the operation's without parsing `dest_side` back out of text.
    // Bound separately rather than derived in SQL because `local` has no id at
    // all, and a missing id and an id of zero are different destinations.
    try stmt.bindOptInt(19, switch (opts.dest_side) {
        .local => null,
        .server => |id| id,
    });
    _ = stmt.step() catch |err| switch (err) {
        error.Constraint => return try createConflict(store, opts),
        else => return err,
    };
    // An `INSERT ... SELECT` whose SELECT matched nothing is not an error to
    // sqlite, and `last_insert_rowid` still holds whatever the previous
    // successful insert on this connection returned. Returning that would hand
    // the caller *another transfer's* checkpoint id to write progress into —
    // the quietest possible way to corrupt two transfers at once.
    if (store.db.changes() == 0) return error.CheckpointOperationMismatch;
    return store.db.lastInsertRowId();
}

/// Names the constraint that refused a `create`. Never returns a value: it is
/// only reached once the insert has already failed, and its whole job is to say
/// why.
///
/// sqlite reports every constraint the same way, and this statement can trip
/// two that mean opposite things to a caller: `UNIQUE(request_id)` says this
/// request already has a checkpoint and the caller has lost track of its own,
/// while the live-destination index says somebody else's transfer is standing
/// on the path. One `error.Constraint` for both leaves the CLI with a single
/// message for "you have a bug" and "that path is busy, try later or pick
/// another" — and no way to tell which it is holding.
///
/// The probes are separate statements, so a row that changes in between is
/// described by its newer state. That only chooses the wording of a refusal
/// that has already happened. Anything neither probe explains comes back as the
/// bare `error.Constraint` it was: guessing a name for a constraint we did not
/// identify would be worse than admitting we did not identify it.
fn createConflict(store: *Store, opts: CreateOptions) Error!noreturn {
    var by_request = try store.db.prepare(
        "SELECT 1 FROM transfer_checkpoints WHERE request_id = ?1",
    );
    defer by_request.deinit();
    try by_request.bindText(1, opts.request_id);
    // Checked first: a caller that already has a checkpoint under this request
    // is confused about its own state, and until that is fixed the question of
    // who holds the destination is not one it is in a position to ask.
    if (try by_request.step()) return error.CheckpointAlreadyExists;

    var by_dest = try store.db.prepare(find_live_dest_sql);
    defer by_dest.deinit();
    var side_buf: [dest_side_buf_len]u8 = undefined;
    try by_dest.bindText(1, opts.dest_side.text(&side_buf));
    try by_dest.bindText(2, opts.dest_path);
    if (try by_dest.step()) return error.DestinationHeld;

    return error.Constraint;
}

/// Rendered from the same predicate as the index that does the refusing, so the
/// probe cannot start disagreeing with the constraint it is explaining.
const find_live_dest_sql = std.fmt.comptimePrint(
    \\SELECT 1 FROM transfer_checkpoints
    \\ WHERE dest_side = ?1 AND dest_path = ?2 AND state IN ({s})
, .{holds_destination_sql});

/// Two of the vocabularies in this statement are rendered from Zig and the
/// rest are not, and the split is deliberate.
///
/// `state` is rendered because `create` is the only writer of `planned` —
/// `predecessors(.planned)` is empty precisely so that no `setState` can put a
/// row back there — and the column has no CHECK, so a rename of the variant
/// would leave this statement quietly inserting a state nothing can parse.
/// `o.status` is rendered because the same window is enforced in three
/// statements here, and three hand-typed copies of it is how the checkpoint
/// state lists came to disagree with the index that enforced them.
///
/// The others are *stored* forms with no Zig owner this file can reach:
/// `push`/`pull`/`fetch` and the three source kinds are CHECKed by the schema,
/// and the three `operations.kind` names belong to a module this one does not
/// import (the dependency runs the other way — see `receipts`). Rendering them
/// would need sixteen `{s}` in an already dense statement to re-state
/// constraints the frozen migration text already pins, and a drift in any of
/// them makes the CASE yield NULL, which refuses every `create` rather than
/// admitting a wrong one.
///
/// `IS`, not `=`, for `?19 IS o.server_id`: `= NULL` evaluates to NULL, so the
/// pull and fetch arms — the two that pass a null id — would match no row and
/// a locally-published transfer could never be recorded.
const create_sql = std.fmt.comptimePrint(
    \\INSERT INTO transfer_checkpoints (
    \\  request_id, schema_version, direction,
    \\  dest_side, dest_path, partial_path, partial_len,
    \\  source_kind, source_path, source_size, source_mtime_ns, source_sha256,
    \\  source_url, source_etag, source_last_modified,
    \\  chunk_size, confirmed_offset, total_bytes,
    \\  no_clobber, state, created_at, updated_at)
    \\SELECT ?1, ?2, ?3, ?4, ?5, ?6, 0,
    \\       ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
    \\       ?15, 0, ?16, ?17, '{[planned]s}', ?18, ?18
    \\  FROM operations o
    \\ WHERE o.request_id = ?1
    \\   AND o.status IN ({[before_submission]s})
    \\   AND o.kind = CASE ?3 WHEN 'push'  THEN 'transfer_push'
    \\                        WHEN 'pull'  THEN 'transfer_pull'
    \\                        WHEN 'fetch' THEN 'fetch' END
    \\   AND ?7 = CASE ?3 WHEN 'push'  THEN 'local_file'
    \\                    WHEN 'pull'  THEN 'remote_file'
    \\                    WHEN 'fetch' THEN 'http'  END
    \\   AND CASE ?3
    \\         WHEN 'push'  THEN (o.server_id IS NOT NULL AND ?19 IS o.server_id
    \\                            AND ?4 = 'server:' || CAST(o.server_id AS TEXT))
    \\         WHEN 'pull'  THEN (o.server_id IS NOT NULL AND ?19 IS NULL AND ?4 = 'local')
    \\         WHEN 'fetch' THEN (o.server_id IS     NULL AND ?19 IS NULL AND ?4 = 'local')
    \\       END
, .{ .planned = @tagName(State.planned), .before_submission = op_before_submission_sql });

const select_columns =
    \\SELECT id, request_id, direction, dest_side, dest_path,
    \\       partial_path, partial_len, partial_sha256,
    \\       source_kind, source_path, source_size, source_mtime_ns, source_sha256,
    \\       source_url, source_etag, source_last_modified,
    \\       chunk_size, confirmed_offset, total_bytes,
    \\       expected_sha256, verified_sha256, no_clobber, state,
    \\       failure_reason, created_at, updated_at
    \\FROM transfer_checkpoints
;

fn dupOpt(a: Allocator, v: ?[]const u8) Allocator.Error!?[]const u8 {
    return if (v) |value| try a.dupe(u8, value) else null;
}

fn rowToCheckpoint(arena: Allocator, stmt: *Db.Stmt) Error!Checkpoint {
    const source: SourceIdentity = blk: {
        const kind = stmt.columnText(8);
        if (std.mem.eql(u8, kind, "http")) break :blk .{ .http = .{
            .url = try arena.dupe(u8, stmt.columnOptText(13) orelse return error.UnknownSourceKind),
            .etag = try dupOpt(arena, stmt.columnOptText(14)),
            .last_modified = try dupOpt(arena, stmt.columnOptText(15)),
            .size = if (stmt.columnOptInt(10)) |v| @intCast(v) else null,
        } };
        const file: FileIdentity = .{
            .path = try arena.dupe(u8, stmt.columnOptText(9) orelse return error.UnknownSourceKind),
            .size = if (stmt.columnOptInt(10)) |v| @intCast(v) else null,
            .mtime_ns = if (stmt.columnOptInt(11)) |v| @as(i128, v) else null,
            .sha256 = try dupOpt(arena, stmt.columnOptText(12)),
        };
        if (std.mem.eql(u8, kind, "local_file")) break :blk .{ .local_file = file };
        if (std.mem.eql(u8, kind, "remote_file")) break :blk .{ .remote_file = file };
        return error.UnknownSourceKind;
    };
    return .{
        .id = stmt.columnInt(0),
        .request_id = try arena.dupe(u8, stmt.columnText(1)),
        .direction = try Direction.parse(stmt.columnText(2)),
        .dest_side = try DestSide.parse(stmt.columnText(3)),
        .dest_path = try arena.dupe(u8, stmt.columnText(4)),
        .partial_path = try arena.dupe(u8, stmt.columnText(5)),
        .partial_len = stmt.columnInt(6),
        .partial_sha256 = try dupOpt(arena, stmt.columnOptText(7)),
        .source = source,
        .chunk_size = stmt.columnInt(16),
        .confirmed_offset = stmt.columnInt(17),
        .total_bytes = stmt.columnOptInt(18),
        .expected_sha256 = try dupOpt(arena, stmt.columnOptText(19)),
        .verified_sha256 = try dupOpt(arena, stmt.columnOptText(20)),
        .no_clobber = stmt.columnInt(21) != 0,
        .state = try State.parse(stmt.columnText(22)),
        .failure_reason = try dupOpt(arena, stmt.columnOptText(23)),
        .created_at = stmt.columnInt(24),
        .updated_at = stmt.columnInt(25),
    };
}

pub fn get(store: *Store, arena: Allocator, id: i64) Error!?Checkpoint {
    var stmt = try store.db.prepare(select_columns ++ " WHERE id = ?1");
    defer stmt.deinit();
    try stmt.bindInt(1, id);
    if (!try stmt.step()) return null;
    return try rowToCheckpoint(arena, &stmt);
}

/// The checkpoint for one request. At most one exists: `UNIQUE(request_id)`
/// in the schema, which is what lets this return a value rather than a choice.
pub fn byRequest(store: *Store, arena: Allocator, request_id: []const u8) Error!?Checkpoint {
    var stmt = try store.db.prepare(select_columns ++ " WHERE request_id = ?1");
    defer stmt.deinit();
    try stmt.bindText(1, request_id);
    if (!try stmt.step()) return null;
    return try rowToCheckpoint(arena, &stmt);
}

/// The resumable checkpoint for a destination, if any.
///
/// At most one can exist — the destination-holding unique index covers a
/// superset of the adoptable states, so it already forbids two of these — and
/// this is therefore a lookup, not a pick. Keyed on both halves of the
/// destination because a path alone does not name one: `/srv/app/out.bin` on
/// two different servers is two destinations, and `/srv/app/out.bin` here is a
/// third.
///
/// Filtered on `isAdoptable`, deliberately *not* on `holdsDestination`. A row
/// in `verifying` or `publishing` is past the last byte: it still owns the
/// path, so a rival is still refused, but there is no offset for a resume to
/// pick up and offering one would be an invitation to restart a transfer that
/// had already finished sending.
pub fn findResumable(
    store: *Store,
    arena: Allocator,
    dest_side: DestSide,
    dest_path: []const u8,
) Error!?Checkpoint {
    var stmt = try store.db.prepare(find_resumable_sql);
    defer stmt.deinit();
    var side_buf: [dest_side_buf_len]u8 = undefined;
    try stmt.bindText(1, dest_side.text(&side_buf));
    try stmt.bindText(2, dest_path);
    if (!try stmt.step()) return null;
    return try rowToCheckpoint(arena, &stmt);
}

const find_resumable_sql = std.fmt.comptimePrint(select_columns ++
    \\ WHERE dest_side = ?1 AND dest_path = ?2
    \\   AND state IN ({s})
, .{adoptable_sql});

/// Observed state of the staging partial, as probed before resuming.
pub const PartialObservation = struct {
    exists: bool,
    len: u64 = 0,
    /// Hash of the first `confirmed_offset` bytes, when we asked for it.
    prefix_sha256: ?[]const u8 = null,
};

pub const ResumeVerdict = union(enum) {
    /// Safe to continue from this offset, and the partial is already exactly
    /// this long.
    resume_from: u64,
    /// Safe to continue from `offset`, but the partial is longer than that and
    /// must be truncated back to it first. The extra bytes were written and
    /// never confirmed — normal after a cut mid-write — and they are not
    /// evidence of anything, so they are discarded rather than counted.
    /// Truncating before the prefix is proven would destroy the only thing
    /// that could have proven it, hence the order: prove, then cut.
    truncate_then_resume: struct {
        offset: u64,
        /// What the partial is now, for the message when the truncate fails.
        partial_len: u64,
    },
    /// Nothing usable at the destination; start over (not an error).
    start_over,
    /// The source is not the one this checkpoint describes.
    source_changed: []const u8,
    /// The staging partial does not match what we confirmed.
    partial_mismatch: []const u8,
    /// The checkpoint's own record is too thin to license a resume, whatever
    /// the source and the partial now look like.
    ///
    /// Its own variant rather than a shade of `source_changed`, because the
    /// tag is the machine-readable half and a caller switching on
    /// `source_changed` will tell an operator their file changed. For a source
    /// that is byte-for-byte what it always was, that sends them to diff a file
    /// that is fine while the actual fault — a record written without the one
    /// field that makes it checkable — goes unnamed.
    ///
    /// No `failed_*` state names this yet, so a caller has to choose one; that
    /// choice belongs with the transfer-execution path, which is also the only
    /// thing that can decide whether to restart from zero instead. What it must
    /// not do is report it as a resume that succeeded.
    unidentified_source: []const u8,
};

/// Decides whether a checkpoint may be resumed. Pure, so the rules are
/// testable without a network or a filesystem.
pub fn verifyResume(
    checkpoint: Checkpoint,
    observed_source: ?SourceIdentity,
    partial: PartialObservation,
) ResumeVerdict {
    if (sourceChanged(checkpoint.source, observed_source)) |why|
        return .{ .source_changed = why };

    const confirmed: u64 = @intCast(@max(checkpoint.confirmed_offset, 0));

    // A file source with no recorded digest cannot be re-identified at all, so
    // the check just above had nothing it could fail on: size and mtime are
    // both reproducible by hand, and a path is not a fact about content. Any
    // resume would append to bytes attributed to that non-comparison. The
    // schema refuses to *store* such a row — `offset_needs_source_identity` —
    // but this function is pure and every caller hands it a struct, so nothing
    // here can assume the schema ever saw it. The `http` arm needs no
    // equivalent: `sourceChanged` already refuses an object that offered no
    // strong validator, whatever its offset.
    if (confirmed > 0) if (checkpoint.source.file()) |was| {
        if (was.sha256 == null) return .{
            .unidentified_source = "the source was never fully identified, so the bytes already sent cannot be shown to belong to it",
        };
    };

    // Nothing staged: a fresh start is correct, and only correct because we
    // just proved the source is unchanged.
    if (!partial.exists) return if (confirmed == 0) .start_over else .{
        .partial_mismatch = "the staging partial disappeared after bytes were confirmed",
    };

    // Shorter than our confirmed offset means bytes we had counted are gone —
    // nothing there can be trusted as a prefix of what we sent.
    if (partial.len < confirmed) return .{ .partial_mismatch = "the staging partial is shorter than the confirmed offset" };

    // Length is not content. Any resume from a non-zero offset appends to
    // bytes we are about to stop looking at, so those bytes must be proven,
    // not counted: a partial of exactly the right length can be a different
    // file, a half-written retry, or another writer's work. Both the recorded
    // hash and the observed one must exist and agree — an equal length with
    // no hash used to be enough, which meant the strictness below only ever
    // applied to the interrupted case and never to the clean-looking one.
    if (confirmed > 0) {
        const recorded = checkpoint.partial_sha256 orelse
            return .{ .partial_mismatch = "no prefix hash was recorded for the bytes already confirmed, so they cannot be proven to be ours" };
        const observed = partial.prefix_sha256 orelse
            return .{ .partial_mismatch = "the partial's prefix hash was not read back for comparison" };
        if (!std.mem.eql(u8, recorded, observed))
            return .{ .partial_mismatch = "the staging partial's content does not match the checkpoint" };
    }

    // Longer is the *normal* shape of an interruption, not a fault: the writer
    // confirms an offset only after the far side acknowledges it, so a cut
    // mid-write leaves bytes there that were never confirmed. Rejecting this
    // outright — as this function used to — made resume unreachable in exactly
    // the case resume exists for.
    //
    // Those unconfirmed bytes still prove nothing, so they are not counted and
    // not trusted; the head was proven just above, and only that licenses
    // cutting the tail away. Proving first is the whole ordering.
    if (partial.len > confirmed) return .{ .truncate_then_resume = .{
        .offset = confirmed,
        .partial_len = partial.len,
    } };
    return .{ .resume_from = confirmed };
}

/// Why the source is not the one the checkpoint was written against, or null.
///
/// Exhaustive over the source union and over the *pairing*: a checkpoint that
/// recorded a local file cannot be re-proved by observing a remote one, even
/// at the same path, because the two are different machines' idea of that
/// path.
fn sourceChanged(recorded: SourceIdentity, observed_opt: ?SourceIdentity) ?[]const u8 {
    const observed = observed_opt orelse return "the source is gone";
    if (std.meta.activeTag(recorded) != std.meta.activeTag(observed))
        return "the source is a different kind of thing than the checkpoint recorded";

    switch (recorded) {
        .local_file, .remote_file => {
            const was = recorded.file().?;
            const now = observed.file().?;
            if (!std.mem.eql(u8, was.path, now.path)) return "the source path changed";
            if (was.size) |recorded_size| {
                const current = now.size orelse return "the source size is unavailable for comparison";
                if (current != recorded_size) return "the source size changed";
            }
            if (was.mtime_ns) |recorded_mtime| {
                const current = now.mtime_ns orelse return "the source mtime is unavailable for comparison";
                if (current != recorded_mtime) return "the source mtime changed";
            }
            if (was.sha256) |recorded_hash| {
                const current = now.sha256 orelse return "the source hash is unavailable for comparison";
                if (!std.mem.eql(u8, recorded_hash, current)) return "the source content changed";
            }
            return null;
        },
        .http => |was| {
            const now = observed.http;
            if (!std.mem.eql(u8, was.url, now.url)) return "the source URL changed";
            // A ranged resume splices bytes fetched at two different moments
            // into one file. Only a strong validator says those moments saw
            // the same object; a matching size says the second one is the same
            // length, which is not the same claim.
            const recorded_tag = was.etag orelse was.last_modified orelse
                return "the source offered no validator when the transfer started, so a ranged resume cannot be proven safe";
            const current_tag = now.etag orelse now.last_modified orelse
                return "the source no longer offers a validator";
            if (!std.mem.eql(u8, recorded_tag, current_tag)) return "the source validator changed";
            return null;
        },
    }
}

/// Advances the confirmed offset. `offset` must be the end of the contiguous
/// completed prefix, never the highest finished chunk.
///
/// Four guards, each of which used to be the caller's problem:
///
/// * `request_id = ?6` — only the operation that currently owns the checkpoint
///   may write to it. Without this a displaced owner, still holding the row id
///   from before a resume adopted it away, would keep writing its own progress
///   over the new operation's.
/// * `?1 > confirmed_offset` — a regressing offset matches no row. A late reply
///   from an earlier chunk could otherwise walk the durable offset backwards,
///   and the next resume would re-send bytes it had confirmed, or worse, trust
///   a prefix hash taken at the higher offset.
/// * `?1 = confirmed_offset AND partial_sha256 IS ?3` — a re-confirm at the
///   same offset is allowed only if it reads the same bytes. Same-offset
///   confirms are *routine*, not suspicious: they happen after every
///   truncate-then-resume, and whenever `contiguousPrefix` comes back unchanged
///   because a chunk closed on the far side of a gap. Banning equality would
///   break the ordinary path; the rule is that an unchanged offset must carry
///   an unchanged digest, because two different digests for one offset means
///   one of the two readings is wrong and nothing here can tell which.
///   `IS`, not `=`: a fresh row is `(0, NULL)` and callers do confirm `(0, 0,
///   null)`, which under `=` would be `NULL = NULL` → unknown → zero rows.
///   The `>` branch deliberately does not filter on null-ness at all, so an
///   advance with no digest still reaches the schema's
///   `confirmed_offset = 0 OR partial_sha256 IS NOT NULL` CHECK and fails there
///   as a constraint violation rather than being quietly dropped here.
/// * the `acceptsOffset` list — a settled or post-byte checkpoint cannot be
///   advanced. Writing progress into a failed or published row would make it
///   resumable again.
///
/// The prefix hash is a plain assignment, not a `COALESCE`. Under COALESCE, a
/// caller passing null kept the *previous* offset's hash while the offset
/// moved on, so the pair stopped describing the same bytes — and that pair is
/// exactly what `verifyResume` compares. The schema now refuses the null
/// outright whenever the offset is non-zero.
pub fn confirmOffset(
    store: *Store,
    id: i64,
    owner_request_id: []const u8,
    offset: u64,
    partial_len: u64,
    prefix_sha256: ?[]const u8,
    now: i64,
) Error!void {
    var stmt = try store.db.prepare(confirm_offset_sql);
    defer stmt.deinit();
    try stmt.bindInt(1, @intCast(offset));
    // `partial_len` is recorded, and nothing reads it back. It is not tied to
    // `confirmed_offset` by the schema, by this statement, or by any guard, and
    // `verifyResume` takes the partial's length from a fresh stat of the file —
    // never from this column, because a length we last wrote down is not
    // evidence of a length on disk. Treat it as a diagnostic breadcrumb; a
    // future reader who mistakes it for the authoritative length will build a
    // resume on a number that no one has checked since it was stored.
    try stmt.bindInt(2, @intCast(partial_len));
    try stmt.bindOptText(3, prefix_sha256);
    try stmt.bindInt(4, now);
    try stmt.bindInt(5, id);
    try stmt.bindText(6, owner_request_id);
    _ = try stmt.step();
    if (store.db.changes() != 0) return;

    const row = try ownedRow(store, id, owner_request_id);
    if (!row.state.acceptsOffset()) return error.IllegalCheckpointTransition;
    // Existence, ownership and state are cleared, so the offset conjunct is
    // what refused it, and it has exactly two ways to fail.
    if (@as(i64, @intCast(offset)) < row.confirmed_offset) return error.CheckpointNotAdvanced;
    return error.PrefixHashConflict;
}

const confirm_offset_sql = std.fmt.comptimePrint(
    \\UPDATE transfer_checkpoints
    \\   SET confirmed_offset = ?1, partial_len = ?2,
    \\       partial_sha256 = ?3, updated_at = ?4
    \\ WHERE id = ?5 AND request_id = ?6
    \\   AND (?1 > confirmed_offset
    \\        OR (?1 = confirmed_offset AND partial_sha256 IS ?3))
    \\   AND state IN ({s})
, .{accepts_offset_sql});

/// Moves a checkpoint to a new state, if the graph has that edge and the row
/// carries whatever evidence that state asserts.
///
/// The guard is `state IN (<predecessors of this exact target>)`, rendered from
/// `predecessors` at comptime — which is why the target has to be
/// comptime-known and why this dispatches with `inline else`, producing one
/// prepared statement per target. The alternative, a single "is it still
/// movable" list, is what let `planned → published` through: an artifact
/// recorded as published without a byte of it ever having been hashed.
///
/// For the two end states the target also adds an evidence conjunct — see
/// `evidenceClause`. Ordering the walk was never enough on its own: every edge
/// of `planned→probing→transferring→verifying→publishing→published` is legal
/// for a transfer that confirmed no bytes and read back no digest, so the
/// statement has to ask what the row actually holds.
///
/// `request_id = ?5` is the other half. A checkpoint has exactly one owner at a
/// time, and a resume moves that ownership with `adopt`; a displaced owner that
/// kept writing would be reporting on a transfer it no longer runs.
///
/// Terminals stay terminal *for this writer*, and the two exceptions the graph
/// names both belong to somebody else. `indeterminate_publish` is not settled,
/// it is *unjudged*, and its four outgoing edges belong to `adjudicateLocked`;
/// every failure has one edge to `superseded`, and it belongs to
/// `supersedeLocked`. Enforced, not merely intended: the statement rendered here
/// is given `Route.transition`, whose predecessor lists have both sets
/// subtracted, so a driver aiming `published` at a parked row is refused
/// `CheckpointAwaitingAdjudication` and one aiming `superseded` at its own
/// failure is refused `SupersessionIsNotATransition`. Beyond those, no terminal
/// is anybody's predecessor. That matters beyond tidiness: the
/// destination-holding states are what the unique index covers, so reviving a
/// settled row would re-enter the set that is supposed to hold one transfer per
/// destination, and could collide with the transfer that replaced it.
pub fn setState(
    store: *Store,
    id: i64,
    owner_request_id: []const u8,
    to: State,
    failure_reason: ?[]const u8,
    now: i64,
) TransitionError!void {
    switch (to) {
        inline else => |target| return transitionLocked(
            store,
            id,
            owner_request_id,
            target,
            .transition,
            failure_reason,
            now,
        ),
    }
}

/// Records what a resolution established about a rename nobody watched.
///
/// `indeterminate_publish` is the one state that looks terminal and is not. The
/// rename may have landed, so the row goes on holding its destination until
/// something can say which way it went — and until this existed, nothing could:
/// the state was nobody's predecessor, it is not adoptable, and no code
/// anywhere deletes a `transfer_checkpoints` row. Every later `create` aimed at
/// that path was answered `DestinationHeld`, permanently.
///
/// The sole writer of those four edges, and the statement is what makes that
/// true rather than a convention: `Route.adjudication` renders a predecessor
/// list of exactly `indeterminate_publish`, and the list `setState` renders has
/// that state subtracted. A driver cannot reach these edges, and this cannot
/// reach a driver's — an adjudication aimed at a row that was never parked is
/// `CheckpointNotAwaitingAdjudication`. Without the split the guarantee ran the
/// wrong way round: the evidence rules in `receipts.publishAdjudication` decide
/// what may be recorded about a rename nobody watched, and `setState` sat
/// underneath them able to record it with no evidence at all.
///
/// Only the four outcomes of a rename are accepted, and the check is at
/// runtime rather than in the type because the target is *derived* from
/// evidence: `receipts.resolve` maps it from the variant it has just admitted,
/// so a four-member enum would move the decision one function earlier without
/// removing it, and the mapping is where a mistake would live. Anything else is
/// `NotAnAdjudicationTarget` — refused, never coerced to the nearest legal
/// state.
///
/// `failed_hash_mismatch` is the one target that reads oddly, so it is stated
/// rather than left to be inferred: it is a *failure* verdict reached from a
/// *present* artifact. The reconciler looked, the file is there, and it hashes
/// to something other than what this transfer promised before it sent a byte.
/// The literal meaning of the state — the digest did not match — is exactly what
/// was proven, and nothing about it is softened by the artifact existing. What
/// makes the verdict safe is that a failure keeps its hold: `holdsDestination`
/// covers every `failed_*`, so the row goes on claiming the path and the next
/// transfer aimed there is refused rather than clobbering bytes an operator has
/// not looked at. Releasing it is `supersedeLocked`'s job, deliberately, because
/// discarding somebody else's wrong artifact is a decision and not a deduction.
///
/// `Locked`: statement only, no transaction of its own. `receipts.resolve`
/// calls it inside the transaction that writes `resolved_status`, so the
/// operation's verdict and the checkpoint's adjudication either both land or
/// neither does. Opening one here would leave a window in which the ledger says
/// the transfer was settled while the path is still held against everyone.
///
/// `published` reached this way is not a weaker `published`. It goes through
/// the same statement as `setState`, evidence conjunct included, so a
/// resolution cannot record an artifact as published against a checkpoint that
/// never read a digest back off it. That will surprise a reader who expects
/// adjudication to be the last word: it is the last word on whether the *rename*
/// landed, and no word at all on what the bytes were.
///
/// `reading` is how the reconciler's own hash of the destination gets to be that
/// digest, and it exists because without it the row was wedged. A transfer that
/// declared a digest, entered `publishing` without recording one, and was killed
/// there normalises to `indeterminate_publish`; an operator hashes the artifact,
/// it matches the declaration, `publishAdjudication` says `published` — and the
/// transition refuses, because the column the dead process never wrote is still
/// null. Nothing could ever write it: `acceptsVerifiedHash` excludes the parked
/// state, `completed_unverified` refuses a row whose digest agrees, and no other
/// edge exists. The path was closed by paperwork, on the one row where the
/// reconciler's reading is *better* evidence than the column — it was taken off
/// the published artifact, after the fact, and compared against a commitment
/// made before a byte moved.
///
/// It is recorded by a statement of its own rather than folded into the
/// transition's `SET`, because SQL evaluates a `WHERE` against the row as it
/// stands: a digest arriving in the same statement could never satisfy
/// `verified_sha256 IS NOT NULL`.
///
/// Two targets take a reading, and they take it differently, because the column
/// means the same thing in both and the rows they start from do not.
///
///  * `published` writes `COALESCE(verified_sha256, ?)`. A digest the transfer
///    recorded for itself is the better evidence of the two and must not be
///    overwritten by a reconciler's; the transition that follows then compares
///    whatever is in the column against `expected_sha256` and refuses with
///    `PublishHashContradictsDeclared` if they differ.
///  * `failed_hash_mismatch` writes the reading outright. Here the two readings
///    are of *different bytes*: a parked row's digest was taken off the staged
///    file while `verifying`, before the rename, and this one is taken off what
///    is at the destination now. The state records what is at the destination,
///    so that is what the column has to hold — and if the pre-rename digest
///    survived, the row would end up a `failed_hash_mismatch` whose columns say
///    the digest agreed. That row is refused outright by
///    `HashMismatchWithAgreeingDigest` (see `evidenceClause`), so an
///    adjudication that supplied no reading cannot reach the state at all
///    rather than reaching it and contradicting itself. This file claimed in
///    three places that such a row could not exist and nothing enforced it; the
///    conjunct is the enforcement and this write is what keeps the honest case
///    from being wedged by it.
///
/// The pre-rename digest is not silently dropped: `receipts.resolve` writes the
/// reconcile event in this same transaction, carrying the reading it admitted
/// and the `declaredSha256` it contradicts — see `ResolutionEvidence.toJson`.
pub fn adjudicateLocked(
    store: *Store,
    id: i64,
    owner_request_id: []const u8,
    to: State,
    reading: ?[]const u8,
    now: i64,
) AdjudicateError!void {
    try store.db.requireTransaction();
    if (reading) |sha256| switch (to) {
        .published => try recordAdjudicatedReading(store, id, owner_request_id, sha256, .keep_existing, now),
        .failed_hash_mismatch => try recordAdjudicatedReading(store, id, owner_request_id, sha256, .replace, now),
        else => {},
    };
    switch (to) {
        inline .published,
        .completed_unverified,
        .failed_publish,
        .failed_hash_mismatch,
        => |target| return transitionLocked(
            store,
            id,
            owner_request_id,
            target,
            .adjudication,
            adjudicationReason(target),
            now,
        ),
        else => return error.NotAnAdjudicationTarget,
    }
}

/// Whether a reading may stand in for a digest already in the column, or has to
/// replace it. See `adjudicateLocked`.
const ReadingWrite = enum {
    /// `published`: the transfer's own reading wins if it has one.
    keep_existing,
    /// `failed_hash_mismatch`: the reading is of the published artifact and the
    /// column may be carrying a digest of the staged bytes instead.
    replace,
};

/// Puts a reconciler's reading of the destination where the transition looks
/// for one. See `adjudicateLocked`.
///
/// Guarded on the parked state and on the owner, like every other write here.
/// The `keep_existing` assignment is a `COALESCE` rather than a plain set, so it
/// is write-once without a `verified_sha256 IS NULL` conjunct — which matters:
/// with that conjunct the statement would match no row for a checkpoint that
/// *does* already carry a digest, and a zero-row UPDATE here has to mean a
/// refusal rather than "there was nothing to do".
fn recordAdjudicatedReading(
    store: *Store,
    id: i64,
    owner_request_id: []const u8,
    sha256: []const u8,
    comptime mode: ReadingWrite,
    now: i64,
) TransitionError!void {
    {
        var stmt = try store.db.prepare(comptime recordAdjudicatedReadingSql(mode));
        defer stmt.deinit();
        try stmt.bindText(1, sha256);
        try stmt.bindInt(2, now);
        try stmt.bindInt(3, id);
        try stmt.bindText(4, owner_request_id);
        _ = try stmt.step();
    }
    if (store.db.changes() != 0) return;

    // Existence and ownership come back under their own names; the only other
    // conjunct is the parked state, and a row that is not parked is not one an
    // adjudication has any business writing to.
    _ = try ownedRow(store, id, owner_request_id);
    return error.CheckpointNotAwaitingAdjudication;
}

fn recordAdjudicatedReadingSql(comptime mode: ReadingWrite) [:0]const u8 {
    return std.fmt.comptimePrint(
        \\UPDATE transfer_checkpoints
        \\   SET verified_sha256 = {[assign]s}, updated_at = ?2
        \\ WHERE id = ?3 AND request_id = ?4
        \\   AND state = '{[parked]s}'
    , .{
        .assign = switch (mode) {
            .keep_existing => "COALESCE(verified_sha256, ?1)",
            .replace => "?1",
        },
        .parked = @tagName(State.indeterminate_publish),
    });
}

/// What goes in `failure_reason` when adjudication settles a publish.
///
/// Provenance, not diagnosis. Nothing on this path observed the rename — that
/// is why the row was parked — so the only honest thing to record against it is
/// which mechanism decided. *Why* it decided that is in the reconcile event
/// `receipts.resolve` writes in the same transaction, with the evidence
/// attached.
fn adjudicationReason(comptime to: State) ?[]const u8 {
    return switch (to) {
        .published, .completed_unverified => null,
        .failed_publish => "adjudicated by the operation's resolution",
        // Same provenance, and the diagnosis it does add is the one thing this
        // path *did* observe rather than deduce: a reading was taken at the
        // destination and it disagreed. Both digests are on the reconcile event
        // — the one that was read in the evidence, the one that was promised in
        // `declaredSha256` — because this column is a fixed string and cannot
        // carry them.
        .failed_hash_mismatch => "adjudicated by the operation's resolution: the destination was read and its digest contradicts the declared one",
        else => @compileError("not an adjudication target: " ++ @tagName(to)),
    };
}

/// The one statement behind `setState` and `adjudicateLocked`, and the
/// classifier for when it matches nothing.
///
/// `route` picks which half of each target's predecessor list the statement
/// accepts, so the two writers cannot reach each other's edges — see `Route`.
fn transitionLocked(
    store: *Store,
    id: i64,
    owner_request_id: []const u8,
    comptime target: State,
    comptime route: Route,
    failure_reason: ?[]const u8,
    now: i64,
) TransitionError!void {
    {
        var stmt = try store.db.prepare(comptime setStateSql(target, route));
        defer stmt.deinit();
        try stmt.bindText(1, target.text());
        try stmt.bindOptText(2, failure_reason);
        try stmt.bindInt(3, now);
        try stmt.bindInt(4, id);
        try stmt.bindText(5, owner_request_id);
        _ = try stmt.step();
    }
    if (store.db.changes() != 0) return;

    // Existence and ownership come back under their own names. What is left is
    // the transition list and, for the two end states, the evidence — answered
    // in the order the statement conjoins them, because a row that cannot make
    // this move at all is not made movable by better evidence.
    //
    // The graph is read here and deliberately not read before the write: the
    // write has already happened (or not), so this only chooses the wording of
    // a refusal, which is the same latitude `ownedRow`'s re-read takes.
    const row = try ownedRow(store, id, owner_request_id);
    if (routeAllows(route, row.state, target)) switch (target) {
        .published => {
            if (!row.has_verified_hash) return error.PublishNeedsVerifiedHash;
            if (!row.hash_matches_declared) return error.PublishHashContradictsDeclared;
        },
        .completed_unverified => {
            if (row.has_verified_hash) return error.CompletedUnverifiedHasVerifiedHash;
            if (row.has_declared_hash) return error.CompletedUnverifiedHasDeclaredHash;
        },
        .failed_hash_mismatch => if (row.claims_hash_agreed)
            return error.HashMismatchWithAgreeingDigest,
        else => {},
    };
    // The edge exists but belongs to another writer. A name per owner rather
    // than one `IllegalCheckpointTransition`, because the mistakes are
    // different and a caller acts on them differently: a driver that reached a
    // parked row has to stop and let a resolution judge it, an adjudication
    // aimed at a row that was never parked was aimed at the wrong row, and a
    // driver reaching for `superseded` is asking to discard its own leftovers
    // without anyone having agreed to it.
    if (canTransition(row.state, target)) return switch (ownerOf(target, row.state)) {
        .transition => error.CheckpointNotAwaitingAdjudication,
        .adjudication => error.CheckpointAwaitingAdjudication,
        .supersession => error.SupersessionIsNotATransition,
    };
    return error.IllegalCheckpointTransition;
}

/// What each end state asserts about the row, as the conjunct that enforces it.
///
/// `published` says the right bytes are at the destination, so it needs a
/// digest read back off the result, and — when the transfer declared one in
/// advance — needs the two to agree. `completed_unverified` says the opposite:
/// bytes arrived and nothing trustworthy proved they were the right ones. In
/// one statement each, the two are mechanically exclusive, which is what stops
/// `completed_unverified` from being the name of a state nothing ever reaches
/// while `published` quietly absorbs both outcomes.
///
/// A null `expected_sha256` is admitted by `published`: a transfer is not
/// obliged to declare a digest up front, and one that read its result back and
/// has nothing to contradict it has still verified more than nothing. What is
/// refused is a declaration the reading disagrees with.
///
/// `completed_unverified` asks for the absence of *both* digests, and the
/// second half is not decoration. "No trustworthy hash or object validator was
/// available" is the state's meaning, and a transfer that named the digest that
/// would prove it landed — before it sent a byte — had one available. Admitting
/// such a row here releases the destination hold (`holdsDestination` is false
/// for this state) and settles the operation `completed` with the declaration
/// never compared against anything. `receipts.resolve` already refuses that
/// shape on the adjudication route, so without this conjunct the same act was
/// refused when it arrived through a crash and admitted when it arrived through
/// the happy path — the lenient one being the path that is taken every time.
///
/// `failed_hash_mismatch` asks that the row not *claim* agreement. The state
/// says the digest did not match; a row in it whose `verified_sha256` equals
/// its `expected_sha256` says the opposite in its columns, and this file
/// asserted that such a row cannot exist in three separate comments while
/// nothing stopped one. Written as "does not claim agreement" rather than
/// "claims disagreement" so that the two honest silences still pass: a row that
/// declared nothing has nothing to disagree with, and one that read nothing
/// back has not spoken. What is refused is the self-contradiction.
///
/// Exhaustive with no `else`, so a new end state has to declare what it claims
/// rather than inheriting silence.
fn evidenceClause(comptime to: State) []const u8 {
    return switch (to) {
        .published => "\n   AND " ++ has_verified_hash_sql ++
            "\n   AND " ++ hash_matches_declared_sql,
        .completed_unverified => "\n   AND " ++ no_verified_hash_sql ++
            "\n   AND " ++ no_declared_hash_sql,
        .failed_hash_mismatch => "\n   AND NOT " ++ claims_hash_agreed_sql,
        .planned,
        .probing,
        .transferring,
        .paused,
        .verifying,
        .publishing,
        .failed_source_changed,
        .failed_remote_partial_mismatch,
        .failed_no_space,
        .failed_clobber_conflict,
        .failed_publish,
        .indeterminate_publish,
        .superseded,
        => "",
    };
}

/// The digest facts, as SQL, written once and used twice: in the guard
/// that refuses the write and in the classifier that names which conjunct did
/// it. Two copies would let the refusal start naming a conjunct the statement
/// no longer evaluates, which is worse than a generic refusal.
const has_verified_hash_sql = "verified_sha256 IS NOT NULL";
const hash_matches_declared_sql = "(expected_sha256 IS NULL OR verified_sha256 = expected_sha256)";
const no_verified_hash_sql = "verified_sha256 IS NULL";
const no_declared_hash_sql = "expected_sha256 IS NULL";
/// Both digests present and equal — the row asserting, in its columns, that
/// what landed is what was promised. Deliberately not `NOT
/// hash_matches_declared_sql`: that fragment reads *true* when nothing was
/// declared, so negating it would refuse a `failed_hash_mismatch` on a transfer
/// that declared no digest, which is a different row and not a contradictory
/// one.
const claims_hash_agreed_sql =
    "(expected_sha256 IS NOT NULL AND verified_sha256 = expected_sha256)";

/// What a target state *unwrites*, as the assignment that enforces it.
///
/// One state has such a rule. `paused` means "interrupted but resumable: the
/// checkpoint is trustworthy", and a resume re-reads the source, re-proves the
/// partial's confirmed head and truncates whatever unconfirmed tail is beyond
/// it. A verification digest that arrived before all that describes bytes the
/// resume is entitled to change, so it cannot survive into `paused` — and until
/// this existed it did, with two consequences that compound:
///
///  * the heir re-hashes after resuming and `recordVerifiedHash` refuses its
///    reading with `VerifiedHashLocked`, which says the row already has one and
///    does not say a *different* one, so a disagreement between the dead
///    attempt's digest and the live one is discarded behind a name that never
///    mentions it;
///  * `setState(.published)` then matches, because the evidence conjuncts
///    compare `verified_sha256` against `expected_sha256` and both were frozen
///    before the interruption. The row is recorded published on a digest the
///    dead process computed over bytes the live one replaced.
///
/// The reachable way in is `recoverLocked`'s `verifying → paused`, which is
/// precisely the state pair where a digest can already exist. The other two
/// predecessors of `paused` cannot carry one at all — `acceptsVerifiedHash`
/// admits only `verifying` and `publishing` — so this is a no-op there and is
/// written for the target rather than for that one edge, because the rule
/// belongs to what `paused` means and not to how a row got there.
///
/// The digest is *lost* from the working record; nothing else stored it.
/// `execution.recoverCheckpoint` reads it before the recovery and puts it on
/// both sides' receipts, so the ledger keeps what the checkpoint table stops
/// claiming. A driver pausing of its own accord loses it with no receipt, and
/// that is the honest trade: a digest kept past the point where it describes
/// anything is not evidence, it is a trap for the next writer.
fn clearClause(comptime to: State) []const u8 {
    return if (comptime discardsVerifiedHash(to)) ",\n       verified_sha256 = NULL" else "";
}

/// Whether arriving at `to` invalidates a digest taken before it.
///
/// The single place that rule lives, because it has two readers that must not
/// be able to disagree: `clearClause` renders the SQL that empties the column,
/// and `execution.recoverCheckpoint` decides from it whether a hand-over receipt
/// may say a digest was discarded. Between them they are "the column is empty"
/// and "here is what used to be in it".
///
/// They did disagree. Recovery read the digest unconditionally and reported it
/// as discarded on both receipts, so a `publishing → indeterminate_publish`
/// recovery — which keeps its digest, because the bytes went to a rename and
/// nobody may truncate them now — filed two receipts announcing the loss of a
/// digest that is still sitting in the row.
///
/// Exhaustive with no `else`, so a new state has to say whether reaching it
/// invalidates a reading taken before it.
pub fn discardsVerifiedHash(to: State) bool {
    return switch (to) {
        .paused => true,
        .planned,
        .probing,
        .transferring,
        .verifying,
        .publishing,
        .published,
        .completed_unverified,
        .failed_source_changed,
        .failed_remote_partial_mismatch,
        .failed_hash_mismatch,
        .failed_no_space,
        .failed_clobber_conflict,
        .failed_publish,
        .indeterminate_publish,
        .superseded,
        => false,
    };
}

fn setStateSql(comptime to: State, comptime route: Route) [:0]const u8 {
    return std.fmt.comptimePrint(
        \\UPDATE transfer_checkpoints
        \\   SET state = ?1, failure_reason = ?2, updated_at = ?3{[clear]s}
        \\ WHERE id = ?4 AND request_id = ?5
        \\   AND state IN ({[predecessors]s}){[evidence]s}
    , .{
        .clear = clearClause(to),
        .predecessors = predecessorList(to, route),
        .evidence = evidenceClause(to),
    });
}

/// Re-points a resumable checkpoint at the operation that is resuming it.
///
/// A resume is a new operation with a new `request_id`, and `UNIQUE(request_id)`
/// means the row cannot simply be copied. The checkpoint is a mutable working
/// record — it tracks where the bytes got to — while the ledger is the audit
/// trail, so moving it is correct and losing the trail would not be.
///
/// `expected_owner` is the operation handing the checkpoint over, and naming
/// it makes the hand-off a compare-and-swap: two resumes racing for the same
/// abandoned transfer cannot both believe they won it.
///
/// Refuses anything that is not `isAdoptable`, and changes no state: an heir
/// picks the transfer up exactly where the row says it stands. A settled
/// checkpoint would hand a new operation an offset into a partial the failure
/// already declared untrustworthy, and a `verifying` or `publishing` one has no
/// offset left to resume from — those two are `recoverLocked`'s business, which
/// normalises them first.
///
/// Everything else about the hand-over — the incumbent rule, the heir clause,
/// the classifier — is `handoverLocked`'s and is shared with recovery. See
/// there.
///
/// Statement only, no transaction of its own, hence the name. The hand-over is
/// more than this row: both operations need a `checkpoint` observation naming
/// the other, and a hand-over recorded on one side only reads as fact while
/// being half a lie. Those writes live in `execution.Execution.adoptCheckpoint`,
/// which wraps all three in one transaction. They cannot live here: `receipts`
/// imports this module to read a declared digest, and importing it back would
/// close that loop.
pub fn adoptLocked(
    store: *Store,
    id: i64,
    expected_owner: []const u8,
    new_request_id: []const u8,
    now: i64,
) Error!void {
    return handoverLocked(
        store,
        id,
        expected_owner,
        new_request_id,
        now,
        adopt_sql,
        State.isAdoptable,
        error.CheckpointNotResumable,
    );
}

/// Takes over a checkpoint whose owner stopped in the middle of an act, and
/// puts the row where that leaves it.
///
/// Two writes, in this order, and the order is the whole design:
///
///  1. the ownership CAS, guarded on `isRecoverable` — the states only a
///     running process can be in and only its owner can leave;
///  2. the normalisation, through `transitionLocked` on the ordinary route,
///     keyed on the *new* owner because by then it is the owner.
///
/// Doing it the other way round is not possible and should not be: the
/// normalisation is an ordinary transition, so it is keyed on whoever owns the
/// row, and a heir writing one before the CAS would be writing as the dead
/// attempt. Doing the normalisation through a private statement is what the
/// route partition exists to prevent — recovery would then be a writer that can
/// move a checkpoint along an edge nobody else has, which is exactly how
/// `setState` came to be able to adjudicate.
///
/// Returns the state the row was normalised *into*, because the two outcomes
/// are different situations for the caller: `paused` is resumable and
/// `indeterminate_publish` is not — it is waiting for somebody to establish
/// whether the rename landed.
///
/// Recovery does not delete, does not release the destination, and does not
/// decide anything about the transfer. It moves the row to the state an
/// interrupted act leaves it in, so the ordinary machinery — resume,
/// adjudication — can reach it again.
///
/// `Locked`: statement only. The composite is more than these two writes — both
/// operations have to record the hand-over — and that transaction belongs to
/// `execution.Execution.recoverCheckpoint`, for the same reason `adoptLocked`'s
/// does.
pub fn recoverLocked(
    store: *Store,
    id: i64,
    abandoned_by: []const u8,
    new_request_id: []const u8,
    now: i64,
) Error!State {
    try store.db.requireTransaction();
    try handoverLocked(
        store,
        id,
        abandoned_by,
        new_request_id,
        now,
        recover_sql,
        State.isRecoverable,
        error.CheckpointNotRecoverable,
    );

    // The CAS matched, so the row exists, is ours, and was in a recoverable
    // state a moment ago inside this transaction. It is re-read rather than
    // assumed, because the target of the normalisation depends on which of the
    // two it was and this is the only place that knows.
    const taken = try rowState(store, id);
    switch (taken) {
        inline else => |s| {
            const target = comptime s.abandonedNormalisation();
            // Comptime-known per branch, so only one arm of this is compiled
            // into each. The refusal is here rather than `unreachable` because
            // the guard that makes it dead is a SQL list in another statement:
            // if the two ever disagree, the cost is a refused recovery and a
            // rolled-back transaction, not a crashed process.
            if (target == null) return error.CheckpointNotRecoverable;
            try transitionLocked(
                store,
                id,
                new_request_id,
                comptime target.?,
                .transition,
                recovery_reason,
                now,
            );
            return comptime target.?;
        },
    }
}

/// What goes in `failure_reason` when a recovery normalises an abandoned row.
///
/// Provenance, like `adjudicationReason` and `supersedeLocked`'s prose: the
/// column is where a row's last state change explains itself, and the one thing
/// a person reading a recovered `paused` row has to know is that nothing
/// re-confirmed its offset since its owner stopped. Who took it over is in both
/// operations' receipts, which is where a caller should read it; this is free
/// text and is not joinable.
const recovery_reason = "recovered from an owner that stopped mid-transfer";

/// The body both hand-overs share: run the CAS, and if it matched nothing, say
/// which conjunct refused it.
///
/// `sql` and `eligible` are the two halves of the state window — the list the
/// statement guards on and the predicate it was rendered from — and they are
/// passed together so a caller cannot pair one window's statement with
/// another's classifier. Everything else is identical between adopting a
/// resumable row and recovering an abandoned one, and was worth having in one
/// place: the incumbent rule and the heir clause are the two things a hand-over
/// is *for*, and a second copy of either is a second thing to keep in step.
fn handoverLocked(
    store: *Store,
    id: i64,
    expected_owner: []const u8,
    new_request_id: []const u8,
    now: i64,
    comptime sql: [:0]const u8,
    comptime eligible: fn (State) bool,
    comptime wrong_state: Error,
) Error!void {
    try store.db.requireTransaction();
    var stmt = try store.db.prepare(sql);
    defer stmt.deinit();
    try stmt.bindText(1, new_request_id);
    try stmt.bindInt(2, now);
    try stmt.bindInt(3, id);
    try stmt.bindText(4, expected_owner);
    _ = try stmt.step();
    if (store.db.changes() != 0) return;

    // Losing this CAS and being displaced are the same SQL conjunct failing,
    // but they are different situations to be in and the caller acts on them
    // differently: a writer told `CheckpointNotOurs` must stop, while an heir
    // told it lost a race to another resume and may re-read and decide again.
    const row = ownedRow(store, id, expected_owner) catch |err| switch (err) {
        error.CheckpointNotOurs => return error.CheckpointOwnerChanged,
        else => |other| return other,
    };
    if (!eligible(row.state)) return wrong_state;
    // Asked before the heir clause because the two refusals point in opposite
    // directions: this one says the heir is fine and the incumbent has to be
    // reconciled first, and telling a perfectly fit heir it was ineligible
    // would send it looking for a fault it does not have.
    if (try incumbentBlocksScope(store, expected_owner))
        return error.SurrenderingOperationMayStillBeRunning;
    // Existence, ownership, the state list and the incumbent are all cleared,
    // so the only conjunct left to have refused it is the one about the heir.
    return error.AdoptingOperationNotEligible;
}

/// Whether the attempt being displaced may still be affecting the remote host.
///
/// Read only to name a refusal that has already happened, never to authorize
/// one: the rule itself is enforced inside the hand-over statement, in the same
/// statement as the write, because a status checked here could change before the
/// UPDATE landed.
///
/// Both columns, in the shape `releasesScopeSql` renders — a resolution is read
/// only where it means something, on an `indeterminate` row. `receipts.resolve`
/// never overwrites `status`; it records the later-proven truth beside it, so
/// an attempt reconciled out of `indeterminate` still reads `indeterminate` in
/// the column a naive check would look at, and would be refused a hand-over
/// forever despite somebody having proved what it did.
fn incumbentBlocksScope(store: *Store, request_id: []const u8) Error!bool {
    var stmt = try store.db.prepare(
        "SELECT status, resolved_status FROM operations WHERE request_id = ?1",
    );
    defer stmt.deinit();
    try stmt.bindText(1, request_id);
    // `transfer_checkpoints.request_id` is a foreign key into `operations` and
    // foreign keys are on, so a checkpoint whose owner does not exist means the
    // database is not the shape this binary was built against. Reported under
    // its own name rather than read as "not blocking", which would answer a
    // question about liveness with a fact about schema damage.
    if (!try stmt.step()) return error.SurrenderingOperationMissing;
    return statusPairBlocksScope(&stmt);
}

/// The Zig half of `releasesScopeSql`, over a statement whose first two columns
/// are `status` and `resolved_status`.
fn statusPairBlocksScope(stmt: *Db.Stmt) Error!bool {
    const status = try op_state.Status.parse(stmt.columnText(0));
    if (!status.blocksScope()) return false;
    if (status != .indeterminate) return true;
    const resolved = stmt.columnOptText(1) orelse return true;
    return !resolvedReleasesScope(try op_state.ResolvedStatus.parse(resolved));
}

/// The hand-over statement, over whichever state window the caller is entitled
/// to. Two conjuncts here are not obvious.
///
/// **The incumbent `EXISTS`** is the one that costs a caller something: the
/// attempt being displaced must not still be affecting the remote host. The
/// predicate is `releasesScopeSql`, the complement of the one the scope barrier
/// itself is written in, read off `status` and — on an `indeterminate` row —
/// off `resolved_status`.
///
/// It used to be `status IN (<terminal>)`, and that was wrong in the one way
/// that matters. `indeterminate` is terminal and means *nobody knows whether
/// the remote process stopped*, so a heir could take a partial away from an
/// attempt that may still be streaming into it — the exact failure the
/// conjunct was added to prevent, admitted by the predicate meant to prevent
/// it. What is required now is that either the attempt never reached the remote
/// (`created`, `connecting`), or it recorded an outcome that is not "unknown",
/// or somebody reconciled the unknown one.
///
/// What that reconcile is worth is exactly what `receipts.resolve` demanded for
/// it, and this conjunct does not decide that. An `operator_override` is
/// admissible evidence there, so a human may release this barrier by asserting
/// an outcome nobody measured — the same latitude an override already has over
/// the scope barrier itself, and the same trade: an attempt nothing mechanical
/// can settle would otherwise hold its partial forever. So the honest reading
/// of "the incumbent does not block scope" is *"the attempt provably never left
/// this machine, or something recorded an outcome for it that a reconciler was
/// willing to sign"* — not "a process disappearance was proved", which is what
/// this comment used to claim and what only the mechanical variants deliver.
///
/// **The heir's last conjunct** is the same-machine one. `dest_side` pins the
/// machine for a push and says `local` for the other two, so the CASE above
/// leaves a pull's *source* machine unchecked — and a pull's source is a remote
/// file whose only record of which host it lives on is the owning operation's
/// `server_id`. A hand-over is the single statement that changes that owner, so
/// without this a checkpoint describing `server1:/data/x.bin` could be handed
/// to an operation bound to server 2 and would then describe a different file
/// on a machine nobody compared. Stated once for all three directions rather
/// than only for the leaky one: a hand-over may not move a transfer to another
/// machine, and `IS` rather than `=` because a fetch has null on both sides.
fn handoverSql(comptime states: []const u8) [:0]const u8 {
    return std.fmt.comptimePrint(
        \\UPDATE transfer_checkpoints
        \\   SET request_id = ?1, updated_at = ?2
        \\ WHERE id = ?3
        \\   AND request_id = ?4
        \\   AND state IN ({[states]s})
        \\   AND EXISTS (
        \\     SELECT 1 FROM operations incumbent
        \\      WHERE incumbent.request_id = ?4
        \\        AND {[released]s})
        \\   AND EXISTS (
        \\     SELECT 1 FROM operations o
        \\      WHERE o.request_id = ?1
        \\        AND o.status IN ({[before_submission]s})
        \\        AND o.resolved_status IS NULL
        \\        AND o.kind = CASE direction WHEN 'push'  THEN 'transfer_push'
        \\                                    WHEN 'pull'  THEN 'transfer_pull'
        \\                                    WHEN 'fetch' THEN 'fetch' END
        \\        AND CASE direction
        \\              WHEN 'push'  THEN dest_side = 'server:' || CAST(o.server_id AS TEXT)
        \\              WHEN 'pull'  THEN (o.server_id IS NOT NULL AND dest_side = 'local')
        \\              WHEN 'fetch' THEN (o.server_id IS NULL AND dest_side = 'local')
        \\            END
        \\        AND o.server_id IS (SELECT server_id FROM operations WHERE request_id = ?4))
    , .{
        .states = states,
        .released = releasesScopeSql("incumbent"),
        .before_submission = op_before_submission_sql,
    });
}

/// The two windows, rendered from the two predicates. Same rules, different
/// answer to one question: is this row one an heir may continue, or one whose
/// owner stopped in the middle of something?
const adopt_sql = handoverSql(adoptable_sql);
const recover_sql = handoverSql(recoverable_sql);

/// Releases a failed transfer's hold on its destination, without deleting it.
///
/// `holdsDestination` keeps every failure on its path, so the next `create`
/// aimed there is refused until somebody says the leftovers may be discarded.
/// This is where they say it. The row is not deleted and nothing about it is
/// rewritten but its state: the partial, the offsets, both digests and the
/// failure that produced them all stay, because the reason an operator was
/// asked in the first place is that there is something at that path worth
/// knowing about.
///
/// **How "superseded" is represented, and why.** A new terminal state, not a
/// nullable `superseded_by` column. The deciding argument is not cost, it is
/// where the destination rule lives: `holdsDestination` is a total function of
/// `State`, and the partial unique index that enforces it is rendered from that
/// function. Represent supersession as a column and the index predicate has to
/// become `state IN (…) AND superseded_by IS NULL` — at which point "does this
/// row hold its destination" is no longer answerable from the state alone, and
/// the rule is split across a Zig predicate and a column exactly as it was
/// split across a predicate and five hand-copied SQL literals the last three
/// times it drifted. The costs run the same way: a state needs no schema change
/// at all (`state` has no CHECK, and a state excluded from `holdsDestination`
/// does not appear in the index predicate), while a column would be a fourth
/// in-place amendment of v11 and a fourth drift needle.
///
/// The price, stated plainly: the superseding request id goes into
/// `failure_reason`, which is free text with an inexact name. It is readable by
/// a person and not joinable by a query, and a column would have been both. It
/// is written by this statement alone and always in the same shape, but nothing
/// enforces that shape, so do not parse it — read the superseding operation's
/// own receipts instead, which is where a caller records the restart.
///
/// Two guards, both inside the statement:
///
/// * `state IN (<supersedable>)`. Only a settled *failure* may be superseded.
///   Superseding a live transfer would release a path a process may still be
///   writing to; superseding an unjudged publish would discard the open
///   question of whether the rename landed; superseding a published row would
///   erase the record that an artifact is there. See `State.isSupersedable`.
/// * the superseding request must exist. The single thing this call produces is
///   a record of who released the path, and a record naming an operation that
///   was never created reads as provenance while being none.
///
/// And one more that had to be added: **the owning attempt must not still be
/// affecting the remote host**, the same conjunct a hand-over carries, over the
/// checkpoint's own `request_id`. A `failed_*` state is a decision about the
/// *transfer*, written by `setState` — it says nothing about the operation that
/// wrote it, which may still be `submitted`, `remote_started` or
/// `indeterminate`, i.e. the remote copier may still exist and may still be
/// writing to the partial beside that path. Releasing a destination is a
/// strictly larger act than taking a partial, and it was the one asking for no
/// evidence at all. `terminus request reconcile <id>` is the way through, the
/// same as for a hand-over.
///
/// Deliberately *not* keyed on the checkpoint's owner. The whole situation is
/// that the owning attempt is over and somebody else wants the path, so
/// requiring the owner's `request_id` — as every other mutator here does — would
/// make the operation unreachable by the only caller it has. Requiring the owner
/// to be *settled* is a different demand and is the one that belongs here.
///
/// `Locked`: statement only. A restart is this write plus a new operation and a
/// new checkpoint, and a supersession that landed while the replacement failed
/// to would leave the path free with nothing on the way to it. The transaction
/// belongs to whoever sequences those three, which today is nobody: there is no
/// transfer CLI, so `--restart` has no wiring and this function has no caller.
/// That wiring belongs with the transfer commands, not here.
pub fn supersedeLocked(
    store: *Store,
    id: i64,
    superseded_by_request_id: []const u8,
    now: i64,
) Error!void {
    try store.db.requireTransaction();
    {
        var stmt = try store.db.prepare(supersede_sql);
        defer stmt.deinit();
        try stmt.bindText(1, superseded_by_request_id);
        try stmt.bindInt(2, now);
        try stmt.bindInt(3, id);
        _ = try stmt.step();
    }
    if (store.db.changes() != 0) return;

    // No ownership conjunct to have failed, so there are exactly four ways to
    // match no row and the first three answer under their own names.
    if (!(try rowState(store, id)).isSupersedable()) return error.CheckpointNotSupersedable;
    if (try ownerBlocksScope(store, id)) return error.SurrenderingOperationMayStillBeRunning;
    return error.SupersedingOperationMissing;
}

/// Whether the attempt that owns this checkpoint may still be affecting the
/// remote host. The classifier half of `supersede_sql`'s incumbent conjunct.
///
/// Reached only after `rowState` has established the row exists, so a missing
/// join partner means the foreign key is not being enforced — reported, never
/// read as "not blocking".
fn ownerBlocksScope(store: *Store, id: i64) Error!bool {
    var stmt = try store.db.prepare(
        \\SELECT o.status, o.resolved_status
        \\  FROM transfer_checkpoints c
        \\  JOIN operations o ON o.request_id = c.request_id
        \\ WHERE c.id = ?1
    );
    defer stmt.deinit();
    try stmt.bindInt(1, id);
    if (!try stmt.step()) return error.SurrenderingOperationMissing;
    return statusPairBlocksScope(&stmt);
}

/// The fixed lead-in of the text `supersedeLocked` writes to `failure_reason`.
/// Concatenated by sqlite so the call needs no allocator.
const supersede_reason_prefix = "superseded by request ";

/// The predecessor list comes from the graph, through the supersession route —
/// so `sourcesFor` partitions these edges away from `setState`'s statement in
/// the same pass that renders them here, and the two cannot come apart.
const supersede_sql = std.fmt.comptimePrint(
    \\UPDATE transfer_checkpoints
    \\   SET state = '{[superseded]s}',
    \\       failure_reason = '{[reason]s}' || ?1,
    \\       updated_at = ?2
    \\ WHERE id = ?3
    \\   AND state IN ({[from]s})
    \\   AND EXISTS (
    \\     SELECT 1 FROM operations owner
    \\      WHERE owner.request_id = transfer_checkpoints.request_id
    \\        AND {[released]s})
    \\   AND EXISTS (SELECT 1 FROM operations WHERE request_id = ?1)
, .{
    .superseded = @tagName(State.superseded),
    .reason = supersede_reason_prefix,
    .from = predecessorList(.superseded, .supersession),
    .released = releasesScopeSql("owner"),
});

/// The state of a row, for a refusal that has no owner to check.
///
/// `ownedRow` cannot serve `supersedeLocked`: the superseding request is by
/// definition not the checkpoint's owner, so asking it would come back
/// `CheckpointNotOurs` — a true statement about the wrong question.
fn rowState(store: *Store, id: i64) TransitionError!State {
    var stmt = try store.db.prepare("SELECT state FROM transfer_checkpoints WHERE id = ?1");
    defer stmt.deinit();
    try stmt.bindInt(1, id);
    if (!try stmt.step()) return error.CheckpointRowMissing;
    return State.parse(stmt.columnText(0));
}

/// Which side of the connection a transfer's destination is on.
///
/// A push lands on the host; a pull and a fetch land here. The distinction
/// matters to whoever verifies the result — reading `/srv/app/out.bin` locally
/// to prove a push would prove nothing about the host.
pub const Side = enum { local, remote };

/// What a published-file hash has to match to settle this transfer.
pub const ExpectedEffect = struct {
    side: Side,
    path: []const u8,
    sha256: []const u8,
    /// What the checkpoint now records about that destination.
    ///
    /// Carried with the commitment because a reading has two questions to
    /// answer and neither is optional: is this the artifact this transfer
    /// promised, and does this transfer's own record leave room for it to have
    /// put one there. The digest answers the first; only the state answers the
    /// second — see `State.renameMayHaveLanded` for the failure a matching
    /// digest alone waves through.
    state: State,
};

/// The commitment this transfer made before it sent anything.
///
/// Read by `receipts.resolve`, inside that module's transaction, to decide
/// whether a published-file hash may settle this operation. Null means the
/// transfer never declared one — in which case no observed digest can prove
/// anything, because there is nothing it could have been checked against.
///
/// Refuses to choose when a request somehow has more than one checkpoint
/// carrying a digest. `UNIQUE(request_id)` makes that unreachable from v11
/// onwards; the check stays because taking the newest would mean a
/// scope-releasing decision made by `ORDER BY id DESC`, and a constraint the
/// code silently relies on is worth restating where the reliance is.
pub fn expectedEffectLocked(
    store: *Store,
    arena: Allocator,
    request_id: []const u8,
) (Db.Error || Allocator.Error || error{ AmbiguousCheckpoint, UnknownDestSide, UnknownTransferState })!?ExpectedEffect {
    try store.db.requireTransaction();
    var stmt = try store.db.prepare(
        \\SELECT dest_side, dest_path, expected_sha256, state
        \\  FROM transfer_checkpoints
        \\ WHERE request_id = ?1 AND expected_sha256 IS NOT NULL
    );
    defer stmt.deinit();
    try stmt.bindText(1, request_id);
    if (!try stmt.step()) return null;

    const dest = try DestSide.parse(stmt.columnText(0));
    const found: ExpectedEffect = .{
        .side = dest.evidenceSide(),
        .path = try arena.dupe(u8, stmt.columnText(1)),
        .sha256 = try arena.dupe(u8, stmt.columnText(2)),
        .state = try State.parse(stmt.columnText(3)),
    };
    if (try stmt.step()) return error.AmbiguousCheckpoint;
    return found;
}

/// Whether a checkpoint in this state can only be continued by handing it to
/// another operation.
///
/// The union of the two hand-over windows, derived rather than classified, so
/// it cannot drift from the statements: `adoptLocked` accepts `isAdoptable`,
/// `recoverLocked` accepts `isRecoverable`, and between them that is every row
/// whose next move belongs to an heir.
///
/// It is asked by `servers.remove`, which is the one command that can take that
/// move away. The hand-over statement's same-machine conjunct compares
/// `dest_side` against the heir's `operations.server_id`, and
/// `operations.server_id` is `ON DELETE SET NULL` — so deleting the server
/// turns `'server:' || CAST(NULL AS TEXT)` into NULL, the conjunct into false,
/// and every one of these rows into a checkpoint that can never be adopted or
/// recovered by anybody, in any state, while still holding its destination.
/// Nothing said so; `server rm` reported memories, facts, sessions, jobs and
/// history entries and not this.
///
/// The other states are deliberately not counted. A `failed_*` row's way out is
/// `supersedeLocked` and a parked publish's is `adjudicateLocked`, and neither
/// statement joins on `server_id`, so both survive the deletion. Refusing on
/// those too would trade one wedge for another: a server that could never be
/// removed because a transfer on it could not be finished.
pub fn dependsOnHandover(s: State) bool {
    return s.isAdoptable() or s.isRecoverable();
}

const handover_bound_sql = sqlList(State, membersWhere(State, dependsOnHandover));

/// How many of this server's checkpoints would lose their only route forward if
/// the server row went away. See `dependsOnHandover`.
///
/// Joined through `operations.server_id` rather than read off `dest_side`,
/// because `dest_side` names the machine only for a push: a pull publishes
/// `local` and knows which host its source is on solely through its operation.
/// Both are the server's transfers and both lose the same conjunct.
pub fn handoverBoundCount(store: *Store, server_id: i64) Db.Error!i64 {
    var stmt = try store.db.prepare(handover_bound_count_sql);
    defer stmt.deinit();
    try stmt.bindInt(1, server_id);
    if (!try stmt.step()) return error.Sqlite;
    return stmt.columnInt(0);
}

const handover_bound_count_sql = std.fmt.comptimePrint(
    \\SELECT COUNT(*)
    \\  FROM transfer_checkpoints c
    \\  JOIN operations o ON o.request_id = c.request_id
    \\ WHERE o.server_id = ?1 AND c.state IN ({s})
, .{handover_bound_sql});

/// Where a transfer said it would put the artifact, without saying what the
/// artifact would be.
pub const Destination = struct {
    side: Side,
    path: []const u8,
};

/// The same, plus what the checkpoint now records about that destination.
///
/// The state travels with the address because a reading of a destination has
/// two questions to answer and they are not separable: is this the place this
/// transfer promised, and is the question of what happened there still open.
pub const CommittedDestination = struct {
    side: Side,
    path: []const u8,
    state: State,

    pub fn address(d: CommittedDestination) Destination {
        return .{ .side = d.side, .path = d.path };
    }
};

/// The destination this transfer committed to, whether or not it ever declared
/// a digest.
///
/// Read by `receipts.resolve`, inside that module's transaction, to decide
/// whether a reading of a destination is a reading of *this* transfer's
/// destination, and whether the outcome it speaks about is still open.
/// `ExpectedEffect` cannot answer the first question: it is null unless a digest
/// was declared, and a transfer with no declared digest still has a destination
/// it promised to publish at — `dest_side` and `dest_path` are NOT NULL and are
/// written by `create`, before anything moves. Requiring a digest for an absence
/// claim would leave every undeclared transfer's parked publish unjudgeable,
/// which is the wedge this evidence exists to open.
///
/// It is still an *advance* commitment, which is the property that makes the
/// comparison worth anything: the path is fixed at `create` — under an
/// operation that has not submitted — and no statement in this module rewrites
/// it. A path chosen afterwards would let a reconciler nominate whichever empty
/// path it liked and call the transfer failed.
///
/// Null means the request has no checkpoint at all. Refuses to choose when it
/// somehow has more than one, for the reason `expectedEffectLocked` does.
pub fn committedDestinationLocked(
    store: *Store,
    arena: Allocator,
    request_id: []const u8,
) (Db.Error || Allocator.Error || error{ AmbiguousCheckpoint, UnknownDestSide, UnknownTransferState })!?CommittedDestination {
    try store.db.requireTransaction();
    var stmt = try store.db.prepare(
        \\SELECT dest_side, dest_path, state FROM transfer_checkpoints WHERE request_id = ?1
    );
    defer stmt.deinit();
    try stmt.bindText(1, request_id);
    if (!try stmt.step()) return null;

    const dest = try DestSide.parse(stmt.columnText(0));
    const found: CommittedDestination = .{
        .side = dest.evidenceSide(),
        .path = try arena.dupe(u8, stmt.columnText(1)),
        .state = try State.parse(stmt.columnText(2)),
    };
    if (try stmt.step()) return error.AmbiguousCheckpoint;
    return found;
}

/// The digest a checkpoint currently records for what landed, if any.
///
/// Read by `execution.recoverCheckpoint` before it recovers a row, because
/// reaching `paused` clears the column — see `clearClause` — and the receipt is
/// then the only place the reading survives.
pub fn verifiedHashLocked(
    store: *Store,
    arena: Allocator,
    id: i64,
) (Db.Error || Allocator.Error)!?[]const u8 {
    try store.db.requireTransaction();
    var stmt = try store.db.prepare(
        "SELECT verified_sha256 FROM transfer_checkpoints WHERE id = ?1",
    );
    defer stmt.deinit();
    try stmt.bindInt(1, id);
    if (!try stmt.step()) return null;
    const found = stmt.columnOptText(0) orelse return null;
    return try arena.dupe(u8, found);
}

/// The id of this request's checkpoint if it is waiting on adjudication, or
/// null if there is nothing to adjudicate.
///
/// Read by `receipts.resolve` inside that module's transaction, immediately
/// before it decides what the resolution says about the artifact. Null covers
/// three ordinary cases that are all the same instruction — do nothing — and
/// none of which is an error: the operation is not a transfer, or its transfer
/// never got as far as a rename, or the rename's outcome was observed and the
/// row already says so.
///
/// Narrow on purpose. `byRequest` would answer the same question, and would
/// drag the whole row's vocabulary — direction, destination side, source family
/// — into the ledger's error set, and through it into the execution boundary's,
/// for facts the ledger does not use. The state is rendered from the enum, so
/// renaming the variant moves this statement with it.
pub fn pendingPublishLocked(store: *Store, request_id: []const u8) Db.Error!?i64 {
    try store.db.requireTransaction();
    var stmt = try store.db.prepare(pending_publish_sql);
    defer stmt.deinit();
    try stmt.bindText(1, request_id);
    if (!try stmt.step()) return null;
    return stmt.columnInt(0);
}

const pending_publish_sql = std.fmt.comptimePrint(
    \\SELECT id FROM transfer_checkpoints
    \\ WHERE request_id = ?1 AND state = '{s}'
, .{@tagName(State.indeterminate_publish)});

/// Declares, in advance, which digest would prove this transfer landed.
///
/// Write-once, and only before the transfer has sent anything — both enforced
/// here, in one statement, rather than left to the caller's ordering. A comment
/// saying "call this first" is not a guarantee: with a plain UPDATE this could
/// be written after `submitted`, after `indeterminate`, or over an existing
/// value, and each of those reopens the laundering hole it exists to close.
/// The dangerous one is the last: read the destination file, write its hash in
/// as the "advance commitment", then present that same hash as proof. The
/// comparison would pass and mean nothing.
///
/// "Has not sent anything" is asked of the *checkpoint* — `beforeFirstByte`
/// and a zero offset — and of the operation, which must still be `created` or
/// `connecting`. The checkpoint half is the load-bearing one, and it was
/// missing: the operation half alone is reset by `adoptLocked`, which re-points
/// a row at a fresh operation whose clock has not started. An attempt could
/// therefore push nine gigabytes, park the checkpoint in `paused`, be adopted
/// by a new operation, and have that operation hash what had landed and declare
/// it as the commitment its predecessor's bytes would be judged by — the very
/// substitution above, reached the long way round. The operation half is kept
/// because a checkpoint's state is only as current as its last write: a
/// `submitted` operation may be sending bytes a `planned` row has not heard
/// about yet.
///
/// A caller that gets `error.ExpectedHashLocked` has either already declared
/// one or has already started, and neither is retryable by trying harder — the
/// two refusals that *are* worth telling apart from those, "no such row" and
/// "not yours any more", come out of `ownedRow` under their own names first.
pub fn recordExpectedHash(
    store: *Store,
    id: i64,
    owner_request_id: []const u8,
    sha256: []const u8,
    now: i64,
) Error!void {
    var stmt = try store.db.prepare(record_expected_hash_sql);
    defer stmt.deinit();
    try stmt.bindText(1, sha256);
    try stmt.bindInt(2, now);
    try stmt.bindInt(3, id);
    try stmt.bindText(4, owner_request_id);
    _ = try stmt.step();
    if (store.db.changes() != 0) return;

    _ = try ownedRow(store, id, owner_request_id);
    return error.ExpectedHashLocked;
}

const record_expected_hash_sql = std.fmt.comptimePrint(
    \\UPDATE transfer_checkpoints
    \\   SET expected_sha256 = ?1, updated_at = ?2
    \\ WHERE id = ?3 AND request_id = ?4
    \\   AND expected_sha256 IS NULL
    \\   AND confirmed_offset = 0
    \\   AND state IN ({[before_first_byte]s})
    \\   AND request_id IN (
    \\         SELECT request_id FROM operations
    \\          WHERE status IN ({[before_submission]s})
    \\       )
, .{
    .before_first_byte = before_first_byte_sql,
    .before_submission = op_before_submission_sql,
});

/// Records what the source turned out to be, once something has read it.
///
/// `create` takes the source's *path*; this takes its identity. They are two
/// calls because the identity is not free at plan time — a content hash means
/// reading the whole file — and the checkpoint has to exist before the probe
/// that reads it can report anything against it. Until this lands, the column
/// the schema demands for a non-zero offset simply has no writer, which is the
/// state this module was left in: `offset_needs_source_identity` was
/// unsatisfiable for any transfer that did not know its digest up front.
///
/// Write-once, on a file source, at offset zero, and only in the two states
/// before the first byte moves. Each closes a different way of laundering, and
/// one of them no longer stands on its own:
///
/// * Rewritable would mean the digest `verifyResume` compares against could be
///   replaced with a reading of whatever is at that path *now* — which is
///   precisely the substitution the comparison exists to catch, performed
///   through the front door.
/// * `source_kind` in the file kinds. An http source has no file identity to
///   record: `source_sha256` and `source_mtime_ns` are read by no http path,
///   and `sourceChanged` re-proves such a source from its validator instead.
///   Unguarded, the call landed on an http row, overwrote `source_size` — which
///   the http arm *does* read — and burned the write-once on a row that never
///   had a file identity to give, so it could never record a real one after.
/// * `confirmed_offset = 0` now sits behind that guard and behind the schema's
///   `offset_needs_source_identity`, which already requires `source_sha256` on
///   any file row past offset zero. So on the only kinds this statement still
///   accepts, `source_sha256 IS NULL` implies a zero offset, and no reachable
///   row can be refused by this conjunct alone: it is not independently
///   falsifiable, and no gate claims to isolate it. The one that used to — an
///   `http` row hundreds of megabytes in with a null digest — is now refused a
///   conjunct earlier. It stays because it is the only one of the three that
///   would still hold if that CHECK were relaxed or a source kind arrived whose
///   identity is not a digest, and dropping a guard because the others
///   currently cover it is how the shape it protects becomes writable again.
/// * The state window is `beforeFirstByte`; see there for why it is narrower
///   than the offset window, and why `recordExpectedHash` shares it.
///
/// All three values are written together and none is optional, because they
/// are one observation of one file at one moment. Keeping a size read earlier
/// beside a digest read now would store an identity triple that never
/// described anything — and a caller holding the digest has already read the
/// file, so it has the other two.
pub fn recordSourceIdentity(
    store: *Store,
    id: i64,
    owner_request_id: []const u8,
    size: u64,
    mtime_ns: i128,
    sha256: []const u8,
    now: i64,
) Error!void {
    var stmt = try store.db.prepare(record_source_identity_sql);
    defer stmt.deinit();
    try stmt.bindOptInt(1, try optU64(size));
    try stmt.bindOptInt(2, try narrowMtime(mtime_ns));
    try stmt.bindText(3, sha256);
    try stmt.bindInt(4, now);
    try stmt.bindInt(5, id);
    try stmt.bindText(6, owner_request_id);
    _ = try stmt.step();
    if (store.db.changes() != 0) return;

    _ = try ownedRow(store, id, owner_request_id);
    return error.SourceIdentityLocked;
}

const record_source_identity_sql = std.fmt.comptimePrint(
    \\UPDATE transfer_checkpoints
    \\   SET source_size = ?1, source_mtime_ns = ?2, source_sha256 = ?3,
    \\       updated_at = ?4
    \\ WHERE id = ?5 AND request_id = ?6
    \\   AND source_kind IN ({[file_kinds]s})
    \\   AND source_sha256 IS NULL
    \\   AND confirmed_offset = 0
    \\   AND state IN ({[before_first_byte]s})
, .{ .file_kinds = file_source_sql, .before_first_byte = before_first_byte_sql });

/// The facts a refused write is classified from.
const OwnedRow = struct {
    state: State,
    confirmed_offset: i64,
    /// Whether a digest was read back off the result, whether one was declared
    /// in advance, and whether the two agree. All three are evaluated by sqlite
    /// from the same fragments the statements guard on, so the classifier
    /// cannot start naming a conjunct the write no longer contains.
    ///
    /// `hash_matches_declared` is NULL — and so reads as false — when no
    /// verified digest exists at all. That never decides anything, because the
    /// only caller asks `has_verified_hash` first. `claims_hash_agreed` is the
    /// same comparison written so that it is false rather than NULL whenever
    /// either side is missing, because its caller asks it on its own.
    has_verified_hash: bool,
    has_declared_hash: bool,
    hash_matches_declared: bool,
    claims_hash_agreed: bool,
};

/// Re-reads a row after its UPDATE matched nothing, and names the first guard
/// that could have refused it.
///
/// Every write in this module addresses one row by primary key and conjoins the
/// guards that make it legal, so a zero-row UPDATE is a refusal and never a
/// no-op: `_ = try stmt.step()` reports that the statement ran, not that it
/// changed anything, and on a durable checkpoint that silence is the difference
/// between "the offset advanced" and "we believe the offset advanced" — the
/// second of which resumes from the wrong place.
///
/// Collapsing every refusal into `CheckpointRowMissing` was the next version of
/// the same problem. "The id is wrong", "a resume adopted this away from you"
/// and "this state cannot go there" want three different responses out of a
/// caller, and one error name gave it none — nor could a human reading the log
/// tell which had happened. This answers the two questions every statement
/// shares, and hands back the state, the offset and the two digest facts so
/// each caller can go on to the guard that is its own.
///
/// The re-read is a second statement, so a row that changes in between is
/// described by its newer values. That only affects the wording of a refusal
/// which has already happened, and getting there needs two writers holding the
/// same `request_id` at once — which the ownership conjunct exists to make a
/// caller's bug rather than a race this has to survive.
fn ownedRow(store: *Store, id: i64, owner_request_id: []const u8) TransitionError!OwnedRow {
    var stmt = try store.db.prepare(owned_row_sql);
    defer stmt.deinit();
    try stmt.bindInt(1, id);
    try stmt.bindText(2, owner_request_id);
    if (!try stmt.step()) return error.CheckpointRowMissing;
    if (stmt.columnInt(1) == 0) return error.CheckpointNotOurs;
    return .{
        .state = try State.parse(stmt.columnText(0)),
        .confirmed_offset = stmt.columnInt(2),
        .has_verified_hash = stmt.columnInt(3) != 0,
        .hash_matches_declared = stmt.columnInt(4) != 0,
        .has_declared_hash = stmt.columnInt(5) != 0,
        .claims_hash_agreed = stmt.columnInt(6) != 0,
    };
}

const owned_row_sql = std.fmt.comptimePrint(
    \\SELECT state, request_id = ?2, confirmed_offset, {[has_hash]s}, {[matches]s},
    \\       NOT {[no_declared]s}, {[agreed]s}
    \\  FROM transfer_checkpoints WHERE id = ?1
, .{
    .has_hash = has_verified_hash_sql,
    .matches = hash_matches_declared_sql,
    .no_declared = no_declared_hash_sql,
    .agreed = claims_hash_agreed_sql,
});

/// Records the digest something computed over what actually landed.
///
/// The counterpart to `recordExpectedHash`, and it had neither of that
/// function's two guards until they were noticed missing: it was the one
/// mutator here whose `WHERE` was nothing but an id and an owner. Both are now
/// present, for the reasons `acceptsVerifiedHash` gives — a verification digest
/// is a record that an act happened, so it may only be written while that act
/// is happening, and it may only be written once.
///
/// Write-once matters even though nothing reads the column yet. A rewritable
/// "this is what it hashed to" is not evidence of anything, because the last
/// writer decides what an auditor reads; a row that reached
/// `failed_hash_mismatch` and then accepted a fresh digest says both that the
/// digest disagreed and that here is the one that agreed.
pub fn recordVerifiedHash(
    store: *Store,
    id: i64,
    owner_request_id: []const u8,
    sha256: []const u8,
    now: i64,
) Error!void {
    var stmt = try store.db.prepare(record_verified_hash_sql);
    defer stmt.deinit();
    try stmt.bindText(1, sha256);
    try stmt.bindInt(2, now);
    try stmt.bindInt(3, id);
    try stmt.bindText(4, owner_request_id);
    _ = try stmt.step();
    if (store.db.changes() != 0) return;

    // Existence and ownership come back under their own names; what is left is
    // the state window or the write-once, and both are the same instruction to
    // a caller — this digest is not one this row can accept — so they share a
    // name rather than being told apart by a second read that could not tell
    // them apart reliably anyway.
    _ = try ownedRow(store, id, owner_request_id);
    return error.VerifiedHashLocked;
}

const record_verified_hash_sql = std.fmt.comptimePrint(
    \\UPDATE transfer_checkpoints SET verified_sha256 = ?1, updated_at = ?2
    \\ WHERE id = ?3 AND request_id = ?4
    \\   AND verified_sha256 IS NULL
    \\   AND state IN ({s})
, .{accepts_verified_hash_sql});

/// End of the contiguous completed prefix, given which chunks finished.
///
/// Parallel chunks complete out of order, so the durable offset may only
/// advance past chunk N once every chunk before it is done. Returning the
/// highest completed chunk instead would leave a hole that a later resume
/// would skip.
pub fn contiguousPrefix(done: []const bool, chunk_size: u64, total: u64) u64 {
    var complete: u64 = 0;
    for (done) |finished| {
        if (!finished) break;
        complete += 1;
    }
    return @min(complete * chunk_size, total);
}

test canTransition {
    const t = std.testing;

    // The whole legal walk, edge by edge.
    try t.expect(canTransition(.planned, .probing));
    try t.expect(canTransition(.probing, .transferring));
    try t.expect(canTransition(.transferring, .verifying));
    try t.expect(canTransition(.verifying, .publishing));
    try t.expect(canTransition(.publishing, .published));

    // The jump this table exists to refuse: an artifact recorded as published
    // without a byte of it ever having been hashed.
    try t.expect(!canTransition(.planned, .published));
    try t.expect(!canTransition(.transferring, .published));
    try t.expect(!canTransition(.verifying, .published));

    // Both post-rename outcomes come only from `publishing` or from a later
    // adjudication, so no earlier state can declare a result about a rename
    // that never ran.
    try t.expect(!canTransition(.transferring, .indeterminate_publish));
    try t.expect(canTransition(.publishing, .indeterminate_publish));
    try t.expect(canTransition(.publishing, .completed_unverified));

    // A failure has to be diagnosable from where it is claimed: a digest
    // cannot disagree before something hashed it — the transfer itself while
    // verifying or renaming, or a reconciler reading the destination of a
    // parked publish.
    try t.expect(!canTransition(.planned, .failed_hash_mismatch));
    try t.expect(canTransition(.verifying, .failed_hash_mismatch));
    try t.expect(canTransition(.indeterminate_publish, .failed_hash_mismatch));

    // The un-wedge edge. Without it a process killed mid-hash leaves a row
    // that can neither move on nor be adopted, holding its destination.
    try t.expect(canTransition(.verifying, .paused));
    try t.expect(canTransition(.paused, .probing));

    // `indeterminate_publish` is the one state that looks terminal and is not.
    // Its four edges are the only way a checkpoint whose rename was never
    // observed can stop holding its destination: it is not adoptable and
    // nothing deletes these rows, so without them the path is claimed for good.
    // The fourth is a failure reached from a *present* artifact — see
    // `adjudicateLocked` — and it keeps the hold, so the way it stops claiming
    // the path is a later supersession rather than this edge.
    try t.expect(canTransition(.indeterminate_publish, .published));
    try t.expect(canTransition(.indeterminate_publish, .completed_unverified));
    try t.expect(canTransition(.indeterminate_publish, .failed_publish));
    try t.expect(canTransition(.indeterminate_publish, .failed_hash_mismatch));

    // Every failure has exactly one way out, and it is an operator releasing
    // the destination it went on holding. Nothing else leads out of one, and
    // nothing that is not a failure leads into `superseded`: a live transfer
    // may still be writing, an unjudged publish is owed an adjudication, and a
    // published row has no hold to release.
    try t.expect(canTransition(.failed_hash_mismatch, .superseded));
    try t.expect(canTransition(.failed_publish, .superseded));
    try t.expect(!canTransition(.publishing, .superseded));
    try t.expect(!canTransition(.indeterminate_publish, .superseded));
    try t.expect(!canTransition(.published, .superseded));

    // Settled is settled: nothing leads out of a real terminal but the
    // supersession edge above, and nothing leads back into `planned`, which
    // only `create` writes. The unjudged state leads only to the four outcomes
    // of the rename, and nowhere else — in particular not back into a state
    // where bytes could start moving again under an artifact that may already
    // be published.
    inline for (@typeInfo(State).@"enum".fields) |field| {
        const to: State = @enumFromInt(field.value);
        try t.expect(!canTransition(.published, to));
        try t.expect(!canTransition(.superseded, to));
        try t.expectEqual(to == .superseded, canTransition(.failed_no_space, to));
        try t.expect(!canTransition(to, .planned));
        switch (to) {
            .published, .completed_unverified, .failed_publish, .failed_hash_mismatch => {},
            else => try t.expect(!canTransition(.indeterminate_publish, to)),
        }
    }
}

test "the three writers partition the graph and none can reach another's edges" {
    const t = std.testing;
    // states × states × routes, all unrolled: the default quota is not enough
    // to walk the whole edge set, and walking the whole edge set is the point.
    @setEvalBranchQuota(20_000);

    // Every edge belongs to exactly one route. A split that dropped an edge
    // would make a state unreachable by anyone, and one that shared an edge
    // would put `setState` back where it started — able to record a verdict on
    // a rename nobody watched, or to clear its own failed attempt's path.
    inline for (@typeInfo(State).@"enum".fields) |to_field| {
        const to: State = @enumFromInt(to_field.value);
        var seen: usize = 0;
        inline for (@typeInfo(State).@"enum".fields) |from_field| {
            const from: State = @enumFromInt(from_field.value);
            var owners: usize = 0;
            inline for (@typeInfo(Route).@"enum".fields) |route_field| {
                const route: Route = @enumFromInt(route_field.value);
                if (routeAllows(route, from, to)) owners += 1;
            }
            try t.expect(owners <= 1);
            try t.expectEqual(canTransition(from, to), owners == 1);
            seen += owners;
        }
        try t.expectEqual(predecessors(to).len, seen);
    }

    // The split, named. A driver walks every edge except the four out of the
    // unjudged state and the ones into `superseded`; a resolution walks those
    // four and nothing else; a supersession walks the release edges and
    // nothing else.
    try t.expect(routeAllows(.transition, .publishing, .published));
    try t.expect(!routeAllows(.transition, .indeterminate_publish, .published));
    try t.expect(routeAllows(.adjudication, .indeterminate_publish, .published));
    try t.expect(!routeAllows(.adjudication, .publishing, .published));
    try t.expect(routeAllows(.supersession, .failed_hash_mismatch, .superseded));
    try t.expect(!routeAllows(.transition, .failed_hash_mismatch, .superseded));
    try t.expect(!routeAllows(.adjudication, .failed_hash_mismatch, .superseded));
    // `failed_hash_mismatch` is the one target both a driver and an
    // adjudication can reach, from different rows, so the partition has to cut
    // *through* a target rather than between them. A driver hashing its own
    // result may declare the mismatch; it may not declare one about a rename it
    // never watched, and an adjudication may not overwrite a live row's verdict.
    try t.expect(routeAllows(.transition, .verifying, .failed_hash_mismatch));
    try t.expect(routeAllows(.transition, .publishing, .failed_hash_mismatch));
    try t.expect(!routeAllows(.transition, .indeterminate_publish, .failed_hash_mismatch));
    try t.expect(routeAllows(.adjudication, .indeterminate_publish, .failed_hash_mismatch));
    try t.expect(!routeAllows(.adjudication, .verifying, .failed_hash_mismatch));

    // And the rendered lists say the same thing, since it is the statement and
    // not the Zig predicate that refuses the write.
    try t.expectEqualStrings("'publishing'", comptime predecessorList(.failed_publish, .transition));
    try t.expectEqualStrings("'indeterminate_publish'", comptime predecessorList(.failed_publish, .adjudication));
    try t.expectEqualStrings(
        "'verifying','publishing'",
        comptime predecessorList(.failed_hash_mismatch, .transition),
    );
    try t.expectEqualStrings(
        "'indeterminate_publish'",
        comptime predecessorList(.failed_hash_mismatch, .adjudication),
    );
    // A target no adjudication reaches renders an unsatisfiable list rather
    // than a syntax error, so the route cannot be widened by accident.
    try t.expectEqualStrings("NULL", comptime predecessorList(.verifying, .adjudication));
    // ...including the driver's view of the release edges, which is the whole
    // of what stops a failed attempt from clearing its own destination.
    try t.expectEqualStrings("NULL", comptime predecessorList(.superseded, .transition));
}

test "the seven role predicates are not one predicate wearing seven hats" {
    const t = std.testing;

    // Every adoptable or offset-accepting state must hold its destination:
    // a row a resume can pick up is a row a rival must not be handed. And a
    // state that may still learn its source's identity must be one that could
    // still record an offset against it, or the identity could never be used.
    // A state that may record a verification digest must still hold the path,
    // because the artifact is not published yet. And a state that may be
    // superseded must hold one too — releasing a hold that does not exist is
    // not an operation — while never being adoptable, because a row a resume
    // could pick up is not one an operator is being asked to discard.
    inline for (@typeInfo(State).@"enum".fields) |field| {
        const s: State = @enumFromInt(field.value);
        if (s.isAdoptable()) try t.expect(s.holdsDestination());
        if (s.acceptsOffset()) try t.expect(s.holdsDestination());
        if (s.beforeFirstByte()) try t.expect(s.acceptsOffset());
        if (s.acceptsVerifiedHash()) try t.expect(s.holdsDestination());
        if (s.isSupersedable()) {
            try t.expect(s.holdsDestination());
            try t.expect(!s.isAdoptable());
        }
    }

    // Recovery and adoption are disjoint and both are hand-overs, which is why
    // they can share one statement shape and must not share a state window. A
    // state in both would be a row an heir could either continue as it stands
    // or rewrite first, decided by which function it happened to call.
    //
    // Recoverable states hold their destination — there is a partial and maybe
    // an artifact at stake — and every one of them is somewhere a *running*
    // process is: `acceptsVerifiedHash` is the same two states, because being
    // able to hash the result is what it means to be in the middle of finishing
    // one.
    inline for (@typeInfo(State).@"enum".fields) |field| {
        const s: State = @enumFromInt(field.value);
        try t.expect(!(s.isRecoverable() and s.isAdoptable()));
        if (s.abandonedNormalisation()) |target| {
            try t.expect(s.holdsDestination());
            try t.expect(s.acceptsVerifiedHash());
            // And where it goes is somewhere the graph can already reach from
            // it. Recovery has no private edge.
            try t.expect(canTransition(s, target));
        }
    }
    // Both normalisations are on the ordinary route, transcribed here rather
    // than derived, so recovery cannot quietly acquire a writer of its own: the
    // two edges belong to `setState`, and recovery walks them as the new owner.
    try t.expect(routeAllows(.transition, .verifying, .paused));
    try t.expect(routeAllows(.transition, .publishing, .indeterminate_publish));
    // The normalised row is never itself recoverable: recovering a recovery
    // would be a second hand-over of a row whose owner is now alive.
    try t.expect(!State.paused.isRecoverable());
    try t.expect(!State.indeterminate_publish.isRecoverable());

    // ...and the containment is strict, in the three states that make it so.
    // Past the last byte there is nothing to resume from and no offset to
    // advance, but the path is still occupied — while verifying, while
    // renaming, and while the outcome of the rename is unknown.
    for ([_]State{ .verifying, .publishing, .indeterminate_publish }) |s| {
        try t.expect(s.holdsDestination());
        try t.expect(!s.isAdoptable());
        try t.expect(!s.acceptsOffset());
    }

    // The commitment window is strictly narrower still, and these two states
    // are the gap. Both may take progress; neither may take a first reading of
    // the source or a first declaration of the digest it will be judged by,
    // because both have already put bytes on the wire under whatever the row
    // said at the time.
    for ([_]State{ .transferring, .paused }) |s| {
        try t.expect(s.acceptsOffset());
        try t.expect(!s.beforeFirstByte());
    }

    // The two digest windows are disjoint, and that is the whole of what
    // "declared in advance" versus "read off the result" means. A state where
    // both were writable would let one transfer commit to a digest and satisfy
    // its own commitment without anything happening in between.
    inline for (@typeInfo(State).@"enum".fields) |field| {
        const s: State = @enumFromInt(field.value);
        try t.expect(!(s.beforeFirstByte() and s.acceptsVerifiedHash()));
    }

    // Nothing may be hashing a result while bytes are still arriving: the
    // digest would cover a length that moved underneath it.
    for ([_]State{ .verifying, .publishing }) |s| {
        try t.expect(s.acceptsVerifiedHash());
        try t.expect(!s.acceptsOffset());
    }

    // Exactly two states release the path, and they are the two in which it
    // stopped being a claim and became the artifact. Every failure keeps it —
    // that is the rule `supersedeLocked` exists to be the one way out of — and
    // `superseded` is what being let out looks like.
    inline for (@typeInfo(State).@"enum".fields) |field| {
        const s: State = @enumFromInt(field.value);
        const releases = switch (s) {
            .published, .completed_unverified, .superseded => true,
            else => false,
        };
        try t.expectEqual(releases, !s.holdsDestination());
    }
    try t.expect(!State.superseded.isSupersedable());
}

test "only the states that claim something about a digest carry an evidence conjunct" {
    const t = std.testing;

    // Every other target is ordered by the graph and by nothing else. A
    // conjunct that crept onto one of them would silently narrow a transition
    // the table says is legal, and `IllegalCheckpointTransition` would then be
    // the name of a refusal that has nothing to do with the transition.
    //
    // Three targets carry one, and each names a different relationship between
    // the two digest columns: `published` says they agree, `completed_unverified`
    // says neither exists, `failed_hash_mismatch` says they do not agree.
    inline for (@typeInfo(State).@"enum".fields) |field| {
        const s: State = @enumFromInt(field.value);
        const clause = comptime evidenceClause(s);
        switch (s) {
            .published, .completed_unverified, .failed_hash_mismatch => try t.expect(clause.len > 0),
            else => try t.expectEqualStrings("", clause),
        }
    }

    // Both end states hang off the same predecessors, so the graph cannot tell
    // them apart at all — the conjuncts are the whole of the difference, and
    // they ask opposite things of one column.
    try t.expect(canTransition(.publishing, .published));
    try t.expect(canTransition(.publishing, .completed_unverified));
    try t.expect(std.mem.indexOf(
        u8,
        comptime evidenceClause(.published),
        has_verified_hash_sql,
    ) != null);
    try t.expect(std.mem.indexOf(
        u8,
        comptime evidenceClause(.completed_unverified),
        no_verified_hash_sql,
    ) != null);
    try t.expect(std.mem.indexOf(
        u8,
        comptime evidenceClause(.published),
        no_verified_hash_sql,
    ) == null);

    // The declaration half of `completed_unverified`. "No trustworthy hash was
    // available" is a claim about what the transfer had, not only about what it
    // read, and the resolution route one module over already refused a transfer
    // that named a digest in advance. Without this the same act was refused
    // when it arrived through a crash and admitted when it arrived through the
    // driver's own happy path — which is the path that is always taken.
    try t.expect(std.mem.indexOf(
        u8,
        comptime evidenceClause(.completed_unverified),
        no_declared_hash_sql,
    ) != null);

    // `failed_hash_mismatch` refuses to *claim agreement*, which is a narrower
    // thing than claiming disagreement. A transfer that declared nothing has
    // nothing to disagree with and a row that read nothing back has not spoken;
    // both are honest silences and both still reach the state. What cannot is
    // the row that says, in its columns, that the digest matched.
    try t.expect(std.mem.indexOf(
        u8,
        comptime evidenceClause(.failed_hash_mismatch),
        claims_hash_agreed_sql,
    ) != null);
    try t.expect(std.mem.startsWith(
        u8,
        std.mem.trimStart(u8, comptime evidenceClause(.failed_hash_mismatch), "\n "),
        "AND NOT ",
    ));
}

test "SQL vocabularies are rendered from their Zig owners" {
    const t = std.testing;
    // The file kinds `recordSourceIdentity` may write to, and the two operation
    // windows the three statements here guard on. Asserted as text because the
    // point is that no statement spells them out: a fourth source kind or a
    // renamed status reaches every guard through these constants.
    try t.expectEqualStrings("'local_file','remote_file'", file_source_sql);
    try t.expectEqualStrings("'created','connecting'", op_before_submission_sql);
    // The incumbent window on a hand-over: every status that is not still
    // affecting the remote host. Written as the complement of `blocksScope` and
    // asserted as text here, because the two properties this list has to keep
    // are both invisible from the predicate — the three blocking statuses are
    // absent, `indeterminate` loudest among them, and the four a resolution can
    // prove are all present, so `COALESCE(resolved_status, status)` can be read
    // against one list instead of two.
    try t.expectEqualStrings(
        "'created','connecting','completed','failed','timed_out','cancelled'",
        op_releases_scope_sql,
    );
}

test contiguousPrefix {
    const t = std.testing;
    // Chunks 0,1 done; 2 still running; 3,4 finished early.
    const done = [_]bool{ true, true, false, true, true };
    // Offset stops at the gap, not at the highest finished chunk.
    try t.expectEqual(@as(u64, 200), contiguousPrefix(&done, 100, 500));

    try t.expectEqual(@as(u64, 0), contiguousPrefix(&[_]bool{ false, true }, 100, 200));
    try t.expectEqual(@as(u64, 500), contiguousPrefix(&[_]bool{ true, true, true, true, true }, 100, 500));
    // A short final chunk must not push the offset past the real length.
    try t.expectEqual(@as(u64, 250), contiguousPrefix(&[_]bool{ true, true, true }, 100, 250));
}

test "DestSide round-trips, and refuses anything it did not write" {
    const t = std.testing;
    var buf: [dest_side_buf_len]u8 = undefined;
    try t.expectEqualStrings("local", DestSide.text(.local, &buf));
    try t.expectEqualStrings("server:12", DestSide.text(.{ .server = 12 }, &buf));
    try t.expectEqual(DestSide.local, try DestSide.parse("local"));
    try t.expectEqual(@as(i64, 12), (try DestSide.parse("server:12")).server);
    // The widest id still fits the buffer `text` promises is enough.
    try t.expectEqualStrings(
        "server:-9223372036854775808",
        DestSide.text(.{ .server = std.math.minInt(i64) }, &buf),
    );
    try t.expectError(error.UnknownDestSide, DestSide.parse("remote"));
    try t.expectError(error.UnknownDestSide, DestSide.parse("server:"));
    try t.expectError(error.UnknownDestSide, DestSide.parse("server:abc"));

    // A push is proved on the host, a pull and a fetch here.
    try t.expectEqual(Side.remote, DestSide.evidenceSide(.{ .server = 3 }));
    try t.expectEqual(Side.local, DestSide.evidenceSide(.local));
}

fn testCheckpoint() Checkpoint {
    return .{
        .id = 1,
        .request_id = "01ABCDEFGH0123456789ABCDEF",
        .direction = .push,
        .dest_side = .{ .server = 1 },
        .dest_path = "/srv/big.bin",
        .partial_path = "/srv/big.bin.terminus-part",
        .partial_len = 400,
        .partial_sha256 = "bbbb",
        .source = .{ .local_file = .{
            .path = "./big.bin",
            .size = 1000,
            .mtime_ns = 42,
            .sha256 = "aaaa",
        } },
        .chunk_size = 100,
        .confirmed_offset = 400,
        .total_bytes = 1000,
        .expected_sha256 = "aaaa",
        .verified_sha256 = null,
        .no_clobber = false,
        .state = .paused,
        .failure_reason = null,
        .created_at = 1,
        .updated_at = 2,
    };
}

fn unchangedSource() SourceIdentity {
    return .{ .local_file = .{
        .path = "./big.bin",
        .size = 1000,
        .mtime_ns = 42,
        .sha256 = "aaaa",
    } };
}

test "verifyResume accepts an unchanged source and matching partial" {
    const t = std.testing;
    const verdict = verifyResume(
        testCheckpoint(),
        unchangedSource(),
        .{ .exists = true, .len = 400, .prefix_sha256 = "bbbb" },
    );
    try t.expectEqual(@as(u64, 400), verdict.resume_from);
}

test "verifyResume refuses a changed source" {
    const t = std.testing;

    // Same size and mtime, different content: caught by the hash.
    try t.expect(verifyResume(testCheckpoint(), .{ .local_file = .{
        .path = "./big.bin",
        .size = 1000,
        .mtime_ns = 42,
        .sha256 = "zzzz",
    } }, .{ .exists = true, .len = 400, .prefix_sha256 = "bbbb" }) == .source_changed);

    // Rewritten in place: mtime moves.
    try t.expect(verifyResume(testCheckpoint(), .{ .local_file = .{
        .path = "./big.bin",
        .size = 1000,
        .mtime_ns = 99,
        .sha256 = "aaaa",
    } }, .{ .exists = true, .len = 400, .prefix_sha256 = "bbbb" }) == .source_changed);

    // Truncated or appended.
    try t.expect(verifyResume(testCheckpoint(), .{ .local_file = .{
        .path = "./big.bin",
        .size = 900,
        .mtime_ns = 42,
        .sha256 = "aaaa",
    } }, .{ .exists = true, .len = 400, .prefix_sha256 = "bbbb" }) == .source_changed);

    // A different path entirely, offered under the same identity.
    try t.expect(verifyResume(testCheckpoint(), .{ .local_file = .{
        .path = "./other.bin",
        .size = 1000,
        .mtime_ns = 42,
        .sha256 = "aaaa",
    } }, .{ .exists = true, .len = 400, .prefix_sha256 = "bbbb" }) == .source_changed);

    // The same path on the *other* machine. Identical bytes would still be a
    // different file, and the old `local_path != null` gate let this through
    // by not being a check at all.
    try t.expect(verifyResume(testCheckpoint(), .{ .remote_file = .{
        .path = "./big.bin",
        .size = 1000,
        .mtime_ns = 42,
        .sha256 = "aaaa",
    } }, .{ .exists = true, .len = 400, .prefix_sha256 = "bbbb" }) == .source_changed);

    // Observed, but with nothing to compare against: silence is not a match.
    try t.expect(verifyResume(testCheckpoint(), .{ .local_file = .{
        .path = "./big.bin",
    } }, .{ .exists = true, .len = 400, .prefix_sha256 = "bbbb" }) == .source_changed);

    // Source gone entirely.
    try t.expect(verifyResume(testCheckpoint(), null, .{ .exists = true, .len = 400 }) == .source_changed);
}

test "verifyResume will not resume an HTTP source without a stable validator" {
    const t = std.testing;
    var checkpoint = testCheckpoint();
    checkpoint.direction = .fetch;
    checkpoint.dest_side = .local;

    // Recorded with a strong validator, and it still holds.
    checkpoint.source = .{ .http = .{ .url = "https://h/f.bin", .etag = "W1" } };
    try t.expectEqual(@as(u64, 400), verifyResume(
        checkpoint,
        .{ .http = .{ .url = "https://h/f.bin", .etag = "W1" } },
        .{ .exists = true, .len = 400, .prefix_sha256 = "bbbb" },
    ).resume_from);

    // The object moved on.
    try t.expect(verifyResume(
        checkpoint,
        .{ .http = .{ .url = "https://h/f.bin", .etag = "W2" } },
        .{ .exists = true, .len = 400, .prefix_sha256 = "bbbb" },
    ) == .source_changed);

    // Same size, no validator either then or now. Size is not identity: a
    // ranged resume splices two moments together, and only a validator says
    // they saw the same object.
    checkpoint.source = .{ .http = .{ .url = "https://h/f.bin", .size = 1000 } };
    try t.expect(verifyResume(
        checkpoint,
        .{ .http = .{ .url = "https://h/f.bin", .size = 1000 } },
        .{ .exists = true, .len = 400, .prefix_sha256 = "bbbb" },
    ) == .source_changed);
}

test "verifyResume refuses a mismatched partial" {
    const t = std.testing;
    const source = unchangedSource();

    // The far side lost bytes we had counted.
    try t.expect(verifyResume(testCheckpoint(), source, .{ .exists = true, .len = 300, .prefix_sha256 = "bbbb" }) == .partial_mismatch);
    // Right length, wrong content.
    try t.expect(verifyResume(testCheckpoint(), source, .{ .exists = true, .len = 400, .prefix_sha256 = "cccc" }) == .partial_mismatch);
    // Longer than confirmed AND the confirmed head does not check out: the
    // tail cannot be discarded on the strength of a head we just disproved.
    try t.expect(verifyResume(testCheckpoint(), source, .{ .exists = true, .len = 500, .prefix_sha256 = "cccc" }) == .partial_mismatch);
    // Nothing recorded to check the head against, at either length. Length is
    // not content: a partial of exactly the confirmed size can be a different
    // file or a half-written retry, and appending to it would splice two
    // sources together into something whose hash matches neither.
    var no_hash = testCheckpoint();
    no_hash.partial_sha256 = null;
    try t.expect(verifyResume(no_hash, source, .{ .exists = true, .len = 500, .prefix_sha256 = "bbbb" }) == .partial_mismatch);
    try t.expect(verifyResume(no_hash, source, .{ .exists = true, .len = 400, .prefix_sha256 = "bbbb" }) == .partial_mismatch);
    // Recorded but not observed: we asked and the far side did not tell us.
    try t.expect(verifyResume(testCheckpoint(), source, .{ .exists = true, .len = 400, .prefix_sha256 = null }) == .partial_mismatch);
    // Partial vanished after we had confirmed progress: not a clean restart.
    try t.expect(verifyResume(testCheckpoint(), source, .{ .exists = false }) == .partial_mismatch);
}

test "verifyResume resumes past unconfirmed bytes, after proving the head" {
    const t = std.testing;
    const source = unchangedSource();

    // The ordinary shape of an interruption: the writer confirms an offset
    // only once the far side acknowledges it, so a cut mid-write leaves more
    // bytes there than were ever confirmed. Refusing this outright — which
    // this function used to do — made resume unreachable in the one case it
    // exists for, and every real resume would have restarted at zero.
    const verdict = verifyResume(testCheckpoint(), source, .{
        .exists = true,
        .len = 500,
        .prefix_sha256 = "bbbb",
    });
    try t.expectEqual(@as(u64, 400), verdict.truncate_then_resume.offset);
    try t.expectEqual(@as(u64, 500), verdict.truncate_then_resume.partial_len);

    // Exactly as long as confirmed needs no truncation at all.
    try t.expectEqual(@as(u64, 400), verifyResume(testCheckpoint(), source, .{
        .exists = true,
        .len = 400,
        .prefix_sha256 = "bbbb",
    }).resume_from);
}

test "verifyResume allows a clean start when nothing was confirmed yet" {
    const t = std.testing;
    var checkpoint = testCheckpoint();
    checkpoint.confirmed_offset = 0;
    checkpoint.partial_len = 0;
    checkpoint.partial_sha256 = null;
    const verdict = verifyResume(checkpoint, unchangedSource(), .{ .exists = false });
    try t.expect(verdict == .start_over);
}
