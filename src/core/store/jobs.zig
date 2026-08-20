//! Store CRUD for the `jobs` table. A job is a tracked long-running
//! remote command living in a dedicated tmux session (`job-<name>` on the
//! remote). The remote log + sentinel decide completion; the row caches
//! the last observed state so `job ls` can render without SSH.
//!
//! Every write here is a compare-and-swap against the row the caller read.
//!
//! That is not defensive style, it is the only thing that makes a write to
//! this table mean anything. The row has no stable address: `id` is a sqlite
//! rowid, which the next INSERT after a DELETE inherits, and `name` is what a
//! takeover transfers from one launch to the next. Three writers here were
//! keyed on one or the other with no owner and no state rule, so "update the
//! job I looked at" could land on the row that replaced it — a different
//! command, on a different attempt, possibly still running.
//!
//! So each writer takes the fields of the row whose change would invalidate
//! its write, conjoins them into the UPDATE, and classifies a zero-row result
//! rather than reporting success. The three field sets are deliberately not
//! the same: a cursor advance is invalidated by a different fact than a finish
//! is. See `FinishExpectation`, `CursorExpectation` and `RemoveExpectation`.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Store = @import("Store.zig");
const Db = @import("Db.zig");

/// `pending` is the launch window: the row exists, but nothing has been typed
/// into the remote shell yet.
///
/// It is a distinct state rather than an early `running` because the row is
/// written before the launcher touches the remote host at all — that is what
/// makes `UNIQUE(server_id, name)` able to pick a winner between two
/// simultaneous launches — and a reservation that never got that far is not
/// work in progress. Calling it `running` would put a job in `job ls` that
/// provably never started.
pub const Status = enum {
    pending,
    running,
    exited,
    killed,

    /// Names a row that may correspond to something on the remote host, and
    /// so must not be silently reused or overwritten.
    pub fn live(self: Status) bool {
        return switch (self) {
            .pending, .running => true,
            .exited, .killed => false,
        };
    }

    pub fn parse(raw: []const u8) error{UnknownStatus}!Status {
        return std.meta.stringToEnum(Status, raw) orelse error.UnknownStatus;
    }

    pub fn text(self: Status) []const u8 {
        return @tagName(self);
    }
};

/// The half of `Status` a settlement may write, as a type.
///
/// `markFinished` used to take a plain `Status`, so "a finish records a
/// settled state" was a rule its callers had to remember rather than one the
/// signature enforced — and nothing stopped a caller writing `running`
/// through it, which would have walked a promotion backwards under the
/// settlement's own guards. The same move `op_state.LiveStatus` makes for
/// operations: narrow the type, and the rule stops needing a check.
pub const Settled = enum {
    exited,
    killed,

    pub fn toStatus(s: Settled) Status {
        return switch (s) {
            .exited => .exited,
            .killed => .killed,
        };
    }
};

comptime {
    // `Settled` is exactly the complement of `Status.live`, and this is what
    // keeps it so. A fifth status that is not live has to appear here, or the
    // settlement route would silently stop being able to reach it while
    // `live()` went on promising that it could.
    for (@typeInfo(Status).@"enum".fields) |field| {
        const s: Status = @enumFromInt(field.value);
        const listed = std.meta.stringToEnum(Settled, field.name) != null;
        if (s.live() == listed) @compileError(
            "Settled must be exactly the non-live members of Status; '" ++
                field.name ++ "' is in one and not the other",
        );
    }
}

/// Legal predecessors of each `jobs.status` — the whole transition graph, in
/// one place.
///
/// Written target-first because that is the direction the SQL needs: every
/// mutator guards its UPDATE with `status IN (<predecessors of its target>)`,
/// and those lists are rendered from this function at comptime rather than
/// typed out. Same shape as `transfers.predecessors`, and for the same reason:
/// this table had no transition rule at all, so `markFinished` would overwrite
/// a `killed` row with `exited` — a settlement rewriting another settlement's
/// verdict, on the row `run --name X` consults before it agrees to launch.
///
/// The edges that carry weight:
///
///  * `pending` has no predecessors. `create` is its only writer, so anything
///    aiming there matches no row and is classified as an illegal move rather
///    than quietly given an edge nobody designed.
///  * `pending → running` is the promotion, and it is the *only* way into
///    `running`. A settlement cannot walk it — see `Route`.
///  * `pending → exited | killed`. A launch whose connection broke between
///    `sendKeys` and the promotion leaves the row `pending` on purpose (it may
///    name something running on the host), and the evidence that later says
///    how that job ended has to be able to land on it.
///  * nothing leaves `exited` or `killed`. A settled row is settled: the
///    second observer reports what the ledger holds instead of overwriting the
///    first one's answer.
///
/// Exhaustive on purpose: a new `Status` variant fails to compile here, which
/// is the only reliable way to be told the graph has a hole.
fn predecessors(to: Status) []const Status {
    return switch (to) {
        .pending => &[_]Status{},
        .running => &[_]Status{.pending},
        .exited => &[_]Status{ .pending, .running },
        .killed => &[_]Status{ .pending, .running },
    };
}

/// Whether `from → to` is an edge of the graph above.
///
/// For callers and tests that need to ask the question in Zig. The mutators
/// deliberately do *not* consult it: asking here and writing in SQL is two
/// decisions that can disagree under a concurrent writer, so they guard on the
/// rendered list and let the check happen inside the same statement as the
/// write.
pub fn canTransition(from: Status, to: Status) bool {
    for (predecessors(to)) |allowed| if (allowed == from) return true;
    return false;
}

/// Which writer a transition statement is being rendered for.
///
/// The graph says which moves exist; this says who may make them. Keeping the
/// two apart is what stops `markFinished` from being handed the promotion
/// edge: `running`'s only predecessor is `pending`, and `pending` is also a
/// predecessor of both settled states, so a settlement rendered from
/// `predecessors` alone would accept `pending` for a target of `running` just
/// as readily as `markStarted` does. Two writers with the same edge is how a
/// promotion arriving late walks a settlement backwards.
const Route = enum {
    /// `markStarted`: the launcher reporting that the command reached the
    /// remote shell.
    promotion,
    /// `markFinishedLocked`: an observer recording how the job ended.
    settlement,
};

/// Which writer owns the edge `from → to`.
///
/// A total function over the edges, which is what makes `sourcesFor` a
/// partition rather than two filters that happen not to overlap today.
fn ownerOf(to: Status, from: Status) Route {
    _ = from;
    return if (to == .running) .promotion else .settlement;
}

/// The predecessors of `to` that `route` may move.
fn sourcesFor(comptime to: Status, comptime route: Route) []const Status {
    comptime {
        var out: []const Status = &[_]Status{};
        for (predecessors(to)) |from| {
            if (ownerOf(to, from) == route) out = out ++ &[_]Status{from};
        }
        return out;
    }
}

/// Whether `route` may walk `from → to`. The Zig side of `sourcesFor`, used by
/// tests and to word a refusal that has already happened.
fn routeAllows(comptime route: Route, from: Status, comptime to: Status) bool {
    inline for (comptime sourcesFor(to, route)) |allowed| if (allowed == from) return true;
    return false;
}

/// Renders enum members as a SQL `IN` list: `'pending','running'`.
///
/// The third copy of this renderer in the store — `transfers` has one for
/// checkpoint states and `op_state` one for operation statuses — because
/// neither is reachable from here without pointing this module at one of
/// those, which is a dependency direction worth more than the twelve lines it
/// would save. What matters is the property all three share: no status
/// literal is typed into SQL anywhere in this file, so a renamed variant moves
/// every statement that constrains it.
///
/// The empty set becomes `NULL`, because `status IN ()` is a syntax error while
/// `status IN (NULL)` is never true — which is exactly what "this target has no
/// legal predecessor" means. `pending` is the only such target.
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

/// The members of `E` satisfying a role predicate, in declaration order.
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

fn predecessorList(comptime to: Status, comptime route: Route) []const u8 {
    return sqlList(Status, sourcesFor(to, route));
}

/// Whether a consumer may record how far it has read on a row in this state.
///
/// Every state — and that is not the same as no guard. The list is rendered
/// positively, so a row whose status this binary cannot name (a newer schema,
/// a hand-edited row) matches nothing and the advance is refused. A status we
/// cannot interpret is not evidence that moving somebody's read position is
/// safe.
///
/// It is every state rather than the live ones because the cursor describes
/// how much of the log a consumer has consumed, and a finished job's log is
/// exactly what a consumer is most likely to still be reading. Refusing the
/// advance once the job ended would leave `job read --from-cursor` re-reading
/// the same bytes for ever.
fn tracksReadCursor(s: Status) bool {
    return switch (s) {
        .pending, .running, .exited, .killed => true,
    };
}

const tracks_read_cursor_sql = sqlList(Status, membersWhere(Status, tracksReadCursor));

/// Which launch a write claims the row belongs to.
///
/// A two-variant type rather than a `?[]const u8`, because the two are
/// different claims and the difference decides what the SQL may match.
///
/// `owner_request_id` is nullable: rows written by 0.1.x predate the column
/// (see the v9 migration). A conjunct written the obvious way —
/// `owner_request_id IS ?1` — matches a legacy row whenever the caller passes
/// NULL, so a CAS built that way degrades to "id only" for exactly the rows
/// most likely to be stale, and id is recycled.
///
/// The policy, chosen and enforced here rather than left implicit:
///
///  * `.launch` renders `owner_request_id = ?`, which is NULL — and so never
///    true — against a legacy row. A caller holding a request id can never
///    accidentally write an unowned row.
///  * `.ownerless` renders `owner_request_id IS NULL`, which matches only
///    legacy rows. It is still a sound identity, and this is why: nothing in
///    this binary can create an unowned row. `create` takes
///    `owner_request_id: []const u8`, not an optional, so every row it writes
///    has one. A recycled rowid can therefore only be inherited by an *owned*
///    row, which `IS NULL` refuses. The pair (id, unowned) names at most one
///    row and cannot be re-pointed at a successor.
///
/// The alternative — refusing legacy rows outright — was rejected because the
/// only writer that could then clear them is `remove`, and a 0.1.x row stuck
/// at `running` would refuse every later `run --name X` until somebody deleted
/// it by hand. Admitting them under an identity that provably cannot slide is
/// strictly better than stranding them.
pub const Owner = union(enum) {
    launch: []const u8,
    ownerless,

    pub fn of(row: Job) Owner {
        return if (row.owner_request_id) |id| .{ .launch = id } else .ownerless;
    }

    fn bindValue(o: Owner) ?[]const u8 {
        return switch (o) {
            .launch => |id| id,
            .ownerless => null,
        };
    }
};

/// The owner conjunct, over a single bound parameter.
///
/// `<p> IS NULL AND owner_request_id IS NULL` is the `.ownerless` claim;
/// `owner_request_id = <p>` is the `.launch` one and is never true when either
/// side is NULL. One parameter, two exclusive readings, no branch at the call
/// site that could pick the wrong one.
fn ownerConjunct(comptime param: []const u8) []const u8 {
    return "((" ++ param ++ " IS NULL AND owner_request_id IS NULL)" ++
        " OR owner_request_id = " ++ param ++ ")";
}

pub const Job = struct {
    id: i64,
    name: []const u8,
    command: []const u8,
    sentinel: []const u8,
    status: Status,
    exit_code: ?i64,
    read_cursor: i64,
    created_at: i64,
    finished_at: ?i64,
    /// The launch that reserved this row. Null for rows written by 0.1.x,
    /// which predate the notion — see `Owner` for what a writer may do with
    /// one.
    owner_request_id: ?[]const u8,

    pub fn finishExpectation(row: Job) FinishExpectation {
        return .{ .id = row.id, .owner = Owner.of(row), .status = row.status };
    }

    pub fn cursorExpectation(row: Job) CursorExpectation {
        return .{ .id = row.id, .owner = Owner.of(row), .read_cursor = row.read_cursor };
    }

    pub fn removeExpectation(row: Job) RemoveExpectation {
        return .{ .id = row.id, .owner = Owner.of(row), .status = row.status };
    }
};

/// What `markFinishedLocked` requires the row to still be.
///
/// Three fields, and each is here because a change to it makes the write
/// wrong:
///
///  * `id` addresses the row, and on its own addresses whatever inherited the
///    rowid;
///  * `owner` says which launch that row belongs to, which is what a recycled
///    id cannot carry across a delete;
///  * `status` is the row as the caller read it. Without it two observers that
///    both saw the job end write in whatever order they happen to arrive, and
///    the one that read `running` overwrites the one that already recorded
///    `killed`. The transition rule alone does not catch that — both writes are
///    legal moves from the state each caller *thinks* the row is in.
///
/// `read_cursor` is deliberately absent. A consumer streaming output moves it
/// constantly and none of that has any bearing on how the job ended; including
/// it would make a finish fail because somebody was reading the log.
pub const FinishExpectation = struct {
    id: i64,
    owner: Owner,
    status: Status,
};

/// What `setCursor` requires the row to still be.
///
/// `read_cursor` is the snapshot here, and `status` is deliberately absent —
/// the exact mirror of the finish. The caller read bytes from position C and
/// is recording that it did; the bytes are real whether or not the job
/// finished while it read them, so a status change must not lose the advance.
/// What must not be lost is a *competing* advance: two consumers both starting
/// from C and writing 4096 and 8192 in whatever order they arrive would leave
/// the cursor wherever the slower one landed, and the faster one's caller
/// believes those bytes are consumed. Requiring the cursor to still be C makes
/// the loser find out.
pub const CursorExpectation = struct {
    id: i64,
    owner: Owner,
    read_cursor: i64,
};

/// What `removeLocked` requires the row to still be.
///
/// Same three fields as the finish, and for two of them the same reasons.
/// `status` is here for a different one: removal is the only write that
/// destroys the row, so the state the caller inspected before deciding to
/// destroy it has to still hold. `job rm` proves on the host that the session
/// is gone and then forgets the row; if between those two the name was taken
/// over by a launch that is now `pending` on a session of its own, deleting
/// what the caller read would delete the newcomer's reservation.
pub const RemoveExpectation = struct {
    id: i64,
    owner: Owner,
    status: Status,
};

/// On what basis the row is being destroyed.
///
/// The two destroying callers have established completely different things and
/// are entitled to completely different rows, so the grounds are part of the
/// statement rather than a comment at the call site.
///
/// They are also entitled to different *routes*, and that is `warrant` below:
/// one of these can be passed to `remove`, which opens a transaction and checks
/// nothing else; the other only reaches `removeLocked` from inside
/// `execution.commitDestruction`.
///
/// `run --name X` used to enforce its half in Zig, several statements before
/// the DELETE, which is the shape this store keeps closing: a guard evaluated
/// outside the transaction that acts on it is not a guard.
pub const RemovalGrounds = enum {
    /// `job rm`: the caller has been to the host and proved the tmux session
    /// is gone. Any status it can name may be forgotten — including `running`,
    /// because the proof that nothing is running is on the host and not in
    /// this column.
    session_proven_gone,
    /// `run --name X` displacing the row that holds the name. A settled row is
    /// free to go, and a `pending` reservation whose owning attempt no longer
    /// blocks a scope is reclaimable (see `cmd_job.reclaimable`). A `running`
    /// row is neither: something may be running under that name, and taking it
    /// away is `job kill` or `job rm`, both of which look at the host first.
    superseded_by_relaunch,

    fn admits(g: RemovalGrounds, s: Status) bool {
        return switch (g) {
            .session_proven_gone => switch (s) {
                .pending, .running, .exited, .killed => true,
            },
            .superseded_by_relaunch => switch (s) {
                .pending, .exited, .killed => true,
                .running => false,
            },
        };
    }

    /// What a caller destroying a row on these grounds has to be holding.
    ///
    /// Exhaustive on purpose, and that is the whole reason it is a function and
    /// not a comment: a grounds variant added later does not compile until it
    /// has said which of these two it is, and `remove` below reads the answer
    /// at comptime.
    pub fn warrant(g: RemovalGrounds) Warrant {
        return switch (g) {
            .session_proven_gone => .reread_claim,
            .superseded_by_relaunch => .grounds_alone,
        };
    }

    pub fn describe(g: RemovalGrounds) []const u8 {
        return switch (g) {
            .session_proven_gone => "removal that has proved the remote session is gone",
            .superseded_by_relaunch => "relaunch under the same name",
        };
    }
};

/// The two things that can stand behind a destruction, and they are not
/// interchangeable.
///
/// `remove` — the route that opens its own transaction — may only be handed
/// grounds whose warrant is `grounds_alone`, and it is `@compileError` rather
/// than a runtime refusal: a caller that reached for the other kind through the
/// short route would be asking for a destruction with no authority behind it,
/// which is not a thing to report at run time. It is a call that must not be
/// writable.
pub const Warrant = enum {
    /// The grounds are the whole of it. `superseded_by_relaunch` is this:
    /// `run --name X` holds a reservation, not a lease, so there is no claim
    /// for anything to re-read — and the state list is what stands in its
    /// place, admitting no `running` row.
    grounds_alone,
    /// An authority claim, re-read inside the very transaction that destroys,
    /// with the terminal receipt landing beside it. `session_proven_gone` is
    /// this: it admits *every* status including `running`, on the strength of a
    /// fact established on the host, and nothing may take that on trust from
    /// outside `execution.commitDestruction`.
    reread_claim,
};

fn removableList(comptime g: RemovalGrounds) []const u8 {
    comptime {
        var out: []const Status = &[_]Status{};
        for (@typeInfo(Status).@"enum".fields) |field| {
            const s: Status = @enumFromInt(field.value);
            if (g.admits(s)) out = out ++ &[_]Status{s};
        }
        return sqlList(Status, out);
    }
}

/// Why a guarded write matched no row.
///
/// One vocabulary for all three writers, because the questions they share are
/// the same questions and a caller has to be able to tell them apart. A
/// boolean `false` that seven call sites each interpreted for themselves is
/// how the cache came to be written by seven callers with no identity: "the
/// row moved on", "somebody else owns the name now" and "that is not a legal
/// move" want three different responses, and one bit gave the caller none of
/// them.
///
/// Every variant is a refusal the caller must report as a refusal. None of
/// them means "nothing to do".
pub const Conflict = union(enum) {
    /// Nothing carries that id any more. The row was removed — by `job rm`, by
    /// a relaunch, or by an aborted launcher releasing its reservation.
    row_gone,
    /// The row is there and it is not the caller's: the name was taken over,
    /// or the id was recycled into a different launch's row. Carries the
    /// status of the row that is actually there, which is what an operator
    /// needs to decide whether it is safe to do anything about.
    not_ours: Status,
    /// The row is the caller's, and it has moved since the caller read it.
    status_moved: struct { expected: Status, found: Status },
    /// The row is the caller's, and somebody else advanced the read cursor
    /// between the caller's read and its write.
    cursor_moved: struct { expected: i64, found: i64 },
    /// The row is the caller's and unchanged; the move itself is not one this
    /// writer may make from where the row is.
    illegal_transition: struct { from: Status, to: Status },
    /// The row is the caller's and unchanged; these grounds do not admit a row
    /// in this state.
    grounds_refuse: struct { grounds: RemovalGrounds, found: Status },
};

/// What a guarded write did, or what refused it.
pub const Write = union(enum) {
    /// The row matched the snapshot and the rule, and now says what was asked.
    applied,
    refused: Conflict,
};

/// An unreadable status is an error, never a default. Guessing `running` here
/// would be the safe direction by luck rather than by design, and the same
/// helper is used to decide whether a name may be reused.
pub const ReadError = Db.Error || Allocator.Error || error{UnknownStatus};
pub const CreateError = Db.Error || error{NameTaken};

pub const WriteError = Db.Error || error{
    UnknownStatus,
    /// A guarded write matched no row and every guard this file knows says it
    /// should have. The statement and the classifier below it have drifted
    /// apart; that is a bug here, not a refusal a caller can act on, so it
    /// leaves under its own name rather than as a `Conflict` somebody would
    /// print as advice.
    UnexplainedJobsRefusal,
};

/// Reserves the job name for one launch. The row starts `pending`: it says
/// "this name is claimed and the remote is being prepared", not "this job is
/// running".
///
/// `error.NameTaken` is the serialisation point of the whole launch path —
/// whoever loses here has not touched the remote host yet.
///
/// `owner_request_id` is what makes the reservation releasable. See the v9
/// migration for why neither the name nor the rowid can play that part. It is
/// not optional, and `Owner` leans on that: because this is the only writer
/// that creates rows, no row written by this binary is ever unowned, which is
/// what makes `(id, owner IS NULL)` a stable identity for the 0.1.x rows that
/// are.
pub fn create(
    store: *Store,
    server_id: i64,
    name: []const u8,
    command: []const u8,
    sentinel: []const u8,
    owner_request_id: []const u8,
    now: i64,
) CreateError!i64 {
    var stmt = try store.db.prepare(create_sql);
    defer stmt.deinit();
    try stmt.bindInt(1, server_id);
    try stmt.bindText(2, name);
    try stmt.bindText(3, command);
    try stmt.bindText(4, sentinel);
    try stmt.bindText(5, owner_request_id);
    try stmt.bindInt(6, now);
    _ = stmt.step() catch |err| return switch (err) {
        error.Constraint => error.NameTaken,
        else => err,
    };
    return store.db.lastInsertRowId();
}

const create_sql = std.fmt.comptimePrint(
    \\INSERT INTO jobs (server_id, name, command, sentinel, status, owner_request_id, created_at)
    \\VALUES (?1, ?2, ?3, ?4, '{[seed]s}', ?5, ?6)
, .{ .seed = @tagName(Status.pending) });

/// Promotes a reservation once the command has actually reached the remote
/// shell.
///
/// Returns false when this row was not ours to promote — it has been taken
/// over by another launcher, or an observer already settled it. The caller
/// must not read that as success: by the time this runs the command has been
/// sent, so a false here means something is running on the host that nothing
/// local is tracking under this name.
///
/// Keyed on the owning request and rendered from the transition table's
/// `promotion` route, which is the only route that has the edge into
/// `running`. A settlement cannot walk it, so a promotion and a finish
/// arriving in either order can no longer overwrite one another.
pub fn markStarted(store: *Store, owner_request_id: []const u8) Db.Error!bool {
    var stmt = try store.db.prepare(mark_started_sql);
    defer stmt.deinit();
    try stmt.bindText(1, owner_request_id);
    _ = try stmt.step();
    return store.db.changes() > 0;
}

const mark_started_sql = std.fmt.comptimePrint(
    \\UPDATE jobs SET status = '{[to]s}'
    \\ WHERE owner_request_id = ?1 AND status IN ({[from]s})
, .{
    .to = @tagName(Status.running),
    .from = predecessorList(.running, .promotion),
});

/// Gives back a reservation this launcher still owns.
///
/// Keyed on the owning request and on the row still being a reservation —
/// never on the name, and never on the rowid. A name is what a takeover
/// transfers; a rowid is reused by the very next INSERT after a delete. Either
/// would have an aborted launcher remove the *replacement's* row, leaving that
/// launcher's command running on the host with nothing tracking it.
///
/// The state list is the promotion route's source set — the states a
/// reservation can still be in — rather than a typed-out `'pending'`, so a
/// second pre-launch state would reach this statement by being classified
/// there.
///
/// Returns false when the row is no longer ours, which is not an error: it
/// means somebody else owns the name now.
pub fn releaseReservation(store: *Store, owner_request_id: []const u8) Db.Error!bool {
    var stmt = try store.db.prepare(release_reservation_sql);
    defer stmt.deinit();
    try stmt.bindText(1, owner_request_id);
    _ = try stmt.step();
    return store.db.changes() > 0;
}

const release_reservation_sql = std.fmt.comptimePrint(
    "DELETE FROM jobs WHERE owner_request_id = ?1 AND status IN ({[reserved]s})",
    .{ .reserved = predecessorList(.running, .promotion) },
);

fn rowToJob(arena: Allocator, stmt: *Db.Stmt) (Allocator.Error || error{UnknownStatus})!Job {
    return .{
        .id = stmt.columnInt(0),
        .name = try arena.dupe(u8, stmt.columnText(1)),
        .command = try arena.dupe(u8, stmt.columnText(2)),
        .sentinel = try arena.dupe(u8, stmt.columnText(3)),
        .status = try Status.parse(stmt.columnText(4)),
        .exit_code = stmt.columnOptInt(5),
        .read_cursor = stmt.columnInt(6),
        .created_at = stmt.columnInt(7),
        .finished_at = stmt.columnOptInt(8),
        .owner_request_id = if (stmt.columnOptText(9)) |v| try arena.dupe(u8, v) else null,
    };
}

const select_columns =
    \\SELECT id, name, command, sentinel, status, exit_code, read_cursor, created_at,
    \\       finished_at, owner_request_id
    \\FROM jobs
;

pub fn getByName(store: *Store, arena: Allocator, server_id: i64, name: []const u8) ReadError!?Job {
    var stmt = try store.db.prepare(select_columns ++ " WHERE server_id = ?1 AND name = ?2");
    defer stmt.deinit();
    try stmt.bindInt(1, server_id);
    try stmt.bindText(2, name);
    if (!try stmt.step()) return null;
    return try rowToJob(arena, &stmt);
}

pub const OwnerReadError = ReadError || error{
    /// Two rows claim the same launch. `create` writes one row per launch and
    /// nothing rewrites `owner_request_id`, so this cannot happen from this
    /// binary — and if it ever does, picking one by row order would be an
    /// identity decided by `ORDER BY`, which is the thing this function exists
    /// to replace.
    AmbiguousJobOwner,
};

/// The row a given launch reserved, or null if it no longer has one.
///
/// The counterpart to `getByName`, and the difference is the whole point.
/// `name` is an alias: a relaunch transfers it, `job rm` frees it, and the row
/// carrying it a moment ago need not be the row carrying it now.
/// `owner_request_id` is identity — `create` takes it, nothing rewrites it, and
/// no row this binary writes is unowned.
///
/// It exists because the snapshot CAS in this module can be handed a
/// self-satisfying expectation. `Owner.of(row)` derives the owner *from the row
/// just read*, so a caller that picked its row by name proves only "this row
/// has not changed since I read it" and never "this row belongs to the
/// operation I am settling". `Cli.jobCacheSync` did exactly that: it looked the
/// blocker's row up by its `job_name` and, when a later launch had taken that
/// name over, stamped the blocker's exit code onto the successor's row — every
/// conjunct satisfied, `applied` returned, nothing refused, nothing printed.
/// A caller that starts from the request id cannot make that mistake.
pub fn byOwner(store: *Store, arena: Allocator, owner_request_id: []const u8) OwnerReadError!?Job {
    var stmt = try store.db.prepare(select_columns ++ " WHERE owner_request_id = ?1");
    defer stmt.deinit();
    try stmt.bindText(1, owner_request_id);
    if (!try stmt.step()) return null;
    const row = try rowToJob(arena, &stmt);
    if (try stmt.step()) return error.AmbiguousJobOwner;
    return row;
}

pub fn list(store: *Store, arena: Allocator, server_id: i64) ReadError![]Job {
    var out: std.ArrayList(Job) = .empty;
    var stmt = try store.db.prepare(select_columns ++ " WHERE server_id = ?1 ORDER BY created_at DESC");
    defer stmt.deinit();
    try stmt.bindInt(1, server_id);
    while (try stmt.step()) try out.append(arena, try rowToJob(arena, &stmt));
    return out.toOwnedSlice(arena);
}

/// The facts a refused write is classified from: the row as it stands now,
/// and whether it is the caller's.
const Found = struct {
    status: Status,
    read_cursor: i64,
    ours: bool,
};

/// Re-reads a row after a guarded write matched nothing.
///
/// The ownership answer is computed by sqlite from the same fragment the
/// statements guard on, so the classifier cannot start naming a conjunct the
/// write no longer contains. Null means no row carries that id at all.
///
/// Every caller runs inside the transaction that performed the write — the
/// `*Locked` writers because their caller holds one, `setCursor` because it
/// opens its own — so this describes the same snapshot the write saw rather
/// than a later one.
fn found(store: *Store, id: i64, owner: Owner) WriteError!?Found {
    var stmt = try store.db.prepare(found_sql);
    defer stmt.deinit();
    try stmt.bindInt(1, id);
    try stmt.bindOptText(2, owner.bindValue());
    if (!try stmt.step()) return null;
    return .{
        .status = try Status.parse(stmt.columnText(0)),
        .read_cursor = stmt.columnInt(1),
        .ours = stmt.columnInt(2) != 0,
    };
}

const found_sql = std.fmt.comptimePrint(
    "SELECT status, read_cursor, {[owner]s} FROM jobs WHERE id = ?1",
    .{ .owner = ownerConjunct("?2") },
);

/// Records how a job ended, against the row the caller read.
///
/// Caller must hold the write transaction, and that is the substance of this
/// signature rather than housekeeping. Every caller settles the operation
/// ledger in the same breath, and the two used to be separate transactions:
/// between them the ledger said the attempt was over while the row that gates
/// the next `run --name X` still said `running`, and any observer arriving in
/// the gap acted on a pair of records that never described the same moment.
/// There is no unlocked variant on purpose — a caller that wants to write this
/// row has to have decided what else belongs in the transaction with it. See
/// `execution.settleAttachedAndSyncJob`.
///
/// Two guards, and they catch different things. The snapshot conjunct
/// (`status = <what the caller read>`) catches a peer that settled the row in
/// between; the route conjunct (`status IN <live states>`) catches a caller
/// whose own snapshot was already settled. Dropping either one leaves a way to
/// overwrite a recorded outcome.
pub fn markFinishedLocked(
    store: *Store,
    expected: FinishExpectation,
    to: Settled,
    exit_code: ?i64,
    now: i64,
) WriteError!Write {
    try store.db.requireTransaction();
    switch (to) {
        inline else => |target| {
            const status = comptime target.toStatus();
            var stmt = try store.db.prepare(comptime markFinishedSql(status));
            defer stmt.deinit();
            try stmt.bindOptInt(1, exit_code);
            try stmt.bindInt(2, now);
            try stmt.bindInt(3, expected.id);
            try stmt.bindOptText(4, expected.owner.bindValue());
            try stmt.bindText(5, expected.status.text());
            _ = try stmt.step();
            if (store.db.changes() != 0) return .applied;

            const row = (try found(store, expected.id, expected.owner)) orelse
                return .{ .refused = .row_gone };
            if (!row.ours) return .{ .refused = .{ .not_ours = row.status } };
            if (row.status != expected.status) return .{ .refused = .{ .status_moved = .{
                .expected = expected.status,
                .found = row.status,
            } } };
            // Ours, and exactly as the caller read it — so what refused the
            // write is the route conjunct, and the caller's own snapshot names
            // a state a settlement cannot leave.
            return .{ .refused = .{ .illegal_transition = .{
                .from = row.status,
                .to = status,
            } } };
        },
    }
}

/// `markFinishedLocked` for the one caller that has nothing to compose with: a
/// `jobs` row whose attempt row is missing, so there is no operation to settle
/// beside it.
///
/// Named for that case rather than offered as a general unlocked writer,
/// because every other caller does have a settlement to put in the transaction
/// and taking it back out is the defect this file exists to have closed. The
/// row still has to stop claiming the job is live: `run --name X` consults it
/// before the scope guard, and a cache stuck at `running` for a job that ended
/// is a wall with no ledger row behind it to explain itself.
pub fn markFinishedUnattached(
    store: *Store,
    expected: FinishExpectation,
    to: Settled,
    exit_code: ?i64,
    now: i64,
) WriteError!Write {
    try store.db.exec("BEGIN IMMEDIATE");
    errdefer store.db.exec("ROLLBACK") catch {};
    const result = try markFinishedLocked(store, expected, to, exit_code, now);
    try store.db.exec("COMMIT");
    return result;
}

fn markFinishedSql(comptime to: Status) [:0]const u8 {
    return std.fmt.comptimePrint(
        \\UPDATE jobs SET status = '{[to]s}', exit_code = ?1, finished_at = ?2
        \\ WHERE id = ?3
        \\   AND {[owner]s}
        \\   AND status = ?5
        \\   AND status IN ({[from]s})
    , .{
        .to = @tagName(to),
        .owner = ownerConjunct("?4"),
        .from = predecessorList(to, .settlement),
    });
}

/// Moves a consumer's read position, against the row the caller read.
///
/// The one writer here with nothing to compose with: advancing a cursor
/// records that bytes were handed to a caller, which no ledger event
/// corresponds to. It opens its own transaction so the UPDATE and the
/// classifying re-read describe one snapshot.
pub fn setCursor(store: *Store, expected: CursorExpectation, cursor: i64) WriteError!Write {
    try store.db.exec("BEGIN IMMEDIATE");
    errdefer store.db.exec("ROLLBACK") catch {};
    const result = try setCursorLocked(store, expected, cursor);
    try store.db.exec("COMMIT");
    return result;
}

fn setCursorLocked(store: *Store, expected: CursorExpectation, cursor: i64) WriteError!Write {
    var stmt = try store.db.prepare(set_cursor_sql);
    defer stmt.deinit();
    try stmt.bindInt(1, cursor);
    try stmt.bindInt(2, expected.id);
    try stmt.bindOptText(3, expected.owner.bindValue());
    try stmt.bindInt(4, expected.read_cursor);
    _ = try stmt.step();
    if (store.db.changes() != 0) return .applied;

    const row = (try found(store, expected.id, expected.owner)) orelse
        return .{ .refused = .row_gone };
    if (!row.ours) return .{ .refused = .{ .not_ours = row.status } };
    if (row.read_cursor != expected.read_cursor) return .{ .refused = .{ .cursor_moved = .{
        .expected = expected.read_cursor,
        .found = row.read_cursor,
    } } };
    // Every conjunct this statement carries has now been shown to hold: the
    // row is there, it is ours, its cursor is where the caller left it, and
    // its status parsed — which is the whole of `tracksReadCursor`. There is
    // nothing left that could have refused the write, so the statement and
    // this classifier no longer describe the same guards.
    return error.UnexplainedJobsRefusal;
}

const set_cursor_sql = std.fmt.comptimePrint(
    \\UPDATE jobs SET read_cursor = ?1
    \\ WHERE id = ?2
    \\   AND {[owner]s}
    \\   AND read_cursor = ?4
    \\   AND status IN ({[states]s})
, .{ .owner = ownerConjunct("?3"), .states = tracks_read_cursor_sql });

/// Displaces a job row, against the row the caller read and on stated grounds.
///
/// Opens its own transaction, and that is the whole of what it can offer: no
/// claim is re-read inside it and no terminal lands beside the DELETE. So it
/// takes only grounds that need neither — `Warrant.grounds_alone` — and the
/// check is a `@compileError`, not a refusal. Today that admits exactly one
/// variant, `superseded_by_relaunch`, and exactly one caller: `run --name X`
/// taking over the row that holds the name. That caller holds a reservation
/// rather than a lease, so there is no claim for a contract to re-read and no
/// operation of somebody else's to settle; the grounds are what stand in for
/// the authority, and they admit no `running` row.
///
/// **`job rm` must not use it**, and now cannot: `session_proven_gone` admits
/// every status on the strength of a trip to the host, and a route with no
/// in-transaction claim check may not act on that. It goes to `removeLocked`
/// through `execution.settleAndForgetJob`, where the delete, the terminal and
/// the claim check land together or not at all.
pub fn remove(
    store: *Store,
    expected: RemoveExpectation,
    comptime grounds: RemovalGrounds,
) WriteError!Write {
    comptime switch (grounds.warrant()) {
        .grounds_alone => {},
        .reread_claim => @compileError(
            "jobs.remove opens a transaction of its own and re-reads no claim, so it" ++
                " cannot destroy on ." ++ @tagName(grounds) ++ " grounds. Those need the" ++
                " destruction contract: execution.Execution.settleAndForgetJob, which" ++
                " reaches jobs.removeLocked inside the transaction that also settles.",
        ),
    };
    try store.db.exec("BEGIN IMMEDIATE");
    errdefer store.db.exec("ROLLBACK") catch {};
    const result = try removeLocked(store, expected, grounds);
    try store.db.exec("COMMIT");
    return result;
}

pub fn removeLocked(
    store: *Store,
    expected: RemoveExpectation,
    comptime grounds: RemovalGrounds,
) WriteError!Write {
    try store.db.requireTransaction();
    var stmt = try store.db.prepare(comptime removeSql(grounds));
    defer stmt.deinit();
    try stmt.bindInt(1, expected.id);
    try stmt.bindOptText(2, expected.owner.bindValue());
    try stmt.bindText(3, expected.status.text());
    _ = try stmt.step();
    if (store.db.changes() != 0) return .applied;

    const row = (try found(store, expected.id, expected.owner)) orelse
        return .{ .refused = .row_gone };
    if (!row.ours) return .{ .refused = .{ .not_ours = row.status } };
    if (row.status != expected.status) return .{ .refused = .{ .status_moved = .{
        .expected = expected.status,
        .found = row.status,
    } } };
    // Ours and unmoved, so what refused it is the grounds list: the caller
    // read this state, and these grounds do not entitle it to destroy a row in
    // it.
    return .{ .refused = .{ .grounds_refuse = .{ .grounds = grounds, .found = row.status } } };
}

fn removeSql(comptime grounds: RemovalGrounds) [:0]const u8 {
    return std.fmt.comptimePrint(
        \\DELETE FROM jobs
        \\ WHERE id = ?1
        \\   AND {[owner]s}
        \\   AND status = ?3
        \\   AND status IN ({[states]s})
    , .{ .owner = ownerConjunct("?2"), .states = removableList(grounds) });
}

test "the two routes partition the transition graph" {
    const t = std.testing;

    // Every edge belongs to exactly one writer. A split that dropped an edge
    // would make a state unreachable; one that shared an edge would put back
    // the rule this partition exists to remove — a settlement able to walk the
    // promotion.
    inline for (@typeInfo(Status).@"enum".fields) |to_field| {
        const to: Status = @enumFromInt(to_field.value);
        for (predecessors(to)) |from| {
            const by_promotion = routeAllows(.promotion, from, to);
            const by_settlement = routeAllows(.settlement, from, to);
            try t.expect(by_promotion != by_settlement);
        }
    }

    // And the edges themselves, spelled out so a change to the table has to
    // be made twice, in two different notations.
    try t.expect(canTransition(.pending, .running));
    try t.expect(canTransition(.pending, .exited));
    try t.expect(canTransition(.running, .killed));
    try t.expect(!canTransition(.exited, .killed));
    try t.expect(!canTransition(.killed, .exited));
    try t.expect(!canTransition(.exited, .exited));
    try t.expect(!canTransition(.running, .pending));
    try t.expect(!canTransition(.running, .running));

    // The promotion has one edge and the settlement cannot walk it.
    try t.expect(routeAllows(.promotion, .pending, .running));
    try t.expect(!routeAllows(.settlement, .pending, .running));
    try t.expect(routeAllows(.settlement, .pending, .exited));
    try t.expect(routeAllows(.settlement, .running, .exited));
}

test "the rendered lists say what the predicates say" {
    const t = std.testing;

    // Pinning the rendered text, not the predicate — these strings are what
    // sqlite evaluates, and a renderer that quietly produced an empty or
    // reordered list would leave every gate above passing.
    try t.expectEqualStrings("'pending'", comptime predecessorList(.running, .promotion));
    try t.expectEqualStrings("'pending','running'", comptime predecessorList(.exited, .settlement));
    try t.expectEqualStrings("'pending','running'", comptime predecessorList(.killed, .settlement));
    try t.expectEqualStrings("NULL", comptime predecessorList(.pending, .settlement));
    try t.expectEqualStrings("'pending','running','exited','killed'", tracks_read_cursor_sql);

    // The two grounds are different lists. `running` is the difference, and it
    // is the whole point: `job rm` has been to the host, a relaunch has not.
    try t.expectEqualStrings(
        "'pending','running','exited','killed'",
        comptime removableList(.session_proven_gone),
    );
    try t.expectEqualStrings(
        "'pending','exited','killed'",
        comptime removableList(.superseded_by_relaunch),
    );
}

test "the short route admits exactly the grounds that need no claim" {
    const t = std.testing;

    // `remove` — the route that opens its own transaction — refuses anything
    // whose warrant is `reread_claim`, and refuses it at compile time, so there
    // is no runtime behaviour here to check. What is checkable is the partition
    // it reads, and the number that partition currently produces.
    //
    // **One of two.** `superseded_by_relaunch` is the only grounds a caller may
    // put through `remove`; `session_proven_gone` admits a `running` row on the
    // strength of a fact established on the host, and nothing may take that on
    // trust outside `execution.commitDestruction`. A change that moved the
    // second one across would make `jobs.remove(row, .session_proven_gone)`
    // writable again, and it fails here first.
    var short_route: usize = 0;
    inline for (@typeInfo(RemovalGrounds).@"enum".fields) |field| {
        const g: RemovalGrounds = @enumFromInt(field.value);
        // Exhaustive by construction — `warrant` is a total switch — so this
        // counts rather than tolerates.
        switch (g.warrant()) {
            .grounds_alone => short_route += 1,
            .reread_claim => {},
        }
    }
    try t.expectEqual(@as(usize, 1), short_route);
    try t.expectEqual(Warrant.grounds_alone, RemovalGrounds.superseded_by_relaunch.warrant());
    try t.expectEqual(Warrant.reread_claim, RemovalGrounds.session_proven_gone.warrant());

    // And the two questions are not the same question. The grounds that need a
    // claim are exactly the grounds that admit a live row, which is why the
    // short route may not carry them — but `admits` is a per-status predicate
    // and `warrant` is a per-route one, and asserting the correspondence here
    // is what keeps a later variant from being given the short route while
    // quietly admitting `running`.
    inline for (@typeInfo(RemovalGrounds).@"enum".fields) |field| {
        const g: RemovalGrounds = @enumFromInt(field.value);
        try t.expectEqual(g.admits(.running), g.warrant() == .reread_claim);
    }
}
