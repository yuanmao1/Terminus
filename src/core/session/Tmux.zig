//! Remote tmux session management, built on Executor exec calls — works
//! identically over a direct SSH connection or the daemon's pooled one.
//!
//! Layout on the remote host:
//! * one tmux session per Terminus session, named `t-<name>`
//! * `tmux pipe-pane` mirrors all pane output into
//!   `~/.terminus/logs/<name>.log`, which is what cursor reads consume
//! * a job additionally writes `~/.terminus/results/<request-id>.json` — its
//!   durable terminal result, keyed by the operation that launched it
//!
//! The local sqlite `sessions.cursor` is a byte offset into that log.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Ssh = @import("../ssh/Client.zig");
const Executor = @import("../exec.zig").Executor;

const log_dir = "$HOME/.terminus/logs";

/// Where job result sidecars live. Separate from the log directory because a
/// result must survive log rotation and `pipe-pane` restarts: the log is a
/// stream someone else owns, the result is a fact about one operation.
const result_dir = "$HOME/.terminus/results";

pub const Error = Ssh.ExecError || error{
    TmuxMissing,
    SessionNotFound,
    /// The session disappeared while a command was running in it (the
    /// command likely terminated the shell, e.g. `exit`).
    SessionDied,
    RemoteFailed,
    /// The remote answered, but not with the framing its own script
    /// guarantees, so what came back is not a reading of anything.
    ///
    /// Deliberately not folded into `RemoteFailed`. That one means "the script
    /// ran and reported failure" — a fact about the host. This one means "the
    /// script's output did not arrive intact" — a fact about the channel. A
    /// caller that cannot tell them apart cannot tell a broken log from a
    /// broken connection, and only one of those is worth retrying unchanged.
    ///
    /// Adding this variant forces no caller to change: nothing switches
    /// exhaustively on `Tmux.Error`. `fatalTmux` (cmd_exec.zig:407) takes
    /// `anyerror` and ends in `else`, and the only other switch over these
    /// errors — `execIn`'s failure arm at cmd_exec.zig:318 — ends in `else`
    /// too, which routes this to `transportLoss` and settles the attempt
    /// `indeterminate`. That is the honest reading of an answer that was cut
    /// short: we asked, something came back, and it does not say anything.
    TruncatedResponse,
    /// A result sidecar is at this request's own address and the host could
    /// not read it. Not "there is no result" — the opposite: something is
    /// there, and the one reader that could have said what it is came back
    /// empty-handed.
    ///
    /// Its own member, and deliberately not a `ResultReading`. The readers
    /// used to run `head -c N "$r" | tr -d '\n'`, and a POSIX pipeline exits
    /// with the status of its *last* command — so `tr` succeeded whenever
    /// `head` failed on a permission error, an I/O error, or a directory where
    /// a file was expected. The script exited 0 with no output, and no output
    /// is the documented spelling of `absent`. A read failure was therefore
    /// indistinguishable from the absence of evidence, and `absent` is the one
    /// reading that lets the log sentinel settle the operation on its own:
    /// a defect at this address was being laundered into a licence to settle
    /// from the weaker record.
    ///
    /// An error rather than a fifth defective reading because the two unions
    /// that would have to carry one — `ResultReading` and `SidecarReading` —
    /// publish their tag names into `skill/SKILL.md` and into
    /// `receipts.ResultRecordReading`, and neither could be touched by the
    /// change that found this. See the note on `result_unreadable_exit`: an
    /// error settles nothing and licenses nothing, which is the property that
    /// mattered; what it costs is the 75 a defective reading earns, because a
    /// caller that never receives a probe cannot settle `indeterminate` from
    /// one.
    ///
    /// Adding this variant forces no caller to change, for the reason
    /// `TruncatedResponse` gives above: nothing switches exhaustively on
    /// `Tmux.Error`.
    ResultUnreadable,
    CommandTimeout,
};

fn logPath(arena: Allocator, name: []const u8) Allocator.Error![]u8 {
    return std.fmt.allocPrint(arena, "{s}/{s}.log", .{ log_dir, name });
}

/// The real tmux session name for a Terminus session: the `t-` prefixed form.
///
/// tmux session names get the prefix to keep Terminus-managed sessions
/// recognizable in `tmux ls` on the server. It is also the only name that
/// exists on the host, so it is the one an operator has to type — which is
/// why this is public. A message telling somebody to run
/// `tmux attach -t <terminus name>` names a session that is not there.
pub fn targetName(arena: Allocator, name: []const u8) Allocator.Error![]u8 {
    return std.fmt.allocPrint(arena, "t-{s}", .{name});
}

/// Wraps `s` in single quotes for POSIX shells ('a'\''b' pattern).
pub fn shellQuote(arena: Allocator, s: []const u8) Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.append(arena, '\'');
    for (s) |ch| {
        if (ch == '\'') {
            try out.appendSlice(arena, "'\\''");
        } else {
            try out.append(arena, ch);
        }
    }
    try out.append(arena, '\'');
    return out.toOwnedSlice(arena);
}

fn run(executor: Executor, arena: Allocator, command: []const u8) Error!Ssh.ExecResult {
    return executor.exec(arena, command);
}

/// A job's durable terminal result, as the remote wrapper recorded it.
pub const JobResult = struct {
    /// The request id the *document itself* named, copied out of the parsed
    /// JSON.
    ///
    /// Deliberately not called `request_id`: it is the identity the evidence
    /// claimed, not the one we went looking for. They are equal only because
    /// `parseJobResult` refused the document otherwise, and a receipt that
    /// records this field records what the document said. Filling a receipt
    /// from the id we searched with instead produces a claim that is true by
    /// construction — it compares a value against itself — which is how the
    /// Store's identity check came to be unfalsifiable.
    claimed_request_id: []const u8,
    exit_code: i32,
    /// Unix seconds as the *remote* clock saw them, or null when the remote
    /// could not say. Optional rather than 0-means-absent: the wrapper writes
    /// 0 on a host without a usable `date`, and a type that cannot express
    /// "absent" forces every reader to re-derive that convention — one of them
    /// will get it wrong and publish 1970 as a finish time.
    ///
    /// Never substituted with a local timestamp: a receipt that says when
    /// something finished must not be quoting a different machine's clock.
    finished_at: ?i64,
};

/// Schema version of the sidecar document. Bump when a reader has to
/// understand something new; the reader rejects versions it does not know
/// rather than guessing at the fields it recognizes.
const result_schema_version: i64 = 1;

/// Builds the line typed into the job's shell.
///
/// Three things happen after the user's command, in this order:
///   1. its status is captured into `__t_rc`, before anything else can
///      clobber `$?`;
///   2. the result sidecar is written to a `.part` file and `mv`'d into
///      place, so a reader never sees a half-written document;
///   3. the log sentinel is echoed.
///
/// The sidecar exists because the sentinel alone is not durable evidence. It
/// is one line in an append-only log, and a job that keeps printing after it
/// finishes — a disowned child, a background tail — pushes it out of the tail
/// window a probe can afford to read. At that point the log can no longer
/// answer how the job ended, and neither could we. The sidecar is a fixed
/// location holding exactly one fact, so it stays answerable forever.
///
/// The sentinel is still written, and still read as a fallback: jobs launched
/// by an older build have no sidecar, and `--discard-evidence` may have taken
/// one away.
pub fn jobLaunchLine(
    arena: Allocator,
    command: []const u8,
    cwd: ?[]const u8,
    sentinel: []const u8,
    request_id: []const u8,
) Allocator.Error![]u8 {
    const body = if (cwd) |dir|
        try std.fmt.allocPrint(arena, "cd {s} && ({s})", .{ dir, command })
    else
        try std.fmt.allocPrint(arena, "({s})", .{command});

    // `date` is best-effort: a host without it still gets a valid document,
    // with finishedAt=0 meaning "the remote could not say".
    return std.fmt.allocPrint(
        arena,
        "mkdir -p {s} 2>/dev/null; {s}; __t_rc=$?; __t_res={s}/{s}.json; " ++
            "printf '{{\"v\":{d},\"requestId\":\"{s}\",\"exitCode\":%s,\"finishedAt\":%s}}' " ++
            "\"$__t_rc\" \"$(date +%s 2>/dev/null || echo 0)\" > \"$__t_res.part\" 2>/dev/null " ++
            "&& mv -f \"$__t_res.part\" \"$__t_res\" 2>/dev/null; echo {s}:$__t_rc",
        .{ result_dir, body, result_dir, request_id, result_schema_version, request_id, sentinel },
    );
}

/// Ceiling on how much of a sidecar we read. The document is one short line;
/// anything bigger is not ours, and reading it is how a probe turns into an
/// unbounded transfer.
const max_result_bytes: i64 = 4096;

/// The exit status both sidecar readers use for "the file is at this address
/// and we could not read it".
///
/// A status of its own, not folded into the 1 that `head` itself returns: 1 is
/// also what any other command in these scripts answers when it fails, and a
/// reader that cannot tell "the result record would not open" from "something
/// else in the script went wrong" has to report the vaguer of the two.
///
/// Chosen out of the same private range as `ensure`'s 41/42 and `sendKeys`'
/// 43. Nothing on the host produces it: `head` exits 0 or 1, and the shell
/// answers 126/127 for a command it cannot run.
const result_unreadable_exit: i32 = 44;

/// The script `readResult` runs, and the one the black-box gate executes
/// through a real POSIX shell.
///
/// Public and separate from `readResult` because reading generated shell text
/// is not the same as knowing what it does — and what this text does under a
/// failing `head` is the whole point of it. The gate needs the exact bytes the
/// binary sends, not a transcription of them.
///
/// Three exits, and they are three different facts:
///   * 0 with no output — nothing at the address. `absent`;
///   * 0 with output — the document, for `parseJobResult` to judge;
///   * `result_unreadable_exit` — the file is there and `head` could not read
///     it. No pipeline: `head` writes straight to stdout, so its status is the
///     script's status. The newline squeezing `tr -d '\n'` used to do is done
///     in Zig now, because `tr` in that position was what threw the status
///     away.
pub fn resultReadScript(arena: Allocator, request_id: []const u8) Allocator.Error![]u8 {
    return std.fmt.allocPrint(arena,
        \\r={s}/{s}.json
        \\[ -f "$r" ] || exit 0
        \\head -c {d} "$r" || exit {d}
    , .{ result_dir, request_id, max_result_bytes, result_unreadable_exit });
}

/// Separates the sidecar document from the log window in a probe's output.
///
/// The sidecar used to be squeezed onto a single line by `tr -d '\n'`, which
/// made a line-start match on this marker provably unable to land inside it.
/// That `tr` is gone — it was the last command of a pipeline, so it answered 0
/// for a `head` that had failed, and a read failure came back as an absence.
/// What is left is weaker and says so: a sidecar carrying a line that is
/// exactly this marker splits in the wrong place.
///
/// It fails closed rather than quietly. The prefix before the false marker is
/// judged by `parseJobResult`, which reads a partial document as `malformed` —
/// a defect that settles nothing — and the remainder is then parsed as the
/// log's byte count, which is not a number, so the probe ends in
/// `error.RemoteFailed`. No outcome can be established through that path,
/// which is the property the `tr` was protecting.
const probe_split_marker = "__TERMINUS_PROBE_SPLIT__";

const ProbeHalves = struct {
    /// The sidecar document, or empty if there was none.
    result: []const u8,
    /// Everything after the marker line: the log size line and the window.
    rest: []const u8,
};

fn splitProbe(stdout: []const u8) ?ProbeHalves {
    var search: usize = 0;
    while (std.mem.indexOfPos(u8, stdout, search, probe_split_marker)) |pos| {
        const line_start = if (std.mem.lastIndexOfScalar(u8, stdout[0..pos], '\n')) |nl| nl + 1 else 0;
        const line_end = std.mem.indexOfScalarPos(u8, stdout, pos, '\n') orelse stdout.len;
        const tail = std.mem.trim(u8, stdout[pos + probe_split_marker.len .. line_end], " \t\r");
        if (line_start == pos and tail.len == 0) return .{
            .result = std.mem.trim(u8, stdout[0..line_start], " \t\r\n"),
            .rest = if (line_end < stdout.len) stdout[line_end + 1 ..] else "",
        };
        search = pos + probe_split_marker.len;
    }
    return null;
}

/// What the sidecar at one request's address turned out to be.
///
/// Five readings, kept apart because an operator does three different things
/// about them. The old return type was `?JobResult`, and `null` meant every
/// one of the first four at once — so a caller could not tell "there is no
/// evidence" from "there is evidence and we cannot read it" from "there is
/// evidence and it belongs to somebody else", and the last of those, which is
/// the loudest fact this parser can establish, was the quietest thing it said.
///
/// None of the four non-`present` readings settles anything, and that is not
/// weakened here. What changes is that each of them now says which it is.
///
/// Four of the five are *defects* and one is an absence, and the difference
/// decides an operation's terminal state. `absent` lets the log sentinel
/// answer, because nothing was written at this address and the sentinel is the
/// only record there is. The other four forbid the sentinel from answering
/// either: something wrote a document at an address derived from this
/// operation's own id and we cannot read it, so the weaker record's agreement
/// with it cannot be checked, and settling from the weaker record alone would
/// publish a proven outcome next to evidence we have just refused. See
/// `defective` and `readingOf`.
pub const ResultReading = union(enum) {
    /// Nothing at the address. The job predates sidecars, or
    /// `--discard-evidence` took it away. The sentinel path is the answer, and
    /// this is the only one of the four where falling through to it is
    /// unremarkable rather than a report an operator needs.
    absent,
    /// Bytes are there and they are not a document this build can parse.
    /// Either a different build of the remote wrapper wrote it, or the file
    /// was cut short mid-write — `jobLaunchLine` writes a `.part` and renames
    /// it precisely so a reader never sees a half-written document, so one
    /// turning up anyway is a fact about the host, not a parser detail.
    malformed,
    /// Parsed, and declares a schema version this build does not know; carries
    /// the version it declared. The recognised fields are deliberately not
    /// read anyway: a reader that keeps the fields it understands is how a
    /// future document whose `exitCode` means something else comes to settle
    /// an operation.
    unknown_schema: i64,
    /// Parsed and ours, but `exitCode` is not a shell exit status (0-255), so
    /// it was not written by our wrapper whatever it claims; carries the value
    /// it carried.
    exit_code_out_of_range: i64,
    /// Parsed, and names a *different* request; carries the id it claimed, for
    /// reporting only. This is the reading that means the result directory is
    /// being reused or two request ids collided, and taking it as ours would
    /// settle this operation from somebody else's exit code — which is the
    /// whole reason results are keyed by request id.
    foreign: []const u8,
    /// A document we can read, at our address, naming us.
    present: JobResult,

    /// The document, when there is a usable one. The only way to a `JobResult`
    /// from here, so a caller cannot reach one down an arm that refused it.
    ///
    /// Says nothing about *why* there is no document, and must not be the only
    /// question a settlement asks. Five arms answer `null` here and they split
    /// two ways — see `defective`.
    pub fn usable(r: ResultReading) ?JobResult {
        return switch (r) {
            .present => |doc| doc,
            .absent, .malformed, .unknown_schema, .exit_code_out_of_range, .foreign => null,
        };
    }

    /// Whether something was written at this operation's own address that we
    /// could not use — as opposed to nothing having been written there at all.
    ///
    /// `absent` is the absence of evidence. The other four are evidence that
    /// something is wrong: a document exists at an address derived from this
    /// request's id, and it is unreadable, from a schema we do not know,
    /// carrying an exit code no shell produces, or naming somebody else. An
    /// operation must not settle on the strength of a weaker record while one
    /// of those sits beside it, and `usable` alone cannot express that because
    /// it answers `null` to both categories.
    ///
    /// Delegates to `SidecarReading.anomalous` rather than repeating the arm
    /// list: the line between the two categories is drawn once, and adding a
    /// reading to either union is a compile error until it is placed on one
    /// side of it.
    pub fn defective(r: ResultReading) bool {
        return r.summary().anomalous();
    }

    /// This reading with the document dropped, for carrying on a `JobProbe`.
    pub fn summary(r: ResultReading) SidecarReading {
        return switch (r) {
            .absent => .absent,
            .malformed => .malformed,
            .unknown_schema => |v| .{ .unknown_schema = v },
            .exit_code_out_of_range => |code| .{ .exit_code_out_of_range = code },
            .foreign => |claimed| .{ .foreign = claimed },
            .present => .present,
        };
    }
};

/// What a probe found at the sidecar's address, minus the document itself.
///
/// The same readings as `ResultReading` plus "we did not look", and
/// deliberately *without* the parsed document on the `present` arm. A
/// `JobProbe` already publishes everything a usable document establishes —
/// `exit_code`, `finished_at`, `result_request_id` — through fields that
/// `readingOf` withholds when the two durable records disagree. Carrying the
/// document here as well would put those same values back within reach on
/// exactly the path that refuses to settle from them.
pub const SidecarReading = union(enum) {
    /// No request id was given, so no sidecar was looked for. Distinct from
    /// `absent`: one is "we did not ask", the other is "we asked and there is
    /// nothing there".
    not_requested,
    absent,
    malformed,
    unknown_schema: i64,
    exit_code_out_of_range: i64,
    foreign: []const u8,
    present,

    /// A stable machine-readable name, so a caller branches on the reading
    /// rather than on prose. Derived from the tag so the two cannot drift.
    pub fn code(r: SidecarReading) []const u8 {
        return @tagName(r);
    }

    /// Whether this reading is something an operator has to be told about.
    ///
    /// "We did not look", "it is not there" and "it is there and it is ours"
    /// are the three ordinary answers. The other four each mean somebody
    /// wrote a document at this operation's own address that we could not use,
    /// which is never routine.
    pub fn anomalous(r: SidecarReading) bool {
        return switch (r) {
            .not_requested, .absent, .present => false,
            .malformed, .unknown_schema, .exit_code_out_of_range, .foreign => true,
        };
    }

    /// The sentence for an anomalous reading, or null when there is nothing
    /// wrong to report.
    ///
    /// One sentence per reading rather than a shared "could not read the
    /// result record": which of the four it is decides what happens next —
    /// check the remote wrapper's build, or go and find out why two
    /// operations are writing to one address.
    pub fn describe(r: SidecarReading, arena: Allocator) Allocator.Error!?[]const u8 {
        return switch (r) {
            .not_requested, .absent, .present => null,
            .malformed => "this job's result record is present but could not be parsed: something wrote a document this build cannot read, or the file was cut short mid-write. It was not read as evidence",
            .unknown_schema => |v| try std.fmt.allocPrint(
                arena,
                "this job's result record is present but declares schema version {d}, which this build does not know (it reads version {d}); the remote wrapper is from a different build. It was not read as evidence",
                .{ v, result_schema_version },
            ),
            .exit_code_out_of_range => |value| try std.fmt.allocPrint(
                arena,
                "this job's result record is present but reports exit {d}, which is not a shell exit status (0-255), so it was not written by our wrapper whatever it claims. It was not read as evidence",
                .{value},
            ),
            .foreign => |claimed| try std.fmt.allocPrint(
                arena,
                "this job's result record is present but names request {s}, not this one: the result directory is being reused, or two request ids collided. It was not read as evidence",
                .{claimed},
            ),
        };
    }
};

/// Reads back the sidecar document, and says what it found.
///
/// The four non-`present` readings are all "no usable result", and the reason
/// they are four values rather than one absence is that they are four
/// different situations. A missing file is ordinary. A document that will not
/// parse, or declares a schema we do not know, or carries an exit code no
/// shell could have produced, means something wrote a document we cannot read.
/// A document naming a *different* request means the result directory is being
/// reused or a request id collided — the loudest of the three, and the one a
/// single `null` return hid most completely.
///
/// The point of keying results by request id is that a leftover file from an
/// earlier attempt must not be read as this attempt's outcome, so a mismatch
/// yields no reading at all rather than a weaker one.
///
/// The returned `claimed_request_id` on the `present` arm is therefore always
/// equal to `request_id` — and it is still carried, because the equality is a
/// fact this parser established rather than one the receipt may assume. The
/// Store checks the same thing again when the evidence is offered
/// (`receipts.resolve`). Two independent checks on a scope-releasing path is
/// the point, not redundancy to be collapsed: this one keeps a foreign
/// document from ever being handed back as a reading, the other keeps a
/// caller from aiming a perfectly good reading at the wrong operation. Delete
/// either and the surviving one has to be trusted alone.
///
/// The checks are in the order below and it is load-bearing. A document whose
/// version we do not know is reported as such even if its `requestId` field
/// also disagrees: under an unknown schema we cannot say that field still
/// means what we think it means, so claiming to know whose document it is
/// would be reading fields out of a layout we have just admitted we do not
/// understand.
fn parseJobResult(arena: Allocator, text: []const u8, request_id: []const u8) Allocator.Error!ResultReading {
    const trimmed = std.mem.trim(u8, text, " \t\r\n");
    if (trimmed.len == 0) return .absent;
    const Doc = struct {
        v: i64 = 0,
        requestId: []const u8 = "",
        exitCode: i64 = -1,
        finishedAt: i64 = 0,
    };
    const doc = std.json.parseFromSliceLeaky(Doc, arena, trimmed, .{
        .ignore_unknown_fields = true,
    }) catch return .malformed;
    if (doc.v != result_schema_version) return .{ .unknown_schema = doc.v };
    // Duped for the reason `claimed_request_id` is: the parser may hand back a
    // slice into the caller's input buffer, and this value is reported to an
    // operator long after the probe that read it.
    if (!std.mem.eql(u8, doc.requestId, request_id))
        return .{ .foreign = try arena.dupe(u8, doc.requestId) };
    // Shell exit statuses are 0-255; anything else means the document was not
    // written by our wrapper, whatever it claims.
    if (doc.exitCode < 0 or doc.exitCode > 255) return .{ .exit_code_out_of_range = doc.exitCode };
    return .{
        .present = .{
            .claimed_request_id = try arena.dupe(u8, doc.requestId),
            .exit_code = @intCast(doc.exitCode),
            // 0 is the wrapper's own "the host had no usable `date`", and a
            // negative stamp is nonsense from a host we should not be quoting
            // either way. Both mean the remote could not say when this finished,
            // which is not the same as it having finished at the epoch — and the
            // answer to "the remote could not say" is never a local clock.
            .finished_at = if (doc.finishedAt > 0) doc.finishedAt else null,
        },
    };
}

/// Deletes a job's result sidecar. Used only by `--discard-evidence`, which
/// is explicit about destroying what it destroys.
pub fn removeResult(executor: Executor, arena: Allocator, request_id: []const u8) Error!void {
    const script = try std.fmt.allocPrint(
        arena,
        "rm -f {s}/{s}.json {s}/{s}.json.part",
        .{ result_dir, request_id, result_dir, request_id },
    );
    const result = try run(executor, arena, script);
    if (result.exit_code != 0) return error.RemoteFailed;
}

/// One round trip for just the sidecar, for callers already reading the log
/// from a cursor and so unable to share `probeTail`'s window.
///
/// Empty output *is* a legitimate reading here, and it means `absent`: the
/// script's `[ -f "$r" ] || exit 0` deliberately prints nothing when the file
/// is not there. That is the opposite of `readLog`'s rule below, where every
/// exit prints a line and silence therefore means the answer never arrived —
/// the difference is in the two scripts, not in how hard each reader is
/// willing to look.
///
/// What makes that safe is that empty output now has exactly one cause. It
/// used to have two: `head -c N "$r" | tr -d '\n'` exits with `tr`'s status, so
/// a `head` that could not open the file left the script exiting 0 with
/// nothing on stdout — the same answer a missing file gives. A defect at this
/// operation's own address was read as the absence of evidence, and `absent` is
/// the one reading that lets the log sentinel settle the operation alone. See
/// `resultReadScript` and `error.ResultUnreadable`.
pub fn readResult(executor: Executor, arena: Allocator, request_id: []const u8) Error!ResultReading {
    const result = try run(executor, arena, try resultReadScript(arena, request_id));
    if (result.exit_code == result_unreadable_exit) return error.ResultUnreadable;
    if (result.exit_code != 0) return error.RemoteFailed;
    return try parseJobResult(arena, result.stdout, request_id);
}

test "gate: a sidecar that could not be read is not a sidecar that is not there" {
    const t = std.testing;
    const Scripted = @import("../exec.zig").Scripted;
    var arena_state: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const empty = try arena.alloc(u8, 0);
    const rid = "01JQXW8ZK4N0RS7T3VYB2MCDEF";

    // The failure the old pipeline could not express. `head` could not open a
    // file that is demonstrably there — `[ -f "$r" ]` passed — so the script
    // exits with its own status and no output. Under `| tr -d '\n'` this was
    // exit 0 with no output, which is the documented spelling of `absent`, and
    // `absent` is the single reading that lets the log sentinel settle an
    // operation on its own.
    var unreadable = Scripted.init(arena, &.{
        .{ .reply = .{ .exit_code = result_unreadable_exit, .stdout = empty, .stderr = empty } },
    });
    try t.expectError(error.ResultUnreadable, readResult(unreadable.executor(), arena, rid));

    // Two halves, and both are needed: the reader has to honour the status,
    // and the script has to be able to produce it. Asserting only the mapping
    // would pass with the pipeline put back, which is where the bug was.
    try t.expect(std.mem.indexOf(u8, unreadable.seen.items[0], "tr -d") == null);
    try t.expect(std.mem.indexOf(u8, unreadable.seen.items[0], " | ") == null);
    try t.expect(std.mem.indexOf(u8, unreadable.seen.items[0], "exit 44") != null);

    // The control that keeps the fix from being "refuse everything": a file
    // that really is not there still reads as `absent`, which is what lets a
    // pre-sidecar job settle from its log.
    var missing = Scripted.init(arena, &.{
        .{ .reply = .{ .exit_code = 0, .stdout = empty, .stderr = empty } },
    });
    try t.expectEqualStrings("absent", (try readResult(missing.executor(), arena, rid)).summary().code());

    // …and a document that is there is still read.
    var present = Scripted.init(arena, &.{
        .{ .reply = .{
            .exit_code = 0,
            .stdout = try std.fmt.allocPrint(
                arena,
                "{{\"v\":1,\"requestId\":\"{s}\",\"exitCode\":3,\"finishedAt\":1750000000}}",
                .{rid},
            ),
            .stderr = empty,
        } },
    });
    const doc = (try readResult(present.executor(), arena, rid)).usable() orelse
        return error.TestExpectedResult;
    try t.expectEqual(@as(i32, 3), doc.exit_code);

    // A remote that failed for some other reason is still told apart from one
    // that could not read this file: `RemoteFailed` says the script ran and
    // reported failure, `ResultUnreadable` names which failure.
    var broken = Scripted.init(arena, &.{
        .{ .reply = .{ .exit_code = 1, .stdout = empty, .stderr = empty } },
    });
    try t.expectError(error.RemoteFailed, readResult(broken.executor(), arena, rid));
}

/// Creates the session if absent (idempotent) and starts output logging.
pub fn ensure(executor: Executor, arena: Allocator, name: []const u8) Error!void {
    const tname = try targetName(arena, name);
    // new-session and pipe-pane must be one tmux command sequence (';'):
    // as separate invocations the second can race a freshly (re)started
    // server and fail with "can't find pane".
    const script = try std.fmt.allocPrint(arena,
        \\command -v tmux >/dev/null || exit 41
        \\mkdir -p {s}
        \\tmux has-session -t ={s} 2>/dev/null && exit 0
        \\tmux new-session -d -s {s} ';' pipe-pane -o 'cat >> {s}/{s}.log' || exit 42
    , .{ log_dir, tname, tname, log_dir, name });
    const result = try run(executor, arena, script);
    switch (result.exit_code) {
        0 => {},
        41 => return error.TmuxMissing,
        else => return error.RemoteFailed,
    }
}

pub const RemoteSession = struct {
    name: []const u8, // Terminus name (prefix stripped)
    created: []const u8, // unix seconds, as reported by tmux
    attached: bool,
};

/// Sessions alive on the remote server right now (source of truth).
pub fn list(executor: Executor, arena: Allocator) Error![]RemoteSession {
    // Space-separated: tmux -F does not expand \t, and our validated
    // session names cannot contain spaces.
    const result = try run(executor, arena,
        \\command -v tmux >/dev/null || exit 41
        \\tmux ls -F '#{session_name} #{session_created} #{session_attached}' 2>/dev/null || true
    );
    if (result.exit_code == 41) return error.TmuxMissing;

    var out: std.ArrayList(RemoteSession) = .empty;
    var lines = std.mem.splitScalar(u8, result.stdout, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.splitScalar(u8, std.mem.trimEnd(u8, line, "\r"), ' ');
        const raw_name = fields.next() orelse continue;
        if (!std.mem.startsWith(u8, raw_name, "t-")) continue;
        try out.append(arena, .{
            .name = raw_name["t-".len..],
            .created = fields.next() orelse "",
            .attached = if (fields.next()) |a| !std.mem.eql(u8, a, "0") else false,
        });
    }
    return out.toOwnedSlice(arena);
}

/// Kills the session. Returns whether it is actually gone afterwards.
///
/// Never touches the log. Destroying evidence is a separate, explicit act:
/// doing it inside the same script meant a kill that failed still deleted the
/// only durable record of how the job ended — the `rm` was its own statement,
/// so it ran whether or not the kill worked, and it ran *before* the survival
/// probe, so even a caller that checked the answer could only learn "still
/// running" after the evidence was gone.
///
/// A surviving session is not a cosmetic problem: `ensure` treats an existing
/// session as ready, so the next command would be typed into the previous
/// job's shell — with its cwd, its environment and its half-finished work.
/// That is why this reports the fact rather than returning `void`; the old
/// `kill` bound it to `_` and no caller could ever learn it.
///
/// The `command -v` line is what makes that boolean mean anything. Without it,
/// a host where `tmux` is not resolvable in this shell answers 127 to both
/// invocations — so `has-session` "fails", the `&&` does not fire, the script
/// reaches `exit 0`, and a session nobody even looked at is reported as proven
/// gone. Callers act on that by deleting the pane log, the result sidecar and
/// the local row, which is the exact destruction this split exists to prevent.
pub fn killSession(executor: Executor, arena: Allocator, name: []const u8) Error!bool {
    const tname = try targetName(arena, name);
    const script = try std.fmt.allocPrint(arena,
        \\command -v tmux >/dev/null || exit 41
        \\tmux kill-session -t ={s} 2>/dev/null
        \\tmux has-session -t ={s} 2>/dev/null && exit 1
        \\exit 0
    , .{ tname, tname });
    const result = try run(executor, arena, script);
    if (result.exit_code == 41) return error.TmuxMissing;
    return result.exit_code == 0;
}

test "killSession answers gone / survived / cannot tell, and never confuses them" {
    const t = std.testing;
    const Scripted = @import("../exec.zig").Scripted;
    var arena_state: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const empty = try arena.alloc(u8, 0);

    // The script's own exits: 0 = killed and verified absent, 1 = still there.
    var gone = Scripted.init(arena, &.{
        .{ .reply = .{ .exit_code = 0, .stdout = empty, .stderr = empty } },
    });
    try t.expect(try killSession(gone.executor(), arena, "j"));

    var survived = Scripted.init(arena, &.{
        .{ .reply = .{ .exit_code = 1, .stdout = empty, .stderr = empty } },
    });
    try t.expect(!try killSession(survived.executor(), arena, "j"));

    // The one that matters. Without the `command -v tmux` guard both tmux
    // invocations exit 127, the `&&` does not fire, the script falls through
    // to `exit 0`, and a session nobody could even look at is reported as
    // proven gone — on which `job rm --discard-evidence` deletes the pane log,
    // the result sidecar and the local row for a job that is still running.
    var no_tmux = Scripted.init(arena, &.{
        .{ .reply = .{ .exit_code = 41, .stdout = empty, .stderr = empty } },
    });
    try t.expectError(error.TmuxMissing, killSession(no_tmux.executor(), arena, "j"));
    // Two halves, and both are needed: the script has to ask the question,
    // and the reader has to honour the answer. Asserting only the mapping
    // would pass with the guard deleted from the script, which is where the
    // bug actually was.
    try t.expect(std.mem.indexOf(u8, no_tmux.seen.items[0], "command -v tmux") != null);

    // Same trap on the read side: "no session" and "no tmux" are different
    // answers, and only one of them is evidence about the job.
    var alive_no_tmux = Scripted.init(arena, &.{
        .{ .reply = .{ .exit_code = 41, .stdout = empty, .stderr = empty } },
    });
    try t.expectError(error.TmuxMissing, isAlive(alive_no_tmux.executor(), arena, "j"));
    try t.expect(std.mem.indexOf(u8, alive_no_tmux.seen.items[0], "command -v tmux") != null);
}

/// Deletes the pane log. The caller must already have proven the session is
/// gone — a live pane simply recreates the file through `pipe-pane`, so a
/// "deleted" log quietly comes back holding a partial history that starts
/// mid-job.
pub fn removeLog(executor: Executor, arena: Allocator, name: []const u8) Error!void {
    const script = try std.fmt.allocPrint(arena, "rm -f {s}/{s}.log", .{ log_dir, name });
    const result = try run(executor, arena, script);
    if (result.exit_code != 0) return error.RemoteFailed;
}

/// Types `input` into the session as if at the keyboard, plus Enter unless
/// `no_enter`. Does not wait for any output.
pub fn sendKeys(executor: Executor, arena: Allocator, name: []const u8, input: []const u8, no_enter: bool) Error!void {
    const tname = try targetName(arena, name);
    const quoted = try shellQuote(arena, input);
    // Pane targets need the trailing ':' (exact session, default window):
    // a bare '=name' is rejected as a pane target by some tmux versions.
    const script = try std.fmt.allocPrint(arena,
        \\tmux has-session -t ={s} 2>/dev/null || exit 43
        \\tmux send-keys -t ={s}: -l -- {s} || exit 42
        \\{s}
    , .{ tname, tname, quoted, if (no_enter) "" else try std.fmt.allocPrint(arena, "tmux send-keys -t ={s}: Enter", .{tname}) });
    const result = try run(executor, arena, script);
    switch (result.exit_code) {
        0 => {},
        43 => return error.SessionNotFound,
        else => return error.RemoteFailed,
    }
}

/// The script `probeTail` runs, and the one the black-box gate executes
/// through a real POSIX shell.
///
/// Public for the reason `resultReadScript` is: this text carries the same
/// sidecar read, and what it does under a failing `head` is not something to
/// take on trust from reading it.
///
/// The sidecar read is a brace group and not a pipeline. `head -c N "$r" | tr
/// -d '\n'` exits with `tr`'s status, so a `head` that could not open a file
/// `[ -f "$r" ]` had just found came back as exit 0 with no output — which the
/// parser spells `absent`, and `absent` is the one reading that lets the log
/// sentinel settle the operation by itself. Braces rather than parentheses so
/// the `exit` ends the script and not a subshell that the rest of the script
/// then carries on past.
///
/// The read failure ends the script, which costs the log window. That is the
/// trade named on `error.ResultUnreadable`: the caller gets no reading at all
/// rather than a probe with a hole in it, and so cannot settle from the
/// sentinel this round trip never delivered.
///
/// Empty `r` when there is no request to look up: `[ -f "" ]` is false, so the
/// framing stays identical and the parser has one shape to handle.
pub fn probeScript(
    arena: Allocator,
    name: []const u8,
    request_id: ?[]const u8,
    tail_bytes: i64,
) Allocator.Error![]u8 {
    return std.fmt.allocPrint(arena,
        \\r={s}
        \\[ -f "$r" ] && {{ head -c {d} "$r" || exit {d}; }}
        \\echo
        \\echo {s}
        \\f={s}
        \\[ -f "$f" ] || {{ echo 0; exit 0; }}
        \\wc -c < "$f"
        \\tail -c {d} "$f"
    , .{
        if (request_id) |id| try std.fmt.allocPrint(arena, "{s}/{s}.json", .{ result_dir, id }) else "",
        max_result_bytes,
        result_unreadable_exit,
        probe_split_marker,
        try logPath(arena, name),
        tail_bytes,
    });
}

/// State probe: reads the durable result sidecar and the *end* of the log,
/// in one round trip.
///
/// Detecting that a job finished is a different problem from streaming its
/// output, and conflating them is a bug: a reader that walks forward in 1 MiB
/// windows from the user's cursor never reaches the sentinel on a job that
/// produced 5 MiB, so the job stays "running" forever. Reading a tail window
/// instead finds a marker that is the last thing written, regardless of how
/// much came before.
///
/// But "the last thing written" is only true if the job stops printing when
/// it exits, and that is not something we control — a disowned child keeps
/// writing into the same pane long after the shell moved on. Then the
/// sentinel scrolls out of any window we are willing to read and the log
/// stops being able to answer the question at all. `request_id` names the
/// sidecar, which is one document in a fixed place holding one fact, so it
/// stays answerable however much noise follows. The sentinel scan remains as
/// the fallback for jobs launched before sidecars existed.
pub fn probeTail(
    executor: Executor,
    arena: Allocator,
    name: []const u8,
    sentinel: []const u8,
    request_id: ?[]const u8,
    tail_bytes: i64,
) Error!JobProbe {
    const result = try run(executor, arena, try probeScript(arena, name, request_id, tail_bytes));
    if (result.exit_code == result_unreadable_exit) return error.ResultUnreadable;
    if (result.exit_code != 0) return error.RemoteFailed;

    var probe = try interpretTail(arena, result.stdout, sentinel, request_id);
    probe.session_alive = try isAlive(executor, arena, name);
    return probe;
}

/// Everything `probeTail` concludes from the bytes the remote sent back —
/// separated out because this, not the SSH call, is where the interesting
/// decision lives: which record gets to say how the job ended.
///
/// `session_alive` is left false; the caller fills it in.
fn interpretTail(
    arena: Allocator,
    stdout: []const u8,
    sentinel: []const u8,
    request_id: ?[]const u8,
) Error!JobProbe {
    const split = splitProbe(stdout) orelse return error.RemoteFailed;
    // Read once, reported twice: `sidecar` is what may settle something,
    // `reading` is what happened when we looked. They come apart exactly when
    // the document is there and unusable, which is the case the old
    // `?JobResult` could not express.
    const sidecar: ?ResultReading = if (request_id) |id| try parseJobResult(arena, split.result, id) else null;
    const reading: SidecarReading = if (sidecar) |r| r.summary() else .not_requested;

    // No size line at all. The script emits `0` for a log that does not exist
    // yet, so reaching here means the output was truncated or garbled rather
    // than the log being absent. The sidecar can still have the answer — it is
    // addressed by request id, not by the log — and with no log there is no
    // second record to disagree with it. The same rule is applied anyway so
    // this branch cannot drift away from the one below.
    const newline = std.mem.indexOfScalar(u8, split.rest, '\n') orelse {
        const only_sidecar = readingOf(sidecar, null);
        return .{
            .output = "",
            .next_cursor = 0,
            .exit_code = only_sidecar.exit_code,
            .exit_source = only_sidecar.exit_source,
            .finished_at = only_sidecar.finished_at,
            .result_request_id = only_sidecar.claimed_request_id,
            .conflict = only_sidecar.conflict,
            .refused = only_sidecar.refused,
            .sidecar = reading,
            .session_alive = false,
        };
    };
    const size_text = std.mem.trim(u8, split.rest[0..newline], " \t\r");
    const log_size = std.fmt.parseInt(i64, size_text, 10) catch return error.RemoteFailed;
    const cleaned = try stripTerminalNoise(arena, split.rest[newline + 1 ..]);

    const result = readingOf(sidecar, findSentinel(cleaned, sentinel));

    return .{
        .output = cleaned,
        .next_cursor = log_size,
        .exit_code = result.exit_code,
        .exit_source = result.exit_source,
        .finished_at = result.finished_at,
        .result_request_id = result.claimed_request_id,
        .conflict = result.conflict,
        .refused = result.refused,
        .sidecar = reading,
        .session_alive = false,
        .business_result = try findBusinessResult(arena, cleaned),
    };
}

test "M2e gate: a buried sentinel does not cost a job its outcome" {
    const t = std.testing;
    var arena_state: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const rid = "01JQXW8ZK4N0RS7T3VYB2MCDEF";

    // What the remote sends back after a job that kept printing long past its
    // own sentinel: the tail window we can afford to read holds only trailing
    // noise, so the sentinel scan finds nothing. This is the case the sidecar
    // exists for.
    const buried = try std.fmt.allocPrint(arena, "{{\"v\":1,\"requestId\":\"{s}\",\"exitCode\":3,\"finishedAt\":1750000000}}\n" ++
        "{s}\n900000\nstill chattering\nand chattering\n", .{ rid, probe_split_marker });

    const found = try interpretTail(arena, buried, "__TERMINUS_JOB_9__", rid);
    try t.expectEqual(@as(?i32, 3), found.exit_code);
    try t.expectEqual(JobProbe.ExitSource.result_file, found.exit_source);
    try t.expectEqual(@as(?i64, 1750000000), found.finished_at);
    try t.expectEqual(@as(i64, 900000), found.next_cursor);
    // The identity travels with the reading, so a receipt can record the id
    // the document named rather than the one the caller was holding.
    try t.expectEqualStrings(rid, found.result_request_id.?);

    // Same bytes, no sidecar: the honest answer is that we cannot say.
    const no_sidecar = try std.fmt.allocPrint(
        arena,
        "\n{s}\n900000\nstill chattering\nand chattering\n",
        .{probe_split_marker},
    );
    const unknown = try interpretTail(arena, no_sidecar, "__TERMINUS_JOB_9__", rid);
    try t.expectEqual(@as(?i32, null), unknown.exit_code);
    try t.expectEqual(JobProbe.ExitSource.none, unknown.exit_source);

    // A job launched before sidecars existed still settles from its log.
    const legacy = try std.fmt.allocPrint(
        arena,
        "\n{s}\n40\nwork done\n__TERMINUS_JOB_9__:7\n",
        .{probe_split_marker},
    );
    const from_log = try interpretTail(arena, legacy, "__TERMINUS_JOB_9__", rid);
    try t.expectEqual(@as(?i32, 7), from_log.exit_code);
    try t.expectEqual(JobProbe.ExitSource.log_sentinel, from_log.exit_source);
    try t.expectEqual(@as(?i64, null), from_log.finished_at);
    // A log line names no request, so there is no identity to carry.
    try t.expectEqual(@as(?[]const u8, null), from_log.result_request_id);
}

test "M2e gate: a result belonging to another request is not evidence" {
    const t = std.testing;
    var arena_state: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const mine = "01JQXW8ZK4N0RS7T3VYB2MCDEF";
    const theirs = "01JQXW8ZK4N0RS7T3VYB2MCXYZ";

    // A leftover document from a different attempt in the same directory.
    // Reading it as ours would settle this operation from someone else's exit
    // code — the exact confusion request-keyed results are meant to prevent.
    const foreign = try std.fmt.allocPrint(arena, "{{\"v\":1,\"requestId\":\"{s}\",\"exitCode\":0,\"finishedAt\":1750000000}}\n{s}\n5\nhi\n", .{ theirs, probe_split_marker });
    const probe = try interpretTail(arena, foreign, "__S__", mine);
    try t.expectEqual(@as(?i32, null), probe.exit_code);
    try t.expectEqual(JobProbe.ExitSource.none, probe.exit_source);
    // …and the probe says *why* it had nothing, naming the id that turned up
    // where ours should have been. Without this the operator sees the same
    // "no result record" a job that never wrote one produces, and never learns
    // that two operations are writing to one address.
    try t.expectEqualStrings("foreign", probe.sidecar.code());
    try t.expectEqualStrings(theirs, probe.sidecar.foreign);
    try t.expect(probe.sidecar.anomalous());

    // Neither is a document from a schema we do not know, nor one whose exit
    // code is not a shell exit status, nor a truncated write. None of them
    // settles anything — and each says which of them it was, because the three
    // send an operator to three different places (the remote wrapper's build,
    // a half-written file, a colliding request id) and "no sidecar" sends them
    // nowhere at all.
    const rejects = [_]struct { doc: []const u8, code: []const u8 }{
        .{ .doc = "{\"v\":2,\"requestId\":\"01JQXW8ZK4N0RS7T3VYB2MCDEF\",\"exitCode\":0,\"finishedAt\":1}", .code = "unknown_schema" },
        .{ .doc = "{\"v\":1,\"requestId\":\"01JQXW8ZK4N0RS7T3VYB2MCDEF\",\"exitCode\":9000,\"finishedAt\":1}", .code = "exit_code_out_of_range" },
        .{ .doc = "{\"v\":1,\"requestId\":\"01JQXW8ZK4N0RS7T3VYB2M", .code = "malformed" },
        .{ .doc = "{\"v\":1,\"requestId\":\"01JQXW8ZK4N0RS7T3VYB2MCXYZ\",\"exitCode\":0,\"finishedAt\":1}", .code = "foreign" },
        .{ .doc = "", .code = "absent" },
    };
    var seen: usize = 0;
    for (rejects) |case| {
        const reading = try parseJobResult(arena, case.doc, mine);
        // The load-bearing half: none of these is usable as evidence.
        try t.expectEqual(@as(?JobResult, null), reading.usable());
        // The half that was missing: they are told apart.
        try t.expectEqualStrings(case.code, reading.summary().code());
        // Absence is the one that is not a defect; the other four are.
        try t.expectEqual(!std.mem.eql(u8, case.code, "absent"), reading.summary().anomalous());
        const sentence = try reading.summary().describe(arena);
        if (reading.summary().anomalous()) {
            // Each anomaly earns its own sentence, and none of them may read
            // as "there was nothing there".
            try t.expect(sentence.?.len > 40);
            try t.expect(std.mem.indexOf(u8, sentence.?, "present") != null);
            seen += 1;
        } else {
            try t.expectEqual(@as(?[]const u8, null), sentence);
        }
    }
    try t.expectEqual(@as(usize, 4), seen);
    // The numbers each reading carries are the ones the document held, so an
    // operator is told which schema and which impossible code turned up.
    try t.expectEqual(
        @as(i64, 2),
        (try parseJobResult(arena, rejects[0].doc, mine)).unknown_schema,
    );
    try t.expectEqual(
        @as(i64, 9000),
        (try parseJobResult(arena, rejects[1].doc, mine)).exit_code_out_of_range,
    );

    // And a good one is accepted, so the rejections above mean something.
    const good = (try parseJobResult(
        arena,
        "{\"v\":1,\"requestId\":\"01JQXW8ZK4N0RS7T3VYB2MCDEF\",\"exitCode\":255,\"finishedAt\":42}",
        mine,
    )).usable() orelse return error.TestExpectedResult;
    try t.expectEqual(@as(i32, 255), good.exit_code);
    try t.expectEqual(@as(?i64, 42), good.finished_at);
    // The identity comes out of the document, not out of what we searched
    // for. A receipt built from this can be checked against the operation it
    // is offered for; one built from the search key checks itself.
    try t.expectEqualStrings(mine, good.claimed_request_id);
    try t.expect(good.claimed_request_id.ptr != mine.ptr);

    // The wrapper writes finishedAt=0 when the host has no usable `date`, and
    // a negative stamp is nonsense from a host we should not be quoting. Both
    // mean "the remote could not say", which reads as absent — not as
    // midnight 1970, and never as our own clock. The exit code in the same
    // document is still perfectly good evidence, so the document stands.
    for ([_][]const u8{
        "{\"v\":1,\"requestId\":\"01JQXW8ZK4N0RS7T3VYB2MCDEF\",\"exitCode\":3,\"finishedAt\":0}",
        "{\"v\":1,\"requestId\":\"01JQXW8ZK4N0RS7T3VYB2MCDEF\",\"exitCode\":3,\"finishedAt\":-5}",
    }) |doc| {
        const clockless = (try parseJobResult(arena, doc, mine)).usable() orelse
            return error.TestExpectedResult;
        try t.expectEqual(@as(i32, 3), clockless.exit_code);
        try t.expectEqual(@as(?i64, null), clockless.finished_at);
    }
}

test "gate: a corrupt or foreign sidecar is not the same reading as no sidecar" {
    const t = std.testing;
    var arena_state: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const mine = "01JQXW8ZK4N0RS7T3VYB2MCDEF";
    const theirs = "01JQXW8ZK4N0RS7T3VYB2MCXYZ";

    // The same log window under five different sidecars. The job's own
    // sentinel is in the tail and says exit 7, so the log is willing to answer
    // in every one of the five — and only one of them may let it. `absent`
    // means nothing was written at this address and the sentinel is the only
    // record there is. The other four mean something *was* written there and
    // we cannot read it, so the sentinel's agreement with the stronger record
    // cannot be checked, and settling `failed` from the weaker one alone would
    // publish a proven outcome standing next to evidence we just refused.
    const tail = "\n40\nwork done\n__TERMINUS_JOB_9__:7\n";
    const cases = [_]struct { doc: []const u8, code: []const u8, anomalous: bool }{
        .{ .doc = "", .code = "absent", .anomalous = false },
        .{ .doc = "{\"v\":1,\"requestId\":\"01JQXW8ZK4N0RS7T3VYB2M", .code = "malformed", .anomalous = true },
        .{ .doc = "{\"v\":7,\"requestId\":\"01JQXW8ZK4N0RS7T3VYB2MCDEF\",\"exitCode\":7,\"finishedAt\":1}", .code = "unknown_schema", .anomalous = true },
        .{ .doc = "{\"v\":1,\"requestId\":\"01JQXW8ZK4N0RS7T3VYB2MCDEF\",\"exitCode\":-9,\"finishedAt\":1}", .code = "exit_code_out_of_range", .anomalous = true },
        .{ .doc = "{\"v\":1,\"requestId\":\"01JQXW8ZK4N0RS7T3VYB2MCXYZ\",\"exitCode\":7,\"finishedAt\":1}", .code = "foreign", .anomalous = true },
    };
    for (cases) |case| {
        const stdout = try std.fmt.allocPrint(arena, "{s}\n{s}{s}", .{ case.doc, probe_split_marker, tail });
        const probe = try interpretTail(arena, stdout, "__TERMINUS_JOB_9__", mine);
        try t.expectEqualStrings(case.code, probe.sidecar.code());
        try t.expectEqual(case.anomalous, probe.sidecar.anomalous());
        if (case.anomalous) {
            // The rule: any defective reading refuses to settle. The sentinel
            // is not promoted to the answer, and the probe is structurally
            // unable to hand one back — four callers settle from `exit_code`
            // and only one of them ever looked at the reading beside it.
            try t.expectEqual(@as(?i32, null), probe.exit_code);
            try t.expectEqual(JobProbe.ExitSource.none, probe.exit_source);
            // …and the verdict that was declined travels out, so the
            // `indeterminate` a caller records can name what it turned down
            // rather than reading as "the job left nothing behind".
            try t.expectEqual(@as(i32, 7), probe.refused.?.sentinel_exit_code);
        } else {
            // The control, and the half of the rule that is easy to lose:
            // absence of a document is not a defect. A job launched before
            // sidecars existed, or one whose evidence was discarded, still
            // settles from its log exactly as it always did.
            try t.expectEqual(@as(?i32, 7), probe.exit_code);
            try t.expectEqual(JobProbe.ExitSource.log_sentinel, probe.exit_source);
            try t.expectEqual(@as(?JobProbe.Refused, null), probe.refused);
        }
        // Nothing from a refused document leaks out as this attempt's own: no
        // finish time, and above all no identity for a receipt to quote.
        try t.expectEqual(@as(?i64, null), probe.finished_at);
        try t.expectEqual(@as(?[]const u8, null), probe.result_request_id);
    }
    try t.expectEqualStrings(theirs, (try interpretTail(
        arena,
        try std.fmt.allocPrint(arena, "{s}\n{s}{s}", .{ cases[4].doc, probe_split_marker, tail }),
        "__TERMINUS_JOB_9__",
        mine,
    )).sidecar.foreign);

    // A defect with no sentinel behind it refuses nothing, because there was
    // no verdict to refuse. The distinction is load-bearing: the caller that
    // sees `refused` settles `indeterminate`, and doing that here would end an
    // operation whose job may still be running — a leftover document from
    // another request says nothing about whether this one has finished.
    const no_verdict = try interpretTail(
        arena,
        try std.fmt.allocPrint(arena, "{s}\n{s}\n40\nstill building\n", .{ cases[4].doc, probe_split_marker }),
        "__TERMINUS_JOB_9__",
        mine,
    );
    try t.expectEqual(@as(?i32, null), no_verdict.exit_code);
    try t.expectEqual(@as(?JobProbe.Refused, null), no_verdict.refused);
    try t.expect(no_verdict.sidecar.anomalous());

    // A probe that was never given a request id did not look, which is a
    // sixth answer and not any of the five above.
    const unasked = try interpretTail(
        arena,
        try std.fmt.allocPrint(arena, "\n{s}{s}", .{ probe_split_marker, tail }),
        "__TERMINUS_JOB_9__",
        null,
    );
    try t.expectEqualStrings("not_requested", unasked.sidecar.code());
    try t.expect(!unasked.sidecar.anomalous());
    try t.expectEqual(@as(?i32, 7), unasked.exit_code);
    try t.expectEqual(@as(?JobProbe.Refused, null), unasked.refused);

    // The control: a usable document still reads as `present`, so the gate
    // cannot pass by every reading having become an anomaly.
    const good = try interpretTail(
        arena,
        try std.fmt.allocPrint(
            arena,
            "{{\"v\":1,\"requestId\":\"{s}\",\"exitCode\":7,\"finishedAt\":1750000000}}\n{s}{s}",
            .{ mine, probe_split_marker, tail },
        ),
        "__TERMINUS_JOB_9__",
        mine,
    );
    try t.expectEqualStrings("present", good.sidecar.code());
    try t.expect(!good.sidecar.anomalous());
    try t.expectEqual(JobProbe.ExitSource.result_file, good.exit_source);
    try t.expectEqualStrings(mine, good.result_request_id.?);
    try t.expectEqual(@as(?JobProbe.Refused, null), good.refused);
}

test "gate: two mechanical records that disagree settle nothing" {
    const t = std.testing;
    var arena_state: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const rid = "01JQXW8ZK4N0RS7T3VYB2MCDEF";

    // The sidecar says the job succeeded; the sentinel in its log says it
    // exited 7. One of the two records is wrong and nothing here can tell
    // which, so this is not evidence of anything. Answering with either would
    // be choosing by the order the reader happens to consult them in — which
    // is exactly what the two readers used to do, in opposite directions.
    const disagree = try std.fmt.allocPrint(arena, "{{\"v\":1,\"requestId\":\"{s}\",\"exitCode\":0,\"finishedAt\":1750000000}}\n" ++
        "{s}\n40\nwork done\n__TERMINUS_JOB_9__:7\n", .{ rid, probe_split_marker });
    const clash = try interpretTail(arena, disagree, "__TERMINUS_JOB_9__", rid);
    try t.expectEqual(@as(?i32, null), clash.exit_code);
    try t.expectEqual(JobProbe.ExitSource.none, clash.exit_source);
    try t.expectEqual(@as(i32, 0), clash.conflict.?.result_exit_code);
    try t.expectEqual(@as(i32, 7), clash.conflict.?.sentinel_exit_code);
    // A finish time taken from a record we are unwilling to settle from is
    // not a fact either. Neither is the identity it named.
    try t.expectEqual(@as(?i64, null), clash.finished_at);
    try t.expectEqual(@as(?[]const u8, null), clash.result_request_id);

    // Agreement is the ordinary case: one answer, attributed to the stronger
    // record, and no conflict to report.
    const agree = try std.fmt.allocPrint(arena, "{{\"v\":1,\"requestId\":\"{s}\",\"exitCode\":7,\"finishedAt\":1750000000}}\n" ++
        "{s}\n40\nwork done\n__TERMINUS_JOB_9__:7\n", .{ rid, probe_split_marker });
    const settled = try interpretTail(arena, agree, "__TERMINUS_JOB_9__", rid);
    try t.expectEqual(@as(?i32, 7), settled.exit_code);
    try t.expectEqual(JobProbe.ExitSource.result_file, settled.exit_source);
    try t.expectEqual(@as(?i64, 1750000000), settled.finished_at);
    try t.expectEqualStrings(rid, settled.result_request_id.?);
    try t.expect(settled.conflict == null);
}

test "gate: the streaming reader applies the same rule as the tail probe" {
    const t = std.testing;
    const Scripted = @import("../exec.zig").Scripted;
    var arena_state: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const rid = "01JQXW8ZK4N0RS7T3VYB2MCDEF";
    const empty = try arena.alloc(u8, 0);
    // `job read` walks the log from the caller's cursor and fetches the
    // sidecar separately, so it is the reader that holds both records at
    // once. It used to compute the sentinel's answer and then overwrite it,
    // discarding the contradiction it was holding.
    const window = try std.fmt.allocPrint(arena, "40\nwork done\n__TERMINUS_JOB_9__:7\n", .{});
    const doc = try std.fmt.allocPrint(
        arena,
        "{{\"v\":1,\"requestId\":\"{s}\",\"exitCode\":0,\"finishedAt\":1750000000}}",
        .{rid},
    );
    var scripted = Scripted.init(arena, &.{
        .{ .reply = .{ .exit_code = 0, .stdout = window, .stderr = empty } }, // readLog
        .{ .reply = .{ .exit_code = 0, .stdout = doc, .stderr = empty } }, // readResult
        .{ .reply = .{ .exit_code = 0, .stdout = empty, .stderr = empty } }, // isAlive
    });
    const probe = try probeJob(scripted.executor(), arena, "j", "__TERMINUS_JOB_9__", rid, 0, 1 << 20);
    try t.expectEqual(@as(?i32, null), probe.exit_code);
    try t.expectEqual(JobProbe.ExitSource.none, probe.exit_source);
    try t.expectEqual(@as(i32, 0), probe.conflict.?.result_exit_code);
    try t.expectEqual(@as(i32, 7), probe.conflict.?.sentinel_exit_code);
    // The caller still gets its output window with the marker trimmed off:
    // what to display is a separate question from what was established.
    try t.expectEqualStrings("work done\n", probe.output);

    // And the refusal rule reaches it too. `job read` fetches the sidecar in a
    // round trip of its own, so it is a second place the two records meet and
    // a second place the sentinel could be promoted over a document nobody can
    // read. The two readers share `readingOf` precisely because they had
    // already drifted once.
    const defective = try std.fmt.allocPrint(
        arena,
        "{{\"v\":1,\"requestId\":\"{s}\",\"exitCode\":9000,\"finishedAt\":1}}",
        .{rid},
    );
    var streamed = Scripted.init(arena, &.{
        .{ .reply = .{ .exit_code = 0, .stdout = window, .stderr = empty } }, // readLog
        .{ .reply = .{ .exit_code = 0, .stdout = defective, .stderr = empty } }, // readResult
        .{ .reply = .{ .exit_code = 0, .stdout = empty, .stderr = empty } }, // isAlive
    });
    const refused = try probeJob(streamed.executor(), arena, "j", "__TERMINUS_JOB_9__", rid, 0, 1 << 20);
    try t.expectEqual(@as(?i32, null), refused.exit_code);
    try t.expectEqual(JobProbe.ExitSource.none, refused.exit_source);
    try t.expectEqual(@as(i32, 7), refused.refused.?.sentinel_exit_code);
    try t.expectEqualStrings("exit_code_out_of_range", refused.sidecar.code());
}

test "gate: neither reader turns an unreadable result record into an absent one" {
    const t = std.testing;
    const Scripted = @import("../exec.zig").Scripted;
    var arena_state: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const rid = "01JQXW8ZK4N0RS7T3VYB2MCDEF";
    const empty = try arena.alloc(u8, 0);
    // A log window whose sentinel says the job exited 7. Both readers would be
    // willing to settle `failed` from it — and neither may, because the
    // stronger record is at this request's own address and could not be read,
    // so the sentinel's agreement with it cannot be checked.
    const window = try std.fmt.allocPrint(arena, "40\nwork done\n__TERMINUS_JOB_9__:7\n", .{});

    // The tail probe reads both records in one round trip, so its script
    // carries the sidecar read and the log read together. The read failure
    // ends the script, which costs the window — and buys the refusal.
    var tail = Scripted.init(arena, &.{
        .{ .reply = .{ .exit_code = result_unreadable_exit, .stdout = empty, .stderr = empty } },
    });
    try t.expectError(
        error.ResultUnreadable,
        probeTail(tail.executor(), arena, "j", "__TERMINUS_JOB_9__", rid, 1 << 10),
    );
    try t.expect(std.mem.indexOf(u8, tail.seen.items[0], "tr -d") == null);
    try t.expect(std.mem.indexOf(u8, tail.seen.items[0], " | ") == null);
    // Braces, not parentheses: `( ... || exit 44 )` ends a subshell and lets
    // the script carry on to print the marker, which is the laundering again
    // with an extra layer.
    try t.expect(std.mem.indexOf(u8, tail.seen.items[0], "{ head -c") != null);

    // The streaming reader fetches the sidecar in a round trip of its own, so
    // it is a second place the failure could have been read as an absence.
    var streamed = Scripted.init(arena, &.{
        .{ .reply = .{ .exit_code = 0, .stdout = window, .stderr = empty } }, // readLog
        .{ .reply = .{ .exit_code = result_unreadable_exit, .stdout = empty, .stderr = empty } }, // readResult
    });
    try t.expectError(
        error.ResultUnreadable,
        probeJob(streamed.executor(), arena, "j", "__TERMINUS_JOB_9__", rid, 0, 1 << 20),
    );

    // The control both readers have to keep passing: nothing at the address is
    // still an absence, and the sentinel still settles the job from it. This is
    // what makes the two refusals above mean something other than "these
    // readers refuse everything".
    var absent_tail = Scripted.init(arena, &.{
        .{ .reply = .{
            .exit_code = 0,
            .stdout = try std.fmt.allocPrint(arena, "\n{s}\n{s}", .{ probe_split_marker, window }),
            .stderr = empty,
        } },
        .{ .reply = .{ .exit_code = 0, .stdout = empty, .stderr = empty } }, // isAlive
    });
    const settled = try probeTail(absent_tail.executor(), arena, "j", "__TERMINUS_JOB_9__", rid, 1 << 10);
    try t.expectEqual(@as(?i32, 7), settled.exit_code);
    try t.expectEqual(JobProbe.ExitSource.log_sentinel, settled.exit_source);
    try t.expectEqualStrings("absent", settled.sidecar.code());

    var absent_stream = Scripted.init(arena, &.{
        .{ .reply = .{ .exit_code = 0, .stdout = window, .stderr = empty } }, // readLog
        .{ .reply = .{ .exit_code = 0, .stdout = empty, .stderr = empty } }, // readResult
        .{ .reply = .{ .exit_code = 0, .stdout = empty, .stderr = empty } }, // isAlive
    });
    const streamed_settled = try probeJob(absent_stream.executor(), arena, "j", "__TERMINUS_JOB_9__", rid, 0, 1 << 20);
    try t.expectEqual(@as(?i32, 7), streamed_settled.exit_code);
    try t.expectEqualStrings("absent", streamed_settled.sidecar.code());
}

pub const ReadResult = struct {
    data: []const u8,
    /// Byte offset to continue from next time.
    next_cursor: i64,
    /// Total size of the remote log (cursor > size means log was truncated).
    log_size: i64,
};

/// Reads the session's output log from byte offset `cursor`, at most
/// `limit` bytes. A missing log file reads as empty *and says so* — with a
/// size line of `0`, which is a reading; see below for why that distinction is
/// the whole of this function's contract.
pub fn readLog(executor: Executor, arena: Allocator, name: []const u8, cursor: i64, limit: i64) Error!ReadResult {
    const path = try logPath(arena, name);
    // First line of output is the log size, the rest is the data window.
    const script = try std.fmt.allocPrint(arena,
        \\f={s}
        \\[ -f "$f" ] || {{ echo 0; exit 0; }}
        \\wc -c < "$f"
        \\tail -c +{d} "$f" | head -c {d}
    , .{ path, cursor + 1, limit });
    const result = try run(executor, arena, script);
    if (result.exit_code != 0) return error.RemoteFailed;

    // A newline-free response cannot be a reading of anything.
    //
    // Both of the script's exits print the byte count on a line of its own:
    // `echo 0` when the log is not there yet, `wc -c` when it is. There is no
    // path through it that answers without a newline, and none that answers
    // with no bytes at all. So silence here is not a log that happens to be
    // empty — an empty log answers "0\n" — it is an answer that was cut short
    // before its first line ended, or one that never started. Exit 0 with zero
    // bytes is the same defect seen from the other end: the script reached
    // neither exit, so the read did not happen.
    //
    // This used to return `{ .data = "", .next_cursor = cursor, .log_size = 0 }`,
    // which hands every caller "the log is empty, zero bytes long, cursor
    // unmoved" — indistinguishable from a genuinely empty log, and consumed as
    // fact by `probeJob`, `execIn`, `job read` and `job watch`. A truncated
    // read reported as a successful empty one is a failed link presented as a
    // finished one.
    const newline = std.mem.indexOfScalar(u8, result.stdout, '\n') orelse
        return error.TruncatedResponse;
    const size_text = std.mem.trim(u8, result.stdout[0..newline], " \t\r");
    const log_size = std.fmt.parseInt(i64, size_text, 10) catch return error.RemoteFailed;
    const data = result.stdout[newline + 1 ..];
    return .{
        .data = data,
        .next_cursor = @min(cursor + @as(i64, @intCast(data.len)), log_size),
        .log_size = log_size,
    };
}

test "gate: a truncated read is not a successfully-read empty log" {
    const t = std.testing;
    const Scripted = @import("../exec.zig").Scripted;
    var arena_state: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const empty = try arena.alloc(u8, 0);

    // The remote script always emits the byte count followed by a newline, on
    // both of its exits. A response without one was cut short, and the old
    // code answered it with `{data:"", next_cursor:cursor, log_size:0}` — the
    // same answer a genuinely empty log gets, which is how a broken channel
    // came to read as "nothing has been printed yet".
    var cut_short = Scripted.init(arena, &.{
        .{ .reply = .{ .exit_code = 0, .stdout = try arena.dupe(u8, "4"), .stderr = empty } },
    });
    try t.expectError(
        error.TruncatedResponse,
        readLog(cut_short.executor(), arena, "j", 0, 1 << 20),
    );

    // Nothing at all under exit 0 is the same defect from the other end: the
    // script reached neither of its exits, so the read did not happen.
    var silent = Scripted.init(arena, &.{
        .{ .reply = .{ .exit_code = 0, .stdout = empty, .stderr = empty } },
    });
    try t.expectError(
        error.TruncatedResponse,
        readLog(silent.executor(), arena, "j", 7, 1 << 20),
    );

    // The controls, so this cannot be satisfied by a `readLog` that refuses
    // everything. A log that is really empty says so, with a size line, and is
    // still a successful read; and an ordinary window still comes back whole.
    var absent_log = Scripted.init(arena, &.{
        .{ .reply = .{ .exit_code = 0, .stdout = try arena.dupe(u8, "0\n"), .stderr = empty } },
    });
    const nothing = try readLog(absent_log.executor(), arena, "j", 0, 1 << 20);
    try t.expectEqualStrings("", nothing.data);
    try t.expectEqual(@as(i64, 0), nothing.log_size);
    try t.expectEqual(@as(i64, 0), nothing.next_cursor);

    var window = Scripted.init(arena, &.{
        .{ .reply = .{ .exit_code = 0, .stdout = try arena.dupe(u8, "12\nhello\n"), .stderr = empty } },
    });
    const got = try readLog(window.executor(), arena, "j", 6, 1 << 20);
    try t.expectEqualStrings("hello\n", got.data);
    try t.expectEqual(@as(i64, 12), got.log_size);
    try t.expectEqual(@as(i64, 12), got.next_cursor);

    // And a remote that reported failure still reports failure, told apart
    // from a remote whose answer never arrived.
    var failed = Scripted.init(arena, &.{
        .{ .reply = .{ .exit_code = 1, .stdout = empty, .stderr = empty } },
    });
    try t.expectError(error.RemoteFailed, readLog(failed.executor(), arena, "j", 0, 1 << 20));
}

pub const ExecInResult = struct {
    output: []const u8,
    exit_code: i32,
    /// Log offset after the command's output (new cursor for the caller).
    next_cursor: i64,
};

/// Runs a command inside the session's shell and waits for completion by
/// watching the output log for a sentinel line. Unlike plain `exec`, the
/// command inherits the session's cwd, env, and running state.
pub fn execIn(
    executor: Executor,
    arena: Allocator,
    io: std.Io,
    name: []const u8,
    command: []const u8,
    start_cursor: i64,
    timeout_ms: i64,
) Error!ExecInResult {
    // Nonce ties the sentinel to this invocation; derived from the wall
    // clock, which is plenty for a single-user CLI.
    const nonce: u64 = @intCast(@mod(std.Io.Timestamp.now(io, .real).nanoseconds, 1_000_000_007));
    const sentinel = try std.fmt.allocPrint(arena, "__TERMINUS_{d}__", .{nonce});

    // `; echo <sentinel>:$?` runs in the session shell after the command,
    // regardless of its exit status.
    const full = try std.fmt.allocPrint(arena, "{s}; echo {s}:$?", .{ command, sentinel });
    try sendKeys(executor, arena, name, full, false);

    // Poll the log until the sentinel shows up. Backoff keeps the SSH
    // round-trips reasonable for long commands.
    var cursor = start_cursor;
    var collected: std.ArrayList(u8) = .empty;
    var waited_ms: i64 = 0;
    var poll_ms: i64 = 150;
    while (true) {
        const chunk = try readLog(executor, arena, name, cursor, 1 << 20);
        cursor = chunk.next_cursor;
        try collected.appendSlice(arena, chunk.data);

        // Search the *stripped* text: escape sequences (bracketed paste,
        // OSC beacons) can precede the marker on the same raw line without
        // a newline, which would defeat a line-start match on raw bytes.
        const cleaned = try stripTerminalNoise(arena, collected.items);
        if (findSentinel(cleaned, sentinel)) |found| {
            // Echoed keystrokes also land in the log: the first line is the
            // typed command (containing the sentinel text); the real marker
            // is a line that *starts* with the sentinel.
            return .{
                .output = cleaned[found.output_start..found.output_end],
                .exit_code = found.exit_code,
                .next_cursor = cursor,
            };
        }

        if (waited_ms >= timeout_ms) return error.CommandTimeout;

        // The command may have killed the shell (e.g. `exit`), which
        // destroys the pane — the sentinel will never arrive.
        if (!try isAlive(executor, arena, name)) return error.SessionDied;

        std.Io.sleep(io, .{ .nanoseconds = poll_ms * std.time.ns_per_ms }, .awake) catch {};
        waited_ms += poll_ms;
        poll_ms = @min(poll_ms * 2, 2000);
    }
}

/// The pid of the session's pane process — the shell the job runs under, and
/// the head of its process group.
///
/// This is what identity a tmux-supervised job can offer. It is a real pid,
/// but nothing here proves a process later found under it is still ours,
/// which is why the recorded capability says `pidProof = weak`.
pub fn panePid(executor: Executor, arena: Allocator, name: []const u8) Error!?i64 {
    const tname = try targetName(arena, name);
    const script = try std.fmt.allocPrint(
        arena,
        "tmux list-panes -t ={s} -F '#{{pane_pid}}' 2>/dev/null | head -1",
        .{tname},
    );
    const result = try run(executor, arena, script);
    const text = std.mem.trim(u8, result.stdout, " \t\r\n");
    if (text.len == 0) return null;
    return std.fmt.parseInt(i64, text, 10) catch null;
}

/// Whether the session exists right now.
///
/// `false` here is read as "the session is gone", which is half of every
/// conclusion this module draws about a finished job — so it must not be what
/// an unrunnable `tmux` looks like. Absence of the tool is a different answer
/// from absence of the session, and only one of them is evidence.
pub fn isAlive(executor: Executor, arena: Allocator, name: []const u8) Error!bool {
    const tname = try targetName(arena, name);
    const script = try std.fmt.allocPrint(arena,
        \\command -v tmux >/dev/null || exit 41
        \\tmux has-session -t ={s} 2>/dev/null
    , .{tname});
    const result = try run(executor, arena, script);
    if (result.exit_code == 41) return error.TmuxMissing;
    return result.exit_code == 0;
}

pub const JobProbe = struct {
    /// New (cleaned) output since the given cursor.
    output: []const u8,
    next_cursor: i64,
    /// Set when the job's end was established: the durable result sidecar was
    /// there, or (failing that) the sentinel line was still in the window and
    /// nothing defective sat at the sidecar's address.
    exit_code: ?i32,
    /// Where `exit_code` came from. A caller writing a receipt has to say
    /// which one it was — "the wrapper's result file said 3" and "we found a
    /// line in a log that said 3" are not the same claim.
    exit_source: ExitSource = .none,
    /// Remote finish time, only ever from the sidecar. The log carries no
    /// timestamp, so a sentinel-only outcome has none.
    finished_at: ?i64 = null,
    /// The request id the sidecar document itself named, when the sidecar is
    /// what answered. Null for a sentinel-only outcome (a log line names no
    /// request) and for a conflict (a record we refuse to settle from is not
    /// one whose identity we may quote).
    ///
    /// A caller writing `job_result` evidence must fill the receipt's
    /// `request_id` from *this*, not from the operation it is reconciling:
    /// the Store re-checks that the two agree, and a check whose two sides
    /// come from the same place can never fail.
    result_request_id: ?[]const u8 = null,
    /// Both durable records answered, and they disagree. Nothing may be
    /// settled from this: two mechanical records of the same fact
    /// contradicting each other means one of them is wrong and we cannot tell
    /// which. Settling from either would be picking a winner by
    /// implementation order.
    ///
    /// `exit_code` is null and `exit_source` is `.none` whenever this is set,
    /// so a caller is structurally unable to settle from a conflict rather
    /// than merely discouraged from it.
    conflict: ?Conflict = null,
    /// A document at this request's own address was defective, and the log
    /// sentinel was willing to answer in its place. Carries the code that was
    /// turned down.
    ///
    /// `exit_code` is null and `exit_source` is `.none` whenever this is set,
    /// for the reason `conflict` gives: a caller has to be structurally unable
    /// to settle from a refused reading rather than merely discouraged from it.
    /// Four callers settle from `exit_code` and only one of them ever checked
    /// the reading beside it.
    ///
    /// Deliberately not derivable from `sidecar.anomalous()` at the caller.
    /// That predicate is also true of a defective document sitting beside a log
    /// that said nothing at all, where there is no verdict to decline and the
    /// job may well still be running — settling that `indeterminate` would end
    /// an operation whose work is still going. This says a verdict was there
    /// and was refused, which is the case that must not come out as either a
    /// proven terminal or "still running".
    refused: ?Refused = null,
    /// What was at the sidecar's address, whether or not it answered.
    ///
    /// Separate from `exit_source`, which says which record *did* answer. This
    /// says what happened when we looked at the stronger of the two, and it is
    /// the only place four of its five readings exist at all: a document that
    /// would not parse, one from a schema this build does not know, one
    /// carrying an impossible exit code and one naming another request are each
    /// `exit_source == .none`, and without this they read identically to a job
    /// that simply never wrote a sidecar.
    ///
    /// Carried so a caller can report which of them it hit. It never settles
    /// anything on its own, and `.foreign`'s payload is a request id belonging
    /// to somebody else: it is for printing, never for filling a receipt's
    /// `request_id`, which comes from `result_request_id` and only from there.
    sidecar: SidecarReading = .not_requested,
    session_alive: bool,
    /// Business-state marker: the value from the last `__TERMINUS_RESULT__:<v>`
    /// line the job printed, distinct from the process exit code (a job can
    /// exit 0 yet report a business failure). Null when the job printed none.
    business_result: ?[]const u8 = null,

    pub const Conflict = struct {
        result_exit_code: i32,
        sentinel_exit_code: i32,
    };

    /// The verdict a defective result record cost the caller.
    ///
    /// A struct rather than a bare `?i32` so it reads the same way `Conflict`
    /// does at every call site, and so a second thing a refusal turns down can
    /// be added without changing four signatures. Which defect it was is not
    /// repeated here: `sidecar` already carries it, with its payload.
    pub const Refused = struct {
        /// The exit code the log sentinel carried, recorded so a settlement's
        /// reason can name what it declined. "This job's result record could
        /// not be read" and "it could not be read, and its log says it exited
        /// 7" send an operator to different places.
        sentinel_exit_code: i32,
    };

    pub const ExitSource = enum {
        none,
        /// `~/.terminus/results/<request-id>.json`.
        result_file,
        /// The `<sentinel>:<code>` line in the pane log.
        log_sentinel,
    };
};

/// What the two durable records, taken together, establish about how the job
/// ended.
///
/// One function because there are two readers of the same two records
/// (`interpretTail` and `probeJob`) and they had already drifted: one
/// evaluated the sentinel only when there was no sidecar, the other computed
/// both and then overwrote the sentinel's answer with the sidecar's. Neither
/// could report a disagreement, and the second one had the contradiction in
/// hand when it discarded it.
///
/// A defective reading is checked before either record is read, and it stops
/// the reading here rather than at each caller. The sidecar is the stronger
/// record; when it is there and unusable, the sentinel's answer cannot be
/// checked against it, and a sentinel that agreed with a document nobody could
/// read is not a thing that can be established. Taking the sentinel anyway
/// settles `completed` or `failed` from the weaker of two records while the
/// stronger one sits at this operation's own address in a state that says
/// something on the host is wrong — a colliding request id, a mismatched
/// wrapper, a truncated write. So nothing is established, and what the
/// sentinel said travels out as `refused` for the settlement's reason to name.
///
/// Takes the whole `ResultReading` rather than the `?JobResult` it used to:
/// `usable()` answers `null` to both an absence and a defect, so a parameter
/// of that type cannot tell them apart and every caller was left to draw the
/// line again. Only one of them ever did.
fn readingOf(reading: ?ResultReading, from_log: ?SentinelHit) struct {
    exit_code: ?i32 = null,
    exit_source: JobProbe.ExitSource = .none,
    finished_at: ?i64 = null,
    claimed_request_id: ?[]const u8 = null,
    conflict: ?JobProbe.Conflict = null,
    refused: ?JobProbe.Refused = null,
} {
    if (reading) |r| {
        if (r.defective()) return .{
            // Null when the log said nothing either: then there was no verdict
            // to decline, only two records that are both silent, and the job
            // may still be running. `refused` means a verdict was available and
            // was turned down, which is the case that has to end `indeterminate`.
            .refused = if (from_log) |found| .{ .sentinel_exit_code = found.exit_code } else null,
        };
        if (r.usable()) |doc| {
            if (from_log) |found| {
                if (found.exit_code != doc.exit_code) return .{ .conflict = .{
                    .result_exit_code = doc.exit_code,
                    .sentinel_exit_code = found.exit_code,
                } };
            }
            // Agreement, or the sidecar alone. The sidecar is the stronger
            // record — a document at an address derived from this operation's
            // own id, versus a line in an append-only log anything on the host
            // can write to — so it is what the receipt says it read, and it is
            // the only one of the two that carries a finish time or an identity.
            return .{
                .exit_code = doc.exit_code,
                .exit_source = .result_file,
                .finished_at = doc.finished_at,
                .claimed_request_id = doc.claimed_request_id,
            };
        }
    }
    if (from_log) |found| return .{ .exit_code = found.exit_code, .exit_source = .log_sentinel };
    return .{};
}

/// Jobs opt into business-state reporting by printing this marker; the
/// value after the colon becomes `businessResult` in status/read output.
pub const business_marker = "__TERMINUS_RESULT__";

/// Returns the value from the LAST `__TERMINUS_RESULT__:<value>` line in
/// `data` (line-start match), or null. Last wins so a job can update its
/// verdict as it progresses.
fn findBusinessResult(arena: Allocator, data: []const u8) Allocator.Error!?[]const u8 {
    var search_from: usize = 0;
    var last: ?[]const u8 = null;
    while (std.mem.indexOfPos(u8, data, search_from, business_marker)) |pos| {
        const line_start = if (std.mem.lastIndexOfScalar(u8, data[0..pos], '\n')) |nl| nl + 1 else 0;
        const line_end = std.mem.indexOfScalarPos(u8, data, pos, '\n') orelse data.len;
        if (line_start == pos) {
            const after = data[pos + business_marker.len .. line_end];
            if (after.len >= 1 and after[0] == ':') {
                last = std.mem.trim(u8, after[1..], " \t\r");
            }
        }
        search_from = pos + business_marker.len;
    }
    return if (last) |v| try arena.dupe(u8, v) else null;
}

/// Answers "how is this job doing": reads new log output from the caller's
/// cursor, establishes whether it ended, checks pane liveness. Used by
/// `job read`, which needs the output stream and so cannot share
/// `probeTail`'s tail window.
pub fn probeJob(
    executor: Executor,
    arena: Allocator,
    name: []const u8,
    sentinel: []const u8,
    request_id: ?[]const u8,
    cursor: i64,
    limit: i64,
) Error!JobProbe {
    const chunk = try readLog(executor, arena, name, cursor, limit);
    const cleaned = try stripTerminalNoise(arena, chunk.data);
    const sidecar: ?ResultReading = if (request_id) |id| try readResult(executor, arena, id) else null;
    const reading: SidecarReading = if (sidecar) |r| r.summary() else .not_requested;

    const from_log = findSentinel(cleaned, sentinel);
    const result = readingOf(sidecar, from_log);
    // Trim the marker out of what the caller shows the user; the window
    // happened to contain it, which is a property of where their cursor was,
    // not of how the job ended. Independent of what the records established:
    // this is presentation, not evidence.
    const output = if (from_log) |found| cleaned[found.output_start..found.output_end] else cleaned;

    return .{
        .output = output,
        .next_cursor = chunk.next_cursor,
        .exit_code = result.exit_code,
        .exit_source = result.exit_source,
        .finished_at = result.finished_at,
        .result_request_id = result.claimed_request_id,
        .conflict = result.conflict,
        .refused = result.refused,
        .sidecar = reading,
        .session_alive = try isAlive(executor, arena, name),
        .business_result = try findBusinessResult(arena, cleaned),
    };
}

/// The pipe-pane log is a raw terminal stream: it carries CSI/OSC escape
/// sequences (bracketed paste, shell integration beacons) and CR line
/// endings. Strip them so agents get plain text.
pub fn stripTerminalNoise(arena: Allocator, raw: []const u8) Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < raw.len) {
        const ch = raw[i];
        if (ch == 0x1b and i + 1 < raw.len) {
            const kind = raw[i + 1];
            if (kind == '[') {
                // CSI: ESC [ params... final-byte(0x40-0x7e)
                i += 2;
                while (i < raw.len and (raw[i] < 0x40 or raw[i] > 0x7e)) i += 1;
                if (i < raw.len) i += 1;
                continue;
            }
            if (kind == ']') {
                // OSC: ESC ] ... (BEL | ESC \)
                i += 2;
                while (i < raw.len) {
                    if (raw[i] == 0x07) {
                        i += 1;
                        break;
                    }
                    if (raw[i] == 0x1b and i + 1 < raw.len and raw[i + 1] == '\\') {
                        i += 2;
                        break;
                    }
                    i += 1;
                }
                continue;
            }
            // Two-byte escape (ESC c, ESC =, ...)
            i += 2;
            continue;
        }
        if (ch == '\r') {
            i += 1;
            continue;
        }
        try out.append(arena, ch);
        i += 1;
    }
    return out.toOwnedSlice(arena);
}

test stripTerminalNoise {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const cleaned = try stripTerminalNoise(
        arena_state.allocator(),
        "\x1b[?2004l\r\x1b]3008;start=abc\x07hello\r\n\x1b[0mworld\n",
    );
    try t.expectEqualStrings("hello\nworld\n", cleaned);
}

const SentinelHit = struct {
    output_start: usize,
    output_end: usize,
    exit_code: i32,
};

/// Locates the sentinel *result* line (line-start match), skipping the
/// echoed keystroke line. Output spans from after the echo line to the
/// marker line.
fn findSentinel(data: []const u8, sentinel: []const u8) ?SentinelHit {
    var search_from: usize = 0;
    var echo_end: ?usize = null;
    while (std.mem.indexOfPos(u8, data, search_from, sentinel)) |pos| {
        const line_start = if (std.mem.lastIndexOfScalar(u8, data[0..pos], '\n')) |nl| nl + 1 else 0;
        const line_end = std.mem.indexOfScalarPos(u8, data, pos, '\n') orelse data.len;
        if (line_start == pos) {
            // Result line: "<sentinel>:<code>"
            const after = data[pos + sentinel.len .. line_end];
            if (after.len >= 2 and after[0] == ':') {
                const code_text = std.mem.trim(u8, after[1..], " \r");
                if (std.fmt.parseInt(i32, code_text, 10)) |code| {
                    // A shell exit status is 0-255, so a line carrying
                    // anything else was not written by `echo <sentinel>:$?`
                    // — it is the job's own output that happens to start
                    // with the marker. Treating it as the result line let a
                    // job settle its own operation with a code the sidecar
                    // reader rejects outright, so the scan continues past it
                    // and reports nothing if no valid line ever turns up.
                    if (code >= 0 and code <= 255) {
                        const start = echo_end orelse 0;
                        return .{ .output_start = @min(start, line_start), .output_end = line_start, .exit_code = code };
                    }
                } else |_| {}
            }
        } else {
            // Echoed keystrokes; real output starts on the next line.
            echo_end = @min(line_end + 1, data.len);
        }
        search_from = pos + sentinel.len;
    }
    return null;
}

test findSentinel {
    const t = std.testing;
    const data = "$ ls; echo __X__:$?\r\nfile1\r\nfile2\r\n__X__:0\r\n";
    const hit = findSentinel(data, "__X__").?;
    try t.expectEqualStrings("file1\r\nfile2\r\n", data[hit.output_start..hit.output_end]);
    try t.expectEqual(0, hit.exit_code);
    try t.expectEqual(null, findSentinel("$ ls; echo __X__:$?\r\npartial", "__X__"));

    // A shell exit status is 0-255. A line starting with the marker and
    // carrying anything else was not written by `echo <sentinel>:$?`, so it
    // is not a result line — the sidecar reader has always rejected such a
    // document outright, and the log reader accepting one meant a job could
    // settle its own operation with a code that could not have come from a
    // shell.
    try t.expectEqual(null, findSentinel("__X__:-1\n", "__X__"));
    try t.expectEqual(null, findSentinel("__X__:256\n", "__X__"));
    try t.expectEqual(null, findSentinel("__X__:99999999999999999999\n", "__X__"));

    // Rejecting one is not the same as giving up: the scan continues, so a
    // bogus line cannot hide the real one behind it.
    const mixed = "__X__:900\nreal output\n__X__:3\n";
    try t.expectEqual(3, findSentinel(mixed, "__X__").?.exit_code);
}
