//! Gates for `terminus docker inspect|wait`.
//!
//! **What is driven, and what is not — read this before the assertions.**
//!
//! There is no live server here and there is no docker daemon. The test host's
//! key exists only inside a database these tests may not touch, so a libssh2
//! channel cannot be stood up at all. Everything below therefore stops at the
//! `Core.Executor` boundary and drives the real code through `Core.Scripted`,
//! feeding it the exact bytes a host would return.
//!
//! **Proven here:**
//!
//!  * the remote command is an argv rendered one shell word per element, and a
//!    container name holding a space, an apostrophe, a `$` and braces comes back
//!    out of `Core.shell.words` as one word equal to itself — never as syntax;
//!  * that rendered line is what the probe script actually carries;
//!  * each of the five distinguishable absences, plus an unreadable answer and a
//!    status the probe does not produce, is reported as itself and not as
//!    another — driven end to end through `inspect`;
//!  * `verdictOf` over its **whole** matrix (2 targets x 8 lifecycles x 5 health
//!    values): `reached` comes back for no combination except the two that are
//!    the target;
//!  * a wait whose deadline expires reports `timed_out`, `ok: false`, and never
//!    `reached` — driven through the real loop, not through the pure rule alone;
//!  * a running container whose image declares no HEALTHCHECK is `cannot_reach`
//!    rather than a 60-second `timed_out`;
//!  * both documents' key sets, and the shared state keys inside them.
//!
//! **Reviewed, not proven:** `run` itself — the server lookup, `Cli.connect`,
//! the human-mode printing and the exit codes. Every one of those needs a store
//! and a host. What `run` contains beyond them is flag reading and a call into
//! the functions below; the key sets it emits are held by the gates at the
//! bottom of this file.
//!
//! **Also reviewed, not proven, and this is the larger share:** the *remote*
//! behaviour the probe rests on — that `command -v docker` answers for the PATH
//! a non-interactive channel gets, that `docker container inspect` exits
//! non-zero for an unknown container, that `docker version` succeeds only when
//! the daemon answers, and that `/var/run/docker.sock` is `root:docker` on a
//! host whose account is not in that group. Those are facts about docker and
//! about distribution packaging, not about this code, and nothing in this
//! process can establish them. What *is* held here is that each of those
//! answers, once given, becomes its own reading and never somebody else's.
const std = @import("std");
const Core = @import("../core/core.zig");
const docker = @import("cmd_docker.zig");

// --- fixtures ----------------------------------------------------------------

/// `ExecResult` owns mutable buffers and `Scripted` dupes whatever it is handed
/// before passing it on, so a literal is never written through. Same reasoning,
/// and same `@constCast`, as `cmd_transfer_test.reply`.
fn replyCode(code: i32, stdout: []const u8, stderr: []const u8) Core.Scripted.Step {
    return .{ .reply = .{
        .exit_code = code,
        .stdout = @constCast(stdout),
        .stderr = @constCast(stderr),
    } };
}

/// A `.State` document, as `docker container inspect --format` prints it.
fn stateLine(arena: std.mem.Allocator, container_status: []const u8, health: ?[]const u8) ![]const u8 {
    return if (health) |word|
        std.fmt.allocPrint(
            arena,
            "{{\"Status\":\"{s}\",\"Running\":true,\"ExitCode\":0,\"StartedAt\":\"2026-08-21T09:00:00Z\",\"FinishedAt\":\"0001-01-01T00:00:00Z\",\"Health\":{{\"Status\":\"{s}\",\"FailingStreak\":0,\"Log\":[]}}}}\n",
            .{ container_status, word },
        )
    else
        std.fmt.allocPrint(
            arena,
            "{{\"Status\":\"{s}\",\"Running\":true,\"ExitCode\":0,\"StartedAt\":\"2026-08-21T09:00:00Z\",\"FinishedAt\":\"0001-01-01T00:00:00Z\"}}\n",
            .{container_status},
        );
}

/// An `std.Io` for the wait loop's clock and sleep. The loop is driven with a
/// zero interval, so nothing here actually sleeps.
const Clock = struct {
    io: std.Io,
    threaded: *std.Io.Threaded,
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator) !Clock {
        const threaded = try allocator.create(std.Io.Threaded);
        threaded.* = .init(allocator, .{});
        return .{ .io = threaded.io(), .threaded = threaded, .allocator = allocator };
    }

    fn deinit(c: *Clock) void {
        c.threaded.deinit();
        c.allocator.destroy(c.threaded);
    }
};

/// A container name holding every byte a shell would otherwise eat. Not a
/// plausible container name — the point is that the quoting is not asked to be
/// clever, and a name a host really could have (`web-1`) would prove nothing.
const nasty_name = "a b'c$d{e}f\"g;h`i";

// --- gate: the command is an argv, and every element survives as one word -----

test "gate: an argv element with a space, a quote, a $ and braces is one shell word" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // The fixture is asserted rather than assumed: a name that had lost its
    // metacharacters would make every assertion below vacuous.
    try t.expect(std.mem.indexOfScalar(u8, nasty_name, ' ') != null);
    try t.expect(std.mem.indexOfScalar(u8, nasty_name, '\'') != null);
    try t.expect(std.mem.indexOfScalar(u8, nasty_name, '$') != null);
    try t.expect(std.mem.indexOfScalar(u8, nasty_name, '{') != null);
    try t.expect(std.mem.indexOfScalar(u8, nasty_name, '}') != null);

    const argv = try docker.inspectArgv(arena, nasty_name);
    try t.expectEqual(docker.inspect_argv_len, argv.len);

    const line = try docker.inspectLine(arena, nasty_name);

    // The honest check: not "the quotes look right", but what a POSIX shell
    // would split this text into. `Core.shell.words` applies the splitting
    // rules; if the list that comes out is the list that went in, nothing in
    // any element became syntax.
    const seen = try Core.shell.words(arena, line);
    try t.expectEqual(docker.inspect_argv_len, seen.len);
    for (argv, seen) |wanted, got| try t.expectEqualStrings(wanted, got);

    // Named individually as well, so a `words` that happened to produce seven
    // of something else could not pass. The format template is the second
    // element a shell would have eaten — a space and four braces.
    try t.expectEqualStrings("docker", seen[0]);
    try t.expectEqualStrings("container", seen[1]);
    try t.expectEqualStrings("inspect", seen[2]);
    try t.expectEqualStrings("--format", seen[3]);
    try t.expectEqualStrings("{{json .State}}", seen[4]);
    try t.expectEqualStrings("--", seen[5]);
    try t.expectEqualStrings(nasty_name, seen[6]);

    // And the name is not in the command line verbatim: its apostrophe has been
    // rewritten, which is the whole difference between one word and three.
    try t.expect(std.mem.indexOf(u8, line, nasty_name) == null);
}

test "gate: the probe script carries the rendered line rather than a concatenation" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const line = try docker.inspectLine(arena, nasty_name);
    const script = try docker.probeScript(arena, nasty_name);

    // Exactly once. A script that had built the command a second way — or had
    // stopped using this one — fails here rather than in production.
    try t.expectEqual(@as(usize, 1), std.mem.count(u8, script, line));
    // The raw name never appears; only the quoted form does.
    try t.expectEqual(@as(usize, 0), std.mem.count(u8, script, nasty_name));

    // The five statuses the readings are made of are all in the script, so a
    // scan over a script that had lost one of them fails instead of quietly
    // finding nothing. Counted, not merely present.
    const wanted = [_][]const u8{ "exit 40", "exit 0", "exit 42", "exit 43", "exit 41" };
    var found: usize = 0;
    for (wanted) |needle| {
        if (std.mem.indexOf(u8, script, needle) != null) found += 1;
    }
    try t.expectEqual(wanted.len, found);
}

// --- gate: five absences, each reported as itself ----------------------------

/// One scripted host answer and the reading it must produce.
const Case = struct {
    label: []const u8,
    step: Core.Scripted.Step,
    want: []const u8,
};

test "gate: each distinguishable failure is reported as itself and not as another" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const cases = [_]Case{
        .{
            .label = "docker is not installed",
            .step = replyCode(40, "", ""),
            .want = "docker_absent",
        },
        .{
            .label = "docker is installed and the daemon did not answer",
            .step = replyCode(41, "", "Cannot connect to the Docker daemon at unix:///var/run/docker.sock."),
            .want = "daemon_unreachable",
        },
        .{
            .label = "the daemon answered and has no such container",
            .step = replyCode(42, "", "Error response from daemon: No such container: api"),
            .want = "container_absent",
        },
        .{
            .label = "the socket is there and this account may not write to it",
            .step = replyCode(43, "", "permission denied while trying to connect to the Docker daemon socket"),
            .want = "permission_denied",
        },
        .{
            .label = "the daemon answered about the container and we cannot read it",
            .step = replyCode(0, "<no value>\n", ""),
            .want = "unparseable",
        },
        .{
            .label = "the probe came back with a status it does not produce",
            .step = replyCode(127, "", "sh: syntax error"),
            .want = "unknown_probe_status",
        },
        .{
            .label = "a state",
            .step = replyCode(0, "{\"Status\":\"running\",\"ExitCode\":0}\n", ""),
            .want = "state",
        },
    };

    // Every arm of the union, or this gate is checking a subset of the
    // vocabulary it claims to hold apart. `@typeInfo` counts them; the list
    // above supplies the answers. An arm added without a case fails here.
    try t.expectEqual(@typeInfo(docker.Reading).@"union".fields.len, cases.len);

    var seen: std.ArrayList([]const u8) = .empty;
    for (cases) |case| {
        var steps = [_]Core.Scripted.Step{case.step};
        var script = Core.Scripted.init(arena, &steps);
        const probe = try docker.inspect(script.executor(), arena, "api");
        if (!std.mem.eql(u8, probe.reading.code(), case.want)) {
            std.debug.print(
                \\
                \\"{s}" was read as `{s}`, and it is `{s}`.
                \\These are separate readings because they send an operator to separate places:
                \\a missing docker, a daemon that is not answering, a refusal, a container that
                \\is not there, an answer we cannot parse and a probe that did not run as
                \\written are six different facts. Collapsing any of them into another is the
                \\pseudo-success this module exists to refuse.
                \\
            , .{ case.label, probe.reading.code(), case.want });
            return error.ReadingCollapsedIntoAnother;
        }
        try seen.append(arena, probe.reading.code());
    }

    // Pairwise distinct. A `code()` that returned one word for two arms would
    // satisfy every assertion above.
    for (seen.items, 0..) |a, i| {
        for (seen.items[i + 1 ..]) |b| try t.expect(!std.mem.eql(u8, a, b));
    }
    try t.expectEqual(cases.len, seen.items.len);

    // ...and each non-state reading says which one it is, in a sentence of its
    // own. A shared "could not read the container" would pass everything above.
    var sentences: std.ArrayList([]const u8) = .empty;
    for (cases) |case| {
        var steps = [_]Core.Scripted.Step{case.step};
        var script = Core.Scripted.init(arena, &steps);
        const probe = try docker.inspect(script.executor(), arena, "api");
        const detail = try probe.reading.describe(arena, "api");
        if (probe.reading.isState()) {
            try t.expectEqual(@as(?[]const u8, null), detail);
            continue;
        }
        try sentences.append(arena, detail orelse return error.AbsenceWithNoSentence);
    }
    try t.expectEqual(cases.len - 1, sentences.items.len);
    for (sentences.items, 0..) |a, i| {
        for (sentences.items[i + 1 ..]) |b| try t.expect(!std.mem.eql(u8, a, b));
    }
}

test "gate: the host's own words travel as prose and never as the reading" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // docker's message says "No such container", and the reading is
    // `daemon_unreachable` because the *exit status* said so. The typed answer
    // comes from the status, never from the English — that is the whole reason
    // the probe spends its exit codes the way it does.
    var steps = [_]Core.Scripted.Step{replyCode(41, "", "Error response from daemon: No such container: api")};
    var script = Core.Scripted.init(arena, &steps);
    const probe = try docker.inspect(script.executor(), arena, "api");
    try t.expectEqualStrings("daemon_unreachable", probe.reading.code());
    try t.expectEqualStrings("Error response from daemon: No such container: api", probe.remote_message.?);
}

// --- gate: what a state document is read as ----------------------------------

test "gate: a state carries both the typed word and the word docker printed" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const reading = try docker.readState(arena, try stateLine(arena, "running", "healthy"));
    const state = switch (reading) {
        .state => |s| s,
        else => return error.ReadableStateWasRefused,
    };
    try t.expectEqual(docker.Lifecycle.running, state.lifecycle);
    try t.expectEqualStrings("running", state.status_reported);
    try t.expectEqual(docker.Health.healthy, state.health);
    try t.expectEqualStrings("healthy", state.health_reported.?);
    try t.expectEqual(@as(?i64, 0), state.exit_code);

    // No `Health` object at all is `none` *and* a null reported word — the same
    // fact twice, one for branching and one for reading. Not `unhealthy`, and
    // not a health of "".
    const no_check = try docker.readState(arena, try stateLine(arena, "running", null));
    const plain = switch (no_check) {
        .state => |s| s,
        else => return error.ReadableStateWasRefused,
    };
    try t.expectEqual(docker.Health.none, plain.health);
    try t.expectEqual(@as(?[]const u8, null), plain.health_reported);

    // A word docker printed that this build does not have is `unrecognised`
    // and the word survives. Never rounded to the nearest member.
    const odd = try docker.readState(arena, try stateLine(arena, "hibernating", "degraded"));
    const strange = switch (odd) {
        .state => |s| s,
        else => return error.ReadableStateWasRefused,
    };
    try t.expectEqual(docker.Lifecycle.unrecognised, strange.lifecycle);
    try t.expectEqualStrings("hibernating", strange.status_reported);
    try t.expectEqual(docker.Health.unrecognised, strange.health);
    try t.expectEqualStrings("degraded", strange.health_reported.?);

    // A document with no `Status` is unreadable, not a container whose status
    // defaulted to something. This is the field with no default in `StateDoc`.
    const headless = try docker.readState(arena, "{\"Running\":true}");
    try t.expectEqualStrings("unparseable", headless.code());

    // Anything the account's login profile echoed ahead of the answer is not
    // the answer: the last non-empty line is.
    const noisy = try docker.readState(arena, "Welcome to Ubuntu\nLast login: today\n{\"Status\":\"paused\"}\n");
    const after_motd = switch (noisy) {
        .state => |s| s,
        else => return error.MotdWasReadAsTheState,
    };
    try t.expectEqual(docker.Lifecycle.paused, after_motd.lifecycle);
}

test "gate: docker's vocabulary and this build's enums are the same list" {
    const t = std.testing;
    // `unrecognised` is terminus's word and is the only member of `Lifecycle`
    // that is not one of docker's. A member added to the enum without a word to
    // read it from — or a word added with no member — lands here.
    try t.expectEqual(
        @typeInfo(docker.Lifecycle).@"enum".fields.len,
        docker.docker_status_words_len + 1,
    );
    // `Health` has two of ours: `none` (no HEALTHCHECK) and `unrecognised`.
    try t.expectEqual(
        @typeInfo(docker.Health).@"enum".fields.len,
        docker.docker_health_words_len + 2,
    );
}

// --- gate: the wait rule, over its whole matrix ------------------------------

test "gate: no combination reports the target reached except the target itself" {
    const t = std.testing;

    const targets = [_]docker.Target{ .healthy, .running };
    const lifecycles = [_]docker.Lifecycle{
        .created, .running, .paused, .restarting, .removing, .exited, .dead, .unrecognised,
    };
    const healths = [_]docker.Health{ .none, .starting, .healthy, .unhealthy, .unrecognised };

    // Exhaustive by construction: a member added to any of the three unions
    // fails here before it can be silently left out of the sweep.
    try t.expectEqual(@typeInfo(docker.Target).@"enum".fields.len, targets.len);
    try t.expectEqual(@typeInfo(docker.Lifecycle).@"enum".fields.len, lifecycles.len);
    try t.expectEqual(@typeInfo(docker.Health).@"enum".fields.len, healths.len);

    var combinations: usize = 0;
    var reached: usize = 0;
    var cannot: usize = 0;
    for (targets) |target| {
        for (lifecycles) |lifecycle| {
            for (healths) |health| {
                combinations += 1;
                const reading: docker.Reading = .{ .state = .{
                    .lifecycle = lifecycle,
                    .status_reported = "x",
                    .health = health,
                    .health_reported = if (health == .none) null else "x",
                    .exit_code = null,
                    .started_at = null,
                    .finished_at = null,
                } };
                const verdict = docker.verdictOf(target, reading);
                switch (verdict) {
                    .reached => {
                        reached += 1;
                        // The property. Waiting for `healthy` may only be
                        // satisfied by `healthy`, and waiting for `running` only
                        // by `running`. Any other combination reporting
                        // `reached` is a health wait succeeding for a container
                        // that never got there.
                        const legitimate = switch (target) {
                            .healthy => health == .healthy,
                            .running => lifecycle == .running,
                        };
                        if (!legitimate) {
                            std.debug.print(
                                \\
                                \\a wait for `{s}` reported `reached` for a container whose status is
                                \\`{s}` and whose health is `{s}`. That is a health wait reporting success
                                \\for a container that never became the thing it was waiting for, which is
                                \\the one outcome this verb may not have.
                                \\
                            , .{ @tagName(target), @tagName(lifecycle), @tagName(health) });
                            return error.WaitReportedSuccessForTheWrongState;
                        }
                    },
                    .cannot_reach => |why| {
                        cannot += 1;
                        // A refusal that says nothing is a refusal an operator
                        // cannot act on.
                        try t.expect(why.len > 0);
                    },
                    .keep_waiting, .undetermined => {},
                }
            }
        }
    }

    // The sweep really covered the matrix, and it really found both answers —
    // a `verdictOf` that returned `keep_waiting` for everything would satisfy
    // the property above by never being right about anything.
    try t.expectEqual(@as(usize, 80), combinations);
    try t.expect(reached > 0);
    try t.expect(cannot > 0);

    // Every non-state reading is `undetermined` and never `keep_waiting`: there
    // is nothing there to wait on, and a wait that polled a host with no docker
    // on it until its deadline would be reporting a timeout for a question it
    // never asked.
    const absences = [_]docker.Reading{
        .docker_absent,
        .daemon_unreachable,
        .permission_denied,
        .container_absent,
        .{ .unparseable = "SyntaxError" },
        .{ .unknown_probe_status = 127 },
    };
    try t.expectEqual(@typeInfo(docker.Reading).@"union".fields.len - 1, absences.len);
    for (targets) |target| {
        for (absences) |reading| {
            switch (docker.verdictOf(target, reading)) {
                .undetermined => {},
                .keep_waiting, .reached, .cannot_reach => {
                    std.debug.print(
                        \\
                        \\a wait for `{s}` did not report `undetermined` for the reading `{s}`.
                        \\None of the six absences is a fact about the container's state, so there is
                        \\nothing there to wait on: a wait that kept polling a host with no docker on
                        \\it would burn its whole deadline and then report a timeout for a question it
                        \\never got to ask.
                        \\
                    , .{ @tagName(target), reading.code() });
                    return error.AbsenceWasWaitedOn;
                },
            }
        }
    }
}

// --- gate: the deadline, driven through the real loop ------------------------

test "gate: a wait whose deadline expires is timed_out, and timed_out is not success" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var clock = try Clock.init(t.allocator);
    defer clock.deinit();

    // A container that is running and whose healthcheck is still `starting`.
    // The one thing a wait must never do is call that `healthy`.
    var steps = [_]Core.Scripted.Step{
        replyCode(0, try stateLine(arena, "running", "starting"), ""),
    };
    var script = Core.Scripted.init(arena, &steps);

    const outcome = try docker.waitFor(script.executor(), arena, clock.io, .{
        .container = "api",
        .target = .healthy,
        // Zero, so the deadline is already past when the first poll returns.
        // The loop still polls once: a wait must never report a deadline it did
        // not first look past.
        .timeout_secs = 0,
        .interval_secs = 0,
    });

    try t.expectEqual(docker.WaitOutcome.Kind.timed_out, outcome.kind);
    try t.expectEqualStrings("timed_out", outcome.code());
    try t.expect(!outcome.ok());
    try t.expectEqual(@as(usize, 1), outcome.polls);
    // It looked. One command really went out, and it is the probe.
    try t.expectEqual(@as(usize, 1), script.seen.items.len);

    // The document. `ok` is false, the outcome word is `timed_out`, and the
    // word `reached` does not appear anywhere in it — this is the assertion
    // that stops a timeout from being read as a success by anything that greps.
    const document = try docker.waitJson(arena, "web", "api", outcome, 0, .healthy, "direct", null);
    try t.expect(!document.ok);
    try t.expectEqualStrings("timed_out", document.outcome);
    try t.expectEqualStrings("state", document.reading);
    // The last reading travels with the timeout, so the caller is told what it
    // was still waiting on rather than only that it stopped.
    try t.expectEqualStrings("running", document.status.?);
    try t.expectEqualStrings("starting", document.health.?);
    try t.expect(document.detail != null);

    var buffer: [4096]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try std.json.Stringify.value(document, .{ .whitespace = .indent_2 }, &writer);
    const text = writer.buffered();
    try t.expect(std.mem.indexOf(u8, text, "\"ok\": false") != null);
    try t.expect(std.mem.indexOf(u8, text, "\"outcome\": \"timed_out\"") != null);
    try t.expect(std.mem.indexOf(u8, text, "reached") == null);
}

test "gate: the same fixture reaching the target is success, and is a different word" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var clock = try Clock.init(t.allocator);
    defer clock.deinit();

    // The discriminating control for the gate above: a `waitFor` that answered
    // `timed_out` unconditionally would satisfy every assertion there.
    // `starting` first, then `healthy`, so the loop really goes round.
    var steps = [_]Core.Scripted.Step{
        replyCode(0, try stateLine(arena, "running", "starting"), ""),
        replyCode(0, try stateLine(arena, "running", "healthy"), ""),
    };
    var script = Core.Scripted.init(arena, &steps);

    const outcome = try docker.waitFor(script.executor(), arena, clock.io, .{
        .container = "api",
        .target = .healthy,
        .timeout_secs = 600,
        .interval_secs = 0,
    });

    try t.expectEqual(docker.WaitOutcome.Kind.reached, outcome.kind);
    try t.expect(outcome.ok());
    try t.expectEqual(@as(usize, 2), outcome.polls);
    try t.expectEqual(@as(usize, 2), script.seen.items.len);
    // Both polls sent the same probe, and it is the one built from the argv.
    const line = try docker.inspectLine(arena, "api");
    for (script.seen.items) |sent| try t.expect(std.mem.indexOf(u8, sent, line) != null);

    const document = try docker.waitJson(arena, "web", "api", outcome, 600, .healthy, "direct", null);
    try t.expect(document.ok);
    try t.expectEqualStrings("reached", document.outcome);
    try t.expect(!std.mem.eql(u8, document.outcome, "timed_out"));
}

test "gate: a running container with no HEALTHCHECK cannot reach healthy, and says so" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var clock = try Clock.init(t.allocator);
    defer clock.deinit();

    // Running, and the image declares no HEALTHCHECK, so `.State` has no
    // `Health` object at all. A wait that treated that as "not healthy yet"
    // would spend its whole deadline and then report `timed_out` for a container
    // that is working — a wrong answer delivered slowly.
    var steps = [_]Core.Scripted.Step{
        replyCode(0, try stateLine(arena, "running", null), ""),
    };
    var script = Core.Scripted.init(arena, &steps);

    const outcome = try docker.waitFor(script.executor(), arena, clock.io, .{
        .container = "api",
        .target = .healthy,
        .timeout_secs = 600,
        .interval_secs = 0,
    });

    try t.expectEqual(docker.WaitOutcome.Kind.cannot_reach, outcome.kind);
    try t.expect(!outcome.ok());
    // One poll: it did not wait for a state that cannot arrive.
    try t.expectEqual(@as(usize, 1), outcome.polls);
    // Not the timeout, and not success.
    try t.expect(!std.mem.eql(u8, outcome.code(), "timed_out"));
    try t.expect(!std.mem.eql(u8, outcome.code(), "reached"));
    // The sentence names the missing HEALTHCHECK and what to do instead. A
    // `cannot_reach` an operator cannot act on is a stall with a nicer word.
    const why = outcome.why orelse return error.CannotReachWithNoReason;
    try t.expect(std.mem.indexOf(u8, why, "HEALTHCHECK") != null);
    try t.expect(std.mem.indexOf(u8, why, "running") != null);

    // ...and the same container, waited on for `running`, is reached at once.
    // The control that keeps the arm above from being a blanket refusal.
    var again = [_]Core.Scripted.Step{
        replyCode(0, try stateLine(arena, "running", null), ""),
    };
    var second = Core.Scripted.init(arena, &again);
    const running = try docker.waitFor(second.executor(), arena, clock.io, .{
        .container = "api",
        .target = .running,
        .timeout_secs = 600,
        .interval_secs = 0,
    });
    try t.expectEqual(docker.WaitOutcome.Kind.reached, running.kind);
}

test "gate: a wait against a host with no docker is undetermined, not a timeout" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var clock = try Clock.init(t.allocator);
    defer clock.deinit();

    var steps = [_]Core.Scripted.Step{replyCode(40, "", "")};
    var script = Core.Scripted.init(arena, &steps);
    const outcome = try docker.waitFor(script.executor(), arena, clock.io, .{
        .container = "api",
        .target = .healthy,
        .timeout_secs = 600,
        .interval_secs = 0,
    });

    // Three words that must stay three words: the deadline expired, the target
    // cannot be reached, and the host never told us anything. This is the third.
    try t.expectEqual(docker.WaitOutcome.Kind.undetermined, outcome.kind);
    try t.expectEqualStrings("docker_absent", outcome.probe.reading.code());
    try t.expect(!outcome.ok());
    try t.expectEqual(@as(usize, 1), outcome.polls);

    const document = try docker.waitJson(arena, "web", "api", outcome, 600, .healthy, "direct", null);
    try t.expectEqualStrings("undetermined", document.outcome);
    try t.expectEqualStrings("docker_absent", document.reading);
    // No state to report, and none reported. A document with a null `status`
    // beside a populated `health` would describe a container nobody read.
    try t.expectEqual(@as(?[]const u8, null), document.status);
    try t.expectEqual(@as(?[]const u8, null), document.health);
    try t.expectEqual(@as(?[]const u8, null), document.statusReported);
    try t.expect(document.detail != null);
}

test "gate: the four wait outcomes are four words, and only one of them is ok" {
    const t = std.testing;
    const kinds = [_]docker.WaitOutcome.Kind{ .reached, .timed_out, .cannot_reach, .undetermined };
    try t.expectEqual(@typeInfo(docker.WaitOutcome.Kind).@"enum".fields.len, kinds.len);

    var ok_count: usize = 0;
    for (kinds, 0..) |kind, i| {
        const outcome: docker.WaitOutcome = .{
            .kind = kind,
            .probe = .{ .reading = .docker_absent, .remote_message = null },
            .polls = 1,
            .waited_secs = 0,
            .why = null,
        };
        if (outcome.ok()) ok_count += 1;
        for (kinds[i + 1 ..]) |other| {
            try t.expect(!std.mem.eql(u8, @tagName(kind), @tagName(other)));
        }
    }
    // Exactly one. A wait that answered `ok` for a timeout, or for a container
    // it could not read, is the failure mode this verb is built around.
    try t.expectEqual(@as(usize, 1), ok_count);
}

// --- gates: the documents ----------------------------------------------------

test "gate: both documents carry the shared state keys, with the same types" {
    const t = std.testing;
    const shared = @typeInfo(docker.StateKeys).@"struct".fields;
    const inspect_fields = @typeInfo(docker.InspectJson).@"struct".fields;
    const wait_fields = @typeInfo(docker.WaitJson).@"struct".fields;

    try t.expectEqual(@as(usize, 7), shared.len);

    // Every state key appears in both emitters, with the same name and the same
    // type. Two hand-written copies of one key set is what this holds together:
    // a key added to `inspect` and not to `wait` would otherwise leave the two
    // verbs describing the same container differently.
    inline for (shared) |f| {
        var in_inspect = false;
        var in_wait = false;
        inline for (inspect_fields) |g| {
            if (comptime std.mem.eql(u8, f.name, g.name)) {
                in_inspect = true;
                try t.expect(f.type == g.type);
            }
        }
        inline for (wait_fields) |g| {
            if (comptime std.mem.eql(u8, f.name, g.name)) {
                in_wait = true;
                try t.expect(f.type == g.type);
            }
        }
        if (!in_inspect or !in_wait) {
            std.debug.print("state key `{s}` is missing from one of the two documents\n", .{f.name});
            return error.DocumentsDisagreeAboutTheState;
        }
    }
}

test "gate: the published key sets are exactly these, and only two of them are prose" {
    const t = std.testing;

    const inspect_keys = [_][]const u8{
        "ok",             "server", "container",      "reading",   "status",
        "statusReported", "health", "healthReported", "exitCode",  "startedAt",
        "finishedAt",     "detail", "dockerSaid",     "transport", "daemonError",
    };
    const wait_keys = [_][]const u8{
        "ok",             "server",        "container",      "target",    "outcome",
        "polls",          "waitedSeconds", "timeoutSeconds", "reading",   "status",
        "statusReported", "health",        "healthReported", "exitCode",  "startedAt",
        "finishedAt",     "detail",        "dockerSaid",     "transport", "daemonError",
    };

    const inspect_fields = @typeInfo(docker.InspectJson).@"struct".fields;
    const wait_fields = @typeInfo(docker.WaitJson).@"struct".fields;

    // A count first, so a key added or dropped fails here rather than being
    // missed by a loop that only checks the ones it knows about.
    try t.expectEqual(inspect_keys.len, inspect_fields.len);
    try t.expectEqual(wait_keys.len, wait_fields.len);
    inline for (inspect_fields, 0..) |f, i| try t.expectEqualStrings(inspect_keys[i], f.name);
    inline for (wait_fields, 0..) |f, i| try t.expectEqualStrings(wait_keys[i], f.name);

    // The two prose keys, named. Everything else is a bool, a number, a null,
    // or a word from a closed vocabulary — so no agent has to parse a sentence
    // to learn anything this verb established. A third prose key added without
    // a decision fails the count above.
    const prose = [_][]const u8{ "detail", "dockerSaid" };
    var found: usize = 0;
    inline for (inspect_fields) |f| {
        inline for (prose) |name| {
            if (comptime std.mem.eql(u8, f.name, name)) found += 1;
        }
    }
    try t.expectEqual(prose.len, found);
}

test "gate: every vocabulary key takes a word from its own closed list" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // `reading`, `status` and `health` are the three keys an agent branches on,
    // and each one is `@tagName` of an enum or union — so the vocabulary the
    // document publishes is the vocabulary the code has, by construction. This
    // walks it rather than trusting it.
    const readings = [_]docker.Reading{
        .docker_absent,
        .daemon_unreachable,
        .permission_denied,
        .container_absent,
        .{ .unparseable = "SyntaxError" },
        .{ .unknown_probe_status = 9 },
        .{ .state = .{
            .lifecycle = .running,
            .status_reported = "running",
            .health = .healthy,
            .health_reported = "healthy",
            .exit_code = null,
            .started_at = null,
            .finished_at = null,
        } },
    };
    try t.expectEqual(@typeInfo(docker.Reading).@"union".fields.len, readings.len);

    var checked: usize = 0;
    for (readings) |reading| {
        const document = try docker.inspectJson(
            arena,
            "web",
            "api",
            .{ .reading = reading, .remote_message = null },
            "direct",
            null,
        );
        // `reading` is one of the union's own tags.
        var named = false;
        inline for (@typeInfo(docker.Reading).@"union".fields) |f| {
            if (std.mem.eql(u8, document.reading, f.name)) named = true;
        }
        try t.expect(named);
        // `ok` is exactly "this is a state" and nothing else.
        try t.expectEqual(reading.isState(), document.ok);
        // `status` and `health` are either absent or members of their enums.
        if (document.status) |word| {
            var member = false;
            inline for (@typeInfo(docker.Lifecycle).@"enum".fields) |f| {
                if (std.mem.eql(u8, word, f.name)) member = true;
            }
            try t.expect(member);
        }
        if (document.health) |word| {
            var member = false;
            inline for (@typeInfo(docker.Health).@"enum".fields) |f| {
                if (std.mem.eql(u8, word, f.name)) member = true;
            }
            try t.expect(member);
        }
        checked += 1;
    }
    try t.expectEqual(readings.len, checked);
}
