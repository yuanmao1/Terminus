//! `terminus docker inspect|wait` — a container's state as typed keys, and a
//! health wait that cannot report success for a container that never got there.
//!
//! **This is an adapter over typed invocation, not an execution path.** It
//! builds an argv, renders it with `Core.shell.render` so every element is
//! exactly one shell word, and sends the result down the same `Core.Executor`
//! every other read in this tree uses. There is no command shaping here (that is
//! `Cli.shapeInvocation`), no connection handling (that is `Cli.connect`), no
//! scope guard and no terminal receipt (that is `Core.execution`) — see
//! "Why no operation row" below for why the last two are absent rather than
//! forgotten.
//!
//! **Why docker and not systemd.** The goal names both. `docker container
//! inspect --format '{{json .State}}'` is very nearly a contract: a documented
//! Go template over a documented struct, one line of JSON, stable since 1.13.
//! `systemctl show --property=…` is a second output shape with a second absence
//! vocabulary (no systemd, unit not found, unit found but never loaded, polkit
//! refusal, a user manager that is not the system one) and none of it is shared
//! with this. Two half-modelled vocabularies would each collapse absences the
//! way this file exists to stop, and neither could be proven here: there is no
//! live host in these gates. So: docker, whole, with its boundaries stated.
//!
//! **Why no operation row, no lease, no receipt.** `exec` opens one because an
//! arbitrary shell command's blast radius is unknowable — `Core.execution`'s own
//! doc says the asymmetry is what decides it. Here the command is not the
//! operator's: it is built in this file from a closed argv in which the only
//! operator-supplied element is a container *name*, and every verb in it
//! (`command -v`, `docker container inspect`, `docker version`, `test`) reads.
//! Nothing this file sends can change a container. `terminus doctor` reaches the
//! same conclusion for the same reason and files nothing either.
//!
//! A `wait` does not change that. Polling a container's state does not make it
//! healthy; the container becomes healthy because of what it is doing. A wait is
//! `inspect` in a loop with a deadline, and a loop of reads is a read. Filing a
//! row per poll would put thirty `exec`-kind rows in the ledger for one wait,
//! each with an argv the operator never typed — and `operations.Kind` may not
//! grow a `docker` member, so `exec` is the only word available and it would be
//! the wrong one.
const std = @import("std");
const Allocator = std.mem.Allocator;
const fatal = Cli.fail;
const Cli = @import("cli.zig");
const Core = @import("../core/core.zig");

pub const Error = Core.Ssh.ExecError || Allocator.Error;

pub const usage =
    \\usage: terminus docker <verb> <server> <container> [--json]
    \\
    \\  docker inspect <server> <container>
    \\        one round trip; the container's state as typed keys
    \\  docker wait <server> <container> [--for healthy|running]
    \\        [--timeout <sec>] [--interval <sec>]
    \\        the same read, polled until the target holds or the deadline expires
    \\
    \\--for defaults to healthy, --timeout to 60 seconds, --interval to 2.
    \\--interval is held between 1 second and 1 hour, so a watch can never
    \\busy-spin or wait past the deadline it was given.
    \\
    \\A wait that runs out of time reports outcome "timed_out" and exits 1. It is
    \\never reported as success; it is a different answer from a container that is
    \\merely "unhealthy" right now (that one is a health value you can still be
    \\waiting on) and from "undetermined", which means the host could not tell us
    \\anything about the container at all.
    \\
;

// --- The vocabulary ----------------------------------------------------------

/// docker's own words for `.State.Status`, as its API reference lists them.
///
/// `unrecognised` is deliberately *not* in here. It is terminus's word for "the
/// host printed something this list does not have", and a host that printed the
/// literal text `unrecognised` has to land on the sentinel because its word is
/// not docker's — not because it happened to match our name for the absence of a
/// match. `State.status_reported` carries the byte-for-byte word either way.
const docker_status_words = [_][]const u8{
    "created", "running", "paused", "restarting", "removing", "exited", "dead",
};

/// How many of `Lifecycle`'s members are docker's own words. `pub` so the gate
/// can hold the enum against the list without the list being public: a member
/// added to one and not the other is then a failing test rather than a status
/// that can never be read.
pub const docker_status_words_len: usize = docker_status_words.len;

/// The container lifecycle, closed.
pub const Lifecycle = enum {
    created,
    running,
    paused,
    restarting,
    removing,
    exited,
    dead,
    /// A word docker printed that this build's vocabulary does not have. Never
    /// a guess at which of the seven it meant.
    unrecognised,
};

/// docker's own words for `.State.Health.Status`.
const docker_health_words = [_][]const u8{ "starting", "healthy", "unhealthy" };

/// The same, for `Health` — which has two members of terminus's own: `none` (no
/// HEALTHCHECK in the image) and `unrecognised`.
pub const docker_health_words_len: usize = docker_health_words.len;

/// The health of a container, closed — with the absence that matters most in it.
pub const Health = enum {
    /// The document carried no `Health` object at all, which is what docker
    /// emits for an image that declares no `HEALTHCHECK`.
    ///
    /// The single most important value here. A container with no healthcheck is
    /// not unhealthy and is not starting: it has no health, and it never will
    /// until somebody changes the image. A wait that treated this as "not
    /// healthy yet" would burn its whole deadline on a container that is
    /// working perfectly — see `verdictOf`.
    none,
    starting,
    healthy,
    unhealthy,
    /// A word docker printed that this build's vocabulary does not have.
    unrecognised,
};

/// One container's state, as the host reported it.
///
/// Both the typed word and the reported word, always. The typed one is what a
/// caller branches on and it is drawn from a closed list; the reported one is
/// what docker actually printed, so an `unrecognised` is never also a *lost*
/// reading.
pub const State = struct {
    lifecycle: Lifecycle,
    /// Exactly the word docker printed for `.State.Status`.
    status_reported: []const u8,
    health: Health,
    /// Exactly the word docker printed for `.State.Health.Status`, or null when
    /// the document carried no `Health` object. Null here and `health == .none`
    /// are the same fact stated twice, on purpose: one is for branching and one
    /// is for reading.
    health_reported: ?[]const u8,
    exit_code: ?i64,
    started_at: ?[]const u8,
    finished_at: ?[]const u8,
};

/// What one probe established. Seven readings, and six of them are absences that
/// are *not* each other.
///
/// The model is `Tmux.SidecarReading` and `transfer.probeRemoteFile`: an absence
/// gets a name rather than a default, because "docker is not installed", "the
/// daemon did not answer", "this account may not talk to the daemon", "there is
/// no such container" and "the daemon answered and we cannot read what it said"
/// send an operator to five different places. Collapsing them into "not running"
/// is the pseudo-success this project keeps removing — it is also the specific
/// shape that makes an agent retry a deploy against a host whose docker daemon
/// is down.
pub const Reading = union(enum) {
    /// `command -v docker` found nothing on the PATH a non-interactive channel
    /// gets. Not "no such container": nothing was asked about the container.
    docker_absent,
    /// docker is installed and the daemon did not answer it. Nothing is known
    /// about the container.
    daemon_unreachable,
    /// The daemon did not answer, and the default socket is present and this
    /// account may not write to it. A refusal, not an outage. See
    /// `probe_script` for exactly how far that test reaches.
    permission_denied,
    /// The daemon answered and has no container by that name. This is the
    /// daemon's own answer — the only one of the seven that is.
    container_absent,
    /// The daemon answered about this container and what came back is not a
    /// document this build can read. Carries the parser's own word for what
    /// stopped it.
    unparseable: []const u8,
    /// The probe script came back with a status it does not produce. Never
    /// folded into one of the six above: the probe did not run as written, so
    /// nothing it "said" may be read as a fact about docker or the container.
    unknown_probe_status: i32,
    /// A state, read.
    state: State,

    /// The stable machine-readable name, derived from the tag so the published
    /// vocabulary and the code cannot drift.
    pub fn code(r: Reading) []const u8 {
        return @tagName(r);
    }

    /// Whether this reading is the container's state.
    pub fn isState(r: Reading) bool {
        return switch (r) {
            .state => true,
            .docker_absent,
            .daemon_unreachable,
            .permission_denied,
            .container_absent,
            .unparseable,
            .unknown_probe_status,
            => false,
        };
    }

    /// The sentence for a reading that is not a state, or null when it is one.
    ///
    /// **Prose. Nothing may branch on it** — every fact in here is also in a
    /// typed key. One sentence per reading rather than a shared "could not read
    /// the container", for the reason `SidecarReading.describe` gives: which one
    /// it is decides what the operator does next.
    pub fn describe(r: Reading, arena: Allocator, container: []const u8) Allocator.Error!?[]const u8 {
        return switch (r) {
            .state => null,
            .docker_absent => try std.fmt.allocPrint(
                arena,
                "docker is not on the PATH this channel gets on the host, so nothing was asked about '{s}'. That is not the same fact as the container being absent and not the same as the daemon being down. If docker is installed but only on an interactive PATH, 'terminus doctor <server>' reports that as a login-only tool",
                .{container},
            ),
            .daemon_unreachable => try std.fmt.allocPrint(
                arena,
                "docker is installed on the host and the daemon did not answer it, so nothing is known about '{s}'. A container that is not running and a daemon that is not running look identical to anything that only asks whether the container is up; this is the second one",
                .{container},
            ),
            .permission_denied => try std.fmt.allocPrint(
                arena,
                "docker is installed and the daemon did not answer, and {s} is present and this account may not write to it — the account is not in the 'docker' group. Nothing is known about '{s}': this is a refusal, not an outage",
                .{ default_socket, container },
            ),
            .container_absent => try std.fmt.allocPrint(
                arena,
                "the daemon answered and has no container named '{s}'. This is the daemon's own answer, not a timeout and not a permission refusal",
                .{container},
            ),
            .unparseable => |cause| try std.fmt.allocPrint(
                arena,
                "the daemon answered about '{s}' and what it returned is not a document this build can read ({s}); it was not read as a state. The probe asks docker for the container's .State through a JSON format template, which prints one line of JSON and nothing else",
                .{ container, cause },
            ),
            .unknown_probe_status => |came_back| try std.fmt.allocPrint(
                arena,
                "the state probe came back with exit status {d}, which it does not produce — it produces 0, 40, 41, 42 and 43 and nothing else. So the probe did not run as written, and nothing it printed may be read as a fact about docker or about '{s}'",
                .{ came_back, container },
            ),
        };
    }
};

/// One probe, with whatever the host wrote to stderr alongside the reading.
pub const Probe = struct {
    reading: Reading,
    /// docker's own message, trimmed and bounded. **Prose from a third-party
    /// tool: reported so an operator has it, never branched on.** Null when the
    /// host wrote nothing.
    remote_message: ?[]const u8,
};

/// The most of the host's stderr that is carried into a report.
pub const max_remote_message: usize = 512;

// --- The command -------------------------------------------------------------

/// The socket the permission test looks at.
///
/// The default, and only the default. See `probe_script`.
pub const default_socket = "/var/run/docker.sock";

/// The argv for one container's state.
///
/// **An argv, not a command string, and that is the whole point of this file's
/// existence as an adapter.** Two of these elements contain characters a shell
/// eats: `{{json .State}}` holds a space and four braces, and the container name
/// is the operator's. `Core.shell.render` turns the list into a command line in
/// which each element is exactly one word, and `Core.shell.words` is the inverse
/// the gates prove it with.
///
/// `docker container inspect` and not `docker inspect`: the short form resolves
/// images as well as containers, so a name that happens to match an image would
/// come back with no `.State` and be reported as a missing container. The `--`
/// terminates the flags so a container named `-f` is a name.
pub fn inspectArgv(arena: Allocator, container: []const u8) Allocator.Error![]const []const u8 {
    const argv = try arena.alloc([]const u8, 7);
    argv[0] = "docker";
    argv[1] = "container";
    argv[2] = "inspect";
    argv[3] = "--format";
    argv[4] = "{{json .State}}";
    argv[5] = "--";
    argv[6] = container;
    return argv;
}

/// How many elements `inspectArgv` has. Pinned so a gate that reads the rendered
/// line is checking a list whose length it knows, rather than whatever is there.
pub const inspect_argv_len: usize = 7;

/// Whether the daemon answers at all, which is what tells a missing container
/// apart from a dead daemon.
fn versionArgv(arena: Allocator) Allocator.Error![]const []const u8 {
    const argv = try arena.alloc([]const u8, 4);
    argv[0] = "docker";
    argv[1] = "version";
    argv[2] = "--format";
    argv[3] = "{{.Server.Version}}";
    return argv;
}

/// `inspectArgv` as one command line, every element exactly one shell word.
pub fn inspectLine(arena: Allocator, container: []const u8) Allocator.Error![]const u8 {
    return Core.shell.render(arena, try inspectArgv(arena, container));
}

/// The exit statuses the probe script produces, and nothing else is one of them.
pub const status = struct {
    pub const state: i32 = 0;
    pub const docker_absent: i32 = 40;
    pub const daemon_unreachable: i32 = 41;
    pub const container_absent: i32 = 42;
    pub const permission_denied: i32 = 43;
};

/// One round trip that tells five absences apart.
///
/// The shape is `transfer.probe_script`'s: a small POSIX program whose *exit
/// status* is the finding, so nothing downstream has to read English out of a
/// third-party tool's stderr. Line by line:
///
///  1. no docker on the PATH → 40. Asked first, because every later line's
///     failure would otherwise mean this one.
///  2. the state read. On success its one line of JSON is on stdout and the
///     script is over.
///  3. the read failed, so ask whether the daemon is answering *at all*. If it
///     is, the daemon has told us there is no such container → 42. This is the
///     line that stops "no such container" and "no such daemon" being one fact.
///  4. the daemon is not answering. If `DOCKER_HOST` is unset (so the CLI is
///     using the default socket) and that socket is there and this account may
///     not write to it, the daemon is running and refusing us → 43.
///  5. otherwise the daemon did not answer → 41.
///
/// **What line 4 rests on, exactly.** That a non-root account outside the
/// `docker` group cannot write `/var/run/docker.sock`, which is how every
/// distribution's docker package ships it (`srw-rw---- root:docker`). It is
/// guarded by `-z "$DOCKER_HOST"` so a host pointed at a TCP endpoint or a
/// rootless socket never reaches it; those report 41, which is true — the daemon
/// did not answer — and merely less specific. **A permission refusal over
/// `DOCKER_HOST=tcp://…` therefore reads as `daemon_unreachable`, and that is a
/// stated boundary, not a bug in the parse.** Rootless docker's socket lives
/// under `$XDG_RUNTIME_DIR` and is owned by the account, so it is writable and
/// reports 41 as well.
///
/// **How we would notice if docker changed under us.** The two things relied on
/// are that `docker container inspect` exits non-zero for an unknown container
/// and that `--format '{{json .State}}'` prints one line of JSON. If the second
/// ever stopped being true the reading becomes `unparseable`, which is a
/// refusal that names itself — never a state with fabricated fields.
const probe_script =
    \\command -v docker >/dev/null 2>&1 || exit 40
    \\{[inspect]s} && exit 0
    \\{[version]s} >/dev/null && exit 42
    \\[ -z "$DOCKER_HOST" ] && [ -S {[socket]s} ] && [ ! -w {[socket]s} ] && exit 43
    \\exit 41
;

/// The whole probe, for one container.
pub fn probeScript(arena: Allocator, container: []const u8) Allocator.Error![]const u8 {
    return std.fmt.allocPrint(arena, probe_script, .{
        .inspect = try inspectLine(arena, container),
        .version = try Core.shell.render(arena, try versionArgv(arena)),
        .socket = default_socket,
    });
}

// --- Reading it back ---------------------------------------------------------

/// The fields of `.State` this build reads.
///
/// `Status` has no default, so a document without it is `error.MissingField` and
/// becomes `unparseable` — never a container whose status defaults to something.
/// Everything else is `?` because docker genuinely may omit it, and null here
/// travels to the caller as null rather than as a zero.
const StateDoc = struct {
    Status: []const u8,
    ExitCode: ?i64 = null,
    StartedAt: ?[]const u8 = null,
    FinishedAt: ?[]const u8 = null,
    Health: ?HealthDoc = null,

    const HealthDoc = struct {
        /// Same rule: a `Health` object with no `Status` is a document we cannot
        /// read, not a container of unknown health.
        Status: []const u8,
    };
};

fn lifecycleOf(word: []const u8) Lifecycle {
    for (docker_status_words) |known| {
        if (std.mem.eql(u8, word, known)) return std.meta.stringToEnum(Lifecycle, known).?;
    }
    return .unrecognised;
}

fn healthOf(reported: ?[]const u8) Health {
    const word = reported orelse return .none;
    for (docker_health_words) |known| {
        if (std.mem.eql(u8, word, known)) return std.meta.stringToEnum(Health, known).?;
    }
    return .unrecognised;
}

/// The last non-empty line of `text`, or null when there is none.
///
/// **The last, and stated rather than inferred.** The probe's own final act on
/// the success path is the `docker container inspect`, and `--format '{{json
/// .State}}'` prints exactly one line. So the last line is the answer, and
/// taking it makes the reading immune to anything the account's login profile
/// echoed to stdout ahead of it. A parser that read from the *first* line — the
/// shape `transfer.probeRemoteFile` can afford, because its own script's first
/// line is its answer — would report a host's MOTD as an unparseable state.
fn lastLine(text: []const u8) ?[]const u8 {
    var rest = std.mem.trim(u8, text, " \t\r\n");
    if (rest.len == 0) return null;
    if (std.mem.lastIndexOfScalar(u8, rest, '\n')) |nl| rest = rest[nl + 1 ..];
    const line = std.mem.trim(u8, rest, " \t\r");
    return if (line.len == 0) null else line;
}

/// A stdout that should hold one line of `.State` JSON, read.
///
/// Public so a gate can drive every shape of it without a transport.
pub fn readState(arena: Allocator, stdout: []const u8) Allocator.Error!Reading {
    const line = lastLine(stdout) orelse return .{ .unparseable = "EmptyOutput" };
    const doc = std.json.parseFromSliceLeaky(StateDoc, arena, line, .{
        .ignore_unknown_fields = true,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        // Every other way the parse can end is one fact: the daemon answered and
        // this is not a document we can read. The parser's own word for it goes
        // into the sentence, and no field of a half-read document is kept.
        else => return .{ .unparseable = @errorName(err) },
    };
    const health_reported: ?[]const u8 = if (doc.Health) |h| try arena.dupe(u8, h.Status) else null;
    return .{
        .state = .{
            .lifecycle = lifecycleOf(doc.Status),
            // Duped for the reason `parseJobResult` dupes: the parser may hand back
            // a slice of the input buffer, and this value is reported long after.
            .status_reported = try arena.dupe(u8, doc.Status),
            .health = healthOf(health_reported),
            .health_reported = health_reported,
            .exit_code = doc.ExitCode,
            .started_at = if (doc.StartedAt) |s| try arena.dupe(u8, s) else null,
            .finished_at = if (doc.FinishedAt) |s| try arena.dupe(u8, s) else null,
        },
    };
}

/// The exit status of the probe, read as one of the five stated absences — or
/// refused as a status the probe does not produce.
///
/// Public so a gate can hold every status against its reading without a host.
pub fn readStatus(arena: Allocator, result: Core.Ssh.ExecResult) Allocator.Error!Reading {
    return switch (result.exit_code) {
        status.state => try readState(arena, result.stdout),
        status.docker_absent => .docker_absent,
        status.daemon_unreachable => .daemon_unreachable,
        status.container_absent => .container_absent,
        status.permission_denied => .permission_denied,
        // Not mapped to the nearest neighbour. A status the script does not
        // produce means the script did not run as written — a shell that could
        // not parse it, a channel that reported somebody else's status — and any
        // of the six readings above would be a claim about docker we have no
        // grounds for.
        else => .{ .unknown_probe_status = result.exit_code },
    };
}

/// One container's state, in one round trip.
pub fn inspect(executor: Core.Executor, arena: Allocator, container: []const u8) Error!Probe {
    const result = try executor.exec(arena, try probeScript(arena, container));
    const trimmed = std.mem.trim(u8, result.stderr, " \t\r\n");
    return .{
        .reading = try readStatus(arena, result),
        .remote_message = if (trimmed.len == 0)
            null
        else
            try arena.dupe(u8, trimmed[0..@min(trimmed.len, max_remote_message)]),
    };
}

// --- Waiting -----------------------------------------------------------------

/// What a wait is waiting for.
pub const Target = enum { healthy, running };

/// The vocabulary as a refusal prints it, derived from the enum so a member the
/// parser accepts cannot be left out of the message that lists them. The shape
/// `Core.shell.kind_list` uses, for the same reason.
pub const target_list = list: {
    var out: []const u8 = "";
    for (@typeInfo(Target).@"enum".fields, 0..) |field, i| {
        out = out ++ (if (i == 0) "" else "|") ++ field.name;
    }
    break :list out;
};

/// What one reading means to a wait.
pub const Verdict = union(enum) {
    /// The target is not true yet and could still become true.
    keep_waiting,
    /// The target is true.
    reached,
    /// Waiting cannot make the target true from here; carries why.
    cannot_reach: []const u8,
    /// The reading is not about the container's state at all, so there is
    /// nothing here to wait on.
    undetermined,
};

/// The whole rule, as a pure function of a target and a reading.
///
/// **Pure, and that is what makes the deadline testable.** A wait's real
/// failure mode is a loop that says "healthy" for something that never was, and
/// the only way to hold that down is to be able to ask this question about every
/// combination of target, lifecycle and health there is — 2 x 8 x 5 of them,
/// with no clock and no host. The gate does exactly that and asserts the one
/// property that matters: `reached` comes back for no combination except the two
/// that are actually the target.
///
/// Three things it deliberately does **not** do:
///
///   * it does not call `exited` unreachable. A container with a restart policy
///     that has just exited is about to be restarted by the daemon, and this
///     module does not read the restart policy — so declaring it hopeless would
///     be a guess. The deadline is what ends that wait, and `timed_out` carrying
///     `status: "exited"` is an answer an operator can act on.
///   * it does not treat `unhealthy` as final. docker's healthcheck retries;
///     unhealthy is a value a container comes back from. It is a reason to keep
///     waiting and, if the deadline runs out, it is what `timed_out` reports.
///   * it does not guess at a word it does not know. An `unrecognised` lifecycle
///     or health means waiting cannot resolve anything, because the thing we
///     would be waiting for is a word we have refused to interpret.
pub fn verdictOf(target: Target, reading: Reading) Verdict {
    const state = switch (reading) {
        .state => |s| s,
        .docker_absent,
        .daemon_unreachable,
        .permission_denied,
        .container_absent,
        .unparseable,
        .unknown_probe_status,
        => return .undetermined,
    };
    return switch (target) {
        .running => switch (state.lifecycle) {
            .running => .reached,
            .created, .restarting, .paused, .exited => .keep_waiting,
            .removing => .{ .cannot_reach = "the container is being removed; it does not become running from there" },
            .dead => .{ .cannot_reach = "docker reports the container dead — its filesystem could not be torn down — and a dead container does not start" },
            .unrecognised => .{ .cannot_reach = "docker reports a container status this build's vocabulary does not have; nothing here can say whether it is running, and waiting cannot resolve a word we refuse to guess at. The word itself is in statusReported" },
        },
        .healthy => switch (state.health) {
            .healthy => .reached,
            .starting, .unhealthy => .keep_waiting,
            // Running with no healthcheck is the trap this arm exists for: it
            // can never become healthy, so a wait that kept polling would spend
            // its whole deadline and then report `timed_out` for a container
            // that is working. Only when it is *running*, because docker does
            // not populate `Health` before a container starts and an absence
            // there is "not yet", not "never".
            .none => if (state.lifecycle == .running)
                .{ .cannot_reach = "the container is running and its image declares no HEALTHCHECK, so it has no health status and will not acquire one. Wait for 'running' instead, or add a HEALTHCHECK to the image" }
            else
                .keep_waiting,
            .unrecognised => .{ .cannot_reach = "docker reports a health status this build's vocabulary does not have; waiting cannot resolve a word we refuse to guess at. The word itself is in healthReported" },
        },
    };
}

/// How a wait ended.
///
/// `timed_out` is its own outcome and is never `reached`. It is also not the
/// same word as an unhealthy container: `unhealthy` is a *health value* that a
/// `timed_out` outcome may be carrying, and an agent reads the two keys
/// separately. And neither is `undetermined`, which means the host never told us
/// anything about the container at all.
pub const WaitOutcome = struct {
    kind: Kind,
    /// The last probe taken, whichever way it ended. Never absent: a wait always
    /// polls at least once before it can report anything.
    probe: Probe,
    polls: usize,
    waited_secs: u64,
    /// Why waiting cannot help. Non-null exactly on `cannot_reach`.
    why: ?[]const u8,

    pub const Kind = enum { reached, timed_out, cannot_reach, undetermined };

    pub fn code(o: WaitOutcome) []const u8 {
        return @tagName(o.kind);
    }

    pub fn ok(o: WaitOutcome) bool {
        return o.kind == .reached;
    }
};

pub const WaitOptions = struct {
    container: []const u8,
    target: Target,
    /// The deadline, in seconds. Checked *after* each poll, so a zero deadline
    /// still reads the container once and reports what it found.
    timeout_secs: u64,
    /// Seconds between polls. Held inside `interval_bounds` by `intervalFlag`
    /// before it gets here — a zero would make the sleep below a no-op and turn
    /// the loop into a busy-spin over the SSH channel. The gates pass zero on
    /// purpose so they do not sleep, which is exactly why the clamp lives at the
    /// flag and not here.
    interval_secs: u64,
};

/// Polls `inspect` until the target holds, cannot hold, or the deadline expires.
///
/// The deadline is measured on the monotonic clock and checked after the poll,
/// which is what makes `--timeout 0` mean "read it once and tell me", rather
/// than "tell me nothing".
pub fn waitFor(
    executor: Core.Executor,
    arena: Allocator,
    io: std.Io,
    opts: WaitOptions,
) Error!WaitOutcome {
    const started = std.Io.Timestamp.now(io, .awake);
    var polls: usize = 0;
    while (true) {
        const probe = try inspect(executor, arena, opts.container);
        polls += 1;
        const waited = elapsedSecs(started, io);
        switch (verdictOf(opts.target, probe.reading)) {
            .reached => return finish(.reached, probe, polls, waited, null),
            .cannot_reach => |why| return finish(.cannot_reach, probe, polls, waited, why),
            .undetermined => return finish(.undetermined, probe, polls, waited, null),
            .keep_waiting => {},
        }
        // The deadline, and the only thing that ends a `keep_waiting`. Checked
        // here rather than at the top of the loop so the poll above has already
        // happened: a wait must never report a deadline it did not first look
        // past.
        if (waited >= opts.timeout_secs)
            return finish(.timed_out, probe, polls, waited, null);
        // A sleep that fails costs a round trip and nothing else — the deadline
        // above still bounds the loop and the answer is unaffected — so it is
        // not made fatal. Same disposition as the watch loop in `cmd_job`.
        std.Io.sleep(io, .{ .nanoseconds = @intCast(opts.interval_secs * std.time.ns_per_s) }, .awake) catch {};
    }
}

fn finish(kind: WaitOutcome.Kind, probe: Probe, polls: usize, waited: u64, why: ?[]const u8) WaitOutcome {
    return .{ .kind = kind, .probe = probe, .polls = polls, .waited_secs = waited, .why = why };
}

fn elapsedSecs(started: std.Io.Timestamp, io: std.Io) u64 {
    const ns = started.durationTo(std.Io.Timestamp.now(io, .awake)).nanoseconds;
    if (ns <= 0) return 0;
    return @intCast(@divTrunc(ns, std.time.ns_per_s));
}

// --- The documents -----------------------------------------------------------

/// The keys that describe a state, shared by both verbs' documents.
///
/// A struct so the two emitters cannot fill them differently, and so the gate at
/// the bottom of this file can hold both key sets against this one rather than
/// against a transcription of it.
pub const StateKeys = struct {
    status: ?[]const u8,
    statusReported: ?[]const u8,
    health: ?[]const u8,
    healthReported: ?[]const u8,
    exitCode: ?i64,
    startedAt: ?[]const u8,
    finishedAt: ?[]const u8,
};

/// Every state key, or every one of them null. Never a mixture: a reading that
/// is not a state has no status to report, and a null status beside a populated
/// `health` would be a document describing a container we never read.
pub fn stateKeys(reading: Reading) StateKeys {
    const s = switch (reading) {
        .state => |value| value,
        .docker_absent,
        .daemon_unreachable,
        .permission_denied,
        .container_absent,
        .unparseable,
        .unknown_probe_status,
        => return .{
            .status = null,
            .statusReported = null,
            .health = null,
            .healthReported = null,
            .exitCode = null,
            .startedAt = null,
            .finishedAt = null,
        },
    };
    return .{
        .status = @tagName(s.lifecycle),
        .statusReported = s.status_reported,
        .health = @tagName(s.health),
        .healthReported = s.health_reported,
        .exitCode = s.exit_code,
        .startedAt = s.started_at,
        .finishedAt = s.finished_at,
    };
}

/// `docker inspect`'s document. No defaults, so a branch that omits a key does
/// not compile — the rule `ReceiptFatalJson` states in `cli.zig`.
///
/// Every key an agent branches on is a bool, a number, a null, or a word from a
/// closed vocabulary derived from an enum (`reading`, `status`, `health`).
/// `detail` and `dockerSaid` are the two prose keys and neither carries a fact
/// that is not also in a typed key above it.
pub const InspectJson = struct {
    ok: bool,
    server: []const u8,
    container: []const u8,
    reading: []const u8,
    status: ?[]const u8,
    statusReported: ?[]const u8,
    health: ?[]const u8,
    healthReported: ?[]const u8,
    exitCode: ?i64,
    startedAt: ?[]const u8,
    finishedAt: ?[]const u8,
    detail: ?[]const u8,
    dockerSaid: ?[]const u8,
    transport: []const u8,
    daemonError: ?[]const u8,
};

/// `docker wait`'s document. Same rule, same two prose keys.
pub const WaitJson = struct {
    ok: bool,
    server: []const u8,
    container: []const u8,
    target: []const u8,
    outcome: []const u8,
    polls: usize,
    waitedSeconds: u64,
    timeoutSeconds: u64,
    reading: []const u8,
    status: ?[]const u8,
    statusReported: ?[]const u8,
    health: ?[]const u8,
    healthReported: ?[]const u8,
    exitCode: ?i64,
    startedAt: ?[]const u8,
    finishedAt: ?[]const u8,
    detail: ?[]const u8,
    dockerSaid: ?[]const u8,
    transport: []const u8,
    daemonError: ?[]const u8,
};

/// The `inspect` document, built where a gate can read it.
pub fn inspectJson(
    arena: Allocator,
    server: []const u8,
    container: []const u8,
    probe: Probe,
    transport: []const u8,
    daemon_error: ?[]const u8,
) Allocator.Error!InspectJson {
    const keys = stateKeys(probe.reading);
    return .{
        .ok = probe.reading.isState(),
        .server = server,
        .container = container,
        .reading = probe.reading.code(),
        .status = keys.status,
        .statusReported = keys.statusReported,
        .health = keys.health,
        .healthReported = keys.healthReported,
        .exitCode = keys.exitCode,
        .startedAt = keys.startedAt,
        .finishedAt = keys.finishedAt,
        .detail = try probe.reading.describe(arena, container),
        .dockerSaid = probe.remote_message,
        .transport = transport,
        .daemonError = daemon_error,
    };
}

/// The `wait` document, built where a gate can read it.
///
/// `detail` is the outcome's own sentence when there is one — the `why` of a
/// `cannot_reach`, or the reading's sentence for an `undetermined` — and the
/// timeout's own, which says in words what `outcome` says in a code.
pub fn waitJson(
    arena: Allocator,
    server: []const u8,
    container: []const u8,
    outcome: WaitOutcome,
    timeout_secs: u64,
    target: Target,
    transport: []const u8,
    daemon_error: ?[]const u8,
) Allocator.Error!WaitJson {
    const keys = stateKeys(outcome.probe.reading);
    const detail: ?[]const u8 = if (outcome.why) |why|
        why
    else if (outcome.kind == .timed_out)
        try std.fmt.allocPrint(
            arena,
            "the deadline of {d}s expired after {d} poll(s) with the container still not {s}. This is not a failure of the container and it is not a report that it is unhealthy — it is the statement that we stopped looking. Its last reading is in the keys above",
            .{ timeout_secs, outcome.polls, @tagName(target) },
        )
    else
        try outcome.probe.reading.describe(arena, container);
    return .{
        .ok = outcome.ok(),
        .server = server,
        .container = container,
        .target = @tagName(target),
        .outcome = outcome.code(),
        .polls = outcome.polls,
        .waitedSeconds = outcome.waited_secs,
        .timeoutSeconds = timeout_secs,
        .reading = outcome.probe.reading.code(),
        .status = keys.status,
        .statusReported = keys.statusReported,
        .health = keys.health,
        .healthReported = keys.healthReported,
        .exitCode = keys.exitCode,
        .startedAt = keys.startedAt,
        .finishedAt = keys.finishedAt,
        .detail = detail,
        .dockerSaid = outcome.probe.remote_message,
        .transport = transport,
        .daemonError = daemon_error,
    };
}

// --- The verb ----------------------------------------------------------------

pub fn run(ctx: *Cli.Ctx, raw_args: []const []const u8) !void {
    if (raw_args.len == 0) fatal("{s}", .{usage});
    const verb = raw_args[0];
    const parsed = Cli.parseArgs(ctx, raw_args[1..]);
    if (parsed.boolean("json")) ctx.out.format = .json;

    const waiting = std.mem.eql(u8, verb, "wait");
    if (!waiting and !std.mem.eql(u8, verb, "inspect"))
        fatal("unknown verb 'docker {s}'\n{s}", .{ verb, usage });

    const server_name = parsed.positional(0) orelse fatal("{s}", .{usage});
    const container = parsed.positional(1) orelse fatal("{s}", .{usage});
    if (container.len == 0) fatal(
        "the container name is empty; nothing was sent. 'docker {s} <server> <container>' needs a name or an id",
        .{verb},
    );

    // Every refusal below this point but before the connection is one that costs
    // nothing: the flags are read first, so a bad `--for` is answered without a
    // dial. The rule `Cli.shapeInvocation` states for the command flags.
    const target: Target = if (parsed.flag("for")) |value|
        std.meta.stringToEnum(Target, value) orelse fatal(
            "--for {s} is not a value terminus has; nothing was sent. Accepted: {s}",
            .{ value, target_list },
        )
    else
        .healthy;
    const timeout_secs = secondsFlag(&parsed, "timeout", 60);
    const interval_secs = intervalFlag(&parsed, 2);

    var store = try Cli.openStore(ctx, &parsed);
    defer store.close();
    const resolved = Cli.resolveServer(ctx, &store, server_name);

    var conn = Cli.connect(ctx, &parsed, resolved.server, resolved.auth);
    defer conn.deinit();
    const executor = conn.executor();

    if (waiting) {
        const outcome = waitFor(executor, ctx.arena, ctx.io, .{
            .container = container,
            .target = target,
            .timeout_secs = timeout_secs,
            .interval_secs = interval_secs,
        }) catch |err| fatal("could not read the state of container '{s}': {s} ({s})", .{
            container, executor.errorMessage(), @errorName(err),
        });
        const document = try waitJson(
            ctx.arena,
            resolved.server.name,
            container,
            outcome,
            timeout_secs,
            target,
            conn.transport,
            conn.daemon_error,
        );
        switch (ctx.out.format) {
            .json => try ctx.out.json(document),
            .human => try printWait(ctx, document),
        }
        if (!document.ok) {
            try ctx.out.flush();
            Cli.exitNow(Cli.exit_code.failure);
        }
        return;
    }

    const probe = inspect(executor, ctx.arena, container) catch |err|
        fatal("could not read the state of container '{s}': {s} ({s})", .{
            container, executor.errorMessage(), @errorName(err),
        });
    const document = try inspectJson(
        ctx.arena,
        resolved.server.name,
        container,
        probe,
        conn.transport,
        conn.daemon_error,
    );
    switch (ctx.out.format) {
        .json => try ctx.out.json(document),
        .human => try printInspect(ctx, document),
    }
    if (!document.ok) {
        try ctx.out.flush();
        Cli.exitNow(Cli.exit_code.failure);
    }
}

/// The bounds a `--interval` is held to, and why a watch has both.
///
/// **The floor.** `waitFor` sleeps `interval_secs` seconds between polls, and a
/// sleep of zero is not a sleep — so `--interval 0` issued `docker container
/// inspect` over the SSH channel as fast as the channel could carry it, for the
/// whole of `--timeout`. `secondsFlag` had no floor and no ceiling, and the
/// gates cannot see it because they pass `.interval_secs = 0` deliberately so
/// the tests do not sleep.
///
/// **The ceiling.** An interval above the deadline is a watch that polls once
/// and reports a timeout it never looked past, which reads as a container that
/// did not come up.
///
/// The same bounds, and the same reason, as `cmd_job.parseInterval`: "so a watch
/// can never busy-spin or hang forever". Clamped at the flag rather than inside
/// `waitFor`, because `waitFor` is what the gates drive and a clamp there would
/// make every one of them sleep.
pub const interval_bounds = struct {
    pub const min: u64 = 1;
    pub const max: u64 = 60 * 60;
};

fn secondsFlag(parsed: *const Cli.Args.Parsed, comptime name: []const u8, default: u64) u64 {
    const text = parsed.flag(name) orelse return default;
    return std.fmt.parseInt(u64, text, 10) catch
        fatal("invalid --" ++ name ++ " '{s}'; it takes a whole number of seconds", .{text});
}

/// `--interval <sec>`, held inside `interval_bounds`.
///
/// A deadline of zero stays zero — `--timeout 0` means "read it once and tell
/// me", which is a documented reading and not a spin — so only the interval is
/// clamped, and it is clamped rather than refused: an operator asking for a
/// tighter poll than the channel can serve wants the tightest one available,
/// not an error.
pub fn intervalFlag(parsed: *const Cli.Args.Parsed, default: u64) u64 {
    return std.math.clamp(
        secondsFlag(parsed, "interval", default),
        interval_bounds.min,
        interval_bounds.max,
    );
}

fn printInspect(ctx: *Cli.Ctx, d: InspectJson) !void {
    try ctx.out.print("container: {s} on {s}\n", .{ d.container, d.server });
    try ctx.out.print("reading:   {s}\n", .{d.reading});
    if (d.status) |value| try ctx.out.print("status:    {s} (docker said: {s})\n", .{
        value, d.statusReported orelse "-",
    });
    if (d.health) |value| try ctx.out.print("health:    {s} (docker said: {s})\n", .{
        value, d.healthReported orelse "-",
    });
    if (d.exitCode) |code| try ctx.out.print("exit code: {d}\n", .{code});
    if (d.startedAt) |at| try ctx.out.print("started:   {s}\n", .{at});
    if (d.detail) |sentence| try ctx.out.print("{s}\n", .{sentence});
    if (d.dockerSaid) |said| try ctx.out.print("docker:    {s}\n", .{said});
}

fn printWait(ctx: *Cli.Ctx, d: WaitJson) !void {
    try ctx.out.print("container: {s} on {s}\n", .{ d.container, d.server });
    try ctx.out.print("waited for: {s}\n", .{d.target});
    try ctx.out.print("outcome:   {s} after {d} poll(s) and {d}s (deadline {d}s)\n", .{
        d.outcome, d.polls, d.waitedSeconds, d.timeoutSeconds,
    });
    try ctx.out.print("reading:   {s}\n", .{d.reading});
    if (d.status) |value| try ctx.out.print("status:    {s} (docker said: {s})\n", .{
        value, d.statusReported orelse "-",
    });
    if (d.health) |value| try ctx.out.print("health:    {s} (docker said: {s})\n", .{
        value, d.healthReported orelse "-",
    });
    if (d.detail) |sentence| try ctx.out.print("{s}\n", .{sentence});
    if (d.dockerSaid) |said| try ctx.out.print("docker:    {s}\n", .{said});
}

test {
    _ = @import("cmd_docker_test.zig");
}
