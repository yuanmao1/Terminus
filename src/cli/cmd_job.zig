//! `terminus run` / `terminus job` — tracked long-running remote tasks.
//!
//! A job runs inside a dedicated remote tmux session named `job-<name>`. When
//! the command returns, its shell records the exit status twice: into
//! `~/.terminus/results/<request-id>.json`, and as a sentinel line in the
//! output log. Either one makes the outcome recoverable later by any process,
//! but only the first stays findable once the job's own output has scrolled
//! the sentinel out of reach — see `Tmux.jobLaunchLine`.
//!
//! Jobs run under the execution boundary, with one twist: the launching
//! command exits while the work continues. `run` therefore *detaches* rather
//! than settling — deliberately leaving the attempt in flight, which keeps it
//! blocking its scope because something really is still running there.
//! Whoever next observes the job settles it.
//!
//! What this file no longer does is guess. A job session that has vanished
//! without recording an exit status used to be recorded as `killed`; but a
//! pane can disappear because the command finished and the shell exited,
//! because somebody killed it, or because the host rebooted mid-write. Those
//! are not the same outcome, and none of them is evidence for the others.
const std = @import("std");
const fatal = Cli.fail;
const Cli = @import("cli.zig");
const Core = @import("../core/core.zig");
const Store = Core.Store;
const Tmux = Core.Tmux;
const fatalTmux = @import("cmd_exec.zig").fatalTmux;

const run_usage =
    \\usage: terminus run <server> --name <job-name> [--cwd <dir>] [--login]
    \\                    [--strict] [--interpreter <bin>] [--json] <command input>
    \\
    \\command input: --stdin | --cmd-file <path> | --cmd "<command>" | -- <command...>
    \\Multiline input runs as a staged remote script. --strict = set -euo pipefail.
    \\--login wraps in `bash -ilc` for the full user PATH (nvm/pm2/etc).
    \\
;
const job_usage =
    \\usage: terminus job <verb> <server> [<name>] [...]
    \\
    \\  job ls      <server> [--active] [--name <substr>] [--limit N] [--json]
    \\  job status  <server> <name> [--json]     probe: running? exit code? businessResult?
    \\  job read    <server> <name> [--from-cursor] [--limit BYTES] [--json]
    \\  job watch   <server> <name> [--interval 15s] [--max N] [--json]
    \\  job kill    <server> <name> [--force]     settle it from its recorded
    \\                                           outcome if it already ended,
    \\                                           else terminate and verify
    \\  job rm      <server> <name> [--force]     forget the job (kills if running)
    \\  job inspect <server> <name> [--json]     what was launched, byte for byte
    \\
    \\'kill' and 'rm' hold a lease on the job for as long as they are working on
    \\it, so a second session is refused rather than racing them. --force takes
    \\that lease over: the displaced claim is recorded, never skipped.
    \\
    \\A job can print '__TERMINUS_RESULT__:<value>' to report business state
    \\separately from its process exit code.
    \\
    \\Exit codes: the job's own code, or 75 when its outcome is unknown.
    \\
;

/// Job sessions are namespaced away from user sessions: session `work`
/// and job `work` never collide.
fn jobSessionName(arena: std.mem.Allocator, name: []const u8) ![]u8 {
    return std.fmt.allocPrint(arena, "job-{s}", .{name});
}

fn jobScope(name: []const u8) Core.execution.Scope {
    return .{ .kind = .job, .key = name };
}

/// Whether a still-live job row may be quietly taken over by a new launch.
///
/// A `pending` row is a reservation, and a launcher killed between taking one
/// and reaching the remote shell leaves one behind. Refusing forever would
/// make every crashed launch a manual cleanup; deleting it on age would
/// eventually delete the row of a launcher that is merely slow. Neither is
/// needed, because the owning attempt already records how far it got.
///
/// So the test is the scope guard's own predicate, asked of the owner: if that
/// operation no longer blocks a scope, it either provably never submitted or
/// its outcome is established. Everything else stays put — including a
/// `running` row, a row from 0.1.x with no owner at all, and one whose
/// operation has vanished. Those need `job rm`, which looks at the host before
/// it agrees.
///
/// **What this does not establish, stated because it was previously claimed.**
/// The doc used to end "…and nothing is running under this name". That does not
/// follow. `blocksScope` is false for `created` and `connecting`, and
/// `connecting` is where a *healthy* launcher sits for its entire setup —
/// `execution.connecting()` runs before `jobs.create`, and `submitted()` is not
/// reached until after `killSession`, `ensure` and a possible script upload.
/// `blocksScope` answers "can this attempt still be affecting the remote", a
/// question about remote effects; whether a local process is still going to use
/// this row is a different question, and nothing in the ledger separates
/// "killed while dialling" from "dialling right now".
///
/// The consequence is bounded rather than absent, and bounded in two places.
/// `Cli.releaseReservation` clears the row on every ordinary failure path, so
/// reaching this predicate at all takes a hard kill; and `runCmd` re-asserts the
/// claim immediately before it sends any keys, so a launcher that lost its name
/// mid-setup refuses with nothing sent instead of handing work to a shell it can
/// no longer name. What remains is a plain `run` taking a mid-setup launcher's
/// name — narrow, reported, and not something this predicate can decide on its
/// own. Separating the two cases needs the launcher's own liveness recorded on
/// the row, which is a schema question.
fn reclaimable(store: *Store, arena: std.mem.Allocator, row: Store.jobs.Job) bool {
    if (row.status != .pending) return false;
    const owner = row.owner_request_id orelse return false;
    const op = (Store.operations.get(store, arena, owner) catch |err|
        Cli.storeFatal(store, err)) orelse return false;
    return !op.effectiveStatus().blocksScope();
}

pub fn runCmd(ctx: *Cli.Ctx, raw_args: []const []const u8) !void {
    const parsed = Cli.parseArgs(ctx, raw_args);
    if (parsed.boolean("json")) ctx.out.format = .json;

    const server_name = parsed.positional(0) orelse fatal("{s}", .{run_usage});
    const job_name = parsed.flag("name") orelse fatal("--name is required\n{s}", .{run_usage});
    validateJobName(job_name);
    const raw_command = (try Cli.trailingContent(ctx, &parsed, "cmd-file", 1)) orelse
        fatal("no command given\n{s}", .{run_usage});

    var store = try Cli.openStore(ctx, &parsed);
    defer store.close();
    const resolved = Cli.resolveServer(ctx, &store, server_name);
    const owner_token = Store.policy.ownerToken(&store, ctx.arena, ctx.io, ctx.now) catch |err|
        Cli.storeFatal(&store, err);

    // Launching a job is a mutation, so an unsettled peer on the same scope
    // or a foreign lease refuses it. That is the whole point: starting a
    // second `deploy` while the first one's fate is unknown is how work gets
    // applied twice.
    //
    // Held in a named value because a blocked launch asks a second time,
    // after trying to settle the blocker from evidence on the host.
    const begin_opts: Core.execution.BeginOptions = .{
        .server_id = resolved.server.id,
        .server_name = resolved.server.name,
        .kind = .job,
        .scope = jobScope(job_name),
        .alias = job_name,
        .mutating = true,
        .argv_redacted = Store.history.redactSecrets(ctx.arena, raw_command) catch
            // Falling back to the raw text would write the very secrets the
            // redaction exists to keep out of an append-only ledger.
            fatal("cannot redact the command for the audit record; refusing to store it unredacted", .{}),
        .argv_sha256 = try sha256Hex(ctx.arena, raw_command),
        .cwd = parsed.flag("cwd") orelse resolved.server.cwd,
        .shell = if (parsed.boolean("login")) "bash-login" else "bash",
        .owner_token = owner_token,
        .force = parsed.boolean("force"),
        .now = ctx.now,
    };
    const start = Core.execution.begin(&store, ctx.arena, ctx.io, begin_opts) catch |err|
        Cli.storeFatal(&store, err);

    // One connection for the whole command, opened wherever it is first
    // needed. The blocked path needs it before the execution exists, the
    // normal path after — and opening a second one would mean two SSH
    // handshakes for one launch.
    var conn_slot: ?Cli.Connection = null;
    defer if (conn_slot) |*c| c.deinit();

    var execution = switch (start) {
        .ready => |e| e,
        // A blocker that might already have finished is worth one connection
        // before we refuse. `begin` inserts nothing on this path, so settling
        // the blocker and asking again costs a round trip and leaks nothing —
        // and the second answer is the one that decides. Anything unprovable
        // (a lease, a non-job) still refuses without dialling at all, and an
        // unreachable host falls back to the refusal rather than reporting a
        // connection error in its place.
        .blocked => |blocker| retry: {
            if (!Cli.blockerMayBeProvable(blocker)) return reportBlocked(blocker);
            conn_slot = Cli.tryConnect(ctx, &parsed, resolved.server, resolved.auth) orelse
                return reportBlocked(blocker);
            Cli.settleProvableBlocker(ctx, &store, conn_slot.?.executor(), blocker);
            const second = Core.execution.begin(&store, ctx.arena, ctx.io, begin_opts) catch |err|
                Cli.storeFatal(&store, err);
            break :retry switch (second) {
                .ready => |e| e,
                .blocked => |still| return reportBlocked(still),
            };
        },
    };
    Cli.registerExecution(&execution);
    defer {
        Cli.clearExecution();
        // Covers the paths `fail`'s hook cannot: a plain error return unwinds
        // through here, and `store` dies with this frame.
        Cli.releaseReservation();
        execution.deinit();
    }

    // A name held by a live job is not something `--force` may take.
    //
    // `--force` means one thing: "I accept the risk of acting while an
    // overlapping operation's outcome is unknown." Letting it also mean "and
    // tear the name away from a launcher that is mid-setup, or from a job
    // that is running right now" is a different and much sharper decision,
    // and merging the two put it behind a flag people reach for casually.
    // Stopping a live job is `job kill` or `job rm`, both of which say what
    // they are doing and leave a record.
    if (Store.jobs.getByName(&store, ctx.arena, resolved.server.id, job_name) catch |err|
        Cli.storeFatal(&store, err)) |existing|
    {
        if (existing.status.live() and !reclaimable(&store, ctx.arena, existing)) fatal(
            "job '{s}' is {t} (since {d}); nothing was sent. Stop it first ('terminus job kill {s} {s}' or 'job rm'), or pick another --name — --force does not take a live job's name",
            .{ job_name, existing.status, existing.created_at, server_name, job_name },
        );
        // The displacement is a compare-and-swap against the row just read,
        // and on grounds that say what this caller is entitled to destroy: a
        // relaunch may take a settled row or a reclaimable reservation, never
        // a `running` one. The check above decides which of those it is; this
        // is what makes the decision binding, because between the two a peer
        // can promote the reservation to `running` and the check has already
        // happened. A refusal here means the name is no longer the caller's to
        // take, and nothing has been sent.
        switch (Store.jobs.remove(&store, existing.removeExpectation(), .superseded_by_relaunch) catch |err|
            Cli.storeFatal(&store, err)) {
            .applied => {},
            .refused => |conflict| fatal(
                "job '{s}' could not be replaced: {s}. Nothing was sent",
                .{ job_name, conflictText(ctx.arena, job_name, conflict) },
            ),
        }
    }

    execution.connecting() catch |err| Cli.receiptFatal(execution.id(), err, "created");
    if (conn_slot == null) conn_slot = Cli.connect(ctx, &parsed, resolved.server, resolved.auth);
    var conn = &conn_slot.?;
    const executor = conn.executor();

    // The guard waved this launch through while something else still holds an
    // overlapping scope (`--force`). If that something is a job which already
    // finished, read its exit status before anything is torn down —
    // opportunistic and one-way, and `submitted()` below re-runs the
    // authoritative guard either way. It has to happen here, ahead of the
    // session teardown, because the blocker on a same-name rerun is the
    // previous attempt in this very session.
    //
    // The blocked path above has already done this for its own blocker; this
    // call covers the launches `begin` let through while still reporting one
    // (`--force`), where `advisory` is the only place the blocker appears.
    Cli.settleProvableBlocker(ctx, &store, executor, execution.advisory);

    const session = try jobSessionName(ctx.arena, job_name);
    const nonce: u64 = @intCast(@mod(std.Io.Timestamp.now(ctx.io, .real).nanoseconds, 1_000_000_007));
    const sentinel = try std.fmt.allocPrint(ctx.arena, "__TERMINUS_JOB_{d}__", .{nonce});

    // Claim the name before touching the remote host, and keep the claim for
    // the whole setup.
    //
    // The check above is a courtesy: it produces a good message, but two
    // launches racing on one name can both pass it. This insert cannot — the
    // `UNIQUE(server_id, name)` index picks exactly one winner, and the loser
    // is still holding an untouched remote when it finds out. That ordering is
    // the point. The next thing this function does is kill the job's tmux
    // session, and a loser that got that far would be killing the session the
    // winner had just filled with real work.
    //
    // The row also has to exist before `sendKeys` for a second reason: if the
    // database failed afterwards, the command would be running on the server
    // with nothing locally able to find it — `status`, `kill` and `reconcile`
    // all key off this row and the attempt.
    _ = Store.jobs.create(&store, resolved.server.id, job_name, raw_command, sentinel, execution.id(), ctx.now) catch |err| switch (err) {
        error.NameTaken => fatal("job '{s}' was claimed by another launch just now; nothing was sent", .{job_name}),
        else => Cli.storeFatal(&store, err),
    };
    // `fail` exits without running defers, so the release is a hook rather
    // than a `defer`. It is keyed on this launch's request id: if someone
    // takes the name over while we are still setting up, the row stops being
    // ours and we must not delete theirs on the way out.
    Cli.registerReservation(&store, execution.id(), job_name);

    // A leftover session from a forgotten job must be *confirmed* gone before
    // we reuse the name. `ensure` treats an existing session as ready, so a
    // kill that quietly failed would type this command into the previous
    // job's shell — with its cwd, its environment and its half-finished work.
    const cleared = Tmux.killSession(executor, ctx.arena, session) catch |err|
        fatalTmux(err, executor, session);
    if (!cleared) fatal(
        "a tmux session for job '{s}' still exists and could not be killed; refusing to reuse it (inspect it with 'tmux attach -t {s}' on the host)",
        .{ job_name, try Tmux.targetName(ctx.arena, session) },
    );
    Tmux.ensure(executor, ctx.arena, session) catch |err| fatalTmux(err, executor, session);

    var command = raw_command;
    var staged_path: ?[]const u8 = null;
    if (Core.script.shouldStage(raw_command) or parsed.flag("interpreter") != null) {
        const staged = Core.script.stage(executor, ctx.arena, raw_command, .{
            .interpreter = parsed.flag("interpreter") orelse "bash",
            .strict = parsed.boolean("strict"),
            .login = parsed.boolean("login"),
        }, nonce) catch |err| switch (err) {
            error.ScriptTooLarge => fatal("script exceeds {d} KiB; push it as a file and run that instead", .{Core.script.max_inline_script / 1024}),
            error.StagingFailed => fatal("could not stage the script on the remote host", .{}),
            else => fatal("staging failed: {s} ({s})", .{ executor.errorMessage(), @errorName(err) }),
        };
        command = staged.command;
        staged_path = staged.remote_path;
    } else if (parsed.boolean("strict")) {
        command = try std.fmt.allocPrint(ctx.arena, "set -euo pipefail; {s}", .{raw_command});
        if (parsed.boolean("login")) command = try Cli.loginWrap(ctx.arena, command);
    } else if (parsed.boolean("login")) {
        command = try Cli.loginWrap(ctx.arena, command);
    }

    const cwd = parsed.flag("cwd") orelse resolved.server.cwd;
    const full = try Tmux.jobLaunchLine(ctx.arena, command, cwd, sentinel, execution.id());

    // The immutable record of what was launched. Survives `job rm` and a
    // same-name rerun, which the mutable `jobs` row does not.
    const attempt_no = Store.job_attempts.nextAttemptNo(&store, resolved.server.id, job_name) catch |err|
        Cli.storeFatal(&store, err);
    _ = Store.job_attempts.create(&store, .{
        .request_id = execution.id(),
        .server_id = resolved.server.id,
        .server_name = resolved.server.name,
        .job_name = job_name,
        .attempt_no = attempt_no,
        .sentinel = sentinel,
        .tmux_session = session,
        .cwd = cwd,
        .interpreter = parsed.flag("interpreter") orelse "bash",
        .shell = if (parsed.boolean("login")) "bash-login" else "bash",
        .script_body_redacted = Store.history.redactSecrets(ctx.arena, raw_command) catch
            fatal("cannot redact the script for the audit record; refusing to store it unredacted", .{}),
        .script_sha256 = try sha256Hex(ctx.arena, raw_command),
        .script_bytes = @intCast(raw_command.len),
        .entry_path = staged_path,
        .now = ctx.now,
    }) catch |err| Cli.storeFatal(&store, err);

    // The reservation is re-asserted here, on the last line before anything can
    // reach the remote shell, and this is the last place a refusal is still
    // free.
    //
    // Everything between `jobs.create` and this point is remote work — a
    // `killSession`, an `ensure`, sometimes a whole script upload — and for all
    // of it this launch's operation sits at `connecting`, which `blocksScope`
    // reports as harmless. A second `run` therefore reads the reservation as
    // reclaimable (see `reclaimable`, which says why it cannot tell a stranded
    // one from a live one) and deletes it. Without this check the next thing
    // that happened was `sendKeys`: the command went into the shell, the
    // promotion below found no row of ours, and the launch exited 75 with work
    // running on the host that nothing could name.
    //
    // Asked by owner rather than by name, because the name is exactly what may
    // have moved. A refusal here is clean: `submitted()` has not run, so the
    // attempt settles as a proven never-submitted failure rather than an
    // unknown, and `fail`'s reservation hook is keyed on this launch's request
    // id so it cannot delete the row that displaced us.
    //
    // It narrows the window to the single `submitted()` transaction below; it
    // does not close it. Closing it means the row carrying something a peer can
    // check for liveness, which this file cannot decide.
    if ((Store.jobs.byOwner(&store, ctx.arena, execution.id()) catch |err|
        Cli.storeFatal(&store, err)) == null) fatal(
        "job '{s}' was taken over by another launch while this one was preparing the remote; nothing was sent. Re-run to claim the name, or pick another --name",
        .{job_name},
    );

    // Keys are about to enter a live shell: from here the remote may act.
    // This is also where the scope guard binds — the check at `begin` was a
    // fast fail, this one is atomic with becoming visible to the next caller.
    switch (execution.submitted() catch |err| Cli.receiptFatal(execution.id(), err, "about to submit")) {
        .submitted => {},
        // `fail` releases the name reservation on the way out: we prepared
        // this launch and are not going to use it, and leaving the row behind
        // would make the next run report a job that never started. The
        // immutable attempt row stays — it is the record that this happened.
        .refused => |blocker| reportBlocked(blocker),
    }
    Tmux.sendKeys(executor, ctx.arena, session, full, false) catch {
        // The keys may have landed before the channel broke, so the job may
        // be running. Recording that and then exiting 1 would tell an agent
        // "failed, safe to retry" — the one conclusion that is not available.
        //
        // The reservation is kept, and deliberately left `pending`: it may
        // name something running on the host, so it must neither be reused
        // nor claimed as started.
        Cli.commitReservation();
        _ = execution.transportLoss(executor.errorMessage()) catch |receipt_err|
            Cli.receiptFatal(execution.id(), receipt_err, "submitted");
        // Nothing has been printed yet, so this needs the full body — an
        // agent parsing `--json` must get an object, not an empty stream and
        // a bare exit code.
        Cli.failIndeterminate(
            execution.id(),
            "the connection broke while handing the job to its remote shell; it may be running",
            "submitted",
        );
    };
    // The command is in the remote shell. The reservation is now a job.
    Cli.commitReservation();

    // Promotion can legitimately fail to find its row: another launcher may
    // have forced this name away while we were setting up. Either way the
    // command has already been sent, so neither a database error nor a
    // zero-row update may leave through the generic failure path — that reads
    // as "safe to retry" for work that is running right now.
    const promoted = Store.jobs.markStarted(&store, execution.id()) catch |err| promoted: {
        std.debug.print(
            "terminus: could not promote the tracking row for job '{s}': {s}\n",
            .{ job_name, @errorName(err) },
        );
        break :promoted false;
    };
    if (!promoted) {
        // The attempt row still carries this launch's own sentinel and
        // session, so the request id remains a complete handle on it even
        // though the job *name* may now belong to somebody else.
        execution.detach("job was handed to its remote shell; the local tracking row is not ours") catch |err|
            Cli.receiptFatal(execution.id(), err, "submitted");
        Cli.failIndeterminate(
            execution.id(),
            "the job was sent, but its local tracking row could not be promoted (another launcher may hold the name); settle it by request id",
            "submitted",
        );
    }

    if (Tmux.panePid(executor, ctx.arena, session) catch null) |pid| {
        execution.remoteStarted(.{ .pid = pid }) catch |err|
            Cli.receiptFatal(execution.id(), err, "remote_started");
    }

    // The work outlives this process. Detaching says so explicitly, and the
    // attempt keeps holding its scope until somebody establishes how it ended.
    execution.detach("job continues in its remote tmux session") catch |err|
        Cli.receiptFatal(execution.id(), err, "remote_started");

    switch (ctx.out.format) {
        .json => try ctx.out.json(.{
            .ok = true,
            .action = "started",
            .requestId = execution.id(),
            .attempt = attempt_no,
            .server = server_name,
            .job = job_name,
            .command = raw_command,
            .cwd = cwd,
            .transport = conn.transport,
            .daemonError = conn.daemon_error,
        }),
        .human => try ctx.out.print("started job '{s}' on '{s}' (request {s}); poll with 'terminus job status {s} {s}'\n", .{
            job_name, server_name, execution.id(), server_name, job_name,
        }),
    }
}

/// The attempt a job row names, or null when it names none.
///
/// Resolved from the row's own `owner_request_id`, never from its name. The row
/// records which launch reserved it; `job_attempts.latest` records which launch
/// used the *alias* most recently, and the two diverge for a whole SSH round
/// trip on every relaunch — `run` writes the row before it kills the old
/// session, stages the script and creates its attempt.
///
/// A `job status` landing in that window read the *new* row and the *previous*
/// launch's attempt, probed the previous launch's result sidecar — which
/// survives every `job rm` not given `--discard-evidence` — and reported that
/// launch's exit code as `{"ok":true,"status":"completed"}` for a launch that
/// had not sent a key. The workflow `run … & terminus job status` prints as the
/// next step is exactly the one that lands there.
///
/// Null covers two different things and neither is guessed at: an unowned row
/// (0.1.x, before the column existed), and an owner whose attempt row is not
/// written yet. Both surface as `Settlement.no_attempt`, whose hint says the
/// row names no attempt.
fn attemptOf(
    store: *Store,
    arena: std.mem.Allocator,
    job: Store.jobs.Job,
) ?Store.job_attempts.Attempt {
    const owner = job.owner_request_id orelse return null;
    return Store.job_attempts.byRequest(store, arena, owner) catch |err|
        Cli.storeFatal(store, err);
}

pub fn jobCmd(ctx: *Cli.Ctx, raw_args: []const []const u8) !void {
    if (raw_args.len == 0) fatal("{s}", .{job_usage});
    const verb = raw_args[0];
    const parsed = Cli.parseArgs(ctx, raw_args[1..]);
    if (parsed.boolean("json")) ctx.out.format = .json;

    const server_name = parsed.positional(0) orelse fatal("{s}", .{job_usage});
    var store = try Cli.openStore(ctx, &parsed);
    defer store.close();
    const resolved = Cli.resolveServer(ctx, &store, server_name);

    if (std.mem.eql(u8, verb, "ls")) return listJobs(ctx, &store, resolved.server.id, server_name, &parsed);

    const job_name = parsed.positional(1) orelse fatal("{s}", .{job_usage});

    if (std.mem.eql(u8, verb, "inspect")) return inspectJob(ctx, &store, resolved.server.id, job_name, &parsed);

    const job = (Store.jobs.getByName(&store, ctx.arena, resolved.server.id, job_name) catch |err|
        Cli.storeFatal(&store, err)) orelse fatal("unknown job '{s}' on '{s}'", .{ job_name, server_name });
    const session = try jobSessionName(ctx.arena, job_name);

    // The attempt links this job to its operation, so an observation here
    // settles the attempt the launching process left in flight. Addressed by
    // the row's owner rather than by its name — see `attemptOf`.
    const attempt = attemptOf(&store, ctx.arena, job);

    // The two mutating verbs take the job scope *before* the connection is
    // opened, so a peer's live claim refuses this command with nothing sent
    // — not even a dial. Everything below it, including `Cli.connect`, then
    // runs with the scope held.
    const mutation: ?Claim = if (std.mem.eql(u8, verb, "kill") or std.mem.eql(u8, verb, "rm"))
        switch (claimJobScope(ctx, &store, resolved.server.id, job_name, &parsed)) {
            .held => |claim| claim,
            .blocked => |lease| reportClaimBlocked(lease),
            .seized => |seizure| blk: {
                // Reported, not silent: `--force` displaced somebody, and the
                // operator has to be told whose work they just took over.
                for (seizure.displaced) |old| std.debug.print(
                    "terminus: --force took the lease on job '{s}' from request {s} (on {s})\n",
                    .{ job_name, old.owner_request_id, old.profile_token },
                );
                break :blk seizure.claim;
            },
        }
    else
        null;

    var conn = Cli.connect(ctx, &parsed, resolved.server, resolved.auth);
    defer conn.deinit();
    const executor = conn.executor();

    if (std.mem.eql(u8, verb, "status")) {
        const state = refresh(ctx, &store, executor, session, job, attempt);
        try reportStatus(ctx, server_name, job, state, conn.transport, conn.daemon_error, attempt);
        // Not `status == .indeterminate`. An attempt the ledger has never seen
        // has no status to compare, and one this observation failed to settle
        // is unproven whatever word the ledger happens to hold.
        switch (observationExit(state, false)) {
            .ok => {},
            .indeterminate => {
                try ctx.out.flush();
                Cli.failIndeterminateAfterOutput(if (attempt) |a| a.request_id else job.name);
            },
            .failure => {
                try ctx.out.flush();
                std.process.exit(Cli.exit_code.failure);
            },
        }
    } else if (std.mem.eql(u8, verb, "read")) {
        const limit: i64 = if (parsed.flag("limit")) |l|
            std.fmt.parseInt(i64, l, 10) catch fatal("invalid --limit '{s}'", .{l})
        else
            1 << 20;
        const from = if (parsed.boolean("from-cursor")) job.read_cursor else 0;
        const probe = Tmux.probeJob(
            executor,
            ctx.arena,
            session,
            job.sentinel,
            if (attempt) |a| a.request_id else null,
            from,
            limit,
        ) catch |err| switch (err) {
            // Named here rather than left to `fatalTmux`'s catch-all, because
            // this is the one command whose whole contract is "give me the
            // bytes after my cursor and move it". The remote's read script
            // prints the log's byte count on a line of its own on every path
            // it can take, so an answer with no newline in it is not a short
            // log — it is an answer that was cut short. `readLog` used to
            // report that as a successful read of an empty log with the cursor
            // left where it was, which is a broken link wearing the shape of a
            // job that has printed nothing yet.
            error.TruncatedResponse => fatal(
                "the remote's answer for job '{s}' was cut short before its size line, so nothing was read and the cursor has not moved; this is a broken read, not an empty log. Re-run it",
                .{job.name},
            ),
            else => fatalTmux(err, executor, session),
        };
        // A refused cursor advance is a failure of this command's contract:
        // the caller asked for the bytes after its position *and* for that
        // position to move, and the next `--from-cursor` will now hand it the
        // same bytes again. Reported rather than swallowed, and the output is
        // still printed — it was really read.
        var cursor_conflict: ?Store.jobs.Conflict = null;
        if (parsed.boolean("from-cursor")) {
            switch (Store.jobs.setCursor(&store, job.cursorExpectation(), probe.next_cursor) catch |err|
                Cli.storeFatal(&store, err)) {
                .applied => {},
                .refused => |conflict| cursor_conflict = conflict,
            }
        }
        const state = applyProbe(ctx, &store, job, probe, attempt);
        const cursor_hint: ?[]const u8 = if (cursor_conflict) |conflict|
            conflictText(ctx.arena, job.name, conflict)
        else
            null;
        switch (ctx.out.format) {
            .json => try ctx.out.json(.{
                .ok = observationExit(state, cursor_conflict != null) == .ok,
                .requestId = if (attempt) |a| a.request_id else null,
                .job = job.name,
                .status = state.status.text(),
                .outcomeProven = state.settlement.proves(),
                .settlement = @tagName(state.settlement),
                .exitCode = state.exit_code,
                .businessResult = state.business_result,
                .finishedAt = state.finished_at,
                .observedAt = state.observed_at,
                .conflict = ConflictJson.from(state.conflict),
                .resultRecord = state.sidecar.code(),
                .resultRecordError = state.sidecarNote(ctx),
                .from = from,
                // What the cursor *is* now, which on a refusal is not where
                // this read ended. `cursorAdvanced` is the difference, and an
                // agent that only reads `to` would otherwise skip the window.
                .to = if (cursor_conflict == null) probe.next_cursor else from,
                .cursorAdvanced = cursor_conflict == null,
                .cursorError = cursor_hint,
                .hint = state.hint(ctx, job.name, attempt),
                .data = probe.output,
            }),
            .human => {
                try ctx.out.print("{s}", .{probe.output});
                if (cursor_hint) |text| try ctx.out.print("\n{s}\n", .{text});
                if (state.sidecarNote(ctx)) |text| try ctx.out.print("\n{s}\n", .{text});
                if (state.hint(ctx, job.name, attempt)) |text| try ctx.out.print("\n{s}\n", .{text});
            },
        }
        switch (observationExit(state, cursor_conflict != null)) {
            .ok => {},
            .indeterminate => {
                try ctx.out.flush();
                Cli.failIndeterminateAfterOutput(if (attempt) |a| a.request_id else job.name);
            },
            .failure => {
                try ctx.out.flush();
                std.process.exit(Cli.exit_code.failure);
            },
        }
    } else if (std.mem.eql(u8, verb, "watch")) {
        try watchJob(ctx, &store, executor, session, job, attempt, &parsed, server_name, conn);
    } else if (std.mem.eql(u8, verb, "kill")) {
        try killJob(ctx, &store, executor, session, job, attempt, mutation.?);
    } else if (std.mem.eql(u8, verb, "rm")) {
        try removeJob(ctx, &store, executor, session, job, attempt, mutation.?, &parsed);
    } else {
        fatal("unknown verb 'job {s}'\n{s}", .{ verb, job_usage });
    }
}

/// Whether the ledger backs what a job command is about to report.
///
/// The three "yes" answers are not the same yes, and folding them into a bool
/// is how `applyProbe` came to report `completed` for an attempt the ledger had
/// refused to settle. Kept as an enum so each caller's JSON can say which of
/// them it is.
const Settlement = enum {
    /// Nothing has ended yet, so there is no outcome to prove.
    open,
    /// The ledger holds a real terminal for this attempt — recorded by this
    /// observation or by an earlier one.
    settled,
    /// The job row names no attempt at all. There is no operation to settle
    /// and nothing holding a scope, so what the host recorded is the whole
    /// answer — the same reading `killJob` takes with `proven = attempt ==
    /// null`. Reported explicitly rather than dressed up as a settlement,
    /// because "the ledger says so" and "the host says so and the ledger has
    /// never heard of this job" are different claims.
    no_attempt,
    /// An outcome was observed and the ledger does not hold it: the attempt
    /// was already settled `indeterminate`, it names a request the ledger has
    /// never seen, or this observation could establish nothing. Exits 75,
    /// because the scope is still held and a retry is not safe.
    unproven,

    fn proves(s: Settlement) bool {
        return switch (s) {
            .open, .settled, .no_attempt => true,
            .unproven => false,
        };
    }
};

const State = struct {
    /// What the ledger holds for this attempt. Derived from the host's record
    /// only in the `no_attempt` case, where there is no ledger row to hold
    /// anything and the hint says so.
    status: Core.Store.op_state.Status,
    /// Whether `status` is backed by the ledger. Decides the exit code, and it
    /// is not the same question as `status == .indeterminate`: an attempt a
    /// peer settled `indeterminate` and an attempt the ledger has never heard
    /// of both leave this `unproven`, and the second one has no status of its
    /// own at all.
    settlement: Settlement,
    exit_code: ?i64,
    /// A remote finish time we can prove, and nothing else. Null whenever the
    /// only record that answered was the log sentinel, which carries no
    /// timestamp — see `observed_at` for what we can always say.
    finished_at: ?i64,
    /// Our own clock, at the moment we looked. Never presented as a finish
    /// time: it is when *we saw* the evidence, on a different machine.
    observed_at: i64,
    /// Set when the two durable records disagree. Carried all the way out to
    /// the caller: without it a contradiction reads as a plain `indeterminate`
    /// with no exit code, which is indistinguishable from "the job left
    /// nothing behind" and sends the operator to a reconcile that will refuse.
    conflict: ?Tmux.JobProbe.Conflict = null,
    /// What was at the job's result sidecar, whether or not it answered.
    ///
    /// Carried out to the caller for the reason `conflict` is: without it,
    /// "there is no result record" and "there is one and it is corrupt, or it
    /// belongs to another request" are one indistinguishable silence. They are
    /// not the same situation — the first is ordinary for a job launched
    /// before sidecars existed or one whose evidence was discarded, the second
    /// means the remote wrapper is from another build or something truncated a
    /// write, and the third means two operations are writing to one address.
    /// Only the first is unremarkable, and it is the one all three used to
    /// look like.
    sidecar: Tmux.SidecarReading = .not_requested,
    business_result: ?[]const u8 = null,
    /// The row is still a reservation, so the probe's reading of its tmux
    /// session establishes nothing about it — see `applyProbe`.
    reservation: bool = false,
    /// What happened to the `jobs` cache row alongside the settlement. A
    /// refusal here is reported, never swallowed: it means the row a later
    /// `run --name X` will consult is not the row this command settled.
    cache: Core.execution.CacheResult = .not_applicable,

    /// The sentence that tells the operator what is missing, or null when
    /// nothing is.
    ///
    /// Concatenated rather than first-wins. A refused cache write and an
    /// unproven settlement are two independent things to do, and the cache
    /// refusal used to `return` before the settlement sentence was reached —
    /// so the one case where the operator owed a reconcile *and* had a stale
    /// row printed only the row message, and the request id and the
    /// `request reconcile` command that are the sole exit from `indeterminate`
    /// were never shown.
    fn hint(state: State, ctx: *Cli.Ctx, job_name: []const u8, attempt: ?Store.job_attempts.Attempt) ?[]const u8 {
        const cache_text: ?[]const u8 = if (state.cache == .refused)
            conflictText(ctx.arena, job_name, state.cache.refused)
        else
            null;
        const settlement_text: ?[]const u8 = if (state.reservation)
            "this job row is still a reservation: the launch that claimed the name has not reported reaching the remote shell, so nothing read from its session says anything about it yet"
        else switch (state.settlement) {
            .open, .settled => null,
            .no_attempt => "this job row has no recorded attempt, so there was no operation to settle; the exit status above is the host's own record and nothing in the ledger claims it",
            .unproven => if (attempt) |a| std.fmt.allocPrint(
                ctx.arena,
                "the ledger records attempt {s} as {s}, so this observation settled nothing; reconcile it with 'terminus request reconcile {s}' before retrying",
                .{ a.request_id, state.status.text(), a.request_id },
            ) catch "the ledger did not accept this observation; reconcile the attempt before retrying" else "the ledger did not accept this observation; reconcile the attempt before retrying",
        };
        const first = cache_text orelse return settlement_text;
        const second = settlement_text orelse return first;
        return std.fmt.allocPrint(ctx.arena, "{s}. Also: {s}", .{ first, second }) catch first;
    }

    /// The sentence a defective result record earns, or null when the reading
    /// was one of the three ordinary ones (not looked for, not there, ours).
    ///
    /// Deliberately not folded into `hint`. `hint` answers "what does the
    /// operator still owe" — a reconcile, a second look at a row that moved.
    /// This answers "what did we find that we could not use", which is a fact
    /// about the host rather than a task, and it is reported on every path,
    /// including the ones where the reading changed nothing because no record
    /// was willing to answer anyway.
    ///
    /// It is not what keeps a defective record out of the exit-code decision.
    /// It used to be described that way — "a report, not a refusal" — and that
    /// was the defect: the note travelled beside a `completed` settled from a
    /// log sentinel while the stronger record sat unreadable at this request's
    /// own address. The refusal is now `Tmux.JobProbe.refused`, decided where
    /// the two records are read, and this stayed a report.
    fn sidecarNote(state: State, ctx: *Cli.Ctx) ?[]const u8 {
        return resultRecordError(ctx, state.sidecar);
    }
};

/// The sentence a defective result record earns, or null when the reading was
/// one of the three ordinary ones (not looked for, not there, ours).
///
/// A free function rather than a method on `State`, because the commands that
/// never build a `State` — `job kill` and `job rm` — have to answer the same
/// question for the same JSON field, and two copies of "when is a reading worth
/// a sentence" would let the field mean one thing under `job status` and
/// another under `job kill`.
fn resultRecordError(ctx: *Cli.Ctx, reading: Tmux.SidecarReading) ?[]const u8 {
    if (!reading.anomalous()) return null;
    // Three of the four sentences need an allocation. If one fails we still
    // name the reading rather than saying nothing — silence would turn a
    // defective record back into the plain absence this exists to tell it
    // apart from.
    return reading.describe(ctx.arena) catch reading.code();
}

/// The same sentence for a caller that is already standing on a refused path
/// and needs prose rather than an option.
///
/// `refused` is only ever set beside an anomalous reading, so the `orelse` is
/// an invariant check and not a fallback: there is no honest sentence to
/// substitute if it ever fires, and naming the reading is strictly better than
/// leaving the reason saying an exit status was declined without saying what
/// declined it.
fn defectSentence(ctx: *Cli.Ctx, reading: Tmux.SidecarReading) []const u8 {
    return resultRecordError(ctx, reading) orelse reading.code();
}

/// The JSON shape of a `JobProbe.Conflict`. One definition so every command
/// that can hit a contradiction names its two halves the same way.
const ConflictJson = struct {
    resultExitCode: i32,
    sentinelExitCode: i32,

    fn from(clash: ?Tmux.JobProbe.Conflict) ?ConflictJson {
        const c = clash orelse return null;
        return .{ .resultExitCode = c.result_exit_code, .sentinelExitCode = c.sentinel_exit_code };
    }
};

/// How much of the log's end a state probe reads. Shared with the launch
/// paths' lazy settlement, so both windows are the same by construction.
const probe_tail_bytes = Cli.probe_tail_bytes;

/// One SSH probe of the log's *end*; settles the operation if it establishes
/// an outcome.
///
/// Deliberately does not use `jobs.read_cursor`. That cursor belongs to
/// whoever is streaming output, and a probe that shared it would (a) move a
/// consumer's position underneath them and (b) never reach the sentinel on a
/// job whose output exceeds one read window.
fn refresh(
    ctx: *Cli.Ctx,
    store: *Store,
    executor: Core.Executor,
    session: []const u8,
    job: Store.jobs.Job,
    attempt: ?Store.job_attempts.Attempt,
) State {
    const probe = Tmux.probeTail(
        executor,
        ctx.arena,
        session,
        job.sentinel,
        if (attempt) |a| a.request_id else null,
        probe_tail_bytes,
    ) catch |err| fatalTmux(err, executor, session);
    if (attempt) |a| {
        Store.job_attempts.recordProbe(store, a.request_id, .{
            .probe_cursor = probe.next_cursor,
            .latest_business_result = probe.business_result,
            .session_alive = probe.session_alive,
            .now = ctx.now,
        }) catch |err| Cli.storeFatal(store, err);
    }
    return applyProbe(ctx, store, job, probe, attempt);
}

/// One sentence per `jobs.Conflict`.
///
/// Every guarded write in `jobs` refuses with the same vocabulary, so every
/// command that can be refused says the same thing about the same fact — and
/// each sentence names what actually happened to the row, because a refusal
/// that only says "no" is one an operator works around.
fn conflictText(
    arena: std.mem.Allocator,
    job_name: []const u8,
    conflict: Store.jobs.Conflict,
) []const u8 {
    return switch (conflict) {
        .row_gone => std.fmt.allocPrint(
            arena,
            "the tracking row for job '{s}' was removed while this command was running, so nothing local tracks it under that name",
            .{job_name},
        ) catch "the job's tracking row was removed while this command was running",
        .not_ours => |status| std.fmt.allocPrint(
            arena,
            "job name '{s}' belongs to another launch now (its row is {s}); this command wrote nothing to it",
            .{ job_name, status.text() },
        ) catch "the job name belongs to another launch now; this command wrote nothing to it",
        .status_moved => |moved| std.fmt.allocPrint(
            arena,
            "job '{s}' was {s} when this command read it and is {s} now; the record that got there first stands",
            .{ job_name, moved.expected.text(), moved.found.text() },
        ) catch "the job row changed while this command was running; the record that got there first stands",
        .cursor_moved => |moved| std.fmt.allocPrint(
            arena,
            "another reader moved job '{s}''s cursor from {d} to {d} while this command was reading, so the bytes above are not marked as consumed",
            .{ job_name, moved.expected, moved.found },
        ) catch "another reader moved the job's cursor; the bytes above are not marked as consumed",
        .illegal_transition => |move| std.fmt.allocPrint(
            arena,
            "job '{s}' is already {s}, so it cannot also be recorded as {s}",
            .{ job_name, move.from.text(), move.to.text() },
        ) catch "the job row is already settled and cannot be settled again",
        .grounds_refuse => |refusal| std.fmt.allocPrint(
            arena,
            "job '{s}' is {s}, which a {s} may not delete",
            .{ job_name, refusal.found.text(), refusal.grounds.describe() },
        ) catch "the job row is in a state these grounds may not delete",
    };
}

/// What `job rm` reports, from what actually happened.
///
/// Pulled out of `removeJob` so it can be gated without an SSH round trip: the
/// defect this closes was a *report* that did not follow from the facts, and a
/// report only testable through three tmux calls and a `std.process.exit` is a
/// report that goes untested.
///
/// Two rules, and the first is the one that was missing. A row that is still
/// there was not removed — printing `{"action":"removed","ok":true}` after a
/// DELETE that matched nothing is how `job rm` came to claim it had forgotten
/// another launcher's running job. The second is unchanged in shape: discarding
/// evidence converts something that could have been proven into an override the
/// caller now owes, and so does anything that leaves the host's evidence
/// present but unusable, so neither reports `ok`.
///
/// `unreconcilable` covers both shapes of unusable evidence — two durable
/// records that disagree, and a defective record beside a sentinel that can no
/// longer be checked against it. They are one parameter because they cost the
/// caller the same thing: `reconcile --from-log` reads exactly these two
/// records and refuses both, so only `--override` is left.
const RemovalReport = struct {
    removed: bool,
    ok: bool,
    action: []const u8,
};

fn removalReport(
    cache: Core.execution.CacheResult,
    proven: bool,
    discard: bool,
    unreconcilable: bool,
) RemovalReport {
    const removed = cache == .synced;
    return .{
        .removed = removed,
        .ok = removed and (proven or (!discard and !unreconcilable)),
        .action = if (removed) "removed" else "not_removed",
    };
}

/// The sentence a refused cache write earns, or null when there was not one.
///
/// A refusal here never invalidates the settlement — the ledger is the record
/// and it is already written — but it must not be silent either: it says the
/// row a later `run --name X` consults does not describe the attempt this
/// command just settled.
fn cacheError(
    ctx: *Cli.Ctx,
    job_name: []const u8,
    cache: Core.execution.CacheResult,
) ?[]const u8 {
    return switch (cache) {
        .not_applicable, .synced, .ledger_already_settled => null,
        .refused => |conflict| conflictText(ctx.arena, job_name, conflict),
    };
}

/// What an observation established, once the ledger has had its say.
const Observed = struct {
    /// What the ledger holds. Null when there is no attempt, or when the
    /// attempt names a request the ledger does not have — neither of which is
    /// a status, and neither of which may be flattened into one.
    status: ?Core.Store.op_state.Status,
    settlement: Settlement,
    cache: Core.execution.CacheResult,

    fn statusText(o: Observed) []const u8 {
        return if (o.status) |s| s.text() else "unknown";
    }
};

/// The cache write that belongs with a settlement, or `.none` when there is
/// none to do.
///
/// A row already marked `killed` records a decision somebody took, and
/// overwriting it with `exited` because we later read the exit status the job
/// happened to leave behind rewrites that history. `jobs`' own settlement route
/// refuses that write anyway; this keeps an ordinary "somebody already recorded
/// it" out of the refusal path, where it would print a conflict at an operator
/// who has nothing to do about it.
fn finishSync(
    job: Store.jobs.Job,
    to: Store.jobs.Settled,
    exit_code: ?i64,
    at: i64,
) Core.execution.JobCacheSync {
    if (!job.status.live()) return .none;
    return .{ .finish = .{
        .expected = job.finishExpectation(),
        .status = to,
        .exit_code = exit_code,
        .at = at,
    } };
}

/// Settles the attempt behind an observation and syncs its cache row, in one
/// transaction, and says what the ledger ended up holding.
///
/// The three cases this distinguishes are the three `applyProbe` collapsed. It
/// computed its answer from `probe.exit_code` alone and discarded the settle
/// outcome with `_ =`, so an attempt the ledger refused to settle — because a
/// peer had already settled it `indeterminate` — was still reported as
/// `completed`, exit 0, no hint, while `operations.unsettledInScope` went on
/// blocking the next `run --name deploy`. `killJob` and `removeJob` already had
/// this logic inline; now all five share it.
fn settleObserved(
    ctx: *Cli.Ctx,
    store: *Store,
    execution: ?*Core.execution.Execution,
    attempt: ?Store.job_attempts.Attempt,
    terminal: Core.Store.op_state.Terminal,
    extra: Core.Store.receipts.TerminalExtra,
    sync: Core.execution.JobCacheSync,
) Observed {
    // No attempt: there is no operation, so there is nothing to settle and
    // nothing holding a scope. The cache row still has to stop claiming the
    // job is live, and there is no settlement to put in the transaction with
    // it — the one caller `markFinishedUnattached` exists for.
    const a = attempt orelse {
        const cache: Core.execution.CacheResult = switch (sync) {
            .none => .not_applicable,
            // No ledger row exists that could hold a rival verdict, so there
            // is nothing to defer to and the cache is the only record there is.
            .finish => |f| resultOf(Store.jobs.markFinishedUnattached(
                store,
                f.expected,
                f.status,
                f.exit_code,
                f.at,
            ) catch |err| Cli.storeFatal(store, err)),
            .forget => |g| resultOf(forgetRow(store, g) catch |err| Cli.storeFatal(store, err)),
        };
        return .{ .status = null, .settlement = .no_attempt, .cache = cache };
    };

    if (execution) |e| {
        const settled = e.settleAttachedAndSyncJob(terminal, extra, sync) catch |err|
            Cli.receiptFatal(a.request_id, err, "observing a job");
        const status = settled.status();
        return .{
            .status = status,
            .settlement = if (status == .indeterminate) .unproven else .settled,
            .cache = settled.cache,
        };
    }

    // `attach` returned null, so the attempt is already terminal — which
    // includes `indeterminate`, the case where nothing was ever established.
    // Ask the ledger what it actually holds rather than reporting the outcome
    // we set out to write.
    //
    // A finish is skipped here: this observation recorded nothing, so it has
    // no verdict to copy into the row. A removal is not, for the reason
    // `settleAttachedAndSyncJob` gives — forgetting a name says nothing about
    // how the job ended, and `job rm` that declined to forget it because
    // somebody else settled the attempt first would leave the row for good.
    const cache: Core.execution.CacheResult = switch (sync) {
        .none, .finish => .ledger_already_settled,
        .forget => |g| resultOf(forgetRow(store, g) catch |err| Cli.storeFatal(store, err)),
    };
    const effective = recordedEffective(ctx, store, a.request_id) orelse
        return .{ .status = null, .settlement = .unproven, .cache = cache };
    return .{
        .status = effective,
        .settlement = if (effective == .indeterminate) .unproven else .settled,
        .cache = cache,
    };
}

fn resultOf(write: Store.jobs.Write) Core.execution.CacheResult {
    return switch (write) {
        .applied => .synced,
        .refused => |conflict| .{ .refused = conflict },
    };
}

/// `jobs.remove` renders its state list from the grounds, so they have to be
/// comptime; a sync request carries them as a value. One `inline else`.
fn forgetRow(
    store: *Store,
    forget: Core.execution.JobCacheSync.Forget,
) Store.jobs.WriteError!Store.jobs.Write {
    return switch (forget.grounds) {
        inline else => |grounds| Store.jobs.remove(store, forget.expected, grounds),
    };
}

/// The store's vocabulary for what this probe found at the result-record
/// address, ready to travel into the terminal receipt.
///
/// An exhaustive switch and not a cast: `Store.receipts.ResultRecordReading` is
/// a separate type because nothing under `store/` may import `session/`, so
/// this is the seam where the two could drift. Adding a reading to
/// `Tmux.SidecarReading` is a compile error here until it has been named on the
/// store side too, which is the only thing keeping the receipt's vocabulary and
/// the probe's the same list.
///
/// Every reading is carried, not just the four defective ones. "We looked and
/// there was nothing" and "we did not look" are different facts about the
/// settlement, and a receipt that recorded only anomalies could not tell either
/// of them from a settlement that predates this field.
fn resultRecordOf(
    ctx: *Cli.Ctx,
    reading: Tmux.SidecarReading,
) Store.receipts.TerminalExtra.ResultRecord {
    return .{
        .arena = ctx.arena,
        .reading = switch (reading) {
            .not_requested => .not_requested,
            .absent => .absent,
            .malformed => .malformed,
            .unknown_schema => .unknown_schema,
            .exit_code_out_of_range => .exit_code_out_of_range,
            .foreign => |claimed| .{ .foreign = claimed },
            .present => .present,
        },
    };
}

/// Turns an observation into a settlement — or into nothing at all.
///
/// Five cases; four of them settle the ledger and the fifth records nothing:
///   * the two durable records disagree — the one case where more evidence
///     leaves us less certain. Settled `indeterminate`, naming both codes;
///   * a defective document sits at this request's own address and the log
///     sentinel was willing to answer in its place — settled `indeterminate`,
///     naming the defect and the code that was declined. Not the exit code:
///     see the branch itself;
///   * a record carried an exit code — the job ended, and how. Settled;
///   * the session is gone with no exit code — something happened and we
///     cannot say what. Settled `indeterminate`, which keeps holding the
///     scope. Not `killed`: a pane also disappears when the command finishes
///     and the shell exits, or when the host reboots mid-write;
///   * otherwise it is still running, and there is nothing to record.
///
/// What is *reported* in the first four is what the ledger holds afterwards,
/// which is not always what we set out to write.
fn applyProbe(
    ctx: *Cli.Ctx,
    store: *Store,
    job: Store.jobs.Job,
    probe: Tmux.JobProbe,
    attempt: ?Store.job_attempts.Attempt,
) State {
    var execution = if (attempt) |a|
        Core.execution.attach(store, ctx.arena, ctx.io, a.request_id) catch |err| Cli.storeFatal(store, err)
    else
        null;

    // Checked before the exit code, not after. `probe.exit_code` is already
    // null on a conflict, but reading it first would make the ordering the
    // thing that keeps a contradiction from settling — and the reason string
    // below is the only place the two codes ever reach a human.
    if (probe.conflict) |clash| {
        // The row is left as it stands, so the sync is `.none`. Writing a
        // status here would have to pick one of the two codes, which is
        // precisely what we refuse to do.
        const settled = settleObserved(ctx, store, if (execution) |*e| e else null, attempt, .{ .indeterminate = .{
            .reason = std.fmt.allocPrint(
                ctx.arena,
                "the job's two durable records disagree: its result file says exit {d}, the sentinel in its log says exit {d}. One of them is wrong and nothing here can say which",
                .{ clash.result_exit_code, clash.sentinel_exit_code },
            ) catch "the job's result file and its log sentinel report different exit codes",
            .last_observed = if (execution) |e| e.status else .remote_started,
        } }, .{ .result_record = resultRecordOf(ctx, probe.sidecar) }, .none);
        return .{
            // A contradiction is unknown however it was recorded, and the one
            // case where a `no_attempt` reading is still not an answer: two
            // host records disagreeing is not "the host's record is the whole
            // answer", it is the absence of one.
            .status = settled.status orelse .indeterminate,
            .settlement = .unproven,
            .exit_code = null,
            .finished_at = null,
            .observed_at = ctx.now,
            .conflict = clash,
            .sidecar = probe.sidecar,
            .business_result = probe.business_result,
            .cache = settled.cache,
        };
    }

    // A defective result record refuses to settle, even when the log sentinel
    // is willing to answer in its place.
    //
    // The sentinel's code is not wrong here so much as uncheckable: the
    // stronger record is sitting at an address derived from this request's own
    // id, and it is unreadable, from a wrapper of another build, carrying a
    // code no shell produces, or naming somebody else. We cannot ask whether
    // the two agree, and settling `completed` or `failed` from the weaker one
    // alone publishes a proven outcome standing next to evidence we have just
    // refused. The row is left alone for the same reason the conflict branch
    // leaves it alone — the sync is `.none` — because writing `exited` into it
    // would put the very code we declined in front of the next `run --name X`.
    //
    // Deliberately keyed on `probe.refused` and not on `probe.sidecar.anomalous()`.
    // The second is also true of a defective document beside a log that said
    // nothing at all, where there is no verdict to decline and the job may
    // still be running — settling that `indeterminate` would end an operation
    // whose work is still going. That case falls through to the branches below
    // and is reported by `State.sidecarNote`, which is what it always was.
    if (probe.refused) |declined| {
        const defect = defectSentence(ctx, probe.sidecar);
        const settled = settleObserved(ctx, store, if (execution) |*e| e else null, attempt, .{ .indeterminate = .{
            .reason = std.fmt.allocPrint(
                ctx.arena,
                "the sentinel in this job's log says exit {d}, but {s}. The stronger of the two records is unusable, so nothing can check the weaker one and its exit status was not read as this job's outcome",
                .{ declined.sentinel_exit_code, defect },
            ) catch "this job's result record is present and unusable, so the exit status in its log was not read as its outcome",
            .last_observed = if (execution) |e| e.status else .remote_started,
        } }, .{ .result_record = resultRecordOf(ctx, probe.sidecar) }, .none);
        // What the ledger holds once the settlement above has run, not what
        // this reading established. The two come apart on an attempt that was
        // already terminal before we looked: `attach` returned null, nothing
        // was written, and `settleObserved` read the recorded outcome back and
        // handed over `.settled`.
        //
        // Hardcoding `.unproven` here reported that attempt as
        // `outcomeProven: false`, exit 75, with a hint naming `request
        // reconcile <request-id>` — a command that fatals on an already
        // terminal operation, `--override` included, so the caller was billed
        // an unknown outcome and handed no way out of it. A refused
        // *re-reading* of an attempt the ledger already proved establishes
        // nothing new about that attempt and must not un-prove it. The defect
        // is still reported: it travels out in `resultRecord` /
        // `resultRecordError` on every one of these paths.
        //
        // Forced to `.unproven` when the ledger holds `indeterminate`, and
        // when it holds nothing at all. The second is the `no_attempt` case,
        // where the host's own record would ordinarily be the whole answer and
        // here is precisely the record that was refused — same reasoning as
        // the conflict branch above.
        const held = settled.status orelse .indeterminate;
        return .{
            .status = held,
            .settlement = if (held == .indeterminate) .unproven else settled.settlement,
            .exit_code = null,
            .finished_at = null,
            .observed_at = ctx.now,
            .sidecar = probe.sidecar,
            .business_result = probe.business_result,
            .cache = settled.cache,
        };
    }

    if (probe.exit_code) |code| {
        // `jobs.finished_at` takes the remote clock when the sidecar reported
        // one and ours otherwise, so the column mixes two machines' clocks and
        // cannot be read as a finish time on its own. That is tolerable only
        // because it is a cache: the ledger is the record. What must not mix
        // is what we *report* — see `State.finished_at` and `State.observed_at`.
        const settled = settleObserved(ctx, store, if (execution) |*e| e else null, attempt, .{
            .exited = .{ .exit_code = code },
        }, .{
            .finished_at = probe.finished_at,
            .stdout = .{ .bytes = @intCast(probe.output.len) },
            // The case this field exists for: the settlement can be perfectly
            // sound — the log sentinel answered — while a document that is not
            // ours, or not readable, sits at this request's own address. The
            // verdict is right and the anomaly is still a fact about the host.
            .result_record = resultRecordOf(ctx, probe.sidecar),
        }, finishSync(job, .exited, code, probe.finished_at orelse ctx.now));
        return .{
            // The ledger's verdict, not the probe's reading. Only when there
            // is no attempt at all does the host's exit code stand on its own,
            // and `Settlement.no_attempt` is what says so out loud.
            .status = settled.status orelse (if (code == 0) .completed else .failed),
            .settlement = settled.settlement,
            .exit_code = code,
            .finished_at = probe.finished_at,
            .observed_at = ctx.now,
            .sidecar = probe.sidecar,
            .business_result = probe.business_result,
            .cache = settled.cache,
        };
    }

    if (!probe.session_alive) {
        // A missing session says nothing about a row that is still a
        // reservation, and settling one from it was how an observer came to
        // stop a launch that was working perfectly. `run` creates the row, then
        // *kills* the job's tmux session and recreates it; for that whole
        // window `has-session` reports absence, and a `job status` arriving in
        // it wrote `killed` over the reservation — a legal settlement edge with
        // owner and status both matching, so the CAS applied it. The launcher's
        // `markStarted` then found no `pending` row, and it exited 75 with its
        // command already running. Worse, the row now read `killed`, which is
        // not live, so the next `run --force` would delete it and kill the
        // session it had just filled with real work.
        //
        // The other two branches need no such guard: both key on *this
        // launch's own* sentinel and request id, neither of which can appear in
        // a log or a result sidecar before its keys are sent. This one asks
        // about a session name shared by every launch that ever used the name.
        if (job.status == .pending) return .{
            .status = if (execution) |e| e.status else .created,
            // Nothing has ended, because nothing has been shown to have
            // started. Reported as a reservation rather than as an outcome, so
            // the hint says which of the two it is.
            .settlement = .open,
            .reservation = true,
            .exit_code = null,
            .finished_at = null,
            .observed_at = ctx.now,
            .sidecar = probe.sidecar,
            .business_result = probe.business_result,
        };

        // The legacy row keeps its own vocabulary — `killed` here means "not
        // live, and no exit code", not a claim that somebody stopped it; the
        // ledger carries the honest `indeterminate`.
        const settled = settleObserved(ctx, store, if (execution) |*e| e else null, attempt, .{ .indeterminate = .{
            .reason = "job session disappeared without reporting an exit status",
            .last_observed = if (execution) |e| e.status else .remote_started,
        } }, .{ .result_record = resultRecordOf(ctx, probe.sidecar) }, finishSync(job, .killed, null, ctx.now));
        return .{
            .status = settled.status orelse .indeterminate,
            // A vanished session with no exit status proves nothing whoever
            // owns the attempt, so this is the one branch where `no_attempt`
            // does not make the host's record the answer: there is no record.
            .settlement = .unproven,
            .exit_code = null,
            // Not `now`. We cannot say when this job finished, and we cannot
            // say that it finished — that is what `indeterminate` means. A
            // timestamp here would read as a finish we never witnessed.
            .finished_at = null,
            .observed_at = ctx.now,
            .sidecar = probe.sidecar,
            .business_result = probe.business_result,
            .cache = settled.cache,
        };
    }

    return .{
        .status = if (execution) |e| e.status else .remote_started,
        .settlement = .open,
        .exit_code = null,
        .finished_at = null,
        .observed_at = ctx.now,
        .sidecar = probe.sidecar,
        .business_result = probe.business_result,
    };
}

/// What an observing job command exits with, given what it established.
///
/// Extracted for the reason `removalReport` was: the defect it closes is an
/// exit code that did not follow from the facts, and an exit code reachable
/// only through an SSH round trip and a `std.process.exit` is one that goes
/// untested. Three commands share it — `status`, `read`, `watch` — and they
/// used to compute `ok` one way and exit another.
const Exit = enum {
    ok,
    /// 75. Nothing here established what the ledger holds for this work, so a
    /// retry is not available.
    indeterminate,
    /// 1. Something this command was asked to do did not happen.
    failure,
};

/// The one place `ok` and the exit code are decided, so they cannot disagree.
///
/// Order is by what forbids the most. An unknown outcome forbids a retry
/// outright; a refused cache write and a refused cursor advance are both
/// ordinary failures of a thing the command was asked to do.
///
/// The `cache` clause is the one that was missing. `State.cache`'s own doc says
/// a refusal means the row a later `run --name X` consults is not the row this
/// command settled — and all three commands reported it only as prose in
/// `hint`, while `ok` stayed true and the process exited 0. `job status` on a
/// job whose row had been relaunched under a new owner printed
/// `{"ok":true,"outcomeProven":true,"status":"completed"}` and exited 0; an
/// agent branching on `ok` or `$?`, which is the documented contract, concluded
/// the job was finished and the name was free, and the row it would actually
/// consult said otherwise.
fn observationExit(state: State, cursor_refused: bool) Exit {
    if (!state.settlement.proves()) return .indeterminate;
    if (state.cache == .refused) return .failure;
    if (cursor_refused) return .failure;
    return .ok;
}

/// What `job kill` exits with when the job had already finished on its own.
///
/// Same extraction, same reason, and the same clause was missing here — with an
/// extra twist: `ok` did include the cache refusal, the JSON `hint` did carry
/// its sentence, and neither the human output nor the exit code did. The
/// operator read "recorded its outcome and cleaned up the session" with `$?`
/// zero, while the row that gates the next launch still said the job was live.
/// The sibling branch below (a kill that really cancelled something) already
/// exits non-zero on this, and says why: the name will go on refusing the next
/// launch and nothing else will explain it.
fn finishedDuringKillExit(
    proven: bool,
    session_gone: bool,
    cache: Core.execution.CacheResult,
) Exit {
    if (!proven) return .indeterminate;
    if (!session_gone) return .failure;
    if (cache == .refused) return .failure;
    return .ok;
}

fn reportStatus(
    ctx: *Cli.Ctx,
    server_name: []const u8,
    job: Store.jobs.Job,
    state: State,
    transport: []const u8,
    daemon_error: ?[]const u8,
    attempt: ?Store.job_attempts.Attempt,
) !void {
    switch (ctx.out.format) {
        .json => try ctx.out.json(.{
            .ok = observationExit(state, false) == .ok,
            .requestId = if (attempt) |a| a.request_id else null,
            .server = server_name,
            .job = job.name,
            .status = state.status.text(),
            // Whether the ledger backs `status`, and which of the four
            // readings it is. `ok` alone cannot say whether a job is still
            // running or whether nothing here could be settled.
            .outcomeProven = state.settlement.proves(),
            .settlement = @tagName(state.settlement),
            .exitCode = state.exit_code,
            .businessResult = state.business_result,
            .command = job.command,
            .createdAt = job.created_at,
            // Two clocks, never merged. `finishedAt` is the remote's own
            // report and is null unless the result sidecar carried one — a
            // sentinel-only outcome has no timestamp, and filling it with our
            // clock would put this machine's time under a key that claims to
            // describe when work ended on another one. `observedAt` is that
            // local clock, labelled as what it is.
            .finishedAt = state.finished_at,
            .observedAt = state.observed_at,
            .conflict = ConflictJson.from(state.conflict),
            // What was at the result sidecar's address, and — when that is
            // something we could not use — why. `"absent"` and `"malformed"`
            // are different answers and an agent may branch on which it got;
            // they used to be the same silence.
            .resultRecord = state.sidecar.code(),
            .resultRecordError = state.sidecarNote(ctx),
            .hint = state.hint(ctx, job.name, attempt),
            .transport = transport,
            .daemonError = daemon_error,
        }),
        .human => {
            try ctx.out.print("job '{s}': {s} (exit={?d})", .{ job.name, state.status.text(), state.exit_code });
            if (state.business_result) |br| try ctx.out.print(" result={s}", .{br});
            try ctx.out.print("\n", .{});
            if (state.conflict) |clash| try ctx.out.print(
                "  its result file says exit {d}, its log sentinel says exit {d}; one of them is wrong and nothing mechanical can say which\n",
                .{ clash.result_exit_code, clash.sentinel_exit_code },
            );
            if (state.sidecarNote(ctx)) |text| try ctx.out.print("  {s}\n", .{text});
            if (state.hint(ctx, job.name, attempt)) |text| try ctx.out.print("  {s}\n", .{text});
        },
    }
}

fn watchJob(
    ctx: *Cli.Ctx,
    store: *Store,
    executor: Core.Executor,
    session: []const u8,
    job: Store.jobs.Job,
    attempt: ?Store.job_attempts.Attempt,
    parsed: *const Cli.Args.Parsed,
    server_name: []const u8,
    conn: anytype,
) !void {
    const interval_ns = parseInterval(parsed.flag("interval") orelse "15s");
    const max_polls: u32 = if (parsed.flag("max")) |m|
        std.fmt.parseInt(u32, m, 10) catch fatal("invalid --max '{s}'", .{m})
    else
        240;

    var polls: u32 = 0;
    var state = refresh(ctx, store, executor, session, job, attempt);
    // A watch runs until the ledger has an answer or refuses to give one, so
    // the loop condition is the settlement rather than the status word: an
    // attempt this process cannot settle will never become `completed` no
    // matter how long it is polled, and looping on the status alone would spin
    // for the full `--max` before reporting it.
    while (state.settlement == .open and polls < max_polls) {
        std.Io.sleep(ctx.io, .{ .nanoseconds = @intCast(interval_ns) }, .awake) catch {};
        polls += 1;
        state = refresh(ctx, store, executor, session, job, attempt);
    }

    const still_running = state.settlement == .open;
    switch (ctx.out.format) {
        .json => try ctx.out.json(.{
            .ok = observationExit(state, false) == .ok,
            .requestId = if (attempt) |a| a.request_id else null,
            .server = server_name,
            .job = job.name,
            .status = state.status.text(),
            .outcomeProven = state.settlement.proves(),
            .settlement = @tagName(state.settlement),
            .exitCode = state.exit_code,
            .businessResult = state.business_result,
            .stillRunning = still_running,
            .conflict = ConflictJson.from(state.conflict),
            .resultRecord = state.sidecar.code(),
            .resultRecordError = state.sidecarNote(ctx),
            .hint = state.hint(ctx, job.name, attempt),
            .polls = polls,
            .transport = conn.transport,
        }),
        .human => if (still_running)
            try ctx.out.print("job '{s}' {s} after {d} polls\n", .{
                job.name,
                if (state.reservation) "is still only a reservation" else "still running",
                polls,
            })
        else {
            try ctx.out.print("job '{s}' {s} (exit={?d})", .{ job.name, state.status.text(), state.exit_code });
            if (state.business_result) |br| try ctx.out.print(" result={s}", .{br});
            try ctx.out.print("\n", .{});
            if (state.conflict) |clash| try ctx.out.print(
                "  its result file says exit {d}, its log sentinel says exit {d}; one of them is wrong and nothing mechanical can say which\n",
                .{ clash.result_exit_code, clash.sentinel_exit_code },
            );
            if (state.sidecarNote(ctx)) |text| try ctx.out.print("  {s}\n", .{text});
            if (state.hint(ctx, job.name, attempt)) |text| try ctx.out.print("  {s}\n", .{text});
        },
    }

    switch (observationExit(state, false)) {
        .ok => {},
        .indeterminate => {
            try ctx.out.flush();
            Cli.failIndeterminateAfterOutput(if (attempt) |a| a.request_id else job.name);
        },
        // Ranked above propagating the job's own exit code, and deliberately.
        // Passing the job's status through is this command's contract, but a
        // refused cache write means the row `run --name X` consults does not
        // describe the attempt just settled — and the one code that would
        // report that as success is 0, which is exactly what a passthrough
        // produces for a job that exited cleanly.
        .failure => {
            try ctx.out.flush();
            std.process.exit(Cli.exit_code.failure);
        },
    }
    if (state.exit_code) |code| {
        if (code != 0) {
            try ctx.out.flush();
            std.process.exit(@intCast(std.math.clamp(code, 1, 255)));
        }
    }
}

/// What the ledger already holds for an attempt, without producing a second
/// opinion.
///
/// `attach` returns null once an attempt is terminal, and terminal includes
/// `indeterminate` — the case where nothing was ever established. Treating
/// "already settled" as "settled successfully" would turn an unknown into a
/// success in the caller's eyes, so the ledger is asked directly.
///
/// Null when the attempt names a request the ledger does not have: that is not
/// a status, and must not be flattened into one.
fn recordedEffective(ctx: *Cli.Ctx, store: *Store, request_id: []const u8) ?Core.Store.op_state.Status {
    const op = (Store.operations.get(store, ctx.arena, request_id) catch |err|
        Cli.storeFatal(store, err)) orelse return null;
    return op.effectiveStatus();
}

/// `recordedEffective` for callers that only need to print it.
fn recordedStatus(ctx: *Cli.Ctx, store: *Store, request_id: []const u8) []const u8 {
    const status = recordedEffective(ctx, store, request_id) orelse return "unknown";
    return status.text();
}

fn settledText(outcome: Core.Store.receipts.SettleOutcome) []const u8 {
    return switch (outcome) {
        .recorded => |r| r.status.text(),
        .already_settled => |r| r.status.text(),
    };
}

fn settledStatus(outcome: Core.Store.receipts.SettleOutcome) Core.Store.op_state.Status {
    return switch (outcome) {
        .recorded => |r| r.status,
        .already_settled => |r| r.status,
    };
}

/// Stops a job and records what that actually established.
///
/// Not a new operation: a kill settles the attempt already in flight, so the
/// receipt shows the launch and its cancellation on one trail.
///
/// Three rules, each of them a bug that was here.
///
/// *Look before you kill.* This used to kill first and ask questions after,
/// which turned a job that had already finished — exit status sitting in its
/// result sidecar — into `indeterminate`, because once the session is gone
/// "gone" proves nothing. The answer had been there the whole time and the
/// kill is what stopped us reading it. So the probe comes first; when it finds
/// a real outcome that is what gets recorded, and the kill becomes cleanup.
/// What is *reported* is then what the ledger holds, which is not always what
/// we set out to write: an attempt a peer already settled `indeterminate`
/// cannot be re-settled, and claiming the outcome anyway would turn an unknown
/// into a success.
///
/// *A contradiction is not a settlement.* When the two durable records report
/// different exit codes, killing the session and calling it `cancelled` would
/// paper over the one case where the evidence is actively untrustworthy.
///
/// *A kill is not proof.* `tmux has-session` reporting the session gone is not
/// evidence that the work stopped: a command that daemonized, called `disown`,
/// or ran under `setsid` outlives the pane that launched it. Under a
/// supervisor whose capability says it cannot prove a process is gone, this
/// settles `indeterminate` — which keeps the scope held — rather than
/// `cancelled`, which would release it and invite a relaunch alongside a
/// process that is still running.
///
/// The log is never deleted here. An `indeterminate` kill points the operator
/// at `request reconcile --from-log`, so this is exactly the caller that must
/// keep the evidence — which is why it uses `killSession` and never
/// `removeLog`.
fn killJob(
    ctx: *Cli.Ctx,
    store: *Store,
    executor: Core.Executor,
    session: []const u8,
    job: Store.jobs.Job,
    attempt: ?Store.job_attempts.Attempt,
    claim: Claim,
) !void {
    // The scope was taken in `jobCmd`, before the connection was opened, and
    // is held from here through the kill to the settlement below.
    const probe = Tmux.probeTail(
        executor,
        ctx.arena,
        session,
        job.sentinel,
        if (attempt) |a| a.request_id else null,
        probe_tail_bytes,
    ) catch |err| fatalTmux(err, executor, session);

    if (probe.conflict) |clash| {
        const reason = std.fmt.allocPrint(
            ctx.arena,
            "kill requested, but the job's two durable records already disagree: its result file says exit {d}, the sentinel in its log says exit {d}. One of them is wrong and nothing here can say which",
            .{ clash.result_exit_code, clash.sentinel_exit_code },
        ) catch "kill requested, but the job's result file and its log sentinel report different exit codes";

        // The ledger and the cache row go together now, which moves the cache
        // write ahead of the kill below. Neither record depends on the kill:
        // the contradiction was established by the probe, and the kill is
        // cleanup the caller asked for.
        var execution = if (attempt) |a|
            Core.execution.attach(store, ctx.arena, ctx.io, a.request_id) catch |err|
                Cli.storeFatal(store, err)
        else
            null;
        // Held from before the connection to here, and renewed once: this is
        // the last stretch where losing it would matter.
        holdClaim(claim, wallClockSeconds(ctx.io));
        const settled = settleObserved(
            ctx,
            store,
            if (execution) |*e| e else null,
            attempt,
            .{ .indeterminate = .{
                .reason = reason,
                .last_observed = if (execution) |e| e.status else .remote_started,
            } },
            .{},
            finishSync(job, .killed, null, ctx.now),
        );

        // Still killed: the caller asked for the session to stop, and both
        // records claim the command already returned. What is refused is
        // reporting the kill as if it had established an outcome.
        const session_gone = Tmux.killSession(executor, ctx.arena, session) catch |err|
            fatalTmux(err, executor, session);
        // The kill is on the far side of the settlement on this branch, so the
        // scope is given back after it rather than at the settle: releasing in
        // between would open the job to a peer mid-`kill-session`.
        Cli.releaseClaim();

        switch (ctx.out.format) {
            .json => try ctx.out.json(.{
                .ok = false,
                .action = "killed",
                .job = job.name,
                .status = settled.statusText(),
                .sessionGone = session_gone,
                .cancellationProven = false,
                .conflict = ConflictJson.from(clash),
                .resultRecord = probe.sidecar.code(),
                .resultRecordError = resultRecordError(ctx, probe.sidecar),
                .requestId = if (attempt) |a| a.request_id else null,
                .cacheError = cacheError(ctx, job.name, settled.cache),
                .hint = "the two records disagree; settle it by hand with 'terminus request reconcile <request-id> --override'",
            }),
            .human => {
                try ctx.out.print(
                    "job '{s}': session killed, but its result file says exit {d} while its log sentinel says exit {d}; the outcome is unknown\n",
                    .{ job.name, clash.result_exit_code, clash.sentinel_exit_code },
                );
                if (cacheError(ctx, job.name, settled.cache)) |text|
                    try ctx.out.print("  {s}\n", .{text});
            },
        }
        try ctx.out.flush();
        Cli.failIndeterminateAfterOutput(if (attempt) |a| a.request_id else job.name);
    }

    // Same shape as the branch above, and for the same reason: the evidence is
    // present and untrustworthy, so the kill goes ahead and the outcome does
    // not. A defective document at this request's own address makes the log
    // sentinel uncheckable, and `job kill` reporting `already_finished (exit 7)`
    // on the strength of it would settle a proven terminal from the weaker of
    // two records while the stronger one says something on the host is wrong.
    if (probe.refused) |declined| {
        const defect = defectSentence(ctx, probe.sidecar);
        const reason = std.fmt.allocPrint(
            ctx.arena,
            "kill requested; the sentinel in the job's log says exit {d}, but {s}. The stronger of the two records is unusable, so its exit status was not read as this job's outcome",
            .{ declined.sentinel_exit_code, defect },
        ) catch "kill requested, but the job's result record is present and unusable, so the exit status in its log was not read as its outcome";

        var execution = if (attempt) |a|
            Core.execution.attach(store, ctx.arena, ctx.io, a.request_id) catch |err|
                Cli.storeFatal(store, err)
        else
            null;
        holdClaim(claim, wallClockSeconds(ctx.io));
        const settled = settleObserved(
            ctx,
            store,
            if (execution) |*e| e else null,
            attempt,
            .{ .indeterminate = .{
                .reason = reason,
                .last_observed = if (execution) |e| e.status else .remote_started,
            } },
            .{ .result_record = resultRecordOf(ctx, probe.sidecar) },
            finishSync(job, .killed, null, ctx.now),
        );

        const session_gone = Tmux.killSession(executor, ctx.arena, session) catch |err|
            fatalTmux(err, executor, session);
        Cli.releaseClaim();

        switch (ctx.out.format) {
            .json => try ctx.out.json(.{
                .ok = false,
                .action = "killed",
                .job = job.name,
                .status = settled.statusText(),
                .sessionGone = session_gone,
                .cancellationProven = false,
                .resultRecord = probe.sidecar.code(),
                .resultRecordError = resultRecordError(ctx, probe.sidecar),
                .requestId = if (attempt) |a| a.request_id else null,
                .cacheError = cacheError(ctx, job.name, settled.cache),
                // Not `--from-log`: that reconcile reads these same two
                // records and will refuse for the same reason.
                .hint = "the result record is unusable, so no mechanical reconcile can settle this; check the host and use 'terminus request reconcile <request-id> --override'",
            }),
            .human => {
                try ctx.out.print(
                    "job '{s}': session killed; its log sentinel says exit {d}, but {s} — the outcome is unknown\n",
                    .{ job.name, declined.sentinel_exit_code, defect },
                );
                if (cacheError(ctx, job.name, settled.cache)) |text|
                    try ctx.out.print("  {s}\n", .{text});
            },
        }
        try ctx.out.flush();
        Cli.failIndeterminateAfterOutput(if (attempt) |a| a.request_id else job.name);
    }

    if (probe.exit_code) |code| {
        // Whether the *ledger* now holds a real outcome for this attempt.
        // Reading an exit code off the host is not the same as recording it:
        // `attach` returns null for an attempt that is already terminal, and
        // terminal includes `indeterminate`, which settles nothing and goes on
        // blocking the scope. With no attempt at all there is no operation to
        // settle and nothing holding a scope, so the exit status we just read
        // is the whole answer — `Settlement.no_attempt`.
        //
        // The cache write travels with the settlement, in one transaction, and
        // is guarded by `finishSync`: a row already marked `killed` records a
        // decision somebody took, and overwriting it with `exited` because we
        // later read the exit status the job happened to leave behind rewrites
        // that history.
        var execution = if (attempt) |a|
            Core.execution.attach(store, ctx.arena, ctx.io, a.request_id) catch |err|
                Cli.storeFatal(store, err)
        else
            null;
        holdClaim(claim, wallClockSeconds(ctx.io));
        const settled = settleObserved(
            ctx,
            store,
            if (execution) |*e| e else null,
            attempt,
            .{ .exited = .{ .exit_code = code } },
            .{
                .finished_at = probe.finished_at,
                .stdout = .{ .bytes = @intCast(probe.output.len) },
            },
            finishSync(job, .exited, code, probe.finished_at orelse ctx.now),
        );
        const settled_status = settled.statusText();
        const proven = settled.settlement.proves();

        const session_gone = Tmux.killSession(executor, ctx.arena, session) catch |err|
            fatalTmux(err, executor, session);
        Cli.releaseClaim();

        // A surviving session is a real failure even though the outcome is
        // known: `ensure` treats one as ready, so the next launch under this
        // name would type into the dead job's shell.
        const exit = finishedDuringKillExit(proven, session_gone, settled.cache);
        const ok = exit == .ok;
        const hint: ?[]const u8 = if (!proven) unproven: {
            // The evidence is sitting on the host and `reconcile --from-log`
            // accepts exactly it, so name the command that would take it.
            const a = attempt orelse break :unproven "the host holds this job's exit status, but there is no recorded attempt to settle it against";
            break :unproven std.fmt.allocPrint(
                ctx.arena,
                "the host holds this job's exit status but the ledger records the attempt as {s}; settle it with 'terminus request reconcile {s} --from-log'",
                .{ settled_status, a.request_id },
            ) catch "the host holds this job's exit status but the ledger does not; settle it with 'terminus request reconcile <request-id> --from-log'";
        } else if (cacheError(ctx, job.name, settled.cache)) |text|
            text
        else if (!session_gone)
            "the job's outcome is recorded, but its tmux session is still present; remove it on the host before relaunching under this name"
        else
            null;

        switch (ctx.out.format) {
            .json => try ctx.out.json(.{
                .ok = ok,
                .action = "already_finished",
                .job = job.name,
                .status = settled_status,
                .exitCode = code,
                .outcomeProven = proven,
                .finishedAt = probe.finished_at,
                .observedAt = ctx.now,
                .sessionCleanedUp = session_gone,
                // Nothing was cancelled: the job had already ended on its own.
                .cancellationProven = false,
                .resultRecord = probe.sidecar.code(),
                .resultRecordError = resultRecordError(ctx, probe.sidecar),
                .requestId = if (attempt) |a| a.request_id else null,
                .hint = hint,
            }),
            .human => {
                if (!proven)
                    try ctx.out.print(
                        "job '{s}' had already finished (exit {d}) on the host, but its attempt is recorded as {s}; nothing here settled it\n",
                        .{ job.name, code, settled_status },
                    )
                else if (session_gone)
                    try ctx.out.print(
                        "job '{s}' had already finished (exit {d}); recorded its outcome and cleaned up the session\n",
                        .{ job.name, code },
                    )
                else
                    try ctx.out.print(
                        "job '{s}' had already finished (exit {d}); its outcome is recorded, but the session could not be cleaned up\n",
                        .{ job.name, code },
                    );
                // Printed here rather than only in the JSON arm. The middle
                // sentence above is a clean success report, and with a refused
                // cache write behind it the operator read "recorded its outcome
                // and cleaned up the session" while the row that gates the next
                // launch still said the job was live — with `$?` zero and
                // nothing on screen to suggest otherwise.
                if (hint) |text| try ctx.out.print("  {s}\n", .{text});
            },
        }
        switch (exit) {
            .ok => {},
            // Unproven outranks a surviving session: "we do not know what the
            // ledger holds for this work" is the conclusion that forbids a
            // retry, and the two sibling branches already exit 75 here.
            .indeterminate => {
                try ctx.out.flush();
                Cli.failIndeterminateAfterOutput(if (attempt) |a| a.request_id else job.name);
            },
            .failure => {
                try ctx.out.flush();
                std.process.exit(Cli.exit_code.failure);
            },
        }
        return;
    }

    // No outcome to preserve *yet*. The kill can change that.
    //
    // A job can finish on its own in the window between the probe above and
    // the kill below, and when it does the wrapper writes its result file.
    // Killing the session does not remove that file. So settling
    // `indeterminate` on the strength of the first probe would be recording
    // "we do not know" while the proof sat on disk — and then charging the
    // caller a reconcile for it. Worse on the `job rm --discard-evidence`
    // path, which would delete the record it never read.
    //
    // Hence: kill, prove the session is gone, then look again.
    const session_gone = Tmux.killSession(executor, ctx.arena, session) catch |err|
        fatalTmux(err, executor, session);

    const final: FinalLook = if (session_gone)
        finalProbe(ctx.arena, executor, session, job.name, job.sentinel, if (attempt) |a| a.request_id else null)
    else
        .{};
    if (final.upgrade) |after| return reportFinishedDuringKill(ctx, store, job, attempt, after, session_gone, claim);

    // The reading this command ends on. The second look happened later and, on
    // the path that matters here, is the only one that saw the document at all
    // — the job wrote it during the SSH round trip. Reporting the pre-kill
    // reading instead would put `"resultRecord":"absent"` on a kill that had
    // just refused to read one.
    const reading: Tmux.SidecarReading = if (final.refusal) |seen| seen.sidecar else probe.sidecar;

    const capability = Core.supervisor.shell_capability;
    const can_prove = Core.supervisor.Requirement.verified_cancellation.satisfiedBy(capability);

    var execution = if (attempt) |a|
        Core.execution.attach(store, ctx.arena, ctx.io, a.request_id) catch |err|
            Cli.storeFatal(store, err)
    else
        null;
    const terminal: Core.Store.op_state.Terminal = if (final.refusal) |seen|
        // Checked ahead of the cancellation, and it outranks it. `killSession`
        // proving the pane is gone says the session stopped; it says nothing
        // about *why*, and here the job left a verdict behind while we were
        // stopping it. Recording `remote_cancel_confirmed` would settle a
        // proven terminal and release the scope over a document at this
        // request's own address that we have just declined to read — the one
        // thing every refused path is forbidden to do.
        .{ .indeterminate = .{
            .reason = std.fmt.allocPrint(
                ctx.arena,
                "the job's session was killed, and a second look found its result record present and unusable: the sentinel in its log says exit {d}, but {s}. The stronger of the two records cannot be read, so the weaker one cannot be checked against it and its exit status was not read as this job's outcome",
                .{ seen.declined.sentinel_exit_code, defectSentence(ctx, seen.sidecar) },
            ) catch "the job's session was killed and its result record is present and unusable, so the exit status in its log was not read as its outcome",
            .last_observed = if (execution) |e| e.status else .remote_started,
        } }
    else if (session_gone and can_prove)
        .{ .remote_cancel_confirmed = .{
            .pid = null,
            .term_sent = true,
            .kill_sent = true,
            .absence_verified_at = ctx.now,
            .verification_method = "supervisor verified the process group is gone",
        } }
    else
        .{ .indeterminate = .{
            .reason = if (session_gone)
                "job session killed, but this supervisor cannot prove the process tree stopped (a daemonized or disowned child survives its pane)"
            else
                "kill issued but the job session is still present",
            .last_observed = if (execution) |e| e.status else .remote_started,
        } };
    holdClaim(claim, wallClockSeconds(ctx.io));
    const settled = settleObserved(
        ctx,
        store,
        if (execution) |*e| e else null,
        attempt,
        terminal,
        .{ .result_record = resultRecordOf(ctx, reading) },
        finishSync(job, .killed, null, ctx.now),
    );
    // The remote work is done on this branch — the kill and the re-probe are
    // both behind us — so the scope goes back with the settlement.
    Cli.releaseClaim();
    const settled_status = settled.statusText();

    // A refusal is never a proven cancellation. The pane really did go away,
    // but what this command would be claiming is that it *stopped* the work,
    // and the record it just refused says the work ended on its own with a
    // verdict nobody could check.
    const proven = final.refusal == null and session_gone and can_prove;
    const cache_error = cacheError(ctx, job.name, settled.cache);
    const hint: ?[]const u8 = if (final.refusal != null)
        // Not `--from-log`: that reconcile reads these same two records and
        // will refuse for the same reason this kill did.
        "the result record is unusable, so no mechanical reconcile can settle this; check the host and use 'terminus request reconcile <request-id> --override'"
    else if (proven)
        null
    else
        Core.supervisor.Requirement.verified_cancellation.explain();
    switch (ctx.out.format) {
        .json => try ctx.out.json(.{
            .ok = proven and cache_error == null,
            .action = "killed",
            .job = job.name,
            .status = settled_status,
            .sessionGone = session_gone,
            .cancellationProven = proven,
            .resultRecord = reading.code(),
            .resultRecordError = resultRecordError(ctx, reading),
            .requestId = if (attempt) |a| a.request_id else null,
            .cacheError = cache_error,
            .hint = hint,
        }),
        .human => {
            if (final.refusal) |seen| {
                try ctx.out.print(
                    "job '{s}': session killed; its log sentinel says exit {d} but its result record is present and unusable ({s}), so its outcome is unknown\n",
                    .{ job.name, seen.declined.sentinel_exit_code, seen.sidecar.code() },
                );
            } else if (proven) {
                try ctx.out.print("killed job '{s}' (absence verified)\n", .{job.name});
            } else if (session_gone) {
                try ctx.out.print("job '{s}': session killed, but absence of the process tree is unproven\n", .{job.name});
            } else {
                try ctx.out.print("kill issued for '{s}' but the session is still present\n", .{job.name});
            }
            if (cache_error) |text| try ctx.out.print("  {s}\n", .{text});
        },
    }
    if (!proven) {
        try ctx.out.flush();
        Cli.failIndeterminateAfterOutput(if (attempt) |a| a.request_id else job.name);
    }
    // A proven cancellation whose cache row could not be brought along is
    // still a failure of this command: the name it just stopped will go on
    // refusing the next launch, and nothing else will explain why.
    if (cache_error != null) {
        try ctx.out.flush();
        std.process.exit(Cli.exit_code.failure);
    }
}

/// One last look for an outcome, after the session is proven gone.
///
/// Two answers, and they are never both present. `upgrade` is a probe that
/// establishes something the first one did not: an exit code, with neither
/// durable record refusing. `refusal` is the opposite finding — a document
/// turned up at this request's own address between the two looks, it is
/// unusable, and the log sentinel beside it was willing to answer. Everything
/// else — a probe that errors, a still-unknown outcome, a fresh disagreement —
/// leaves both null and lets the caller fall through to the path it was
/// already on, which is the conservative one.
///
/// Not fatal on error. The kill has already happened; failing here costs only
/// the chance to *upgrade* the answer, and turning that into a hard failure
/// would make a flaky read worse than no read.
const FinalLook = struct {
    /// A probe good enough to settle from. Structurally never carries a
    /// refusal or a conflict, so a caller cannot reach one through it.
    upgrade: ?Tmux.JobProbe = null,
    /// What the second look refused, when it refused something.
    ///
    /// Reported separately instead of by handing back the whole probe. The
    /// probe would then be a value carrying both a refusal and — in the caller
    /// that assigns it over the first probe — the power to replace an outcome
    /// that had already been established, which is exactly the promotion
    /// `finalProbe` exists to forbid.
    refusal: ?Refusal = null,

    const Refusal = struct {
        declined: Tmux.JobProbe.Refused,
        /// The defect that caused it. Carried alongside because a reason
        /// naming the declined exit code without naming what declined it sends
        /// an operator nowhere.
        sidecar: Tmux.SidecarReading,
    };
};

fn finalProbe(
    arena: std.mem.Allocator,
    executor: Core.Executor,
    session: []const u8,
    job_name: []const u8,
    sentinel: []const u8,
    request_id: ?[]const u8,
) FinalLook {
    const probe = Tmux.probeTail(
        executor,
        arena,
        session,
        sentinel,
        request_id,
        probe_tail_bytes,
    ) catch |err| {
        std.debug.print(
            "terminus: could not re-read job '{s}' after killing its session: {s}; " ++
                "reporting the cancellation without it\n",
            .{ job_name, @errorName(err) },
        );
        return .{};
    };
    // A disagreement between the two durable records carries no exit code —
    // `Tmux.readingOf` refuses to pick a winner — and neither does a defective
    // record beside a sentinel, for the same reason. So today the last line
    // alone would reject both. They are written out anyway because the three
    // say different things: one is "there is nothing here to upgrade to", the
    // others are "there is something here and it must not be used". If the
    // probe ever learns to report a preferred code alongside a refusal, these
    // two lines are what stop that from silently settling a killed job.
    if (probe.conflict != null) return .{};
    // Rejected as an upgrade and still reported, which is the half that was
    // missing. Returning a bare null here threw the finding away: the caller
    // stayed on the pre-kill probe, `unreconcilable` came out false, and
    // `job rm` printed `{"action":"removed","ok":true}` with a hint naming a
    // `--from-log` reconcile that reads these same two records and refuses for
    // the very reason this removal never mentioned. The exit code then depended
    // only on which of the two probes happened to see the defect first, and the
    // receipt — the only record that survives a removal — never named the
    // document at all.
    if (probe.refused) |declined| return .{ .refusal = .{
        .declined = declined,
        .sidecar = probe.sidecar,
    } };
    if (probe.exit_code == null) return .{};
    return .{ .upgrade = probe };
}

test finalProbe {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // `probeTail`'s wire shape: the sidecar document, the split marker alone
    // on its line, the log's byte count, then the tail window.
    const marker = "__TERMINUS_PROBE_SPLIT__\n";
    const finished =
        "{\"v\":1,\"requestId\":\"01ABCDEFGHJKMNPQRSTVWXYZ00\",\"exitCode\":7,\"finishedAt\":1750}\n" ++
        marker ++ "12\n" ++ "building...\n";
    // The same job still running: no sidecar was written, and the sentinel is
    // not in the window either.
    const unfinished = "\n" ++ marker ++ "12\n" ++ "building...\n";
    // Both durable records answered and they disagree. This is the dangerous
    // one: it *looks* like an upgrade, and taking it would settle the job on
    // whichever record the reader happened to prefer.
    const conflicting =
        "{\"v\":1,\"requestId\":\"01ABCDEFGHJKMNPQRSTVWXYZ00\",\"exitCode\":7,\"finishedAt\":1750}\n" ++
        marker ++ "20\n" ++ "__TERMINUS_END_7__:3\n";
    // The job reached its own end during the round trip and left a document no
    // shell could have written, with its sentinel still in the window. Not an
    // upgrade — nothing here may settle — but not nothing either, and the
    // difference is the whole point: the caller has to be told, or it reports a
    // clean cancellation over a record it could not read.
    const defective =
        "{\"v\":1,\"requestId\":\"01ABCDEFGHJKMNPQRSTVWXYZ00\",\"exitCode\":9000,\"finishedAt\":1750}\n" ++
        marker ++ "20\n" ++ "__TERMINUS_END_7__:3\n";

    const empty = try arena.alloc(u8, 0);
    const Case = struct {
        what: []const u8,
        step: Core.Scripted.Step,
        /// What the second look is allowed to hand back. Exactly one of the
        /// three, because an upgrade and a refusal must never arrive together.
        want: enum { upgrade, nothing, refusal },
    };
    const cases = [_]Case{
        .{
            .what = "a job that finished while we were killing it",
            .step = .{ .reply = .{
                .exit_code = 0,
                .stdout = try arena.dupe(u8, finished),
                .stderr = empty,
            } },
            .want = .upgrade,
        },
        .{
            // No outcome to upgrade to. Falling through leaves the caller on
            // the cancellation path it was already taking.
            .what = "a job whose end is still unrecorded",
            .step = .{ .reply = .{
                .exit_code = 0,
                .stdout = try arena.dupe(u8, unfinished),
                .stderr = empty,
            } },
            .want = .nothing,
        },
        .{
            // The read failed mid-stream. A kill that already happened must
            // not be reported *better* because we could not look again.
            .what = "a probe that could not be read at all",
            .step = .{ .transport_error = error.ReadFailed },
            .want = .nothing,
        },
        .{
            // Caught today by the missing exit code rather than by the
            // conflict check itself; see `finalProbe`. What matters here is
            // the observable: a disagreement never upgrades a cancellation.
            .what = "two durable records that disagree",
            .step = .{ .reply = .{
                .exit_code = 0,
                .stdout = try arena.dupe(u8, conflicting),
                .stderr = empty,
            } },
            .want = .nothing,
        },
        .{
            .what = "a result record that turned up defective during the kill",
            .step = .{ .reply = .{
                .exit_code = 0,
                .stdout = try arena.dupe(u8, defective),
                .stderr = empty,
            } },
            .want = .refusal,
        },
    };

    for (cases) |case| {
        // `probeTail` reads the tail, then asks whether the session is still
        // there. Exit 1 = gone, which is where a post-kill probe starts.
        var scripted = Core.Scripted.init(arena, &.{
            case.step,
            .{ .reply = .{ .exit_code = 1, .stdout = empty, .stderr = empty } },
        });
        const got = finalProbe(
            arena,
            scripted.executor(),
            "terminus-job-build",
            "build",
            "__TERMINUS_END_7__",
            "01ABCDEFGHJKMNPQRSTVWXYZ00",
        );
        switch (case.want) {
            .upgrade => {
                try t.expectEqual(@as(?i32, 7), got.upgrade.?.exit_code);
                // The remote clock reading has to survive: it is the only
                // reason this second look beats settling as a cancellation.
                try t.expectEqual(@as(?i64, 1750), got.upgrade.?.finished_at);
                try t.expectEqual(@as(?FinalLook.Refusal, null), got.refusal);
            },
            .nothing => {
                try t.expectEqual(@as(?Tmux.JobProbe, null), got.upgrade);
                try t.expectEqual(@as(?FinalLook.Refusal, null), got.refusal);
            },
            .refusal => {
                // Never promoted: the rule `finalProbe` enforces is unchanged,
                // and a caller that assigned this over its first probe could
                // settle a killed job from a record nobody could read.
                std.testing.expectEqual(@as(?Tmux.JobProbe, null), got.upgrade) catch |err| {
                    std.debug.print("{s} was promoted to an upgrade\n", .{case.what});
                    return err;
                };
                // …and the finding still travels, which is what the caller
                // needs to stop reporting `ok: true` over it. Named rather than
                // unwrapped: dropping the refusal is the regression this case
                // exists for, and a null unwrap kills the test process, so
                // every gate after it stops running too.
                const seen = got.refusal orelse {
                    std.debug.print("{s} was reported as nothing at all\n", .{case.what});
                    return error.RefusedReadingWasSwallowed;
                };
                // Both halves: the verdict that was declined, and the defect
                // that declined it.
                try t.expectEqual(@as(i32, 3), seen.declined.sentinel_exit_code);
                try t.expectEqualStrings("exit_code_out_of_range", seen.sidecar.code());
            },
        }
    }
}

/// The job ended by itself while we were killing it, and left its receipt.
///
/// Reported as its own action rather than folded into `already_finished`,
/// because the two are answers to different questions: one says the kill was
/// unnecessary, this says the kill raced with the job and lost. The exit code
/// is the real one either way, and it is the reason nothing here is
/// `indeterminate`.
fn reportFinishedDuringKill(
    ctx: *Cli.Ctx,
    store: *Store,
    job: Store.jobs.Job,
    attempt: ?Store.job_attempts.Attempt,
    probe: Tmux.JobProbe,
    session_gone: bool,
    claim: Claim,
) !void {
    const code = probe.exit_code.?;
    var execution = if (attempt) |a|
        Core.execution.attach(store, ctx.arena, ctx.io, a.request_id) catch |err|
            Cli.storeFatal(store, err)
    else
        null;
    holdClaim(claim, wallClockSeconds(ctx.io));
    const settled = settleObserved(
        ctx,
        store,
        if (execution) |*e| e else null,
        attempt,
        .{ .exited = .{ .exit_code = code } },
        .{
            // The host's own clock when it reported one. Null otherwise —
            // the ledger's `finished_at` is a remote reading or nothing.
            .finished_at = probe.finished_at,
            .stdout = .{ .bytes = @intCast(probe.output.len) },
        },
        finishSync(job, .exited, code, probe.finished_at orelse ctx.now),
    );
    Cli.releaseClaim();
    const settled_status = settled.statusText();
    const proven = settled.settlement.proves();
    const cache_error = cacheError(ctx, job.name, settled.cache);

    switch (ctx.out.format) {
        .json => try ctx.out.json(.{
            .ok = proven and cache_error == null,
            .action = "finished_during_kill",
            .job = job.name,
            .status = settled_status,
            .exitCode = code,
            .outcomeProven = proven,
            .finishedAt = probe.finished_at,
            .observedAt = ctx.now,
            .sessionGone = session_gone,
            // Nothing was cancelled: the job reached its own end first.
            .cancellationProven = false,
            .resultRecord = probe.sidecar.code(),
            .resultRecordError = resultRecordError(ctx, probe.sidecar),
            .requestId = if (attempt) |a| a.request_id else null,
            .cacheError = cache_error,
            .hint = if (proven) cache_error else @as(
                ?[]const u8,
                "the host holds this job's exit status but the ledger does not; settle it with 'terminus request reconcile <request-id> --from-log'",
            ),
        }),
        .human => {
            try ctx.out.print(
                "job '{s}' finished on its own (exit {d}) while its session was being killed; recorded that, not a cancellation\n",
                .{ job.name, code },
            );
            if (cache_error) |text| try ctx.out.print("  {s}\n", .{text});
        },
    }
    if (!proven) {
        try ctx.out.flush();
        Cli.failIndeterminateAfterOutput(if (attempt) |a| a.request_id else job.name);
    }
    if (cache_error != null) {
        try ctx.out.flush();
        std.process.exit(Cli.exit_code.failure);
    }
}

/// Forgets a job's name while preserving what can still be proven.
///
/// The original version killed the session — which also deleted the remote log
/// — then settled `indeterminate` and reported `{ok:true, "removed"}`. That
/// destroyed the only mechanical evidence of how the job ended and left a human
/// override as the sole way to ever settle it, while telling the caller
/// everything went fine.
///
/// The version after that kept the log but faked the safety check: on the
/// `--discard-evidence` branch `cleared` was the literal `true`, so the guard
/// reading "refusing to forget a job that may still be running" was dead code
/// on precisely the branch that also deleted the evidence. A job whose session
/// survived the kill could lose its log, its result record and its local row
/// while the process kept running.
///
/// So the order below is the whole point, and it is the same for both
/// branches: probe, kill, *prove the session is gone*, and only then destroy
/// anything. Nothing is deleted on a session that is still there — not the
/// log, not the sidecar, not the row.
fn removeJob(
    ctx: *Cli.Ctx,
    store: *Store,
    executor: Core.Executor,
    session: []const u8,
    job: Store.jobs.Job,
    attempt: ?Store.job_attempts.Attempt,
    claim: Claim,
    parsed: *const Cli.Args.Parsed,
) !void {
    // The scope was taken in `jobCmd`, before the connection was opened, and
    // is held through the kill, the evidence decision and the settlement.
    const discard = parsed.boolean("discard-evidence");

    // Look before destroying: if the outcome is provable right now, it need
    // never become an override. Re-read after the kill (below), because the
    // window between the two is long enough for the job to finish in.
    var probe = Tmux.probeTail(
        executor,
        ctx.arena,
        session,
        job.sentinel,
        if (attempt) |a| a.request_id else null,
        probe_tail_bytes,
    ) catch |err| fatalTmux(err, executor, session);

    // The real boolean, on both branches. `killSession` never touches the log;
    // destroying evidence is a separate act below, gated on this answer.
    const cleared = Tmux.killSession(executor, ctx.arena, session) catch |err|
        fatalTmux(err, executor, session);
    if (!cleared) fatal(
        "job '{s}' session is still present after cleanup; refusing to forget a job that may still be running. Nothing was deleted — no log, no result record, no local row. Inspect it with 'tmux attach -t {s}' on the host",
        .{ job.name, try Tmux.targetName(ctx.arena, session) },
    );

    // Look again before destroying anything.
    //
    // The probe above ran before the kill, and a job can reach its own end in
    // between — the wrapper writes its result file when it does, and killing
    // the session does not remove that file. Acting on the first probe alone
    // meant `--discard-evidence` could delete a receipt written seconds
    // earlier and then settle `indeterminate` for want of it: the command
    // destroys the proof and bills the caller for its absence.
    const final = finalProbe(ctx.arena, executor, session, job.name, job.sentinel, if (attempt) |a| a.request_id else null);
    if (final.upgrade) |after| probe = after;

    // What is at the result record's address now.
    //
    // The second look is the later of the two and, on the path this exists
    // for, the only one that saw a document at all — the job reached its own
    // end during the SSH round trip. Kept beside the probe rather than written
    // into it: a `JobProbe` whose `exit_code` is set while its reading is
    // defective is a value `readingOf` can never produce, and every caller
    // downstream is entitled to assume it cannot exist.
    const reading: Tmux.SidecarReading = if (final.refusal) |seen| seen.sidecar else probe.sidecar;

    // The refusal this removal acts on, from whichever look found one.
    //
    // Adopted from the second look only when the first probe established
    // nothing of its own. An exit code or a contradiction read before the kill
    // is a fact about this job that a later reading of the other record does
    // not erase, and letting the refusal displace it would decide the removal
    // by which of the two probes happened to look first — the same coin flip
    // this change exists to remove, mirrored. What the second look found still
    // reaches the receipt through `reading` in every case.
    const declined: ?Tmux.JobProbe.Refused = probe.refused orelse blk: {
        if (probe.exit_code != null or probe.conflict != null) break :blk null;
        break :blk if (final.refusal) |seen| seen.declined else null;
    };

    if (discard) {
        // Only now, with the session proven gone. A live pane recreates the
        // log through `pipe-pane`, so deleting it under a surviving session
        // would leave a file that quietly comes back holding a partial
        // history starting mid-job.
        Tmux.removeLog(executor, ctx.arena, session) catch |err|
            fatal("job '{s}': its session is stopped but its log could not be deleted: {s} ({s}); nothing was removed locally, so the job is still tracked", .{ job.name, executor.errorMessage(), @errorName(err) });
        // The sidecar is evidence too. Leaving it behind after being told to
        // discard evidence would make the next `reconcile --from-log` settle
        // from a file the caller believes is gone. A half-discarded evidence
        // set must not be reported as a clean removal, so this is fatal.
        if (attempt) |a| Tmux.removeResult(executor, ctx.arena, a.request_id) catch |err|
            fatal("job '{s}': its log was deleted but its result record could not be: {s} ({s}); the evidence set is now half gone. Delete {s}.json under ~/.terminus/results by hand, then re-run this command", .{ job.name, executor.errorMessage(), @errorName(err), a.request_id });
    }

    // The settlement and the deletion are one transaction. Split apart, a
    // delete that outlived a failed settlement left an unsettled attempt with
    // no local row naming it, and a settlement whose delete was refused
    // reported `{"action":"removed","ok":true}` while the row was still there
    // — which is exactly what happened when the row belonged to a different
    // launcher by then.
    //
    // The grounds are `session_proven_gone`, and they are earned above: this
    // command killed the session and refused to go any further until
    // `killSession` said it was gone. That is the only reason it may delete a
    // row that still says `running`.
    var execution = if (attempt) |a|
        Core.execution.attach(store, ctx.arena, ctx.io, a.request_id) catch |err|
            Cli.storeFatal(store, err)
    else
        null;
    const terminal: Core.Store.op_state.Terminal = if (probe.conflict) |clash|
        // Two mechanical records contradicting each other is not an outcome,
        // so this stays unproven, exits 75, and the caller owes a reconcile.
        .{ .indeterminate = .{
            .reason = std.fmt.allocPrint(
                ctx.arena,
                "job removed while its two durable records disagreed: its result file says exit {d}, the sentinel in its log says exit {d}",
                .{ clash.result_exit_code, clash.sentinel_exit_code },
            ) catch "job removed while its result file and its log sentinel reported different exit codes",
            .last_observed = if (execution) |e| e.status else .remote_started,
        } }
    else if (declined) |refusal|
        // The other unreconcilable shape, and it ends the same way. A document
        // at this request's own address is unusable, so the sentinel beside it
        // cannot be checked and `job rm` must not record `exited` from it. The
        // reason names the code it declined, because "no outcome was
        // established" and "an outcome was there and refused" send the operator
        // to different places and the receipt is the only place that survives.
        .{ .indeterminate = .{
            .reason = std.fmt.allocPrint(
                ctx.arena,
                "job removed while its result record was unusable: the sentinel in its log says exit {d}, but {s}",
                .{ refusal.sentinel_exit_code, defectSentence(ctx, reading) },
            ) catch "job removed while its result record was present and unusable, so the exit status in its log was not read as its outcome",
            .last_observed = if (execution) |e| e.status else .remote_started,
        } }
    else if (probe.exit_code) |code|
        .{ .exited = .{ .exit_code = code } }
    else
        .{ .indeterminate = .{
            .reason = if (discard)
                "job removed with --discard-evidence; the log was deleted, so its outcome can no longer be established mechanically"
            else
                "job removed before its outcome was established; the log is retained for 'request reconcile --from-log'",
            .last_observed = if (execution) |e| e.status else .remote_started,
        } };
    holdClaim(claim, wallClockSeconds(ctx.io));
    const settled = settleObserved(
        ctx,
        store,
        if (execution) |*e| e else null,
        attempt,
        terminal,
        .{
            .finished_at = probe.finished_at,
            // The reading goes into the receipt on every removal path, not
            // only the refused one. `job rm` deletes the local row, so the
            // receipt is the only record that outlives the command — and a
            // removal that never mentions the document the second look read is
            // how an operator comes to find nothing on the host and no note
            // saying anybody had looked.
            .result_record = resultRecordOf(ctx, reading),
        },
        .{ .forget = .{
            .expected = job.removeExpectation(),
            .grounds = .session_proven_gone,
        } },
    );
    Cli.releaseClaim();
    // `proven` is about the outcome, not about the deletion: it is true only
    // when a real exit code reached the ledger. A removal that settled
    // `indeterminate` deleted the row just the same, and saying otherwise
    // would turn the unknown into a success.
    const proven = probe.conflict == null and probe.exit_code != null and settled.settlement.proves();
    // Both shapes mean the same thing to the caller: the evidence is on the
    // host, it is not trustworthy, and re-reading it will not help. `job rm`
    // used to report a defective record as an ordinary unproven removal —
    // `ok: true`, exit 0, and a hint naming `reconcile --from-log`, which reads
    // these same two records and now refuses for the same reason the removal
    // did. Telling an operator to run a command that cannot succeed is the
    // pseudo-success this closes.
    const unreconcilable = probe.conflict != null or declined != null;
    const report = removalReport(settled.cache, proven, discard, unreconcilable);
    const removed = report.removed;
    const settled_status = if (attempt == null) "unchanged" else settled.statusText();
    const cache_error = cacheError(ctx, job.name, settled.cache);

    const ok = report.ok;
    const hint: ?[]const u8 = if (cache_error) |text|
        text
    else if (proven)
        null
    else if (probe.conflict != null)
        "the job's two durable records disagree; no mechanical reconcile can settle this — use 'terminus request reconcile <request-id> --override'"
    else if (declined != null)
        "the job's result record is present and unusable, so the exit status in its log could not be checked against it; no mechanical reconcile can settle this — use 'terminus request reconcile <request-id> --override'"
    else if (discard)
        null
    else
        "outcome still unknown; settle it with 'terminus request reconcile <request-id> --from-log'";
    switch (ctx.out.format) {
        .json => try ctx.out.json(.{
            .ok = ok,
            // What actually happened to the row, which is the fact this
            // command exists to report. `"removed"` on a row that survived was
            // the shape that had `job rm` claim it had forgotten another
            // launcher's running job.
            .action = report.action,
            .job = job.name,
            .status = settled_status,
            .outcomeProven = proven,
            .rowRemoved = removed,
            .evidenceRetained = !discard,
            .attemptRetained = attempt != null,
            .conflict = ConflictJson.from(probe.conflict),
            .requestId = if (attempt) |a| a.request_id else null,
            .cacheError = cache_error,
            .hint = hint,
        }),
        .human => {
            if (!removed) {
                try ctx.out.print(
                    "job '{s}' was NOT removed: {s}\n",
                    .{ job.name, cache_error orelse "its row is no longer the row this command read" },
                );
            } else if (proven) {
                try ctx.out.print("removed job '{s}' (outcome recorded from its log)\n", .{job.name});
            } else if (probe.conflict) |clash| {
                try ctx.out.print(
                    "removed job '{s}'; its result file says exit {d} while its log sentinel says exit {d}, so its outcome is unknown\n",
                    .{ job.name, clash.result_exit_code, clash.sentinel_exit_code },
                );
            } else if (declined) |refusal| {
                try ctx.out.print(
                    "removed job '{s}'; its log sentinel says exit {d} but its result record is present and unusable ({s}), so its outcome is unknown\n",
                    .{ job.name, refusal.sentinel_exit_code, reading.code() },
                );
            } else if (discard) {
                try ctx.out.print("removed job '{s}' and deleted its log; its outcome can no longer be proven\n", .{job.name});
            } else {
                try ctx.out.print("removed job '{s}'; outcome unknown, log retained for reconcile\n", .{job.name});
            }
            // A proven or unreconcilable removal takes an earlier branch, so
            // the deletion has to be stated on its own rather than folded into
            // the discard branch — otherwise `--discard-evidence` on a job
            // whose records disagreed, or whose result record could not be
            // read, never tells the operator that those records are now gone.
            if (discard and (proven or unreconcilable))
                try ctx.out.print("  its log and result record were deleted; nothing can read them again\n", .{});
        },
    }
    if (!ok) {
        try ctx.out.flush();
        // A row that survived is a plain failure and safe to retry: nothing
        // remote is unknown because of it. An unknown *outcome* is not, and
        // outranks it.
        if (removed) Cli.failIndeterminateAfterOutput(if (attempt) |a| a.request_id else job.name);
        std.process.exit(Cli.exit_code.failure);
    }
}

/// One row of `job ls --json`.
///
/// A projection rather than the `Store.jobs.Job` row itself, for one field.
/// The row's `finished_at` falls back to local time when the host reported
/// none, and serializing the row verbatim published it under a name one
/// character away from `job status`'s `finishedAt` — which is documented as a
/// remote clock reading that is *never* backfilled with local time. Two
/// near-identical keys with opposite meanings, side by side in the same tool's
/// output, is a trap; `cachedFinishedAt` says what it is.
const ListedJob = struct {
    name: []const u8,
    command: []const u8,
    sentinel: []const u8,
    status: Store.jobs.Status,
    exitCode: ?i64,
    /// Local seconds when we last wrote this row, or the host's finish time
    /// if it happened to report one. Not authoritative: ask `job status`.
    cachedFinishedAt: ?i64,
    createdAt: i64,
    ownerRequestId: ?[]const u8,
};

fn listedJobs(ctx: *Cli.Ctx, rows: []const Store.jobs.Job) ![]ListedJob {
    const out = try ctx.arena.alloc(ListedJob, rows.len);
    for (rows, out) |row, *slot| slot.* = .{
        .name = row.name,
        .command = row.command,
        .sentinel = row.sentinel,
        .status = row.status,
        .exitCode = row.exit_code,
        .cachedFinishedAt = row.finished_at,
        .createdAt = row.created_at,
        .ownerRequestId = row.owner_request_id,
    };
    return out;
}

fn listJobs(
    ctx: *Cli.Ctx,
    store: *Store,
    server_id: i64,
    server_name: []const u8,
    parsed: *const Cli.Args.Parsed,
) !void {
    const all = Store.jobs.list(store, ctx.arena, server_id) catch |err| Cli.storeFatal(store, err);
    const only_active = parsed.boolean("active");
    const name_filter = parsed.flag("name");
    const limit: usize = if (parsed.flag("limit")) |l|
        std.fmt.parseInt(usize, l, 10) catch fatal("invalid --limit '{s}'", .{l})
    else
        20;

    var filtered: std.ArrayList(Store.jobs.Job) = .empty;
    for (all) |j| {
        if (only_active and !j.status.live()) continue;
        if (name_filter) |nf| if (std.mem.indexOf(u8, j.name, nf) == null) continue;
        try filtered.append(ctx.arena, j);
    }
    const total = filtered.items.len;
    const shown = filtered.items[0..@min(limit, total)];

    switch (ctx.out.format) {
        // Cached snapshot: these are last-observed values, not a live probe.
        .json => try ctx.out.json(.{
            .ok = true,
            .server = server_name,
            .jobs = try listedJobs(ctx, shown),
            .total = total,
            .shown = shown.len,
            .source = "cache",
        }),
        .human => {
            if (total == 0) return ctx.out.print("no jobs on '{s}'\n", .{server_name});
            for (shown) |j| {
                const first_line = std.mem.sliceTo(j.command, '\n');
                const brief = if (first_line.len > 60) first_line[0..60] else first_line;
                try ctx.out.print("{s}\t{t}\texit={?d}\t{s}\n", .{ j.name, j.status, j.exit_code, brief });
            }
            if (shown.len < total)
                try ctx.out.print("... {d} more (raise --limit to see all)\n", .{total - shown.len});
        },
    }
}

/// What was actually launched, from the immutable attempt record.
fn inspectJob(
    ctx: *Cli.Ctx,
    store: *Store,
    server_id: i64,
    job_name: []const u8,
    parsed: *const Cli.Args.Parsed,
) !void {
    const history = Store.job_attempts.history(store, ctx.arena, server_id, job_name) catch |err|
        Cli.storeFatal(store, err);
    if (history.len == 0) fatal("no recorded attempts for job '{s}'", .{job_name});
    const latest = history[0];

    switch (ctx.out.format) {
        .json => try ctx.out.json(.{
            .ok = true,
            .job = job_name,
            .attempt = latest.attempt_no,
            .totalAttempts = history.len,
            .requestId = latest.request_id,
            .cwd = latest.cwd,
            .interpreter = latest.interpreter,
            .shell = latest.shell,
            // Redacted body plus the hash of the raw text: enough to answer
            // "is this the script that ran?" without persisting credentials.
            .scriptSha256 = latest.script_sha256,
            .scriptBytes = latest.script_bytes,
            .script = if (parsed.boolean("show-script")) latest.script_body_redacted else null,
            .entryPath = latest.entry_path,
            .tmuxSession = latest.tmux_session,
            .createdAt = latest.created_at,
        }),
        .human => {
            try ctx.out.print("job '{s}' attempt {d} of {d}\n", .{ job_name, latest.attempt_no, history.len });
            try ctx.out.print("  request : {s}\n", .{latest.request_id});
            try ctx.out.print("  cwd     : {s}\n", .{latest.cwd orelse "(none)"});
            try ctx.out.print("  script  : {?s} ({?d} bytes)\n", .{ latest.script_sha256, latest.script_bytes });
            if (parsed.boolean("show-script")) {
                try ctx.out.print("---\n{s}\n---\n", .{latest.script_body_redacted orelse ""});
            }
        },
    }
}

/// The job-scope lease a `job kill` or `job rm` holds while it works.
///
/// The old shape was `requireNoForeignLease`: one read of `conflictFor` at the
/// top of each command and nothing after it. That is a check, not a claim, and
/// it was worth nothing twice over. It compared `policy.ownerToken`, which is
/// one token per *machine*, so a second agent on this machine was never a
/// foreign owner at all; and it took no lease of its own, so even between two
/// machines the answer went stale the instant it was read — the whole of
/// probe → kill → settle ran with nothing held.
///
/// Now the command takes the lease before its first remote call and holds it
/// across all three steps. Ownership is `request_id`, minted per invocation, so
/// two `job kill`s on one machine are two owners; `--force` is an audited
/// `takeover` that displaces the incumbent and records it, never a way to skip
/// the lease; and the claim is released at settle, from `Cli.releaseClaim` on
/// every process-ending path, or by its TTL if the process is killed outright.
const Claim = struct {
    store: *Store,
    server_id: i64,
    scope: Core.execution.Scope,
    /// This invocation's identity. Not the job's attempt: `job kill` acts *on*
    /// somebody else's attempt, and holding the lease under that id would make
    /// two concurrent kills renew each other — the defect one level down.
    owner_request_id: []const u8,
    job_name: []const u8,

    /// Long enough that probe → kill → settle never renews in practice, short
    /// enough that a hard-killed `job kill` does not lock the operator out of
    /// its own job for long. A claim that outlives its holder is released by
    /// lapsing, which is the only thing a dead process can do.
    const ttl_secs: i64 = 120;

    /// What a peer's live claim did to this command.
    const Outcome = union(enum) {
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

/// Takes the job scope, before anything is sent to the host.
///
/// `--force` reaches `takeover` rather than skipping the acquisition: an
/// override that took no lease would leave the scope free for a third session
/// to walk into behind it, and would leave nothing saying whose claim was
/// broken.
fn claimJobScope(
    ctx: *Cli.Ctx,
    store: *Store,
    server_id: i64,
    job_name: []const u8,
    parsed: *const Cli.Args.Parsed,
) Claim.Outcome {
    const minted = Store.ids.generate(ctx.io);
    const owner_request_id = ctx.arena.dupe(u8, &minted) catch
        fatal("out of memory claiming the scope for job '{s}'", .{job_name});
    const opts: Store.leases.AcquireOptions = .{
        .server_id = server_id,
        .scope = jobScope(job_name),
        .owner_request_id = owner_request_id,
        // Audit subject: which machine did this. It decides nothing — that is
        // the whole point of the column — but a claim with no record of who
        // took it is not much of an audit trail.
        .profile_token = Store.policy.ownerToken(store, ctx.arena, ctx.io, ctx.now) catch |err|
            Cli.storeFatal(store, err),
        .owner_label = job_name,
        .ttl_secs = Claim.ttl_secs,
        .now = ctx.now,
    };
    const claim: Claim = .{
        .store = store,
        .server_id = server_id,
        .scope = opts.scope,
        .owner_request_id = owner_request_id,
        .job_name = job_name,
    };

    if (parsed.boolean("force")) {
        const taken = Store.leases.takeover(store, ctx.arena, opts) catch |err|
            Cli.storeFatal(store, err);
        registerClaim(ctx, claim);
        return switch (taken) {
            .acquired => .{ .held = claim },
            .taken => |t| .{ .seized = .{ .claim = claim, .displaced = t.from } },
        };
    }

    return switch (Store.leases.acquire(store, ctx.arena, opts) catch |err|
        Cli.storeFatal(store, err)) {
        .acquired => blk: {
            registerClaim(ctx, claim);
            break :blk .{ .held = claim };
        },
        // A freshly minted request id cannot already hold a lease, so this
        // variant is unreachable here and is not quietly folded into `held`:
        // reaching it would mean `ids.generate` had repeated itself, and a
        // second command silently sharing an owner is exactly what this
        // whole change exists to stop.
        .renewed => |lease| fatal(
            "internal: the id minted for this command ({s}) already held a lease on job '{s}'; refusing to share an owner with whatever took it",
            .{ lease.owner_request_id, job_name },
        ),
        .conflict => |lease| .{ .blocked = lease },
    };
}

fn registerClaim(ctx: *Cli.Ctx, claim: Claim) void {
    Cli.registerClaim(
        claim.store,
        claim.server_id,
        claim.scope,
        claim.owner_request_id,
        claim.job_name,
        ctx.now,
    );
}

/// Refuses a job mutation while a peer's claim is live, before anything is sent.
fn reportClaimBlocked(lease: Store.leases.Lease) noreturn {
    fatal(
        "refused: request {s} (on {s}) holds a lease on an overlapping scope until {d}; nothing was sent to the host. Wait, or pass --force to take it over",
        .{ lease.owner_request_id, lease.profile_token, lease.expires_at },
    );
}

/// Wall-clock seconds, as opposed to `ctx.now` — which is the process's start
/// time and is what every other row in this file is stamped with.
///
/// A lease is the one thing here that is *compared* against a clock rather than
/// merely stamped with one: `expires_at` is what decides whether a peer may
/// take the scope, and `leases.renew` refuses a lease that has already lapsed.
/// Renewing with `ctx.now` would write back the same expiry the acquisition
/// already set, so a command that outran its TTL would extend nothing while
/// reporting that it had — the renewal would be a call that always succeeds and
/// never does anything.
fn wallClockSeconds(io: std.Io) i64 {
    const ts = std.Io.Timestamp.now(io, .real);
    return @intCast(@divTrunc(ts.nanoseconds, std.time.ns_per_s));
}

/// Keeps the claim alive across the remote work, and says so when it is gone.
///
/// Called once, between the last remote call and the settlement. A claim we no
/// longer hold means somebody forced their way past us and may be acting on
/// this job right now — which cannot change what we do next (the kill has
/// already happened and the ledger must record it) but must not be silent
/// either. Reported the way `finalProbe` reports a failed re-read: on the way
/// out, where there is no error to return and no result to withhold.
fn holdClaim(claim: Claim, now: i64) void {
    const still_ours = Store.leases.renew(
        claim.store,
        claim.server_id,
        claim.scope,
        claim.owner_request_id,
        Claim.ttl_secs,
        now,
    ) catch |err| {
        std.debug.print(
            "terminus: could not renew the scope lease for job '{s}': {s}; " ++
                "recording this command's outcome anyway\n",
            .{ claim.job_name, @errorName(err) },
        );
        return;
    };
    if (!still_ours) std.debug.print(
        "terminus: this command's lease on job '{s}' is no longer held — it lapsed or was taken over " ++
            "while the host was being contacted, so another session may be acting on the same job\n",
        .{claim.job_name},
    );
}

/// Refuses an attempt that another claim on the same scope makes unsafe.
///
/// Reachable from `begin` (before we dial) and from `submitted` (the point of
/// no return). Both mean the same thing to the caller: the job was not
/// started, so retrying after reconciling is safe.
fn reportBlocked(blocker: Core.execution.Blocker) noreturn {
    switch (blocker) {
        .unsettled => |op| fatal(
            "refused: request {s} is {s} on an overlapping scope, so this could be applied twice; the job was not started. Reconcile it ('terminus request reconcile {s}') or pass --force",
            .{ op.request_id, op.status.text(), op.request_id },
        ),
        .lease => |lease| fatal(
            "refused: request {s} (on {s}) holds a lease on an overlapping scope until {d}; the job was not started. Wait, take it over, or pass --force",
            .{ lease.owner_request_id, lease.profile_token, lease.expires_at },
        ),
    }
}

fn sha256Hex(arena: std.mem.Allocator, text: []const u8) ![]const u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(text, &digest, .{});
    return std.fmt.allocPrint(arena, "{x}", .{&digest});
}

fn validateJobName(name: []const u8) void {
    if (name.len == 0 or name.len > 60) fatal("job name must be 1-60 chars", .{});
    for (name) |ch| {
        switch (ch) {
            'a'...'z', 'A'...'Z', '0'...'9', '-', '_', '.' => {},
            else => fatal("job name may only contain [a-zA-Z0-9._-]", .{}),
        }
    }
}

/// Parses "15s" / "5m" / "1h" (bare number = seconds) into nanoseconds,
/// clamped to [1s, 1h] so a watch can never busy-spin or hang forever.
fn parseInterval(spec: []const u8) i64 {
    if (spec.len == 0) fatal("empty --interval", .{});
    const last = spec[spec.len - 1];
    const unit_ns: i64 = switch (last) {
        's' => std.time.ns_per_s,
        'm' => std.time.ns_per_min,
        'h' => std.time.ns_per_hour,
        '0'...'9' => std.time.ns_per_s,
        else => fatal("invalid --interval '{s}' (e.g. 15s, 5m, 1h)", .{spec}),
    };
    const digits = if (last >= '0' and last <= '9') spec else spec[0 .. spec.len - 1];
    const value = std.fmt.parseInt(i64, digits, 10) catch fatal("invalid --interval '{s}'", .{spec});
    return std.math.clamp(value * unit_ns, std.time.ns_per_s, std.time.ns_per_hour);
}

/// Scratch database under .zig-cache, the same shape `cmd_server` uses. These
/// gates need a real store because the property under test is what the ledger
/// says back, and a fake that answered would be answering for it.
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
        const unique = try std.fmt.allocPrint(allocator, "{s}_{d}", .{ name, std.Thread.getCurrentId() });
        defer allocator.free(unique);
        const path = try std.fmt.allocPrintSentinel(allocator, "{s}/{s}.db", .{ dir, unique }, 0);
        var s: Scratch = .{ .io = io, .threaded = threaded, .path = path, .allocator = allocator };
        s.removeFiles();
        return s;
    }

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

test "gate: a job mutation takes the scope before it reaches the host, and --force takes it by audit" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "cmd_job_claim");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var discard: std.Io.Writer.Discarding = .init(&.{});
    var out: Cli.Output = .{ .writer = &discard.writer };
    var environ: std.process.Environ.Map = .init(arena);
    defer environ.deinit();
    var ctx: Cli.Ctx = .{
        .io = scratch.io,
        .arena = arena,
        .environ = &environ,
        .out = &out,
        .now = 5000,
    };

    var store = try Store.open(scratch.path);
    defer store.close();
    try store.db.exec(
        \\INSERT INTO servers (id, name, host, port, username, created_at, updated_at)
        \\VALUES (1, 'box', '10.0.0.1', 22, 'ubuntu', 100, 100)
    );

    // A peer's live claim on the same job, taken from the same machine. That
    // last part is the whole point: `requireNoForeignLease` compared
    // `policy.ownerToken`, one token per machine, so this lease was never
    // "foreign" and every assertion below passed vacuously — two agents in one
    // checkout killed each other's jobs freely.
    const profile = try Store.policy.ownerToken(&store, arena, scratch.io, 4000);
    const peer: []const u8 = "01PEEEEEEER0123456789ABCDE";
    switch (try Store.leases.acquire(&store, arena, .{
        .server_id = 1,
        .scope = jobScope("deploy"),
        .owner_request_id = peer,
        .profile_token = profile,
        .ttl_secs = 600,
        .now = 4900,
    })) {
        .acquired => {},
        .renewed, .conflict => return error.PeerLeaseDidNotTake,
    }

    const plain = Cli.parseArgs(&ctx, &.{ "box", "deploy" });
    switch (claimJobScope(&ctx, &store, 1, "deploy", &plain)) {
        .blocked => |lease| {
            try t.expectEqualStrings(peer, lease.owner_request_id);
            // The profile is reported, as the audit subject it now is — and it
            // is *ours*, which is exactly why it cannot be what decides this.
            try t.expectEqualStrings(profile, lease.profile_token);
        },
        .held, .seized => return error.PeerLeaseWasIgnored,
    }

    // Nothing was sent, and nothing could have been: `claimJobScope` has no
    // executor to send with, `jobCmd` runs it before `Cli.connect`, and
    // `killJob`/`removeJob` cannot be called without the `Claim` it is the only
    // producer of. A refusal here is therefore a refusal with no dial, no
    // probe and no `kill-session`.
    comptime {
        for (@typeInfo(@TypeOf(claimJobScope)).@"fn".params) |param| {
            if (param.type) |ty| if (ty == Core.Executor) @compileError(
                "claimJobScope must not be able to reach the host: it decides before the connection exists",
            );
        }
        for (@typeInfo(@TypeOf(killJob)).@"fn".params) |param| {
            if (param.type) |ty| if (ty == Claim) break;
        } else @compileError("killJob must be unreachable without a held Claim");
    }
    // The peer still holds it, so the refusal took nothing away either.
    try t.expectEqual(@as(usize, 1), (try Store.leases.active(&store, arena, 1, 5000)).len);

    // `--force` is an audited takeover, not a way past the lease.
    const forced = Cli.parseArgs(&ctx, &.{ "box", "deploy", "--force" });
    const ours = switch (claimJobScope(&ctx, &store, 1, "deploy", &forced)) {
        .seized => |seizure| blk: {
            try t.expectEqual(@as(usize, 1), seizure.displaced.len);
            try t.expectEqualStrings(peer, seizure.displaced[0].owner_request_id);
            break :blk seizure.claim;
        },
        .held => return error.ForceFoundNothingToDisplace,
        .blocked => return error.ForceWasRefused,
    };

    // A lease was really taken — `--force` did not simply skip the layer — and
    // the displaced row records who took it from whom.
    const held = try Store.leases.active(&store, arena, 1, 5001);
    try t.expectEqual(@as(usize, 1), held.len);
    try t.expectEqualStrings(ours.owner_request_id, held[0].owner_request_id);
    {
        var stmt = try store.db.prepare(
            \\SELECT release_reason, superseded_by FROM leases WHERE owner_request_id = ?1
        );
        defer stmt.deinit();
        try stmt.bindText(1, peer);
        try t.expect(try stmt.step());
        try t.expectEqualStrings("takeover", stmt.columnText(0));
        try t.expectEqual(held[0].id, stmt.columnInt(1));
    }

    // Renewed across the remote work, which is what "hold" means: the claim
    // taken at 5000 would otherwise lapse at 5120 while a slow probe → kill →
    // settle was still running, and the settlement would land on a scope
    // somebody else was free to take.
    holdClaim(ours, 5100);
    {
        var stmt = try store.db.prepare(
            "SELECT expires_at FROM leases WHERE owner_request_id = ?1 AND released_at IS NULL",
        );
        defer stmt.deinit();
        try stmt.bindText(1, ours.owner_request_id);
        try t.expect(try stmt.step());
        try t.expectEqual(@as(i64, 5100 + 120), stmt.columnInt(0));
    }

    // Releasing is what every ending does — the settlements call it directly,
    // and `Cli.fail`, `failWithCode`, `failIndeterminate`,
    // `failIndeterminateAfterOutput` and `receiptFatal` all route through this
    // same function because `std.process.exit` skips defers.
    Cli.releaseClaim();
    try t.expectEqual(@as(usize, 0), (try Store.leases.active(&store, arena, 1, 5002)).len);

    // ...and it is idempotent, so a settle that released followed by a fatal
    // exit does not go looking for a second row to give away.
    Cli.releaseClaim();
    try t.expectEqual(@as(usize, 0), (try Store.leases.active(&store, arena, 1, 5003)).len);

    // With the scope free, an unrelated invocation takes it cleanly — so the
    // release above really freed it rather than merely stopping the count.
    switch (claimJobScope(&ctx, &store, 1, "deploy", &plain)) {
        .held => {},
        .blocked, .seized => return error.ScopeStillHeldAfterRelease,
    }
    // Two invocations, two ids: the second is refused even though both are
    // this machine and this checkout.
    switch (claimJobScope(&ctx, &store, 1, "deploy", &plain)) {
        .blocked => {},
        .held, .seized => return error.SecondInvocationSharedAnOwner,
    }
    Cli.releaseClaim();
}

test "gate: an observation the ledger will not accept is not reported as an outcome" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "cmd_job_unproven");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var discard: std.Io.Writer.Discarding = .init(&.{});
    var out: Cli.Output = .{ .writer = &discard.writer };
    var environ: std.process.Environ.Map = .init(arena);
    defer environ.deinit();
    var ctx: Cli.Ctx = .{
        .io = scratch.io,
        .arena = arena,
        .environ = &environ,
        .out = &out,
        .now = 5000,
    };

    var store = try Store.open(scratch.path);
    defer store.close();
    try store.db.exec(
        \\INSERT INTO servers (id, name, host, port, username, created_at, updated_at)
        \\VALUES (1, 'box', '10.0.0.1', 22, 'ubuntu', 100, 100)
    );

    // A launch, detached the way `run` leaves one.
    const start = try Core.execution.begin(&store, arena, scratch.io, .{
        .server_id = 1,
        .server_name = "box",
        .kind = .job,
        .scope = jobScope("deploy"),
        .alias = "deploy",
        .owner_token = "agent",
        .now = 1000,
    });
    var launch = switch (start) {
        .ready => |e| e,
        .blocked => return error.ScopeUnexpectedlyBlocked,
    };
    launch.settled = true;
    const request_id = try arena.dupe(u8, launch.id());
    _ = try Store.jobs.create(&store, 1, "deploy", "make deploy", "__TERMINUS_JOB_1__", request_id, 1000);
    try t.expect(try Store.jobs.markStarted(&store, request_id));
    _ = try Store.job_attempts.create(&store, .{
        .request_id = request_id,
        .server_id = 1,
        .server_name = "box",
        .job_name = "deploy",
        .attempt_no = 1,
        .sentinel = "__TERMINUS_JOB_1__",
        .tmux_session = "job-deploy",
        .now = 1000,
    });
    try Store.operations.advance(&store, request_id, .connecting, 1001);
    try Store.operations.advance(&store, request_id, .submitted, 1002);

    // A peer settles it `indeterminate` — the case where nothing was ever
    // established, and the one the scope guard goes on blocking for.
    switch (try Store.receipts.settle(&store, request_id, .{ .indeterminate = .{
        .reason = "a peer lost its connection and could not say what happened",
        .last_observed = .submitted,
    } }, .{}, 2000)) {
        .recorded => {},
        .already_settled => return error.PeerDidNotSettle,
    }

    // Now this process probes and finds an exit status on the host. The
    // ledger will not take it: `attach` refuses a terminal attempt, and
    // terminal includes `indeterminate`. Reporting `completed` here — which is
    // what computing the status from `probe.exit_code` did — told the caller
    // the job had succeeded, exited 0, and left no hint, while
    // `operations.unsettledInScope` went on refusing the next
    // `run --name deploy`.
    const job = (try Store.jobs.getByName(&store, arena, 1, "deploy")).?;
    const attempt = (try Store.job_attempts.latest(&store, arena, 1, "deploy")).?;
    const probe: Tmux.JobProbe = .{
        .output = "building...\n",
        .next_cursor = 12,
        .exit_code = 0,
        .exit_source = .result_file,
        .finished_at = 1900,
        .session_alive = true,
    };
    const state = applyProbe(&ctx, &store, job, probe, attempt);

    try t.expectEqual(Settlement.unproven, state.settlement);
    try t.expect(!state.settlement.proves());
    // The ledger's word, not the probe's reading.
    try t.expectEqual(Core.Store.op_state.Status.indeterminate, state.status);
    // The exit code is still reported — it was really read — but as an
    // observation of the host and not as a settled outcome.
    try t.expectEqual(@as(?i64, 0), state.exit_code);
    try t.expect(state.hint(&ctx, job.name, attempt) != null);

    // And the cache row was not rewritten to say the job exited 0, because
    // nothing here established that it did.
    const row = (try Store.jobs.getByName(&store, arena, 1, "deploy")).?;
    try t.expectEqual(Store.jobs.Status.running, row.status);

    // The control: a job row with no attempt at all. There is no operation to
    // settle and nothing holding a scope, so the host's exit status is the
    // whole answer — reported as `no_attempt` rather than dressed up as a
    // settlement, and the hint says so.
    _ = try Store.jobs.create(&store, 1, "orphan", "make orphan", "__TERMINUS_JOB_2__", "01AAAAAAAA0123456789ABCDEF", 1000);
    const orphan = (try Store.jobs.getByName(&store, arena, 1, "orphan")).?;
    const orphan_state = applyProbe(&ctx, &store, orphan, probe, null);
    try t.expectEqual(Settlement.no_attempt, orphan_state.settlement);
    try t.expect(orphan_state.settlement.proves());
    try t.expect(orphan_state.hint(&ctx, orphan.name, null) != null);
    try t.expectEqual(
        Store.jobs.Status.exited,
        (try Store.jobs.getByName(&store, arena, 1, "orphan")).?.status,
    );
}

test "gate: 'job rm' reports what happened to the row, not what it set out to do" {
    const t = std.testing;

    // The defect, in one line: a DELETE that matched no row — because the name
    // had been taken over by another launcher whose job is running — still
    // printed `{"action":"removed","ok":true}`.
    const refused = removalReport(
        .{ .refused = .{ .not_ours = .running } },
        true, // the outcome really was proven; that is not the question
        false,
        false,
    );
    try t.expect(!refused.removed);
    try t.expect(!refused.ok);
    try t.expectEqualStrings("not_removed", refused.action);

    // The control: the same proven outcome with the row actually gone is a
    // clean removal. Without this half the gate would also pass if `job rm`
    // had simply stopped reporting success at all.
    const done = removalReport(.synced, true, false, false);
    try t.expect(done.removed);
    try t.expect(done.ok);
    try t.expectEqualStrings("removed", done.action);

    // The two pre-existing rules are unchanged, and they only ever subtract:
    // discarding the evidence and a contradiction between the two durable
    // records both leave the caller owing an override.
    try t.expect(!removalReport(.synced, false, true, false).ok);
    try t.expect(!removalReport(.synced, false, false, true).ok);
    try t.expect(removalReport(.synced, false, false, false).ok);
    // ...and neither of them turns a surviving row into a removal.
    try t.expect(!removalReport(.{ .refused = .row_gone }, false, false, false).removed);
}

test "gate: a refused cache write is not reported as a clean observation" {
    const t = std.testing;

    // The defect these three commands shared: `State.cache`'s doc says a
    // refusal means the row a later `run --name X` will consult is not the row
    // this command settled, and all three reported that only as prose in
    // `hint` — `ok` stayed true and the process exited 0. `job status` on a job
    // whose row had been relaunched under a new owner printed
    // `{"ok":true,"outcomeProven":true,"status":"completed","exitCode":0}` and
    // exited 0, and the agent branching on it concluded the name was free.
    const refused: State = .{
        .status = .completed,
        .settlement = .settled,
        .exit_code = 0,
        .finished_at = 1900,
        .observed_at = 2000,
        .cache = .{ .refused = .{ .not_ours = .running } },
    };
    try t.expectEqual(Exit.failure, observationExit(refused, false));
    // Still proven: the ledger holds a real terminal, which is a different
    // fact and is still reported as one. What is not true is that this command
    // did everything it was asked to.
    try t.expect(refused.settlement.proves());

    // The controls, so this cannot be satisfied by a command that fails at
    // everything. A clean settlement exits 0; the two pre-existing failures
    // keep their ranking, with the unknown outcome outranking the stuck cursor
    // because it is the one that forbids a retry.
    const clean: State = .{
        .status = .completed,
        .settlement = .settled,
        .exit_code = 0,
        .finished_at = 1900,
        .observed_at = 2000,
        .cache = .synced,
    };
    try t.expectEqual(Exit.ok, observationExit(clean, false));
    try t.expectEqual(Exit.failure, observationExit(clean, true));
    var unproven = clean;
    unproven.settlement = .unproven;
    try t.expectEqual(Exit.indeterminate, observationExit(unproven, false));
    unproven.cache = .{ .refused = .row_gone };
    try t.expectEqual(Exit.indeterminate, observationExit(unproven, true));

    // `job kill` on a job that had already finished had the same hole with an
    // extra twist: `ok` did account for the refusal and the exit code did not,
    // so the JSON said `"ok":false` while `$?` was 0 and the human output said
    // "recorded its outcome and cleaned up the session" and nothing else.
    try t.expectEqual(Exit.ok, finishedDuringKillExit(true, true, .synced));
    try t.expectEqual(
        Exit.failure,
        finishedDuringKillExit(true, true, .{ .refused = .{ .not_ours = .running } }),
    );
    try t.expectEqual(Exit.failure, finishedDuringKillExit(true, false, .synced));
    try t.expectEqual(Exit.indeterminate, finishedDuringKillExit(false, true, .synced));
}

test "gate: two things to do are both said" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "cmd_job_hint");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var discard: std.Io.Writer.Discarding = .init(&.{});
    var out: Cli.Output = .{ .writer = &discard.writer };
    var environ: std.process.Environ.Map = .init(arena);
    defer environ.deinit();
    var ctx: Cli.Ctx = .{
        .io = scratch.io,
        .arena = arena,
        .environ = &environ,
        .out = &out,
        .now = 5000,
    };

    const attempt: Store.job_attempts.Attempt = .{
        .id = 1,
        .request_id = "01JQXW8ZK4N0RS7T3VYB2MCDEF",
        .server_id = 1,
        .server_name = "box",
        .job_name = "deploy",
        .attempt_no = 1,
        .sentinel = "__TERMINUS_JOB_1__",
        .tmux_session = "job-deploy",
        .cwd = null,
        .interpreter = null,
        .shell = null,
        .script_body_redacted = null,
        .script_sha256 = null,
        .script_bytes = null,
        .options_json = null,
        .env_redacted_json = null,
        .entry_path = null,
        .entry_sha256 = null,
        .created_at = 1000,
    };

    // Both wrong at once, which is the case the early `return` lost. The
    // operator owes a reconcile *and* has a row that no longer describes this
    // attempt, and only the row message was printed — so the request id and the
    // `request reconcile` command, which are the sole exit from
    // `indeterminate`, were never shown.
    const both: State = .{
        .status = .indeterminate,
        .settlement = .unproven,
        .exit_code = null,
        .finished_at = null,
        .observed_at = 2000,
        .cache = .{ .refused = .{ .not_ours = .running } },
    };
    const text = both.hint(&ctx, "deploy", attempt).?;
    try t.expect(std.mem.indexOf(u8, text, "belongs to another launch") != null);
    try t.expect(std.mem.indexOf(u8, text, "request reconcile") != null);
    try t.expect(std.mem.indexOf(u8, text, attempt.request_id) != null);

    // Each on its own still says its own thing and nothing else.
    var only_cache = both;
    only_cache.settlement = .settled;
    only_cache.status = .completed;
    const cache_only = only_cache.hint(&ctx, "deploy", attempt).?;
    try t.expect(std.mem.indexOf(u8, cache_only, "belongs to another launch") != null);
    try t.expect(std.mem.indexOf(u8, cache_only, "request reconcile") == null);

    var only_ledger = both;
    only_ledger.cache = .synced;
    const ledger_only = only_ledger.hint(&ctx, "deploy", attempt).?;
    try t.expect(std.mem.indexOf(u8, ledger_only, "request reconcile") != null);
    try t.expect(std.mem.indexOf(u8, ledger_only, "belongs to another launch") == null);

    // Nothing wrong, nothing said.
    var fine = only_cache;
    fine.cache = .synced;
    try t.expectEqual(@as(?[]const u8, null), fine.hint(&ctx, "deploy", attempt));

    // A reservation says so instead of saying nothing: `settlement` is `.open`
    // there, and an operator polling a name whose launcher never arrived would
    // otherwise be told only that the job is still running.
    var reserved = fine;
    reserved.reservation = true;
    reserved.settlement = .open;
    try t.expect(std.mem.indexOf(
        u8,
        reserved.hint(&ctx, "deploy", attempt).?,
        "still a reservation",
    ) != null);
}

test "gate: a result record that was there and unusable is not silence" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "cmd_job_sidecar_reading");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var discard: std.Io.Writer.Discarding = .init(&.{});
    var out: Cli.Output = .{ .writer = &discard.writer };
    var environ: std.process.Environ.Map = .init(arena);
    defer environ.deinit();
    var ctx: Cli.Ctx = .{
        .io = scratch.io,
        .arena = arena,
        .environ = &environ,
        .out = &out,
        .now = 5000,
    };

    // The four ways a result record can be there and unusable. Each says its
    // own thing: a wrong-build wrapper, a truncated write, an impossible exit
    // code and a colliding request id send an operator to four different
    // places, and all four used to arrive as the same silence a job that never
    // wrote a sidecar produces.
    const defects = [_]Tmux.SidecarReading{
        .malformed,
        .{ .unknown_schema = 7 },
        .{ .exit_code_out_of_range = 9000 },
        .{ .foreign = "01JQXW8ZK4N0RS7T3VYB2MCXYZ" },
    };
    var sentences: [defects.len][]const u8 = undefined;
    for (defects, 0..) |reading, i| {
        const state: State = .{
            .status = .remote_started,
            .settlement = .open,
            .exit_code = null,
            .finished_at = null,
            .observed_at = 2000,
            .sidecar = reading,
        };
        const note = state.sidecarNote(&ctx) orelse {
            std.debug.print("reading {s} said nothing\n", .{reading.code()});
            return error.UnusableResultRecordReportedAsSilence;
        };
        try t.expect(std.mem.indexOf(u8, note, "present") != null);
        // Not folded into `hint`: a defective document is a fact about the
        // host, not a task the operator owes, and `hint`'s two sentences are
        // gated separately above.
        try t.expectEqual(@as(?[]const u8, null), state.hint(&ctx, "deploy", null));
        // A report, not a refusal. Deliberate and stated: the sentinel still
        // settles what it always settled, and this note travels beside the
        // answer rather than changing it.
        try t.expectEqual(Exit.ok, observationExit(state, false));
        sentences[i] = note;
    }
    for (sentences, 0..) |a, i| for (sentences[i + 1 ..]) |b|
        try t.expect(!std.mem.eql(u8, a, b));

    // The three ordinary readings stay silent, so the note means something
    // when it appears.
    for ([_]Tmux.SidecarReading{ .not_requested, .absent, .present }) |ordinary| {
        const state: State = .{
            .status = .remote_started,
            .settlement = .open,
            .exit_code = null,
            .finished_at = null,
            .observed_at = 2000,
            .sidecar = ordinary,
        };
        try t.expectEqual(@as(?[]const u8, null), state.sidecarNote(&ctx));
    }

    // And the reading survives the trip through `applyProbe`, which is the
    // only route from the probe to anything a command prints.
    var store = try Store.open(scratch.path);
    defer store.close();
    try store.db.exec(
        \\INSERT INTO servers (id, name, host, port, username, created_at, updated_at)
        \\VALUES (1, 'box', '10.0.0.1', 22, 'ubuntu', 100, 100)
    );
    _ = try Store.jobs.create(&store, 1, "deploy", "make deploy", "__S__", "01AAAAAAAA0123456789ABCDEF", 1000);
    try t.expect(try Store.jobs.markStarted(&store, "01AAAAAAAA0123456789ABCDEF"));
    const job = (try Store.jobs.getByName(&store, arena, 1, "deploy")).?;
    const probe: Tmux.JobProbe = .{
        .output = "building...\n",
        .next_cursor = 12,
        .exit_code = null,
        .exit_source = .none,
        .finished_at = null,
        .sidecar = .{ .foreign = "01JQXW8ZK4N0RS7T3VYB2MCXYZ" },
        .session_alive = true,
    };
    const state = applyProbe(&ctx, &store, job, probe, null);
    try t.expectEqualStrings("foreign", state.sidecar.code());
    try t.expect(std.mem.indexOf(
        u8,
        state.sidecarNote(&ctx).?,
        "01JQXW8ZK4N0RS7T3VYB2MCXYZ",
    ) != null);
}

test "gate: a defective result record settles nothing and goes on holding the scope" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "cmd_job_defective_refuses");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var discard: std.Io.Writer.Discarding = .init(&.{});
    var out: Cli.Output = .{ .writer = &discard.writer };
    var environ: std.process.Environ.Map = .init(arena);
    defer environ.deinit();
    var ctx: Cli.Ctx = .{
        .io = scratch.io,
        .arena = arena,
        .environ = &environ,
        .out = &out,
        .now = 5000,
    };

    var store = try Store.open(scratch.path);
    defer store.close();
    try store.db.exec(
        \\INSERT INTO servers (id, name, host, port, username, created_at, updated_at)
        \\VALUES (1, 'box', '10.0.0.1', 22, 'ubuntu', 100, 100)
    );

    // A launch that reached the remote shell, under a scope of its own so each
    // arm below is a separate operation with a separate barrier.
    const Launched = struct {
        request_id: []const u8,
        job: Store.jobs.Job,
        attempt: ?Store.job_attempts.Attempt,
    };
    const launch = struct {
        fn go(s: *Store, a: std.mem.Allocator, io: std.Io, name: []const u8) !Launched {
            var e = switch (try Core.execution.begin(s, a, io, .{
                .server_id = 1,
                .server_name = "box",
                .kind = .job,
                .scope = jobScope(name),
                .alias = name,
                .owner_token = "agent",
                .now = 1000,
            })) {
                .ready => |ready| ready,
                .blocked => return error.ScopeUnexpectedlyBlocked,
            };
            e.settled = true;
            const request_id = try a.dupe(u8, e.id());
            try Store.operations.advance(s, request_id, .connecting, 1001);
            try Store.operations.advance(s, request_id, .submitted, 1002);
            try Store.operations.advance(s, request_id, .remote_started, 1003);
            _ = try Store.jobs.create(s, 1, name, "make deploy", "__S__", request_id, 1000);
            if (!try Store.jobs.markStarted(s, request_id)) return error.RowNotReserved;
            _ = try Store.job_attempts.create(s, .{
                .request_id = request_id,
                .server_id = 1,
                .server_name = "box",
                .job_name = name,
                .attempt_no = 1,
                .sentinel = "__S__",
                .tmux_session = name,
                .now = 1000,
            });
            const row = (try Store.jobs.getByName(s, a, 1, name)).?;
            return .{ .request_id = request_id, .job = row, .attempt = attemptOf(s, a, row) };
        }
    }.go;

    // Whether the scope this job's name reserves is still barred to a relaunch.
    const barred = struct {
        fn check(s: *Store, a: std.mem.Allocator, io: std.Io, name: []const u8) !bool {
            return switch (try Core.execution.begin(s, a, io, .{
                .server_id = 1,
                .server_name = "box",
                .kind = .job,
                .scope = jobScope(name),
                .alias = name,
                .owner_token = "agent",
                .now = 6000,
            })) {
                .ready => false,
                .blocked => true,
            };
        }
    }.check;

    // The sentinel says the job succeeded. Chosen deliberately: a regression
    // that lets a defective record fall through to the log settles `completed`
    // and releases the scope, which is the loudest wrong answer available and
    // the one an agent acts on hardest.
    const declined: Tmux.JobProbe.Refused = .{ .sentinel_exit_code = 0 };
    const defects = [_]Tmux.SidecarReading{
        .malformed,
        .{ .unknown_schema = 7 },
        .{ .exit_code_out_of_range = 9000 },
        .{ .foreign = "01JQXW8ZK4N0RS7T3VYB2MCXYZ" },
    };
    for (defects, 0..) |reading, i| {
        const name = try std.fmt.allocPrint(arena, "deploy{d}", .{i});
        const it = try launch(&store, arena, scratch.io, name);
        const state = applyProbe(&ctx, &store, it.job, .{
            .output = "work done\n",
            .next_cursor = 40,
            // What `Tmux.readingOf` hands back for this reading: the sentinel's
            // verdict was declined, so there is no exit code and no source.
            .exit_code = null,
            .exit_source = .none,
            .finished_at = null,
            .refused = declined,
            .sidecar = reading,
            .session_alive = true,
        }, it.attempt);

        // Not a proven terminal, and not silence either.
        try t.expectEqual(Core.Store.op_state.Status.indeterminate, state.status);
        try t.expectEqual(Settlement.unproven, state.settlement);
        try t.expectEqual(@as(?i64, null), state.exit_code);
        try t.expectEqualStrings(reading.code(), state.sidecar.code());
        // 75, not 1: a retry is not available, and an agent branching on the
        // exit code has to be able to tell that from a command that failed.
        try t.expectEqual(Exit.indeterminate, observationExit(state, false));

        // The ledger holds the same thing the report claimed.
        const op = (try Store.operations.get(&store, arena, it.request_id)).?;
        try t.expectEqual(Core.Store.op_state.Status.indeterminate, op.status);

        // …and the scope is still barred. This is the whole point of settling
        // `indeterminate` rather than `completed`: the name stays reserved
        // until somebody establishes what actually happened.
        try t.expect(try barred(&store, arena, scratch.io, name));

        // The reason names which defect it was and what it cost, so a
        // reconciler reading the receipt months later knows what it is looking
        // at. A bare "could not settle" would send it to the same place a job
        // that left nothing behind does.
        const rows = try Store.receipts.list(&store, arena, it.request_id);
        var reason: ?[]const u8 = null;
        var record: ?[]const u8 = null;
        for (rows) |row| if (row.is_terminal) {
            reason = row.transport_error;
            record = row.detail_json;
        };
        try t.expect(std.mem.indexOf(u8, reason.?, "exit 0") != null);
        try t.expect(std.mem.indexOf(u8, reason.?, "not read as this job's outcome") != null);
        // The machine-readable half: the reading's own name, and for a
        // collision the id that turned up in our place.
        try t.expect(std.mem.indexOf(u8, record.?, reading.code()) != null);
        if (reading == .foreign)
            try t.expect(std.mem.indexOf(u8, record.?, "01JQXW8ZK4N0RS7T3VYB2MCXYZ") != null);
    }

    // The other half of the rule, and the one a hardcoded `.unproven` got
    // wrong: a refusal is a statement about *this reading*, not a retraction of
    // what the ledger already holds. Here the attempt was settled `completed`
    // before anybody looked again — a newer build reading a `v:2` document, a
    // peer that got there first — and the second look then finds a record it
    // cannot read. Nothing is written: `attach` returns null on a terminal
    // attempt, so this is a pure read of the recorded outcome.
    //
    // Reporting that as unproven billed the caller exit 75 and a hint naming
    // `request reconcile <request-id>`, which fatals on an already-terminal
    // operation with or without `--override` — an unknown outcome and no way
    // out of it, for an attempt the ledger had proven. The defect is still
    // reported, through `resultRecord` and `sidecarNote`; what it may not do is
    // un-prove a settled attempt.
    const settled_first = try launch(&store, arena, scratch.io, "settled-first");
    _ = try Store.receipts.settle(&store, settled_first.request_id, .{
        .exited = .{ .exit_code = 0 },
    }, .{}, 4000);
    const after = applyProbe(&ctx, &store, settled_first.job, .{
        .output = "work done\n",
        .next_cursor = 40,
        .exit_code = null,
        .exit_source = .none,
        .finished_at = null,
        .refused = declined,
        .sidecar = .{ .unknown_schema = 2 },
        .session_alive = true,
    }, settled_first.attempt);
    try t.expectEqual(Core.Store.op_state.Status.completed, after.status);
    try t.expectEqual(Settlement.settled, after.settlement);
    try t.expectEqual(Exit.ok, observationExit(after, false));
    // The reading travels out regardless, so nothing about the host is hidden
    // by the attempt having been proven earlier.
    try t.expectEqualStrings("unknown_schema", after.sidecar.code());
    try t.expect(after.sidecarNote(&ctx) != null);
    // Nothing was written, so the ledger says exactly what it said before.
    const held = (try Store.operations.get(&store, arena, settled_first.request_id)).?;
    try t.expectEqualStrings("completed", held.status.text());
    try t.expect(!try barred(&store, arena, scratch.io, "settled-first"));

    // The control, and the half of the rule that is easy to lose: `absent` is
    // not a defect. Same log window, same sentinel, same exit 0 — and because
    // nothing was written at this request's address there is nothing to refuse,
    // so the sentinel answers as it always did, the operation settles
    // `completed`, and the scope is released.
    const clean = try launch(&store, arena, scratch.io, "clean");
    const settled = applyProbe(&ctx, &store, clean.job, .{
        .output = "work done\n",
        .next_cursor = 40,
        .exit_code = 0,
        .exit_source = .log_sentinel,
        .finished_at = null,
        .refused = null,
        .sidecar = .absent,
        .session_alive = true,
    }, clean.attempt);
    try t.expectEqual(Core.Store.op_state.Status.completed, settled.status);
    try t.expectEqual(Settlement.settled, settled.settlement);
    try t.expectEqual(@as(?i64, 0), settled.exit_code);
    try t.expectEqual(Exit.ok, observationExit(settled, false));
    try t.expect(!try barred(&store, arena, scratch.io, "clean"));
}

test "gate: a defective record beside a silent log does not settle a running job" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "cmd_job_defective_still_running");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var discard: std.Io.Writer.Discarding = .init(&.{});
    var out: Cli.Output = .{ .writer = &discard.writer };
    var environ: std.process.Environ.Map = .init(arena);
    defer environ.deinit();
    var ctx: Cli.Ctx = .{
        .io = scratch.io,
        .arena = arena,
        .environ = &environ,
        .out = &out,
        .now = 5000,
    };

    var store = try Store.open(scratch.path);
    defer store.close();
    try store.db.exec(
        \\INSERT INTO servers (id, name, host, port, username, created_at, updated_at)
        \\VALUES (1, 'box', '10.0.0.1', 22, 'ubuntu', 100, 100)
    );
    _ = try Store.jobs.create(&store, 1, "deploy", "make deploy", "__S__", "01AAAAAAAA0123456789ABCDEF", 1000);
    try t.expect(try Store.jobs.markStarted(&store, "01AAAAAAAA0123456789ABCDEF"));
    const job = (try Store.jobs.getByName(&store, arena, 1, "deploy")).?;

    // A leftover document from another request, a live session, and a log that
    // has not reached any sentinel: the job is still building. `refused` is
    // null because no verdict was there to decline, and the refusal must key on
    // that and not on the reading being defective — settling `indeterminate`
    // here would end an operation whose work is still going, and a foreign
    // document says nothing whatever about whether *this* job has finished.
    const state = applyProbe(&ctx, &store, job, .{
        .output = "building...\n",
        .next_cursor = 12,
        .exit_code = null,
        .exit_source = .none,
        .finished_at = null,
        .refused = null,
        .sidecar = .{ .foreign = "01JQXW8ZK4N0RS7T3VYB2MCXYZ" },
        .session_alive = true,
    }, null);
    try t.expectEqual(Settlement.open, state.settlement);
    try t.expectEqual(Exit.ok, observationExit(state, false));
    try t.expectEqual(Store.jobs.Status.running, (try Store.jobs.getByName(&store, arena, 1, "deploy")).?.status);
    // Still reported, though: the operator is told a document is sitting at
    // this request's address that nobody can read, which is how they find out
    // the next attempt will hit it too.
    try t.expect(std.mem.indexOf(u8, state.sidecarNote(&ctx).?, "01JQXW8ZK4N0RS7T3VYB2MCXYZ") != null);
}

test "gate: a settlement writes only the row its own launch reserved" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "cmd_job_owner_sync");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    try store.db.exec(
        \\INSERT INTO servers (id, name, host, port, username, created_at, updated_at)
        \\VALUES (1, 'box', '10.0.0.1', 22, 'ubuntu', 100, 100)
    );

    // Launch A reserves "deploy" and is displaced: its row goes, launch D's
    // takes the name — and, because sqlite reuses the rowid of the row that was
    // just deleted, very likely the id as well.
    const a: []const u8 = "01AAAAAAAA0123456789ABCDEF";
    const d: []const u8 = "01DDDDDDDD0123456789ABCDEF";
    _ = try Store.jobs.create(&store, 1, "deploy", "make deploy", "__S_A__", a, 1000);
    try t.expect(try Store.jobs.releaseReservation(&store, a));
    const d_row = try Store.jobs.create(&store, 1, "deploy", "make deploy", "__S_D__", d, 2000);
    try t.expect(try Store.jobs.markStarted(&store, d));

    // Both launches get an attempt row under the same job name, and that is
    // load-bearing rather than scene-setting. The route the defect took was
    // `attempt.job_name` — `settleProvableBlocker` has the blocker's attempt in
    // hand and used its name to find "the" row — so a gate with no attempts in
    // the table cannot distinguish the fix from a `jobCacheSync` that has
    // simply stopped finding anything. With them, restoring the by-name lookup
    // makes the assertion below fail on the row it writes rather than on the
    // control at the end, which is the difference between a gate that fires and
    // a gate that fires for this reason.
    for ([_][]const u8{ a, d }) |id| try Store.operations.create(&store, .{
        .request_id = id,
        .server_id = 1,
        .server_name = "box",
        .kind = .job,
        .now = 900,
    });
    _ = try Store.job_attempts.create(&store, .{
        .request_id = a,
        .server_id = 1,
        .server_name = "box",
        .job_name = "deploy",
        .attempt_no = 1,
        .sentinel = "__S_A__",
        .tmux_session = "job-deploy",
        .now = 1001,
    });
    _ = try Store.job_attempts.create(&store, .{
        .request_id = d,
        .server_id = 1,
        .server_name = "box",
        .job_name = "deploy",
        .attempt_no = 2,
        .sentinel = "__S_D__",
        .tmux_session = "job-deploy",
        .now = 2001,
    });

    // The hazard, stated as a fact about the CAS rather than as a story: a
    // snapshot taken from a row selected *by name* satisfies every conjunct of
    // the row it was taken from. `Owner.of` reads the owner off that same row,
    // so the compare-and-swap can only ever prove "this row has not changed" —
    // never "this row is the one I am settling for".
    const by_name = (try Store.jobs.getByName(&store, arena, 1, "deploy")).?;
    try t.expectEqualStrings(d, by_name.owner_request_id.?);

    // Addressed by A's request id, there is nothing to write. That is the whole
    // fix: `jobCacheSync` used to look the row up by `attempt.job_name` and
    // hand `finishExpectation` the successor's row, so settling A stamped A's
    // exit code and A's `finished_at` onto D's *running* job. Every conjunct
    // matched, `applied` came back, and the "reported, never swallowed" branch
    // never fired because nothing had been refused.
    try t.expectEqual(
        @as(?Store.jobs.Job, null),
        try Store.jobs.byOwner(&store, arena, a),
    );
    try t.expect(Cli.jobCacheSync(&store, arena, a, 0, 1900, 3000) == .none);

    // D's row is untouched: still running, still D's, no exit code.
    const survivor = (try Store.jobs.getByName(&store, arena, 1, "deploy")).?;
    try t.expectEqual(Store.jobs.Status.running, survivor.status);
    try t.expectEqualStrings(d, survivor.owner_request_id.?);
    try t.expectEqual(@as(?i64, null), survivor.exit_code);

    // The control, so the gate cannot pass by `jobCacheSync` having become a
    // function that never writes: D's own settlement still produces a write,
    // and it is aimed at D's row.
    const own = Cli.jobCacheSync(&store, arena, d, 3, 1900, 3000);
    try t.expect(own == .finish);
    try t.expectEqual(d_row, own.finish.expected.id);
    try t.expectEqualStrings(d, own.finish.expected.owner.launch);
}

test "gate: an observation reads the attempt its row names, not the last one to use the name" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "cmd_job_attempt_identity");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var store = try Store.open(scratch.path);
    defer store.close();
    try store.db.exec(
        \\INSERT INTO servers (id, name, host, port, username, created_at, updated_at)
        \\VALUES (1, 'box', '10.0.0.1', 22, 'ubuntu', 100, 100)
    );

    // Launch A ran under "deploy" and left an attempt behind — attempts are
    // immutable and survive `job rm` and same-name reruns, which is the point
    // of them. Launch B has since taken the name and is mid-setup: its row
    // exists, its attempt row does not yet. `run` writes them in that order,
    // with a `killSession`, an `ensure` and possibly a script upload in
    // between.
    const a: []const u8 = "01AAAAAAAA0123456789ABCDEF";
    const b: []const u8 = "01BBBBBBBB0123456789ABCDEF";
    const legacy_owner: []const u8 = "01MMMMMMMM0123456789ABCDEF";
    for ([_][]const u8{ a, b, legacy_owner }) |id| try Store.operations.create(&store, .{
        .request_id = id,
        .server_id = 1,
        .server_name = "box",
        .kind = .job,
        .now = 900,
    });
    _ = try Store.job_attempts.create(&store, .{
        .request_id = a,
        .server_id = 1,
        .server_name = "box",
        .job_name = "deploy",
        .attempt_no = 1,
        .sentinel = "__S_A__",
        .tmux_session = "job-deploy",
        .now = 1000,
    });
    _ = try Store.jobs.create(&store, 1, "deploy", "make deploy", "__S_B__", b, 2000);
    const row = (try Store.jobs.getByName(&store, arena, 1, "deploy")).?;

    // The alias says A. The row says B. Answering with A is what let a
    // `job status` on B report A's exit code, read out of A's result sidecar,
    // as a settled outcome for a launch that had not sent a key.
    const by_alias = (try Store.job_attempts.latest(&store, arena, 1, "deploy")).?;
    try t.expectEqualStrings(a, by_alias.request_id);
    try t.expectEqual(@as(?Store.job_attempts.Attempt, null), attemptOf(&store, arena, row));

    // Once B writes its attempt, that is the one that comes back — so the null
    // above is "not yet", not "never".
    _ = try Store.job_attempts.create(&store, .{
        .request_id = b,
        .server_id = 1,
        .server_name = "box",
        .job_name = "deploy",
        .attempt_no = 2,
        .sentinel = "__S_B__",
        .tmux_session = "job-deploy",
        .now = 2001,
    });
    try t.expectEqualStrings(b, attemptOf(&store, arena, row).?.request_id);

    // And an unowned 0.1.x row names no attempt rather than inheriting
    // whichever one used the name last.
    try store.db.exec(
        \\INSERT INTO jobs (id, server_id, name, command, sentinel, status, created_at)
        \\VALUES (99, 1, 'legacy', 'make old', '__S_L__', 'running', 500)
    );
    _ = try Store.job_attempts.create(&store, .{
        .request_id = legacy_owner,
        .server_id = 1,
        .server_name = "box",
        .job_name = "legacy",
        .attempt_no = 1,
        .sentinel = "__S_L__",
        .now = 600,
    });
    const legacy = (try Store.jobs.getByName(&store, arena, 1, "legacy")).?;
    try t.expectEqual(@as(?[]const u8, null), legacy.owner_request_id);
    try t.expectEqual(@as(?Store.job_attempts.Attempt, null), attemptOf(&store, arena, legacy));
}

test "gate: a missing session settles nothing about a row that is still a reservation" {
    const t = std.testing;
    var scratch = try Scratch.init(t.allocator, "cmd_job_reservation_probe");
    defer scratch.deinit();
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var discard: std.Io.Writer.Discarding = .init(&.{});
    var out: Cli.Output = .{ .writer = &discard.writer };
    var environ: std.process.Environ.Map = .init(arena);
    defer environ.deinit();
    var ctx: Cli.Ctx = .{
        .io = scratch.io,
        .arena = arena,
        .environ = &environ,
        .out = &out,
        .now = 5000,
    };

    var store = try Store.open(scratch.path);
    defer store.close();
    try store.db.exec(
        \\INSERT INTO servers (id, name, host, port, username, created_at, updated_at)
        \\VALUES (1, 'box', '10.0.0.1', 22, 'ubuntu', 100, 100)
    );

    // A launcher mid-setup: it has claimed the name and is at `connecting`,
    // which is where it sits from `execution.connecting()` until it has killed
    // the old tmux session, recreated it and staged its script. For part of
    // that window `has-session` reports the session gone — the launcher killed
    // it on purpose and has not recreated it yet.
    const start = try Core.execution.begin(&store, arena, scratch.io, .{
        .server_id = 1,
        .server_name = "box",
        .kind = .job,
        .scope = jobScope("deploy"),
        .alias = "deploy",
        .owner_token = "agent",
        .now = 1000,
    });
    var launch = switch (start) {
        .ready => |e| e,
        .blocked => return error.ScopeUnexpectedlyBlocked,
    };
    launch.settled = true;
    const request_id = try arena.dupe(u8, launch.id());
    try Store.operations.advance(&store, request_id, .connecting, 1001);
    _ = try Store.jobs.create(&store, 1, "deploy", "make deploy", "__S_B__", request_id, 1000);
    const job = (try Store.jobs.getByName(&store, arena, 1, "deploy")).?;
    try t.expectEqual(Store.jobs.Status.pending, job.status);

    // An observer arrives and probes. No session, no exit code — which for a
    // reservation is the ordinary state of a launch in progress and not
    // evidence that anything stopped.
    const probe: Tmux.JobProbe = .{
        .output = "",
        .next_cursor = 0,
        .exit_code = null,
        .exit_source = .none,
        .finished_at = null,
        .session_alive = false,
    };
    const state = applyProbe(&ctx, &store, job, probe, attemptOf(&store, arena, job));

    // Nothing established, and said so. This used to settle the row `killed`
    // and the attempt `indeterminate`: `pending -> killed` is a legal
    // settlement edge and the owner and status both matched, so the CAS applied
    // it. The launcher's `markStarted` then found no `pending` row and exited
    // 75 with its command running — and the row now read `killed`, which is not
    // live, so the next `run --force` would delete it and kill the session it
    // had just filled with real work.
    try t.expect(state.reservation);
    try t.expectEqual(Settlement.open, state.settlement);
    try t.expectEqual(Exit.ok, observationExit(state, false));
    try t.expect(state.hint(&ctx, job.name, null) != null);

    // The row is exactly as the launcher left it, and so is the ledger.
    const after = (try Store.jobs.getByName(&store, arena, 1, "deploy")).?;
    try t.expectEqual(Store.jobs.Status.pending, after.status);
    try t.expectEqual(@as(?i64, null), after.finished_at);
    try t.expectEqualStrings(request_id, after.owner_request_id.?);
    try t.expectEqual(
        Core.Store.op_state.Status.connecting,
        (try Store.operations.get(&store, arena, request_id)).?.status,
    );

    // The control: promote the row the way `run` does once its keys are in the
    // shell, and the same probe *does* settle it. A vanished session under a
    // `running` row is a real observation; the guard above is about `pending`
    // and nothing else.
    try t.expect(try Store.jobs.markStarted(&store, request_id));
    try Store.operations.advance(&store, request_id, .submitted, 1002);
    const promoted = (try Store.jobs.getByName(&store, arena, 1, "deploy")).?;
    const settled = applyProbe(&ctx, &store, promoted, probe, attemptOf(&store, arena, promoted));
    try t.expect(!settled.reservation);
    try t.expectEqual(Settlement.unproven, settled.settlement);
    try t.expectEqual(
        Store.jobs.Status.killed,
        (try Store.jobs.getByName(&store, arena, 1, "deploy")).?.status,
    );
}
