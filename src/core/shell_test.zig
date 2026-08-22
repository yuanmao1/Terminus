//! The registry: every module that splices a value into remote shell text, and
//! what each one is allowed to splice raw.
//!
//! **Why this file exists, and what it replaced.** `shell.scan` had two callers:
//! one for `transfer.zig` and one for `session/Tmux.zig`. Every other module
//! that composes remote shell text was unscanned, and the `Tmux` caller granted
//! that file a **blanket exemption** from the `{s}` clause — one
//! `expect(string_placeholders >= 10)` justified in prose by three arguments
//! that are perfectly sound: session names validated to `[a-zA-Z0-9._-]`, ULIDs
//! this program minted, and `$HOME/...` directories that must stay unquoted to
//! expand at all.
//!
//! Every one of those three justifications is about an *argument*. The exemption
//! was about a *file*, so it covered all 77 placeholders in it — and one of
//! them was `cd {s}`, whose argument is `--cwd`, which nothing validated, nobody
//! had reasoned about, and which a POSIX shell answers with `cd: too many
//! arguments` the moment it holds a space. That is the shape of the defect: not
//! a missing file in a list, but an exemption that did not have to name what it
//! exempted.
//!
//! So the unit here is a **function**, and an entry has to state how many raw
//! values that function splices and why each of them must stay raw. Adding a
//! `{s}` to a registered function fails; adding a script-building function to a
//! registered file fails; and a reason too short to be a reason fails. See
//! `shell.Exemption` for the four failure modes and for the honest limit — a
//! wholly new module is still a human adding an entry to this list, and this
//! list is one place.
const std = @import("std");
const shell = @import("shell.zig");
/// The shared source reader the text-level gates in this tree use, for the
/// function bodies these exemptions are about.
const Control = @import("control.zig");

const tmux_source = @embedFile("session/Tmux.zig");
const transfer_source = @embedFile("transfer.zig");
const script_source = @embedFile("script.zig");
const shell_source = @embedFile("shell.zig");
const cmd_sync_source = @embedFile("../cli/cmd_sync.zig");
const cmd_exec_source = @embedFile("../cli/cmd_exec.zig");

/// Extracts the body of every registered function, in order, so
/// `expectExempted` can hold each against its own entry.
fn bodiesOf(
    arena: std.mem.Allocator,
    source: []const u8,
    exemptions: []const shell.Exemption,
) ![]const []const u8 {
    const out = try arena.alloc([]const u8, exemptions.len);
    for (exemptions, out) |exemption, *slot| {
        slot.* = Control.bodyOf(source, exemption.header) catch |err| {
            std.debug.print(
                \\
                \\the registry names `{s}`, and it is not in the source it was registered
                \\against ({s}). A renamed or deleted script builder must be renamed or
                \\deleted here too — an entry that resolves to nothing is an exemption for
                \\code that no longer exists, and the code that replaced it is unscanned.
                \\
            , .{ exemption.header, @errorName(err) });
            return err;
        };
    }
    return out;
}

// --- transfer.zig: nothing at all -------------------------------------------

test "gate: transfer.zig has no spelling for a raw value in a remote script" {
    const t = std.testing;
    const found = shell.scan(transfer_source);

    // **Zero single-quoted placeholders.** The shape all thirty sites had:
    // quotes owned by the template and no escaping of the value, so the first
    // apostrophe in an operator's path ended the word and the rest of the path
    // became syntax.
    try t.expectEqual(@as(usize, 0), found.quoted_placeholders);

    // **Zero `{s}` placeholders of any spelling.** Every string this module
    // splices into a command is a shell word, so a `{s}` is a raw slice standing
    // where a `shell.Word` belongs — and dropping the quotes is not the safer
    // half of the fix: `rm -f {[path]s}` word-splits on the first space. This is
    // the clause that stops the thirty-first site rather than repairing it:
    // `'{[path]s}'` with a `[]const u8` argument compiles perfectly well, and
    // nothing else in this tree would have a word to say about it.
    //
    // The one module with an empty exemption table, and the only one that can
    // have one: every value it handles is a path.
    try t.expectEqual(@as(usize, 0), found.string_placeholders);
    try shell.expectAccounted("transfer.zig", transfer_source, 0, 0);

    // **And the file still has templates in it.** A count, so a scan over a
    // module that was emptied, renamed, or had its script text moved somewhere
    // else fails here instead of reporting that it found nothing wrong.
    try t.expect(found.word_placeholders >= 20);
}

// --- session/Tmux.zig: fourteen script builders, each with its reason -------

/// The values `Tmux.zig` splices into remote shell text without quoting them,
/// one entry per function that does it.
///
/// Three reasons recur, and they are the three the old per-file exemption gave —
/// stated here against the arguments they are actually about:
///
///   * a **session name**, validated to `[a-zA-Z0-9._-]` by
///     `cmd_session.validateName` before it can reach any of these, and passed
///     as the `t-` prefixed target from `targetName`;
///   * a **request id**, a ULID this program minted (`store/ids.zig`, Crockford
///     base32), which has no byte a shell reads;
///   * `log_dir` and `result_dir`, this file's own `$HOME/...` constants, which
///     must stay unquoted because `cd '$HOME/x'` and `mkdir -p '$HOME/x'` create
///     a directory literally named `$HOME`.
///
/// What is *not* on that list any more is `--cwd`. It goes through
/// `shell.cdInto` now, and `jobLaunchLine`'s count is two lower than it was.
const tmux_exemptions = [_]shell.Exemption{
    .{
        .header = "\nfn logPath(",
        .placeholders = 2,
        .why = "log_dir is this file's own $HOME/... constant and has to expand; the session name is validated to [a-zA-Z0-9._-] by cmd_session.validateName",
    },
    .{
        .header = "\npub fn targetName(",
        .placeholders = 1,
        .why = "the session name, validated to [a-zA-Z0-9._-] before it reaches here; this only prefixes it with `t-`",
    },
    .{
        .header = "\npub fn jobLaunchLine(",
        .placeholders = 7,
        .why = "result_dir twice (a $HOME/... constant that must expand), the request id twice (a minted ULID) inside the printf and the sidecar path, the sentinel this program minted, and the composed body and command — which are program text and would be run as a filename if quoted. --cwd is no longer among them: it goes through shell.cdInto",
    },
    .{
        .header = "\npub fn resultReadScript(",
        .placeholders = 2,
        .why = "result_dir (a $HOME/... constant that must expand) and the request id, a minted ULID",
    },
    .{
        .header = "\npub fn removeResult(",
        .placeholders = 4,
        .why = "result_dir and the request id, twice each — the .json address and the .part address that jobLaunchLine renames from",
    },
    .{
        .header = "\npub fn ensure(",
        .placeholders = 5,
        .why = "log_dir twice (a $HOME/... constant, once bare and once inside the quotes tmux itself re-parses for pipe-pane) and the validated session name three times as a tmux target",
    },
    .{
        .header = "\npub fn killSession(",
        .placeholders = 2,
        .why = "the validated session name, twice: the kill and the has-session that proves it worked",
    },
    .{
        .header = "\npub fn removeLog(",
        .placeholders = 2,
        .why = "log_dir (a $HOME/... constant that must expand) and the validated session name",
    },
    .{
        .header = "\npub fn sendKeys(",
        .placeholders = 5,
        .why = "the validated session name three times as a tmux target, the operator's input already materialised by shell.quote on the line above, and the optional Enter line this function composed itself",
    },
    .{
        .header = "\npub fn probeScript(",
        .placeholders = 5,
        .why = "the sidecar address (result_dir plus a minted ULID), the probe split marker, and the log path from logPath — all of them this file's own text or values it validated",
    },
    .{
        .header = "\npub fn readLog(",
        .placeholders = 1,
        .why = "the log path from logPath, which is a $HOME/... constant joined to a validated session name",
    },
    .{
        .header = "\npub fn execIn(",
        .placeholders = 2,
        .why = "the operator's command, which is program text and must not be quoted, and the sentinel this program minted",
    },
    .{
        .header = "\npub fn panePid(",
        .placeholders = 1,
        .why = "the validated session name as a tmux target",
    },
    .{
        .header = "\npub fn isAlive(",
        .placeholders = 1,
        .why = "the validated session name as a tmux target",
    },
};

test "gate: every raw value Tmux.zig sends to a host is exempted by name and reason" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // The clause that always applied: no placeholder inside a shell quote the
    // template owns. `printf '{{` is an escaped literal brace, not one.
    try t.expectEqual(@as(usize, 0), shell.scan(tmux_source).quoted_placeholders);

    const bodies = try bodiesOf(arena, tmux_source, &tmux_exemptions);
    const accounted = try shell.expectExempted("session/Tmux.zig", &tmux_exemptions, bodies);

    // The number the old blanket exemption never had to state. Pinned, so an
    // entry that is silently dropped from the table takes the total with it.
    try t.expectEqual(@as(usize, 40), accounted);
    try t.expectEqual(@as(usize, 14), tmux_exemptions.len);

    // And nothing outside those fourteen functions splices a raw value into
    // anything, bar one sentence. This is the half that catches a *new* script
    // builder rather than a new line in an old one.
    try shell.expectAccounted("session/Tmux.zig", tmux_source, accounted, 1);

    // The one: `SidecarReading.describe`'s report that a result record names
    // somebody else's request. An error sentence read by a person, which
    // reaches no host — named here so the prose count above is a statement
    // about a known line and not a spare unit of slack.
    try t.expect(std.mem.indexOf(
        u8,
        tmux_source,
        "names request {s}, not this one",
    ) != null);
}

// --- script.zig: the argument that genuinely cannot be one word -------------

/// `script.zig` stages a script and runs it, and one of its splices is the only
/// value in this tree that is *unquotable* rather than merely unquoted.
const script_exemptions = [_]shell.Exemption{
    .{
        .header = "\npub fn stage(",
        .placeholders = 8,
        .quoted = 1,
        .why = "remote_dir and remote_path — this file's own /tmp/.terminus constant and a path it built from a nonce — five times across the mkdir/truncate/chmod and the base64 append, the base64 payload itself, and the --interpreter, which cannot be one word: `--interpreter '/usr/bin/env python3'` names no program, because `env` and `python3` have to arrive as two arguments. That is the one splice here that quoting would break rather than merely inconvenience, and it is why it is stated rather than fixed. The one template-owned quote is the pair around that base64 payload: it is written by std.base64.standard.Encoder two statements above, whose alphabet is A-Za-z0-9+/= — so it provably cannot hold the apostrophe that would end the word",
    },
    .{
        .header = "\npub fn cleanup(",
        .placeholders = 2,
        .why = "the staged path this call staged and remote_dir, both derived from this file's own /tmp/.terminus constant and a local nonce",
    },
};

test "gate: script.zig's raw values are named, including the one that cannot be quoted" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const bodies = try bodiesOf(arena, script_source, &script_exemptions);
    const accounted = try shell.expectExempted("script.zig", &script_exemptions, bodies);
    try t.expectEqual(@as(usize, 10), accounted);
    try shell.expectAccounted("script.zig", script_source, accounted, 0);

    // The `--interpreter` splice is the reason this entry reads the way it does,
    // so the gate confirms the line is still the one the reason is about: two
    // words, interpreter then path, with nothing between them but a space.
    const stage = bodies[0];
    try t.expect(std.mem.indexOf(u8, stage, "\"{s} {s}\", .{ options.interpreter, remote_path }") != null);
}

// --- cmd_sync.zig: the two composed splices, and no third ------------------

/// After the `--exclude` fix, `cmd_sync` splices raw text in exactly two places
/// and both are *already-rendered shell text* rather than values.
const cmd_sync_exemptions = [_]shell.Exemption{
    .{
        .header = "\npub fn stagingPath(",
        .placeholders = 1,
        .why = "the request id, a minted ULID, building a value and not shell text — every script below renders that value through shell.word, so the path is one word wherever it lands",
    },
    .{
        .header = "\npub fn unpackScript(",
        .placeholders = 1,
        .why = "the optional `rm -rf <dir> && ` clause, which is shell text this function composed two statements above with the directory already rendered through shell.word",
    },
    .{
        .header = "\npub fn archiveScript(",
        .placeholders = 1,
        .why = "the --exclude arguments, already rendered as one quoted shell word per pattern by excludeArg; splicing them is composition of shell text and not of a value",
    },
    .{
        .header = "\npub fn probeScript(",
        .placeholders = 0,
        .why = "nothing: the remote directory is the only value here and it goes through shell.word, which is what a zero-count entry is for — it says this builder was looked at",
    },
};

test "gate: cmd_sync's script builders splice no value raw, and its excludes are words" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // No placeholder inside a template-owned quote — the clause `'*{s}*'` and
    // `'{s}'` would have failed, and the reason `cmd_sync` is scanned at all.
    // Held over the registered bodies rather than the whole file: this module
    // quotes paths in its *English* (`fatal("cannot open '{s}'")`), which reads
    // as six violations file-wide while being none. `expectExempted` applies it
    // where it means something.
    const bodies = try bodiesOf(arena, cmd_sync_source, &cmd_sync_exemptions);
    const accounted = try shell.expectExempted("cmd_sync.zig", &cmd_sync_exemptions, bodies);
    try t.expectEqual(@as(usize, 3), accounted);
    try t.expectEqual(@as(usize, 4), cmd_sync_exemptions.len);

    // `expectAccounted` is deliberately not applied to this file: its non-test
    // placeholders are dominated by refusal sentences and `--json` documents,
    // and a gate that failed whenever one of those was reworded is a gate people
    // learn to read past. What holds the completeness half here instead is that
    // everything this verb sends goes out through one of the builders above or
    // the single direct `exec` below — so a new script cannot reach a host
    // without changing one of these two counts.
    try t.expectEqual(@as(usize, 1), shell.countInCode(cmd_sync_source, "executor.exec("));
    try t.expect(std.mem.indexOf(u8, cmd_sync_source, "\"rm -f {f}\", .{Core.shell.word(remote_tmp)}") != null);
}

// --- the one spelling of "run this somewhere else" --------------------------

test "gate: the cd template exists once, in shell.zig, and nowhere else" {
    const t = std.testing;

    // `cmd_exec.runOneShot` and `Tmux.jobLaunchLine` each held a copy of
    // `"cd {s} && ({s})"`, both taking `--cwd` or the server's workspace, and
    // neither quoted it. One copy is now `shell.cdInto` and the other two call
    // it, which is the only arrangement in which fixing the quoting fixes both.
    const template = "cd -- {f} && ({s})";
    try t.expectEqual(@as(usize, 1), shell.countInCode(shell_source, template));

    // The shape of the defect, in every file that used to have it. Not `"cd "`,
    // which appears in prose: the two placeholders side by side are what made a
    // directory and a command share a template with no quoting between them.
    var checked: usize = 0;
    for ([_]struct { name: []const u8, source: []const u8 }{
        .{ .name = "cmd_exec.zig", .source = cmd_exec_source },
        .{ .name = "session/Tmux.zig", .source = tmux_source },
        .{ .name = "cmd_sync.zig", .source = cmd_sync_source },
    }) |file| {
        checked += 1;
        const found = shell.countInCode(file.source, "cd {s}");
        if (found != 0) {
            std.debug.print(
                \\
                \\{s} builds a `cd` out of a raw value again ({d} site(s)). A directory holding
                \\a space renders `cd /srv/two words`, which a POSIX shell answers with
                \\`cd: too many arguments` — so the `&&` never fires, the operator's command is
                \\never sent, and the attempt settles an exit code for a command that did not
                \\run. Call `shell.cdInto`.
                \\
            , .{ file.name, found });
            return error.CdTemplateReintroduced;
        }
    }
    try t.expectEqual(@as(usize, 3), checked);

    // And both callers reach the shared one.
    try t.expect(shell.countInCode(cmd_exec_source, "shell.cdInto(") >= 1);
    try t.expect(shell.countInCode(tmux_source, "shell.cdInto(") >= 1);
}

// --- the mechanism itself ---------------------------------------------------

test "gate: an unjustified {s} in an exempted file fails, four different ways" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const reason = "a session name validated to [a-zA-Z0-9._-] before it reaches here";
    const one: shell.Exemption = .{ .header = "\nfn f(", .placeholders = 1, .why = reason };

    // The baseline: one placeholder, one declared, and it passes.
    try t.expectEqual(@as(usize, 1), try shell.expectExempted(
        "synthetic",
        &.{one},
        &.{"    return p(\"has-session -t ={s}\", .{name});\n"},
    ));

    // **A new placeholder in a registered function.** The case the per-file
    // exemption could not see: `cd {s}` appearing under a reason written about
    // session names.
    try t.expectError(error.ExemptionMiscounted, shell.expectExempted(
        "synthetic",
        &.{one},
        &.{"    return p(\"cd {s} && has-session -t ={s}\", .{ dir, name });\n"},
    ));

    // **A placeholder that went away.** A scan that finds nothing must fail, not
    // pass: a renamed template leaves an exemption describing code that is gone.
    try t.expectError(error.ExemptionMiscounted, shell.expectExempted(
        "synthetic",
        &.{one},
        &.{"    return p(\"has-session -t ={f}\", .{shell.word(name)});\n"},
    ));

    // **A reason that is not one.**
    try t.expectError(error.ExemptionUnreasoned, shell.expectExempted(
        "synthetic",
        &.{.{ .header = "\nfn f(", .placeholders = 1, .why = "safe" }},
        &.{"    return p(\"-t ={s}\", .{name});\n"},
    ));

    // **Two entries for one function**, which is how one reason comes to cover
    // another's argument all over again.
    try t.expectError(error.ExemptionDuplicated, shell.expectExempted(
        "synthetic",
        &.{ one, one },
        &.{ "    return p(\"-t ={s}\", .{name});\n", "" },
    ));

    // **A quote the template owns**, which has to be declared and argued for
    // rather than merely present — the shape every `'{[path]s}'` in
    // `transfer.zig` had.
    try t.expectError(error.QuotedPlaceholderInScript, shell.expectExempted(
        "synthetic",
        &.{one},
        &.{"    return p(\"rm -f '{s}'\", .{path});\n"},
    ));
    // And a declared one passes, which is what `script.stage`'s base64 payload
    // needs. Note the count clause still holds it: the quotes being justified
    // does not make the raw value unaccounted for.
    try t.expectEqual(@as(usize, 1), try shell.expectExempted(
        "synthetic",
        &.{.{ .header = "\nfn f(", .placeholders = 1, .quoted = 1, .why = reason }},
        &.{"    return p(\"rm -f '{s}'\", .{path});\n"},
    ));
    // The narrow edge of the quote detector, stated so nobody relies on the
    // wrong clause: `'*{s}*'` is a placeholder inside template-owned quotes and
    // the `'{` test does **not** see it, because the apostrophe is followed by
    // `*`. It was the `--exclude` defect, and what catches it is the count — a
    // raw value is a raw value whatever surrounds it.
    try t.expectEqual(@as(usize, 0), shell.scan("p(\" --exclude='*{s}*'\", .{x})").quoted_placeholders);
    try t.expectError(error.ExemptionMiscounted, shell.expectExempted(
        "synthetic",
        &.{.{ .header = "\nfn f(", .placeholders = 0, .why = reason }},
        &.{"    return p(\" --exclude='*{s}*'\", .{pattern});\n"},
    ));

    // **A placeholder outside every registered function.** A brand-new script
    // builder in a file the registry already covers.
    const grown = try std.mem.concat(arena, u8, &.{
        script_source,
        "\nfn newBuilder(a: A) ![]u8 {\n    return p(\"rm -rf {s}\", .{dir});\n}\n",
    });
    try t.expectError(error.RawValueUnaccounted, shell.expectAccounted("synthetic", grown, 10, 0));
    // …and the real file, unchanged, passes the same call.
    try shell.expectAccounted("script.zig", script_source, 10, 0);

    // A registered function that was renamed out from under its entry is not
    // silently skipped either.
    try t.expectError(error.FunctionMissing, bodiesOf(
        arena,
        script_source,
        &.{.{ .header = "\npub fn stageTheScript(", .placeholders = 1, .why = reason }},
    ));
}

test "gate: the registry's own reasons are reasons" {
    const t = std.testing;
    // Every entry in every table, held to the same floor `expectExempted`
    // applies — asserted here as well so a table that is never reached by a
    // failing gate still cannot carry a one-word exemption.
    var entries: usize = 0;
    for ([_][]const shell.Exemption{
        &tmux_exemptions,
        &script_exemptions,
        &cmd_sync_exemptions,
    }) |table| {
        for (table) |exemption| {
            entries += 1;
            try t.expect(exemption.why.len >= shell.min_reason_len);
            try t.expect(exemption.header.len > 4);
            try t.expect(std.mem.startsWith(u8, exemption.header, "\n"));
        }
    }
    try t.expectEqual(@as(usize, 20), entries);
}
