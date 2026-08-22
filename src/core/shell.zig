//! POSIX shell words: the one place a value becomes an argument.
//!
//! Every remote side effect in this project is a line of shell text sent down an
//! exec channel, and the values spliced into that text are the operator's own —
//! a path they typed, a command they wrote. Splicing a value into a script is
//! therefore not string formatting; it is the point at which data either stays
//! data or becomes syntax.
//!
//! **Why this is a module and not a helper on a caller.** The function lived on
//! `session/Tmux.zig`, which is where the first caller happened to be, and
//! `core/transfer.zig` — a transport module that knows nothing about sessions —
//! could not reach it without importing a session module for a string function.
//! So `transfer.zig` did not reach it: it wrote `'{[path]s}'` in twenty-four
//! places instead, which is a single-quoted shell word with no escaping in it at
//! all. A path holding an apostrophe (`/data/John's files/x` — an ordinary
//! path, not an attack) ended that word early, and what followed was whatever
//! the rest of the path happened to spell. Nothing in this file is new
//! knowledge; what is new is that both modules can depend on it, and that
//! neither one is underneath the other.
//!
//! **`Word` exists so the mistake cannot be spelled.** The escaping is correct
//! in `quote` and always was — the defect was never a wrong algorithm, it was
//! twenty-four places that did not call one. A `[]const u8` in a `{s}` reads
//! exactly like a value that has been handled; a `Word` cannot be printed with
//! `{s}` at all (`std.Io.Writer.printValue` rejects a struct there, at compile
//! time), and its only rendering is the quoted one. So a script template that
//! takes `Word` arguments has no spelling for the raw value, and the writer of
//! the twenty-fifth line does not have to remember anything.
//!
//! What that does *not* cover is somebody adding a template argument of a
//! different type, and `Word` cannot make that a compile error from here. That
//! half is held by the scan at the bottom of this file, which reads the source
//! of every module that splices into remote shell text and refuses both shapes
//! the defect can take. The exemptions to it are per *function*, each stating
//! how many raw values it splices and why — see `Exemption`, and
//! `shell_test.zig` for the registry itself. A per-file exemption is what let
//! `cd {s}` through: the three reasons written on it were reasons about three
//! other arguments.
const std = @import("std");
const Allocator = std.mem.Allocator;

/// One value, rendered as exactly one POSIX shell word.
///
/// Format it with `{f}`. `{s}` is a compile error, which is the property this
/// type exists for: a script template holding `Word` arguments has no way to
/// write the unescaped value.
///
/// Holds a borrowed slice and allocates nothing — the escaping happens as it is
/// written, so a 2 GiB push's per-slice command does not also allocate a quoted
/// copy of its path 116 000 times.
pub const Word = struct {
    raw: []const u8,

    /// Single quotes, with an embedded `'` closed, escaped and reopened
    /// (`'\''`) — the standard POSIX form, and the only one that needs no
    /// knowledge of the shell's metacharacter set. Inside single quotes *every*
    /// byte is literal: a space, a `$`, a backtick, a `"`, a `;`, a newline. The
    /// apostrophe is the sole exception because it is the terminator, and it is
    /// the sole thing rewritten here.
    ///
    /// Not `printf %q`, not a backslash-escape of a metacharacter list: both
    /// require the list to be right, and a list that is missing one byte is a
    /// quoting function that works until it does not.
    pub fn format(w: Word, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.writeByte('\'');
        var rest = w.raw;
        while (std.mem.indexOfScalar(u8, rest, '\'')) |at| {
            try writer.writeAll(rest[0..at]);
            try writer.writeAll("'\\''");
            rest = rest[at + 1 ..];
        }
        try writer.writeAll(rest);
        try writer.writeByte('\'');
    }
};

/// `s` as one shell word, for a template argument.
pub fn word(s: []const u8) Word {
    return .{ .raw = s };
}

/// `s` as one shell word, materialised.
///
/// For the callers that hand a finished string to something other than a format
/// template — `tmux send-keys -- <word>`, `bash -ilc <word>` — where there is no
/// placeholder to put a `Word` in.
pub fn quote(arena: Allocator, s: []const u8) Allocator.Error![]u8 {
    const buf = try arena.alloc(u8, quotedLen(s));
    var writer = std.Io.Writer.fixed(buf);
    // The buffer is exactly `quotedLen` bytes and `format` writes exactly that
    // many, so the fixed writer cannot run out. `catch unreachable` rather than
    // a propagated error: the alternative is an error union whose failure arm no
    // caller can reach and none can test. The equality is asserted rather than
    // assumed, so a `quotedLen` that ever disagreed with `format` would trip
    // here instead of returning a short word.
    word(s).format(&writer) catch unreachable;
    std.debug.assert(writer.end == buf.len);
    return buf;
}

/// How many bytes `quote` will produce. Exact, not an upper bound.
///
/// Load-bearing for `transfer.appendSlice`, which prints one push slice's
/// command into a buffer sized once for the whole transfer: a path of *n*
/// apostrophes quotes to 4*n* + 2 bytes, so a buffer sized from `raw.len` runs
/// out and the transfer is refused as `RemotePathTooLong` — a path that is not
/// long, for a reason that is not its length.
pub fn quotedLen(s: []const u8) usize {
    var n: usize = 2;
    for (s) |ch| n += if (ch == '\'') 4 else 1;
    return n;
}

// --- An argv, and the shell that runs it -------------------------------------

/// An argv as a command line: every element becomes exactly one shell word.
///
/// **What this is not.** `libssh2_channel_process_startup` takes a command
/// *string*, not an argv array, and the remote sshd hands that string to the
/// account's shell whatever we do. So nothing here bypasses a shell. What it
/// does is make the string one the shell splits back into the list it came
/// from: every element is quoted, so a space, an apostrophe, a `$`, a backtick,
/// a newline or a `;` inside one is a byte of that word and never a piece of
/// syntax. `words` is the inverse and the honest way to check it — apply the
/// splitting rules and see whether the list that comes out is the list that
/// went in.
///
/// Exact sizing and then a fixed writer, the same arrangement as `quote` and
/// for the same reason: the length and the rendering are one statement, so they
/// cannot disagree.
pub fn render(arena: Allocator, argv: []const []const u8) Allocator.Error![]u8 {
    // An empty argv is not a command. The callers refuse it with a sentence
    // before they reach here, so this is the assertion that they did.
    std.debug.assert(argv.len != 0);
    var total: usize = argv.len - 1; // the separating spaces
    for (argv) |element| total += quotedLen(element);
    const buf = try arena.alloc(u8, total);
    var writer = std.Io.Writer.fixed(buf);
    for (argv, 0..) |element, i| {
        if (i != 0) writer.writeByte(' ') catch unreachable;
        word(element).format(&writer) catch unreachable;
    }
    std.debug.assert(writer.end == buf.len);
    return buf;
}

/// `<binary> -ilc <command>`, with the command as one shell word.
///
/// Both letters are load-bearing. `-l` alone is not enough: distros guard
/// `~/.bashrc` with an interactive-only early return, and the version managers
/// people are missing (nvm, bun, pm2) initialise exactly there — so `-i` is
/// required too. The job-control warnings `-i` emits without a tty are stripped
/// from stderr by `Cli.stripLoginNoise`.
///
/// The one spelling of a login wrap in this tree. There were two: this one and
/// `bash -ilc '{s}'` in `script.zig`, whose quotes belonged to the format
/// template and escaped nothing — an `--interpreter` holding an apostrophe
/// ended that word early and the rest of it became syntax, which is the exact
/// defect `Word` exists for. A caller now names the binary and hands over the
/// command; it has no way to spell the quoting itself.
pub fn loginWrap(arena: Allocator, binary: []const u8, command: []const u8) Allocator.Error![]u8 {
    return std.fmt.allocPrint(arena, "{s} -ilc {f}", .{ binary, word(command) });
}

// --- A working directory, the one value a shell still has to expand ---------

/// The one expansion a `Cwd` performs, and the only text it emits unquoted.
pub const home_expansion = "$HOME";

/// A working directory, rendered as exactly one shell word.
///
/// **Why this is not simply a `Word`.** Every other value in this file is data
/// and nothing else, so `Word` is the whole answer: quote it and no byte of it
/// can be syntax. A working directory is the one argument in this project where
/// that is not the whole answer, because `cd '~/app'` is not a slower `cd
/// ~/app` — it is a different command, and it fails. The tilde is expanded by
/// the shell before `cd` ever sees it, so a value that is quoted has lost the
/// expansion it was written for, and `~/app` and `$HOME/app` are what operators
/// actually put in `terminus workspace set`.
///
/// **A value cannot be both expandable and safe, so the expansion is ours.** An
/// expansion performed by the remote shell is by definition the shell reading
/// the value as syntax — that is what expansion *is* — and there is no quoting
/// that admits one expansion and refuses the rest. So this type does not ask
/// the shell to expand anything the operator typed. It recognises the two
/// spellings of the remote home itself, emits `$HOME` as text of its own, and
/// quotes every byte the operator wrote after it:
///
///   * `~`            → `$HOME`
///   * `~/app dir`    → `$HOME/'app dir'`
///   * `$HOME/app`    → `$HOME/'app'`
///   * `/srv/two words` → `'/srv/two words'`
///   * `/tmp; rm -rf ~` → `'/tmp; rm -rf ~'`, which is a path and not a command
///
/// The `$HOME` it writes is its own literal, not the operator's — so the only
/// expansion that survives is one this file spelled, and the remainder is one
/// quoted word whatever is in it.
///
/// **What that leaves, and why it is refused rather than rendered.** A value
/// like `$RELEASE/app` was expanded before this type existed and is a literal
/// path now, so it would silently become a directory nobody has. That is not
/// rendered quietly: `cwdRefusal` names it, and the callers that can still
/// refuse — before a connection and before a ledger row — do. See its doc
/// comment for which those are.
pub const Cwd = struct {
    raw: []const u8,

    pub fn format(c: Cwd, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        const rest = homeRemainder(c.raw) orelse return word(c.raw).format(writer);
        try writer.writeAll(home_expansion);
        if (rest.len == 0) return;
        try writer.writeByte('/');
        try word(rest).format(writer);
    }
};

/// `dir` as one shell word, for a template argument.
pub fn cwd(dir: []const u8) Cwd {
    return .{ .raw = dir };
}

/// What follows a leading `~/` or `$HOME/`; `""` for a bare `~` or `$HOME`, and
/// null when `dir` does not name the remote home at all.
fn homeRemainder(dir: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, dir, "~") or std.mem.eql(u8, dir, home_expansion)) return "";
    if (std.mem.startsWith(u8, dir, "~/")) return dir[2..];
    if (std.mem.startsWith(u8, dir, home_expansion ++ "/")) return dir[home_expansion.len + 1 ..];
    return null;
}

/// Why `dir` cannot be carried as one shell word without changing what it
/// meant, or null when it can.
///
/// This is the honest half of `Cwd`. `Cwd` is total — it always renders one
/// word, so nothing an operator types can become syntax — but a value that was
/// relying on an expansion beyond `~` and `$HOME` is now a literal path, and
/// turning it into one quietly would trade an injection for a directory that is
/// not there. The values named here are refused *before* a connection exists,
/// which is the one disposition that cannot leave a ledger row: a refusal has
/// no exit code, and a `cd` that fails does.
///
/// Called by `cmd_exec` (before `begin`) and by `cmd_workspace set` (so the
/// store stops accepting one). `Tmux.jobLaunchLine` renders without refusing:
/// by the time `cmd_job` composes that line it has already created the job row
/// and the tmux session, so a refusal there would be later than the side
/// effects it is refusing on behalf of.
pub fn cwdRefusal(dir: []const u8) ?[]const u8 {
    if (dir.len == 0) return "it is empty, and an empty operand makes `cd` change to the home directory instead";
    const rest = homeRemainder(dir) orelse blk: {
        if (dir[0] == '~') return "it starts with `~` and a user name, and terminus expands only `~` and `~/`";
        break :blk dir;
    };
    if (std.mem.indexOfScalar(u8, rest, '$') != null)
        return "it contains `$`, and terminus expands only a leading `~` or `" ++ home_expansion ++ "`";
    if (std.mem.indexOfScalar(u8, rest, '`') != null)
        return "it contains a backtick, which is command substitution and not part of a path";
    return null;
}

/// `cd -- <dir> && (<command>)` — the one spelling of "run this somewhere else".
///
/// **Why it is a function and not a template each caller writes.** It was a
/// template each caller wrote: `cmd_exec.runOneShot` and `Tmux.jobLaunchLine`
/// held one `"cd {s} && ({s})"` each, both taking `--cwd` or the server's
/// workspace, and neither validated or quoted it. A `--cwd` holding a space
/// therefore produced `cd /srv/two words`, which a POSIX shell answers with
/// `cd: too many arguments` — so the `&&` never fired, the operator's command
/// was never sent, and `exec` settled the attempt `exited` with code 1. The
/// ledger recorded a proven failure of a command that had not run. One
/// spelling, in one place, is what stops the third caller writing a third copy.
///
/// `--` is load-bearing and not decoration. Quoting does not stop `cd` reading
/// its operand as an option: `cd '-P'` is `cd -P`, which takes no operand and
/// succeeds *in the home directory* — a working directory silently different
/// from the one that was asked for, which is the same class of defect as the
/// injection and quieter. `cd -- '-P'` reports that there is no such directory.
pub fn cdInto(arena: Allocator, dir: []const u8, command: []const u8) Allocator.Error![]u8 {
    return std.fmt.allocPrint(arena, "cd -- {f} && ({s})", .{ cwd(dir), command });
}

/// The `--shell` vocabulary: which interpreter a command is declared to run
/// under, and whether terminus adds a shell layer of its own at all.
///
/// **Why the vocabulary is closed, and why `powershell` is not in it.**
/// `supervisor.wrapShell` is what provides the start marker, the pid, the pgid,
/// the start token and the exit marker that `parseShell` reads, and it is
/// written in POSIX shell — `$$`, `$?`, `$(…)`, `/proc`, `awk`, `printf`,
/// `ps -o`, `tr -d`. PowerShell does not run that program. A `--shell
/// powershell` that was merely passed along would lose the whole supervision
/// layer: no identity, no exit marker, and `runCommand` would settle every
/// command `indeterminate` because the marker never arrives. So a value only
/// enters this enum once a wrapper exists for it, and every other value is
/// refused by name before anything is sent.
pub const Kind = enum {
    bash,
    zsh,
    /// No shell layer from terminus. The command is sent as it stands — no
    /// login wrap, no `set -euo pipefail` prefix, no staged script — and an
    /// argv is rendered one word per element so nothing in it can become
    /// syntax. It does not and cannot mean "no shell ran it": the remote sshd
    /// still hands the string to the account's shell.
    none,

    /// The binary a login wrap and a staged script use. `none` has none, which
    /// is the entire content of `none`.
    pub fn binary(k: Kind) ?[]const u8 {
        return switch (k) {
            .bash => "bash",
            .zsh => "zsh",
            .none => null,
        };
    }
};

/// The vocabulary as a refusal prints it, derived from the enum so a member the
/// parser accepts cannot be left out of the message that lists them.
pub const kind_list = list: {
    var out: []const u8 = "";
    for (@typeInfo(Kind).@"enum".fields, 0..) |field, i| {
        out = out ++ (if (i == 0) "" else "|") ++ field.name;
    }
    break :list out;
};

/// Values that name a real interpreter for which `supervisor.wrapShell` is not
/// a program. Refused with that reason rather than as an unknown word, because
/// "powershell is not a value terminus has" invites a second attempt while "the
/// supervisor is POSIX shell" does not.
pub const unsupervised_names = [_][]const u8{
    "powershell", "pwsh", "powershell.exe", "cmd", "cmd.exe", "fish", "csh", "tcsh",
};

pub const KindError = error{
    /// A real interpreter, with no supervisor wrapper for it.
    Unsupervised,
    /// Not a value this vocabulary has at all.
    Unknown,
};

/// `--shell <value>`, or a refusal that says which kind of wrong it is.
pub fn parseKind(value: []const u8) KindError!Kind {
    if (std.meta.stringToEnum(Kind, value)) |kind| return kind;
    for (unsupervised_names) |name| {
        if (std.mem.eql(u8, value, name)) return error.Unsupervised;
    }
    return error.Unknown;
}

// --- Reading a script back ---------------------------------------------------

/// The shell words a POSIX shell would see in `text`, as it would see them.
///
/// The inverse of `Word.format`, and public for the same reason
/// `Tmux.resultReadScript` is: a gate that reads generated shell text and
/// eyeballs the quote marks is checking that the bytes look right, which is not
/// the question. The question is what the *host* would split that text into, and
/// the only honest way to answer it without a host is to apply the splitting
/// rules and look at the words that come out. A path that survives quoting is a
/// path that comes back out as one word equal to itself.
///
/// It implements exactly what these scripts use — unquoted whitespace separates
/// words, single quotes make every byte inside them literal, and an unquoted
/// backslash makes the next byte literal — and **refuses** anything else it
/// meets rather than guessing:
///
///   * an unbalanced `'` is `error.UnbalancedQuote`, which is precisely the
///     failure an unescaped apostrophe in a path produces;
///   * a `"` is `error.UnsupportedQuoting`, because this reader does not
///     implement double-quote rules and one that silently treated `"` as an
///     ordinary byte would report word boundaries the shell does not have. No
///     script in this project double-quotes a value.
///
/// The backslash rule is not optional decoration: `'\''` — the escape at the
/// centre of `Word.format` — is a closed quote, an unquoted `\'`, and a reopened
/// quote, so a reader without it cannot read the output of the quoter it exists
/// to check.
///
/// **It does not recognise operators.** `;`, `|`, `&&` and the redirections are
/// ordinary bytes here, so `echo a;b` is one word and `rm -f 'p';` comes back as
/// `p;`. That is the right model for the question these gates ask — where does
/// the *value* begin and end — and being wrong in this direction is safe: an
/// operator glued to a value shows up attached to it, which is a visible finding,
/// never a hidden one.
///
/// Kept next to `Word.format` on purpose: a quoter and the reader that checks it
/// drift apart the moment they live in different files.
pub const SplitError = error{ UnbalancedQuote, UnsupportedQuoting } || Allocator.Error;

pub fn words(arena: Allocator, text: []const u8) SplitError![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var current: std.ArrayList(u8) = .empty;
    var started = false;
    var i: usize = 0;
    while (i < text.len) : (i += 1) {
        switch (text[i]) {
            ' ', '\t', '\n', '\r' => {
                if (started) {
                    try out.append(arena, try current.toOwnedSlice(arena));
                    started = false;
                }
            },
            '\'' => {
                started = true;
                const close = std.mem.indexOfScalarPos(u8, text, i + 1, '\'') orelse
                    return error.UnbalancedQuote;
                try current.appendSlice(arena, text[i + 1 .. close]);
                i = close;
            },
            '\\' => {
                // A trailing backslash is a line continuation, which nothing
                // here emits; refused rather than dropped.
                if (i + 1 == text.len) return error.UnsupportedQuoting;
                started = true;
                i += 1;
                try current.append(arena, text[i]);
            },
            '"' => return error.UnsupportedQuoting,
            else => {
                started = true;
                try current.append(arena, text[i]);
            },
        }
    }
    if (started) try out.append(arena, try current.toOwnedSlice(arena));
    return out.toOwnedSlice(arena);
}

/// How many words in `text` are exactly `value`.
pub fn wordCount(arena: Allocator, text: []const u8, value: []const u8) SplitError!usize {
    var n: usize = 0;
    for (try words(arena, text)) |w| {
        if (std.mem.eql(u8, w, value)) n += 1;
    }
    return n;
}

// --- The guard --------------------------------------------------------------

/// The two shapes the defect takes, and the count that says the scan looked at
/// something.
///
/// Reading a file's own source for a forbidden spelling is what this tree
/// already does for renewal adjacency and the cascade routes, and it is here for
/// the reason it is there: the property is about text that has not been written
/// yet. `Word` makes the twenty-fifth *use* of an existing template argument
/// safe; it cannot stop somebody declaring a twenty-fifth argument of a
/// different type, because the compiler is perfectly happy with
/// `'{[path]s}'` + `.{ .path = some_slice }`.
///
/// Two forbidden shapes, because the defect has two:
///
///   * `'{` — a format placeholder inside single quotes. The shape all
///     twenty-four sites had. The value is escaped by nobody and the quotes
///     belong to the template, so the first apostrophe in the value ends the
///     word. `'{{` is exempt: `{{` is an escaped literal brace, not a
///     placeholder.
///   * `s}` — a `{s}` (or `{[name]s}`) placeholder. Every string this file
///     splices into a command is a shell word, so a `{s}` in it is a raw slice
///     going somewhere a `Word` belongs, quoted or not. Unquoted is not the
///     safer half: `rm -f {[path]s}` word-splits on the first space.
///
/// And a floor on `f}`, so a scan over a file that was emptied, renamed or had
/// its templates moved out fails instead of quietly finding nothing wrong.
pub const Scan = struct {
    /// Placeholders inside single quotes. Must be zero.
    quoted_placeholders: usize,
    /// `{s}` placeholders of any spelling.
    string_placeholders: usize,
    /// `{f}` placeholders — values rendered through `Word`.
    word_placeholders: usize,
};

pub fn scan(source: []const u8) Scan {
    var out: Scan = .{
        .quoted_placeholders = 0,
        .string_placeholders = 0,
        .word_placeholders = 0,
    };
    var lines = std.mem.splitScalar(u8, source, '\n');
    while (lines.next()) |raw_line| {
        const line = scanLine(codeOf(raw_line));
        out.quoted_placeholders += line.quoted_placeholders;
        out.string_placeholders += line.string_placeholders;
        out.word_placeholders += line.word_placeholders;
    }
    return out;
}

/// `line` with any trailing `//` comment removed.
///
/// Comments have to come off, and this is the one place the scan can be talked
/// out of its own finding: a doc comment naming the shape it forbids — the
/// header of `transfer.zig` names `'{[path]s}'` to say what was wrong with it —
/// would otherwise be a permanent failure, and the way that gets fixed at 2am is
/// by deleting the gate.
///
/// Two things keep a `//` inside a string from being read as a comment: an odd
/// number of `"` before it means it is inside a quoted literal, and a `\\`
/// before it means the rest of the line is a multiline string. Both tests are
/// conservative — when in doubt the line is scanned whole, so the guard can only
/// ever look at more text than it needs to, never less.
fn codeOf(line: []const u8) []const u8 {
    const at = std.mem.indexOf(u8, line, "//") orelse return line;
    const before = line[0..at];
    if (std.mem.indexOf(u8, before, "\\\\") != null) return line;
    var quotes: usize = 0;
    for (before) |ch| {
        if (ch == '"') quotes += 1;
    }
    if (quotes % 2 != 0) return line;
    return before;
}

/// How many times `needle` appears in `source`, ignoring `//` comments.
///
/// `pub` because the gates that forbid a spelling in a *command's* source need
/// it and `grep -c` does not do it: a count that includes comments makes the
/// doc comment explaining why a spelling is forbidden into the reason the gate
/// fails, and a gate that cannot be satisfied gets deleted. Same `codeOf` the
/// placeholder scan uses, so the two agree about what a comment is.
pub fn countInCode(source: []const u8, needle: []const u8) usize {
    var n: usize = 0;
    var lines = std.mem.splitScalar(u8, source, '\n');
    while (lines.next()) |raw_line| {
        n += std.mem.count(u8, codeOf(raw_line), needle);
    }
    return n;
}

fn scanLine(line: []const u8) Scan {
    var out: Scan = .{
        .quoted_placeholders = 0,
        .string_placeholders = 0,
        .word_placeholders = 0,
    };
    var i: usize = 0;
    while (i < line.len) : (i += 1) {
        switch (line[i]) {
            '\'' => {
                if (i + 2 < line.len and line[i + 1] == '{' and line[i + 2] != '{')
                    out.quoted_placeholders += 1;
            },
            '{' => {
                // A placeholder is `{` … `}` with no `{` in between; `{{` is an
                // escaped brace and is skipped whole so its second brace cannot
                // open one. Line at a time, so a `{` with no `}` after it on
                // the same line is not a placeholder — which is what every
                // brace of Zig's own syntax looks like.
                if (i + 1 < line.len and line[i + 1] == '{') {
                    i += 1;
                    continue;
                }
                const rest = line[i + 1 ..];
                const end = std.mem.indexOfScalar(u8, rest, '}') orelse continue;
                const body = rest[0..end];
                if (body.len == 0 or std.mem.indexOfScalar(u8, body, '{') != null) continue;
                switch (body[body.len - 1]) {
                    's' => out.string_placeholders += 1,
                    'f' => out.word_placeholders += 1,
                    else => {},
                }
                i += end + 1;
            },
            else => {},
        }
    }
    return out;
}

// --- The exemption, which has to say what it exempts ------------------------

/// One script-building function, the raw values it splices, and why each one
/// must stay raw.
///
/// **Why the unit is a function and not a file.** It was a file. `Tmux.zig` held
/// a blanket exemption from the `{s}` clause — one `expect(found.string_placeholders
/// >= 10)` justified in prose by three arguments that really are safe: session
/// names validated to `[a-zA-Z0-9._-]`, ULIDs this program minted, and
/// `$HOME/...` directories that have to stay unquoted to expand at all. Every
/// one of those justifications is *about an argument*. The exemption was about a
/// file, and so it covered all 77 placeholders in it — including `cd {s}`, whose
/// argument is `--cwd`, which nothing validated and nobody had reasoned about.
/// A new `{s}` anywhere in the file was silently covered by somebody else's
/// argument for a different value.
///
/// So an exemption now names a function and states how many raw values that
/// function splices. Four things then fail rather than pass:
///
///   * a `{s}` in a function nobody registered — it is unaccounted for;
///   * a *new* `{s}` in a registered function — the count no longer matches, and
///     the message prints the body so the reader sees which value appeared;
///   * a registered function that lost its placeholders, was renamed or was
///     emptied — the count no longer matches in the other direction, so a scan
///     cannot pass by finding nothing;
///   * a reason too short to be one.
///
/// What it does not do is discover a script-building function that nobody
/// registered in a file nobody registered. `expectAccounted` closes the first
/// half of that — a registered file's non-test placeholders must all be inside
/// registered functions or a declared prose count — and a wholly new module is
/// the part a human still has to add. It is one list, in one place, which is the
/// most that can be said for it.
pub const Exemption = struct {
    /// The function header, as `bodyOf` takes it: `"\npub fn ensure("`.
    header: []const u8,
    /// Exactly how many `{s}` placeholders its body carries.
    placeholders: usize,
    /// Exactly how many placeholders sit inside a quote the template owns —
    /// the `'{` shape. Almost always zero, and the default is zero so an entry
    /// has to say otherwise out loud. `script.stage` is the one place in this
    /// tree where it is not, and `why` carries the argument for it.
    quoted: usize = 0,
    /// Why none of them can be a `Word`. Not optional and not a word: this is
    /// the thing the per-file exemption did not have.
    why: []const u8,
};

/// The shortest a reason may be. A `why` of "ok" is a blanket exemption with
/// extra steps.
pub const min_reason_len: usize = 24;

pub const ExemptionError = error{
    /// A registered function does not splice what it says it splices.
    ExemptionMiscounted,
    /// A reason too short to be one.
    ExemptionUnreasoned,
    /// Two entries name the same function.
    ExemptionDuplicated,
    /// A registered script builder owns the quotes around a placeholder, which
    /// is the shape no reason can justify.
    QuotedPlaceholderInScript,
    /// A registered file has `{s}` outside every registered function and
    /// outside its declared prose count.
    RawValueUnaccounted,
};

/// Checks one file's exemptions against its own source, and returns how many
/// raw values they accounted for.
///
/// `bodies` are the function bodies, already extracted by the caller — `bodyOf`
/// lives in `control.zig` and this file does not import it. Parallel to
/// `exemptions`, and asserted so.
pub fn expectExempted(
    file: []const u8,
    exemptions: []const Exemption,
    bodies: []const []const u8,
) ExemptionError!usize {
    std.debug.assert(exemptions.len == bodies.len);
    var accounted: usize = 0;
    for (exemptions, bodies, 0..) |exemption, body, i| {
        if (exemption.why.len < min_reason_len) {
            std.debug.print(
                \\
                \\{s}: the exemption for `{s}` gives no reason for the {d} raw value(s) it
                \\splices ("{s}"). An exemption that does not say what it exempts and why is
                \\the per-file exemption this mechanism replaced.
                \\
            , .{ file, exemption.header, exemption.placeholders, exemption.why });
            return error.ExemptionUnreasoned;
        }
        for (exemptions, 0..) |other, j| {
            if (j == i) continue;
            if (std.mem.eql(u8, other.header, exemption.header)) {
                std.debug.print(
                    \\
                    \\{s}: `{s}` is registered twice, so the two reasons cover each other and
                    \\neither count means anything.
                    \\
                , .{ file, exemption.header });
                return error.ExemptionDuplicated;
            }
        }
        const found = scan(body);
        // The clause that is almost never exempted, counted here rather than
        // over the whole file: a CLI module quotes paths in its *English* —
        // `fatal("cannot open '{s}'")` — and reads as six violations file-wide
        // while being none. A nonzero declaration is an argument its `why` has
        // to carry, and the default of zero is what makes it an argument
        // somebody had to make.
        if (found.quoted_placeholders != exemption.quoted) {
            std.debug.print(
                \\
                \\{s}: `{s}` puts {d} placeholder(s) inside a quote the template owns, and its
                \\exemption declares {d}. The quotes escape nothing, so the first apostrophe in
                \\the value ends the word and the rest of it becomes syntax — this is the shape
                \\thirty sites in `transfer.zig` had. Render the value with `shell.word` and drop
                \\the quotes; `{{f}}` writes its own. If the value provably cannot hold an
                \\apostrophe, raise `quoted` and say why in the same breath as the rest.
                \\
                \\The declared reason is:
                \\  {s}
                \\
                \\{s}
                \\
            , .{ file, exemption.header, found.quoted_placeholders, exemption.quoted, exemption.why, body });
            return error.QuotedPlaceholderInScript;
        }
        if (found.string_placeholders != exemption.placeholders) {
            std.debug.print(
                \\
                \\{s}: `{s}` splices {d} raw value(s) into shell text, and its exemption
                \\declares {d}.
                \\
                \\The declared reason is:
                \\  {s}
                \\
                \\If a value was added, that reason was written for the other ones — say what
                \\the new value is and why a shell must read it as syntax rather than as one
                \\word, or render it through `shell.word`/`shell.cwd` and drop the count. If a
                \\value was removed, lower the count so the next reader is not told this
                \\function still splices something it does not.
                \\
                \\The body this gate read:
                \\{s}
                \\
            , .{ file, exemption.header, found.string_placeholders, exemption.placeholders, exemption.why, body });
            return error.ExemptionMiscounted;
        }
        accounted += found.string_placeholders;
    }
    return accounted;
}

/// Checks that a registered file has no raw value outside its registered
/// functions, beyond a declared count of placeholders that are not shell text
/// at all.
///
/// The half that catches a *new* script-building function. `accounted` is what
/// `expectExempted` returned; `prose` is the file's declared number of `{s}`
/// that reach no host — an error sentence, a JSON document, a diagnostic. Its
/// reason is stated at the call site next to the number.
///
/// Test bodies are excluded from the denominator, and only they: a `{s}` inside
/// a `test` block builds a fixture for a stand-in executor and cannot reach a
/// host, while a `{s}` anywhere else in the file might. Counting them would tie
/// this gate to every fixture edit, which is how a gate stops being read.
pub fn expectAccounted(
    file: []const u8,
    source: []const u8,
    accounted: usize,
    prose: usize,
) ExemptionError!void {
    const outside = nonTestScan(source).string_placeholders;
    if (outside != accounted + prose) {
        std.debug.print(
            \\
            \\{s}: {d} raw value(s) outside its `test` blocks, and its registry accounts for
            \\{d} in registered functions plus {d} declared as prose.
            \\
            \\A `{{s}}` appeared, or moved, somewhere this registry does not describe. Decide
            \\which it is: if it splices into remote shell text, register the function that
            \\builds it and say why each value must stay raw; if it is an error sentence or a
            \\document that reaches no host, raise the prose count and say so there. Adding
            \\the file to a scan list is what this mechanism replaced — the next unscanned
            \\thing is a function, not a file.
            \\
        , .{ file, outside, accounted, prose });
        return error.RawValueUnaccounted;
    }
}

/// `scan`, over the lines that are not inside a top-level `test` block.
///
/// The block rule is the one `zig fmt` guarantees: a top-level declaration
/// starts in column zero, so a `test` there runs to the next `}` in column
/// zero. Nothing in this tree nests a top-level declaration.
pub fn nonTestScan(source: []const u8) Scan {
    var out: Scan = .{
        .quoted_placeholders = 0,
        .string_placeholders = 0,
        .word_placeholders = 0,
    };
    var in_test = false;
    var lines = std.mem.splitScalar(u8, source, '\n');
    while (lines.next()) |raw_line| {
        if (!in_test and std.mem.startsWith(u8, raw_line, "test ")) in_test = true;
        if (!in_test) {
            const line = scanLine(codeOf(raw_line));
            out.quoted_placeholders += line.quoted_placeholders;
            out.string_placeholders += line.string_placeholders;
            out.word_placeholders += line.word_placeholders;
        }
        if (in_test and std.mem.eql(u8, raw_line, "}")) in_test = false;
    }
    return out;
}

test "a shell word is every byte literal, and the apostrophe is the only one rewritten" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Each of these is an ordinary path on an ordinary host, and each of them is
    // a byte the shell reads as syntax when it is not quoted.
    const cases = [_][]const u8{
        "/srv/app/out.bin",
        "/data/John's files/x",
        "/data/it's/all/'quotes'",
        "/srv/two words/a b",
        "/srv/\"double\"/x",
        "/srv/$HOME/x",
        "/srv/`whoami`/x",
        "/srv/a;rm -rf ~/x",
        "/srv/a\nb/x",
        "/srv/a|b&&c/x",
        "/srv/*/?/[a]",
        "'",
        "''''",
        "",
    };

    for (cases) |raw| {
        const quoted = try quote(arena, raw);
        try t.expectEqual(quotedLen(raw), quoted.len);
        // It is one word, and it is the value. Not "it contains the value":
        // the assertion is on what a shell would split this into.
        const got = try words(arena, quoted);
        if (raw.len == 0) {
            try t.expectEqual(@as(usize, 1), got.len);
            try t.expectEqualStrings("", got[0]);
        } else {
            try t.expectEqual(@as(usize, 1), got.len);
            try t.expectEqualStrings(raw, got[0]);
        }
        // And `{f}` is the same bytes as `quote`, so a template and a
        // materialised word cannot disagree.
        try t.expectEqualStrings(quoted, try std.fmt.allocPrint(arena, "{f}", .{word(raw)}));
    }

    // The exact POSIX form, pinned. A quoter that produced `'\''` as `\'` or as
    // `'"'"'` would pass every round-trip assertion above against this same
    // reader while being wrong about what a shell does.
    try t.expectEqualStrings("'/data/John'\\''s files/x'", try quote(arena, "/data/John's files/x"));
    try t.expectEqualStrings("''\\'''", try quote(arena, "'"));
}

test "the reader refuses to model what it does not implement" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // The failure an unescaped apostrophe produces. This is the whole defect,
    // seen from the host's side: the word does not end where the template
    // thought it did.
    try t.expectError(error.UnbalancedQuote, words(arena, "[ -f '/data/John's files/x' ]"));
    // Constructs this reader does not implement are refused, not treated as
    // ordinary bytes — a reader that guessed would report word boundaries the
    // shell does not have, and every gate resting on it would be measuring
    // nothing.
    try t.expectError(error.UnsupportedQuoting, words(arena, "echo \"a b\""));
    try t.expectError(error.UnsupportedQuoting, words(arena, "echo a\\"));

    // An unquoted backslash makes the next byte literal, which is what `'\''`
    // rests on — so `\ ` does not separate two words.
    const escaped = try words(arena, "echo a\\ b");
    try t.expectEqual(@as(usize, 2), escaped.len);
    try t.expectEqualStrings("a b", escaped[1]);

    // Unquoted whitespace separates; quoted whitespace does not.
    const got = try words(arena, "wc -c < '/srv/two words/a b'");
    try t.expectEqual(@as(usize, 4), got.len);
    try t.expectEqualStrings("/srv/two words/a b", got[3]);
}

test "gate: the scan sees both shapes of the defect and counts what it looked at" {
    const t = std.testing;

    // A single-quoted placeholder, in each spelling the defect had.
    try t.expectEqual(@as(usize, 1), scan("\\\\[ -f '{[path]s}' ]").quoted_placeholders);
    try t.expectEqual(@as(usize, 2), scan("mv -f '{s}' '{s}'").quoted_placeholders);
    // An escaped literal brace is not a placeholder. `Tmux.jobLaunchLine`
    // writes `printf '{{\"v\":…` and it is correct; a scan that flagged it
    // would be turned off.
    try t.expectEqual(@as(usize, 0), scan("printf '{{\"v\":{d}}}'").quoted_placeholders);
    // The fixed shape.
    try t.expectEqual(@as(usize, 0), scan("\\\\[ -f {[path]f} ]").quoted_placeholders);
    try t.expectEqual(@as(usize, 1), scan("\\\\[ -f {[path]f} ]").word_placeholders);

    // A raw slice reaching a template is caught whether or not it is quoted.
    try t.expectEqual(@as(usize, 1), scan("rm -f {[path]s}").string_placeholders);
    try t.expectEqual(@as(usize, 0), scan("rm -f {[path]f}").string_placeholders);
    // A width or an index is not a specifier this cares about.
    try t.expectEqual(@as(usize, 0), scan("seek={[len]d} mode={[mode]o}").string_placeholders);
    // `{{` is skipped whole, so its second brace cannot open a placeholder that
    // swallows the rest of the line.
    try t.expectEqual(@as(usize, 0), scan("{{s}").string_placeholders);

    // Comments come off, and only comments. A doc comment that names the shape
    // it forbids — `transfer.zig`'s header names `'{[path]s}'` to say what was
    // wrong with it — must not be a permanent failure, because a gate that
    // cannot be satisfied gets deleted.
    try t.expectEqual(@as(usize, 0), scan("//! thirty places, `'{[path]s}'` and friends").quoted_placeholders);
    try t.expectEqual(@as(usize, 0), scan("    const x = 1; // '{[path]s}'").quoted_placeholders);
    // A `//` inside a string is not a comment, so the code after it is still
    // scanned. Both spellings, because both appear in this tree.
    try t.expectEqual(@as(usize, 1), scan("        \\\\curl http://h '{[path]s}'").quoted_placeholders);
    try t.expectEqual(@as(usize, 1), scan("    x(\"//\", \"'{[path]s}'\");").quoted_placeholders);
    // And a real comment on a line that also holds real code does not hide the
    // code before it.
    try t.expectEqual(@as(usize, 1), scan("    x(\"'{[path]s}'\"); // fine").quoted_placeholders);
}

test "a working directory is one word, and the only expansion in it is ours" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Every case is a directory somebody could reasonably have in
    // `terminus workspace set`, and the assertion is on the words a shell would
    // split the rendering into — not on the quote marks.
    const cases = [_]struct {
        dir: []const u8,
        rendered: []const u8,
        /// The single word the host sees, before it expands `$HOME`.
        word: []const u8,
    }{
        .{ .dir = "/srv/app", .rendered = "'/srv/app'", .word = "/srv/app" },
        // The case that made a command silently not run: `cd /srv/two words`
        // is `cd` with two operands, which a POSIX shell refuses outright.
        .{ .dir = "/srv/two words", .rendered = "'/srv/two words'", .word = "/srv/two words" },
        .{ .dir = "/data/John's app", .rendered = "'/data/John'\\''s app'", .word = "/data/John's app" },
        // Not a command. Each of these was syntax before `Cwd` existed.
        .{ .dir = "/tmp; rm -rf ~", .rendered = "'/tmp; rm -rf ~'", .word = "/tmp; rm -rf ~" },
        .{ .dir = "/tmp/`whoami`", .rendered = "'/tmp/`whoami`'", .word = "/tmp/`whoami`" },
        .{ .dir = "/tmp/a\nb", .rendered = "'/tmp/a\nb'", .word = "/tmp/a\nb" },
        .{ .dir = "/tmp/a|b&&c", .rendered = "'/tmp/a|b&&c'", .word = "/tmp/a|b&&c" },
        // A directory named like an option. `cd '-P'` is `cd -P`, which lands
        // in the home directory and reports success; `cdInto` puts `--` in
        // front, and this is the word that has to arrive for that to matter.
        .{ .dir = "-P", .rendered = "'-P'", .word = "-P" },
        // The two spellings of the remote home, which have to keep expanding.
        .{ .dir = "~", .rendered = "$HOME", .word = "$HOME" },
        .{ .dir = "$HOME", .rendered = "$HOME", .word = "$HOME" },
        .{ .dir = "~/app", .rendered = "$HOME/'app'", .word = "$HOME/app" },
        .{ .dir = "$HOME/app", .rendered = "$HOME/'app'", .word = "$HOME/app" },
        // …and the remainder after the prefix is still just data.
        .{ .dir = "~/two words", .rendered = "$HOME/'two words'", .word = "$HOME/two words" },
        .{ .dir = "~/a;b", .rendered = "$HOME/'a;b'", .word = "$HOME/a;b" },
    };

    var checked: usize = 0;
    for (cases) |case| {
        checked += 1;
        const rendered = try std.fmt.allocPrint(arena, "{f}", .{cwd(case.dir)});
        try t.expectEqualStrings(case.rendered, rendered);
        // One word, and it is the one expected. `words` is the inverse of the
        // quoter, so this is what the *host* would split the text into.
        const got = try words(arena, rendered);
        try t.expectEqual(@as(usize, 1), got.len);
        try t.expectEqualStrings(case.word, got[0]);
        // The only unquoted text a `Cwd` ever emits is its own `$HOME`.
        if (!std.mem.startsWith(u8, rendered, home_expansion))
            try t.expect(rendered[0] == '\'');
    }
    try t.expectEqual(@as(usize, 14), checked);
}

test "cdInto composes one command, and the directory in it is one word" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // The exact case the audit measured against a real `sh`: a `--cwd` with a
    // space used to render `cd /srv/two words`, which answers `cd: too many
    // arguments` — so the `&&` never fired and the command was never sent.
    const line = try cdInto(arena, "/srv/two words", "true");
    try t.expectEqualStrings("cd -- '/srv/two words' && (true)", line);

    const got = try words(arena, line);
    // `cd`, `--`, the directory, `&&`, and the parenthesised command. `words`
    // does not model operators, so `&&` and `(true)` come back as words — what
    // matters is that the directory is exactly one of them and is intact.
    try t.expectEqual(@as(usize, 5), got.len);
    try t.expectEqualStrings("cd", got[0]);
    try t.expectEqualStrings("--", got[1]);
    try t.expectEqualStrings("/srv/two words", got[2]);
    try t.expectEqualStrings("&&", got[3]);
    try t.expectEqualStrings("(true)", got[4]);

    // Every byte a shell reads as syntax, inside a directory, still one word —
    // and the command after it still exactly the operator's own text.
    const nasty = try cdInto(arena, "/srv/John's app; rm -rf ~", "make test");
    const nasty_words = try words(arena, nasty);
    try t.expectEqual(@as(usize, 6), nasty_words.len);
    try t.expectEqualStrings("/srv/John's app; rm -rf ~", nasty_words[2]);

    // `--` before the operand, always: without it a directory named `-P` is an
    // option and `cd` succeeds in the home directory instead.
    try t.expect(std.mem.startsWith(u8, try cdInto(arena, "-P", "true"), "cd -- '-P'"));

    // A home-relative directory keeps expanding, and the command after it is
    // untouched — it is the operator's own program text and quoting it would
    // run it as a filename.
    try t.expectEqualStrings(
        "cd -- $HOME/'app' && (make -j4 && ./run)",
        try cdInto(arena, "~/app", "make -j4 && ./run"),
    );
}

test "gate: a working directory that cannot keep its meaning is refused, not rendered quietly" {
    const t = std.testing;

    // Refused, with the reason named. Each of these expanded before `Cwd`
    // existed, so rendering it as a literal path would trade an injection for a
    // directory nobody has — and a `cd` that fails is an exit code on an
    // attempt whose command never ran.
    const refused = [_][]const u8{
        "", // not a directory at all
        "$RELEASE/app", // a variable that is not $HOME
        "$HOME/$RELEASE", // …including after the prefix
        "/srv/`date +%F`", // command substitution
        "~deploy/app", // another account's home
    };
    var named: usize = 0;
    for (refused) |dir| {
        const why = cwdRefusal(dir) orelse {
            std.debug.print(
                \\
                \\`{s}` is accepted as a working directory. It relied on an expansion `Cwd`
                \\does not perform, so it is now a literal path — which `cd` will not find,
                \\which makes the `&&` not fire, which settles an exit code for a command
                \\that never ran. That is the failure this whole change exists to remove,
                \\arriving from the other side.
                \\
            , .{dir});
            return error.UnexpandableCwdAccepted;
        };
        try t.expect(why.len >= min_reason_len);
        named += 1;
    }
    try t.expectEqual(@as(usize, 5), named);

    // Accepted, because `Cwd` renders each of these as exactly what it means.
    // The apostrophe and the semicolon are the point: they are refused by
    // nothing and dangerous in nothing, because they are quoted.
    const accepted = [_][]const u8{
        "/srv/app",
        "/srv/two words",
        "/data/John's app",
        "/tmp; rm -rf ~",
        "~",
        "~/app",
        "$HOME",
        "$HOME/app",
        "-P",
    };
    var passed: usize = 0;
    for (accepted) |dir| {
        if (cwdRefusal(dir)) |why| {
            std.debug.print("\n`{s}` was refused: {s}\n", .{ dir, why });
            return error.SafeCwdRefused;
        }
        passed += 1;
    }
    try t.expectEqual(@as(usize, 9), passed);
}

test {
    _ = @import("shell_test.zig");
}
