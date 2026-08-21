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
//! half is held by the scan at the bottom of this file, which reads
//! `transfer.zig`'s own source and refuses both shapes the defect can take.
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
    while (lines.next()) |raw_line| scanLine(codeOf(raw_line), &out);
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

fn scanLine(line: []const u8, out: *Scan) void {
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

test "gate: transfer.zig has no spelling for a raw value in a remote script" {
    const t = std.testing;
    const found = scan(@embedFile("transfer.zig"));

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
    try t.expectEqual(@as(usize, 0), found.string_placeholders);

    // **And the file still has templates in it.** A count, so a scan over a
    // module that was emptied, renamed, or had its script text moved somewhere
    // else fails here instead of reporting that it found nothing wrong.
    //
    // A floor with room in it, not the exact count. The conversion produced
    // thirty; pinning thirty makes this gate fail for any edit that consolidates
    // a line of shell — two of the no-clobber mutations do exactly that, and
    // both already have a gate of their own that says what is wrong. A gate that
    // fails for somebody else's reason is a gate people learn to read past.
    try t.expect(found.word_placeholders >= 20);
}

test "gate: Tmux.zig puts no placeholder inside a shell quote either" {
    const t = std.testing;
    const found = scan(@embedFile("session/Tmux.zig"));

    // The same first clause, on the other module that writes remote shell text.
    // It already passes — `Tmux` reaches for `shell.quote` where it interpolates
    // a value the operator wrote, and the one `'{` in the file is `printf '{{`,
    // an escaped literal brace in a JSON format string.
    try t.expectEqual(@as(usize, 0), found.quoted_placeholders);

    // Not the `{s}` clause. `Tmux` interpolates session names and request ids
    // bare and on purpose: a session name is validated to `[a-zA-Z0-9._-]`
    // before it reaches here (`cmd_session.validateName`), a request id is a
    // ULID this program minted, and the log and result directories are
    // `$HOME/...` — which have to stay unquoted to expand at all. Demanding
    // `Word` here would be demanding `cd '~/app'`, which is a directory almost
    // nobody has. Counted, so this exemption is a statement about a file that
    // still has script text in it.
    try t.expect(found.string_placeholders >= 10);
}
