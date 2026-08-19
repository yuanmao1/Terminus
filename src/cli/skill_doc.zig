//! The one parser for `skill/SKILL.md`, and the one place that holds what the
//! document claims against what the code actually has.
//!
//! **Why this file exists.** The emitter structs cannot drift from themselves:
//! they have no defaults, so a branch that omits a key does not compile. What
//! can drift is the document. `skill/SKILL.md` publishes each verb's key set and
//! each key's value vocabulary as prose — a count, a never-null list, a nullable
//! list, a parenthetical of values — and prose does not fail to build when
//! somebody adds a field, renames one, takes a `?` off, or invents a word no
//! branch emits.
//!
//! So the prose is parsed and held against `@typeInfo`. Nullability is read from
//! the field's type rather than from a list maintained beside it, because a list
//! maintained beside it is one more thing to forget.
//!
//! **Why it is a module rather than two copies.** It was two copies:
//! `cmd_job.zig` held `KillJson` and `RemovalJson` against their paragraphs, and
//! `cmd_session.zig` grew a second, smaller transcription of the same machinery
//! for `RemovalJson`'s own paragraph because those helpers were file-private.
//! Two copies of a drift detector is itself a drift risk — the detector can
//! drift, and a fix applied to one copy and not the other shows up as a gate
//! that quietly checks less than it says. Four consumers read it now and every
//! new JSON contract adds pressure for a third copy, so it has one home.
//!
//! **What is not here.** The gates themselves. Each one names types that are
//! private to the command that emits them (`KillJson`, `RemovalJson`,
//! `error_code`, `state`), so they stay in those files and call in here for the
//! reading. This file knows how to read English; it does not know what any verb
//! publishes.
//!
//! The parse is a literal read of English, and will break if those paragraphs
//! are reflowed. That is the trade, taken deliberately: a reformat that defeats
//! the check fails the gate rather than quietly checking nothing. Every failure
//! below prints the literal it was looking for, so the repair is to the
//! document — or, if the wording genuinely moved on, to the needle in the gate
//! that passed it.
const std = @import("std");

/// The same text `terminus setup` ships, embedded rather than read: the gates run
/// wherever the tests run, with no working directory to be wrong about.
///
/// `@embedFile` of the build's `terminus_skill` anonymous import (`build.zig`),
/// not a path — and it must stay that way. A runtime read would make every gate
/// depend on the process's working directory, which is the one thing a compile
/// -time check has no business depending on.
pub const text = @embedFile("terminus_skill");

/// One named error per parse step, so a failure says which reading broke rather
/// than that "the document is wrong".
pub const ParseError = error{
    SkillAnchorMissing,
    SkillCountUnreadable,
    SkillListUnterminated,
    SkillParensUnbalanced,
    SkillCodeSpanUnterminated,
};

/// The document and the code disagree. Distinct from every `ParseError`: those
/// mean the gate could not read the claim, this means it read it and it is false.
pub const DriftError = error{SkillKeySetDrifted};

/// Whatever follows `needle` in `hay`, or a loud failure naming it.
pub fn after(hay: []const u8, needle: []const u8, what: []const u8) ParseError![]const u8 {
    const at = std.mem.indexOf(u8, hay, needle) orelse {
        std.debug.print(
            \\
            \\skill/SKILL.md: cannot find {s}.
            \\  looked for the literal: "{s}"
            \\A gate parses that text to learn what the document claims about the --json
            \\key sets and value vocabularies. If the paragraph was reworded or reflowed,
            \\fix the needle in the gate that passed it (src/cli/cmd_job.zig or
            \\src/cli/cmd_session.zig); deleting the gate puts the document back to
            \\drifting from the structs unnoticed — which is how it came to publish 11 keys
            \\for a 12-field struct.
            \\
        , .{ what, needle });
        return error.SkillAnchorMissing;
    };
    return hay[at + needle.len ..];
}

/// The end of the paragraph starting at `s`: its first blank line, or all of it.
/// A line of only spaces, tabs or `\r` is blank, so the parse does not depend on
/// how the checkout wrote its line endings.
pub fn paragraphEnd(s: []const u8) usize {
    var i: usize = 0;
    while (std.mem.indexOfScalarPos(u8, s, i, '\n')) |nl| {
        var j = nl + 1;
        while (j < s.len and (s[j] == ' ' or s[j] == '\t' or s[j] == '\r')) j += 1;
        if (j == s.len or s[j] == '\n') return nl;
        i = nl + 1;
    }
    return s.len;
}

/// The paragraph `needle` opens: everything after it up to the next blank line.
pub fn paragraphAfter(needle: []const u8, what: []const u8) ParseError![]const u8 {
    const opened = try after(text, needle, what);
    return opened[0..paragraphEnd(opened)];
}

/// One list out of the prose: the text after `label`, ending either at `end`
/// or — when `end` is null — at the first `.` that is outside both parentheses
/// and code spans.
///
/// Parenthetical asides are the reason this is not a plain search for the next
/// period: the document puts examples in them (`killed`, `removed`), puts each
/// key's value vocabulary in one, and even puts a reference to one key inside the
/// note on another (`conflict`, inside the note on `exitCode`). Those are not
/// entries of the list being read.
pub fn segment(
    hay: []const u8,
    label: []const u8,
    end: ?[]const u8,
    what: []const u8,
) ParseError![]const u8 {
    const rest = try after(hay, label, what);
    if (end) |needle| {
        const at = std.mem.indexOf(u8, rest, needle) orelse {
            std.debug.print(
                \\
                \\skill/SKILL.md: found {s} but not where it ends.
                \\  looked for the literal: "{s}"
                \\
            , .{ what, needle });
            return error.SkillListUnterminated;
        };
        return rest[0..at];
    }
    var depth: usize = 0;
    var in_code = false;
    for (rest, 0..) |c, i| {
        if (c == '`') {
            in_code = !in_code;
            continue;
        }
        if (in_code) continue;
        switch (c) {
            '(' => depth += 1,
            ')' => {
                if (depth == 0) return unbalanced(what, rest);
                depth -= 1;
            },
            '.' => if (depth == 0) return rest[0..i],
            else => {},
        }
    }
    std.debug.print(
        \\
        \\skill/SKILL.md: {s} runs to the end of the file without a sentence-ending
        \\period outside its parenthetical asides, so the gate cannot tell where the
        \\list stops.
        \\
    , .{what});
    return error.SkillListUnterminated;
}

fn unbalanced(what: []const u8, seg: []const u8) ParseError {
    std.debug.print(
        \\
        \\skill/SKILL.md: unbalanced parentheses in {s}, so the gate cannot tell the
        \\entries from the asides.
        \\  text read: "{s}"
        \\
    , .{ what, seg });
    return error.SkillParensUnbalanced;
}

/// Every `code span` in `seg` that is not inside a parenthetical aside.
///
/// A label found with zero entries after it is refused rather than reported as an
/// empty list: it is never right, and it is the shape in which a gate checks
/// nothing while passing.
pub fn entries(
    gpa: std.mem.Allocator,
    seg: []const u8,
    what: []const u8,
) (ParseError || std.mem.Allocator.Error)![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    errdefer out.deinit(gpa);
    var depth: usize = 0;
    var i: usize = 0;
    while (i < seg.len) : (i += 1) {
        switch (seg[i]) {
            '(' => depth += 1,
            ')' => {
                if (depth == 0) return unbalanced(what, seg);
                depth -= 1;
            },
            '`' => {
                const close = std.mem.indexOfScalarPos(u8, seg, i + 1, '`') orelse {
                    std.debug.print(
                        \\
                        \\skill/SKILL.md: an unclosed `code span` in {s}.
                        \\  text read: "{s}"
                        \\
                    , .{ what, seg });
                    return error.SkillCodeSpanUnterminated;
                };
                if (depth == 0) try out.append(gpa, seg[i + 1 .. close]);
                i = close;
            },
            else => {},
        }
    }
    if (depth != 0) return unbalanced(what, seg);
    if (out.items.len == 0) {
        std.debug.print(
            \\
            \\skill/SKILL.md: {s} is empty — the gate found the label but no `entries`
            \\after it, which is never right and would otherwise check nothing.
            \\  text read: "{s}"
            \\
        , .{ what, seg });
        return error.SkillListUnterminated;
    }
    return out.toOwnedSlice(gpa);
}

/// `segment` and `entries` in one call, which is how every gate uses them.
///
/// A value list published as a parenthetical is read by passing the opening
/// `` "`key` (" `` as the label and `")"` as the end: the code spans inside it are
/// then at depth 0 of the segment, which is exactly what `entries` collects.
pub fn list(
    gpa: std.mem.Allocator,
    hay: []const u8,
    label: []const u8,
    end: ?[]const u8,
    what: []const u8,
) (ParseError || std.mem.Allocator.Error)![]const []const u8 {
    return entries(gpa, try segment(hay, label, end, what), what);
}

fn has(items: []const []const u8, entry: []const u8) bool {
    for (items) |item| if (std.mem.eql(u8, item, entry)) return true;
    return false;
}

/// One documented list against the one the code actually has, in both
/// directions. Both matter: an entry the document invented is as wrong as one
/// it forgot, and a field whose `?` came or went shows up as one of each.
pub fn expectList(
    what: []const u8,
    documented: []const []const u8,
    actual: []const []const u8,
) DriftError!void {
    var drifted = false;
    for (documented) |entry| {
        if (!has(actual, entry)) {
            std.debug.print(
                \\
                \\skill/SKILL.md lists `{s}` among {s}, and the code has nothing of that
                \\name there — it was removed, renamed, or moved to the other list.
                \\
            , .{ entry, what });
            drifted = true;
        }
    }
    for (actual) |entry| {
        if (!has(documented, entry)) {
            std.debug.print(
                \\
                \\The code has `{s}` among {s}, and skill/SKILL.md does not list it there.
                \\
            , .{ entry, what });
            drifted = true;
        }
    }
    if (!drifted and documented.len != actual.len) {
        std.debug.print(
            \\
            \\skill/SKILL.md repeats an entry among {s}: {d} listed for {d} in the code.
            \\
        , .{ what, documented.len, actual.len });
        drifted = true;
    }
    if (drifted) return error.SkillKeySetDrifted;
}

/// One documented value list against the namespace the branches actually spell it
/// from.
///
/// Held against a namespace rather than a transcription of one, so renaming a
/// word rewrites the check along with the code. The namespaces exist for this.
pub fn expectVocabulary(
    gpa: std.mem.Allocator,
    what: []const u8,
    documented: []const []const u8,
    comptime namespace: type,
) (DriftError || std.mem.Allocator.Error)!void {
    var actual: std.ArrayList([]const u8) = .empty;
    defer actual.deinit(gpa);
    inline for (@typeInfo(namespace).@"struct".decls) |decl| {
        try actual.append(gpa, @field(namespace, decl.name));
    }
    try expectList(what, documented, actual.items);
}

/// Holds one verb's documented key set against the struct that emits it.
///
/// `heading` is the line the count lives on, e.g. ``"\n`job kill` — "``, and the
/// paragraph it opens is everything up to the next blank line.
///
/// `count_suffix` is what follows the number in that paragraph — `" keys."` where
/// the sentence ends there, `" keys,"` where it goes on. Parameterised rather than
/// guessed at: a reader that accepted either would also accept a paragraph whose
/// count sentence had been rewritten into something else entirely.
pub fn expectKeySet(
    gpa: std.mem.Allocator,
    comptime T: type,
    heading: []const u8,
    count_suffix: []const u8,
    never_null_what: []const u8,
    nullable_what: []const u8,
) !void {
    const fields = @typeInfo(T).@"struct".fields;

    var never_null: std.ArrayList([]const u8) = .empty;
    defer never_null.deinit(gpa);
    var nullable: std.ArrayList([]const u8) = .empty;
    defer nullable.deinit(gpa);
    inline for (fields) |f| {
        // From the type. A hand-kept list of which keys are optional would be
        // exactly the drift this gate exists to catch.
        const bucket = if (@typeInfo(f.type) == .optional) &nullable else &never_null;
        try bucket.append(gpa, f.name);
    }

    const para = try paragraphAfter(heading, "the key-set paragraph it opens");
    // The needle carries a leading newline so it can only match at the start of
    // a line; nothing below wants to print it.
    const line = std.mem.trimStart(u8, heading, "\n");

    const keys_at = std.mem.indexOf(u8, para, count_suffix) orelse {
        std.debug.print(
            \\
            \\skill/SKILL.md: "{s}" is not followed by "<n>{s}", so the gate cannot read
            \\the count the document claims.
            \\
        , .{ line, count_suffix });
        return error.SkillCountUnreadable;
    };
    const claimed = std.fmt.parseInt(usize, para[0..keys_at], 10) catch {
        std.debug.print(
            \\
            \\skill/SKILL.md: "{s}" is followed by "{s}{s}", which is not a number.
            \\
        , .{ line, para[0..keys_at], count_suffix });
        return error.SkillCountUnreadable;
    };
    if (claimed != fields.len) {
        std.debug.print(
            \\
            \\skill/SKILL.md says "{s}{d}{s}"; the struct has {d} fields. This is the
            \\exact drift the gate was added for.
            \\
        , .{ line, claimed, count_suffix, fields.len });
        return error.SkillKeySetDrifted;
    }

    const documented_never_null = try list(gpa, para, "Never null: ", null, never_null_what);
    defer gpa.free(documented_never_null);
    const documented_nullable = try list(gpa, para, "Nullable: ", null, nullable_what);
    defer gpa.free(documented_nullable);

    // Both, before either is raised: a field that gained or lost its `?` is
    // one complaint from each list, and reporting half of that would send the
    // reader looking for a rename that never happened.
    const never_null_verdict = expectList(never_null_what, documented_never_null, never_null.items);
    const nullable_verdict = expectList(nullable_what, documented_nullable, nullable.items);
    try never_null_verdict;
    try nullable_verdict;
}
