#!/usr/bin/env python3
"""Read-only census of Terminus stores on this machine.

Written because a drop-and-recreate migration was justified by the claim
"no non-test checkpoint row exists anywhere", and that claim was a one-off
command nobody else could re-run. This makes it reproducible, and — just as
important — makes its *scope* explicit: it reports what it searched, so the
answer is "no such row among these N databases under these roots" rather
than an unfalsifiable "anywhere".

    python tools/enumerate_stores.py
    python tools/enumerate_stores.py --json docs/evidence/store-census.json
    python tools/enumerate_stores.py --raw
    python tools/enumerate_stores.py --root D:/ --root E:/data

Exit status is the point of the whole thing, and it carries **two independent
verdicts**. Either one withholds authorisation:

* `offender_found` — a checkpoint row exists in a store outside this repo's
  own test scratch. That is exactly the condition under which the v11
  drop-and-recreate would destroy something somebody meant to keep.
* `coverage_incomplete` — the census could not see everything the scope it
  declares says it covers.

What "the scope it declares" means is no longer implied by prose and by
whatever the walk happened to do. It is an object in the artifact,
`effective_scope`, and it states in one sentence what the census claims:
every regular file enumerated by a *successful* directory listing at or below
`depth_max` levels beneath a searched root, minus the declared exclusions,
never following a reparse point, and with content read only from files that
pass `content_read_rule`. Every path the walk then declined or failed to read
lands in exactly one category of `failure_matrix`, and each category carries
its own definition, its own count and a `drives_coverage_incomplete` flag.
`coverage_incomplete` is `any(count > 0)` over exactly the flagged ones, so a
category cannot be moved between the two sets to change a number without the
move being visible in the artifact.

Seven categories withhold authorisation, because in each of them the census
could not answer:

    inside_but_not_visited   a link target inside a declared root that no walk
                             ever read, and that no declared depth bound
                             explains. This is the defect the matrix was built
                             to expose: `covered_by != null` used to be
                             published as though it meant "visited"
    depth_shadowed_target    the same, except that this census's own declared
                             `depth_max` is what stopped it. Still a gap — the
                             content was not read — but a named one: raising
                             `--depth` or declaring the target a root closes
                             it, and both change the declared scope
    unreadable               an OS error stopped the census learning what a
                             path is, where it points, or what it holds
    vanished                 listed, then genuinely gone before it was opened
    path_too_long            WinError 206 / ENAMETOOLONG. Permanent, and a
                             re-run will never close it
    not_a_regular_file       stat succeeded and the path is neither a link,
                             nor a directory, nor a regular file
    root_unresolvable        the environment variable naming a root was unset,
                             so no path could be formed at all

Six do not, because in each the census either got an answer or declined
something it had declared in advance that it would decline:

    out_of_declared_scope    a link whose target is outside every searched
                             root. Declining to leave the declared scope is
                             the scope working, not a failure to cover it.
                             Nothing is deleted: the records are kept in full
                             and they stay in the corroboration artifact's
                             `could_not_see`
    depth_limited            a directory below `depth_max`, which the artifact
                             publishes as part of the scope
    excluded                 a directory matching a published exclusion
    dangling                 a reparse point whose target does not exist:
                             lstat succeeds, stat says ENOENT
    not_content_read         a file enumerated and never opened, because it
                             failed the published `content_read_rule`
    root_absent              a declared root whose raw stat said ENOENT

`within_declared_root` and `actually_visited` are two facts, and they are two
recorded fields on every link. A target inside a declared root means the census
*promised* to cover those bytes; it does not mean any walk read them. The two
were one field once, and four junctions into `%TEMP%` six levels down were
published as covered territory when nothing had ever opened them.

Both facts are decided about the path the link actually points at, which is not
always the string it stores. A relative target — `mklink /D link ..\\t`, git
with `core.symlinks=true`, npm, pnpm — resolves against the directory holding
the link and against nothing else; it used to be resolved against the *census
process's* working directory, so scope, depth, visitation and reason were
decided about a fabricated path, and the category could change by running the
tool from a different directory. `target` and `target_resolved` are both
recorded, because a reader who sees only the resolved path cannot tell a
relative link from an absolute one.

"We looked and there is nothing there" is an answer, and "we could not look"
is not. The dangling-link case is worth naming because it was got wrong twice.
Windows reports a reparse point whose target is missing as WinError 3, the same
error a genuinely deleted directory gives, so 18 stale build junctions were
counted as directories that "vanished mid-walk under a concurrent build"; they
had not vanished during anything, and they reproduced identically on every run.
The second mistake was quieter: the test was `os.path.lexists(p) and not
os.path.exists(p)`, and both of those swallow `OSError` and return False, so a
target that exists and denies access was filed as "nothing there" — a gap
laundered into a verified empty set. It is now a raw `os.lstat`/`os.stat` pair
in a `try`, and anything but a clean ENOENT from the second call is
`unreadable`.

    0   searched everything it set out to search, and found no offender.
        The only status that clears the v11 drop-and-recreate to be written
    1   offender_found
    2   coverage_incomplete
    3   both
    64  usage error — deliberately not 2, so a mistyped flag can never be
        read as a coverage result
    65  a committed artifact would have carried a drive-letter path, a UNC
        host or the account name, so it was not written. Deliberately not 2
        for the same reason: a redaction failure is not a fact about this
        machine's stores

The three census codes are a bitmask: `status & 1` asks "was a row found",
`status & 2` asks "were there holes", and no caller has to enumerate the
combinations. This split exists because the second verdict used to be
invisible: the script exited 0 with 23 unexaminable paths in its own report,
and that 0 was read as clearance. "We found nothing" and "we could not look"
are different answers and must not share a status.

A path that vanished mid-walk — a build tree deleted underneath the scan — is
incomplete coverage exactly like a path that refused to open. It is not
excused, because a database that existed for part of the walk is a database
the census cannot speak for. The two are reported separately only because they
tell an operator to do different things: re-run when the machine is quiet
versus go and look at what is denying access.

Two outputs, because they have different readers:

* `--json` writes the **committed** artifact. It carries the two verdicts, the
  coverage numbers, the filesystem-effect summary, and per store its
  `user_version`, whether it has a `transfer_checkpoints` table, and whether
  that table holds any row — which is the whole of what the migration argument
  rests on. Every path in it is tokenised, and that is now enforced rather
  than hoped for: the finished document is read back before it is written, and
  a drive-letter path, a UNC host or the account name anywhere in it refuses
  the write and exits 65. It was previously an allow-list of eight prefixes
  with nothing checking the output — `--root D:/data`, the example above, put
  `D:\\data` in the artifact verbatim. It carries no file sizes, no counts
  of anybody's servers, keys, memories or facts, and no request ids. Every path
  segment below a tokenised prefix is replaced by an opaque id — see
  `path_coarsening` — because tokenisation rewrites root prefixes and emitted
  everything below them verbatim, which is how a private GitHub org, a private
  repository name and a PR number came to be committed here. It also carries no
  path at all for the two frontier categories: `depth_limited` and `excluded`
  are counted, not retained, because the count is the whole of what they
  establish.
* `--raw` writes **everything the census saw**, untokenised: absolute paths,
  file sizes, user-data counts and checkpoint request ids. It defaults to
  `docs/evidence/raw/store-census.raw.json`, under a directory that is
  git-ignored, because this output names absolute paths on whoever's machine
  ran it and is not fit to commit.

Read-only, in two senses that are worth separating:

* No database page and no WAL frame is written. Every file is opened with
  SQLite's `mode=ro` URI, which refuses writes at the VFS layer — an INSERT on
  such a connection fails with "attempt to write a readonly database".
* Not literally no filesystem effect: reading a WAL-mode database creates its
  `-shm` (32 KiB shared-memory index) and an *empty* `-wal` if they are absent,
  and updates the read marks inside an existing `-shm`. Sidecars, never content.

The second sentence used to be an assertion backed by one check — whether a
`-shm` had appeared, which missed the `-wal` entirely. It is now a measurement:
every candidate's `.db`, `-wal` and `-shm` is digested (size, mtime_ns, content
hash) before the run and again afterwards, and every difference is reported.
The one that matters is called out by name: a change to a `.db` file itself, or
a `-wal` that gained bytes, would contradict the claim above. Note that the
census cannot distinguish its own effect from a concurrent writer's; if a test
run is touching a store while this runs, that shows up here too, which is the
right failure mode for an audit.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import re
import sqlite3
import stat
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from collections import Counter
from dataclasses import dataclass, asdict, field
from pathlib import Path

# A Terminus store is identified by the tables 0.1.x created, not by filename:
# the file may be a copy called anything, and other tools ship .db files that
# are none of our business.
SIGNATURE = {"servers", "keys", "memories", "facts"}

SQLITE_MAGIC = b"SQLite format 3\x00"

# The smallest SQLite page, and the greatest common divisor of every legal page
# size (512 … 65536, all powers of two). A whole SQLite database is an exact
# number of pages, so its size is always a multiple of this. Used as a cheap
# pre-filter before the header sniff, because on Windows the open() itself is
# the expensive part (~17 ms/file through the antivirus filter driver) and this
# rejects ~96% of files using the size scandir already returned for free. What
# it can hide: a *partially copied* or trailing-garbage store, whose size is
# arbitrary — but SQLite would refuse to open that too, so it could not have
# been counted either way.
PAGE_FLOOR = 512

# The sniff is one open + one 16-byte read per file: no CPU, all syscall, and
# the GIL is released for both. Threads turn ~75 s of serial opens into ~10 s,
# and a census nobody wants to wait for is a census nobody re-runs.
SNIFF_WORKERS = 16

# Bounds the wait when a candidate is a live database another process holds a
# lock on. Without it a single locked file can stall the census for the SQLite
# default of 5 s, and there are hundreds of browser-profile databases out here.
OPEN_TIMEOUT_S = 2.0

# Head/tail size for the content digest of a large file. The first 4 KiB covers
# the SQLite header, and the header holds the file change counter (offset 24)
# and the version-valid-for number (offset 92), both bumped by any committed
# write — so a page write in the middle of a 362 MB store still shows up here.
DIGEST_ENDS = 4096


def default_roots() -> list[tuple[str, Path | None]]:
    """Every root this run intends to search, in walk order, label and path.

    The path is `None` for exactly one reason: the environment variable naming
    the root was unset, so no path could be formed at all. That is the first
    of the two ways a root can fail to be searched, and they look alike and are
    not alike:

    * **The variable is unset**, so nothing is known about where that root
      would have been, let alone what is inside it. It withholds
      authorisation, under `root_unresolvable`.
    * **The variable resolved and the directory does not exist.** The caller
      decides that against the filesystem with a raw `os.stat` in a `try` —
      never `Path.exists()`, which swallows `OSError` and would file a root
      that exists and denies access as a verified empty set. A directory that
      does not exist contains no databases, so ENOENT there is an answer
      (`root_absent`) rather than a blind spot, and anything else from that
      stat is `unreadable` and does withhold.

    Both are returned to the caller as declared intent, before outcome, so the
    artifact shows what the run meant to search as well as what it reached.
    """
    declared: list[tuple[str, Path | None]] = []
    for var, sub in (("APPDATA", "terminus"), ("LOCALAPPDATA", "terminus"), ("TEMP", "")):
        base = os.environ.get(var)
        label = f"%{var}%" + (f"/{sub}" if sub else "")
        if not base:
            declared.append((label + " (environment variable unset)", None))
            continue
        declared.append((label, Path(base) / sub if sub else Path(base)))
    for name in (
        ".terminus", "Desktop", "Downloads", "Documents",
        # Added because `~/Documents` contains Windows' legacy compatibility
        # junctions `My Videos`, `My Pictures` and `My Music`, which point
        # here and carry a deny-everyone ACL. The census cannot read the
        # junctions, so before these were declared the link rule counted three
        # gaps. Declaring the targets searches strictly more rather than
        # excusing anything, and the gaps close because the bytes are now read
        # under their real names.
        "Videos", "Pictures", "Music",
    ):
        home = Path.home() / name
        declared.append((str(home), home))
    return declared


# Directories whose databases are known not to be ours and are numerous enough
# to dominate the walk. Recorded here rather than applied silently, because an
# exclusion is part of what the census does and does not cover.
EXCLUDE_DIR_NAMES = {
    "node_modules", ".git", ".venv", "venv", "__pycache__", ".codegraph",
}
# Matched against the path with separators normalised to "/", which is what the
# three `AppData/Local/...` entries always needed: they were sitting in the
# directory-name set, where a multi-component string can never equal a single
# path component, so they excluded nothing.
EXCLUDE_PATH_FRAGMENTS = [
    "AppData/Local/Google", "AppData/Local/Microsoft", "AppData/Local/Mozilla",
    "playwright_chromium", "pw-apply-profile", "codex-apply-extension",
]

MAX_DEPTH = 6

# The two verdicts, as bits, so a caller can ask which one refused without
# enumerating combinations. 64 is EX_USAGE from sysexits(3): argparse's own
# default for a bad flag is 2, which here already means "coverage incomplete",
# and a mistyped `--root` must not be reported as a fact about the machine.
EXIT_CLEAR = 0
EXIT_OFFENDER = 1
EXIT_INCOMPLETE = 2
# EX_DATAERR. A committed artifact that would carry a drive-letter path, a UNC
# host or the account name is not written at all, and that refusal is not a
# fact about this machine's stores either — so, like the usage error, it gets a
# status of its own outside the two-bit verdict space rather than borrowing 2.
EXIT_REDACTION = 65
EXIT_USAGE = 64

# Under `docs/evidence/` so it sits beside the artifact it is the unredacted
# form of, and in its own directory so the ignore rule that keeps it out of the
# repository is one line and obvious: `docs/evidence/raw/`.
RAW_DEFAULT = "docs/evidence/raw/store-census.raw.json"

# Committed, unlike the raw census: it is tokenised, and it is the one artifact
# whose subject is a claim rather than a machine. Named `-corroboration` and
# not `-clearance` because the filename is the first thing anyone reads and it
# must not promise what the file cannot deliver.
CORROBORATION_DEFAULT = "docs/evidence/v11-recut-corroboration.json"

EXIT_HELP = """\
exit status carries two independent verdicts, and either one withholds
authorisation for the v11 drop-and-recreate:

  0   searched everything it set out to search, and found no offender.
      The only status that clears the recut to be written
  1   offender_found       a checkpoint row in a store outside this repo's
                           own test scratch
  2   coverage_incomplete  a category of failure_matrix flagged
                           drives_coverage_incomplete has a non-zero count
  3   both
  64  usage error, deliberately not 2 — a mistyped flag is not a fact about
      this machine and must not be reported as one
  65  a committed artifact would have carried a drive-letter path, a UNC host
      or the account name. It was not written; the previous file, if any, is
      untouched. Deliberately not 2 for the same reason as 64

The three census codes are a bitmask: `status & 1` is the row, `status & 2`
the holes. What counts as a hole is not a judgement made per run: every
declined or failed path lands in exactly one failure_matrix category, each
category declares once and for all whether it withholds, and the verdict is
`any(count > 0)` over the ones that do. Seven withhold: inside_but_not_visited,
depth_shadowed_target, unreadable, vanished, path_too_long,
not_a_regular_file, root_unresolvable. Six do not: out_of_declared_scope,
depth_limited, excluded, dangling, not_content_read, root_absent — every one
of them either an answer the census got, or a bound the artifact publishes in
effective_scope before the walk starts.
"""


class Parser(argparse.ArgumentParser):
    """Exits 64 on a usage error rather than argparse's default of 2.

    2 is `coverage_incomplete` here. A caller that reads the status to decide
    whether the recut is safe must never be handed a bad-flag error dressed as
    a finding about the filesystem.
    """

    def error(self, message: str):  # noqa: D102 - argparse's own contract
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: error: {message}\n")



@dataclass
class Store:
    path: str
    bytes: int
    user_version: int
    has_checkpoints_table: bool
    checkpoint_rows: int | None
    checkpoint_request_ids: list[str]
    is_repo_scratch: bool
    counts: dict = field(default_factory=dict)


@dataclass
class Census:
    # The verdicts come first because they are the answer and everything below
    # them is the working. Both are recorded even when false, so a reader can
    # tell "this census asked and the answer was no" from "this census did not
    # think to ask" — which is what the single-verdict version could not say.
    offender_found: bool
    coverage_incomplete: bool
    coverage_gaps: dict
    coverage_verified_empty: dict
    exit_code: int
    # What the census claims to have covered, as a definition rather than as
    # prose somewhere else, so the claim can be checked against the definition
    # instead of against the code.
    effective_scope: dict
    # Every declined or failed path, in exactly one category each.
    failure_matrix: dict
    links_by_reason: dict
    roots_searched: list[str]
    roots_absent: list[str]
    roots_unresolvable: list[str]
    roots_unreadable: list[dict]
    excluded_dir_names: list[str]
    excluded_path_fragments: list[str]
    max_depth: int
    # Directories whose os.scandir returned without raising. This is the
    # denominator `depth_limited` is read against, and it is the same set
    # `actually_visited` is answered from, so a reader can check the ratio
    # instead of taking it from prose.
    directories_listed: int
    files_seen: int
    files_size_filtered: int
    files_sniffed: int
    non_sqlite_files: int
    sqlite_candidates: int
    stores: list[Store]
    repo_scratch_without_checkpoints: int
    non_store_sqlite: int
    sqlite_unreadable: list[dict]
    unexaminable: list[dict]
    not_regular_files: list[dict]
    links: list[dict]
    frontier_depth_limited: list[dict]
    frontier_excluded: list[dict]
    filesystem_effect: dict
    seconds: float


# Why a path could not be examined, decided by exception type and by asking the
# filesystem one more question with raw syscalls, rather than by matching on a
# message — the message is localised, and on this machine WinError 3 arrives in
# Chinese.
#
# P2: within the error family, the most specific *verified* cause wins, in this
# exact order, so that the vaguest label can never absorb a case that has a
# name. Each of the four prints a different instruction to an operator, which
# is the whole reason for the ordering.
#
# 1. path_too_long — WinError 206 / ENAMETOOLONG. Tested first because Python
#    maps winerror 206 to FileNotFoundError errno 2, so without this test it is
#    filed as "vanished" and told to re-run, which will never close it.
# 2. dangling  — raw lstat succeeds AND raw stat raises ENOENT. The path is a
#    reparse point whose target does not exist: it resolves cleanly and the
#    answer is "nothing there". NOT a hole. This is the only label that removes
#    a gap, which is why its test is the strictest one here.
# 3. vanished  — FileNotFoundError/NotADirectoryError where raw lstat ALSO
#    raises ENOENT. A real mid-walk deletion. The census cannot speak for it.
# 4. unreadable — everything else. The census could not look, and "could not
#    look" is not an answer.
def is_name_too_long(exc: OSError) -> bool:
    return getattr(exc, "winerror", None) == 206 or exc.errno == errno.ENAMETOOLONG


def read_target(path: str) -> tuple[str | None, OSError | ValueError | None]:
    """The target string, or the exception that stopped us spelling it.

    Kept apart from *whether* the link resolves, because the two questions come
    apart: a WSL symlink (tag 0xA000001D) resolves to nothing in the Win32
    namespace *and* defeats `readlink`.
    """
    try:
        return os.readlink(path), None
    except (OSError, ValueError) as exc:
        return None, exc


def classify(path: str, exc: OSError) -> tuple[str, str | None]:
    """(reason, target) for a path the census could not examine."""
    if is_name_too_long(exc):
        return "path_too_long", None
    if not isinstance(exc, (FileNotFoundError, NotADirectoryError)):
        return "unreadable", None
    try:
        os.lstat(path)
    except FileNotFoundError as link_exc:
        # Nothing at all is there under that spelling any more.
        return ("unreadable" if is_name_too_long(link_exc) else "vanished"), None
    except OSError:
        return "unreadable", None
    # The link itself is there. Is the other end?
    try:
        os.stat(path)
    except FileNotFoundError as target_exc:
        if is_name_too_long(target_exc):
            return "unreadable", read_target(path)[0]
        return "dangling", read_target(path)[0]
    except OSError:
        return "unreadable", read_target(path)[0]
    # It exists, it resolves, and it still would not open.
    return "unreadable", None


REMEDY = {
    "unreadable": "go and look at what is denying access",
    "vanished": "re-run when the machine is quiet",
    "path_too_long": "shorten the path or enable long paths; a re-run will not close this",
    "dangling": None,
}


def error_record(path: str, exc: OSError, origin: str,
                 carried_sqlite_header: bool | None = None) -> dict:
    """One failed decision, carrying the origin that produced it.

    `origin` is mandatory because six different failures land in `unreadable`
    and each is a different instruction. The per-origin counts are published at
    `failure_matrix.categories.unreadable.by_origin` — not at
    `unreadable_by_origin`, which this docstring named for a while and which has
    never existed — so that the entry for `sqlite_open` still says what the old
    separate `sqlite_unreadable` counter said. It is a Counter over the origins
    a run *observed*, so an origin that produced no records has no key rather
    than a key holding 0; the six legal values are enumerated in the category's
    own definition, where a reader can find them whether or not they fired.
    """
    reason, target = classify(path, exc)
    return {
        "path": path,
        "error": f"{type(exc).__name__}: {exc}",
        "origin": origin,
        "reason": reason,
        "target": target,
        # Same two facts as on a link record, for the same reason: a relative
        # target is not a path until it is resolved against the link's own
        # directory. Nothing here decides scope from it, and it is recorded so
        # that the `dangling` category reads the same whichever of its two
        # decision sites produced the entry.
        "target_resolved": None if target is None else resolve_target(path, target),
        "resolution": "target_absent" if reason == "dangling" else "unknown",
        "carried_sqlite_header": carried_sqlite_header,
        # The walk only reaches paths under a searched root, so membership is
        # settled by construction here rather than by a prefix test.
        "within_declared_root": True,
        "actually_visited": None if reason == "dangling" else False,
        "not_tested_because": "target does not exist" if reason == "dangling" else None,
        "remedy": REMEDY[reason],
    }



# Every path that reaches the JSON goes through this first. The artifact is
# committed to a public repository and its subject is *where stores are*, not
# whose machine this is; a token keeps the location and drops the identity.
# Longest value wins, so %TEMP% beats %LOCALAPPDATA%. Replacement is anywhere
# in the string, not just at the start, because the paths that leak are mostly
# the ones an OSError embedded in the middle of its own message.
def tokenise(text: str) -> str:
    for token, value in sorted(PATH_TOKENS, key=lambda kv: -len(kv[1])):
        for form in (value, value.replace("\\", "\\\\"), value.replace("\\", "/")):
            # Case-insensitive, because Windows paths are. A reparse point
            # records the target in whatever case the link was created with,
            # so `C:\users\<name>\desktop` and `C:\Users\<Name>\Desktop` are
            # the same directory and a literal match redacts only one of them.
            text = re.sub(re.escape(form), token.replace("\\", "\\\\"), text,
                          flags=re.IGNORECASE)
    return text


PATH_TOKENS: list[tuple[str, str]] = []


# `tokenise` is an allow-list — eight environment-derived prefixes and the
# account name — and everything outside them used to be emitted verbatim: the
# prefix was rewritten and every segment below it was not. `coarsen` covers
# those segments now; these rules do not test for them, because a coarsened
# segment is already unreadable. Nothing read
# the document back, so "every path in it is tokenised" was a property held by
# luck: `--root D:/data`, the invocation in this module's own docstring, puts
# `D:\data` straight into `effective_scope.roots_declared`, and a junction into
# `C:\Windows\Temp` or a UNC share lands verbatim in a link target. That
# %PROGRAMFILES%, %PROGRAMFILES(X86)% and %PROGRAMDATA% are in the token list
# at all is the record of this failing once already: they were added after a
# link to a JDK was noticed in an artifact. "Add a token after a leak is
# spotted" is not a mechanism.
#
# These rules run over the tokenised document that is about to be written —
# over the output, not the inputs — so a path arriving through a field nobody
# thought of is caught by the same test as one arriving through a known field.
REDACTION_RULES: list[tuple[str, str]] = [
    # C:\x, d:/x. The commonest shape, and the one the docstring's own example
    # produces. Also catches an untokenised extended-prefix target, because
    # `\\?\D:\x` contains `D:\`.
    ("drive_letter_path", r"[A-Za-z]:[\\/]"),
    # \\host\share, the only absolute path shape the rule above cannot see.
    #
    # It is anchored to the start of a path rather than matched anywhere,
    # because a doubled separator is not a UNC host and the document is full of
    # them: `OSError.__str__` embeds the filename as a *repr*, so a perfectly
    # tokenised `%TEMP%\hsperfdata_<user>\31172` arrives inside an error string
    # as `%TEMP%\\hsperfdata_<user>\\31172`. (That is also why `tokenise`
    # substitutes the doubled form of every token.) A path starts at the start
    # of a value or after a quote, bracket, comma, equals or space — so both
    # spellings of a real UNC host are caught, `\\host` on its own and
    # `\\\\host` inside a repr — and `\\?\` / `\\.\`, the Win32 device
    # namespaces, are not hosts and are excluded.
    ("unc_path", r"(?:^|(?<=['\"\s(\[=,]))\\\\(?:\\\\)?(?![\\?.])"),
]


def redaction_rules() -> list[tuple[str, re.Pattern]]:
    """The rules, plus the account name when it is long enough to test for.

    The length guard is the same one `build_path_tokens` applies to the same
    string and for the same reason: a two- or three-letter account name occurs
    inside ordinary words, so substituting it would shred the document and
    testing for it would fail on every run. Both say so rather than pretending
    the shorter case is covered.
    """
    rules = [(name, re.compile(pattern)) for name, pattern in REDACTION_RULES]
    user = os.environ.get("USERNAME", "")
    if len(user) >= 4:
        rules.append(("account_name", re.compile(re.escape(user), re.IGNORECASE)))
    return rules


def redaction_violations(value, rules: list[tuple[str, re.Pattern]],
                         where: str = "") -> list[dict]:
    """Every string in the document that is not fit for a public repository.

    Returned rather than raised, and reported with the JSON path that carries
    it, because the operator's next question is always "which field", and a
    document that fails this test must not be written at all — a partially
    redacted artifact is the failure mode this is here to prevent.
    """
    if isinstance(value, dict):
        found: list[dict] = []
        for k, v in value.items():
            here = f"{where}.{k}" if where else str(k)
            found += redaction_violations(str(k), rules, here)
            found += redaction_violations(v, rules, here)
        return found
    if isinstance(value, list):
        found = []
        for index, item in enumerate(value):
            found += redaction_violations(item, rules, f"{where}[{index}]")
        return found
    if isinstance(value, str):
        hits = []
        for name, expression in rules:
            match = expression.search(value)
            if match:
                hits.append({"json_path": where, "rule": name,
                             "matched": match.group(0), "value": value})
        return hits
    return []


# FILE_ATTRIBUTE_REPARSE_POINT. Set on Windows junctions and symlinks alike.
# `os.path.islink` is False for a junction — Python reserves that for
# IO_REPARSE_TAG_SYMLINK — so islink alone cannot see the thing that matters
# here, and `entry.is_dir(follow_symlinks=False)` returns True for one, which
# is how junctions came to be walked into as if they were directories.
FILE_ATTRIBUTE_REPARSE_POINT = 0x400

# Win32's own test for "this reparse point stands in for another path"
# (`IsReparseTagNameSurrogate`). It matters because the reparse attribute alone
# is far too broad: OneDrive placeholders, AppExecLink stubs and deduplicated
# files all carry it and are ordinary readable files. Treating those as links
# would quietly drop real candidates out of the census — the opposite mistake
# to the one that let junctions be walked into. Junctions (0xA0000003) and
# symlinks (0xA000000C) have the bit; the others do not.
IO_REPARSE_TAG_NAME_SURROGATE = 0x20000000


def is_link(path: str, st: os.stat_result) -> bool:
    if getattr(st, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT:
        return bool(getattr(st, "st_reparse_tag", 0) & IO_REPARSE_TAG_NAME_SURROGATE)
    return stat.S_ISLNK(st.st_mode)


def strip_extended(target: str) -> str:
    """`\\\\?\\C:\\x` and `\\\\?\\UNC\\host\\share` are the same paths as `C:\\x`
    and `\\\\host\\share`. Windows hands back the extended form from a reparse
    point, and it will not compare equal to a root spelled the ordinary way."""
    if target.startswith("\\\\?\\UNC\\"):
        return "\\\\" + target[len("\\\\?\\UNC\\"):]
    if target.startswith("\\\\?\\"):
        return target[len("\\\\?\\"):]
    return target


def resolve_target(link_path: str, target: str) -> str:
    """The path a link actually points at, from the link's own location.

    `os.readlink` returns the target *as stored*, and a symlink created with
    SYMLINK_FLAG_RELATIVE stores a relative string — `mklink /D link ..\\t`,
    git with `core.symlinks=true`, npm and pnpm all produce them. A relative
    target resolves against the directory holding the link, and against nothing
    else; feeding the raw string to `key` resolved it against the *census
    process's* current working directory instead, so `link -> docs` under
    `%TEMP%` was answered about `<cwd>/docs`, and the answer changed when the
    tool was run from a different directory. Every downstream field —
    `within_declared_root`, `covering_root`, the two depths, `actually_visited`
    and `reason` — was then decided about a path that does not exist.

    `os.path.join` is doing three jobs and each is the Windows-correct one: an
    absolute target with a drive replaces the base entirely, a rooted but
    drive-less target (`\\foo`) keeps the link's drive, and a relative target is
    appended. `normpath` then collapses the `..` a relative target usually
    carries — lexically, which is the same namespace `key` already works in and
    the only one available to a census that never follows a link. The result is
    not `realpath`'d for that same reason: the point is where the target *is*,
    not what is at the far end of a chain of them.
    """
    return os.path.normpath(os.path.join(os.path.dirname(link_path),
                                         strip_extended(target)))


def key(path: str) -> str:
    """One spelling per file, so a store is not counted twice for being
    reachable two ways. Case-folded because Windows paths are.

    `abspath` here resolves against the process's current working directory,
    which is correct for the walk — every path it hands in is already absolute
    — and is exactly wrong for a link target, which resolves against the link's
    own directory. `resolve_target` settles that before anything reaches here,
    and nothing else may hand this function a relative path.
    """
    return os.path.normcase(os.path.abspath(path))


def key_prefix(path: str) -> str:
    """`key(path)` with exactly one trailing separator, for prefix tests.

    A drive root is the whole reason this exists. `key(str(Path("D:/")))` is
    `d:\\`, which already ends in a separator, so the obvious `key(r) + os.sep`
    spells `d:\\\\` and no path on that drive starts with it: `--root D:/` —
    the invocation in this module's own docstring — matched nothing, and every
    link target on that drive was published as `out_of_declared_scope` when it
    was inside the declared scope and unvisited. That is the gap-removing
    direction, in the one category the matrix exists to protect.
    """
    folded = key(path)
    return folded if folded.endswith(os.sep) else folded + os.sep


def containing_roots(target: str, roots: list[Path]) -> list[Path]:
    """Every declared root that contains this target, in walk order.

    Membership is the whole of the scope question for a link: a link is not a
    directory and is never walked into, so what matters about one is whether
    the bytes it points at are inside the territory the census declared. It is
    emphatically *not* the whole of the coverage question — that is
    `actually_visited`, and it is answered from the walk's own record. The two
    were one field once, and being inside a root was published as though it
    meant the content had been read.

    `target` must already be absolute and extended-prefix-stripped: for a link
    that is what `resolve_target` returns, and nothing else may call this.
    """
    t = key(target)
    return [r for r in roots if t == key(str(r)) or t.startswith(key_prefix(str(r)))]


def longest_root(target: str, roots: list[Path]) -> Path | None:
    """P7: attribution is longest-prefix, not first-match.

    First-match names `~/Desktop` as the covering root of a path inside this
    repository, which is true and useless: the depth arithmetic derived from it
    is then measured from the wrong place. Membership is unaffected by the
    choice; only the name and the number are.
    """
    inside = containing_roots(target, roots)
    return max(inside, key=lambda r: len(key(str(r)))) if inside else None


def first_root(target: str, roots: list[Path]) -> Path | None:
    """The root whose walk reaches this target first, which owns its depth
    budget. `roots` must be in walk order.

    Since per-root depth, walk order is longest-prefix first, so this returns
    the same root as `longest_root` and the budget it owns is the full
    `depth_max`. Both are still computed and both are still published: their
    agreeing on every record is what shows no root is being walked on an
    ancestor root's leftovers, and if the walk order is ever changed back the
    two will disagree in the artifact rather than silently in the code."""
    inside = containing_roots(target, roots)
    return inside[0] if inside else None


def depth_below(root: Path, target: str) -> int:
    """Levels of descent from `root` to `target`, counted the way `collect`
    counts them: the root itself is 0 and each component below it is one more.

    The slice is taken past `key_prefix`, not past `key(root) + 1`, so a root
    that already ends in a separator — `D:\\` — does not lose a level.
    `target` must already be absolute; see `containing_roots`."""
    t, r = key(target), key(str(root))
    if t == r:
        return 0
    return len([part for part in t[len(key_prefix(str(root))):].split(os.sep) if part])


# Tokens whose environment variable was empty on this run, so no substitution
# for them exists. Recorded rather than skipped in silence: a token that is not
# built cannot redact anything, and the failure it produces downstream — a
# drive-letter path in the finished document — names the *field*, not the
# reason. The list is printed, and it is named again in the redaction failure
# so an operator is not sent to `build_path_tokens` to add a token that is
# already there and merely unset.
TOKENS_UNBUILT: list[str] = []


def build_path_tokens(repo: Path) -> None:
    PATH_TOKENS.clear()
    TOKENS_UNBUILT.clear()
    for token, value in (
        ("<repo>", str(repo)),
        ("%TEMP%", os.environ.get("TEMP", "")),
        ("%LOCALAPPDATA%", os.environ.get("LOCALAPPDATA", "")),
        ("%APPDATA%", os.environ.get("APPDATA", "")),
        ("%USERPROFILE%", os.environ.get("USERPROFILE", "")),
        # System install roots. Nothing about the roots themselves is private —
        # they are the same on every Windows machine — but a link out of the
        # searched territory records its target, and a JDK under Program Files
        # is the commonest such target here. Tokenising them keeps "this
        # artifact contains no absolute path" true as a property somebody can
        # check in one grep, instead of a claim that has to be re-argued path by
        # path every time a new link shows up. What is *below* them is a vendor
        # and product tree and is coarsened like everything else below a
        # prefix; the remedy a gap under one of them names is therefore no
        # longer literally actionable from the committed artifact, and the
        # operator has to read the path out of the --raw census. That is the
        # price of not publishing directory names nobody vetted.
        ("%PROGRAMFILES%", os.environ.get("ProgramFiles", "")),
        ("%PROGRAMFILES(X86)%", os.environ.get("ProgramFiles(x86)", "")),
        ("%PROGRAMDATA%", os.environ.get("ProgramData", "")),
    ):
        if value:
            PATH_TOKENS.append((token, value))
        else:
            TOKENS_UNBUILT.append(token)
    # Last, and shortest, so the directory tokens above win wherever they can.
    # This one exists for the names that *embed* the account rather than living
    # under its profile — `%TEMP%\hsperfdata_<user>` is the one on this machine.
    # Still guarded on length, because substituting a two-letter account name
    # everywhere would shred the document — but the guard no longer ends the
    # story. `account_name_publishable` refuses to write at all in that case,
    # rather than letting the one entry this census must keep producing carry
    # the account name into a public repository with nothing testing for it.
    user = os.environ.get("USERNAME", "")
    if len(user) >= 4:
        PATH_TOKENS.append(("<user>", user))
    else:
        TOKENS_UNBUILT.append("<user>")


# The account name is the one string in this scheme that has no fallback. The
# `<user>` token is skipped below four characters because a two- or
# three-letter name occurs inside ordinary words and substituting it would
# shred the document — and `redaction_rules` skips the matching test for the
# same reason, so on such a machine the name was neither replaced nor looked
# for. It was published, by exactly the entry this census is required to keep
# producing: `%TEMP%\hsperfdata_<user>` embeds the account name in a directory
# name, and that entry is what drives the red verdict.
#
# So this fails closed instead. No committed artifact is written, the run exits
# 65 like any other redaction failure, and the census verdict is still printed —
# what failed is the publishing, not the census.
def account_name_publishable() -> list[dict]:
    user = os.environ.get("USERNAME", "")
    if len(user) >= 4:
        return []
    why = ("USERNAME is unset, so this tool does not know the account name and can "
           "neither substitute nor test for it"
           if not user else
           f"USERNAME is {len(user)} characters, and this tool can neither substitute "
           "nor test for an account name that short: substituting it would rewrite "
           "ordinary words and testing for it would match them")
    return [{
        "json_path": "(whole document)",
        "rule": "account_name_untestable",
        "matched": "USERNAME" if user else "USERNAME (unset)",
        "value": (
            why + ". Paths on this machine still embed it — "
            "%TEMP%\\hsperfdata_<account> is the standard case — so the committed "
            "artifacts cannot be shown to be free of it and are not written. Run "
            "with an account name of four characters or more, or publish only the "
            "--raw census, which is git-ignored and never claimed to be redacted."
        ),
    }]


# Applied to the whole document rather than to a list of known path fields, so
# a field added later is covered without anyone remembering to add it here.
def tokenised(value):
    if isinstance(value, dict):
        return {k: tokenised(v) for k, v in value.items()}
    if isinstance(value, list):
        return [tokenised(v) for v in value]
    if isinstance(value, str):
        return tokenise(value)
    return value


# ---------------------------------------------------------------------------
# Coarsening: what happens to a path segment *below* the tokenised prefix.
#
# `tokenise` rewrites root prefixes and nothing else, so every segment below a
# prefix reached the committed artifacts verbatim. That is not a leak the token
# list can be extended to cover: those segments are not roots, no environment
# variable names them, and there is no list of them to allow. It is how a
# private GitHub org, a private repository name and a PR number came to be
# published — in `unreadable.entries[].path`, and again inside the `OSError`
# repr embedded in the same entries' `error` string, which is the copy nobody
# looked at.
#
# So every segment below the prefix is replaced, in the committed artifacts
# only, by an opaque id: `<seg:` plus the first COARSE_WIDTH hex digits of the
# SHA-256 of the *tokenised path prefix ending at that segment*, lower-cased,
# separators normalised to a single `/`. Four properties follow, and the scheme
# was chosen for exactly them:
#
# * **Deterministic.** The same input path yields the same id on every run, so
#   two runs are diffable and a gap that moved is visible as a gap that moved.
# * **Not a reversible encoding.** It is a digest, not a transform of the text.
#   Because the input is the whole prefix and not the segment alone, a
#   dictionary of likely directory names does not invert it either: an attacker
#   would have to guess the entire path.
# * **Structure-preserving.** One id per level, so the depth of a coarsened
#   path is still countable and still checks against the depth fields published
#   beside it, and two entries under a common parent still visibly share it.
# * **Visibly an id.** `<` and `>` are illegal in a Windows path component, so
#   `<seg:9f4c2a1b>` cannot be mistaken for a directory that exists, and it is
#   the same visual form as the `<repo>` and `<user>` tokens already in use.
#
# Two things stay in plaintext, and both are stated in the artifact rather than
# only here:
#
# * everything below `<repo>`, because that is this repository, it is public,
#   and the store table is unreadable without it;
# * segments matching COARSE_KEEP_SEGMENTS — an explicit, published allow-list
#   of segments that are themselves the evidence.
#
# Correlating a coarsened entry back to a real path: take the path from the
# git-ignored `--raw` census, tokenise it, normalise it, and hash each prefix.
# The recipe is published in `path_coarsening` so that is checkable rather than
# taken on trust.
COARSE_WIDTH = 8

# Segments kept verbatim because the segment *is* the evidence, each with the
# reason it earns the exemption. Anchored, narrow, and published: a reader can
# see exactly what is exempt, and nothing is exempt by accident.
COARSE_KEEP_SEGMENTS: list[tuple[str, str]] = [
    (r"^hsperfdata_",
     "the JVM's per-user performance-data directory. The one entry that "
     "reliably drives coverage_incomplete on this machine is a file inside it, "
     "held open by a live JVM, and a reader who cannot see what the directory "
     "is cannot tell that gap from a permissions problem worth chasing. The "
     "account name it embeds is already replaced by <user>."),
    (r"^_bazel_",
     "bazel's output base under the user profile. Thirteen of the "
     "out_of_declared_scope link targets are inside it, and the claim that "
     "they are a build cache rather than somebody's documents is exactly what "
     "this segment carries. The account name it embeds is already replaced by "
     "<user>."),
]

# The prefixes a path keeps in full: the token itself and every declared root,
# in tokenised form. Without this a coarsened `roots_searched` would say
# `%USERPROFILE%\<seg:1a2b3c4d>` and the scope claim — the artifact's central
# object — would be unreadable. Declared roots are not a disclosure: they are
# standard Windows profile directories, they are named in the design document,
# and they are the definition of what the census covers.
KEEP_PREFIXES: set[str] = set()

# `<user>` is a token but not a path prefix: it stands for a name that appears
# *inside* a segment (`hsperfdata_<user>`), never at the head of a path. Letting
# it anchor a path run would coarsen `hsperfdata_<user>\31172` against the
# prefix `<user>` and produce a different id for the same directory than the
# fully-rooted spelling of it does, which is exactly the diffability the ids
# exist to provide.
NON_PREFIX_TOKENS = {"<user>"}


def normal_path(text: str) -> str:
    """One spelling for hashing and for prefix tests: lower-case, forward
    slashes, no doubled separators. The doubled form matters: a path inside an
    `OSError` repr arrives as `%TEMP%\\\\hsperfdata_<user>\\\\31172`, and it
    must hash to the same ids as the plain `path` field beside it or the two
    copies of one path would coarsen to two different things."""
    collapsed = re.sub(r"[\\/]+", "/", text)
    return collapsed.lower()


def prefix_tokens() -> list[str]:
    return [token for token, _value in PATH_TOKENS if token not in NON_PREFIX_TOKENS]


def build_keep_prefixes(declared: list[tuple[str, Path | None]]) -> None:
    KEEP_PREFIXES.clear()
    for token in prefix_tokens():
        KEEP_PREFIXES.add(normal_path(token))
    for _label, path in declared:
        if path is not None:
            KEEP_PREFIXES.add(normal_path(tokenise(str(path))))


def coarse_id(prefix: str) -> str:
    return ("<seg:"
            + hashlib.sha256(normal_path(prefix).encode("utf-8")).hexdigest()[:COARSE_WIDTH]
            + ">")


def kept_segment(segment: str) -> bool:
    return any(re.search(pattern, segment, re.IGNORECASE)
               for pattern, _why in COARSE_KEEP_SEGMENTS)


def coarsen_run(root: str, tail: str) -> str:
    """Rewrite one token-prefixed path run, keeping the separators it came with.

    Separators are preserved exactly — one backslash, two backslashes inside a
    repr, or a forward slash — because the surrounding string is often an
    `OSError` message and mangling it would make the error unreadable for the
    sake of the path inside it.
    """
    verbatim = normal_path(root) == normal_path("<repo>")
    out = root
    prefix = root
    for separator, segment in re.findall(r"([\\/]{1,2})([^\\/]*)", tail):
        prefix = prefix + "/" + segment
        if not segment:
            out += separator
            continue
        if verbatim or normal_path(prefix) in KEEP_PREFIXES or kept_segment(segment):
            out += separator + segment
        else:
            out += separator + coarse_id(prefix)
    return out


def coarsen(text: str) -> str:
    """Coarsen every token-prefixed path run in one string.

    Anchored on the tokens rather than on a list of fields, for the same reason
    `tokenised` is applied to the whole document: a path arriving through a
    field nobody thought of is rewritten by the same rule as one arriving
    through a known field, and the `error` string that carried the original
    leak is covered without anyone having to parse it.

    A token not followed by a separator is left alone, so prose that mentions a
    token is untouched and only actual path runs are rewritten.
    """
    if not PATH_TOKENS:
        return text
    tokens = "|".join(re.escape(token) for token in
                      sorted(prefix_tokens(), key=len, reverse=True))
    return re.sub(rf"({tokens})((?:[\\/]{{1,2}}[^\\/\r\n\t\"']*)+)",
                  lambda m: coarsen_run(m.group(1), m.group(2)), text)


def coarsened(value):
    if isinstance(value, dict):
        return {k: coarsened(v) for k, v in value.items()}
    if isinstance(value, list):
        return [coarsened(v) for v in value]
    if isinstance(value, str):
        return coarsen(value)
    return value


def path_coarsening() -> dict:
    """The recipe, in the artifact, so a coarsened entry can be checked."""
    return {
        "what_this_is": (
            "Every path segment below the prefixes listed in kept_prefixes is "
            "replaced in this artifact by an opaque id of the form "
            "<seg:xxxxxxxx>. tokenise rewrites root prefixes and nothing else, "
            "so everything below a prefix used to be published verbatim; that "
            "is how a private GitHub org, a private repository name and a PR "
            "number were committed here, both in a path field and inside the "
            "OSError repr embedded in the error string beside it."
        ),
        "id_rule": (
            "<seg:> + the first {n} hex digits of SHA-256 over the tokenised "
            "path prefix ending at that segment, lower-cased with separators "
            "normalised to a single '/'. It is a digest of the whole prefix, "
            "not of the segment, so guessing a likely directory name does not "
            "invert it. The same input path yields the same id on every run, so "
            "two runs of this census can be diffed against each other."
        ).format(n=COARSE_WIDTH),
        "why_it_cannot_be_read_as_a_path": (
            "'<' and '>' are illegal in a Windows path component, so an id can "
            "never be mistaken for a directory that exists."
        ),
        "kept_prefixes": sorted(KEEP_PREFIXES),
        "kept_below_repo": (
            "Everything below <repo> is kept in full: it is this repository, it "
            "is already public, and the store table is unreadable without it."
        ),
        "kept_segments": [
            {"pattern": pattern, "why": why} for pattern, why in COARSE_KEEP_SEGMENTS
        ],
        "correlating_back": (
            "The un-coarsened paths are in the git-ignored --raw census "
            "(docs/evidence/raw/store-census.raw.json). To find the entry a "
            "given id stands for: tokenise the raw path with the same tokens, "
            "normalise it, and hash each prefix by id_rule. Nothing in this "
            "artifact recovers a segment without that file."
        ),
    }


# The committed artifact, built by naming what belongs in it rather than by
# deleting what does not. A field added to `Store` later is therefore absent
# from the public document until someone decides it belongs in a public
# repository, which is the opposite of how a redaction list fails.
#
# What it carries is what the claims in docs/m3a-artifact-transfer.md §7.0.1
# rest on: the two verdicts, the coverage numbers, the filesystem effect, and
# per store the three facts the migration argument turns on. What it drops is
# everything that is true of this machine rather than of the migration — file
# sizes, how many servers and keys and memories and facts somebody has, and
# the request ids of any checkpoint row found.
def public(census: Census) -> dict:
    return {
        "offender_found": census.offender_found,
        "coverage_incomplete": census.coverage_incomplete,
        "coverage_gaps": census.coverage_gaps,
        "coverage_verified_empty": census.coverage_verified_empty,
        "exit_code": census.exit_code,
        # What happened to every path segment below a tokenised prefix, and how
        # to correlate a coarsened entry back to the --raw census.
        "path_coarsening": path_coarsening(),
        "record_caps": cap_report({
            "sqlite_unreadable": census.sqlite_unreadable,
            "unexaminable": census.unexaminable,
            "not_regular_files": census.not_regular_files,
            "links": census.links,
            "filesystem_effect.contradicting_read_only":
                census.filesystem_effect["contradicting_read_only"],
        }),
        # The scope claim, as a definition the reader can check the numbers
        # against. Its roots_*, excluded_* and depth_max fields are populated
        # from the same values as the top-level copies below rather than
        # recomputed, so the two cannot drift apart.
        "effective_scope": census.effective_scope,
        "failure_matrix": census.failure_matrix,
        "links_by_reason": census.links_by_reason,
        "roots_searched": census.roots_searched,
        "roots_absent": census.roots_absent,
        "roots_unresolvable": census.roots_unresolvable,
        "roots_unreadable": census.roots_unreadable,
        "excluded_dir_names": census.excluded_dir_names,
        "excluded_path_fragments": census.excluded_path_fragments,
        "max_depth": census.max_depth,
        "directories_listed": census.directories_listed,
        "files_seen": census.files_seen,
        "files_size_filtered": census.files_size_filtered,
        "files_sniffed": census.files_sniffed,
        "non_sqlite_files": census.non_sqlite_files,
        "sqlite_candidates": census.sqlite_candidates,
        # v11 drops and recreates `transfer_checkpoints`. What matters about a
        # store is therefore what version it stopped at, whether it has the
        # table, and whether the recut would take a row with it — three facts,
        # and a count of rows is not one of them.
        "stores": [
            {
                "path": s.path,
                "user_version": s.user_version,
                "has_checkpoints_table": s.has_checkpoints_table,
                "has_checkpoint_rows": None if s.checkpoint_rows is None else s.checkpoint_rows > 0,
                "is_repo_scratch": s.is_repo_scratch,
            }
            for s in census.stores
        ],
        "repo_scratch_without_checkpoints": census.repo_scratch_without_checkpoints,
        "non_store_sqlite": census.non_store_sqlite,
        # The holes keep their paths, their errors and their reason: they are
        # the evidence for `coverage_incomplete`, and a verdict whose grounds
        # are a bare count cannot be checked by a reader. Bounded at
        # ERROR_SAMPLE like every other per-path list here; see record_caps.
        "sqlite_unreadable": capped(census.sqlite_unreadable),
        "unexaminable": capped(census.unexaminable),
        "not_regular_files": capped(census.not_regular_files),
        # Links are cheap and few, and every one of them carries the same key
        # set with explicit nulls, so a consumer can tell "not applicable" from
        # "not asked". This is the complete ledger; failure_matrix is the
        # categorised view of it, and the `covered_and_visited` records appear
        # here and nowhere else, because a closed question is not a failure.
        "links": capped(census.links),
        # `contradicting_read_only` is kept whenever it is not empty: that is
        # the one failure this artifact exists to make visible and withholding
        # it would be hiding it. What it no longer carries is the before/after
        # digests — a byte size, an mtime_ns and a SHA-256 of real database
        # content, in a document that says it carries no file sizes.
        "filesystem_effect": {
            "files_digested_before_and_after":
                census.filesystem_effect["files_digested_before_and_after"],
            "by_category": census.filesystem_effect["by_category"],
            "contradicting_read_only": [
                effect_without_digests(c)
                for c in capped(census.filesystem_effect["contradicting_read_only"])
            ],
        },
        "seconds": census.seconds,
    }


# The v11 recut corroboration artifact.
#
# A bounded negative, which is what this script was built to produce: "no such
# row among these N databases under these roots" rather than an unfalsifiable
# "anywhere". The green/red gate came later and sits on top; when the gate is
# red the bounded negative is still a real finding, and throwing it away would
# discard evidence because a *different* claim could not be made.
#
# Every guard against misreading it is a field rather than prose kept somewhere
# else, because the file will be read by people who never saw the discussion
# that produced it, and a caveat that lives in another document is a caveat
# that will be missed.
def corroboration(census: Census, as_of: str) -> dict:
    # Everything the census could not read: an OS error stopped it, or it is a
    # link it declined on scope. `out_of_declared_scope` no longer drives
    # `coverage_incomplete` — a census that declines to leave its declared
    # scope has not failed to cover that scope — but it stays here, because
    # dropping it would make does_not_assert[4] false. What is *not* here is
    # the far larger population that went unread because a published bound said
    # so; that is counted, category by category, in `not_read_by_declared_rule`
    # below, and the two together are what does_not_assert[4] now points at.

    unread = [g for g in census.unexaminable
              if g.get("reason") in ("unreadable", "vanished", "path_too_long")]
    unread += census.sqlite_unreadable + census.roots_unreadable + census.not_regular_files
    link_unread = [dict(link) for link in census.links
                   if link.get("reason") in ("out_of_declared_scope",
                                             "inside_but_not_visited",
                                             "depth_shadowed_target",
                                             "unreadable_link")]
    # The other way a path goes unread: a bound the artifact publishes before
    # the walk starts. These are not in the list above and their paths are not
    # retained — 110,100 tokenised paths are megabytes, and two of the four
    # categories are counted-not-retained in the census itself — but the counts
    # belong beside it. Without them `could_not_see` said "everything the
    # census did not read" over 29 entries while these four stood at 110,100,
    # and does_not_assert[4] pointed the reader at the 29 as the measure of
    # what was missed. Read from the matrix this run built, not recomputed, so
    # the two cannot disagree; a KeyError here means a category was renamed
    # without this being updated, which is the right way for that to fail.
    declined_by_rule = {
        name: census.failure_matrix["categories"][name]["count"]
        for name in ("depth_limited", "excluded", "not_content_read", "dangling")
    }
    found = len(census.stores) + census.repo_scratch_without_checkpoints
    outside = [s for s in census.stores if not s.is_repo_scratch]
    return {
        "artifact": "v11-recut-corroboration",
        "not_clearance": (
            "This file does not clear, authorise or permit the v11 "
            "drop-and-recreate. It records what one census found, on one "
            "machine, at one moment. See does_not_assert."
        ),
        "as_of": as_of,
        "asserts": {
            "claim": (
                "Among the {n} Terminus stores found under the {r} declared "
                "roots listed here, none outside this repository's own test "
                "scratch holds a row in transfer_checkpoints."
            ).format(n=found, r=len(census.roots_searched)),
            "stores_found": found,
            "stores_outside_repo_scratch": len(outside),
            # Derived from the stores this run actually opened, not written as
            # a literal 0. A number that cannot come out any other way is not
            # evidence of anything.
            "checkpoint_rows_outside_repo_scratch": sum(
                s.checkpoint_rows or 0 for s in outside),
            "stores_in_repo_scratch_holding_a_row": sum(
                1 for s in census.stores if s.is_repo_scratch and s.checkpoint_rows),
            "roots_searched": census.roots_searched,
            "roots_absent_and_therefore_empty": census.roots_absent,
            "max_depth": census.max_depth,
            # The scope claim in full, so "under the declared roots" is a
            # definition here rather than a phrase.
            "effective_scope": census.effective_scope,
        },
        "does_not_assert": [
            "That the v11 drop-and-recreate was authorised. It was not, by this "
            "or by anything else this script produced: see "
            "postdates_what_it_corroborates.",
            "That no checkpoint row exists anywhere. The claim is bounded to the "
            "roots in asserts.roots_searched, to max_depth below each, and to "
            "the exclusions the census records.",
            "That anything holds for any machine other than the one this ran on.",
            "That anything holds at any moment other than as_of. Stores are "
            "created and deleted continuously; the repository's own test scratch "
            "churns on every test run.",
            "That the census saw everything under those roots. It did not, and "
            "there are two separate measures of that: could_not_see is what it "
            "could not read plus the links it declined on scope, and "
            "not_read_by_declared_rule counts what a bound published in "
            "effective_scope — depth, an exclusion, the content rule, or a link "
            "target that does not exist — kept it from reading. The second is "
            "the larger by orders of magnitude. Either one alone understates "
            "what went unread.",
        ],
        "could_not_see": {
            "count": len(unread) + len(link_unread),
            "entries_recorded": len(capped(unread)) + len(capped(link_unread)),
            "entries_truncated": (len(unread) > ERROR_SAMPLE
                                  or len(link_unread) > ERROR_SAMPLE),
            "what_this_is": (
                "Everything the census could not read, plus the links it "
                "declined on scope. Facts only: each entry is a path, why it "
                "could not be read, and where it resolves to if it is a link. "
                "Whether any of these could hold a Terminus store is left to "
                "the reader. Not every entry here is a coverage gap: a link out "
                "of the declared scope was declined on purpose and does not "
                "withhold authorisation, and it is listed anyway, because "
                "unread is unread. Which entries withhold is stated in "
                "census.failure_matrix, one flag per category. This is NOT the "
                "whole of what went unread — see not_read_by_declared_rule, "
                "which is much the larger number — and it used to describe "
                "itself as though it were. count is the full population; the "
                "two lists below are bounded at census.record_caps.cap, which "
                "these two lists used to defeat by republishing the census's "
                "records uncapped."
            ),
            "unreadable_paths": capped(unread),
            "links_not_read": capped(link_unread),
        },
        "not_read_by_declared_rule": {
            "count": sum(declined_by_rule.values()),
            "by_category": declined_by_rule,
            "what_this_is": (
                "The paths that went unread because a bound this artifact "
                "publishes in asserts.effective_scope said so: below depth_max, "
                "under an exclusion, failing content_read_rule, or a link whose "
                "target does not exist. None of them withholds authorisation "
                "and none of them is a hole in the declared scope — they are "
                "the declared scope. They are counted here and their paths are "
                "not retained: the count is what establishes the bound was "
                "applied, and tens of thousands of paths would carry no more "
                "evidence at the price of a megabyte-scale artifact naming "
                "every directory on the machine. The per-category definitions, "
                "flags and reconciliation are in census.failure_matrix; the "
                "full lists are in the git-ignored --raw census."
            ),
        },
        "postdates_what_it_corroborates": {
            "ddl_commit": "14c8a2d",
            "ddl_committed_at": "2026-08-14 13:05:25 +0800",
            "census_script_first_committed": "0d7ff00",
            "census_script_committed_at": "2026-08-15 05:30:59 +0800",
            "elapsed": "about sixteen hours",
            "meaning": (
                "The migration this file corroborates was written and committed "
                "before the script that produced this file existed. This is "
                "evidence gathered afterwards. It cannot have authorised "
                "anything, and no run of this script has ever returned the "
                "status that would."
            ),
        },
        "the_guard": (
            "checkBeforeApply remains the guard. It returns "
            "error.CheckpointsWouldBeDropped for any store below v11 that still "
            "holds checkpoint rows, and runs before apply rather than after it "
            "(src/core/store/migrate.zig:759, refusal at :790-799, as of "
            "7d61e66). A store this census never reached is covered by that "
            "refusal, not by this file."
        ),
        "census": public(census),
    }


@dataclass
class Walk:
    """What the walk saw, including what it could not look at."""
    sized: list[Path] = field(default_factory=list)
    files_seen: int = 0
    size_filtered: int = 0
    unexaminable: list[dict] = field(default_factory=list)
    links: list[dict] = field(default_factory=list)
    not_regular: list[dict] = field(default_factory=list)
    # P8: the directories whose `os.scandir` returned WITHOUT raising. This is
    # deliberately not the visited-set: `seen.add()` happens before the scandir,
    # so `seen` means "attempted" and would answer `actually_visited` yes for a
    # directory that refused to open.
    listed: set[str] = field(default_factory=set)
    # The depth at which each directory was first reached, measured rather than
    # derived, so `root_shadowing` reports the budget a root actually got.
    depth_of: dict[str, int] = field(default_factory=dict)
    # The two frontier decisions, recorded where there used to be a bare
    # `continue`. Neither withholds authorisation — both are bounds the
    # artifact publishes in `effective_scope` before the walk starts — but
    # roughly half the frontier lands in `depth_limited`, and a bound nobody
    # counts is indistinguishable from a bound nobody applied.
    depth_limited: list[dict] = field(default_factory=list)
    excluded: list[dict] = field(default_factory=list)


def exclusion_rule(path: Path) -> tuple[str, str, str] | None:
    """(kind, rule, matched text) for the first exclusion this path trips.

    Both rule kinds are matched against the *whole* path, not against the
    directory's own name, so any ancestor triggers them. That is broader than
    "the directory is called node_modules" and `effective_scope` says so.
    """
    text = str(path).replace("\\", "/")
    lowered = text.lower()
    for fragment in EXCLUDE_PATH_FRAGMENTS:
        at = lowered.find(fragment.lower())
        if at >= 0:
            # The matched span, in the case it really has on disk.
            return "path_fragment", fragment, text[at:at + len(fragment)]
    for part in path.parts:
        if part in EXCLUDE_DIR_NAMES:
            return "dir_name", part, part
    return None


def collect(root: Path, max_depth: int, walk: Walk, seen: set[str]) -> None:
    """Bounded walk. `Path.rglob` would descend forever into a profile dir.

    Uses `scandir` rather than `os.walk` + `stat` because on Windows the
    directory entry already carries the size, so the pre-filter is free.

    Links are never walked into. `follow_symlinks=False` was supposed to see to
    that and does not: on Windows a junction is not a symlink as far as Python
    is concerned, and `is_dir(follow_symlinks=False)` calls one a directory. So
    the check is explicit, and it doubles as the cycle guard the old comment
    claimed — a junction pointing at its own ancestor is now recorded and
    stepped over rather than descended into forever.

    Which directories get pushed is exactly what it was before; what changed is
    that the two ways of *not* pushing one are now recorded instead of being a
    bare `continue`. P1 is visible in the ordering: the frontier decision is
    only reached when `entry.stat` and `is_dir` both succeeded, so an error
    never gets filed as a policy decline.

    The root itself is tested by the exclusion rule too. It used to be pushed
    straight onto the stack, so `--root C:/proj/node_modules` was listed in full
    while `effective_scope.excluded_dir_names_note` told the reader that any
    ancestor triggers the rule — one path in the whole census exempt from the
    rule the artifact publishes as universal.
    """
    rule = exclusion_rule(root)
    if rule is not None:
        walk.excluded.append({
            "path": str(root), "depth": 0, "parent": None,
            "matched_kind": rule[0], "matched_rule": rule[1],
            "matched_component": rule[2],
        })
        return
    stack: list[tuple[str, int]] = [(str(root), 0)]
    while stack:
        here, depth = stack.pop()
        # One visit per directory, however many names reach it. Roots can
        # overlap and a root can sit inside another; without this a store under
        # both is two stores. Roots are walked longest-prefix first, so the
        # visit that lands here is the one with the largest remaining budget —
        # see the walk order in `main`.
        if key(here) in seen:
            continue
        seen.add(key(here))
        walk.depth_of[key(here)] = depth
        try:
            entries = list(os.scandir(here))
        except OSError as exc:
            walk.unexaminable.append(error_record(here, exc, "walk_directory"))
            continue
        walk.listed.add(key(here))
        for entry in entries:
            try:
                info = entry.stat(follow_symlinks=False)
                if is_link(entry.path, info):
                    walk.links.append(link_record(entry.path))
                    continue
                if entry.is_dir(follow_symlinks=False):
                    rule = exclusion_rule(Path(entry.path))
                    if rule is not None:
                        # P5: an exclusion beats the depth bound when both
                        # hold. It is the more specific and the more actionable
                        # fact — it applies at any depth, so raising --depth
                        # will never bring this directory in, and an operator
                        # must not be told otherwise.
                        walk.excluded.append({
                            "path": entry.path, "depth": depth + 1, "parent": here,
                            "matched_kind": rule[0], "matched_rule": rule[1],
                            "matched_component": rule[2],
                        })
                    elif depth + 1 < max_depth:
                        stack.append((entry.path, depth + 1))
                    else:
                        walk.depth_limited.append({
                            "path": entry.path, "depth": depth + 1, "parent": here,
                        })
                    continue
                if not entry.is_file(follow_symlinks=False):
                    # Not a link, not a directory, not a regular file. The
                    # census cannot say what this is, and an unclassifiable
                    # path used to be dropped here before `files_seen` was
                    # incremented, so it appeared in no counter and no list.
                    walk.not_regular.append({
                        "path": entry.path,
                        "st_mode": info.st_mode,
                        "st_file_attributes": getattr(info, "st_file_attributes", None),
                        "reason": "not_a_regular_file",
                        "origin": "walk_entry",
                        "within_declared_root": True,
                        "actually_visited": False,
                        "remedy": "identify what this path is; the census could not",
                    })
                    continue
                size = info.st_size
            except OSError as exc:
                walk.unexaminable.append(error_record(entry.path, exc, "walk_entry"))
                continue
            walk.files_seen += 1
            if size >= PAGE_FLOOR and size % PAGE_FLOOR == 0:
                walk.sized.append(Path(entry.path))
            else:
                walk.size_filtered += 1


# Every links[] record carries all of these, with explicit nulls, so a consumer
# can tell "not applicable" from "not asked". Before this there were three
# different shapes on disk and no way to tell them apart.
LINK_KEYS = (
    "path", "target", "target_resolved", "target_is_directory", "origin",
    "reason", "resolution",
    "within_declared_root", "covering_root", "target_depth_below_covering_root",
    "first_reaching_root", "target_depth_below_first_reaching_root",
    "actually_visited", "content_read", "not_visited_reason",
    "not_tested_because", "also_counted_in", "error", "remedy",
)


def link_count(walk: Walk, reason: str) -> int:
    return sum(1 for r in walk.links if r.get("reason") == reason)


def link_record(path: str) -> dict:
    """A link, where it goes, and — later — whether anything read the target.

    Resolution is answered with a raw `os.lstat`/`os.stat` pair in a `try`,
    never with `os.path.exists`/`lexists`: both of those catch
    `(OSError, ValueError)` internally and return False, so a target that
    exists and denies access came back indistinguishable from a target that is
    not there, and was filed as a verified empty set. `dangling` is the only
    label in this whole scheme that removes a gap, so it gets the strictest
    test: the link itself must be there, and the stat through it must raise
    ENOENT specifically.

    Scope and visitation are settled by the caller once the roots and the walk
    record exist. Spelling and resolution are settled here, and they come apart:
    a WSL symlink (tag 0xA000001D) resolves to nothing in the Win32 namespace
    *and* defeats `readlink`.
    """
    record: dict = {k: None for k in LINK_KEYS}
    record["path"] = path
    record["origin"] = "link"

    try:
        os.lstat(path)
        link_present, link_error = True, None
    except OSError as exc:
        link_present, link_error = False, exc

    target_error: OSError | None = None
    if link_present:
        try:
            through = os.stat(path)
            record["resolution"] = "target_present"
            record["target_is_directory"] = stat.S_ISDIR(through.st_mode)
        except FileNotFoundError as exc:
            if is_name_too_long(exc):
                record["resolution"], target_error = "unknown", exc
            else:
                record["resolution"] = "target_absent"
        except OSError as exc:
            record["resolution"], target_error = "unknown", exc
    else:
        record["resolution"] = "unknown"

    target, readlink_error = read_target(path)
    record["target"] = target
    # The raw string is what the link stores; the resolved path is what it
    # points at. They differ for a relative target, and every scope, depth and
    # visitation field below is about the resolved one — see `resolve_target`.
    # Both are recorded, because a reader who can see only the resolved path
    # cannot tell a relative link from an absolute one.
    if target is not None:
        record["target_resolved"] = resolve_target(path, target)

    if record["resolution"] == "target_absent":
        # P3(a), and P2a: it resolves cleanly and the answer is "nothing
        # there". The target string is the evidence — without it "this link
        # points nowhere" is an assertion rather than something a reader can
        # check — and it is recorded even when readlink refuses to produce it.
        record["reason"] = "dangling"
        record["not_tested_because"] = "target does not exist"
        if readlink_error is not None:
            record["error"] = f"readlink: {type(readlink_error).__name__}: {readlink_error}"
    elif not link_present or target_error is not None or target is None:
        # P3(b): it points somewhere and will not say where, or it will not
        # say what it is. Coverage cannot be decided, so it is a gap.
        record["reason"] = "unreadable_link"
        record["origin"] = "link_target"
        record["actually_visited"] = False
        record["content_read"] = False
        record["not_tested_because"] = "the census could not learn where this link points"
        record["remedy"] = REMEDY["unreadable"]
        failure = link_error or target_error or readlink_error
        record["error"] = f"{type(failure).__name__}: {failure}"
    # Everything else is decided in `classify_links`, once the roots are known.
    return record


def classify_links(links: list[dict], roots: list[Path], walk: Walk,
                   content_read: set[str], max_depth: int) -> None:
    """P3(c)-(e): scope, then visitation, for every link that resolved.

    `within_declared_root` and `actually_visited` are separate recorded fields
    because they are separate facts. Being inside a declared root says the
    census promised to cover those bytes. Being visited says a walk read them.
    Publishing the first as though it were the second is the defect this
    function exists to end.

    `roots` must be in **walk order**, which since per-root depth means longest
    prefix first. `first_root` reads it positionally.
    """
    depth_limited_keys = {key(e["path"]) for e in walk.depth_limited}
    excluded_keys = {key(e["path"]) for e in walk.excluded}
    # Why an ancestor stopped the walk, keyed by path. All three error reasons
    # are here, not only `unreadable`: a target under a directory that vanished
    # or whose name was too long went unread for a reason the census recorded,
    # and reporting it as "no declared bound accounts for it" tells an operator
    # to go and investigate something the artifact already answers two
    # categories away.
    ancestor_error = {key(e["path"]): e["reason"] for e in walk.unexaminable
                      if e["reason"] in ("unreadable", "vanished", "path_too_long")}
    # A reparse point is recorded and stepped over, so a target below one was
    # never reached, and `link_policy: never_followed` is exactly the declared
    # bound that accounts for it.
    link_keys = {key(r["path"]) for r in links}
    for record in links:
        if record["reason"]:
            continue
        # Resolved from the link's own directory, never from the process's
        # working directory: a relative target answered against the latter is a
        # fabricated path, and every field set below would then be a statement
        # about somewhere else. See `resolve_target`.
        target = record["target_resolved"]
        covering = longest_root(target, roots)
        if covering is None:
            # P3(c). Not a coverage gap: the census promised to cover the
            # declared scope, and a name inside the scope pointing outside it
            # is the link policy working as declared. Retained and reported in
            # full, and still listed in the corroboration's could_not_see.
            record["reason"] = "out_of_declared_scope"
            record["within_declared_root"] = False
            record["not_tested_because"] = "target outside every searched root"
            record["remedy"] = "declare this target a root to bring it in scope"
            continue
        first = first_root(target, roots)
        record["within_declared_root"] = True
        record["covering_root"] = str(covering)
        record["target_depth_below_covering_root"] = depth_below(covering, target)
        record["first_reaching_root"] = str(first)
        effective_depth = depth_below(first, target)
        record["target_depth_below_first_reaching_root"] = effective_depth
        # P8: answered from the walk's own record, never from a prefix test, a
        # depth calculation or an exclusion test.
        t = key(target)
        if record["target_is_directory"]:
            record["actually_visited"] = t in walk.listed
        else:
            record["actually_visited"] = key(os.path.dirname(target)) in walk.listed
        record["content_read"] = t in content_read
        if t in depth_limited_keys:
            record["also_counted_in"] = "depth_limited"
        elif t in excluded_keys:
            record["also_counted_in"] = "excluded"
        if record["actually_visited"]:
            # P3(d). A closed question: the bytes were read under their real
            # name, so the link adds nothing and there is no matrix record.
            record["reason"] = "covered_and_visited"
            continue
        # P3(e) and P4. Inside the territory the census's own scope claim names
        # by root, and nothing read it. Calling that "covered" was the defect;
        # calling it "correctly declined" would be the same overclaim wearing a
        # new label, because no run of this census established anything about
        # those bytes. Both categories below withhold authorisation for exactly
        # that reason. What separates them is which of two very different
        # things a reader is being told.
        why_not = "unknown"
        if effective_depth >= max_depth:
            why_not = "below_depth_limit"
        elif exclusion_rule(Path(target)) is not None:
            why_not = "under_exclusion"
        else:
            # Up the chain from the target's parent to the root that owns its
            # depth budget. It used to stop at `covering` while every depth
            # number beside it was measured from `first`, so on a machine where
            # those differed the ancestors between them were never examined and
            # the answer came out "unknown" for a target the census could
            # explain. Since per-root depth they are the same root by
            # construction; the bound is written as the one that owns the
            # budget because that is what makes it correct rather than lucky.
            ancestor = os.path.dirname(target)
            while True:
                folded = key(ancestor)
                if folded in ancestor_error:
                    # P1: an OS error beats policy, so this is tested before
                    # the link rule for an ancestor that is both.
                    why_not = "ancestor_" + ancestor_error[folded]
                    break
                if folded in link_keys:
                    why_not = "ancestor_is_a_link"
                    break
                if folded == key(str(first)):
                    break
                parent = os.path.dirname(ancestor)
                if parent == ancestor:
                    break
                ancestor = parent
        # P4. `depth_shadowed_target` is a gap — the content genuinely was not
        # read — but it says which gap: the census's own published depth_max
        # stopped it, not an unbounded miss. `inside_but_not_visited` keeps the
        # harder meaning, and a reader must be able to tell "my own declared
        # bound stopped me" from "I should have reached this and did not".
        record["reason"] = ("depth_shadowed_target" if why_not == "below_depth_limit"
                            else "inside_but_not_visited")
        record["not_visited_reason"] = why_not
        record["remedy"] = {
            "below_depth_limit": "raise --depth past the target's depth below its "
                                 "first-reaching root, or declare the target a root",
            "under_exclusion": "remove the exclusion rule this target matches; "
                               "raising --depth will not bring it in",
            "ancestor_unreadable": "go and look at what is denying access on the "
                                   "unreadable ancestor",
            "ancestor_vanished": "re-run when the machine is quiet: an ancestor of "
                                 "this target was deleted mid-walk",
            "ancestor_path_too_long": "shorten the path or enable long paths on the "
                                      "ancestor; a re-run will not close this",
            "ancestor_is_a_link": "an ancestor of this target is itself a reparse "
                                  "point, and link_policy is never_followed; declare "
                                  "the target a root to reach it under its own name",
            "unknown": "investigate: the walk never entered this target and no "
                       "declared bound accounts for it",
        }[why_not]


def sniff(path: Path) -> tuple[Path, str | None, dict | None]:
    """Is this file a SQLite database? Decided by its first 16 bytes.

    Filename is not evidence. The census exists because a store may have been
    *copied* somewhere, and a copy can be called `v4copy.db`, `backup`, or
    nothing in particular — over half the SQLite databases under these roots
    are not named `*.db` at all, and thirteen of them are called `Login Data`.
    What this still cannot see is a store on a drive that is not a search root,
    or below the depth limit: the header sniff widens what counts as a
    candidate, it does not widen where the walk goes.
    """
    try:
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_BINARY", 0))
        try:
            head = os.read(fd, len(SQLITE_MAGIC))
        finally:
            os.close(fd)
    except OSError as exc:
        return path, "error", error_record(str(path), exc, "sniff")
    return path, ("sqlite" if head == SQLITE_MAGIC else None), None


def digest(path: Path) -> dict | None:
    """Size, mtime and content hash — or None when the file does not exist.

    Small files are hashed whole; large ones by their ends, which is enough to
    catch a database write (see DIGEST_ENDS) without reading 362 MB three times
    per run.
    """
    try:
        stat = path.stat()
    except OSError:
        return None
    try:
        with open(path, "rb") as handle:
            if stat.st_size <= 2 * DIGEST_ENDS:
                body = handle.read()
                span = "whole file"
            else:
                body = handle.read(DIGEST_ENDS)
                handle.seek(-DIGEST_ENDS, os.SEEK_END)
                body += handle.read(DIGEST_ENDS)
                span = f"first and last {DIGEST_ENDS} bytes"
    except OSError as exc:
        # A file we cannot hash is still a file whose size and mtime we can
        # compare; say so rather than dropping it out of the comparison.
        return {"size": stat.st_size, "mtime_ns": stat.st_mtime_ns,
                "sha256": None, "hashed": f"unreadable: {type(exc).__name__}"}
    return {"size": stat.st_size, "mtime_ns": stat.st_mtime_ns,
            "sha256": hashlib.sha256(body).hexdigest(), "hashed": span}


def sidecars(path: Path) -> list[Path]:
    return [path, path.parent / (path.name + "-wal"), path.parent / (path.name + "-shm")]


def snapshot(candidates: list[Path]) -> dict[str, dict | None]:
    state: dict[str, dict | None] = {}
    for candidate in candidates:
        for target in sidecars(candidate):
            state[str(target)] = digest(target)
    return state


def compare(before: dict[str, dict | None], after: dict[str, dict | None]) -> list[dict]:
    changes: list[dict] = []
    for path in sorted(set(before) | set(after)):
        was, now = before.get(path), after.get(path)
        if was == now:
            continue
        if was is None:
            what = "created"
        elif now is None:
            what = "deleted"
        else:
            moved = [k for k in ("size", "mtime_ns", "sha256") if was.get(k) != now.get(k)]
            what = "changed: " + ", ".join(moved)
        changes.append({"path": path, "change": what, "before": was, "after": now,
                        "contradicts_read_only": contradicts(path, what, now)})
    return changes


def contradicts(path: str, what: str, now: dict | None) -> bool:
    """Would this change disprove "no page and no WAL frame was written"?

    Creating an empty `-wal` or a `-shm`, and moving an existing `-shm`'s mtime
    or read marks, are what a read-only WAL reader unavoidably does. Anything
    touching the database file itself, or putting bytes into a `-wal`, is not —
    and is the only part of this report worth reading twice.
    """
    if path.endswith("-shm"):
        return False
    if path.endswith("-wal"):
        return what == "deleted" or (now or {}).get("size", 0) > 0
    return True


def category(change: dict) -> str:
    path, what = change["path"], change["change"]
    part = "-shm" if path.endswith("-shm") else "-wal" if path.endswith("-wal") else "database file"
    if what == "created":
        if part == "-wal":
            return "-wal created, empty (no frame)" if not (change["after"] or {}).get("size") \
                else "-wal created WITH CONTENT"
        return f"{part} created"
    if what == "deleted":
        return f"{part} deleted"
    return f"{part} {what}"


def inspect(path: Path, repo: Path) -> tuple[Store | None, dict | None]:
    uri = "file:" + str(path).replace("?", "%3f").replace("#", "%23") + "?mode=ro"
    try:
        con = sqlite3.connect(uri, uri=True, timeout=OPEN_TIMEOUT_S)
        cur = con.cursor()
        tables = {r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not SIGNATURE.issubset(tables):
            con.close()
            return None, None
        version = cur.execute("PRAGMA user_version").fetchone()[0]
        has = "transfer_checkpoints" in tables
        rows = cur.execute("SELECT COUNT(*) FROM transfer_checkpoints").fetchone()[0] if has else None
        # The request id is what tells a gate's row from a person's: `testId()`
        # emits `PVSH0000…`, and no real ULID is shaped like that. Carrying the
        # ids into the artifact means that claim can be checked by reading the
        # JSON instead of being taken on trust. The column is only read when it
        # exists, because the v6 shape of this table is not the v10 shape.
        ids: list[str] = []
        if rows:
            columns = {r[1] for r in cur.execute("PRAGMA table_info(transfer_checkpoints)")}
            if "request_id" in columns:
                ids = [str(r[0]) for r in cur.execute(
                    "SELECT request_id FROM transfer_checkpoints ORDER BY id LIMIT 20")]
        counts = {
            t: cur.execute('SELECT COUNT(*) FROM "%s"' % t).fetchone()[0]
            for t in sorted(SIGNATURE)
        }
        con.close()
        # Scratch databases the test suite leaves behind when a gate crashes.
        # Their rows are gate data by construction; naming them keeps them from
        # being counted as evidence either way.
        scratch = str(repo / ".zig-cache") in str(path)
        return Store(str(path), path.stat().st_size, version, has, rows, ids, scratch, counts), None
    except Exception as exc:  # noqa: BLE001 - the point is to report, not to handle
        # A file that carries the SQLite header and still will not open is a
        # hole, and it is the same kind of hole as a path that refused to be
        # listed, so it is recorded in the same shape and lands in the same
        # `unreadable` category under its own origin. `sqlite3.Error` is not an
        # OSError, so the specific-cause ladder cannot run on it and it is
        # named plainly rather than guessed at.
        if isinstance(exc, OSError):
            return None, error_record(str(path), exc, "sqlite_open", carried_sqlite_header=True)
        return None, {
            "path": str(path),
            "error": f"{type(exc).__name__}: {exc}",
            "origin": "sqlite_open",
            "reason": "unreadable",
            "target": None,
            "target_resolved": None,
            "resolution": "unknown",
            "carried_sqlite_header": True,
            "within_declared_root": True,
            "actually_visited": False,
            "not_tested_because": None,
            "remedy": REMEDY["unreadable"],
        }


# The two frontier categories are counted, not retained, in the same way and
# for the same reason as `not_content_read`. What they have to establish is a
# number — the declines against the directories whose listing succeeded are the
# whole of the claim that the depth bound was applied, and the verdict reads
# `count` and nothing else — and a sample of 50 paths establishes none of it.
# What the sample did do was publish filesystem-path strings that no other part
# of the artifact named, into a public repository: a private GitHub org, a
# private repository name, a PR number and an internal product tree, none of
# which the tokeniser could touch, because it rewrites root prefixes and emits
# everything below them as-is. Coarsening now covers the segments the tokeniser
# cannot, so the sample would no longer publish those names — and it is still
# not restored, because it never carried any evidence to begin with. The full
# lists are in `--raw`, under `frontier_depth_limited` and
# `frontier_excluded`, uncapped.
FRONTIER_RETAINED = 0
FRONTIER_NOTE = (
    "paths are counted, not retained: the count is what this category has to "
    "establish, the verdict reads no other field of it, and a sample of them "
    "publishes tens of thousands of directory names for no "
    "evidentiary gain. The full list is in the --raw census, which is "
    "git-ignored"
)
# The error categories are small by nature and are published whole. The bound
# exists so that a machine where they are not small cannot silently produce a
# multi-megabyte artifact — and it still says when it bites.
ERROR_SAMPLE = 200


# ERROR_SAMPLE used to bound the failure_matrix view and nothing else, while the
# same records were republished uncapped three more times: in the census's own
# top-level `unexaminable`, `sqlite_unreadable`, `not_regular_files` and
# `links`, and again inside the corroboration, which embeds the whole census
# *and* re-lists the error and link records beside it. So the cap bounded the
# view and not the artifact, and the committed pair's disclosure surface was
# unbounded in the number of unreadable paths on the machine — the one quantity
# nobody controls. Every list of per-path records in either committed document
# now goes through here.
#
# Truncation is never silent. The count is the full count, the artifact says how
# many it kept, and `record_caps` in each document names every list it bounded.
def capped(records: list, cap: int = ERROR_SAMPLE) -> list:
    return records[:cap]


def cap_report(lists: dict[str, list]) -> dict:
    return {
        "cap": ERROR_SAMPLE,
        "what_this_is": (
            "Every list of per-path records in this document is bounded at cap "
            "entries. The counts and the verdicts are computed over the full "
            "population, never over the kept entries, so a truncated list "
            "changes what a reader can inspect and nothing about what the "
            "census concluded. The full lists are in the git-ignored --raw "
            "census. This bound used to apply to the failure_matrix view alone "
            "while the same records were republished uncapped elsewhere in the "
            "same two files."
        ),
        "lists": {
            name: {"total": len(items),
                   "recorded": min(len(items), ERROR_SAMPLE),
                   "truncated": len(items) > ERROR_SAMPLE}
            for name, items in sorted(lists.items())
        },
    }


# `filesystem_effect.contradicting_read_only` used to be published whole,
# `before` and `after` digests included — so on a run where it is not empty the
# committed artifact would carry the byte size, the mtime_ns and a SHA-256 of
# real database content, in a document whose own contract says it carries no
# file sizes. The failure must stay fully visible, so nothing here is dropped:
# every contradicting change keeps its path, its category and which fields
# moved, plus the direction the size went, which is the part an operator acts
# on. What it stops carrying is the values, and it says where they are.
def effect_without_digests(change: dict) -> dict:
    was, now = change.get("before"), change.get("after")
    moved = [k for k in ("size", "mtime_ns", "sha256")
             if (was or {}).get(k) != (now or {}).get(k)]
    if was is None or now is None:
        direction = "file created" if was is None else "file deleted"
    elif was.get("size") == now.get("size"):
        direction = "size unchanged"
    else:
        direction = "size grew" if now.get("size", 0) > was.get("size", 0) else "size shrank"
    return {
        "path": change["path"],
        "change": change["change"],
        "category": category(change),
        "fields_changed": moved,
        "size_direction": direction,
        "contradicts_read_only": change["contradicts_read_only"],
        "digests_in": ("the --raw census, under filesystem_effect: the before and "
                       "after size, mtime_ns and SHA-256 are file sizes and "
                       "content fingerprints of real databases and this document "
                       "carries neither"),
    }


def project(record: dict, keys: tuple[str, ...]) -> dict:
    """The fields this category is about, with explicit nulls for the rest.

    The matrix is a categorised *view*; the full record with every key lives in
    `links`, `unexaminable` or `not_regular_files`. Projecting keeps the two
    from drifting into two different truths.
    """
    return {k: record.get(k) for k in keys}


def bucket(drives: bool, definition: str, why: str,
           entries: list[dict], keys: tuple[str, ...], cap: int,
           extra: dict | None = None) -> dict:
    ordered = sorted(entries, key=lambda r: key(str(r.get("path") or r.get("variable") or "")))
    shown = ordered[:cap]
    out = {
        "count": len(entries),
        "drives_coverage_incomplete": drives,
        "definition": definition,
        "why": why,
        "entries_total": len(entries),
        "entries_recorded": len(shown),
        "entries_truncated": len(shown) < len(entries),
        "entries": [project(r, keys) for r in shown],
    }
    if extra:
        out.update(extra)
    return out


ERROR_KEYS = ("path", "error", "origin", "reason", "carried_sqlite_header",
              "within_declared_root", "actually_visited", "remedy")
DANGLING_KEYS = ("path", "target", "target_resolved", "origin", "resolution",
                 "reason", "within_declared_root", "actually_visited",
                 "not_tested_because")
OUTSIDE_KEYS = ("path", "target", "target_resolved", "within_declared_root",
                "actually_visited", "not_tested_because", "reason", "remedy")
INSIDE_KEYS = ("path", "target", "target_resolved", "within_declared_root",
               "covering_root",
               "target_depth_below_covering_root", "first_reaching_root",
               "target_depth_below_first_reaching_root", "actually_visited",
               "content_read", "not_visited_reason", "also_counted_in",
               "reason", "remedy")


def failure_matrix(walk: Walk, sqlite_unreadable: list[dict],
                   unresolvable: list[str], absent: list[str],
                   unreadable_roots: list[dict], max_depth: int) -> dict:
    """Every declined or failed decision, in exactly one category each.

    Disjointness is by construction rather than by adjudication: every record
    is produced at exactly one decision site and carries the `origin` of that
    site. `depth_limited` and `excluded` hold only walk-frontier records;
    `out_of_declared_scope` and `inside_but_not_visited` hold only link
    records; `root_unresolvable` and `root_absent` hold only root records.

    A path may still be named by two records of different origin — the link
    targets in `inside_but_not_visited` are also, separately, frontier
    directories their parent declined on depth. That is not double counting:
    the census made two different decisions about that path and both are facts.
    The link record carries `also_counted_in` so the reconciliation is stated
    here rather than left for a reader to find by diffing path lists.
    """
    errors = walk.unexaminable + sqlite_unreadable + unreadable_roots
    by_reason = lambda reason: [e for e in errors if e["reason"] == reason]  # noqa: E731
    links = lambda reason: [r for r in walk.links if r["reason"] == reason]  # noqa: E731

    unreadable = by_reason("unreadable") + links("unreadable_link")
    origins = Counter(r.get("origin") for r in unreadable)

    return {
        "what_this_is": (
            "Every path the walk declined or failed to read. Each record lands "
            "in exactly one category, and each category states its own "
            "definition and whether it withholds authorisation. A *path* may "
            "still be named by two records, because the census made two "
            "different decisions about it at two different decision sites: the "
            "commonest case is a link target that is also, separately, a "
            "frontier directory its own parent declined on depth. That is not "
            "double counting and it is not an exception to the rule above — "
            "the rule is about records — but it does mean the category counts "
            "do not sum to a count of distinct paths. See also_counted_in."
        ),
        "also_counted_in": (
            "Present on a link record whose *target* is additionally the "
            "subject of a frontier record in another category, and naming that "
            "category. It exists so the reconciliation is stated here rather "
            "than left for a reader to find by diffing path lists, and it is "
            "the field that makes the 'exactly one category' rule checkable "
            "instead of merely asserted. null means no other category names "
            "this path."
        ),
        "verdict_rule": (
            "coverage_incomplete = any(count > 0) over exactly the categories "
            "flagged drives_coverage_incomplete. A category may not be moved "
            "between the two sets to change a number."
        ),
        "precedence": [
            "P1 FAILURE BEATS POLICY. If an OS error prevented the census from "
            "learning what a path is, the record is an error category "
            "regardless of whether depth, exclusion or scope would also have "
            "declined it. A decline is only correct if the thing declined was "
            "understood.",
            "P2 WITHIN THE ERROR FAMILY, most specific verified cause first: "
            "path_too_long, then dangling, then vanished, then unreadable. The "
            "vaguest label is last so it can never absorb a case that has a "
            "name.",
            "P2a DANGLING IS THE ONLY GAP-REMOVING LABEL, so its test is the "
            "strictest: raw lstat returns AND raw stat raises ENOENT. "
            "os.path.exists and os.path.lexists are banned from this decision "
            "and from the root filter, because both swallow OSError.",
            "P3 LINK RECORDS: resolution, then spellability, then scope, then "
            "visitation, in that order.",
            "P4 For a link target under a searched root AND at or below "
            "depth_max from the root that owns its depth budget, the record is "
            "depth_shadowed_target, which withholds. depth_limited (not a gap) "
            "does not win: the frontier record is about the census declining to "
            "descend, and this record is about content inside the declared "
            "scope that nothing read. The two are both kept, and the link "
            "record says so in also_counted_in.",
            "P4a depth_shadowed_target is separated from inside_but_not_visited "
            "because they are different failures. In the first, the census's "
            "own published depth_max stopped it, and raising --depth or "
            "declaring the target a root closes it. In the second, no declared "
            "bound accounts for the target and the walk simply never got there. "
            "Both withhold; conflating them told a reader the wrong thing about "
            "what to do next.",
            "P4b A link target under a published exclusion is "
            "inside_but_not_visited, and withholds, while the excluded "
            "directory itself is not a gap. The two are decided about different "
            "things — a directory the census declined to descend into, and "
            "content inside the declared scope that nothing read — and the "
            "remedy on the link record says to remove the exclusion because "
            "that is what would close it. Whether declining an exclusion should "
            "instead stop the target being a gap, as declining to leave the "
            "declared scope already does, is not settled by this artifact and "
            "is not decided here.",
            "P5 FRONTIER: excluded wins over depth_limited when both hold, "
            "because raising --depth will never bring an excluded directory in.",
            "P6 Unresolved ties resolve toward withholding, and that may only "
            "ever add a gap, never remove one.",
            "P7 Root attribution is longest-prefix, not first-match. Since "
            "per-root depth the root that reaches a target first is the "
            "longest-prefix root, so covering_root and first_reaching_root "
            "agree by construction; they are both published because their "
            "agreeing is itself the evidence that no root is walked on another "
            "root's budget.",
            "P8 actually_visited is answered only from the walk's own record, "
            "never from a prefix test, a depth calculation or an exclusion test.",
        ],
        "categories": {
            "inside_but_not_visited": bucket(
                True,
                "A link whose target is under a searched root by longest-prefix "
                "match, which no walk read — for a directory target, the target "
                "is absent from the set of directories whose os.scandir "
                "returned; for a file target, its parent is — and which "
                "depth_max did not stop. A target depth_max did stop is "
                "depth_shadowed_target. not_visited_reason is computed, never "
                "guessed, and names what did stop the walk: an exclusion (see "
                "P4b), an ancestor that was unreadable, vanished or too long to "
                "name, an ancestor that is itself a reparse point the link "
                "policy forbids following, or nothing the census can account "
                "for at all.",
                "This is territory the census's own scope claim names by root, "
                "that nothing read, and that no declared depth bound explains. "
                "Calling it covered was the defect. Calling it correctly "
                "declined would be the same overclaim wearing a new label: no "
                "run of this census established anything about those bytes.",
                links("inside_but_not_visited"), INSIDE_KEYS, ERROR_SAMPLE),
            "depth_shadowed_target": bucket(
                True,
                "A link whose target is under a searched root by longest-prefix "
                "match, which no walk read, and whose depth below the root that "
                "owns its depth budget is at or beyond depth_max. Same test as "
                "inside_but_not_visited in every other respect; split from it "
                "by not_visited_reason == below_depth_limit alone.",
                "It withholds, because the content genuinely was not read and "
                "the census cannot speak for it. What the name adds is which "
                "kind of miss it is: the census's own declared depth_max, "
                "published in effective_scope before the walk started, is what "
                "stopped it — not an unbounded blind spot. Raising --depth past "
                "the target's depth, or declaring the target a root, closes it, "
                "and both of those change the declared scope. The frontier "
                "record for the same directory is separately in depth_limited, "
                "which does not withhold, and the link record names it in "
                "also_counted_in; declining to descend and failing to read "
                "in-scope content are two decisions and the artifact stopped "
                "conflating them.",
                links("depth_shadowed_target"), INSIDE_KEYS, ERROR_SAMPLE),
            "unreadable": bucket(
                True,
                "An OS error prevented the census from learning what a path is, "
                "where it points or what it contains, and none of "
                "path_too_long, dangling or vanished holds. origin is "
                "mandatory: root, walk_directory, walk_entry, sniff, "
                "sqlite_open or link_target.",
                "The census could not look, and 'could not look' is not an "
                "answer. Origin is mandatory because six different failures "
                "land here and each is a different instruction. Note that cloud "
                "placeholders (WinError 1920) and other non-permission failures "
                "land here too, so this does not mean 'access denied'.",
                unreadable, ERROR_KEYS, ERROR_SAMPLE,
                {"by_origin": dict(sorted(origins.items())),
                 "by_origin_note": (
                     "A Counter over the origins this run observed, so an "
                     "origin with no records has no key here rather than a key "
                     "with 0. The six legal values are in the definition above."
                 )}),
            "vanished": bucket(
                True,
                "FileNotFoundError or NotADirectoryError where a raw os.lstat "
                "also raises ENOENT — listed, then genuinely gone before it was "
                "opened — and winerror is not 206.",
                "A real mid-walk deletion. The census cannot speak for it, and "
                "unlike dangling it will not reproduce, so the instruction is "
                "'re-run' rather than 'go and look'.",
                by_reason("vanished"), ERROR_KEYS, ERROR_SAMPLE),
            "path_too_long": bucket(
                True,
                "An OSError whose winerror is 206 (ERROR_FILENAME_EXCED_RANGE), "
                "or on POSIX whose errno is ENAMETOOLONG. Tested before the "
                "FileNotFoundError branch, because Python maps winerror 206 to "
                "FileNotFoundError errno 2.",
                "The census could not examine the path and the condition is "
                "permanent. Split out because the advice printed for vanished — "
                "'re-run when the machine is quiet' — is wrong for it and will "
                "never close it, and a gap under a name whose remedy does not "
                "work is a gap that never gets fixed.",
                by_reason("path_too_long"), ERROR_KEYS, ERROR_SAMPLE),
            "not_a_regular_file": bucket(
                True,
                "An entry whose stat succeeded, which is not a name-surrogate "
                "reparse point, not a directory, and not a regular file.",
                "The census cannot say what this path was, and an "
                "unclassifiable path must not be silently absent from an "
                "artifact whose subject is what it did and did not see. It used "
                "to be dropped before files_seen was incremented, so it "
                "appeared in no counter and no list.",
                walk.not_regular,
                ("path", "st_mode", "st_file_attributes", "reason", "origin"),
                ERROR_SAMPLE),
            "root_unresolvable": bucket(
                True,
                "A declared root whose environment variable was unset, so no "
                "path could be formed at all. No path exists to record; the "
                "entry is the variable name.",
                "Nothing whatever is known about where that root would have "
                "been, let alone what is under it. It is in the matrix rather "
                "than left as a lone top-level counter so that every driver of "
                "coverage_incomplete is findable in one place.",
                [{"variable": v, "reason": "root_unresolvable",
                  "note": "no path could be formed"} for v in unresolvable],
                ("variable", "reason", "note"), ERROR_SAMPLE),
            "out_of_declared_scope": bucket(
                False,
                "A link whose target exists, whose target string could be "
                "spelled, and which is under no searched root. No other "
                "predicate participates.",
                "The census promised to cover the declared scope. A name inside "
                "the scope pointing outside it is the link policy working as "
                "declared: not covering what was never promised is not a "
                "failure to cover what was promised. Nothing is deleted — the "
                "records are kept in full and they remain in the "
                "corroboration's could_not_see, because unread is unread.",
                links("out_of_declared_scope"), OUTSIDE_KEYS, ERROR_SAMPLE),
            "depth_limited": bucket(
                False,
                "A frontier decision: a directory the walk understood, that no "
                "exclusion matched, and for which depth + 1 < depth_max is "
                "false.",
                "depth_max is part of the declared scope and is published in "
                "effective_scope. Stopping at a bound the artifact publishes is "
                "the census obeying its own contract; making it a gap would set "
                "coverage_incomplete true on every run of every machine by "
                "construction, and a permanently-true verdict withholds nothing "
                "because it distinguishes nothing. Roughly half the frontier "
                "lands here, which is exactly why it is counted and published "
                "rather than left silent. This is a decision not to descend, "
                "and it is not the same fact as in-scope content going unread: "
                "when a link points at one of these directories, the link "
                "record is depth_shadowed_target and does withhold. See P4.",
                walk.depth_limited, (), FRONTIER_RETAINED,
                {"note": FRONTIER_NOTE}),
            "excluded": bucket(
                False,
                "The same frontier decision, except an exclusion matched — "
                "regardless of whether depth would also have permitted the "
                "descent. Both rule kinds are matched against the whole path, "
                "so any ancestor triggers them, and a declared search root is "
                "tested by the same rule as any directory below one.",
                "An exclusion is declared configuration, published in "
                "effective_scope. Declining a directory the artifact says it "
                "declines is not a failure to cover the declared scope. It is "
                "separate from depth_limited because the operator instruction "
                "differs: raising --depth will never bring an excluded "
                "directory in. As with depth_limited this is a decision not to "
                "descend, and a link pointing at an excluded target is a "
                "separate record that does withhold — see P4b, which also "
                "records that whether it should is unsettled.",
                walk.excluded, (), FRONTIER_RETAINED,
                {"note": FRONTIER_NOTE,
                 "matched_rules": dict(sorted(Counter(
                     e["matched_rule"] for e in walk.excluded).items()))}),
            "dangling": bucket(
                False,
                "A raw os.lstat succeeded (the link is there) and a raw os.stat "
                "raised ENOENT (the target is not). Both in a try; neither "
                "os.path.exists nor os.path.lexists may decide this, because "
                "both swallow OSError and would file a target that exists and "
                "denies access as 'nothing there'.",
                "A verified empty set, not a blind spot: the census asked the "
                "filesystem and the answer was 'there is nothing at the other "
                "end'. Stable across runs, which is the giveaway that it is an "
                "answer rather than a race.",
                links("dangling") + by_reason("dangling"), DANGLING_KEYS,
                ERROR_SAMPLE),
            "not_content_read": bucket(
                False,
                "A file enumerated by a successful directory listing that "
                "failed content_read_rule: NOT (size >= 512 and size % 512 == "
                "0). This is the same branch as files_size_filtered, and the "
                "two numbers are equal by construction.",
                "A declared, deterministic, published content rule, exactly "
                "like the depth bound. It is named because most enumerated "
                "paths land here, and a reader who has just been told the "
                "difference between 'enumerated' and 'read' must be able to "
                "find that number under a name instead of deriving it by "
                "subtraction.",
                [], (), 0,
                {"rule": "size >= 512 and size % 512 == 0",
                 "count": walk.size_filtered,
                 "entries_total": walk.size_filtered,
                 "entries_truncated": True,
                 "note": "paths are counted, not retained: tens of thousands of "
                         "tokenised paths would grow this artifact by megabytes "
                         "and the rule is checkable against any file without "
                         "them"}),
            "root_absent": bucket(
                False,
                "A declared root that resolved to a path where a raw os.stat "
                "raised ENOENT. Not decided by Path.exists(), which swallows "
                "OSError and would file a root that exists and denies access as "
                "verified-empty.",
                "A directory that does not exist contains no databases: the "
                "census looked and there is nothing there. Kept in the matrix "
                "as the symmetric counterpart of root_unresolvable, so a reader "
                "can tell 'we looked and it was not there' from 'we could not "
                "look'.",
                [{"path": p, "reason": "root_absent", "error": None} for p in absent],
                ("path", "reason", "error"), ERROR_SAMPLE),
        },
    }


def effective_scope(declared: list[tuple[str, Path | None]], roots: list[Path],
                    absent: list[str], unresolvable: list[str],
                    walk: Walk, max_depth: int) -> dict:
    """The scope contract, carried by the artifact.

    Everything here is a term of the one sentence in `statement`. The point is
    that a reader checks the claim against this definition rather than against
    the code, which is what "the scope is part of the claim" has to mean if it
    is to mean anything.
    """
    nesting = []
    for root in roots:
        outer = [r for r in roots
                 if key(str(r)) != key(str(root))
                 and key(str(root)).startswith(key_prefix(str(r)))]
        if not outer:
            continue
        parent = max(outer, key=lambda r: len(key(str(r))))
        # Measured from the walk's own depth record, not derived. It is 0 for
        # every root now, and it is published rather than assumed so that a
        # regression in the walk order shows up here as a non-zero number
        # instead of as a quietly smaller file count.
        reached = walk.depth_of.get(key(str(root)))
        nesting.append({
            "root": str(root),
            "nested_inside": str(parent),
            "first_reached_at_depth": reached,
            "effective_depth_budget": None if reached is None else max(0, max_depth - reached),
        })
    fragment_hits = Counter(e["matched_rule"] for e in walk.excluded
                            if e["matched_kind"] == "path_fragment")
    return {
        "statement": (
            "Every regular file enumerated by a successful directory listing at "
            "or below depth_max levels beneath the nearest searched root "
            "containing it, excluding the names and fragments below; reparse "
            "points are recorded and never followed, inside or outside this "
            "scope; a file's content is read only if it passes "
            "content_read_rule."
        ),
        "roots_declared": [label if path is None else str(path)
                           for label, path in declared],
        "roots_searched": [str(r) for r in roots],
        "roots_absent": absent,
        "roots_unresolvable": unresolvable,
        "root_shadowing": nesting,
        "root_shadowing_note": (
            "A root that lies inside another declared root used to inherit that "
            "root's depth budget rather than getting its own: the visited-set "
            "short-circuit returned immediately for a directory the outer root "
            "had already reached, so <repo>, three levels below a declared "
            "profile directory, got 3 of its 6 declared levels and "
            "roots_searched plus depth_max asserted coverage the walk did not "
            "deliver. Each root's depth is now counted from that root. The walk "
            "visits the roots longest-prefix first, so the visit that reaches a "
            "directory is the one with the largest remaining budget and the "
            "single-visit rule still holds. This field records which roots are "
            "nested and at what depth each was in fact first reached: it is 0 "
            "for every entry, and it is published so that a regression shows up "
            "as a number here rather than as a quietly smaller file count."
        ),
        "depth_max": max_depth,
        "depth_measured_from": "the nearest declared root containing the path, "
                               "counted from that root (first_reaching_root on a "
                               "link record)",
        "depth_boundary_rule": (
            "A directory at depth < depth_max is listed. Its children at depth "
            "== depth_max are named and stat'd by that listing but never "
            "opened. The deepest file that can be seen is therefore at depth == "
            "depth_max; the deepest directory whose contents are known is at "
            "depth == depth_max - 1."
        ),
        "excluded_dir_names": sorted(EXCLUDE_DIR_NAMES),
        "excluded_dir_names_note": (
            "Matched against every component of the whole absolute path, so any "
            "ancestor triggers the rule. That is broader than 'the directory is "
            "named X'. A declared search root is tested by the same rule and is "
            "not exempt from it: a root that matches an exclusion is recorded "
            "under excluded and not walked."
        ),
        "excluded_path_fragments": [
            {"fragment": fragment, "matched_paths": fragment_hits.get(fragment, 0)}
            for fragment in EXCLUDE_PATH_FRAGMENTS
        ],
        "excluded_path_fragments_note": (
            "The per-fragment hit count is part of the field: a fragment that "
            "cannot fire under any searched root shows 0, and a list published "
            "without hit counts overstates what the census excludes."
        ),
        "link_policy": "never_followed",
        "link_policy_note": (
            "A target inside a declared root is NOT thereby covered. Being "
            "under a root and having been read are two facts; see "
            "within_declared_root and actually_visited on each link record. "
            "Declining to follow a link out of this scope is the policy "
            "working; failing to have read a target inside it is a gap."
        ),
        "content_read_rule": (
            "A file is opened and its first 16 bytes read only if size >= 512 "
            "and size % 512 == 0. Every other enumerated file was seen and "
            "never read."
        ),
        "visited_definition": (
            "actually_visited(dir) = the directory was entered and os.scandir "
            "returned without raising. actually_visited(file) = its parent "
            "directory satisfies that. content_read(file) = it additionally "
            "passed content_read_rule and was opened. Membership is taken from "
            "the walk's own record, never inferred from a path prefix, a depth "
            "calculation or an exclusion test."
        ),
    }


def write_committed(destination: str, document: dict, note: str) -> list[dict]:
    """Tokenise, coarsen, check, and only then write. Returns what stopped it.

    The check is not advisory. A committed artifact that would carry a
    drive-letter path, a UNC host or the account name is not written — the
    previous file on disk is left exactly as it was, and the caller exits
    non-zero — because the alternative to refusing is publishing, and the
    artifact's own claim is that a reader can check the redaction with one grep.
    Substituting some new token for the offending string would be worse than
    either: it invents a name nobody agreed on to make a failing check pass.

    It runs **twice**, before and after coarsening, and that ordering is the
    point rather than belt and braces. Coarsening replaces a segment with a
    digest, so a segment that carried a violation would come out of it looking
    clean: on a machine whose account name is too short to tokenise, running the
    check only on the coarsened document would report success about a document
    from which the evidence had just been removed. Checking the tokenised
    document first means coarsening can never turn a failing document into a
    passing one; checking the coarsened one as well means it cannot introduce a
    violation either.
    """
    body = tokenised(document)
    rules = redaction_rules()
    found = account_name_publishable() + redaction_violations(body, rules)
    body = coarsened(body)
    found += redaction_violations(body, rules)
    seen: set[tuple[str, str]] = set()
    violations = []
    for hit in found:
        signature = (hit["json_path"], hit["rule"])
        if signature in seen:
            continue
        seen.add(signature)
        violations.append(hit)
    if violations:
        return [dict(v, artifact=destination) for v in violations]
    out = Path(destination)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(body, indent=2), encoding="utf-8")
    print(f"wrote {destination} ({note})")
    return []


def main() -> int:
    ap = Parser(description=__doc__.split("\n")[0], epilog=EXIT_HELP,
                formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", action="append", type=Path, help="extra search root (repeatable)")
    ap.add_argument("--json", metavar="PATH",
                    help="write the committed artifact: the two verdicts, coverage numbers, "
                         "filesystem effect, and per store its user_version, whether it has a "
                         "transfer_checkpoints table and whether that table holds a row. Paths "
                         "tokenised, and the finished document checked before it is written: a "
                         "drive-letter path, a UNC host or the account name anywhere in it "
                         "refuses the write and exits 65. No file sizes, no user-data counts, "
                         "no request ids")
    ap.add_argument("--raw", metavar="PATH", nargs="?", const=RAW_DEFAULT,
                    help="write the full census, untokenised, including absolute paths, file "
                         f"sizes, user-data counts and checkpoint request ids (default "
                         f"{RAW_DEFAULT}, which is git-ignored — this output is not fit to commit)")
    ap.add_argument("--corroboration", metavar="PATH", nargs="?",
                    const=CORROBORATION_DEFAULT,
                    help="write the bounded negative as a self-describing artifact: what it "
                         "asserts, what it explicitly does not assert, and everything it could "
                         "not see. Written whatever the exit status, because a bounded negative "
                         f"is a finding even when the gate is red (default {CORROBORATION_DEFAULT})")
    ap.add_argument("--depth", type=int, default=MAX_DEPTH)
    args = ap.parse_args()

    started = time.time()
    repo = Path(__file__).resolve().parent.parent
    declared = default_roots()
    declared += [(str(repo), repo)] + [(str(r), r) for r in (args.root or [])]
    unresolvable = [label for label, path in declared if path is None]
    # A root that does not exist used to be dropped here without a word, so a
    # mistyped `--root D:/data` produced a confident census of somewhere else.
    # It is still reported — a directory that does not exist holds no databases,
    # so ENOENT here is a reading of the filesystem rather than a gap in it.
    # The test is a raw `os.stat` in a `try` and not `Path.exists()`, because
    # `exists()` swallows `OSError` and would file a root that exists and denies
    # access as a verified empty set. Anything but ENOENT is `unreadable`, and
    # that withholds.
    roots: list[Path] = []
    absent: list[str] = []
    unreadable_roots: list[dict] = []
    for _label, path in declared:
        if path is None:
            continue
        try:
            os.stat(str(path))
        except FileNotFoundError:
            absent.append(str(path))
            continue
        except OSError as exc:
            unreadable_roots.append(error_record(str(path), exc, "root"))
            continue
        roots.append(path)

    # Per-root depth. Each declared root's budget is counted from that root and
    # is never inherited from an ancestor root. Walking longest-prefix first is
    # what makes that true while every directory is still visited exactly once:
    # the visit that lands on a directory is the one from the nearest containing
    # root, which is the one with the largest remaining budget, so no later walk
    # could improve on it and the visited-set short-circuit costs nothing.
    #
    # <repo> sits three levels below a declared profile directory and used to
    # inherit that root's remaining 3 of its declared 6, so a store at
    # <repo>/a/b/c/d/store.db was never enumerated while effective_scope.statement
    # asserted it was covered. This changes files_seen, the size-filtered and
    # sniffed counts, the store list, root_shadowing and possibly the verdicts,
    # and that is the point of changing it.
    walk_roots = sorted(roots, key=lambda r: -len(key_prefix(str(r))))
    walk = Walk()
    seen: set[str] = set()
    for root in walk_roots:
        collect(root, args.depth, walk, seen)
    # Deduped on the case-folded absolute path as well as on the object, so a
    # file two roots both reach is one candidate and one store.
    walk.sized = sorted({key(str(p)): p for p in walk.sized}.values())

    candidates: list[Path] = []
    non_sqlite = 0
    # Which files were actually opened and read, as opposed to merely
    # enumerated. This is the set `content_read` on a file link target is
    # answered from, and it costs nothing extra because the sniff already
    # produced it.
    content_read: set[str] = set()
    with ThreadPoolExecutor(max_workers=SNIFF_WORKERS) as pool:
        for path, verdict, gap in pool.map(sniff, walk.sized):
            if verdict == "sqlite":
                candidates.append(path)
                content_read.add(key(str(path)))
            elif verdict is None:
                non_sqlite += 1
                content_read.add(key(str(path)))
            else:
                walk.unexaminable.append(gap)
    candidates.sort()

    # Links are classified once the roots and the walk record both exist:
    # scope needs the roots, and `actually_visited` needs the set of
    # directories whose listing succeeded. Answering the second from the first
    # is exactly the defect this ordering exists to prevent. The roots are
    # handed over in walk order, because `first_root` reads the list
    # positionally and "the root that reaches this first" has to mean the walk's
    # order and not the declaration's.
    classify_links(walk.links, walk_roots, walk, content_read, args.depth)

    before = snapshot(candidates)

    stores: list[Store] = []
    # A file that carries the SQLite header and still will not open is a hole in
    # the census — encrypted, corrupt, or locked — and is nothing like a file
    # that simply is not a database. The two used to share one list, where the
    # hundreds of uninteresting ones buried the interesting ones.
    sqlite_unreadable: list[dict] = []
    for path in candidates:
        store, problem = inspect(path, repo)
        if store:
            stores.append(store)
        if problem:
            sqlite_unreadable.append(problem)

    changes = compare(before, snapshot(candidates))

    # Both verdicts are decided here, before anything is printed or written, so
    # the status, the human report and the two JSON documents cannot disagree
    # about what this run concluded.
    outside = [s for s in stores if not s.is_repo_scratch]
    scratch = [s for s in stores if s.is_repo_scratch]
    offenders = [s for s in outside if (s.checkpoint_rows or 0) > 0]
    scope = effective_scope(declared, roots, absent, unresolvable, walk, args.depth)
    matrix = failure_matrix(walk, sqlite_unreadable, unresolvable, absent,
                            unreadable_roots, args.depth)
    # P9. The two dicts are the matrix split by its own flag, so neither can
    # say something the matrix does not, and moving a category between them is
    # a visible edit to `drives_coverage_incomplete` rather than a quiet edit
    # to a number.
    gaps = {name: c["count"] for name, c in matrix["categories"].items()
            if c["drives_coverage_incomplete"]}
    verified_empty = {name: c["count"] for name, c in matrix["categories"].items()
                      if not c["drives_coverage_incomplete"]}
    # The fifth link reason has no matrix record, because a question the census
    # closed is not a failure. It is counted here so that the five reasons
    # reconcile against len(links) in the artifact rather than in a reader's
    # head.
    links_by_reason = {reason: link_count(walk, reason) for reason in (
        "covered_and_visited", "inside_but_not_visited", "depth_shadowed_target",
        "out_of_declared_scope", "dangling", "unreadable_link")}
    offender_found = bool(offenders)
    coverage_incomplete = any(gaps.values())
    exit_code = ((EXIT_OFFENDER if offender_found else 0)
                 | (EXIT_INCOMPLETE if coverage_incomplete else 0))

    census = Census(
        offender_found=offender_found,
        coverage_incomplete=coverage_incomplete,
        coverage_gaps=gaps,
        coverage_verified_empty=verified_empty,
        exit_code=exit_code,
        effective_scope=scope,
        failure_matrix=matrix,
        links_by_reason=links_by_reason,
        # Populated from the same values `effective_scope` carries, not
        # recomputed, so the two copies cannot drift apart.
        roots_searched=scope["roots_searched"],
        roots_absent=scope["roots_absent"],
        roots_unresolvable=scope["roots_unresolvable"],
        roots_unreadable=unreadable_roots,
        excluded_dir_names=scope["excluded_dir_names"],
        excluded_path_fragments=EXCLUDE_PATH_FRAGMENTS,
        max_depth=scope["depth_max"],
        directories_listed=len(walk.listed),
        files_seen=walk.files_seen,
        files_size_filtered=walk.size_filtered,
        files_sniffed=len(walk.sized),
        non_sqlite_files=non_sqlite,
        sqlite_candidates=len(candidates),
        # Full records for every store outside this repo, and for the scratch
        # ones that hold a checkpoint row — those two sets are what the census
        # is for. The remaining scratch stores are a count: a full test run
        # leaves a hundred of them, they are deleted by `zig build`, and the
        # only interesting fact about one is the checkpoint row it does not
        # have.
        stores=[s for s in stores if not s.is_repo_scratch or s.checkpoint_rows],
        repo_scratch_without_checkpoints=len(
            [s for s in stores if s.is_repo_scratch and not s.checkpoint_rows]),
        # A count, not the paths. What the census has to establish is coverage —
        # how many SQLite files were opened and found not to be ours — and the
        # number carries that. The paths do not: they are every browser profile,
        # chat client and package cache on the machine, and this artifact is
        # committed to a public repository. Re-run the script to see them.
        non_store_sqlite=len([p for p in candidates
                              if str(p) not in {s.path for s in stores}
                              and str(p) not in {u["path"] for u in sqlite_unreadable}]),
        sqlite_unreadable=sqlite_unreadable,
        unexaminable=walk.unexaminable,
        not_regular_files=walk.not_regular,
        links=walk.links,
        frontier_depth_limited=walk.depth_limited,
        frontier_excluded=walk.excluded,
        # The claim is "a mode=ro census changed no database". Hundreds of
        # `-shm` mtime bumps are how that claim was measured, not the claim;
        # they are summarised by category. Anything a read-only open cannot
        # cause is listed in full, because that is the claim failing.
        filesystem_effect={
            "files_digested_before_and_after": len(before),
            "by_category": dict(sorted(Counter(category(c) for c in changes).items())),
            "contradicting_read_only": [c for c in changes if c["contradicts_read_only"]],
        },
        seconds=round(time.time() - started, 1),
    )

    print("roots searched:")
    for r in census.roots_searched:
        print("  " + r)
    if census.roots_absent:
        print("roots requested but not present on this machine (searched: nothing to "
              "search — a directory that does not exist holds no databases):")
        for r in census.roots_absent:
            print("  " + r)
    if census.roots_unresolvable:
        print("roots that could not even be resolved (NOT searched — this is a hole):")
        for r in census.roots_unresolvable:
            print("  " + r)
    if census.roots_unreadable:
        print("roots that exist and would not stat (NOT searched — this is a hole):")
        for r in census.roots_unreadable:
            print(f"  {r['path']}: {r['error']}")
    for entry in scope["root_shadowing"]:
        print(f"note: {entry['root']} lies inside {entry['nested_inside']}, is walked "
              f"from itself at depth {entry['first_reached_at_depth']}, and therefore "
              f"gets {entry['effective_depth_budget']} of its {census.max_depth} "
              f"declared levels")
    print(f"depth limit {census.max_depth}; excluded {len(EXCLUDE_DIR_NAMES)} dir names "
          f"and {len(EXCLUDE_PATH_FRAGMENTS)} path fragments")
    print(f"{census.directories_listed} directories listed")
    print(f"{census.files_seen} files seen; {census.files_size_filtered} rejected on size; "
          f"{census.files_sniffed} header-sniffed; {census.sqlite_candidates} are SQLite; "
          f"{len(stores)} are Terminus stores\n")

    # Stores outside the repo's scratch are listed one per line: those are the
    # ones a person might care about. The scratch ones are summarised, because
    # a full test run leaves dozens and the only interesting fact about them is
    # which hold a checkpoint row.
    print(f"{'ver':>4}  {'ckpt':>5}  {'rows':>5}  path   (stores outside the repo's test scratch)")
    for s in sorted(outside, key=lambda s: s.path):
        rows = "-" if s.checkpoint_rows is None else str(s.checkpoint_rows)
        print(f"{s.user_version:>4}  {str(s.has_checkpoints_table):>5}  {rows:>5}  {s.path}")

    scratch_rows = sum(s.checkpoint_rows or 0 for s in scratch)
    if scratch:
        versions = sorted({s.user_version for s in scratch})
        print(f"\nrepo test scratch (.zig-cache/tmp): {len(scratch)} stores, user_version "
              f"{versions[0]}-{versions[-1]}, {scratch_rows} checkpoint row(s):")
        for s in sorted(scratch, key=lambda s: s.path):
            if s.checkpoint_rows:
                print(f"  {s.checkpoint_rows} in {Path(s.path).name}: "
                      f"{', '.join(s.checkpoint_request_ids)}")

    print()
    print(f"checkpoint rows outside the repo's test scratch: "
          f"{sum(s.checkpoint_rows or 0 for s in offenders)}")
    print(f"checkpoint rows in the repo's test scratch:      {scratch_rows}")
    for s in offenders:
        print(f"  {s.path}: {s.checkpoint_rows} row(s), "
              f"request ids {', '.join(s.checkpoint_request_ids) or '(none recorded)'}")

    # The failure matrix, printed in the same two groups the verdict is built
    # from, so the human report and the exit status cannot tell different
    # stories. Gap-driving categories first, with the entries that carry the
    # verdict; the rest after, counted, because a bound nobody counts is
    # indistinguishable from a bound nobody applied.
    for drives, headline in (
        (True, "!! these withhold authorisation — the census could not answer:"),
        (False, "these do not withhold — an answer the census got, or a bound it "
                "declared in advance:"),
    ):
        rows = [(name, c) for name, c in matrix["categories"].items()
                if c["drives_coverage_incomplete"] is drives]
        print(f"\n{headline}")
        for name, c in rows:
            note = ""
            if c["entries_truncated"]:
                note = f"  ({c['entries_recorded']} of {c['entries_total']} listed)"
            print(f"  {c['count']:>6}  {name}{note}")
            if name == "unreadable" and c.get("by_origin"):
                for origin, n in c["by_origin"].items():
                    print(f"          {n:>6}  origin={origin}")
            if not drives or not c["entries"]:
                continue
            for entry in c["entries"][:20]:
                detail = entry.get("error") or entry.get("not_visited_reason") or ""
                arrow = f" -> {entry['target']}" if entry.get("target") else ""
                print(f"          {entry.get('path') or entry.get('variable')}"
                      f"{arrow}{': ' + detail if detail else ''}")
            if len(c["entries"]) > 20:
                print(f"          … {len(c['entries']) - 20} more, in the JSON")

    print(f"\nlinks, by what resolving them established ({len(walk.links)} total):")
    for reason, gloss in (
        ("covered_and_visited", "target inside a searched root, and the walk read it"),
        ("inside_but_not_visited", "!! target inside a searched root, nothing read it, "
                                   "and no declared depth bound accounts for it"),
        ("depth_shadowed_target", "!! target inside a searched root that nothing read, "
                                  "stopped by this census's own declared depth_max"),
        ("out_of_declared_scope", "target outside every searched root — declined by "
                                  "policy, not a gap; declare the target a root to "
                                  "bring it in"),
        ("dangling", "target does not exist — nothing there to search"),
        ("unreadable_link", "!! the census could not learn where this points"),
    ):
        print(f"  {links_by_reason[reason]:>6}  {reason}: {gloss}")

    if changes:
        # Grouped, because the per-file list runs to hundreds of lines on a
        # machine with browser profiles on it and the shape of the effect is
        # what matters; every line is in the JSON under "filesystem_changes".
        print(f"\nfilesystem effect, measured on {len(before)} database, -wal and -shm "
              f"files digested before and after the run:")
        for name, count in sorted(Counter(category(c) for c in changes).items()):
            print(f"  {count:>5}  {name}")
        alarming = [c for c in changes if c["contradicts_read_only"]]
        if alarming:
            print(f"\n!! {len(alarming)} change(s) a mode=ro census cannot cause — either "
                  f"something else wrote during the run, or the read-only claim is false:")
            for c in alarming:
                print(f"  {c['change']:<28} {c['path']}")
        else:
            print("  no database file changed in size, mtime or content, and no -wal "
                  "gained a byte")
    else:
        print(f"\nno filesystem change at all: {len(before)} database, -wal and -shm files "
              f"digested before and after are byte-for-byte and mtime identical")

    print(f"\n{census.seconds}s")

    # Strings a committed artifact may not carry. Collected rather than raised
    # at the first hit, so one run names every offending field instead of
    # making an operator re-run to find the next one.
    leaked: list[dict] = []

    if args.json:
        build_path_tokens(repo)
        build_keep_prefixes(declared)
        leaked += write_committed(
            args.json, public(census),
            "committed artifact: verdicts, coverage, per-store version and "
            "checkpoint presence")

    if args.raw:
        out = Path(args.raw)
        out.parent.mkdir(parents=True, exist_ok=True)
        # Untokenised on purpose: this is the copy an operator uses to go and
        # find the offending file, and a tokenised path is not a path. It is
        # therefore the copy that must not be committed, and the only one the
        # redaction check does not run against.
        out.write_text(json.dumps(asdict(census), indent=2), encoding="utf-8")
        print(f"wrote {args.raw} (raw census: absolute paths, file sizes, user-data counts "
              f"and request ids — do not commit; keep `docs/evidence/raw/` git-ignored)")

    if args.corroboration:
        build_path_tokens(repo)
        build_keep_prefixes(declared)
        leaked += write_committed(
            args.corroboration, corroboration(census, time.strftime("%Y-%m-%d")),
            "corroboration: a bounded negative, NOT clearance — it carries what it "
            "does not assert and everything it could not see")

    # Printed whether or not anything leaked, because an unbuilt token is a
    # fact about this run's redaction and the output check only sees its
    # consequences. It does not change the status by itself: whether a missing
    # token mattered is decided by testing the finished document, not by
    # guessing from the environment, and a machine with no ProgramFiles(x86)
    # and no link into one has nothing wrong with it.
    if TOKENS_UNBUILT and (args.json or args.corroboration):
        print(f"\nnote: {len(TOKENS_UNBUILT)} path token(s) were not built, because the "
              f"environment variable naming each was empty: " + ", ".join(TOKENS_UNBUILT)
              + ". A token that is not built redacts nothing. The home roots come from "
                "Path.home(), which does not need the same variables, so a path under a "
                "root can still reach the document with no token to rewrite it — the "
                "redaction check below is what decides whether it did.")

    # Two verdicts, printed last because they are the answer and everything
    # above is how it was reached. Both are stated even when false: "asked and
    # the answer was no" has to be distinguishable from "never asked".
    def mark(flag: bool) -> str:
        return "YES" if flag else "no "

    print()
    print(f"offender_found      {mark(offender_found)}  checkpoint row(s) in a store outside "
          f"this repo's test scratch")
    withholding = [f"{n} {name}" for name, n in gaps.items() if n]
    print(f"coverage_incomplete {mark(coverage_incomplete)}  "
          + (", ".join(withholding) if withholding
             else "every gap-driving category of failure_matrix is empty"))
    print("                         declined or answered, and therefore not gaps: "
          + ", ".join(f"{n} {name}" for name, n in verified_empty.items() if n))

    # Printed after the verdicts and returned instead of them. The census
    # reached its two verdicts and they are stated above; what failed is the
    # publishing, and a redaction failure is not a fact about this machine's
    # stores, so it must not be reported in the status that is read as one.
    if leaked:
        print(f"\n!! {len(leaked)} string(s) in a committed artifact are not fit to commit. "
              f"NOTHING WAS WRITTEN for the artifact(s) named — the file on disk, if any, "
              f"is the previous run's:")
        for v in leaked[:20]:
            print(f"  {v['artifact']}  {v['json_path']}  [{v['rule']}] {v['matched']!r} "
                  f"in {v['value']}")
        if len(leaked) > 20:
            print(f"  … {len(leaked) - 20} more")
        print("\nThe tokeniser rewrites known root prefixes and nothing else, so a path "
              "outside them — an extra --root, a link into a directory no token covers, a "
              "UNC share — reaches the document verbatim. Give the location a token in "
              "build_path_tokens, or take the field out of the committed projection.")
        if TOKENS_UNBUILT:
            print("Before doing either, note that these tokens exist and were NOT built "
                  "on this run, because the environment variable naming each was empty: "
                  + ", ".join(TOKENS_UNBUILT) + ". A token that is not built redacts "
                  "nothing, and the home roots are derived from Path.home(), which does "
                  "not need the same variable — so the two can disagree and the paths "
                  "arrive untokenised. Set the variable rather than adding a token.")
        print(f"\nexit {EXIT_REDACTION}: no committed artifact was written. This run's "
              f"census verdict was {exit_code}, and it is deliberately not the status: a "
              f"redaction failure is not a finding about this machine.")
        return EXIT_REDACTION

    if exit_code == EXIT_CLEAR:
        print("\nexit 0: searched everything it set out to search and found no offender. "
              "This, and only this, clears the v11 drop-and-recreate.")
    else:
        because = []
        if offender_found:
            because.append("a checkpoint row exists where the recut would destroy it")
        if coverage_incomplete:
            because.append("the census could not see everything the scope it declares "
                           "says it covers, so it cannot speak for what it did not reach")
        print(f"\nexit {exit_code}: NOT cleared — " + "; ".join(because) + ".")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
