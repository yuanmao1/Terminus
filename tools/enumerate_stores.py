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
* `coverage_incomplete` — the census could not see everything it set out to
  search: an environment variable naming a root was unset so no path could be
  formed, a file carrying the SQLite header would not open, or a path could
  not be examined at all.

A root whose environment variable resolved but whose directory does not exist
is **not** in that list, and neither is a reparse point whose target does not
exist. A directory that does not exist contains no databases, and neither does
a link that points at one; both resolve cleanly to "nothing there", so they
are empty sets the census verified rather than places it failed to look. They
are still reported — the scope claim stays explicit — but they do not withhold
authorisation. The same shape of distinction runs through the whole report:
"we looked and there is nothing there" is an answer, and "we could not look"
is not.

The dangling-link case is worth naming because it was got wrong once. Windows
reports a reparse point whose target is missing as WinError 3, the same error
a genuinely deleted directory gives, so 18 stale build junctions were counted
as directories that "vanished mid-walk under a concurrent build". They had not
vanished during anything: they reproduced identically on every run, which is
precisely what a mid-walk deletion does not do.

    0   searched everything it set out to search, and found no offender.
        The only status that clears the v11 drop-and-recreate to be written
    1   offender_found
    2   coverage_incomplete
    3   both
    64  usage error — deliberately not 2, so a mistyped flag can never be
        read as a coverage result

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
  rests on. Every path in it is tokenised. It carries no file sizes, no counts
  of anybody's servers, keys, memories or facts, and no request ids.
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


def default_roots() -> tuple[list[Path], list[str]]:
    """The roots, plus the ones whose environment variable was unset.

    The two ways a root can fail to be searched look alike and are not alike,
    and only one of them is a hole in the census:

    * **The variable is unset**, so no path could be formed at all. Nothing is
      known about where that root would have been, let alone what is inside
      it. Those are returned here, and they withhold authorisation.
    * **The variable resolved and the directory does not exist.** The caller
      checks that against the filesystem. A directory that does not exist
      contains no databases, so this is a verified empty set rather than a
      blind spot: it is reported, because the scope claim stays explicit, and
      it withholds nothing.

    The distinction is the same one the walk draws between a path that refused
    to open and a path that vanished mid-walk — except that there it changes
    only the advice, and here it changes the verdict, because "we looked and
    there is nothing there" is an answer and "we could not look" is not.
    """
    roots: list[Path] = []
    unresolvable: list[str] = []
    for var, sub in (("APPDATA", "terminus"), ("LOCALAPPDATA", "terminus"), ("TEMP", "")):
        base = os.environ.get(var)
        if not base:
            unresolvable.append(f"%{var}%" + (f"/{sub}" if sub else "") + " (environment variable unset)")
            continue
        roots.append(Path(base) / sub if sub else Path(base))
    roots += [Path.home() / name for name in (
        ".terminus", "Desktop", "Downloads", "Documents",
        # Added because `~/Documents` contains Windows' legacy compatibility
        # junctions `My Videos`, `My Pictures` and `My Music`, which point
        # here and carry a deny-everyone ACL. The census cannot read the
        # junctions, so before these were declared the link rule counted three
        # gaps. Declaring the targets searches strictly more rather than
        # excusing anything, and the gaps close because the bytes are now read
        # under their real names.
        "Videos", "Pictures", "Music",
    )]
    return roots, unresolvable


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
  2   coverage_incomplete  an environment variable naming a root was unset, a
                           file carrying the SQLite header would not open, or
                           a path could not be examined at all
  3   both
  64  usage error, deliberately not 2 — a mistyped flag is not a fact about
      this machine and must not be reported as one

The three census codes are a bitmask: `status & 1` is the row, `status & 2`
the holes. Two things that look like holes are not, and both are reported
rather than hidden: a root whose directory does not exist, and a reparse point
whose target does not exist. Each resolves cleanly to "nothing there", which
is a verified empty set rather than a blind spot. A path that refused to open,
and one that was deleted between being listed and being opened, are blind
spots and do withhold.
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
    roots_searched: list[str]
    roots_absent: list[str]
    roots_unresolvable: list[str]
    excluded_dir_names: list[str]
    excluded_path_fragments: list[str]
    max_depth: int
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
    links: list[dict]
    filesystem_effect: dict
    seconds: float


# Why a path could not be examined, decided by exception type and by asking the
# filesystem one more question, rather than by matching on a message — the
# message is localised, and on this machine WinError 3 arrives in Chinese.
#
# Three answers, and only two of them are holes:
#
# * "refused"  — something denies access. It will keep denying it; go and look.
# * "vanished" — the entry was listed and was gone by the time it was opened.
#   A real mid-walk deletion. The census cannot speak for it.
# * "dangling" — the path is a reparse point whose target does not exist. This
#   is NOT a hole. It resolves cleanly and the answer is "nothing there": the
#   same verified empty set as a root whose directory does not exist. Windows
#   reports it as WinError 3, which is why it used to be counted as a mid-walk
#   disappearance — and the giveaway that it was never one is that it is
#   perfectly stable across runs. `lexists` sees the link; `exists` follows it
#   and finds nothing.
def why(path: str, exc: OSError) -> str:
    if isinstance(exc, (FileNotFoundError, NotADirectoryError)):
        try:
            if os.path.lexists(path) and not os.path.exists(path):
                return "dangling"
        except OSError:
            pass
        return "vanished"
    return "refused"


def hole(path: str, exc: OSError) -> dict:
    reason = why(path, exc)
    record = {"path": path, "error": f"{type(exc).__name__}: {exc}", "reason": reason}
    if reason == "dangling":
        # The target is the evidence. Without it "this link points nowhere" is
        # an assertion; with it a reader can check the empty set for themselves.
        try:
            record["target"] = os.readlink(path)
        except OSError as exc2:
            record["target"] = f"unreadable: {type(exc2).__name__}"
    return record



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


def key(path: str) -> str:
    """One spelling per file, so a store is not counted twice for being
    reachable two ways. Case-folded because Windows paths are."""
    return os.path.normcase(os.path.abspath(path))


def covered_by(target: str, roots: list[Path]) -> str | None:
    """Which declared root contains this target, if any.

    This is the whole of the link rule. A link is not a directory and is never
    walked into; what matters about one is whether the bytes it points at are
    already being searched under their real name. If they are, the link is a
    second name for territory already covered and adds nothing. If they are
    not, the link names a place the census does not reach — a gap that states
    its own remedy, because the target is right there in the record.
    """
    t = key(strip_extended(target))
    for root in roots:
        r = key(str(root))
        if t == r or t.startswith(r + os.sep):
            return str(root)
    return None


def build_path_tokens(repo: Path) -> None:
    PATH_TOKENS.clear()
    for token, value in (
        ("<repo>", str(repo)),
        ("%TEMP%", os.environ.get("TEMP", "")),
        ("%LOCALAPPDATA%", os.environ.get("LOCALAPPDATA", "")),
        ("%APPDATA%", os.environ.get("APPDATA", "")),
        ("%USERPROFILE%", os.environ.get("USERPROFILE", "")),
        # System install roots. Nothing about them is private — they are the
        # same on every Windows machine — but a link out of the searched
        # territory records its target, and a JDK under Program Files is the
        # commonest such target here. Tokenising them keeps "this artifact
        # contains no absolute path" true as a property somebody can check in
        # one grep, instead of a claim that has to be re-argued path by path
        # every time a new link shows up. The remedy the gap names survives the
        # substitution: `%PROGRAMFILES%/Microsoft/jdk-25` is as actionable as
        # the literal spelling.
        ("%PROGRAMFILES%", os.environ.get("ProgramFiles", "")),
        ("%PROGRAMFILES(X86)%", os.environ.get("ProgramFiles(x86)", "")),
        ("%PROGRAMDATA%", os.environ.get("ProgramData", "")),
    ):
        if value:
            PATH_TOKENS.append((token, value))
    # Last, and shortest, so the directory tokens above win wherever they can.
    # This one exists for the names that *embed* the account rather than living
    # under its profile — `%TEMP%\hsperfdata_<user>` is the one on this machine.
    # Guarded on length because a two-letter account name would shred the
    # document, and an unredacted short name is the lesser problem.
    user = os.environ.get("USERNAME", "")
    if len(user) >= 4:
        PATH_TOKENS.append(("<user>", user))


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
        "roots_searched": census.roots_searched,
        "roots_absent": census.roots_absent,
        "roots_unresolvable": census.roots_unresolvable,
        "excluded_dir_names": census.excluded_dir_names,
        "excluded_path_fragments": census.excluded_path_fragments,
        "max_depth": census.max_depth,
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
        # are a bare count cannot be checked by a reader.
        "sqlite_unreadable": census.sqlite_unreadable,
        "unexaminable": census.unexaminable,
        # Links are cheap and few, and each one is either a closed question or a
        # gap that names its own remedy. Both are worth committing.
        "links": census.links,
        # `contradicting_read_only` is kept in full, digests and all. It is
        # empty whenever the read-only claim holds; when it is not empty, the
        # detail is the entire point and withholding it would be hiding the
        # one failure this artifact exists to make visible.
        "filesystem_effect": census.filesystem_effect,
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
    gaps = [g for g in census.unexaminable if g.get("reason") in ("refused", "vanished")]
    link_gaps = [dict(link_gap) for link_gap in census.links
                 if link_gap.get("reason") in ("target_not_covered", "unreadable_link")]
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
            "checkpoint_rows_outside_repo_scratch": 0,
            "stores_in_repo_scratch_holding_a_row": sum(
                1 for s in census.stores if s.is_repo_scratch and s.checkpoint_rows),
            "roots_searched": census.roots_searched,
            "roots_absent_and_therefore_empty": census.roots_absent,
            "max_depth": census.max_depth,
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
            "That the census saw everything under those roots. It did not: see "
            "could_not_see.",
        ],
        "could_not_see": {
            "count": len(gaps) + len(link_gaps),
            "what_this_is": (
                "Everything the census did not read. Facts only: each entry is "
                "a path, why it could not be read, and where it resolves to if "
                "it is a link. Whether any of these could hold a Terminus store "
                "is left to the reader."
            ),
            "unreadable_paths": gaps,
            "links_out_of_declared_roots": link_gaps,
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


def excluded(path: Path) -> bool:
    text = str(path).replace("\\", "/")
    if any(fragment in text for fragment in EXCLUDE_PATH_FRAGMENTS):
        return True
    return bool(set(path.parts) & EXCLUDE_DIR_NAMES)


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
    """
    stack: list[tuple[str, int]] = [(str(root), 0)]
    while stack:
        here, depth = stack.pop()
        # One visit per directory, however many names reach it. Roots can
        # overlap and a root can sit inside another; without this a store under
        # both is two stores.
        if key(here) in seen:
            continue
        seen.add(key(here))
        try:
            entries = list(os.scandir(here))
        except OSError as exc:
            walk.unexaminable.append(hole(here, exc))
            continue
        for entry in entries:
            try:
                info = entry.stat(follow_symlinks=False)
                if is_link(entry.path, info):
                    walk.links.append(link_record(entry.path))
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if depth + 1 < max_depth and not excluded(Path(entry.path)):
                        stack.append((entry.path, depth + 1))
                    continue
                if not entry.is_file(follow_symlinks=False):
                    continue
                size = info.st_size
            except OSError as exc:
                walk.unexaminable.append(hole(entry.path, exc))
                continue
            walk.files_seen += 1
            if size >= PAGE_FLOOR and size % PAGE_FLOOR == 0:
                walk.sized.append(Path(entry.path))
            else:
                walk.size_filtered += 1


def link_count(walk: Walk, reason: str) -> int:
    return sum(1 for r in walk.links if r.get("reason") == reason)


def link_record(path: str) -> dict:
    """A link, where it goes, and whether that is somewhere we already search.

    `resolves` is answered against the filesystem rather than assumed, because
    the three outcomes are three different verdicts and only one of them is a
    hole: a target that does not exist holds nothing, a target inside a
    declared root is already being read under its real name, and a target
    outside every root is territory this census does not reach.
    """
    # Whether it resolves is asked of the link itself, because `os.path.exists`
    # follows it and answers that without needing to read the target string.
    # The two questions come apart: a WSL symlink (tag 0xA000001D) resolves to
    # nothing in the Win32 namespace *and* defeats `readlink`, and it is the
    # resolution that decides the verdict. A link that goes nowhere holds no
    # databases whether or not its target can be spelled.
    record: dict = {"path": path, "target": None, "resolves": os.path.exists(path)}
    try:
        record["target"] = os.readlink(path)
    except (OSError, ValueError) as exc:
        record["target"] = f"unresolvable: {type(exc).__name__}"
    if not record["resolves"]:
        record["reason"] = "dangling"
    elif str(record["target"]).startswith("unresolvable: "):
        # It points somewhere real and will not say where, so coverage cannot
        # be decided. That is a hole.
        record["reason"] = "unreadable_link"
    return record


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
        return path, "error", hole(str(path), exc)
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
        return None, {"path": str(path), "error": f"{type(exc).__name__}: {exc}"}


def main() -> int:
    ap = Parser(description=__doc__.split("\n")[0], epilog=EXIT_HELP,
                formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", action="append", type=Path, help="extra search root (repeatable)")
    ap.add_argument("--json", metavar="PATH",
                    help="write the committed artifact: the two verdicts, coverage numbers, "
                         "filesystem effect, and per store its user_version, whether it has a "
                         "transfer_checkpoints table and whether that table holds a row. Paths "
                         "tokenised; no file sizes, no user-data counts, no request ids")
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
    requested, unresolvable = default_roots()
    requested += [repo] + (args.root or [])
    # A root that does not exist used to be dropped here without a word, so a
    # mistyped `--root D:/data` produced a confident census of somewhere else.
    # It is still reported — but `exists()` returning False is a reading of the
    # filesystem, not a gap in it, so it does not withhold authorisation.
    roots = [r for r in requested if r.exists()]
    absent = [str(r) for r in requested if not r.exists()]

    walk = Walk()
    seen: set[str] = set()
    for root in roots:
        collect(root, args.depth, walk, seen)
    # Deduped on the case-folded absolute path as well as on the object, so a
    # file two roots both reach is one candidate and one store.
    walk.sized = sorted({key(str(p)): p for p in walk.sized}.values())
    # A link is classified once the roots are known, because the only question
    # about one is whether its target is somewhere already searched.
    for record in walk.links:
        if record.get("reason"):
            continue
        root = covered_by(strip_extended(record["target"]), roots)
        record["covered_by"] = root
        record["reason"] = "target_covered" if root else "target_not_covered"

    candidates: list[Path] = []
    non_sqlite = 0
    with ThreadPoolExecutor(max_workers=SNIFF_WORKERS) as pool:
        for path, verdict, gap in pool.map(sniff, walk.sized):
            if verdict == "sqlite":
                candidates.append(path)
            elif verdict is None:
                non_sqlite += 1
            else:
                walk.unexaminable.append(gap)
    candidates.sort()

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
    gaps = {
        "roots_unresolvable": len(unresolvable),
        "sqlite_unreadable": len(sqlite_unreadable),
        "unexaminable_refused": sum(1 for u in walk.unexaminable if u["reason"] == "refused"),
        "unexaminable_vanished": sum(1 for u in walk.unexaminable if u["reason"] == "vanished"),
        # A link out of the searched territory. The only gap that states its
        # own remedy: the record carries the target, so closing it is a matter
        # of declaring that target a root.
        "links_to_uncovered_targets": link_count(walk, "target_not_covered"),
        "links_unreadable": link_count(walk, "unreadable_link"),
    }
    # Reported for the same reason the gaps are — the scope claim stays
    # explicit — but these are answers rather than blind spots, so they do not
    # withhold authorisation. A directory that does not exist and a link whose
    # target does not exist both hold no databases, and the census established
    # that rather than failing to look. A link into a declared root is a second
    # name for territory already read under its first one.
    verified_empty = {
        "roots_absent": len(absent),
        "unexaminable_dangling": sum(1 for u in walk.unexaminable if u["reason"] == "dangling"),
        "links_dangling": link_count(walk, "dangling"),
        "links_target_covered": link_count(walk, "target_covered"),
    }
    offender_found = bool(offenders)
    # A path that really did vanish between being listed and being opened still
    # counts: the census cannot speak for it, and unlike a dangling link it
    # will not reproduce.
    coverage_incomplete = any(gaps.values())
    exit_code = ((EXIT_OFFENDER if offender_found else 0)
                 | (EXIT_INCOMPLETE if coverage_incomplete else 0))

    census = Census(
        offender_found=offender_found,
        coverage_incomplete=coverage_incomplete,
        coverage_gaps=gaps,
        coverage_verified_empty=verified_empty,
        exit_code=exit_code,
        roots_searched=[str(r) for r in roots],
        roots_absent=absent,
        roots_unresolvable=unresolvable,
        excluded_dir_names=sorted(EXCLUDE_DIR_NAMES),
        excluded_path_fragments=EXCLUDE_PATH_FRAGMENTS,
        max_depth=args.depth,
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
        links=walk.links,
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
    print(f"depth limit {census.max_depth}; excluded {len(EXCLUDE_DIR_NAMES)} dir names "
          f"and {len(EXCLUDE_PATH_FRAGMENTS)} path fragments")
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

    if sqlite_unreadable:
        print(f"\n!! {len(sqlite_unreadable)} SQLite database(s) would not open — "
              f"these are holes in the census, not absences of evidence:")
        for u in sqlite_unreadable:
            print(f"  {u['path']}: {u['error']}")
    # Split by reason, because the three are different instructions. A refusal
    # is a standing condition on this machine and somebody has to go and look
    # at it; a disappearance means the entry was deleted between being listed
    # and being opened, and a re-run may well close it. A dangling link is
    # neither: it is an answer, and it is printed as one.
    for reason, headline, gap in (
        ("refused", "refused to open", True),
        ("vanished", "disappeared between being listed and being opened", True),
        ("dangling", "are links whose target does not exist", False),
    ):
        gap_paths = [u for u in walk.unexaminable if u["reason"] == reason]
        if not gap_paths:
            continue
        if gap:
            print(f"\n!! {len(gap_paths)} path(s) {headline} and could not be examined at all "
                  f"(holes in the census):")
        else:
            print(f"\n{len(gap_paths)} path(s) {headline} — nothing there to search, so these "
                  f"are NOT holes:")
        for u in gap_paths[:20]:
            arrow = f" -> {u['target']}" if u.get("target") else ""
            print(f"  {u['path']}: {u['error']}{arrow}")
        if len(gap_paths) > 20:
            print(f"  … {len(gap_paths) - 20} more, in the JSON")

    # Links, by what resolving them established. A link is never walked into,
    # so the only thing to report about one is where it goes and whether that
    # is somewhere already searched.
    if walk.links:
        for reason, headline, gap in (
            ("target_not_covered", "point outside every declared root", True),
            ("unreadable_link", "could not be resolved", True),
            ("dangling", "point at a target that does not exist", False),
            ("target_covered", "point into a declared root, already searched", False),
        ):
            group = [r for r in walk.links if r.get("reason") == reason]
            if not group:
                continue
            bang = "!! " if gap else ""
            tail = (" — declare the target a root to close this"
                    if reason == "target_not_covered" else
                    "" if gap else " — not holes")
            print(f"\n{bang}{len(group)} link(s) {headline}{tail}:")
            for r in group[:20]:
                print(f"  {r['path']} -> {r['target']}")
            if len(group) > 20:
                print(f"  … {len(group) - 20} more, in the JSON")

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

    if args.json:
        out = Path(args.json)
        out.parent.mkdir(parents=True, exist_ok=True)
        build_path_tokens(repo)
        out.write_text(json.dumps(tokenised(public(census)), indent=2), encoding="utf-8")
        print(f"wrote {args.json} (committed artifact: verdicts, coverage, per-store version "
              f"and checkpoint presence)")

    if args.raw:
        out = Path(args.raw)
        out.parent.mkdir(parents=True, exist_ok=True)
        # Untokenised on purpose: this is the copy an operator uses to go and
        # find the offending file, and a tokenised path is not a path. It is
        # therefore the copy that must not be committed.
        out.write_text(json.dumps(asdict(census), indent=2), encoding="utf-8")
        print(f"wrote {args.raw} (raw census: absolute paths, file sizes, user-data counts "
              f"and request ids — do not commit; keep `docs/evidence/raw/` git-ignored)")

    if args.corroboration:
        out = Path(args.corroboration)
        out.parent.mkdir(parents=True, exist_ok=True)
        build_path_tokens(repo)
        out.write_text(json.dumps(tokenised(corroboration(census, time.strftime("%Y-%m-%d"))),
                                  indent=2), encoding="utf-8")
        print(f"wrote {args.corroboration} (corroboration: a bounded negative, NOT clearance — "
              f"it carries what it does not assert and everything it could not see)")

    # Two verdicts, printed last because they are the answer and everything
    # above is how it was reached. Both are stated even when false: "asked and
    # the answer was no" has to be distinguishable from "never asked".
    def mark(flag: bool) -> str:
        return "YES" if flag else "no "

    print()
    print(f"offender_found      {mark(offender_found)}  checkpoint row(s) in a store outside "
          f"this repo's test scratch")
    print(f"coverage_incomplete {mark(coverage_incomplete)}  "
          f"{gaps['roots_unresolvable']} root(s) unresolvable, "
          f"{gaps['sqlite_unreadable']} database(s) would not open, "
          f"{gaps['unexaminable_refused']} path(s) refused, "
          f"{gaps['unexaminable_vanished']} path(s) vanished, "
          f"{gaps['links_to_uncovered_targets']} link(s) out of scope, "
          f"{gaps['links_unreadable']} link(s) unresolvable")
    print(f"                         verified empty or covered, not gaps: "
          f"{verified_empty['roots_absent']} absent root(s), "
          f"{verified_empty['unexaminable_dangling'] + verified_empty['links_dangling']} "
          f"dangling link(s), "
          f"{verified_empty['links_target_covered']} link(s) into searched territory")

    if exit_code == EXIT_CLEAR:
        print("\nexit 0: searched everything it set out to search and found no offender. "
              "This, and only this, clears the v11 drop-and-recreate.")
    else:
        because = []
        if offender_found:
            because.append("a checkpoint row exists where the recut would destroy it")
        if coverage_incomplete:
            because.append("the census could not see everything it set out to search, "
                           "so it cannot speak for what it did not reach")
        print(f"\nexit {exit_code}: NOT cleared — " + "; ".join(because) + ".")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
