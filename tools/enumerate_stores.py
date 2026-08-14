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
    python tools/enumerate_stores.py --root D:/ --root E:/data

Exit status is the point of the whole thing: **1 when any checkpoint row
exists outside this repo's own test scratch**, 0 when none does. That is
exactly the condition under which the v11 drop-and-recreate would destroy
something somebody meant to keep, so the audit is a gate rather than a
paragraph.

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
import sqlite3
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
    """The roots, plus the ones an unset environment variable took away.

    An absent `%TEMP%` must not silently shrink the census: it is returned as a
    named gap so the report can say the search never looked there.
    """
    roots: list[Path] = []
    missing: list[str] = []
    for var, sub in (("APPDATA", "terminus"), ("LOCALAPPDATA", "terminus"), ("TEMP", "")):
        base = os.environ.get(var)
        if not base:
            missing.append(f"%{var}%" + (f"/{sub}" if sub else "") + " (environment variable unset)")
            continue
        roots.append(Path(base) / sub if sub else Path(base))
    roots += [Path.home() / name for name in (".terminus", "Desktop", "Downloads", "Documents")]
    return roots, missing


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
    roots_searched: list[str]
    roots_absent: list[str]
    excluded_dir_names: list[str]
    excluded_path_fragments: list[str]
    max_depth: int
    files_seen: int
    files_size_filtered: int
    files_sniffed: int
    non_sqlite_files: int
    sqlite_candidates: int
    stores: list[Store]
    non_store_sqlite: int
    sqlite_unreadable: list[dict]
    unexaminable: list[dict]
    filesystem_changes: list[dict]
    seconds: float


@dataclass
class Walk:
    """What the walk saw, including what it could not look at."""
    sized: list[Path] = field(default_factory=list)
    files_seen: int = 0
    size_filtered: int = 0
    unexaminable: list[dict] = field(default_factory=list)


def excluded(path: Path) -> bool:
    text = str(path).replace("\\", "/")
    if any(fragment in text for fragment in EXCLUDE_PATH_FRAGMENTS):
        return True
    return bool(set(path.parts) & EXCLUDE_DIR_NAMES)


def collect(root: Path, max_depth: int, walk: Walk) -> None:
    """Bounded walk. `Path.rglob` would descend forever into a profile dir.

    Uses `scandir` rather than `os.walk` + `stat` because on Windows the
    directory entry already carries the size, so the pre-filter is free.
    """
    stack: list[tuple[str, int]] = [(str(root), 0)]
    while stack:
        here, depth = stack.pop()
        try:
            entries = list(os.scandir(here))
        except OSError as exc:
            walk.unexaminable.append({"path": here, "error": f"{type(exc).__name__}: {exc}"})
            continue
        for entry in entries:
            try:
                # follow_symlinks=False: a junction pointing at its own ancestor
                # would otherwise make the depth limit meaningless.
                if entry.is_dir(follow_symlinks=False):
                    if depth + 1 < max_depth and not excluded(Path(entry.path)):
                        stack.append((entry.path, depth + 1))
                    continue
                if not entry.is_file(follow_symlinks=False):
                    continue
                size = entry.stat(follow_symlinks=False).st_size
            except OSError as exc:
                walk.unexaminable.append({"path": entry.path, "error": f"{type(exc).__name__}: {exc}"})
                continue
            walk.files_seen += 1
            if size >= PAGE_FLOOR and size % PAGE_FLOOR == 0:
                walk.sized.append(Path(entry.path))
            else:
                walk.size_filtered += 1


def sniff(path: Path) -> tuple[Path, str | None]:
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
        return path, f"{type(exc).__name__}: {exc}"
    return path, ("sqlite" if head == SQLITE_MAGIC else None)


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
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--root", action="append", type=Path, help="extra search root (repeatable)")
    ap.add_argument("--json", metavar="PATH", help="write the census as JSON")
    ap.add_argument("--depth", type=int, default=MAX_DEPTH)
    args = ap.parse_args()

    started = time.time()
    repo = Path(__file__).resolve().parent.parent
    requested, absent = default_roots()
    requested += [repo] + (args.root or [])
    # A root that does not exist used to be dropped here without a word, so a
    # mistyped `--root D:/data` produced a confident census of somewhere else.
    roots = [r for r in requested if r.exists()]
    absent += [str(r) for r in requested if not r.exists()]

    walk = Walk()
    for root in roots:
        collect(root, args.depth, walk)
    walk.sized = sorted(set(walk.sized))

    candidates: list[Path] = []
    non_sqlite = 0
    with ThreadPoolExecutor(max_workers=SNIFF_WORKERS) as pool:
        for path, verdict in pool.map(sniff, walk.sized):
            if verdict == "sqlite":
                candidates.append(path)
            elif verdict is None:
                non_sqlite += 1
            else:
                walk.unexaminable.append({"path": str(path), "error": verdict})
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

    census = Census(
        roots_searched=[str(r) for r in roots],
        roots_absent=absent,
        excluded_dir_names=sorted(EXCLUDE_DIR_NAMES),
        excluded_path_fragments=EXCLUDE_PATH_FRAGMENTS,
        max_depth=args.depth,
        files_seen=walk.files_seen,
        files_size_filtered=walk.size_filtered,
        files_sniffed=len(walk.sized),
        non_sqlite_files=non_sqlite,
        sqlite_candidates=len(candidates),
        stores=stores,
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
        filesystem_changes=changes,
        seconds=round(time.time() - started, 1),
    )

    print("roots searched:")
    for r in census.roots_searched:
        print("  " + r)
    if census.roots_absent:
        print("roots requested but absent (NOT searched):")
        for r in census.roots_absent:
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
    outside = [s for s in stores if not s.is_repo_scratch]
    scratch = [s for s in stores if s.is_repo_scratch]
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

    offenders = [s for s in outside if (s.checkpoint_rows or 0) > 0]
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
    if walk.unexaminable:
        print(f"\n!! {len(walk.unexaminable)} path(s) could not be examined at all "
              f"(also holes):")
        for u in walk.unexaminable[:20]:
            print(f"  {u['path']}: {u['error']}")
        if len(walk.unexaminable) > 20:
            print(f"  … {len(walk.unexaminable) - 20} more, in the JSON")

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
        out.write_text(json.dumps(asdict(census), indent=2), encoding="utf-8")
        print(f"wrote {args.json}")

    # Non-zero when a store outside this repo's test scratch holds a checkpoint:
    # that is the condition under which the v11 drop-and-recreate would destroy
    # something. Exit 0 is the only thing that clears the migration to be written.
    return 1 if offenders else 0


if __name__ == "__main__":
    sys.exit(main())
