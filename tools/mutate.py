#!/usr/bin/env python3
"""Replayable mutation testing for the Terminus release gates.

A gate that cannot fail is not a gate. This runs the gates against
deliberately broken copies of the source and records, per mutation, which
gate caught it — so the claim "these rules are enforced" is a command anyone
can re-run rather than a sentence in a commit message.

    python tools/mutate.py                 # run every mutation
    python tools/mutate.py --id P0-1a      # run one
    python tools/mutate.py --list          # show the manifest
    python tools/mutate.py --json out.json # machine-readable results

Each mutation names the gate it must break. A mutation that no gate catches
is reported as SURVIVED and exits non-zero: it means either the rule is not
actually enforced, or the gate that claims to prove it does not.

The manifest lives in `tools/mutations.json` next to this file. Adding a rule
to the codebase without adding a mutation here leaves that rule unproven.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import hashlib
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
MANIFEST = Path(__file__).resolve().parent / "mutations.json"


def find_zig() -> str:
    """Zig is not always on PATH on Windows; check the usual install first."""
    for candidate in (
        os.environ.get("ZIG"),
        "C:/Program Files (x86)/zig/zig.exe",
        "C:/Program Files/zig/zig.exe",
    ):
        if candidate and Path(candidate).exists():
            return candidate
    found = shutil.which("zig")
    if found:
        return found
    sys.exit("zig not found: set ZIG=<path to zig.exe> or put it on PATH")


@dataclass
class Mutation:
    id: str
    rule: str
    file: str
    find: str
    replace: str
    expect_gate: str

    def path(self) -> Path:
        return REPO / self.file


@dataclass
class Result:
    id: str
    rule: str
    file: str
    expect_gate: str
    outcome: str  # KILLED | SURVIVED | WRONG_GATE | NOT_APPLIED | BUILD_ERROR
    failing_gates: list[str]
    seconds: float
    detail: str = ""
    # What the build actually said, for every outcome that is not KILLED.
    #
    # Kept because the first version of this runner reported `BUILD_ERROR` as the
    # bare sentence "the mutation does not compile" and discarded the compiler
    # output — which made a genuine compile error and a wedged build environment
    # produce byte-identical reports. A 39-entry run failed that way: one real
    # error, then every later entry `BUILD_ERROR` in 0s, and nothing on record to
    # say whether the manifest or the machine was at fault. An unexplained
    # failure is not evidence.
    build_output: str = ""


# A build that fails in under this many seconds did not compile anything. Zig
# takes tens of seconds to reach a failing test here, so a near-instant failure
# means the build never really ran — a held cache lock, a killed peer process, a
# wedged `.zig-cache`. Recorded rather than acted on: the decision to stop is
# made by re-testing the restored tree, not by a stopwatch.
INSTANT_FAILURE_SECONDS = 5.0


def load(ids: list[str] | None) -> list[Mutation]:
    raw = json.loads(MANIFEST.read_text(encoding="utf-8"))
    muts = [Mutation(**m) for m in raw["mutations"]]
    if ids:
        wanted = set(ids)
        muts = [m for m in muts if m.id in wanted]
        missing = wanted - {m.id for m in muts}
        if missing:
            sys.exit("no such mutation(s): %s" % ", ".join(sorted(missing)))
    return muts


def run_gates(zig: str) -> tuple[int, str]:
    # UTF-8 explicitly: gate names carry non-ASCII (`gate: every kind × terminal
    # cell ...`), and decoding zig's output with the console codepage — cp936 on
    # the machine this was written on — turns `×` into mojibake, so the entry
    # naming that gate can never match and reports WRONG_GATE against the gate
    # that did in fact catch it.
    proc = subprocess.run(
        [zig, "build", "test", "--summary", "all"],
        cwd=REPO,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return proc.returncode, proc.stdout + proc.stderr


# `error: 'cli.cmd_job.test.gate: SKILL.md's --json key sets ...' failed:`
#
# The closing quote is found by the ` failed` / ` exited with code` that follows
# it, not by being the next apostrophe: test names contain apostrophes, and
# stopping at the first one truncated `gate: SKILL.md's --json key sets are the
# ones these structs emit` to `gate: SKILL.md` — which is also a prefix of
# `gate: SKILL.md's resultRecord codes ...`, so the two gates became
# indistinguishable and either could satisfy an entry naming the other.
GATE_FAILURE = re.compile(r"error: '(.+?)' (?:failed|exited with code)")


def failing_gate_names(output: str) -> list[str]:
    """Zig prints `error: 'module.test.NAME' failed:` for each failing test."""
    names = []
    for line in output.splitlines():
        m = GATE_FAILURE.search(line)
        if m and m.group(1) not in names:
            names.append(m.group(1))
    return names


def apply(mut: Mutation) -> bytes | None:
    """Rewrites the file in place; returns the original bytes, or None if the
    pattern was not found exactly once (a drifted manifest, not a passing
    mutation — those are different outcomes and must not be conflated).

    Bytes, not `Path.read_text`/`write_text`: those translate newlines on
    Windows, so an LF repo came back CRLF after every mutation. `.gitattributes`
    says `*.zig text eol=lf`, which means `git diff` normalises the damage away
    and shows nothing — while `cmd_job.zig`'s adjacency gate, which reads its
    own source and ends a function body at "\\n}\\n", fails outright on CRLF
    text with no mutation applied at all. The result was not a silent runner but
    a lying one: real gate failures attributed to whichever mutation happened to
    run next.
    """
    raw = mut.path().read_bytes()
    text = raw.decode("utf-8")
    if text.count(mut.find) != 1:
        return None
    mut.path().write_bytes(text.replace(mut.find, mut.replace, 1).encode("utf-8"))
    return raw


def restore(mut: Mutation, original: bytes) -> None:
    """Puts the file back and proves it went back, byte for byte.

    A restore that does not restore poisons every result after it, and the one
    this runner shipped was invisible to `git diff`. So the write is checked
    rather than trusted, and a mismatch stops the run: continuing would produce
    outcomes that look like findings and are not. It is deliberately not a
    repair — a runner that quietly fixes its own corruption is how the first one
    went unnoticed.
    """
    path = mut.path()
    path.write_bytes(original)
    after = path.read_bytes()
    if after == original:
        return
    sys.exit(
        f"\nrestore of {mut.file} did not reproduce the file it started from "
        f"({len(original)} bytes before, {len(after)} after).\n"
        f"The working tree is now modified and every result past this point "
        f"would be measuring the runner, not the gates.\n"
        f"Recover with: git checkout -- {mut.file}"
    )


def git_out(*args: str) -> str:
    """A read-only git query, stripped. Never a write: this tool must not touch
    history."""
    proc = subprocess.run(
        ["git", *args], cwd=REPO, capture_output=True, text=True,
        encoding="utf-8", errors="replace",
    )
    return proc.stdout.strip() if proc.returncode == 0 else f"<git {args[0]} failed>"


def git_status_lines() -> list[str]:
    """`git status --porcelain`, with leading whitespace intact.

    Deliberately not `git_out`: that strips the whole output, which eats the
    leading space of the *first* porcelain line only. Porcelain v1 is two status
    characters then a space, so `line[3:]` is the path — and a shifted first line
    silently reported `ools/mutate.py`. One wrong character in a path is exactly
    the kind of detail that makes a reader distrust the rest of the artifact.
    """
    proc = subprocess.run(
        ["git", "status", "--porcelain"], cwd=REPO, capture_output=True, text=True,
        encoding="utf-8", errors="replace",
    )
    if proc.returncode != 0:
        sys.exit("git status failed; refusing to report provenance we cannot read")
    return [ln for ln in proc.stdout.split("\n") if ln.strip()]


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def provenance() -> dict:
    """What the run was measured against.

    A bare list of outcomes cannot be re-checked: it does not say which commit it
    describes, whether the tree was clean, or which manifest produced it. Without
    those, "39/39 killed" is a number someone has to be taken at their word for.

    Tracked modifications and untracked files are reported separately, and only
    the first is a problem. A mutation edits a file that is already tracked, so a
    mutation that failed to revert can only ever show up as a tracked change —
    while an untracked file is this run's own `--json` artifact, or unrelated
    scratch. Conflating the two made a clean 39/39 run end on "every mutation is
    supposed to be reverted; this means one was not", pointing at the artifact it
    had just written.
    """
    lines = git_status_lines()
    untracked = [ln[3:] for ln in lines if ln.startswith("??")]
    tracked = [ln[3:] for ln in lines if not ln.startswith("??")]
    return {
        "head": git_out("rev-parse", "HEAD"),
        "head_subject": git_out("log", "-1", "--format=%s"),
        "tracked_clean": tracked == [],
        "tracked_dirty_paths": tracked,
        "untracked_paths": untracked,
        "manifest_sha256": sha256_of(MANIFEST),
        "manifest_entries": len(json.loads(MANIFEST.read_text(encoding="utf-8"))["mutations"]),
    }


ARTIFACT_ALLOWLIST = ("docs/evidence/mutation-run.json",)


def is_tracked(rel: str) -> bool:
    """Whether git has this path in the index. A read; never a write."""
    proc = subprocess.run(
        ["git", "ls-files", "--error-unmatch", "--", rel],
        cwd=REPO, capture_output=True, text=True,
    )
    return proc.returncode == 0


class JsonTarget:
    """Where the artifact goes, resolved once and used everywhere after.

    Two defects made the first version of this guard partly theatre, and both are
    the same mistake: validating one thing and acting on another.

    It resolved a relative path against REPO but the writes used the raw string,
    which Python resolves against the *current working directory*. Run from
    outside the repository, the check inspected one file and the write landed on a
    different one.

    And "it already parses as JSON" was the wrong test for "this is a previous
    artifact". `docs/evidence/store-census.json` and
    `v11-recut-corroboration.json` are tracked, parseable, and outside the guarded
    directories, so both census evidence artifacts could be overwritten and then
    excluded from the residue check that exists to notice exactly that.

    So: the path is canonicalised once, `absolute` is what every write uses, and
    the rule is now trackedness rather than parseability — no tracked file may be
    overwritten at all, with one allowlisted exception for the artifact this tool
    is for.
    """

    def __init__(self, absolute, rel):
        self.absolute = absolute
        self.rel = rel

    def as_posix(self):
        return self.rel


def vet_json_target(raw: str) -> JsonTarget:
    path = Path(raw)
    if path.suffix != ".json":
        sys.exit(f"--json must name a .json file; got {raw}")
    resolved = (path if path.is_absolute() else (REPO / path)).resolve()
    try:
        rel = resolved.relative_to(REPO.resolve()).as_posix()
    except ValueError:
        sys.exit(f"--json must stay inside the repository; got {raw}")
    for guarded in ("src/", "test/", "tools/", "vendor/", "skill/", "npm/"):
        if rel.startswith(guarded):
            sys.exit(
                f"--json would write into {guarded} — refusing. "
                f"That directory holds source, not evidence, and this tool "
                f"overwrites its target without asking."
            )
    if rel not in ARTIFACT_ALLOWLIST and is_tracked(rel):
        sys.exit(
            f"--json target {rel} is tracked by git — refusing to overwrite it. "
            f"Only these artifacts may be replaced: "
            f"{', '.join(ARTIFACT_ALLOWLIST)}. "
            f"Parseable-as-JSON is not the same as 'a previous artifact of this "
            f"tool': the census evidence files are both."
        )
    return JsonTarget(resolved, rel)


def write_json(path: str, payload) -> None:
    """Writes the artifact with LF endings, byte-exactly.

    `Path.write_text` translates newlines on Windows, so the first artifact this
    tool produced landed CRLF while its committed blob is LF under
    `*.json text eol=lf` — the file on disk therefore disagreed with the file in
    the repository, which is the exact drift this repo spent several commits
    eliminating. A run that reports on line-ending discipline must not violate it.
    """
    text = json.dumps(payload, indent=2, ensure_ascii=False) + chr(10)
    Path(path).write_bytes(text.encode("utf-8"))


def tail_of(output: str, limit: int = 4000) -> str:
    """The end of the build output, which is where zig puts the reason."""
    out = output.strip()
    if len(out) <= limit:
        return out
    return "...(truncated)...\n" + out[-limit:]


def evaluate(mut: Mutation, zig: str) -> Result:
    started = time.time()
    original = apply(mut)
    if original is None:
        return Result(
            mut.id, mut.rule, mut.file, mut.expect_gate, "NOT_APPLIED", [],
            time.time() - started,
            "the manifest's `find` text does not appear exactly once in the file; "
            "the code moved and this mutation no longer tests what it claims to",
        )
    try:
        code, output = run_gates(zig)
        gates = failing_gate_names(output)
        elapsed = time.time() - started
        if code == 0:
            return Result(mut.id, mut.rule, mut.file, mut.expect_gate, "SURVIVED", [], elapsed,
                          "every gate passed with the rule removed", tail_of(output))
        if not gates:
            return Result(mut.id, mut.rule, mut.file, mut.expect_gate, "BUILD_ERROR", [], elapsed,
                          "the build failed without a failing test: the mutation does not compile, "
                          "so it proves nothing about the gates", tail_of(output))
        if any(mut.expect_gate in g for g in gates):
            return Result(mut.id, mut.rule, mut.file, mut.expect_gate, "KILLED", gates, elapsed)
        return Result(mut.id, mut.rule, mut.file, mut.expect_gate, "WRONG_GATE", gates, elapsed,
                      "caught, but not by the gate that claims to prove this rule", tail_of(output))
    finally:
        restore(mut, original)


def main() -> int:
    # Gate names reach stdout verbatim, `×` included; a gbk console would raise
    # on the way out and lose the report that was already paid for.
    sys.stdout.reconfigure(encoding="utf-8")

    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])

    ap.add_argument("--id", action="append", help="run only this mutation (repeatable)")
    ap.add_argument("--list", action="store_true", help="print the manifest and exit")
    ap.add_argument("--json", metavar="PATH", help="write results as JSON")
    ap.add_argument(
        "--check-anchors", action="store_true",
        help="verify every `find` still occurs exactly once, and exit; no builds",
    )
    args = ap.parse_args()

    json_target = vet_json_target(args.json) if args.json else None

    muts = load(args.id)
    if args.list:
        for m in muts:
            print(f"{m.id:<24} {m.file}")
            print(f"{'':<24} rule:  {m.rule}")
            print(f"{'':<24} gate:  {m.expect_gate}")
        return 0

    if args.check_anchors:
        # Seconds, no builds, so there is no excuse for skipping it after a
        # commit that touched an anchored file.
        #
        # This exists because a real commit retired a rule's proof without
        # anyone noticing: `M4-lost-terminal-hoisted`'s anchor occurred once
        # before `7d2e72a` and zero times after it, and that commit was landed on
        # a fully green suite. A green suite says the gates pass. It says nothing
        # about whether the manifest still points at the code those gates guard,
        # and a mutation whose `find` matches nothing reports NOT_APPLIED — which
        # only appears if someone runs the ~30-minute full pass.
        worst = 0
        for m in muts:
            n = m.path().read_bytes().decode("utf-8").count(m.find)
            if n != 1:
                worst = 1
                print(f"DRIFTED  {m.id}")
                print(f"         {m.file}: `find` occurs {n} times, needs exactly 1")
                print(f"         rule: {m.rule}")
        if worst:
            print(
                f"\nA drifted anchor tests nothing. Re-derive it from current source, "
                f"then confirm it still goes red: python tools/mutate.py --id <id>"
            )
            return 1
        print(f"{len(muts)} anchor(s) each occur exactly once")
        return 0

    zig = find_zig()
    print(f"zig: {zig}")

    before = provenance()
    print(f"HEAD: {before['head'][:12]}  {before['head_subject']}")
    print(f"tree: {'clean' if before['tracked_clean'] else 'DIRTY -> ' + ', '.join(before['tracked_dirty_paths'])}")
    print(f"manifest: {before['manifest_entries']} entries, sha256 {before['manifest_sha256'][:12]}")
    if not before["tracked_clean"]:
        sys.exit(
            "\nthe working tree has tracked modifications, so a mutation cannot be "
            "told apart from an edit that was already there. Commit or stash first."
        )

    # Prove the tree is green before mutating it. Every outcome below is a claim
    # of the form "the suite went red *because* the rule was removed", and that
    # claim is worthless if the suite was already red — or if the build was never
    # working on this machine to begin with.
    print("baseline: building the unmutated tree ... ", end="", flush=True)
    base_started = time.time()
    base_code, base_output = run_gates(zig)
    base_seconds = time.time() - base_started
    print(f"{'green' if base_code == 0 else 'RED'} ({base_seconds:.0f}s)")
    if base_code != 0:
        sys.exit(
            "\nthe unmutated tree does not pass its own gates, so nothing below "
            "would measure a mutation.\n\n" + tail_of(base_output)
        )

    print(f"\n{len(muts)} mutation(s); each one runs the full gate suite\n")

    results: list[Result] = []
    for i, mut in enumerate(muts, 1):
        print(f"[{i}/{len(muts)}] {mut.id} ... ", end="", flush=True)
        r = evaluate(mut, zig)
        results.append(r)
        print(f"{r.outcome} ({r.seconds:.0f}s)")
        if r.outcome != "KILLED":
            print(f"      rule:   {r.rule}")
            print(f"      expect: {r.expect_gate}")
            if r.failing_gates:
                print(f"      caught by: {', '.join(r.failing_gates)}")
            if r.detail:
                print(f"      {r.detail}")
            if r.build_output:
                print("      --- what the build said ---")
                for line in r.build_output.splitlines():
                    print(f"      {line}")
                print("      ---")

        # A `BUILD_ERROR` says the mutated source did not compile. That is only
        # believable if the *restored* source still does — and when it does not,
        # every later entry inherits the breakage and reports `BUILD_ERROR` for a
        # reason that has nothing to do with its own mutation.
        #
        # That is not hypothetical. A 39-entry run produced one real failure and
        # then 34 consecutive `BUILD_ERROR`s in 0s apiece, and because the
        # compiler output was discarded there was no way to tell that only the
        # first was a finding. Re-testing the restored tree turns that silent
        # cascade into one loud stop, and costs an extra build only on the path
        # that is already in trouble.
        if r.outcome == "BUILD_ERROR":
            print("      re-testing the restored tree ... ", end="", flush=True)
            back_code, back_output = run_gates(zig)
            print("green" if back_code == 0 else "STILL RED")
            if back_code != 0:
                if args.json:
                    write_json(json_target.absolute, [asdict(x) for x in results])
                    print(f"      wrote partial results to {args.json}")
                sys.exit(
                    f"\nthe tree still fails after restoring {mut.file}, so the build "
                    f"environment is broken rather than the mutation.\n"
                    f"Stopping: every later entry would report BUILD_ERROR for a reason "
                    f"unrelated to its own mutation, which is how a whole run gets "
                    f"mistaken for 34 findings.\n"
                    f"Check for a stale `.zig-cache` lock or a killed peer build, then "
                    f"re-run.\n\n" + tail_of(back_output)
                )

    killed = [r for r in results if r.outcome == "KILLED"]
    bad = [r for r in results if r.outcome != "KILLED"]

    if args.json:
        outcomes: dict[str, int] = {}
        for r in results:
            outcomes[r.outcome] = outcomes.get(r.outcome, 0) + 1
        artifact = {
            "provenance_before": before,
            "provenance_after": provenance(),
            "zig": zig,
            "zig_version": subprocess.run(
                [zig, "version"], cwd=REPO, capture_output=True, text=True,
                encoding="utf-8", errors="replace",
            ).stdout.strip(),
            "baseline_green": True,
            "baseline_seconds": round(base_seconds, 1),
            "requested_ids": args.id,
            "totals": {
                "entries": len(results),
                "killed": len(killed),
                "not_killed": len(bad),
                "by_outcome": outcomes,
            },
            "results": [asdict(r) for r in results],
        }
        write_json(json_target.absolute, artifact)
        print(f"\nwrote {args.json}")

    print(f"\n{len(killed)}/{len(results)} killed by the gate that claims the rule")
    for r in bad:
        print(f"  {r.outcome:<12} {r.id}")
    after = provenance()
    # The `--json` artifact is this run's own output, so its being modified is
    # the tool working, not a mutation left behind. Excluded by path rather than
    # by tracked-vs-untracked: the first version of this check ignored untracked
    # files, which held only until the artifact was committed — after that,
    # rewriting it was a *tracked* modification and a clean 58/58 run again
    # accused itself of leaving a mutation applied.
    wrote = {json_target.as_posix()} if json_target else set()
    left_behind = [p for p in after["tracked_dirty_paths"] if p not in wrote]
    if left_behind:
        print("\nWARNING: tracked files are modified after the run:")
        for p in left_behind:
            print(f"  {p}")
        print("Every mutation is supposed to be reverted; this means one was not.")
        return 1
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
