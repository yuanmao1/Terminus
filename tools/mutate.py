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
                          "every gate passed with the rule removed")
        if not gates:
            return Result(mut.id, mut.rule, mut.file, mut.expect_gate, "BUILD_ERROR", [], elapsed,
                          "the build failed without a failing test: the mutation does not compile, "
                          "so it proves nothing about the gates")
        if any(mut.expect_gate in g for g in gates):
            return Result(mut.id, mut.rule, mut.file, mut.expect_gate, "KILLED", gates, elapsed)
        return Result(mut.id, mut.rule, mut.file, mut.expect_gate, "WRONG_GATE", gates, elapsed,
                      "caught, but not by the gate that claims to prove this rule")
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
    args = ap.parse_args()

    muts = load(args.id)
    if args.list:
        for m in muts:
            print(f"{m.id:<24} {m.file}")
            print(f"{'':<24} rule:  {m.rule}")
            print(f"{'':<24} gate:  {m.expect_gate}")
        return 0

    zig = find_zig()
    print(f"zig: {zig}")
    print(f"{len(muts)} mutation(s); each one runs the full gate suite\n")

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

    if args.json:
        Path(args.json).write_text(
            json.dumps([asdict(r) for r in results], indent=2), encoding="utf-8"
        )
        print(f"\nwrote {args.json}")

    killed = [r for r in results if r.outcome == "KILLED"]
    print(f"\n{len(killed)}/{len(results)} killed by the gate that claims the rule")
    bad = [r for r in results if r.outcome != "KILLED"]
    for r in bad:
        print(f"  {r.outcome:<12} {r.id}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
