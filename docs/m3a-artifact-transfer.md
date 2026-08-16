# M3a: the ArtifactTransfer contract

> Status: **decided; partially implemented.** All seven §7 questions are
> answered — §7.3, §7.4 and §7.5 by the programmer directly, the rest by the
> instruction to implement §2–§6 as written, which is written against the
> recommendation in each. The answers are recorded in §7.0; the option text
> is kept below unchanged, because what was weighed is part of the record.
>
> Synthesised from three competing designs and nine independent judgements.
> Every fatal flaw those judgements found is closed here, in §2, by name; the
> ones that could only be closed by touching a B-class surface are closed in
> §2 *and* surfaced as a decision in §7 so the shape of the fix is yours.

---

## 7.0 What was decided, and what has landed

| § | Question | Answer | State |
|---|---|---|---|
| 7.1 | closing the `filesystem_effect` laundering hole | **A**, tightened further | **implemented** (`212289e`) |
| 7.2 | a terminal for a locally-published artifact | **A** — new `Terminal.local_effect` | not started |
| 7.3 | HTTP fetch in M3a or M3b | **defer to M3b** | not started |
| 7.4 | reshaping `transfer_checkpoints` | **A** — new migration, drop and recreate | **implemented** (`14c8a2d`, amended by `2b670a9`) |
| 7.5 | what happens to `terminus sync` | **port onto the artifact primitive** | not started |
| 7.6 | the `history` table's last two writers | **B**, scheduled for **M4**, not M3 | not started |
| 7.7 | where the streaming seam lives | **A** — on `Executor`, `daemon` refuses loudly | not started |

**§7.1 as built differs from option A in three ways, all narrowing.** The
comparison is not digest-only: evidence carries a `side` (`local`/`remote`)
alongside the path and digest, and all three must equal what the transfer
declared — a push that also wrote the same bytes to a scratch path, or a
reading taken on the wrong machine, no longer settles it. The declaration is
write-once and only legal while the operation is in `created`/`connecting`
(`error.ExpectedHashLocked`), so "declared in advance" is enforced rather than
commented. And a request carrying two declared digests is
`error.AmbiguousCheckpoint` rather than the newest one by `ORDER BY id DESC` —
picking between them would turn insertion order into a scope-releasing
decision. §7.4's `UNIQUE(request_id)` is what makes that case unreachable
rather than merely refused.

**Settled, and the residual risk moved into the code.** The audit that
preceded the drop-and-recreate DDL was an ad-hoc command, not the census in
§7.0.1: it ran on 2026-08-14 and found no checkpoint row in any store outside
this repo's test scratch, and the v11 migration records that in its own
comment (`src/core/store/migrate.zig:413-418`). The census below was written
afterwards to make that claim re-runnable, and it has never returned a status
that would authorise the recut — see §7.0.1. What the census covers is now a
definition it carries rather than a description of what its walker happened to
do, so "no such row under these roots" can be checked against the definition
instead of against the code — and as of 2026-08-16 the walk delivers that
definition inside this repository too, where it previously covered three of the
six levels it claimed. A database no census reached is
therefore covered not by an audit but by a refusal:
`checkBeforeApply` returns `error.CheckpointsWouldBeDropped` for any store
below v11 that still holds checkpoint rows, and runs before `apply` rather
than after it, so such a store is refused rather than silently emptied
(`migrate.zig:759`, refusal at `:790-799`).

### 7.0.1 The store census (read-only, 2026-08-14; re-run 2026-08-16)

Reproduce with exactly this:

```
python tools/enumerate_stores.py --json docs/evidence/store-census.json \
                                 --corroboration
```

That command exits **2** on this machine, not 0. The exit status carries two
verdicts and this run fails the second one; both are set out below. The
corroboration artifact is written regardless, for the reason given there.

It writes two artifacts: `docs/evidence/store-census.json` and
`docs/evidence/v11-recut-corroboration.json`. Both, and
`tools/enumerate_stores.py`, are in the repository, so this
section's evidence is reproducible from it rather than from one
machine's shell history. Every number this section states about **this run** is
in one of the two — the counts and the failure matrix in the census,
`could_not_see` in the corroboration — and where a number comes from somewhere
else it is labelled: a count from an earlier artifact, a reading from the
git-ignored `--raw` census, or a measurement taken during the migration
rehearsal. That distinction used to be a flat promise that every number was in
the two artifacts, which was never true of the rehearsal's table counts or of
any of the before/after comparisons. Add `--raw` to the command above to get
the third file; it is git-ignored, it is the only place the un-coarsened paths
exist, and it is what a reader needs to turn an opaque segment id back into a
directory. The script states
its own scope, which is the point: the first version of this audit was an
ad-hoc command whose answer — "there is no non-test row anywhere" — was
unfalsifiable, and wrong in two places besides.

**The committed artifact is deliberately not the whole census.** `--json`
writes only what the claims here rest on: the two verdicts below, the scope
definition, the failure matrix, the coverage
numbers, the filesystem effect, and per store its `user_version`, whether it
has a `transfer_checkpoints` table, and whether that table holds any row
(`tools/enumerate_stores.py:1108-1201`). It carries no file sizes, no counts of
anybody's servers, keys, memories or facts, and no checkpoint request ids. A
public repository is the wrong place for a description of the author's
machine, and the request-id field is the sharper edge: today every row it
would name is a gate fixture, but the first time this census finds a real
checkpoint it would commit real request ids to a public repository as a side
effect of running the audit. `--raw` writes everything the census saw,
untokenised and including those ids, and defaults to
`docs/evidence/raw/store-census.raw.json` (`tools/enumerate_stores.py:320`).
That file is not fit to commit — it names absolute paths on whichever machine
ran it — so `docs/evidence/raw/` is ignored wholesale in `.gitignore:10`.

**Below the tokenised prefix, every path segment is now an opaque id, because
tokenisation structurally could not redact them.** `tokenise` rewrites root
prefixes and emits everything under them as it found it, so the artifacts
committed at `ad20c26` and after published third-party directory names that no
environment variable names and no token list can reach: a private GitHub org, a
private repository name and a PR number, in the `path` of four `unreadable`
entries and again inside the `OSError` repr embedded in the same entries'
`error` string. The second copy is the one that makes this structural rather
than careless — the leak arrived through a field whose subject is an error
message, and no list of "path fields" would have caught it.

So `coarsen` (`tools/enumerate_stores.py:1002-1053`) runs over the finished
document, anchored on the tokens rather than on a list of fields, and replaces
each segment below the prefix with `<seg:` plus the first eight hex digits of
the SHA-256 of the tokenised path prefix ending at that segment. The recipe is
published in the artifact as `path_coarsening`
(`tools/enumerate_stores.py:1066-1105`), so a coarsened entry is checkable
rather than taken on trust. Four properties are the reason for that shape: the
same input path yields the same id on every run, so two runs are diffable; the
id is a digest of the whole prefix rather than of the segment, so a dictionary
of likely directory names does not invert it; there is one id per level, so the
depth of a coarsened path is still countable against the depth fields beside
it; and `<` and `>` are illegal in a Windows path component, so an id can never
be misread as a directory that exists. Two things stay in plaintext and the
artifact names both: everything below `<repo>`, which is this repository and is
already public, and an allow-list of two anchored patterns — `hsperfdata_` and
`_bazel_` — whose segments are themselves the evidence for what the entry is.
The declared roots keep every component, or `roots_searched` would be
unreadable and the scope claim with it. This run's census names **116** distinct
token-prefixed path strings and **155** distinct segment ids; the plaintext
behind them is in the `--raw` census and nowhere else. What this costs is real
and is not hidden: the remedy on an out-of-scope link used to be literally
actionable from the committed file and now is not, an operator has to read the
path out of `--raw`, and the store table below can no longer name a store by
its filename.

**The scope is now a definition the artifact carries, not a description of
what the walker did.** `effective_scope` states the claim in one sentence —
every regular file enumerated by a *successful* directory listing at or below
`depth_max` levels beneath the nearest searched root containing it, minus the
declared exclusions, never following a reparse point, with content read only
from files that pass `content_read_rule` — and every term in that sentence is a
field beside it (`tools/enumerate_stores.py:2435-2545`). A reader checks the
claim against the definition instead of against the code. That matters because
the previous version of this section stated the scope in prose while the walker
did something else, and nothing in the artifact could have revealed the
difference.

Ten roots were searched — `%APPDATA%/terminus`, `%TEMP%`, `~/.terminus`,
`~/Desktop`, `~/Downloads`, `~/Documents`, `~/Videos`, `~/Pictures`,
`~/Music`, and this repo — to a depth of six
directories below each, skipping `node_modules`, `.git`, `.venv`, `venv`,
`__pycache__` and `.codegraph` by directory name and `AppData/Local/Google`,
`AppData/Local/Microsoft`, `AppData/Local/Mozilla`, `playwright_chromium`,
`pw-apply-profile`, `codex-apply-extension` by path fragment. Both exclusion
kinds are matched against the whole absolute path, so any ancestor triggers
them, which is broader than "the directory is named that" and
`effective_scope.excluded_dir_names_note` says so. A declared search root is
tested by the same rule and is no longer exempt from it: `collect` used to push
the root straight onto the stack and apply `exclusion_rule` only to child
directories, so `--root C:/proj/node_modules` was listed in full while the note
told the reader that any ancestor triggers the rule — one path in the whole
census outside the rule the artifact publishes as universal
(`tools/enumerate_stores.py:1441-1448`). No root on this machine matches an
exclusion, so no count moved.

The fragments carry a per-fragment hit count, and three of the six —
`AppData/Local/{Google,Microsoft,Mozilla}` — score **0**. The reason given here
used to be "no searched root can reach `AppData/Local` at all", and that is
false: `%TEMP%` **is** `AppData\Local\Temp`, a searched root inside
`AppData\Local`. What is true is narrower. A fragment matches anywhere in an
absolute path, so one of those three fires only if some path under a searched
root spells `AppData/Local/Google` — and the only searched root inside
`AppData\Local` is `%TEMP%`, which is a *sibling* of those three directories,
not an ancestor of them. Nothing under it repeats the fragment. The three would
also have scored 0 had they still been in the directory-name set, where a
multi-component string can never equal a single path component; that is the bug
they were moved out of. A list of exclusions published without hit counts
overstates what the census excludes; on this machine half of it excludes
nothing.

An eleventh root,
`%LOCALAPPDATA%/terminus`, does not exist on this machine and was therefore
**not** searched; the script reports absent roots rather than dropping them, so
a mistyped `--root` can no longer yield a confident census of somewhere else.
It does **not** count as a hole. A directory that does not exist contains no
databases, so that is an empty set the census verified rather than a place it
failed to look; what does count is an environment variable that was unset,
because then no path could be formed and nothing is known about where that
root would have been (`tools/enumerate_stores.py:240-284`). The test that
separates the two is now a raw `os.stat` in a `try`
(`tools/enumerate_stores.py:2632-2642`) and not `Path.exists()`, which
swallows `OSError` and would have filed a root that exists and denies access
as verified-empty. Anything but ENOENT from that stat is `unreadable`, and
`unreadable` withholds.

**`depth_max` is six levels, and every root now counts them from itself.** The
walk still visits each directory once, but the roots are walked longest-prefix
first, so the visit that lands on a directory is the one from the nearest
containing root — the one with the largest remaining budget — and no later walk
could improve on it (`tools/enumerate_stores.py:2645-2661`). Before this,
`<repo>` sat at `~/Desktop/drafts/zig/Terminus`, was first reached on
`~/Desktop`'s walk at depth **3**, and got an effective depth budget of **3**,
not 6, while `effective_scope.statement` asserted coverage of six levels beneath
a searched root. A store at `<repo>/a/b/c/d/store.db` was never enumerated and
the artifact said it was in scope. The previous version of this section recorded
that as `root_shadowing` and declined to fix it, on the grounds that fixing it
would change `files_seen`, the store list and possibly the verdicts. It has now
been fixed, and it changed all three. Measured across the fix — the run before
it, and the run immediately after — `files_seen` went **98,394 → 110,564**,
`directories_listed` **14,036 → 20,549**, files sniffed **1,774 → 7,615**,
SQLite candidates **443 → 453**, Terminus stores **139 → 149**. The artifact
committed here is a third run, later again: **114,008**, **22,395**, **7,837**,
**454** and **150**. Nothing about the walk changed between the second and the
third — the machine did, and every number below is labelled with which of the
two it comes from.
`root_shadowing` survives as the check rather than the confession: it still
lists which roots are nested, and it now reports `<repo>` first reached at depth
**0** with an effective budget of **6** of its 6 declared levels, so a
regression in the walk order shows up there as a number rather than as a
quietly smaller file count.

Two of those movements need a word, because neither is what it looks like.
`depth_limited` **fell**, 13,216 → 9,516 across the fix (**9,913** in the
committed run), and a falling count in a bound
category is worth explaining rather than pocketing: the frontier moved down
into the repository, and the directories that now sit on it hold fewer
subdirectories than the ones that used to. It is not a gap-driving category
either way. And the store count is the one number here that this section
should not attribute to the fix. All ten of the extra stores are repo test
scratch, the five scratch stores the artifact lists individually sit at depth
**3** below `<repo>` — reachable under the old budget as well as the new one —
and the paths of the 141 summarised ones are deliberately not published, so
nothing in either artifact separates "found by the deeper walk" from "created
by a test run between the two censuses". The test suite creates and deletes
scratch databases constantly, which is the more likely reading, and the third
run — one more store again, on an unchanged walk — is that reading happening
in front of the reader.

What the deeper walk does establish is this: **the offender test ran over the
whole of the declared scope for the first time, and still found nothing.**
`offender_found` is false, `stores_outside_repo_scratch` is 4 and
`checkpoint_rows_outside_repo_scratch` is 0, over a walk that covers three more
levels of the root most likely to contain a store somebody made and least
likely to be reached — the repository itself, which was also the one root the
walk could not reach the bottom of. Had a row turned up down there,
`offender_found` would have become true and the exit 3.

**A link is never followed, and being inside a root is not the same fact as
having been read.** A reparse point is recorded, resolved, and stepped over
(`tools/enumerate_stores.py:668-671, 1538-1772`). Detection uses Win32's own
`IsReparseTagNameSurrogate` bit rather than the reparse attribute alone,
because OneDrive placeholders, AppExecLink stubs and deduplicated files all
carry that attribute and are ordinary readable files; treating those as links
would drop real candidates out of the census, which is the same mistake as
walking into a junction, pointed the other way. Links are stepped over rather
than followed, so a junction pointing at its own ancestor cannot loop, and
directories are visited once however many names reach them.

What has changed is what resolving a link is taken to prove. Every link record
now carries `within_declared_root` — is the target inside the territory the
census declared? — and `actually_visited` — did a walk read that content, at
that path or any other? — as two separate recorded fields. They used to be one
field. `covered_by != null` was published as though it meant the bytes had
been read, and it does not: it means the census *promised* to read them.
`actually_visited` is answered only from the walk's own record, the set of
directories whose `os.scandir` returned without raising
(`tools/enumerate_stores.py:1466`), never from a prefix test, a depth
calculation or an exclusion test. A file target additionally carries
`content_read`, because a file that was enumerated is not a file that was
opened. All twenty keys are present on all 53 link records with explicit
nulls, so a consumer can tell "not applicable" from "not asked"; before this
there were three different shapes on disk and no way to tell them apart.

Root attribution is longest-prefix rather than first-match
(`tools/enumerate_stores.py:758-768`). First-match named `~/Desktop` as the
covering root of a target inside this repository, which is true and useless:
every depth number derived from it was then measured from the wrong place.
Since per-root depth, the root that reaches a target *first* is the
longest-prefix root, so `covering_root` and `first_reaching_root` agree on
every record. Both are still published, because their agreeing is the evidence
that no root is being walked on another root's leftovers, and a regression in
the walk order would make them disagree in the artifact rather than silently in
the code (`tools/enumerate_stores.py:770-783`).

**Both facts are now decided about the path the link actually points at, and
two bugs in that arithmetic are fixed.** Neither changed a number on this
machine, and both would have, silently, on a machine one link different.

*A relative target used to be resolved against the wrong directory.*
`os.readlink` returns the target as stored, and a symlink created with
`SYMLINK_FLAG_RELATIVE` — `mklink /D link ..\t`, git with `core.symlinks=true`,
npm, pnpm — stores a relative string. That string resolves against the
directory holding the link and against nothing else; it was being handed
straight to `key`, whose `os.path.abspath` resolves it against the *census
process's* working directory. So `within_declared_root`, `covering_root`, both
depths, `actually_visited` and `reason` were all decided about a path that does
not exist, and the category could change by running the tool from a different
directory. Worse in one specific way: a fabricated target that landed on a
directory the walk happened to have listed came out `covered_and_visited`,
which has no `failure_matrix` record at all, so the unread bytes left the
artifact entirely while the link record asserted they had been read — the
`covered_by != null` defect re-entering through a different door.
`resolve_target` (`tools/enumerate_stores.py:685-709`) joins the target to the
link's own directory and normalises the result, and every link record now
carries `target` (what the link stores) and `target_resolved` (where that
points from there) as separate fields. Every link on this machine that yields a
target string at all — 49 of the 53; the other four are the WinError 1920 ones
whose `readlink` raises — stores an absolute `\\?\` path, so `target_resolved`
equals the stripped `target` in all 49 cases and no published number moves.

*A drive-letter root matched nothing.* Membership was `t.startswith(key(root) +
os.sep)`, and `key(Path("D:/"))` is `d:\`, which already ends in a separator —
so the test spelled `d:\\` and no path on that drive satisfied it. `--root D:/`
is the invocation printed in the tool's own docstring, and under it every link
target on that drive was published as `out_of_declared_scope` — declined by
policy, not a gap — when it was inside the declared scope and unvisited, which
is a gap. That is the gap-*removing* direction, in the one category the matrix
exists to protect, and the same arithmetic made `depth_below` one short. Both
now go through `key_prefix` (`tools/enumerate_stores.py:725-737`), which
normalises the trailing separator. Verified directly: `containing_roots(r"D:\proj\archive",
[Path("D:/")])` returns the root instead of `[]`, `depth_below(Path("D:/"),
r"D:\a\b")` returns 2 instead of 1, and a sibling root — `~/Desktop2` against
`~/Desktop` — still correctly returns `[]`.

**`~/Videos`, `~/Pictures` and `~/Music` are declared roots because of that
rule.** `~/Documents` contains Windows' legacy compatibility junctions
`My Videos`, `My Pictures` and `My Music`, which point at those three
directories and carry a deny-everyone ACL. The census cannot read the
junctions, so under the link rule they were three gaps whose remedy their own
records named. Declaring the targets searches strictly more rather than
excusing anything, and the three closed. The published scope grew by three
directories, which is why it is written down here.

**The link rule shrank the file counts, and what it exposed is a fact about
the instrument.** `files_seen` fell from 107,567 to 94,189 and files
sniffed from 6,919 to 1,753 between the artifact before the link rule and the
one after it. (Today's run sees **114,008** and sniffs **7,837**. Those are
above both earlier numbers, and the reason is per-root depth rather than the
link rule: the repo now gets its own six levels instead of `~/Desktop`'s
leftover three. The counts also move run to run because `%TEMP%` and the repo's
test scratch churn.)
Nothing that was ever declared stopped being searched. Those ~13,000 files were
reached *through* links, into a JDK under `%PROGRAMFILES%`, a bazel output
cache and a Codex runtime's `node_modules`. The old walk followed junctions
silently, because `is_dir(follow_symlinks=False)` reports a junction as a
directory and `scandir` on a junction opens its target — so every previous run
of this census, and every file count this section has ever quoted, was reading
outside the roots it declared. The scope claim was false, and it was false in
the direction that is hardest to notice: the census was over-reaching, not
under-reaching, so nothing was missing from the output to give it away. Nobody
could have caught it from the artifact, because the artifact reported the
roots it intended to search and the counts it got by searching more than that.
The twenty records that appeared then are not territory lost. They are the
places the census had been entering undeclared, now declined and named — and
as of this run they are named `out_of_declared_scope` and no longer withhold,
for the reason given below. An audit tool whose own
scope claim was wrong, and whose output could not reveal it, is exactly the
kind of thing this document exists to record.

**Every path the walk declined or failed to read now lands in exactly one
named category.** `failure_matrix` has fourteen of them, each carrying its own
definition, its own count, a `drives_coverage_incomplete` flag, and its
entries wherever the entries are themselves evidence; `coverage_incomplete` is `any(count > 0)` over exactly the flagged ones
(`tools/enumerate_stores.py:2086-2433`, wired at `:2725-2740`). Disjointness is
by construction rather than by adjudication: every record is produced at one
decision site and carries that site's `origin`, so `depth_limited` and
`excluded` hold only walk-frontier records, `inside_but_not_visited`,
`depth_shadowed_target`, `exclusion_shadowed_target` and
`out_of_declared_scope` hold only link records, and
`root_unresolvable` and `root_absent` hold only root records.

A *path* may still be named by two records of *different* origin — the four
`depth_shadowed_target` targets are also, separately, frontier directories
their parent declined on depth — and the link record says so in
`also_counted_in`. The matrix used to open by claiming that every path lands in
exactly one category, which is false for precisely the records that produce
exit 2, and `also_counted_in` was published on all 53 link records without being
defined anywhere in either artifact. Both are fixed in the artifact rather than
here: `what_this_is` now says the rule is about records and that the category
counts therefore do not sum to a count of distinct paths, and `also_counted_in`
carries its own definition beside it.

| Category | This run | Withholds | What it is |
|---|---|---|---|
| `inside_but_not_visited` | **0** | **yes** | link target inside a searched root that no walk read, and no declared bound explains |
| `depth_shadowed_target` | **4** | **yes** | the same, except this census's own `depth_max` is what stopped it |
| `exclusion_shadowed_target` | **0** | **yes** | the same, except one of this census's own exclusion rules is what stopped it |
| `unreadable` | **4** | **yes** | an OS error stopped the census learning what a path is, where it points or what it holds |
| `vanished` | 0 | **yes** | listed, then genuinely gone before it was opened |
| `path_too_long` | 0 | **yes** | WinError 206 / ENAMETOOLONG; permanent |
| `not_a_regular_file` | 0 | **yes** | stat succeeded and it is neither link, directory nor regular file |
| `root_unresolvable` | 0 | **yes** | the variable naming a root was unset; no path could be formed |
| `out_of_declared_scope` | 20 | no | link target outside every searched root |
| `depth_limited` | 9,913 | no | a directory below `depth_max` |
| `excluded` | 268 | no | a directory matching a published exclusion |
| `dangling` | 19 | no | reparse point whose target does not exist |
| `not_content_read` | 106,171 | no | enumerated, and failed `content_read_rule` |
| `root_absent` | 1 | no | declared root whose raw stat said ENOENT |

**`depth_shadowed_target` and `exclusion_shadowed_target` are new, and they are
a split rather than a
reclassification.** All four `depth_shadowed_target` records were
`inside_but_not_visited` before, they
still withhold, and the verdict does not move. What the split ends is a
conflation: `inside_but_not_visited` was carrying three different failures under
one name. In the first, the census's own `depth_max` — published in
`effective_scope`
before the walk starts — is what stopped it, and raising `--depth` past the
target's depth or declaring the target a root closes it, both of which change
the declared scope. In the second, one of the census's own exclusion rules is
what stopped it, and neither raising `--depth` nor declaring the target a root
closes that one, because a declared root is tested by the same rule; only
removing the rule will. In the third, no declared bound accounts for the target
and
the walk simply never got there, which is the harder finding and the one that
says go and look. A reader has to be able to tell "my own declared bound
stopped me" from "I should have reached this and did not", and then which
bound. All three categories
withhold, because in all three the content genuinely was not read; the
precedence
that decides between them is stated in the artifact as P4, P4a, P4b and P4c
rather than left in the code.

`not_visited_reason` is what the split reads, and it was answering `"unknown"`
for cases the declared scope does account for, then printing "no declared bound
accounts for it" about them. Three cases and one bug are fixed. The ancestor
test recognised only
`reason == 'unreadable'`, so an ancestor that `vanished` or hit
`path_too_long` — both of them categories this artifact publishes — came out
unknown; each now has its own reason and its own remedy. An ancestor that is
itself a reparse point was unknown too, although `link_policy: never_followed`
is exactly the declared bound that accounts for it; that is now
`ancestor_is_a_link`. And the ancestor walk stopped at the *covering* root while
every depth beside it was measured from the *first-reaching* root, so on a
machine where those differed the ancestors between them were never examined;
it now stops at the root that owns the budget. Per-root depth makes those two
roots the same by construction, so that last one is closed twice over
(`tools/enumerate_stores.py:1615-1772`). All four `not_visited_reason` values
on this machine are `below_depth_limit`, so none of this moved a number here.

**The exclusion tension is settled, and it is settled toward the gap.** A link
target under a published exclusion used to be `inside_but_not_visited`, with a
remedy telling the operator to remove a bound the same artifact publishes as
declared scope, and the precedence list said nothing about the case at all. It
is now `exclusion_shadowed_target`, it withholds, and P4b carries the reasoning:
an exclusion bounds where the walk goes and says nothing about what is inside
the target, so the content is unread for the same kind of reason as a target
behind `depth_max` — which already withholds. Reporting one as a gap and the
other as a closed question would have been an inconsistency rather than a
distinction. The alternative was to stop treating it as a gap by symmetry with
`out_of_declared_scope`; that was rejected because it would have reopened
`depth_shadowed_target` on the same argument and taken the gap count down with
it, which is the wrong direction to move a coverage verdict. The record names
the rule that matched in `matched_exclusion`, in the same three fields the
frontier's own `excluded` records carry, so the two can be joined. Nothing on
this machine is in that state today — the category is **0** — and the ordinary
shape that produces it is a link like
`%TEMP%\proj\bin -> %TEMP%\proj\node_modules\.bin`, which is what npm and pnpm
write on Windows.

The depth test still runs before the exclusion test, so a target both bounds
hold for is `depth_shadowed_target`. That order is now P4c, and it is written
down because it decides the operator instruction and not the verdict: such a
record carries `matched_exclusion` as well, and its remedy says that raising
`--depth` alone will not close it. None of the four records on this machine
carries one.

Four of those categories are new work rather than renamed counters.
`depth_limited` and `excluded` were a bare `continue` and appeared in no
number at all (`:1473-1491`); at 9,913 declines against the 22,395
directories whose listing succeeded, close to a third of the frontier landed
there silently, and a bound nobody counts is indistinguishable from a bound
nobody applied. They are published as
a count and a total, and **no paths at all** — `entries` is empty and
`entries_truncated` says so. It was a deterministically sorted sample of 50
each, and that sample was a mistake of exactly the kind this section exists to
record: those two categories exist in the design only to be *counted*, the
counts carry the whole claim, the verdict reads no other field of them, and the
100 sampled records carried none of it — while publishing, into a public
repository, third-party directory names the tokeniser structurally could not
redact. Among them were a private GitHub org, a private repository name,
a PR number and an internal product tree. No count of the strings that sample
published is quoted here, because there is nothing to check it against: the
sample was removed before either committed artifact carried a failure matrix at
all, so it exists in no file in this repository. Coarsening would defeat that
class of leak today, and the sample is still not restored, because it never
carried any evidence to begin with. The full lists
are in the `--raw` census, uncapped, under
`frontier_depth_limited` and `frontier_excluded`; `excluded` additionally
publishes `matched_rules`, a per-rule hit count, which is evidence the sample
never was. `not_content_read` is the same
branch as `files_size_filtered` given a name (`:1517`), because after being
told the difference between "enumerated" and "read" a reader must be able to
find the number 106,171 under a name rather than derive it by subtraction; its
paths are counted and not retained. `not_a_regular_file` was a second silent
`continue` that dropped an entry before `files_seen` was incremented, so it
appeared in no counter and no list; it is 0 on this machine, which is exactly
when to name a category, before it appears and is mistaken for an arithmetic
error.

**Every per-path list in both committed files is bounded, and the bound used to
bound almost nothing.** `ERROR_SAMPLE` is 200 and it capped the failure-matrix
*view* — while the same records were republished uncapped three more times: in
the census's own top-level `unexaminable`, `sqlite_unreadable`,
`not_regular_files` and `links`, and again in the corroboration, which embeds
the whole census and re-lists the error and link records beside it in
`could_not_see`. So the cap bounded a view and not the artifact, and the
committed pair's disclosure surface was unbounded in the number of unreadable
paths on the machine — the one quantity nobody controls. Every such list now
goes through the same cap, the counts and the verdicts are still computed over
the full population, and `record_caps` names each bounded list with its total,
how many entries were kept and whether it truncated
(`tools/enumerate_stores.py:1975-2015`). Nothing truncates on this machine: the
largest list is 53 links.

**Within the error family the most specific verified cause wins, and the only
gap-removing label has the strictest test.** The order is `path_too_long`,
then `dangling`, then `vanished`, then `unreadable`
(`tools/enumerate_stores.py:471-494`), so the vaguest label cannot absorb a
case that has a name — each of the four prints a different instruction, and
"re-run when the machine is quiet" is wrong advice for a path that is too long
and will never close it. `dangling` is the one label that turns a hole into a
verified empty set, so it is assigned only when a raw `os.lstat` returns *and*
a raw `os.stat` raises ENOENT specifically. `os.path.exists` and
`os.path.lexists` are banned from the decision, here and in the root filter,
because both catch `(OSError, ValueError)` internally and return `False`.

That change moved four records, and it moved them into the red. Four bazel
convenience links under `~/Documents`, all in one directory, have a `readlink`
that raises `ValueError` and an `os.stat` that raises **WinError 1920**, "the
system cannot access the file". The census does not know whether anything is at
the other end. Under the old test `exists()` swallowed that error, returned
`False`, and all four were published as `links_dangling` under
`coverage_verified_empty` — four unknowns laundered into an answer. They are
now `unreadable` with `origin=link_target`, and they withhold. `dangling`
therefore fell 23 → **19** and `unreadable` rose 1 → 5. It stands at **4** in
the committed run, and those four links are the whole of it: the `origin=sniff`
entries earlier runs recorded were files a live process happened to be holding
at the moment the sniff reached them, and this run caught none. Tightening that
test can only ever add gaps.

Those four are also the entries that carried the leak coarsening now closes.
Their directory names spell a private GitHub org, a private repository and a PR
number, and until this run the committed artifacts published all three — once
in `path`, and once more inside the `OSError` repr in `error`. They read
`%USERPROFILE%\Documents\<seg:…>\<seg:…>\<seg:…>\<seg:…>\<seg:…>` now, in both
fields, and the full paths are in the `--raw` census.

A file counts as a Terminus store when it has the
`servers`+`keys`+`memories`+`facts` tables, and it becomes a candidate by
carrying the 16-byte SQLite header rather than by being named `*.db`. The old
name filter was a hole on its face: a copy can be called anything, and most of
the SQLite databases under these roots are named something other than `*.db` —
some of them are called `Login Data`. That breakdown is not in the artifact and
never has been: the script states it in a docstring
(`tools/enumerate_stores.py:1775-1794`) and does not compute it, so it is an
argument here rather than a number. Of **114,008** files seen, 106,171 were
rejected on size alone (a whole SQLite database is an exact number of pages, so
its size is always a non-zero multiple of 512), 7,837 were opened and sniffed —
every one of which opened, on this run — **454 carry the SQLite header**, and
**150 of those are
Terminus stores**: 9 listed one by one and 141 repo-scratch stores with no
checkpoint row, summarised. Two identities hold in the artifact and are worth
checking against it: `files_seen` equals `files_size_filtered` plus
`files_sniffed`, and `files_sniffed` equals `sqlite_candidates` plus
`non_sqlite_files` plus however many `unreadable` records carry `origin=sniff`
— 454 + 7,383 + 0 here, and the third term is the one that moves between runs.
Not one SQLite file refused to open: the 306 "unreadable"
candidates the first census reported were files that are not databases at all,
which is not evidence of anything. That distinction is kept — a database that
will not open is a hole, is counted under
`failure_matrix.categories.unreadable.by_origin` with `origin=sqlite_open` and
is printed loudly; a file that was never a database is merely counted. That
field is a `Counter` over the origins a run *observed*, so `sqlite_open` has no
key at all today rather than a key holding 0; the six legal origins — `root`,
`walk_directory`, `walk_entry`, `sniff`, `sqlite_open`, `link_target` — are
enumerated in the category's own `definition`, where a reader can find them
whether or not they fired. This section named that field
`unreadable_by_origin.sqlite_open` for several revisions, and the tool's own
docstring named it too. There has never been such a field.

| Store | `user_version` | `transfer_checkpoints` | holds a row |
|---|---|---|---|
| `%APPDATA%/terminus/<seg:…>` — the real store | **4** | absent | — |
| 2 × `%TEMP%/<seg:…>` — empty dev scratch | 11 | yes | no |
| 1 × `%TEMP%/<seg:…>` — empty dev scratch, table present at version 0 | 0 | yes | no |
| 5 × `<repo>/.zig-cache/tmp/gate_*.db` — gate scratch | 10–11 | yes | **yes** |
| 141 × `<repo>/.zig-cache/tmp/*.db` — gate scratch, summarised | — | — | no |

The `%APPDATA%` and `%TEMP%` filenames are coarsened, so the table identifies
those four by root, version and table shape, which is what the artifact
publishes and what the migration argument turns on; the names are in `--raw`.
The repo-scratch names are not coarsened, because everything below `<repo>` is
kept, and they are the evidence for the five checkpoint rows.

Four stores sit outside this repo's test scratch and not one of them holds a
checkpoint row; 146 are repo scratch and five of those do. The counts move
between runs because the test suite creates and deletes scratch databases
constantly — across runs they have spanned `user_version` 4 through 12 — and
what does not
move is which side of the scratch boundary a checkpoint row falls on. Stores
in the scratch that hold no row are summarised as a count rather than listed,
because a full test run leaves dozens and the only interesting fact about them
is which hold a row. Every path in the artifact is tokenised (`<repo>`,
`%TEMP%`, `%LOCALAPPDATA%`, `%APPDATA%`, `%USERPROFILE%`, `%PROGRAMFILES%`,
`%PROGRAMFILES(X86)%`, `%PROGRAMDATA%`, `<user>`), case-insensitively, because
a reparse point records its target in whatever case the link was created with
and a literal match would have redacted only one spelling of the same
directory. The substitution runs over the whole document rather than over a
list of known path fields (`tools/enumerate_stores.py:889-896`), so the fields
added by this change — `target_resolved` on every link record among them —
are covered without anyone having to remember them.

**That last sentence used to be the whole of the guarantee, and it is not one.**
The tokeniser is an *allow-list* of nine substitutions: a path outside all of
them is emitted verbatim, and nothing read the document back. `--root D:/data`
— the invocation printed in the tool's own docstring — put the literal string
`D:\data` into `effective_scope.roots_declared`, `roots_searched` and the
corroboration's `asserts.roots_searched`; a junction into `C:\Windows\Temp` or
a UNC share would land verbatim in a link target with no flag at all. That
this class of leak had already fired once is recorded in the code: three of the
nine tokens exist only because a link to a JDK under `%PROGRAMFILES%` was
spotted in an artifact after the fact. "Add a token once a leak is noticed" is
not a mechanism.

There is now a detector, and it is the last thing that runs before either
committed file is written (`tools/enumerate_stores.py:582-648`, enforced at
`:2548-2588`). Every string in the finished document — values and
keys, at every depth — is tested for a drive-letter path (`[A-Za-z]:[\\/]`), a
UNC host, and the account name. On a hit **nothing is written**: the file on
disk stays as the previous run left it, every offending JSON path is printed,
and the process exits **65**. It does not "fix" the string by inventing a new
token, because that would be making a failing check pass by renaming the
problem. Exit 65 is outside the two-verdict bitmask for the same reason 64 is:
a redaction failure is not a finding about this machine's stores and must never
be read as one. Verified by running the documented `--root D:/data` form: **13**
offending fields named across the two artifacts, neither file written, exit 65.
Neither committed artifact contains a drive-letter path, a UNC host or the
account name — that is still one `grep` on each file, and it is now also a
property the tool cannot violate silently.

The detector runs **twice**, before and after coarsening, and the ordering is
load-bearing rather than belt and braces. Coarsening replaces a segment with a
digest, so a segment that carried a violation comes out of it looking clean;
checking only the coarsened document would report success about a document from
which the evidence had just been removed. Checking the tokenised document first
means coarsening can never turn a failing document into a passing one.

**Two ways the redaction could still degrade quietly are closed, and one of
them by refusing to publish at all.** The `<user>` token was skipped for an
account name shorter than four characters, because substituting a two- or
three-letter name would rewrite ordinary words — and `redaction_rules` skipped
the *matching* test for the same reason, so on such a machine the name was
neither replaced nor looked for. It was published by exactly the entry this
census is required to keep producing: `%TEMP%\hsperfdata_<user>` embeds the
account name in a directory name, and that entry is one of the gaps driving the
red verdict. Neither substituting nor testing is safe at that length, so
`account_name_publishable` refuses: no committed artifact is written, the run
exits 65 like any other redaction failure, and the census verdict is still
printed, because what failed is the publishing and not the census
(`tools/enumerate_stores.py:863-886`). Verified by running with `USERNAME=zyk`
and with `USERNAME` unset: exit 65 both times, and neither destination file
created.

Separately, `build_path_tokens` skipped a token whose environment variable was
empty, silently, while `default_roots` derives the home roots from
`Path.home()`, which does not need the same variable. The two can therefore
disagree. What that does **not** do is degrade the redaction silently: run with
`USERPROFILE` unset and `HOMEDRIVE`/`HOMEPATH` set, and the home roots still
resolve, `%USERPROFILE%` is not built, the paths arrive with a drive letter and
the output check refuses the write — verified, 44 offending fields, exit 65.
What it did do was send the operator the wrong way, because the failure names
the *field* and the advice is "give the location a token in
`build_path_tokens`" when the token is already there and merely unset. Unbuilt
tokens are now listed in the run output and named again in the redaction
failure. They do not change the status by themselves: whether a missing token
mattered is decided by testing the finished document, not by guessing from the
environment, and a machine with no `ProgramFiles(x86)` and no link into one has
nothing wrong with it.

**All five checkpoint rows are gate fixtures, and all five are in this repo's
test scratch.** Their request ids are `PVSH0000000000000000000000` (three
times), `ABSENT00000000000000000000` and `PR0CPVSH000000000000000000` — what
`testId()` returns for the labels `push`, `absent` and `procpush` once it maps
`O`→`0` and `U`→`V` (`src/core/store/gates_test.zig:278`) — and no real ULID
is shaped like that. Those ids are **not** in the committed artifact: they are
in the `--raw` census, which is why that sentence is checkable by re-running
the script and not by reading the committed JSON. That is a deliberate trade.
Carrying the ids into a public artifact made this one claim self-evidencing at
the cost of committing whatever ids the census finds next time, and the ids it
finds next time are the ones that would matter.

**The one checkpoint row this audit found outside the repo's scratch is gone
with its file.** `%TEMP%/rotest.db` — a dev store at `user_version` 10 holding
a single fixture row, created and last written 2026-08-14 14:02:17, which no
test, tool or script in this repo names — was deleted between the 2026-08-14
census and its 2026-08-15 re-run, and does not appear in the regenerated
artifact. It is the reason the first run of this census reported an offender
and the reason later runs do not. What wrote it was never established, and now
cannot be.

**Two stores were missed by the first audit, not three.** `%TEMP%/v4copy.db`
(created 2026-08-13 15:32:14) and the second real store under
`%USERPROFILE%/Desktop` (created 2026-07-28
13:19:26) both existed when that audit ran and neither appears in its table.
`%TEMP%/rotest.db` was not missed, because there was nothing there to find:
Windows records its creation at 2026-08-14 14:02:17, 75 minutes after the audit
was committed (`2f86f89`, 12:47:21 +0800).

**The census returns two verdicts, and it is not green.** It used to answer
one question — is there a checkpoint row where the recut would destroy it —
and exit 0 for everything else, including for its own blind spots. It now
answers two independently, and either one withholds authorisation
(`tools/enumerate_stores.py:2725-2740`):

* `offender_found` is **false**, and this run is the first in which that claim
  is not partly unfalsifiable. No store outside the repo's `.zig-cache`
  scratch holds a checkpoint row: the four such stores are three empty
  `%TEMP%` dev scratch databases and the real store, which has no
  `transfer_checkpoints` table at all. Per-root depth put the same test over
  three more levels of this repository, the one root the walk previously could
  not reach the bottom of, and nothing turned up there. The
  claim in the corroboration artifact
  is derived from the non-scratch stores' row counts rather than written as a
  literal `0` — a number that cannot come out any other way is not evidence of
  anything (`tools/enumerate_stores.py:1270-1271`).
* `coverage_incomplete` is **true**, for **8** paths in two categories.
  **Four** are `depth_shadowed_target`: bazel install and grpc include
  junctions under `%TEMP%` whose targets sit at depth 6 below `%TEMP%`, so
  their parent listed them and nothing ever opened them. **Four** are
  `unreadable`, all of them the WinError 1920
  links described above (`origin=link_target`). Twenty out-of-scope links,
  nineteen dangling links, 9,913 depth-limited directories, 268 excluded
  directories, 106,171 files that failed the content rule and one absent root
  are reported alongside these and count for nothing. Two kinds of gap that
  earlier runs recorded are absent from this one, and both are the kind a
  quiet machine closes: files a live process was holding when the header sniff
  reached them — `origin=sniff`, `PermissionError`, errno 13, most often a
  JVM's `hsperfdata_<user>` perf-data file — and two repo scratch databases the
  test suite deleted between being listed and being opened, the only genuine
  mid-walk disappearances this census has ever recorded.

**Twenty entries left `coverage_incomplete`, and eight joined it.** That is
the whole of the movement from `ad20c26`, and it is worth stating as arithmetic
because the headline number fell from 21 to 9 and a falling gap count is
exactly the shape of a check being quietly weakened. The same 53 links are
classified before and after; not one record was dropped:

| Was, in `ad20c26` | Is now | n | Gap → gap? |
|---|---|---|---|
| `target_not_covered` | `out_of_declared_scope` | 20 | gap → **not a gap** |
| `target_covered` | `covered_and_visited` | 6 | not a gap → not a gap |
| `target_covered` | `depth_shadowed_target` | 4 | not a gap → **gap** |
| `dangling` | `unreadable_link` | 4 | not a gap → **gap** |
| `dangling` | `dangling` | 19 | not a gap → not a gap |

21 − 20 + 8 = 9, and the one path in that 9 that is not a link — a JVM's
`hsperfdata` file, held open when the sniff reached it — is the only one that
has moved since. The count has gone 9 → 10 → **8**: one more held-open file in
the run before this one, and none at all in this one. Nothing was reclassified
to produce either movement, and no category changed its flag; the difference is
which files a running process happened to be holding at the moment the walk
arrived. The eight that remain are the four in the third row and the four in
the fourth, both of them links whose classification has not changed since.
The four in the third row were `inside_but_not_visited` in the intervening
revision and are `depth_shadowed_target` now, which is a split of one gap
category into three and not a movement across the flag — they withheld before
and they withhold now.

The one authorised reclassification is `links_to_uncovered_targets`, 20 →
`out_of_declared_scope`, which no longer withholds. The grounds are narrow:
the census promised to cover the declared scope, and a name inside that scope
pointing outside it is the link policy working as declared. Not covering what
was never promised is not a failure to cover what was promised. **Nothing is
deleted.** All twenty records are still in `links`, still in the failure
matrix under their own category, and still in the corroboration artifact's
`could_not_see`, because unread is unread — dropping them would make
`does_not_assert[4]`, "that the census saw everything under those roots",
false. By root token, which is what the artifact publishes and what decides
scope, their targets are **6** under `%PROGRAMFILES%` and **14** under
`%USERPROFILE%`; read against `--raw`, the 6 are one JDK installation, 13 of
the 14 are bazel's output base — `%USERPROFILE%\_bazel_<user>`, which the
coarsening allow-list keeps legible for exactly this reason — and the
fourteenth is a Codex runtime's `node_modules` under a cache directory. This
section called all fourteen a bazel cache, which was wrong by one. All twenty
are outside every searched root, so nothing in scope leaves with them.

Against that, eight entries moved the other way. `links_target_covered`, 10,
which used to sit under `coverage_verified_empty`, splits into **6**
`covered_and_visited` — genuinely closed, the walk read those directories —
and **4** that are now gaps. Those four were the
defect: `covered_by != null` was published as though the census had walked
that content, and it had not. And the tightened `dangling` test moves **4**
more from `links_dangling` to `unreadable`, as described above. Every other
change is neutral — new non-gap categories over decisions that were previously
recorded nowhere, so nothing migrated out of a gap into them — or additive:
`path_too_long`, `not_a_regular_file`, `root_unresolvable` and the tightened
root stat can only ever produce more gaps, and all are 0 on this machine
today.

The run above therefore exits **2**, and now for two independent reasons where
before there was effectively one. The codes are a bitmask: 1 is
`offender_found`, 2 is `coverage_incomplete`, 3 is both, and 0 — the only
status that clears the recut — means "searched everything it set out to
search, and found no offender" (`tools/enumerate_stores.py:302-315, 3030-3031`). A
usage error exits 64 rather than argparse's default of 2, so a mistyped
`--root` can never be read as a finding about the filesystem
(`tools/enumerate_stores.py:358-369`); a document that fails the redaction
check exits 65, for the same reason and with the same care not to borrow 2.

**The census has never gone green, and on this machine it cannot.** That is
the result, not a failure to finish, and the argument has to account for all
eight gaps rather than the most convenient of them. None of the eight depends
on any process being alive, and all eight reproduce on every run.

The four `depth_shadowed_target` junctions are bazel workspace links under
`%TEMP%`; the same four paths appear in the artifact committed at `ad20c26`,
where they were published as `target_covered`. They sit at depth 6 below
`%TEMP%`, so closing them means either raising `--depth` past 6 or declaring
their targets roots, both of which change the declared scope — which is the
whole reason they now have a category that says so in its own definition. The
four WinError 1920 links under `~/Documents` are stale bazel convenience links
whose `os.stat` fails the same way every time; they reproduce identically, and
the only thing that would close them is somebody deleting the links or
restoring what they point at. Neither set is closed by an idle machine.

This run is the first to demonstrate that rather than argue it. The gaps that
do depend on what is running are absent from it: no file was held open when the
sniff reached it, and no scratch database vanished mid-walk. Earlier runs
recorded one or two held-open files every time, and the *identity* changed on
every run — a 786,432-byte `.tmp`, then `hsperfdata_<user>/37304`, `/38072`,
`/31172`, `/31548` — which is what a per-process lifetime looks like from
outside. A quiet machine closes that kind of gap and closed it here. The verdict
did not move, because the eight structural gaps carry exit **2** on their own,
which is exactly what the previous revision of this section claimed and could
not show.

And the twenty out-of-scope links are structural, though they are not gaps:
bringing them in means
declaring a JDK installation and a bazel cache to be places Terminus stores
live, which they are not — which is precisely why they are reported and not
counted. **A census taken on a live workstation cannot
authorise a destructive migration.** That is a more useful finding than a
green light obtained by looking away, and it is why `checkBeforeApply` is the
guard and this artifact is not.

**The bounded negative is archived anyway, at
`docs/evidence/v11-recut-corroboration.json`.** A red gate is not a reason to
discard a real finding: ten declared roots were searched and nothing outside
this repo's test scratch holds a checkpoint row. That is what this script was
built to produce — "no such row among these N databases under these roots"
rather than an unfalsifiable "anywhere" — and the green/red gate was layered
on top of it afterwards. Nor would a clean-machine run be worth more, because
it would prove the wrong machine: the one that might hold an old store is this
one. The file is named `-corroboration` and not `-clearance` deliberately, and
it carries its own guards against being misread as fields rather than as prose
kept elsewhere: `asserts` (the claim, with N, the roots, the date and now the
whole `effective_scope` object, so "under the declared roots" is a definition
in the file rather than a phrase),
`does_not_assert` (not authorisation, not "anywhere", not more than this
machine, not any moment but the one it ran in, and not that the census saw
everything), `could_not_see` (the **28** paths the census could not read plus
the links it declined on scope, each
with its reason and, for a
link, its resolved target — facts, with the judgement about whether a JDK
install or a bazel output base could hold a store left to the
reader; all 28 are links on this run, because no other path went unread, and
earlier runs put a live JVM's `hsperfdata` file in the same list;
not every one of them withholds, and which do is stated one flag per
category in `census.failure_matrix` rather than implied by being listed here;
both of its lists are bounded at `census.record_caps.cap`, which they used to
defeat by republishing the census's records uncapped),
`not_read_by_declared_rule`
(**116,371** more: 9,913 depth-limited, 268 excluded, 106,171 that failed the
content rule, 19 dangling — counted, not listed),
and `postdates_what_it_corroborates` (the DDL landed in `14c8a2d`;
the script that produced this was first committed sixteen hours later in
`0d7ff00`). Regenerate it with `--corroboration`; it is written whatever the
exit status, because a bounded negative is a finding even when the gate is
red. **`checkBeforeApply` remains the guard**, and the artifact's own
`the_guard` field says so.

**`could_not_see` used to call itself "everything the census did not read",
and it was short by 110,100.** It listed 29 entries; the same artifact's own
`coverage_verified_empty` reported 13,215 depth-limited directories, 256
excluded, 96,610 files that failed the content rule and 19 dangling links —
every one of them equally unread, and `not_content_read.why` conceding the
enumerated/read distinction in as many words. `does_not_assert[4]` then sent
the reader to `could_not_see` as *the* measure of what was missed, so the bound
the corroboration advertised read three and a half orders of magnitude tighter
than it was. The stated reason for keeping the 20 out-of-scope links in the
list — "unread is unread" — simply was not applied to the other 110,100. There
are now two measures and `does_not_assert[4]` names both: `could_not_see` for
what the census could not read or declined on scope, and
`not_read_by_declared_rule` for what a bound published in `effective_scope`
kept it from reading. Neither is a coverage gap it hides — the flags are
unchanged, the verdict is unchanged — but a reader is no longer handed 29 as
the size of the blind spot.

**This changes what the census can be said to have cleared, which is
nothing.** The v11 drop-and-recreate landed in `14c8a2d` at 13:05 on
2026-08-14, eighteen minutes after the ad-hoc audit it actually rested on was
committed (`2f86f89`, 12:47). `tools/enumerate_stores.py` was not committed
until `0d7ff00` the following morning, and its first run — which postdates the
DDL either way — exited 1: it found a checkpoint row in `%TEMP%/rotest.db`
that the ad-hoc audit could not have seen, because that file did not exist
when the ad-hoc audit ran. The second run, recorded in the artifact committed
at `c979d92`, left five paths it could not read, which under the contract
above is exit 2. The run above is exit 2 as well. No run of this
script has ever returned the status that authorises the recut. What covers the
databases the census did not reach is therefore not the audit but the refusal:
`checkBeforeApply` returns `error.CheckpointsWouldBeDropped` for any store
below v11 that still holds checkpoint rows, and runs before `apply`
(`src/core/store/migrate.zig:759`, refusal at `:790-799`). That is the guard §7.0 already names,
and on this record it is not a backstop to the audit — it is the guard.

**What "read-only" is measured to mean, rather than asserted to mean.** Every
candidate's `.db`, `-wal` and `-shm` is digested — size, mtime_ns, and SHA-256
of the file or of its first and last 4 KiB — before the run and again after. In
the run recorded in that artifact, **1,362** database, `-wal` and `-shm` files
were digested before and after; **241** `-shm` files changed mtime and nothing
else, **one** changed mtime and content, no sidecar was
created or deleted, and
**no database file changed in size, mtime or content, and no `-wal` gained a
byte**. That is the entire
effect, and `filesystem_effect.contradicting_read_only` is empty. A `mode=ro`
reader of a WAL-mode database does create an empty `-wal` and a 32 KiB `-shm`
where none existed, and does move read marks inside an existing `-shm` — which
is what that one content change is: an
earlier run of this same script created 85 empty `-wal` and 92 `-shm` sidecars
that way, and later runs had none left to create. "Nothing was written" is therefore true of
business data and false
of the filesystem taken literally, and the census cannot tell its own effect
from a concurrent writer's — which is why it reports the difference instead of
promising there isn't one. An earlier run of this census, taken while the test
suite was writing, showed seven `-shm` files changing content as well as
mtime; that is the distinction doing its job rather than a failure of it.

**The two plaintext copies this audit found are gone.** `%TEMP%/v4copy.db` —
361,644,032 bytes, `user_version` 7, 12 rows in `keys` — and the second real
store, which sat in another project's working directory under
`%USERPROFILE%/Desktop` and held
11 more, were both deleted between the 2026-08-14 census and its 2026-08-15
re-run: neither file is on disk and neither appears in the regenerated
artifact. The sizes and key counts in that sentence come from the earlier
artifact, which committed them; the artifact as it now stands carries no file
sizes and no `keys` counts at all, so the surviving claim it supports is that
the real store is the only Terminus store outside the repo's scratch that has
ever held key material. Terminus still stores private keys and passphrases in
plaintext, so what stands is the hazard rather than the instance: the only
surviving copy of the e2e fixture key recorded in `MEMORY.md` now lives in the
real store alone, and any future copy of that store is twelve private keys in
whatever directory it is left in.

**Two things follow for the migration.** The real store has never been opened
by a 0.2.0 build — it is still `user_version` 4 and has no
`transfer_checkpoints` at all — so it will run v5 → v11 in one go the first
time anything touches it, creating the table at v6 and replacing it at v11
with nothing in it. And the migration must still be correct for a store that
stopped anywhere in v6–v10: two of the nine individually enumerated stores
are exactly that, both repo scratch at v10, and both hold a fixture row. The
versions of the 141 summarised scratch stores are not in the artifact. For
those stores the rule is no longer "be correct" but "refuse":
`checkBeforeApply` returns `error.CheckpointsWouldBeDropped` before any DDL
runs (`src/core/store/migrate.zig:759`, refusal at `:790-799`).

**Rehearsed, not assumed.** A copy of the real 362 MB store was migrated v4 →
v11 with the built binary: 0.8 s, `user_version` 11, all seven table counts
identical across the migration (13 servers, 12 keys, 142 memories, 45 facts,
959 jobs, 39 279 history, 6 sessions), `integrity_check` ok,
`foreign_key_check` clean, key material intact — including the 1679-byte PEM
that `MEMORY.md` records as the only surviving copy of the e2e fixture key. The
copy was deleted immediately afterwards because it contained that key in
plaintext. Those seven counts are the rehearsal's snapshot rather than a
standing fact: the live store has been written since and now holds 960 jobs and
39 369 history rows.

---

## 1. What the current code actually does

### 1.1 Confirmed defects (each reproducible from the cited line)

**D1 — a short SCP read is reported as success, and it suppresses the only
verified backend.**
`Client.scpRecvBytes` takes the remote size from `sb.st_size`
(`src/core/ssh/Client.zig:453`), allocates it whole
(`src/core/ssh/Client.zig:455`), then loops `while (received < total)` with
`if (n == 0) break;` (`src/core/ssh/Client.zig:460`) and returns
`data[0..received]` (`src/core/ssh/Client.zig:463`). `total` is never compared
to `received`. The caller takes that buffer (`src/cli/cmd_transfer.zig:151`),
writes it to the destination file (`src/cli/cmd_transfer.zig:65`) and reports
`ok: true` with the truncated count (`src/cli/cmd_transfer.zig:87`, `:92`).
Because no error is raised, the automatic fallback to the md5-verified exec
backend at `src/cli/cmd_transfer.zig:152-155` never fires — **the unverified
partial read beats the correct backend.** The same shape is in the dead
`Client.scpRecv` (`src/core/ssh/Client.zig:492`).

**D2 — the default push is unverified in both directions.**
`Client.scpSendBytes` writes and then returns `data.len` unconditionally
(`src/core/ssh/Client.zig:410-438`); it never reads the channel exit status.
`cmd_transfer.zig` returns `"scp"` immediately on that success
(`src/cli/cmd_transfer.zig:118-119`). `scpRecvBytes` has no check at all, not
even a size compare. Only the exec backend digests anything
(`src/core/transfer.zig:67-71`), and only with md5. So **the default
single-file path — the one nobody passes a flag for — proves nothing.**

**D3 — the exec push truncates the real destination before it starts.**
`transfer.pushBytes` opens with `: > '{s}' || exit 42`
(`src/core/transfer.zig:44`) against the *final* path, then appends slice by
slice through `printf '%s' '<b64>' | base64 -d >> '<path>'`
(`src/core/transfer.zig:61`). A failure at slice 3 of 500 leaves a truncated
file at the real destination, and the md5 check that would have caught it
(`src/core/transfer.zig:67-71`) never runs. There is no staging path, no
rename, no no-clobber. SCP push is no better: it writes directly to the final
path (`src/core/ssh/Client.zig:410-425`).

**D4 — the durable record structurally cannot represent a failed transfer.**
`Store.history.add(...) catch {}` at `src/cli/cmd_transfer.zig:77-83` and
`src/cli/cmd_sync.zig:59-67`, on the success path only, with
`.exit_code = 0` hardcoded (`cmd_transfer.zig:80`, `cmd_sync.zig:64`) and the
write error swallowed. `src/cli/cli.zig:295` already names this pattern as the thing `receiptFatal`
(`src/cli/cli.zig:299`) exists to replace.

**D5 — a stderr read error is treated as EOF, discarding the remote's
diagnosis.** `drainBoth` at `src/core/ssh/Client.zig:338`:
`err_eof = true; // 0 (EOF) or error: stop reading stderr`. This is on every
`exec`, not just transfers. "No space left on device" is exactly the message
this drops.

**D6 — whole-file-in-memory at both layers, on every live path.** CLI push
reads the whole file with a 2 GiB cap (`src/cli/cmd_transfer.zig:56`);
`scpRecvBytes` allocates the entire remote size with **no cap at all**
(`src/core/ssh/Client.zig:455`); `transfer.pullBytes` holds roughly 3× the
file at peak; `cmd_sync` tars a whole tree into an `Allocating` writer
(`src/cli/cmd_sync.zig:137`). The only fixed-buffer streaming code in the repo
is dead (`scpSend`, `scpRecv`).

**D7 — the shell-injection guard runs after the bytes.**
`validateRemotePath` (`src/cli/cmd_transfer.zig:164`) is called at
`src/cli/cmd_transfer.zig:126` — *after* the SCP attempt at `:118` has already
been made — and at `:157` for pull, after `:150`. A second copy lives at
`src/cli/cmd_sync.zig:278`.

**D8 — `sync --delete` destroys the destination before its replacement
exists.** The delete clause is `rm -rf '<remote_dir>' && `
(`src/cli/cmd_sync.zig:183`), spliced into the script *before* `mkdir -p` and
`tar -xf` (`src/cli/cmd_sync.zig:186-193`). A tar failure after the `rm -rf`
leaves nothing.

**D9 — total ledger bypass.** Neither `cmd_transfer.zig` nor `cmd_sync.zig`
references `Core.execution`. No `request_id`, no scope guard, no receipt, no
reconcile. `operations.Kind.transfer_push`, `.transfer_pull` and `.fetch`
(`src/core/store/operations.zig:32-34`) are now required by
`transfers.create_sql`, which refuses an insert whose operation kind does not
match the checkpoint's direction (`transfers.zig:1321-1323`, and again on
handover at `:2458-2460`), and by every arm of `receipts.appliesToKind`
(`receipts.zig:1169-1370`). `transfer_checkpoints` is dropped and recreated by
v11 (`src/core/store/migrate.zig:442-511`; the v6 table at `:195-224` is what
it replaces), and `transfers.zig` is its only writer outside test fixtures:
one INSERT at `transfers.zig:1308` and eight UPDATEs (`:1678`, `:1915`,
`:2167`, `:2444`, `:2596`, `:2913`, `:2996`, `:3117`).
`ResolutionEvidence.filesystem_effect` (`src/core/store/receipts.zig:874`) is
constructed throughout the gate suite (`gates_test.zig:2025`, `:2644-2695`,
`:4895-4914`, `:5211`, `:5607`) and admitted for the three transfer kinds in
`appliesToKind` (`receipts.zig:1305-1306`). What none of them has is a
constructor on the *live* transfer path: `cmd_transfer.zig` and `cmd_sync.zig`
open no operation at all.

**D10 — zero test coverage of the live transfer path.**
`src/core/store/transfers.zig` now carries 13 tests (`:3138-3708`) and is
called by `execution.zig` and `receipts.resolve`, but none of that reaches the
shipping commands: `src/cli/cmd_transfer.zig` and `src/cli/cmd_sync.zig`
contain zero tests between them, and nothing exercises `Client.scpSendBytes`,
`Client.scpRecvBytes` or `transfer.pushBytes`/`pullBytes`.

### 1.2 Confirmed dead code

| Symbol | Location | Evidence it is dead |
|---|---|---|
| `Client.execWithStdin` | `src/core/ssh/Client.zig:258` | zero callers; its doc at `:250-252` claims "this is how exec-based file transfer moves bytes" (false — `transfer.zig` puts data in the *command string*), and `:254-257` claims the 30 s timeout stays armed while `:286` sets it to 0 |
| `Client.scpSend` | `:359` | zero callers; the only streaming push (1 MiB buffer) in the repo |
| `Client.scpRecv` | `:467` | zero callers; carries D1's shape at `:492` |
| `Client.Progress` | `:351` | only used by the two dead functions |

Three rows that stood here — `transfers.zig` as a whole, the three transfer
`operations.Kind` values, and `ResolutionEvidence.filesystem_effect` — are no
longer dead and were removed rather than corrected. `transfers.zig` is 3708
lines with 13 tests at `:3138-3708`, called by `execution.zig:440`/`:502`/
`:507`/`:522` and by `receipts.resolve` at `receipts.zig:2149`/`:2231`/
`:2251`/`:2261`/`:2319`/`:2368`. All three kinds are load-bearing — see
`transfers.zig:1321-1323`, `receipts.zig:1169-1370`, and the gate
constructors at `gates_test.zig:1465`, `:3590` and `:6949` (push), `:7348`
(pull) and `:6653` (fetch). `filesystem_effect` lives at `receipts.zig:874`
and gained both constructors and an identity check in `resolve` at
`receipts.zig:2148-2178`.

### 1.3 Design smells (not defects, but they are why the defects were possible)

* **Two transports selected by a silent fallback.** `--via` is parsed at
  `src/cli/cmd_transfer.zig:36-38`; the default catches the SCP error, *drops
  it* (`:120-124`), and retries over exec — so after a double failure the
  printed message describes only the exec attempt. Same shape at
  `src/cli/cmd_sync.zig:177-180` and `:246-248`. A fallback from a verified
  path to an unverified one is bad; here it runs the other way (D1).
* **Two digest algorithms, both md5** (`transfer.zig:28`, `cmd_sync.zig:169`,
  `:251`), for integrity of artifacts that may be executables.
* **Swallowed errors on the sync path**: `catch continue` at
  `cmd_sync.zig:151` and `catch 0` at `:162` silently drop stat failures out
  of the dry-run byte count; `catch {}` at `:249` drops the temp-file cleanup;
  `catch null` at `:271` drops the walk that produces the reported file count.
* **`transfers.zig` was push-shaped and fail-silent — closed in `14c8a2d` and
  `2b670a9`.** The column is `partial_sha256`, paired with the offset by a
  schema CHECK (`migrate.zig:489`); `confirmOffset` assigns the prefix hash
  rather than `COALESCE`-ing it and writes no `state`, guarding
  `state IN (acceptsOffset)` and `request_id` instead
  (`transfers.zig:1677-1685`); every mutator now guards `changes()` and
  classifies a zero-row write into a named refusal (`transfers.zig:1235`,
  `:1667`, `:1904`, `:1974`, `:2343`, `:2560`, `:2906`, `:2989`, `:3105`);
  `findResumable` keys on `(dest_side, dest_path)`
  (`transfers.zig:1424-1442`); and the `i128 → i64` mtime narrowing is a
  checked `std.math.cast` returning `error.MtimeOutOfRange`
  (`transfers.zig:1147-1150`).
* **`verifyResume` used to reject the only thing a real interruption produces
  — closed in `b6e4254`, tightened in `14c8a2d`.** A partial longer than
  `confirmed_offset` is now the normal interrupted shape: `verifyResume`
  proves the head against the recorded prefix hash
  (`transfers.zig:1534-1541`) and then returns
  `.truncate_then_resume{offset, partial_len}` (`transfers.zig:1552-1555`), so
  the unconfirmed tail is discarded rather than counted. `partial_mismatch`
  now means a *shorter* partial (`:1525`), a missing or disagreeing prefix
  hash (`:1535-1540`), or a partial that disappeared (`:1519-1521`). Held by
  `transfers.zig:3675`.
* **`verifyResume` used to be blind to an HTTP source — closed in
  `14c8a2d`.** `local_path` is gone; the source is a `SourceIdentity` union
  (`transfers.zig:870-888`) and `sourceChanged` is exhaustive over it, with
  the `.http` arm refusing a resume when no strong validator (`etag`, else
  `last_modified`) was recorded or is still offered
  (`transfers.zig:1589-1602`). The schema says the same by name in
  `offset_needs_source_identity` (`migrate.zig:498-502`). Held by
  `transfers.zig:3618`.
* **`ResolutionEvidence.filesystem_effect` used to prove nothing — closed in
  `212289e`, tightened in `2b670a9`.** `sha256` is now `[]const u8`
  (`receipts.zig:879`), so the null case is a compile error rather than a
  settle, and the reading carries a `side` alongside the path
  (`receipts.zig:877`). `resolve` compares side, path and digest against
  `transfers.expectedEffectLocked` (`receipts.zig:2148-2162`,
  `transfers.zig:2662-2686`) — the digest the transfer declared *before* it
  submitted — and refuses `effect_hash_unproven` on any mismatch or missing
  declaration; it then refuses `effect_reading_against_recorded_outcome`
  unless the checkpoint's own state admits the rename may have landed
  (`receipts.zig:2172-2178`). The `supports` arm is still
  `.filesystem_effect => resolved == .completed` (`receipts.zig:1105`), and
  that is now correct: the binding lives in `resolve`. Held by
  `gates_test.zig:2644-2695` and `:4895-4914`.

---

## 2. The contract

### 2.0 The one rule this section exists to hold

> A terminal is reachable only from evidence about **the bytes at the
> destination path**, read back from that path after it was published. Not
> from the bytes we sent, not from the bytes we received, not from a channel
> reaching EOF, not from a file existing.

Everything below is machinery for that sentence.

### 2.1 One transport

All three current transports are deleted (§3). One survives: **an SSH exec
channel carrying raw binary on stdin/stdout, driven by a generated POSIX
shell program on the far end.** There is no `--via` and no fallback, because:

* Verification (`sha256sum` over the destination), atomic publish (`ln`/`mv`),
  free-space probing and remote-partial probing all need an exec channel
  *regardless of how the bytes move*. Once that channel exists, a second
  byte-moving protocol is a second implementation of the one thing it can
  still do.
* `libssh2_scp_send64` takes the total size up front and always writes the
  final destination path (`src/core/ssh/Client.zig:372`, `:418`). It cannot
  express an offset, a staging path, or no-clobber. It structurally cannot
  pass the agreed resume gate.
* Deleting SCP costs no throughput: vendored `scp.c` opens an ordinary
  session channel and does `process_startup("exec", "scp -t …")`, then calls
  `libssh2_channel_write_ex` — the same call our channel uses.
* base64-in-argv existed only to smuggle bytes through the *command string*
  (`src/core/transfer.zig:61`). With stdin streaming, the 4/3 inflation, the
  18 KiB slice ceiling (`transfer.zig:19`) and the round-trip-per-slice all
  disappear.

Capability is asked once, at probe time, and answered with a **refusal, never
a downgrade**: if the remote has neither `sha256sum` nor `shasum -a 256`, the
transfer is refused before a byte moves. No md5 fallback — replacing a strong
digest with a weak one to avoid changing a caller is the pattern this project
forbids.

Transfers stay on a direct SSH connection. The daemon protocol is line-based
JSON and cannot carry binary; the CLI refuses that transport *before*
constructing the executor. This is a stated precondition, not a type-level
guarantee — see §7.7.

### 2.2 The Zig API

**`src/core/exec.zig` — `Executor` gains streaming and a shell arm** (§7.7):

```zig
pub const Executor = union(enum) {
    direct: *Ssh,
    daemon: *DaemonClient,
    scripted: *Scripted,
    /// A real local POSIX shell over a real scratch directory. Runs the
    /// ACTUAL generated remote programs, so the gates test the protocol
    /// rather than a mock of it. Same precedent and same justification as
    /// `scripted` (exec.zig:12-16); the difference is that `scripted`
    /// replays exit codes while this one executes the scripts.
    shell: *ShellTransport,

    pub fn exec(e: Executor, arena: Allocator, command: []const u8) Ssh.ExecError!Ssh.ExecResult;

    /// Runs `command` with `src` as its stdin. Pulls <= 1 MiB at a time and
    /// interleaves the stdout/stderr drain with the write, so peak RSS is
    /// independent of `len` and libssh2's shared receive window keeps moving.
    pub fn sendStream(e: Executor, arena: Allocator, command: []const u8,
                      src: *std.Io.Reader, len: u64) StreamError!Ssh.ExecResult;

    /// Runs `command` and streams its stdout into `dst` through a fixed
    /// buffer, capping stderr in memory. Never reads one stream to EOF
    /// before the other.
    pub fn recvStream(e: Executor, arena: Allocator, command: []const u8,
                      dst: *std.Io.Writer) StreamError!StreamResult;
};

pub const StreamError = Ssh.ExecError || error{
    /// The daemon transport cannot carry binary. A named refusal, not a
    /// fallback: the CLI must never reach this.
    StreamingUnsupported,
};
pub const StreamResult = struct { exit_code: i32, bytes: u64, stderr: []u8 };
```

`Ssh.Client` gains exactly two functions (`execStreamIn`, `execStreamOut`) and
loses six (§3). `drainBoth`'s stderr-error-as-EOF (`Client.zig:338`) becomes
`return error.ReadFailed`.

**Deliberately NOT a `std.Io.Writer` adapter.** `std.Io.Writer.Error` is
`error{WriteFailed}` alone, so a sink implemented as a `Writer` vtable cannot
propagate "the remote refused this chunk at offset N with exit 45" — it must
flatten it and stash it out of band. Flattening a failure is the one thing
this project will not do, so the sink is a plain struct with explicit methods
and an explicit error set.

**`src/core/artifact.zig` — the state machine:**

```zig
pub const Direction = Store.transfers.Direction; // push | pull | fetch

pub const Source = union(enum) {
    local_file: struct { path: []const u8 },
    remote_file: struct { path: []const u8 },
    http: struct { url: []const u8 },            // M3b — see §7.3
};
pub const Dest = union(enum) {
    remote: struct { path: []const u8, mode: u32 = 0o644 },
    local:  struct { path: []const u8 },
};

pub const Plan = struct {
    source: Source,
    dest: Dest,
    /// One confirm point per chunk. The ONLY large allocation is one
    /// `io_buffer` of 1 MiB, independent of this.
    chunk_size: u64 = 8 << 20,
    no_clobber: bool = false,
    /// Deliberately discard a stale checkpoint. The only way to start from
    /// zero after a source-changed refusal; never implicit.
    restart: bool = false,
};

pub const Outcome = struct {
    checkpoint_state: Store.transfers.State,
    status: op_state.Status,
    bytes_total: u64,
    bytes_moved: u64,
    resumed_from: u64,
    /// The digest re-read FROM THE DESTINATION after publish. Present on
    /// `completed` and on nothing else.
    published_sha256: ?[]const u8,
    /// Named and printed when a staging file is deliberately left for resume.
    leftover_partial: ?[]const u8,
    warnings: []const []const u8,
};

pub const Error = Executor.StreamError || Store.transfers.Error ||
    execution.Error || Allocator.Error || error{ ... };

/// Returns only after a terminal receipt exists for `execution`.
/// Takes an `Executor`, never a `*Ssh`: that is what makes §5's gates
/// compilable at all.
pub fn run(
    ex: *execution.Execution,
    executor: Executor,
    store: *Store,
    arena: Allocator,
    io: std.Io,
    plan: Plan,
) Error!Outcome;
```

**`src/core/artifact/remote.zig` — the generated programs**, as pure
`fn(arena, args) Allocator.Error![]u8` builders. Their *text* is unit-tested
in-process; their *behaviour* is tested by executing them through the real
`-Dposix-sh` the build already resolves (`build.zig:167-174`).

### 2.3 The state machine, and where `submitted()` fires

This is the spine of the design, and it is the one thing all nine judgements
independently said to keep.

```
phase        checkpoint state   Execution status   what happens
-----------------------------------------------------------------------------
plan         planned            created            findResumable / create / adopt / recover
                                                   (`findResumable` sees only the four
                                                    adoptable states; a row abandoned in
                                                    `verifying` or `publishing` still holds the
                                                    path and needs `execution.recoverCheckpoint`,
                                                    which normalises it to `paused` or
                                                    `indeterminate_publish` first)
lease        planned            created            leases.acquire {path,dest}
probe        probing            connecting         ONE exec: capability, dest dir
                                                   writable, df, source stat,
                                                   partial length + prefix hash
resume-check probing            connecting         transfers.verifyResume
transfer     transferring       connecting         N chunk execs (push) or one
                                                   streamed channel (pull)
verify       verifying          connecting         digest re-read from the
                                                   STAGING file, both ends
publish      publishing         submitted   <-- execution.submitted() HERE
published    published          completed          one atomic ln/mv, then a
                                                   read-back digest of dest
```

**`execution.submitted()` is called immediately before the single publish
act, and nowhere earlier.** Everything before it is staging, in exactly the
sense `op_state.zig:234-247` already blesses and `cmd_exec.zig:224-244`
already relies on: it reaches the host, it can leave an artefact behind, and
it is not the caller's operation. The destination path is not named by any
command until the publish program, so it is *provably* untouched until then.

Consequences, all of them load-bearing:

* A connection lost mid-transfer is `connecting`, so
  `op_state.terminalForTransportLoss` (`op_state.zig:316`, the
  `.created, .connecting` arm at `:321`) gives
  `.never_submitted` → **failed, exit 1, resumable**. Not a shrug.
* The `indeterminate` / exit-75 window collapses from a multi-GiB transfer to
  one `ln` syscall.
* `.exited{0}` from the publish program is honest evidence, because the
  program's exit 0 is reachable only after the digest comparison inside it
  passed.

**The cost of submit-late, stated rather than hidden:** `connecting` does not
block scope (`op_state.zig:61`), so during the transfer the ledger's guard is
not holding the destination. That is what the **lease** is for: `leases.acquire` on
`{kind: .path, key: remote_side_path}` before probing, renewed during the
transfer, released at settle — the remote destination for a push, the remote
source for a pull, matching the scope §2.9 binds. A lease is held by **one
attempt, named by its `request_id`** (`leases.Lease.owner_request_id`,
`leases.zig:71-73`; `heldBy` at `:89`), which is the only thing an acquisition
compares. Until v12 it was held by `policy.ownerToken`, a token minted once per
machine profile, so every session on one machine was the same owner and
`acquire` read a peer's overlap as its own renewal; that token is still written
on every row as `profile_token` and now decides nothing (`leases.zig:74-78`).
A lease is always a claim
inside one server's namespace (`leases.server_id` is `NOT NULL REFERENCES
servers(id)`, `migrate.zig:564`; `AcquireOptions.server_id` is `i64`,
`leases.zig:109`), so it cannot hold a *local* destination at all. For a pull
or a fetch the destination is local, and the only thing standing on it is
`idx_checkpoints_live_dest` — "the only collision guard a locally-published
transfer gets" (`transfers.zig:91-97`). `execution.begin` consults
`leases.conflictForLocked` through `blockerLocked` (`execution.zig:273`,
reached from `begin` at `:791`) and `submitted()` re-checks it under the write
lock (`execution.zig:352`, `:359`), so a peer is refused at both ends; the
lease expires on its own if we die; `--force` does not skip the acquisition but
reaches `leases.takeover`, which displaces every overlapping lease, links each
displaced row through `superseded_by`, and writes a `forced_past_blocker` audit
event naming both the request that was displaced and the machine that did it
(`execution.zig:963-990`).

### 2.4 The remote programs

Two hard rules, both machine-checkable from the emitted text (§5, gate A):

1. **The destination path appears exactly once across all emitted programs
   for an operation, inside the publish command.** This is what turns "hash
   mismatch / disk full / rename failure leave the existing destination
   untouched" from three behaviours you must trigger into one string
   assertion.
2. **Every failure branch of a program that reads stdin must drain stdin to
   EOF before exiting.** The sender writes the whole chunk before it can
   observe an exit status; a script that writes to stderr and exits *before*
   consuming stdin deadlocks the writer and its exit code never arrives. This
   is why the chunk program below has `cat > /dev/null` on both failure arms.

`part` is a deterministic sibling of `dest`:
`dirname(dest) + "/." + basename(dest) + ".terminus-part"`. Deterministic
because resume must find it; exclusive because of the lease and the partial
unique index (§2.7), never because of a unique name.

```sh
# probeScript(part, dest, src, need_bytes)      -- read-only except as noted
set -e
command -v sha256sum >/dev/null || command -v shasum >/dev/null || exit 41
[ -w "$(dirname '<dest>')" ] || exit 44
avail=$(df -Pk "$(dirname '<dest>')" | awk 'NR==2{print $4}')
[ "$((avail * 1024))" -ge '<need_bytes>' ] || exit 50
n=0; [ -e '<part>' ] && n=$(wc -c < '<part>')
printf 'part=%s\n' "$n"
[ "$n" -gt 0 ] && { h=$(head -c '<confirmed>' '<part>' | sha256sum); printf 'prefix=%s\n' "${h%% *}"; }
[ -n '<src>' ] && { s=$(sha256sum '<src>') ; printf 'srcsha=%s\n' "${s%% *}"; }
exit 0
```

```sh
# chunkScript(part, expect_offset, expect_end)  -- reads stdin
n=0; [ -e '<part>' ] && n=$(wc -c < '<part>')
[ "$n" = '<expect_offset>' ] || { cat > /dev/null; echo "partial is $n" >&2; exit 45; }
cat >> '<part>' || { cat > /dev/null; exit 42; }
n=$(wc -c < '<part>')
[ "$n" = '<expect_end>' ] || { echo "short append: $n" >&2; exit 42; }
printf 'len=%s\n' "$n"
```

```sh
# publishScript(part, dest, want_sha, total, mode, no_clobber)
set -e
[ -n '<want_sha>' ] || exit 66            # an empty expectation is a bug, never a match
chmod 0400 '<part>'                       # close the hash->link window to non-root writers
got=$(sha256sum '<part>') || exit 66      # NO pipeline: a pipeline's status is `cut`'s
got=${got%% *}
[ "$got" = '<want_sha>' ] || exit 43
[ "$(wc -c < '<part>')" = '<total>' ] || exit 43
chmod '<mode>' '<part>'
ln '<part>' '<dest>' || { [ -e '<dest>' ] && exit 47; exit 48; }   # no-clobber
# overwrite mode instead:  mv -f '<part>' '<dest>' || exit 48
rm -f '<part>' || echo "terminus: staging file <part> left behind" >&2
back=$(sha256sum '<dest>') || exit 49     # READ BACK FROM THE DESTINATION
[ "${back%% *}" = "$got" ] || exit 49
```

Notes on what is deliberately absent and why:

* **No `openssl dgst` in the capability set.** Its output is
  `SHA256(f)= <hex>`, which needs a third parser. `sha256sum` and
  `shasum -a 256` both print `<hex>  <name>`, so `${x%% *}` handles both.
* **No `cut`, no pipeline, for any verdict.** A pipeline's exit status is the
  last command's, so a failing digest tool with a succeeding `cut` yields
  `got=""` at status 0.
* **No `sync(1)` per chunk.** POSIX `sync` flushes all dirty pages
  system-wide; running it 256 times per 2 GiB upload on someone's production
  host is not acceptable, and durability is not what this design rests on —
  the read-back digest is. A power loss mid-transfer leaves a part longer than
  the confirmed offset, which §2.6 handles.
* **`ln` then `rm`, not `mv`, for no-clobber.** POSIX `mv` has no atomic
  no-clobber. `ln` fails atomically if the destination exists. Hash-then-`ln`
  operates on one inode, so there is no window in which the verified bytes and
  the published bytes differ.
* **The `rm -f` failure is a warning, not a verdict.** The artifact really is
  published; reporting `failed` there would be the lie.

**Remote exit vocabulary** (every one is a real remote exit status, so
`.exited{code}` justifies `failed` with no new machinery): 41 no digest tool ·
42 remote write failed · 43 staging digest or length mismatch · 44 destination
directory not writable · 45 partial length moved under us · 46 remote source
changed · 47 destination exists (no-clobber) · 48 publish rename failed · 49
**read-back after publish disagrees** · 50 insufficient free space · 60 partial
prefix digest disagrees.

### 2.5 Pull: where the offsets are confirmed, and where the digest comes from

The single most common flaw across all three input designs was that pull was
push-shaped: verified by a *remote* command, over the bytes at the *source*,
with nothing ever re-reading the local destination. That reproduces D1 on the
local side. The rule that fixes it:

> **The side that holds the partial file is the side that confirms offsets,
> and the destination is always re-read from disk before the operation is
> called complete.**

* **Push** — the part is remote. Offsets advance on a remote-reported length
  (`chunkScript`'s `len=` line) plus the running local digest of the confirmed
  prefix. Verification is the remote `sha256sum '<part>'` inside
  `publishScript`, and the read-back is the remote `sha256sum '<dest>'`
  (exit 49).
* **Pull** — the part is local. One `recvStream` channel runs
  `tail -c +$((OFF+1)) -- '<src>'` and streams the remainder into the local
  part file; offsets advance on the local part's own length after each
  `chunk_size` boundary. **There is no per-chunk remote exec on pull** —
  which is what avoids the O(n²) whole-source re-read that a naive
  chunk-per-exec pull produces. Never `2>/dev/null`: the remote's stderr is
  captured and preserved into the receipt (D5).
  Verification is three-way, all of it mandatory:
  1. the in-flight digest of what we received,
  2. the source digest the probe read remotely (mismatch → exit 46),
  3. **a re-read of the local part from disk after `flush()` and `close()`**,
     which is the check that catches a short write, a dropped flush, or a torn
     positional write. Only then is the local rename performed, and the
     destination is then **re-read and hashed again** — the local equivalent of
     exit 49.

`tail -c +N` is POSIX and takes a byte offset. `dd skip=` is not used: it
counts in `bs` blocks, and mixing a 64 MiB confirm granularity with a 1 MiB
block size is a 64× offset bug waiting to happen.

### 2.6 `transfer_checkpoints`: how it is used, and the six things fixed

Used as built: `contiguousPrefix` and the *pure rules* of `verifyResume`.
Everything else was re-cut by v11. Every mutator now takes the owning
`request_id` and CASes on it, and `create` is an `INSERT ... SELECT` over
`operations` — four agreement conjuncts in the same statement as the write —
followed by `if (store.db.changes() == 0) return
error.CheckpointOperationMismatch`, because a SELECT that matched nothing is
not an error to sqlite and `lastInsertRowId` would otherwise hand the caller
another transfer's checkpoint id (`transfers.zig:1226-1236`). Four further
mutators exist that the six fixes below do not name: `recordSourceIdentity`
(`:2971`), `recoverLocked` (`:2258`), `supersedeLocked` (`:2545`) and
`adjudicateLocked` (`:1836`). Fixed:

**F1 — resume must survive the interruption it exists for.**
`verifyResume` used to reject `partial.len > confirmed_offset`, which is
exactly what a connection loss leaves. That rejection is gone: it now returns
`.truncate_then_resume{ offset, partial_len }` (`transfers.zig:1552-1555`),
having first proved the head from the recorded/observed `partial_sha256` pair
(`:1534-1541`). The caller truncates to `offset` and continues. The remote
script below is one way to perform that cut, not a precondition of calling
`verifyResume`, and it keeps the same ordering — prove the prefix, then
truncate to it, with truncation gated on the proof:

```sh
n=$(wc -c < '<part>')
[ "$n" -lt '<confirmed>' ] && exit 60
h=$(head -c '<confirmed>' '<part>' | sha256sum); h=${h%% *}
[ "$h" = '<recorded_prefix>' ] || exit 60      # do NOT truncate on a mismatch
[ "$n" -gt '<confirmed>' ] && { dd if=/dev/null of='<part>' bs=1 seek='<confirmed>' 2>/dev/null; }
printf 'len=%s prefix=%s pre_truncate=%s\n' "$(wc -c < '<part>')" "$h" "$n"
```

`verifyResume` is then called with `remote.len == confirmed` and a real
`prefix_sha256`, and returns `resume_from`. The destructive act is gated by the
remote's own comparison, so a polluted or foreign partial is never silently
trimmed. The pre-truncation length is recorded as a `checkpoint` observation,
so the trail reads "found 8.3 GiB, proved 8.0 GiB, discarded 0.3 GiB".
`dd if=/dev/null seek=` is used rather than `truncate(1)`, which is not
universal.

**F2 — the prefix hash must actually be written.** The column is
`partial_sha256`, `confirmOffset` plain-assigns it rather than COALESCEing it
(`transfers.zig:1680`), and `verifyResume`'s prefix branch is mandatory rather
than dead: at a non-zero offset both the recorded and the observed digest must
be present and equal, or the verdict is `partial_mismatch`
(`transfers.zig:1534-1541`). The schema enforces the same invariant —
`CHECK (confirmed_offset = 0 OR partial_sha256 IS NOT NULL)`
(`migrate.zig:489`) — so a null can no longer be written under a non-zero
offset even by a caller that skips the guard. The chunk-close confirm now
passes the prefix digest **every time** — it is free, because `Sha256` is a
value type: `var snap = hasher; snap.final(&d)` yields the digest of the
confirmed prefix at each boundary.

**F3 — fail-silent writes become fail-loud.** `confirmOffset` gains
`AND state IN (<acceptsOffset>)` — `planned`, `probing`, `transferring`,
`paused`, rendered from `State.acceptsOffset` (`transfers.zig:393-410`), so it
cannot advance a `verifying`, `publishing`, published or failed row. `paused`
is deliberately in the set: it is where a resumable transfer waits. It also
gains `AND request_id = ?6`, so only the operation that currently owns the
checkpoint may write progress into it. It then checks `store.db.changes()` and
re-reads the row through `ownedRow` to name which conjunct refused it:
`CheckpointRowMissing`, `CheckpointNotOurs`, `IllegalCheckpointTransition`,
`CheckpointNotAdvanced` (a regressing offset) or `PrefixHashConflict`
(`transfers.zig:1666-1674`). `setState` classifies the same way through the
same re-read, into the named members of `TransitionError` — including
`CheckpointAwaitingAdjudication` and `SupersessionIsNotATransition`, which say
the edge exists but belongs to `adjudicateLocked` or `supersedeLocked` rather
than to a driver (`transfers.zig:1974-2010`).

**F4 — the source shape becomes role-based, not push-shaped.**
`verifyResume`'s `if (checkpoint.local_path != null)` gate is gone, replaced
by the `SourceIdentity` union (`transfers.zig:870-888`) and an exhaustive
switch in `sourceChanged` (`transfers.zig:1565-1604`), so a remote source is
validated by its own size + mtime + digest and an HTTP source by its strong
validator. The schema enforces the same families — a file kind must carry
`source_path` and no `source_url`, and vice versa (`migrate.zig:479-485`) —
and goes one step further with `CONSTRAINT offset_needs_source_identity`
(`migrate.zig:498-502`), which makes a non-zero `confirmed_offset` unstorable
without a content digest for a file or a strong validator for an http object.
`verifyResume` re-checks it purely, because it is handed a struct and cannot
assume the schema ever saw the row, and returns a sixth verdict for it:
`unidentified_source` (`transfers.zig:1487`, checked at `:1511-1515`). (For
M3a only the first two source kinds are constructible; see §7.3.)

**F5 — checkpoint identity gains a destination side.** `findResumable` used to
key on `remote_path` alone, with no server dimension. It now takes
`(dest_side, dest_path)` — `dest_side` is `server:<id>` or `local` — and
filters on `State.isAdoptable` (`transfers.zig:1410-1442`), so a `verifying`
or `publishing` row still holds its path but is not offered as resumable; the
`remote_*` columns are gone entirely (`migrate.zig:442-511`). It also gains a
**partial unique index over every destination-holding state** —
`idx_checkpoints_live_dest` (`migrate.zig:504-511`), whose predicate names the
six live states, all six `failed_*` states and `indeterminate_publish`:
thirteen in all, the same set as `State.holdsDestination`
(`transfers.zig:129-150`), which `gates_test` pins against the stored DDL
through `holds_destination_sql` (`transfers.zig:715`). Only `published`,
`completed_unverified` and `superseded` release the path; a failed transfer
goes on holding it, and answering the next `create` with `DestinationHeld`,
until `supersedeLocked` (`transfers.zig:2545`) releases it (§2.7).

**F6 — `adopt`.** A resumed transfer is a new operation with a new
`request_id`, so the checkpoint row must be re-pointed:
`transfers.adoptLocked(store, id, expected_owner, new_request_id, now)`
(`transfers.zig:2207`) verifies the state is `isAdoptable` and re-points the
FK, keyed on `expected_owner` so two racing resumes cannot both believe they
won. It is a bare statement and requires an open transaction; that
transaction, and the `checkpoint` observation on both operations naming the
other, are `execution.Execution.adoptCheckpoint` (`execution.zig:427`). A
row whose owner died mid-`verifying` or mid-`publishing` is not adoptable — it
goes through `recoverLocked` / `execution.recoverCheckpoint` first. The checkpoint is a mutable
working record; the ledger is the audit trail.

Also fixed: the no-op `@divTrunc(l.mtime_ns, 1)` is now `narrowMtime` —
`std.math.cast(i64, v) orelse error.MtimeOutOfRange` (`transfers.zig:1147-1150`)
— because narrowing a mtime silently would make a source that changed look
unchanged.

**Two writers, one verdict — the ordering rule.** `transfers.setState` and
`receipts.settle` both record how a transfer ended, and they *can* now share a
transaction: `receipts.settleLocked` (`receipts.zig:752`) was split out so a
settlement can be composed with the other writes that have to land with it,
and `receipts.resolve` (`receipts.zig:1949`) already lands a checkpoint
adjudication and the operation's resolution together (`receipts.zig:2368` →
`transfers.adjudicateLocked`, which calls `requireTransaction` at
`transfers.zig:1844`). `settle` (`receipts.zig:718`) is only the wrapper that
opens `BEGIN IMMEDIATE` (`receipts.zig:725`) for a caller holding no lock.
The rule is: **the ledger is authoritative for the verdict; the checkpoint is
authoritative for the offset; the offset is re-proved on every resume by the
prefix hash.** Write order is checkpoint-first, then settle — chosen so that a
crash between them leaves a checkpoint marked failed under an *unsettled*
operation, which the next run sees as a scope-blocking peer and refuses. The
failure direction is a spurious refusal, never a spurious resume.

### 2.7 Concurrency: three layers, and what none of them covers

| Layer | Mechanism | Covers |
|---|---|---|
| `begin` | `blockerLocked` (`execution.zig:240-279`) — `unsettledInScope` at `:250`, `leases.conflictForLocked` at `:273` — reached from `begin` at `execution.zig:791` | a peer already working this scope in this realm (a server, or — when `server_id` is null — this machine); refuses before dialing, and only against a *mutating* caller (`execution.zig:813`, `:360`). Its unsettled half counts only peers that declared `mutating = 1` (`holds_scope_predicate`, `operations.zig:290`) — the lease half is the only one blind to the peer's own flag |
| `create` | `idx_checkpoints_live_dest`: `UNIQUE INDEX ON transfer_checkpoints(dest_side, dest_path)` over `State.holdsDestination` — **thirteen** states, not four: the six live ones, all six `failed_*`, and `indeterminate_publish` (`migrate.zig:504-511`, rendered from `transfers.zig:129-150`) | **any** second live transfer to the same destination on this machine, including pull and fetch, where `server_id` is null — today only `fetch`, since §2.9 gives a pull the remote host's id. The operation half of the guard *does* run in that realm: `blockerLocked` takes a `?i64` and null names the local realm rather than switching the check off (`execution.zig:240-279`, signature at `:243`). What the local realm cannot have is a *lease* — `leases.server_id` is `NOT NULL REFERENCES servers(id)` (`migrate.zig:564`, the v12 shape; the frozen v7 text at `:276` says the same) and `conflictForLocked` takes a plain `i64` (`leases.zig:189-196`), so `execution.zig:272-273` skips that half. A failed transfer goes on holding its destination until `supersedeLocked` (`transfers.zig:2545`) releases it |
| `submitted()` | the scope guard re-checked under the write lock (`execution.zig:359`, inside `submitted`'s `BEGIN IMMEDIATE` at `:352`) | the last-moment race between two racers that both cleared `begin` |

The partial unique index is the layer that matters for pull, and it is
deliberately server-independent: `unsettledInScope` filters by `server_id`
(`operations.zig:388`), so two pulls *from different servers* into one local
path would both clear the guard — and two pulls to the *same* server clear it
too, because §2.9 declares a pull non-mutating and the unsettled half counts
only `mutating = 1` peers (`operations.zig:290`). A DB-level uniqueness
constraint is the only thing that can see them both.

**What none of this covers, stated plainly:** two Terminus processes on two
*different machines* writing the same NFS/SMB destination. Nothing local can
see that. `ln` is atomic on POSIX local filesystems; on NFS silly-rename and
on SMB it is not guaranteed, and we do not claim it is.

### 2.8 Which evidence justifies which terminal

| Situation | Evidence | Ledger status | Exit |
|---|---|---|---|
| push: publish program exits 0 (digest matched **and** read-back matched) | `.exited{0}` | `completed` | 0 |
| push: publish exits 43 / 47 / 48 / 49 / 66 | `.exited{code}` | `failed` | 1 |
| probe/resume refusal: 41, 44, 46, 50, 60, source changed, partial mismatch | `.never_submitted{reason, error_code}` | `failed` | 1 |
| chunk exits 42 / 45 (destination never named) | `.never_submitted{reason}` | `failed` | 1, resumable |
| connection lost while staging (status `connecting`) | `terminalForTransportLoss(.connecting)` → `.never_submitted` | `failed` | 1, JSON `resumable:true, confirmedOffset:N` |
| **push: connection lost inside the publish exec** (status `submitted`) | `execution.transportLoss` → `.indeterminate{last_observed:.submitted}` + checkpoint `indeterminate_publish` | `indeterminate` | **75** |
| pull: local rename succeeded and the destination re-read matches | `.local_effect{path, published_sha256}` (NEW — §7.2) | `completed` | 0 |
| pull: local rename provably failed (`PathAlreadyExists`, `NoSpaceLeft`, `AccessDenied`) | `.local_effect{path, failure}` | `failed` | 1 |
| pull: the rename outcome cannot be classified | `.indeterminate` | `indeterminate` | 75 |
| any ledger write fails | `Cli.receiptFatal` (`cli.zig:299`) | — | **76** (`exit_code.receipt_persist_failed`, `cli.zig:239`) |

**`completed_unverified` is reachable in M3a by exactly two routes, and both
record the weakness on the row rather than hiding it.** The driver reaches it
from `publishing` when no digest was ever declared — the target's evidence
clause requires both digest columns to stay null (`transfers.evidenceClause`,
`transfers.zig:2054`) — and a reconciler reaches it from
`indeterminate_publish` by offering `destination_present_unverified`
(`receipts.zig:1848`). Both predecessors are in the graph at
`transfers.zig:564`, and `ownerOf` (`transfers.zig:662`) hands the first edge
to the driver and the second to adjudication, so neither writer can walk the
other's. No *driver* writes `completed` to the ledger for an unverified
artifact: we compute our own digest over the bytes we handled and re-read the
destination after publishing, so verification never depends on the *source*
offering a hash — it depends only on a digest tool existing, and when one does
not, we refuse before sending a byte. Reconcile can, and says so on its face:
`destination_present_unverified` supports `.completed` (`receipts.zig:1129`)
for a transfer that declared no digest, it is admissible for all three
transfer kinds (`receipts.zig:1322-1328`), and the checkpoint it forces is
`completed_unverified` (`receipts.zig:1848`), not `published` — so an auditor
can tell a proven delivery from an unproven one without going to look at
whether a commitment existed. Past a non-empty verification method, all
`resolve` asks of it is side and path matching the destination committed at
`create`, a publish still in question, and no digest ever declared
(`receipts.zig:2219-2258`); the variant's own comment concedes that a stale
file from an earlier run satisfies that (`receipts.zig:961-962`). That is
still not the flaw all three input designs shared — each of them settled a
`completed_unverified` fetch as ledger-`completed` via an `.exited{0}` that no
process produced. The enum value is `transfers.State.completed_unverified`
(`transfers.zig:65`); §7.3's argument (3) is superseded by this, and §7.3
itself was already answered "defer to M3b" in §7.0.

**The reconcile path, and the hole that has since closed.**
`ResolutionEvidence.filesystem_effect` carries `side`, `path` and a
non-optional `sha256` (`receipts.zig:874-880`); `supports` maps it to
`.completed` and nothing else (`receipts.zig:1105`); and `resolve` compares
all three against `transfers.expectedEffectLocked`, refusing with
`effect_hash_unproven` (`receipts.zig:2156-2161`) and then with
`effect_reading_against_recorded_outcome` when the checkpoint records an
outcome no rename could have reached (`receipts.zig:2172-2177`). The hazard
that motivated it: the *one* `indeterminate` this design creates has exactly
one documented exit, and unbound that exit proved nothing — after a lost
publish the destination most likely still holds the **old** file, and hashing
it would settle `completed`.

All three required steps landed. Steps 1 and 2 are the sentence above; the
outcome a failed comparison returns is `effect_hash_unproven`
(`receipts.zig:1575`), not the `evidence_unverifiable` this section proposed,
which exists nowhere in the tree. The comparison runs inside the `BEGIN
IMMEDIATE` `resolve` opens itself (`receipts.zig:1957`, `:2148-2161`). Step 3
is `transfers.recordExpectedHash(store, id, owner_request_id, sha256, now)`
(`transfers.zig:2892`), called after the whole source is streamed and hashed
and **before** `execution.submitted()`. It is write-once: a second
declaration, or one attempted after the first byte, is
`error.ExpectedHashLocked` (`transfers.zig:2909`).

`terminus request reconcile <id> --verify-artifact` re-hashes the destination
over a fresh connection and offers that as the evidence. The shape of this fix
is §7.1.

### 2.9 Binding to `execution.begin`

```zig
const start = try execution.begin(&store, arena, io, .{
    .server_id   = resolved.server.id,          // null for fetch (M3b)
    .server_name = resolved.server.name,
    .kind        = switch (dir) { .push => .transfer_push,
                                  .pull => .transfer_pull,
                                  .fetch => .fetch },
    // push: the remote DESTINATION. pull: the remote SOURCE.
    .scope       = .{ .kind = .path, .key = remote_side_path },
    .mutating    = (dir == .push),              // a read cannot make a later change unsafe
    .transport   = "direct",
    .argv_redacted = "<src> -> <dest>",
    .owner_token = try Store.policy.ownerToken(&store, arena, io, ctx.now),
    // ^ audit subject, not identity: it records *which machine* forced past a
    //   blocker. The lease is held by this operation's request_id
    //   (`execution.zig:70-77`).
    .force       = parsed.boolean("force"),
    .now         = ctx.now,
});
```

`begin` inserts nothing on its blocked path, so a refusal leaks no operation
row. The lease on `{path, dest}` is acquired immediately after `.ready` and
released at settle.

---

## 3. What gets deleted

| File:line | What it is | Why it goes |
|---|---|---|
| `src/core/transfer.zig` (whole file, 110 lines) | base64-over-exec transport: `push_slice:19`, `Error:21`, `md5Hex:28`, `pushBytes:35`, `pullBytes:75` | Existed only to smuggle bytes through the command string; stdin streaming removes the reason. Contains D3 (`: > '{s}'` at `:44`) and the repo's second md5. |
| `src/core/core.zig:9` | `pub const transfer = @import("transfer.zig")` | its module is gone |
| `src/core/ssh/Client.zig:250-301` | `execWithStdin` | dead; doc at `:250-252` and `:254-257` both false (`:286` disables the timeout it claims stays armed). Replaced by `execStreamIn`. |
| `src/core/ssh/Client.zig:344-349` | `TransferError` | only the SCP functions used it |
| `src/core/ssh/Client.zig:351-354` | `Progress` | only the two dead SCP functions used it |
| `src/core/ssh/Client.zig:356-407` | `scpSend` | dead |
| `src/core/ssh/Client.zig:409-439` | `scpSendBytes` | **D2** — returns `data.len` with no exit-status read (`:438`) |
| `src/core/ssh/Client.zig:441-464` | `scpRecvBytes` | **D1** and **D6** — `:455` uncapped alloc, `:460` short read as success, `:463` returns the truncation |
| `src/core/ssh/Client.zig:466-499` | `scpRecv` | dead; carries D1's shape at `:492` |
| `src/core/ssh/Client.zig:338` | `err_eof = true;` on a stderr READ ERROR | **D5** — becomes `return error.ReadFailed` |
| `build.zig:27` | `"scp.c"` in `libssh2_sources` | nothing references `libssh2_scp_*` after the above; the linker proves the deletion is complete |
| `src/cli/cmd_transfer.zig:18-25` | two-backend usage text | there is one transport |
| `src/cli/cmd_transfer.zig:36-38` | `--via` parsing | §4 |
| `src/cli/cmd_transfer.zig:56` | `readFileAlloc(.limited(1 << 31))` | **D6** |
| `src/cli/cmd_transfer.zig:77-83` | `history.add(...) catch {}`, `.exit_code = 0` at `:80` | **D4** |
| `src/cli/cmd_transfer.zig:104-130` | `pushData` and the fallback ladder, incl. the dropped SCP error at `:120-124` and the post-hoc `validateRemotePath` at `:126` | §1.3, **D7** |
| `src/cli/cmd_transfer.zig:132-161` | `PullResult`, `pullData`, the pull fallback at `:152-155` | same |
| `src/cli/cmd_transfer.zig:164-167` | `validateRemotePath` | moves into `artifact/remote.zig` as the single copy, and runs before anything is sent |
| `src/cli/cmd_transfer.zig:169-185` | `fatalTransfer`, `fatalExecTransfer` | replaced by the ledger's terminal reporting |
| `src/cli/cmd_sync.zig:59-67` | `history.add(...) catch {}`, `.exit_code = 0` at `:64` | **D4** |
| `src/cli/cmd_sync.zig:137` | the in-memory tar `Allocating` writer | **D6** |
| `src/cli/cmd_sync.zig:151`, `:162`, `:249`, `:271` | `catch continue`, `catch 0`, `catch {}`, `catch null` | swallowed errors |
| `src/cli/cmd_sync.zig:169-171`, `:251-255` | md5 computation and comparison | one digest, sha256 |
| `src/cli/cmd_sync.zig:177-180`, `:246-248` | the two scp→exec fallback ladders | §1.3 |
| `src/cli/cmd_sync.zig:183` + `:186-193` | `rm -rf '<dir>' && ` before extraction | **D8** — prune AFTER a verified extraction |
| `src/cli/cmd_sync.zig:278-281` | the duplicate `validateRemotePath` | **D7** |
| ~~`src/core/store/transfers.zig` — push-shaped parts~~ | **Done in v11** (`migrate.zig:402-511`): the table is re-cut around `dest_side`/`dest_path`, the `local_*`/`remote_path`/`remote_partial_*` column families are gone, the `local_path != null` gate is replaced by the exhaustive `SourceIdentity` union (`transfers.zig:870`) and the no-op `@divTrunc` is deleted. | §2.6. The pure resume rules, `contiguousPrefix` (`transfers.zig:3129`) and all six pre-existing tests survived, two under new names. Only the state name `failed_remote_partial_mismatch` (`transfers.zig:67`) still carries the old vocabulary. |
| `src/cli/dispatch.zig` help text | "upload a file over SCP" / "tar+md5" | no longer true |

**Not deleted, deliberately:** `transfers.zig`'s resume rules and
`contiguousPrefix` (unexercised in production until parallel fetch lands —
said plainly rather than pretended otherwise); `Executor` (control commands
still go through it — only two streaming primitives are added);
`history.redactSecrets`, which has four live callers — `cmd_exec.zig:88`,
`cmd_job.zig:145`, `cmd_job.zig:329`, and `receipts.zig:1491`, the `redact`
helper `ResolutionEvidence.toJson` runs over every free-text field of every
evidence variant — and is not dead even though
`history.add` loses its last two (§7.6).

---

## 4. Breaking changes

| What breaks | Who notices | New correct usage |
|---|---|---|
| `--via scp\|exec` removed from `push`/`pull` | anyone scripting a pinned backend | drop the flag; there is one verified transport. Passing it is a **hard error naming the reason**, not a silent ignore — `args.zig` does not reject unknown flag names, so a silently-accepted `--via scp` would change behaviour without saying so |
| `push` no longer writes through the destination path | anyone pushing onto a **symlink, FIFO, or a path whose inode identity matters** | push to the resolved target. The destination is now *replaced* (staging file + `ln`/`mv`), where the old exec path did `: > '<path>'` (`transfer.zig:44`) and the old SCP path wrote the final path directly (`Client.zig:418-425`) |
| a failed push no longer leaves a truncated destination | anyone who relied on partial output | the original destination is byte-for-byte intact, plus a `.<name>.terminus-part` staging file whose path is printed and recorded |
| md5 → sha256 everywhere, and a remote with neither `sha256sum` nor `shasum -a 256` is **refused** | minimal images that have `base64` but no digest tool | install `coreutils`/`busybox` with sha256 support. This is a real capability regression and it is deliberate: the alternative is an unverified transfer reported as `ok` |
| a remote with no `scp` binary is now normal rather than a fallback case | nobody, positively | — |
| `push`/`pull` gain `--no-clobber`, `--chunk-size <MiB>`, `--restart` | new surface | `--restart` is the only way to start from zero after a source-changed refusal — never implicit |
| JSON: `backend` **removed**; `ok` is no longer hardcoded true | every JSON consumer | branch on `status` and `requestId`. New fields: `requestId`, `status` (`completed`\|`failed`\|`indeterminate`), `sha256` (the **destination read-back** digest), `verified` (bool), `bytesTotal`, `bytesMoved`, `resumedFrom`, `chunkSize`, `resumable`, `confirmedOffset`, `leftoverPartial`, `warnings` |
| exit codes: `push`/`pull`/`sync` can now exit **75** and **76** | any agent treating non-zero as "retry" | 75 = indeterminate, reachable only if the connection dies inside the publish exec — **never retry blindly**, run `request reconcile <id> --verify-artifact` first. 76 = the receipt could not be written. `if push; then` keeps working |
| `history` rows for `push`/`pull`/`sync` disappear | `terminus history <server>` users | `terminus request ls` / `request show <id>` / `request receipt <id>`. The rows being deleted were success-only with `exit_code` hardcoded 0, so the surface being removed could not represent a failure anyway |
| transfers now take a `path` scope and a lease | anyone running two pushes to overlapping paths | the second is refused with "nothing was sent"; `--force` takes the lease over rather than skipping it, displacing every overlapping holder and recording each displacement |
| `sync push --delete` prunes **after** a verified extraction | anyone relying on the old destroy-first ordering | none needed; the destination is no longer deleted before its replacement exists |
| remote temp paths change | scripts watching `/tmp/.terminus_sync_<ts>.tar` | single-file transfers stage at `<dir>/.<name>.terminus-part`; sync stages under a request-id-derived path |
| library surface: `Ssh.Progress`, `scpSend`, `scpSendBytes`, `scpRecvBytes`, `scpRecv`, `execWithStdin`, `Core.transfer.*` disappear | in-repo callers only (all rewritten) | `Core.artifact.run` |
| **schema**: `transfer_checkpoints` dropped and recreated at v11 (§7.4) | a developer database below v11 that holds checkpoint rows | delete the rows, or the database. An empty pre-v11 table migrates in place; one with rows is refused at open with `error.CheckpointsWouldBeDropped` (`migrate.zig:759`, refusal at `:790-799`) rather than silently emptied. The real store has no `transfer_checkpoints` at all and migrates v4 → v11 in one go |
| `leases.TakeoverOutcome.taken.from` is `[]const Lease`, not `Lease` | any caller reading who was displaced | iterate. A takeover displaces *every* lease overlapping its scope, and `acquire` permits any number of mutually non-overlapping ones, so a takeover of `path:/srv/app` seizes both `path:/srv/app/dist` and `path:/srv/app/build`. Newest first, never empty — displacing nobody is `.acquired` (`leases.zig:430-447`, field at `:444`) |
| `leases.takeover` returns `TakeoverError!TakeoverOutcome`, not `Error!` | any caller switching exhaustively on the error set | handle `error.LeaseVanishedDuringTakeover`: the release UPDATE matched no row under the write lock, which is proof the lock is not doing what the rest of the function assumes. Declared on `takeover` alone rather than widened into `Error`, so no other lease caller sees it (`leases.zig:467`, justified at `:425-428`) |
| `leases.insertLocked` takes `supersedes: []const i64`, not `?i64` | in-module callers only (`leases.zig:291`, `:498`) | pass `&.{}` for a plain acquisition, `displaced_ids.items` for a takeover. Every displaced row is linked through `superseded_by`, so a seizure cannot leave a lease that ends with no successor recorded and reads as an expiry (`leases.zig:327-333`) |
| `transfers.handoverBoundCount` renamed `handoverBoundCountLocked`, and refuses outside a transaction | `servers.removeLocked` (`servers.zig:318`) and the gates (`gates_test.zig:8556`, `:8574`) | call it inside the write transaction. It is the third of `removeLocked`'s three barriers and was the only one not asserting it held the lock; a count taken outside the lock describes a moment that has already passed by the time the DELETE runs (`transfers.zig:2732`) |

---

## 5. Acceptance gates

Two harnesses. `Executor.scripted` (`exec.zig:37`) replays exit codes for
fault injection at chosen instants; `Executor.shell` runs the **actual
generated programs** through the real POSIX shell the build already resolves
(`build.zig:167-174`, `test/blackbox.zig:45`) against a real scratch
directory. That is what makes this design gateable without a server: the gates
test the protocol and the scripts, not a mock of them. What it does **not**
cover is libssh2 channel behaviour, which stays in the live e2e. Said plainly
rather than papered over.

### 5.1 Runs in `zig build test`, no network

**A. Script text** (`artifact/remote_test.zig`) — properties assertable on the
emitted strings:
* A1. The destination path appears **exactly once** across the emitted probe +
  chunk + publish programs, inside the publish command. *(Machine-checkable
  form of agreed gate 7 for all three of its cases.)*
* A2. The chunk program contains `>>` and never `>` against `$PART` (the exact
  shape of D3).
* A3. **Every failure branch of every stdin-reading program drains stdin to
  EOF before exiting** — asserted by parsing the emitted text. Without this,
  exit 45 is unreachable in practice.
* A4. No verdict is produced by a pipeline (no `| cut`, no `| awk`, in any
  line whose status is tested).
* A5. `no_clobber` emits `ln` and no `mv`; overwrite emits `mv -f` and no `ln`.
* A6. A path containing `'`, `"`, `` ` ``, `$` or a newline is rejected **by
  the emitter**, before any channel is opened *(D7)*.

**B. Pure rules** (`store/transfers.zig`, now 13 tests at `:3138-3708`) —
**B1, B2 and B5 have landed** (`transfers.zig:3567-3573`, same size and mtime
with different content → `source_changed`; `:3657`, right length wrong prefix
→ `partial_mismatch`; `:3602-3607` and `:3615` for a `remote_file` source and
a null one). B3's backwards refusal is `error.CheckpointNotAdvanced`
(`gates_test.zig:4006-4009`) and its terminal-row refusal
`error.IllegalCheckpointTransition` (`:4045-4048`); B4 is gated at
`gates_test.zig:3924-3935` and `:4162-4232`. B3's "refuses to resurrect a
**paused** row" was not built and was decided against: `State.acceptsOffset`
admits `.paused` (`transfers.zig:393-410`), because that is the state a resume
starts from.

**C. End to end through `Executor.shell`** (`artifact_test.zig`) — real files,
real scripts, real `ln`:
* C1. Push and pull of a 64 MiB file: destination digest equals source digest;
  the transfer arena is wrapped in a ceiling allocator that **trips if live
  bytes exceed `4 × chunk_size`**, proving the bound is size-independent.
  Behind `-Dbig-transfer`, the same run at 2 GiB sparse. *(Agreed gate 1 —
  partially; see §5.3.)*
* C2. Resume after a cut at an arbitrary mid-chunk offset: assert (a) the
  checkpoint's `confirmed_offset` equals the last confirmed boundary, (b) the
  second run's `bytes_moved == total - resumed_from` — so a "resume" that
  silently restarts from zero fails the gate, (c) both digests match, (d) the
  first operation's terminal is `failed`/`never_submitted`, **never**
  `indeterminate`. *(Agreed gate 2.)*
* C3. Source touched between attempts → exit 1, checkpoint
  `failed_source_changed`, destination byte-identical to before, and
  `--restart` is the only thing that clears it. *(Agreed gate 3, e2e half.)*
* C4. Junk appended to the part between runs → exit 1,
  `failed_remote_partial_mismatch`, destination untouched, the failure names
  the digest that disagreed, **and the part is not truncated** (proving the
  truncation is gated on the proof). *(Agreed gate 4, e2e half.)*
* C5. Corrupt the part before publish → exit 43; make the destination an
  existing directory → exit 48; make it exist under `--no-clobber` → exit 47.
  In all three, byte-compare the pre-existing destination before and after.
  *(Agreed gate 7, two of three cases.)*
* C6. `--no-clobber` race: two real `sh` processes race `ln` against one
  destination; exactly one exits 0, the other exits 47, and the destination
  holds the winner's bytes. The `ln` primitive is doing the work, so the gate
  tests the actual mechanism. *(Agreed gate 6, local filesystem only.)*
* C7. Pre-flight `df` refusal: ask for 2^60 bytes against the real scratch
  filesystem → real exit 50, nothing transferred. *(Agreed gate 7, the
  automatable half of "disk full".)*
* C8. **Pull local-write fault**: truncate the local part between verify and
  publish → the read-back check fires, exit 1, pre-existing destination
  unchanged. This is the gate that proves D1 was not relocated to the local
  side.

**D. Ledger and concurrency** (`artifact_test.zig`, `gates_test.zig`), using
the thread pattern already at `execution_test.zig:60`:
* D1g. Two `begin`s on `{path, /srv/app/x}` → the second is `.blocked`;
  `--force` proceeds, takes the lease over from its holder, and writes a
  `forced_past_blocker` audit event carrying the displaced request id and the
  forcing machine's profile token (`execution.zig:963-990`).
* D2g. Two `transfers.create` for the same `(dest_side, dest_path)` while live
  → `error.DestinationHeld` (and `error.CheckpointAlreadyExists` for two
  checkpoints on one request), not a convention. **Landed** at
  `gates_test.zig:3840` (`:3882`, `:3899`, and the hold walked across
  `probing`/`transferring`/`verifying`/`publishing` at `:3907-3911`); the §2.7
  hole is closed by v11's partial unique index over `State.holdsDestination`
  (`migrate.zig:504-511`). Still to add there: the local-destination case — a
  pull whose scope guard is filtered by `server_id`, and a fetch that has none
  at all. *(Agreed gate 5, with the hole §2.7 names.)*
* D3g. **The submit-late boundary.** A transport failure one exec before the
  publish → exit 1 with a resumable checkpoint; a transport failure *inside*
  the publish exec → exit 75, `indeterminate_publish`, and an operation that
  still blocks its scope. This is the gate that would catch a future refactor
  moving `submitted()` back to the first byte.
* D4g. **The reconcile binding.** `filesystem_effect` with a null hash, with a
  hash that does not match `expected_sha256`, or against an operation with no
  recorded expectation → **refused**, `indeterminate` preserved. Only a
  matching hash at the recorded destination path resolves to `completed`.
  *(Closes §1.3's worst finding. **Landed** in `receipts.resolve`'s
  `.filesystem_effect` arm (`receipts.zig:2148-2178`), which compares side,
  path and digest against `transfers.expectedEffectLocked` and then refuses a
  reading that overrules a recorded verdict; gated at
  `gates_test.zig:2645-2693`. The null-hash case is now unrepresentable —
  `sha256` is `[]const u8` (`receipts.zig:879`). What is still unwritten is
  the driver half: no transfer driver exists to produce the reading.)*
* D5g. **Local publish evidence.** A pull whose local rename hits
  `PathAlreadyExists` settles `failed`, exit 1, pre-existing destination
  unchanged — never `completed`, never 75.
* D6g. **Exit 76.** A receipt write failure during settle exits 76. *(There is
  no exit-76 gate in `test/blackbox.zig` today — grep confirms; one must be
  written.)*

### 5.2 Needs a real host (live e2e)

* Real peak RSS at 2 GiB via `GetProcessMemoryInfo` on the child process
  (requires a ~15-line `psapi` `extern` block — no binding exists in the repo).
* Real ENOSPC arriving mid-append (covered locally only by the generic
  write-failure path, exit 42).
* libssh2 window / EAGAIN behaviour under a sustained multi-GiB stream. The
  repo's own comment at `Client.zig:303-308` says the blocking reader "can
  still wedge on window bookkeeping" past a few hundred KiB, and this design
  deliberately pushes gigabytes through it. This is the single largest
  technical risk and no local harness can retire it.
* Whether the exec channel matches SCP's throughput in the field.
* A remote whose `sha256sum` is busybox's.
* `ln` atomicity on NFS / SMB.

### 5.3 Agreed gates this design cannot fully satisfy

* **Agreed gate 1 (>2 GiB sparse fixture with a *recorded peak RSS*)** —
  partially. `zig build test` proves the *allocation* invariant (ceiling
  allocator, size-independent) against a real 2 GiB file through the shell
  transport. Real resident-set measurement needs a child-process handle and a
  psapi binding, and the SSH arm needs a host. **The recorded peak RSS is a
  live-e2e artifact and this document does not claim `zig build test` produces
  it.**
* **Agreed gate 6 (`--no-clobber` under concurrent race)** — satisfied for a
  local POSIX filesystem, which is where `ln`'s atomicity is a real guarantee.
  Not satisfied, and not satisfiable, for network filesystems.
* **Agreed gate 7, the "disk full" case** — the pre-flight `df` refusal is
  fully automated; a real kernel ENOSPC mid-write is not reproducible on
  Windows without a loop device.

---

## 6. Implementation order

Each step compiles, passes the whole existing suite, and names the gate that
proves it. Steps 1–3 are prerequisites for everything; do not start step 4
until §7.1, §7.2 and §7.4 are answered.

1. **Close the reconcile hole first** (§7.1). Make `filesystem_effect.sha256`
   non-optional; add the identity check in `resolve`; add
   `transfers.recordExpectedHash`. → gate **D4g**. *Done first because until
   it is, every later `indeterminate` has an unproven exit, and shipping the
   transfer before the exit would create the exact laundering path M3 exists
   to prevent.*
2. **Terminal evidence for a local publish** (§7.2). Add
   `Terminal.local_effect` with its `canSettle` arm, its
   both-fields/neither-field contradiction check, and the kind gate in
   `settle`. → gates **D5g** and the `op_state` unit tests.
3. ~~**Schema** (§7.4)~~ — **done** (`14c8a2d`, amended by `2b670a9`).
   `transfer_checkpoints` is recreated at v11 in role-based columns
   (`dest_side`/`dest_path`, `partial_path`/`partial_len`/`partial_sha256`,
   and one exhaustive `source_kind` family — `source_path` for a file,
   `source_url`/`source_etag`/`source_last_modified` for HTTP, *not* a single
   `source_locator`) plus the partial unique index `idx_checkpoints_live_dest`
   (`src/core/store/migrate.zig:443-511`); `transfers.zig` is rewritten onto
   them with `adoptLocked` and `recordExpectedHash`
   (`src/core/store/transfers.zig:2207`, `:2892`). → gates **B1–B5**, **D2g**.
4. **The transport.** `Executor.sendStream`/`recvStream`; `Client.execStreamIn`
   / `execStreamOut`; delete the six SCP/stdin functions and `"scp.c"`; fix
   `drainBoth`'s stderr-error-as-EOF. `ShellTransport`. → compiles; the
   existing exec suite still passes; the stderr fix is a new unit test.
5. **The remote programs**, as pure builders. → gates **A1–A6**. *No network,
   no transfer machinery — this step is entirely testable on its own.*
6. **`artifact.run` for push.** Plan → lease → probe → resume-check → chunk
   loop → verify → `submitted()` → publish → settle. → gates **C1**, **C3**,
   **C5**, **C6**, **C7**, **D1g**, **D3g**.
7. **`artifact.run` for pull**, with the local three-way verification and the
   destination read-back of §2.5. → gates **C8**, **D5g**.
8. **`cmd_transfer.zig` rewritten** onto `artifact.run`; `--via` removed with
   an explanatory hard error; new JSON and exit codes;
   `request reconcile --verify-artifact`. → gates **D4g**, **D6g**, and the
   blackbox JSON assertions.
9. **`cmd_sync.zig`** (§7.5): tar to a local temp *file*, push it as an
   artifact, one exec to extract into a staging directory, one exec to swap,
   one exec to prune — in that order. → the reordered `--delete` gate.
10. **Resume**, end to end, once 6–9 are green. → gates **C2**, **C4**.

---

## 7. Decisions for the programmer

Seven B-class calls. §2 is written against my recommendation in each case and
marks where. None of these is settled anywhere else in this document.

> All seven are now answered — see §7.0 for the answers and what has landed.
> The option tables below are left exactly as they were written, before the
> answers were known.
>
> Where a **Current state** paragraph has since been rewritten to record what
> landed — §7.1's and §7.4's both were — the option table and the
> recommendation under it were not. They still argue from the facts as they
> stood before the answer, so a claim inside one — §7.4's "zero rows, zero
> writers", for instance — can be contradicted by the opening paragraph of its
> own section. That is the record, not an oversight.

---

### 7.1 How to close the `filesystem_effect` laundering hole

**Current state (superseded — this landed in `212289e` and `2b670a9`).**
`ResolutionEvidence.filesystem_effect` is `{ side: transfers.Side, path:
[]const u8, sha256: []const u8 }` (`receipts.zig:874-880`), with three further
destination readings beside it (`receipts.zig:909`, `:964`, `:1023`).
`supports` is `.filesystem_effect => resolved == .completed`
(`receipts.zig:1105`), and that is now correct because the binding lives in
`resolve`: it compares side, path and digest against
`transfers.expectedEffectLocked` (`receipts.zig:2148-2162`) and then refuses a
reading that overrules an already-recorded verdict (`receipts.zig:2172-2178`);
the `.job_result` identity check is at `receipts.zig:2027`. `appliesToKind`
(`receipts.zig:1305-1307`, now exhaustive with no default arm) restricts this
variant to `transfer_push`/`transfer_pull`/`fetch`. It has constructors in the
gate suite (e.g. `gates_test.zig:2646`, `:2709`, `:5607`); what it still lacks
is a production producer — the only non-test construction of it is the receipt
serialiser's re-wrap at `receipts.zig:1412`.

**Why it blocks.** M3 creates exactly one `indeterminate`: a connection lost
inside the publish exec. Its *only* documented exit is this evidence. After a
lost publish the most likely content at the destination is the **previous**
file — so `reconcile --verify-artifact` hashing it and resolving `completed`
would release the scope barrier on a transfer that never happened. Shipping
M3a without closing this creates a laundering path that did not previously
exist, because today nothing constructs the variant at all.

| Option | Change footprint | Breakage | Data impact | Effort | Long-term cost |
|---|---|---|---|---|---|
| **A. Tighten in place** — `sha256` becomes required; `resolve` gains a `.filesystem_effect` identity arm reading `transfer_checkpoints.expected_sha256` under the same transaction; new `evidence_unverifiable` outcome; `transfers.recordExpectedHash` called before `submitted()` | `receipts.zig` ~+70, `transfers.zig` ~+25, `cmd_request.zig` ~+60 | the variant has no callers, so none | none (the checkpoint table has no rows anywhere) | ~1 day | `receipts` gains a read of `transfer_checkpoints`, i.e. a dependency from the ledger onto a domain table it did not previously know about |
| **B. New variant** — leave `filesystem_effect` alone and add `artifact_digest { request_id, path, sha256 }` with the identity check keyed on the carried `request_id`, mirroring `job_result` exactly | `receipts.zig` ~+90, plus `cmd_request.zig` | none | none | ~1.2 days | two filesystem-shaped evidence variants, one of which is dead and unprovable — the "two implementations" the project forbids, unless `filesystem_effect` is deleted in the same change |
| **C. No reconcile-by-probe in M3a** — `indeterminate_publish` is resolvable only by `operator_override`, which is already honest (it records that a human asserted it) | ~0 | none | none | 0 | every lost publish needs a human forever; the checkpoint's `expected_sha256` stays unwritten, so option A gets harder later, not easier |

**Recommendation: A, with `filesystem_effect.sha256` made required.** It is the
smallest change that makes the evidence mean what its own doc comment already
claims ("a hash matching proves the bytes landed"), it reuses the exact
identity-check pattern `resolve` already runs for `.job_result`, and B's
second variant would have to delete the first one anyway to avoid keeping an
unprovable path alive. The ledger→`transfer_checkpoints` read is the real cost
and I do not think it is avoidable: the only place the expected digest can
live is the transfer's own record.

---

### 7.2 A terminal for an artifact published on the *local* machine

**Current state.** `op_state.canSettle` (`op_state.zig:347`, the `.exited` arm
at `:357-360`) admits `.exited` only from `.submitted`/`.remote_started`, and
`.exited` is documented as "the remote reported a real exit status"
(`op_state.zig:229`). `canTransition` (`op_state.zig:195`, the `.connecting`
arm at `:204-207`) makes `connecting → completed` illegal, so an operation
that never reaches `submitted` can never complete.

**Why it blocks.** A **pull** publishes to a local path. There is no remote
process whose exit status could stand for the local rename. Today a pull has
no honest terminal at all: `.exited{0}` claims a status no process produced
(the flaw two judges found in all three input designs — one of them settles a
purely local download as `completed` with `connected = true`);
`.never_submitted` is barred by `canSettle` after `submitted`; and
`indeterminate` + exit 75 would tell an agent *not* to retry the one case
where retrying is exactly right. This is not fixable inside `artifact.zig`.

| Option | Change footprint | Breakage | Data impact | Effort | Long-term cost |
|---|---|---|---|---|---|
| **A. New `Terminal.local_effect { path, published_sha256: ?[]const u8, failure: ?[]const u8 }`** — `status()` is `completed` iff a digest is present and `failure` is null; `canSettle` admits it only from `.submitted`; `terminalEvent` returns `error.ContradictoryEvidence` when both or neither field is set; `settle` gains a kind gate (`transfer_pull`/`fetch` only), symmetric with `resolve`'s existing `appliesToKind` | `op_state.zig` ~+45, `receipts.zig` ~+35, tests ~+80 | none — no existing caller can construct it | one new value in the `status` vocabulary? No: it maps to existing statuses. No schema change | ~1 day | one more evidence variant, fenced by type and by kind |
| **B. Stretch `.exited`** — settle a pull with `.exited{0}` and put the local detail in `detail_json` | ~0 | none | none | 0 | the ledger records a remote exit status and `connected = true` for work no remote performed. `terminus request show` — the audit surface transfers are being redirected to — would read `completed` on evidence that does not exist. This is the flaw M3 is supposed to remove, reintroduced |
| **C. Defer pull to M3b** — M3a ships push only; `terminus pull` keeps SCP | SCP survives | none now | none | −2 days now, +3 later | keeps **D1** (the truncation-as-success defect) alive, keeps two transports and the fallback ladder alive, and D1 is the worst confirmed defect in the repo |

**Recommendation: A.** B is the exact lie this milestone exists to delete, and
C keeps the worst defect shipping. A adds one variant, and unlike the version
one input design proposed (a failure-only, free-text
`local_effect_failed`), this one carries the **published digest** on the
success path, so `completed` for a pull rests on a re-read of the destination
rather than on a rename returning 0. The kind gate in `settle` is what makes
"exec and job cannot reach it" a type-and-data guarantee rather than a
convention.

---

### 7.3 HTTP fetch: in M3a, or deferred to M3b?

**Current state.** The approved plan puts HTTP fetch in M3 ("HTTP fetch
reuses the same receipt/checkpoint model", parallel Range requests with
206/`Content-Range`/length/ETag validation). `operations.Kind.fetch` and the
`source_url`/`source_etag`/`source_last_modified` columns exist and are
unused. This repo has **zero** prior `std.http` usage.

**Why it blocks.** Three things make it a research task rather than an
implementation task: (1) TLS plus the Windows system certificate store plus N
threads each holding a connection is exercised by nothing in this repo, and
the natural gate (a plaintext in-process `std.http.Server` over loopback)
tests none of it; (2) parallel Range writes make an in-stream digest
impossible, so `--sha256` must re-read the assembled file, and out-of-order
chunks leave a partial longer than the confirmed prefix that must be truncated
before `verifyResume` will accept it; (3) with no trustworthy validator there
is no honest `completed`, which forces either a refusal or a new ledger status
— and `completed_unverified` is no longer unreachable: a push or pull that
declares no digest and is killed mid-publish now settles there via
`destination_present_unverified` (`transfers.zig:564`, `receipts.zig:1848`,
ledger verdict at `receipts.zig:1129`, gated at `gates_test.zig:5573-5642`),
so fetch would add no new ledger status.

| Option | Change footprint | Breakage | Data impact | Effort | Long-term cost |
|---|---|---|---|---|---|
| **A. Defer to M3b** | none — the columns, the `Kind` value and the `Source.http` arm are shaped now and left unconstructible | `terminus fetch` does not ship in 0.2.0 unless M3b lands first | none | 0 now | 4 unused enum values and 5 unused columns persist a while longer; `contiguousPrefix` stays unexercised in production |
| **B. Ship it in M3a** | +~350 lines (`fetch.zig`, ranged GET, four validators, parallel placement), +~200 gate lines, plus the HTTPS-on-Windows unknown | none | none | +3–5 days, with the widest error bars in the whole milestone | the milestone's riskiest surface lands next to its riskiest transport (libssh2 bulk streaming), so a failure in either blocks both |
| **C. Ship a sequential, single-range, validator-required fetch** — no parallelism, refuse when there is no strong validator | +~180 lines | none | none | +1.5 days | the parallel design still has to be built later, and the sequential version's resume path is a second thing to migrate |

**Recommendation: A.** M3a already deletes both live transports in one change;
adding an unproven third protocol to the same commit means that if the exec
channel wedges under bulk traffic (the live-e2e risk in §5.2), there is no
transfer at all and no way to bisect which half broke. C is tempting but its
resume path would be rewritten by the parallel design anyway. Defer, keep the
`Source.http` arm and the columns shaped for it, and take the "4 dead enum
values persist" cost knowingly.

---

### 7.4 How to reshape `transfer_checkpoints`

**Current state (this section is now history — option A landed as v11 in
`14c8a2d`).** The v6 DDL survives frozen at `migrate.zig:195-224`, naming the
source `local_*` and the partial `remote_partial_*`, with `remote_path NOT
NULL` and a non-unique `(remote_path, state)` index (`migrate.zig:224`) —
names that are correct for push and an active lie for pull, and a `NOT NULL`
that made a local-destination transfer structurally impossible. A
`source_size` column already existed, so a naive `local_size → source_size`
rename was invalid SQL. The live shape is v11 at `migrate.zig:440-511`:
`dest_side`/`dest_path` (`:449-450`), `partial_path`/`partial_len`/
`partial_sha256` (`:451-453`), a `source_kind` family with its own CHECK
(`:455`, `:479`), `UNIQUE(request_id)` (`:445`) and the partial unique index
over the destination-holding states (`:504`). `latest_version` is
`migrations.len` (`migrate.zig:516`) and the chain runs to **v11**
(`migrate.zig:402`, DDL at `:440`). The table now has writers —
`transfers.create` (`transfers.zig:1183`), `setState` (`:1720`),
`confirmOffset` (`:1642`), `recordExpectedHash` (`:2892`),
`recordVerifiedHash` (`:3091`), `adoptLocked` (`:2207`), `supersedeLocked`
(`:2545`) — and rows do exist; see the census at §7.0.1. `Store.open` refuses
a pre-v11 store carrying checkpoint rows with `error.CheckpointsWouldBeDropped`
rather than recutting over them (`migrate.zig:759`, refusal at `:790-799`, gated at
`gates_test.zig:1869`).

**Why it blocks.** §2.5 (pull's partial is local), §2.6 (F4, F5) and §2.7 (the
partial unique index that is the only guard a local destination gets) all
depend on the column shape. Nothing in M3a can be built against the current one.

| Option | Change footprint | Breakage | Data impact | Effort | Long-term cost |
|---|---|---|---|---|---|
| **A. New v11 step** that drops and recreates the table with role-based columns and the partial unique index; v6 text stays frozen in the chain | `migrate.zig` ~+50 | none | **not nil in general** — a developer database below v11 whose `transfer_checkpoints` is *empty* upgrades in place with no action (`gates_test.zig:1918-1933`); one holding any row is refused outright with `error.CheckpointsWouldBeDropped` (`migrate.zig:679-689`, gated at `gates_test.zig:1878-1916`) and must be dealt with by hand | ~0.5 day | one more migration step, and dead v6 DDL that every fresh database still walks through |
| **B. Edit v6 in place** and extend `checkPreReleaseDrift` (`migrate.zig:422`) to detect the old `remote_partial_path` column | `migrate.zig` ~+25 | **every existing developer database is rejected on next run** and must be deleted and recreated — including the live e2e fixture, which per `MEMORY.md` holds the only surviving test SSH key | nil for the table; **the e2e fixture must be backed up first** | ~0.3 day + the fixture dance | none; the chain stays clean |
| **C. Additive only** — keep the old columns, add `dest_side`/`dest_path`/`partial_*` beside them | `migrate.zig` ~+30 | none | none | ~0.4 day | two column families for one concept, forever, and `verifyResume` has to decide which to trust — the compatibility-branch pattern the project forbids |

**Recommendation: A.** B is cheaper on paper and the module's own doc
(`migrate.zig:416-421`) blesses pre-0.2.0 in-place edits, but it forces a
delete-and-recreate of every dev database, and `MEMORY.md` records that the
live e2e fixture's SSH key exists **only** inside a real `terminus.db`. Making
a schema-tidiness decision that risks that key is a bad trade for one dead DDL
block. C is out on principle. Note that A means writing "drop and recreate" DDL
— which is C-class if any of these databases were production. They are not
(zero rows, zero writers), and I am flagging it rather than assuming.

---

### 7.5 What happens to `terminus sync`

**Current state.** `cmd_sync.zig` is a caller of **every** transport being
deleted: `scpSendBytes` (`:177`), `transfer.pushBytes` (`:178`),
`scpRecvBytes` (`:246`), `transfer.pullBytes` (`:247`). It also has its own
md5 verify (`:169-171`, `:251-255`), its own `validateRemotePath` (`:278`), the
in-memory tar (`:137`), and D8's destroy-before-extract (`:183`, `:186-193`).
It cannot be left alone.

**Why it blocks.** `artifact.Plan` describes a *file* with a size, an mtime and
a digest. A streamed tar of a live tree has none of those until it is finished,
so sync cannot resume and cannot be a plain `artifact.run` call without first
materialising the archive. Leaving it on a private copy of verify+publish is
the "second implementation" the project forbids.

| Option | Change footprint | Breakage | Data impact | Effort | Long-term cost |
|---|---|---|---|---|---|
| **A. Port it**: tar to a local temp *file*, push that file as an artifact, then one exec to extract into a staging dir, one to swap, one to prune | `cmd_sync.zig` 281 → ~260, all of it rewritten | temp paths change; `--delete` reorders; `verified` changes meaning from "archive md5 matched" to "archive sha256 matched and the extraction exited 0" | none | ~1.5 days | tree materialisation is a second destination-publish path (`tar -x` + swap) alongside `ln`, so §5.1's A1 invariant covers files but not trees. Disclosed, not hidden |
| **B. Delete `terminus sync` in M3a**, reintroduce in M3b on the artifact primitive | `cmd_sync.zig` deleted, `dispatch.zig` −1 | the command disappears from 0.2.0 unless M3b lands | none | −1.5 days now | a user-visible command vanishes mid-milestone-series; pre-1.0 makes that permissible, but it is a product call, not a technical one |
| **C. Keep a private copy of verify+publish inside sync** | ~0 | none | none | 0 | two verify implementations, two publish implementations. Forbidden by the project's own rules |

**Recommendation: A.** C is not an option. Between A and B: A is only ~1.5 days
and it deletes more than it adds, and it removes D8 (destroy-before-extract),
which is a real data-loss bug that would otherwise ship. The honest cost is the
one I have named — trees publish through `tar -x` + swap, not through `ln`, so
they get a weaker structural guarantee than files do. That is worth stating in
the release notes and revisiting in M4.

---

### 7.6 The `history` table loses its last two writers

**Current state.** `Store.history.add` has exactly two callers repo-wide:
`cmd_transfer.zig:77` and `cmd_sync.zig:59`. Both are deleted (§3, D4). After
M3a the `history` table has **zero writers**, while `terminus history`
(`cmd_history.zig`, registered in `dispatch.zig`) and `history.list` remain as
readers of a table nothing fills. Separately, `history.redactSecrets` has four
live callers — `cmd_exec.zig:88`, `cmd_job.zig:145`, `cmd_job.zig:329` and
`receipts.zig:1491` — so `history.zig` itself is **not** dead.

**Why it blocks.** Nothing technical — M3a works either way. It is on this list
because "a reader of a table nothing writes" is exactly the long-lived dead
surface §6 of `CLAUDE.md` says to report rather than quietly keep.

| Option | Change footprint | Breakage | Data impact | Effort | Long-term cost |
|---|---|---|---|---|---|
| **A. Leave it** | 0 | none | existing rows preserved | 0 | a command that shows an ever-staler snapshot and silently stops covering new work |
| **B. Repoint `terminus history` at the `operations` ledger** (a filtered `request ls`) | `cmd_history.zig` ~+60, `history.zig` `add`/`list` deleted, table dropped in the same migration as §7.4 | `terminus history` output shape changes; historical rows are lost unless migrated | **existing rows would be dropped** — needs your call on whether any dev database's history matters | ~0.7 day | one durable record of "what was done here", which is what M2 built the ledger to be |
| **C. Delete `terminus history` outright** | `cmd_history.zig` deleted, `dispatch.zig` −1, table dropped | the command disappears | rows dropped | ~0.2 day | one fewer surface; `request ls` covers exec, job and now transfers |

**Recommendation: B**, but **not in M3a** — schedule it for M4. It is
independent of everything in §2–§6, and bundling a table drop into the
milestone that also drops and recreates `transfer_checkpoints` makes both
harder to review. If you would rather not carry a writerless table through
0.2.0, C is defensible and cheap. Either way, please say which, because A is a
decision too and it should be a deliberate one.

---

### 7.7 Where the streaming seam lives

**Current state.** `Executor` (`exec.zig:9`) has three arms
(`direct`/`daemon`/`scripted`) and two methods, `exec` (`exec.zig:19`) and
`errorMessage` (`:27`). Transfers today bypass
it entirely and hold a raw `*Core.Ssh` (`cmd_transfer.zig:44`,
`cmd_sync.zig`). `Scripted` (`exec.zig:37`) is a production-union test double
with an in-source justification at `exec.zig:12-16`, and it is the backbone of
the in-process suite (`execution_test.zig`, `session/Tmux.zig`).

**Why it blocks.** Two of the three input designs declared
`run(execution, client: *Ssh, ...)` and then proposed gates that inject a
double into it. That does not compile, and it silently deletes the *entire*
in-process gate suite for the states that matter (`D3g`, `C2`, `C4`, `D5g`).
Whatever `run` takes must be injectable.

| Option | Change footprint | Breakage | Data impact | Effort | Long-term cost |
|---|---|---|---|---|---|
| **A. `Executor` gains `sendStream`/`recvStream` and a `.shell` arm**; `daemon` returns a named `error.StreamingUnsupported`; the CLI refuses the daemon transport for transfers *before* building the executor | `exec.zig` ~+120 (incl. `ShellTransport`), `Client.zig` +2 functions | none | none | ~1 day | one dispatch union with 4 arms and 4 methods; two of the arms are test doubles; the daemon arm carries a method it can never implement |
| **B. A separate `artifact.Transport` union** (`ssh`/`shell`/`scripted`) beside `Executor` | new ~80 lines | none | none | ~0.8 day | two dispatch unions covering overlapping transports; the number of paths does not actually rise (transfers bypass `Executor` today), but a reader now has to know which union applies where |
| **C. `run` takes `*Ssh`**, and every gate that needs fault injection moves to the live e2e | ~0 | none | none | 0 now | the submit-late boundary, resume, the polluted-partial refusal and the local-publish evidence are all ungated locally. This is what caps every input design's buildability score |

**Recommendation: A.** C is not acceptable — it un-gates the specific
behaviours this milestone exists to guarantee. Between A and B, A keeps one
definition of "how a command reaches a host", which is the same argument
`scope.zig:1-6` makes for having one definition of overlap. The honest cost is
that `daemon` gains two methods it can only refuse; I would rather have a
named, loud `StreamingUnsupported` that the CLI is structured never to reach
than a second union that makes "which dispatch path is this" a question with
two answers.

---

## 8. Cost, and what this does not solve

### 8.1 Cost

Calibrated against this codebase's actual density (`cmd_job.zig` is 1406 lines
for comparable ledger orchestration; `gates_test.zig` is 1820 for the ledger's
rules alone; `execution_test.zig` is 892). The input designs estimated
"2–3 focused days" and "~520 lines" for the state machine; both are roughly
2× optimistic, and I am not repeating them.

| File | Δ |
|---|---|
| `src/core/artifact.zig` (new) | +~700 |
| `src/core/artifact/remote.zig` (new — the three programs + the escaper + the ack parsers) | +~250 |
| `src/core/exec.zig` (streaming methods, `ShellTransport`) | +~200 |
| `src/core/ssh/Client.zig` | −208 / +~140 |
| `src/core/transfer.zig` | −110 |
| `src/core/store/transfers.zig` | ~220 of 510 rewritten, +~90 (`adopt`, `recordExpectedHash`, the `changes()` checks, the source union) |
| `src/core/store/migrate.zig` | +~55 (v11) |
| `src/core/store/op_state.zig` | +~45 (`local_effect`) |
| `src/core/store/receipts.zig` | +~105 (`local_effect` arm, the `filesystem_effect` identity check, the kind gate in `settle`) |
| `src/cli/cmd_transfer.zig` | 185 → ~280, rewritten |
| `src/cli/cmd_sync.zig` | 281 → ~260, rewritten |
| `src/cli/cmd_request.zig` | +~70 (`--verify-artifact`) |
| `build.zig`, `core.zig`, `dispatch.zig` | ~±10 |
| Gates: `artifact/remote_test.zig`, `artifact_test.zig`, `test/blackbox.zig` | +~900 |

**Net: roughly +2,900 / −600.** Six to ten working days for someone who
already knows this codebase, with the error bars concentrated entirely in
step 4.

**The hardest part, by a distance, is `execStreamOut` under blocking libssh2.**
`drainBoth`'s own comment (`Client.zig:303-308`) records that callers keep a
single command's stdout "under a few hundred KiB" because "beyond that
libssh2's blocking reader can still wedge on window bookkeeping" — and pull
deliberately pushes gigabytes of stdout through one channel. The design's
answer is that the described wedge is a stdout/stderr interleaving deadlock,
which `execStreamOut` avoids by construction (it never reads one stream to EOF
before the other) and by never buffering (continuous draining is what keeps
the receive window moving). **If that turns out to be wrong, the mitigation is
a smaller chunk constant, not a second code path** — and it is why §7.3
recommends not landing HTTP fetch in the same commit.

Second hardest: the interrupted-transfer fork. Deciding between "proven
failure, destination untouched, exit 1" and "we could not go and look, exit
75" requires a re-probe on a fresh channel after the session may already be
damaged, and requires that a failed re-probe is never mistaken for a clean
answer. Submit-late shrinks this enormously — after submit-late the fork only
matters *inside* the publish exec — but it does not remove it.

### 8.2 What M3a does not solve

* **HTTP fetch** (§7.3). Four `operations.Kind`/`transfers.State` values and
  five columns stay unused; `contiguousPrefix` stays unexercised in production
  (its unit test at `transfers.zig:400` is all it has).
* **Parallel anything.** Push chunks are strictly sequential; pull is one
  stream. That is what makes an in-stream digest possible.
* **Resumable directory sync.** A tree is materialised into one archive and
  pushed as one artifact; interrupting it restarts the archive. Resumable
  per-file sync is an M4+ shape.
* **Throughput.** Nothing here measures the exec channel against SCP. The
  argument that they are the same `libssh2_channel_write_ex` calls is
  structural, not empirical.
* **The libssh2 bulk-streaming risk** (§5.2). No local harness retires it.
* **`ln` on network filesystems** (§2.7). Not claimed, not gated.
* **Real ENOSPC mid-write** (§5.3).
* **Real peak RSS** (§5.3) — the allocation invariant is gated locally; the
  measurement is a live-e2e artifact.
* **`history`** (§7.6) — deliberately left for M4.
* **Symlink and FIFO destinations** (§4) behave differently now, and there is
  no `--follow-symlinks` to restore the old behaviour. If someone needs it,
  that is a new flag with its own decision, not a compatibility branch.
* **A root-owned foreign writer** can still modify the staging file between
  the `chmod 0400` and the `ln`. `chmod 0400` closes the window to everyone
  else; nothing in userspace closes it to root, and the read-back at exit 49
  narrows but does not eliminate it.
