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

**Settled, and the residual risk moved into the code.** The audit below was
run before the drop-and-recreate DDL was written; it found no checkpoint row
in any store outside this repo's test scratch, and the v11 migration records
that in its own comment (`src/core/store/migrate.zig:413-418`). A database
this census never reached is no longer covered by the audit but by a refusal:
`checkBeforeApply` returns `error.CheckpointsWouldBeDropped` for any store
below v11 that still holds checkpoint rows, and runs before `apply` rather
than after it, so such a store is refused rather than silently emptied
(`migrate.zig:626-630, 679-689`).

### 7.0.1 The store census (read-only, 2026-08-14; re-run 2026-08-15)

Reproduce with exactly this:

```
python tools/enumerate_stores.py --json docs/evidence/store-census.json
```

The artifact that command writes is at `docs/evidence/store-census.json` —
regenerated 2026-08-15 and **not yet committed** (`docs/evidence/` is
untracked, and `tools/enumerate_stores.py` has uncommitted changes, so
re-running from HEAD produces the older JSON shape) — and every number below is
in it. Commit both, or this section's evidence is not reproducible from the
repository. The script prints its own scope, which is the
point: the first version of this audit was an ad-hoc command whose answer —
"there is no non-test row anywhere" — was unfalsifiable, and wrong in two
places besides.

**The scope is part of the claim, so it is stated inside the claim.** Seven
roots were searched — `%APPDATA%/terminus`, `%TEMP%`, `~/.terminus`,
`~/Desktop`, `~/Downloads`, `~/Documents`, and this repo — to a depth of six
directories below each, skipping `node_modules`, `.git`, `.venv`, `venv`,
`__pycache__` and `.codegraph` by directory name and `AppData/Local/Google`,
`AppData/Local/Microsoft`, `AppData/Local/Mozilla`, `playwright_chromium`,
`pw-apply-profile`, `codex-apply-extension` by path fragment. An eighth root,
`%LOCALAPPDATA%/terminus`, does not exist on this machine and was therefore
**not** searched; the script now reports absent roots rather than dropping
them, so a mistyped `--root` can no longer yield a confident census of
somewhere else. Three directories refused to open
(`%USERPROFILE%/Documents/My Pictures`, `My Music`, `My Videos`), two files
refused on permission, and eighteen directories vanished mid-walk under a
concurrent build; those 23 paths are holes and each is listed with its error
in the artifact's `unexaminable`. So everything below is quantified over *the
databases those seven roots reach at that depth* — never over "this machine".

A file counts as a Terminus store when it has the
`servers`+`keys`+`memories`+`facts` tables, and it becomes a candidate by
carrying the 16-byte SQLite header rather than by being named `*.db`. The old
name filter was a hole on its face: a copy can be called anything, and most of
the SQLite databases under these roots are named something other than `*.db` —
some of them are called `Login Data`. That breakdown is not in the artifact and
never has been: the script states it in a docstring
(`tools/enumerate_stores.py:266`) and does not compute it, so it is an argument
here rather than a number. Of **106,827** files seen, 100,218 were rejected on
size alone (a whole SQLite database is an exact number of pages, so its size is
always a non-zero multiple of 512), 6,379 were opened and sniffed — two of
which could not be read at all and are recorded in `unexaminable` as holes —
**417 carry the SQLite header**, and **113 of those are Terminus stores**: 8
listed one by one and 105 repo-scratch stores with no checkpoint row,
summarised. Not one SQLite file refused to open: the 306 "unreadable"
candidates the first census reported were files that are not databases at all,
which is not evidence of anything. That distinction is kept — a database that
will not open is a hole and is printed loudly; a file that was never a database
is merely counted.

| Store | `user_version` | `transfer_checkpoints` | rows |
|---|---|---|---|
| `%APPDATA%/terminus/terminus.db` — the real one, 363,249,664 bytes | **4** | absent | — |
| `%TEMP%/f0.db`, `%TEMP%/t.db` — empty dev scratch | 11 | yes | 0 |
| `%TEMP%/t0.db` — empty dev scratch, table present at version 0 | 0 | yes | 0 |
| 4 × `<repo>/.zig-cache/tmp/gate_*.db` — gate scratch | 10–11 | yes | **1** each |
| 105 × `<repo>/.zig-cache/tmp/*.db` — gate scratch, summarised | — | — | 0 |

Four stores sit outside this repo's test scratch and not one of them holds a
checkpoint row; 109 are repo scratch and four of those do. Stores in the
scratch that hold no row are summarised as a count rather than listed, because
a full test run leaves dozens and the only interesting fact about them is
which hold a row. Every path in the artifact is tokenised (`<repo>`, `%TEMP%`,
`%APPDATA%`, `%USERPROFILE%`, `<user>`), so no absolute path or account name
is committed.

**All four checkpoint rows are gate fixtures, and all four are in this repo's
test scratch.** Their request ids are `PVSH0000000000000000000000` (twice),
`ABSENT00000000000000000000` and `PR0CPVSH000000000000000000` — what
`testId()` returns for the labels `push`, `absent` and `procpush` once it maps
`O`→`0` and `U`→`V` (`src/core/store/gates_test.zig:278`) — and no real ULID
is shaped like that. The census copies request ids into the artifact, so that
sentence can be checked by reading the JSON instead of being taken on trust;
it deliberately copies nothing else about the row, so the id shape is the
whole of the claim.

**The one checkpoint row this audit found outside the repo's scratch is gone
with its file.** `%TEMP%/rotest.db` — a dev store at `user_version` 10 holding
a single fixture row, created and last written 2026-08-14 14:02:17, which no
test, tool or script in this repo names — was deleted between the 2026-08-14
census and its 2026-08-15 re-run, and does not appear in the regenerated
artifact. It is the reason the first run of this census exited 1 and the
reason the second exits 0. What wrote it was never established, and now cannot
be.

**Two stores were missed by the first audit, not three.** `%TEMP%/v4copy.db`
(created 2026-08-13 15:32:14) and the OCP-Catalog store (created 2026-07-28
13:19:26) both existed when that audit ran and neither appears in its table.
`%TEMP%/rotest.db` was not missed, because there was nothing there to find:
Windows records its creation at 2026-08-14 14:02:17, 75 minutes after the audit
was committed (`2f86f89`, 12:47:21 +0800).

**The census is a gate, and it is now green.** It exits 1 when a checkpoint
row exists in any store outside this repo's `.zig-cache` scratch — precisely
the condition under which the v11 drop-and-recreate would destroy something
(`tools/enumerate_stores.py:533, 585-588`). No store outside the repo's
scratch holds one: the four such stores are three empty `%TEMP%` dev scratch
databases and the real store, which has no `transfer_checkpoints` table at
all. So the run above exits 0, and that is what cleared the v11 DDL to be
written.

**What "read-only" is measured to mean, rather than asserted to mean.** Every
candidate's `.db`, `-wal` and `-shm` is digested — size, mtime_ns, and SHA-256
of the file or of its first and last 4 KiB — before the run and again after. In
the run recorded in that artifact, **205** `-shm` files changed mtime — the
only category in `filesystem_effect.by_category` — across the **1,251**
database, `-wal` and `-shm` files digested before and after, and **no database
file changed in size, mtime or content, and no `-wal` gained a byte**. That is the
entire effect. A `mode=ro` reader of a WAL-mode database does create an empty
`-wal` and a 32 KiB `-shm` where none existed, and does move read marks inside
an existing `-shm`: an earlier run of this same script created 85 empty `-wal`
and 92 `-shm` sidecars that way. "Nothing was written" is therefore true of
business data and false of the filesystem taken literally, and the census
cannot tell its own effect from a concurrent writer's — which is why it reports
the difference instead of promising there isn't one.

**The two plaintext copies this audit found are gone.** `%TEMP%/v4copy.db` —
361,644,032 bytes, `user_version` 7, 12 rows in `keys` — and the second real
store under `~/Desktop/drafts/OCP-Catalog/.codex-work/terminus/`, which held
11 more, were both deleted between the 2026-08-14 census and its 2026-08-15
re-run: neither file is on disk and neither appears in the regenerated
artifact, whose only store with key material is the real one (`keys: 12`).
Terminus still stores private keys and passphrases in plaintext, so what
stands is the hazard rather than the instance: the only surviving copy of the
e2e fixture key recorded in `MEMORY.md` now lives in the real store alone, and
any future copy of that store is twelve private keys in whatever directory it
is left in.

**Two things follow for the migration.** The real store has never been opened
by a 0.2.0 build — it is still `user_version` 4 and has no
`transfer_checkpoints` at all — so it will run v5 → v11 in one go the first
time anything touches it, creating the table at v6 and replacing it at v11
with nothing in it. And the migration must still be correct for a store that
stopped anywhere in v6–v10: two of the eight individually enumerated stores
are exactly that, both repo scratch at v10, and both hold a fixture row. The
versions of the 105 summarised scratch stores are not in the artifact. For
those stores the rule is no longer "be correct" but "refuse":
`checkBeforeApply` returns `error.CheckpointsWouldBeDropped` before any DDL
runs (`src/core/store/migrate.zig:679-689`).

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
write error swallowed. `src/cli/cli.zig:222` already names this pattern as the thing `receiptFatal`
(`src/cli/cli.zig:226`) exists to replace.

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
lines with 13 tests at `:3138-3708`, called by `execution.zig:424`/`:486`/
`:491`/`:506` and by `receipts.resolve` at `receipts.zig:2149`/`:2231`/
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
source for a pull, matching the scope §2.9 binds. A lease is always a claim
inside one server's namespace (`leases.server_id` is `NOT NULL REFERENCES
servers(id)`, `migrate.zig:276`; `AcquireOptions.server_id` is `i64`,
`leases.zig:82`), so it cannot hold a *local* destination at all. For a pull
or a fetch the destination is local, and the only thing standing on it is
`idx_checkpoints_live_dest` — "the only collision guard a locally-published
transfer gets" (`transfers.zig:91-97`). `execution.begin` consults
`leases.conflictForLocked` through `blockerLocked` (`execution.zig:260`,
reached from `begin` at `:790`) and `submitted()` re-checks it under the write
lock (`execution.zig:343`), so a peer is refused at both ends; the lease expires on its own if we die; `--force` overrides through the
existing audited path. No new mechanism.

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
other, are `execution.Execution.adoptCheckpoint` (`execution.zig:411-428`). A
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
| `begin` | `blockerLocked` (`execution.zig:224-266`) — `unsettledInScope` at `:235`, `leases.conflictForLocked` at `:260` — reached from `begin` at `execution.zig:790` | a peer already working this scope in this realm (a server, or — when `server_id` is null — this machine); refuses before dialing, and only against a *mutating* caller (`execution.zig:791`, `:344`). Its unsettled half counts only peers that declared `mutating = 1` (`holds_scope_predicate`, `operations.zig:290`) — the lease half is the only one blind to the peer's own flag |
| `create` | `idx_checkpoints_live_dest`: `UNIQUE INDEX ON transfer_checkpoints(dest_side, dest_path)` over `State.holdsDestination` — **thirteen** states, not four: the six live ones, all six `failed_*`, and `indeterminate_publish` (`migrate.zig:504-511`, rendered from `transfers.zig:129-150`) | **any** second live transfer to the same destination on this machine, including pull and fetch, where `server_id` is null — today only `fetch`, since §2.9 gives a pull the remote host's id. The operation half of the guard *does* run in that realm: `blockerLocked` takes a `?i64` and null names the local realm rather than switching the check off (`execution.zig:206-266`). What the local realm cannot have is a *lease* — `leases.server_id` is `NOT NULL REFERENCES servers(id)` (`migrate.zig:276`) and `conflictForLocked` takes a plain `i64` (`leases.zig:154-157`), so `execution.zig:260` skips that half. A failed transfer goes on holding its destination until `supersedeLocked` (`transfers.zig:2545`) releases it |
| `submitted()` | the scope guard re-checked under the write lock (`execution.zig:343`, inside `submitted`'s `BEGIN IMMEDIATE`) | the last-moment race between two racers that both cleared `begin` |

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
| any ledger write fails | `Cli.receiptFatal` (`cli.zig:226`) | — | **76** (`exit_code.receipt_persist_failed`, `cli.zig:168`) |

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
`cmd_job.zig:141`, `cmd_job.zig:325`, and `receipts.zig:1491`, the `redact`
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
| transfers now take a `path` scope and a lease | anyone running two pushes to overlapping paths | the second is refused with "nothing was sent"; `--force` overrides and is audited |
| `sync push --delete` prunes **after** a verified extraction | anyone relying on the old destroy-first ordering | none needed; the destination is no longer deleted before its replacement exists |
| remote temp paths change | scripts watching `/tmp/.terminus_sync_<ts>.tar` | single-file transfers stage at `<dir>/.<name>.terminus-part`; sync stages under a request-id-derived path |
| library surface: `Ssh.Progress`, `scpSend`, `scpSendBytes`, `scpRecvBytes`, `scpRecv`, `execWithStdin`, `Core.transfer.*` disappear | in-repo callers only (all rewritten) | `Core.artifact.run` |
| **schema**: `transfer_checkpoints` dropped and recreated at v11 (§7.4) | a developer database below v11 that holds checkpoint rows | delete the rows, or the database. An empty pre-v11 table migrates in place; one with rows is refused at open with `error.CheckpointsWouldBeDropped` (`migrate.zig:679-689`) rather than silently emptied. The real store has no `transfer_checkpoints` at all and migrates v4 → v11 in one go |
| `leases.TakeoverOutcome.taken.from` is `[]const Lease`, not `Lease` | any caller reading who was displaced | iterate. A takeover displaces *every* lease overlapping its scope, and `acquire` permits any number of mutually non-overlapping ones, so a takeover of `path:/srv/app` seizes both `path:/srv/app/dist` and `path:/srv/app/build`. Newest first, never empty — displacing nobody is `.acquired` (`leases.zig:389-406`, field at `:403`) |
| `leases.takeover` returns `TakeoverError!TakeoverOutcome`, not `Error!` | any caller switching exhaustively on the error set | handle `error.LeaseVanishedDuringTakeover`: the release UPDATE matched no row under the write lock, which is proof the lock is not doing what the rest of the function assumes. Declared on `takeover` alone rather than widened into `Error`, so no other lease caller sees it (`leases.zig:387`, `:426`) |
| `leases.insertLocked` takes `supersedes: []const i64`, not `?i64` | in-module callers only (`leases.zig:252`, `:456`) | pass `&.{}` for a plain acquisition, `displaced_ids.items` for a takeover. Every displaced row is linked through `superseded_by`, so a seizure cannot leave a lease that ends with no successor recorded and reads as an expiry (`leases.zig:288-294`) |
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
  `--force` proceeds and writes a `forced_past_blocker` audit event.
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
rather than recutting over them (`migrate.zig:679-689`, gated at
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
readers of a table nothing fills. Separately, `history.redactSecrets` has three
live callers (`cmd_exec.zig:88`, `cmd_job.zig:120`, `cmd_job.zig:289`) and
`receipts.zig:731`, so `history.zig` itself is **not** dead.

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
(`direct`/`daemon`/`scripted`) and one method (`exec`). Transfers today bypass
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
