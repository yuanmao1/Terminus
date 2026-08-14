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
| 7.4 | reshaping `transfer_checkpoints` | **A** — new migration, drop and recreate | not started; gated on the row-count audit below |
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

**Still open before §7.4 can be implemented:** the claim that
`transfer_checkpoints` is empty everywhere rests on "the current source has no
writer", which does not establish anything about databases written by earlier
builds or by hand. The real database must be enumerated read-only and its row
count established before any drop-and-recreate DDL is written.

### 7.0.1 The row-count audit (read-only, 2026-08-14)

Every SQLite database on this machine that could be a Terminus store was
opened with `mode=ro` and counted. Nothing was written.

| Database | `user_version` | has `transfer_checkpoints` | rows |
|---|---|---|---|
| `%APPDATA%/terminus/terminus.db` (the real one, 362 MB) | **4** | **no — the table does not exist** | — |
| `%TEMP%/m1test.db` (M1 dev store) | 7 | yes | 0 |
| 14 × `.zig-cache/tmp/*.db` (gate scratch left by crashed runs) | 9–10 | yes | 2 total |

The two rows are in `gate_job_evidence_kind_*.db`, written minutes earlier by
the transfer gate in this repo's own test run. There is no non-test row
anywhere.

Two things follow. The drop-and-recreate is safe — this is now established
rather than inferred. And the real store has never been opened by a 0.2.0
build at all: it will run v5 → v11 in one go the first time one touches it,
creating `transfer_checkpoints` at v6 and replacing it at v11 with nothing in
it. The migration still has to be correct for a store that stopped anywhere in
v6–v10, because the dev stores above are exactly that.

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
write error swallowed. `src/cli/cli.zig:197` already names this pattern as the
thing `receiptFatal` exists to replace.

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
(`src/core/store/operations.zig:32-34`) have zero users;
`transfer_checkpoints` (`src/core/store/migrate.zig:195-224`) has zero writers
repo-wide; `ResolutionEvidence.filesystem_effect`
(`src/core/store/receipts.zig:618`) has zero constructors.

**D10 — zero test coverage of the live transfer path.** The four tests in
`src/core/store/transfers.zig:400-510` cover a module nothing calls.

### 1.2 Confirmed dead code

| Symbol | Location | Evidence it is dead |
|---|---|---|
| `Client.execWithStdin` | `src/core/ssh/Client.zig:258` | zero callers; its doc at `:250-252` claims "this is how exec-based file transfer moves bytes" (false — `transfer.zig` puts data in the *command string*), and `:254-257` claims the 30 s timeout stays armed while `:286` sets it to 0 |
| `Client.scpSend` | `:359` | zero callers; the only streaming push (1 MiB buffer) in the repo |
| `Client.scpRecv` | `:467` | zero callers; carries D1's shape at `:492` |
| `Client.Progress` | `:351` | only used by the two dead functions |
| `src/core/store/transfers.zig` | whole file | 510 lines, 4 passing tests, zero callers outside the `Store` re-export |
| `operations.Kind.transfer_push/transfer_pull/fetch` | `operations.zig:32-34` | never constructed |
| `ResolutionEvidence.filesystem_effect` | `receipts.zig:618` | never constructed |

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
* **`transfers.zig` is push-shaped and fail-silent.** `create`'s INSERT
  (`transfers.zig:155-163`) omits `remote_partial_sha256`, so it is always
  NULL; `confirmOffset` then writes
  `remote_partial_sha256 = COALESCE(?3, remote_partial_sha256)`
  (`transfers.zig:347`), so a caller passing null leaves it NULL forever and
  `verifyResume`'s prefix-hash branch (`transfers.zig:324-329`) is dead code.
  `confirmOffset` also hardcodes `state = 'transferring'` (`:348`), silently
  un-pausing a paused row, and neither it nor `setState` (`:360`) checks
  `changes()` — contrast `receipts.zig:923-928`, which does. `findResumable`
  (`transfers.zig:250`) keys on `remote_path` alone (`:252`), with no server
  dimension, so two hosts sharing `/srv/app.tar` share checkpoints.
  `create` has a no-op `@divTrunc(l.mtime_ns, 1)` (`:171`) hiding an
  unchecked `i128 → i64` narrowing.
* **`verifyResume` rejects the only thing a real interruption produces.**
  `transfers.zig:322` returns `partial_mismatch` when
  `remote.len > confirmed_offset`, and its own comment names "a crash
  mid-append" as the case it refuses. Since `confirmed_offset` may only
  advance on a *confirmed* boundary, every genuine connection loss leaves a
  partial longer than the confirmed offset. As written, resume is
  unreachable. (Fixed in §2.6.)
* **`verifyResume` cannot see an HTTP source at all.** The whole source
  identity block is gated on `checkpoint.local_path != null`
  (`transfers.zig:291`), so `source_etag` / `source_last_modified` /
  `source_size` are consulted nowhere. A resumed `fetch` could splice two
  object generations.
* **`ResolutionEvidence.filesystem_effect` cannot prove anything.**
  `sha256` is `?[]const u8 = null` (`receipts.zig:620`); `supports` is
  `.filesystem_effect => resolved == .completed` (`receipts.zig:665`) with no
  look at the hash; `resolve` runs an identity check for `.job_result` only
  (`receipts.zig:867-877`). So `filesystem_effect{path, sha256: null}` flips
  any `indeterminate` transfer to `completed` and releases the scope barrier
  **on the strength of a path existing.** This is the single most dangerous
  thing in the repo for M3, because it is the *designated* exit from the one
  `indeterminate` M3 creates, and after a lost publish the most likely content
  at the destination is the *previous* file. (Fixed in §2.8 / §7.1.)

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
`-Dposix-sh` the build already resolves (`build.zig:165-172`).

### 2.3 The state machine, and where `submitted()` fires

This is the spine of the design, and it is the one thing all nine judgements
independently said to keep.

```
phase        checkpoint state   Execution status   what happens
-----------------------------------------------------------------------------
plan         planned            created            findResumable / create / adopt
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
sense `op_state.zig:172-177` already blesses and `cmd_exec.zig:224-244`
already relies on: it reaches the host, it can leave an artefact behind, and
it is not the caller's operation. The destination path is not named by any
command until the publish program, so it is *provably* untouched until then.

Consequences, all of them load-bearing:

* A connection lost mid-transfer is `connecting`, so
  `op_state.terminalForTransportLoss` (`op_state.zig:255`) gives
  `.never_submitted` → **failed, exit 1, resumable**. Not a shrug.
* The `indeterminate` / exit-75 window collapses from a multi-GiB transfer to
  one `ln` syscall.
* `.exited{0}` from the publish program is honest evidence, because the
  program's exit 0 is reachable only after the digest comparison inside it
  passed.

**The cost of submit-late, stated rather than hidden:** `connecting` does not
block scope (`op_state.zig:61`), so during the transfer the ledger's guard is
not holding the destination. That is what the **lease** is for:
`leases.acquire` on `{kind: .path, key: dest}` before probing, renewed during
the transfer, released at settle. `execution.begin` already consults
`leases.conflictForLocked` (`execution.zig:130`) and `submitted()` re-checks
it under the write lock (`execution.zig:209`), so a peer is refused at both
ends; the lease expires on its own if we die; `--force` overrides through the
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

Used as built: `create`, `byRequest`, `confirmOffset`, `setState`,
`recordVerifiedHash`, `contiguousPrefix`, and the *pure rules* of
`verifyResume`. Fixed:

**F1 — resume must survive the interruption it exists for.**
`verifyResume` rejects `remote.len > confirmed_offset`
(`transfers.zig:322`), which is exactly what a connection loss leaves. The
rule stays; what changes is that the probe **proves the prefix, then truncates
to it, in one remote script, with truncation gated on the proof**:

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

**F2 — the prefix hash must actually be written.** `create`'s INSERT
(`transfers.zig:155-163`) omits `remote_partial_sha256`, and `confirmOffset`
COALESCEs a null over it (`:347`), so `verifyResume`'s prefix branch
(`:324-329`) is dead code today. The chunk-close confirm now passes the prefix
digest **every time** — it is free, because `Sha256` is a value type:
`var snap = hasher; snap.final(&d)` yields the digest of the confirmed prefix
at each boundary — and the COALESCE becomes a plain assignment.

**F3 — fail-silent writes become fail-loud.** `confirmOffset` gains
`AND state IN ('planned','probing','transferring')` (so it cannot resurrect a
paused or failed row) and checks `store.db.changes()`, returning
`error.CheckpointNotAdvanced` when it matched nothing. `setState` refuses to
leave a terminal checkpoint state and checks `changes()` the same way. Both
follow `receipts.zig:923-928`, which already does this.

**F4 — the source shape becomes role-based, not push-shaped.**
`verifyResume`'s `if (checkpoint.local_path != null)` gate
(`transfers.zig:291`) is deleted and replaced by an exhaustive switch on a
`SourceIdentity` union (`local_file` / `remote_file` / `http`), so a remote
source is validated by its own size + mtime + digest, and an HTTP source by
its strong validator. No source shape can fall through the check by being
`null`. (For M3a only the first two are constructible; see §7.3.)

**F5 — checkpoint identity gains a destination side.** `findResumable` keys on
`remote_path` alone (`transfers.zig:252`) with no server dimension. It becomes
`(dest_side, dest_path)` where `dest_side` is `server:<id>` or `local`, and
gains a **partial unique index over live states** (§2.7).

**F6 — `adopt`.** A resumed transfer is a new operation with a new
`request_id`, so the checkpoint row must be re-pointed:
`transfers.adopt(store, id, new_request_id, now)` verifies the state is
resumable and reassigns the FK in one transaction, writing a `checkpoint`
observation on both operations naming the other. The checkpoint is a mutable
working record; the ledger is the audit trail.

Also fixed: the no-op `@divTrunc(l.mtime_ns, 1)` (`transfers.zig:171`) becomes
a checked narrowing.

**Two writers, one verdict — the ordering rule.** `transfers.setState` and
`receipts.settle` both record how a transfer ended, and they cannot share a
transaction (`settle` opens its own `BEGIN IMMEDIATE`, `receipts.zig:509`).
The rule is: **the ledger is authoritative for the verdict; the checkpoint is
authoritative for the offset; the offset is re-proved on every resume by the
prefix hash.** Write order is checkpoint-first, then settle — chosen so that a
crash between them leaves a checkpoint marked failed under an *unsettled*
operation, which the next run sees as a scope-blocking peer and refuses. The
failure direction is a spurious refusal, never a spurious resume.

### 2.7 Concurrency: three layers, and what none of them covers

| Layer | Mechanism | Covers |
|---|---|---|
| `begin` | `leases.conflictForLocked` (`execution.zig:130`) + `unsettledInScope` | a peer already working this destination on this server; refuses before dialing |
| `create` | new `UNIQUE INDEX ON transfer_checkpoints(dest_side, dest_path) WHERE state IN ('planned','probing','transferring','paused')` | **any** second live transfer to the same destination on this machine, including pull and fetch, where `server_id` is null and the scope guard does not run at all (`execution.zig:208` skips the guard entirely for a null server) |
| `submitted()` | the scope guard re-checked under the write lock (`execution.zig:209`) | the last-moment race between two racers that both cleared `begin` |

The partial unique index is the layer that matters for pull, and it is
deliberately server-independent: `unsettledInScope` filters by `server_id`
(`operations.zig:308`), so two pulls *from different servers* into one local
path would both clear the guard. A DB-level uniqueness constraint is the only
thing that can see them both.

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
| any ledger write fails | `Cli.receiptFatal` (`cli.zig:201`) | — | **76** |

**`completed_unverified` is unreachable in M3a, and that is the point.** We
compute our own digest over the bytes we handled and re-read the destination
after publishing, so verification never depends on the *source* offering a
hash. It depends only on a digest tool existing, and when one does not, we
refuse before sending a byte. There is therefore **no path that writes
`completed` to the ledger for an unverified artifact** — which is exactly the
flaw all three input designs shared, each of them settling a
`completed_unverified` fetch as ledger-`completed` via an `.exited{0}` that no
process produced. The enum value stays in `transfers.State`
(`transfers.zig:50`) unused, and its fate is tied to §7.3.

**The reconcile path, and the hole that must close first.**
`ResolutionEvidence.filesystem_effect` today accepts `sha256: null`
(`receipts.zig:620`), `supports` waves it through to `.completed`
(`receipts.zig:665`), and `resolve` compares it to nothing
(`receipts.zig:867-877` checks only `.job_result`). As it stands, the *one*
`indeterminate` this design creates has exactly one documented exit and that
exit is unproven: after a lost publish the destination most likely still holds
the **old** file, and hashing it would settle `completed`. Required fix:

1. `sha256` becomes non-optional on `filesystem_effect`.
2. `resolve` gains an identity check for `.filesystem_effect`, structurally
   parallel to the one it already runs for `.job_result`: inside the same
   transaction, read `transfer_checkpoints` for this `request_id`, require
   `expected_sha256` to be present, require `evidence.path` to equal the
   checkpoint's destination path, and require `evidence.sha256` to equal
   `expected_sha256`. A mismatch or a missing expectation returns a new
   `evidence_unverifiable` outcome — never a resolution.
3. `expected_sha256` must therefore exist *before* the publish exec. New
   `transfers.recordExpectedHash(store, id, sha256, now)` is called after the
   whole source is streamed and hashed and **before** `execution.submitted()`.
   Without step 3, step 2 degenerates to "a file exists" again.

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
| `src/core/store/transfers.zig` — push-shaped parts | `local_*`/`source_*` as the only two source shapes; `remote_partial_*` names; the `local_path != null` gate at `:291`; the hardcoded `state = 'transferring'` at `:348`; the COALESCE at `:347`; the `remote_path`-only key at `:252`; the no-op `@divTrunc` at `:171` | §2.6. The pure resume rules, `contiguousPrefix` and all four existing tests survive. |
| `src/cli/dispatch.zig` help text | "upload a file over SCP" / "tar+md5" | no longer true |

**Not deleted, deliberately:** `transfers.zig`'s resume rules and
`contiguousPrefix` (unexercised in production until parallel fetch lands —
said plainly rather than pretended otherwise); `Executor` (control commands
still go through it — only two streaming primitives are added);
`history.redactSecrets`, which has three live callers (`cmd_exec.zig:88`,
`cmd_job.zig:120`, `cmd_job.zig:289`) and is not dead even though
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
| **schema**: `transfer_checkpoints` reshaped (§7.4) | nobody's data — the table has never had a writer, so no row exists in any database anywhere | a dev database is migrated in place (or rejected with a clear message, depending on §7.4) |

---

## 5. Acceptance gates

Two harnesses. `Executor.scripted` (`exec.zig:37`) replays exit codes for
fault injection at chosen instants; `Executor.shell` runs the **actual
generated programs** through the real POSIX shell the build already resolves
(`build.zig:165-172`, `test/blackbox.zig:45`) against a real scratch
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

**B. Pure rules** (`store/transfers.zig`, extending the four existing tests):
* B1. Locally modified source rejects its old checkpoint, including a
  modification inside the already-transferred prefix with size and mtime
  unchanged. *(Agreed gate 3, unit half.)*
* B2. Polluted partial: right length, wrong prefix digest → `partial_mismatch`.
  *(Agreed gate 4, unit half.)*
* B3. `confirmOffset` refuses to move backwards **and reports that it
  refused**; refuses to resurrect a paused or failed row.
* B4. `setState` refuses to leave a terminal checkpoint state.
* B5. `verifyResume` validates a `remote_file` source by its own identity, and
  no source shape falls through by being `null`.

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
  → `error.Constraint`, not a convention. Includes the **pull** case, where
  `server_id` is null and the scope guard does not run at all. *(Agreed gate
  5, with the hole §2.7 names.)*
* D3g. **The submit-late boundary.** A transport failure one exec before the
  publish → exit 1 with a resumable checkpoint; a transport failure *inside*
  the publish exec → exit 75, `indeterminate_publish`, and an operation that
  still blocks its scope. This is the gate that would catch a future refactor
  moving `submitted()` back to the first byte.
* D4g. **The reconcile binding.** `filesystem_effect` with a null hash, with a
  hash that does not match `expected_sha256`, or against an operation with no
  recorded expectation → **refused**, `indeterminate` preserved. Only a
  matching hash at the recorded destination path resolves to `completed`.
  *(Closes §1.3's worst finding. Does not exist today in any form.)*
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
3. **Schema** (§7.4). `transfer_checkpoints` reshaped to role-based columns
   (`source_kind/source_locator/source_size/source_mtime_ns/source_sha256`,
   `dest_side/dest_path`, `partial_path/partial_len/partial_sha256`) plus the
   partial unique index; `transfers.zig` rewritten onto them with the six
   fixes of §2.6 and `adopt`/`recordExpectedHash`. → gates **B1–B5**, **D2g**.
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

---

### 7.1 How to close the `filesystem_effect` laundering hole

**Current state.** `ResolutionEvidence.filesystem_effect` is
`{ path: []const u8, sha256: ?[]const u8 = null }` (`receipts.zig:618-621`).
`supports` is `.filesystem_effect => resolved == .completed`
(`receipts.zig:665`) — true unconditionally, with no look at the hash.
`resolve` runs an identity check for `.job_result` only
(`receipts.zig:867-877`); nothing compares a filesystem hash to anything.
`appliesToKind` (`receipts.zig:678-680`) already restricts this variant to
`transfer_push`/`transfer_pull`/`fetch`. It has zero constructors today.

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

**Current state.** `op_state.canSettle` (`op_state.zig:291-293`) admits
`.exited` only from `.submitted`/`.remote_started`, and `.exited` is
documented as "the remote reported a real exit status"
(`op_state.zig:163`). `canTransition` (`op_state.zig:138-141`) makes
`connecting → completed` illegal, so an operation that never reaches
`submitted` can never complete.

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
— and §2.8's guarantee that `completed_unverified` is unreachable holds only
while fetch is out.

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

**Current state.** The v6 DDL (`migrate.zig:195-224`) names the source
`local_*` and the partial `remote_partial_*`, has `remote_path NOT NULL`, and
indexes `(remote_path, state)` non-uniquely (`migrate.zig:224`). Those names
are correct for push and an active lie for pull, where the partial is local
and the source is remote; `remote_path NOT NULL` makes a local-destination
transfer structurally impossible. A `source_size` column already exists, so a
naive `local_size → source_size` rename is invalid SQL. `latest_version` is
`migrations.len` (`migrate.zig:405`) and the chain currently runs to v10
(`migrate.zig:386`). **The table has never had a writer**, so no row exists in
any database anywhere — verifiable by grep: `transfers` appears only in the
`Store.zig` re-export.

**Why it blocks.** §2.5 (pull's partial is local), §2.6 (F4, F5) and §2.7 (the
partial unique index that is the only guard a local destination gets) all
depend on the column shape. Nothing in M3a can be built against the current one.

| Option | Change footprint | Breakage | Data impact | Effort | Long-term cost |
|---|---|---|---|---|---|
| **A. New v11 step** that drops and recreates the table with role-based columns and the partial unique index; v6 text stays frozen in the chain | `migrate.zig` ~+50 | none | **provably nil** — zero rows exist. Developer databases upgrade in place with no action | ~0.5 day | one more migration step, and dead v6 DDL that every fresh database still walks through |
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
