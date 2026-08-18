# M3b — `ControlAuthority`: who may destroy what, and what they must prove

> Status: **partly implemented.** This was a contract for review; the first
> slice of it is now code, and the rest is not. Read the three lists below
> before trusting any tense in the sections that follow.
>
> **Implemented.**
> * `d3bef52` — `session rm` gained a `control` operation
>   (`operations.Kind.control`, `operations.zig:62`; taken at
>   `cmd_session.zig:196-204`), a `.job`-scope lease derived from the session
>   name (`contentionScope`, `cmd_session.zig:592`; acquired at `:224`), and a
>   renewal immediately before every step that changes the host or the local
>   record (`cmd_session.zig:241`, `:270`, `:280`, `:303`). This is §1.2's first
>   half and §7's "Implementation order" slice — **half of it.** See the open
>   half below.
> * `ae9c261` — the lease-renewal barrier moved into `src/core/control.zig` and
>   is now owned once: `Claim` (`:69`), `Authority` (`:111`), `holdClaim`
>   (`:217`), `stillOurs` (`:269`), `wallClockSeconds` (`:199`) and the
>   adjacency scan `renewalsAreAdjacent` (`:345`) over one shared
>   `destructive_remote_calls` vocabulary (`:330`). That settles §7.6 as option
>   (c). `cmd_job.zig:35-39` and `cmd_session.zig:35-38` are aliases onto it,
>   not second copies.
> * `8c068b2` — `stillOurs` latches: once a renewal has answered "not ours" the
>   later steps are forbidden and no later answer may overwrite the first loss
>   (`control.zig:269-273`). The same commit converged the two verbs' divergent
>   wording onto naming *the scope for* the subject rather than the subject,
>   because for `session rm` those are different strings (`Subject`,
>   `control.zig:28-57`; the sentences at `:152-180`).
>
> **Decided but unbuilt.** §7's eleven items were decided in `b33e4ec` and §7
> already reads as decisions, not options — but a decision is not an
> implementation. Nothing in §4 (per-attempt session identity) exists. Nothing
> in §5 exists: the newest migration in the frozen list is v12
> (`migrate.zig:520`, `leases_reowned_version = 12` at `:604`,
> `latest_version = migrations.len` at `:588`), so there is no `session` scope
> kind and no `target_*` column, and §3.3's target relation still travels in
> `alias` (`cmd_session.zig:201`). `job kill` and `job rm` still have no
> operation row of their own (§1.1).
>
> **Still open.** §1.3 (the scope vocabulary), §1.4, §1.5, §1.6 — untouched.
> And the other half of §1.2, which is the one thing most likely to be misread:
>
> > **`session new` has no authority at all.** `newSession`
> > (`cmd_session.zig:75-111`) takes no operation, makes no claim, holds no
> > lease, and still reports `action: "created"` unconditionally (`:100`). So it
> > can run `Tmux.ensure` (`:90`) and `sessions.ensure` (`:91`) under the same
> > name *while* `session rm` is between its kill (`:271`), its log deletion
> > (`:285`) and its row deletion (`:317`) — recreating the shell, and the local
> > row, that `session rm` is in the middle of removing. Nothing displaces
> > `session rm`'s lease in that sequence, so its renewals at `:280` and `:303`
> > answer `held` and refuse nothing. §1.2 is **not** closed end-to-end. Do not
> > read the implemented half as the whole.
>
> **A review of the merged slice found further defects, being addressed
> separately.** Reported: the composite delete is not transactional (the kill at
> `cmd_session.zig:271`, the log at `:285` and the row at `:317` are three
> independent steps); the ledger can record success before the delete completes
> (`execution.settle` at `:305` precedes `sessions.remove` at `:317`); a refused
> attempt is not audited; a failed lease release is not reported; and the
> `--json` key set does not match the documentation (`RemovalJson` carries
> twelve fields, `cmd_session.zig:149-171`, where `skill/SKILL.md:528-532` says
> eleven keys). None of these are fixed as of `3e18d23`, and this document does
> not record an outcome for them.
>
> Claims about current behaviour carry a `file:line`. Those written before the
> first slice landed were read at `7d2e72a` and some of their line numbers have
> since moved; every citation added or changed by this status pass was read at
> `3e18d23`. Where a claim could not be verified it is marked as such or absent.

---

## 0. The shape in one page

Six verbs destroy or seize something on a host. Each answers "may I?" its own
way, and when this was written two of them did not answer at all. `session rm`
now answers (`d3bef52`); `session new` still does not.

| verb | contends on | proves identity | proves the act | records the act |
|---|---|---|---|---|
| `job kill` | lease `.job:<job>` | no — aims by name | yes (`killSession` bool) | no operation row |
| `job rm` | lease `.job:<job>` | no — aims by name | yes | no operation row |
| `session rm` | lease on the `.job` scope for the session | no | yes (`gone` before delete) | a `control` operation |
| `session new` | **nothing** | no | n/a (adopts silently) | no operation row |
| `run` cleanup | `jobs.remove` CAS | no | partially | **nothing** — see below |
| `write --force` | bypasses both | no | n/a | the force is recorded |

The `session rm` row is the one line of this table that `d3bef52` changed: its
contention and record cells were both **nothing** when this was written, and are
now a lease taken at `cmd_session.zig:224` over `contentionScope(name)` (`:592`)
and a `control` operation taken at `:196-204`. Its identity cell is unchanged —
it still aims by name. Every other row is as first written, `session new`
included, which is why §1.2 is only half closed.

The `run`-cleanup cell needs its footnote, because the code reads as if it
records something: `jobs.remove(..., .superseded_by_relaunch)`
(`cmd_job.zig:221`) passes `RemovalGrounds`, but that is a **comptime guard on
which statuses may be deleted** (`jobs.zig:397-428`, the status matrix at
`:410-420`), not a column. The row is deleted and the grounds are not persisted
anywhere.

`ControlAuthority` is the single concept those cells are missing. It asks four
questions, in this order, and every destructive step in the tree runs under all
four:

1. **Identity** — is the thing I am about to destroy the thing I mean? Today
   answered by name, and a name is reused. §4.
2. **Contention** — does anything else hold a claim that overlaps it? Today
   answered on a scope vocabulary that cannot spell "session". §5.
3. **Proof** — did the destruction happen, and is each *subsequent*
   destruction still licensed? Answered well today for `job kill`/`job rm`,
   answered well for `session rm`, not answered at all elsewhere. §2.2.
4. **Record** — can anyone ask later what was attempted and what came of it?
   Answered for `run` and `write`, and — since `d3bef52` — for `session rm`
   (`cmd_session.zig:196-204`). Still unanswered for `job kill`, `job rm` and
   `session new`. §3.

The verbs are not six problems. They are three primitives used six ways, and
naming them once is most of this document: `stopSession`, `discardEvidence`,
`attachSession` (§2.3).

---

## 1. What is broken, with citations

### 1.1 `job kill` and `job rm` leave no ledger entry

Both mint a ULID and use it *only* as a lease owner (`cmd_job.zig:4204-4210`).
`leases.requireOwner` checks it is non-empty and nothing else
(`leases.zig:192-194`). There is no `operations` row for the control command,
and the schema says so deliberately: v12's own comment explains that
`owner_request_id` carries no foreign key because "`job kill` and `job rm` are
supervisory acts on somebody *else's* attempt, so they mint an id from the same
generator and have no `operations` row of their own" (`migrate.zig:536-541`).

The consequence is that five questions have no answer: whether anyone tried to
kill job `deploy`, who, when, whether it succeeded, and whether this was the
first attempt or the third. The outcome of a *control* act is written onto the
*target's* attempt instead — which is why `fdd1144` had to decide by hand
whether a lost lease may overwrite a proven exit code. One row was carrying two
subjects.

`operations` also has no relation column at all (`migrate.zig:105-130`). The
only `correlation_id` in the schema is on `operation_events`
(`migrate.zig:173`), which is the wrong grain: relating two operations should
not require walking one's event stream.

### 1.2 `session rm` had no authority of any kind — `session rm` is fixed, `session new` is the open half

**As written (`7d2e72a`).** `cmd_session.zig:77-109`. No lease, no operation, no
scope guard, no `--force`, no request id. It kills the remote session, deletes
the pane log, and deletes the local row — whose delete cascades the session's
memories (`sessions.zig:64-75`).

**Fixed for `session rm` in `d3bef52`.** It now takes a `control` operation
before it dials (`cmd_session.zig:196-204`), takes a lease over the `.job` scope
its session name maps to (`:224`, `contentionScope` at `:592`), and renews that
lease with nothing between the renewal and the act it gates — before submitting
(`:241`), before the kill (`:270`, `:271`), before the log deletion (`:280`,
`:285`) and before the row deletion (`:303`, `:317`). A refusal before the kill
sends nothing to the host; a refusal after it keeps both the log and the local
row.

**Not fixed: `session new`, and that is the open half of this item.**
`newSession` (`cmd_session.zig:75-111`) has no operation, no claim and no lease,
and reports `action: "created"` unconditionally (`:100`). It calls `Tmux.ensure`
(`:90`) and `sessions.ensure` (`:91`) with nothing contending, so it can create
or adopt a session under the very name `session rm` is removing, at any point
between that command's kill (`:271`), log deletion (`:285`) and row deletion
(`:317`). Nothing in that sequence displaces `session rm`'s lease, so its
renewals at `:280` and `:303` answer `held` and refuse nothing: the recreated
shell keeps running, its `pipe-pane` log is deleted underneath it, and the local
row `session new` just wrote is deleted too — the orphan this section's own
reasoning says must not exist. Closing this needs `session new` to hold the same
claim, which is the second half of the slice §7's "Implementation order"
describes and which is not written.

Two things `session rm` did right and that survived the change:

* it proves the kill before deleting anything and refuses if the session
  survived (as written: `cmd_session.zig:84-88`; now `:271-272`, with
  `refuseSurvivedKill` at `:399`);
* it deletes the log only after that proof, because a live pane recreates its
  log through `pipe-pane`, so a log deleted under a surviving session comes back
  holding a partial history (as written: `cmd_session.zig:90-95`; now `:285`,
  with `Tmux.zig:726-734` unchanged).

The discarded bool from `sessions.remove` was documented as *not* a swallowed
refusal — false means only that this machine had no metadata row, an ordinary
state for a session started outside Terminus. That reasoning stands, and
`d3bef52` went further: the bool is no longer discarded but reported, as
`localRow: removed | absent | kept` (`cmd_session.zig:317`, the field at
`:162-166`).

**The sharp case, now refused.** A job's tmux session is `job-<name>`
(`cmd_job.zig:64-66`), and `Tmux.list` strips the `t-` prefix
(`Tmux.zig:639-641`), so a running job appears in `session ls` as a session
named `job-deploy`. `session rm web job-deploy` used to kill that running job's
shell while `job kill web deploy` held a lease on `.job:"deploy"` and never saw
it. `contentionScope` maps the session name `job-deploy` onto the scope
`.job:deploy` (`cmd_session.zig:592-597`, asserted at `:599-613`), so the two now
collide and the removal is refused before anything is sent — gated end to end at
`test/blackbox.zig:3781`. The collision is derived by string surgery on a name,
not by a scope vocabulary that can spell "session"; that is still §1.3, and it
over-refuses in the other direction as §1.3 describes.

### 1.3 The scope vocabulary conflates sessions with jobs, in both directions

There is no `session` scope kind. Scopes are `server`, `job`, `path`
(`scope.zig:9-16`), so everything session-shaped is spelled as a `job` scope
whose key happens to be a session name:

* `write` claims `.job:<session name>` (`cmd_read_write.zig:419-421`);
* `exec <server>:<session>` claims the same (`cmd_exec.zig:82-85`);
* a job claims `.job:<job name>` (`cmd_job.zig:68-70`).

Two defects fall straight out of that, and they point opposite ways.

**False collision.** A user session named `deploy` (`t-deploy`) and a job named
`deploy` (`t-job-deploy`) are different shells — `cmd_job.zig:62-63` says
namespacing them is deliberate — but both produce the scope key `deploy`, so
work on one refuses work on the other for no reason.

**False miss.** A `write` to session `job-deploy` claims `.job:"job-deploy"`,
which does not overlap the running job's `.job:"deploy"`. The two commands are
typing into the same pane and neither barrier sees the other. Reaching it takes
one extra step, because `write` requires a local `sessions` row
(`cmd_read_write.zig:51-53`) and `job run` never creates one — but
`session new web job-deploy` creates it, and `Tmux.ensure` treats the existing
session as ready (`Tmux.zig:607`), so the sequence is three ordinary commands.

### 1.4 `reclaimable()` cannot tell a dead launcher from a live one

`cmd_job.zig:107-113` lets a new launch take over a `pending` row when the
owning operation no longer blocks a scope. Its own doc records the gap
(`cmd_job.zig:87-106`): `blocksScope` is false for `created` and `connecting`
(`op_state.zig:58-64`), and `connecting` is where a healthy launcher sits for
its entire setup — `execution.connecting()` runs at `cmd_job.zig:231` and
`submitted()` not until `:369`, with `killSession`, `ensure` and a possible
script upload in between. Nothing in the ledger separates "killed while
dialling" from "dialling right now". The doc calls the fix "a schema question"
(`cmd_job.zig:105-106`).

### 1.5 `write --force` bypasses both barriers

`--force` reaches `execution.begin` (`cmd_read_write.zig:126`,
`execution.zig:79`) and proceeds past an unsettled overlapping writer *and* a
foreign lease; the refusals it skips are at `cmd_read_write.zig:382-393`. The
force itself is recorded (`execution.zig:373`, `:850`), which is the part that
is right.

### 1.6 A same-name relaunch appends to the previous attempt's log

`Tmux.ensure` starts `pipe-pane -o 'cat >> $HOME/.terminus/logs/<name>.log'`
(`Tmux.zig:608`), the log path is derived from the session name
(`Tmux.zig:81-83`), and `job run` never removes it — `removeLog` has only two
callers, `session rm` and `job rm --discard-evidence`. A new `jobs` row starts
at `read_cursor = 0` (`migrate.zig:65`), so `job read` on attempt 2 reads
attempt 1's bytes first and nothing marks the boundary. The result *sidecar* is
already per-attempt, keyed by request id (`Tmux.zig:180-185`, `Tmux.zig:22`);
only the log is not.

---

## 2. `ControlAuthority` — one concept, six verbs

### 2.1 The four questions

`ControlAuthority` is a value a command holds, not a check it performs. It is
constructed before the connection opens and re-asserted immediately before
every step that changes anything. It carries answers to:

**Identity.** The physical thing this command is entitled to act on, named in a
way that cannot be re-minted under it. §4 makes this the attempt's own request
id. A step whose identity does not match refuses and changes nothing.

**Contention.** A lease over a scope that actually covers that thing, plus the
absence of an unsettled overlapping writer. Both already exist
(`leases.zig:344`, `operations.zig:396-408`); what is missing is a scope
vocabulary that can name a session (§5).

**Proof.** The remote's own answer to "is it gone", carried as a value rather
than assumed. `Tmux.killSession` already returns it (`Tmux.zig:670-681`) and
`Tmux.removeLog` already documents that it may only be called after
(`Tmux.zig:726-729`).

**Record.** An `operations` row of this command's own, with a request id, a
typed action, and the target it acted on. §3.

The `Authority` union that was in `cmd_job.zig` when this was written is exactly
question 2, and only question 2, for exactly one scope kind. Its three answers —
`held`, `lapsed`, `unreadable` — and its rule that "a question we could not ask
is not a yes" are the right shape and are kept verbatim as `ControlAuthority`'s
contention arm. §7.6 has since been decided and built: `ae9c261` moved it to
`src/core/control.zig:111-181` alongside `Claim` (`:69`), `holdClaim` (`:217`)
and `stillOurs` (`:269`), which is where the two verbs that hold a claim now
read it from (`cmd_job.zig:35-39`, `cmd_session.zig:35-38`). The name collision
that §7.6 was about is gone; the remaining three questions are still not part of
it.

### 2.2 What each verb needs

Read this table as the contract. Where two rows say the same thing, that
sameness is the design.

**`job kill`**
* *authority*: contention on the job's session; identity = the attempt's own
  session incarnation.
* *must prove before acting*: the lease was ours on the line above the kill.
  Already true, and held by a gate that reads this file's own source
  (`cmd_job.zig:4541-4551`), asserting seven sites
  (`destructive_remote_call_count`, `cmd_job.zig:4532`). Note the gate's reach:
  it scans `killJob` and `removeJob` only (`claim_holding_bodies`,
  `cmd_job.zig:4539`), so the `Tmux.killSession` in `runCmd`
  (`cmd_job.zig:282`) is outside it — it runs under a reservation and takes no
  lease, so it has no renewal to be adjacent to (`cmd_job.zig:4534-4538`).
  `session rm` is no longer outside it either: since `ae9c261` the *scan* is
  shared (`Control.renewalsAreAdjacent`) and `cmd_session.zig` keeps its own
  gate over its own body, asserting two sites
  (`cmd_session.zig:707`, `:710`, the test at `:712-722`). Plus: the session it
  is about to kill is the one this job's live attempt created.
* *may destroy*: the tmux session and the work in its shell.
* *must refuse*: a lost or unreadable lease (nothing sent); an identity
  mismatch; `killSession` returning false (`cmd_job.zig:3649-3652` does this
  for `rm`).
* *must never destroy*: the pane log, the result sidecar, the local row.
* *records*: a control operation, settled from its own evidence, plus the
  target attempt settled from the job's evidence (§3.4).

**`job rm`**
* Everything `job kill` needs, **plus** the right to delete the local `jobs`
  row, **plus** — under `--discard-evidence` — the log and the sidecar.
* *must additionally prove*: the session is gone before any deletion
  (`cmd_job.zig:3647-3652`); the sidecar was *readable*, because a removal that
  could not read it must not delete it (`cmd_job.zig:3711`, and the rationale at
  `:3703-3710`); the lease is still ours between the kill and each delete
  (`cmd_job.zig:3721`).
* *records*: as `job kill`. The control operation is the **only** durable
  record that the removal happened, because the target row is gone.

**`session rm`** — *built (`d3bef52`), except for the identity arm.*
* *needs exactly what `job rm` needs.* This is the point of the whole
  document: aimed at a job's session it destroys the same three things in the
  same order with the same failure modes, and when this was written it held none
  of the four answers (§1.2). It is not a smaller act than `job rm`; it is
  `job rm` with the ledger removed.
* It now holds contention (`cmd_session.zig:224`), proof (`:271-272`) and record
  (`:196-204`). **Identity it still does not hold**, and cannot until §4 exists:
  it kills by the name it was handed (`:271`).
* *may destroy*: the session, the log, the local `sessions` row and its
  cascaded memories.
* *must refuse*: a session under a live claim — done, on the derived `.job`
  scope rather than the `session` scope §5 would give it
  (`cmd_session.zig:210-213`, `reportBlocked` at `:546`); a session that
  survived the kill (already right when written, now `:272`).
* *records*: a control operation, and which of the two `sessions.remove`
  answers it got — so the discarded bool becomes reported rather than merely
  justified. Done: `localRow` (`cmd_session.zig:162-166`, written at `:317`).

**`session new`** — *not built. This is the open half of §1.2.*
* Destroys nothing, and is still an authority act, because `Tmux.ensure` is
  idempotent (`Tmux.zig:607`): on an existing session it hands the caller
  somebody else's live shell and reports `action: "created"` unconditionally
  (`cmd_session.zig:100`). Adopting is not creating, and saying "created" for
  an adoption is a false statement about a remote state.
* *needs*: contention on the session scope, so a `new` cannot land inside an
  `rm`; and, once identity exists, the right to *refuse* adoption of a session
  whose incarnation belongs to a live job attempt.
* *must prove*: whether it created or adopted, and say which.
* *records*: at minimum the truthful verb. Whether it gets an operation row of
  its own is §7.3, decided as (a) — yes.
* **None of the above is written.** `newSession` (`cmd_session.zig:75-111`)
  takes no operation, no claim and no lease, so the "cannot land inside an `rm`"
  half of §1.2 is still open in exactly the way §1.2 now describes.

**`run` stale cleanup (`reclaimable()`)**
* Destroys two things: a local row (`jobs.remove ... superseded_by_relaunch`,
  `cmd_job.zig:221-228`) and then a remote session (`cmd_job.zig:282-287`).
* *needs*: identity, and nothing else can supply it. A `pending` row whose
  recorded incarnation is **not** on the host was abandoned; one whose
  incarnation **is** on the host is in use. That is a fact about the host, not a
  predicate about scope-blocking, which is why §1.4's gap is not closable in the
  ledger alone.
* *must refuse*: taking a row whose recorded incarnation is alive on the host —
  regardless of what `blocksScope` says about its owner.
* *records*: nothing today (§0's footnote). Under this contract the session
  kill it performs becomes a control operation, because it is a remote
  destruction like any other; whether the local row deletion also earns a
  record is §7.11.

**`write --force`**
* Destroys nothing, but types into a shell, which is unrecoverable in the way
  that matters: the bytes cannot be un-typed.
* *needs*: contention (which `--force` may displace) and identity (which it
  may not).
* *`--force` may*: displace a lease and proceed past an unsettled overlapping
  writer. The displacement is already recorded.
* *`--force` must not*: type into a session whose incarnation has changed since
  the caller last observed it — that is a different shell, and no override
  makes it the intended one. Nor may it suppress the `input_refused` terminal
  (`op_state.zig:324-328`): forcing is about who may act, never about what the
  remote answered.
* *open*: whether `--force` may proceed past an `indeterminate` operation on an
  overlapping scope. Today it may. §7.4.

### 2.3 The sameness, named once

Three primitives cover all six verbs. Each takes a `ControlAuthority` and
returns a value the caller must consume.

* **`stopSession(authority, incarnation) -> gone`** — used by `job kill`,
  `job rm`, `session rm`, and `run`'s cleanup. Renews contention, checks
  identity, sends the kill, returns the remote's own answer. Four call sites
  still do this four ways. The *renewal* half is no longer duplicated —
  `ae9c261` put it in `src/core/control.zig` and all three claim-holding call
  sites read it from there — but the primitive itself does not exist: each verb
  still writes its own renew/kill/consume sequence inline
  (`cmd_session.zig:270-272`, and `job kill`/`job rm` in `cmd_job.zig`), and
  `run`'s cleanup still kills with no claim at all.
* **`discardEvidence(authority, incarnation, reading)`** — used by
  `job rm --discard-evidence` and `session rm`. Requires `gone == true` and a
  *readable* sidecar reading. `job rm` already enforces both
  (`cmd_job.zig:3711`, `:3721`); `session rm` enforces the first and has no
  concept of the second.
* **`attachSession(authority, expected_incarnation) -> created | adopted`** —
  used by `session new`, `exec <server>:<session>`, `write`, and `run`. Makes
  adoption a reported outcome rather than a silent one, and gives `write
  --force` the identity check it must not be able to skip.

### 2.4 What authority cannot do

Contention plus identity does **not** make check-and-act atomic. `1f47542`
narrowed the window between a successful local renewal and the host acting to
the width of one round trip, and its own message states the limit: "no local
lock closes it without immutable remote session identity". Identity does not
close it either. What identity removes is the *consequence*: a stale kill can
no longer destroy a session it did not create, because it names one that no
longer exists and the host refuses it. The race survives; its damage does not.
Any claim stronger than that is false and must not be written into a comment.

---

## 3. The control operation

### 3.1 A new `Kind`

A new variant on `operations.Kind` (`operations.zig:29-51`) for a control act.

**Cost: no migration.** `operations.kind` is bare `TEXT NOT NULL`
(`migrate.zig:110`), unlike `status` and `resolved_status`, which carry CHECKs
(`migrate.zig:114-119`). Note that `operations.scope_kind` is *also* bare TEXT
(`migrate.zig:111`) — the `scope_kind` CHECK lives on `leases`
(`migrate.zig:565`), which is what makes §5 a leases migration rather than an
operations one.

**Cost: two exhaustive switches and their mirror.** A new `Kind` stops the build
in `receipts.appliesToKind` (`receipts.zig:1235`) and
`receipts.terminalDescribesKind` (`receipts.zig:1645`), both exhaustive in both
directions with no `else` (`receipts.zig:1640-1644`), plus the tables
`gates_test.zig` states a second time from the other direction. That is the
forcing function, not an obstacle: each cell has to be answered on purpose. The
name of the variant is §7.1.

### 3.2 A typed action

```zig
pub const ControlAction = enum {
    kill_session,      // job kill
    forget_job,        // job rm
    remove_session,    // session rm
    reclaim_session,   // run's stale cleanup
};
```

Stored as text, rendered by `@tagName`. **Not** a free string: `KillJson.action`
and `RemovalJson.action` are free strings today (`cmd_job.zig:923`, `:961`) and
the doc-vs-struct gate can hold their *presence and nullability* against
`skill/SKILL.md` but not their enumerated values (`cmd_job.zig:992-1004`).

### 3.3 A target relation

A control operation must name what it acted on. `operations` has no relation
column (§1.1), so this is where the v13 additive columns go: a target kind, a
target key, and — when there is one — the target attempt's request id.

The target request must be nullable, and the null must mean one thing: "there is
no attempt to point at". A `jobs` row from before v6 has no attempt row, and
`session rm` targets a session that never had an operation at all. That is
different from "the attempt is unknown", and the two must not collapse into one
null. Column names are §7.2.

### 3.4 Control and target settle independently

|  | records | settled by |
|---|---|---|
| **control** operation | what *this command* did | its own evidence: lease held or lost, kill sent or withheld, the host's answer |
| **target** attempt | what happened to *the job* | the job's own evidence: sentinel, sidecar, exit code |

Consequences, stated so they are not re-litigated:

* A control operation that loses its lease before sending anything settles
  `failed` — it provably changed nothing. The target is untouched.
* A control operation whose kill was sent and whose confirmation was lost
  settles `indeterminate`, carrying the `AUTHORITY_LOST` code that
  `Authority.lost_code` already defines (`control.zig:128`, moved there by
  `ae9c261`). The target is untouched unless the job's own evidence says
  otherwise.
* A proven target exit code survives a lost control lease, because they are
  different subjects. This is the rule `fdd1144` reached by hand; here it falls
  out of the model.
* `job rm` deletes the target's row. The control operation and its receipt are
  the only durable record that the removal happened.

No new `Terminal` variant is proposed *for the outcomes above*. Every one of
them is expressible with `exited`, `never_submitted`, `local_abandon`,
`remote_cancel_confirmed`, `input_refused` and `indeterminate` as they stand
(`src/core/store/op_state.zig:228-335`) — and the built slice bears that out:
`session rm` settles `remote_cancel_confirmed` on a proven kill
(`cmd_session.zig:360-378`), `never_submitted` on a lease lost before the kill
(`refuseBeforeKill`, `:447`) and `indeterminate` carrying
`Authority.lost_code = "AUTHORITY_LOST"` (`control.zig:128`) on a lease lost
after it (`refuseAfterKill`, `:493`). An identity mismatch is a proven refusal by
the remote, not an unknown; §7.5 decided that it gets a variant of its own, and
that variant does not exist yet because §4 does not.

**Known gap: `remote_cancel_confirmed`'s `term_sent` and `kill_sent` are not
persisted.** Both are required fields of the payload
(`src/core/store/op_state.zig:276-277`) and both callers set them deliberately —
`job kill` writes `true`/`true` (`cmd_job.zig:3104-3105`), `session rm` writes
`true`/`false` with a comment explaining that `tmux kill-session` hangs the pane
up and nothing sends SIGKILL (`cmd_session.zig:350-370`). `receipts.terminalEvent`
then drops them: its `remote_cancel_confirmed` arm
(`src/core/store/receipts.zig:684-708`) carries `verification_method` into
`cancel_method`, the pid/token pair, and `absence_verified_at` into
`finished_at`, and reads neither bool. There is no column for them —
`operation_events` (`migrate.zig:135-175`) has `cancel_method` (`:160`) and
nothing else cancel-shaped — so nothing downstream can recover them: the
receipt's own read-back lists the same columns (`receipts.zig:3160`, `:3200`).
What survives is only whatever the free-text `verification_method` happens to
say, which is prose and not a field a reader may branch on.

Cost to close: **a schema change.** Two nullable `INTEGER` columns on
`operation_events` in the next migration (v13 or later — the frozen list stops
at v12, `migrate.zig:604`), plus the column list and binds in
`receipts.insert` (`receipts.zig:348-356`), the `Event` field beside
`cancel_method` (`:110`), the read-back projection (`:3160`, `:3200`) and the
`hasColumn` drift probe pattern (`migrate.zig:906-907`). It is additive and
carries no data rewrite, so it is the §9.4-style exception rather than a rebuild.
`detail_json` is not an alternative channel: it is caller-owned, already refuses
to coexist with a result record (`ConflictingTerminalDetail`, `receipts.zig:604`),
and putting a module-owned field inside a document whose shape this module does
not control is the thing that comment exists to forbid.

---

## 4. Per-attempt physical session identity — decided

### 4.1 The contract

Each job attempt gets its own physical tmux session. A session is never reused
across attempts, and a command may only act on a session its own attempt
created.

**The incarnation is the attempt's request id.** It is minted by
`execution.begin` before anything reaches the host (`cmd_job.zig:156`), it is
already stored twice — `jobs.owner_request_id` (v9) and
`job_attempts.request_id` — it is already what the result sidecar is keyed by
(`Tmux.zig:180-185`), and it is 26 characters of Crockford base32
(`ids.zig:20`), which is inside the `[a-zA-Z0-9._-]` charset every name check in
the tree allows. Nothing new is stored and nothing is reordered to store it.

The physical session becomes `job-<name>-<request_id>`, so tmux sees
`t-job-<name>-<request_id>` through the existing `targetName`
(`Tmux.zig:92-94`). Length: `t-` + `job-` + ≤60 (`validateJobName` bounds the
name) + `-` + 26 = ≤93 characters.

**`job_attempts.tmux_session` already exists** (`job_attempts.zig:36`, `:62`,
`migrate.zig:234`) and already receives the session name at launch
(`cmd_job.zig:325`). Per-attempt identity changes what goes into that column,
not the schema.

### 4.2 Consequences, worked out

**Addressing stops going through the verb's argument.** `job kill`/`job rm`
derive the session from the job name they were handed
(`cmd_job.zig:502` via `:64-66`). Under this contract they must read it from the
attempt (`cmd_job.zig:507` already fetches the attempt). Deriving it from the
argument is precisely how a stale kill lands on a new session.

**A `jobs` row with no attempt becomes unkillable by `job kill`.** `attemptOf`
is optional throughout (`cmd_job.zig:3617`), and `job_attempts` arrived at v6,
so a row from before v6 has no attempt and therefore no recorded incarnation.
There is no derivable name to kill. It must **refuse** and say so, naming the
row and telling the operator to kill it by hand — a fallback to the old
`job-<name>` would be exactly the compatibility branch this project forbids.
This is a breaking change for pre-v6 rows and is the only one.

**The log becomes per-attempt for free.** `logPath` derives from the session
name (`Tmux.zig:81-83`), so attempt 2 gets `logs/job-deploy-<id>.log` and can no
longer append to attempt 1's bytes. That fixes §1.6 without touching the log
code, and it puts the log at the same grain as the sidecar.

**The cost of that is unbounded log accumulation.** Today one file per session
name; under this contract one per attempt, and nothing prunes them. `job run`
kills the previous attempt's session but never its log. This needs an answer:
§7.7.

**`session ls` gains a noisier remote half.** `Tmux.list` strips `t-`
(`Tmux.zig:639-641`) and `merge` matches remote names against local rows
(`cmd_session.zig:124-151`). Job sessions have no local `sessions` row —
`cmd_job.zig` never calls `sessions.ensure`, unlike `cmd_exec.zig:289` and
`cmd_session.zig:41` — so they already appear as remote-only entries named
`job-deploy` and would become `job-deploy-<id>`. Presentation is §7.8. What must
not happen is hiding them: an orphan nobody can see is an orphan nobody cleans
up.

**`tmux attach` ergonomics: the name stops being guessable.** An operator cannot
type `tmux attach -t t-job-deploy` any more. Two of the three messages that
print an attach hint already render `Tmux.targetName(session)` and stay correct
if `session` comes from the attempt (`cmd_job.zig:286`, `:3651`); the third
hand-writes `t-{s}` from the caller's argument (`cmd_session.zig:86`) and would
print a name that does not exist. The mitigation already exists: `job inspect`
publishes the attempt's `tmuxSession` (`cmd_job.zig:4112`). Every message that
tells an operator to attach must render the recorded name, never a derived one.

**An orphan from a crashed launcher stops being self-cleaning, and this is the
sharpest cost.** Today `job run` kills `job-<name>` before `ensure`
(`cmd_job.zig:282-288`), so the next launch of the same name clears the
wreckage. Under per-attempt naming the next launch has a *different* name and
will not touch the orphan, which keeps a shell — and possibly a running process
— indefinitely.

The answer is the same fact that makes identity work: the incarnation is the
request id, which is recorded on the `jobs` row (v9) and on every attempt before
anything reaches the host. So an orphan is always nameable from the ledger, and
`job run` must, before creating its own session, stop the sessions this job
name's own prior unsettled attempts recorded. That converts "kill the session
with my name" — a name-based act, and unsafe — into "kill the sessions my
predecessors recorded", an identity-based act. It is a remote destruction, so it
runs under `ControlAuthority` and records a control operation, which is how the
verb count grows and why §7.7's site-count gate matters.

**`reclaimable()` stops being a schema question.** It becomes two stages, and
the split is what keeps it fail-closed:

* the existing local predicate (`cmd_job.zig:107-113`) stays as a *fast
  refusal* — it may say "no", it may say "maybe", it may never say "yes";
* only a remote identity check may authorise the takeover: the owner's recorded
  incarnation is absent from the host, therefore that launcher is gone.

Cost: a launch that will be refused now dials before finding out.
`reclaimable` is consulted at `cmd_job.zig:209`, before
`execution.connecting()` at `:231` and `Cli.connect` at `:232`, so the local
stage preserves the cheap refusal for the cases it can decide and only the
ambiguous ones pay a round trip. A dial is not a mutation, but the change is
real and should not be discovered later.

### 4.3 Scope of the contract: attempts, not user sessions

A job attempt is a well-defined unit (`job_attempts.attempt_no`, per server and
job name, never reused — `job_attempts.zig:110-120`). A user session has no
attempts: `session new`, `exec <server>:<session>` and `write` exist *in order
to* reuse one shell across many commands, and `Tmux.ensure`'s idempotence is the
feature (`Tmux.zig:607`).

So this contract binds job sessions. For user sessions the analogous unit is an
incarnation minted by `session new` and invalidated by `session rm`, so that a
`write` holding a stale incarnation is refused rather than typed. Whether user
sessions get one at all, and where it is stored, is §7.9 — it is a separate
decision from the one made here, and pretending otherwise would smuggle a
`sessions`-table change in under a job-side heading.

**The scope key is the logical session; the kill target is the physical
incarnation.** These must not be the same string. If contention were keyed on
the per-attempt name, two attempts of the same job would hold non-overlapping
scopes and could run at once — reintroducing the exact defect the barrier
exists to prevent. Contention is logical and stable (`job-deploy`); identity is
physical and per-attempt (`job-deploy-<id>`).

---

## 5. Proposal: a v13 `session` scope

**This is a proposal, not a migration.** Nothing below has been applied: the
frozen migration list still stops at v12 (`migrate.zig:520`,
`leases_reowned_version = 12` at `:604`, `latest_version = migrations.len` at
`:588`), and `scope.Kind` still has no `session` variant. The first slice
(`d3bef52`) deliberately avoided all of this by deriving a `.job` scope from the
session name (`cmd_session.zig:592-597`).

### 5.1 What changes

* `scope.Kind` gains `session` (`scope.zig:9-16`). `parse` is
  `stringToEnum` (`:17-19`), so no table drives the vocabulary.
* `Scope.overlaps` gains a `.session` arm (`scope.zig:39-47`). The switch is
  exhaustive, so the build stops until the cell is answered; the answer is
  key equality, the same rule `.job` uses.
* `operations`: **no change.** `operations.scope_kind` is bare `TEXT`
  (`migrate.zig:111`), so a `session`-scoped operation row inserts today.
  `idx_operations_unsettled` (`migrate.zig:133-134`) hardcodes a *status* list,
  not a scope list, and is unaffected — worth stating because it looks like it
  should be.
* `leases`: **the CHECK is here** (`migrate.zig:565`) and SQLite cannot alter a
  CHECK, so v13 must rebuild the table.

### 5.2 The rebuild, and why it is cheaper than v12's

v12 already dropped and recreated `leases` (`migrate.zig:559-583`), so the shape
is precedented. v13 differs in the one way that matters: **rows can be carried.**
Every existing `scope_kind` value satisfies the widened CHECK and no column's
meaning changes, so v13 needs no `Refusal` variant, no live-lease refusal, and
no data loss. v12 needed all three because a pre-v12 `owner_token` was a machine
profile that must never be read as a request id (`migrate.zig:549-558`,
`Refusal.live_leases_cannot_be_reowned` at `:713`, the check at `:807-816`).

Sketch, with explicit column names per the SQL rules:

```sql
CREATE TABLE leases_v13 ( ... scope_kind TEXT NOT NULL
  CHECK (scope_kind IN ('server','job','path','session')), ... );
INSERT INTO leases_v13 (id, server_id, scope_kind, scope_key, owner_request_id,
  profile_token, owner_label, note, acquired_at, renewed_at, expires_at,
  released_at, release_reason, superseded_by) SELECT ... FROM leases;
DROP TABLE leases;
ALTER TABLE leases_v13 RENAME TO leases;
-- recreate idx_leases_active and idx_leases_owner
```

### 5.3 What else must move — the part a casual proposal misses

`checkPreReleaseDrift` compares the *stored* DDL text of `leases` and both its
indexes against frozen v12 slices (`migrate.zig:939-952`, slices at `:659-670`),
gated on `version >= leases_reowned_version` (`:604`). A v13 store's stored text
is the v13 statement, so **that probe fails on every v13 database** unless it
becomes version-gated: below 13 hold against the v12 text, at 13 and above
against a new v13 slice. All three probes, because a rebuild plus rename
re-stores all three statements. `leases_reowned_version` gains a sibling
constant for the two reasons its own doc gives (`migrate.zig:598-604`): the
drift probes key on it, and it must be a frozen number rather than "the latest".
The fresh-store gate that holds the frozen text (`migrate.zig:656-658`) must
learn the v13 slices too.

### 5.4 What breaks

* **Nothing in the data.** No row is rewritten and no value becomes illegal.
* **A binary rollover on one store, bounded by the lease TTL.** After v13,
  `write` and `exec <server>:<session>` claim `.session:<name>` where they
  claimed `.job:<name>`. A live lease row written by an older binary under the
  old key stops overlapping a new binary's claim. The exposure is one store
  driven by two binary versions inside one TTL — 120 seconds
  (`Claim.ttl_secs`, `control.zig:85`) — after which the stale row expires. Real,
  small, and stated rather than hidden.
* **`job kill`'s scope key changes**, and how is §7.10 — it is the one part of
  this proposal with more than one defensible answer.

---

## 6. Boundary notes

**`run`'s pre-`sendKeys` re-assertion stays.** `cmd_job.zig:337-364` re-reads
the reservation by owner on the last line before anything can reach the shell,
and its comment already says it narrows the window rather than closing it
(`:357-359`). Identity does not make it redundant; it makes its refusal
cheaper to explain.

**Reclaiming a local row creates no control operation.** Deleting a `jobs` row
mutates nothing remote. If a takeover must kill a session first, *that* is a
control operation with its own row (§2.2).

**`--force` on `run` keeps its current bound.** It already may not take a live
job's name (`cmd_job.zig:197-212`), and the displacement is a compare-and-swap
against the row just read (`:213-228`). Neither changes.

**`write` needs no control operation.** It is already `session_write` since
`7d0898a`. What it needs is the identity check in §2.2 and an answer to §7.4.

---

## 7. Decided — with the options kept as the rationale

**These were delegated to the Commander on 2026-08-18 and are now decided.** The
options below each item are kept, because a decision whose alternatives have been
deleted cannot be re-examined.

| | decision | departs from the recommendation below? |
|---|---|---|
| 7.1 | `control` | no |
| 7.2 | three columns on `operations`: `target_kind`, `target_key`, `target_request` | no |
| 7.3 | yes, `session new` gets an operation | no |
| 7.4 | refuse `--force` past an `indeterminate` overlap | no |
| 7.5 | **a new `Terminal` variant**, not `input_refused` | **yes** |
| 7.6 | a new `src/core/control.zig` | no (took (c) of (b)/(c)) |
| 7.7 | **`retention_rules`**, not a delete in the launch path | **yes** |
| 7.8 | one row per physical session | no |
| 7.9 | no incarnation for user sessions in M3b | no |
| 7.10 | `.session:"job-<name>"` only | no |
| 7.11 | on the control operation where a kill happened, otherwise none | no |

Two departures, both for the same reason — the repo has repeatedly paid for
putting a convenient word in a durable place.

**7.5.** Reusing `input_refused` is rejected. `input_accepted` and
`input_refused` exist *because* settling a write as `.exited{0}` wrote a false
word into a receipt where an auditor reads the exit code first (`7d0898a`).
Reusing an input-named terminal for a session identity mismatch repeats that
mistake one level up. The build stopping in `terminalDescribesKind` for every
kind is the forcing function, not the cost. `(c)` stays rejected for the reason
given: a mismatch is proven, and recording a proof as an unknown leaves a scope
blocked.

**7.7.** Deleting the previous attempt's log in `job run` is rejected because it
misreads what per-attempt naming already buys. Once each attempt owns its log
path, §1.6's corruption — appending to the previous attempt's log and then
reading it from cursor 0 — is gone. What remains is disk growth alone. Paying for
that with a new destructive site in the launch path means new authority, new
failure modes, and a change to the asserted site count of the "renewed on the
line above" gate — poor value for a housekeeping problem `retention_rules`
(`migrate.zig:350`) already exists to solve.

### Implementation order, decided

The first slice is the one with **no migration at all**: `session rm` and
`session new` get a `control` operation and a lease on the **existing** `.job`
scope. That closes §1.2 — a destructive remote mutation running with no ledger
entry, able to kill a running job's shell — without waiting for v13.

It is available today because `operations.kind` is bare `TEXT`
(`migrate.zig:110`), `leases` already speaks `.job` (`migrate.zig:565`), and
`alias` already carries session names (`cmd_exec.zig:86`). The `target_*` columns
of 7.2 and the `.session` scope of §5 follow in v13, and §1.3's scope-vocabulary
hole closes with them — not before, since fixing it *is* the scope change.

---

## 7a. The options, as reasoned at the time

**7.1 The `Kind` variant's name.** (a) `job_control` — matches the M3b brief,
but `session rm` is not a job. (b) `control` — accurate across all four
actions, and short. (c) one variant per action, no `ControlAction` enum —
maximal type safety, four times the `receipts` cells, and the action stops being
a queryable column. *Recommend (b)*: the target relation already says what it
was about, and the two `receipts` tables get one column instead of four.

**7.2 The target relation's columns.** (a) three columns on `operations`
(target kind, key, request) — queryable, indexable, three nullable additions in
v13. (b) one JSON column — one addition, not indexable, and it puts a relation
inside a blob. (c) a separate `operation_targets` table — cleanest if a control
act ever names two targets, and a join for every read. *Recommend (a)*, on the
grounds that "control operations targeting X" must be answerable without
walking events or parsing JSON. Names themselves are yours.

**7.3 Does `session new` get an operation row?** (a) yes — every remote act is
in the ledger, and adoption is a remote act; costs a row per session creation.
(b) no, but it must stop reporting `action: "created"` for an adoption
(`cmd_session.zig:50`); cheapest, and leaves creation unledgered. (c) an
operation only when it *adopts*. *Recommend (a)*: `session new` reaches the host
and can fail there, and (c) makes the ledger's coverage depend on a remote
answer.

**7.4 `write --force` past an `indeterminate` overlapping operation.** Allowed
today. (a) keep it — no break, and it is the one case where forcing types the
same bytes into the same shell twice. (b) refuse it, keep `--force` for leases
only — safer, and a breaking change to a documented escape hatch. (c) refuse
unless a second flag is given — honest, and two flags for one act is a smell.
*Recommend (b)*, and note plainly that it breaks a published behaviour.

**7.5 Which terminal carries an identity mismatch.** (a) `input_refused` —
already means "the remote answered, and nothing was touched"
(`op_state.zig:324-328`), but its name is about input. (b) a new `Terminal`
variant — accurate, and it stops the build in `terminalDescribesKind` for every
kind and needs a `migrate` column review for its evidence. (c) `indeterminate`
with a distinct `error_code` — cheapest, and wrong: a mismatch is *proven*, and
recording a proof as an unknown leaves a scope blocked. *Recommend (a)* for the
control kind and *(b) only if* the reviewer wants the name to read correctly.
Not (c).

**7.6 Where `ControlAuthority` lives, and the name collision.**
`cmd_job.zig:4309` already defines `Authority`. (a) rename the existing one and
keep both in `cmd_job.zig` — no module move, and `session rm` cannot reach it.
(b) move it to `src/core/` so `cmd_session.zig` and `cmd_read_write.zig` can
hold one — the right home, and a module-boundary change. (c) a new
`src/core/control.zig` owning the three primitives of §2.3 — cleanest, largest.
*Recommend (b) or (c)* — **this is a module boundary decision and is yours.**

**7.7 Log retention under per-attempt naming, and the gate's site count.**
(a) `job run` deletes the previous attempt's log after proving that session
gone — bounded, and it is a destruction, so it needs authority and adds a site
to the "renewed on the line above" gate whose count `1f47542` asserts.
(b) a retention rule in the existing `retention_rules` table
(`migrate.zig:350`) — no new destruction in the launch path, and logs live until
a sweep runs. (c) nothing — unbounded growth. *Recommend (a)*, and note that
every new destructive site changes that gate's asserted count.

**7.8 What `session ls` shows.** (a) one row per physical session, incarnation
included — honest, noisier, and orphans are visible. (b) group by logical
session with an incarnation column — readable, and it needs the logical name
parsed back out of the physical one, which is string surgery on a name.
(c) hide job sessions behind a flag — quietest, and it hides exactly the
orphans somebody has to clean up. *Recommend (a)*.

**7.9 Do user sessions get an incarnation?** (a) no — job sessions only; `write`
keeps no identity check, and §1.3's false-miss is closed by the scope change
alone. (b) yes, a column on `sessions` minted by `session new` — closes
`write`'s identity gap, and it is a `sessions`-table change with its own
migration and its own `session ls` consequences. (c) yes, derived from the
remote `session_created` field tmux already reports (`Tmux.zig:620`,
`:642`) — no schema change at all, and it trusts a value the host controls and
that survives nothing. *Recommend (a) for M3b* and (b) as its own decision
later; (c) reads an identity out of a field an unrelated tmux restart can
change.

**7.10 What scope does a job claim after v13?** (a) `.session:"job-<name>"`
only — one lease, and the job *name*'s exclusivity is already enforced by
`UNIQUE(server_id, name)` (`migrate.zig:68`) plus `jobs.remove`'s
compare-and-swap (`cmd_job.zig:221-228`), so the `.job` scope is largely
redundant. (b) both `.job:<name>` and `.session:"job-<name>"` — strictly safer,
and it needs two lease rows per job, which introduces a lock-ordering rule the
tree does not have today (`leases.AcquireOptions.scope` is singular). (c) make
`.session` overlap `.job` when the session name is `job-<key>` — no extra lease,
and it puts string surgery inside `Scope.overlaps`, which is the one function
that must stay obviously correct. *Recommend (a)*. It newly blocks
`write web:job-deploy` against a running job — the hole in §1.3 — and stops
blocking `exec web:deploy` against job `deploy`, which are different shells and
should never have blocked each other.

**7.11 Does deleting a local row earn a record?** `jobs.remove`'s grounds are a
comptime guard and are not persisted (§0's footnote). (a) no — the immutable
attempt row survives the delete and is the audit record; a second one duplicates
it. (b) yes, on the control operation that performed the takeover's kill —
free, because that row exists anyway under §2.2. (c) a ledger entry for
local-only destruction in general — the complete answer, and it is a new
terminal or a new kind for a class of act this document did not survey.
*Recommend (b)* where a kill happened and *(a)* where none did.

---

## 8. How this would be verified

Listed so the contract is judged with its cost attached. Written for the
`session rm` slice only; everything else on this list is still unwritten. The
gates that exist are named inline below, and the slice's mutation entries are
`tools/mutations.json:517-603` (the nine `M3b-session-rm-*` ids), with the
shared barrier's two at `:164-179` (`M4-still-ours-always`,
`M4-authority-latch`, both over `src/core/control.zig`).

* A control operation exists, is queryable by request id, and settles
  independently of its target — asserted by reading both rows out of the store,
  not out of the report. **Done for `session rm`**
  (`test/blackbox.zig:3366`); its target is a session with no attempt row, so
  the independent-settlement half is still unexercised.
* Lease lost before the kill: control `failed`, target untouched, and **zero**
  remote commands asserted on the fake host's received list. **Done for
  `session rm`** (`test/blackbox.zig:3502`), which needed a seizure on the
  version handshake because its first remote call *is* the kill
  (`test/blackbox.zig:948-967`).
* Lease lost after the kill: control `indeterminate` carrying `AUTHORITY_LOST`,
  target's proven exit code intact. **Done for `session rm`**, in both windows —
  after the kill (`test/blackbox.zig:3577`) and inside the log deletion
  (`:3643`).
* Incarnation mismatch: the kill is refused, the session survives, the control
  operation records the refusal as a *proven* outcome, not an unknown. Driven by
  launching, killing and relaunching under one job name. **Unwritten** — §4 does
  not exist.
* `session rm` under a held session lease is refused and records the refusal.
  **Done** on the derived `.job` scope (`test/blackbox.zig:3436`), not on the
  `session` scope §5 would give it.
* `session rm web job-deploy` against a running job is refused — the case that
  used to succeed silently (§1.2). **Done** (`test/blackbox.zig:3781`).
* A `session new` cannot land inside a `session rm`. **Unwritten**, because the
  behaviour is unwritten (§1.2's open half).
* `write web:job-deploy` against a running job is refused without `--force`
  — the false miss in §1.3. **Unwritten.**
* A second attempt's `job read --from-cursor` returns none of the first
  attempt's bytes (§1.6). **Unwritten.**
* An orphan session from a killed launcher is found and stopped by the next
  `run` of the same job name, by recorded incarnation and not by name.
  **Unwritten.**
* A pre-v6 `jobs` row with no attempt is **refused** by `job kill`, with a
  message naming the row. **Unwritten.**
* v13: a v12 store carrying live lease rows opens, migrates, keeps every row,
  and passes the version-gated drift probes; a v13 store opened by a v12 binary
  is refused by the existing future-version check (`migrate.zig:775-781`).
  **Unwritten** — there is no v13.
* Every new gate mutation-tested and added to `tools/mutations.json`. **Done for
  the gates this slice added**; the rule stands for the rest.
