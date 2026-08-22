---
name: terminus
description: >-
  Operate remote servers over SSH with persistent sessions and per-server
  memory. Use when the user asks to run commands on a remote server, manage
  long-running remote tasks, or when returning to a server you have worked
  on before (check memory first). Covers: remote exec, persistent tmux
  sessions, cursor-based output reading, and storing/recalling knowledge
  about servers.
---

# Terminus — remote servers with memory

Terminus gives you durable remote shell workspaces instead of one-shot SSH
commands. Everything supports `--json` for reliable parsing.

**Requires terminus >= 0.1.10.** If a documented flag is rejected, the
installed binary is older than this document: check `terminus version`
and upgrade with `npm install -g terminus-shell@latest`.

## Passing commands and content reliably (Windows/PowerShell!)

PowerShell and some tool-call layers mangle `--`, `;`, `*` in bare
arguments. Prefer the quote-proof channels, most robust first:

```bash
terminus exec <server> --argv-json '["uname","-a"]'  # argv; one word per element
terminus exec <server> --stdin                      # command from stdin
terminus exec <server> --cmd-file ./script.sh       # run a local script remotely
terminus exec <server> --cmd "uname -a"             # single flag value
terminus exec <server> -- uname -a                  # classic; fine in bash

terminus memory add <server> --key gotchas --stdin  # content from stdin
terminus memory add <server> --key gotchas --content-file notes.txt
terminus memory add <server> --key gotchas --content "text with ; and *"
```

For agents: **use `--argv-json` when any argument is a value you did not write
yourself** (a path, a name, anything with a space or a quote in it), `--cmd` for
one-liners you wrote, and `--stdin` for multiline scripts.

Windows CRLF is **not** rewritten for you. Command text from `--stdin` and
`--cmd-file` is sent as they were read, byte for byte. If it holds a carriage
return, terminus says so once on stderr and publishes the count in `--json`
(`commandCarriageReturns`, and `commandNormalizedLf` for whether anything was
changed) — because a `\r` a POSIX shell keeps turns `true` into `true\r` and
nothing downstream explains why the comparison failed. Pass `--normalize-lf` to
convert CRLF/CR to LF; that is the only thing that rewrites those bytes.

## Multiline scripts run byte-exact

Multiline input to `exec`/`run` is automatically staged as a remote temp
file and executed as one script — heredocs, nested quoting, `$VAR`, and
error line numbers all behave exactly as in a local script. Two flags:

```bash
# Deploy script: stop at the first failing line, exit code = that line's
printf 'git pull\nnpm ci\nnpm run build\n' | terminus exec prod --stdin --strict

# Any interpreter, not just bash:
terminus exec prod --stdin --interpreter python3 <<'EOF'
import json, pathlib
print(json.dumps({"files": len(list(pathlib.Path(".").iterdir()))}))
EOF
```

**Use `--strict` for deploy/migration scripts** — without it bash keeps
going after a failed line and only the last line's exit code is reported.
Single-line commands skip staging entirely (no overhead) unless
`--interpreter` is given, which always stages. Staged files are removed at the
end of a one-shot `terminus exec`, which is also where the daily sweep of older
staged files rides — session `exec` and `run` stage without cleaning up, so
their temp files wait for the next one-shot `exec` to sweep them.

## Tools missing in non-interactive shells (nvm/pm2/bun)

Plain SSH exec skips ~/.bashrc, where nvm/bun/pm2 set up PATH. If a tool
"exists on the server but isn't found":

```bash
terminus doctor <server> --json    # loginOnlyTools lists exactly these
terminus exec <server> --login --cmd "pm2 list"   # wraps in bash -ilc
```

Sessions (`<server>:<sess>`) **refuse** `--login` — they are real interactive
shells already, so it would do nothing. Earlier versions accepted it, dropped
it, and recorded `shell: "bash-login"` for a command nothing had wrapped; the
refusal happens before anything is sent, so dropping the flag is the whole fix.

## Naming a command as an argv, and naming the shell

Two flags for the case where the command is *data* — a path an operator typed,
a value out of a config file — rather than something you wrote yourself:

```bash
# Every element becomes exactly one shell word. A space, an apostrophe, a $, a
# backtick, a newline or a ; inside an element stays a byte of that word.
terminus exec prod --argv-json '["rm","-f","/data/John'"'"'s files/x.log"]'
terminus run prod --name tidy --argv-json '["find","/srv","-name","*.tmp","-delete"]'

# Declare the interpreter. bash (the default), zsh, or none.
terminus exec prod --shell none --argv-json '["/usr/local/bin/report","--to","a b"]'
```

`--argv-json` takes a JSON **array of strings**. It is one command, never a
script: it is never staged, so `--interpreter` alongside it is refused, and a
newline inside an element is part of that word rather than a second line. It is
also a command *source*, so pairing it with `--stdin`, `--cmd`, `--cmd-file`,
`--` or a bare positional is refused — two sources for one command is an
ambiguity, not a precedence question. A malformed value is refused by which
mistake it was: not JSON, not an array, an element that is not a string (with
its index), or an empty array.

`--shell` declares the interpreter and takes `bash|zsh|none`:

- `bash` is the default and is what every earlier version did.
- `zsh` wraps and stages under zsh instead (`zsh -ilc`, `zsh <script>`).
- `none` means **terminus adds no shell layer of its own** — no `bash -ilc`, no
  `set -euo pipefail` prefix, no staged script. It does not and cannot mean "no
  shell ran it": SSH exec takes a command *string*, and the remote sshd hands
  that string to the account's shell whatever terminus does. So `--login`,
  `--strict`, `--interpreter` and a multiline command are each refused with
  `--shell none`, because each of them is a layer it says are absent.

**Any other value is refused before anything is sent**, and `powershell` is the
one worth stating: terminus supervises a command with a POSIX shell wrapper —
that wrapper is what reports the pid, the pgid, a start token and the exit
status. PowerShell does not run it, so a command sent there would come back with
no exit marker and every run would settle `indeterminate`. A shell enters the
vocabulary once a wrapper exists for it, not before, which is why `sh` and `dash`
are refused too.

The shell that ran a command is recorded on its ledger row (`bash`,
`bash-login`, `zsh`, `zsh-login`, `none`) and is the wrap that actually
happened — `exec`, `run` and session `exec` all shape their command through one
code path, so `--strict --login` composes the same way on all of them:
`bash -ilc 'set -euo pipefail; <cmd>'`, with `--strict` inside the wrap so the
first failing line's status is the one reported.

## Golden rule: recall before you act

Before touching a server you may have seen before:

```bash
terminus server ls --json            # what servers exist?
terminus memory ls <server> --json   # what do I know about it?
```

Every `exec --json` response that reaches the remote also includes `memoryKeys`
— the list of memory keys stored for that server. (A failed `exec` prints the
plain `{"ok":false,"error":...}` shape and carries no `memoryKeys`.) If you see
keys you haven't read this conversation (e.g. `services`, `deploy`), read them
before continuing:

```bash
terminus memory show <server> --key services --json
```

Memory entries record deploy paths, service quirks, past incidents. Read
them first; they replace re-discovery work.

## Structured memory keys (convention)

Use these keys so future agents (including you) find facts predictably:

| Key | Content |
|---|---|
| `services` | What runs on this server: name, port, how managed (systemd/docker/pm2) |
| `deploy` | How to deploy: directory, commands, order, restart procedure |
| `layout` | Important paths: app dirs, configs, logs, data |
| `access` | Quirks: sudo rules, users, firewall, jump hosts |
| `gotchas` | Past incidents and surprises — read before risky changes |

For single stable values you plug into commands (paths, tool names), prefer
`fact set/get` — facts are exact key/value lookups, memories are prose.

Example of good memory upkeep after discovering a server:

```bash
terminus memory add prod --key services -- "nginx :80/:443 (systemd), api :3000 (docker compose in /srv/app), postgres :5432 (systemd)"
terminus memory add prod --key deploy -- "cd /srv/app && git pull && docker compose up -d --build; nginx config in /etc/nginx/sites-enabled/app"
terminus memory add prod --key gotchas -- "docker compose v1 NOT v2 — use 'docker-compose' with dash"
```

Same `--key` **replaces** the entry (the JSON response includes `previous`
so nothing vanishes silently); use `--append` to add a line instead. Keep
each entry short and factual — it's an index card, not a log.

## Quick reference

```bash
# First contact with a server: probe its capabilities
terminus doctor <server> --json      # shell, OS, tmux?, disk, memoryKeys

# One-shot remote command (no tmux needed on the server)
terminus exec <server> --json --cmd "uname -a"

# Set a default working directory once, stop writing `cd X && ...`
terminus workspace set <server> /srv/app
terminus exec <server> -- git status          # runs in /srv/app

# Tracked background job (survives CLI exit; needs tmux)
terminus run <server> --name build -- npm run build
# status: submitted | remote_started | completed | failed | indeterminate
terminus job status <server> build --json     # + exitCode; exits 75 when outcomeProven is false
terminus job read <server> build --from-cursor --json
terminus job watch <server> build --interval 30s --json  # block until it ends
terminus job kill <server> build               # 75 if unprovable, 1 if the kill was refused
terminus job ls <server> --active --limit 20 --json

# Persistent interactive session (requires tmux on the server)
terminus session new <server> <name>
terminus exec <server>:<name> --json -- cd /srv/app   # state persists
terminus exec <server>:<name> --json -- docker compose ps
# Kill it + delete its log + forget its memories. Refused while a job or another
# command holds the session's scope; 1 if refused, never a silent success.
terminus session rm <server> <name> --json

# File transfer (SCP) — single files or whole directories
terminus push <server> ./local-file /remote/path [--mode 755]
terminus pull <server> /remote/file ./local-path
# No scp binary on the server (minimal images, OpenSSH 9+)? add --via exec
# — moves bytes over the plain command channel (needs base64 on the host), any
# size. Downloads are slow (libssh2 read speed; the scp backend is no faster)
# but reliable. push/pull auto-fall back to exec if scp is absent.
terminus push <server> ./cfg /etc/app/cfg --via exec
# A path an unfinished transfer is still standing on is refused, and the refusal
# names which of the two verbs its state calls for — see "File transfer".
# --resume continues an interrupted one from its confirmed offset (exec only);
# --restart releases a settled failure's hold and starts from zero.
terminus push <server> ./app.tar /srv/app/app.tar --resume
terminus push <server> ./app.tar /srv/app/app.tar --restart
terminus sync push <server> ./dist /srv/app/dist --exclude node_modules,.git [--dry-run] [--delete]
terminus sync pull <server> /var/log/myapp ./logs [--exclude *.gz]

# Machine-readable facts (for orchestration; memory is for prose)
terminus fact set <server> app_root /srv/app
terminus fact get <server> app_root          # plug into commands
terminus fact ls <server> --json

# Audit trail of everything you ran
terminus history <server> --limit 20 --json

# Raw session I/O (when you need keystroke-level control)
terminus write <server>:<name> -- "journalctl -f"
terminus read <server>:<name> --from-cursor --json

# Save what you learned (do this before finishing!)
terminus memory add <server> --key deploy_dir -- "app in /srv/app, deploy via compose"
```

## Choosing exec mode

| Situation | Use |
|---|---|
| Single command, no state needed | `exec <server>` — works everywhere, no tmux required |
| Anything longer than ~60s | `run --name X` then poll `job status` — exit code never lost, other commands stay free |
| Multiple related commands (cd, env, activate) | `exec <server>:<sess>` — state persists between calls |
| Interactive process (REPL, log follow) | `write` + `read --from-cursor` |
| Remote has no tmux | plain `exec <server>` only; `doctor` tells you upfront |

Long `exec` calls (multi-minute scans/builds) are fine — they don't block
other terminus commands, which run concurrently on their own connections.
Jobs are still preferred past ~60s: they survive your process dying and
report status without holding anything open.

Every failure carries `"ok":false` in `--json` mode. Exit 1 is a refusal or a
proven failure; exit 75 means the remote outcome could not be established —
**never retry that blindly**; exit 76 means the local receipt could not be
written. A hard failure prints `{"ok":false,"error":"..."}` and nothing else, but
a refusal a verb owns prints that verb's own full key set with `ok:false` and no
`error` key — `job kill`'s `"action":"not_killed"` is one — so branch on `ok` and
the verb's own fields, never on the presence of `error`. `transport` ("daemon" or
"direct") and `daemonError` appear on the commands that open a connection —
`run`, `exec`, `doctor`, `server ping`, `write` and `job status` carry both,
`job watch` carries `transport` only. Mention repeated daemon fallbacks if
you see them. Purely local commands (`memory`, `fact`, `history`,
`daemon status`, `import`/`export`) carry neither, `job read`/`job kill`/`job rm`
and session `read` carry neither, and `push`/`pull`/`sync` are always direct and
report `backend` instead.

## Jobs: the reliable way to run long tasks

`run` starts the command in a dedicated remote tmux session. When the command
returns, its exit status is recorded on the host twice: authoritatively in
`~/.terminus/results/<request-id>.json`, and as a fallback sentinel line in the
pane log. The sidecar is what keeps a job answerable — a job that keeps printing
after it finishes pushes the sentinel out of the readable tail window, the file
never moves. Nothing is lost if your process, the CLI, or the SSH connection
dies — the job keeps running and stays queryable:

```bash
terminus run prod --name migrate --cwd /srv/app -- ./migrate.sh
# ...later, from any process:
terminus job status prod migrate --json   # {"status":"completed","exitCode":0,...}
terminus job read prod migrate --json     # full output
terminus job rm prod migrate              # cleanup when done
```

Job names are unique per server while running; finished names can be reused.

### The `status` field: these values and no others

`job status`, `job read` and `job watch` report the **operation's** status, not
a process state. The complete set:

| `status` | Meaning |
|---|---|
| `created`, `connecting`, `submitted` | the launch has not been confirmed on the remote shell yet — a row still in its launch window reads `created` |
| `remote_started` | running; no outcome yet |
| `completed` | the command exited 0 |
| `failed` | the command exited non-zero — `exitCode` says which |
| `indeterminate` | the outcome could not be established; the command exits 75 |
| `timed_out`, `cancelled` | only after a human `request reconcile --override` (full form below) |

There is no `pending`, `running`, `exited` or `killed` in this field — those are
the four cached row labels `job ls` prints from its local snapshot, and matching
them against `job status` never fires.

`ok` is **not** `status != "indeterminate"`. It is true only when
`outcomeProven` is true *and* nothing else the command was asked to do was
refused: a local cache row that could not be brought along, or — on `job read` —
a cursor that could not advance (`cursorAdvanced:false`), each make `ok` false
and exit 1 while `status` still reads `completed`. These three verbs report a
refused cache row only in `hint`; the machine-readable `cacheError` key exists on
`job kill` / `job rm` only. Branch on `ok` and `outcomeProven`, never on `status`
alone.

`indeterminate` means one of: the session vanished without recording an exit
status; the two durable records disagree; the result record is present and
unusable; or a `job kill` / `job rm` lost its scope lease mid-flight, which is
recorded as `indeterminate` carrying `error_code: "AUTHORITY_LOST"` — not a
state of its own. **Do not relaunch the work**: the attempt goes on blocking
same-scope commands until it is settled with
`terminus request reconcile <request-id> [--from-log]`, or by hand with
`--override "<reason>" --by <who> --resolved <completed|failed|timed_out|cancelled>`
(all three parts are required; a bare `--override` is rejected).

A launch refused by such a blocker will first spend one connection asking the
host whether that blocker has in fact already finished, and settle it from the
evidence if so — which usually means the relaunch simply proceeds. If the host
is unreachable the refusal stands and says so; it is never replaced by a
connection error.

### Fields on job status / read / watch

- `exitCode` — the remote exit code, `null` while unknown.
- `businessResult` — the last `__TERMINUS_RESULT__:<v>` line (see below).
- `progress` — the last `__TERMINUS_PROGRESS__:<json-object>` line, as the raw
  JSON text the job printed, or `null`. `phase` is the last
  `__TERMINUS_PHASE__:<label>` line. Both are **remembered**: they are recorded
  as the job runs and go on being reported after the job has ended, after its
  tmux session is gone and after its log has been rotated away. That is what
  makes them answerable on a finished job, and it means a value here is
  something the job really printed at some point — not necessarily something it
  printed recently. `progressError` says when the reading is not current.
- `progressError` — prose, `null` when nothing was wrong. Two things reach it:
  the job's most recent `__TERMINUS_PROGRESS__` line was refused (its body is
  not a JSON object, or it is over 4096 bytes), or the forward read of the log
  did not happen at all. Either way `progress` beside it is the last value that
  *was* usable rather than a reading of the log as it stands. A refused line
  never overwrites a good one — a job that starts printing malformed progress
  does not lose the last progress it reported.
  `progress`, `phase` and `progressError` are on `job status` and `job watch`
  only; `job read` carries none of them.
- `outcomeProven` / `settlement` — whether the ledger actually backs `status`,
  and which reading it is: `open` (nothing has ended), `settled`, `no_attempt`
  (the row names no attempt, so the host's own record is the whole answer), or
  `unproven` (this observation settled nothing — exits 75).
- `resultRecord` — what was at the result sidecar's address, as a stable word.
  Three are ordinary — `not_requested` (we did not look), `absent`, `present`
  (it is there and it is ours) — and four say a document at this attempt's own
  address could not be used: `malformed`, `unknown_schema`,
  `exit_code_out_of_range`, `foreign`. On `job kill` and `job rm` two further
  values can arrive, and they are not readings at all: `read_error` and
  `probe_error` — the first says the look after the kill found a file at that
  address and the host could not obtain its bytes; the second says that look
  never happened at all, because the round trip failed (a broken channel, a
  remote failure, a `tmux` that stopped being runnable). Either way nothing was
  read, so no reading may be assumed — least of all `absent`, the one word that
  lets the log's sentinel settle the job by itself. `read_error` comes from both
  verbs; `probe_error` from `job rm` only, because `job kill` already reports
  that fault as its ordinary unprovable cancellation. `resultRecordError` is
  prose beside it, `null` for the three ordinary readings, with two exceptions —
  two stable values it may branch on: `read_error` and `probe_error`. Each
  arrives on exactly the branch where `resultRecord` says the same word, and
  nowhere else.
- `finishedAt` — a **remote** finish time in unix seconds, taken from the result
  file. `null` unless the host reported its own clock (a sentinel-only outcome
  has no timestamp). Never backfilled with local time.
- `observedAt` — local unix seconds when we saw the evidence. Not a finish time.
  `finishedAt` and `observedAt` are on `job status` and `job read` only —
  `job watch` carries neither.
- `conflict` — normally `null`; `{"resultExitCode":N,"sentinelExitCode":M}` when
  the result file and the log sentinel report different exit codes. The
  observation then settles nothing, so `status` reads `indeterminate` and the
  command exits 75 — unless the ledger had already settled this attempt from
  earlier evidence, which stands. No mechanical reconcile can settle a live
  contradiction; it needs
  `terminus request reconcile <request-id> --override "<reason>" --by <who> --resolved <status>`.
- Command-specific: `job status` adds `server`, `command`, `createdAt`,
  `transport`, `daemonError`; `job read` adds `from`, `to`, `data`,
  `cursorAdvanced` and `cursorError` (on a refused cursor advance `to` stays at
  `from` — read `cursorAdvanced`, not `to`, to know whether you may move on);
  `job watch` adds `server`, `stillRunning`, `polls` and `transport`.
  `job read`'s `from` / `to` are the **reader's** cursor. The state probe keeps
  its own, which `job read` never moves and which never moves the reader's.

**`job ls` is a different shape and a different clock.** It prints the local
cache, so its `status` holds the cached row labels
`pending`/`running`/`exited`/`killed` rather than an operation status
(`pending` is a row whose launch has not reached the remote shell yet;
`--active` shows exactly `pending` and `running`), and its finish time is
`cachedFinishedAt` — named apart from `finishedAt` on purpose, because it falls
back to local time when the host reported none. Use `job status` when the answer
matters; `job ls` is for looking around.

### Stopping and forgetting jobs

Both verbs hold a scope lease and **renew it immediately before every step that
changes something** — the kill, each deletion, the settlement. Only a renewal
that answers "still ours" lets the next step run; a renewal that could not be
performed at all counts as a loss, not a yes. Both report `authority`
(`held` | `lapsed` | `unreadable`) and `authorityError` (prose, `null` while
`held` — branch on `authority`).

- **Lease lost *before* the kill**: nothing is sent to the host and nothing local
  is written. `action` is `not_killed` / `not_removed`, `ok:false`, and the exit
  code is **1, not 75** — this command changed nothing, so nothing about the
  remote is unknown *because of it*, and re-running once the scope frees is safe.
  The log, the result record and the local row are exactly as they were.
- **Lease lost *after* the kill**: the session really did stop, and every step
  after it is forbidden — the pane log, the result sidecar and the local job row
  are all **kept**. `job rm` reports `rowRemoved:false`, `action:"not_removed"`
  and exits 1. The ledger records the ordinary `indeterminate` terminal carrying
  `error_code: "AUTHORITY_LOST"`; there is no `authority_lost` state.
- **A lost lease costs the claims, not the reading.** An exit code that was
  actually read still counts: the sidecar is keyed by this attempt's request id,
  so another holder cannot forge it and a relaunch would be a new attempt under a
  new id. So `job kill` still records `exited` and still reports that `exitCode`
  with `"action":"finished_during_kill"`. What downgrades is every claim resting
  on the kill having landed — `cancellationProven` goes false and the
  `remote_cancel_confirmed` terminal is never published. `ok` is still false and
  the exit is 1.
- **One asymmetry, deliberate.** On a `job kill` that loses the scope with *no*
  exit code in hand, the local `job ls` row reads `killed` while the ledger reads
  `indeterminate`/`AUTHORITY_LOST`. The row records that the pane was proven gone
  in the round trip that stopped it; the ledger records that we can no longer say
  what happened to the work. That case is still unprovable, so it exits **75**,
  not 1.
- `job kill` probes before it kills. If the job had already finished it records
  that outcome and reports `"action":"already_finished"` — the real exit code,
  not a cancellation. Otherwise it kills the session and reports
  `cancellationProven`, which is **false in every shipped path**: the shell
  supervisor's `pid_proof` is `weak` and a proven cancellation requires `strong`,
  because a disowned or `setsid` child outlives its pane. So the kill settles
  `indeterminate` and exits 75 rather than claiming the work stopped. The log is
  never deleted here, so `reconcile --from-log` stays possible.
- Once the session is confirmed gone, `kill` and `rm` look **once more**. A job
  that ended by itself in the gap between the first probe and the kill has left
  a real exit status, and settling it as an unprovable cancellation would throw
  that away. `kill` reports that as `"action":"finished_during_kill"` with the
  job's own exit code; `rm` uses it to settle before it removes anything. A
  second look that still finds nothing, or turns up a fresh disagreement,
  changes nothing — the cancellation path stands. Two findings do change things.
  A result record *present and unusable*: nothing may settle from it,
  `resultRecord` reports the defect, and both verbs send you to `--override`
  rather than `--from-log`. And a result record the host **could not read** at
  all: `resultRecord` and `resultRecordError` both read `read_error`, both verbs
  settle `indeterminate` and exit **75**, and **nothing is destroyed** — the pane
  log, the result file and the local job row all stay, on `job rm` and on
  `job rm --discard-evidence` alike (`rowRemoved:false`,
  `action:"not_removed"`, `evidenceRetained:true`). A read that failed is not an
  absence, so the log's sentinel is not allowed to settle the job in its place.
  A second look that could not be taken **at all** — a broken channel, a remote
  failure, a `tmux` that stopped being runnable between the kill and the look — is
  the same refusal under the other word: `job rm` and `job rm --discard-evidence`
  report `probe_error` in both keys, settle `indeterminate`, exit **75** and
  destroy nothing, and here the next step is `--from-log` rather than
  `--override`, because both records are still on the host exactly as the job
  left them. `job kill` is deliberately unchanged by that one: the fault already
  lands on its ordinary unprovable cancellation, which is `indeterminate` and 75
  as well.
- **`job kill` exit codes.** **0** only when it has something proven and every
  step it was asked to take happened. **75** whenever the outcome is unknown:
  the ordinary unprovable cancellation, a lost lease after a kill with no exit
  code, a `conflict` between the two records (reported as `"action":"killed"`,
  `ok:false`, with the `conflict` object), an unusable result record, a result
  record that could not be read after the kill, and an `already_finished` or
  `finished_during_kill` the ledger refused to settle.
  **1** when the outcome is not in doubt but this command is: a pre-kill lease
  refusal (`not_killed`), a
  `finished_during_kill` that lost the lease, a proven outcome whose tmux session
  survived the kill (the next launch under that name would otherwise type into
  the dead job's shell), and a settlement whose local row could not be brought
  along (`cacheError` non-null).
- `job rm` kills the session first and refuses to delete anything — log, result
  file, or local row — if the session is still there afterwards; that refusal is
  a plain `{"ok":false,"error":"..."}` and exit 1, not a removal record. It
  settles from the better of its two probes — the one taken beforehand, upgraded
  by the post-kill look when that is the one that saw the exit status. With the
  outcome provable you get `outcomeProven:true`; with the outcome still unknown
  it removes the job, keeps the log, and returns `ok:true` with a hint to run
  `reconcile <request-id> --from-log`. A `conflict` or an unusable result record
  removes the row too and exits 75. Two cases **keep** the row: a post-kill look
  that could not read the result record, and a post-kill look that could not be
  taken at all. Both report `action:"not_removed"`, `rowRemoved:false` and exit
  75; the first sends you to `--override` (the document itself will not open), the
  second to `--from-log` (the documents are intact; the wire was not).
- **Refused when it was about to be recorded.** Every renewal held and the kill
  went out, and then the one transaction that was to write the terminal and forget
  the row declined it. Three reads can decline it and each names itself in
  `errorCode`: a peer's claim on the scope (`SCOPE_TAKEN_BEFORE_COMMIT`), this
  command's own lease no longer being live and ours (`CLAIM_LOST_BEFORE_COMMIT`),
  and the compare-and-swap matching nothing (`ROW_MOVED_BEFORE_COMMIT`). On all
  three: `action:"not_removed"`, `rowRemoved:false`, the row is **kept**, and
  `authority` still reads `held` — the renewals answered truthfully about the
  moments they were asked, and what refused this is the read inside the
  transaction, which is exactly what `errorCode` is for. The attempt is still this
  command's to settle and is settled on the way out, and **the exit code follows
  that settlement, not the refusal**: an exit status this command actually read is
  not made false by a scope that moved, so a proven outcome exits **1** and an
  unproven one exits **75**. `hint` carries the recovery that can actually work,
  which is not the same sentence for all three — `--force` takes a scope *lease*
  over and does nothing to an unsettled peer operation or to a row that moved.
- **The row moved under it** is the third of those and the one with no `session rm`
  counterpart, because a session delete has no expectation to lose. The `jobs` row
  on disk is not the row this command read — the name was relaunched into, a peer
  settled it, or it is already gone — so the delete matches nothing and the whole
  transaction goes back: nothing was deleted and no terminal was written by it.
  `errorCode:"ROW_MOVED_BEFORE_COMMIT"`, the row stays, and `cacheError` carries
  the conflict, which is this key set's one signal that the local row was not
  updated. Exit **1** with a proven outcome and **75** without one, as above.
  Re-read the job with `job ls` before acting on it again; no takeover helps,
  because no lease is what refused it.
- `job rm --discard-evidence` additionally deletes the pane log and then the
  result file, each behind its own lease renewal and only once the session is
  proven gone. Unless the outcome was provable, discarding is not a success: it
  exits 75, because it turned something that could have been proven into an
  override you now owe. `evidenceRetained` reports what actually happened to the
  **log**, not what the flag asked for — a removal that stopped before the delete
  reports `evidenceRetained:true`. Nothing is deleted at all when the post-kill
  look could not read the result record, or could not be taken at all: the one
  thing that would make the deletion safe — knowing what that record says — is
  exactly what both of those failed to obtain.
- If `tmux` is not runnable on the host, none of these report the session as
  gone. Found missing *before* anything has been stopped, the verb fails with
  "tmux is not installed" and touches nothing. If it goes missing between the kill
  and the look that has to follow it, that look is where it surfaces: `job kill`
  settles its ordinary unprovable cancellation, and `job rm` and
  `job rm --discard-evidence` report `probe_error`, keep the row and exit 75.
  Absence of the tool is not evidence about the job, and nothing is deleted on it
  on any of those paths.

**The `--json` key sets are fixed and uniform.** Every branch of each verb emits
every key of its set — the emitter structs have no defaults, so a missing key is
a compile error rather than a shape you discover at runtime. Absent is never a
signal; `null` means "there is no such reading", never "we did not look".

`job kill` — 21 keys. Never null: `ok`,
`action` (`killed` | `already_finished` | `finished_during_kill` | `not_killed`),
`job`, `status`, `outcomeProven`, `observedAt`, `sessionGone`,
`sessionCleanedUp` (the
same boolean under the older name, published everywhere so it means one thing),
`cancellationProven`, `resultRecord`,
`authority` (`held` | `lapsed` | `unreadable`),
`leaseRelease` (`not_taken` | `released` | `not_ours` | `left_held`).
Nullable: `exitCode` (null when no record answered, and deliberately null on the
`conflict` and unusable-record branches — those codes must not be read as an
outcome), `finishedAt`, `conflict`, `requestId` (null when the row names no
attempt), `resultRecordError`, `cacheError`, `authorityError`,
`leaseReleaseError`, `hint`.

`job rm` — 19 keys. Never null: `ok`, `action` (`removed` | `not_removed`),
`errorCode`, `job`, `status`, `outcomeProven`, `rowRemoved`, `evidenceRetained`,
`attemptRetained`, `resultRecord`,
`authority` (`held` | `lapsed` | `unreadable`),
`leaseRelease` (`not_taken` | `released` | `not_ours` | `left_held`).
Nullable: `conflict`, `requestId`, `resultRecordError`, `cacheError`,
`authorityError`, `leaseReleaseError`, `hint`.
`resultRecord` / `resultRecordError` are on this verb too — `job rm` deletes the
local row, so this line and the receipt are the only places the reading survives.

`job rm --json`'s `errorCode` is one of `none`, `AUTHORITY_LOST_BEFORE_KILL`,
`AUTHORITY_LOST`, `SCOPE_TAKEN_BEFORE_COMMIT`, `CLAIM_LOST_BEFORE_COMMIT`,
`ROW_MOVED_BEFORE_COMMIT`, `RESULT_RECORD_UNREADABLE`, `PROBE_FAILED`,
`RECORDS_DISAGREE`, `RESULT_RECORD_UNUSABLE`, `EVIDENCE_DISCARDED_UNPROVEN`,
`CACHE_REFUSED`, `RECEIPT_PERSIST_FAILED`. It is never null and never absent:
`none` is the value on the branches that removed the row with nothing to report —
including the ordinary unproven removal that keeps the log for
`reconcile --from-log`, which is `ok:true` — so a caller never has to decide
whether a missing key means success or an older binary. It is the same
vocabulary `session rm` publishes wherever the two verbs describe the same fact.
`RECEIPT_PERSIST_FAILED` is the one word that never arrives inside this key set:
that branch could not write the transaction carrying the terminal and the delete,
so it reports the fatal envelope
(`{ok, error, errorCode, requestId, cause, remoteStatus, localRow, leaseRelease,
leaseReleaseError, hint}`) and
exits **76** — read `localRow` there, which is `kept` when the undo was proved and
`unknown` when it was not.

`leaseRelease` is the same key `session rm` publishes, and it answers a different
question from `authority`: that one says whether the scope lease was still ours
while there were steps left to take, this one says whether the scope is free now.
`left_held` is a leak — the lease is still holding this job's scope, so the next
`job kill`, `job rm` or `run --name` on it is refused until the lease lapses (120s)
— and it used to be a line on stderr under a document that said `ok: true`. It
does **not** change the exit code or `ok`: on a completed kill or removal the act
did complete and is durably recorded, so exiting non-zero would say otherwise and
send you into a retry the leaked lease would refuse. Branch on `leaseRelease`;
`leaseReleaseError` is prose.

**`leaseRelease` is on every envelope these verbs can exit through.** All
three claim-holding verbs — `job kill`, `job rm`, `session rm` — take the scope
lease *before* they dial, on purpose: a peer's live claim then refuses them with
nothing sent, not even a dial. The cost is that every failure from there on happens
with the lease already held — a connect that never opened, a ledger write that could
not be made, a store call that was refused, a `tmux` the host does not have. All of
them used to hand the lease back through a path that dropped the answer onto
stderr, under JSON that never mentioned a lease. They now carry it:

- **The connection could not be opened or authenticated**:
  `{ok, error, leaseRelease, leaseReleaseError}`, exit **1**. Not the verb's key
  set — nothing was established, and neither verb's `errorCode` vocabulary has a
  word for "we never got a connection" — and not silent about the lease either.
- **A ledger write made under the claim failed**:
  `{ok, error, errorCode, requestId, cause, remoteStatus, leaseRelease,
  leaseReleaseError, hint}` with `errorCode:"RECEIPT_PERSIST_FAILED"`, exit **76**.
  `job rm`'s composite adds `localRow` to that, as above. `session rm` does not use
  this envelope at all: every ledger failure of that verb emits its own 16 keys.
- **Any other failure while the lease was held** — the store refused a write, the
  host has no `tmux`, a result record could not be read, a session survived its
  cleanup: `{ok, error, leaseRelease, leaseReleaseError}`, exit **1**, plus
  `errorCode` where the refusal has one. This is the shared refusal envelope the
  whole CLI uses, and the two lease keys are present on it **exactly when a lease
  was held**. A command that never took one — every non-destructive verb, and these
  three before they claim the scope — emits `{ok, error}` as it always did, so
  absence here means "no lease was involved" and never "we did not say".

`left_held` means the same thing on all of them, and it is the reason to read it
here: the recovery each of these branches recommends is a retry, and a lease this
command could not hand back refuses exactly that until it lapses (120s).

`status` on these two verbs is the ledger's word for the attempt, plus one value
`job status` never prints, so it is `unknown` (the row names no attempt, or names
a request the ledger does not have — both verbs, on every branch).
`authorityError`, `cacheError`, `leaseReleaseError` and `hint` are prose — do not
match their text.
`resultRecordError` is prose too, with the exceptions named above: the tokens
`read_error` and `probe_error`, which are stable and always arrive beside the
same word in `resultRecord`. Presence alone is meaningful only for `cacheError`,
where non-null is the one signal that the local row was not updated; the others
mirror `resultRecord`, `authority` and `leaseRelease`, which you can branch on
directly.

### Removing a session

`terminus session rm <server> <name>` is destructive three times over: it stops
the remote shell, deletes that session's pane log, and drops the local row —
which cascades away every memory attached to that session. It now runs under the
same discipline as `job kill` / `job rm`: a **control operation** in the ledger,
a **scope lease**, and a renewal immediately before each step that changes
something.

- **It contends with a running job.** A job's tmux session is `job-<name>`, and
  `session ls` shows it under that name, so `session rm web job-deploy` is aimed
  at the same shell `job kill web deploy` is. That removal is now **refused**
  while the job is unsettled — nothing is sent to the host and the job's row,
  log and result record are untouched. The refusal names the blocking request id;
  settle it (`terminus request reconcile <id>`) or use `job kill` / `job rm`,
  which are the verbs for a job.
  A user session named exactly `deploy` contends with job `deploy` for the same
  reason. That is deliberate over-refusal: a wait costs a wait, and the other
  mistake destroys a shell.
- **The order is the safety, and it has not changed.** The kill is *proven*
  before anything is deleted — and the log is deleted only after that proof,
  because a live pane recreates its log through `pipe-pane` and a log deleted
  under a surviving session comes back holding a partial history.
  If the host still reports the session present after the kill, **nothing** is
  removed — not the log, not the local row — and the record says so: status
  `failed` with `error_code:"SESSION_SURVIVED_KILL"`, exit **1**. It is 1 rather
  than 75 because the host *answered*: what it answered proves this removal did not
  happen, so the ledger records a proven failure rather than an unknown, that
  record bars nothing, and the scope is free — a retry walks into no refusal. Go
  and look (`tmux attach -t t-<name>`) to find out why the kill did not take, then
  run the removal again.
- **Lease lost *before* the kill**: nothing is sent, nothing local is written.
  `action:"not_removed"`, `errorCode:"AUTHORITY_LOST_BEFORE_KILL"`,
  `sessionState:"not_attempted"`, `localRow:"kept"`, and the exit code is **1, not
  75** — this command changed nothing, so re-running once the scope frees is safe.
  The ledger records `failed`.
- **Lease lost *after* the kill**: the session really did stop, and every step
  after it is declined — the pane log and the local row (with its memories) are
  both **kept**. `action:"not_removed"`, `errorCode:"AUTHORITY_LOST"`, `logState`
  reports which side of the log the loss fell on, `localRow:"kept"`, exit 1. The
  ledger records the ordinary `indeterminate` terminal carrying
  `error_code:"AUTHORITY_LOST"`.
- **The scope taken just before the record was written**: the kill and the log
  deletion both landed, and the one transaction that re-validates the scope, writes
  the terminal and deletes the local row found a peer's claim — so all three rolled
  back together. `errorCode:"SCOPE_TAKEN_BEFORE_COMMIT"`, `logState:"deleted"`,
  `localRow:"kept"`, `authority:"held"` (the renewals *did* hold; the atomic
  re-validation is what refused), exit 1. There is no state in which the ledger
  says a session was removed and the row is still there: nothing is deleted unless
  the terminal is written in the same commit, and neither is written unless both
  are.
- **The log deletion failed**: the session is gone, its pane log is still on the
  host with nothing left to recreate it, and this machine still holds the metadata
  row and this session's memories. `errorCode:"LOG_DELETE_FAILED"`,
  `logState:"delete_failed"` — which is *not* `not_attempted`, so you know to go
  looking for the orphan — `localRow:"kept"`, exit **1**. The ledger settles
  `cancelled`, because the session's absence was proven before that step and a
  later failure does not make an earlier reading unknown; the receipt's
  `detail_json` carries `logDeleted:false` and `localRecordDropped:false`, which is
  what tells this apart from a completed removal. The scope is left free, so the
  repair is simply to run the same command again.
- **The kill got no answer**: the `kill-session` round trip failed at the
  transport, or the host answered with a tmux error instead of a result. The kill
  may have landed and nothing here can say. `errorCode:"KILL_UNANSWERED"`,
  `sessionState:"unknown"` — not `present`, which nothing reported, and not
  `not_attempted`, which would deny a command that was sent — `logState` and
  `localRow` both untouched, exit **75**. The ledger records `indeterminate`
  carrying the same code, so the scope stays barred until you reconcile it. Look
  at the host before re-running.
- **The host has no tmux**: the kill script's own `command -v tmux` guard answered
  before its `kill-session` line, so the kill provably never ran and nothing was
  touched. `errorCode:"KILL_NEVER_RAN"`, `sessionState:"unknown"` — the script
  stopped before `has-session`, so nothing read the session, and a host without
  tmux is *inferred* to have no sessions rather than observed to — `logState` and
  `localRow` both untouched, exit **1**. The ledger records `failed` carrying the
  same code. This is the discriminating pair with `KILL_UNANSWERED`: both mean the
  kill produced no result, but this one bars nothing and needs no reconcile,
  because the host answered and its answer settles the question. Install tmux, or
  put it on the PATH a non-interactive shell sees, then run the removal again.
- **This command's own lease stopped being live before the record was written**:
  every renewal held, and the one transaction that re-validates then writes found
  *this command's* lease no longer live and ours — it lapsed during the last round
  trip, or was swept, or a peer had it. Frequently there is no peer at all, which
  is why this is not `SCOPE_TAKEN_BEFORE_COMMIT`: a swept lease leaves the scope
  genuinely clear, and "is anybody else claiming this" answers *no* while the
  answer to "is it still ours" is also no. `errorCode:"CLAIM_LOST_BEFORE_COMMIT"`,
  `logState:"deleted"`, `localRow:"kept"`, exit 1. Nothing was deleted and no
  terminal was written.
- **A ledger write failed**: any step of this command that writes to the ledger and
  cannot. `errorCode:"RECEIPT_PERSIST_FAILED"`, exit **76**, and the three step
  keys report exactly how far the command had got — including the branch where the
  refusal's *own* record is what could not be written, where `requestId` is the id
  the command minted and nothing exists under it (`status:"unknown"` says so), and
  including the branch where the store refused the **scope lease** this removal has
  to hold: nothing was sent, all three step keys are untouched, and `leaseRelease`
  is `not_taken` because nothing was registered to hand back. Whether that refused
  acquisition left a row behind is *not* claimed either way — if it did, it lapses
  at its TTL.
  `localRow` is `"unknown"` only when a composite could not commit *and* its
  rollback could not be confirmed; every other branch can prove the row is where it
  was and says `"kept"`.
- **The connection could not be opened or authenticated**: this verb claims the
  scope before it dials, so that failure happens with the lease held. It reports
  `{ok, error, leaseRelease, leaseReleaseError}` and exits **1** — not the 16 keys,
  because nothing was established and no `errorCode` here means "we never got a
  connection". The attempt is settled `failed` on the way out, so the scope is free
  and re-running once the host is reachable is safe.
- **Refused by a peer's claim**: `errorCode:"SCOPE_HELD_BY_PEER"`, nothing sent,
  exit 1 — **and the refusal is recorded**, as a `control` operation of its own
  settled `cancelled`. It is queryable by `requestId` and it does **not** bar the
  next command; the scope was never yours to begin with, and a record that refused
  the next attempt would be worse than no record.
- **The receipt never carries an exit code.** A removal runs no command of
  yours; what it establishes is that the session is gone, and that is what the
  ledger holds — status `cancelled`, evidence `remote_cancel_confirmed`, with the
  tmux commands that proved it named on the receipt. It does **not** claim that
  anything running inside that shell stopped: a process that daemonized,
  `disown`ed or ran under `setsid` outlives the session, and nothing here says
  otherwise.
- There is no `--force`. A takeover would displace somebody's claim on a shell
  about to be destroyed along with its memories; wait the lease out (120s).

`session rm --json` — 16 keys, every branch emitting all of them.
Never null: `ok`, `action` (`removed` | `not_removed`), `errorCode`, `session`,
`server`, `requestId`, `status`,
`sessionState` (`gone` | `present` | `unknown` | `not_attempted`),
`logState` (`deleted` | `delete_failed` | `not_attempted`),
`localRow` (`removed` | `absent` | `kept` | `unknown`),
`authority` (`held` | `lapsed` | `unreadable`),
`leaseRelease` (`not_taken` | `released` | `not_ours` | `left_held`).
Nullable: `authorityError`, `leaseReleaseError`, `reason`, `hint` — all four
prose, do not match their text.

`session rm --json`'s `errorCode` is one of `none`, `SCOPE_HELD_BY_PEER`,
`AUTHORITY_LOST_BEFORE_KILL`, `AUTHORITY_LOST`, `SCOPE_TAKEN_BEFORE_COMMIT`,
`CLAIM_LOST_BEFORE_COMMIT`, `SESSION_SURVIVED_KILL`, `KILL_NEVER_RAN`,
`KILL_UNANSWERED`, `LOG_DELETE_FAILED`, `LEDGER_ALREADY_SETTLED`,
`LEDGER_WRITE_FAILED`, `RECEIPT_PERSIST_FAILED`, `OWNER_COLLISION`. It is never
null and never absent: `none` is the value on the one branch that completed the
removal, so a caller never has to decide whether a missing key means success.
`LEDGER_WRITE_FAILED` and `RECEIPT_PERSIST_FAILED` both exit **76**: a write this
command needed could not be made, so reconcile before acting on that session again.

Exit codes for the three kill outcomes, by what the ledger settled. Each is gated
against the binary's real exit status, so this list cannot drift the way the
survived-kill bullet above once did — it published 75 for a branch that exits 1, and
no gate read the number.

- `KILL_UNANSWERED` exits **75** — the one kill outcome nothing can establish, so
  the record bars this session's scope until you reconcile it.
- `SESSION_SURVIVED_KILL` exits **1** — the host answered that the session is still
  present, which proves the removal did not happen.
- `KILL_NEVER_RAN` exits **1** — the host answered that it has no tmux, which proves
  the kill never ran.

The two proven failures settle `failed`, bar nothing and are safe to re-run; the
unknown settles `indeterminate` and is not.

`session rm --json`'s `status` is the ledger's word for this attempt, except on the
one branch where the write that would have created the row is what failed — there
is nothing to read a word off, so it is `unknown`.

Three things this key set is deliberate about. `localRow:"absent"` is not a
failure: it means this machine had no metadata row for the session, which is
ordinary for a session started outside Terminus, and the *session* was still
proven gone. `logState` and `sessionState` are words rather than booleans because
`false` cannot tell "we tried and the host refused" from "we never got that far",
and those two leave different things behind. And `leaseRelease` is on every branch
because a lease this command could not hand back goes on refusing the next command
on that scope until it lapses — `left_held` is that leak, reported in the document
rather than only on stderr. It does **not** change the exit code: on a completed
removal the removal really did complete and is durably recorded, so exiting
non-zero would say the opposite and invite a retry into a refusal.

### Waiting on a job and reporting business state

- **Don't poll in a busy loop.** `terminus job watch <server> <name>
  --interval 30s --json` blocks and returns the instant the job reaches a
  terminal state (or after `--max` polls, reported as `stillRunning:true`).
  `watch` also exits with the job's own exit code when it ended non-zero — but
  only after the two codes that outrank it: 75 if the outcome could not be
  established, 1 if the local row could not be brought along.
- **Exit code ≠ business success.** A job can exit 0 yet fail its actual
  purpose (0 rows migrated, health check red). Have the job print a
  marker line and Terminus surfaces it as `businessResult`, separate from
  `exitCode`, in `job status`/`job read`/`job watch`:

  ```bash
  terminus run db --name migrate -- 'bash -c "./migrate.sh; echo __TERMINUS_RESULT__:rows=$(count)"'
  terminus job watch db migrate --json   # -> {"exitCode":0,"businessResult":"rows=1240",...}
  ```

  Use `__TERMINUS_RESULT__:success` / `:failed` / `:<any value>` — the
  last such line wins, so a job can update its verdict as it runs.

- **Report progress and stages the same way.** Two more markers, read the same
  way (line start, colon, last one wins) and reported as `progress` and `phase`:

  ```bash
  echo '__TERMINUS_PHASE__:download'
  echo '__TERMINUS_PROGRESS__:{"pct":42,"files":128}'
  ```

  `__TERMINUS_PROGRESS__` must carry a **JSON object** and at most 4096 bytes;
  anything else is refused and reported in `progressError` rather than recorded.
  `__TERMINUS_PHASE__` carries a plain label, at most 256 bytes. Both are read
  by a probe that walks the log **forward from its own cursor**, so a marker
  printed early is still seen on a job that has since printed megabytes, and one
  split across two reads is reassembled and parsed once. That cursor is not the
  one `job read --from-cursor` moves: streaming output and probing state are
  separate positions and neither moves the other.

### Recovering a wedged daemon

`transport` ("daemon"/"direct") and `daemonError` ride on the responses listed
under "Choosing exec mode" above. If the daemon repeatedly errors or a call hangs
unusually long:

```bash
terminus daemon status --json           # is it up? which pid?
terminus daemon restart                 # graceful; next call respawns it
terminus daemon restart --force --json  # hard-kill a wedged daemon by pidfile
```

`--force` still tries the graceful socket stop first, then reads the pidfile,
kills that pid and deletes the socket and pidfile. (The pid kill is implemented
on Windows only; elsewhere `--force` amounts to the graceful stop plus the file
cleanup.) Remote tmux jobs are unaffected — they live on the server, not in the
daemon. Commands always fall back to direct SSH meanwhile.

## File transfer: what a push or a pull leaves behind

Every byte goes to `<destination>.terminus-part` beside the destination, and the
last act is a rename. So a hash mismatch, a full disk and a failed publish all
leave what was at the destination exactly as it was. Both ends hash with
SHA-256 (`sha256sum`, or `shasum -a 256` where there is no `sha256sum`), and the
rename happens only once the two agree.

`transferState` in `--json` is the verdict. It is *not* `ok`, and the exit code
is what to branch on:

- `published` — exit **0**. Both ends hashed to the digest declared before the
  first byte and the rename was watched. The only outcome that exits 0.
- `completed_unverified` — exit **75**. The bytes arrived and matched their
  length and the host could not hash them, so nothing establishes they are the
  right bytes. The artifact *is* at the destination and the ledger does not say
  so, which is exactly the state you must not read as done. Install `sha256sum`
  or `shasum` on the host.
- `failed_source_changed` — exit **1**. The source is not the one this transfer
  was about: a push found its file hashing differently when it was sent than
  when it was probed, or a resume found the source changed before it moved
  anything. Nothing was renamed.
- `failed_remote_partial_mismatch` — exit **1**. A resume found the staged
  partial beside the destination was not the prefix this transfer had confirmed
  — the wrong length, or the right length and the wrong bytes — so there was
  nothing safe to splice onto. Nothing was sent. This is a different fact from
  `failed_source_changed` and it points at a different file.
- `failed_hash_mismatch` — exit **1**. The two ends hashed to different digests.
  Nothing was renamed.
- `failed_clobber_conflict` — exit **1**. `--no-clobber` was asked for and
  something already occupies the destination. Nothing was linked, so that path
  holds exactly what it held. This is the only publish refusal that is a fact
  about your data rather than about the mechanism.
- `failed_publish` — exit **1**. The rename itself reported failure. Nothing was
  renamed.
- `indeterminate_publish` — exit **75**. The rename was issued and its answer
  was lost, so it may or may not have landed. Never report this as a failure;
  read the destination and `terminus request reconcile <id>`.
- `paused` — exit **75**. The transfer stopped before the destination came into
  it. The destination is untouched and the staged partial is trustworthy. This
  is the resumable one: re-run with `--resume`.

A ledger write this command could not make exits **76**, as everywhere else.

**A transfer that did not publish keeps its destination**, and that is
deliberate rather than a leak: a failed run leaves a partial beside the path and
a half-told story about what is at it, so the next transfer aimed there is
refused rather than walking onto the leftovers. The refusal names the request
holding the path, its transfer's state, and the way past it.

There are two ways past it and **they are for different states**. The refusal
names exactly one; do what it says rather than trying the other.

`--resume` continues an interrupted transfer. It takes the checkpoint over,
re-proves the source and the staged prefix, and streams on from the confirmed
offset. Nothing is discarded and nothing already confirmed is re-sent. It
applies to the four *unfinished* states — `planned`, `probing`, `transferring`,
`paused` — and every abort parks at `paused`, so this is the common case after
an interruption.

- the artifact is still judged by the digest the interrupted attempt declared
  **before its first byte**. A resume cannot re-declare one; it reads it. So a
  resumed transfer reaching `published` means exactly what a fresh one does.
- a resume that finds the source changed, or the staged prefix wrong, refuses
  and says which — `failed_source_changed` or
  `failed_remote_partial_mismatch` — and moves nothing. Both are decided
  failures, so `--restart` is then available if you want to start over.
- **resuming is exec-only.** libssh2's scp support moves a whole file from byte
  zero and has no ranged form, so `--via scp` with `--resume` is refused; an
  unpinned resume reports `backendReason` saying why it had no choice.
  `resumedFrom` in `--json` is where this run's first byte went.

`--restart` releases the holder's claim and starts the replacement in the same
transaction — so the path is never free with nothing on the way to it — and it
refuses everything else. It releases **5** of the nine verdicts above:
the five proven failures. What to do about the rest:

- the holding request is not settled (`indeterminate`): a copier on the far side
  may still be writing beside that path, so nothing may take it — neither verb.
  Establish what it did with `terminus request reconcile <id>`, then re-run with
  whichever verb its state calls for.
- the holder is `indeterminate_publish`: the artifact may already be at that
  path and nobody has judged it. Adjudicate it — `terminus request reconcile
  <id>` — before anything overwrites it.
- the holder is `verifying` or `publishing`: its owner stopped in the middle of
  an act, so it is past its last byte. `--resume` has no offset to continue from
  and `--restart` has no decision to release. Recovering one of these is a
  hand-over of its own and **no verb reaches it yet**, so that path stays held —
  send to a different destination.

`--restart` never deletes the staged partial. The superseded row, its offsets and
both its digests are all kept, because the reason you were asked in the first
place is that there is something at that path worth knowing about; the
replacement truncates and rewrites the partial on its way through anyway. A
`--resume` truncates nothing below its confirmed offset — that is the point of
it — and cuts away only the unconfirmed tail, after proving the prefix.

### `--no-clobber`: refusing to replace, without looking first

`--no-clobber` on `push` or `pull` refuses to overwrite an existing destination.
It is not a check followed by a rename — that has a window in which two
transfers both find the path free and the second silently destroys the first's
artifact. The refusal happens **in the kernel**:

- a **push** publishes with `ln` and then unlinks the partial. POSIX `link(2)` is
  specified to fail when the name exists, and it decides a race between two
  publishes rather than reporting on one. (`mv -n` is not used: it is a GNU/BSD
  extension, absent from busybox, and implemented as exactly the check this
  avoids.)
- a **pull** publishes with an atomic non-replacing rename —
  `renameat2(RENAME_NOREPLACE)` on Linux, `NtSetInformationFile` with
  `REPLACE_IF_EXISTS = false` on Windows, link-then-unlink elsewhere.

Two refusals, and they are **different facts**. Do not treat them as one:

- `failed_clobber_conflict` — something is at that path. Your data. Read it,
  then either send elsewhere or re-run with `--restart` and without
  `--no-clobber` to replace it deliberately.
- `failed_publish` — the publish could not be *performed*: the host could not
  hard-link, the filesystem has no atomic non-replacing rename, the directory is
  read-only. The destination is empty as far as anything could tell. Reporting
  this as a conflict would be a false statement about your data, so it is not
  reported as one.

Without the flag the publish is an ordinary replacing rename, exactly as before —
the default is unchanged.

**The promise lives on the checkpoint, not on the command line.** `no_clobber` is
written once, when the transfer is created, and nothing updates it. So:

- a `--resume` honours the promise the interrupted attempt made, even if you omit
  the flag. The instruction was about the destination, not about one attempt.
- a `--resume` that *adds* `--no-clobber` to a transfer that did not have it is
  **refused**. There is no way to make the record agree, and a driver refusing a
  publish the record says was permitted is worse than a refusal you can read.
  Use `--restart --no-clobber`, which mints a fresh checkpoint.
- a `--restart` mints that fresh checkpoint from the command line you just typed,
  so its `--no-clobber` is the one you passed — not the superseded row's.

`noClobber` in `--json` is the promise that was actually in force, which on a
resume is the row's and not your argument's.

## Memory discipline

- **Server scope** (`<server>`): durable facts — use the structured keys
  above. Always `--key` so updates overwrite instead of duplicating.
- **Session scope** (`<server>:<sess>`): task progress, temporary state.
  Dies with the session.
- Reading session memory merges server entries automatically.
- After completing meaningful work, update `services`/`deploy`/`gotchas`
  with what changed and what surprised you.

## Setup (once per machine)

**Key requirement: PKCS#1 PEM RSA only** — the file must start with
`-----BEGIN RSA PRIVATE KEY-----`. OPENSSH-format (`ssh-keygen` default since
2018), EC/ECDSA and PKCS#8 keys are rejected before the auth call, with
conversion instructions. The limit comes from the Windows crypto backend, but
the check is not OS-gated: it refuses the same formats on every platform (an
ed25519 key is caught as OPENSSH-format). When in doubt, generate a dedicated
key:

```bash
ssh-keygen -t rsa -b 4096 -m PEM -f terminus_key   # then add .pub to the server
```

Convert an existing OPENSSH-format RSA key (copy first — this rewrites in place):

```bash
copy id_rsa id_rsa.pem && ssh-keygen -p -m PEM -f id_rsa.pem -N ""
```

```bash
terminus key add mykey --kind rsa --private-file ./terminus_key
terminus server add prod --host 1.2.3.4 --port 22 --user ubuntu --key mykey
terminus server ping prod    # verify connect+auth (~1 round trip)
```

Passwords: `terminus key add pw --kind password --passphrase '...'`.

Housekeeping: `server rename/set` change names and connection details in
place — memories, facts, jobs, and history follow automatically (never
rm+re-add, that erases accumulated knowledge; `rm` warns and requires
`--force` when data would be lost). `--force` covers the cascade only:
unsettled operations, held leases and resumable transfers refuse the removal
whether or not you pass it.

## Moving knowledge between machines

`export`/`import` move all servers + memories + facts as one JSON file,
with agent-controlled merging (never a blind overwrite):

```bash
# On the old machine:
terminus export --out terminus-backup.json          # config + knowledge
terminus export --include-keys --out full.json      # + PLAINTEXT key material

# On the new machine — ALWAYS dry-run first and review the plan:
terminus import backup.json --dry-run --json
#   every item is labeled new | identical | conflict (local vs incoming shown)

terminus import backup.json                    # apply additions only; conflicts stay local
terminus import backup.json --strategy theirs  # conflicts: incoming wins
terminus import backup.json --only web1,prod   # limit to specific servers
```

For conflicts you want to resolve individually: read both values from the
dry-run plan, then write the merged truth with `memory add --key ...`
(it upserts). Re-import is idempotent — identical items are skipped.

## Feeding a command its own standard input

`--stdin-file <path>` streams a local file into the remote command's standard
input. It is a **different channel from `--stdin`**, and the difference is the
one thing to get right:

- `--stdin` and `--cmd-file` supply the *command* — the bytes the remote shell
  parses and runs.
- `--stdin-file` supplies what that command *reads*.
  It is not the bytes of the command; it is the bytes the command consumes on
  fd 0.

```bash
# Restore a dump without ever writing it to the remote disk first
terminus exec db --stdin-file ./dump.sql.gz --cmd "gunzip | psql app"

# A binary payload, unchanged: no base64, no shell quoting of the contents
terminus exec host --stdin-file ./firmware.bin --cmd "cat > /tmp/fw.bin"
```

What it guarantees:

- **byte for byte.** The channel is 8-bit clean, so NUL, `\r\n`, and every other
  byte value go through untouched. Nothing normalizes this input and nothing
  inspects it for carriage returns — here they are data, not line endings.
- **streamed, at any size.** The bytes are never held in memory: the peak is one
  fixed window whatever the file's size, so there is no ceiling to hit and no
  point at which it quietly starts base64-ing or truncating.
- **the receipt says what went in.** `--json` carries `stdinBytes` and
  `stdinSha256`, and the terminal receipt stores both. They are the count the
  channel **accepted** and the SHA-256 of exactly those bytes — never the
  source's length and never a digest of the file taken separately.

When it does not work:

- if the channel stops accepting before the file is exhausted, that is **not** a
  smaller success. The run settles `indeterminate` (exit **75**) and the reason
  names how many bytes were accepted and their digest. The remote command may
  already have acted on that prefix, so re-sending is a decision for you and
  not a retry to make blindly. In particular the end-of-input marker is *not*
  sent on that path: the remote sees a broken channel rather than a truncated
  input that looks complete.
- `--stdin-file` needs a one-shot exec channel, so a `<server>:<session>`
  target is refused — typing into a live shell has no separate input channel.
  Send the file with `terminus push` instead.
- it needs a direct SSH connection: the local daemon's pooled protocol carries
  a command and an answer and no third channel. terminus takes a direct
  connection for you and reports it in `transport`/`daemonError`.

## What a command's output does when there is a lot of it

A command's output is capped at **1 MiB**, and the cap keeps **both ends**: the
first 512 KiB and the last 512 KiB. Anything between them is dropped and the
place it went is marked, in the stream, with a line beginning
`__TERMINUS_OUTPUT_TRUNCATED__`.

Read that marker as authoritative. **If it is absent, you have every byte the
command printed.** If it is present, you do not — and you must not draw a
conclusion from output whose middle is missing without saying so.

```bash
# Nothing to think about: output under 1 MiB comes back byte-for-byte.
terminus exec web --cmd "systemctl status nginx"

# Large output. Read the marker and the counts, not just the text.
terminus exec web --json --cmd "journalctl -u api --no-pager"
```

`--json` carries the whole story, and the receipt (`terminus history`) stores the
same three numbers:

- `stdoutBytes` — every byte that **passed**, not the amount you were given. On a
  truncated run this is larger than the `stdout` you can see.
- `stdoutSha256` — the SHA-256 of **all** of those bytes, including the ones that
  were dropped. It is computed as the output streams, so a truncated run is still
  provable: you can check a full copy you fetch later against this digest.
- `stdoutTruncated` — `true` exactly when the middle was dropped. `stderrBytes`,
  `stderrSha256` and `stderrTruncated` say the same for the other stream, which
  is capped the same way.

Why both ends rather than a simple head or tail: terminus reads the command's
process identity from the *first* line of the stream and its exit status from the
*last*. A head-only cap would lose the exit status and report a perfectly ordinary
command as `indeterminate` (exit 75); a tail-only cap would lose the pid and pgid
the attempt is reconciled by. Keeping both is what lets a command that prints ten
gigabytes still come back with its own exit code.

**When you need all of it, do not raise the ceiling — move the bytes as a file.**

```bash
terminus exec web --cmd "journalctl -u api --no-pager > /tmp/api.log"
terminus pull web /tmp/api.log ./api.log   # any size, resumable, digest-verified
```

Peak local memory is fixed at the cap and does not grow with the output, so a
command that prints ten gigabytes costs the same as one that prints ten
kilobytes. Note that this cap is on a **command's** output; `terminus pull` and
`terminus push` stream and are not subject to it.

## What a sync records, and what it does when the answer is unknown

`terminus sync push` replaces a directory on the host: it uploads one archive and
runs `rm -rf` on the destination (with `--delete`) before unpacking over it. Every
run now mints an operation, so the thing that happened has a handle.

```bash
terminus sync push web ./dist /srv/app/dist --json
```

The `--json` answer carries `requestId` and `status` beside the counts. `status`
is the operation's own word: `completed`, `failed`, or `indeterminate`.

**Read `status`, not the exit code alone.** A sync that could not establish what
the host did exits **75** and reports `indeterminate` — the archive was staged and
the unpack script went out, and the channel then broke or closed without reporting
a status. Do not retry a `sync push` on 75: the retry runs `rm -rf` on the
destination a second time, and the first one may already have finished. Establish
what happened first:

```bash
terminus request reconcile <requestId>
```

An ordinary failure is different and safe to act on: exit 1 with `status: failed`
means the host answered and did not unpack. A digest that did not match is one of
those — the host checks the archive before it touches the destination, so nothing
was replaced.

**What a sync contends on.** The attempt claims the **remote directory** it names,
as a path scope, and paths nest: a sync holding `/srv/app` blocks a sync into
`/srv/app/dist` and a `terminus push` aimed at `/srv/app/config.json`, in both
directions. If an earlier attempt on an overlapping path is still unsettled, the
new one is refused with nothing sent — reconcile it, or pass `--force` to proceed
and have the override recorded on the trail.

A `sync pull` reads the remote directory rather than writing it, and `--dry-run`
changes nothing in either direction. Both still get a row you can find, and
neither holds the barrier, so previewing a push does not refuse the push.

## Docker containers: a typed state, and a wait that cannot lie about it

`terminus docker` reads a container's state and hands it back as keys you branch
on. It never asks you to parse a sentence out of docker's English, and it never
answers "not running" for a question it was unable to ask.

```bash
# One round trip. Exits 0 only when a state was actually read.
terminus docker inspect web api --json

# Block until the container's own healthcheck says healthy — or give up and say
# exactly that.
terminus docker wait web api --for healthy --timeout 120 --interval 5

# ...or just until it is up, which is the right target for an image that
# declares no HEALTHCHECK.
terminus docker wait web api --for running --timeout 60
```

`--for` takes `healthy` (the default) or `running`. `--timeout` is a whole number
of seconds (default 60), `--interval` is whole seconds between polls (default 2).
Both verbs are reads: they open no operation row, take no lease and block nobody,
for the same reason `terminus doctor` does not — nothing they send can change a
container, and polling one does not make it healthy.

### `reading` says what was established, and absences are not each other

Five ways this can fail to be a state, and they are five different facts about
your host. Branch on `reading`, never on the prose:

- `docker_absent` — `docker` is not on the PATH a non-interactive SSH command
  gets. **Nothing was asked about your container.** Run `terminus doctor
  <server>` to see whether it is installed but on the login shell's PATH only.
- `daemon_unreachable` — docker is installed and the daemon did not answer it.
  Again, nothing is known about the container. This is the one a naive "is it
  up?" check reports as "it is down".
- `permission_denied` — the daemon did not answer *and* `/var/run/docker.sock`
  is present and this account may not write to it, i.e. the account is not in
  the `docker` group. A refusal, not an outage, and it will not fix itself.
- `container_absent` — the daemon answered and has no container by that name.
  The daemon's own answer, and the only one of the five that is.
- `unparseable` — the daemon answered about this container and what came back is
  not a document terminus can read. Never quietly turned into a state.
- `unknown_probe_status` — the probe came back with an exit status it does not
  produce, so it did not run as written and nothing it printed is evidence.

`reading: "state"` is the sixth value, and the only one where `ok` is `true`.

One stated boundary: over a `DOCKER_HOST` that is not the default unix socket, a
permission refusal reports as `daemon_unreachable` rather than
`permission_denied`. The socket test looks at `/var/run/docker.sock` and only
when `DOCKER_HOST` is unset — so it is less specific there, never wrong.

### `status` and `health` are closed lists, and both keep docker's own word

- `status` is `created`, `running`, `paused`, `restarting`, `removing`,
  `exited`, `dead`, or `unrecognised`. `statusReported` carries the word docker
  actually printed, always, so an `unrecognised` never also loses it.
- `health` is `none`, `starting`, `healthy`, `unhealthy`, or `unrecognised`,
  with `healthReported` beside it the same way. **`none` means the image
  declares no `HEALTHCHECK`.** It is not "unhealthy" and it is not "not yet".

### A wait that runs out of time is not a wait that succeeded

`outcome` is one of four words, and only the first of them is `ok: true`:

- `reached` — the target became true. Exit 0.
- `timed_out` — the deadline expired with the target still not true. Exit 1.
  The last reading travels with it, so `status` and `health` tell you what it
  was still waiting on. This is **not** the same answer as an unhealthy
  container: `unhealthy` is a `health` value you can go on waiting through, and
  it shows up *inside* a `timed_out` result.
- `cannot_reach` — waiting cannot make the target true from here, so it stopped
  at once instead of burning the deadline. The common case by far: you waited
  for `healthy` on a **running** container whose image has no `HEALTHCHECK`, so
  it has no health status and will never acquire one. Wait for `running`
  instead. Exit 1.
- `undetermined` — the host never told us anything about the container at all,
  i.e. one of the five readings above. Exit 1.

`polls`, `waitedSeconds` and `timeoutSeconds` are numbers, so a deadline that
expired after one look is distinguishable from one that expired after thirty.

`detail` and `dockerSaid` are the only prose keys in either document —
terminus's sentence and docker's own message. Nothing you need to act on lives
only in them.

**What this rests on, so you know when to stop trusting it.** The state comes
from `docker container inspect` with a JSON format template over `.State`: a
documented struct, one line of output. If that ever stops being one readable
line, the answer becomes `unparseable` — a refusal that names itself — and never
a state with invented fields.
