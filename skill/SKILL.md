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
terminus exec <server> --stdin                      # command from stdin
terminus exec <server> --cmd-file ./script.sh       # run a local script remotely
terminus exec <server> --cmd "uname -a"             # single flag value
terminus exec <server> -- uname -a                  # classic; fine in bash

terminus memory add <server> --key gotchas --stdin  # content from stdin
terminus memory add <server> --key gotchas --content-file notes.txt
terminus memory add <server> --key gotchas --content "text with ; and *"
```

For agents: **use `--cmd`/`--content` for one-liners and `--stdin` for
anything with quotes, semicolons, globs, or multiple lines.**

Windows CRLF is handled automatically: `--stdin` and `--cmd-file` input
is normalized from CRLF/CR to LF before it reaches the remote shell, so a
`\r` can never turn `true` into `true\r`. Pass `--raw` to keep bytes
exactly (rare — only for binary-in-script cases).

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
Staged files are removed after exec and swept daily; single-line commands
skip staging entirely (no overhead).

## Tools missing in non-interactive shells (nvm/pm2/bun)

Plain SSH exec skips ~/.bashrc, where nvm/bun/pm2 set up PATH. If a tool
"exists on the server but isn't found":

```bash
terminus doctor <server> --json    # loginOnlyTools lists exactly these
terminus exec <server> --login --cmd "pm2 list"   # wraps in bash -ilc
```

Sessions (`<server>:<sess>`) don't need `--login` — they are real
interactive shells already.

## Golden rule: recall before you act

Before touching a server you may have seen before:

```bash
terminus server ls --json            # what servers exist?
terminus memory ls <server> --json   # what do I know about it?
```

Every `exec --json` response also includes `memoryKeys` — the list of
memory keys stored for that server. If you see keys you haven't read this
conversation (e.g. `services`, `deploy`), read them before continuing:

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
terminus job status <server> build --json     # + exitCode; exits 75 if indeterminate
terminus job read <server> build --from-cursor --json
terminus job watch <server> build --interval 30s --json  # block until it ends
terminus job kill <server> build               # exits 75 unless the kill is provable
terminus job ls <server> --active --limit 20 --json

# Persistent interactive session (requires tmux on the server)
terminus session new <server> <name>
terminus exec <server>:<name> --json -- cd /srv/app   # state persists
terminus exec <server>:<name> --json -- docker compose ps

# File transfer (SCP) — single files or whole directories
terminus push <server> ./local-file /remote/path [--mode 755]
terminus pull <server> /remote/file ./local-path
# No scp binary on the server (minimal images, OpenSSH 9+)? add --via exec
# — moves bytes over the plain command channel (needs only base64), any
# size, md5-verified. Downloads are slow (libssh2 read speed; the scp
# backend is no faster) but reliable. push/pull auto-fall back to exec if
# scp is absent.
terminus push <server> ./cfg /etc/app/cfg --via exec
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
proven failure (`{"ok":false,"error":"..."}`); exit 75 means the remote outcome
could not be established — **never retry that blindly**; exit 76 means the local
receipt could not be written. Responses include `transport` ("daemon" or
"direct") and `daemonError` when the connection daemon was skipped — mention it
if you see repeated fallbacks.

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
| `submitted`, `remote_started` | still running; no outcome yet |
| `completed` | the command exited 0 |
| `failed` | the command exited non-zero — `exitCode` says which |
| `indeterminate` | the outcome could not be established; the command exits 75 |

There is no `running`, `exited` or `killed` in this field — those are the cached
row labels `job ls` prints from its local snapshot, and matching them against
`job status` never fires. `ok` is exactly `status != "indeterminate"`.

`indeterminate` means the session vanished without recording an exit status, or
the two durable records disagree. **Do not relaunch the work**: the attempt goes
on blocking same-scope commands until it is settled with
`terminus request reconcile <request-id> [--from-log]`.

A launch refused by such a blocker will first spend one connection asking the
host whether that blocker has in fact already finished, and settle it from the
evidence if so — which usually means the relaunch simply proceeds. If the host
is unreachable the refusal stands and says so; it is never replaced by a
connection error.

### Fields on job status / read / watch

- `exitCode` — the remote exit code, `null` while unknown.
- `businessResult` — the last `__TERMINUS_RESULT__:<v>` line (see below).
- `finishedAt` — a **remote** finish time in unix seconds, taken from the result
  file. `null` unless the host reported its own clock (a sentinel-only outcome
  has no timestamp). Never backfilled with local time.
- `observedAt` — local unix seconds when we saw the evidence. Not a finish time.
- `conflict` — normally `null`; `{"resultExitCode":N,"sentinelExitCode":M}` when
  the result file and the log sentinel report different exit codes. Then
  `status` is `indeterminate` and no mechanical reconcile can settle it — it
  needs `terminus request reconcile <request-id> --override`.
- Command-specific: `job status` adds `command`, `createdAt`, `server`,
  `transport`, `daemonError`; `job read` adds `from`, `to`, `data`; `job watch`
  adds `stillRunning` and `polls`.

**`job ls` is a different shape and a different clock.** It prints the local
cache row verbatim, so its keys are snake_case (`exit_code`, `finished_at`,
`read_cursor`) and its `status` holds the cached labels `running`/`exited`/
`killed` rather than an operation status. In particular `finished_at` there is
**not** `finishedAt`: it falls back to local time when the host reported none.
Use `job status` when the answer matters; `job ls` is for looking around.

### Stopping and forgetting jobs

- `job kill` probes before it kills. If the job had already finished it records
  that outcome and reports `"action":"already_finished"` — the real exit code,
  not a cancellation. Otherwise it kills the session and reports
  `cancellationProven`, which is **false** with today's shell supervisor: a
  disowned or `setsid` child outlives its pane, so the kill settles
  `indeterminate` and exits 75 rather than claiming the work stopped. The log is
  never deleted here, so `reconcile --from-log` stays possible.
- Two `job kill` outcomes are neither success nor 75. A `conflict` between the
  result file and the log sentinel reports `"action":"killed"` with `ok:false`
  and the `conflict` object, and needs `reconcile --override`. And an outcome
  that *was* proven but whose tmux session survived the kill exits **1**: the
  next launch under that name would otherwise type into the dead job's shell.
- `job rm` kills the session first and refuses to delete anything — log, result
  file, or local row — if the session is still there afterwards. It settles from
  the probe it took beforehand: with the outcome provable you get
  `outcomeProven:true`; with the outcome still unknown it removes the job, keeps
  the log, and returns `ok:true` with a hint to run
  `reconcile <request-id> --from-log`. A `conflict` exits 75.
- `job rm --discard-evidence` additionally deletes the pane log and the result
  file, and only once the session is proven gone. Unless the outcome was already
  provable from that first probe, discarding is not a success: it exits 75,
  because it turned something that could have been proven into an override you
  now owe.
- If `tmux` is not runnable on the host, none of these report the session as
  gone — they fail with "tmux is not installed" instead. Absence of the tool is
  not evidence about the job, and nothing is deleted on it.

### Waiting on a job and reporting business state

- **Don't poll in a busy loop.** `terminus job watch <server> <name>
  --interval 30s --json` blocks and returns the instant the job reaches a
  terminal state (or after `--max` polls, reported as `stillRunning:true`).
  `watch` also exits with the job's own exit code when it ended non-zero.
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

### Recovering a wedged daemon

Every response carries `transport` ("daemon"/"direct") and `daemonError`.
If the daemon repeatedly errors or a call hangs unusually long:

```bash
terminus daemon status --json           # is it up? which pid?
terminus daemon restart                 # graceful; next call respawns it
terminus daemon restart --force --json  # hard-kill a wedged daemon by pidfile
```

`--force` bypasses the (possibly hung) socket, kills the pid, and clears
stale files. Remote tmux jobs are unaffected — they live on the server,
not in the daemon. Commands always fall back to direct SSH meanwhile.

## Memory discipline

- **Server scope** (`<server>`): durable facts — use the structured keys
  above. Always `--key` so updates overwrite instead of duplicating.
- **Session scope** (`<server>:<sess>`): task progress, temporary state.
  Dies with the session.
- Reading session memory merges server entries automatically.
- After completing meaningful work, update `services`/`deploy`/`gotchas`
  with what changed and what surprised you.

## Setup (once per machine)

**Key requirement (Windows crypto backend): PKCS#1 PEM RSA only** —
the file must start with `-----BEGIN RSA PRIVATE KEY-----`. OPENSSH-format
(`ssh-keygen` default since 2018), ed25519, and ECDSA keys are rejected
with conversion instructions. When in doubt, generate a dedicated key:

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
`--force` when data would be lost).

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
