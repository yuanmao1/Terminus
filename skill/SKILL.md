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

**Requires terminus >= 0.1.8.** If a documented flag is rejected, the
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
terminus job status <server> build --json     # running | exited | killed + exitCode
terminus job read <server> build --from-cursor --json
terminus job kill <server> build
terminus job ls <server> --json

# Persistent interactive session (requires tmux on the server)
terminus session new <server> <name>
terminus exec <server>:<name> --json -- cd /srv/app   # state persists
terminus exec <server>:<name> --json -- docker compose ps

# File transfer (SCP) — single files or whole directories
terminus push <server> ./local-file /remote/path [--mode 755]
terminus pull <server> /remote/file ./local-path
# No scp binary on the server (minimal images, OpenSSH 9+)? add --via exec
# — moves bytes over the plain command channel (base64); push any size,
# pull up to ~1.5 MB. push/pull auto-fall back to exec if scp is absent.
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

All failures are `{"ok":false,"error":"..."}` with exit 1 in `--json` mode.
Responses include `transport` ("daemon" or "direct") and `daemonError` when
the connection daemon was skipped — mention it if you see repeated fallbacks.

## Jobs: the reliable way to run long tasks

`run` starts the command in a dedicated remote tmux session with a sentinel
that captures the exit code. Nothing is lost if your process, the CLI, or
the SSH connection dies — the job keeps running and stays queryable:

```bash
terminus run prod --name migrate --cwd /srv/app -- ./migrate.sh
# ...later, from any process:
terminus job status prod migrate --json   # {"status":"exited","exitCode":0,...}
terminus job read prod migrate --json     # full output
terminus job rm prod migrate              # cleanup when done
```

Job names are unique per server while running; finished names can be reused.

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
