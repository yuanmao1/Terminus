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

Update (`--key` upserts), don't append duplicates. Keep each entry short
and factual — it's an index card, not a log.

## Quick reference

```bash
# First contact with a server: probe its capabilities
terminus doctor <server> --json      # shell, OS, tmux?, disk, memoryKeys

# One-shot remote command (no tmux needed on the server)
terminus exec <server> --json -- uname -a

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
| Anything longer than ~60s | `run --name X` then poll `job status` — exit code never lost |
| Multiple related commands (cd, env, activate) | `exec <server>:<sess>` — state persists between calls |
| Interactive process (REPL, log follow) | `write` + `read --from-cursor` |
| Remote has no tmux | plain `exec <server>` only; `doctor` tells you upfront |

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

```bash
terminus key add mykey --kind rsa --private-file ~/.ssh/id_rsa
terminus server add prod --host 1.2.3.4 --port 22 --user ubuntu --key mykey
terminus exec prod -- echo ok    # verify
```

Passwords: `terminus key add pw --kind password --passphrase '...'`.
