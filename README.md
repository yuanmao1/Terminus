# Terminus

**Agent-friendly persistent remote shell.** SSH exec, durable tmux sessions, tracked background jobs, directory sync, and per-server memory — designed for AI agents, usable by humans.

```bash
npm install -g terminus-shell
terminus setup          # install the agent skill into Claude Code / Codex
```

Written in Zig 0.16. Single ~3 MB binary, zero runtime dependencies — SQLite and libssh2 (WinCNG backend) are compiled in. Windows x64 today; Linux/macOS planned.

---

## Why

Most shell tools give agents one-shot command execution and amnesia. Terminus gives them a durable remote workbench:

```text
persistent session > one-shot process
tracked job        > lost long task
structured output  > terminal scraping
recalled memory    > re-discovery
```

- **Jobs** — long tasks run in dedicated remote tmux sessions. When the command returns, its exit status is recorded on the host twice: authoritatively in `~/.terminus/results/<request-id>.json`, and as a fallback sentinel line in the pane log. Nothing is lost if the CLI, agent process, or SSH connection dies; the job stays queryable from any process.
- **Sessions** — a Terminus session maps to a remote tmux session. cwd/env persist between calls; disconnects don't destroy state.
- **Memory & facts** — agents store what they learned about a server (deploy paths, service layout, gotchas) and recall it next conversation. Every `exec --json` response carries the server's memory keys.
- **Stable JSON contract** — every command supports `--json`; every failure carries `"ok":false`. Exit 1 is a refusal or a proven failure (`{"ok":false,"error":"..."}`), 75 means the remote outcome could not be established and a blind retry is unsafe, 76 means the receipt could not be persisted. Remote exit codes pass through.
- **Connection daemon** — repeated calls reuse a pooled SSH connection (~0.6 s vs ~2.3 s cold). It exits itself after 5 idle minutes and never leaves processes or stale sockets behind; any daemon failure falls back to direct SSH, visibly (`transport` / `daemonError` fields).

## Quick start

```bash
# Keys: the Windows crypto backend needs PKCS#1 PEM RSA
# ("-----BEGIN RSA PRIVATE KEY-----"). Other formats are rejected with
# conversion instructions. Simplest: generate a dedicated key.
ssh-keygen -t rsa -b 4096 -m PEM -f terminus_key

terminus key add mykey --kind rsa --private-file ./terminus_key
terminus server add prod --host 1.2.3.4 --port 22 --user ubuntu --key mykey
terminus server ping prod

# Probe what the server supports (shell, tmux, disk, capabilities)
terminus doctor prod --json

# One-shot command (works on any server, no tmux needed)
terminus exec prod -- uname -a

# Set a default working directory once
terminus workspace set prod /srv/app
terminus exec prod -- git status         # runs in /srv/app

# Tracked background job
terminus run prod --name build -- npm run build
# status: submitted | remote_started | completed | failed | indeterminate (+ exitCode)
terminus job status prod build --json    # exits 75 while the outcome is unknown
terminus job read prod build --from-cursor --json
terminus job kill prod build             # 75 unless the process tree is proven gone

# Persistent interactive session
terminus session new prod dev
terminus exec prod:dev -- cd /srv/app    # state persists across calls
terminus exec prod:dev -- docker compose ps
terminus write prod:dev -- "journalctl -f"
terminus read prod:dev --from-cursor --json

# Files and directories
terminus push prod ./app.tar.gz /tmp/app.tar.gz
terminus pull prod /var/log/app.log ./app.log
terminus sync push prod ./dist /srv/app/dist --exclude node_modules,.git --dry-run
terminus sync pull prod /etc/nginx ./nginx-backup       # tar + scp + md5 verify

# Knowledge that survives between conversations
terminus memory add prod --key services -- "nginx :443 (systemd), api :3000 (docker compose)"
terminus fact set prod app_root /srv/app                # machine-readable k/v
terminus history prod --limit 20 --json                 # audit trail
```

## Command surface

| Command | Purpose |
|---|---|
| `server` / `key` | server and SSH key resources (SQLite-backed) |
| `exec` | synchronous remote command; `<server>` or `<server>:<session>` |
| `run` / `job` | tracked background jobs: start, ls, status, read, kill, rm |
| `session` / `read` / `write` | persistent tmux sessions with cursor-based output reading |
| `push` / `pull` / `sync` | file transfer (SCP) and recursive directory sync (tar + md5) |
| `memory` / `fact` | per-server agent knowledge: prose notes and machine k/v |
| `workspace` | per-server default remote cwd |
| `doctor` | one-round environment capability probe |
| `history` | local audit trail (what ran, where, exit code, transport) |
| `setup` | install the agent skill (Claude Code, Codex, Cursor, Windsurf, AGENTS.md) |
| `daemon` | connection pool lifecycle (status / stop / run) |

Global flags, any position: `--json`, `--db <path>`. Per-connection: `--no-daemon`.

## Agent integration

`terminus setup` installs a skill teaching agents the workflow — recall memory before acting, choose the right exec mode, save knowledge after working:

```bash
terminus setup                          # Claude Code + Codex (user-wide)
terminus setup cursor windsurf agents   # project-local rules / AGENTS.md
```

## Architecture

```text
agent / human
    │  CLI subcommands (--json)
┌───▼──────────────────────────────────────────┐
│ CLI (src/cli/)  args → dispatch → dual output │
└───┬──────────────────────────────────────────┘
┌───▼──────────────────────────────────────────┐
│ core (src/core/)                              │
│  store/    SQLite: servers keys sessions      │
│            memories jobs facts history        │
│  ssh/      libssh2: exec, SCP, auth           │
│  session/  remote tmux + results + cursors    │
│  daemon/   local unix-socket connection pool  │
└───┬───────────────────────────┬──────────────┘
    │ ssh (direct)              │ unix socket
┌───▼─────────────┐   ┌─────────▼─────────────┐
│ remote server    │   │ terminus daemon       │
│ tmux sessions    │   │ pooled SSH, idle-exit │
└──────────────────┘   └───────────────────────┘
```

Design notes live in [docs/PLAN.md](docs/PLAN.md), including a milestone-by-milestone record of what's done and the gotchas hit along the way (Zig 0.16 Windows IO, tmux races, WinCNG limits).

## Building from source

Requires Zig 0.16.0 on Windows. All C dependencies are vendored:

```bash
zig build              # debug
zig build test         # unit tests
zig build -Doptimize=ReleaseSafe
```

`zig build test` additionally needs a POSIX shell on `PATH`: two black-box gates run generated shell text through a real `sh` instead of trusting a reading of it, and they fail rather than skip when none is found. Git for Windows supplies one; if yours lives elsewhere, point the build at it with `zig build test -Dposix-sh=<path-to-sh>`.

## Security status

Current release is a **development tool, not a production credential store**:

- Private keys and passphrases are stored unencrypted in the local SQLite database (DPAPI encryption planned).
- No known-hosts verification yet — host keys are accepted on first contact.
- The daemon socket lives in your user profile; auth material transits it per-request.

Planned: DPAPI key encryption, known-hosts pinning, destructive-command policies.

## Roadmap

- **M4** — Windows ConPTY local sessions, `attach` for human takeover, key encryption
- **M5** — Linux/macOS (OpenSSL/wolfSSL backend for ed25519), MCP server adapter

## License

[MIT](LICENSE)
