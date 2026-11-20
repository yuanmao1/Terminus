# Terminus

**Agent-friendly persistent remote shell.** SSH exec, durable tmux sessions, tracked background jobs, directory sync, and per-server memory — designed for AI agents, usable by humans.

```bash
npm install -g terminus-shell
terminus setup          # install the agent skill into Claude Code / Codex
```

Written in Zig 0.17. Single binary, zero runtime dependencies — SQLite and libssh2 are compiled in (WinCNG crypto backend on Windows, vendored mbedTLS on Linux/macOS). Prebuilt for Windows x64, Linux x64/arm64 (static musl) and macOS x64/arm64.

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
# Keys: on Windows Terminus needs PKCS#1 PEM RSA without a passphrase
# ("-----BEGIN RSA PRIVATE KEY-----"); on Linux/macOS any RSA or ECDSA key
# (OpenSSH, PEM or PKCS#8). ed25519 is not supported. Unusable keys are
# rejected with conversion instructions. Simplest: generate a dedicated key.
ssh-keygen -t rsa -b 4096 -m PEM -f terminus_key

terminus key add mykey --kind rsa --private-file ./terminus_key
terminus server add prod --host 1.2.3.4 --port 22 --user ubuntu --key mykey
terminus server ping prod

# Probe what the server supports (shell, tmux, disk, capabilities)
terminus doctor prod --json

# One-shot command (works on any server, no tmux needed)
terminus exec prod -- uname -a
terminus exec prod --read-only --cmd 'psql -c "SELECT now()"'
terminus exec prod --script ./deploy.sh              # CRLF-safe local script channel
terminus exec prod --detach --cmd './long-build.sh'  # durable helper-backed execution
terminus request inspect <request-id> --json
terminus request tail <request-id> --follow
terminus request cancel <request-id> --grace-ms 2000

# Set a default working directory once
terminus workspace set prod /srv/app
terminus exec prod -- git status         # runs in /srv/app

# Tracked background job
terminus run prod --name build -- npm run build
# status: submitted | remote_started | completed | failed | indeterminate (+ exitCode)
terminus job status prod build --json    # exits 75 while the outcome is unknown
terminus job watch prod build --interval 15s --max 4 --json  # initial probe, then at most four more
terminus job read prod build --from-cursor --json
terminus job kill prod build             # 75 unless the process tree is proven gone

# Persistent interactive session
terminus session new prod dev
terminus exec prod:dev -- cd /srv/app    # state persists across calls
terminus exec prod:dev -- docker compose ps
terminus write prod:dev -- "journalctl -f"
terminus read prod:dev --from-cursor --json

# A human at the keyboard: real TTY (vim, htop, Ctrl-C, resize all work)
terminus shell prod                      # login shell; not persistent
terminus attach prod:dev                 # the agent's tmux session; survives detach,
                                         # reconnects by itself after a network drop
# In either, Ctrl-] then ? lists local commands: d detach, . force disconnect,
# p push a file, g pull a file, Ctrl-] Ctrl-] sends a literal Ctrl-].

# No tmux on the host? Install the one Terminus carries (static, no root,
# no network needed on the host), or pass --allow-tmux-install to attach.
terminus server tmux prod --allow-tmux-install

# Files and directories
terminus push prod ./app.tar.gz /tmp/app.tar.gz
# recognized binaries/scripts default to mode 755; other files default to 644
terminus pull prod /var/log/app.log ./app.log
terminus sync push prod ./dist /srv/app/dist --exclude node_modules,.git --dry-run
terminus sync pull prod /etc/nginx ./nginx-backup       # tar + scp + md5 verify

# Knowledge that survives between conversations
terminus memory add prod --key services -- "nginx :443 (systemd), api :3000 (docker compose)"
terminus fact set prod app_root /srv/app                # machine-readable k/v
terminus history prod --limit 20 --json                 # audit trail

# Read-only disk inspection and manifest-bound cleanup
terminus audit prod disk --largest 30
terminus audit prod disk --mounts
terminus audit prod disk --containers
terminus cleanup prod --manifest ./cleanup.json --dry-run
terminus cleanup prod --manifest ./cleanup.json --apply --plan-sha <sha256>
```

## Command surface

| Command | Purpose |
|---|---|
| `server` / `key` | server and SSH key resources (SQLite-backed) |
| `exec` / `request` | supervised command execution, detach, inspect, tail, and verified cancellation |
| `audit` / `cleanup` | closed read-only audits and manifest-bound cleanup with dry-run/apply separation |
| `run` / `job` | tracked background jobs: start, ls, status, read, kill, rm |
| `session` / `read` / `write` | persistent tmux sessions with cursor-based output reading |
| `push` / `pull` / `sync` | file transfer (SCP) and recursive directory sync (tar + md5) |
| `memory` / `fact` | per-server agent knowledge: prose notes and machine k/v |
| `workspace` | per-server default remote cwd |
| `doctor` | one-round environment capability probe |
| `history` | local audit trail (what ran, where, exit code, transport) |
| `setup` | install the agent skill (Claude Code, Codex, Cursor, Windsurf, AGENTS.md) |
| `daemon` | local daemon diagnostics (status / stop / restart / run) |

Global flags, any position: `--json`, `--db <path>`. Per-connection:
`--no-daemon`, placed after the command target (for example
`terminus exec prod --no-daemon --cmd "uname -a"`).

The released Windows build uses direct SSH immediately and does not auto-start
or route commands through the daemon, avoiding a first-connection stall that
could last minutes.

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

## Building from source

Requires Zig 0.17.0 (Windows, Linux or macOS host). All C dependencies are vendored:

```bash
zig build              # debug
zig build test         # unit tests
zig build -Doptimize=ReleaseSafe
```

Cross-compiling the npm binaries from any host (`npm/bin/` names in brackets):

```bash
zig build -Doptimize=ReleaseSafe -Dtarget=x86_64-windows   # Terminus.exe
zig build -Doptimize=ReleaseSafe -Dtarget=x86_64-linux-musl  -Dstrip -p out/linux-x64     # terminus-linux-x64
zig build -Doptimize=ReleaseSafe -Dtarget=aarch64-linux-musl -Dstrip -p out/linux-arm64   # terminus-linux-arm64
zig build -Doptimize=ReleaseSafe -Dtarget=x86_64-macos       -p out/darwin-x64    # terminus-darwin-x64
zig build -Doptimize=ReleaseSafe -Dtarget=aarch64-macos      -p out/darwin-arm64  # terminus-darwin-arm64
```

`zig build test` additionally needs a POSIX shell on `PATH`: two black-box gates run generated shell text through a real `sh` instead of trusting a reading of it, and they fail rather than skip when none is found. Git for Windows supplies one; if yours lives elsewhere, point the build at it with `zig build test -Dposix-sh=<path-to-sh>`.

## Security status

Current release is a **development tool, not a production credential store**:

- Private keys and passphrases are stored unencrypted in the local SQLite database (DPAPI encryption planned).
- No known-hosts verification yet — host keys are accepted on first contact.
- The daemon socket lives in your user profile; auth material transits it per-request.

Planned: DPAPI key encryption, known-hosts pinning, destructive-command policies.

## Roadmap

- **M4** — Windows ConPTY local sessions, key encryption (`shell` / `attach` for human takeover have landed)
- **M5** — Linux/macOS (landed, mbedTLS backend); ed25519 keys, MCP server adapter

## License

[MIT](LICENSE)
