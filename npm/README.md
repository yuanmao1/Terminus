# terminus-shell

**Agent-friendly persistent remote shell.** SSH exec, durable tmux sessions, cursor-based output reading, and per-server memory — designed for AI agents, usable by humans.

```bash
npm install -g terminus-shell
terminus setup            # install the agent skill into Claude Code / Codex
```

## Why

Most shell tools give agents one-shot command execution. Terminus gives them a durable workspace:

- **Persistent sessions** — a session maps to a remote tmux session; cwd/env survive across calls, disconnects don't destroy state.
- **Cursor reads** — `read --from-cursor` returns only new output since last read; long tasks become fire-then-poll.
- **Per-server memory** — agents store and recall facts about servers (deploy paths, quirks, task state) across conversations.
- **Stable `--json`** everywhere; remote exit codes pass through.
- **Connection daemon** — repeated calls reuse a pooled SSH connection (~0.6s instead of ~2.3s); the daemon exits itself after 5 idle minutes and never leaves processes behind.

## Quick start

```bash
terminus key add mykey --kind rsa --private-file ~/.ssh/id_rsa
terminus server add prod --host 1.2.3.4 --user ubuntu --key mykey

terminus exec prod -- uname -a                  # one-shot (no tmux needed)
terminus exec prod:work -- cd /srv/app          # persistent session
terminus exec prod:work -- docker compose ps    # same cwd as previous call

terminus write prod:work -- "./deploy.sh 2>&1"  # fire and forget
terminus read prod:work --from-cursor --json    # collect new output later

terminus memory add prod --key deploy_dir -- "app lives in /srv/app"
terminus memory ls prod --json                  # recall before acting
```

## Agent integration

`terminus setup` installs the skill for Claude Code and Codex (user-wide). Project-local targets:

```bash
terminus setup cursor windsurf agents   # .cursor/rules, .windsurf/rules, AGENTS.md
```

## Platform

Windows x64 (prebuilt, zero dependencies — SQLite and libssh2 are compiled in). Linux/macOS planned.

Currently no known-hosts verification and keys are stored unencrypted locally — treat it as a dev tool, not a production credential store, until those land.

## License

MIT
