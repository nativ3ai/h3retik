# h3retik v0.0.1 — Literate Build Notes

This document explains the packaged system as executable narrative: each section maps directly to code and commands.

## 1) One command UX

Design goal: operator runs one global command.

- Entry command: `h3retik`
- Source: `h3retik`
- Install helper: `scripts/install_h3retik.sh`

Default flow:

1. Ensure TUI binary exists (`bin/juicetui`)
2. Ensure Kali runtime is up (`docker compose up -d kali`)
3. Launch TUI

## 2) Preconfigured Kali runtime

Design goal: deterministic image for headless tooling.

- Compose file: `docker-compose.yml`
- Docker build: `Dockerfile.kali`
- Image tag: `h3retik/kali:v0.0.1`

The Kali image includes OSINT, exploit, and onchain wrappers under:

- `kali-headless/osint-*`
- `kali-headless/onchain-*`

## 3) Global install model

Design goal: no manual path juggling.

- Installer copies runtime to `~/.local/share/h3retik/<version>`
- Installs launcher to `~/.local/bin/h3retik`
- Optional local TUI build if `go` is available

Install:

```bash
./scripts/install_h3retik.sh
```

## 4) Pipeline and telemetry contract

Design goal: interactive + headless share the same evidence stream.

- Target control: `scripts/targetctl.py`
- Headless orchestration: `scripts/security_pipeline.py`, `scripts/observatory_runner.py`
- Telemetry bus: `telemetry/{commands,findings,loot,exploits}.jsonl`

## 5) Skill handoff for agents

Design goal: any agent can orient quickly.

- Skill file: `SKILL.md`
- Focus: runtime topology, control entrypoints, pipeline locations, and operator workflow (not per-tool docs)
