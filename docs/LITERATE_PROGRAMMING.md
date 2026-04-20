# Literate Programming Guide — h3retik v0.0.3

This document is written as an executable narrative: every capability maps to concrete files and commands.

## 1. Problem Statement

Red-team workflows often fragment across terminal tabs, ad-hoc notes, and disconnected scripts.  
h3retik unifies execution, evidence, and operator state into one loop.

## 2. Core Design

### 2.1 Control Plane

- TUI source: `cmd/juicetui/main.go`
- Runtime entry: `h3retik`
- Install bootstrap: `scripts/install_h3retik.sh`

The control plane supports mode-scoped workflows:

- exploit
- osint
- onchain
- coop (CALDERA C2)

### 2.2 Execution Plane

Headless command execution happens through:

- local runtime (`python3`/native commands)
- Kali runtime (`docker exec $H3RETIK_KALI_CONTAINER bash -lc ...`)

Kali is provisioned by:

- `Dockerfile.kali`
- `docker-compose.yml`

If `h3retik-kali` already exists on the machine, `h3retik` can attach to it instead of bringing up a fresh compose container, provided `H3RETIK_SKIP_UP=1` is set or the default container already matches the expected name.

### 2.3 Evidence Plane

All actions should converge into JSONL telemetry:

- `telemetry/commands.jsonl`
- `telemetry/findings.jsonl`
- `telemetry/loot.jsonl`
- `telemetry/exploits.jsonl`

This is the canonical source for OPS/PWNED/LOOT/MAP rendering.

## 3. Pipeline Sources

### 3.1 Orchestrators

- `scripts/targetctl.py` — target lifecycle and state
- `scripts/security_pipeline.py` — exploit pipelines
- `scripts/observatory_runner.py` — high-level orchestrated runs

### 3.2 Modular Extensions

- `modules/exploit/*.json` — dynamic fireable modules in CTRL

### 3.3 Headless Wrappers

- `kali-headless/osint-*`
- `kali-headless/onchain-*`
- `kali-headless/coop-*`

## 4. Operational Loop

1. Set/verify target (`targetctl`)
2. Fire scoped actions from CTRL
3. Review compromise in PWNED
4. Inspect extracted evidence in LOOT
5. Explore relationships and access paths in MAP
6. Iterate with OPSEC-aware next actions

## 5. Release v0.0.3 Contract

v0.0.3 guarantees:

- single global command (`h3retik`)
- preconfigured Kali image tag (`h3retik/kali:v0.0.3`)
- agent skill profile (`SKILL.md`)
- documented capabilities (`docs/CAPABILITIES.md`)

## 6. Reproducibility Recipe

```bash
./scripts/install_h3retik.sh
export PATH="$HOME/.local/bin:$PATH"
h3retik up
h3retik doctor
h3retik
```

## 7. Next SOTA Milestones (post v0.0.3)

- multi-operator shared ops space (presence, role separation, conflict controls)
- blue-team co-observation panel with remediation proposals
- signed module marketplace and capability policy sandbox
- immutable evidence ledger + report provenance
