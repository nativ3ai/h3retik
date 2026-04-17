# h3retik v0.0.1

SOTA red teaming operations cockpit: headless Kali execution, gamified operator UX, and evidence-first telemetry.

```text
                            ,--.
                           {    }
                           K,   }
                          /  ~Y`
                     ,   /   /
                    {_'-K.__/
                      `/-.__L._
                      /  ' /`\_}
                     /  ' /
             ____   /  ' /
      ,-'~~~~    ~~/  ' /_
    ,'             ``~~~  ',
   (                        Y
  {                         I
 {      -                    `,
 |       ',                   )
 |        |   ,..__      __. Y
 |    .,_./  Y ' / ^Y   J   )|
 \           |' /   |   |   ||
  \          L_/    . _ (_,.'(
   \,   ,      ^^""' / |      )
     \_  \          /,L]     /
       '-_~-,       ` `   ./`
          `'{_            )
              ^^\..___,.--`
```

## What It Does

- Runs exploit, OSINT, and onchain workflows from one keyboard-first control plane.
- Executes operator actions as reproducible headless CLI commands (`kali` or `local`).
- Captures structured evidence in telemetry streams (`commands`, `findings`, `loot`, `exploits`).
- Maps operations into fast views (`OPS`, `PWNED`, `LOOT`, `MAP`) with OPSEC signal and next actions.

## Why H3retik

- Operator-first design with mode-scoped workflow (`exploit`, `osint`, `onchain`).
- Target-agnostic execution from target URL + discovered evidence.
- Unified runtime: packaged Kali + wrappers + modular pipelines.
- Gamified but professional UX for real operations tempo.

### Peer Feature Baseline (Operator-Relevant)

Verification source: public upstream repository docs/readmes (snapshot checked on **2026-04-17**).

| Professional red-team feature | `PurpleAILAB/Decepticon` | `rapid7/metasploit-framework` | `mitre/caldera` | `infobyte/faraday` | **`nativ3ai/h3retik`** |
|---|---:|---:|---:|---:|---:|
| Exploit module ecosystem (built-in) | Partial | Yes | Partial | No | Partial |
| Adversary emulation / kill-chain orchestration | Yes | Partial | Yes | No | Partial |
| C2 / agent management in-core | Partial | Partial | Yes | No | No |
| Credential attack workflows (online/offline) | Partial | Yes | Partial | No | Yes |
| Operator-in-the-loop UX (fast steering) | Partial | Partial | Partial | Yes | **Yes** |
| Evidence capture for later reporting/audit | Partial | Partial | Partial | Yes | **Yes** |
| Multi-tool unification into one loop | Partial | Partial | Partial | Partial | **Yes** |
| Preconfigured Kali runtime + wrappers | No | No | No | No | **Yes** |
| Integrated OSINT lane in same runtime | No | No | No | No | **Yes** |
| Integrated onchain lane in same runtime | No | No | No | No | **Yes** |

Notes:
- `Yes` = ships as a first-class, default workflow in the core project/runtime.
- `Partial` = achievable via plugins/manual composition/integration, but not the default operator loop.
- This table compares “what a working operator gets out of the box”, not what can be built with enough glue.

### What You Configure (Primitives)

| Repo / Tool | Primary configuration primitive (what operators actually edit / drive) |
|---|---|
| `PurpleAILAB/Decepticon` | Engagement plan + agent configuration (kill-chain automation driven from a run plan) |
| `rapid7/metasploit-framework` | Modules, payload options, resource scripts (`.rc`), sessions/workspaces |
| `mitre/caldera` | Abilities/TTPs + operations/tasking + plugins (server + agent C2 configuration) |
| `infobyte/faraday` | Projects + imports/normalization + reporting/dashboard configuration |
| **`nativ3ai/h3retik`** | Target scope + operator pipelines + evidence/telemetry streams (`telemetry/*.jsonl`, `telemetry/state.json`) |

## One-Liner Install

### Local repo one-liner

```bash
bash -lc 'cd /Users/native/Desktop/heretic/juiceshop-blackbox && ./scripts/install_h3retik.sh && export PATH="$HOME/.local/bin:$PATH" && h3retik up && h3retik'
```

### GitHub bootstrap one-liner

```bash
bash -lc 'curl -fsSL https://raw.githubusercontent.com/nativ3ai/h3retik/main/scripts/bootstrap_h3retik.sh | bash'
```

After install:

```bash
export PATH="$HOME/.local/bin:$PATH"
h3retik up
h3retik
```

Optional agent skill wiring (for agent runtimes that support local skills):

```bash
mkdir -p ~/.codex/skills/h3retik
ln -sf "$(pwd)/SKILL.md" ~/.codex/skills/h3retik/SKILL.md
```

- Local skill source: [`SKILL.md`](SKILL.md)
- Optional remote skill source: `https://raw.githubusercontent.com/nativ3ai/h3retik/main/SKILL.md`

## Command Surface

```bash
h3retik                          # start kali + launch TUI
h3retik up                       # start/build kali service
h3retik down                     # stop stack
h3retik target ...               # scripts/targetctl.py passthrough
h3retik pipeline ...             # scripts/security_pipeline.py passthrough
h3retik observatory ...          # scripts/observatory_runner.py passthrough
h3retik kali "<cmd>"             # execute command in kali container
h3retik doctor                   # runtime checks
```

## Mounted Runtime + Suite

- Kali image: `h3retik/kali:v0.0.1`
- Compose service: `kali` (`jsbb-kali`)
- Mounted volumes:
  - `./telemetry -> /telemetry`
  - `./artifacts -> /artifacts`
- Wrapper packs:
  - `kali-headless/osint-*`
  - `kali-headless/onchain-*`

Capability matrix: [`docs/CAPABILITIES.md`](docs/CAPABILITIES.md)

## Documentation Index

- Literate architecture: [`docs/LITERATE_PROGRAMMING.md`](docs/LITERATE_PROGRAMMING.md)
- Release design notes: [`docs/V0_0_1_LITERATE.md`](docs/V0_0_1_LITERATE.md)
- Capability matrix: [`docs/CAPABILITIES.md`](docs/CAPABILITIES.md)
- Agent skill profile: [`SKILL.md`](SKILL.md)
- Contribution workflow: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Security policy: [`SECURITY.md`](SECURITY.md)

## Operational Model (h3retik vs typical red-team TUI)

| Dimension | Typical toolchains | h3retik v0.0.1 |
|---|---|---|
| Execution model | Mixed terminals and ad hoc scripts | Unified headless CLI bus (`kali` + `local`) |
| Evidence model | Scattered outputs | Structured telemetry (`commands/findings/loot/exploits`) |
| Workflow control | Script-level only | TUI CTRL + map/pwn/loot loop |
| Domain coverage | Usually single-domain | Exploit + OSINT + onchain in one cockpit |
| Operator guidance | Limited | OPSEC cues + next-best actions |

```mermaid
flowchart LR
  A[Target Input] --> B[CTRL Fire Engine]
  B --> C[Kali / Local Headless Commands]
  C --> D[Telemetry Bus]
  D --> E[PWNED / LOOT / OPS / MAP]
  E --> F[Operator Decisions]
  F --> B
```

## Quick Start

```bash
h3retik target set --kind custom --url http://127.0.0.1:8080
h3retik up
h3retik
```

## Governance

- License: Apache 2.0 (`LICENSE`)
- Contribution guide: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Security policy: [`SECURITY.md`](SECURITY.md)
