# h3retik v0.0.5

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
              ^^\..h3retik
```

## What It Does
- Gamifies redteaming hacking opex through an intuitive TUI
- Runs exploit, local-file/package, OSINT, onchain, and co-op/C2 workflows from one keyboard-first control plane.
- Executes operator actions as reproducible headless CLI commands (`kali` or `local`).
- Captures structured evidence in telemetry streams (`commands`, `findings`, `loot`, `exploits`).
- Maps operations into fast views (`OPS`, `PWNED`, `LOOT`, `MAP`) with OPSEC signal and next actions.

## Why H3retik

- Operator-first design with mode-scoped workflow (`exploit`, `local`, `osint`, `onchain`, `coop`).
- Target-agnostic execution from target URL + discovered evidence.
- Unified runtime: packaged Kali + wrappers + modular pipelines.
- Gamified but professional UX for real operations tempo.

### Peer Feature Baseline (Operator-Relevant)

Verification source: public upstream repository docs/readmes (snapshot checked on **2026-04-17**).

| Professional red-team feature | `PurpleAILAB/Decepticon` | `rapid7/metasploit-framework` | `mitre/caldera` | `infobyte/faraday` | **`nativ3ai/h3retik`** |
|---|---:|---:|---:|---:|---:|
| Exploit module ecosystem (built-in) | Partial | Yes | Partial | No | Partial |
| Adversary emulation / kill-chain orchestration | Yes | Partial | Yes | No | Partial |
| C2 / agent management in-core | Partial | Partial | Yes | No | Partial |
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

## Installation Requirements (Fresh Machine)

| Requirement | Needed for | Required |
|---|---|---|
| `docker` + `docker compose` plugin | Kali runtime, wrappers, co-op stack | Yes |
| `git` | bootstrap/source install | Yes |
| `bash` | launcher + installer scripts | Yes |
| `python3` | `target`/`pipeline`/`observatory` helpers | Yes |
| `go` | local build of `juicetui` (`h3retik build`) | Recommended |

## Platform Support

| Host OS | Entry path | Status |
|---|---|---|
| macOS (Apple Silicon / Intel) | source installer or npm (`@h1dr4/h3retik`) | Supported |
| Linux (x86_64 / arm64) | source installer or npm (`@h1dr4/h3retik`) | Supported |
| Windows 11/10 + Docker Desktop | npm (`@h1dr4/h3retik`) native launcher | Supported |

The runtime is target-agnostic and machine-agnostic: host OS only provides launcher + Docker, while operations execute through the same Kali toolchain.

Go clarity:
- If `bin/juicetui` is already present (prebuilt), H3RETIK can run without Go.
- If no prebuilt binary is present, Go becomes required to compile the TUI.
- `h3retik setup` explains this path and can attempt dependency install.

Runtime footprint:
- Current Kali image size on disk: ~`17–18GB` (`h3retik/kali:v0.0.5`).
- Recommended free disk for first install/build + artifacts: `30GB+` (better: `40GB`).
- Recommended memory: `8GB+` (`16GB` preferred for heavy scan/fuzz workloads).

## One-Liner Install

### Source install one-liner (global path)

```bash
bash -lc 'SRC="${H3RETIK_SRC_DIR:-$HOME/.local/src/h3retik}"; rm -rf "$SRC"; git clone https://github.com/nativ3ai/h3retik.git "$SRC" && cd "$SRC" && ./scripts/install_h3retik.sh && export PATH="$HOME/.local/bin:$PATH" && h3retik'
```

### GitHub bootstrap one-liner

```bash
bash -lc 'curl -fsSL https://raw.githubusercontent.com/nativ3ai/h3retik/main/scripts/bootstrap_h3retik.sh | bash'
```

### npm global install (multiplatform)

```bash
npm i -g @h1dr4/h3retik
h3retik init
```

Non-interactive universal default:

```bash
npm i -g @h1dr4/h3retik
h3retik init --yes --profile full
```

npm package behavior by platform:
- macOS/Linux: installs and invokes the native `h3retik` launcher (`scripts/install_h3retik.sh`) and keeps full CLI parity.
- Windows: runs a native Node launcher, ensures `juicetui.exe`, brings up Docker Compose runtime, then starts the TUI.
- Binary bootstrap: pulls prebuilt `juicetui_<version>_<os>_<arch>.tar.gz` from GitHub Releases; if unavailable, falls back to local `go build`.
- Guided modular setup: `h3retik init` / `h3retik setup` prompts for profile:
  - `TUI only` (no Docker auto-up)
  - `Full Docker runtime + TUI`
  - `Headless CLI only`
  - `Custom` (native setup wizard)
- Fully non-interactive install path:
  - `h3retik init --yes --profile full`
  - `h3retik init --yes --profile tui-only`
  - `h3retik init --yes --profile headless`

For Windows, Docker Desktop must be running. Native `h3retik` command works directly from PowerShell:

```powershell
npm i -g @h1dr4/h3retik
h3retik init
```

What the all-in-one installer does:
- Pulls `nativ3ai/h3retik` source to `~/.local/src/h3retik` (or updates it).
- Copies runtime payload to `~/.local/share/h3retik/<version>`.
- Installs global launcher at `~/.local/bin/h3retik`.
- Creates writable runtime dirs: `telemetry/`, `artifacts/`, `bin/`.
- Builds `bin/juicetui` if `go` is installed (otherwise build happens later when available).
- Does not auto-start containers; runtime comes up with `h3retik up` or first `h3retik`.
- On first `h3retik` launch, opens a guided setup wizard (`h3retik setup`) to configure runtime mode, deps, and optional bundles.

After install:

```bash
export PATH="$HOME/.local/bin:$PATH"
h3retik
```

First run launches a guided safe installer wizard automatically:
- `bundled`: managed Kali container (recommended)
- `attach`: attach to your own existing Docker Kali/container
- `local`: local-only mode (no Kali/Docker)
- modular tool footprint profiles:
- `minimal` (base runtime only)
- `local-lite` (local exploit lane pack)
- `web-lite` (web lane packs)
- `full` (all bundled packs)
- custom bundle checklist or custom comma-separated tool list

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
h3retik init                     # guided modular install profile
h3retik setup                    # guided first-run setup (runtime mode, deps, optional bundles)
h3retik attach                   # attach TUI to existing running kali container (no compose up)
h3retik --kali-container my-kali tui
h3retik --kali-image my/kali:tag up
h3retik up                       # start/build kali service
h3retik down                     # stop stack
h3retik build                    # rebuild TUI binary in active h3retik root
h3retik build-kali               # build kali image
h3retik target ...               # scripts/targetctl.py passthrough
h3retik pipeline ...             # scripts/security_pipeline.py passthrough
h3retik observatory ...          # scripts/observatory_runner.py passthrough
h3retik pipeline-cloud ...       # convert built-in named pipelines to cloud-ready command payload
h3retik import-runs <path>       # import campaign telemetry into local telemetry/runs
h3retik tools list               # list optional on-demand tools in kali
h3retik tools install recon-plus # install optional recon tool bundle in kali
h3retik tools install web-adv-plus
h3retik tools install ad-plus
h3retik tools install k8s-plus
h3retik tools install crack-plus
h3retik tools install coop-plus    # install wildmesh collaboration runtime
h3retik tools install local-plus   # install local redteam suite (privesc/binary/code/internal)
h3retik tools install local-plus --strict # fail if any requested local tool is missing
h3retik modules add-local-tool --name "Semgrep Quick" --cmd "semgrep --config auto ." --category Code
h3retik modules list               # list user-registered modules (~/.config/h3retik/modules)
h3retik modules remove --id user-semgrep-quick --yes # remove a user module
h3retik kali "<cmd>"             # execute command in kali container
h3retik local stack-check        # local lane stack check wrappers
h3retik local privesc /workspace # local lane privesc wrappers
h3retik local binary /workspace  # local lane binary triage wrappers
h3retik local package /workspace # local lane package/code audit wrappers
h3retik local internal           # local lane internal recon wrappers
h3retik coop caldera <cmd>       # caldera helpers (check/up/status/stop/api/report)
h3retik coop wildmesh <cmd>      # wildmesh helpers (check/setup/up/status/discover/policy/sync/automate/stop)
h3retik update                   # pull latest repo + reinstall global launcher
h3retik doctor                   # runtime checks
```

- If you run the global launcher (`~/.local/bin/h3retik`), `h3retik build` rebuilds the TUI in the active installed root (`~/.local/share/h3retik/<version>`).
- Use `h3retik update` to pull latest upstream changes and refresh the installed runtime.
- On TUI startup, h3retik checks upstream version and prompts: update now, ignore this version, or continue.
- Setup wizard supports runtime modes: `bundled` (recommended), `attach`, `local` (no Kali/Docker).
- To bypass first-run setup in automation, set `H3RETIK_NO_SETUP_WIZARD=1`.
- Setup state/config is persisted in `~/.config/h3retik` (override with `H3RETIK_CONFIG_DIR`).
- TUI fast mode keys in CTRL: `o` OSINT, `y` LOCAL, `c` ONCHAIN, `g` CO-OP.

## Cloud Companion

For hosted/on-the-go usage:
- Portal: `https://h1dr4.dev/h3retik`
- API base: `https://h1dr4.dev/h3retik/api`
- Agent cloud skill: `https://h1dr4.dev/h3retik/skills/h3retik-agent.md`

Pipeline portability to cloud without new endpoint:

```bash
h3retik pipeline-cloud --target https://target.tld --pipeline full-chain
```

Use `suggested_cloud_job_cmd` as cloud job `args.cmd` and lease/install needed tools first.

## Documentation Map (Canonical)

- Start here: [`docs/START_HERE.md`](docs/START_HERE.md)
- Fast daily operator flow: [`docs/OPERATOR_CHEATSHEET.md`](docs/OPERATOR_CHEATSHEET.md)
- Full TUI reference: [`docs/TUI_OPERATOR_REFERENCE.md`](docs/TUI_OPERATOR_REFERENCE.md)
- Full command matrix: [`docs/PIPELINES_AND_COMMANDS.md`](docs/PIPELINES_AND_COMMANDS.md)
- Capability matrix: [`docs/CAPABILITIES.md`](docs/CAPABILITIES.md)
- Tool inventory: [`docs/TOOLS_REFERENCE.md`](docs/TOOLS_REFERENCE.md)
- Local exploit workflows: [`docs/LOCAL_LANE_RUNBOOK.md`](docs/LOCAL_LANE_RUNBOOK.md)
- Agent orchestration workflows: [`docs/AGENT_ORCHESTRATION_COOKBOOK.md`](docs/AGENT_ORCHESTRATION_COOKBOOK.md)

## Maintainer Release

Release publishing is maintainer-only and intentionally kept out of contributor workflow docs.
Contributors should focus on:
- reproducible code quality (`bash -n`, tests, smoke checks)
- documentation clarity and canonical docs updates
- non-breaking modular changes with telemetry continuity

## Existing Kali / External Runtime

h3retik can run only the TUI against an already-running container. If `h3retik-kali` already exists, `h3retik` will reuse it automatically; otherwise set the container name explicitly.

```bash
export H3RETIK_KALI_CONTAINER=<your-kali-container>
export H3RETIK_SKIP_UP=1
h3retik tui
```

Or with one command:

```bash
h3retik --kali-container <your-kali-container> attach
```

For the default container name, no extra flag is needed if `h3retik-kali` is already running:

```bash
h3retik
```

Optional image override for compose-managed mode:

```bash
export H3RETIK_KALI_IMAGE=<custom-image-tag>
h3retik up
```

Equivalent one-shot flag:

```bash
h3retik --kali-image <custom-image-tag> up
```

Important:
- Some actions fail if your external Kali image does not include required wrappers/packages.
- Required wrappers are documented in `docs/CAPABILITIES.md` (`osint-*`, `onchain-*`, `coop-*`).
- `CTRL` runtime can be changed in-TUI: `TARGET -> KALI Runtime Container (Type)` and `TARGET -> KALI Runtime Image (Type)`.
- FIRE options are capability-aware: missing Kali tools are filtered/locked so non-runnable commands are not presented as ready.

Minimum compatibility checklist for external Kali images:
- Base runtime: `bash`, `python3`, `curl`, `jq`, `git`.
- Exploit lane core: `nmap`, `ffuf`, `nikto`, `sqlmap`, `hydra`, `medusa`, `nuclei`, `metasploit-framework`.
- Local lane core: `linpeas`, `lse`, `pspy`, `linux-exploit-suggester`, `checksec`, `radare2`, `semgrep`, `gitleaks`, `trivy`, `grype`.
- OSINT lane core: `theharvester`, `bbot`, `spiderfoot`, `recon-ng`, `rengine` (or equivalent callable wrapper).
- Onchain lane core: `slither`, `myth` (mythril), `forge`, `cast`, `echidna`, `medusa`, `halmos`.
- Co-op lane core: `caldera` and/or `wildmesh` + wrappers (`coop-caldera-*`, `coop-wildmesh-*`).

If you want full feature parity, use `h3retik up` with the default bundled Kali image.

## Runtime + Suite

- Kali image: `h3retik/kali:v0.0.5`
- Compose service: `kali` (`${H3RETIK_KALI_CONTAINER:-h3retik-kali}`)
- Mounted volumes:
  - `./telemetry -> /telemetry`
  - `./artifacts -> /artifacts`
- Wrapper packs:
  - `kali-headless/osint-*`
  - `kali-headless/onchain-*`
  - `kali-headless/coop-*`

Capability matrix: [`docs/CAPABILITIES.md`](docs/CAPABILITIES.md)

## Co-op UX Flow (Backend-Agnostic)

- Open `CTRL`, press `g` to switch scope to `CO-OP`.
- Use `[]` to choose section (`LAUNCH`, `TARGET`, `FIRE`, `HISTORY`).
- Use `↑/↓` for category selection and `,/.` for options in the selected category.
- In `TARGET`, set backend profile (`CALDERA` or `WILDMESH`), then configure backend-specific fields.
- In `FIRE`, run the loop:
  - CALDERA: start C2 -> status -> agents -> operations -> report.
  - WILDMESH: setup node -> status -> discover -> policy check -> snapshot sync.
- A non-invasive context hint appears in `CTRL` while in `CO-OP` mode to guide next step.

## Repository Includes

- [`cmd/juicetui/`](cmd/juicetui) — TUI source (CTRL/ARCH/OPS/PWNED/LOOT/MAP).
- [`kali-headless/`](kali-headless) — headless wrappers for exploit/OSINT/onchain/co-op.
- [`modules/exploit/`](modules/exploit) — dynamic exploit module manifests.
- [`scripts/`](scripts) — install/bootstrap + target/pipeline orchestration.
- [`docs/`](docs) — literate architecture, scoring, capability matrix, tutorials.
- [`telemetry/`](telemetry) — JSON/JSONL operation streams consumed by the TUI.
- [`artifacts/`](artifacts) — persisted command outputs/evidence bundles.

## Telemetry Contract

h3retik uses JSONL telemetry as source-of-truth for all panes:

- `telemetry/state.json`
- `telemetry/commands.jsonl`
- `telemetry/findings.jsonl`
- `telemetry/loot.jsonl`
- `telemetry/exploits.jsonl`

Telemetry usage by pane:
- `OPS` reads command/event timeline from `commands.jsonl`.
- `PWNED` reads normalized vulnerabilities/impact from `findings.jsonl` + `exploits.jsonl`.
- `LOOT` reads validated artifacts/entities from `loot.jsonl`.
- `ARCH`/`MAP` reads current target and campaign state from `state.json` + correlated findings.

This keeps TUI state and headless execution synchronized, replayable, and exportable.

## Documentation Index

- Literate architecture: [`docs/LITERATE_PROGRAMMING.md`](docs/LITERATE_PROGRAMMING.md)
- Release design notes: [`docs/V0_0_1_LITERATE.md`](docs/V0_0_1_LITERATE.md)
- Capability matrix: [`docs/CAPABILITIES.md`](docs/CAPABILITIES.md)
- TUI operator manual (keys/panels/modes): [`docs/TUI_OPERATOR_REFERENCE.md`](docs/TUI_OPERATOR_REFERENCE.md)
- Operator cheat sheet (fast field card): [`docs/OPERATOR_CHEATSHEET.md`](docs/OPERATOR_CHEATSHEET.md)
- Operator cheat sheet (A4 condensed): [`docs/OPERATOR_CHEATSHEET_A4.md`](docs/OPERATOR_CHEATSHEET_A4.md)
- Pipelines + commands + follow-ups: [`docs/PIPELINES_AND_COMMANDS.md`](docs/PIPELINES_AND_COMMANDS.md)
- Preinstalled tool-by-tool reference: [`docs/TOOLS_REFERENCE.md`](docs/TOOLS_REFERENCE.md)
- Co-op CALDERA tutorial: [`docs/COOP_CALDERA_TUTORIAL.md`](docs/COOP_CALDERA_TUTORIAL.md)
- Scoring model: [`docs/SCORING.md`](docs/SCORING.md)
- Agent skill profile: [`SKILL.md`](SKILL.md)
- Contribution workflow: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Security policy: [`SECURITY.md`](SECURITY.md)

## Operational Model (h3retik vs typical red-team TUI)

| Dimension | Typical toolchains | h3retik v0.0.5 |
|---|---|---|
| Execution model | Mixed terminals and ad hoc scripts | Unified headless CLI bus (`kali` + `local`) |
| Evidence model | Scattered outputs | Structured telemetry (`commands/findings/loot/exploits`) |
| Workflow control | Script-level only | TUI CTRL + map/pwn/loot loop |
| Domain coverage | Usually single-domain | Exploit + OSINT + onchain + co-op/C2 in one cockpit |
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

## Security Reporting

- Supported release line: `v0.0.5` (latest tagged release on `main`).
- Report vulnerabilities privately through GitHub Security Advisories (preferred) or direct maintainer contact.
- Do not publish exploitable details in public issues before coordinated disclosure.
