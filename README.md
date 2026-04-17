# h3retik v0.0.1

SOTA red teaming operations cockpit: headless Kali execution + gamified TUI + evidence-first telemetry.

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

- Runs exploit, OSINT, and onchain operations from one keyboard-first control plane.
- Executes every operator action as reproducible headless CLI commands (`kali` or `local`).
- Captures operation state as structured telemetry (`commands`, `findings`, `loot`, `exploits`).
- Turns raw evidence into operator workflow views (`OPS`, `PWNED`, `LOOT`, `MAP`) with OPSEC cues.

## SOTA Positioning

- **Operator-first UX**: fast keyboard navigation, mode-scoped control (`exploit`, `osint`, `onchain`), live telemetry.
- **Headless by default**: every action resolves to CLI execution (`kali` or `local`) with reproducible command trails.
- **Target-agnostic execution**: pipelines/modules run from target URL + discovered evidence, not hardcoded app logic.
- **Gamified clarity**: attack-degree maps, OPSEC meters, compromise posture, and guided next-best actions.

## SOTA Comparison (Peer OSS Tools vs h3retik)

Verification source: public upstream repository descriptions (snapshot checked on **2026-04-17**).

| Repo / Tool | Official focus (upstream) | Exploit ops | OSINT ops | Onchain ops | Unified TUI cockpit | Telemetry-first evidence bus | Preconfigured Kali runtime |
|---|---|---:|---:|---:|---:|---:|---:|
| `rapid7/metasploit-framework` | Metasploit Framework | ✅ | ❌ | ❌ | ❌ | ⚠️ Partial | ❌ |
| `infobyte/faraday` | Open Source Vulnerability Management Platform | ⚠️ Partial | ❌ | ❌ | ❌ | ✅ | ❌ |
| `owasp-amass/amass` | In-depth attack surface mapping and asset discovery | ❌ | ✅ | ❌ | ❌ | ⚠️ Partial | ❌ |
| `smicallef/spiderfoot` | Automates OSINT for threat intelligence and attack surface mapping | ❌ | ✅ | ❌ | ❌ | ⚠️ Partial | ❌ |
| `lanmaster53/recon-ng` | OSINT gathering from open sources | ❌ | ✅ | ❌ | ❌ | ⚠️ Partial | ❌ |
| `crytic/slither` | Static analyzer for Solidity/Vyper | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| `ConsenSysDiligence/mythril` | Symbolic security analysis for EVM bytecode | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| **`nativ3ai/h3retik`** | **SOTA multi-domain operator cockpit** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

Legend:
- ✅ native in core workflow
- ⚠️ partial/adjacent capability
- ❌ not a core capability

## One-Liner Install

### Local repo one-liner

```bash
bash -lc 'cd /Users/native/Desktop/heretic/juiceshop-blackbox && ./scripts/install_h3retik.sh && export PATH="$HOME/.local/bin:$PATH" && h3retik up && h3retik'
```

### GitHub one-liner (global install script)

```bash
bash -lc 'curl -fsSL https://raw.githubusercontent.com/nativ3ai/h3retik/main/scripts/bootstrap_h3retik.sh | bash'
```

After install:

```bash
export PATH="$HOME/.local/bin:$PATH"
h3retik up
h3retik
```

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

- **Kali image**: `h3retik/kali:v0.0.1`
- **Compose service**: `kali` (`jsbb-kali` container)
- **Mounted volumes**:
  - `./telemetry -> /telemetry`
  - `./artifacts -> /artifacts`
- **Wrapper packs**:
  - `kali-headless/osint-*`
  - `kali-headless/onchain-*`

See full capability matrix in `docs/CAPABILITIES.md`.

## Literate Programming Docs

- `docs/LITERATE_PROGRAMMING.md` — executable architecture narrative (what, why, where in code).
- `docs/V0_0_1_LITERATE.md` — packaging/release design notes.
- `SKILL.md` — agent/operator skill profile for immediate autonomous usage.

## SOTA Delta (h3retik vs. typical red-team TUI)

| Dimension | Typical toolchains | h3retik v0.0.1 |
|---|---|---|
| Execution model | Mixed/manual terminals | Unified headless CLI bus (`kali` + `local`) |
| Evidence model | Scattered outputs | Structured telemetry (`commands/findings/loot/exploits`) |
| Workflow control | Script-level only | TUI CTRL + map/pwn/loot operational loop |
| OSINT/onchain integration | External ad hoc | Mode-scoped first-class pipelines |
| Operator guidance | Low | Next-best actions + OPSEC + attack posture |

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

## Contributing + Governance

- Contribution guide: `CONTRIBUTING.md`
- Security policy: `SECURITY.md`
- License: Apache 2.0 (`LICENSE`)

---

If you want source-available/no-reuse terms later (non-OSI), switch from Apache-2.0 to a BUSL/PolyForm-style license in the next major release.
