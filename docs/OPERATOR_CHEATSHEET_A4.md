# H3retik Operator Cheat Sheet (A4)

> One-page condensed reference for live operations.

## Mission Loop

1. `LAUNCH` runtime + stack check
2. `TARGET` set exact scope input
3. `FIRE` smallest high-value action
4. Read `OPS` + `PWNED` + `LOOT`
5. Run LOOT follow-up only when justified
6. Repeat until objective evidence is complete

## Fast Start

```bash
h3retik up
h3retik
```

Existing container attach:

```bash
export H3RETIK_KALI_CONTAINER=<name>
export H3RETIK_SKIP_UP=1
h3retik tui
```

## Essential Keys

- Move/select: `↑/↓`, `enter`, `f`
- Section/pane: `[` `]`
- Option cycle: `,` `.`
- Tabs: `h/l` or arrows
- Replay: `x`
- Loot raw toggle: `v`
- Scope: `o` OSINT, `c` ONCHAIN, `g` CO-OP
- Exploit map: `m`
- Refresh: `r`
- Quit: `q`

Map/editor quick keys:

- Action quick-select: `1..9`
- Edit endpoint/payload: `e` / `p`
- Method/token: `y` / `t`
- Payload field cycle/edit: `[` `]` / `i`

## Panel Intent

- `ARCH`: campaign state + graph/map + readiness
- `OPS`: timeline of executed commands/events
- `PWNED`: finding severity/impact progression
- `LOOT`: extracted artifacts + generated follow-ups
- `CTRL`: launch/target/fire/history execution cockpit

## Scope Playbooks

### Exploit

`prelim` -> `surface-map` -> `vuln-sweep` -> `api-probe/initial-exploit` -> `post-enum/password-attacks/privesc`

### OSINT

seed -> deep (`bbot`/`spiderfoot`) -> recon-ng -> reNgine

### Onchain

RPC catalog/check -> address flow -> static/dynamic analyzers

### Co-op (CALDERA)

up -> status -> agents -> operations -> report

## OPSEC Rules

- `LOW`: read/inspect (preferred by default)
- `MED`: authenticated probing
- `HIGH`: brute-force, write/mutation, destructive actions

Run `HIGH` only if objective value > trace cost.

## Telemetry Truth Sources

- `telemetry/state.json`
- `telemetry/commands.jsonl`
- `telemetry/findings.jsonl`
- `telemetry/loot.jsonl`
- `telemetry/exploits.jsonl`

If it is not in telemetry, treat it as unverified.

## Loot-to-Action Checklist

1. Select loot item
2. Check parsed view (`v` for raw)
3. Select generated follow-up
4. Execute (`enter`/`f`)
5. Validate in `OPS`
6. Confirm new `PWNED`/`LOOT` entries

## Quick Headless Diagnostics

```bash
h3retik doctor
h3retik coop status
h3retik pipeline --target http://127.0.0.1:3000 --profile quick
```

## Failure Triage

- Wrong scope? (`exploit/local/osint/onchain/coop`)
- Wrong target? (`CTRL -> TARGET`)
- Runtime not reachable? (`doctor`, container env vars)
- No new evidence? switch to minimal recon and rebuild chain from telemetry

