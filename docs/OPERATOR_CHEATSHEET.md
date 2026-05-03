# H3retik Operator Cheat Sheet

Minimal, fast, and OPSEC-aware field card.

## 0) Prime Directive

- Authorized targets only.
- Start low-noise, escalate only with evidence.
- Every action should improve telemetry quality or objective progress.

## 1) Launch Sequence (60 seconds)

```bash
h3retik up
h3retik
```

In TUI:

1. `CTRL` -> `LAUNCH` -> runtime/stack check
2. `CTRL` -> `TARGET` -> set scope input
3. `CTRL` -> `FIRE` -> run first minimal action

## 2) Keybindings You Actually Use

- Move/select: `↑/↓`, `enter`, `f`
- Section/pane: `[` `]`
- Option cycle: `,` `.`
- Tabs: `h/l` (or arrows)
- Replay: `x`
- Loot raw/parsing: `v`
- Scope switch: `o` (OSINT), `y` (LOCAL), `c` (ONCHAIN), `g` (CO-OP)
- Exploit map: `m`
- Refresh: `r`

## 3) Scope Runbooks

### Exploit

- Start: `prelim` -> `surface-map` -> `vuln-sweep`
- Pivot: `api-probe` / `initial-exploit`
- Escalate: `post-enum` -> `password-attacks` -> `privesc`
- Consolidate: `full-chain` or evidence snapshot

### OSINT

- Seed -> deep (`bbot`/`spiderfoot`) -> recon-ng -> reNgine
- Keep entities clean and deduplicated in loot

### Onchain

- RPC catalog/check -> address flow -> static + dynamic analyzers
- Preserve artifacts for reproducible reporting

### Co-op (CALDERA)

- Up -> status -> agents -> operations -> report
- Use inline `hint :: ...` as next-step guide

### Local

- Stack-check -> privesc -> binary triage -> package audit -> internal recon
- Target path defaults to `/workspace` for headless wrappers

## 4) OPSEC Quick Policy

- `LOW` meter: read-only checks/inspection.
- `MED` meter: authenticated probing and boundary validation.
- `HIGH` meter: brute-force, mutation, or write operations.

Practical rule:

- Execute HIGH only when objective value is clear and evidence gap justifies trace cost.

## 5) PWN Progress Quick Read

- PWN is inferred from telemetry-backed chain progress and evidence depth.
- Use `ARCH` campaign snapshot + `PWNED` + `LOOT` together:
  - `PWNED` tells impact/risk
  - `LOOT` tells usable access artifacts
  - `ARCH` tells campaign progression

## 6) Loot-to-Action Loop (Most Important)

1. Select loot item.
2. Read parsed view (`v` toggles raw if needed).
3. Run generated follow-up.
4. Validate output in `OPS`.
5. Check new `PWNED`/`LOOT` entries.
6. Repeat.

## 7) Fast Headless Checks

```bash
h3retik doctor
h3retik coop status
h3retik pipeline --target http://127.0.0.1:3000 --profile quick
```

## 8) If Something Feels Off

- `r` to refresh telemetry
- verify scope mode (`exploit/local/osint/onchain/coop`)
- verify target in `CTRL -> TARGET`
- verify runtime/container (`H3RETIK_KALI_CONTAINER`, `H3RETIK_SKIP_UP`)
