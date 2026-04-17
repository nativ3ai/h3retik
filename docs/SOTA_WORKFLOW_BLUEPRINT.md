# SOTA Workflow Blueprint

This control room serves three operator profiles and keeps each mode isolated:

- `EXPLOIT` → red team operations
- `OSINT` → investigative journalism workflows
- `ONCHAIN` → smart-contract / flow auditing

## Design Rules

1. One mode owns one workflow lane (commands, findings, loot, graph, chain state).
2. `CTRL` is execution-only; taxonomy/arch views are analysis-only.
3. Every action is stage-mapped so operators know what is done vs missing.
4. UI only shows controls relevant to the current mode.
5. Loot is partitioned by mode and never mixed.

## Canonical Stage Model

### EXPLOIT (Red Team)
1. Recon
2. Access
3. Privilege
4. Objective
5. Evidence

### OSINT (Investigative Journalism)
1. Input / Seeding
2. Discovery / Enrichment
3. Collection
4. Processing / Normalization
5. Analysis / Correlation
6. Validation / Verification
7. Reporting / Action

### ONCHAIN (Audit + Flow Investigation)
1. Scope / Chain Select
2. RPC Validation
3. Flow Mapping
4. Static Analysis
5. Dynamic/Fuzz Analysis
6. Correlation / Attribution
7. Evidence Export

## Execution Surface

- `CTRL -> launch`: readiness and stack checks only.
- `CTRL -> target`: seed/address/profile definition only.
- `CTRL -> fire`: pipeline actions only, strictly mode-scoped.
- `CTRL -> history`: replay/snapshot only.

## Navigation Contract

- `o` sets OSINT workflow context.
- `c` sets ONCHAIN workflow context.
- default remains `EXPLOIT`.
- Up/Down drives selection; Enter executes in CTRL and never inside taxonomy-only panels.
