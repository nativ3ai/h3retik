# START HERE (Canonical Onboarding)

If you are new, read in this exact order:

1. `README.md` (install + command surface)
2. `docs/START_HERE.md` (this file)
3. `docs/OPERATOR_CHEATSHEET.md` (fast daily use)
4. `docs/TUI_OPERATOR_REFERENCE.md` (full keyboard/TUI behavior)
5. `docs/PIPELINES_AND_COMMANDS.md` (all command families)
6. `docs/CAPABILITIES.md` + `docs/TOOLS_REFERENCE.md` (tool coverage)
7. `docs/LOCAL_LANE_RUNBOOK.md` (local exploit workflows)
8. `docs/AGENT_ORCHESTRATION_COOKBOOK.md` (agent operation patterns)

## 1) Day-0 install

```bash
h3retik up
h3retik doctor
h3retik
```

## 2) First safe run (TUI)

- `CTRL -> LAUNCH` run stack checks
- `CTRL -> TARGET` set scope input
- `CTRL -> FIRE` run one low-noise action first

Fast mode keys in CTRL:

- `o` OSINT
- `y` LOCAL
- `c` ONCHAIN
- `g` CO-OP

## 3) Local exploit workflow (headless)

```bash
h3retik local stack-check
h3retik local privesc /workspace
h3retik local binary /workspace
h3retik local package /workspace
h3retik local internal
```

## 4) Modular install model

Install by bundle:

```bash
h3retik tools install recon-plus
h3retik tools install web-adv-plus
h3retik tools install ad-plus
h3retik tools install k8s-plus
h3retik tools install crack-plus
h3retik tools install coop-plus
h3retik tools install local-plus
```

Install exact tools only:

```bash
h3retik tools install semgrep,gitleaks,trivy,grype --strict
```

`--strict` exits non-zero if any requested tool is missing.

## 5) User-owned modular actions

Module load order:

- `modules/exploit/*.json`
- `modules/local/*.json`
- `~/.config/h3retik/modules/*.json`
- `$H3RETIK_MODULES_DIR/*.json`

Use `group` in module JSON to keep telemetry/category views clean.

## 6) Source-of-truth policy

- Canonical CLI syntax: `README.md`
- Canonical TUI behavior: `docs/TUI_OPERATOR_REFERENCE.md`
- Canonical command catalog: `docs/PIPELINES_AND_COMMANDS.md`
- Canonical capability map: `docs/CAPABILITIES.md`

If another doc conflicts, trust these canonical files.
