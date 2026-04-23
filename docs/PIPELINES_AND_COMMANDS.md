# Pipelines, Commands, and Follow-ups Reference

This document explains all operator command surfaces: `h3retik` CLI, TUI `CTRL` actions, exploit/OSINT/onchain/co-op pipelines, manual command paths, and follow-up mechanics.

## 1) Global CLI Command Surface

`h3retik` supports:

- `h3retik` / `h3retik tui` — start TUI
- `h3retik up` / `h3retik down` — compose runtime control
- `h3retik build` / `h3retik build-kali` — build TUI / Kali image
- `h3retik shell` — interactive shell in Kali container
- `h3retik kali "<cmd>"` — execute one command in Kali
- `h3retik coop <check|up|status|stop|api|report>` — CALDERA helpers
- `h3retik target <args...>` — passthrough to `scripts/targetctl.py`
- `h3retik pipeline <args...>` — passthrough to `scripts/security_pipeline.py`
- `h3retik observatory <args...>` — passthrough to `scripts/observatory_runner.py`
- `python3 ./scripts/telemetryctl.py new-campaign` — archive current run then reset live telemetry/artifacts while keeping active target scope
- `h3retik reset` — reset telemetry/custom target
- `h3retik doctor` — runtime checks
- `h3retik install` — global launcher install

## 2) TUI CTRL Command Architecture

CTRL is split into sections:

- `LAUNCH`: bootstrap and stack verification
- `TARGET`: choose/set scope inputs and profiles
- `FIRE`: run mode-specific actions and pipelines
- `HISTORY`: live/replay selection

Execution runtimes:

- `local` — executed on host
- `kali` — executed in Kali container
- `internal` — UI state changes (no shell command)

## 3) Exploit Pipelines (Catalog)

Built-in exploit pipeline names and intent:

- `prelim` — quick target sanity and fingerprint
- `surface-map` — attack surface mapping
- `web-enum` — deeper web endpoint enumeration
- `vuln-sweep` — vulnerability template sweep
- `api-probe` — API behavior/auth probing
- `initial-exploit` — initial foothold attempts
- `post-enum` — post-foothold environment discovery
- `password-attacks` — credential cracking/online auth pressure
- `privesc` — privilege escalation pathing
- `lateral-pivot` — pivot/lateral movement candidates
- `full-escalation` — compact post-shell escalation chain
- `full-chain` — end-to-end operation chain

Pipeline prerequisites used by readiness tags:

- `initial-exploit` requires `recon`
- `post-enum` requires `breach`
- `password-attacks` requires `access`
- `privesc` requires `access`
- `full-escalation` requires `breach`
- `full-chain` requires `recon` and `breach`

## 4) Exploit FIRE Groups

Primary exploit FIRE groups:

- `Recon`
- `Surface`
- `Web-Adv`
- `Exploit`
- `Access`
- `AD`
- `K8S`
- `Crack`
- `Privilege`
- `Objective`
- `Utility`
- `Modules`
- `Custom`

What group selection controls:

- Which pipeline subset is shown by default.
- Which tactical commands are prioritized in FIRE.

## 5) OSINT Pipeline (TUI + Wrappers)

OSINT operator flow:

1. Seed input (`domain/url/person/email/...`)
2. Deep automation (`bbot` or `spiderfoot`)
3. Recon-ng module stage
4. reNgine runtime stage
5. Stack validation/report artifacts

Wrappers called by FIRE actions:

- `osint-seed-harvest`
- `osint-deep-bbot`
- `osint-deep-spiderfoot`
- `osint-reconng`
- `osint-rengine`
- `osint-stack-check`

## 6) Onchain Pipeline (TUI + Wrappers)

Onchain operator flow:

1. Network/RPC profile selection
2. RPC catalog + connectivity check
3. Address flow analysis
4. Contract auditing/fuzz/symbolic checks
5. Artifact collection for evidence

Wrappers called by FIRE actions:

- `onchain-rpc-catalog`
- `onchain-rpc-check`
- `onchain-address-flow`
- `onchain-slither`
- `onchain-mythril`
- `onchain-foundry-check`
- `onchain-echidna`
- `onchain-medusa`
- `onchain-halmos`
- `onchain-stack-check`

## 7) Co-op / CALDERA Command Chain

Typical co-op chain:

1. `coop-caldera-up`
2. `coop-caldera-status`
3. `coop-caldera-api /api/agents GET`
4. `coop-caldera-api /api/operations GET`
5. `coop-caldera-op-report`

Stop path:

- `coop-caldera-stop`

## 8) Manual and Modular Commands

### Custom command lane

In exploit/osint/onchain/coop FIRE you can run custom commands.

Capabilities:

- Edit command text
- Select runtime (`kali` or `local`)
- Load templates by mode
- Execute with telemetry capture

### Module lane (`modules/exploit/*.json`)

Each enabled module provides:

- metadata (`id`, `label`, `description`, `group`, `runtime`)
- `command_template` with placeholders:
  - `{{target_url}}`, `{{target_base}}`, `{{target_host}}`, `{{docker_target}}`
  - `{{osint_seed}}`, `{{onchain_target}}`, `{{chain_key}}`, `{{chain_id}}`
  - `{{input:<key>}}`
- typed inputs (`text`, `bool`, `int`, `select`) with validation
- readiness requirements and evidence hints

New lane-ready module groups:

- `Web-Adv`: crawling, historical endpoints, reflected/XSS checks, JWT analysis
- `AD`: kerberos user enum, LDAP collection, AD CS checks, WinRM validation
- `K8S`: remote cluster probe, Kubernetes posture scans
- `Crack`: offline hash cracking workflows

New dynamic requirements used by modules:

- `loot-hash`
- `loot-credential`
- `loot-token`
- `loot-endpoint`

Install optional lane tools as needed:

- `h3retik tools install web-adv-plus`
- `h3retik tools install ad-plus`
- `h3retik tools install k8s-plus`
- `h3retik tools install crack-plus`

## 9) Follow-up Mechanics (LOOT)

Follow-up actions are generated from selected loot context.

Decision inputs:

- loot type/kind metadata
- source path or endpoint
- preview parsing (JSON/entity extraction)
- DB/credential/token hints
- write privilege hints
- target URL + discovered endpoints

Follow-up command families:

- file inspection / pretty-print (`sed`, `jq`)
- sqlite inspect and achievement table discovery
- mysql/postgres pivots + schema/sample extraction
- credential fit sweeps and auth boundary checks
- endpoint probes and collection inspection
- optional write probes for mutation-capable contexts
- onchain artifact browsing
- fallback telemetry digest

## 10) Example Command Recipes

Exploit quick scan:

```bash
h3retik pipeline --target http://127.0.0.1:3000 --profile quick
```

Exploit deep chain:

```bash
h3retik pipeline --target http://127.0.0.1:3000 --pipeline full-chain
```

Run one tool directly in Kali:

```bash
h3retik kali "nuclei -u http://127.0.0.1:3000 -silent"
```

CALDERA API probe:

```bash
h3retik coop api /api/operations GET
```

## 11) Operational Notes

- Prefer pipeline/module actions to keep telemetry normalized.
- Use manual/custom commands when hypothesis-specific commands are needed.
- Treat write/tamper follow-ups as explicit operator decisions (high trace).
