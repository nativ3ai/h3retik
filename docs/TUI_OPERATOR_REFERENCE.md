# TUI Operator Reference

This document is the complete operator guide for the `h3retik` TUI: navigation, panel behavior, mode mechanics, telemetry linkage, follow-ups, and execution flow.

## 1) Core Model

h3retik is a telemetry-driven operator cockpit.

- Every meaningful action writes telemetry (`commands`, `findings`, `loot`, `exploits`, `state`).
- Panels are read-models over telemetry, not independent state machines.
- Scope (`exploit`, `osint`, `onchain`, `coop`) changes what commands, findings, and loot are shown.

## 2) Keyboard Shortcuts (Complete)

Global navigation and execution:

- `↑` / `k` — move up
- `↓` / `j` — move down
- `←` / `h` — previous tab
- `→` / `l` / `tab` — next tab
- `[` — previous pane/section
- `]` — next pane/section
- `,` — previous option
- `.` — next option
- `enter` — select/execute selected action
- `f` — fire selected action
- `pgup` / `u` — scroll detail up
- `pgdn` / `d` — scroll detail down
- `x` — replay selected event/action
- `v` — toggle LOOT raw/analyzed view
- `o` — switch to OSINT scope
- `c` — switch to ONCHAIN scope
- `g` — switch to CO-OP scope
- `m` — ARCH map mode toggle (exploit)
- `r` — refresh telemetry state
- `q` / `ctrl+c` — quit

Context-sensitive map/editor controls:

- `1..9` — quick-select map node action
- `e` — edit endpoint buffer (map editor)
- `p` — edit payload buffer (map editor)
- `y` — cycle/edit HTTP method (map editor)
- `t` — toggle auth token use (map editor)
- `[` / `]` — cycle editable payload field (map editor context)
- `i` — edit selected payload field value

## 3) Tabs and Panel Roles

Main tabs:

- `ARCH` — operation context + campaign snapshot + map mode.
- `OPS` — command/event timeline, replay-friendly.
- `PWNED` — finding-centric exploitation state and impact.
- `LOOT` — extracted artifacts/entities and dynamic follow-ups.
- `CTRL` — execution control plane (launch/target/fire/history).

### ARCH

Normal view:

- Left side: operator profile, target state, service ledger, replay hints.
- Right side: scoped campaign metrics, mission board, workflow chain.
- Exploit scope adds: live attack graph, node details, attack degree map.
- Co-op scope adds: C2 readiness block (`state`, `score`, `steps`).

Map mode (`m`, exploit scope):

- Left: tree attack map (hierarchical nodes).
- Right: selected node detail + node action panel + interactive tamper editor.
- Node action roles:
  - `EXP` = inspect/read actions
  - `TMP` = tamper/probe actions
  - `MOD` = modifying/write actions

Map interaction details:

- Tree navigation uses arrows; hierarchy traversal is left/right.
- Collapse/expand behavior uses map controls (`h/l` where available in map context).
- Action quick-select supports numeric selection (`1..9`) for node actions.
- Editor controls shown inline in map detail panel.

### OPS

- Displays scoped command timeline with phase/tool/state/duration/command.
- Supports selecting historical entries and replaying from timeline (`x`).
- Used for operational auditing and deterministic reruns.

### PWNED

- Displays scoped finding set and severity/impact distribution.
- Used as exploit state/impact board rather than raw loot browser.
- Designed to identify what is compromised and where deeper actions are justified.

### LOOT

- Displays extracted entities/artifacts (credentials, paths, tokens, files, DB hints, onchain artifacts, etc.).
- Supports raw/analyzed toggle (`v`) for operator-friendly parsing.
- Selecting a loot item builds dynamic follow-up action list from item metadata/content.

### CTRL

The execution cockpit.

Sections (navigated with `[`/`]`):

- `LAUNCH` — runtime bootstrap and stack readiness actions.
- `TARGET` — target/scope input + profile setup.
- `FIRE` — mode-specific tactical actions/pipelines.
- `HISTORY` — replay/live telemetry source switching.

Navigation model:

- `↑/↓` selects category/action row in current section.
- `,/.` cycles options inside current section/context.
- `enter` or `f` executes selected action.

Status/tags in options:

- `[DONE]` action already succeeded previously in telemetry.
- `[READY]` action can run now.
- `[LOCKED]` prerequisites are unmet.
- `[KALI]`, `[LOCAL]`, `[MENU]` runtime/type hints.

### CTRL Usable Option Families (Fully Covered)

- `LAUNCH`
  - runtime startup
  - stack checks
  - quickstart cards
  - readiness/artifact checks
- `TARGET`
  - manual input entry
  - scope-specific profile fields
  - target derivation from active URL/context
  - exploit inner-target mapping controls
- `FIRE`
  - grouped tactical actions
  - pipelines
  - module actions
  - custom command lane
  - scope-specific wrappers (`osint-*`, `onchain-*`, `coop-*`)
- `HISTORY`
  - switch live telemetry/replay runs
  - load latest replay

## 4) Scope / Mode Mechanics

Scopes are operator lanes:

- `exploit` (default): offensive recon-to-impact workflows.
- `osint`: investigation pipeline workflows (seed -> enrichment -> analysis).
- `onchain`: chain/RPC/flow/audit workflows.
- `coop`: CALDERA C2 collaboration workflows.

Scope affects:

- Which commands/findings/loot are displayed.
- Which `CTRL` target/fire actions are available.
- Which workflow board and next-actions are rendered in ARCH/CTRL.

### Exploit Scope: All Usable Option Families

- `TARGET`
  - custom URL set
  - CVE task set/start/info
  - inner endpoint next/prev/manual/apply/clear
- `FIRE`
  - grouped lanes (`Recon`, `Surface`, `Exploit`, `Access`, `Privilege`, `Objective`, `Utility`, `Modules`, `Custom`)
  - brute/auth settings and adaptive brute execution
  - pipeline execution and group-based pipeline selection
  - module configure/execute
  - custom runtime/template/run
  - replay selected OPS command

### OSINT Scope: All Usable Option Families

- `TARGET`
  - seed input edit
  - seed type cycle
  - derive seed from active target URL
- `FIRE`
  - seed harvest
  - deep engine stage (bbot/spiderfoot)
  - recon-ng stage
  - reNgine stage
  - stack check / artifact listing
  - custom command lane

### Onchain Scope: All Usable Option Families

- `TARGET`
  - onchain input edit
  - input type cycle
  - network/chain profile cycle
- `FIRE`
  - RPC catalog/check
  - address flow analysis
  - static analyzers
  - dynamic/fuzz/symbolic analyzers
  - stack check
  - custom command lane

### Co-op Scope: All Usable Option Families

- `TARGET`
  - CALDERA URL/API key/operation/group
- `FIRE`
  - guided quickstart
  - C2 up/status
  - list agents/list operations
  - operation snapshot report
  - C2 stop
  - custom command lane

## 5) Follow-ups (What They Are)

Follow-ups are auto-generated actions derived from selected loot/finding context.

They are not hardcoded to a single target; they are synthesized from:

- loot kind/name/source/preview metadata
- parsed JSON/entity hints
- discovered endpoints
- extracted credentials/tokens
- DB connection hints
- available local artifacts

Common follow-up families:

- Artifact inspection (`sed`, `jq`, sqlite table listing).
- Credential-fit sweeps against discovered auth/API endpoints.
- Auth boundary probes.
- Endpoint probes from path/URL loot.
- Collection/record inspect + optional write probe when write hints exist.
- DB pivots (mysql/postgres), schema/sample reads, optional write probes.
- Onchain artifact inspection.

If no specific follow-up is derivable, fallback action is telemetry digest.

## 6) Telemetry: What It Is and How Panels Use It

Telemetry files:

- `telemetry/state.json` — active target/runtime context.
- `telemetry/commands.jsonl` — command execution events.
- `telemetry/findings.jsonl` — normalized vulnerabilities/impact conditions.
- `telemetry/loot.jsonl` — extracted entities/artifacts.
- `telemetry/exploits.jsonl` — exploit classification/escalation records.

Panel usage:

- `OPS` reads `commands.jsonl`.
- `PWNED` reads `findings.jsonl` + `exploits.jsonl`.
- `LOOT` reads `loot.jsonl`.
- `ARCH` combines state + scoped command/finding/loot correlations.
- `CTRL` uses telemetry to compute readiness/done/lock and suggestions.

Operational implications:

- Actions are replayable.
- Evidence trails are auditable.
- UI remains deterministic across TUI and headless command usage.

## 7) Target and Runtime Resolution

Target can be configured in CTRL/TARGET or via CLI (`h3retik target ...`).

Runtime resolution:

- Default execution path uses compose service `kali` container.
- Override container name with `H3RETIK_KALI_CONTAINER`.
- Override compose image with `H3RETIK_KALI_IMAGE`.
- If `jsbb-kali` already exists and is running, `h3retik` reuses it automatically.
- Use `H3RETIK_SKIP_UP=1` to attach to an existing running container and skip compose startup.
- Use `h3retik attach` to launch TUI against an existing running container only.
- In TUI, runtime can be changed live in `CTRL -> TARGET`:
  - `KALI Runtime Container (Type)`
  - `KALI Runtime Image (Type)`
- FIRE actions are capability-aware: when Kali is running, commands requiring missing tools are filtered from action menus.

## 8) End-to-End Operator Flow (Recommended)

1. `LAUNCH`: bring runtime up + run stack checks.
2. `TARGET`: set target/scope input accurately.
3. `FIRE`: execute smallest meaningful action first.
4. Observe `OPS` + `PWNED` + `LOOT` deltas.
5. Trigger derived follow-ups from LOOT where justified.
6. Use `ARCH` to monitor state progression/readiness.
7. Use `HISTORY` / replay to verify reproducibility.

## 8.1) LOOT Follow-up Execution Flow

1. Select loot entry in `LOOT`.
2. Inspect parsed or raw (`v`) data.
3. Choose generated follow-up in detail pane.
4. Execute (`enter` or `f`).
5. Validate outcomes in `OPS` and updated `PWNED`/`LOOT`.
6. Repeat until objective path is complete.

## 9) Co-op (CALDERA) in TUI

Quick sequence:

1. `CTRL` -> press `g`.
2. `TARGET`: set CALDERA URL/key/op/group.
3. `FIRE`: start -> status -> agents -> operations -> report.

Non-invasive guidance:

- Inline `hint :: ...` appears in CTRL co-op context.
- Hint updates based on completed co-op steps in telemetry.

## 10) Examples (TUI + CLI)

Start and enter cockpit:

```bash
h3retik up
h3retik
```

Attach to existing Kali container:

```bash
export H3RETIK_KALI_CONTAINER=my-kali
export H3RETIK_SKIP_UP=1
h3retik tui
```

Single-command attach:

```bash
h3retik --kali-container my-kali attach
```

If the default `jsbb-kali` container is already running, plain `h3retik` is enough.

Headless co-op quick checks:

```bash
h3retik coop up
h3retik coop status
h3retik coop report
```

Replay usage:

```bash
h3retik
# CTRL -> HISTORY -> load latest replay
```

## 11) Notes on Modularity

- Attack modules are loaded from `modules/exploit/*.json`.
- Mode-specific command templates are parameterized from target/scope context.
- Follow-ups are data-derived and can operate across arbitrary targets where data supports the action.
