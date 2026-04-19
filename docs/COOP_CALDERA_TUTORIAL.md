# Co-op CALDERA Tutorial (Guided)

This tutorial is the fast path for using h3retik co-op mode with CALDERA C2.

## 0) Preconditions

- Authorized environment only.
- Docker engine running.
- `jsbb-kali` container available, or set `H3RETIK_KALI_CONTAINER` to your container name.
- If you use a non-default CALDERA endpoint/key, export:
  - `COOP_CALDERA_URL`
  - `COOP_CALDERA_API_KEY`

## 1) Start Runtime

```bash
h3retik up
h3retik
```

Inside TUI:
- go to `CTRL`
- press `g` to switch `FIRE` mode to `CO-OP`
- follow the inline `hint :: ...` line in `CTRL` for the recommended next co-op action

Attach mode:

- if `jsbb-kali` is already running, `h3retik` will reuse it automatically
- to attach to a different Kali container, export `H3RETIK_KALI_CONTAINER=<name>` and `H3RETIK_SKIP_UP=1`

## 2) Guided Setup (CTRL -> TARGET)

Set:
- `CO-OP Caldera URL (Type)` (default: `http://127.0.0.1:8888`)
- `CO-OP Caldera API Key (Type)` (default insecure profile: `ADMIN123`)
- `CO-OP Operation Name (Type)`
- `CO-OP Agent Group (Type)`

## 3) Guided Run (CTRL -> FIRE)

Run in order:
1. `[COOP] Start CALDERA C2`
2. `[COOP] CALDERA Status`
3. `[COOP] List Agents`
4. `[COOP] List Operations`
5. `[COOP] Pull Operation Snapshot`

The TUI keeps command results and status in the same panes used by exploit/osint/onchain.

## 4) Evidence and Telemetry

- Raw co-op artifacts:
  - `artifacts/coop/`
- Structured telemetry:
  - `telemetry/commands.jsonl`
  - `telemetry/loot.jsonl`
  - `telemetry/findings.jsonl`

Use:
- `h3retik coop status`
- `h3retik coop report`

for headless verification from terminal.

## 5) Existing Kali / External Container

If you already run a Kali container and only want the TUI:

```bash
export H3RETIK_KALI_CONTAINER=<your-container-name>
export H3RETIK_SKIP_UP=1
h3retik tui
```

Notes:
- h3retik executes wrappers with `docker exec $H3RETIK_KALI_CONTAINER`.
- Missing wrappers/packages in that container will cause action failures.
- For full feature parity, your container should include `kali-headless/*` wrappers plus required tools listed in `docs/CAPABILITIES.md`.
