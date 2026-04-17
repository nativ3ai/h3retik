# h3retik Operator Skill

Use this skill when operating the `h3retik` black-box TUI + headless Kali runtime.

## Mission

Run exploit, OSINT, and onchain workflows from one control plane:

- `h3retik` for interactive TUI operations.
- `h3retik pipeline ...` and wrapper scripts for headless automation.
- `h3retik kali "<cmd>"` for direct Kali execution.

## Runtime Topology

- Root launcher: `h3retik`
- Kali image: `h3retik/kali:v0.0.1` (compose service: `kali`)
- Kali container (default): `jsbb-kali`
- Telemetry: `telemetry/`
- Artifacts: `artifacts/`

## Fast Path

1. Start runtime: `h3retik up`
2. Set target: `h3retik target set --kind custom --url http://127.0.0.1:8080`
3. Launch TUI: `h3retik`
4. Headless pipeline (optional): `h3retik pipeline --target http://127.0.0.1 --profile standard`

## Where Pipelines Live

- Dynamic module manifests: `modules/exploit/*.json`
- Headless wrappers (Kali): `kali-headless/`
- Orchestrators:
  - `scripts/security_pipeline.py`
  - `scripts/observatory_runner.py`
  - `scripts/targetctl.py`

## Operating Model

- Keep target selection in `targetctl` / CTRL panel.
- Fire mode-specific actions from CTRL.
- Validate output via telemetry streams (`commands`, `findings`, `loot`).
- Treat `loot` as extracted evidence, `pwned` as compromise/vulnerability evidence.

## Notes

- Pipelines are target-agnostic; avoid target-specific assumptions.
- Prefer module/pipeline execution before ad-hoc one-off commands.
- Use OPSEC cues in TUI before noisy actions (bruteforce/tamper/write operations).
