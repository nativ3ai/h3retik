# Agent Orchestration Cookbook

This is the practical guide for running `h3retik` through autonomous/assistant agents.

## Core protocol (always)

1. Preflight: `h3retik doctor`
2. Set scope/target
3. Run one action at a time
4. Read telemetry before claims
5. Pick next action from evidence

## Minimal reporting format

Every agent update should include:

- target scope
- action executed
- telemetry evidence (`commands/findings/loot`)
- opsec implication
- next command

## Headless patterns

Exploit lane:

```bash
h3retik pipeline --target http://127.0.0.1:3000 --profile quick
```

Local lane:

```bash
h3retik local stack-check
h3retik local package /workspace
```

Onchain lane:

```bash
h3retik kali "onchain-rpc-check eth-mainnet"
```

Co-op lane:

```bash
h3retik coop caldera status
h3retik coop wildmesh status
```

## Safe escalation policy

- Start read-only.
- Escalate only when evidence justifies it.
- Any write/tamper/destructive action must be explicit and logged.

## Module authoring for agents

Preferred module locations:

- `modules/exploit/*.json`
- `modules/local/*.json`
- `~/.config/h3retik/modules/*.json`
- `$H3RETIK_MODULES_DIR/*.json`

Rules:

- Keep `command_template` target-agnostic.
- Use typed `inputs` and defaults.
- Set `group` clearly for telemetry categories.
- Define `evidence` fields to normalize findings/loot.

## Deterministic installs in automation

Use strict mode in CI/agents:

```bash
h3retik tools install local-plus --strict
```

If this exits non-zero, fail fast and report missing tools.
