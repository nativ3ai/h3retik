# Contributing to h3retik

Thanks for contributing.

## Scope

h3retik is an operator-grade red teaming cockpit. Contributions must preserve:

- target-agnostic behavior
- headless execution parity
- telemetry-first evidence model
- fast keyboard-first UX

## Dev Setup

```bash
go test ./...
bash -n h3retik scripts/install_h3retik.sh scripts/start_lab.sh scripts/reset_lab.sh
```

Optional runtime checks:

```bash
./h3retik doctor
```

## Pull Request Rules

1. Keep changes mode-scoped (`exploit`, `osint`, `onchain`) when possible.
2. Avoid hardcoding target-specific endpoints.
3. Ensure new actions emit telemetry (`commands/findings/loot/exploits`) where relevant.
4. Update docs if behavior or command surface changes.
5. Include test coverage for non-trivial behavior changes in `cmd/juicetui/main_test.go`.

## Code Quality

- Keep patches focused; avoid unrelated refactors.
- Prefer deterministic wrappers over shell one-offs for repeated workflows.
- Preserve backward-compatible keybindings unless explicitly changed in docs.

## Commit Convention (recommended)

Use concise prefixes:

- `feat:`
- `fix:`
- `docs:`
- `refactor:`
- `test:`
- `chore:`

## Security

Follow `SECURITY.md` for vulnerability disclosure and sensitive reporting.
Use private GitHub Security Advisories for exploitable reports; avoid public issues for live vulnerabilities.
