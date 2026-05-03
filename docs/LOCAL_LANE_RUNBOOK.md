# Local Lane Runbook

Purpose: run red-team operations against local files, packages, binaries, and internal host surface.

Scope: authorized local targets only.

## Quickstart

```bash
h3retik local stack-check
h3retik local privesc /workspace
h3retik local binary /workspace
h3retik local package /workspace
h3retik local internal
```

## Pipeline (recommended order)

1. `local-stack-check`
2. `local-privesc <target_path>`
3. `local-binary-triage <target_path>`
4. `local-package-audit <target_path>`
5. `local-internal-recon`

## What each stage covers

- `local-stack-check`
- verifies wrappers + local lane tools are callable

- `local-privesc`
- host priv-esc indicators (`linpeas`, `lse`, `pspy64`, `linux-exploit-suggester`)

- `local-binary-triage`
- executable triage (`file`, `checksec`, `rabin2`, `strings`)

- `local-package-audit`
- code/package audit (`semgrep`, `gitleaks`, `trivy fs`, `grype`)

- `local-internal-recon`
- local/internal service recon (`smbclient`, `ldapsearch`, `rpcclient`, `netexec`)

## TUI usage

- Go to `CTRL`
- Press `y` to enter `LOCAL` mode
- Run lane actions from `FIRE`
- Review artifacts in `LOOT` and command status in `OPS`

## Artifacts and telemetry

Local lane writes:

- artifacts: `artifacts/local/*`
- telemetry: `commands.jsonl` + local loot entries in `loot.jsonl`

## Troubleshooting

Missing tools:

```bash
h3retik tools install local-plus --strict
```

Custom minimal toolset:

```bash
h3retik tools install linpeas,lse,checksec,semgrep,gitleaks --strict
```

If wrappers are missing in a custom image/container, ensure `/usr/local/bin/local-*` exists and is executable.
