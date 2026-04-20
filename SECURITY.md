# Security Policy

## Supported Versions

| Version | Support status |
|---|---|
| `v0.0.3` | Supported |
| `v0.0.2` | Not supported |
| `v0.0.1` | Not supported |

Support window: latest tagged release on `main` is supported for coordinated disclosure and fixes.

## Reporting a Vulnerability

Do not open public issues for exploitable defects that could impact users directly.

Preferred workflow:

1. Open a private GitHub Security Advisory draft in this repository, or contact maintainers privately.
2. Include reproducible steps, impact, and affected files.
3. Provide telemetry snippets if available (`commands/findings/loot`) with sensitive values redacted.
4. Include exact version/commit (`h3retik version`, git SHA, runtime image tag).

## Response Targets

- Initial triage: within `72h`
- Severity assessment + CWE/CVSS classification: within `7d`
- Mitigation plan: within `14d` for high/critical confirmed issues
- Coordinated disclosure timeline agreed with reporter before public release

## Hardening Expectations

Contributors should prioritize:

- target-agnostic controls over target-specific shortcuts
- safe defaults in command generation
- explicit OPSEC risk signaling for noisy/destructive actions
- strict telemetry integrity (no fabricated/implicit success states)
