# Security Policy

## Supported Version

- `v0.0.1` (current)

## Reporting a Vulnerability

Do not open public issues for exploitable defects that could impact users directly.

Preferred workflow:

1. Send a private report to project maintainers.
2. Include reproducible steps, impact, and affected files.
3. Provide telemetry snippets if available (`commands/findings/loot`) with sensitive values redacted.

## Response Targets

- Initial triage: within 72 hours
- Severity assessment: within 7 days
- Fix/mitigation target: depends on severity and exploitability

## Hardening Expectations

Contributors should prioritize:

- target-agnostic controls over target-specific shortcuts
- safe defaults in command generation
- explicit OPSEC risk signaling for noisy/destructive actions
