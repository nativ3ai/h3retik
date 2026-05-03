# h3retik Capability Matrix (v0.0.4)

This matrix documents the mounted suite and how each class is exposed in h3retik.

## Runtime Topology

- Kali container: `${H3RETIK_KALI_CONTAINER:-h3retik-kali}`
- Compose service: `kali`
- Image tag: `${H3RETIK_KALI_IMAGE:-h3retik/kali:v0.0.4}`
- Persistent mounts:
  - `/telemetry` (host `telemetry/`)
  - `/artifacts` (host `artifacts/`)

## Exploit Suite

| Category | Representative tools |
|---|---|
| Recon / surface | `nmap`, `httpx`, `ffuf`, `gobuster`, `nikto`, `whatweb` |
| Web advanced | `katana`, `gau`, `waybackurls`, `dalfox`, `kxss`, `jwt-tool` |
| Vulnerability sweep | `nuclei`, `sqlmap`, `commix`, `xsser` |
| Access / auth pressure | `hydra`, `medusa`, `john`, `hashcat` |
| AD operations | `kerbrute`, `ldapdomaindump`, `certipy`, `evil-winrm` |
| Kubernetes surface | `kube-hunter`, `trivy`, `kubescape` |
| Frameworks | `metasploit-framework`, `searchsploit` |
| Post-enum / pivot | `enum4linux-ng`, `smbclient`, `smbmap`, `ldapsearch`, `snmpwalk`, `netexec` |

Optional tool bundles installable from CLI:

- `h3retik tools install web-adv-plus`
- `h3retik tools install ad-plus`
- `h3retik tools install k8s-plus`
- `h3retik tools install crack-plus`

## OSINT Suite

| Wrapper | Purpose |
|---|---|
| `osint-seed-harvest` | seed acquisition and baseline metadata extraction |
| `osint-deep-bbot` | automated enrichment + discovery expansion |
| `osint-deep-spiderfoot` | broader automated intelligence sweep |
| `osint-reconng` | module-driven custom recon-ng workflows |
| `osint-rengine` | deep web application OSINT profiling |
| `osint-stack-check` | runtime verification for OSINT toolchain |

## Onchain Suite

| Wrapper | Purpose |
|---|---|
| `onchain-rpc-catalog` | curated RPC endpoint visibility |
| `onchain-rpc-check` | chain/RPC reachability validation |
| `onchain-address-flow` | inflow/outflow tracing for target addresses |
| `onchain-dossier` | investigator dossier pack (flags + chain-of-custody + report artifacts) |
| `onchain-slither` | static smart-contract analysis |
| `onchain-mythril` | symbolic/security checks for contracts |
| `onchain-foundry-check` | Foundry-driven validation flow |
| `onchain-echidna` | property/fuzz testing |
| `onchain-medusa` | fuzzing workflow checks |
| `onchain-halmos` | symbolic pipeline execution |
| `onchain-stack-check` | runtime verification for onchain suite |

Map/telemetry behavior:

- `ARCH` map in `onchain` scope builds a live entity tree from `onchain-address-flow` artifacts.
- Actor/token pivots are generated from flow telemetry (`top_in_counterparties`, `top_out_counterparties`, `top_tokens`).
- Running flow actions appends normalized onchain loot entries (`onchain-flow`, `onchain-actor`, `onchain-token`) for LOOT + MAP sync.
- Flow snapshots include per-token/per-actor amount summaries (`in/out/net`) and feed directly into map node details.
- `onchain-dossier` emits investigator artifacts (`dossier_json`, `dossier_md`) with triage flags + chain-of-custody hashes.

## Local Redteam Suite

| Wrapper | Purpose |
|---|---|
| `local-stack-check` | verify local-lane tooling coverage and runtime availability |
| `local-privesc` | run local privilege-escalation recon (`linpeas`,`lse`,`pspy`,`linux-exploit-suggester`) |
| `local-binary-triage` | executable triage and hardening metadata (`checksec`,`rabin2`,`strings`) |
| `local-package-audit` | local repo/package audit (`semgrep`,`gitleaks`,`trivy fs`,`grype`) |
| `local-internal-recon` | local/internal network baseline recon (`smb`,`ldap`,`rpc`,`netexec`) |

User-owned modular actions:

- Repo modules: `modules/local/*.json`
- User modules: `~/.config/h3retik/modules/*.json`
- Optional override dir: `$H3RETIK_MODULES_DIR`
- Each module keeps a `group` category label for telemetry tracking and FIRE lane categorization.

## Co-op / Collaboration Suite

| Wrapper | Purpose |
|---|---|
| `coop-caldera-check` | validate CALDERA binaries/config/runtime wiring |
| `coop-caldera-up` | launch CALDERA headlessly in Kali |
| `coop-caldera-status` | summarize process/API status + quick health telemetry |
| `coop-caldera-api` | generic authenticated API call helper (`KEY` header) |
| `coop-caldera-op-report` | build operation+agent snapshot artifact |
| `coop-caldera-stop` | stop CALDERA process cleanly |
| `coop-wildmesh-check` | validate WildMesh binary/config/runtime wiring |
| `coop-wildmesh-setup` | bootstrap WildMesh node + default channel |
| `coop-wildmesh-up` | start detached WildMesh daemon |
| `coop-wildmesh-status` | summarize daemon/profile/peer/channel state |
| `coop-wildmesh-discover` | force discovery pulse + peer browse |
| `coop-wildmesh-policy-check` | enforce collaboration policy + opsec guardrail |
| `coop-wildmesh-sync-report` | publish telemetry summary + save coop artifact |
| `coop-wildmesh-automation` | repeatable automation tick/loop (policy + sync) |
| `coop-wildmesh-stop` | stop detached WildMesh daemon |

## Control and Telemetry Contract

All operator actions should emit to:

- `telemetry/commands.jsonl`
- `telemetry/findings.jsonl`
- `telemetry/loot.jsonl`
- `telemetry/exploits.jsonl`

This keeps `OPS`, `PWNED`, `LOOT`, and `MAP` synchronized and replayable.
