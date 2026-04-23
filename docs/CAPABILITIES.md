# h3retik Capability Matrix (v0.0.3)

This matrix documents the mounted suite and how each class is exposed in h3retik.

## Runtime Topology

- Kali container: `${H3RETIK_KALI_CONTAINER:-h3retik-kali}`
- Compose service: `kali`
- Image tag: `${H3RETIK_KALI_IMAGE:-h3retik/kali:v0.0.3}`
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
| `onchain-slither` | static smart-contract analysis |
| `onchain-mythril` | symbolic/security checks for contracts |
| `onchain-foundry-check` | Foundry-driven validation flow |
| `onchain-echidna` | property/fuzz testing |
| `onchain-medusa` | fuzzing workflow checks |
| `onchain-halmos` | symbolic pipeline execution |
| `onchain-stack-check` | runtime verification for onchain suite |

## Co-op / C2 Suite (CALDERA)

| Wrapper | Purpose |
|---|---|
| `coop-caldera-check` | validate CALDERA binaries/config/runtime wiring |
| `coop-caldera-up` | launch CALDERA headlessly in Kali |
| `coop-caldera-status` | summarize process/API status + quick health telemetry |
| `coop-caldera-api` | generic authenticated API call helper (`KEY` header) |
| `coop-caldera-op-report` | build operation+agent snapshot artifact |
| `coop-caldera-stop` | stop CALDERA process cleanly |

## Control and Telemetry Contract

All operator actions should emit to:

- `telemetry/commands.jsonl`
- `telemetry/findings.jsonl`
- `telemetry/loot.jsonl`
- `telemetry/exploits.jsonl`

This keeps `OPS`, `PWNED`, `LOOT`, and `MAP` synchronized and replayable.
