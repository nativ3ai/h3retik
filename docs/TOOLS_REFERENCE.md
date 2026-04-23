# Preinstalled Tools Reference

This document lists the preinstalled h3retik Kali toolset and what each tool is used for.

## Runtime Requirements (Must-Have For Full TUI)

If you attach h3retik to your own Kali container/image, these are the minimum requirements for full feature parity:

- Base: `bash`, `python3`, `curl`, `jq`, `git`.
- Exploit core: `nmap`, `ffuf`, `nikto`, `sqlmap`, `hydra`, `medusa`, `nuclei`, `msfconsole`.
- OSINT wrappers: `osint-seed-harvest`, `osint-deep-bbot` or `osint-deep-spiderfoot`, `osint-reconng`, `osint-rengine`, `osint-stack-check`.
- Onchain wrappers: `onchain-rpc-catalog`, `onchain-rpc-check`, `onchain-address-flow`, `onchain-slither`, `onchain-mythril`, `onchain-foundry-check`, `onchain-echidna`, `onchain-medusa`, `onchain-halmos`, `onchain-stack-check`.
- Co-op wrappers: `coop-caldera-check`, `coop-caldera-up`, `coop-caldera-status`, `coop-caldera-api`, `coop-caldera-op-report`, `coop-caldera-stop`.

Behavior in TUI:

- FIRE menus are capability-aware when Kali runtime is online.
- Actions requiring missing Kali tools are filtered/locked and not shown as runnable.
- Runtime container/image can be switched in `CTRL -> TARGET` without restarting the TUI process.

Optional lane bundles (install on demand):

- `h3retik tools install web-adv-plus` -> `katana,gau,waybackurls,dalfox,kxss,jwt-tool`
- `h3retik tools install ad-plus` -> `kerbrute,ldapdomaindump,certipy,evil-winrm`
- `h3retik tools install k8s-plus` -> `trivy,kubescape,kube-hunter`
- `h3retik tools install crack-plus` -> `hashcat,john`

## 1) Runtime and Build Tooling

| Tool | Purpose |
|---|---|
| `python3-full`, `python3-dev`, `python3-pip` | Python runtime for orchestrators/wrappers and scripts. |
| `pipx` | Isolated Python CLI installs (e.g., slither, mythril, bbot). |
| `build-essential`, `cmake`, `pkg-config` | Native build chain for dependencies/extensions. |
| `rustc`, `cargo` | Rust toolchain for tools requiring Rust builds. |
| `golang-go` | Go toolchain for Go-based utilities (e.g., medusa go tool). |
| `libssl-dev`, `libffi-dev`, `libxml2-dev`, `libxslt1-dev`, `zlib1g-dev` | Common native crypto/parsing/compression libraries. |
| `curl`, `wget`, `jq` | HTTP fetch/probe and JSON processing. |
| `git` | Source checkout/update for installed repositories. |
| `vim`, `tmux` | Interactive shell editing/session multiplexing. |
| `ca-certificates` | TLS trust store. |

## 2) Recon and Surface Discovery

| Tool | Purpose |
|---|---|
| `nmap` | Host/service and version discovery. |
| `dnsrecon` | DNS recon and enumeration. |
| `fierce` | DNS and subdomain reconnaissance. |
| `amass` | Asset/subdomain mapping. |
| `theharvester` | Seed collection from public sources. |
| `recon-ng` | Modular recon framework. |
| `whatweb` | Web stack fingerprinting. |
| `nikto` | Web server misconfiguration/vuln checks. |
| `wpscan` | WordPress-oriented scanning. |
| `feroxbuster` | Recursive content discovery fuzzing. |
| `wfuzz` | Web parameter/path fuzzing. |
| `arjun` | Hidden parameter discovery. |
| `dirb` | Directory brute-force enumeration. |
| `gobuster` | Directory/DNS/vhost brute-force enumeration. |
| `ffuf` | Fast web fuzzing/enumeration. |
| `arp-scan` | Local network ARP discovery. |

## 3) Enumeration, Lateral, and Infra Access

| Tool | Purpose |
|---|---|
| `enum4linux`, `enum4linux-ng` | SMB/Windows domain enumeration. |
| `smbclient` | SMB share interaction. |
| `smbmap` | SMB permissions/share mapping. |
| `samba-common-bin` | SMB support utilities. |
| `ldap-utils` | LDAP query and directory interaction. |
| `snmp` | SNMP query tooling. |
| `crackmapexec`, `netexec` | Credentialed network/AD operations. |
| `python3-impacket`, `impacket-scripts` | AD/network protocol offensive utilities. |
| `bloodhound`, `bloodhound.py`, `bloodhound-ce-python`, `sharphound` | AD graph collection and attack-path analysis. |
| `responder` | LLMNR/NBT-NS poisoning and credential capture scenarios. |

## 4) Exploitation and Vuln Frameworks

| Tool | Purpose |
|---|---|
| `sqlmap` | SQL injection testing/exploitation. |
| `commix` | Command injection testing. |
| `xsser` | XSS testing/exploitation support. |
| `exploitdb` (`searchsploit`) | Public exploit lookup/metadata. |
| `metasploit-framework` | Exploit, payload, and post-exploitation framework. |
| `set` | Social Engineering Toolkit workflows. |
| `nuclei` | Template-based vuln scanning. |

## 5) Credential and Password Attack Tooling

| Tool | Purpose |
|---|---|
| `hydra` | Online authentication brute-force. |
| `medusa` | Parallelized online auth brute-force. |
| `john` | Offline password/hash cracking. |
| `hashcat` | GPU/CPU accelerated hash cracking. |
| `mimikatz` | Windows credential extraction utility (lab/legal use only). |
| `python3-pypykatz` | Python parsing/extraction for LSASS artifacts and creds. |

## 6) Web App Security Suites

| Tool | Purpose |
|---|---|
| `burpsuite` | Intercept/proxy/repeater web testing suite. |
| `zaproxy` | OWASP ZAP web app assessment suite. |

## 7) OSINT and Intelligence Tooling

| Tool | Purpose |
|---|---|
| `maltego` | Link analysis and entity relationship mapping. |
| `bbot` | Automated recon/OSINT expansion. |
| `spiderfoot` | Automated OSINT collection/correlation. |
| `reNgine` | Recon/web intelligence orchestration framework. |
| `python3-shodan`, `python3-pyshodan` | Shodan API integration and scripting. |
| `python3-censys` | Censys API integration and scripting. |

## 8) Onchain / Smart Contract Tooling

| Tool | Purpose |
|---|---|
| `slither` | Static smart contract analysis. |
| `mythril` (`myth`) | Symbolic analysis for EVM contracts. |
| `forge`, `cast`, `anvil` (Foundry) | Solidity testing/building/RPC interaction/local chain simulation. |
| `echidna` | Property-based fuzzing for contracts. |
| `medusa` (Go) | Contract fuzzing workflow utility. |
| `halmos` | Symbolic execution/checking for Solidity workflows. |

## 9) Co-op / C2 Tooling

| Tool | Purpose |
|---|---|
| `caldera` | MITRE CALDERA C2/adversary emulation server. |
| `sliver` | C2 framework tooling (operator-managed usage). |

## 10) Network, VPN, and Traffic Routing

| Tool | Purpose |
|---|---|
| `openvpn` | VPN connectivity. |
| `wireguard` | VPN connectivity (WireGuard). |
| `proxychains4` | Route tools through SOCKS proxies. |
| `tor` | Onion routing/network egress option. |

## 11) h3retik Wrapper Layer (Headless Entry Points)

These wrappers are the preferred, stable entry points for TUI/CLI pipelines.

### OSINT wrappers

- `osint-seed-harvest`
- `osint-deep-bbot`
- `osint-deep-spiderfoot`
- `osint-reconng`
- `osint-rengine`
- `osint-stack-check`

### Onchain wrappers

- `onchain-rpc-catalog`
- `onchain-rpc-check`
- `onchain-address-flow`
- `onchain-slither`
- `onchain-mythril`
- `onchain-foundry-check`
- `onchain-echidna`
- `onchain-medusa`
- `onchain-halmos`
- `onchain-stack-check`

### Co-op wrappers

- `coop-caldera-check`
- `coop-caldera-up`
- `coop-caldera-status`
- `coop-caldera-api`
- `coop-caldera-op-report`
- `coop-caldera-stop`

## 12) Safety and Usage Notes

- Tool presence does not imply automatic execution; actions run only when operator fires commands.
- Scope and authorization remain operator responsibility.
- For repeatable operations, prefer wrappers/pipelines over ad hoc shell commands.
