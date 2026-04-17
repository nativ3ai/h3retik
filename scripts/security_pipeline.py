#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
TELEMETRY = ROOT / "telemetry"
ARTIFACTS = ROOT / "artifacts"
RUNS_DIR = TELEMETRY / "runs"
STATE_PATH = TELEMETRY / "state.json"
COMMANDS_PATH = TELEMETRY / "commands.jsonl"
FINDINGS_PATH = TELEMETRY / "findings.jsonl"
LOOT_PATH = TELEMETRY / "loot.jsonl"
EXPLOITS_PATH = TELEMETRY / "exploits.jsonl"
KALI_CONTAINER = "jsbb-kali"


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_dirs() -> None:
    TELEMETRY.mkdir(parents=True, exist_ok=True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)


def append_jsonl(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(data, ensure_ascii=True) + "\n")


def read_state() -> dict[str, Any]:
    if not STATE_PATH.exists():
        return {
            "lab_name": "Black Box Observatory Lab",
            "target_name": "Custom Target",
            "target_url": "http://127.0.0.1",
            "docker_target": "",
            "network": "unknown",
            "target_kind": "custom",
            "target_id": "custom",
            "status": "idle",
            "phase": "waiting",
            "last_updated": "",
            "services": [],
        }
    return json.loads(STATE_PATH.read_text(encoding="utf-8"))


def write_state(state: dict[str, Any]) -> None:
    state["last_updated"] = now()
    STATE_PATH.write_text(json.dumps(state, indent=2), encoding="utf-8")


def command_id() -> str:
    return f"cmd-{time.time_ns()}"


def run_logged(phase: str, tool: str, command: list[str], timeout: int) -> subprocess.CompletedProcess[str] | None:
    cmd_id = command_id()
    display = subprocess.list2cmdline(command)
    append_jsonl(
        COMMANDS_PATH,
        {
            "command_id": cmd_id,
            "timestamp": now(),
            "phase": phase,
            "tool": tool,
            "command": display,
            "status": "started",
            "exit_code": 0,
            "duration_ms": 0,
            "output_preview": "",
        },
    )
    started = time.time()
    try:
        proc = subprocess.run(command, capture_output=True, text=True, check=False, timeout=timeout)
    except subprocess.TimeoutExpired:
        duration_ms = int((time.time() - started) * 1000)
        append_jsonl(
            COMMANDS_PATH,
            {
                "command_id": cmd_id,
                "timestamp": now(),
                "phase": phase,
                "tool": tool,
                "command": display,
                "status": "error",
                "exit_code": 124,
                "duration_ms": duration_ms,
                "output_preview": "command timeout",
            },
        )
        return None

    duration_ms = int((time.time() - started) * 1000)
    combined = (proc.stdout + ("\n" + proc.stderr if proc.stderr else "")).strip()
    append_jsonl(
        COMMANDS_PATH,
        {
            "command_id": cmd_id,
            "timestamp": now(),
            "phase": phase,
            "tool": tool,
            "command": display,
            "status": "ok" if proc.returncode == 0 else "error",
            "exit_code": proc.returncode,
            "duration_ms": duration_ms,
            "output_preview": combined[:4000],
        },
    )
    return proc


def run_logged_kali(
    phase: str,
    tool: str,
    command: list[str],
    timeout: int,
    note: str = "",
) -> subprocess.CompletedProcess[str] | None:
    adapted = adapt_command_for_kali(command)
    shell_cmd = shlex.join(adapted)
    if note:
        shell_cmd = f"{shell_cmd} # {note}"

    cmd_id = command_id()
    display = f"docker exec {KALI_CONTAINER} bash -lc {shlex.quote(shell_cmd)}"
    append_jsonl(
        COMMANDS_PATH,
        {
            "command_id": cmd_id,
            "timestamp": now(),
            "phase": phase,
            "tool": tool,
            "command": display,
            "status": "started",
            "exit_code": 0,
            "duration_ms": 0,
            "output_preview": "",
        },
    )
    started = time.time()
    try:
        proc = subprocess.run(
            ["docker", "exec", KALI_CONTAINER, "bash", "-lc", shell_cmd],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        duration_ms = int((time.time() - started) * 1000)
        append_jsonl(
            COMMANDS_PATH,
            {
                "command_id": cmd_id,
                "timestamp": now(),
                "phase": phase,
                "tool": tool,
                "command": display,
                "status": "error",
                "exit_code": 124,
                "duration_ms": duration_ms,
                "output_preview": "command timeout",
            },
        )
        return None

    duration_ms = int((time.time() - started) * 1000)
    combined = (proc.stdout + ("\n" + proc.stderr if proc.stderr else "")).strip()
    append_jsonl(
        COMMANDS_PATH,
        {
            "command_id": cmd_id,
            "timestamp": now(),
            "phase": phase,
            "tool": tool,
            "command": display,
            "status": "ok" if proc.returncode == 0 else "error",
            "exit_code": proc.returncode,
            "duration_ms": duration_ms,
            "output_preview": combined[:4000],
        },
    )
    return proc


def kali_running() -> bool:
    proc = subprocess.run(
        ["docker", "ps", "--filter", f"name=^{KALI_CONTAINER}$", "--format", "{{.Names}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode == 0 and KALI_CONTAINER in proc.stdout.splitlines()


def tool_exists_in_kali(tool: str) -> bool:
    proc = subprocess.run(
        ["docker", "exec", KALI_CONTAINER, "bash", "-lc", f"command -v {shlex.quote(tool)} >/dev/null 2>&1"],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode == 0


def adapt_text_for_kali(value: str) -> str:
    rewrites = [
        ("http://127.0.0.1", "http://host.docker.internal"),
        ("https://127.0.0.1", "https://host.docker.internal"),
        ("http://localhost", "http://host.docker.internal"),
        ("https://localhost", "https://host.docker.internal"),
        ("ssh://127.0.0.1", "ssh://host.docker.internal"),
        ("ssh://localhost", "ssh://host.docker.internal"),
        ("artifacts/", "/artifacts/"),
    ]
    out = value
    for old, new in rewrites:
        out = out.replace(old, new)
    if out == "127.0.0.1" or out == "localhost":
        return "host.docker.internal"
    return out


def adapt_command_for_kali(command: list[str]) -> list[str]:
    return [adapt_text_for_kali(part) for part in command]


def safe_hostname(raw_url: str) -> str:
    try:
        return (urlparse(raw_url).hostname or "").lower()
    except ValueError:
        return ""


def should_force_local(command: list[str]) -> bool:
    script_path = str(Path(__file__).resolve())
    for part in command:
        if script_path in part:
            return True
    return False


def log_finding(severity: str, title: str, endpoint: str, evidence: str, impact: str, phase: str) -> None:
    normalized = (
        severity.strip().lower(),
        title.strip().lower(),
        endpoint.strip().lower(),
        evidence.strip().lower(),
        impact.strip().lower(),
        phase.strip().lower(),
    )
    if finding_already_logged(normalized):
        return
    append_jsonl(
        FINDINGS_PATH,
        {
            "timestamp": now(),
            "severity": severity,
            "title": title,
            "endpoint": endpoint,
            "evidence": evidence,
            "impact": impact,
            "phase": phase,
        },
    )


def finding_already_logged(key: tuple[str, str, str, str, str, str], scan_limit: int = 400) -> bool:
    if not FINDINGS_PATH.exists():
        return False
    try:
        lines = FINDINGS_PATH.read_text(encoding="utf-8").splitlines()
    except Exception:
        return False
    for line in reversed(lines[-scan_limit:]):
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except Exception:
            continue
        existing = (
            str(item.get("severity", "")).strip().lower(),
            str(item.get("title", "")).strip().lower(),
            str(item.get("endpoint", "")).strip().lower(),
            str(item.get("evidence", "")).strip().lower(),
            str(item.get("impact", "")).strip().lower(),
            str(item.get("phase", "")).strip().lower(),
        )
        if existing == key:
            return True
    return False


def log_exploit(exploit_type: str, escalation_degree: str, novelty: str, vector: str, evidence: str, source: str) -> None:
    append_jsonl(
        EXPLOITS_PATH,
        {
            "timestamp": now(),
            "exploit_type": exploit_type,
            "escalation_degree": escalation_degree,
            "novelty": novelty,
            "vector": vector,
            "evidence": evidence,
            "source": source,
        },
    )


def log_loot(kind: str, name: str, source: str, preview: str) -> None:
    normalized = (kind.strip().lower(), name.strip().lower(), source.strip().lower())
    if loot_already_logged(normalized):
        return
    append_jsonl(
        LOOT_PATH,
        {
            "timestamp": now(),
            "kind": kind,
            "name": name,
            "source": source,
            "preview": preview[:2000],
        },
    )


def loot_already_logged(key: tuple[str, str, str], scan_limit: int = 300) -> bool:
    if not LOOT_PATH.exists():
        return False
    try:
        lines = LOOT_PATH.read_text(encoding="utf-8").splitlines()
    except OSError:
        return False
    for raw in reversed(lines[-scan_limit:]):
        raw = raw.strip()
        if not raw:
            continue
        try:
            item = json.loads(raw)
        except json.JSONDecodeError:
            continue
        item_key = (
            str(item.get("kind", "")).strip().lower(),
            str(item.get("name", "")).strip().lower(),
            str(item.get("source", "")).strip().lower(),
        )
        if item_key == key:
            return True
    return False


FLAG_PATTERNS = [
    re.compile(r"(?i)\b(flag\{[^}\n]{3,200}\})"),
    re.compile(r"(?i)\b(HTB\{[^}\n]{3,200}\})"),
    re.compile(r"(?i)\b(THM\{[^}\n]{3,200}\})"),
    re.compile(r"(?i)\b(picoCTF\{[^}\n]{3,200}\})"),
]

TOKEN_PATTERNS = [
    re.compile(r"(?i)\b(jwt|token|apikey|api_key|bearer)\b[^\n:=]{0,40}[:=]\s*([A-Za-z0-9_\-\.=]{12,})"),
]

CRED_PATTERNS = [
    re.compile(r"(?i)\b(user(name)?|login)\b[^\n]{0,30}\b(pass(word)?|pwd)\b[^\n:=]{0,20}[:=]\s*([^\s\"']{3,})"),
]


def extract_loot(module: Module, target: str, output: str, artifact: Path, execution_mode: str) -> None:
    seen: set[tuple[str, str, str]] = set()
    target_host = safe_hostname(target)

    def push(kind: str, name: str, source: str, preview: str) -> None:
        key = (kind.strip().lower(), name.strip().lower(), source.strip().lower())
        if key in seen:
            return
        seen.add(key)
        log_loot(kind, name, source, preview)

    rel_artifact = str(artifact.relative_to(ROOT)) if artifact.is_absolute() and ROOT in artifact.parents else str(artifact)
    push(
        "artifact",
        artifact.name,
        module.name,
        f"{execution_mode} :: {module.tool} :: {module.description or module.name} :: {rel_artifact}",
    )

    if module.name == "robots":
        for match in re.finditer(r"(?im)^Disallow:\s*(/\S+)", output):
            path = match.group(1).strip()
            push("path", f"disallow {path}", f"{target.rstrip('/')}/robots.txt", path)

    for pattern in FLAG_PATTERNS:
        for match in pattern.finditer(output):
            token = match.group(1).strip()
            push("flag", "captured-flag", module.name, token)

    for pattern in TOKEN_PATTERNS:
        for match in pattern.finditer(output):
            secret_kind = match.group(1).lower()
            token = match.group(2).strip()
            push("token", secret_kind, module.name, token)

    for pattern in CRED_PATTERNS:
        for match in pattern.finditer(output):
            preview = truncate_text(match.group(0).strip(), 180)
            push("credential", "possible-credential", module.name, preview)

    for year, cve_id in CVE_RE.findall(output):
        cve = f"CVE-{year}-{cve_id}"
        push("vuln", cve, module.name, "referenced in module output")

    for url_match in re.finditer(r"https?://[^\s\"'<>]+", output):
        discovered = url_match.group(0).strip()
        if len(discovered) > 200:
            continue
        discovered_host = safe_hostname(discovered)
        if discovered_host and target_host and discovered_host not in {target_host, "host.docker.internal", "127.0.0.1", "localhost"}:
            continue
        if "host.docker.internal" in discovered:
            discovered = discovered.replace("host.docker.internal", "127.0.0.1")
        push("endpoint", truncate_text(discovered, 80), module.name, discovered)


def truncate_text(value: str, max_len: int) -> str:
    if len(value) <= max_len:
        return value
    return value[: max_len - 3] + "..."


def snapshot_run() -> None:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = RUNS_DIR / stamp
    dest.mkdir(parents=True, exist_ok=True)
    for path in [STATE_PATH, COMMANDS_PATH, FINDINGS_PATH, LOOT_PATH, EXPLOITS_PATH]:
        if path.exists():
            shutil.copy2(path, dest / path.name)


@dataclass(frozen=True)
class Module:
    name: str
    phase: str
    tool: str
    command: list[str]
    description: str = ""


def parse_target(target: str) -> tuple[str, str]:
    try:
        parsed = urlparse(target)
    except ValueError as exc:
        raise SystemExit(f"Invalid target URL: {exc}") from exc
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    return host, str(port)


def build_modules(target: str, profile: str) -> list[Module]:
    host, port = parse_target(target)
    base: list[Module] = [
        Module("http-headers", "surface", "curl", ["curl", "-sSI", target], "Collect response headers"),
        Module("robots", "surface", "curl", ["curl", "-sS", target.rstrip("/") + "/robots.txt"], "Collect robots.txt hints"),
    ]
    if profile in {"standard", "deep"}:
        base.extend(
            [
                Module("service-fingerprint", "enum", "nmap", ["nmap", "-sV", "-Pn", "-p", port, host], "Service fingerprint"),
                Module("template-scan", "enum", "nuclei", ["nuclei", "-u", target, "-silent"], "Template-based checks"),
            ]
        )
    if profile == "deep":
        base.extend(
            [
                Module("web-vuln-audit", "vuln", "nikto", ["nikto", "-h", target], "Web vuln signatures"),
                Module(
                    "content-discovery",
                    "vuln",
                    "ffuf",
                    ["ffuf", "-u", target.rstrip("/") + "/FUZZ", "-w", "/usr/share/wordlists/dirb/common.txt", "-mc", "200,204,301,302,307,401,403"],
                    "Path/content discovery",
                ),
            ]
        )
    return base


PIPELINE_DESCRIPTIONS: dict[str, str] = {
    "prelim": "Fast preliminary posture check (headers, robots, homepage).",
    "surface-map": "Surface + service mapping (prelim + nmap + whatweb).",
    "web-enum": "Web endpoint enumeration (ffuf + gobuster).",
    "vuln-sweep": "Vulnerability sweep (nuclei + nikto).",
    "api-probe": "API-oriented probing (common OpenAPI/docs and methods).",
    "initial-exploit": "Turn vuln into shell/RCE pathing (sqlmap/msf/searchsploit/commix/xsser).",
    "post-enum": "Enumerate host/domain context after foothold (enum4linux/smb/ldap/snmp/system data).",
    "password-attacks": "Crack/bruteforce creds from discovered artifacts (john/hydra/hashcat/medusa).",
    "privesc": "Privilege escalation triage from low-priv context (linpeas/searchsploit/sudo checks).",
    "lateral-pivot": "Multi-host discovery and pivot-oriented probing (nmap/arp-scan/responder/routes).",
    "full-escalation": "Kitchen-sink escalation chain (post-enum -> password-attacks -> privesc).",
    "full-chain": "Full chain for early blackbox triage.",
}


TOOL_CATALOG: dict[str, list[str]] = {
    "network_scan": ["nmap", "masscan", "rustscan", "naabu", "zmap", "arp-scan"],
    "web_scan": ["nikto", "gobuster", "ffuf", "feroxbuster", "nuclei", "whatweb", "wfuzz", "arjun", "burpsuite", "zaproxy"],
    "enumeration": ["enum4linux-ng", "smbclient", "smbmap", "rpcclient", "ldapsearch", "snmpwalk", "nbtscan", "responder"],
    "exploitation": ["sqlmap", "msfconsole", "searchsploit", "commix", "xsser"],
    "password_attacks": ["hydra", "medusa", "john", "hashcat"],
    "osint": [
        "theHarvester",
        "bbot",
        "osint-deep-spiderfoot",
        "osint-reconng",
        "osint-rengine",
        "amass",
        "subfinder",
        "dnsrecon",
        "fierce",
    ],
    "utilities": ["curl", "wget", "jq", "dig", "whois", "openssl"],
}


def build_named_pipeline(target: str, pipeline: str) -> list[Module]:
    host, port = parse_target(target)
    base_url = target.rstrip("/")
    if pipeline == "prelim":
        return [
            Module("http-headers", "surface", "curl", ["curl", "-sSI", target], "Response headers"),
            Module("homepage", "surface", "curl", ["curl", "-sS", target], "Homepage fetch"),
            Module("robots", "surface", "curl", ["curl", "-sS", f"{base_url}/robots.txt"], "Robots clues"),
        ]
    if pipeline == "surface-map":
        return [
            Module("http-headers", "surface", "curl", ["curl", "-sSI", target], "Response headers"),
            Module("service-fingerprint", "enum", "nmap", ["nmap", "-sV", "-Pn", "-p", port, host], "Service fingerprint"),
            Module("tech-fingerprint", "enum", "whatweb", ["whatweb", "--no-errors", target], "Tech stack fingerprint"),
        ]
    if pipeline == "web-enum":
        return [
            Module("ffuf-enum", "enum", "ffuf", ["ffuf", "-u", f"{base_url}/FUZZ", "-w", "/usr/share/wordlists/dirb/common.txt", "-mc", "200,204,301,302,307,401,403"], "Fuzz common paths"),
            Module("gobuster-enum", "enum", "gobuster", ["gobuster", "dir", "-u", base_url, "-w", "/usr/share/wordlists/dirb/common.txt", "-q"], "Directory brute force"),
        ]
    if pipeline == "vuln-sweep":
        return [
            Module("template-scan", "vuln", "nuclei", ["nuclei", "-u", target, "-silent"], "Nuclei template sweep"),
            Module("web-vuln-audit", "vuln", "nikto", ["nikto", "-h", target], "Nikto web checks"),
        ]
    if pipeline == "api-probe":
        return [
            Module("openapi-json", "enum", "curl", ["curl", "-sS", f"{base_url}/openapi.json"], "Probe OpenAPI"),
            Module("swagger-ui", "enum", "curl", ["curl", "-sSI", f"{base_url}/swagger"], "Probe swagger path"),
            Module("options-root", "enum", "curl", ["curl", "-sSI", "-X", "OPTIONS", target], "Probe allowed methods"),
        ]
    if pipeline == "initial-exploit":
        return [
            Module("sqlmap-crawl", "exploit", "sqlmap", ["sqlmap", "-u", target, "--batch", "--crawl=2", "--risk=2", "--level=3"], "SQLMap crawl-based exploit discovery"),
            Module("sqlmap-os-shell-template", "exploit", "bash", ["bash", "-lc", "test -f artifacts/req.txt && sqlmap -r artifacts/req.txt --batch --os-shell || echo 'missing artifacts/req.txt for sqlmap -r --os-shell'"], "SQLMap request-file os-shell workflow"),
            Module("searchsploit-triage", "exploit", "searchsploit", ["searchsploit", host], "Search exploit-db references"),
            Module("commix-auto", "exploit", "commix", ["commix", "--url", target, "--batch"], "Command injection automation"),
            Module("xsser-auto", "exploit", "xsser", ["xsser", "--url", target], "XSS-oriented testing"),
            Module("msfconsole-exploit-template", "exploit", "msfconsole", ["msfconsole", "-q", "-x", "search type:exploit; exit"], "Metasploit exploit module search template"),
        ]
    if pipeline == "post-enum":
        return [
            Module("enum4linux-ng", "post-enum", "enum4linux-ng", ["enum4linux-ng", "-A", host], "SMB/domain enum"),
            Module("smbclient-list", "post-enum", "smbclient", ["smbclient", "-L", f"//{host}", "-N"], "SMB share listing"),
            Module("smbmap-list", "post-enum", "smbmap", ["smbmap", "-H", host], "SMB mapping"),
            Module("rpcclient-users", "post-enum", "rpcclient", ["rpcclient", "-U", "", "-N", host, "-c", "enumdomusers"], "RPC user enum"),
            Module("ldapsearch-base", "post-enum", "ldapsearch", ["ldapsearch", "-x", "-H", f"ldap://{host}", "-s", "base"], "LDAP base query"),
            Module("snmpwalk-system", "post-enum", "snmpwalk", ["snmpwalk", "-v2c", "-c", "public", host, "1.3.6.1.2.1.1"], "SNMP system tree"),
            Module("system-context", "post-enum", "bash", ["bash", "-lc", "whoami; id; uname -a; cat /etc/passwd | head -n 60"], "System context baseline"),
            Module("linpeas-template", "post-enum", "bash", ["bash", "-lc", "test -f artifacts/linpeas.sh && bash artifacts/linpeas.sh || echo 'upload linpeas.sh to artifacts/ to run local privesc enum'"], "LinPEAS execution template"),
        ]
    if pipeline == "password-attacks":
        return [
            Module("john-hashes", "password", "bash", ["bash", "-lc", "test -f artifacts/hashes.txt && john artifacts/hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt || echo 'missing artifacts/hashes.txt'"], "John wordlist cracking"),
            Module("hashcat-hashes", "password", "bash", ["bash", "-lc", "test -f artifacts/hashes.txt && hashcat -m 0 -a 0 artifacts/hashes.txt /usr/share/wordlists/rockyou.txt --quiet || echo 'missing artifacts/hashes.txt or hashcat setup'"], "Hashcat cracking"),
            Module("hydra-ssh", "password", "bash", ["bash", "-lc", "test -f artifacts/users.txt && test -f artifacts/pass.txt && hydra -L artifacts/users.txt -P artifacts/pass.txt ssh://" + host + " || echo 'missing artifacts/users.txt or artifacts/pass.txt'"], "Hydra SSH brute force"),
            Module("medusa-ssh", "password", "bash", ["bash", "-lc", "test -f artifacts/users.txt && test -f artifacts/pass.txt && medusa -h " + host + " -U artifacts/users.txt -P artifacts/pass.txt -M ssh || echo 'missing artifacts/users.txt or artifacts/pass.txt'"], "Medusa SSH brute force"),
        ]
    if pipeline == "privesc":
        return [
            Module("kernel-fingerprint", "privesc", "bash", ["bash", "-lc", "uname -a; cat /proc/version"], "Kernel info"),
            Module("searchsploit-kernel", "privesc", "searchsploit", ["searchsploit", "linux kernel"], "Kernel exploit lookup"),
            Module("sudo-rights", "privesc", "bash", ["bash", "-lc", "sudo -l || true"], "Sudo rights enumeration"),
            Module("suid-binaries", "privesc", "bash", ["bash", "-lc", "find / -perm -4000 -type f 2>/dev/null | head -n 120"], "SUID discovery"),
            Module("writable-cron", "privesc", "bash", ["bash", "-lc", "ls -la /etc/cron* 2>/dev/null; find /etc/cron* -type f -writable 2>/dev/null"], "Cron misconfig scan"),
            Module("docker-socket", "privesc", "bash", ["bash", "-lc", "ls -la /var/run/docker.sock 2>/dev/null || true"], "Docker socket exposure"),
            Module("linpeas-template", "privesc", "bash", ["bash", "-lc", "test -f artifacts/linpeas.sh && bash artifacts/linpeas.sh || echo 'upload linpeas.sh to artifacts/'"], "LinPEAS execution"),
            Module("msf-post-template", "privesc", "msfconsole", ["msfconsole", "-q", "-x", "show post; exit"], "Metasploit post module template"),
        ]
    if pipeline == "lateral-pivot":
        subnet = host + "/24"
        return [
            Module("nmap-subnet", "pivot", "nmap", ["nmap", "-sV", "-Pn", subnet], "Subnet service sweep"),
            Module("arp-scan-local", "pivot", "arp-scan", ["arp-scan", "--localnet"], "L2 discovery"),
            Module("responder-template", "pivot", "bash", ["bash", "-lc", "echo 'run responder with explicit iface: responder -I <iface> -wrf'"], "Responder launch template"),
            Module("ssh-dynamic-pivot-template", "pivot", "bash", ["bash", "-lc", "echo 'ssh -D 1080 user@" + host + " then proxy nmap through socks'"], "SOCKS pivot template"),
            Module("msf-routes-template", "pivot", "msfconsole", ["msfconsole", "-q", "-x", "route; exit"], "Metasploit route template"),
        ]
    if pipeline == "full-escalation":
        return [
            Module("chain-post-enum", "chain", "python3", ["python3", str(Path(__file__).resolve()), "--target", target, "--pipeline", "post-enum", "--no-snapshot"], "Run post-enum stage"),
            Module("chain-password-attacks", "chain", "python3", ["python3", str(Path(__file__).resolve()), "--target", target, "--pipeline", "password-attacks", "--no-snapshot"], "Run password stage"),
            Module("chain-privesc", "chain", "python3", ["python3", str(Path(__file__).resolve()), "--target", target, "--pipeline", "privesc", "--no-snapshot"], "Run privesc stage"),
            Module("flag-hunt-template", "chain", "bash", ["bash", "-lc", "ls -la /root/flag.txt /home/*/flag.txt 2>/dev/null || true"], "Flag location check"),
        ]
    if pipeline == "full-chain":
        return [
            Module("http-headers", "surface", "curl", ["curl", "-sSI", target], "Response headers"),
            Module("robots", "surface", "curl", ["curl", "-sS", f"{base_url}/robots.txt"], "Robots clues"),
            Module("service-fingerprint", "enum", "nmap", ["nmap", "-sV", "-Pn", "-p", port, host], "Service fingerprint"),
            Module("tech-fingerprint", "enum", "whatweb", ["whatweb", "--no-errors", target], "Tech stack fingerprint"),
            Module("ffuf-enum", "enum", "ffuf", ["ffuf", "-u", f"{base_url}/FUZZ", "-w", "/usr/share/wordlists/dirb/common.txt", "-mc", "200,204,301,302,307,401,403"], "Path fuzzing"),
            Module("template-scan", "vuln", "nuclei", ["nuclei", "-u", target, "-silent"], "Nuclei checks"),
            Module("web-vuln-audit", "vuln", "nikto", ["nikto", "-h", target], "Nikto checks"),
        ]
    raise SystemExit(f"Unknown pipeline: {pipeline}")


EXPLOIT_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"sql\s*injection", re.I), "SQL_INJECTION", "high"),
    (re.compile(r"xss|cross[- ]site scripting", re.I), "XSS", "medium"),
    (re.compile(r"remote code execution|\brce\b", re.I), "RCE", "critical"),
    (re.compile(r"command injection", re.I), "CMD_INJECTION", "critical"),
    (re.compile(r"path traversal|directory traversal", re.I), "PATH_TRAVERSAL", "high"),
    (re.compile(r"idor|insecure direct object", re.I), "IDOR", "medium"),
    (re.compile(r"ssrf", re.I), "SSRF", "high"),
    (re.compile(r"auth.*bypass|broken authentication", re.I), "AUTH_BYPASS", "high"),
]

CVE_RE = re.compile(r"CVE-(\d{4})-(\d+)", re.I)


def novelty_from_text(text: str) -> str:
    year_now = datetime.now(timezone.utc).year
    matches = CVE_RE.findall(text)
    if not matches:
        lowered = text.lower()
        if "0day" in lowered or "zero-day" in lowered:
            return "0day"
        return "known"
    newest = max(int(year) for year, _ in matches)
    if newest >= year_now - 1:
        return "one-day"
    return "known"


def classify_and_log(module: Module, target: str, output: str) -> None:
    lower_output = output.lower()

    if module.name == "robots" and ("/admin" in lower_output or "/ftp" in lower_output):
        log_finding(
            "high",
            "robots.txt discloses sensitive paths",
            "/robots.txt",
            "disallowed paths include admin/ftp style routes",
            "increases attack surface for unauthorized exploration",
            module.phase,
        )
        log_exploit("SURFACE_DISCLOSURE", "medium", "known", "/robots.txt", "sensitive path disclosure", module.tool)

    if "server:" in lower_output or "x-powered-by" in lower_output:
        log_finding(
            "low",
            "technology fingerprint exposed",
            target,
            "response headers leak stack identifiers",
            "improves attacker targeting and exploit selection",
            module.phase,
        )
        log_exploit("TECH_FINGERPRINT", "low", "known", "http headers", "stack/version metadata exposed", module.tool)

    found_any = False
    for pattern, exploit_type, escalation in EXPLOIT_PATTERNS:
        if not pattern.search(output):
            continue
        found_any = True
        novelty = novelty_from_text(output)
        log_exploit(exploit_type, escalation, novelty, module.name, pattern.pattern, module.tool)
        sev = "critical" if escalation == "critical" else "high" if escalation == "high" else "medium"
        log_finding(
            sev,
            f"Potential {exploit_type.replace('_', ' ')} indicator",
            target,
            pattern.pattern,
            f"Detected exploit signature with escalation={escalation}, novelty={novelty}",
            module.phase,
        )

    if not found_any and module.phase in {"surface", "enum"}:
        log_exploit("SURFACE_MAPPING", "low", "known", module.name, "enumeration completed", module.tool)


def run_pipeline(target: str, profile: str, pipeline: str | None, timeout: int, snapshot: bool) -> int:
    ensure_dirs()
    state = read_state()
    state["target_url"] = target
    state["target_name"] = state.get("target_name") or "Custom Target"
    state["status"] = "running"
    state["phase"] = "pipeline"
    write_state(state)

    modules = build_named_pipeline(target, pipeline) if pipeline else build_modules(target, profile)
    kali_ok = kali_running()
    kali_tool_cache: dict[str, bool] = {}

    print(f"pipeline target={target} profile={profile} mode={'named:'+pipeline if pipeline else 'profile'}")
    print(f"kali_container={KALI_CONTAINER} running={'yes' if kali_ok else 'no'}")
    for module in modules:
        tool_bin = module.command[0]
        force_local = should_force_local(module.command)
        has_local = shutil.which(tool_bin) is not None
        has_kali = False
        if not has_local and kali_ok and not force_local:
            if tool_bin not in kali_tool_cache:
                kali_tool_cache[tool_bin] = tool_exists_in_kali(tool_bin)
            has_kali = kali_tool_cache[tool_bin]

        print(f"[{module.phase}] {module.name} :: {module.description or module.tool}")

        if not has_local and not has_kali:
            append_jsonl(
                COMMANDS_PATH,
                {
                    "command_id": command_id(),
                    "timestamp": now(),
                    "phase": module.phase,
                    "tool": module.tool,
                    "command": subprocess.list2cmdline(module.command),
                    "status": "error",
                    "exit_code": 127,
                    "duration_ms": 0,
                    "output_preview": f"tool not found (local+kali): {module.command[0]}",
                },
            )
            log_finding(
                "low",
                f"Tool unavailable: {module.command[0]}",
                target,
                module.name,
                "scan depth reduced due to missing dependency",
                module.phase,
            )
            print(f"  -> skipped (missing tool: {tool_bin})")
            continue

        if has_local or force_local:
            proc = run_logged(module.phase, module.tool, module.command, timeout)
            execution_mode = "local"
        else:
            proc = run_logged_kali(module.phase, module.tool, module.command, timeout, note="auto-routed-to-kali")
            execution_mode = "kali"

        if proc is None:
            log_finding(
                "medium",
                f"Scan timeout: {module.name}",
                target,
                module.name,
                "command exceeded timeout and was aborted",
                module.phase,
            )
            log_exploit("TIMEOUT_OR_STEALTH", "medium", "unknown", module.name, "timeout", module.tool)
            print(f"  -> timeout ({execution_mode})")
            continue

        output = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
        artifact = ARTIFACTS / f"pipeline-{module.name}.txt"
        artifact.write_text(output, encoding="utf-8")
        classify_and_log(module, target, output)
        extract_loot(module, target, output, artifact, execution_mode)
        print(f"  -> rc={proc.returncode} ({execution_mode})")

    state = read_state()
    state["status"] = "complete"
    state["phase"] = "pipeline-complete"
    write_state(state)
    if snapshot:
        snapshot_run()
    return 0


def list_pipelines() -> None:
    for name, desc in PIPELINE_DESCRIPTIONS.items():
        print(f"{name}: {desc}")


def list_tools() -> None:
    kali_ok = kali_running()
    for category, tools in TOOL_CATALOG.items():
        local_installed = [tool for tool in tools if shutil.which(tool) is not None]
        kali_installed = [tool for tool in tools if shutil.which(tool) is None and kali_ok and tool_exists_in_kali(tool)]
        missing = [tool for tool in tools if tool not in local_installed and tool not in kali_installed]
        print(f"[{category}]")
        print("  installed(local): " + (", ".join(local_installed) if local_installed else "none"))
        print("  installed(kali):  " + (", ".join(kali_installed) if kali_installed else "none"))
        print("  missing:   " + (", ".join(missing) if missing else "none"))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Modular security scan pipeline with telemetry + exploit classification.")
    parser.add_argument("--target", default="http://127.0.0.1", help="Target URL to scan")
    parser.add_argument("--profile", choices=["quick", "standard", "deep"], default="standard", help="Scan depth profile")
    parser.add_argument("--pipeline", choices=sorted(PIPELINE_DESCRIPTIONS.keys()), help="Named operator pipeline")
    parser.add_argument("--timeout", type=int, default=90, help="Per-module timeout in seconds")
    parser.add_argument("--no-snapshot", action="store_true", help="Do not archive telemetry to telemetry/runs")
    parser.add_argument("--list-pipelines", action="store_true", help="Print available named pipelines and exit")
    parser.add_argument("--list-tools", action="store_true", help="Print tool inventory by category and exit")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.list_pipelines:
        list_pipelines()
        return 0
    if args.list_tools:
        list_tools()
        return 0
    try:
        return run_pipeline(args.target, args.profile, args.pipeline, args.timeout, snapshot=not args.no_snapshot)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # pragma: no cover
        print(f"pipeline failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
