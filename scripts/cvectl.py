#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
TELEMETRY = ROOT / "telemetry"
STATE_PATH = TELEMETRY / "state.json"
CACHE_DIR = TELEMETRY / "cve-cache"

CVE_RE = re.compile(r"(?i)\bCVE-\d{4}-\d{4,7}\b")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_cve(raw: str) -> str:
    value = str(raw or "").strip().upper()
    match = CVE_RE.search(value)
    if not match:
        raise SystemExit(f"invalid CVE id: {raw!r} (expected format like CVE-2026-20722)")
    return match.group(0)


def http_get_json(url: str) -> dict[str, Any]:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "h3retik-cvectl/0.0.7",
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        body = resp.read().decode("utf-8", errors="replace")
    return json.loads(body)


def fetch_from_cveawg(cve_id: str) -> dict[str, Any]:
    url = f"https://cveawg.mitre.org/api/cve/{urllib.parse.quote(cve_id)}"
    data = http_get_json(url)
    cna = ((data.get("containers") or {}).get("cna") or {})
    descriptions = cna.get("descriptions") or []
    summary = ""
    for item in descriptions:
        if isinstance(item, dict) and str(item.get("lang", "")).lower().startswith("en"):
            summary = str(item.get("value", "")).strip()
            if summary:
                break
    if not summary and descriptions and isinstance(descriptions[0], dict):
        summary = str(descriptions[0].get("value", "")).strip()
    references = []
    for ref in cna.get("references") or []:
        if isinstance(ref, dict) and ref.get("url"):
            references.append(str(ref["url"]).strip())
    affected = []
    for item in cna.get("affected") or []:
        if not isinstance(item, dict):
            continue
        vendor = str(item.get("vendor", "")).strip()
        product = str(item.get("product", "")).strip()
        if vendor or product:
            affected.append((vendor + " " + product).strip())
    return {
        "id": cve_id,
        "source": "cveawg",
        "summary": summary,
        "severity": "",
        "affected": affected[:12],
        "references": references[:20],
        "raw": data,
        "fetched_at": now_iso(),
    }


def fetch_from_nvd(cve_id: str) -> dict[str, Any]:
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={urllib.parse.quote(cve_id)}"
    data = http_get_json(url)
    vulns = data.get("vulnerabilities") or []
    if not vulns:
        raise SystemExit(f"cve not found in NVD: {cve_id}")
    cve = (vulns[0] or {}).get("cve") or {}
    descriptions = cve.get("descriptions") or []
    summary = ""
    for item in descriptions:
        if isinstance(item, dict) and str(item.get("lang", "")).lower().startswith("en"):
            summary = str(item.get("value", "")).strip()
            if summary:
                break
    references = []
    for ref in cve.get("references") or []:
        if isinstance(ref, dict) and ref.get("url"):
            references.append(str(ref["url"]).strip())
    metrics = cve.get("metrics") or {}
    severity = ""
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        arr = metrics.get(key) or []
        if arr and isinstance(arr[0], dict):
            cvss = (arr[0].get("cvssData") or {})
            sev = str(cvss.get("baseSeverity", "")).strip()
            score = cvss.get("baseScore")
            if sev and score is not None:
                severity = f"{sev} {score}"
            elif sev:
                severity = sev
            if severity:
                break
    return {
        "id": cve_id,
        "source": "nvd",
        "summary": summary,
        "severity": severity,
        "affected": [],
        "references": references[:20],
        "raw": data,
        "fetched_at": now_iso(),
    }


def cache_path(cve_id: str) -> Path:
    return CACHE_DIR / f"{cve_id}.json"


def save_cache(record: dict[str, Any]) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path = cache_path(record["id"])
    path.write_text(json.dumps(record, indent=2), encoding="utf-8")


def load_cache(cve_id: str) -> dict[str, Any] | None:
    path = cache_path(cve_id)
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def fetch_cve_record(cve_id: str, refresh: bool = False) -> dict[str, Any]:
    if not refresh:
        cached = load_cache(cve_id)
        if cached:
            return cached
    errors: list[str] = []
    for fn in (fetch_from_cveawg, fetch_from_nvd):
        try:
            record = fn(cve_id)
            save_cache(record)
            return record
        except urllib.error.HTTPError as exc:
            errors.append(f"{fn.__name__}: HTTP {exc.code}")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{fn.__name__}: {exc}")
    raise SystemExit(f"failed to fetch {cve_id}: " + " | ".join(errors))


def read_state() -> dict[str, Any]:
    if not STATE_PATH.exists():
        return {}
    return json.loads(STATE_PATH.read_text(encoding="utf-8"))


def write_state(state: dict[str, Any]) -> None:
    TELEMETRY.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state, indent=2), encoding="utf-8")


def state_cve_refs(state: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    raw = state.get("cve_references")
    if isinstance(raw, list):
        for item in raw:
            text = str(item or "").strip()
            if not text:
                continue
            try:
                cve = normalize_cve(text)
            except SystemExit:
                continue
            if cve not in refs:
                refs.append(cve)
    active = str(state.get("cve_reference") or "").strip()
    if active:
        try:
            cve = normalize_cve(active)
            if cve not in refs:
                refs.append(cve)
        except SystemExit:
            pass
    return refs


def persist_state_cve_refs(state: dict[str, Any], refs: list[str], active: str | None = None) -> dict[str, Any]:
    normalized: list[str] = []
    for item in refs:
        cve = normalize_cve(item)
        if cve not in normalized:
            normalized.append(cve)
    state["cve_references"] = normalized
    if active is None:
        current = str(state.get("cve_reference") or "").strip()
        if current:
            try:
                current = normalize_cve(current)
            except SystemExit:
                current = ""
        if current and current in normalized:
            state["cve_reference"] = current
        elif normalized:
            state["cve_reference"] = normalized[0]
        else:
            state["cve_reference"] = ""
    else:
        state["cve_reference"] = normalize_cve(active) if active else ""
    state["updated_at"] = now_iso()
    write_state(state)
    return state


def apply_cve(cve_id: str) -> dict[str, Any]:
    state = read_state()
    refs = state_cve_refs(state)
    if cve_id not in refs:
        refs.append(cve_id)
    return persist_state_cve_refs(state, refs, active=cve_id)


def print_record(record: dict[str, Any]) -> None:
    print(f"id:        {record.get('id', '')}")
    print(f"source:    {record.get('source', '')}")
    print(f"severity:  {record.get('severity', '') or 'n/a'}")
    print(f"fetched:   {record.get('fetched_at', '')}")
    print(f"summary:   {record.get('summary', '') or 'n/a'}")
    affected = record.get("affected") or []
    if affected:
        print("affected:")
        for item in affected[:8]:
            print(f"  - {item}")
    refs = record.get("references") or []
    if refs:
        print("references:")
        for ref in refs[:8]:
            print(f"  - {ref}")


def cmd_load(args: argparse.Namespace) -> int:
    cve_id = normalize_cve(args.cve)
    record = fetch_cve_record(cve_id, refresh=args.refresh)
    state = None
    if args.apply:
        state = apply_cve(cve_id)
    elif args.track:
        cur = read_state()
        refs = state_cve_refs(cur)
        if cve_id not in refs:
            refs.append(cve_id)
        state = persist_state_cve_refs(cur, refs, active=None)
    if args.json:
        print(json.dumps(record, indent=2))
    else:
        print_record(record)
        if args.apply:
            print(f"\napplied:   {cve_id}")
        elif args.track:
            print(f"\ntracked:   {cve_id}")
    if args.state_json and state is not None:
        print(json.dumps(state, indent=2))
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    cve_id = normalize_cve(args.cve)
    record = fetch_cve_record(cve_id, refresh=args.refresh)
    if args.json:
        print(json.dumps(record, indent=2))
    else:
        print_record(record)
    return 0


def cmd_apply(args: argparse.Namespace) -> int:
    cve_id = normalize_cve(args.cve)
    apply_cve(cve_id)
    print(json.dumps({"status": "ok", "applied_cve": cve_id, "state": str(STATE_PATH)}, indent=2))
    return 0


def cmd_unload(args: argparse.Namespace) -> int:
    state = read_state()
    refs = state_cve_refs(state)
    if args.all:
        updated = persist_state_cve_refs(state, [], active="")
        print(json.dumps({"status": "ok", "unloaded": "all", "state": str(STATE_PATH), "active": updated.get("cve_reference", "")}, indent=2))
        return 0
    cve_id = normalize_cve(args.cve or "")
    refs = [item for item in refs if item.upper() != cve_id.upper()]
    active = str(state.get("cve_reference") or "").strip().upper()
    next_active = active
    if active == cve_id:
        next_active = refs[0] if refs else ""
    updated = persist_state_cve_refs(state, refs, active=next_active)
    print(json.dumps({"status": "ok", "unloaded": cve_id, "state": str(STATE_PATH), "active": updated.get("cve_reference", "")}, indent=2))
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    rows = []
    for entry in sorted(CACHE_DIR.glob("CVE-*.json")):
        try:
            data = json.loads(entry.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        rows.append(
            {
                "id": data.get("id", entry.stem),
                "source": data.get("source", ""),
                "severity": data.get("severity", ""),
                "summary": str(data.get("summary", "")).strip(),
            }
        )
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    if not rows:
        print("No cached CVE records.")
        return 0
    for row in rows:
        summary = row["summary"][:120]
        print(f"{row['id']} | {row['source']} | {row['severity'] or 'n/a'} | {summary}")
    return 0


def cmd_list_active(args: argparse.Namespace) -> int:
    state = read_state()
    refs = state_cve_refs(state)
    active = str(state.get("cve_reference") or "").strip()
    payload = {"active": active, "loaded": refs, "state": str(STATE_PATH)}
    if args.json:
        print(json.dumps(payload, indent=2))
        return 0
    print(f"active: {active or 'none'}")
    if not refs:
        print("loaded: none")
        return 0
    print("loaded:")
    for item in refs:
        marker = "*" if item == active else "-"
        print(f"  {marker} {item}")
    return 0


def cmd_scaffold(args: argparse.Namespace) -> int:
    cve_id = normalize_cve(args.cve)
    name = str(args.name or "").strip().lower()
    if not name:
        raise SystemExit("--name is required")
    slug = re.sub(r"[^a-z0-9._-]+", "-", name).strip("-")
    if not slug:
        raise SystemExit("invalid --name")
    modules_dir = ROOT / "modules" / "exploit"
    modules_dir.mkdir(parents=True, exist_ok=True)
    module_id = f"{cve_id.lower()}-{slug}"
    out_path = modules_dir / f"{module_id}.json"
    if out_path.exists() and not args.force:
        raise SystemExit(f"module already exists: {out_path} (use --force to overwrite)")
    template = {
        "id": module_id,
        "mode": "exploit",
        "group": args.group,
        "runtime": args.runtime,
        "label": f"{cve_id} :: {args.name}",
        "description": f"CVE-scaffolded module for {cve_id}. Replace command_template with your exploit chain.",
        "command_template": "echo 'TODO: implement CVE chain for {{target_url}} {{input:payload}}' && true",
        "requires": ["recon"],
        "action_id": module_id,
        "enabled": True,
        "tags": [f"cve:{cve_id.lower()}", "scaffold"],
        "inputs": [
            {"key": "payload", "label": "Payload", "default": "", "required": False, "type": "text", "options": []}
        ],
        "evidence": {
            "loot_kind": "cve-module-output",
            "loot_name": module_id,
            "finding_severity": "high",
            "finding_title": f"{cve_id} module execution",
            "finding_impact": "Operator-executed CVE-specific module",
            "phase": "exploit",
        },
    }
    out_path.write_text(json.dumps(template, indent=2), encoding="utf-8")
    print(json.dumps({"status": "ok", "module": str(out_path), "cve": cve_id, "id": module_id}, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cvectl.py", description="h3retik CVE loader/cache/apply helper")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_load = sub.add_parser("load", help="fetch CVE record from public source and cache it")
    p_load.add_argument("cve")
    p_load.add_argument("--refresh", action="store_true")
    p_load.add_argument("--apply", action="store_true")
    p_load.add_argument("--track", action="store_true", help="add CVE to loaded list without making it active")
    p_load.add_argument("--state-json", action="store_true", help="print updated telemetry state when --apply/--track is used")
    p_load.add_argument("--json", action="store_true")
    p_load.set_defaults(func=cmd_load)

    p_show = sub.add_parser("show", help="show CVE record from cache/public source")
    p_show.add_argument("cve")
    p_show.add_argument("--refresh", action="store_true")
    p_show.add_argument("--json", action="store_true")
    p_show.set_defaults(func=cmd_show)

    p_apply = sub.add_parser("apply", help="set active CVE reference in telemetry state")
    p_apply.add_argument("cve")
    p_apply.set_defaults(func=cmd_apply)

    p_unload = sub.add_parser("unload", help="remove one CVE (or all) from loaded telemetry CVE list")
    p_unload.add_argument("cve", nargs="?")
    p_unload.add_argument("--all", action="store_true")
    p_unload.set_defaults(func=cmd_unload)

    p_active = sub.add_parser("list-active", help="show active + loaded CVE references from telemetry state")
    p_active.add_argument("--json", action="store_true")
    p_active.set_defaults(func=cmd_list_active)

    p_scaffold = sub.add_parser("scaffold", help="create a CVE-dedicated exploit module scaffold for agent customization")
    p_scaffold.add_argument("cve")
    p_scaffold.add_argument("--name", required=True, help="short module name, e.g. auth-bypass-check")
    p_scaffold.add_argument("--group", default="Exploit")
    p_scaffold.add_argument("--runtime", choices=["kali", "local"], default="kali")
    p_scaffold.add_argument("--force", action="store_true")
    p_scaffold.set_defaults(func=cmd_scaffold)

    p_list = sub.add_parser("list", help="list cached CVE records")
    p_list.add_argument("--json", action="store_true")
    p_list.set_defaults(func=cmd_list)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
