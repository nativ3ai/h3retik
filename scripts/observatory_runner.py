#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
TELEMETRY = ROOT / "telemetry"
STATE_PATH = TELEMETRY / "state.json"
COMMANDS_PATH = TELEMETRY / "commands.jsonl"
TARGETCTL = ROOT / "scripts" / "targetctl.py"
SECURITY_PIPELINE = ROOT / "scripts" / "security_pipeline.py"


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def append_jsonl(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(data, ensure_ascii=True) + "\n")


def command_id() -> str:
    return f"cmd-{datetime.now(timezone.utc).timestamp():.6f}".replace(".", "")


def read_state() -> dict[str, Any]:
    if not STATE_PATH.exists():
        return {
            "lab_name": "Black Box Observatory Lab",
            "target_name": "Custom Blackbox Target",
            "target_url": "http://127.0.0.1",
            "docker_target": "http://127.0.0.1",
            "network": "custom",
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
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state, indent=2), encoding="utf-8")


def update_state(**updates: object) -> dict[str, Any]:
    state = read_state()
    state.update(updates)
    write_state(state)
    return state


def run_logged(phase: str, tool: str, command: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    cid = command_id()
    display = subprocess.list2cmdline(command)
    append_jsonl(
        COMMANDS_PATH,
        {
            "command_id": cid,
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
    started = datetime.now(timezone.utc)
    proc = subprocess.run(command, cwd=str(cwd) if cwd else None, capture_output=True, text=True, check=False)
    duration_ms = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)
    preview = (proc.stdout + ("\n" + proc.stderr if proc.stderr else "")).strip()[:4000]
    append_jsonl(
        COMMANDS_PATH,
        {
            "command_id": cid,
            "timestamp": now(),
            "phase": phase,
            "tool": tool,
            "command": display,
            "status": "ok" if proc.returncode == 0 else "error",
            "exit_code": proc.returncode,
            "duration_ms": duration_ms,
            "output_preview": preview,
        },
    )
    return proc


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generic observatory runner (target-agnostic).")
    parser.add_argument("--kind", choices=["active", "custom", "cve-bench"], default="active")
    parser.add_argument("--task", help="CVE-Bench task id when --kind cve-bench")
    parser.add_argument("--url", help="Custom target URL for --kind custom")
    parser.add_argument("--strategy", choices=["auto", "recon", "solution"], default="auto")
    parser.add_argument("--start", action="store_true", help="Start and verify target profile before run")
    parser.add_argument("--no-build", action="store_true", help="Skip CVE-Bench image build")
    return parser.parse_args(argv)


def resolve_target(args: argparse.Namespace) -> dict[str, Any]:
    if args.kind == "active":
        return read_state()
    if args.kind == "custom":
        if not args.url:
            raise SystemExit("--url is required with --kind custom")
        cmd = [sys.executable, str(TARGETCTL), "set", "--kind", "custom", "--url", args.url]
        if args.start:
            cmd[2] = "start"
        proc = subprocess.run(cmd, cwd=str(ROOT), check=False)
        if proc.returncode != 0:
            raise SystemExit(proc.returncode)
        return read_state()
    if not args.task:
        raise SystemExit("--task is required with --kind cve-bench")
    cmd = [sys.executable, str(TARGETCTL), "set", "--kind", "cve-bench", "--task", args.task]
    if args.start:
        cmd[2] = "start"
        if args.no_build:
            cmd.append("--no-build")
    proc = subprocess.run(cmd, cwd=str(ROOT), check=False)
    if proc.returncode != 0:
        raise SystemExit(proc.returncode)
    return read_state()


def strategy_to_pipeline(strategy: str) -> str:
    if strategy == "recon":
        return "surface-map"
    if strategy == "solution":
        return "full-chain"
    return "vuln-sweep"


def run_generic_observatory(state: dict[str, Any], strategy: str) -> int:
    target_url = str(state.get("target_url", "")).strip() or "http://127.0.0.1"
    pipeline = strategy_to_pipeline(strategy)
    update_state(status="running", phase=f"observatory-{strategy}")
    proc = run_logged(
        phase="observatory",
        tool="security_pipeline",
        command=[sys.executable, str(SECURITY_PIPELINE), "--target", target_url, "--pipeline", pipeline],
        cwd=ROOT,
    )
    if proc.returncode == 0:
        update_state(status="completed", phase=f"observatory-{strategy}-done")
        return 0
    update_state(status="failed", phase=f"observatory-{strategy}-failed")
    return proc.returncode


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    state = resolve_target(args)
    return run_generic_observatory(state, args.strategy)


if __name__ == "__main__":
    raise SystemExit(main())

