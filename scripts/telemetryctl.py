#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
TELEMETRY = ROOT / "telemetry"
RUNS_DIR = TELEMETRY / "runs"


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def count_jsonl(path: Path) -> int:
    if not path.exists():
        return 0
    count = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            count += 1
    return count


def run_paths() -> list[Path]:
    if not RUNS_DIR.exists():
        return []
    runs: list[Path] = []
    for entry in RUNS_DIR.iterdir():
        if not entry.is_dir():
            continue
        if (entry / "state.json").exists():
            runs.append(entry)
    runs.sort(key=lambda p: p.name, reverse=True)
    return runs


def summarize_run(run_dir: Path) -> dict[str, Any]:
    state = read_json(run_dir / "state.json")
    return {
        "run": run_dir.name,
        "target_name": state.get("target_name", "unknown"),
        "target_url": state.get("target_url", "unknown"),
        "target_kind": state.get("target_kind", "unknown"),
        "phase": state.get("phase", "unknown"),
        "status": state.get("status", "unknown"),
        "commands": count_jsonl(run_dir / "commands.jsonl"),
        "findings": count_jsonl(run_dir / "findings.jsonl"),
        "loot": count_jsonl(run_dir / "loot.jsonl"),
        "exploits": count_jsonl(run_dir / "exploits.jsonl"),
    }


def cmd_list(_: argparse.Namespace) -> int:
    runs = run_paths()
    if not runs:
        print("No telemetry runs found.")
        return 0
    for run in runs:
        summary = summarize_run(run)
        print(
            f"{summary['run']} | {summary['target_name']} | {summary['target_url']} | "
            f"cmd={summary['commands']} finding={summary['findings']} loot={summary['loot']} exploit={summary['exploits']}"
        )
    return 0


def resolve_run(run: str) -> Path:
    runs = run_paths()
    if run == "latest":
        if not runs:
            raise SystemExit("No telemetry runs available")
        return runs[0]
    path = RUNS_DIR / run
    if not path.exists():
        raise SystemExit(f"Run not found: {run}")
    return path


def cmd_show(args: argparse.Namespace) -> int:
    run_dir = resolve_run(args.run)
    summary = summarize_run(run_dir)
    print(json.dumps(summary, indent=2))
    return 0


def cmd_snapshot(_: argparse.Namespace) -> int:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = RUNS_DIR / stamp
    dest.mkdir(parents=True, exist_ok=True)
    for name in ["state.json", "commands.jsonl", "findings.jsonl", "loot.jsonl", "exploits.jsonl"]:
        src = TELEMETRY / name
        if src.exists():
            shutil.copy2(src, dest / name)
    print(dest)
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Telemetry run management for TUI/CLI replay.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="List replay runs")

    show = sub.add_parser("show", help="Show summary for one replay run")
    show.add_argument("--run", default="latest", help="Run id (timestamp dir) or latest")

    sub.add_parser("snapshot", help="Snapshot current telemetry into telemetry/runs")

    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.cmd == "list":
        return cmd_list(args)
    if args.cmd == "show":
        return cmd_show(args)
    if args.cmd == "snapshot":
        return cmd_snapshot(args)
    raise SystemExit(f"Unknown command: {args.cmd}")


if __name__ == "__main__":
    raise SystemExit(main())
