#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
TELEMETRY = ROOT / "telemetry"
RUNS_DIR = TELEMETRY / "runs"
ARTIFACTS = ROOT / "artifacts"
ARTIFACT_RUNS_DIR = ARTIFACTS / "runs"


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


def looks_like_telemetry_dir(path: Path) -> bool:
    required = ["state.json", "commands.jsonl", "findings.jsonl", "loot.jsonl"]
    return all((path / name).exists() for name in required)


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


def snapshot_current_telemetry() -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = RUNS_DIR / stamp
    dest.mkdir(parents=True, exist_ok=True)
    for name in ["state.json", "commands.jsonl", "findings.jsonl", "loot.jsonl", "exploits.jsonl"]:
        src = TELEMETRY / name
        if src.exists():
            shutil.copy2(src, dest / name)
    return dest


def cmd_snapshot(_: argparse.Namespace) -> int:
    dest = snapshot_current_telemetry()
    print(dest)
    return 0


def clear_live_streams() -> None:
    TELEMETRY.mkdir(parents=True, exist_ok=True)
    for name in ["commands.jsonl", "findings.jsonl", "loot.jsonl", "exploits.jsonl"]:
        (TELEMETRY / name).write_text("", encoding="utf-8")


def archive_and_clear_artifacts(run_id: str) -> None:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    ARTIFACT_RUNS_DIR.mkdir(parents=True, exist_ok=True)
    destination = ARTIFACT_RUNS_DIR / run_id
    destination.mkdir(parents=True, exist_ok=True)

    # Archive everything from live artifacts except historical runs.
    for entry in ARTIFACTS.iterdir():
        if entry.name == "runs":
            continue
        if entry.name == ".gitkeep":
            continue
        target = destination / entry.name
        if entry.is_dir():
            shutil.copytree(entry, target, dirs_exist_ok=True)
        else:
            shutil.copy2(entry, target)

    # Clear live artifacts for the next campaign, keep runs folder.
    for entry in ARTIFACTS.iterdir():
        if entry.name == "runs":
            continue
        if entry.is_dir():
            shutil.rmtree(entry, ignore_errors=True)
        else:
            entry.unlink(missing_ok=True)
    (ARTIFACTS / ".gitkeep").touch(exist_ok=True)


def preserve_target_state() -> None:
    state_path = TELEMETRY / "state.json"
    state: dict[str, Any]
    if state_path.exists():
        state = read_json(state_path)
    else:
        state = {}
    state["phase"] = "campaign"
    state["status"] = "ready"
    state["updated_at"] = datetime.now(timezone.utc).isoformat()
    state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")


def cmd_new_campaign(_: argparse.Namespace) -> int:
    run_dir = snapshot_current_telemetry()
    clear_live_streams()
    archive_and_clear_artifacts(run_dir.name)
    preserve_target_state()
    print(json.dumps({
        "status": "ok",
        "campaign": "fresh",
        "archived_run": run_dir.name,
        "telemetry_reset": True,
        "artifacts_archived_to": str(ARTIFACT_RUNS_DIR / run_dir.name),
    }, indent=2))
    return 0


def infer_run_id(path: Path) -> str:
    name = path.name.strip()
    if re.match(r"^\d{8}T\d{6}Z$", name):
        return name
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def unique_run_dest(run_id: str) -> Path:
    destination = RUNS_DIR / run_id
    index = 1
    while destination.exists():
        destination = RUNS_DIR / f"{run_id}-{index:02d}"
        index += 1
    return destination


def import_one(source: Path) -> dict[str, str]:
    source = source.resolve()
    if not looks_like_telemetry_dir(source):
        raise SystemExit(f"Not a telemetry campaign directory: {source}")
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    try:
        if source.samefile(RUNS_DIR) or source.parent.samefile(RUNS_DIR):
            return {"source": str(source), "destination": str(source), "status": "already-local"}
    except FileNotFoundError:
        pass
    run_id = infer_run_id(source)
    dest = unique_run_dest(run_id)
    shutil.copytree(source, dest)
    return {"source": str(source), "destination": str(dest), "status": "imported"}


def candidate_runs_from(path: Path) -> list[Path]:
    path = path.resolve()
    if looks_like_telemetry_dir(path):
        return [path]
    if (path / "runs").is_dir():
        return [entry for entry in sorted((path / "runs").iterdir()) if entry.is_dir() and looks_like_telemetry_dir(entry)]
    if path.is_dir():
        return [entry for entry in sorted(path.iterdir()) if entry.is_dir() and looks_like_telemetry_dir(entry)]
    return []


def cmd_import_run(args: argparse.Namespace) -> int:
    source = Path(args.path).expanduser()
    candidates = candidate_runs_from(source)
    if not candidates:
        raise SystemExit(f"No telemetry campaign directories found at: {source}")
    if len(candidates) > 1 and not args.all:
        # Import latest when multiple candidates exist unless --all is set.
        candidates = [candidates[-1]]
    imported = [import_one(path) for path in candidates]
    print(json.dumps({
        "status": "ok",
        "imported_count": len(imported),
        "results": imported,
    }, indent=2))
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Telemetry run management for TUI/CLI replay.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="List replay runs")

    show = sub.add_parser("show", help="Show summary for one replay run")
    show.add_argument("--run", default="latest", help="Run id (timestamp dir) or latest")

    sub.add_parser("snapshot", help="Snapshot current telemetry into telemetry/runs")
    sub.add_parser("new-campaign", help="Archive current run and reset live telemetry/artifacts while preserving target scope")
    import_run = sub.add_parser("import-run", help="Import telemetry campaign directory (or runs folder) into telemetry/runs")
    import_run.add_argument("--path", required=True, help="Path to campaign dir, telemetry dir, or runs dir")
    import_run.add_argument("--all", action="store_true", help="Import all campaigns when path contains multiple runs")

    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.cmd == "list":
        return cmd_list(args)
    if args.cmd == "show":
        return cmd_show(args)
    if args.cmd == "snapshot":
        return cmd_snapshot(args)
    if args.cmd == "new-campaign":
        return cmd_new_campaign(args)
    if args.cmd == "import-run":
        return cmd_import_run(args)
    raise SystemExit(f"Unknown command: {args.cmd}")


if __name__ == "__main__":
    raise SystemExit(main())
