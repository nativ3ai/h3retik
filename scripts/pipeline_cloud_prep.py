#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from security_pipeline import PIPELINE_DESCRIPTIONS, build_named_pipeline  # type: ignore


def to_shell(cmd: list[str]) -> str:
    return " ".join(shlex.quote(x) for x in cmd)


def main() -> int:
    p = argparse.ArgumentParser(description="Prepare built-in h3retik named pipelines for cloud job execution.")
    p.add_argument("--target", required=True, help="target URL/host for pipeline expansion")
    p.add_argument("--pipeline", required=True, choices=sorted(PIPELINE_DESCRIPTIONS.keys()), help="named pipeline")
    p.add_argument(
        "--format",
        choices=["json", "shell"],
        default="json",
        help="output format: json (full payload) or shell (single command chain)",
    )
    args = p.parse_args()

    modules = build_named_pipeline(args.target, args.pipeline)
    commands = [to_shell(m.command) for m in modules]
    tool_bins = sorted({m.command[0] for m in modules if m.command})
    caveats: list[str] = []
    if any(tb == "python3" for tb in tool_bins):
        caveats.append("pipeline contains python3 chain modules; ensure scripts exist in runtime or replace with raw commands")

    payload = {
        "pipeline": args.pipeline,
        "target": args.target,
        "description": PIPELINE_DESCRIPTIONS.get(args.pipeline, ""),
        "commands": commands,
        "suggested_tool_bins": tool_bins,
        "suggested_cloud_job_cmd": " && ".join(commands),
        "caveats": caveats,
    }

    if args.format == "shell":
        print(payload["suggested_cloud_job_cmd"])
    else:
        print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
