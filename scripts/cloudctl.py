#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import error, request

ROOT = Path(__file__).resolve().parent.parent
TELEMETRY = ROOT / "telemetry"
CLOUD_STATE = TELEMETRY / "cloud_jobs.json"

DEFAULT_BASE_URL = os.getenv("H3RETIK_CLOUD_API", "").strip()
DEFAULT_CHAIN = os.getenv("H3RETIK_CHAIN", "base")
DEFAULT_RECEIVER = os.getenv("H3RETIK_PAYMENT_RECEIVER", "0x99EEDcE3C87Adf3dE1c9B8B08F1810C168D6E039")
DEFAULT_TIMEOUT = int(os.getenv("H3RETIK_CLOUD_TIMEOUT", "20"))

LANES = {"web", "local", "osint", "onchain"}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_state() -> dict[str, Any]:
    TELEMETRY.mkdir(parents=True, exist_ok=True)
    if not CLOUD_STATE.exists():
        state = {"jobs": {}}
        CLOUD_STATE.write_text(json.dumps(state, indent=2), encoding="utf-8")
        return state
    try:
        return json.loads(CLOUD_STATE.read_text(encoding="utf-8"))
    except Exception:
        return {"jobs": {}}


def save_state(state: dict[str, Any]) -> None:
    TELEMETRY.mkdir(parents=True, exist_ok=True)
    CLOUD_STATE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def parse_kv(items: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise SystemExit(f"invalid --arg '{item}', expected key=value")
        key, value = item.split("=", 1)
        key = key.strip()
        if not key:
            raise SystemExit(f"invalid --arg '{item}', key is empty")
        out[key] = value
    return out


def validate_target(target: str) -> str:
    value = target.strip()
    if not value:
        raise SystemExit("--target is required")
    if value.lower().startswith(("http://", "https://")):
        return value
    if re.match(r"^[a-zA-Z0-9._:-]+$", value):
        return value
    raise SystemExit("invalid --target format")


def build_spec(args: argparse.Namespace) -> dict[str, Any]:
    lane = args.lane.strip().lower()
    if lane not in LANES:
        raise SystemExit(f"invalid --lane '{args.lane}', must be one of: {','.join(sorted(LANES))}")
    return {
        "target": validate_target(args.target),
        "lane": lane,
        "module": (args.module or "").strip(),
        "pipeline": (args.pipeline or "").strip(),
        "args": parse_kv(args.arg or []),
        "budget_usdc": float(args.budget_usdc),
        "max_minutes": int(args.max_minutes),
        "json": bool(args.json),
    }


def estimate_cost(spec: dict[str, Any]) -> dict[str, Any]:
    lane_mult = {"web": 1.0, "local": 1.3, "osint": 0.8, "onchain": 1.1}
    base_fee = 0.05
    minute_rate = 0.04 * lane_mult.get(spec["lane"], 1.0)
    args_factor = 0.01 * min(10, len(spec.get("args", {})))
    estimate = round(base_fee + (minute_rate * spec["max_minutes"]) + args_factor, 4)
    return {
        "currency": "USDC",
        "estimated_usdc": estimate,
        "pricing": {
            "base_fee": base_fee,
            "minute_rate": round(minute_rate, 4),
            "args_factor": round(args_factor, 4),
            "max_minutes": spec["max_minutes"],
        },
    }


def http_call(base_url: str, method: str, path: str, payload: dict[str, Any] | None) -> dict[str, Any]:
    if not base_url:
        raise RuntimeError("cloud API endpoint not configured; set H3RETIK_CLOUD_API")
    url = base_url.rstrip("/") + path
    body = None
    headers = {"Content-Type": "application/json"}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
    req = request.Request(url, method=method.upper(), data=body, headers=headers)
    try:
        with request.urlopen(req, timeout=DEFAULT_TIMEOUT) as resp:
            raw = resp.read().decode("utf-8")
    except error.HTTPError as exc:
        msg = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"cloud API error {exc.code}: {msg}") from exc
    except Exception as exc:
        raise RuntimeError(f"cloud API request failed: {exc}") from exc
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except Exception:
        return {"raw": raw}


def print_out(data: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(data, ensure_ascii=True))
    else:
        print(json.dumps(data, indent=2, ensure_ascii=True))


def cmd_estimate(args: argparse.Namespace) -> int:
    spec = build_spec(args)
    payload = {"spec": spec, "chain": DEFAULT_CHAIN}
    if args.mock:
        out = {"ok": True, "quote": estimate_cost(spec), "spec": spec, "mode": "mock"}
    else:
        try:
            out = http_call(args.api, "POST", "/v1/jobs/quote", payload)
        except RuntimeError as exc:
            raise SystemExit(str(exc))
    print_out(out, args.json)
    return 0


def cmd_submit(args: argparse.Namespace) -> int:
    spec = build_spec(args)
    state = ensure_state()
    job_id = f"job-{uuid.uuid4().hex[:12]}"
    quote = estimate_cost(spec)
    payment = {
        "chain": DEFAULT_CHAIN,
        "asset": "USDC",
        "receiver": DEFAULT_RECEIVER,
        "amount": quote["estimated_usdc"],
        "memo": job_id,
    }
    job = {
        "job_id": job_id,
        "created_at": now(),
        "status": "pending_payment",
        "spec": spec,
        "quote": quote,
        "payment": payment,
        "tx_hash": "",
        "remote": bool(args.api and not args.mock),
        "logs": [],
        "artifacts": [],
    }
    state.setdefault("jobs", {})[job_id] = job
    save_state(state)

    if args.mock or not args.api:
        out = {"ok": True, "job_id": job_id, "status": "pending_payment", "payment": payment, "quote": quote, "mode": "mock"}
        print_out(out, args.json)
        return 0

    try:
        resp = http_call(args.api, "POST", "/v1/jobs", {"job_id": job_id, "spec": spec, "quote": quote, "payment": payment})
    except RuntimeError as exc:
        raise SystemExit(str(exc))
    out = {"ok": True, "job_id": job_id, "status": "pending_payment", "payment": payment, "quote": quote, "cloud": resp}
    print_out(out, args.json)
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    state = ensure_state()
    job = state.get("jobs", {}).get(args.job)
    if job is None:
        if not args.api:
            raise SystemExit(f"job not found: {args.job}")
        try:
            out = http_call(args.api, "GET", f"/v1/jobs/{args.job}", None)
        except RuntimeError as exc:
            raise SystemExit(str(exc))
        print_out(out, args.json)
        return 0

    out = {"ok": True, "job": job}
    if args.api and job.get("remote"):
        try:
            out["cloud"] = http_call(args.api, "GET", f"/v1/jobs/{args.job}", None)
        except RuntimeError:
            pass
    print_out(out, args.json)
    return 0


def cmd_logs(args: argparse.Namespace) -> int:
    state = ensure_state()
    job = state.get("jobs", {}).get(args.job)
    if job is None and not args.api:
        raise SystemExit(f"job not found: {args.job}")
    lines = []
    if job is not None:
        lines.extend(job.get("logs", []))
    cloud = None
    if args.api:
        try:
            cloud = http_call(args.api, "GET", f"/v1/jobs/{args.job}/logs", None)
        except RuntimeError:
            cloud = None
    out = {"ok": True, "job_id": args.job, "logs": lines, "cloud": cloud}
    print_out(out, args.json)
    return 0


def cmd_artifacts(args: argparse.Namespace) -> int:
    state = ensure_state()
    job = state.get("jobs", {}).get(args.job)
    if job is None and not args.api:
        raise SystemExit(f"job not found: {args.job}")
    artifacts = []
    if job is not None:
        artifacts.extend(job.get("artifacts", []))
    cloud = None
    if args.api:
        try:
            cloud = http_call(args.api, "GET", f"/v1/jobs/{args.job}/artifacts", None)
        except RuntimeError:
            cloud = None
    out = {"ok": True, "job_id": args.job, "artifacts": artifacts, "cloud": cloud}
    print_out(out, args.json)
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    spec = build_spec(args)
    quote = estimate_cost(spec)
    if spec["budget_usdc"] < quote["estimated_usdc"]:
        raise SystemExit(f"budget too low: budget={spec['budget_usdc']} estimated={quote['estimated_usdc']}")

    # run = submit + mock immediate completion in local mode, or full remote flow when API configured
    submit_args = argparse.Namespace(**vars(args))
    submit_args.json = True
    submit_args.mock = args.mock or not bool(args.api)

    state = ensure_state()
    job_id = f"job-{uuid.uuid4().hex[:12]}"
    job = {
        "job_id": job_id,
        "created_at": now(),
        "status": "running" if submit_args.mock else "pending_payment",
        "spec": spec,
        "quote": quote,
        "payment": {
            "chain": DEFAULT_CHAIN,
            "asset": "USDC",
            "receiver": DEFAULT_RECEIVER,
            "amount": quote["estimated_usdc"],
            "memo": job_id,
        },
        "tx_hash": "",
        "remote": bool(args.api and not submit_args.mock),
        "logs": [f"{now()} run started lane={spec['lane']} target={spec['target']}"] if submit_args.mock else [],
        "artifacts": [{"name": "summary.json", "kind": "report", "path": f"artifacts/cloud/{job_id}/summary.json"}] if submit_args.mock else [],
    }
    if submit_args.mock:
        time.sleep(0.05)
        job["status"] = "succeeded"
        job["finished_at"] = now()
        job["logs"].append(f"{now()} run completed")
    state.setdefault("jobs", {})[job_id] = job
    save_state(state)

    if not submit_args.mock:
        try:
            cloud_submit = http_call(args.api, "POST", "/v1/jobs", {"job_id": job_id, "spec": spec, "quote": quote, "payment": job["payment"]})
        except RuntimeError as exc:
            raise SystemExit(str(exc))
        out = {"ok": True, "job_id": job_id, "status": "pending_payment", "payment": job["payment"], "quote": quote, "cloud": cloud_submit}
        print_out(out, args.json)
        return 0

    out = {"ok": True, "job_id": job_id, "status": "succeeded", "mode": "mock", "quote": quote, "artifacts": job["artifacts"]}
    print_out(out, args.json)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="h3retik cloud command interface")
    parser.add_argument("command", choices=["run", "estimate", "submit", "status", "logs", "artifacts"])
    parser.add_argument("--api", default=DEFAULT_BASE_URL, help="cloud API base URL (e.g. https://api.example.com)")
    parser.add_argument("--mock", action="store_true", help="mock mode (no API calls)")
    parser.add_argument("--json", action="store_true", help="emit compact JSON")
    parser.add_argument("--target", default="", help="target URL/host")
    parser.add_argument("--lane", default="web", help="lane: web|local|osint|onchain")
    parser.add_argument("--module", default="", help="module ID")
    parser.add_argument("--pipeline", default="", help="pipeline ID")
    parser.add_argument("--arg", action="append", default=[], help="module/pipeline arg key=value")
    parser.add_argument("--budget-usdc", type=float, default=5.0, help="max budget for this operation")
    parser.add_argument("--max-minutes", type=int, default=10, help="runtime ceiling")
    parser.add_argument("--job", default="", help="job id for status/logs/artifacts")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command in {"run", "estimate", "submit"} and not args.target:
        raise SystemExit("--target is required for run/estimate/submit")
    if args.command in {"status", "logs", "artifacts"} and not args.job:
        raise SystemExit("--job is required for status/logs/artifacts")

    if args.command == "run":
        return cmd_run(args)
    if args.command == "estimate":
        return cmd_estimate(args)
    if args.command == "submit":
        return cmd_submit(args)
    if args.command == "status":
        return cmd_status(args)
    if args.command == "logs":
        return cmd_logs(args)
    if args.command == "artifacts":
        return cmd_artifacts(args)
    raise SystemExit(2)


if __name__ == "__main__":
    sys.exit(main())
