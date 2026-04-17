#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parent.parent
TELEMETRY = ROOT / "telemetry"
ARTIFACTS = ROOT / "artifacts"
STATE_PATH = TELEMETRY / "state.json"
CVEBENCH_ROOT = ROOT / "external" / "cve-bench"
LOCAL_UV_IMAGE = "local/uv:0.9"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Manage the active observatory target.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    for name in ("set", "start"):
        sub = subparsers.add_parser(name)
        sub.add_argument("--kind", choices=["cve-bench", "custom"], required=True)
        sub.add_argument("--task", help="CVE-Bench task id, e.g. CVE-2024-2624")
        sub.add_argument("--url", help="Custom target URL, e.g. http://127.0.0.1:8080")
        sub.add_argument("--no-build", action="store_true", help="Skip CVE-Bench image build when starting a task")

    info = subparsers.add_parser("info")
    info.add_argument("--kind", choices=["cve-bench", "custom"], required=True)
    info.add_argument("--task", help="CVE-Bench task id, e.g. CVE-2024-2624")
    info.add_argument("--url", help="Custom target URL, e.g. http://127.0.0.1:8080")

    return parser.parse_args()


def ensure_dirs() -> None:
    TELEMETRY.mkdir(parents=True, exist_ok=True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)


def read_cvebench_metadata(task: str) -> dict[str, str]:
    path = CVEBENCH_ROOT / "src" / "critical" / "metadata" / f"{task}.yml"
    if not path.exists():
        raise SystemExit(f"Missing CVE-Bench metadata: {path}")
    data: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or ": " not in line:
            continue
        key, value = line.split(": ", 1)
        data[key.strip()] = value.strip()
    if "application_url" not in data:
        raise SystemExit(f"application_url missing from {path}")
    return data


def host_url_from_application_url(application_url: str) -> str:
    service, rest = application_url.split(":", 1)
    port, _, suffix = rest.partition("/")
    path = f"/{suffix}" if suffix else ""
    if service == "target":
        host_port = "9090"
    else:
        host_port = port
    return f"http://127.0.0.1:{host_port}{path}"


def normalize_custom_url(raw: str | None) -> str:
    value = (raw or "").strip()
    if not value:
        raise SystemExit("--url is required for --kind custom")
    if "://" not in value:
        value = "http://" + value
    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        raise SystemExit(f"Invalid --url value: {raw!r}")
    return value


def state_for_target(kind: str, task: str | None, url: str | None) -> dict[str, object]:
    if kind == "custom":
        target_url = normalize_custom_url(url)
        parsed = urlparse(target_url)
        return {
            "lab_name": "Black Box Observatory Lab",
            "target_name": "Custom Blackbox Target",
            "target_url": target_url,
            "docker_target": target_url,
            "network": parsed.hostname or "custom",
            "target_kind": "custom",
            "target_id": target_url,
            "status": "idle",
            "phase": "waiting",
            "last_updated": "",
            "services": [],
        }
    if not task:
        raise SystemExit("--task is required for cve-bench")
    meta = read_cvebench_metadata(task)
    application_url = meta["application_url"]
    return {
        "lab_name": "Black Box Observatory Lab",
        "target_name": f"CVE-Bench {task}",
        "target_url": host_url_from_application_url(application_url),
        "docker_target": f"http://{application_url}",
        "network": f"{task.lower()}_default",
        "target_kind": "cve-bench",
        "target_id": task,
        "status": "idle",
        "phase": "waiting",
        "last_updated": "",
        "services": [],
    }


def write_state(state: dict[str, object]) -> None:
    ensure_dirs()
    STATE_PATH.write_text(json.dumps(state, indent=2), encoding="utf-8")


def cvebench_env() -> dict[str, str]:
    env = dict(os.environ)
    env.setdefault("PYTHONPATH", "src")
    env.setdefault("CVEBENCH_TAG", "2.1.0")
    env.setdefault("CVEBENCH_UV_IMAGE", LOCAL_UV_IMAGE)
    env.setdefault("DOCKER_DEFAULT_PLATFORM", "linux/amd64")
    return env


def run(cmd: list[str], cwd: Path | None = None, env: dict[str, str] | None = None) -> None:
    proc = subprocess.run(cmd, cwd=str(cwd) if cwd else None, env=env, check=False)
    if proc.returncode != 0:
        raise SystemExit(proc.returncode)


def run_capture(
    cmd: list[str],
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def ensure_cvebench_checkout() -> None:
    if not (CVEBENCH_ROOT / ".git").exists():
        raise SystemExit(f"Missing CVE-Bench checkout at {CVEBENCH_ROOT}")


def ensure_local_uv_image() -> None:
    inspect = subprocess.run(
        ["docker", "image", "inspect", "--format", "{{.Os}}/{{.Architecture}}", LOCAL_UV_IMAGE],
        capture_output=True,
        text=True,
        check=False,
    )
    if inspect.returncode == 0 and inspect.stdout.strip() == "linux/amd64":
        return

    dockerfile = "\n".join(
        [
            "FROM ubuntu:24.04",
            "RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && rm -rf /var/lib/apt/lists/*",
            "RUN curl -LsSf https://astral.sh/uv/0.9.0/install.sh | sh",
            "RUN cp /root/.local/bin/uv /uv",
            "",
        ]
    )
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "Dockerfile"
        path.write_text(dockerfile, encoding="utf-8")
        run(["docker", "buildx", "build", "--platform", "linux/amd64", "--load", "-t", LOCAL_UV_IMAGE, tmpdir])


def active_cvebench_tasks() -> list[str]:
    proc = run_capture(["docker", "ps", "-a", "--format", "{{.Names}}"])
    tasks: set[str] = set()
    pattern = re.compile(r"^(cve-\d{4}-\d+)-(?:target|agent|secrets_init)-1$")
    for raw in proc.stdout.splitlines():
        match = pattern.match(raw.strip())
        if match:
            tasks.add(match.group(1).upper())
    return sorted(tasks)


def stop_other_cvebench_tasks(current_task: str) -> None:
    env = cvebench_env()
    for task in active_cvebench_tasks():
        if task == current_task:
            continue
        run(["./run", "down", task], cwd=CVEBENCH_ROOT, env=env)


def verify_cvebench_target(task: str, host_url: str, timeout_s: int = 45) -> None:
    expected_prefix = task.lower()
    deadline = time.time() + timeout_s
    last_error = "target did not become reachable"
    while time.time() < deadline:
        ps = run_capture(["docker", "ps", "--format", "{{.Names}}|{{.Status}}|{{.Ports}}"])
        target_ok = False
        port_ok = False
        for line in ps.stdout.splitlines():
            parts = (line.split("|", 2) + ["", "", ""])[:3]
            name, status, ports = parts
            if name == f"{expected_prefix}-target-1":
                target_ok = "Up" in status
                port_ok = "0.0.0.0:9090" in ports or "[::]:9090" in ports or "0.0.0.0:8080" in ports or "[::]:8080" in ports
                break
        probe = run_capture(["curl", "-fsS", "--max-time", "3", host_url])
        if probe.returncode == 0 and target_ok:
            return
        if probe.returncode != 0:
            last_error = (probe.stderr or probe.stdout or last_error).strip()
        elif not target_ok:
            last_error = "target container is not running"
        elif not port_ok:
            last_error = "target container did not bind the expected host port"
        time.sleep(1)
    raise SystemExit(f"Failed to verify {task} at {host_url}: {last_error}")


def start_target(kind: str, task: str | None, url: str | None, no_build: bool) -> dict[str, object]:
    ensure_dirs()
    run(["docker", "compose", "up", "-d", "kali"], cwd=ROOT)
    if kind == "custom":
        state = state_for_target(kind, task, url)
        probe = run_capture(["curl", "-fsS", "--max-time", "3", str(state["target_url"])])
        if probe.returncode != 0:
            raise SystemExit(f"Failed to verify custom target at {state['target_url']}: {(probe.stderr or probe.stdout).strip()}")
        return state

    ensure_cvebench_checkout()
    ensure_local_uv_image()
    env = cvebench_env()
    run(["uv", "sync", "--dev"], cwd=CVEBENCH_ROOT, env=env)
    if not task:
        raise SystemExit("--task is required for cve-bench")
    stop_other_cvebench_tasks(task)
    cmd = ["./run", "up"]
    cmd.append(task)
    if no_build:
        cmd.append("--no-build")
    run(cmd, cwd=CVEBENCH_ROOT, env=env)
    state = state_for_target(kind, task, url)
    verify_cvebench_target(task, str(state["target_url"]))
    return state


def print_target_info(kind: str, task: str | None, url: str | None) -> None:
    print(json.dumps(state_for_target(kind, task, url), indent=2))


def main() -> None:
    args = parse_args()
    if args.command == "info":
        print_target_info(args.kind, args.task, args.url)
        return
    if args.command == "set":
        state = state_for_target(args.kind, args.task, args.url)
        write_state(state)
        print(f"Active target set to {state['target_name']} at {state['target_url']}")
        return
    if args.command == "start":
        state = start_target(args.kind, args.task, args.url, args.no_build)
        write_state(state)
        print(f"Target ready: {state['target_name']} at {state['target_url']}")
        return
    raise SystemExit(f"Unknown command: {args.command}")


if __name__ == "__main__":
    main()
