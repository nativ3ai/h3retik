#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

rm -f telemetry/*.json telemetry/*.jsonl telemetry/*.log
mkdir -p telemetry artifacts
touch artifacts/.gitkeep

docker compose up -d kali >/dev/null 2>&1 || true
python3 "$ROOT/scripts/targetctl.py" set --kind custom --url http://127.0.0.1

python3 - <<'PY'
import json
from pathlib import Path
state_path = Path("telemetry/state.json")
state = json.loads(state_path.read_text(encoding="utf-8"))
state["phase"] = "reset"
state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")
PY

echo "Target reset on http://127.0.0.1"
