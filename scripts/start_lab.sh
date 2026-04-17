#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ $# -eq 0 ]]; then
  set -- --kind custom --url http://127.0.0.1
fi

python3 "$ROOT/scripts/targetctl.py" start "$@"
