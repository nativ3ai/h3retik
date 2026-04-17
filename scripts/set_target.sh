#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ $# -eq 0 ]]; then
  echo "Usage: ./scripts/set_target.sh --kind custom --url http://target | --kind cve-bench --task CVE-YYYY-NNNN" >&2
  exit 1
fi

python3 "$ROOT/scripts/targetctl.py" set "$@"
