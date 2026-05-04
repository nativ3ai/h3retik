#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${H3RETIK_REPO_URL:-https://github.com/nativ3ai/h3retik.git}"
SRC_DIR="${H3RETIK_SRC_DIR:-$HOME/.local/src/h3retik}"

command -v git >/dev/null 2>&1 || { echo "h3retik bootstrap: git is required" >&2; exit 1; }
command -v bash >/dev/null 2>&1 || { echo "h3retik bootstrap: bash is required" >&2; exit 1; }

mkdir -p "$(dirname "$SRC_DIR")"

if [[ -d "$SRC_DIR/.git" ]]; then
  git -C "$SRC_DIR" fetch --all --prune
  git -C "$SRC_DIR" checkout main
  git -C "$SRC_DIR" pull --ff-only
else
  rm -rf "$SRC_DIR"
  git clone "$REPO_URL" "$SRC_DIR"
fi

"$SRC_DIR/scripts/install_h3retik.sh"

echo ""
echo "Bootstrap complete."
echo "Run:"
echo "  export PATH=\"$HOME/.local/bin:\$PATH\""
echo "  h3retik          # launches guided setup wizard on first run"
echo "  # then follow wizard: bundled kali / attach existing container / local-only mode"
