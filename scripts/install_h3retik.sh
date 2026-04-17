#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$(cat "$ROOT/VERSION" 2>/dev/null || echo "0.0.1")"

INSTALL_BASE="${H3RETIK_INSTALL_BASE:-$HOME/.local/share/h3retik}"
INSTALL_ROOT="${H3RETIK_INSTALL_ROOT:-$INSTALL_BASE/$VERSION}"
BIN_DIR="${H3RETIK_BIN_DIR:-$HOME/.local/bin}"
LAUNCHER="$BIN_DIR/h3retik"

mkdir -p "$INSTALL_ROOT" "$BIN_DIR"

rm -rf "$INSTALL_ROOT"
mkdir -p "$INSTALL_ROOT"

copy_items=(
  "Dockerfile.kali"
  "README.md"
  "VERSION"
  "docker-compose.yml"
  "h3retik"
  "SKILL.md"
  "go.mod"
  "go.sum"
  "assets"
  "cmd"
  "docs"
  "kali-headless"
  "modules"
  "scripts"
)

for item in "${copy_items[@]}"; do
  if [[ -e "$ROOT/$item" ]]; then
    cp -R "$ROOT/$item" "$INSTALL_ROOT/"
  fi
done

mkdir -p "$INSTALL_ROOT/telemetry" "$INSTALL_ROOT/artifacts" "$INSTALL_ROOT/bin"
touch "$INSTALL_ROOT/artifacts/.gitkeep"

cat >"$LAUNCHER" <<EOF
#!/usr/bin/env bash
set -euo pipefail
export H3RETIK_ROOT="$INSTALL_ROOT"
exec "$INSTALL_ROOT/h3retik" "\$@"
EOF
chmod +x "$LAUNCHER"
chmod +x "$INSTALL_ROOT/h3retik" "$INSTALL_ROOT/scripts/start_lab.sh" "$INSTALL_ROOT/scripts/reset_lab.sh" "$INSTALL_ROOT/scripts/install_h3retik.sh"

if command -v go >/dev/null 2>&1; then
  (cd "$INSTALL_ROOT" && ./h3retik build >/dev/null)
fi

echo "h3retik v$VERSION installed at: $INSTALL_ROOT"
echo "launcher created: $LAUNCHER"
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
  echo ""
  echo "Add to your shell profile:"
  echo "  export PATH=\"$BIN_DIR:\$PATH\""
fi
echo ""
echo "Next:"
echo "  h3retik up"
echo "  h3retik"
