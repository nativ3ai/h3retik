#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROMO_DIR="$ROOT/scripts/promo"
OUT_DIR="$PROMO_DIR/out"
mkdir -p "$OUT_DIR"

if ! command -v ffmpeg >/dev/null 2>&1; then
  echo "ffmpeg missing" >&2
  exit 1
fi

VERT_DIR="$OUT_DIR/frames_vertical"
MAIN_DIR="$OUT_DIR/frames_main"
rm -rf "$VERT_DIR" "$MAIN_DIR"

python3 "$PROMO_DIR/render_promo_frames.py" \
  --width 1080 --height 1920 \
  --out-dir "$VERT_DIR" \
  --ascii-json "$ROOT/assets/skull_pixel_loading_frames.json"

python3 "$PROMO_DIR/render_promo_frames.py" \
  --width 1920 --height 1080 \
  --out-dir "$MAIN_DIR" \
  --ascii-json "$ROOT/assets/skull_pixel_loading_frames.json"

ffmpeg -y -framerate 30 -i "$VERT_DIR/frame_%05d.png" -c:v libx264 -pix_fmt yuv420p -crf 20 -preset medium "$OUT_DIR/promo_h3retik_short.mp4"
ffmpeg -y -framerate 30 -i "$MAIN_DIR/frame_%05d.png" -c:v libx264 -pix_fmt yuv420p -crf 20 -preset medium "$OUT_DIR/promo_h3retik_main.mp4"

echo "Rendered:"
echo "  $OUT_DIR/promo_h3retik_short.mp4"
echo "  $OUT_DIR/promo_h3retik_main.mp4"
