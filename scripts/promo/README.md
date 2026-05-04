# h3retik Promo Renderer

Programmatic teaser video generator for h3retik.

Outputs:
- `scripts/promo/out/promo_h3retik_short.mp4` (9:16)
- `scripts/promo/out/promo_h3retik_main.mp4` (16:9)

## Run

```bash
scripts/promo/build_promo.sh
```

Requirements:
- `python3`
- `ffmpeg` (encoding only; no subtitle/drawtext filters required)
- Python Pillow (`PIL`)

## Notes

- Uses real h3retik ASCII animation source from `assets/skull_pixel_loading_frames.json`.
- Renders terminal-style command scenes + animated ASCII overlay frame-by-frame via Pillow.
- Easy to customize by editing scene text blocks in `scripts/promo/render_promo_frames.py`.
