#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

DURATION = 16.0
FPS = 30

TERM1 = """$ curl -fsSL https://h1dr4.dev/install.sh | bash
[setup] h3retik setup wizard booting...
[mode] bundled kali (recommended)
[profile] web-lite
[ok] docker + python3 + go checks passed
[ok] kali image ready
$ h3retik"""

TERM2 = """[h3retik] FIRE lane :: RECON/FINGERPRINT
$ h3retik tools install recon-plus,web-adv-plus
[ok] naabu, httpx, katana, dalfox installed
$ h3retik --headless --target scanme.nmap.org --pipeline full-chain
[run] nmap -> httpx -> nuclei -> loot export
[ok] telemetry persisted"""

TERM3 = """[h3retik cloud]
POST /h3retik/api/lease/start
POST /h3retik/api/exec
POST /h3retik/api/session/status
[ok] pay-per-job compute + scale-to-zero"""


def load_font(size: int):
    for cand in ["/System/Library/Fonts/Menlo.ttc", "Menlo.ttc", "/System/Library/Fonts/Supplemental/Courier New.ttf"]:
        try:
            return ImageFont.truetype(cand, size)
        except Exception:
            pass
    return ImageFont.load_default()


def pick_segment(t: float):
    if t < 5.2:
        return "startup wizard", TERM1
    if t < 10.8:
        return "modular lanes", TERM2
    return "cloud commands", TERM3


def draw_multiline(draw: ImageDraw.ImageDraw, x: int, y: int, text: str, font, fill, spacing=8):
    draw.multiline_text((x, y), text, font=font, fill=fill, spacing=spacing)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--width", type=int, required=True)
    ap.add_argument("--height", type=int, required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--ascii-json", required=True)
    args = ap.parse_args()

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    ascii_frames = json.loads(Path(args.ascii_json).read_text(encoding="utf-8")).get("frames", [])
    if not ascii_frames:
        raise SystemExit("no ascii frames")

    title_font = load_font(max(24, args.width // 45))
    sub_font = load_font(max(20, args.width // 55))
    term_font = load_font(max(16, args.width // 62))
    cta_font = load_font(max(22, args.width // 50))

    nframes = int(DURATION * FPS)
    for i in range(nframes):
        t = i / FPS
        im = Image.new("RGB", (args.width, args.height), "#06080f")
        draw = ImageDraw.Draw(im)

        x0 = int(args.width * 0.06)
        y0 = int(args.height * 0.06)
        w0 = int(args.width * 0.88)
        h0 = int(args.height * 0.88)

        draw.rectangle([x0, y0, x0 + w0, y0 + h0], fill="#0f1422")
        draw.rectangle([x0, y0, x0 + w0, y0 + 58], fill="#1b2438")

        draw.text((int(args.width * 0.09), int(args.height * 0.075)), "h3retik // operator teaser", font=title_font, fill="#d7e6ff")

        label, term = pick_segment(t)
        draw.text((int(args.width * 0.10), int(args.height * 0.14)), label, font=sub_font, fill="#93a9d1")
        draw_multiline(draw, int(args.width * 0.10), int(args.height * 0.19), term, term_font, "#b6c8ee", spacing=8)

        if t >= 12.5:
            draw.text((int(args.width * 0.10), int(args.height * 0.86)), "h1dr4.dev/h3retik", font=cta_font, fill="#ff5c8a")
            draw.text((int(args.width * 0.10), int(args.height * 0.90)), "agent-native red-team orchestration", font=sub_font, fill="#a7f3d0")

        af = ascii_frames[int((t * 9) % len(ascii_frames))].rstrip("\n")
        overlay = Image.new("RGBA", (args.width, args.height), (0, 0, 0, 0))
        od = ImageDraw.Draw(overlay)
        od.multiline_text((int(args.width * 0.035), int(args.height * (0.11 if args.height > args.width else 0.08))), af, font=term_font, fill=(215, 230, 255, 65), spacing=4)
        im = Image.alpha_composite(im.convert("RGBA"), overlay).convert("RGB")

        im.save(out / f"frame_{i:05d}.png")


if __name__ == "__main__":
    main()
