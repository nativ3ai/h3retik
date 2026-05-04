#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

DURATION = 18.0
FPS = 30


def load_font(size: int):
    for cand in [
        "/System/Library/Fonts/Menlo.ttc",
        "Menlo.ttc",
        "/System/Library/Fonts/Supplemental/Courier New.ttf",
    ]:
        try:
            return ImageFont.truetype(cand, size)
        except Exception:
            pass
    return ImageFont.load_default()


def extract_backtick_const(src: str, name: str) -> str:
    m = re.search(rf"const\s+{re.escape(name)}\s*=\s*`(.*?)`", src, re.S)
    return m.group(1).strip("\n") if m else ""


def extract_pwned_const(src: str) -> str:
    m = re.search(r"const\s+pwnedSkullASCII\s*=\s*\"\"\s*\+\s*(.*?)(?:\n\nconst|\nfunc)", src, re.S)
    if not m:
        return ""
    block = m.group(1)
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', block)
    out = ""
    for p in parts:
        out += bytes(p, "utf-8").decode("unicode_escape")
    return out.strip("\n")


def load_ascii_assets(repo_root: Path):
    src = (repo_root / "cmd/juicetui/main.go").read_text(encoding="utf-8")
    return {
        "fallback": extract_backtick_const(src, "fallbackASCII"),
        "ascii_skull": extract_backtick_const(src, "asciiSkull"),
        "taxonomy": extract_backtick_const(src, "skullTaxonomyASCII"),
        "osint": extract_backtick_const(src, "osintNavigatorASCII"),
        "pwned": extract_pwned_const(src),
    }


def draw_block(draw: ImageDraw.ImageDraw, x: int, y: int, text: str, font, fill, spacing=6):
    draw.multiline_text((x, y), text, font=font, fill=fill, spacing=spacing)


def typewriter(text: str, t: float, cps: float) -> str:
    n = int(max(0, t) * cps)
    return text[: min(len(text), n)]


def apply_zoom(im: Image.Image, z: float) -> Image.Image:
    if abs(z - 1.0) < 1e-3:
        return im
    w, h = im.size
    zw, zh = int(w * z), int(h * z)
    zoomed = im.resize((zw, zh), Image.Resampling.BICUBIC)
    left = (zw - w) // 2
    top = (zh - h) // 2
    return zoomed.crop((left, top, left + w, top + h))


def scene_time(t: float):
    # 5 scenes
    cuts = [0.0, 3.8, 7.2, 10.8, 14.4, DURATION]
    for i in range(len(cuts) - 1):
        if cuts[i] <= t < cuts[i + 1]:
            return i, t - cuts[i], cuts[i + 1] - cuts[i]
    return len(cuts) - 2, 0.0, cuts[-1] - cuts[-2]


def render_frame(i: int, args, ascii_assets, startup_frames, loading_frames):
    t = i / FPS
    scene, st, slen = scene_time(t)

    w, h = args.width, args.height
    im = Image.new("RGB", (w, h), "#05070d")
    draw = ImageDraw.Draw(im)

    title_font = load_font(max(24, w // 42))
    ui_font = load_font(max(15, w // 70))
    cmd_font = load_font(max(16, w // 68))
    big_font = load_font(max(20, w // 55))

    # cinematic background layers
    draw.rectangle([0, 0, w, h], fill="#05070d")
    draw.rectangle([0, int(h * 0.62), w, h], fill="#0a0f1b")

    px = int(w * 0.06)
    py = int(h * 0.06)
    pw = int(w * 0.88)
    ph = int(h * 0.84)
    draw.rounded_rectangle([px, py, px + pw, py + ph], radius=18, fill="#0f1526", outline="#26324f", width=2)
    draw.rectangle([px, py, px + pw, py + 52], fill="#1a2440")
    draw.text((px + 20, py + 12), "h3retik // operator command bus", font=ui_font, fill="#d7e6ff")

    # shared terminal split
    left_x = px + 24
    left_y = py + 74

    if scene == 0:
        draw.text((left_x, left_y - 28), "BOOTSTRAP", font=big_font, fill="#9eb9ff")
        cmd = "$ curl -fsSL https://h1dr4.dev/install.sh | bash\n$ h3retik"
        draw_block(draw, left_x, left_y + 8, typewriter(cmd, st, 32), cmd_font, "#b8c9ef", 7)
        frame = startup_frames[int((st * 9) % len(startup_frames))].rstrip("\n")
        draw_block(draw, int(w * 0.52), int(h * 0.18), frame, ui_font, "#9fc1ff", 4)

    elif scene == 1:
        draw.text((left_x, left_y - 28), "STARTUP SIGIL", font=big_font, fill="#9eb9ff")
        draw_block(draw, left_x, left_y, ascii_assets["fallback"], ui_font, "#8fb0f3", 4)
        frame = loading_frames[int((st * 10) % len(loading_frames))].rstrip("\n")
        draw_block(draw, int(w * 0.55), int(h * 0.24), frame, ui_font, "#cfe1ff", 4)

    elif scene == 2:
        draw.text((left_x, left_y - 28), "TACTICAL UI", font=big_font, fill="#9eb9ff")
        draw_block(draw, left_x, left_y, ascii_assets["taxonomy"], ui_font, "#a9c2f7", 3)
        telemetry = (
            "[TARGET] scanme.nmap.org\n"
            "[MODE] exploit\n"
            "[FIRE] recon -> httpx -> nuclei\n"
            "[TELEMETRY] cmds: 42  findings: 8  loot: 13\n"
            "[STATUS] operator command in-flight"
        )
        draw.rounded_rectangle([int(w*0.54), int(h*0.20), int(w*0.90), int(h*0.47)], radius=12, fill="#131c31", outline="#304060", width=2)
        draw_block(draw, int(w * 0.56), int(h * 0.22), telemetry, cmd_font, "#bfe1d1", 8)

    elif scene == 3:
        draw.text((left_x, left_y - 28), "PWNED STATE", font=big_font, fill="#ff7fa1")
        draw_block(draw, left_x, left_y, ascii_assets["pwned"], ui_font, "#ff9bb6", 3)
        ops = (
            "[MODULE] Privesc Local Full   [OK]\n"
            "[MODULE] Nmap Service Profile [OK]\n"
            "[MODULE] Nuclei Focused       [OK]\n"
            "[LOOT] /tmp/report.json\n"
            "[FINDING] CRITICAL: auth bypass path"
        )
        draw.rounded_rectangle([int(w*0.52), int(h*0.21), int(w*0.90), int(h*0.50)], radius=12, fill="#291521", outline="#5b2a42", width=2)
        draw_block(draw, int(w * 0.54), int(h * 0.23), ops, cmd_font, "#ffd2de", 7)

    else:
        draw.text((left_x, left_y - 28), "MULTI-LANE + CLOUD", font=big_font, fill="#8df2c5")
        draw_block(draw, left_x, left_y, ascii_assets["osint"], ui_font, "#9ec8c2", 3)
        cta = (
            "h3retik setup -> pick profile (local-lite/web-lite/full/custom)\n"
            "h3retik pipeline-cloud --target <target> --pipeline full-chain\n"
            "h1dr4.dev/h3retik"
        )
        draw.rounded_rectangle([int(w*0.49), int(h*0.22), int(w*0.92), int(h*0.47)], radius=12, fill="#12241f", outline="#2f5e53", width=2)
        draw_block(draw, int(w * 0.51), int(h * 0.24), cta, cmd_font, "#c5f7e7", 8)

    # Beat bar
    progress = (t / DURATION)
    draw.rectangle([px, py + ph + 14, px + pw, py + ph + 24], fill="#1d2b46")
    draw.rectangle([px, py + ph + 14, px + int(pw * progress), py + ph + 24], fill="#5f9cff")

    # rhythmic zoom/pulse
    z = 1.0 + 0.02 * (st / max(0.001, slen))
    im = apply_zoom(im, z)
    return im


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--width", type=int, required=True)
    ap.add_argument("--height", type=int, required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--startup-json", required=True)
    ap.add_argument("--loading-json", required=True)
    ap.add_argument("--repo-root", required=True)
    args = ap.parse_args()

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    startup_frames = json.loads(Path(args.startup_json).read_text(encoding="utf-8")).get("frames", [])
    loading_frames = json.loads(Path(args.loading_json).read_text(encoding="utf-8")).get("frames", [])
    if not startup_frames or not loading_frames:
        raise SystemExit("missing startup/loading frames")

    ascii_assets = load_ascii_assets(Path(args.repo_root))

    n = int(DURATION * FPS)
    for i in range(n):
        im = render_frame(i, args, ascii_assets, startup_frames, loading_frames)
        im.save(out / f"frame_{i:05d}.png")


if __name__ == "__main__":
    main()
