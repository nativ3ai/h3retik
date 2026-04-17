#!/usr/bin/env python3

import json
import re
import sys
from pathlib import Path
from urllib.request import urlopen


DEFAULT_URL = "https://ascii.co.uk/animated-art/skull-flying-animated-ascii-art-by-eloy-lanno.html"


def fetch(url: str) -> str:
    with urlopen(url) as response:
        return response.read().decode("utf-8", errors="replace")


def extract_frames(html: str) -> list[str]:
    matches = re.findall(r"n\[\d+\]\s*=\s*'(.*?)';", html, re.DOTALL)
    frames = []
    for raw in matches:
        frame = bytes(raw, "utf-8").decode("unicode_escape")
        frames.append(frame.rstrip("\n"))
    return frames


def main() -> int:
    url = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_URL
    out_path = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("assets/skull_flying_frames.json")
    html = fetch(url)
    frames = extract_frames(html)
    if not frames:
        print("no frames extracted", file=sys.stderr)
        return 1
    out_path.parent.mkdir(parents=True, exist_ok=True)
    title = "Animated ASCII"
    match = re.search(r"<title>(.*?)</title>", html, re.DOTALL | re.IGNORECASE)
    if match:
        title = re.sub(r"\s+", " ", match.group(1)).strip()
    payload = {"title": title, "source": url, "frames": frames}
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"wrote {len(frames)} frames to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
