#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


def ass_escape(text: str) -> str:
    return (
        text.replace('\\', r'\\')
        .replace('{', r'\{')
        .replace('}', r'\}')
        .replace('\n', r'\N')
    )


def to_ass_time(seconds: float) -> str:
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    s = seconds % 60
    return f"{h}:{m:02d}:{s:05.2f}"


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert JSON ASCII frame array to ASS subtitle animation")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--fps", type=float, default=8.0)
    parser.add_argument("--title", default="ASCII Animation")
    args = parser.parse_args()

    src = Path(args.input)
    dst = Path(args.output)
    data = json.loads(src.read_text(encoding="utf-8"))
    frames = data.get("frames", [])
    if not frames:
        raise SystemExit("no frames in input JSON")

    frame_dt = 1.0 / args.fps
    lines = []
    lines.append("[Script Info]")
    lines.append("ScriptType: v4.00+")
    lines.append(f"Title: {args.title}")
    lines.append("PlayResX: 1080")
    lines.append("PlayResY: 1920")
    lines.append("ScaledBorderAndShadow: yes")
    lines.append("")
    lines.append("[V4+ Styles]")
    lines.append("Format: Name, Fontname, Fontsize, PrimaryColour, SecondaryColour, OutlineColour, BackColour, Bold, Italic, Underline, StrikeOut, ScaleX, ScaleY, Spacing, Angle, BorderStyle, Outline, Shadow, Alignment, MarginL, MarginR, MarginV, Encoding")
    lines.append("Style: Frame,DejaVu Sans Mono,20,&H00D7E6FF,&H00D7E6FF,&H00511122,&H64000000,0,0,0,0,100,100,0,0,1,1,0,5,38,38,260,1")
    lines.append("")
    lines.append("[Events]")
    lines.append("Format: Layer, Start, End, Style, Name, MarginL, MarginR, MarginV, Effect, Text")

    t = 0.0
    for frame in frames:
        start = to_ass_time(t)
        end = to_ass_time(t + frame_dt)
        text = ass_escape(frame.rstrip("\n"))
        lines.append(f"Dialogue: 0,{start},{end},Frame,,0,0,0,,{text}")
        t += frame_dt

    dst.write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
