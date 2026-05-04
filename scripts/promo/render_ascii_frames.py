#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument('--input', required=True)
    p.add_argument('--out-dir', required=True)
    p.add_argument('--width', type=int, required=True)
    p.add_argument('--height', type=int, required=True)
    p.add_argument('--font-size', type=int, default=20)
    p.add_argument('--color', default='#d7e6ff')
    p.add_argument('--bg', default='#000000')
    p.add_argument('--margin-x', type=int, default=38)
    p.add_argument('--margin-y', type=int, default=220)
    args = p.parse_args()

    data = json.loads(Path(args.input).read_text(encoding='utf-8'))
    frames = data.get('frames', [])
    if not frames:
        raise SystemExit('no frames in input')

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    try:
        font = ImageFont.truetype('Menlo.ttc', args.font_size)
    except Exception:
        try:
            font = ImageFont.truetype('/System/Library/Fonts/Menlo.ttc', args.font_size)
        except Exception:
            font = ImageFont.load_default()

    for i, frame in enumerate(frames):
        im = Image.new('RGB', (args.width, args.height), color=args.bg)
        d = ImageDraw.Draw(im)
        d.multiline_text((args.margin_x, args.margin_y), frame.rstrip('\n'), font=font, fill=args.color, spacing=4)
        im.save(out / f'frame_{i:04d}.png')


if __name__ == '__main__':
    main()
