#!/usr/bin/env python3
"""Rasteriza assets/ws-client-icon.svg a PNG/ICO para PyInstaller.

PyInstaller no acepta SVG: Windows necesita .ico, Linux .png. Este script
intenta ImageMagick/Inkscape; si no hay, pinta el icono con Pillow (mismo
layout que el SVG del repo).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import List, Optional, Tuple

Point = Tuple[float, float]

W = 512
H = 512


def _run(cmd: List[str]) -> bool:
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except (OSError, subprocess.CalledProcessError):
        return False


def _via_external(svg: str, png: str, ico: str) -> bool:
    magick = shutil.which("magick") or shutil.which("convert")
    if magick:
        ok_png = _run([magick, "-background", "none", svg, "-resize", f"{W}x{H}", png])
        ok_ico = _run(
            [
                magick,
                "-background",
                "none",
                svg,
                "-define",
                "icon:auto-resize=256,128,64,48,32,16",
                ico,
            ]
        )
        if ok_png and ok_ico and os.path.isfile(png) and os.path.isfile(ico):
            return True
    inkscape = shutil.which("inkscape")
    if inkscape and _run(
        [inkscape, svg, "--export-type=png", f"--export-filename={png}", f"--export-width={W}"]
    ):
        return _png_to_ico(png, ico)
    rsvg = shutil.which("rsvg-convert")
    if rsvg and _run([rsvg, "-w", str(W), "-h", str(H), "-o", png, svg]):
        return _png_to_ico(png, ico)
    return False


def _png_to_ico(png: str, ico: str) -> bool:
    try:
        from PIL import Image
    except ImportError:
        return False
    im = Image.open(png).convert("RGBA")
    sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    im.save(ico, format="ICO", sizes=sizes)
    return os.path.isfile(ico)


def _lerp_rgb(a: Tuple[int, int, int], b: Tuple[int, int, int], t: float) -> Tuple[int, int, int]:
    t = max(0.0, min(1.0, t))
    return (
        int(a[0] + (b[0] - a[0]) * t),
        int(a[1] + (b[1] - a[1]) * t),
        int(a[2] + (b[2] - a[2]) * t),
    )


def _cubic(p0: Point, p1: Point, p2: Point, p3: Point, n: int = 48) -> List[Point]:
    pts: List[Point] = []
    for i in range(n + 1):
        t = i / n
        u = 1.0 - t
        x = u**3 * p0[0] + 3 * u**2 * t * p1[0] + 3 * u * t**2 * p2[0] + t**3 * p3[0]
        y = u**3 * p0[1] + 3 * u**2 * t * p1[1] + 3 * u * t**2 * p2[1] + t**3 * p3[1]
        pts.append((x, y))
    return pts


def _font(size: int):
    from PIL import ImageFont

    candidates = [
        "C:/Windows/Fonts/arialbd.ttf",
        "C:/Windows/Fonts/arial.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
        "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
        "/System/Library/Fonts/Supplemental/Arial.ttf",
    ]
    for path in candidates:
        if os.path.isfile(path):
            try:
                return ImageFont.truetype(path, size)
            except OSError:
                continue
    return ImageFont.load_default()


def _via_pillow(png: str, ico: str) -> bool:
    from PIL import Image, ImageDraw, ImageFilter

    img = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    bg = Image.new("RGB", (W, H))
    px = bg.load()
    c0, c1 = (15, 23, 42), (30, 58, 138)
    denom = float(W + H - 2)
    for y in range(H):
        for x in range(W):
            px[x, y] = _lerp_rgb(c0, c1, (x + y) / denom)
    mask = Image.new("L", (W, H), 0)
    ImageDraw.Draw(mask).rounded_rectangle((24, 24, 488, 488), radius=96, fill=255)
    rgba = Image.new("RGBA", (W, H))
    rgba.paste(bg.convert("RGBA"), (0, 0))
    rgba.putalpha(mask)
    img = Image.alpha_composite(img, rgba)

    wave: List[Point] = []
    wave.extend(_cubic((90, 256), (130, 186), (190, 186), (230, 256)))
    wave.extend(_cubic((230, 256), (270, 326), (330, 326), (370, 256))[1:])
    wave.extend(_cubic((370, 256), (400, 206), (430, 206), (452, 256))[1:])

    layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    draw = ImageDraw.Draw(layer)
    n = max(1, len(wave) - 1)
    cyan, violet = (34, 211, 238, 255), (167, 139, 250, 255)
    for i in range(n):
        t = i / n
        col = (
            int(cyan[0] + (violet[0] - cyan[0]) * t),
            int(cyan[1] + (violet[1] - cyan[1]) * t),
            int(cyan[2] + (violet[2] - cyan[2]) * t),
            255,
        )
        draw.line([wave[i], wave[i + 1]], fill=col, width=28, joint="curve")
        p = wave[i]
        r = 14
        draw.ellipse((p[0] - r, p[1] - r, p[0] + r, p[1] + r), fill=col)
    p = wave[-1]
    draw.ellipse((p[0] - 14, p[1] - 14, p[0] + 14, p[1] + 14), fill=violet)
    layer = layer.filter(ImageFilter.GaussianBlur(0.6))
    img = Image.alpha_composite(img, layer)

    draw = ImageDraw.Draw(img)
    draw.ellipse((132 - 18, 256 - 18, 132 + 18, 256 + 18), fill=(34, 211, 238, 255))
    draw.ellipse((380 - 18, 256 - 18, 380 + 18, 256 + 18), fill=(167, 139, 250, 255))
    font = _font(78)
    text = "WS"
    bbox = draw.textbbox((0, 0), text, font=font)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    draw.text((256 - tw / 2, 370 - th * 0.85), text, font=font, fill=(226, 232, 240, 255))

    img.save(png, format="PNG")
    sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    img.save(ico, format="ICO", sizes=sizes)
    return os.path.isfile(png) and os.path.isfile(ico)


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    svg = argv[0] if argv else os.path.join(root, "assets", "ws-client-icon.svg")
    png = argv[1] if len(argv) > 1 else os.path.join(root, "assets", "ws-client-icon.png")
    ico = argv[2] if len(argv) > 2 else os.path.join(root, "assets", "ws-client-icon.ico")
    if not os.path.isfile(svg):
        print(f"[icon] no existe {svg}", file=sys.stderr)
        return 1
    os.makedirs(os.path.dirname(os.path.abspath(png)) or ".", exist_ok=True)
    if _via_external(svg, png, ico) or _via_pillow(png, ico):
        print(f"[icon] {png} y {ico} desde {svg}")
        return 0
    print("[icon] no se pudo rasterizar el SVG (instala Pillow en el venv de build)", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
