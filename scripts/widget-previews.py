"""Preview images for the Android home-screen widgets.

Android 12+ renders the real layout in the widget picker (previewLayout);
older launchers show a bitmap, and this draws one per widget in the same
dark card style. Output: src-tauri/gen/android/app/src/main/res/drawable-nodpi/.

    python scripts/widget-previews.py
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "src-tauri" / "gen" / "android" / "app" / "src" / "main" / "res" / "drawable-nodpi"

# Two pixels per dp, i.e. xhdpi.
S = 2

CARD = (15, 18, 26, 242)
STROKE = (255, 255, 255, 31)
TEXT = (241, 245, 249, 255)
DIM = (148, 163, 184, 255)
CHIP = (255, 255, 255, 20)
VIOLET = (124, 58, 237)
CYAN = (34, 211, 238)
GREEN = (34, 197, 94, 255)


def font(size_dp: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    for name in (("segoeuib.ttf" if bold else "segoeui.ttf"), ("arialbd.ttf" if bold else "arial.ttf")):
        try:
            return ImageFont.truetype(name, size_dp * S)
        except OSError:
            continue
    return ImageFont.load_default()


def dp(v: float) -> int:
    return int(round(v * S))


def gradient_disc(size_px: int) -> Image.Image:
    """Violet-to-cyan disc, top-left to bottom-right, anti-aliased edge."""
    ss = 4
    big = size_px * ss
    img = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    px = img.load()
    for y in range(big):
        for x in range(big):
            t = (x + y) / (2 * big)
            px[x, y] = (
                int(VIOLET[0] + (CYAN[0] - VIOLET[0]) * t),
                int(VIOLET[1] + (CYAN[1] - VIOLET[1]) * t),
                int(VIOLET[2] + (CYAN[2] - VIOLET[2]) * t),
                255,
            )
    mask = Image.new("L", (big, big), 0)
    ImageDraw.Draw(mask).ellipse((0, 0, big - 1, big - 1), fill=255)
    img.putalpha(mask)
    return img.resize((size_px, size_px), Image.LANCZOS)


def button(canvas: Image.Image, cx: int, cy: int, size_dp: int) -> None:
    """The «on» button: glow ring, gradient disc, power glyph."""
    draw = ImageDraw.Draw(canvas)
    r = dp(size_dp) // 2
    draw.ellipse((cx - r, cy - r, cx + r, cy + r), fill=(124, 58, 237, 51))
    inner = r - dp(5)
    disc = gradient_disc(inner * 2)
    canvas.alpha_composite(disc, (cx - inner, cy - inner))
    # Power glyph: an open arc plus a stem, like ic_power.xml.
    g = int(inner * 0.5)
    w = max(2, dp(2.2))
    draw = ImageDraw.Draw(canvas)
    draw.arc((cx - g, cy - g, cx + g, cy + g), start=-55, end=235, fill=(255, 255, 255, 255), width=w)
    draw.line((cx, cy - g - dp(1), cx, cy - dp(1)), fill=(255, 255, 255, 255), width=w)


def card(width_dp: int, height_dp: int) -> Image.Image:
    img = Image.new("RGBA", (dp(width_dp), dp(height_dp)), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.rounded_rectangle((0, 0, img.width - 1, img.height - 1), radius=dp(22), fill=CARD, outline=STROKE, width=S)
    return img


def dot(draw: ImageDraw.ImageDraw, x: int, y: int, color) -> None:
    r = dp(3.5)
    draw.ellipse((x - r, y - r, x + r, y + r), fill=color)


def arrow(draw: ImageDraw.ImageDraw, x: int, y: int, size: int, down: bool, color) -> None:
    w = max(2, dp(1.8))
    half = size // 2
    draw.line((x, y - half, x, y + half), fill=color, width=w)
    tip = y + half if down else y - half
    d = -1 if down else 1
    draw.line((x - half * 0.7, tip + d * half * 0.7, x, tip), fill=color, width=w)
    draw.line((x + half * 0.7, tip + d * half * 0.7, x, tip), fill=color, width=w)


def toggle() -> Image.Image:
    img = Image.new("RGBA", (dp(70), dp(70)), (0, 0, 0, 0))
    button(img, dp(35), dp(35), 60)
    return img


def compact() -> Image.Image:
    img = card(180, 62)
    button(img, dp(10 + 23), dp(31), 46)
    draw = ImageDraw.Draw(img)
    x = dp(10 + 46 + 10)
    dot(draw, x + dp(3.5), dp(20), GREEN)
    draw.text((x + dp(13), dp(12)), "Connected", font=font(13, bold=True), fill=TEXT)
    y = dp(38)
    arrow(draw, x + dp(5), y, dp(9), True, CYAN)
    draw.text((x + dp(13), y - dp(7)), "1.2 MB/s", font=font(11), fill=TEXT)
    arrow(draw, x + dp(72), y, dp(9), False, VIOLET)
    draw.text((x + dp(80), y - dp(7)), "96 KB/s", font=font(11), fill=TEXT)
    return img


def full() -> Image.Image:
    img = card(320, 140)
    draw = ImageDraw.Draw(img)
    pad = dp(14)
    # Header
    draw.text((pad + dp(20), dp(11)), "Aurora VPN", font=font(11, bold=True), fill=DIM)
    shield = [(pad + dp(7), dp(11)), (pad + dp(13), dp(13)), (pad + dp(13), dp(19)),
              (pad + dp(7), dp(24)), (pad + dp(1), dp(19)), (pad + dp(1), dp(13))]
    draw.polygon(shield, fill=DIM)
    chip_w = dp(86)
    cx0 = img.width - pad - chip_w
    draw.rounded_rectangle((cx0, dp(9), cx0 + chip_w, dp(27)), radius=dp(9), fill=CHIP)
    dot(draw, cx0 + dp(11), dp(18), GREEN)
    draw.text((cx0 + dp(20), dp(11)), "Connected", font=font(11, bold=True), fill=TEXT)
    # Middle
    draw.text((pad, dp(46)), "Amsterdam · REALITY", font=font(15, bold=True), fill=TEXT)
    y = dp(78)
    arrow(draw, pad + dp(7), y, dp(13), True, CYAN)
    draw.text((pad + dp(18), y - dp(12)), "1.2 MB/s", font=font(18, bold=True), fill=TEXT)
    arrow(draw, pad + dp(110), y, dp(13), False, VIOLET)
    draw.text((pad + dp(121), y - dp(12)), "96 KB/s", font=font(18, bold=True), fill=TEXT)
    button(img, img.width - pad - dp(28), dp(66), 56)
    # Footer
    draw = ImageDraw.Draw(img)
    fy = dp(118)
    arrow(draw, pad + dp(5), fy, dp(9), True, DIM)
    draw.text((pad + dp(13), fy - dp(8)), "3.4 GB", font=font(11), fill=DIM)
    arrow(draw, pad + dp(62), fy, dp(9), False, DIM)
    draw.text((pad + dp(70), fy - dp(8)), "412 MB", font=font(11), fill=DIM)
    r = dp(5)
    clock_x = img.width - pad - dp(52)
    draw.ellipse((clock_x - r, fy - r, clock_x + r, fy + r), outline=DIM, width=S)
    draw.line((clock_x, fy - dp(3), clock_x, fy), fill=DIM, width=S)
    draw.line((clock_x, fy, clock_x + dp(2.5), fy + dp(1.5)), fill=DIM, width=S)
    draw.text((clock_x + dp(9), fy - dp(8)), "1:42:07", font=font(11), fill=DIM)
    return img


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, image in (("toggle", toggle()), ("compact", compact()), ("full", full())):
        path = OUT / f"widget_preview_{name}.png"
        image.save(path, optimize=True)
        print(f"{path.relative_to(ROOT)}  {image.width}×{image.height}")


if __name__ == "__main__":
    main()
