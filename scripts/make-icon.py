"""Generate the source app icon (1024x1024 RGBA PNG) with no image libraries.

A rounded-square aurora gradient carrying a white shield with a lightning bolt
knocked out of it. `npm run icons` feeds the result to `tauri icon`, which
derives every platform size plus .ico/.icns.
"""

import math
import os
import struct
import sys
import zlib

SIZE = 1024
SS = 2  # supersampling factor per axis


def write_png(path: str, width: int, height: int, pixels: bytearray) -> None:
    raw = bytearray()
    stride = width * 4
    for y in range(height):
        raw.append(0)  # filter type 0 (None)
        raw += pixels[y * stride:(y + 1) * stride]

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(bytes(raw), 9))
    png += chunk(b"IEND", b"")
    with open(path, "wb") as f:
        f.write(png)


def lerp(a, b, t):
    return a + (b - a) * t


def rounded_rect(px, py, size, radius):
    """Inside-test for a rounded square covering the whole canvas."""
    cx = min(max(px, radius), size - radius)
    cy = min(max(py, radius), size - radius)
    dx, dy = px - cx, py - cy
    return dx * dx + dy * dy <= radius * radius


def shield(px, py, cx, cy, hw, hh):
    """Classic shield: straight shoulders, rounded top, tapering to a point."""
    x = (px - cx) / hw
    y = (py - (cy - hh)) / (2 * hh)
    if y < 0 or y > 1 or abs(x) > 1:
        return False

    if y <= 0.5:
        limit = 1.0
        r = 0.22
        if y < r:  # round the top corners
            limit = (1 - r) + math.sqrt(max(0.0, r * r - (r - y) ** 2))
    else:
        u = (y - 0.5) / 0.5
        limit = max(0.0, 1 - u * u) ** 0.7
    return abs(x) <= limit


BOLT = [
    (0.16, -0.52), (-0.34, 0.06), (-0.04, 0.06),
    (-0.16, 0.56), (0.36, -0.08), (0.04, -0.08),
]


def in_polygon(x, y, poly):
    inside = False
    n = len(poly)
    for i in range(n):
        x1, y1 = poly[i]
        x2, y2 = poly[(i + 1) % n]
        if (y1 > y) != (y2 > y):
            xint = x1 + (y - y1) * (x2 - x1) / (y2 - y1)
            if x < xint:
                inside = not inside
    return inside


def main() -> int:
    out = sys.argv[1] if len(sys.argv) > 1 else "app-icon.png"
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)

    pixels = bytearray(SIZE * SIZE * 4)
    radius = SIZE * 0.22
    cx = cy = SIZE / 2
    hw, hh = SIZE * 0.225, SIZE * 0.285
    bolt_scale = hw * 1.02

    # Aurora gradient endpoints (violet -> cyan) sampled along the diagonal.
    c0 = (124, 58, 237)
    c1 = (34, 211, 238)
    weight = 1.0 / (SS * SS)

    for y in range(SIZE):
        row = y * SIZE * 4
        for x in range(SIZE):
            cover_bg = 0.0
            cover_mark = 0.0
            for sy in range(SS):
                for sx in range(SS):
                    px = x + (sx + 0.5) / SS
                    py = y + (sy + 0.5) / SS
                    if not rounded_rect(px, py, SIZE, radius):
                        continue
                    cover_bg += weight
                    if shield(px, py, cx, cy, hw, hh):
                        bx = (px - cx) / bolt_scale
                        by = (py - cy) / bolt_scale
                        if not in_polygon(bx, by, BOLT):
                            cover_mark += weight

            if cover_bg <= 0.0:
                continue

            t = (x / SIZE) * 0.35 + (y / SIZE) * 0.65
            r = lerp(c0[0], c1[0], t)
            g = lerp(c0[1], c1[1], t)
            b = lerp(c0[2], c1[2], t)

            # Composite the white mark over the gradient before applying the
            # shape's own alpha, so edges stay clean at every icon size.
            r = lerp(r, 255, cover_mark)
            g = lerp(g, 255, cover_mark)
            b = lerp(b, 255, cover_mark)

            i = row + x * 4
            pixels[i] = int(r)
            pixels[i + 1] = int(g)
            pixels[i + 2] = int(b)
            pixels[i + 3] = int(cover_bg * 255)

    write_png(out, SIZE, SIZE, pixels)
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
