"""Generate the small bundled flag PNG assets with the Python standard library."""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

WIDTH = 28
HEIGHT = 18


def _png(rows: list[list[tuple[int, int, int, int]]]) -> bytes:
    raw = b"".join(
        b"\x00" + b"".join(bytes(pixel) for pixel in row)
        for row in rows
    )

    def chunk(name: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + name
            + data
            + struct.pack(">I", zlib.crc32(name + data) & 0xFFFFFFFF)
        )

    header = struct.pack(">IIBBBBB", WIDTH, HEIGHT, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )


def _turkish_flag() -> bytes:
    rows = [[(227, 10, 23, 255) for _x in range(WIDTH)] for _y in range(HEIGHT)]
    for y in range(HEIGHT):
        for x in range(WIDTH):
            if (x - 11) ** 2 + (y - 9) ** 2 <= 28:
                rows[y][x] = (255, 255, 255, 255)
            if (x - 13) ** 2 + (y - 9) ** 2 <= 20:
                rows[y][x] = (227, 10, 23, 255)
    star = ((17, 6), (18, 8), (21, 8), (19, 10), (20, 13), (17, 11), (15, 13), (16, 10), (14, 8), (17, 8))
    for x, y in star:
        if 0 <= x < WIDTH and 0 <= y < HEIGHT:
            rows[y][x] = (255, 255, 255, 255)
    return _png(rows)


def _british_flag() -> bytes:
    blue = (1, 33, 105, 255)
    white = (255, 255, 255, 255)
    red = (200, 16, 46, 255)
    rows = [[blue for _x in range(WIDTH)] for _y in range(HEIGHT)]
    for y in range(HEIGHT):
        for x in range(WIDTH):
            diagonal = abs(y - (x * HEIGHT / WIDTH)) < 2 or abs(
                y - ((WIDTH - 1 - x) * HEIGHT / WIDTH)
            ) < 2
            if diagonal:
                rows[y][x] = white
            if abs(y - HEIGHT // 2) <= 2 or abs(x - WIDTH // 2) <= 3:
                rows[y][x] = white
            if abs(y - HEIGHT // 2) <= 1 or abs(x - WIDTH // 2) <= 1:
                rows[y][x] = red
    return _png(rows)


def main() -> None:
    target = Path(__file__).resolve().parent.parent / "assets" / "flags"
    target.mkdir(parents=True, exist_ok=True)
    (target / "tr.png").write_bytes(_turkish_flag())
    (target / "gb.png").write_bytes(_british_flag())


if __name__ == "__main__":
    main()
