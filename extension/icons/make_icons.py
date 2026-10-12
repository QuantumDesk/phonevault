#!/usr/bin/env python3
"""Generate the extension icons (crisp pixel art, integer scales only) and the EIP-6963 SVG.

Big padlock (48/128 px, the wallet-list SVG): the 14x16 design also used for the companion's
menu-bar icon. Small padlock (16/32 px): an 8x10 simplification that stays legible at toolbar
size. Mint on the brand's near-black rounded tile.
"""
from pathlib import Path
from PIL import Image, ImageDraw

BIG = ["....######....", "...########...", "..###....###..", "..##......##..", "..##......##..",
       "..##......##..", ".############.", "##############", "##############", "#####....#####",
       "#####....#####", "######..######", "######..######", "##############", "##############",
       ".############."]
SMALL = ["..####..", ".##..##.", ".#....#.", "########", "########", "###..###", "###..###",
         "###..###", "########", "########"]
TILE, MINT = (6, 6, 8, 255), (184, 239, 211, 255)
HERE = Path(__file__).parent

def icon(size, art, scale, radius):
    im = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    ImageDraw.Draw(im).rounded_rectangle([0, 0, size - 1, size - 1], radius=radius, fill=TILE)
    w, h = len(art[0]) * scale, len(art) * scale
    ox, oy = (size - w) // 2, (size - h) // 2
    for y, row in enumerate(art):
        for x, c in enumerate(row):
            if c == "#":
                for dy in range(scale):
                    for dx in range(scale):
                        im.putpixel((ox + x * scale + dx, oy + y * scale + dy), MINT)
    return im

for size, art, scale, radius in ((16, SMALL, 1, 3), (32, SMALL, 2, 6), (48, BIG, 2, 10), (128, BIG, 6, 28)):
    icon(size, art, scale, radius).save(HERE / f"icon-{size}.png", optimize=True)

# EIP-6963 announcement icon (dApp wallet lists): same big design as SVG rects on a 1024 tile.
cell, w, h = 56, 14, 16
ox, oy = (1024 - w * cell) // 2, (1024 - h * cell) // 2
rects = "".join(f'<rect x="{ox + x * cell}" y="{oy + y * cell}" width="{cell}" height="{cell}"/>'
                for y, row in enumerate(BIG) for x, c in enumerate(row) if c == "#")
(HERE / "icon.svg").write_text(
    '<svg xmlns="http://www.w3.org/2000/svg" width="1024" height="1024" viewBox="0 0 1024 1024" shape-rendering="crispEdges">'
    '<!-- Phone Vault: 14x16 pixel padlock (extension/icons/make_icons.py) -->'
    f'<rect width="1024" height="1024" rx="224" fill="#060608"/><g fill="#b8efd3">{rects}</g></svg>\n')
print("ok")
