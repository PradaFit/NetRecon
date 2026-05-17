"""
Generate packaging\NetRecon.ico from NetRecon_Images\NetRecon_Img_1.png.

Run once before building the installer:
    python packaging\make_icon.py

Requires Pillow (already in requirements.txt).
"""

import sys
from pathlib import Path

try:
    from PIL import Image
except ImportError:
    print("Pillow is required. Install with: pip install Pillow")
    sys.exit(1)


ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "NetRecon_Images" / "NetRecon_Img_1.png"
DST = ROOT / "packaging" / "NetRecon.ico"

ICON_SIZES = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]


def main():
    if not SRC.exists():
        print(f"Source image not found: {SRC}")
        sys.exit(1)

    img = Image.open(SRC).convert("RGBA")

    # Pad to square if needed so the icon scales cleanly.
    w, h = img.size
    side = max(w, h)
    if w != h:
        canvas = Image.new("RGBA", (side, side), (0, 0, 0, 0))
        canvas.paste(img, ((side - w) // 2, (side - h) // 2))
        img = canvas

    img.save(DST, format="ICO", sizes=ICON_SIZES)
    print(f"Wrote {DST}")


if __name__ == "__main__":
    main()
