r"""
Generate packaging\NetRecon.ico from the clean NetRecon icon mark.

Source preference (first hit wins):
    1. packaging\NetRecon-mark.png
       (pre-cropped square icon mark)
    2. NetRecon_Images\For_NetRecon_Store_Imgs\NetRecon_StoreImg3.png
       (1080x1080 composite; we crop the circular icon mark from the
       top half so the wordmark / subtitle never reach the .ico)
    3. NetRecon_Images\NetRecon_Img_1.png
       (legacy fallback)

Run before building the installer:
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
PACK = ROOT / "packaging"

MARK_PNG    = PACK / "NetRecon-mark.png"
STORE_IMG3  = ROOT / "NetRecon_Images" / "For_NetRecon_Store_Imgs" / "NetRecon_StoreImg3.png"
LEGACY_PNG  = ROOT / "NetRecon_Images" / "NetRecon_Img_1.png"
DST         = PACK / "NetRecon.ico"

ICON_SIZES = [(16, 16), (24, 24), (32, 32), (48, 48),
              (64, 64), (128, 128), (256, 256)]


def trim_alpha(img: Image.Image) -> Image.Image:
    if img.mode != "RGBA":
        img = img.convert("RGBA")
    bbox = img.split()[3].getbbox()
    return img.crop(bbox) if bbox else img


def crop_icon_from_storeimg3(img: Image.Image) -> Image.Image:
    """
    NetRecon_StoreImg3.png is a 1080x1080 composite. The circular icon
    mark sits in the top ~55% of the canvas; the wordmark + subtitle
    fill the bottom. Crop a generous square around the icon only.
    """
    w, h = img.size
    side = int(min(w, h) * 0.52)
    cx   = w // 2
    cy   = int(h * 0.30)
    box  = (cx - side // 2,
            max(0, cy - side // 2),
            cx + side // 2,
            max(0, cy - side // 2) + side)
    return trim_alpha(img.crop(box))


def load_mark() -> Image.Image:
    if MARK_PNG.exists():
        print(f"Source: {MARK_PNG.relative_to(ROOT)}")
        return trim_alpha(Image.open(MARK_PNG).convert("RGBA"))
    if STORE_IMG3.exists():
        print(f"Source: {STORE_IMG3.relative_to(ROOT)} (cropping icon mark)")
        return crop_icon_from_storeimg3(Image.open(STORE_IMG3).convert("RGBA"))
    if LEGACY_PNG.exists():
        print(f"Source: {LEGACY_PNG.relative_to(ROOT)} (legacy)")
        return trim_alpha(Image.open(LEGACY_PNG).convert("RGBA"))
    print("No icon source found. Expected one of:")
    print(f"  {MARK_PNG}\n  {STORE_IMG3}\n  {LEGACY_PNG}")
    sys.exit(1)


def main() -> None:
    img = load_mark()

    # Pad to perfect square so resizes stay centred.
    w, h = img.size
    side = max(w, h)
    if w != h:
        canvas = Image.new("RGBA", (side, side), (0, 0, 0, 0))
        canvas.paste(img, ((side - w) // 2, (side - h) // 2), img)
        img = canvas

    # Upscale once to 256 for the largest frame; PIL's ICO writer
    # generates the smaller frames itself with high-quality resampling.
    if img.size[0] < 256:
        img = img.resize((256, 256), Image.LANCZOS)

    img.save(DST, format="ICO", sizes=ICON_SIZES)
    print(f"Wrote {DST.relative_to(ROOT)} with sizes {[s[0] for s in ICON_SIZES]}")


if __name__ == "__main__":
    main()
