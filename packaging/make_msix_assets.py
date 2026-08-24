"""
Generate MSIX tile / splash assets for NetRecon Network Toolkit.

Design rules (driven by Microsoft Store policy 10.1.1.11 rejection):
  - Tiles are ICON-FIRST. No tiny subtitle text.
  - Small tiles (16/24/32/44/48) are icon-only with safe padding.
  - Square150x150: icon-only with generous padding.
  - Wide310x150: icon on left + clean large "NetRecon" wordmark, no subtitle.
  - SplashScreen: centred icon on dark background, no text.
  - StoreLogo (50x50): icon-only.

Source preference:
  1. packaging/NetRecon-mark.png  (pre-cropped square icon mark, if present)
  2. NetRecon_Images/For_NetRecon_Store_Imgs/NetRecon_StoreImg3.png
     (1080x1080 composite; we crop the circular icon mark from the top
     half so the wordmark / subtitle never reach the tiles)
  3. packaging/NetRecon.ico  (legacy fallback)

Outputs (PNG, RGBA) into packaging/Assets/.
"""

from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent
OUT = ROOT / "Assets"
OUT.mkdir(exist_ok=True)

MARK_PNG    = ROOT / "NetRecon-mark.png"
STORE_IMG3  = REPO / "NetRecon_Images" / "For_NetRecon_Store_Imgs" / "NetRecon_StoreImg3.png"
ICON_FILE   = ROOT / "NetRecon.ico"

# Brand colours sampled from NetRecon_StoreImg3.png.
DARK_BG    = (10, 15, 31, 255)     # #0A0F1F deep navy
TEXT_FILL  = (240, 245, 255, 255)  # near-white
ACCENT     = (60, 160, 255, 255)   # NetRecon blue (for accent rule, optional)

WORDMARK_TEXT = "NetRecon"


# ------------------------------------------------------------------
# Source loading
# ------------------------------------------------------------------
def _trim_alpha(img: Image.Image) -> Image.Image:
    """Trim fully-transparent border so the icon mark fills its canvas."""
    if img.mode != "RGBA":
        img = img.convert("RGBA")
    bbox = img.split()[3].getbbox()
    return img.crop(bbox) if bbox else img


def _crop_icon_from_storeimg3(img: Image.Image) -> Image.Image:
    """
    NetRecon_StoreImg3.png is a 1080x1080 composite: circular icon mark
    occupies roughly the top half, the wordmark + subtitle fills the
    bottom. Crop a square containing the icon mark only.
    """
    w, h = img.size
    # Empirically the icon mark is centred horizontally and sits in the
    # top ~55% of the canvas. Crop a generous square then trim.
    side = int(min(w, h) * 0.52)
    cx   = w // 2
    cy   = int(h * 0.30)
    box  = (cx - side // 2, max(0, cy - side // 2),
            cx + side // 2, max(0, cy - side // 2) + side)
    return _trim_alpha(img.crop(box))


def load_mark() -> Image.Image:
    """Return a square RGBA image containing only the icon mark."""
    if MARK_PNG.exists():
        return _trim_alpha(Image.open(MARK_PNG).convert("RGBA"))

    if STORE_IMG3.exists():
        src = Image.open(STORE_IMG3).convert("RGBA")
        mark = _crop_icon_from_storeimg3(src)
        # Pad to a perfect square so downstream resizes stay centred.
        size = max(mark.size)
        square = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        square.paste(mark, ((size - mark.size[0]) // 2,
                            (size - mark.size[1]) // 2), mark)
        return square

    if ICON_FILE.exists():
        im = Image.open(ICON_FILE)
        sizes = im.info.get("sizes") or [im.size]
        im.size = max(sizes, key=lambda s: s[0] * s[1])
        return _trim_alpha(im.convert("RGBA"))

    raise SystemExit("No icon source found. Expected one of: "
                     f"{MARK_PNG}, {STORE_IMG3}, {ICON_FILE}")


# ------------------------------------------------------------------
# Font loading (Segoe UI preferred, Arial fallback)
# ------------------------------------------------------------------
def load_font(size: int, bold: bool = True) -> ImageFont.FreeTypeFont:
    candidates = [
        r"C:\Windows\Fonts\segoeuib.ttf" if bold else r"C:\Windows\Fonts\segoeui.ttf",
        r"C:\Windows\Fonts\seguisb.ttf",                # Semibold
        r"C:\Windows\Fonts\arialbd.ttf" if bold else r"C:\Windows\Fonts\arial.ttf",
    ]
    for p in candidates:
        if Path(p).exists():
            return ImageFont.truetype(p, size)
    return ImageFont.load_default()


# ------------------------------------------------------------------
# Tile composers
# ------------------------------------------------------------------
def square_icon(mark: Image.Image, side: int, padding_ratio: float = 0.10,
                bg=(0, 0, 0, 0)) -> Image.Image:
    """Icon-only square. Transparent bg so Windows uses the accent colour."""
    canvas = Image.new("RGBA", (side, side), bg)
    pad = int(side * padding_ratio)
    inner = side - 2 * pad
    scaled = mark.resize((inner, inner), Image.LANCZOS)
    canvas.paste(scaled, (pad, pad), scaled)
    return canvas


def small_icon(mark: Image.Image, side: int) -> Image.Image:
    """Very small tiles get less padding so the glyph reads at 16-48 px."""
    pad = max(1, side // 16)  # ~6% padding
    canvas = Image.new("RGBA", (side, side), (0, 0, 0, 0))
    inner = side - 2 * pad
    scaled = mark.resize((inner, inner), Image.LANCZOS)
    canvas.paste(scaled, (pad, pad), scaled)
    return canvas


def wide_tile(mark: Image.Image, w: int = 310, h: int = 150) -> Image.Image:
    """
    Wide tile: dark background, icon on the left, large 'NetRecon'
    wordmark on the right. No subtitle, no tiny text.
    """
    canvas = Image.new("RGBA", (w, h), DARK_BG)
    draw = ImageDraw.Draw(canvas)

    # Icon block on the left
    icon_side = int(h * 0.78)
    icon_pad  = (h - icon_side) // 2
    icon = mark.resize((icon_side, icon_side), Image.LANCZOS)
    canvas.paste(icon, (icon_pad, icon_pad), icon)

    # Wordmark area
    text_left = icon_pad + icon_side + int(h * 0.08)
    available_w = w - text_left - int(h * 0.08)

    # Auto-fit font: shrink until 'NetRecon' fits the remaining width.
    font_size = int(h * 0.46)
    while font_size > 10:
        font = load_font(font_size, bold=True)
        bbox = draw.textbbox((0, 0), WORDMARK_TEXT, font=font)
        tw = bbox[2] - bbox[0]
        th = bbox[3] - bbox[1]
        if tw <= available_w:
            break
        font_size -= 2
    ty = (h - th) // 2 - bbox[1]
    draw.text((text_left, ty), WORDMARK_TEXT, font=font, fill=TEXT_FILL)

    return canvas


def splash(mark: Image.Image, w: int = 620, h: int = 300) -> Image.Image:
    """Centred icon on dark background. No text."""
    canvas = Image.new("RGBA", (w, h), DARK_BG)
    side = int(min(w, h) * 0.62)
    scaled = mark.resize((side, side), Image.LANCZOS)
    canvas.paste(scaled, ((w - side) // 2, (h - side) // 2), scaled)
    return canvas


# ------------------------------------------------------------------
# Driver
# ------------------------------------------------------------------
def save(img: Image.Image, name: str) -> None:
    path = OUT / name
    img.save(path, "PNG", optimize=True)
    print(f"  {path.relative_to(REPO)}  ({img.size[0]}x{img.size[1]})")


def main() -> None:
    mark = load_mark()
    print(f"Icon mark source resolved to {mark.size} RGBA")
    print(f"Output: {OUT}")

    # Square44x44 family (icon-only, transparent bg so accent colour shows).
    save(square_icon(mark, 44, padding_ratio=0.09), "Square44x44Logo.png")
    for s in (16, 24, 32, 48):
        save(small_icon(mark, s), f"Square44x44Logo.targetsize-{s}.png")
    save(square_icon(mark, 256, padding_ratio=0.08), "Square44x44Logo.targetsize-256.png")

    # Medium tile
    save(square_icon(mark, 150, padding_ratio=0.12), "Square150x150Logo.png")

    # Wide tile: icon + clean wordmark, no subtitle
    save(wide_tile(mark), "Wide310x150Logo.png")

    # Store logo (Partner Center / Store listing chip)
    save(square_icon(mark, 50, padding_ratio=0.08), "StoreLogo.png")

    # Splash
    save(splash(mark), "SplashScreen.png")

    print("Done.")


if __name__ == "__main__":
    main()
