"""Deterministic synthetic image corpus for image_service eval.

No real sensitive images are downloaded or stored — every case is drawn from
scratch with PIL so the suite is reproducible and safe to commit. This is the
accept/reject gate every hardening phase re-runs (the hard-won lesson from the
WAF arc: held-out numbers alone hide regressions; re-run the adversarial set).

Case labels:
  benign_gradient      — plain image, no text, no threat -> ALLOW
  secret_screenshot    — a live-looking AWS key + password rendered as pixels
  pii_screenshot       — US SSN + credit-card-shaped number rendered as pixels
  business_doc         — "CONFIDENTIAL Q4 revenue" text (keyword-only, no secret)
  trailing_zip         — valid PNG with a ZIP appended past IEND (polyglot)
  exif_gps             — JPEG carrying GPS EXIF tags (location leak)
  gif_payload_frame2   — 2-frame GIF, benign frame 1, secret text in frame 2
"""
import io
import zipfile

from PIL import Image, ImageDraw, ImageFont
from PIL.TiffImagePlugin import IFDRational

# A slightly larger bitmap font renders more reliably through Tesseract than the
# tiny built-in default. Fall back to the default if no TTF is available.
_FONT = None
for _cand in (
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    # Arch and other distros: DejaVu elsewhere, or a metric-similar *sans* face. Sans fonts OCR
    # the fake keys intact; Liberation/Free Mono were measured to drop or misread characters.
    "/usr/share/fonts/TTF/DejaVuSans.ttf",
    "/usr/share/fonts/liberation/LiberationSans-Regular.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
    "/usr/share/fonts/gnu-free/FreeSans.otf",
):
    try:
        _FONT = ImageFont.truetype(_cand, 28)
        break
    except OSError:
        continue
if _FONT is None:
    _FONT = ImageFont.load_default()


def render_text_png(lines, size=(700, 450)):
    """Render text lines as black-on-white PNG bytes (OCR-friendly)."""
    img = Image.new("RGB", size, "white")
    draw = ImageDraw.Draw(img)
    y = 24
    for line in lines:
        draw.text((24, y), line, fill="black", font=_FONT)
        y += 40
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _benign_gradient(size=(256, 256)):
    img = Image.new("RGB", size)
    px = img.load()
    for x in range(size[0]):
        for y in range(size[1]):
            px[x, y] = (x % 256, y % 256, (x + y) % 256)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _trailing_zip():
    png = _benign_gradient()
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w") as zf:
        zf.writestr("payload.txt", "hidden appended content")
    return png + zbuf.getvalue()


def _exif_gps():
    img = Image.new("RGB", (128, 128), "skyblue")
    exif = img.getexif()
    gps_ifd = {
        1: "N",
        2: (IFDRational(33, 1), IFDRational(41, 1), IFDRational(0, 1)),  # 33°41'0" N
        3: "E",
        4: (IFDRational(73, 1), IFDRational(3, 1), IFDRational(0, 1)),   # 73°3'0" E
    }
    # 0x8825 = GPSInfo IFD pointer tag.
    exif[0x8825] = gps_ifd
    buf = io.BytesIO()
    img.save(buf, format="JPEG", exif=exif)
    return buf.getvalue()


def make_gif(frame_texts):
    """Build a multi-frame GIF; each element is a list of text lines."""
    frames = []
    for lines in frame_texts:
        img = Image.new("RGB", (700, 300), "white")
        draw = ImageDraw.Draw(img)
        y = 24
        for line in lines:
            draw.text((24, y), line, fill="black", font=_FONT)
            y += 40
        frames.append(img)
    buf = io.BytesIO()
    frames[0].save(
        buf, format="GIF", save_all=True, append_images=frames[1:], duration=200, loop=0
    )
    return buf.getvalue()


SYNTH_CASES = {
    "benign_gradient": _benign_gradient(),
    "secret_screenshot": render_text_png([
        "AWS deployment config",
        "aws_access_key_id = AKIAIOSFODNN7REALKEYX",
        "password: hunter2SuperSecret",
    ]),
    "pii_screenshot": render_text_png([
        "Employee record",
        "SSN 123-45-6789",
        "Card 4111 1111 1111 1111",
    ]),
    "business_doc": render_text_png([
        "CONFIDENTIAL",
        "Q4 revenue summary",
        "budget review internal use only",
    ]),
    "trailing_zip": _trailing_zip(),
    "exif_gps": _exif_gps(),
    "gif_payload_frame2": make_gif([
        ["welcome to the newsletter", "cute cat photos inside"],
        ["aws_access_key_id = AKIAIOSFODNN7REALKEYX"],
    ]),
}
