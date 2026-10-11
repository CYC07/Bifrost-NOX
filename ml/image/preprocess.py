"""Preprocessing helpers for OCR and CLIP — signal-in improvements, no weights.

OCR: Tesseract reads screenshots more reliably after grayscale + contrast
normalisation + upscaling small images. We deliberately do NOT force a fixed
`--psm` page-segmentation mode: the synthetic corpus is single-block text, so
tuning psm on it would overfit; default auto-layout (psm 3) generalises to
multi-column/UI screenshots.

CLIP: a small ID card in the corner of a large screenshot is missed by one
global view. `crops` yields whole + centre + quadrant tiles for max-pooling.
NOTE: max-pooling over crops raises every group score monotonically, which
would invalidate the single-view cutoffs in clip_labels.GROUP_CUTOFF — so the
classifier keeps multi-crop OFF unless IMAGE_CLIP_MULTICROP is set (see
clip_classifier.classify). Recalibration against a real labelled image set is
required before it can be the default.
"""
from PIL import Image, ImageOps

# Upscale small images up to this longest-edge target to help Tesseract.
_OCR_UPSCALE_TARGET = 1000
_OCR_MAX_SCALE = 2.0


def for_ocr(image: Image.Image) -> Image.Image:
    """Grayscale + autocontrast + upscale-if-small. Layout-preserving; no
    binarisation threshold (which can erase anti-aliased screenshot text)."""
    img = image.convert("L")
    img = ImageOps.autocontrast(img)
    longest = max(img.size)
    if longest < _OCR_UPSCALE_TARGET:
        scale = min(_OCR_MAX_SCALE, _OCR_UPSCALE_TARGET / longest)
        new_size = (round(img.width * scale), round(img.height * scale))
        img = img.resize(new_size, Image.LANCZOS)
    return img


def crops(image: Image.Image):
    """Whole image + centre crop + four quadrants (RGB). Each is fed through
    the CLIP processor separately, so no manual resize is needed here."""
    img = image.convert("RGB")
    w, h = img.size
    out = [img]
    # Centre crop (60% box).
    cw, ch = int(w * 0.6), int(h * 0.6)
    left, top = (w - cw) // 2, (h - ch) // 2
    out.append(img.crop((left, top, left + cw, top + ch)))
    # Quadrants.
    mx, my = w // 2, h // 2
    out.append(img.crop((0, 0, mx, my)))
    out.append(img.crop((mx, 0, w, my)))
    out.append(img.crop((0, my, mx, h)))
    out.append(img.crop((mx, my, w, h)))
    return out
