"""Robust OCR text extraction for screenshots (glue around Tesseract; weights unchanged).

Why: the single default-psm read on a grayscale image drops/misreads characters
in monospace code/terminal screenshots (the most likely real secret screenshots)
and on coloured syntax highlighting / dark themes. Secret detection is an OR over
the text, so the text of several differently-conditioned reads can simply be
UNIONed: extra reads only ever add recall (false-positive control is done in
ml.image.ocr_scan, which is also hardened against OCR-noise artefacts).

Reads (see VARIANTS):
  legacy   the pre-existing read (preprocess.for_ocr + default psm) - kept so the
           union is a strict superset of the old behaviour
  ink      colour-agnostic "ink" image (distance from the modal background
           colour, black on white, so dark themes and coloured tokens are
           handled), rescaled so text lines are ~TARGET_LINE_PX tall, read with
           --psm 6 and a printable-ASCII whitelist (stops Tesseract inventing
           euro/yen/accented glyphs inside tokens)
  ink_alt  same, at a different scale, --psm 4 (independent errors for the union)

DEFAULT = ink + ink_alt (~2.1x the legacy single read's latency, measured; adding
legacy gave 3.2x for no measured gain). Override with IMAGE_OCR_VARIANTS=a,b,...
"""
from __future__ import annotations

import os
import shlex
import string
from typing import Callable, Iterable

import numpy as np
import pytesseract
from PIL import Image

from ml.image import preprocess

TARGET_LINE_PX = int(os.getenv("IMAGE_OCR_TARGET_LINE_PX", "34"))
MAX_PIXELS = 14_000_000
_WHITELIST = string.ascii_letters + string.digits + "-_.:/@=+,;!#$%&*()[]{}<>?\"'~^|\\` "
_WL_CFG = "-c " + shlex.quote("tessedit_char_whitelist=" + _WHITELIST)

# Unicode look-alikes Tesseract emits for ASCII punctuation inside tokens.
_ASCII_FIX = str.maketrans({
    "‐": "-", "‑": "-", "‒": "-", "–": "-", "—": "-", "−": "-",
    "‘": "'", "’": "'", "“": '"', "”": '"',
})


def ink_image(image: Image.Image) -> Image.Image:
    """Black-on-white 'ink' map: per-pixel max-channel distance from the modal
    (background) colour, stretched to full range. Theme/colour agnostic."""
    rgb = np.asarray(image.convert("RGB"))
    sub = rgb[:: max(1, rgb.shape[0] // 256), :: max(1, rgb.shape[1] // 256)].reshape(-1, 3)
    keys = (sub[:, 0].astype(np.int32) << 16) | (sub[:, 1].astype(np.int32) << 8) | sub[:, 2]
    vals, counts = np.unique(keys, return_counts=True)
    top = int(vals[counts.argmax()])
    bg = np.array([(top >> 16) & 255, (top >> 8) & 255, top & 255], dtype=np.int16)
    dist = np.abs(rgb.astype(np.int16) - bg).max(axis=2).astype(np.float32)
    peak = float(dist.max())
    if peak < 8:  # flat image: nothing to read
        return Image.fromarray(np.full(dist.shape, 255, np.uint8))
    return Image.fromarray((255.0 - dist * (255.0 / peak)).astype(np.uint8))


def estimate_line_px(ink: Image.Image) -> float:
    """Median height of horizontal text bands (rows holding ink), from the
    projection profile. Returns 0 if no band is found."""
    arr = np.asarray(ink) < 160
    rows = arr.sum(axis=1) > max(1, arr.shape[1] * 0.002)
    bands, run = [], 0
    for r in rows:
        if r:
            run += 1
        elif run:
            bands.append(run)
            run = 0
    if run:
        bands.append(run)
    bands = [b for b in bands if b >= 3]
    return float(np.median(bands)) if bands else 0.0


def _scaled(ink: Image.Image, mult: float) -> Image.Image:
    h = estimate_line_px(ink)
    f = TARGET_LINE_PX / h if h else 2.0
    f = min(max(f * mult, 1.0), 4.0)
    f = min(f, (MAX_PIXELS / (ink.width * ink.height)) ** 0.5)
    if f < 1.05:
        return ink
    return ink.resize((round(ink.width * f), round(ink.height * f)), Image.LANCZOS)


def _legacy(image: Image.Image) -> str:
    return pytesseract.image_to_string(preprocess.for_ocr(image))


def _ink(image: Image.Image) -> str:
    return pytesseract.image_to_string(_scaled(ink_image(image), 1.0), config=f"--psm 6 {_WL_CFG}")


def _ink_alt(image: Image.Image) -> str:
    return pytesseract.image_to_string(_scaled(ink_image(image), 0.7), config=f"--psm 4 {_WL_CFG}")


VARIANTS: dict[str, Callable[[Image.Image], str]] = {"legacy": _legacy, "ink": _ink, "ink_alt": _ink_alt}
DEFAULT = tuple(os.getenv("IMAGE_OCR_VARIANTS", "ink,ink_alt").split(","))


def normalize(text: str) -> str:
    return text.translate(_ASCII_FIX)


def read_text(image: Image.Image, variants: Iterable[str] = DEFAULT) -> str:
    """Union (concatenation) of the texts of the selected reads. A failing read
    is skipped so the others still count; if all fail the error propagates."""
    texts, err = [], None
    for name in variants:
        try:
            texts.append(VARIANTS[name](image))
        except Exception as e:  # noqa: BLE001 - one bad config must not hide the rest
            err = e
    if not texts and err:
        raise err
    return normalize("\n".join(texts))
