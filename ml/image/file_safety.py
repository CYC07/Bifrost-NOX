"""Malicious-input guards that run on the raw bytes BEFORE model decoding.

image_service previously called Image.open on untrusted bytes with no guards.
This adds the checks a firewall actually needs:

  - format allow-list      — magic-byte sniff; reject SVG (script-bearing XML)
                             and anything not a known raster format.
  - decompression bomb     — cap pixel count so a tiny file that declares huge
                             dimensions can't exhaust memory on decode.
  - trailing-bytes polyglot — bytes after the image stream's real end (PNG
                             IEND+CRC / JPEG EOI) hide appended ZIP/PHP/etc.
  - EXIF GPS leak          — advisory (non-blocking) location-privacy signal.

Pure functions on bytes; fail-open (any unexpected error -> neutral result).
"""
import io
import logging

from PIL import Image

from common.schemas import AnalysisResult, RiskLevel

logger = logging.getLogger("image_service")

# Cap decoded pixel count (width*height). PIL's own default bomb threshold is
# ~89M; we set a tighter, explicit cap for transit images.
MAX_PIXELS = 40_000_000
Image.MAX_IMAGE_PIXELS = MAX_PIXELS

_MAGIC = {
    b"\x89PNG\r\n\x1a\n": "png",
    b"\xff\xd8\xff": "jpeg",
    b"GIF87a": "gif",
    b"GIF89a": "gif",
    b"BM": "bmp",
    b"II*\x00": "tiff",
    b"MM\x00*": "tiff",
}


def _sniff(data: bytes):
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    for magic, fmt in _MAGIC.items():
        if data.startswith(magic):
            return fmt
    # SVG / XML vector — script-bearing, reject explicitly.
    head = data[:256].lstrip().lower()
    if head.startswith(b"<?xml") or head.startswith(b"<svg"):
        return "svg"
    return None


# Executable / archive / script magics that should never ride in an image's
# trailing bytes. Real files routinely carry BENIGN trailing bytes (camera
# padding, Android Motion Photo appending an MP4, scanner block padding), so
# "any trailing byte" over-blocks. We require an actual payload signature —
# higher precision for the same polyglot threat.
_PAYLOAD_MAGICS = (
    b"PK\x03\x04",   # ZIP / JAR / APK / Office
    b"PK\x05\x06",   # empty ZIP
    b"Rar!\x1a\x07", # RAR
    b"7z\xbc\xaf\x27\x1c",  # 7z
    b"MZ",           # PE / DOS executable
    b"\x7fELF",      # ELF executable
    b"<?php",        # PHP webshell
    b"<%",           # ASP/JSP
    b"#!",           # shell/script shebang
    b"\x1f\x8b",     # gzip
)


def _trailing_payload(data: bytes, fmt: str) -> bytes | None:
    """Return the payload magic if data past the image's real end-of-stream
    marker begins with (or contains near its start) a known payload signature."""
    if fmt == "png":
        idx = data.rfind(b"IEND")
        if idx == -1:
            return None
        tail = data[idx + 8:]  # 'IEND' + 4-byte CRC
    elif fmt == "jpeg":
        idx = data.rfind(b"\xff\xd9")  # EOI
        if idx == -1:
            return None
        tail = data[idx + 2:]
    else:
        # GIF trailer (0x3B) and container formats carry length in-header; skip.
        return None
    if not tail.strip(b"\x00\r\n\t "):
        return None  # only benign padding
    for magic in _PAYLOAD_MAGICS:
        # Check the very start and a short window (skip a few pad bytes).
        if tail[:64].lstrip(b"\x00\r\n\t ").startswith(magic) or magic in tail[:8]:
            return magic
    return None


def check_bytes(data: bytes) -> AnalysisResult:
    if not data:
        return AnalysisResult(module="file_safety", score=0.0, findings=["Empty file"],
                              blocked=True, risk=RiskLevel.MEDIUM)
    try:
        fmt = _sniff(data)

        if fmt is None or fmt == "svg":
            what = "SVG/XML vector" if fmt == "svg" else "unknown/unsupported"
            return AnalysisResult(
                module="file_safety", score=1.0,
                findings=[f"Rejected file format: {what} (not an allowed raster image)"],
                blocked=True, risk=RiskLevel.HIGH,
            )

        payload = _trailing_payload(data, fmt)
        if payload is not None:
            return AnalysisResult(
                module="file_safety", score=1.0,
                findings=[f"Polyglot: {payload!r} payload appended past {fmt.upper()} end-of-stream"],
                blocked=True, risk=RiskLevel.HIGH,
            )

        # Decompression-bomb / decode-integrity probe.
        try:
            with Image.open(io.BytesIO(data)) as probe:
                w, h = probe.size
                if w * h > MAX_PIXELS:
                    return AnalysisResult(
                        module="file_safety", score=1.0,
                        findings=[f"Decompression bomb: {w}x{h} exceeds {MAX_PIXELS} pixel cap"],
                        blocked=True, risk=RiskLevel.HIGH,
                    )
                probe.verify()
        except Image.DecompressionBombError:
            return AnalysisResult(
                module="file_safety", score=1.0,
                findings=["Decompression bomb detected on decode"],
                blocked=True, risk=RiskLevel.HIGH,
            )
        except Exception as e:
            return AnalysisResult(
                module="file_safety", score=1.0,
                findings=[f"Corrupt/undecodable image: {e}"],
                blocked=True, risk=RiskLevel.MEDIUM,
            )

        # EXIF GPS — advisory only.
        findings = []
        try:
            with Image.open(io.BytesIO(data)) as img:
                exif = img.getexif()
                gps = exif.get_ifd(0x8825) if exif else None
                if gps:
                    findings.append("EXIF GPS location metadata present (privacy)")
        except Exception:
            pass

        risk = RiskLevel.MEDIUM if findings else RiskLevel.SAFE
        return AnalysisResult(module="file_safety", score=0.0, findings=findings,
                              blocked=False, risk=risk)
    except Exception as e:
        logger.error(f"file_safety error: {e}")
        return AnalysisResult(module="file_safety", score=0.0, findings=[])
