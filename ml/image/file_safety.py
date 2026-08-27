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


def _has_trailing_bytes(data: bytes, fmt: str) -> bool:
    """True if bytes exist past the format's real end-of-stream marker."""
    if fmt == "png":
        idx = data.rfind(b"IEND")
        if idx == -1:
            return False
        end = idx + 4 + 4  # 'IEND' + 4-byte CRC
        return len(data) > end
    if fmt == "jpeg":
        idx = data.rfind(b"\xff\xd9")  # EOI
        if idx == -1:
            return False
        return len(data) > idx + 2
    # GIF trailer (0x3B) and container formats carry length in-header; skip.
    return False


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

        if _has_trailing_bytes(data, fmt):
            return AnalysisResult(
                module="file_safety", score=1.0,
                findings=[f"Polyglot: {len(data)} bytes with data appended past {fmt.upper()} end-of-stream"],
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
