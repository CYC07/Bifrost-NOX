"""Forensic metadata analysis for documents.

Pulls metadata via ``pyexiftool`` when the ``exiftool`` binary is available,
otherwise falls back to PyMuPDF for PDFs and ``zipfile``/XML parsing for Office
documents. Findings include path-leak regex hits, GPS coordinates, suspicious
producer/creator strings, and presence of revision history in docx files.
"""

from __future__ import annotations

import io
import logging
import os
import re
import shutil
import sys
import tempfile
import zipfile
from typing import Any, Dict, List

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.schemas import AnalysisResult

logger = logging.getLogger("document_service.metadata")

try:
    import fitz  # PyMuPDF
except Exception as exc:  # pragma: no cover - environment dependent
    fitz = None
    logger.warning("PyMuPDF unavailable for metadata extraction: %s", exc)

try:
    import exiftool  # pyexiftool
except Exception as exc:  # pragma: no cover - environment dependent
    exiftool = None
    logger.info("pyexiftool not importable: %s", exc)


PATH_LEAK_PATTERNS = [
    re.compile(r"C:\\Users\\[^\\\"\s]+", re.IGNORECASE),
    re.compile(r"/home/[^/\s\"]+/"),
    re.compile(r"/Users/[^/\s\"]+/"),
]

PRODUCER_ALLOWLIST = {
    "microsoft word",
    "microsoft excel",
    "microsoft powerpoint",
    "microsoft office",
    "libreoffice",
    "openoffice",
    "adobe",
    "acrobat",
    "chromium",
    "chrome",
    "skia",
    "macos",
    "preview",
    "pages",
    "tex",
    "latex",
    "pdftex",
    "xetex",
    "luatex",
    "pdfkit",
    "wkhtmltopdf",
    "mupdf",
    "pymupdf",
    "ghostscript",
}

SUSPICIOUS_PRODUCER_HINTS = (
    "metasploit",
    "msfvenom",
    "cobaltstrike",
    "empire",
    "exploit",
    "payload",
)


def _exiftool_available() -> bool:
    return exiftool is not None and shutil.which("exiftool") is not None


def _extract_with_exiftool(data: bytes) -> Dict[str, Any]:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
        tmp.write(data)
        tmp_path = tmp.name
    try:
        with exiftool.ExifToolHelper() as et:
            metadata = et.get_metadata(tmp_path)
        return metadata[0] if metadata else {}
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def _extract_pdf_metadata(data: bytes) -> Dict[str, Any]:
    if fitz is None:
        return {}
    try:
        doc = fitz.open(stream=data, filetype="pdf")
    except Exception as exc:
        logger.warning("PyMuPDF metadata open failed: %s", exc)
        return {}
    try:
        meta = dict(doc.metadata or {})
        meta["page_count"] = doc.page_count
        return meta
    finally:
        doc.close()


def _extract_office_metadata(data: bytes) -> Dict[str, Any]:
    meta: Dict[str, Any] = {}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = set(zf.namelist())
            if "docProps/core.xml" in names:
                core = zf.read("docProps/core.xml").decode("utf-8", errors="ignore")
                meta["core_xml"] = core
            if "docProps/app.xml" in names:
                app = zf.read("docProps/app.xml").decode("utf-8", errors="ignore")
                meta["app_xml"] = app
            if "word/document.xml" in names:
                body = zf.read("word/document.xml").decode("utf-8", errors="ignore")
                meta["has_revisions"] = ("w:ins" in body) or ("w:del" in body)
    except zipfile.BadZipFile:
        return {}
    return meta


def extract(data: bytes) -> Dict[str, Any]:
    if _exiftool_available():
        try:
            return _extract_with_exiftool(data)
        except Exception as exc:
            logger.warning("exiftool extraction failed, falling back: %s", exc)
    if data.startswith(b"%PDF"):
        return _extract_pdf_metadata(data)
    if data.startswith(b"PK\x03\x04"):
        return _extract_office_metadata(data)
    return {}


def _flatten_strings(meta: Dict[str, Any]) -> str:
    parts: List[str] = []
    for key, value in meta.items():
        if isinstance(value, (str, int, float)):
            parts.append(f"{key}={value}")
        else:
            parts.append(f"{key}={value!r}")
    return "\n".join(parts)


def analyze(data: bytes) -> AnalysisResult:
    try:
        meta = extract(data)
    except Exception as exc:
        logger.exception("metadata extraction failed: %s", exc)
        return AnalysisResult(
            module="metadata",
            score=0.0,
            findings=[f"metadata error: {exc}"],
        )

    if not meta:
        return AnalysisResult(module="metadata", score=0.0, findings=[])

    findings: List[str] = []
    score = 0.0
    haystack = _flatten_strings(meta)

    for pattern in PATH_LEAK_PATTERNS:
        for hit in pattern.findall(haystack):
            findings.append(f"Local path leak: {hit}")
            score += 0.25

    if "GPSLatitude" in haystack or "GPSLongitude" in haystack:
        findings.append("GPS coordinates embedded in document metadata")
        score += 0.25

    producer_fields = []
    for key in ("producer", "Producer", "creator", "Creator", "creatorTool"):
        val = meta.get(key)
        if isinstance(val, str):
            producer_fields.append(val)

    for value in producer_fields:
        lowered = value.lower()
        if any(hint in lowered for hint in SUSPICIOUS_PRODUCER_HINTS):
            findings.append(f"Suspicious producer: {value}")
            score += 0.25
            continue
        if not any(allowed in lowered for allowed in PRODUCER_ALLOWLIST):
            findings.append(f"Unrecognised producer/creator: {value}")
            score += 0.1

    if meta.get("has_revisions"):
        findings.append("Document contains tracked changes / revision history")
        score += 0.25

    score = min(score, 0.9)

    return AnalysisResult(
        module="metadata",
        score=float(score),
        findings=findings,
        raw_data={"metadata_keys": sorted(meta.keys())},
    )
