"""Document content understanding.

Extracts text from PDFs (PyMuPDF), DOCX (zipfile XML), and plaintext, then
runs a regex keyword sweep against known sensitive document classes.
"""

from __future__ import annotations

import io
import logging
import os
import re
import sys
import zipfile
from typing import List, Optional, Tuple

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.schemas import AnalysisResult

logger = logging.getLogger("document_service.content")

try:
    import fitz  # PyMuPDF
except Exception as exc:  # pragma: no cover
    fitz = None
    logger.warning("PyMuPDF unavailable for content rendering: %s", exc)

REFERENCE_LABELS: List[str] = [
    "internal financial balance sheet",
    "confidential legal contract",
    "non-disclosure agreement",
    "source code listing with credentials",
    "network diagram with internal ip addresses",
    "employee personal record with salary",
    "public terms of service",
    "marketing brochure",
    "invoice",
    "resume cv",
]

SENSITIVE_LABELS = {
    "internal financial balance sheet",
    "confidential legal contract",
    "non-disclosure agreement",
    "source code listing with credentials",
    "network diagram with internal ip addresses",
    "employee personal record with salary",
}

KEYWORD_BUCKETS = {
    "internal financial balance sheet": [
        r"\bbalance sheet\b",
        r"\bquarterly (?:revenue|earnings)\b",
        r"\binternal financial\b",
    ],
    "confidential legal contract": [
        r"\bconfidential\b",
        r"\bnon[- ]disclosure\b",
        r"\bnda\b",
        r"\battorney[- ]client\b",
    ],
    "employee personal record with salary": [
        r"\bsalary\b",
        r"\bsocial security number\b",
        r"\bssn\b",
        r"\bpayroll\b",
    ],
    "source code listing with credentials": [
        r"api[_ ]?key\s*[=:]",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        r"AKIA[0-9A-Z]{16}",
    ],
    "network diagram with internal ip addresses": [
        r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        r"\b192\.168\.\d{1,3}\.\d{1,3}\b",
        r"\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b",
    ],
}

def load_model() -> None:
    """No-op — kept for API compatibility with main.py startup."""
    logger.info("content_model ready (text + keyword path)")


def _extract_text_pdf(data: bytes) -> str:
    if fitz is None:
        return ""
    try:
        doc = fitz.open(stream=data, filetype="pdf")
    except Exception as exc:
        logger.warning("PyMuPDF text open failed: %s", exc)
        return ""
    try:
        chunks: List[str] = []
        for page in doc:
            chunks.append(page.get_text("text"))
            if len(chunks) >= 5:
                break
        return "\n".join(chunks)
    finally:
        doc.close()


def _extract_text_docx(data: bytes) -> str:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            if "word/document.xml" not in zf.namelist():
                return ""
            xml = zf.read("word/document.xml").decode("utf-8", errors="ignore")
            return re.sub(r"<[^>]+>", " ", xml)
    except zipfile.BadZipFile:
        return ""


def extract_text(data: bytes) -> str:
    if data.startswith(b"%PDF"):
        return _extract_text_pdf(data)
    if data.startswith(b"PK\x03\x04"):
        return _extract_text_docx(data)
    try:
        return data[:65536].decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _keyword_classify(text: str) -> Tuple[Optional[str], float, List[str]]:
    if not text:
        return None, 0.0, []
    lowered = text.lower()
    best_label: Optional[str] = None
    best_score = 0.0
    findings: List[str] = []

    for label, patterns in KEYWORD_BUCKETS.items():
        hits = 0
        for pat in patterns:
            if re.search(pat, lowered, re.IGNORECASE):
                hits += 1
        if hits == 0:
            continue
        # Score: 0.5 baseline + 0.15 per additional hit, capped at 0.95.
        score = min(0.95, 0.5 + 0.15 * (hits - 1))
        findings.append(f"Keyword bucket '{label}' matched {hits} pattern(s)")
        if score > best_score:
            best_score = score
            best_label = label

    return best_label, best_score, findings


def analyze(data: bytes) -> AnalysisResult:
    try:
        text = extract_text(data)
        kw_label, kw_score, findings = _keyword_classify(text)

        score = 0.0
        chosen_label = None
        if kw_label and kw_label in SENSITIVE_LABELS:
            score = kw_score
            chosen_label = kw_label
            findings.append(f"Sensitive content (keywords): {kw_label} ({kw_score:.2f})")

        return AnalysisResult(
            module="content",
            score=float(score),
            findings=findings,
            raw_data={"label": chosen_label, "text_sample": text[:500]},
        )
    except Exception as exc:
        logger.exception("content model failed: %s", exc)
        return AnalysisResult(
            module="content",
            score=0.0,
            findings=[f"content error: {exc}"],
        )
