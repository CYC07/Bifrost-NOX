"""Run the firewall's existing text detectors over OCR'd image text.

The old image `model_ocr` only substring-matched ~12 keywords, so a screenshot
carrying a live AWS key or an SSN passed clean unless a literal keyword was
present. This reuses the already-built, precise detectors instead:

  1. ml.secrets.detect        — 14 vendor patterns + structural validation.
  2. Presidio PII             — financial/gov identifiers block; contact info
                                (email/phone) is informational only.
  3. US-SSN regex fallback    — this Presidio version does NOT detect US_SSN
                                (verified); a small validated regex closes that
                                gap for the DLP path.
  4. Sensitive-keyword list   — business-document language (confidential/Q4/
                                budget) as a NON-blocking signal, kept from the
                                original so aggregation can combine it with the
                                CLIP visual signal.

Every analyzer sets its own calibrated decision; the caller ORs them.
Fail-open: any exception yields a neutral result, never a crash.
"""
import logging
import re

from common.schemas import AnalysisResult, RiskLevel
from ml.secrets.detector import detect as detect_secrets

logger = logging.getLogger("image_service")

# Financial/government identifiers — never benign in transit, so they block.
# Contact info (email/phone) is surfaced but does not block (routine traffic).
_BLOCKING_PII = {"CREDIT_CARD", "US_SSN", "IBAN"}
_CONTACT_PII = {"EMAIL_ADDRESS", "PHONE_NUMBER"}
_PRESIDIO_ENTITIES = list(_BLOCKING_PII | _CONTACT_PII)

# Non-blocking business-document keywords (kept from the original model_ocr).
_SENSITIVE_KEYWORDS = [
    "confidential", "secret", "password", "private key", "internal use only",
    "revenue", "q1", "q2", "q3", "q4", "budget", "ssn",
]

# US SSN: AAA-GG-SSSS with the standard invalid-block exclusions (area 000/666/
# 900-999, group 00, serial 0000). Compensates for the Presidio SSN gap.
_SSN_RE = re.compile(r"\b(?!000|666|9\d\d)(\d{3})-(?!00)\d{2}-(?!0000)\d{4}\b")


def _risk_index(level: RiskLevel) -> int:
    return list(RiskLevel).index(level)


def scan_ocr_text(text: str, presidio) -> AnalysisResult:
    """Scan OCR-extracted text; return a blocking AnalysisResult on any secret
    or financial/gov identifier, else a non-blocking signal for keyword hits."""
    if not text or not text.strip():
        return AnalysisResult(module="ocr", score=0.0, findings=[])

    findings: list[str] = []
    blocked = False
    risk = RiskLevel.SAFE
    score = 0.0

    # 1. Secrets (blocking, severity -> risk).
    try:
        for f in detect_secrets(text):
            findings.append(f"Secret in image text: {f.kind} (severity={f.severity})")
            blocked = True
            sev = RiskLevel(f.severity)
            if _risk_index(sev) > _risk_index(risk):
                risk = sev
            score = 1.0
    except Exception as e:  # fail-open on this analyzer only
        logger.error(f"OCR secret scan error: {e}")

    # 2. Presidio PII.
    try:
        for res in presidio.analyze(text=text, entities=_PRESIDIO_ENTITIES, language="en"):
            findings.append(f"PII in image text: {res.entity_type} ({res.score:.2f})")
            if res.entity_type in _BLOCKING_PII:
                blocked = True
                if _risk_index(RiskLevel.CRITICAL) > _risk_index(risk):
                    risk = RiskLevel.CRITICAL
                score = max(score, 0.9)
    except Exception as e:
        logger.error(f"OCR Presidio scan error: {e}")

    # 3. SSN regex fallback (Presidio-version gap).
    try:
        if _SSN_RE.search(text):
            findings.append("PII in image text: US_SSN (regex fallback)")
            blocked = True
            risk = RiskLevel.CRITICAL
            score = max(score, 0.9)
    except Exception as e:
        logger.error(f"OCR SSN scan error: {e}")

    # 4. Sensitive keywords — non-blocking signal.
    low = text.lower()
    kw_hits = [k for k in _SENSITIVE_KEYWORDS if k in low]
    if kw_hits:
        findings.append(f"Sensitive keyword(s) in image text: {', '.join(kw_hits)}")
        if not blocked:
            score = max(score, 0.4)

    return AnalysisResult(
        module="ocr",
        score=score,
        findings=findings,
        raw_data={"extracted_text": text[:500]},
        blocked=blocked,
        risk=risk,
    )
