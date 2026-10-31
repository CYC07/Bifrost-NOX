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
from ml.image.ocr_tolerant import tolerant_findings
from ml.secrets.detector import detect as detect_secrets
from ml.secrets.patterns import PLACEHOLDER_VALUES

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


# --- OCR-noise hardening (these only ever REDUCE blocking or recover a clear true positive) ---
# Presidio's weakest SSN patterns (bare digit runs) score ~0.05 and fire on log
# numbers/ids; real SSNs in dashed form are still caught by _SSN_RE below.
_MIN_SSN_SCORE = 0.3

# A vendor example key (AKIA...EXAMPLE) misread by OCR by 1-2 characters is still
# the example key, not a leaked secret.
_PLACEHOLDER_MAX_EDITS = 2

# JWT whose base64 segments carry a few OCR errors: the strict validator in
# ml.secrets rejects it, so recognise the shape + "decodes to mostly-printable JSON".
_FUZZY_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{12,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}")


def _edit_distance_le(a: str, b: str, k: int) -> bool:
    if abs(len(a) - len(b)) > k:
        return False
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1] <= k


def _near_placeholder(text: str, span: tuple) -> bool:
    """True if the whole token around `span` is within a few edits of a vendor
    placeholder (OCR may insert/drop characters, shifting the fixed-width match)."""
    a, b = span
    while a > 0 and (text[a - 1].isalnum() or text[a - 1] == "_"):
        a -= 1
    while b < len(text) and (text[b].isalnum() or text[b] == "_"):
        b += 1
    tok = text[a:b]
    return any(_edit_distance_le(tok, p, _PLACEHOLDER_MAX_EDITS) for p in PLACEHOLDER_VALUES)


def _b64_head_is_json(seg: str, n: int = 8) -> bool:
    import base64
    seg = seg[:n]
    seg = seg[: len(seg) - len(seg) % 4]
    try:
        raw = base64.urlsafe_b64decode(seg)
    except Exception:
        return False
    return raw.startswith(b"{\"") and all(32 <= c < 127 for c in raw)


def _fuzzy_jwt(text: str) -> bool:
    """OCR splits long tokens with spaces and injects stray glyphs, so collapse
    whitespace / drop non-token glyphs per line and require JWT shape with two
    base64 segments whose heads decode to JSON ('{"alg"...', '{"sub"...')."""
    for line in text.splitlines():
        i = line.find("eyJ")
        if i < 0:
            continue
        cand = re.sub(r"[^A-Za-z0-9_.-]", "", line[i:].replace(")", "J").replace("]", "J"))
        m = _FUZZY_JWT_RE.match(cand)
        if m:
            h, pl, _sig = m.group(0).split(".", 2)
            if _b64_head_is_json(h) and _b64_head_is_json(pl):
                return True
    return False


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
            if _near_placeholder(text, f.span):
                continue
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
            if res.entity_type == "US_SSN" and res.score < _MIN_SSN_SCORE:
                continue
            findings.append(f"PII in image text: {res.entity_type} ({res.score:.2f})")
            if res.entity_type in _BLOCKING_PII:
                blocked = True
                if _risk_index(RiskLevel.CRITICAL) > _risk_index(risk):
                    risk = RiskLevel.CRITICAL
                score = max(score, 0.9)
    except Exception as e:
        logger.error(f"OCR Presidio scan error: {e}")

    # 2a. OCR-damaged prefixed tokens / key header / DB URL (see ocr_tolerant).
    try:
        have = " ".join(findings)
        for kind, sev in tolerant_findings(text):
            if kind in have:
                continue
            findings.append(f"Secret in image text: {kind} (severity={sev})")
            blocked = True
            if _risk_index(RiskLevel(sev)) > _risk_index(risk):
                risk = RiskLevel(sev)
            score = 1.0
    except Exception as e:
        logger.error(f"OCR tolerant scan error: {e}")

    # 2b. OCR-damaged JWT (strict validator rejects it).
    try:
        if not any("JWT" in f for f in findings) and _fuzzy_jwt(text):
            findings.append("Secret in image text: JWT (OCR-tolerant) (severity=high)")
            blocked = True
            if _risk_index(RiskLevel.HIGH) > _risk_index(risk):
                risk = RiskLevel.HIGH
            score = 1.0
    except Exception as e:
        logger.error(f"OCR JWT scan error: {e}")

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
