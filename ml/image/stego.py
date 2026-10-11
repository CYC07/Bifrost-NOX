"""LSB steganalysis via the chi-square attack — ADVISORY TELEMETRY ONLY.

The original heuristic tested a single R-channel LSB plane and flagged images
whose mean LSB density was within 0.005 of 0.5 — near-noise. This computes the
chi-square Pairs-of-Values statistic (Westfeld & Pfitzmann) across all channels
instead, which is the classic detector for sequential LSB replacement.

HONEST LIMITATION: a single global chi-square over the whole image is a weak
detector, and these thresholds are NOT validated against a real stego corpus
(none was available). Measured behaviour: a smooth synthetic gradient scores
chi/dof=0.0 (looks maximally "embedded" but is benign), while a random-noise
image and an LSB-embedded image sit at ~0.48 and ~0.42 — i.e. this global
statistic does not cleanly separate embedded from clean. Because of that:

  - stego NEVER blocks (worst case would be finding-spam, not blocked traffic);
  - the chi/dof value is always returned in raw_data as telemetry;
  - the alarming "possible steganography" finding is emitted ONLY when
    IMAGE_STEGO_STRICT is set, so production doesn't cry wolf on every gradient.

A proper detector (RS analysis, or per-region sequential chi-square with a
p-value) plus a labelled stego test set is the follow-up.
"""
import logging
import os

import numpy as np
from PIL import Image

from common.schemas import AnalysisResult, RiskLevel

logger = logging.getLogger("image_service")

STRICT = os.getenv("IMAGE_STEGO_STRICT", "").lower() in ("1", "true", "yes")


def chi_square_lsb(image: Image.Image) -> AnalysisResult:
    try:
        arr = np.asarray(image.convert("RGB")).ravel()
        hist = np.bincount(arr, minlength=256).astype(np.float64)
        even = hist[0::2]
        odd = hist[1::2]
        pair_sum = even + odd
        mask = pair_sum >= 32
        if mask.sum() == 0:
            return AnalysisResult(module="stego", score=0.0, findings=[])
        expected = pair_sum[mask] / 2.0
        observed = even[mask]
        chi = float(np.sum((observed - expected) ** 2 / expected))
        dof = int(mask.sum())
        ratio = chi / dof

        raw = {"chi_over_dof": round(ratio, 4), "strict": STRICT}
        findings = []
        if STRICT and ratio < 0.25:
            # Only the most extreme equalisation, and only when explicitly asked.
            findings.append(
                f"LSB pairs strongly equalised (chi/dof={ratio:.3f}) — advisory, "
                f"UNVALIDATED steganography heuristic"
            )
        # Never blocks; advisory risk stays LOW at most, and only in strict mode.
        risk = RiskLevel.LOW if findings else RiskLevel.SAFE
        return AnalysisResult(module="stego", score=0.0, findings=findings,
                              raw_data=raw, blocked=False, risk=risk)
    except Exception as e:
        logger.error(f"Stego error: {e}")
        return AnalysisResult(module="stego", score=0.0, findings=[])
