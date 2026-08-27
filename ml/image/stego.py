"""LSB steganalysis via the chi-square attack.

The original heuristic tested a single R-channel LSB plane and flagged images
whose mean LSB density was within 0.005 of 0.5 — which is where most natural
images already sit, so it was near-noise.

The chi-square attack (Westfeld & Pfitzmann) is the classic detector for
sequential LSB embedding: LSB replacement makes the two values of each
Pairs-of-Values (2k, 2k+1) tend toward equal frequency. We measure how close
each PoV pair is to equalisation across all channels and map that to an
advisory signal. Steganalysis is inherently probabilistic, so this NEVER blocks
on its own — it is a LOW/MEDIUM signal that aggregation may combine with others.
"""
import logging

import numpy as np
from PIL import Image

from common.schemas import AnalysisResult, RiskLevel

logger = logging.getLogger("image_service")


def chi_square_lsb(image: Image.Image) -> AnalysisResult:
    try:
        arr = np.asarray(image.convert("RGB")).ravel()
        # Histogram of byte values 0..255.
        hist = np.bincount(arr, minlength=256).astype(np.float64)
        # Pairs of Values: (2k, 2k+1). Under LSB embedding the pair equalises.
        even = hist[0::2]
        odd = hist[1::2]
        pair_sum = even + odd
        # Only pairs with enough samples are meaningful.
        mask = pair_sum >= 32
        if mask.sum() == 0:
            return AnalysisResult(module="stego", score=0.0, findings=[])
        expected = pair_sum[mask] / 2.0
        observed = even[mask]
        chi = np.sum((observed - expected) ** 2 / expected)
        dof = int(mask.sum())
        # Normalise: chi/dof near 0 => pairs are equalised => embedding-like.
        # Natural images have chi/dof well above 1 (uneven pair frequencies).
        ratio = chi / dof
        findings = []
        score = 0.0
        risk = RiskLevel.SAFE
        if ratio < 0.5:
            score = 0.4
            risk = RiskLevel.MEDIUM
            findings.append(f"LSB pairs strongly equalised (chi/dof={ratio:.3f}) — possible LSB steganography")
        elif ratio < 1.0:
            score = 0.2
            risk = RiskLevel.LOW
            findings.append(f"LSB pairs somewhat equalised (chi/dof={ratio:.3f}) — weak steganography signal")
        return AnalysisResult(
            module="stego", score=score, findings=findings,
            raw_data={"chi_over_dof": round(float(ratio), 4)},
            blocked=False, risk=risk,
        )
    except Exception as e:
        logger.error(f"Stego error: {e}")
        return AnalysisResult(module="stego", score=0.0, findings=[])
