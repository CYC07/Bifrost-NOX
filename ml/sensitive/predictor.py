"""Zero-shot sensitive-content classifier (DeBERTa-v3 NLI).

Replaces the MiniLM cosine `model_nlp_semantic` heuristic. Instead of comparing
against a hardcoded list of "dangerous concept" sentences, this runs zero-shot
NLI: each candidate label (see labels.py) is scored independently against the
text (multi_label), and the request is flagged when the top label crosses the
threshold. New categories = edit labels.py, no retraining.

Mirrors ml/waf/predictor.py: config-driven, singleton, fail-open — a missing or
broken model yields a non-sensitive allow with a note, never an exception.

Env:
    SENSITIVE_MODEL      HF model id (default MoritzLaurer/deberta-v3-base-zeroshot-v2.0)
    SENSITIVE_THRESHOLD  block cutoff on the top label score (default 0.85)
    SENSITIVE_LABELS     comma-separated label override (see labels.py)
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field

from ml.sensitive.labels import get_labels, risk_for

logger = logging.getLogger("sensitive.predictor")

DEFAULT_MODEL = os.getenv("SENSITIVE_MODEL", "MoritzLaurer/deberta-v3-base-zeroshot-v2.0")
# 0.6: benign traffic scores <=~0.1, real sensitive content >=~0.7 (measured) —
# so 0.6 sits in the wide gap between them. Catches medical (~0.71) without
# risking benign false positives.
DEFAULT_THRESHOLD = float(os.getenv("SENSITIVE_THRESHOLD", "0.6"))


@dataclass
class SensitivePrediction:
    label: str                       # top sensitive category (or "none")
    score: float                     # score of the top label
    blocked: bool                    # top score >= threshold
    risk: str                        # risk level for the top label
    scores: dict[str, float] = field(default_factory=dict)
    note: str = ""


class SensitiveClassifier:
    def __init__(self, model_name: str = DEFAULT_MODEL, threshold: float = DEFAULT_THRESHOLD) -> None:
        self.model_name = model_name
        self.threshold = threshold
        self._pipe = None
        self._labels: list[str] = get_labels()
        self._loaded = False

    def load(self) -> bool:
        try:
            from transformers import pipeline  # lazy: heavy import
            self._pipe = pipeline(
                "zero-shot-classification",
                model=self.model_name,
                # CPU; -1 device. Truncate long content so a big paste can't OOM.
                device=-1,
            )
            self._loaded = True
            logger.info("Sensitive model loaded (%s, %d labels)", self.model_name, len(self._labels))
        except Exception as exc:  # noqa: BLE001 — fail open
            logger.warning("Sensitive model load failed (%s) — fail-open to non-sensitive", exc)
            self._loaded = False
        return self._loaded

    def predict(self, text: str) -> SensitivePrediction:
        if not self._loaded:
            return SensitivePrediction("none", 0.0, False, "safe", note="model not loaded")
        if not text or not text.strip():
            return SensitivePrediction("none", 0.0, False, "safe")
        try:
            out = self._pipe(
                text[:2000],  # cap: NLI is quadratic-ish in length, keep latency bounded
                candidate_labels=self._labels,
                multi_label=True,
                truncation=True,
            )
            scores = {lbl: float(s) for lbl, s in zip(out["labels"], out["scores"])}
            top_label = out["labels"][0]        # pipeline returns sorted desc
            top_score = float(out["scores"][0])
            blocked = top_score >= self.threshold
            return SensitivePrediction(
                label=top_label if blocked else "none",
                score=top_score,
                blocked=blocked,
                risk=risk_for(top_label) if blocked else "safe",
                scores=scores,
            )
        except Exception as exc:  # noqa: BLE001 — fail open on any inference error
            logger.error("Sensitive inference failed: %s", exc)
            return SensitivePrediction("none", 0.0, False, "safe", note=f"inference error: {exc}")


_singleton: SensitiveClassifier | None = None


def get_classifier() -> SensitiveClassifier:
    global _singleton
    if _singleton is None:
        _singleton = SensitiveClassifier()
        _singleton.load()
    return _singleton
