"""Zero-shot sensitive-content classifier (DeBERTa-v3 NLI).

Replaces the MiniLM cosine `model_nlp_semantic` heuristic. Instead of comparing
against a hardcoded list of "dangerous concept" sentences, this runs zero-shot
NLI: each hypothesis (see labels.py) is scored independently against the text
(multi_label), and the request is flagged by a small, measured policy:

    1. a sensitive label at/above its own threshold blocks, unless a benign contrast class
       (terms of service, public law, news, ...) scores within MARGIN of it;
    2. a weaker sensitive score blocks only together with corroborating evidence
       (ml/sensitive/evidence.py: confidentiality marking, ID number, pay list, patient narrative);
    3. a bundle of identity signals (e.g. passport number + home address) blocks on its own.

The checkpoint is NOT swapped: calibration only. New categories = edit labels.py, no retraining.

Mirrors ml/waf/predictor.py: config-driven, singleton, fail-open — a missing or
broken model yields a non-sensitive allow with a note, never an exception.

Env:
    SENSITIVE_MODEL      HF model id (default MoritzLaurer/deberta-v3-base-zeroshot-v2.0)
    SENSITIVE_THRESHOLD  if set, overrides every label's `block` threshold (default: per-label, see labels.py)
    SENSITIVE_LABELS     comma-separated label override (see labels.py)
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field

from ml.sensitive import labels as lb
from ml.sensitive.evidence import IDENTITY, find_evidence, question_form

logger = logging.getLogger("sensitive.predictor")

DEFAULT_MODEL = os.getenv("SENSITIVE_MODEL", "MoritzLaurer/deberta-v3-base-zeroshot-v2.0")
# Informational only (logged at start-up): the global override, if any. The decision uses the per-label
# thresholds in labels.py unless SENSITIVE_THRESHOLD / the constructor argument override them.
DEFAULT_THRESHOLD = float(os.getenv("SENSITIVE_THRESHOLD", "0.6"))
MAX_CHARS = 2000  # cap: NLI is quadratic-ish in length, keep latency bounded


@dataclass
class SensitivePrediction:
    label: str                       # top sensitive category (or "none")
    score: float                     # NLI score of that label (0 for an evidence-only block)
    blocked: bool
    risk: str                        # risk level for the label
    scores: dict[str, float] = field(default_factory=dict)   # hypothesis -> score (sensitive + contrast)
    note: str = ""
    evidence: list[str] = field(default_factory=list)        # corroborating signals found in the text
    reason: str = ""                 # nli | nli+evidence | identity-bundle | "" (not blocked)
    contrast: float = 0.0            # best benign-contrast score


@dataclass(frozen=True)
class Decision:
    label: str
    score: float
    blocked: bool
    risk: str
    reason: str
    contrast: float


NONE = Decision("none", 0.0, False, "safe", "", 0.0)


def decide_from_scores(scores: dict[str, float], evidence: list[str], *, threshold: float | None = None) -> Decision:
    """The blocking policy, as a pure function of NLI scores (keyed by hypothesis) and evidence names.

    `threshold`, if given, replaces every label's own `block` threshold and disables the evidence tier
    (the legacy single-threshold behaviour used when a caller pins one explicitly)."""
    labels = lb.sensitive_labels()
    ident = sum(1 for e in evidence if e in IDENTITY)
    if lb.IDENTITY_BUNDLE and ident >= lb.IDENTITY_BUNDLE:
        return Decision("identity details (ID number, date of birth, home address)", 0.0, True, "high", "identity-bundle", 0.0)
    contrast = [scores.get(h, 0.0) for h in lb.contrast_labels()]
    cmax = max(contrast, default=0.0)
    best: Decision | None = None
    top = NONE
    for hyp, spec in labels.items():
        s = scores.get(hyp, 0.0)
        if s > top.score:
            top = Decision(spec.name, s, False, "safe", "", cmax)
        if contrast and s - cmax < lb.MARGIN:
            continue
        block = threshold if threshold is not None else spec.block
        reason = ""
        if s >= block:
            reason = "nli"
        elif threshold is None and spec.low is not None and s >= spec.low and len(evidence) >= lb.MIN_EVIDENCE:
            reason = "nli+evidence"
        if reason and (best is None or s > best.score):
            best = Decision(spec.name, s, True, spec.risk, reason, cmax)
    return best or top


class SensitiveClassifier:
    def __init__(self, model_name: str = DEFAULT_MODEL, threshold: float | None = None) -> None:
        self.model_name = model_name
        self._threshold_override = threshold          # None = per-label policy
        self.threshold = threshold if threshold is not None else DEFAULT_THRESHOLD   # for logging
        self._pipe = None
        self._loaded = False

    @property
    def _labels(self) -> list[str]:
        return lb.get_labels()

    def load(self) -> bool:
        try:
            import torch
            from transformers import pipeline  # lazy: heavy import
            self._pipe = pipeline(
                "zero-shot-classification",
                model=self.model_name,
                # CPU; -1 device. Truncate long content so a big paste can't OOM.
                device=-1,
                # transformers>=5 honours the checkpoint's stored dtype; this one is
                # fp16, which is ~14x slower than fp32 on CPU (4.3 s vs 0.3 s/request).
                dtype=torch.float32,
            )
            self._loaded = True
            logger.info("Sensitive model loaded (%s, %d hypotheses)", self.model_name, len(self._labels))
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
            evidence = find_evidence(text)
            # an identity bundle blocks without the model (saves the NLI pass)
            if lb.IDENTITY_BUNDLE and sum(1 for e in evidence if e in IDENTITY) >= lb.IDENTITY_BUNDLE:
                d = decide_from_scores({}, evidence)
                return SensitivePrediction(d.label, d.score, True, d.risk, evidence=evidence, reason=d.reason)
            # a short question with no hard evidence asks ABOUT a topic ("How is my credit score calculated?"
            # scores 0.96 on the finance label); it holds no record, so the topic-scoring NLI is skipped
            if not evidence and question_form(text):
                return SensitivePrediction("none", 0.0, False, "safe", reason="question")
            hyps = self._labels
            out = self._pipe(
                text[:MAX_CHARS],
                candidate_labels=hyps,
                hypothesis_template="{}",   # hypotheses are complete sentences (labels.py)
                multi_label=True,
                truncation=True,
                # one batched forward over all hypotheses instead of one pass per label
                # (2-4x faster; scores differ by <1e-4)
                batch_size=len(hyps),
            )
            scores = {lbl: float(s) for lbl, s in zip(out["labels"], out["scores"])}
            d = decide_from_scores(scores, evidence, threshold=self._threshold_override)
            return SensitivePrediction(
                label=d.label if d.blocked else "none",
                score=d.score,
                blocked=d.blocked,
                risk=d.risk if d.blocked else "safe",
                scores=scores,
                evidence=evidence,
                reason=d.reason,
                contrast=d.contrast,
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
