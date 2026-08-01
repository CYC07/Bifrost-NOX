"""Prompt-injection detector — wraps a fine-tuned classifier
(protectai/deberta-v3-base-prompt-injection-v2 by default) that flags text
attempting to manipulate an LLM's instructions ("ignore previous
instructions", role-override jailbreaks, embedded fake system directives).

Mirrors ml/sensitive/predictor.py and ml/waf/predictor.py: config-driven,
singleton, fail-open — a missing or broken model yields a SAFE allow with a
note, never an exception.

Env:
    PROMPT_INJECTION_MODEL      HF model id (default protectai/deberta-v3-base-prompt-injection-v2)
    PROMPT_INJECTION_THRESHOLD  block cutoff on the INJECTION label score (default 0.9)
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass

logger = logging.getLogger("prompt_injection.predictor")

DEFAULT_MODEL = os.getenv("PROMPT_INJECTION_MODEL", "protectai/deberta-v3-base-prompt-injection-v2")
DEFAULT_THRESHOLD = float(os.getenv("PROMPT_INJECTION_THRESHOLD", "0.9"))
INJECTION_LABEL = "INJECTION"


@dataclass
class PromptInjectionPrediction:
    label: str        # "INJECTION" or "SAFE"
    score: float       # confidence of the top label
    blocked: bool
    risk: str = "critical"  # manipulating the firewall's own AI pipeline is a serious attack
    note: str = ""


class PromptInjectionClassifier:
    def __init__(self, model_name: str = DEFAULT_MODEL, threshold: float = DEFAULT_THRESHOLD) -> None:
        self.model_name = model_name
        self.threshold = threshold
        self._pipe = None
        self._loaded = False

    def load(self) -> bool:
        try:
            from transformers import pipeline  # lazy: heavy import
            self._pipe = pipeline("text-classification", model=self.model_name, device=-1)
            self._loaded = True
            logger.info("Prompt-injection model loaded (%s)", self.model_name)
        except Exception as exc:  # noqa: BLE001 — fail open
            logger.warning("Prompt-injection model load failed (%s) — fail-open to SAFE", exc)
            self._loaded = False
        return self._loaded

    def predict(self, text: str) -> PromptInjectionPrediction:
        if not self._loaded:
            return PromptInjectionPrediction("SAFE", 0.0, False, risk="safe", note="model not loaded")
        if not text or not text.strip():
            return PromptInjectionPrediction("SAFE", 0.0, False, risk="safe")
        try:
            out = self._pipe(text[:2000], truncation=True)[0]
            label = out["label"]
            score = float(out["score"])
            blocked = label == INJECTION_LABEL and score >= self.threshold
            return PromptInjectionPrediction(
                label=label if blocked else "SAFE",
                score=score,
                blocked=blocked,
                risk="critical" if blocked else "safe",
            )
        except Exception as exc:  # noqa: BLE001 — fail open on any inference error
            logger.error("Prompt-injection inference failed: %s", exc)
            return PromptInjectionPrediction("SAFE", 0.0, False, risk="safe", note=f"inference error: {exc}")


_singleton: PromptInjectionClassifier | None = None


def get_classifier() -> PromptInjectionClassifier:
    global _singleton
    if _singleton is None:
        _singleton = PromptInjectionClassifier()
        _singleton.load()
    return _singleton
