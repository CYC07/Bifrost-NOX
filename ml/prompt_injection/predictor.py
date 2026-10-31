"""Prompt-injection detector — wraps a fine-tuned classifier
(protectai/deberta-v3-base-prompt-injection-v2 by default) that flags text
attempting to manipulate an LLM's instructions ("ignore previous
instructions", role-override jailbreaks, embedded fake system directives).

Mirrors ml/sensitive/predictor.py and ml/waf/predictor.py: config-driven,
singleton, fail-open — a missing or broken model yields a SAFE allow with a
note, never an exception.

Env:
    PROMPT_INJECTION_MODEL      HF model id (default protectai/deberta-v3-base-prompt-injection-v2)
    PROMPT_INJECTION_THRESHOLD  cutoff on the INJECTION label score for predict() (default 0.9)
    PROMPT_INJECTION_SOLO / _CUE / _ADVISORY   P(INJECTION) cutoffs of the request gate used by
                                predict_texts() (see gating.py for the policy; defaults in gating.DEFAULT)
"""
from __future__ import annotations

import logging
import math
import os
from dataclasses import dataclass

from ml.prompt_injection import cues, gating
from ml.prompt_injection.html_text import extract_text
from ml.prompt_injection.prompts import windows

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
    advisory: bool = False   # evidence too weak to block: reported (CENSOR / WARN), request allowed
    margin: float = 0.0      # log-odds the decision rests on (resolves past the softmax saturation)
    cues: tuple = ()         # structural cue families found in the deciding window
    reason: str = ""         # model | model+cue | borderline | role


class PromptInjectionClassifier:
    def __init__(self, model_name: str = DEFAULT_MODEL, threshold: float = DEFAULT_THRESHOLD,
                 config: "gating.GateConfig | None" = None) -> None:
        self.model_name = model_name
        self.threshold = threshold
        self.config = config or gating.default_config()
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
            text = extract_text(text)  # raw HTML/CSS/JS is out-of-distribution -> false INJECTION
            if not text.strip():
                return PromptInjectionPrediction("SAFE", 0.0, False, risk="safe")
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

    @staticmethod
    def _margin_of_output(o) -> float:
        """Log-odds of INJECTION from one pipeline output: a list of {label, logit} (top_k=None,
        function_to_apply="none"), or the legacy single {label, score} dict."""
        if isinstance(o, dict):
            m = gating.margin_of(float(o["score"]))
            return m if o["label"] == INJECTION_LABEL else -m
        inj = [float(d["score"]) for d in o if d["label"] == INJECTION_LABEL]
        other = [float(d["score"]) for d in o if d["label"] != INJECTION_LABEL]
        return inj[0] - (max(other) if other else 0.0)

    def predict_texts(self, texts: list[str], max_windows: int = 32, roles: list[str] | None = None) -> PromptInjectionPrediction:
        """Score several strings (e.g. an LLM request's messages), each split into overlapping
        windows so padding can't push an injection past the model's input limit, then decide with
        the request gate (gating.py): block on a strong score alone or a lower score plus a
        structural cue in the same window; weaker evidence and any evidence found only in
        developer-authored `system` text is ADVISORY. `roles` aligns with `texts` (default: unknown)."""
        if not self._loaded:
            return PromptInjectionPrediction("SAFE", 0.0, False, risk="safe", note="model not loaded")
        roles = roles if roles is not None and len(roles) == len(texts) else ["unknown"] * len(texts)
        chunks: list[tuple[int, str, int, str]] = []        # (segment, role, windows in segment, text)
        for si, (t, role) in enumerate(zip(texts, roles)):
            if role in self.config.ignore_roles:
                continue
            t = extract_text(t)
            if t and t.strip():
                ws = windows(t)
                chunks.extend((si, role, len(ws), w) for w in ws)
        if len(chunks) > max_windows:                       # keep what can block first, then fill with the rest
            order = sorted(range(len(chunks)), key=lambda i: (chunks[i][1] not in self.config.block_roles, i))[:max_windows]
            chunks = [chunks[i] for i in sorted(order)]
        if not chunks:
            return PromptInjectionPrediction("SAFE", 0.0, False, risk="safe")
        try:
            outs = self._pipe([c[3] for c in chunks], truncation=True, batch_size=8, top_k=None, function_to_apply="none")
            wins = [gating.WindowScore(c[0], c[1], c[2], self._margin_of_output(o), cues.detect(c[3]))
                    for c, o in zip(chunks, outs)]
            d = gating.decide(wins, self.config)
            score = 1.0 / (1.0 + math.exp(-max(min(d.margin, 50.0), -50.0)))
            if d.blocked:
                return PromptInjectionPrediction(INJECTION_LABEL, score, True, risk="critical",
                                                 margin=d.margin, cues=d.cues, reason=d.reason)
            return PromptInjectionPrediction("SAFE", score, False, risk="low" if d.advisory else "safe", advisory=d.advisory,
                                             margin=d.margin, cues=d.cues, reason=d.reason)
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
