"""Inference wrapper for the WAF classifier.

Loads a trained model and returns a calibrated decision. Two backends share
the same ``WAFPrediction`` contract:

- sklearn joblib bundle (char-n-gram baseline) — ``WAF_MODEL_PATH`` is a file
- fine-tuned HF transformer (DistilBERT) — ``WAF_MODEL_PATH`` is a directory
  saved with ``save_pretrained`` (config carries id2label in taxonomy order)

Fail-open: a missing or broken model yields a ``clean`` allow with a note,
never an exception — matching the firewall's fail-open philosophy.

The model path is config-driven via ``WAF_MODEL_PATH`` so Colab weights drop in
with no code change.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field

from ml.waf.taxonomy import RISK, is_attack

logger = logging.getLogger("waf.predictor")

_HERE = os.path.dirname(__file__)
DEFAULT_MODEL_PATH = os.getenv(
    "WAF_MODEL_PATH", os.path.join(_HERE, "artifacts", "waf_baseline.joblib")
)
DEFAULT_THRESHOLD = float(os.getenv("WAF_THRESHOLD", "0.5"))
# Must match the tokenizer max_length used in Colab fine-tuning.
TRANSFORMER_MAX_LENGTH = 256


@dataclass
class WAFPrediction:
    label: str                     # top predicted class
    score: float                   # probability of the top class
    blocked: bool                  # calibrated decision
    risk: str                      # taxonomy risk level for the label
    scores: dict[str, float] = field(default_factory=dict)
    note: str = ""


class WAFClassifier:
    def __init__(self, model_path: str = DEFAULT_MODEL_PATH, threshold: float = DEFAULT_THRESHOLD) -> None:
        self.model_path = model_path
        self.threshold = threshold
        self._pipeline = None
        self._tokenizer = None
        self._model = None
        self._labels: list[str] = []
        self._backend = ""
        self._loaded = False

    def load(self) -> bool:
        try:
            if os.path.isdir(self.model_path):
                self._load_transformer()
            else:
                self._load_sklearn()
            self._loaded = True
            logger.info(
                "WAF model loaded from %s (%s backend, %d classes)",
                self.model_path, self._backend, len(self._labels),
            )
        except Exception as exc:  # noqa: BLE001 — fail open
            logger.warning("WAF model load failed (%s) — fail-open to clean", exc)
            self._loaded = False
        return self._loaded

    def _load_sklearn(self) -> None:
        import joblib
        bundle = joblib.load(self.model_path)
        self._pipeline = bundle["pipeline"]
        self._labels = bundle["labels"]
        self._backend = "sklearn"

    def _load_transformer(self) -> None:
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
        self._tokenizer = AutoTokenizer.from_pretrained(self.model_path)
        self._model = AutoModelForSequenceClassification.from_pretrained(self.model_path)
        self._model.eval()
        id2label = self._model.config.id2label
        self._labels = [id2label[i] for i in range(len(id2label))]
        self._backend = "transformer"

    def _score(self, text: str) -> dict[str, float]:
        if self._backend == "transformer":
            import torch
            enc = self._tokenizer(
                text, truncation=True, max_length=TRANSFORMER_MAX_LENGTH, return_tensors="pt"
            )
            # Colab-saved tokenizer emits token_type_ids; DistilBERT's forward
            # does not accept them.
            enc.pop("token_type_ids", None)
            with torch.no_grad():
                logits = self._model(**enc).logits[0]
            probs = torch.softmax(logits, dim=-1).tolist()
            return {label: float(p) for label, p in zip(self._labels, probs)}
        proba = self._pipeline.predict_proba([text])[0]
        return {label: float(p) for label, p in zip(self._pipeline.classes_, proba)}

    def predict(self, text: str) -> WAFPrediction:
        if not self._loaded:
            return WAFPrediction("clean", 0.0, False, "safe", note="model not loaded")
        if not text or not text.strip():
            return WAFPrediction("clean", 0.0, False, "safe")
        try:
            scores = self._score(text)
            top_label = max(scores, key=scores.get)
            top_score = scores[top_label]
            blocked = is_attack(top_label) and top_score >= self.threshold
            return WAFPrediction(
                label=top_label,
                score=top_score,
                blocked=blocked,
                risk=RISK.get(top_label, "medium"),
                scores=scores,
            )
        except Exception as exc:  # noqa: BLE001 — fail open on any inference error
            logger.error("WAF inference failed: %s", exc)
            return WAFPrediction("clean", 0.0, False, "safe", note=f"inference error: {exc}")


_singleton: WAFClassifier | None = None


def get_classifier() -> WAFClassifier:
    global _singleton
    if _singleton is None:
        _singleton = WAFClassifier()
        _singleton.load()
    return _singleton
