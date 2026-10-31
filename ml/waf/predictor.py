"""Inference wrapper for the WAF classifier.

Loads a trained model and returns a calibrated decision. Backends share
the same ``WAFPrediction`` contract:

- sklearn joblib bundle (char-n-gram baseline) — ``WAF_MODEL_PATH`` is a file
- fine-tuned HF transformer (DistilBERT) — ``WAF_MODEL_PATH`` is a directory
  saved with ``save_pretrained`` (config carries id2label in taxonomy order)

A transformer directory may also carry ``waf_v2.json`` (written by the v2 Colab notebook). With
``arm == "B_sigmoid6"`` the model has one sigmoid head per ATTACK family (default-allow): it blocks
when the largest head probability is strictly above ``recommended_threshold`` (``WAF_THRESHOLD``
overrides it; the constructor ``threshold`` is ignored because text_service always passes its own
``WAF_ATTACK_THRESHOLD``) and reports ``clean`` as ``1 - max head``. ``arm == "A_softmax7"`` and
directories without the file behave exactly as before (7-class softmax, constructor threshold).

Fail-open: a missing or broken model yields a ``clean`` allow with a note,
never an exception — matching the firewall's fail-open philosophy. A directory whose
``waf_v2.json`` is unreadable, names an unknown arm or disagrees with the weights is treated as
broken, never guessed to be a softmax model.

The model path is config-driven via ``WAF_MODEL_PATH`` so Colab weights drop in
with no code change.
"""
from __future__ import annotations

import json
import logging
import math
import os
from dataclasses import dataclass, field

from ml.waf.taxonomy import ATTACK_LABELS, RISK, is_attack

logger = logging.getLogger("waf.predictor")

_HERE = os.path.dirname(__file__)
DEFAULT_MODEL_PATH = os.getenv(
    "WAF_MODEL_PATH", os.path.join(_HERE, "artifacts", "waf_distilbert")
)
DEFAULT_THRESHOLD = float(os.getenv("WAF_THRESHOLD", "0.5"))
# Must match the tokenizer max_length used in Colab fine-tuning.
TRANSFORMER_MAX_LENGTH = 256
V2_CONFIG_NAME = "waf_v2.json"
ARM_A = "A_softmax7"
ARM_B = "B_sigmoid6"


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
        self._max_len = TRANSFORMER_MAX_LENGTH
        self._loaded = False

    def load(self) -> bool:
        try:
            if os.path.isdir(self.model_path):
                self._load_transformer()
            else:
                self._load_sklearn()
            self._loaded = True
            logger.info(
                "WAF model loaded from %s (%s backend, %d classes, threshold %.4f)",
                self.model_path, self._backend, len(self._labels), self.threshold,
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
        cfg = _read_v2_config(self.model_path)
        if cfg is not None and cfg.get("arm") == ARM_B:
            self._load_sigmoid(cfg)
            return
        if cfg is not None and cfg.get("arm") != ARM_A:
            # never guess: a 6-head model loaded as a 7-class softmax gives wrong verdicts silently
            raise ValueError(f"{V2_CONFIG_NAME}: unknown arm {cfg.get('arm')!r}")
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
        self._tokenizer = AutoTokenizer.from_pretrained(self.model_path)
        self._model = AutoModelForSequenceClassification.from_pretrained(self.model_path)
        self._model.eval()
        id2label = self._model.config.id2label
        self._labels = [id2label[i] for i in range(len(id2label))]
        self._backend = "transformer"

    def _load_sigmoid(self, cfg: dict) -> None:
        """Arm B: one sigmoid head per attack family. Any inconsistency raises (-> fail-open in load())."""
        heads = cfg.get("attack_labels")
        if (not isinstance(heads, list) or not heads or len(set(heads)) != len(heads)
                or not all(isinstance(h, str) and h in ATTACK_LABELS for h in heads)):
            raise ValueError(f"{V2_CONFIG_NAME}: attack_labels must be unique attack classes, got {heads!r}")
        threshold = _threshold_for_arm_b(cfg)
        max_len = int(cfg.get("max_len", TRANSFORMER_MAX_LENGTH))
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
        tokenizer = AutoTokenizer.from_pretrained(self.model_path)
        model = AutoModelForSequenceClassification.from_pretrained(self.model_path)
        model.eval()
        if model.config.num_labels != len(heads):
            raise ValueError(f"model has {model.config.num_labels} outputs but attack_labels has {len(heads)}")
        id2label = model.config.id2label
        if [id2label[i] for i in range(len(heads))] != heads:
            raise ValueError("model id2label does not match attack_labels order")
        limit = getattr(model.config, "max_position_embeddings", None)
        if max_len < 2 or (limit is not None and max_len > limit):
            raise ValueError(f"max_len {max_len} outside 2..{limit}")
        self._tokenizer, self._model = tokenizer, model
        self._labels, self._max_len, self.threshold = list(heads), max_len, threshold
        self._backend = "transformer_sigmoid"

    def _score(self, text: str) -> dict[str, float]:
        if self._backend in ("transformer", "transformer_sigmoid"):
            import torch
            enc = self._tokenizer(
                text, truncation=True, max_length=self._max_len, return_tensors="pt"
            )
            # Colab-saved tokenizer emits token_type_ids; DistilBERT's forward
            # does not accept them.
            enc.pop("token_type_ids", None)
            with torch.no_grad():
                logits = self._model(**enc).logits[0]
            if self._backend == "transformer_sigmoid":
                probs = torch.sigmoid(logits).tolist()
                scores = {label: float(p) for label, p in zip(self._labels, probs)}
                scores["clean"] = 1.0 - max(scores.values())
                return scores
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
            if self._backend == "transformer_sigmoid":
                return self._decide_sigmoid(scores)
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

    def _decide_sigmoid(self, scores: dict[str, float]) -> WAFPrediction:
        """Default-allow: block iff the largest attack head is strictly above the threshold."""
        heads = {k: v for k, v in scores.items() if k != "clean"}
        label = max(heads, key=heads.get)
        top = heads[label]
        blocked = top > self.threshold
        return WAFPrediction(label=label, score=top, blocked=blocked,
                             risk=RISK.get(label, "medium") if blocked else "safe", scores=scores)


def _read_v2_config(model_dir: str) -> dict | None:
    """Parsed ``waf_v2.json`` of a model directory, None if there is none. A present-but-unreadable
    file raises: the directory then cannot be trusted to be a softmax model."""
    path = os.path.join(model_dir, V2_CONFIG_NAME)
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as f:
        cfg = json.load(f)
    if not isinstance(cfg, dict):
        raise ValueError(f"{V2_CONFIG_NAME} must be a JSON object")
    return cfg


def _threshold_for_arm_b(cfg: dict) -> float:
    """WAF_THRESHOLD (read now, not at import) wins; else the notebook's recommended_threshold."""
    raw = os.environ.get("WAF_THRESHOLD") or cfg.get("recommended_threshold")
    if raw is None:
        raise ValueError(f"{V2_CONFIG_NAME}: no recommended_threshold and WAF_THRESHOLD is unset")
    thr = float(raw)
    if not (math.isfinite(thr) and 0.0 <= thr <= 1.0):
        raise ValueError(f"threshold {raw!r} outside [0, 1]")
    return thr


_singleton: WAFClassifier | None = None


def get_classifier() -> WAFClassifier:
    global _singleton
    if _singleton is None:
        _singleton = WAFClassifier()
        _singleton.load()
    return _singleton
