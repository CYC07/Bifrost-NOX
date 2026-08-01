"""Content-shape router — decides which expensive text_service analyzer(s)
to run on a given text blob, before any threat detection happens.

Char n-gram TF-IDF + Logistic Regression — same recipe as ml/waf/'s baseline,
chosen for the same reason: this needs to be genuinely cheap (sub-millisecond,
no GPU) since it runs before the analyzers it's gating, or it doesn't save
any time at all. A full transformer here would defeat the point of routing.

Fail-open: on load/inference failure, route everything to "web_request" (the
safest default — still runs the WAF classifier, the analyzer least likely to
miss something if the router itself is broken).
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field

logger = logging.getLogger("router.predictor")

_HERE = os.path.dirname(__file__)
DEFAULT_MODEL_PATH = os.getenv(
    "ROUTER_MODEL_PATH", os.path.join(_HERE, "artifacts", "router_baseline.joblib")
)


@dataclass
class RouteDecision:
    route: str                     # top predicted class
    score: float                   # confidence of the top class
    scores: dict[str, float] = field(default_factory=dict)
    note: str = ""


class RouterClassifier:
    def __init__(self, model_path: str = DEFAULT_MODEL_PATH) -> None:
        self.model_path = model_path
        self._pipeline = None
        self._labels: list[str] = []
        self._loaded = False

    def load(self) -> bool:
        try:
            import joblib
            bundle = joblib.load(self.model_path)
            self._pipeline = bundle["pipeline"]
            self._labels = bundle["labels"]
            self._loaded = True
            logger.info("Router model loaded from %s (%d classes)", self.model_path, len(self._labels))
        except Exception as exc:  # noqa: BLE001 — fail open
            logger.warning("Router model load failed (%s) — fail-open to web_request", exc)
            self._loaded = False
        return self._loaded

    def route(self, text: str) -> RouteDecision:
        if not self._loaded:
            return RouteDecision("web_request", 0.0, note="model not loaded")
        if not text or not text.strip():
            return RouteDecision("web_request", 0.0, note="empty text")
        try:
            proba = self._pipeline.predict_proba([text])[0]
            scores = {label: float(p) for label, p in zip(self._pipeline.classes_, proba)}
            top_label = max(scores, key=scores.get)
            return RouteDecision(route=top_label, score=scores[top_label], scores=scores)
        except Exception as exc:  # noqa: BLE001 — fail open on any inference error
            logger.error("Router inference failed: %s", exc)
            return RouteDecision("web_request", 0.0, note=f"inference error: {exc}")


_singleton: RouterClassifier | None = None


def get_router() -> RouterClassifier:
    global _singleton
    if _singleton is None:
        _singleton = RouterClassifier()
        _singleton.load()
    return _singleton
