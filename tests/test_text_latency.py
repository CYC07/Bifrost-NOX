"""Latency regressions in the text service.

Profiling showed the zero-shot sensitive-content model (DeBERTa NLI) took 4-7 s
per request because transformers>=5 loads its fp16 checkpoint as float16, which
is very slow on CPU, and the pipeline scored labels one at a time. Everything
else took <0.2 s. Slow verdicts made the gateway time out and fail open.
"""
import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.schemas import AnalysisResult, RiskLevel  # noqa: E402
from ml.sensitive.predictor import SensitiveClassifier  # noqa: E402
from ml.sensitive.labels import get_labels  # noqa: E402


# --- sensitive classifier ---------------------------------------------------
def test_sensitive_scores_all_labels_in_one_batch():
    seen = {}

    def fake_pipe(text, **kwargs):
        seen.update(kwargs)
        labels = kwargs["candidate_labels"]
        return {"labels": labels, "scores": [0.01] * len(labels)}

    c = SensitiveClassifier()
    c._loaded, c._pipe = True, fake_pipe
    c.predict("some prose to classify")
    assert seen["batch_size"] == len(get_labels())


def _sensitive_model_available() -> bool:
    return SensitiveClassifier().load()


@pytest.mark.skipif(not _sensitive_model_available(), reason="sensitive model unavailable")
def test_sensitive_model_loads_as_float32():
    import torch
    c = SensitiveClassifier()
    c.load()
    assert c._pipe.model.dtype == torch.float32


# --- text service short-circuit ---------------------------------------------
from text_service import main as svc  # noqa: E402


class _Req:
    # LLM-scoped by default: the prompt-injection model only runs for LLM traffic
    def __init__(self, text, metadata=None):
        self._text = text
        self._md = {"host": "api.openai.com", "direction": "outbound"} if metadata is None else metadata

    async def json(self):
        return {"text": self._text, "metadata": self._md}


def _result(module, blocked):
    return AnalysisResult(module=module, score=1.0 if blocked else 0.0, findings=[],
                          blocked=blocked, risk=RiskLevel.CRITICAL if blocked else RiskLevel.SAFE)


def _patch(monkeypatch, *, pi_blocked, sensitive):
    monkeypatch.setattr(svc, "_route", lambda t: "prose")
    monkeypatch.setattr(svc, "model_code_analysis", lambda t, *a, **k: _result("code", False))
    monkeypatch.setattr(svc, "model_patterns", lambda t: _result("pattern", False))
    monkeypatch.setattr(svc, "model_prompt_injection", lambda t: _result("prompt_injection", pi_blocked))
    monkeypatch.setattr(svc, "model_sensitive", sensitive)


def _call(text="x"):
    import json
    return json.loads(asyncio.run(svc.analyze_text(_Req(text))).body)


def test_expensive_analyzer_skipped_when_cheap_one_already_blocked(monkeypatch):
    def boom(t):
        raise AssertionError("sensitive analyzer must not run once a block is decided")
    _patch(monkeypatch, pi_blocked=True, sensitive=boom)
    out = _call()
    assert out["status"] == "block" and "prompt_injection" in out["reason"]


def test_expensive_analyzer_still_runs_and_can_block_when_nothing_else_does(monkeypatch):
    calls = []

    def sens(t):
        calls.append(t)
        return _result("sensitive", True)
    _patch(monkeypatch, pi_blocked=False, sensitive=sens)
    out = _call("medical record text")
    assert calls == ["medical record text"]
    assert out["status"] == "block" and "sensitive" in out["reason"]
