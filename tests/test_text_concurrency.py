"""Text-service throughput: verdict cache, off-event-loop analysis, bounded concurrency.

The service ran blocking model code inside an `async def`, so one slow request froze
every other, and identical bodies (Windows telemetry repeats constantly) were
re-analysed each time. Queueing pushed verdicts past the gateway's timeout.
"""
import asyncio
import json
import os
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.schemas import AnalysisResult, RiskLevel  # noqa: E402
from text_service import main as svc  # noqa: E402


class _Req:
    # LLM-scoped by default: the prompt-injection model only runs for LLM traffic
    def __init__(self, text, metadata=None):
        self._text = text
        self._md = {"host": "api.openai.com", "direction": "outbound"} if metadata is None else metadata

    async def json(self):
        return {"text": self._text, "metadata": self._md}


def _result(module, blocked=False):
    return AnalysisResult(module=module, score=1.0 if blocked else 0.0, findings=[],
                          blocked=blocked, risk=RiskLevel.CRITICAL if blocked else RiskLevel.SAFE)


def _call(text):
    return json.loads(asyncio.run(svc.analyze_text(_Req(text))).body)


def _patch_slow(monkeypatch, calls, delay=0.3):
    def slow_pi(t):
        calls.append(t)
        time.sleep(delay)
        return _result("prompt_injection")
    monkeypatch.setattr(svc, "_route", lambda t: "code")
    monkeypatch.setattr(svc, "model_code_analysis", lambda t, *a, **k: _result("code"))
    monkeypatch.setattr(svc, "model_patterns", lambda t: _result("pattern"))
    monkeypatch.setattr(svc, "model_prompt_injection", slow_pi)
    svc._cache_clear()
    svc._reset_semaphore()


def test_identical_bodies_are_analyzed_once(monkeypatch):
    calls = []
    _patch_slow(monkeypatch, calls, delay=0.01)
    first, second = _call("same telemetry body"), _call("same telemetry body")
    assert first == second and len(calls) == 1
    _call("a different body")
    assert len(calls) == 2


def test_cache_is_bounded(monkeypatch):
    calls = []
    _patch_slow(monkeypatch, calls, delay=0.0)
    monkeypatch.setattr(svc, "_CACHE_MAX", 2)
    for t in ("a", "b", "c"):
        _call(t)
    _call("a")  # evicted by "c" -> recomputed
    assert calls.count("a") == 2


def test_event_loop_stays_responsive_during_analysis(monkeypatch):
    _patch_slow(monkeypatch, [])

    async def scenario():
        ticks = 0

        async def ticker():
            nonlocal ticks
            while True:
                await asyncio.sleep(0.02)
                ticks += 1
        t = asyncio.create_task(ticker())
        await svc.analyze_text(_Req("unique body for loop test"))
        t.cancel()
        return ticks
    # 0.3 s of blocking model work: a blocked loop would tick ~0 times
    assert asyncio.run(scenario()) >= 8


def test_concurrent_requests_overlap_up_to_the_cap(monkeypatch):
    _patch_slow(monkeypatch, [])
    monkeypatch.setattr(svc, "_MAX_CONC", 2)
    svc._reset_semaphore()

    async def scenario():
        t0 = time.perf_counter()
        await asyncio.gather(*(svc.analyze_text(_Req(f"body {i}")) for i in range(4)))
        return time.perf_counter() - t0
    elapsed = asyncio.run(scenario())
    assert 0.5 < elapsed < 1.1   # 4 x 0.3 s at concurrency 2 ~ 0.6 s (serial would be 1.2 s)
