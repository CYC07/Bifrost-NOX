"""WAF stage: request-side only, and JSON bodies are scored value-by-value.

The WAF (DistilBERT) classified *shape* rather than content: every benign JSON body came back
as SQLi (0.81-0.999), HTML as XSS, robots.txt as path traversal. Scoring each JSON value (how
real WAFs inspect parameters) fixed 7 of 9 benign JSON bodies with no loss on JSON-wrapped
attacks, and the WAF is a request-side control, so it no longer runs on inbound replies.
Availability over security: when in doubt, allow.
"""
import asyncio
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.schemas import RiskLevel  # noqa: E402
from text_service import main as svc  # noqa: E402


class _Pred:
    def __init__(self, blocked, label="sqli", score=0.99):
        self.blocked, self.label, self.score, self.risk = blocked, label, score, "high"


class FakeWAF:
    """Blocks any input containing a quote-OR pattern; records every input it sees."""
    def __init__(self):
        self.seen = []

    def predict(self, text):
        self.seen.append(text)
        return _Pred("' OR '" in text)


@pytest.fixture
def waf(monkeypatch):
    f = FakeWAF()
    monkeypatch.setattr(svc, "waf_classifier", f)
    return f


# --- value-wise scoring ------------------------------------------------------
def test_json_body_is_scored_per_value_not_as_a_blob(waf):
    svc.model_web_attack(json.dumps({"username": "alice", "password": "hunter2", "age": 31}))
    assert sorted(waf.seen) == ["31", "alice", "hunter2"]


def test_attack_hidden_in_a_json_value_still_blocks(waf):
    r = svc.model_web_attack(json.dumps({"username": "admin' OR '1'='1' --", "password": "x"}))
    assert r.blocked and "sqli" in r.findings[0]


def test_nested_and_list_values_are_reached(waf):
    r = svc.model_web_attack(json.dumps({"filter": {"where": ["name", "=", "x' OR '1'='1"]}}))
    assert r.blocked


def test_benign_json_login_is_not_blocked(waf):
    assert not svc.model_web_attack(json.dumps({"username": "alice", "password": "hunter2"})).blocked


def test_non_json_text_is_scored_whole_once(waf):
    svc.model_web_attack("username=admin&password=secret123")
    assert waf.seen == ["username=admin&password=secret123"]


def test_malformed_json_falls_back_to_the_whole_text(waf):
    svc.model_web_attack('{"a": "unterminated')
    assert waf.seen == ['{"a": "unterminated']


def test_value_count_and_length_are_capped(waf):
    svc.model_web_attack(json.dumps({f"k{i}": f"v{i}" for i in range(500)}))
    assert len(waf.seen) <= svc.WAF_MAX_VALUES
    waf.seen.clear()
    svc.model_web_attack(json.dumps({"k": "x" * 100000}))
    assert all(len(s) <= svc.WAF_MAX_VALUE_CHARS for s in waf.seen)


def test_empty_or_trivial_json_does_not_crash(waf):
    for body in ("{}", "[]", "null", '{"a": null}', '{"a": ""}'):
        assert not svc.model_web_attack(body).blocked


# --- request-side only -------------------------------------------------------
class _Req:
    def __init__(self, text, md):
        self._t, self._md = text, md

    async def json(self):
        return {"text": self._t, "metadata": self._md}


def _call(text, md):
    return json.loads(asyncio.run(svc.analyze_text(_Req(text, md))).body)


@pytest.fixture
def pipeline(monkeypatch, waf):
    from common.schemas import AnalysisResult
    ok = lambda m: (lambda t, *a, **k: AnalysisResult(module=m, score=0.0, findings=[]))
    monkeypatch.setattr(svc, "_route", lambda t: "web_request")
    monkeypatch.setattr(svc, "model_code_analysis", ok("code"))
    monkeypatch.setattr(svc, "model_patterns", ok("pattern"))
    svc._cache_clear()
    svc._reset_semaphore()
    return waf


def test_waf_runs_on_outbound_requests(pipeline):
    out = _call("id=1' OR '1'='1", {"host": "app.example", "direction": "outbound"})
    assert out["status"] == "block" and "web_attack" in out["reason"]


def test_waf_does_not_run_on_inbound_replies(pipeline):
    out = _call("id=1' OR '1'='1", {"host": "app.example", "direction": "inbound"})
    assert out["status"] == "allow" and pipeline.seen == []


def test_missing_direction_is_treated_as_outbound(pipeline):
    assert _call("id=1' OR '1'='1", {"host": "app.example"})["status"] == "block"


def test_cache_does_not_mix_directions(pipeline):
    a = _call("id=1' OR '1'='1", {"direction": "outbound"})
    b = _call("id=1' OR '1'='1", {"direction": "inbound"})
    assert a["status"] == "block" and b["status"] == "allow"


# --- real model: the shapes we measured --------------------------------------
def _waf_available() -> bool:
    from ml.waf.predictor import WAFClassifier
    return WAFClassifier().load()


needs_waf = pytest.mark.skipif(not _waf_available(), reason="WAF model unavailable")

BENIGN_JSON = [
    {"username": "alice", "password": "hunter2"},
    {"email": "bob@example.com", "password": "S3cure!pass"},
    {"name": "Carol", "email": "c@example.com", "password": "pw123456", "age": 31},
    {"query": "best pizza near me", "page": 2},
    {"refresh_token": "abc123def456", "grant_type": "refresh_token"},
    {"deviceId": "abc123", "events": [{"t": 1, "n": "heartbeat"}], "ver": "10.0.19045"},
    {"user": {"id": 42, "prefs": {"theme": "dark", "lang": "en-US"}}, "items": [{"sku": "A-1", "qty": 2}]},
]
ATTACK_JSON = [
    {"username": "admin' OR '1'='1' --", "password": "x"},
    {"id": "1 UNION SELECT username, password FROM users--"},
    {"comment": "<script>alert(document.cookie)</script>"},
    {"ip": "8.8.8.8 && whoami"},
    {"file": "../../../../etc/passwd"},
    {"name": "{{7*7}}{{config.items()}}"},
]


@pytest.fixture
def real_waf(monkeypatch):
    from ml.waf.predictor import WAFClassifier
    c = WAFClassifier(threshold=svc.WAF_ATTACK_THRESHOLD)
    c.load()
    monkeypatch.setattr(svc, "waf_classifier", c)


@needs_waf
@pytest.mark.parametrize("obj", BENIGN_JSON, ids=lambda o: list(o)[0])
def test_real_model_allows_ordinary_json(real_waf, obj):
    assert not svc.model_web_attack(json.dumps(obj)).blocked


@needs_waf
@pytest.mark.parametrize("obj", ATTACK_JSON, ids=lambda o: list(o)[0])
def test_real_model_still_blocks_json_wrapped_attacks(real_waf, obj):
    assert svc.model_web_attack(json.dumps(obj)).blocked


@needs_waf
@pytest.mark.xfail(strict=True, reason=(
    "KNOWN MODEL GAP (needs retraining with hard negatives): values containing a URL or an apostrophe+ampersand "
    "('O'Brien & Sons', 'http://host/path') are still flagged. See WAF analysis in memory."))
def test_real_model_residual_false_positives_documented(real_waf):
    assert not svc.model_web_attack(json.dumps({"title": "O'Brien & Sons", "redirect": "https://example.com/account?tab=settings"})).blocked
