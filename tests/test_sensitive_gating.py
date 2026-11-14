"""How the sensitive-content analyzer is wired into the text service: direction policy and routing.

* Inbound (a server's reply) is never exfiltration: a sensitive-content hit is advisory (CENSOR), like the
  PII and secret analyzers. Outbound it blocks. SENSITIVE_INBOUND=block restores the old behaviour.
* The router only sends "prose" bodies to the NLI. A pay list ("Alice 142000, Bob 98000, ... confidential")
  routes as web_request, so the NLI never saw it; a body carrying strong private-data evidence is now
  analysed whatever the router said. Ordinary web_request bodies still skip the NLI (latency).
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.schemas import AnalysisResult, RiskLevel  # noqa: E402
from text_service import main as svc  # noqa: E402

PAYLIST = "Employee salary list: Alice 142000, Bob 98000, Carol 175000, confidential."
JSON_BODY = '{"user": "dana", "theme": "dark", "items": [1, 2, 3]}'


def _res(module, blocked=False):
    return AnalysisResult(module=module, score=0.9 if blocked else 0.0,
                          findings=["x"] if blocked else [], blocked=blocked,
                          risk=RiskLevel.HIGH if blocked else RiskLevel.SAFE)


@pytest.fixture
def calls(monkeypatch):
    seen = []
    monkeypatch.setattr(svc, "model_code_analysis", lambda t, *a, **k: _res("code"))
    monkeypatch.setattr(svc, "model_patterns", lambda t, *a, **k: _res("pattern"))
    monkeypatch.setattr(svc, "model_pi_signatures", lambda t, s: _res("prompt_injection_signature"))
    monkeypatch.setattr(svc, "model_web_attack", lambda t, parts=None: _res("web_attack"))
    monkeypatch.setattr(svc, "waf_gate_parts", lambda t: [])
    monkeypatch.setattr(svc, "model_sensitive", lambda t: (seen.append(t), _res("sensitive", True))[1])
    monkeypatch.delenv("SENSITIVE_INBOUND", raising=False)
    return seen


def test_outbound_sensitive_hit_blocks(calls, monkeypatch):
    monkeypatch.setattr(svc, "_route", lambda t: "prose")
    out = svc._analyze_sync("some prose", False, "outbound")
    assert out["status"] == "block" and "sensitive" in out["reason"]


def test_inbound_sensitive_hit_is_advisory_not_a_block(calls, monkeypatch):
    monkeypatch.setattr(svc, "_route", lambda t: "prose")
    out = svc._analyze_sync("Our terms of service describe how we handle your account and data.", False, "inbound")
    assert out["status"] == "censor"
    assert "advisory" in out["reason"].lower()
    assert calls, "the analyzer still runs inbound (its finding is shown as a WARN)"


def test_inbound_can_be_switched_back_to_blocking(calls, monkeypatch):
    monkeypatch.setattr(svc, "_route", lambda t: "prose")
    monkeypatch.setenv("SENSITIVE_INBOUND", "block")
    assert svc._analyze_sync("some prose", False, "inbound")["status"] == "block"


def test_payroll_list_routed_as_web_request_is_still_analysed(calls, monkeypatch):
    monkeypatch.setattr(svc, "_route", lambda t: "web_request")
    out = svc._analyze_sync(PAYLIST, False, "outbound")
    assert calls == [PAYLIST]
    assert out["status"] == "block" and "sensitive" in out["reason"]


def test_evidence_fallback_is_outbound_only(calls, monkeypatch):
    """Inbound the finding is only advisory, so an inbound API reply that merely mentions 'account number
    12345678' must not pay for an NLI pass (nor add a WARN row)."""
    monkeypatch.setattr(svc, "_route", lambda t: "web_request")
    out = svc._analyze_sync(PAYLIST, False, "inbound")
    assert calls == [] and out["status"] == "allow"


def test_ordinary_web_request_body_does_not_pay_for_the_nli(calls, monkeypatch):
    monkeypatch.setattr(svc, "_route", lambda t: "web_request")
    out = svc._analyze_sync(JSON_BODY, False, "outbound")
    assert calls == []
    assert out["status"] == "allow"


def test_code_route_with_no_evidence_skips_the_nli(calls, monkeypatch):
    monkeypatch.setattr(svc, "_route", lambda t: "code")
    svc._analyze_sync("def f(x):\n    return x + 1\n", False, "outbound")
    assert calls == []
