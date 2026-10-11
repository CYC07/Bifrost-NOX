"""Orchestrator: forwards request context, honours AI_FAIL_MODE, shows advisory findings."""
import os
import sys

import pytest
from starlette.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from master_ai import orchestrator as orch  # noqa: E402


class _Resp:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._p = payload or {"status": "allow", "risk_level": "safe", "reason": "ok", "detailed_findings": {}}
        self.text = str(self._p)

    def json(self):
        return self._p


def _fake_client(calls, *, resp=None, boom=None):
    class Fake:
        def __init__(self, *a, **k):
            calls["client_kwargs"] = k

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json=None, files=None, **k):
            calls["json"] = json
            if boom:
                raise boom
            return resp or _Resp()
    return Fake


FORM = {"content_type": "text", "source_ip": "10.0.0.2", "destination_ip": "api.example",
        "port": "443", "text_content": "hello", "direction": "outbound",
        "host": "api.example", "method": "POST", "path": "/v1/chat/completions"}


def _post(monkeypatch, fake):
    monkeypatch.setattr(orch.httpx, "AsyncClient", fake)
    # ingest endpoints are loopback-only by design (control-plane auth), like the real gateway
    return TestClient(orch.app, client=("127.0.0.1", 50000)).post("/analyze_traffic", data=FORM).json()


def test_context_is_forwarded_to_the_text_service(monkeypatch):
    calls = {}
    _post(monkeypatch, _fake_client(calls))
    md = calls["json"]["metadata"]
    assert md["direction"] == "outbound" and md["host"] == "api.example"
    assert md["path"] == "/v1/chat/completions" and md["method"] == "POST"
    assert md["src"] == "10.0.0.2" and md["dst"] == "api.example"


def test_request_target_kind_is_forwarded(monkeypatch):
    calls = {}
    monkeypatch.setattr(orch.httpx, "AsyncClient", _fake_client(calls))
    TestClient(orch.app, client=("127.0.0.1", 50000)).post("/analyze_traffic", data={**FORM, "kind": "url"})
    assert calls["json"]["metadata"]["kind"] == "url"
    TestClient(orch.app, client=("127.0.0.1", 50000)).post("/analyze_traffic", data=FORM)
    assert calls["json"]["metadata"]["kind"] == ""


def test_service_timeout_is_explicit_configurable_and_below_the_gateway(monkeypatch):
    calls = {}
    monkeypatch.delenv("SERVICE_TIMEOUT", raising=False)
    _post(monkeypatch, _fake_client(calls))
    assert calls["client_kwargs"]["timeout"] == 8.0           # gateway AI_TIMEOUT default is 10
    monkeypatch.setenv("SERVICE_TIMEOUT", "3")
    _post(monkeypatch, _fake_client(calls))
    assert calls["client_kwargs"]["timeout"] == 3.0


def test_failure_fails_open_by_default(monkeypatch):
    monkeypatch.delenv("AI_FAIL_MODE", raising=False)
    out = _post(monkeypatch, _fake_client({}, boom=RuntimeError("down")))
    assert out["status"] == "allow"


@pytest.mark.parametrize("kind", ["exception", "non200"])
def test_failure_blocks_when_fail_closed(monkeypatch, kind):
    monkeypatch.setenv("AI_FAIL_MODE", "closed")
    fake = _fake_client({}, boom=RuntimeError("down")) if kind == "exception" else _fake_client({}, resp=_Resp(500))
    out = _post(monkeypatch, fake)
    assert out["status"] == "block" and "unavailable" in out["reason"].lower()


def test_healthy_block_verdict_is_untouched_by_fail_mode(monkeypatch):
    monkeypatch.setenv("AI_FAIL_MODE", "closed")
    blk = _Resp(200, {"status": "block", "risk_level": "critical", "reason": "Blocked by: code", "detailed_findings": {}})
    assert _post(monkeypatch, _fake_client({}, resp=blk))["status"] == "block"


def test_advisory_verdict_shows_as_warn_row_with_reason_and_no_threat(monkeypatch):
    adv = _Resp(200, {"status": "censor", "risk_level": "low",
                      "reason": "Advisory (not blocked): prompt-injection signature override_prior_instructions",
                      "detailed_findings": {}})
    threats_before = len(orch.RECENT_THREATS)
    out = _post(monkeypatch, _fake_client({}, resp=adv))
    row = orch.RECENT_LOGS[0]
    assert out["status"] == "censor"
    assert row["level"] == "WARN" and "signature" in row["reason"]
    assert len(orch.RECENT_THREATS) == threats_before


def test_request_target_and_waf_blocks_get_meaningful_labels():
    assert orch._classify_reason("Blocked by: request_target")[0] == "Malicious Request Target"
    assert orch._classify_reason("Blocked by: web_attack")[0] == "Web Attack"
    assert orch._classify_reason("Blocked by: code, web_attack")[0] != "Anomalous Content"


def test_prompt_injection_block_is_labelled_prompt_injection_not_command_injection():
    t, sev, _ = orch._classify_reason("Blocked by: prompt_injection")
    assert t == "Prompt Injection" and sev == "critical"
    assert orch._classify_reason("Blocked by: web_attack, sql injection")[0] == "SQL Injection"
