"""Orchestrator document path: DOC_SCAN_MODE=advisory (default) | block | off(gateway-side).

The measured false-positive rate of the existing document analyzers on real benign PDFs is not
zero (a Ghostscript manual trips PDF_JavaScript_Launcher via the /JS prefix + /OpenAction), so a
document-service BLOCK is reported as advisory (CENSOR = warn row, nothing blocked) unless the
operator sets DOC_SCAN_MODE=block. Fail-open behaviour is unchanged.
"""
import os
import sys

import pytest
from starlette.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from master_ai import orchestrator as orch  # noqa: E402

BLOCK = {"status": "block", "risk_level": "critical", "reason": "Critical document threat (max=0.95)",
         "detailed_findings": {"findings": ["YARA: PDF_JavaScript_Launcher"], "scores": {"malware": 0.95}}}
ALLOW = {"status": "allow", "risk_level": "safe", "reason": "Safe", "detailed_findings": {}}


class _Resp:
    def __init__(self, code=200, payload=None):
        self.status_code, self._p, self.text = code, payload or ALLOW, "x"

    def json(self):
        return self._p


def _fake(resp=None, boom=None, seen=None):
    class Fake:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json=None, files=None, **k):
            if seen is not None:
                seen.append(url)
            if boom:
                raise boom
            return resp or _Resp()
    return Fake


FORM = {"content_type": "document", "source_ip": "10.0.0.2", "destination_ip": "files.example",
        "port": "443", "direction": "inbound", "host": "files.example", "method": "GET", "path": "/a.pdf"}


def _post(monkeypatch, fake):
    monkeypatch.setattr(orch.httpx, "AsyncClient", fake)
    c = TestClient(orch.app, client=("127.0.0.1", 50000))
    return c.post("/analyze_traffic", data=FORM, files={"file": ("blob", b"%PDF-1.4 x", "application/octet-stream")}).json()


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.delenv("DOC_SCAN_MODE", raising=False)
    monkeypatch.delenv("AI_FAIL_MODE", raising=False)


def test_default_mode_downgrades_a_document_block_to_advisory(monkeypatch):
    out = _post(monkeypatch, _fake(_Resp(200, BLOCK)))
    assert out["status"] == "censor"
    assert "advisory" in out["reason"].lower() and "PDF_JavaScript_Launcher" in str(out["detailed_findings"])


def test_block_mode_enforces(monkeypatch):
    monkeypatch.setenv("DOC_SCAN_MODE", "block")
    assert _post(monkeypatch, _fake(_Resp(200, BLOCK)))["status"] == "block"


def test_clean_document_is_allowed_in_both_modes(monkeypatch):
    assert _post(monkeypatch, _fake(_Resp(200, ALLOW)))["status"] == "allow"
    monkeypatch.setenv("DOC_SCAN_MODE", "block")
    assert _post(monkeypatch, _fake(_Resp(200, ALLOW)))["status"] == "allow"


def test_document_is_posted_to_the_document_service(monkeypatch):
    seen = []
    _post(monkeypatch, _fake(seen=seen))
    assert any(u.endswith(":8002/analyze") or "/analyze" in u and "8002" in u for u in seen)


def test_service_error_fails_open_by_default(monkeypatch):
    assert _post(monkeypatch, _fake(_Resp(500)))["status"] == "allow"
    assert _post(monkeypatch, _fake(boom=RuntimeError("down")))["status"] == "allow"


def test_service_error_fails_closed_when_configured(monkeypatch):
    monkeypatch.setenv("AI_FAIL_MODE", "closed")
    assert _post(monkeypatch, _fake(_Resp(500)))["status"] == "block"


def test_advisory_does_not_touch_text_and_image_verdicts(monkeypatch):
    monkeypatch.setattr(orch.httpx, "AsyncClient", _fake(_Resp(200, BLOCK)))
    form = dict(FORM, content_type="text", text_content="x")
    out = TestClient(orch.app, client=("127.0.0.1", 50000)).post("/analyze_traffic", data=form).json()
    assert out["status"] == "block"
