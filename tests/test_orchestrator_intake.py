"""AI Intake (dashboard upload -> POST /analyze_traffic) must RECORD what the AI actually said.

Bugs fixed here:
* the queue row only carried `risk=` and 60 characters of the reason; the findings ("Classified as: ...", YARA hits,
  OCR secrets) and per-module scores were dropped, so the page could not show the result;
* a CENSOR verdict (advisory documents, borderline images) left the row at status "analyzing" forever;
* with the default fail-open policy a failed image/document service call fell back to "No threats detected", so an
  UNANALYSED file showed as safe. The verdict returned to the caller is unchanged (fail-open is a design priority);
  only the intake record says the analysis did not happen.
"""
import os
import sys

import httpx
import pytest
from starlette.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from master_ai import orchestrator as orch  # noqa: E402


def verdict(status="allow", risk="safe", reason="No analyzer flagged a block", findings=None, scores=None):
    return {"status": status, "risk_level": risk, "reason": reason,
            "detailed_findings": {"findings": findings if findings is not None else [], "scores": scores or {}}}


class _Resp:
    def __init__(self, code=200, payload=None):
        self.status_code, self._p, self.text = code, payload or verdict(), "x"

    def json(self):
        return self._p


def _fake(resp=None, boom=None):
    class Fake:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json=None, files=None, **k):
            if boom:
                raise boom
            return resp or _Resp()
    return Fake


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for k in ("AI_FAIL_MODE", "DOC_SCAN_MODE"):
        monkeypatch.delenv(k, raising=False)
    orch.UPLOAD_QUEUE.clear()
    yield
    orch.UPLOAD_QUEUE.clear()


def upload(monkeypatch, fake, kind="image", name="pic.png"):
    monkeypatch.setattr(orch.httpx, "AsyncClient", fake)
    c = TestClient(orch.app, client=("127.0.0.1", 50000))
    form = {"content_type": kind, "source_ip": "dashboard", "destination_ip": "ai-intake"}
    r = c.post("/analyze_traffic", data=form, files={"file": (name, b"\x89PNG\r\n" + b"x" * 2000, "application/octet-stream")})
    return r.json(), c.get("/uploads").json()["uploads"]


# --- the result is recorded -----------------------------------------------------------------------
def test_findings_and_scores_reach_the_record(monkeypatch):
    v = verdict(findings=["Classified as: google or gmail account sign in page with logo (0.13)", "OCR: 12 words read"],
                scores={"semantic": 0.13, "ocr": 0.0})
    out, rows = upload(monkeypatch, _fake(_Resp(200, v)))
    r = rows[0]
    assert out["status"] == "allow" and r["status"] == "indexed" and r["name"] == "pic.png"
    assert r["tags"][0] == "risk=safe" and any("Classified as: google" in t for t in r["tags"])
    assert r["detail"]["findings"][:2] == v["detailed_findings"]["findings"]
    assert r["detail"]["scores"] == {"semantic": 0.13, "ocr": 0.0} and r["detail"]["reason"] == "No analyzer flagged a block"


def test_block_is_flagged_with_its_evidence(monkeypatch):
    v = verdict("block", "critical", "Secret in image: AWS key", ["OCR secret: AWS Access Key"], {"ocr": 0.95})
    _, rows = upload(monkeypatch, _fake(_Resp(200, v)))
    assert rows[0]["status"] == "flagged" and any("AWS Access Key" in t for t in rows[0]["tags"])


@pytest.mark.parametrize("kind,name", [("image", "p.png"), ("document", "a.pdf")])
def test_censor_is_review_not_stuck_analyzing(monkeypatch, kind, name):
    v = verdict("censor", "medium", "Advisory: possible JavaScript", ["PDF has /OpenAction"], {"structure": 0.7})
    out, rows = upload(monkeypatch, _fake(_Resp(200, v)), kind, name)
    assert out["status"] == "censor" and rows[0]["status"] == "review"
    assert rows[0]["detail"]["findings"] == ["PDF has /OpenAction"]


def test_document_advisory_downgrade_is_review_with_the_original_findings(monkeypatch):
    v = verdict("block", "critical", "Critical document threat (max=0.95)", ["YARA: PDF_JavaScript_Launcher"], {"malware": 0.95})
    out, rows = upload(monkeypatch, _fake(_Resp(200, v)), "document", "manual.pdf")
    assert out["status"] == "censor" and rows[0]["status"] == "review"
    assert "PDF_JavaScript_Launcher" in str(rows[0]["detail"]["findings"]) and rows[0]["detail"]["scores"] == {"malware": 0.95}


# --- an unanalysed file must not look safe --------------------------------------------------------
@pytest.mark.parametrize("resp,boom", [(_Resp(500), None), (_Resp(503), None), (None, httpx.ConnectError("refused")), (None, httpx.ReadTimeout("slow")),
                                       (None, RuntimeError("boom"))])
def test_a_failed_analysis_is_an_error_row_but_the_verdict_stays_fail_open(monkeypatch, resp, boom):
    out, rows = upload(monkeypatch, _fake(resp, boom))
    assert out["status"] == "allow", "fail-open for callers is unchanged"
    assert rows[0]["status"] == "error"
    assert any("unavailable" in t.lower() or "not analy" in t.lower() for t in rows[0]["tags"])
    assert rows[0]["detail"]["error"]


def test_fail_closed_unavailable_is_an_error_row_not_a_malicious_flag(monkeypatch):
    monkeypatch.setenv("AI_FAIL_MODE", "closed")
    out, rows = upload(monkeypatch, _fake(_Resp(500)))
    assert out["status"] == "block" and rows[0]["status"] == "error"


def test_document_service_failure_is_an_error_row_too(monkeypatch):
    _, rows = upload(monkeypatch, _fake(_Resp(500)), "document", "a.pdf")
    assert rows[0]["status"] == "error"


# --- bounds and robustness ------------------------------------------------------------------------
def test_record_size_is_bounded_and_odd_findings_are_ignored(monkeypatch):
    v = verdict(findings=["x" * 5000] + [f"finding {i}" for i in range(100)] + [None, 7, {"a": 1}],
                scores={f"m{i}": i / 100 for i in range(50)})
    _, rows = upload(monkeypatch, _fake(_Resp(200, v)))
    d = rows[0]["detail"]
    assert len(d["findings"]) <= 25 and all(isinstance(f, str) and len(f) <= 240 for f in d["findings"])
    assert len(d["scores"]) <= 12 and len(rows[0]["tags"]) <= 6 and all(len(t) <= 80 for t in rows[0]["tags"])


def test_verdict_without_detailed_findings_still_records(monkeypatch):
    v = {"status": "allow", "risk_level": "safe", "reason": "Safe", "detailed_findings": None}
    _, rows = upload(monkeypatch, _fake(_Resp(200, v)))
    assert rows[0]["status"] == "indexed" and rows[0]["detail"]["findings"] == []


def test_text_and_gateway_traffic_do_not_create_intake_rows(monkeypatch):
    monkeypatch.setattr(orch.httpx, "AsyncClient", _fake(_Resp(200, verdict())))
    c = TestClient(orch.app, client=("127.0.0.1", 50000))
    c.post("/analyze_traffic", data={"content_type": "text", "text_content": "hello", "source_ip": "a", "destination_ip": "b"})
    assert c.get("/uploads").json()["uploads"] == []
