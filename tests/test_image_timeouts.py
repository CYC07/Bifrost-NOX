"""Images get a longer verdict timeout than text, in both the orchestrator and the gateway.

Text analysis takes well under a second, but an image goes through OCR, object detection and CLIP and, during a burst,
waits its turn behind other images. With the same 8 s / 10 s limits as text, later images timed out unanalysed and were
let through. Layering still matters: the orchestrator must give up (and say why) BEFORE the gateway does.
"""
import asyncio
import os
import sys

import httpx
import pytest
from starlette.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "gateway")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import proxy as gw  # noqa: E402
from master_ai import orchestrator as orch  # noqa: E402


# ---------------------------------------------------------------- orchestrator

class _Resp:
    status_code = 200
    text = "x"

    def json(self):
        return {"status": "allow", "risk_level": "safe", "reason": "ok", "detailed_findings": {}}


def _recording_client(seen):
    class Fake:
        def __init__(self, *a, **k):
            seen["client_timeout"] = k.get("timeout")

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json=None, files=None, **k):
            seen.setdefault("calls", []).append((url, k.get("timeout")))
            return _Resp()
    return Fake


def _analyze(monkeypatch, content_type, **form):
    seen = {}
    monkeypatch.setattr(orch.httpx, "AsyncClient", _recording_client(seen))
    c = TestClient(orch.app, client=("127.0.0.1", 50000))
    files = {"file": ("a.png", b"\x89PNG....", "image/png")} if content_type != "text" else None
    data = {"content_type": content_type, "source_ip": "10.0.0.2", "destination_ip": "x", "port": "443",
            "direction": "inbound", "text_content": "hello" if content_type == "text" else "", **form}
    assert c.post("/analyze_traffic", data=data, files=files).status_code == 200
    return seen


def test_orchestrator_waits_longer_for_the_image_service(monkeypatch):
    monkeypatch.delenv("IMAGE_SERVICE_TIMEOUT", raising=False)
    monkeypatch.delenv("SERVICE_TIMEOUT", raising=False)
    seen = _analyze(monkeypatch, "image")
    (url, timeout), = seen["calls"]
    assert url.endswith("/analyze") and timeout == 30.0
    assert seen["client_timeout"] == 8.0                      # the default for everything else is unchanged


def test_text_calls_keep_the_short_default(monkeypatch):
    monkeypatch.delenv("SERVICE_TIMEOUT", raising=False)
    seen = _analyze(monkeypatch, "text")
    (_url, timeout), = seen["calls"]
    assert timeout is None and seen["client_timeout"] == 8.0   # no per-call override: the client's 8 s applies


def test_image_service_timeout_is_configurable(monkeypatch):
    monkeypatch.setenv("IMAGE_SERVICE_TIMEOUT", "12.5")
    assert _analyze(monkeypatch, "image")["calls"][0][1] == 12.5
    monkeypatch.setenv("IMAGE_SERVICE_TIMEOUT", "nonsense")
    assert _analyze(monkeypatch, "image")["calls"][0][1] == 30.0
    monkeypatch.setenv("IMAGE_SERVICE_TIMEOUT", "-4")
    assert _analyze(monkeypatch, "image")["calls"][0][1] == 30.0


# ---------------------------------------------------------------- gateway

def _gateway_timeout(monkeypatch, c_type, **env):
    for k in ("AI_TIMEOUT", "AI_TIMEOUT_IMAGE"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    seen = {}

    async def post(url, data=None, files=None, timeout=None):
        seen["timeout"] = timeout

        class R:
            status_code = 200

            def json(self):
                return {"status": "allow"}
        return R()
    insp = gw.IDPInspector()
    insp.client = type("C", (), {"post": staticmethod(post)})()
    asyncio.run(insp.send_to_ai(c_type, b"x" * 10, "inbound", "1.1.1.1", "2.2.2.2", 443))
    return seen["timeout"]


def test_gateway_waits_longer_for_images(monkeypatch):
    assert _gateway_timeout(monkeypatch, "image") == 40.0
    assert _gateway_timeout(monkeypatch, "text") == 10.0
    assert _gateway_timeout(monkeypatch, "document") == 10.0


def test_gateway_timeouts_are_configurable_and_tolerate_garbage(monkeypatch):
    assert _gateway_timeout(monkeypatch, "image", AI_TIMEOUT_IMAGE="55") == 55.0
    assert _gateway_timeout(monkeypatch, "text", AI_TIMEOUT="7.5") == 7.5
    assert _gateway_timeout(monkeypatch, "image", AI_TIMEOUT_IMAGE="soon") == 40.0
    assert _gateway_timeout(monkeypatch, "text", AI_TIMEOUT="-1") == 10.0


def test_the_orchestrator_gives_up_before_the_gateway_does(monkeypatch):
    for k in ("IMAGE_SERVICE_TIMEOUT", "AI_TIMEOUT_IMAGE"):
        monkeypatch.delenv(k, raising=False)
    assert orch._image_timeout() < _gateway_timeout(monkeypatch, "image")
