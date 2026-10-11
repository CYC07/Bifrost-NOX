"""Gateway behaviour when the AI analysis path is slow or broken."""
import asyncio
import os
import sys

import httpx

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "gateway")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import proxy as gw  # noqa: E402


class _Resp:
    def __init__(self, status_code=200, payload=None):
        self.status_code, self._p = status_code, payload or {"status": "allow"}

    def json(self):
        return self._p


def _inspector(post):
    i = gw.IDPInspector()
    i.client = type("C", (), {"post": staticmethod(post)})()
    return i


def _send(inspector):
    return asyncio.run(inspector.send_to_ai("text", b"hello", "outbound", "1.1.1.1", "2.2.2.2", 80))


async def _timeout(*a, **k):
    raise httpx.ReadTimeout("")


def test_timeout_fails_open_by_default(monkeypatch):
    monkeypatch.delenv("AI_FAIL_MODE", raising=False)
    assert _send(_inspector(_timeout))["status"] == "allow"


def test_timeout_blocks_when_fail_closed(monkeypatch):
    monkeypatch.setenv("AI_FAIL_MODE", "closed")
    v = _send(_inspector(_timeout))
    assert v["status"] == "block" and "unavailable" in v["reason"].lower()


def test_non_200_is_a_failure_not_a_silent_allow(monkeypatch):
    async def err(*a, **k):
        return _Resp(500)
    monkeypatch.setenv("AI_FAIL_MODE", "closed")
    assert _send(_inspector(err))["status"] == "block"


def test_healthy_verdict_passes_through_in_both_modes(monkeypatch):
    async def ok(*a, **k):
        return _Resp(200, {"status": "block", "reason": "Blocked by: code"})
    for mode in ("open", "closed"):
        monkeypatch.setenv("AI_FAIL_MODE", mode)
        assert _send(_inspector(ok))["status"] == "block"


def test_request_context_is_forwarded_to_the_orchestrator(monkeypatch):
    seen = {}

    async def spy(url, data=None, files=None, timeout=None):
        seen.update(data)
        return _Resp()

    i = _inspector(spy)
    asyncio.run(i.send_to_ai("text", b"hello", "outbound", "1.1.1.1", "api.example", 443,
                             host="api.example", method="POST", path="/v1/chat/completions"))
    assert seen["direction"] == "outbound"
    assert seen["host"] == "api.example"
    assert seen["method"] == "POST"
    assert seen["path"] == "/v1/chat/completions"


def test_inspect_full_passes_context_through(monkeypatch):
    captured = {}

    async def fake_send(c_type, payload, direction, src_ip="", dst_ip="", dst_port="", **ctx):
        captured.update(ctx, direction=direction)
        return {"status": "allow"}

    i = gw.IDPInspector()
    monkeypatch.setattr(i, "send_to_ai", fake_send)
    verdict = asyncio.run(i.inspect_full(
        {"content-type": "application/json"}, b'{"a": "b"}', "outbound", True,
        src_ip="10.0.0.2", dst_ip="api.example", dst_port=443,
        host="api.example", method="POST", path="/v1/messages"))
    assert verdict == "allow"
    assert captured == {"host": "api.example", "method": "POST", "path": "/v1/messages", "direction": "outbound"}


# --- request-target (path + query) inspection --------------------------------------
def _target_inspector(verdicts):
    """Inspector whose send_to_ai records calls and answers from `verdicts` (by kind)."""
    calls = []

    async def fake_send(c_type, payload, direction, src_ip="", dst_ip="", dst_port="", **ctx):
        calls.append({"c_type": c_type, "payload": payload, "direction": direction, **ctx})
        return {"status": verdicts.get(ctx.get("kind", "body"), "allow")}

    i = gw.IDPInspector()
    i.send_to_ai = fake_send
    return i, calls


def _inspect(i, body, path, direction="outbound", method="GET"):
    return asyncio.run(i.inspect_full({"content-type": "text/plain"}, body, direction, True,
                                      src_ip="10.0.0.2", dst_ip="app.example", dst_port=443,
                                      host="app.example", method=method, path=path))


def test_bodyless_request_with_attack_in_query_is_analyzed_and_blocked():
    i, calls = _target_inspector({"url": "block"})
    assert _inspect(i, b"", "/item?id=1%27%20OR%20%271%27%3D%271%27%20--") == "block"
    assert calls[0]["kind"] == "url" and calls[0]["payload"].startswith(b"/item?id=")


def test_secret_in_a_query_string_with_no_attack_characters_is_still_analyzed():
    i, calls = _target_inspector({"url": "block"})
    assert _inspect(i, b"", "/export?api_key=" + "AKIA" + "IOSFODNN7REALKEYX") == "block"
    assert calls[0]["kind"] == "url"


def test_ordinary_targets_cost_nothing_no_analysis_call():
    i, calls = _target_inspector({"url": "block"})
    for p in ("/index.html", "/search?q=best+pizza&page=2", "/auth?token=abc.def-ghi_jkl", "/a/b/../c.html"):
        assert _inspect(i, b"", p) == "allow"
    assert calls == []


def test_traversal_in_path_alone_is_analyzed():
    i, calls = _target_inspector({"url": "block"})
    assert _inspect(i, b"", "/../../../../etc/passwd") == "block"


def test_inbound_responses_are_never_target_checked():
    i, calls = _target_inspector({"url": "block"})
    assert _inspect(i, b"", "/item?id=1%27%20OR%20%271%27", direction="inbound") == "allow"
    assert calls == []


def test_query_attack_is_blocked_even_when_the_body_is_clean():
    i, calls = _target_inspector({"url": "block", "body": "allow"})
    assert _inspect(i, b"name=alice", "/save?id=1%27%20OR%20%271%27%3D%271", method="POST") == "block"
    assert [c.get("kind") for c in calls] == ["url"]          # blocked before the body is analysed


def test_clean_target_with_body_still_analyses_the_body():
    i, calls = _target_inspector({"body": "block"})
    assert _inspect(i, b"id=1' OR '1'='1", "/save?x=1", method="POST") == "block"
    assert [c.get("kind", "body") for c in calls] == ["body"]


def test_target_check_failure_fails_open_by_the_same_policy(monkeypatch):
    monkeypatch.delenv("AI_FAIL_MODE", raising=False)
    i = _inspector(_timeout)
    assert asyncio.run(i.inspect_full({}, b"", "outbound", True, src_ip="a", dst_ip="b", dst_port=80,
                                      host="b", method="GET", path="/i?id=%27%20OR%201%3D1--")) == "allow"


def test_timeout_is_configurable(monkeypatch):
    seen = {}

    async def spy(*a, **k):
        seen.update(k)
        return _Resp()
    monkeypatch.setenv("AI_TIMEOUT", "7.5")
    _send(_inspector(spy))
    assert seen["timeout"] == 7.5
    monkeypatch.delenv("AI_TIMEOUT")
    _send(_inspector(spy))
    assert seen["timeout"] == 10.0
