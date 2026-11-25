"""The event the gateway posts to the orchestrator for a connection that could not be completed."""
import asyncio
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "gateway")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import proxy as gw  # noqa: E402


def _post_spy():
    sent = []

    async def post(url, json=None, timeout=None):
        sent.append(json)
    return sent, post


def _inspector(post):
    i = gw.IDPInspector()
    i.client = type("C", (), {"post": staticmethod(post)})()
    return i


def test_default_event_is_still_a_pinned_tls_block():
    sent, post = _post_spy()
    asyncio.run(_inspector(post).log_block("10.0.0.2", "1.2.3.4", 443, "app.example", "Client rejected MITM cert"))
    assert sent[0]["rule"] == "PINNED-TLS" and sent[0]["status"] == "block"
    assert sent[0]["destination_ip"] == "app.example"


def test_upstream_failure_event_is_labelled_and_not_a_block():
    sent, post = _post_spy()
    asyncio.run(_inspector(post).log_block("10.0.0.2", "1.2.3.4", 443, "www.bing.com",
                                           "Upstream unreachable: timed out", rule="UPSTREAM-FAIL", status="allow"))
    ev = sent[0]
    assert ev["rule"] == "UPSTREAM-FAIL"
    assert ev["status"] == "allow"                     # the orchestrator counts only "block" as a block
    assert ev["risk_level"] == "safe"
    assert "timed out" in ev["reason"]
