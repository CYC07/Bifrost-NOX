"""The page the gateway serves when it blocks a request (HTTP 403), per the Bifrost NØX brand kit (mockup M2).

It is served on whatever site was blocked, so it must be fully self-contained (nothing loaded from outside), must
escape every value that came off the wire, and may only state what the gateway really knows.
"""
import base64
import hashlib
import os
import re
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "gateway")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import block_page as bp  # noqa: E402
from common import threat_taxonomy as tax  # noqa: E402

CET = timezone(timedelta(hours=1), "CET")
WHEN = datetime(2026, 11, 24, 14, 2, 11, tzinfo=CET)


def info(**kw):
    base = dict(reason="Blocked by: prompt_injection", direction="outbound", host="chat.example-ai.com",
                client_ip="10.0.4.23", request_id="nox-7f3a-91c2-e04b", when=WHEN, is_https=True, fail_closed=False)
    base.update(kw)
    return bp.BlockInfo(**base)


def parse(resp: bytes):
    head, _, body = resp.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    headers = {k.lower(): v for k, v in (l.split(": ", 1) for l in lines[1:])}
    return lines[0], headers, body.decode("utf-8")


def text_of(html: str) -> str:
    html = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", html, flags=re.S)
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html)).strip()


# ---------------------------------------------------------------- shared taxonomy

def test_orchestrator_and_gateway_share_one_reason_taxonomy():
    from master_ai import orchestrator as orch
    assert orch.THREAT_PATTERNS is tax.THREAT_PATTERNS and orch._classify_reason is tax.classify_reason
    assert tax.classify_reason("Blocked by: prompt_injection")[0] == "Prompt Injection"


# ---------------------------------------------------------------- BlockVerdict stays a drop-in for "block"

def test_block_verdict_compares_equal_to_the_plain_string():
    v = bp.BlockVerdict("Blocked by: web_attack")
    assert v == "block" and isinstance(v, str) and v != "allow"
    assert v.reason == "Blocked by: web_attack"
    assert bp.BlockVerdict("x", category="Scanner Tool", detector="scanner-ua").category == "Scanner Tool"


# ---------------------------------------------------------------- categories and detectors

@pytest.mark.parametrize("reason,category", [
    ("Blocked by: prompt_injection", "Prompt Injection"),
    ("Blocked by: prompt_injection_signature", "Prompt Injection"),
    ("Blocked by: web_attack", "Web Attack"),
    ("Blocked by: web_attack, sql injection", "SQL Injection"),
    ("Blocked by: request_target", "Malicious Request Target"),
    ("Blocked by: code", "Secret Leak"),
    ("Blocked by: pattern", "PII Exposure"),
    ("something nobody has seen before", "Anomalous Content"),
])
def test_ai_reasons_map_to_the_dashboard_categories(reason, category):
    assert bp.category_for(reason) == category


def test_gateway_originated_blocks_carry_their_own_category_and_are_not_misread_as_sql():
    # "sqlmap" contains "sql": the generic keyword table would call a scanner a SQL injection.
    v = bp.BlockVerdict("scanner tool 'sqlmap'", category="Scanner Tool", detector="scanner-ua")
    i = bp.BlockInfo.from_verdict(v, host="shop.example", direction="outbound", client_ip="10.0.0.5", is_https=False)
    assert i.category == "Scanner Tool" and i.detectors == ("scanner-ua",)


def test_detectors_come_from_the_blocked_by_list():
    assert bp.detectors_for("Blocked by: code, web_attack") == ("code", "web_attack")
    assert bp.detectors_for("Executable detected") == ()


# ---------------------------------------------------------------- the HTTP response

def test_response_is_a_403_html_page_with_safe_headers():
    status, h, body = parse(bp.render_block_response(info()))
    assert status == "HTTP/1.1 403 Forbidden"
    assert h["content-type"] == "text/html; charset=utf-8"
    assert int(h["content-length"]) == len(body.encode("utf-8"))
    assert h["cache-control"] == "no-store" and h["x-content-type-options"] == "nosniff"
    assert h["connection"] == "close" and h["referrer-policy"] == "no-referrer"
    assert h["x-bifrost-request-id"] == "nox-7f3a-91c2-e04b"


def test_page_content_matches_the_mockup():
    _, _, html = parse(bp.render_block_response(info()))
    t = text_of(html)
    assert "<title>Blocked — Bifrost NØX</title>" in html
    assert "BLOCK · PROMPT INJECTION" in t
    assert "Blocked by Bifrost NØX" in t                                   # also what the lab scripts look for
    assert "Your request to chat.example-ai.com was stopped before it left the network." in t
    assert "The text you were sending matched a prompt-injection pattern." in t
    for label in ("DETECTOR", "POLICY", "REQUEST ID", "TIME", "CLIENT"):
        assert label in t
    assert "prompt_injection" in t                                         # the detector module
    assert "nox-7f3a-91c2-e04b" in t
    assert "24 Nov 2026 · 14:02:11 CET" in t
    assert "10.0.4.23" in t
    assert "Go back" in t and "Request a review" in t
    assert "ask IT Security to review it and quote the request ID" in t


def test_inbound_blocks_are_worded_for_a_response():
    t = text_of(parse(bp.render_block_response(info(direction="inbound", reason="Blocked by: pattern")))[2])
    assert "A response from chat.example-ai.com was stopped before it reached your device." in t
    assert "BLOCK · PERSONAL DATA" in t


def test_footer_tells_the_truth_about_the_failure_mode():
    open_t = text_of(parse(bp.render_block_response(info(fail_closed=False)))[2])
    closed_t = text_of(parse(bp.render_block_response(info(fail_closed=True)))[2])
    assert "fails open" in open_t and "traffic passes" in open_t
    assert "fails open" not in closed_t and "held" in closed_t


def test_no_invented_facts():
    """The mockup's 'prompt-guard 3.2 · score 0.97' and 'lab-pc-17' do not exist in the gateway: never print them."""
    t = text_of(parse(bp.render_block_response(info()))[2])
    assert "prompt-guard" not in t and "score" not in t.lower() and "lab-pc" not in t


# ---------------------------------------------------------------- safety

HOSTILE = '"><script>alert(1)</script><img src=x onerror=alert(2)>'


def test_everything_from_the_wire_is_escaped():
    resp = bp.render_block_response(info(host=HOSTILE, reason="Blocked by: " + HOSTILE, client_ip=HOSTILE))
    _, h, html = parse(resp)
    assert "alert(1)" not in re.sub(r"&lt;script&gt;alert\(1\)&lt;/script&gt;", "", html)
    assert "<img src=x" not in html and "onerror=alert" not in html.replace("&quot;", "").replace("onerror=alert(2)&gt;", "")
    assert html.count("<script") == 1                                       # only the page's own script
    assert int(h["content-length"]) == len(html.encode("utf-8"))


def test_overlong_values_are_truncated():
    html = parse(bp.render_block_response(info(host="a" * 5000, reason="Blocked by: " + "x" * 5000)))[2]
    assert len(html) < 20000


def test_page_is_self_contained():
    _, h, html = parse(bp.render_block_response(info()))
    assert not re.search(r"(src|href)=[\"']https?:", html, re.I)
    assert "@import" not in html and not re.search(r"url\(\s*[\"']?https?:", html, re.I)
    assert "default-src 'none'" in h["content-security-policy"]
    assert "connect-src" not in h["content-security-policy"] or "'none'" in h["content-security-policy"]


def test_csp_allows_exactly_the_pages_own_script():
    _, h, html = parse(bp.render_block_response(info()))
    script = re.search(r"<script>(.*?)</script>", html, re.S).group(1)
    digest = base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode()
    assert f"script-src 'sha256-{digest}'" in h["content-security-policy"]


def test_both_logo_variants_and_dark_mode_are_present():
    html = parse(bp.render_block_response(info()))[2]
    assert "prefers-color-scheme: dark" in html
    assert "#A85A45" in html and "#1A1714" in html and "#FAF8F4" in html   # verdict line, ink, paper
    assert 'rel="icon"' in html


# ---------------------------------------------------------------- request ids and the review button

def test_request_ids_look_like_the_mockup_and_do_not_repeat():
    ids = {bp.new_request_id() for _ in range(200)}
    assert len(ids) == 200 and all(re.fullmatch(r"nox-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}", i) for i in ids)


def test_review_button_is_a_link_only_when_a_contact_is_configured(monkeypatch):
    monkeypatch.delenv("BLOCK_REVIEW_URL", raising=False)
    plain = parse(bp.render_block_response(info()))[2]
    assert 'id="review"' in plain and 'href="mailto:' not in plain       # default: copies the request id

    monkeypatch.setenv("BLOCK_REVIEW_URL", "mailto:security@example.org?subject=Block%20nox-7f3a")
    linked = parse(bp.render_block_response(info()))[2]
    assert 'href="mailto:security@example.org?subject=Block%20nox-7f3a"' in linked


@pytest.mark.parametrize("bad", ["javascript:alert(1)", "data:text/html,x", "//evil.example", 'https://x"onmouseover="y'])
def test_only_safe_review_links_are_accepted(monkeypatch, bad):
    monkeypatch.setenv("BLOCK_REVIEW_URL", bad)
    html = parse(bp.render_block_response(info()))[2]
    assert "javascript:" not in html and "evil.example" not in html and "onmouseover" not in html


def test_the_old_no_argument_call_still_works():
    status, _, html = parse(bp.render_block_response(None))
    assert status == "HTTP/1.1 403 Forbidden" and "Blocked by Bifrost NØX" in text_of(html)
