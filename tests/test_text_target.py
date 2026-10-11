"""Text service: analysing a request target (kind="url") — secrets, signatures, WAF on active values only."""
import asyncio
import importlib.util
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.schemas import AnalysisResult, RiskLevel  # noqa: E402
from text_service import main as svc  # noqa: E402

_spec = importlib.util.spec_from_file_location("rt", os.path.join(os.path.dirname(__file__), "test_request_target.py"))
_rt = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_rt)
BENIGN, ATTACKS = _rt.BENIGN, _rt.ATTACKS

AWS = "AKIA" + "IOSFODNN7REALKEYX"      # concatenated: keeps push-protection scanners quiet


class _Pred:
    def __init__(self, blocked):
        self.blocked, self.label, self.score, self.risk = blocked, "sqli", 0.99, "high"


class FakeWAF:
    def __init__(self):
        self.seen = []

    def predict(self, text):
        self.seen.append(text)
        return _Pred("' OR '" in text)


class _Req:
    def __init__(self, text, md):
        self._t, self._md = text, md

    async def json(self):
        return {"text": self._t, "metadata": self._md}


def URL(text, direction="outbound", **extra):
    return json.loads(asyncio.run(svc.analyze_text(_Req(text, {"kind": "url", "direction": direction,
                                                               "host": "app.example", **extra}))).body)


@pytest.fixture
def waf(monkeypatch):
    f = FakeWAF()
    monkeypatch.setattr(svc, "waf_classifier", f)
    svc._cache_clear()
    svc._reset_semaphore()
    return f


def test_sqli_in_query_is_blocked_and_the_model_sees_only_the_active_decoded_value(waf):
    out = URL("/item?id=1%27%20OR%20%271%27%3D%271%27%20--&page=2&sort=name")
    assert out["status"] == "block" and "web_attack" in out["reason"]
    assert waf.seen == ["1' OR '1'='1' --"]          # page=2 / sort=name never reach the model


def test_benign_target_is_allowed_and_the_model_is_not_called(waf):
    out = URL("/search?q=best+pizza&page=2&fields=id,name,email")
    assert out["status"] == "allow" and waf.seen == []


def test_secret_in_a_query_string_is_blocked(waf):
    out = URL(f"/export?api_key={AWS}&format=csv")
    assert out["status"] == "block" and "code" in out["reason"]
    assert waf.seen == []                              # cheap analyzers decide first


JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." "eyJzdWIiOiIxMjM0NTY3ODkwIn0." "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")


@pytest.mark.parametrize("secret", [
    "ghp_" + "A1b2C3d4E5" * 3 + "F6g7H8",             # GitHub PAT
    "sk_live_" + "a1B2c3D4e5F6g7H8i9J0k1L2",          # Stripe live key
    "xoxb-" + "1234567890-1234567890123-" + "AbCdEfGhIjKlMnOpQrStUvWx",  # Slack bot token
])
def test_vendor_secrets_that_never_belong_in_a_url_still_block(waf, secret):
    assert URL(f"/cb?x={secret}")["status"] == "block"


@pytest.mark.parametrize("t", [
    f"/auth?token={JWT}",                                        # SSO callbacks, magic links
    "/maps?key=AIza" + "SyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q",     # client-side Google API key
    "/login?password=correct-horse-battery",                     # legacy GET login (bad, but real)
])
def test_credentials_that_legitimately_appear_in_urls_are_advisory_not_blocked(waf, t):
    out = URL(t)
    assert out["status"] in ("censor", "allow"), out
    if out["status"] == "censor":
        assert "advisory" in out["reason"].lower()


@pytest.mark.parametrize("t", ["/../../../../etc/passwd", "/d?file=..%2F..%2Fsecret", "/d?f=/etc/shadow"])
def test_traversal_signatures_block_without_the_model(waf, t):
    out = URL(t)
    assert out["status"] == "block" and "request_target" in out["reason"]
    assert waf.seen == []


def test_inbound_targets_are_never_analyzed(waf):
    assert URL("/item?id=1%27%20OR%20%271%27", direction="inbound")["status"] == "allow"
    assert waf.seen == []


def test_target_analysis_skips_router_prompt_injection_and_sensitive(waf, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("must not run for a request target")
    for name in ("_route", "model_prompt_injection", "model_sensitive", "model_pi_signatures", "model_patterns"):
        monkeypatch.setattr(svc, name, boom)
    assert URL("/q?x=%27%20OR%20%271")["status"] == "block"
    assert URL("/q?x=plain")["status"] == "allow"


def test_a_target_and_a_body_with_the_same_text_are_not_confused_by_the_cache(waf):
    text = "/q?x=%27%20OR%20%271"
    a = URL(text)
    b = json.loads(asyncio.run(svc.analyze_text(_Req(text, {"direction": "outbound"}))).body)
    assert a["status"] == "block"
    assert "request_target" not in b["reason"]


def test_malformed_targets_do_not_crash(waf):
    for t in ("", "?", "/%zz?x=%", "/q?" + "a=%27&" * 3000, "http://[::1"):
        assert URL(t)["status"] in ("allow", "block")


# --- real models: the same 28 benign / 12 attack targets measured in the probe -------------
def _waf_available() -> bool:
    from ml.waf.predictor import WAFClassifier
    return WAFClassifier().load()


needs_waf = pytest.mark.skipif(not _waf_available(), reason="WAF model unavailable")


@pytest.fixture(scope="module")
def real_waf_module():
    from ml.waf.predictor import WAFClassifier
    c = WAFClassifier(threshold=svc.WAF_ATTACK_THRESHOLD)
    c.load()
    return c


@needs_waf
def test_real_model_zero_false_positives_on_ordinary_targets(real_waf_module, monkeypatch):
    monkeypatch.setattr(svc, "waf_classifier", real_waf_module)
    svc._cache_clear()
    blocked = [t for t in BENIGN if URL(t)["status"] == "block"]
    assert blocked == []


@needs_waf
def test_real_model_catches_every_attack_target(real_waf_module, monkeypatch):
    monkeypatch.setattr(svc, "waf_classifier", real_waf_module)
    svc._cache_clear()
    missed = [t for t in ATTACKS if URL(t)["status"] != "block"]
    assert missed == []
