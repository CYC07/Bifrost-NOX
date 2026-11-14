"""The WAF must judge DECODED form / query-string values on the web_request route.

The model is trained on decoded payloads (the gateway scores decoded request targets), but a
urlencoded body such as `q=%27+OR+%271%27%3D%271` reached it as `%27+OR+...`, which it does not
recognise. Outbound bodies that look like key=value&... or carry %XX escapes are now also scored
as decoded values (active values only, like request targets); the raw text is still scored first.
Inbound stays unscanned and JSON keeps its per-value scoring.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ml.router.predictor import RouteDecision  # noqa: E402
from text_service import main as svc  # noqa: E402


class _Pred:
    def __init__(self, blocked):
        self.blocked, self.label, self.score, self.risk = blocked, "xss", 0.99, "high"


class FakeWAF:
    """Blocks only decoded payloads (it cannot read %XX), records every input."""
    def __init__(self):
        self.seen = []

    def predict(self, text):
        self.seen.append(text)
        return _Pred(any(k in text.lower() for k in ("' or '", "<script", "union select", "../../", "boot.ini")))


class FixedRouter:
    def route(self, text):
        return RouteDecision("web_request", 0.9)


@pytest.fixture
def waf(monkeypatch):
    f = FakeWAF()
    monkeypatch.setattr(svc, "waf_classifier", f)
    monkeypatch.setattr(svc, "router_classifier", FixedRouter())
    return f


def _blocked(out):
    return str(out["status"]).lower().endswith("block")


ENCODED_ATTACKS = {
    "single field": "q=%27+OR+%271%27%3D%271",
    "multi field": "a=1&comment=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&sort=asc",
    "query string": "/search?utm_source=news&q=1+UNION+SELECT+user%2Cpass+FROM+u--",
    "bare encoded": "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "double encoded": "file=%252e%252e%252f%252e%252e%252fetc%252fpasswd%252f..%252f..%252f",
    "raw form value": "name=x&q=<script>alert(1)</script>",
}


@pytest.mark.parametrize("name", sorted(ENCODED_ATTACKS))
def test_encoded_attack_is_blocked_on_web_request_route(waf, name):
    assert _blocked(svc._analyze_sync(ENCODED_ATTACKS[name], False, "outbound"))


def test_raw_text_is_still_scored_first(waf):
    body = "q=%27+OR+%271%27%3D%271"
    svc.model_web_attack(body)
    assert waf.seen[0] == body
    assert "' OR '1'='1" in waf.seen


def test_inbound_is_never_waf_scanned(waf):
    out = svc._analyze_sync(ENCODED_ATTACKS["single field"], False, "inbound")
    assert waf.seen == [] and not _blocked(out)


def test_plain_plus_signs_are_not_decoded_outside_forms(waf):
    svc.model_web_attack("C++ and a+b are fun")
    assert waf.seen == ["C++ and a+b are fun"]


def test_benign_urlencoded_form_is_not_blocked_and_inactive_values_are_not_scored(waf):
    body = "name=Dana+O%27Neil&note=hello+world&lang=en&redirect=https%3A%2F%2Fexample.com%2Fa%3Fb%3D1"
    out = svc._analyze_sync(body, False, "outbound")
    assert not _blocked(out)
    # plain words / plain URL values are skipped, the apostrophe name is the only decoded value
    assert sorted(set(waf.seen) - {body}) == ["Dana O'Neil"]


def test_json_is_still_scored_per_value_and_not_decoded(waf):
    svc.model_web_attack(json.dumps({"q": "100%25 sure", "n": "a+b"}))
    assert sorted(waf.seen) == ["100%25 sure", "a+b"]


def test_part_count_is_capped(waf):
    body = "&".join(f"k{i}=%27x{i}" for i in range(500))
    assert len(svc._waf_inputs(body)) == svc.WAF_MAX_FORM_VALUES + 1


def test_cache_key_is_the_raw_body_and_variants_cannot_collide(waf):
    svc._cache_clear()
    enc = "q=%27+OR+%271%27%3D%271"
    dec = "q=hello world"
    assert _blocked(svc._analyze_cached(enc, False, "outbound"))
    assert not _blocked(svc._analyze_cached(dec, False, "outbound"))
    assert _blocked(svc._analyze_cached(enc, False, "outbound"))  # cached verdict intact
    assert not _blocked(svc._analyze_cached(enc, False, "inbound"))  # direction still keys the cache
    svc._cache_clear()


def test_decoded_text_without_attack_shape_is_not_scored(waf):
    body = "sort=asc&file=%2Fvar%2Flog%2Fapp.log"
    assert svc._waf_inputs(body) == [body]


def test_overlong_utf8_traversal_is_scored_decoded(waf):
    body = "ref=home&template=%c0%ae%c0%ae%c0%afboot.ini"
    assert len(svc._waf_inputs(body)) > 1
    assert _blocked(svc._analyze_sync(body, False, "outbound"))
