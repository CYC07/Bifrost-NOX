"""The WAF must also judge DECODED JSON string values on the web_request route.

Form and query values are percent-decoded before scoring (tests/test_waf_form_decode.py), but a
JSON body whose string value is itself percent-encoded (`{"q": "1%27%20UNION%20SELECT..."}`)
reached the model only as `1%27%20UNION...`, which it does not recognise. Each raw value is still
scored as before; a value with %XX escapes also contributes its decoded form, but only when that
is attack-shaped (ml/waf/target.py worth_scoring), so ordinary encoded URLs, emails and spaces
never newly reach the model. Inbound stays unscanned.
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
        return _Pred(any(k in text.lower() for k in ("union select", "<script", "../../", "; cat ", "{{7*7}}")))


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


ENCODED_JSON_ATTACKS = {
    "sqli": {"q": "1%27%20UNION%20SELECT%20password%20FROM%20users--"},
    "xss": {"comment": "%3Cscript%3Ealert(1)%3C%2Fscript%3E"},
    "double encoded traversal": {"file": "%252e%252e%252f%252e%252e%252fetc%252fpasswd"},
    "nested": {"user": {"prefs": [{"bio": "%3Cscript%3Ealert(1)%3C/script%3E"}]}},
    "top-level array": ["ok", "127.0.0.1%3B%20cat%20%2Fetc%2Fpasswd"],
}


@pytest.mark.parametrize("name", sorted(ENCODED_JSON_ATTACKS))
def test_encoded_json_value_is_blocked_on_web_request_route(waf, name):
    assert _blocked(svc._analyze_sync(json.dumps(ENCODED_JSON_ATTACKS[name]), False, "outbound"))


def test_raw_value_is_still_scored_before_its_decoded_form(waf):
    raw = "1%27%20UNION%20SELECT%20password%20FROM%20users--"
    assert svc._waf_inputs(json.dumps({"q": raw})) == [raw, "1' UNION SELECT password FROM users--"]


def test_inbound_json_is_never_waf_scanned(waf):
    out = svc._analyze_sync(json.dumps(ENCODED_JSON_ATTACKS["xss"]), False, "inbound")
    assert waf.seen == [] and not _blocked(out)


BENIGN = {
    "redirect": "https%3A%2F%2Fexample.com%2Fa%3Fb%3Dc",
    "email": "a%40b.com",
    "greeting": "hello%20world",
    "token": "abc123XYZ",
    "path": "%2Fvar%2Flog%2Fapp.log",
    "percent": "100%25 sure",
    "plus": "a+b",
}


def test_benign_encoded_json_values_add_no_decoded_inputs(waf):
    body = json.dumps(BENIGN)
    assert svc._waf_inputs(body) == list(BENIGN.values())
    assert not _blocked(svc._analyze_sync(body, False, "outbound"))


def test_plus_is_kept_in_decoded_json_values(waf):
    # JSON is not form-encoded: '+' is a literal plus, only %XX escapes are decoded
    assert svc._waf_inputs(json.dumps({"q": "%3Cb%3Ea+b"})) == ["%3Cb%3Ea+b", "<b>a+b"]


def test_decoded_json_values_are_capped(waf):
    body = json.dumps({f"k{i}": f"%27x{i}" for i in range(100)})
    parts = svc._waf_inputs(body)
    raw = [p for p in parts if p.startswith("%")]
    assert len(raw) == svc.WAF_MAX_VALUES
    assert len(parts) - len(raw) == svc.WAF_MAX_FORM_VALUES
