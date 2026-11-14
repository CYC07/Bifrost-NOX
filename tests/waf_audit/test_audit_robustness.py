"""AUDIT - robustness of the whole WAF path: evasion by padding / nesting / encoding, pathological input
(catastrophic regex backtracking), size, concurrency, hostile types. Real router + real WAF."""
import json
import threading
import time
from urllib.parse import quote

import pytest

from ml.waf import target as t
from audit_helpers import blocked, is_block, verdict

SQLI = "1' UNION SELECT username, password FROM users--"
XSS = "<script>alert(document.cookie)</script>"


# ---------------------------------------------------------------- evasion by padding / position / nesting
def _pad(n=3000):
    return "This is a perfectly ordinary comment about the product and the delivery service. " * (n // 80 + 1)


@pytest.mark.parametrize("name,body", [
    ("form, payload after 3 KB of text", lambda p: "comment=" + quote(_pad() + p, safe="")),
    ("form, payload before 3 KB of text", lambda p: "comment=" + quote(p + " " + _pad(), safe="")),
    ("json, payload after 3 KB of text", lambda p: json.dumps({"comment": _pad() + p})),
    ("bare, payload after 3 KB of text", lambda p: _pad() + p),
    ("bare, payload in the middle of 6 KB", lambda p: _pad(3000) + p + " " + _pad(3000)),
    ("form, payload as the 30th of 60 fields", lambda p: "&".join([f"f{i}=value{i}" for i in range(29)] + ["x=" + quote(p, safe="")] + [f"g{i}=value{i}" for i in range(30)])),
    ("json, payload as the 200th of 400 values", lambda p: json.dumps({"v": [f"item {i}" for i in range(199)] + [p] + [f"item {i}" for i in range(200)]})),
    ("json, payload after 2.2 KB of hex padding", lambda p: json.dumps({"token": "0123456789abcdef" * 140 + p})),
    ("form, payload after 2.2 KB of hex padding", lambda p: "t=" + "0123456789abcdef" * 140 + quote(p, safe="")),
    ("json, payload as value 71 of 71", lambda p: json.dumps({"v": [f"item {i}" for i in range(70)] + [p]})),
    ("json, payload in a nested object", lambda p: json.dumps({"a": {"b": {"c": [{"d": p}]}}})),
    ("json, payload under a 40-deep nest", lambda p: '{"a":' * 40 + json.dumps(p) + "}" * 40),
])
@pytest.mark.parametrize("payload", [SQLI, XSS], ids=["sqli", "xss"])
def test_payload_cannot_be_hidden_by_position_or_padding(svc, name, body, payload):
    assert blocked(svc, body(payload)), f"{name} evaded the WAF"


@pytest.mark.parametrize("name,body", [
    ("double-encoded form value", "q=%2527%2520OR%25201%253D1--"),
    ("encoded plus-spaces", "q=1%27+UNION+SELECT+username%2Cpassword+FROM+users--"),
    ("mixed-case with comment spaces", "q=1%27%20uNiOn/**/sElEcT/**/username%20FROM%20users--"),
    ("tab/newline whitespace", "q=1%27%09UNION%0aSELECT%0dusername%20FROM%20users--"),
    ("json unicode escapes", '{"q": "\\u0027 OR \\u00271\\u0027=\\u00271"}'),
    ("json escaped slashes", '{"p": "..\\/..\\/..\\/etc\\/passwd"}'),
    ("xss with null byte", "q=%3Cscr%00ipt%3Ealert(1)%3C/script%3E"),
    ("xss, uppercase tag", "q=%3CSCRIPT%3EALERT(1)%3C/SCRIPT%3E"),
    ("xss, event handler no quotes", "q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E"),
    ("cmdi, ${IFS}", "host=127.0.0.1%3Bcat${IFS}/etc/passwd"),
    ("cmdi, newline separator", "host=127.0.0.1%0acat%20/etc/passwd"),
    ("traversal, double-encoded slashes", "file=..%252f..%252f..%252fetc%252fpasswd"),
    ("traversal, backslashes", "file=..%5c..%5c..%5cwindows%5cwin.ini"),
])
def test_common_encoding_evasions_are_still_blocked(svc, name, body):
    assert blocked(svc, body), f"evasion not blocked: {name}"


# ---------------------------------------------------------------- pathological input must stay fast
PATHOLOGICAL = {
    "select x20000": "select " * 20_000, "select..from spaced": "select " + "a " * 40_000,
    "open quotes": "'" * 100_000, "quote-or pairs": "' or" * 30_000, "braces": "{{" * 30_000,
    "angle brackets": "<" * 50_000, "script attrs": "<script" + " a=1" * 20_000, "subshell": "$(" * 30_000,
    "dots": ".." * 50_000, "slashes": "../" * 50_000, "percent runs": "%2e" * 60_000, "union runs": "union " * 20_000,
    "keys": "&".join(f"k{i}=v" for i in range(30_000)), "long key": "k" * 100_000 + "=v",
}


@pytest.mark.parametrize("fn_name", ["waf_values", "signature_hits", "body_values", "worth_scoring"])
@pytest.mark.parametrize("name", sorted(PATHOLOGICAL))
def test_each_target_filter_stays_fast_at_the_production_input_caps(name, fn_name):
    """The service feeds these at most 16 KB (targets/forms) or 2 KB (values); budget 1 s per call."""
    s = PATHOLOGICAL[name][:16384]
    arg = {"waf_values": "/p?q=" + s, "signature_hits": "/p?q=" + s, "body_values": s, "worth_scoring": s}[fn_name]
    t0 = time.perf_counter()
    getattr(t, fn_name)(arg)
    assert time.perf_counter() - t0 < 1.0


@pytest.mark.parametrize("name", sorted(PATHOLOGICAL))
def test_worth_scoring_is_linear_even_without_the_callers_size_caps(name):
    """worth_scoring is a public function; it should not rely on every caller truncating first."""
    t0 = time.perf_counter()
    t.worth_scoring(PATHOLOGICAL[name])
    assert time.perf_counter() - t0 < 3.0


@pytest.mark.parametrize("name", sorted(PATHOLOGICAL))
def test_full_pipeline_answers_hostile_input_within_a_bounded_time(svc, name):
    s = PATHOLOGICAL[name]
    t0 = time.perf_counter()
    verdict(svc, s)
    assert time.perf_counter() - t0 < 20.0


def test_large_ordinary_body_is_fast_enough_not_to_stall_the_proxy(svc):
    body = "name=Bob&comment=" + quote("great product, fast delivery. " * 20_000, safe="")
    t0 = time.perf_counter()
    assert not blocked(svc, body)
    assert time.perf_counter() - t0 < 10.0


# ---------------------------------------------------------------- hostile types, concurrency
@pytest.mark.parametrize("bad", [None, 123, b"q=1' OR 1=1--", ["q"], {"q": 1}])
def test_pipeline_does_not_raise_on_non_string_input(svc, bad):
    try:
        verdict(svc, bad)
    except Exception as exc:  # noqa: BLE001
        pytest.fail(f"{type(bad).__name__} input raised {type(exc).__name__}: {exc}")


def test_pipeline_is_consistent_under_concurrency(svc):
    bodies = ["q=" + quote(SQLI, safe=""), "q=hello+world", "q=" + quote(XSS, safe=""), '{"a":"fine"}'] * 4
    want = [is_block(verdict(svc, b)) for b in bodies]
    got = [None] * len(bodies)

    def run(i):
        got[i] = is_block(verdict(svc, bodies[i]))
    ths = [threading.Thread(target=run, args=(i,)) for i in range(len(bodies))]
    [x.start() for x in ths]
    [x.join() for x in ths]
    assert got == want


def test_the_waf_cannot_be_bypassed_by_a_failing_router(svc, monkeypatch):
    """Router failure must fall back to web_request (the safe default), not to a route that skips the WAF."""
    monkeypatch.setattr(svc, "router_classifier", None)
    assert blocked(svc, "q=" + quote(SQLI, safe=""))
