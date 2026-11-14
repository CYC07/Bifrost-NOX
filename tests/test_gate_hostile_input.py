"""The marker gate and its strong-marker test run on attacker-controlled text, now on every route, so a hostile shape
must not make them superlinear. Regression: 8,000 characters of '{{' cost 1.3 s, and '{{ x ', '${', '<a ' were slow too,
because each start offset retried a bounded-but-large pattern. Budgets are generous (a loaded CI box) yet far below the old cost.
"""
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ml.waf.gate import has_strong_marker, waf_gate_parts  # noqa: E402

SHAPES = ["{{", "{{ x ", "{{a*", "${", "${ x ", "#{", "<%", "{%", "<a ", "<img ", "<svg ", "<script ", "$(", "`", "' or ", "union ", "../", "%2e", ";cat "]


@pytest.mark.parametrize("unit", SHAPES, ids=lambda u: repr(u))
def test_strong_marker_is_not_superlinear_on_repeated_shapes(unit):
    s = (unit * (8000 // len(unit) + 1))[:8000]
    t0 = time.perf_counter()
    has_strong_marker(s)
    assert time.perf_counter() - t0 < 0.3


@pytest.mark.parametrize("unit", ["{{", "{{ x ", "${", "<a ", "<img "], ids=lambda u: repr(u))
def test_gate_on_a_large_hostile_body_stays_bounded(unit):
    body = (unit * (150_000 // len(unit) + 1))[:150_000]
    t0 = time.perf_counter()
    waf_gate_parts(body)
    assert time.perf_counter() - t0 < 3.0


@pytest.mark.parametrize("payload", [
    "{{config.__class__.__init__.__globals__}}", "{{7*7}}", "${7*7}", "${T(java.lang.Runtime).getRuntime().exec('id')}",
    "<img src=x onerror=alert(1)>", "<script src=//evil.example/x.js></script>", "<script>alert(document.cookie)</script>",
    "<svg onload=alert(1)>", "<body onload=alert(document.domain)>",
])
def test_the_bounded_patterns_still_match_the_real_payloads(payload):
    assert has_strong_marker(payload)
    assert waf_gate_parts("noise " * 50 + payload + " tail " * 50)


def test_a_payload_after_a_long_run_of_hostile_filler_is_still_found():
    assert has_strong_marker("{{" * 2000 + " {{7*7}}")
    assert has_strong_marker("<a " * 1500 + '<img src=x onerror=alert(1)>')
