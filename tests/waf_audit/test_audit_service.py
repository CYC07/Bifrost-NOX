"""AUDIT - text_service WAF hooks: _waf_inputs / _form_inputs / model_web_attack and the routing in _analyze_sync.

Input-selection tests use no model. Routing tests use the real router + real WAF (see conftest).
"""
import json

import pytest

from audit_helpers import blocked, verdict, is_block

SQLI = "1' UNION SELECT username, password FROM users--"


# ---------------------------------------------------------------- _waf_inputs
def test_json_leaves_are_scored_value_by_value_not_as_a_blob(svc):
    parts = svc._waf_inputs(json.dumps({"user": "alice", "n": 3, "ok": True, "x": None, "tags": ["a", "b"], "o": {"k": "deep"}}))
    assert parts == ["alice", "3", "a", "b", "deep"]          # bool/None skipped, numbers stringified, order kept


def test_percent_encoded_json_string_is_followed_by_its_decoded_attack_shape(svc):
    parts = svc._waf_inputs(json.dumps({"q": "1%27%20UNION%20SELECT%20password%20FROM%20users--"}))
    assert any("UNION SELECT" in p for p in parts)


def test_plain_encoded_json_text_is_not_decoded_for_the_model(svc):
    parts = svc._waf_inputs(json.dumps({"q": "caf%C3%A9%20au%20lait", "u": "https%3A%2F%2Fexample.com%2Fa"}))
    assert parts == ["caf%C3%A9%20au%20lait", "https%3A%2F%2Fexample.com%2Fa"]


def test_malformed_json_falls_back_to_the_whole_text(svc):
    assert svc._waf_inputs('{"q": "' + SQLI)[0].startswith('{"q"')


def test_leaf_count_cap_cannot_be_used_to_hide_a_payload(svc):
    body = json.dumps({"items": ["benign item %d" % i for i in range(100)] + [SQLI]})
    assert any("UNION SELECT" in p for p in svc._waf_inputs(body)), "payload at leaf 101 was never offered to the model"


def test_payload_in_a_json_key_is_inspected(svc):
    assert any("<script>" in p for p in svc._waf_inputs(json.dumps({"<script>alert(1)</script>": 1})))


def test_deeply_nested_json_is_still_scored(svc):
    depth = 800
    body = '{"a":' * depth + json.dumps(SQLI) + "}" * depth
    try:
        parts = svc._waf_inputs(body)
    except RecursionError:
        pytest.fail("RecursionError: the caller swallows it and the WAF silently skips the body (fail-open evasion)")
    assert any("UNION SELECT" in p for p in parts)


def test_payload_after_long_benign_text_in_one_json_value_is_still_inspected(svc):
    body = json.dumps({"comment": "great product, " * 200 + SQLI})
    assert any("UNION SELECT" in p[-400:] or p.endswith("--") for p in svc._waf_inputs(body)), \
        "only the first 2000 chars of the value reach the model"


# ---------------------------------------------------------------- _form_inputs
def test_form_body_gets_raw_text_first_then_decoded_attack_shaped_values(svc):
    parts = svc._form_inputs("name=Bob&q=1%27%20OR%20%271%27%3D%271&ok=fine")
    assert parts[0].startswith("name=Bob") and "1' OR '1'='1" in parts and "fine" not in parts


def test_form_value_cap_does_not_let_padding_hide_a_payload(svc):
    pad = "&".join(f"n{i}=O%27Brien" for i in range(40))
    parts = svc._form_inputs(pad + "&id=1%27%20UNION%20SELECT%20password%20FROM%20users--")
    assert any("UNION SELECT" in p for p in parts)


def test_bare_encoded_payload_is_judged_decoded(svc):
    assert any("OR '1'='1" in p for p in svc._form_inputs("%27%20OR%20%271%27%3D%271"))


# ---------------------------------------------------------------- model_web_attack
def test_model_web_attack_without_a_model_reports_not_loaded_and_allows(svc, monkeypatch):
    monkeypatch.setattr(svc, "waf_classifier", None)
    r = svc.model_web_attack(SQLI)
    assert not r.blocked and "not loaded" in " ".join(r.findings)


def test_model_web_attack_fails_open_on_any_exception(svc, monkeypatch):
    class Boom:
        def predict(self, _t):
            raise RuntimeError("boom")
    monkeypatch.setattr(svc, "waf_classifier", Boom())
    assert not svc.model_web_attack(SQLI).blocked


def test_model_web_attack_fails_open_on_non_string_input(svc):
    assert not svc.model_web_attack(None).blocked


def test_model_web_attack_stops_at_the_first_blocking_part_and_reports_it(svc):
    r = svc.model_web_attack("", parts=["hello", SQLI, "ignored"])
    assert r.blocked and "sqli" in r.findings[0] and r.risk.value == "critical"


def test_explicit_parts_override_the_text(svc):
    assert not svc.model_web_attack(SQLI, parts=["hello"]).blocked


# ---------------------------------------------------------------- routing
def test_outbound_attack_is_blocked_by_the_web_attack_analyzer(svc):
    v = verdict(svc, "q=" + "1%27%20UNION%20SELECT%20password%20FROM%20users--")
    assert is_block(v) and "web_attack" in v["reason"]


def test_inbound_bodies_are_never_waf_scanned(svc):
    v = verdict(svc, "q=1%27%20UNION%20SELECT%20password%20FROM%20users--", "inbound")
    assert "web_attack" not in v["reason"] and not is_block(v)


def test_sqli_shaped_like_code_still_reaches_the_waf_through_the_gate(svc):
    assert blocked(svc, "1 UNION SELECT username, password FROM users--")


def test_ordinary_source_code_does_not_reach_the_waf(svc):
    code = "def add(a, b):\n    return a + b\n\nfor i in range(10):\n    print(add(i, 1))\n"
    assert not blocked(svc, code)


def test_waf_still_runs_when_an_unrelated_analyzer_allows(svc):
    assert blocked(svc, "comment=Nice+post&q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E")


def test_empty_and_whitespace_bodies_are_allowed(svc):
    assert not blocked(svc, "") and not blocked(svc, "   \n ")


def test_a_transient_inference_error_in_one_part_does_not_hide_a_later_attack_part(svc, monkeypatch):
    """With the REAL classifier: predict() fails open per part, so the next part is still judged."""
    from ml.waf.predictor import WAFClassifier
    c = WAFClassifier(threshold=0.8)
    c._loaded, c._backend = True, "stub"
    calls = []

    def score(text):
        calls.append(text)
        if len(calls) == 1:
            raise RuntimeError("transient")
        return {"clean": 0.01, "sqli": 0.99}
    c._score = score
    monkeypatch.setattr(svc, "waf_classifier", c)
    assert svc.model_web_attack("", parts=["first", "second"]).blocked
