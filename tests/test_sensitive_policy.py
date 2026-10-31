"""Decision policy of the sensitive-content classifier (ml/sensitive/): per-label thresholds, benign
contrast classes, evidence-corroborated tier, identity bundle. NLI scores are faked, so these test the
policy itself, independent of the shipped numbers in labels.py.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ml.sensitive import labels as lb  # noqa: E402
from ml.sensitive.predictor import SensitiveClassifier, decide_from_scores  # noqa: E402

A = lb.SensitiveLabel("alpha record", "This example is alpha record.", "critical", 0.9)
B = lb.SensitiveLabel("beta document", "This example is beta document.", "high", 0.5, low=0.3)
TOS = "This text is terms of service or a privacy policy."
LAW = "This text is a public legal text."


@pytest.fixture
def policy(monkeypatch):
    monkeypatch.delenv("SENSITIVE_LABELS", raising=False)
    monkeypatch.delenv("SENSITIVE_THRESHOLD", raising=False)
    monkeypatch.setattr(lb, "SENSITIVE", {"a": A, "b": B})
    monkeypatch.setattr(lb, "CONTRAST", {})
    monkeypatch.setattr(lb, "MARGIN", 0.0)
    monkeypatch.setattr(lb, "MIN_EVIDENCE", 1)
    monkeypatch.setattr(lb, "IDENTITY_BUNDLE", 0)
    return lb


def S(a=0.0, b=0.0, **contrast):
    return {A.hypothesis: a, B.hypothesis: b, **{k: v for k, v in contrast.items()}}


# --- per-label thresholds ----------------------------------------------------
def test_each_label_uses_its_own_threshold(policy):
    assert not decide_from_scores(S(a=0.7), []).blocked      # alpha needs 0.9
    assert decide_from_scores(S(b=0.7), []).blocked          # beta needs 0.5
    d = decide_from_scores(S(a=0.95), [])
    assert d.blocked and d.label == "alpha record" and d.risk == "critical" and d.reason == "nli"


def test_highest_passing_label_is_reported(policy):
    d = decide_from_scores(S(a=0.92, b=0.99), [])
    assert d.blocked and d.label == "beta document" and d.score == 0.99


def test_global_threshold_env_overrides_every_label(policy, monkeypatch):
    monkeypatch.setenv("SENSITIVE_THRESHOLD", "0.99")
    assert not decide_from_scores(S(a=0.95, b=0.95), []).blocked
    monkeypatch.setenv("SENSITIVE_THRESHOLD", "0.2")
    assert decide_from_scores(S(a=0.25), []).blocked


def test_constructor_threshold_pins_one_cutoff(policy):
    assert not decide_from_scores(S(a=0.95), [], threshold=0.99).blocked
    assert decide_from_scores(S(b=0.4), [], threshold=0.35).blocked
    # the pinned legacy cutoff has no evidence tier
    assert not decide_from_scores(S(b=0.4), ["confidentiality-marker"], threshold=0.45).blocked


# --- benign contrast ---------------------------------------------------------
def test_a_benign_class_that_scores_as_high_suppresses_the_hit(policy, monkeypatch):
    monkeypatch.setattr(lb, "CONTRAST", {"tos": TOS, "law": LAW})
    monkeypatch.setattr(lb, "MARGIN", 0.2)
    assert not decide_from_scores(S(a=0.95, **{TOS: 0.97}), []).blocked           # a terms-of-service page
    assert not decide_from_scores(S(a=0.95, **{TOS: 0.80}), []).blocked           # margin 0.15 < 0.2
    assert decide_from_scores(S(a=0.95, **{TOS: 0.50, LAW: 0.1}), []).blocked     # clearly a record
    d = decide_from_scores(S(a=0.95, **{TOS: 0.50, LAW: 0.1}), [])
    assert d.contrast == 0.50


def test_contrast_applies_to_the_evidence_tier_too(policy, monkeypatch):
    monkeypatch.setattr(lb, "CONTRAST", {"tos": TOS})
    monkeypatch.setattr(lb, "MARGIN", 0.2)
    assert not decide_from_scores(S(b=0.4, **{TOS: 0.9}), ["confidentiality-marker"]).blocked


def test_no_contrast_configured_means_no_margin_rule(policy):
    assert decide_from_scores(S(a=0.95, **{TOS: 0.99}), []).blocked


# --- evidence-corroborated tier ----------------------------------------------
def test_weaker_nli_score_needs_evidence(policy):
    assert not decide_from_scores(S(b=0.4), []).blocked
    d = decide_from_scores(S(b=0.4), ["id-number"])
    assert d.blocked and d.reason == "nli+evidence" and d.label == "beta document"
    assert not decide_from_scores(S(b=0.2), ["id-number"]).blocked    # below the low tier: evidence alone is not enough


def test_min_evidence_is_respected(policy, monkeypatch):
    monkeypatch.setattr(lb, "MIN_EVIDENCE", 2)
    assert not decide_from_scores(S(b=0.4), ["id-number"]).blocked
    assert decide_from_scores(S(b=0.4), ["id-number", "name-amount-list"]).blocked


def test_label_without_a_low_tier_ignores_evidence(policy):
    assert not decide_from_scores(S(a=0.5), ["id-number", "confidentiality-marker"]).blocked


# --- identity bundle ---------------------------------------------------------
def test_identity_bundle_blocks_on_evidence_alone(policy, monkeypatch):
    monkeypatch.setattr(lb, "IDENTITY_BUNDLE", 2)
    d = decide_from_scores({}, ["id-number", "home-address"])
    assert d.blocked and d.reason == "identity-bundle" and d.risk == "high"
    assert not decide_from_scores({}, ["id-number"]).blocked
    assert not decide_from_scores({}, ["confidentiality-marker", "name-amount-list"]).blocked   # not identity signals


# --- classifier plumbing -----------------------------------------------------
def _clf(pipe):
    c = SensitiveClassifier()
    c._loaded, c._pipe = True, pipe
    return c


def test_one_batch_scores_sensitive_and_contrast_hypotheses(policy, monkeypatch):
    monkeypatch.setattr(lb, "CONTRAST", {"tos": TOS})
    seen = {}

    def pipe(text, **kw):
        seen.update(kw)
        return {"labels": kw["candidate_labels"], "scores": [0.01] * len(kw["candidate_labels"])}

    _clf(pipe).predict("some prose")
    assert seen["candidate_labels"] == [A.hypothesis, B.hypothesis, TOS]
    assert seen["batch_size"] == 3 and seen["hypothesis_template"] == "{}" and seen["multi_label"] is True


def test_predict_applies_the_policy_and_reports_evidence(policy, monkeypatch):
    monkeypatch.setattr(lb, "CONTRAST", {"tos": TOS})
    monkeypatch.setattr(lb, "MARGIN", 0.2)
    text = "Bonus pool, strictly confidential: Alice 120000, Bob 98000, Carol 175000"

    def pipe(t, **kw):
        sc = {A.hypothesis: 0.1, B.hypothesis: 0.4, TOS: 0.05}
        return {"labels": list(sc), "scores": list(sc.values())}

    p = _clf(pipe).predict(text)
    assert p.blocked and p.reason == "nli+evidence" and p.label == "beta document" and p.risk == "high"
    assert "confidentiality-marker" in p.evidence and "name-amount-list" in p.evidence
    p2 = _clf(pipe).predict("Our quarterly meeting is on Tuesday")
    assert not p2.blocked and p2.label == "none" and p2.risk == "safe"


def test_identity_bundle_short_circuits_the_model(policy, monkeypatch):
    monkeypatch.setattr(lb, "IDENTITY_BUNDLE", 2)

    def boom(*a, **k):
        raise AssertionError("the NLI must not run for an identity bundle")

    p = _clf(boom).predict("My passport number is X1234567 and my home address is 12 Elm St.")
    assert p.blocked and p.reason == "identity-bundle"


def test_inference_error_fails_open(policy):
    def boom(*a, **k):
        raise RuntimeError("cuda out of memory")

    p = _clf(boom).predict("anything")
    assert not p.blocked and "inference error" in p.note


def test_unloaded_model_fails_open(policy):
    p = SensitiveClassifier().predict("anything")
    assert not p.blocked and p.note == "model not loaded"


def test_label_override_env_wraps_bare_labels(monkeypatch):
    monkeypatch.setenv("SENSITIVE_LABELS", "a secret recipe, a customer list")
    monkeypatch.delenv("SENSITIVE_THRESHOLD", raising=False)
    assert lb.get_labels() == ["This example is a secret recipe.", "This example is a customer list."]
    assert lb.contrast_labels() == []
    assert lb.risk_for("a secret recipe") == "medium"
