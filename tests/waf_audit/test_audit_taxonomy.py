"""AUDIT - ml/waf/taxonomy.py: the label space is a contract with trained models and the service."""
import json
import os

import pytest

from common.schemas import RiskLevel
from ml.waf import taxonomy as t

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def test_label_order_is_the_frozen_training_contract():
    assert t.LABELS == ["clean", "sqli", "xss", "path_traversal", "command_injection", "ssti", "scanner"]


def test_label_maps_are_inverse_bijections():
    assert len(set(t.LABELS)) == len(t.LABELS)
    assert {t.ID_TO_LABEL[t.LABEL_TO_ID[l]] for l in t.LABELS} == set(t.LABELS)
    assert sorted(t.LABEL_TO_ID.values()) == list(range(len(t.LABELS)))


def test_every_label_has_a_description_and_a_risk():
    assert set(t.DESCRIPTIONS) == set(t.LABELS) == set(t.RISK)
    assert all(t.DESCRIPTIONS[l].strip() for l in t.LABELS)


def test_every_risk_value_is_a_valid_service_risk_level():
    """text_service does RiskLevel(pred.risk): an unknown string would raise and the WAF would fail open."""
    for label, risk in t.RISK.items():
        assert RiskLevel(risk), label


def test_clean_is_the_only_safe_class():
    assert t.RISK["clean"] == "safe"
    assert all(t.RISK[l] != "safe" for l in t.ATTACK_LABELS)


def test_is_attack_semantics_including_unknown_labels():
    assert not t.is_attack("clean")
    assert all(t.is_attack(l) for l in t.LABELS if l != "clean")
    assert not t.is_attack("not-a-label")          # must not raise
    assert not t.is_attack("")
    assert not t.is_attack("SQLI")                 # labels are case-sensitive


def test_validate_label_accepts_known_and_rejects_unknown():
    for l in t.LABELS:
        assert t.validate_label(l) == l
    for bad in ("", "SQLI", "sql injection", None):
        with pytest.raises((ValueError, TypeError)):
            t.validate_label(bad)


def test_shipped_model_id2label_matches_the_taxonomy_order():
    """A reordered/renamed head would silently relabel every verdict (sqli reported as xss, ...)."""
    cfg = os.path.join(ROOT, "ml", "waf", "artifacts", "waf_distilbert", "config.json")
    if not os.path.exists(cfg):
        pytest.skip("model artifacts not present")
    id2label = json.load(open(cfg))["id2label"]
    assert [id2label[str(i)] for i in range(len(id2label))] == t.LABELS
