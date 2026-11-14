"""Tests for the sensitive-content evaluation tooling (dataset_tools/sensitive/): the set builder's
text cutter / sampler / generators and the offline sweep's decision rule, which must agree with the
production policy (ml/sensitive/predictor.decide_from_scores)."""
import os
import random
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "sensitive"))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "..")))
import build_eval as B  # noqa: E402
import sweep_lib as L  # noqa: E402
from hypotheses import POOL, STAGE1, STAGE2  # noqa: E402
from ml.sensitive import labels as lb  # noqa: E402
from ml.sensitive.evidence import find_evidence  # noqa: E402
from ml.sensitive.predictor import decide_from_scores  # noqa: E402


# --- builder ------------------------------------------------------------------
def test_cut_respects_bounds_and_boundaries():
    para = ("Sentence number one is here. " * 30).strip()
    c = B.cut(para)
    assert c and B.LO <= len(c) <= B.HI and c.endswith(".")
    assert B.cut("too short") is None
    assert B.cut("x" * 5000) is not None and len(B.cut("x" * 5000)) <= B.HI


def test_builder_is_deterministic_dedupes_and_splits_stably():
    texts = [f"Document {i}: " + "lorem ipsum dolor sit amet " * 12 for i in range(40)] * 2
    a, b = B.Builder(7), B.Builder(7)
    a.add("s", "neg", texts, 10)
    b.add("s", "neg", texts, 10)
    assert [r["id"] for r in a.records] == [r["id"] for r in b.records]
    assert len({r["text"] for r in a.records}) == len(a.records) == 10
    assert {r["split"] for r in a.records} <= {"dev", "test"}
    c = B.Builder(8)
    c.add("s", "neg", texts, 10)
    assert [r["id"] for r in c.records] != [r["id"] for r in a.records]


def test_holdout_builder_never_redraws_excluded_texts():
    texts = [f"Doc {i} " + "alpha beta gamma delta " * 15 for i in range(30)]
    first = B.Builder(7)
    first.add("s", "neg", texts, 10)
    second = B.Builder(9, exclude={r["text"] for r in first.records})
    second.add("s", "neg", texts, 10)
    assert not ({r["text"] for r in first.records} & {r["text"] for r in second.records})


def test_scale_multiplies_set_sizes():
    texts = [f"Doc {i} " + "alpha beta gamma delta " * 15 for i in range(60)]
    b = B.Builder(7, scale=2.0)
    b.add("s", "neg", texts, 10)
    assert len(b.records) == 20


def test_unmarked_synthetic_hr_text_has_no_explicit_marking():
    assert not any(B.MARKER.search(t) for t in B.gen_hr_fin(7, 40, marked=False))
    assert all(B.MARKER.search(t) for t in B.gen_hr_fin(7, 40, marked=True))


def test_synthetic_identity_sentences_are_not_trivially_the_user_example():
    ts = B.gen_pii_ids(7, 100)
    assert len(set(ts)) > 90
    assert sum("My passport number is" in t for t in ts) < 40      # several different phrasings
    assert all(find_evidence(t) for t in ts)


# --- offline rule == production policy ------------------------------------------
def test_pool_contains_exactly_the_production_hypotheses():
    for h in lb.get_labels():
        assert h in POOL.values(), f"shipped hypothesis not in the measured pool: {h}"
    assert not set(STAGE1) & set(STAGE2)


def test_sweep_decision_agrees_with_production_policy_on_random_scores():
    rule = L.shipped_rule()
    rev = {v: k for k, v in POOL.items()}
    hyps = list(lb.sensitive_labels()) + lb.contrast_labels()
    rng = random.Random(3)
    evs = [[], ["confidentiality-marker"], ["id-number"], ["id-number", "home-address"], ["name-amount-list", "confidentiality-marker"],
           ["patient-narrative"], ["date-of-birth", "id-number"]]
    for _ in range(3000):
        scores = {h: rng.choice([0.0, 0.03, 0.1, 0.2, 0.35, 0.5, 0.6, 0.75, 0.9, 0.99, rng.random()]) for h in hyps}
        ev = rng.choice(evs)
        prod = decide_from_scores(scores, ev).blocked
        sweep = L.decide(rule, {rev[h]: v for h, v in scores.items()}, ev)[0]
        assert prod == sweep, (scores, ev)


def test_vectorised_sweep_rule_equals_the_reference_implementation():
    import numpy as np
    rng = random.Random(5)
    keys = [f"k{i}" for i in range(4)] + ["b1", "b2"]
    evs = [[], ["confidentiality-marker"], ["id-number", "home-address"], ["id-number"], ["name-amount-list", "patient-narrative"]]
    scores = [{k: rng.choice([0.0, 0.1, 0.3, 0.5, 0.7, 0.95, rng.random()]) for k in keys} for _ in range(400)]
    ev = [rng.choice(evs) for _ in range(400)]
    q = np.array([rng.random() < .4 for _ in range(400)])
    A = L.Arrays({k: np.array([s[k] for s in scores]) for k in keys}, np.array([len(e) for e in ev]),
                 np.array([sum(1 for x in e if x in L.IDENT) for e in ev]), 400,
                 *(np.array(["x"] * 400) for _ in range(4)), np.zeros(400), q)
    for trial in range(60):
        rule = {"keys": keys[:4], "thr": {k: rng.choice([0.3, 0.5, 0.7, 0.9]) for k in keys[:4]}}
        if rng.random() < .6:
            rule["low"] = {k: rng.choice([0.05, 0.2, 0.4]) for k in keys[:4] if rng.random() < .7}
            rule["min_ev"] = rng.choice([1, 2])
        if rng.random() < .6:
            rule["contrast"] = rng.sample(["b1", "b2"], rng.choice([1, 2]))
            rule["margin"] = rng.choice([0.0, 0.1, 0.3])
        if rng.random() < .4:
            rule["identity_bundle"] = rng.choice([1, 2])
        # `low` must stay below `thr` for the two tiers to be distinguishable; the equivalence holds regardless
        if rng.random() < .5:
            rule["question"] = True
        want = np.array([L.decide(rule, scores[i], ev[i], bool(q[i]))[0] for i in range(400)])
        assert (L.vblock(rule, A) == want).all(), rule


def test_end_to_end_gate_inbound_is_advisory_and_evidence_gate_is_outbound_only():
    import numpy as np
    recs = [{"set": "s", "split": "dev", "label": "neg", "text": "x"}] * 3
    feats = [{"route_raw": "prose"}, {"route_raw": "web_request"}, {"route_raw": "web_request"}]
    d = L.Data(recs, [{"k": 0.9}] * 3, feats, [[], ["confidentiality-marker"], []])
    A = L.arrays(d)
    rule = {"keys": ["k"], "thr": {"k": 0.5}}
    blk, cen, only = L.e2e(d, A, rule, "outbound", evidence_gate=True)
    assert blk.tolist() == [True, True, False]                # prose, and non-prose WITH evidence; plain web_request skips
    blk, cen, only = L.e2e(d, A, rule, "outbound", evidence_gate=False)
    assert blk.tolist() == [True, False, False]               # the base gate
    blk, cen, only = L.e2e(d, A, rule, "inbound", evidence_gate=True)
    assert blk.tolist() == [False, False, False] and cen.tolist() == [True, False, False]   # advisory, prose only
    blk, cen, only = L.e2e(d, A, rule, "inbound", evidence_gate=True, inbound_mode="block")
    assert blk.tolist() == [True, False, False]


def test_wilson_interval_brackets_the_rate():
    lo, hi = L.wilson(5, 100)
    assert lo < 0.05 < hi and 0 <= lo and hi <= 1
    assert L.wilson(0, 0) == (0.0, 0.0)
