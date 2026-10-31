"""WAF predictor: Arm B (one sigmoid head per attack family, default-allow) next to the 7-class softmax.

`WAF_MODEL_PATH` may point at a directory holding `waf_v2.json` (written by the v2 Colab notebook):
arm == "B_sigmoid6" loads DistilBERT with `len(attack_labels)` sigmoid heads, blocks when the largest
head probability is STRICTLY above `recommended_threshold` (or `WAF_THRESHOLD` if set), and reports
`clean` = 1 - max head. Arm A / a directory without the file / a joblib keep the softmax behaviour.

Everything here uses a tiny randomly-initialised DistilBERT with a character vocabulary written to
tmp_path: no network, no real weights.
"""
import json
import math
import os
import sys

import pytest

os.environ.setdefault("HF_HUB_OFFLINE", "1")
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
torch = pytest.importorskip("torch")
transformers = pytest.importorskip("transformers")
from ml.waf import predictor  # noqa: E402
from ml.waf.predictor import WAFClassifier, WAFPrediction  # noqa: E402
from ml.waf.taxonomy import LABELS, RISK  # noqa: E402

ATTACKS = LABELS[1:]
VOCAB = ["[PAD]", "[UNK]", "[CLS]", "[SEP]", "[MASK]"] + list("abcdefghijklmnopqrstuvwxyz0123456789 '=<>/-;.")


def _logit(p):
    return math.log(p / (1 - p))


def make_model(tmp_path, name, n_labels, id2label, probs=None, config=None, max_positions=64):
    """Save a tiny DistilBERT classifier + tokenizer (+ waf_v2.json). With `probs` the classifier is
    forced to output sigmoid(bias)=probs (arm B) or softmax(log probs) (arm A) for every input."""
    from transformers import DistilBertConfig, DistilBertForSequenceClassification, DistilBertTokenizerFast
    d = tmp_path / name
    d.mkdir()
    (d / "vocab.txt").write_text("\n".join(VOCAB))
    tok = DistilBertTokenizerFast(vocab_file=str(d / "vocab.txt"), do_lower_case=True)
    (d / "vocab.txt").unlink()
    cfg = DistilBertConfig(vocab_size=len(VOCAB), dim=16, hidden_dim=32, n_layers=1, n_heads=2,
                           max_position_embeddings=max_positions, num_labels=n_labels,
                           id2label=dict(enumerate(id2label)), label2id={l: i for i, l in enumerate(id2label)})
    torch.manual_seed(0)
    model = DistilBertForSequenceClassification(cfg)
    if probs is not None:
        with torch.no_grad():
            model.classifier.weight.zero_()
            model.classifier.bias.copy_(torch.tensor(probs, dtype=torch.float))
    model.save_pretrained(str(d))
    tok.save_pretrained(str(d))
    if config is not None:
        (d / "waf_v2.json").write_text(config if isinstance(config, str) else json.dumps(config))
    return str(d)


def cfg_b(**kw):
    base = dict(arm="B_sigmoid6", labels=LABELS, attack_labels=ATTACKS, max_len=32, recommended_threshold=0.6)
    base.update(kw)
    return base


def sigmoid_logits(ps):
    return [_logit(p) for p in ps]


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("WAF_THRESHOLD", raising=False)


@pytest.fixture
def arm_b(tmp_path):
    # heads: sqli .90, xss .10, path .20, cmdi .30, ssti .05, scanner .40
    return make_model(tmp_path, "b", 6, ATTACKS, sigmoid_logits([0.90, 0.10, 0.20, 0.30, 0.05, 0.40]), cfg_b())


def load(path, **kw):
    clf = WAFClassifier(model_path=path, **kw)
    assert clf.load(), "model should load"
    return clf


# --- arm B decision rule ---------------------------------------------------------------------------
def test_arm_b_blocks_on_max_head_above_the_json_threshold(arm_b):
    p = load(arm_b).predict("select 1 or 1=1")
    assert isinstance(p, WAFPrediction)
    assert p.blocked and p.label == "sqli" and p.score == pytest.approx(0.90, abs=1e-5)
    assert p.risk == RISK["sqli"]
    assert set(p.scores) == set(ATTACKS) | {"clean"}
    assert p.scores["xss"] == pytest.approx(0.10, abs=1e-5) and p.scores["scanner"] == pytest.approx(0.40, abs=1e-5)
    assert p.scores["clean"] == pytest.approx(1 - 0.90, abs=1e-5)


def test_arm_b_allows_when_every_head_is_at_or_below_the_threshold(tmp_path):
    path = make_model(tmp_path, "low", 6, ATTACKS, sigmoid_logits([0.50, 0.10, 0.20, 0.30, 0.05, 0.40]), cfg_b())
    p = load(path).predict("hello world")
    assert not p.blocked and p.score == pytest.approx(0.50, abs=1e-5)
    assert p.label == "sqli"                    # label is the argmax head even when it is not blocked
    assert p.risk == "safe"
    assert p.scores["clean"] == pytest.approx(0.50, abs=1e-5)


def test_label_is_the_argmax_head(tmp_path):
    path = make_model(tmp_path, "ssti", 6, ATTACKS, sigmoid_logits([0.1, 0.2, 0.1, 0.1, 0.95, 0.1]), cfg_b())
    p = load(path).predict("{{7*7}}")
    assert p.blocked and p.label == "ssti" and p.risk == RISK["ssti"]


def test_threshold_comparison_is_strict(arm_b, monkeypatch):
    p = load(arm_b).predict("x")
    monkeypatch.setenv("WAF_THRESHOLD", repr(p.score))
    assert not load(arm_b).predict("x").blocked, "max_prob == threshold must NOT block"
    monkeypatch.setenv("WAF_THRESHOLD", repr(p.score - 1e-4))
    assert load(arm_b).predict("x").blocked


def test_threshold_comes_from_json_unless_env_overrides_at_load_time(tmp_path, monkeypatch):
    path = make_model(tmp_path, "t", 6, ATTACKS, sigmoid_logits([0.70, 0.1, 0.1, 0.1, 0.1, 0.1]),
                      cfg_b(recommended_threshold=0.8))
    clf = load(path)
    assert clf.threshold == pytest.approx(0.8) and not clf.predict("a").blocked
    monkeypatch.setenv("WAF_THRESHOLD", "0.6")            # read at load(), not at import
    clf = load(path)
    assert clf.threshold == pytest.approx(0.6) and clf.predict("a").blocked


def test_constructor_threshold_is_ignored_for_arm_b(tmp_path):
    """text_service always passes WAF_ATTACK_THRESHOLD (0.8) explicitly; the model's own calibrated
    threshold must win or the drop-in would silently use the wrong operating point."""
    path = make_model(tmp_path, "c", 6, ATTACKS, sigmoid_logits([0.70, 0.1, 0.1, 0.1, 0.1, 0.1]),
                      cfg_b(recommended_threshold=0.6))
    clf = load(path, threshold=0.99)
    assert clf.threshold == pytest.approx(0.6) and clf.predict("a").blocked


def test_arm_b_honours_max_len_from_the_json(tmp_path):
    """Text beyond max_len must not influence the scores; a larger max_len must see it."""
    text = " ".join("abcdefghij"[i % 10] for i in range(40))
    other = text + " z y x w v u t s r q"
    short = load(make_model(tmp_path, "s", 6, ATTACKS, None, cfg_b(max_len=8), max_positions=64))
    # same weights, different max_len: reuse the saved model with a rewritten json
    p1, p2 = short.predict(text), short.predict(other)
    assert p1.scores == p2.scores
    d = tmp_path / "s"
    (d / "waf_v2.json").write_text(json.dumps(cfg_b(max_len=60)))
    long_ = load(str(d))
    assert long_.predict(text).scores != long_.predict(other).scores


def test_arm_b_max_len_defaults_to_the_predictor_constant_and_must_fit_the_model(tmp_path):
    cfg = cfg_b()
    del cfg["max_len"]
    path = make_model(tmp_path, "d", 6, ATTACKS, sigmoid_logits([0.9] + [0.1] * 5), cfg, max_positions=512)
    assert load(path)._max_len == predictor.TRANSFORMER_MAX_LENGTH
    too_long = make_model(tmp_path, "e", 6, ATTACKS, sigmoid_logits([0.9] + [0.1] * 5), cfg_b(max_len=500),
                          max_positions=64)
    assert not WAFClassifier(model_path=too_long).load()


# --- fail-open on a broken / inconsistent arm B directory -----------------------------------------------
@pytest.mark.parametrize("name,config", [
    ("badjson", "{not json"),
    ("unknownarm", cfg_b(arm="C_whatever")),
    ("noarm", {k: v for k, v in cfg_b().items() if k != "arm"}),
    ("nothr", {k: v for k, v in cfg_b().items() if k != "recommended_threshold"}),
    ("thr_range", cfg_b(recommended_threshold=1.5)),
    ("thr_nan", cfg_b(recommended_threshold="nan")),
    ("labels_mismatch", cfg_b(attack_labels=ATTACKS[:5])),
    ("unknown_label", cfg_b(attack_labels=ATTACKS[:5] + ["nonsense"])),
    ("clean_as_head", cfg_b(attack_labels=["clean"] + ATTACKS[1:])),
    ("dup_label", cfg_b(attack_labels=ATTACKS[:5] + [ATTACKS[0]])),
    ("reordered", cfg_b(attack_labels=list(reversed(ATTACKS)))),
])
def test_bad_arm_b_directory_fails_open_and_never_loads_as_softmax(tmp_path, name, config):
    path = make_model(tmp_path, name, 6, ATTACKS, sigmoid_logits([0.9] + [0.1] * 5), config)
    clf = WAFClassifier(model_path=path)
    assert clf.load() is False
    p = clf.predict("' OR 1=1 --")
    assert not p.blocked and p.label == "clean" and "not loaded" in p.note


def test_inference_error_fails_open(arm_b, monkeypatch):
    clf = load(arm_b)
    monkeypatch.setattr(clf, "_tokenizer", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    p = clf.predict("x")
    assert not p.blocked and p.label == "clean" and "inference error" in p.note


def test_empty_text_is_clean(arm_b):
    assert not load(arm_b).predict("   ").blocked


# --- arm A and the legacy layout are unchanged -----------------------------------------------------------
def softmax_bias(ps):
    return [math.log(p) for p in ps]


def test_arm_a_directory_keeps_the_softmax_rule_and_constructor_threshold(tmp_path):
    probs = [0.1, 0.7, 0.05, 0.05, 0.05, 0.03, 0.02]
    cfg = dict(arm="A_softmax7", labels=LABELS, attack_labels=ATTACKS, max_len=256, recommended_threshold=0.3)
    path = make_model(tmp_path, "a", 7, LABELS, softmax_bias(probs), cfg)
    clf = load(path, threshold=0.8)
    p = clf.predict("x")
    assert clf._backend == "transformer" and clf.threshold == 0.8        # json threshold is NOT applied to arm A
    assert p.label == "sqli" and p.score == pytest.approx(0.7, abs=1e-5) and not p.blocked
    assert set(p.scores) == set(LABELS)
    assert load(path, threshold=0.5).predict("x").blocked


def test_directory_without_the_json_is_the_legacy_softmax_model(tmp_path):
    probs = [0.7, 0.1, 0.05, 0.05, 0.05, 0.03, 0.02]
    path = make_model(tmp_path, "legacy", 7, LABELS, softmax_bias(probs))
    clf = load(path, threshold=0.5)
    p = clf.predict("x")
    assert p.label == "clean" and not p.blocked and clf._backend == "transformer"


def test_arm_a_still_truncates_at_the_predictor_constant(tmp_path, monkeypatch):
    probs = [0.1, 0.7, 0.05, 0.05, 0.05, 0.03, 0.02]
    path = make_model(tmp_path, "a2", 7, LABELS, softmax_bias(probs), None, max_positions=512)
    clf = load(path)
    seen = {}
    real = clf._tokenizer

    def spy(text, **kw):
        seen.update(kw)
        return real(text, **kw)
    monkeypatch.setattr(clf, "_tokenizer", spy)
    clf.predict("a b c")
    assert seen["max_length"] == predictor.TRANSFORMER_MAX_LENGTH and seen["truncation"] is True


def test_missing_path_fails_open(tmp_path):
    clf = WAFClassifier(model_path=str(tmp_path / "nope"))
    assert clf.load() is False and not clf.predict("' or 1=1").blocked
