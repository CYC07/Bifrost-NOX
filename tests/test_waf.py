"""Unit tests for the WAF dataset pipeline and classifier.

Covers the pure logic (taxonomy, source loaders, split, predictor decisions and
fail-open). Training a full model is exercised via a small in-test fit on the
seed so the tests need no committed model artifact.
"""
import json
import os
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
    ],
)
def test_transformer_allows_benign_in_distribution(transformer_classifier, benign):
    p = transformer_classifier.predict(benign)
    assert p.blocked is False


@needs_distilbert
@pytest.mark.xfail(
    reason="known weakness: bare simple-English key=value query strings remain "
    "thin in the clean corpus (goodqueries.txt is 96% pathless URLs, not "
    "key=value pairs) — still fails at this test's 0.5 threshold though it "
    "clears production's 0.8 WAF_THRESHOLD",
    strict=True,
)
@pytest.mark.parametrize("benign", ["q=best pizza near me"])
def test_transformer_allows_benign_out_of_distribution(transformer_classifier, benign):
    p = transformer_classifier.predict(benign)
    assert p.blocked is False


@needs_distilbert
@pytest.mark.xfail(
    reason="known weakness: benign login/credential-style POST bodies "
    "(username=admin&password=...) remain unrepresented in any available "
    "public benign corpus (nobody publishes real form bodies) — blocks at "
    "0.999 confidence, clears no reasonable threshold. Needs synthesized "
    "(faker-generated) benign form/JSON bodies, not more scraped URLs.",
    strict=True,
)
def test_transformer_allows_benign_login_form(transformer_classifier):
    p = transformer_classifier.predict("username=admin&password=secret123")
    assert p.blocked is False


@needs_distilbert
def test_transformer_prediction_contract(transformer_classifier):
    p = transformer_classifier.predict("id=1' OR '1'='1--")
    assert set(p.scores) == set(taxonomy.LABELS)
    assert abs(sum(p.scores.values()) - 1.0) < 1e-3          # softmax distribution
    assert p.risk in {"safe", "low", "medium", "high", "critical"}
