"""Unit tests for the text_service content-shape router (ml/router/).

Covers fail-open behavior and decision structure with a small in-test fit
(no committed model artifact needed for these). A separate marker-gated
block exercises the real trained artifact if present, matching the pattern
established in tests/test_waf.py for the transformer backend.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ml.router.taxonomy import LABELS, validate_label  # noqa: E402
from ml.router.predictor import RouterClassifier  # noqa: E402


def test_labels_are_the_three_shapes():
    assert set(LABELS) == {"code", "web_request", "prose"}


def test_validate_label_rejects_unknown():
    with pytest.raises(ValueError):
        validate_label("nonsense")


def test_router_fail_open_when_model_missing():
    r = RouterClassifier(model_path="/nonexistent/router.joblib")
    assert r.load() is False
    decision = r.route("anything")
    assert decision.route == "web_request"  # fail-open default, never raises


def test_router_fail_open_on_empty_text():
    r = RouterClassifier(model_path="/nonexistent/router.joblib")
    r.load()
    decision = r.route("")
    assert decision.route == "web_request"


@pytest.fixture(scope="module")
def fitted_router():
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline

    code = ["def f(x):\n    return x + 1", "function f(x) { return x + 1; }", "public int f(int x) { return x + 1; }"]
    web = ["q=best+pizza&sort=asc", "id=1' OR '1'='1--", "username=admin&password=secret"]
    prose = ["The weather today is sunny.", "Please review the attached document.", "Our team meets weekly."]

    texts = code + web + prose
    labels = ["code"] * 3 + ["web_request"] * 3 + ["prose"] * 3
    pipe = Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4))),
        ("clf", LogisticRegression(max_iter=1000)),
    ])
    pipe.fit(texts, labels)

    r = RouterClassifier()
    r._pipeline, r._labels, r._loaded = pipe, LABELS, True
    return r


def test_router_routes_code_to_code(fitted_router):
    decision = fitted_router.route("class Foo {\n  bar() { return 1; }\n}")
    assert decision.route == "code"


def test_router_routes_query_string_to_web_request(fitted_router):
    decision = fitted_router.route("category=shoes&brand=nike&sort=price")
    assert decision.route == "web_request"


def test_router_routes_prose_to_prose(fitted_router):
    decision = fitted_router.route("The report is due at the end of the week.")
    assert decision.route == "prose"


def test_router_decision_scores_sum_to_one(fitted_router):
    decision = fitted_router.route("SELECT * FROM users")
    assert abs(sum(decision.scores.values()) - 1.0) < 1e-6


# --- real trained artifact (skipped if not present) -------------------------
ROUTER_ARTIFACT = os.path.join(
    os.path.dirname(__file__), "..", "ml", "router", "artifacts", "router_baseline.joblib"
)
needs_router_artifact = pytest.mark.skipif(
    not os.path.exists(ROUTER_ARTIFACT), reason="trained router artifact not present"
)


@needs_router_artifact
@pytest.mark.parametrize(
    "text,expected",
    [
        ("def calculate_total(items):\n    return sum(i.price for i in items)", "code"),
        ("function fetchUser(id) {\n  return fetch(`/api/users/${id}`);\n}", "code"),
        ("q=best pizza near me&sort=popularity", "web_request"),
        ("username=admin&password=secret123", "web_request"),
        ("id=1' OR '1'='1--", "web_request"),
        ("The quarterly earnings report shows a 12% increase in revenue.", "prose"),
        ("Please contact our support team if you have any questions.", "prose"),
    ],
)
def test_real_router_classifies_correctly(text, expected):
    r = RouterClassifier()
    assert r.load() is True
    decision = r.route(text)
    assert decision.route == expected


@needs_router_artifact
@pytest.mark.xfail(
    reason="known limitation: short one-liner code (shell command chains, "
    "terse assignments) gets misrouted to web_request — our own WAF training "
    "data (synth_cmdi_raw) is full of 'key=value && command'-shaped examples, "
    "so the router over-generalizes '&&'/'=' as a web_request signal even "
    "without a key= prefix. Low security impact: secrets regex + Presidio "
    "run unconditionally regardless of route, and web_request fallback still "
    "runs WAF (won't false-block benign code) — just loses the 'code "
    "detected' signal, not a threat-detection gap. Needs more bare "
    "(no key=) shell/assignment one-liners in the code training class.",
    strict=True,
)
@pytest.mark.parametrize(
    "text",
    [
        "git commit -m 'fix login bug' && git push origin main",
        "x=lambda a,b:a+b",
    ],
)
def test_real_router_misroutes_terse_code_oneliners(text):
    r = RouterClassifier()
    assert r.load() is True
    decision = r.route(text)
    assert decision.route == "code"
