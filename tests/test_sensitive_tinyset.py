"""The 12 strings that started this work, through the REAL router + sensitive model (skipped when the DeBERTa
checkpoint or the router artifact is not present). This is an acceptance check, not a calibration set: the
policy was chosen on the public evaluation set in dataset_tools/sensitive/, never on these strings.

Measured on the base commit through the same path: 1 of 8 benign blocked (the terms-of-service line) and 2 of 4
sensitive missed (the salary list, which the router sends to web_request so the NLI never ran, and the passport
line, which the NLI scores 0.16).
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from text_service import main as svc  # noqa: E402

BENIGN = [
    "The quarterly meeting is on Tuesday at 3pm in room 4.",
    "Our terms of service describe how we handle your account and data.",
    "Recipe: mix flour, eggs and milk, then bake for 20 minutes.",
    "Please review the attached project timeline.",
    "The weather tomorrow will be sunny with a light breeze.",
    "Privacy policy: we respect your privacy and use cookies to improve the site.",
    "Click here to reset your password if you forgot it.",
    "Invoice #4021 is due on the 15th of next month.",
]
SENSITIVE = [
    "Here is the patient's full medical record including diagnosis and HIV status.",
    "Employee salary list: Alice 142000, Bob 98000, Carol 175000, confidential.",
    "Attached are our unreleased Q4 earnings figures before the public announcement.",
    "My passport number is X1234567 and my home address is 12 Elm St.",
]


@pytest.fixture(scope="module")
def stack():
    from ml.router.predictor import RouterClassifier
    from ml.sensitive.predictor import SensitiveClassifier
    router = RouterClassifier()
    if not router.load():
        pytest.skip("router artifact unavailable")
    clf = SensitiveClassifier()
    if not clf.load():
        pytest.skip("sensitive model unavailable")
    saved = (svc.router_classifier, svc.sensitive_classifier, svc.presidio_analyzer, svc.waf_classifier)
    svc.router_classifier, svc.sensitive_classifier, svc.presidio_analyzer, svc.waf_classifier = router, clf, None, None
    svc._cache_clear()
    yield
    svc.router_classifier, svc.sensitive_classifier, svc.presidio_analyzer, svc.waf_classifier = saved
    svc._cache_clear()


def status(text, direction="outbound"):
    return svc._analyze_sync(text, False, direction)["status"]


@pytest.mark.parametrize("text", BENIGN)
def test_benign_line_is_not_blocked_outbound(stack, text):
    assert status(text) != "block"


@pytest.mark.parametrize("text", SENSITIVE)
def test_sensitive_line_is_blocked_outbound(stack, text):
    assert status(text) == "block"


def test_terms_of_service_coming_in_is_never_a_block(stack):
    assert status("Our terms of service describe how we handle your account and data.", "inbound") != "block"
