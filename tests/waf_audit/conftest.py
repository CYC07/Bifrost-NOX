"""Shared fixtures for the WAF audit: the REAL v1 model and the REAL router (no fakes), so a failure here
means the shipped WAF does not behave as a WAF should, not that a mock was wrong.

Only the WAF and the router are loaded into text_service; the other analyzers stay unloaded (they fail open),
so a block seen in these tests came from the WAF path or the cheap regex analyzers, not from a model that is
irrelevant to the audit.
"""
import os
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, ROOT)

WAF_THRESHOLD = float(os.getenv("WAF_ATTACK_THRESHOLD", "0.99"))


@pytest.fixture(scope="session")
def waf():
    from ml.waf.predictor import WAFClassifier
    clf = WAFClassifier(threshold=WAF_THRESHOLD)
    if not clf.load():
        pytest.skip("WAF model artifacts not present (ml/waf/artifacts/waf_distilbert)")
    return clf


@pytest.fixture(scope="session")
def svc(waf):
    from ml.router.predictor import RouterClassifier
    from text_service import main as m
    router = RouterClassifier()
    if not router.load():
        pytest.skip("router artifacts not present")
    m.waf_classifier = waf
    m.router_classifier = router
    return m


def pytest_collection_modifyitems(config, items):
    """Mark every CONFIRMED gap (known_gaps.GAPS) as a strict xfail with its diagnosis as the reason."""
    import re

    from known_gaps import GAPS
    compiled = [(re.compile(g["pattern"]), g) for g in GAPS]
    for item in items:
        if "waf_audit" not in item.nodeid:
            continue
        for rx, g in compiled:
            if rx.search(item.nodeid):
                item.add_marker(pytest.mark.xfail(
                    strict=True, reason=f"[{g['id']}] {g['module']} / {g['stage']} ({g['severity']}): {g['why']} FIX: {g['fix']}"))
                break
