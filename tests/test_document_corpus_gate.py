"""Corpus gate for document_service (opt-in: DOC_CORPUS_GATE=1, takes ~7 min).

Needs the corpora from ``dataset_tools/document/build_corpus.py`` under
~/FYP/corpora/. Gate: combined-verdict FP on real benign files <= 0.5 %, and
detection of the real malicious files not below the pre-fix baseline.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

ROOT = os.path.expanduser("~/FYP/corpora")
pytestmark = pytest.mark.skipif(
    os.environ.get("DOC_CORPUS_GATE") != "1" or not os.path.isdir(os.path.join(ROOT, "doc_benign")),
    reason="set DOC_CORPUS_GATE=1 and build the corpora first",
)

BASELINE_REAL_DETECTED = 7  # before the precision fixes (of 50 real files)


def _blocked_names(setname: str) -> tuple[int, set]:
    from document_service import content_model, main as dmain, malware_model, metadata_model, structure_model

    structure_model.load_model()
    malware_model.load_rules()
    d = os.path.join(ROOT, setname)
    man = json.load(open(os.path.join(d, "manifest.json")))
    blocked = set()
    for fn in man:
        data = open(os.path.join(d, fn), "rb").read()
        rs = [structure_model.analyze(data), content_model.analyze(data),
              asyncio.run(malware_model.analyze(data)), metadata_model.analyze(data)]
        if str(getattr(dmain._aggregate(rs).status, "value", dmain._aggregate(rs).status)).lower() == "block":
            blocked.add(fn)
    return len(man), blocked


def test_benign_false_positive_rate():
    n, blocked = _blocked_names("doc_benign")
    assert n >= 200
    assert len(blocked) / n <= 0.005, sorted(blocked)


def test_real_malicious_detection_not_below_baseline():
    n, blocked = _blocked_names("doc_malicious_real")
    assert n >= 30
    assert len(blocked) >= BASELINE_REAL_DETECTED
