"""Ordinary consumer questions ("How is my credit score calculated?") score 0.9+ on the finance / medical / HR
labels because the NLI scores TOPIC. A short question carries no record, so it must not block on topic alone;
hard evidence (a marking, an ID number, ...) still makes it count."""
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ml.sensitive import labels as lb  # noqa: E402
from ml.sensitive.evidence import question_form  # noqa: E402
from ml.sensitive.predictor import SensitiveClassifier  # noqa: E402

A = lb.SensitiveLabel("alpha record", "This example is alpha record.", "critical", 0.9)
B = lb.SensitiveLabel("beta document", "This example is beta document.", "high", 0.5, low=0.3)


@pytest.mark.parametrize("text", [
    "How do I set up a standing order on my savings account?",
    "what was the biggest tax change from tax reform",
    "A guy scammed me, but he gave me a bank account number. Can I use that to take out what he owes me?",
    "Insurance company sent me huge check instead of pharmacy. Now what?",
    "How is my credit score calculated?\nSure, here is some general information.\nThanks, can you explain that in more detail?",
    "I have had a headache and nausea since yesterday, what could it be?",
])
def test_short_questions_are_question_form(text):
    assert question_form(text)


@pytest.mark.parametrize("text", [
    "Here is the patient's full medical record including diagnosis and HIV status.",
    "Employee salary list: Alice 142000, Bob 98000, Carol 175000, confidential.",
    "Attached are our unreleased Q4 earnings figures before the public announcement.",
    "My passport number is X1234567 and my home address is 12 Elm St.",
    "CHIEF COMPLAINT: rash. HISTORY OF PRESENT ILLNESS: itching. Is this clear? " + "x " * 400,   # long pasted content
    "",
])
def test_statements_and_long_pastes_are_not_question_form(text):
    assert not question_form(text)


@pytest.fixture
def policy(monkeypatch):
    monkeypatch.delenv("SENSITIVE_LABELS", raising=False)
    monkeypatch.delenv("SENSITIVE_THRESHOLD", raising=False)
    monkeypatch.setattr(lb, "SENSITIVE", {"a": A, "b": B})
    monkeypatch.setattr(lb, "CONTRAST", {})
    monkeypatch.setattr(lb, "MARGIN", 0.0)
    monkeypatch.setattr(lb, "MIN_EVIDENCE", 1)
    monkeypatch.setattr(lb, "IDENTITY_BUNDLE", 0)


def _clf(pipe):
    c = SensitiveClassifier()
    c._loaded, c._pipe = True, pipe
    return c


def test_a_short_question_is_never_blocked_on_topic_alone(policy):
    def pipe(*a, **k):
        raise AssertionError("no NLI pass for a plain question")

    p = _clf(pipe).predict("How do I set up a standing order on my savings account?")
    assert not p.blocked and p.reason == "question"


def test_a_question_that_carries_hard_evidence_is_still_judged(policy):
    sc = {A.hypothesis: 0.1, B.hypothesis: 0.4}
    p = _clf(lambda t, **kw: {"labels": list(sc), "scores": list(sc.values())}).predict(
        "My passport number is X1234567, can you help me renew it?")
    assert p.blocked and p.reason == "nli+evidence"


def test_a_long_paste_with_a_question_mark_is_still_judged(policy):
    sc = {A.hypothesis: 0.95, B.hypothesis: 0.0}
    assert _clf(lambda t, **kw: {"labels": list(sc), "scores": list(sc.values())}).predict(
        "Is this ok? " + "pasted private record text " * 40).blocked
