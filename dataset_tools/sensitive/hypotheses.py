"""The pool of NLI hypotheses scored once per eval text (see nli_pool.py).

Key scheme:  <template>:<label>
  t0  production template "This example is {}." with the production label strings (ml/sensitive/labels.py
      as of the base commit; copied here so the baseline stays reproducible after labels.py changes)
  t2  "This text is {}." with grammatical noun phrases (article added)
  b2  benign "contrast" classes under the t2 template
  e   evidence hypotheses (specific, checkable statements)

The NLI pass is expensive (CPU, ~300 tokens x pairs per document), so the pool is staged:
STAGE1 = the six production hypotheses (the baseline), STAGE2 = everything the sweep may add.
"""
from __future__ import annotations

# production labels at base commit c173e0e (frozen copy)
BASE_LABELS = [
    "confidential or internal company document",
    "proprietary source code or trade secret",
    "sensitive personal financial records or account statements",
    "private medical or health record",
    "classified or restricted government information",
    "confidential legal or contractual document",
]

# grammatical variants of four of the categories (the code / government labels never fire on this traffic)
SENS_T2 = {
    "conf": "a confidential or internal company document",
    "med": "a private medical or health record",
    "legal": "a confidential legal or contractual document",
}

# benign contrast classes: what a topic detector confuses with a confidential document
BENIGN = {
    "tos": "terms of service or a privacy policy",
    "publaw": "a public legal text such as a law, court opinion or open-source license",
    "news": "a news article",
    "pubhealth": "public health information or a medical textbook passage",
    "pubfin": "a public financial news story or a published company report",
    "docs": "software documentation or a manual",
}

# specific, checkable evidence statements (full sentences)
EVIDENCE = {
    "pii": "This text contains a person's private identifying details such as an ID number, passport number or home address.",
    "pay": "This text lists named employees with their salaries or compensation.",
    "person": "This text contains private information about a specific named person.",
    "patient": "This text describes one specific patient's diagnosis or treatment.",
}


def _build() -> tuple[dict[str, str], list[str], list[str]]:
    s1: dict[str, str] = {}
    s2: dict[str, str] = {}
    for lbl in BASE_LABELS:
        s1[f"t0:{lbl}"] = f"This example is {lbl}."
    for k, np_ in SENS_T2.items():
        s2[f"t2:{k}"] = f"This text is {np_}."
    for k, np_ in BENIGN.items():
        s2[f"b2:{k}"] = f"This text is {np_}."
    for k, sent in EVIDENCE.items():
        s2[f"e:{k}"] = sent
    return {**s1, **s2}, list(s1), list(s2)


POOL, STAGE1, STAGE2 = _build()
