"""Hypotheses and decision policy for the zero-shot sensitive-content classifier.

Design note: labels describe *confidentiality*, not *topic*. "sensitive financial records" — not "finance" —
so public financial NEWS (benign) does not trip while an internal earnings leak does. A NLI over a topic
cannot, on its own, tell a public terms-of-service / licence / textbook from a private document on the same
topic, so the policy has three more parts (all measured in dataset_tools/sensitive/):

  * per-label thresholds       the labels are not equally calibrated (a legal-document label fires on any
                               contract-looking prose, a medical-record label is far sharper);
  * contrast hypotheses        explicit BENIGN classes ("terms of service or a privacy policy", "a public legal
                               text", ...) scored in the same batch; a sensitive label must beat the best
                               benign class by MARGIN or it is not trusted;
  * corroborating evidence     ml/sensitive/evidence.py (confidentiality markings, ID numbers, pay lists, ...):
                               a weaker NLI score blocks only together with evidence, and a bundle of identity
                               signals blocks on its own (the NLI cannot see "passport X1234567, home 12 Elm St").

Override the label set at runtime with SENSITIVE_LABELS (comma-separated bare labels, wrapped as
"This example is <label>."; no contrast, no evidence tier, uniform threshold SENSITIVE_THRESHOLD) if a
deployment needs it. SENSITIVE_THRESHOLD alone overrides every label's `block` threshold.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class SensitiveLabel:
    name: str                # human label shown in findings ("private medical or health record")
    hypothesis: str          # the full NLI hypothesis sentence scored against the text
    risk: str                # firewall risk level (aligns with common.schemas RiskLevel values)
    block: float             # NLI score at/above which the label blocks on its own
    low: float | None = None  # NLI score at/above which it blocks together with MIN_EVIDENCE signals


def _label(name: str, risk: str, block: float, low: float | None = None) -> SensitiveLabel:
    return SensitiveLabel(name, f"This example is {name}.", risk, block, low)


# key -> label. Hypotheses use the pipeline's default template "This example is {}." spelled out.
# Thresholds were chosen on the DEV half of the public evaluation set in dataset_tools/sensitive/ (sweep.py:
# maximise core_real recall s.t. dev benign FP <= 3% and dev terms-of-service FP <= 6%) and reported on TEST.
# Two base labels are no longer scored: "proprietary source code or trade secret" only ever fired on man pages,
# licences and READMEs (real source code is routed to `code` and never reaches this analyzer: 139/140 repo
# files) and "classified or restricted government information" only on medical text. Dropping them also takes
# a third off the NLI cost of every request.
SENSITIVE: dict[str, SensitiveLabel] = {
    "conf": _label("confidential or internal company document", "high", 0.8, 0.2),
    "fin": _label("sensitive personal financial records or account statements", "high", 0.4, 0.2),
    "med": _label("private medical or health record", "critical", 0.5, 0.2),
    "legal": _label("confidential legal or contractual document", "high", 0.95, 0.2),
}

# benign contrast classes (full hypothesis sentences); empty = no contrast rule
# One contrast class survived the measurement: terms of service / privacy policy (the user-reported false
# positive). Adding public-law, public-health, news, finance, docs classes cost 1-2 real positives per class for
# 1-2 fewer false positives (see the report); a margin of 0.1 loses nothing on dev.
CONTRAST: dict[str, str] = {"tos": "This text is terms of service or a privacy policy."}
MARGIN = 0.1           # sensitive score must exceed the best contrast score by this much
MIN_EVIDENCE = 1        # corroborating signals needed for the `low` tier
IDENTITY_BUNDLE = 2     # identity signals (ID number / date of birth / home address) that block alone; 0 = off


def _override() -> list[str]:
    raw = os.getenv("SENSITIVE_LABELS", "").strip()
    return [s.strip() for s in raw.split(",") if s.strip()]


def sensitive_labels() -> dict[str, SensitiveLabel]:
    """The active sensitive labels keyed by hypothesis, honouring SENSITIVE_LABELS / SENSITIVE_THRESHOLD."""
    thr_env = os.getenv("SENSITIVE_THRESHOLD", "").strip()
    ov = _override()
    if ov:
        thr = float(thr_env) if thr_env else 0.6
        return {l.hypothesis: l for l in (_label(s, "medium", thr) for s in ov)}
    out = {v.hypothesis: v for v in SENSITIVE.values()}
    if thr_env:
        t = float(thr_env)
        out = {h: SensitiveLabel(v.name, v.hypothesis, v.risk, t, v.low) for h, v in out.items()}
    return out


def contrast_labels() -> list[str]:
    return [] if _override() else list(CONTRAST.values())


def get_labels() -> list[str]:
    """Every hypothesis scored for a request (sensitive + contrast), i.e. one NLI batch."""
    return list(sensitive_labels()) + contrast_labels()


def risk_for(label: str) -> str:
    """Risk of a sensitive label given its name or its hypothesis."""
    for h, v in sensitive_labels().items():
        if label in (h, v.name):
            return v.risk
    return "medium"
