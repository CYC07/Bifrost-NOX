"""Candidate labels for the zero-shot sensitive-content classifier.

Design note: labels describe *confidentiality*, not *topic*. "sensitive financial
records" — not "finance" — so public financial NEWS (benign) does not trip while
an internal earnings leak does. Topic-only labels were what made the old MiniLM
DANGEROUS_CONCEPTS false-block benign news; we deliberately avoid that.

Each label maps to the firewall risk level it represents. Override the label set
at runtime with SENSITIVE_LABELS env (comma-separated) if a deployment needs it.
"""
from __future__ import annotations

import os

# label -> risk level (aligns with common.schemas RiskLevel string values)
LABEL_RISK: dict[str, str] = {
    "confidential or internal company document": "high",
    "proprietary source code or trade secret": "high",
    "sensitive personal financial records or account statements": "high",
    "private medical or health record": "critical",
    "classified or restricted government information": "critical",
    "confidential legal or contractual document": "high",
}


def get_labels() -> list[str]:
    override = os.getenv("SENSITIVE_LABELS", "").strip()
    if override:
        return [s.strip() for s in override.split(",") if s.strip()]
    return list(LABEL_RISK.keys())


def risk_for(label: str) -> str:
    return LABEL_RISK.get(label, "medium")
