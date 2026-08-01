"""Content-shape taxonomy for the text_service micro-orchestrator.

Not an attack taxonomy — this router decides which EXPENSIVE analyzer(s) to
run on a given text blob, before any threat detection happens. See
ml/router/predictor.py for the routing decision itself.
"""
from __future__ import annotations

LABELS: list[str] = ["code", "web_request", "prose"]
LABEL_TO_ID: dict[str, int] = {name: i for i, name in enumerate(LABELS)}


def validate_label(label: str) -> str:
    if label not in LABEL_TO_ID:
        raise ValueError(f"unknown router label: {label!r}, expected one of {LABELS}")
    return label
