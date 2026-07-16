"""WAF attack taxonomy — the label space for the web-attack classifier.

One flat, mutually-exclusive class per sample. ``clean`` is the negative class;
everything else is an attack family. Kept aligned with what a network content
firewall actually sees crossing HTTP, and with common public datasets
(CIC-IDS, CSIC-2010) so downloaded data maps onto these labels.
"""
from __future__ import annotations

# Ordered so the index is stable for model training (do not reorder — retrain
# if you must). New classes append at the end.
LABELS: list[str] = [
    "clean",
    "sqli",
    "xss",
    "path_traversal",
    "command_injection",
    "ssti",
    "scanner",
]

LABEL_TO_ID: dict[str, int] = {name: i for i, name in enumerate(LABELS)}
ID_TO_LABEL: dict[int, str] = {i: name for i, name in enumerate(LABELS)}

# Human-facing descriptions + the firewall risk level each class maps to.
DESCRIPTIONS: dict[str, str] = {
    "clean": "Benign / legitimate HTTP request or content",
    "sqli": "SQL injection (UNION, boolean/time-based, stacked queries)",
    "xss": "Cross-site scripting (reflected/stored/DOM script injection)",
    "path_traversal": "Directory traversal / local file inclusion (../, /etc/passwd)",
    "command_injection": "OS command injection (shell metacharacters, chained commands)",
    "ssti": "Server-side template injection ({{7*7}}, ${...}, <%= %>)",
    "scanner": "Automated recon / vuln scanner / probe (dirbuster, nikto, sqlmap fingerprint)",
}

RISK: dict[str, str] = {
    "clean": "safe",
    "sqli": "critical",
    "xss": "high",
    "path_traversal": "high",
    "command_injection": "critical",
    "ssti": "high",
    "scanner": "low",
}

ATTACK_LABELS: set[str] = {name for name in LABELS if name != "clean"}


def is_attack(label: str) -> bool:
    return label in ATTACK_LABELS


def validate_label(label: str) -> str:
    if label not in LABEL_TO_ID:
        raise ValueError(f"unknown label {label!r}; must be one of {LABELS}")
    return label
