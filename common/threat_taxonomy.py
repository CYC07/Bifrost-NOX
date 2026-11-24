"""Reason text -> threat category, shared by the dashboard (orchestrator) and the block page (gateway).

Analyzer verdicts carry a free-text reason such as "Blocked by: code, web_attack" (module names) or a sentence.
This table turns that into the category shown to people, so the dashboard's threat feed and the page a blocked user
sees say the same thing. Order matters: the first matching substring wins.
"""
from __future__ import annotations

THREAT_PATTERNS: list[tuple[str, str, str, float]] = [
    # (substring, type, severity, confidence)
    ("sql", "SQL Injection", "high", 0.94),
    ("xss", "Cross-Site Scripting", "high", 0.90),
    ("prompt_injection", "Prompt Injection", "critical", 0.97),
    ("prompt injection", "Prompt Injection", "critical", 0.97),
    ("request_target", "Malicious Request Target", "high", 0.92),
    ("web_attack", "Web Attack", "high", 0.90),
    ("code", "Secret Leak", "high", 0.95),        # analyzer module names, as in "Blocked by: code"
    ("pattern", "PII Exposure", "high", 0.90),
    ("injection", "Command Injection", "critical", 0.98),
    ("malware", "Malware Payload", "critical", 0.96),
    ("eicar", "EICAR Test Signature", "medium", 0.99),
    ("pii", "PII Exfiltration", "high", 0.92),
    ("dlp", "Data Loss Prevention", "high", 0.90),
    ("brute", "Brute Force", "medium", 0.85),
    ("scan", "Port Scan", "low", 0.72),
    ("credential", "Credential Stuffing", "high", 0.91),
    ("phish", "Phishing Attempt", "high", 0.88),
    ("nsfw", "NSFW Content", "medium", 0.86),
    ("api key", "API Key Leak", "critical", 0.95),
    ("api_key", "API Key Leak", "critical", 0.95),
]


def classify_reason(reason: str) -> tuple[str, str, float]:
    """(type, severity, confidence) for a verdict reason; "Anomalous Content" when nothing matches."""
    low = (reason or "").lower()
    for sub, t, sev, conf in THREAT_PATTERNS:
        if sub in low:
            return t, sev, conf
    return "Anomalous Content", "medium", 0.80
