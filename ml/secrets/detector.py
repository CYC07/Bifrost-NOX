"""Secret detection over free text. Deterministic regex + structural
validation + known-placeholder exclusion — see patterns.py for why this
stays regex rather than becoming a model.
"""
from __future__ import annotations

from dataclasses import dataclass

from ml.secrets.patterns import PATTERNS, PLACEHOLDER_VALUES

# Generic placeholder shapes no vendor-specific list can enumerate — a
# password/token that's literally the word "placeholder" or all-x's is
# obviously not a real leaked secret.
_GENERIC_PLACEHOLDER_WORDS = {"changeme", "placeholder", "your_api_key_here", "example", "dummy"}


@dataclass(frozen=True)
class SecretFinding:
    kind: str
    severity: str  # matches common.schemas.RiskLevel string values
    span: tuple[int, int]
    # Deliberately no raw matched text field — findings must never carry the
    # actual secret value into logs/dashboards/downstream storage.


def _is_placeholder(value: str) -> bool:
    stripped = value.strip().strip("'\"")
    if stripped in PLACEHOLDER_VALUES:
        return True
    low = stripped.lower()
    if low in _GENERIC_PLACEHOLDER_WORDS:
        return True
    return len(stripped) > 3 and len(set(low)) == 1  # e.g. "xxxxxxxxxxxx"


def detect(text: str) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    for pattern in PATTERNS:
        for match in pattern.regex.finditer(text):
            # Some patterns (e.g. Generic Secret) match a whole key="value"
            # assignment; a named "value" group isolates just the secret
            # itself for the placeholder check. Patterns without one match
            # the token directly, so group(0) is already the right thing.
            value = match.groupdict().get("value") or match.group(0)
            if _is_placeholder(value):
                continue
            if pattern.validator and not pattern.validator(value):
                continue
            findings.append(SecretFinding(kind=pattern.name, severity=pattern.severity, span=match.span()))
    return findings
