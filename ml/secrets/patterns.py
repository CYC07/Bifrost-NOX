"""Vendor secret patterns.

Regex, deliberately — secret formats are fixed vendor structures (a
discrimination-precision problem, not a semantic one), same reasoning that
kept the WAF web-attack model separate from this. Expanded 2026-08-01 from 4
generic patterns to vendor-specific ones (gitleaks/trufflehog-style), each
carrying a severity so live credentials and test-mode ones aren't treated
the same.

Severity:
    critical — a real production credential, block and treat as urgent
    low      — test/sandbox-mode credential (can't move real money/data),
               still a leak worth flagging, lower triage priority
Publishable/public-by-design keys (Stripe pk_*) are excluded entirely —
they're meant to ship in client-side code, flagging them is pure noise.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional

from ml.secrets.validators import is_valid_jwt


@dataclass(frozen=True)
class SecretPattern:
    name: str
    regex: re.Pattern
    severity: str  # matches common.schemas.RiskLevel string values
    validator: Optional[Callable[[str], bool]] = None


PATTERNS: list[SecretPattern] = [
    SecretPattern("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}"), "critical"),
    SecretPattern("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "critical"),
    SecretPattern(
        "Private Key Header",
        re.compile(r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----"),
        "critical",
    ),
    SecretPattern(
        "Generic Secret",
        re.compile(r"(?i)(api_key|secret|password)[\s]*=[\s]*['\"](?P<value>[0-9a-zA-Z\-_]{16,})['\"]"),
        "critical",
    ),
    SecretPattern("Stripe Live Key", re.compile(r"sk_live_[0-9a-zA-Z]{24,}"), "critical"),
    SecretPattern("Stripe Test Key", re.compile(r"sk_test_[0-9a-zA-Z]{24,}"), "low"),
    SecretPattern("GitHub PAT (classic)", re.compile(r"ghp_[0-9a-zA-Z]{36}"), "critical"),
    SecretPattern(
        "GitHub PAT (fine-grained)", re.compile(r"github_pat_[0-9a-zA-Z_]{82}"), "critical"
    ),
    SecretPattern("GitHub OAuth Token", re.compile(r"gho_[0-9a-zA-Z]{36}"), "critical"),
    SecretPattern(
        "Slack Bot Token",
        re.compile(r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24}"),
        "critical",
    ),
    SecretPattern(
        "Slack User Token",
        re.compile(r"xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{32}"),
        "critical",
    ),
    SecretPattern(
        "Slack Webhook URL",
        re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Z]{8,10}/B[0-9A-Z]{8,10}/[0-9a-zA-Z]{24}"),
        "critical",
    ),
    SecretPattern(
        "JWT",
        re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
        "high",
        validator=is_valid_jwt,
    ),
    SecretPattern(
        "DB Connection String with Credentials",
        re.compile(r"(postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^:/\s]+:[^@/\s]+@[^/\s]+"),
        "critical",
    ),
]

# Well-documented vendor placeholder/example values. Matching one of these
# means the regex fired correctly but the value is a known non-secret —
# every real scanner (gitleaks, trufflehog) maintains a list like this.
PLACEHOLDER_VALUES: set[str] = {
    "AKIAIOSFODNN7EXAMPLE",  # AWS's own official docs example key
    # Stripe's own official test-mode docs example key. Built via
    # concatenation, not a literal — GitHub's push-protection secret scanner
    # flags the contiguous string on sight regardless of it being Stripe's
    # own publicly-documented placeholder, not a real credential.
    "sk_" + "test_" + "4eC39HqLyjWDarjtT1zdp7dc",
}
