"""Inspect a request target (path + query string) with a precision-first filter.

The WAF model was trained on bare payloads and classifies the *shape* of benign values (JWTs,
comma lists, non-ASCII search terms, OAuth redirect URLs) as attacks. Sending every query value
to it gave 5 false positives on 28 ordinary targets. So:

* only values with an *active* character (quote, <>, ;|&$(){}, backslash, "..", NUL) or a SQL
  phrase (UNION SELECT, DROP TABLE, SLEEP(...)) are passed to the model; plain URLs are skipped;
* path traversal and sensitive files are caught by high-precision regex, never the model;
* everything is percent-decoded (twice, for double encoding) before looking at it.

Availability over security: a payload with none of these markers is not inspected here.
Pure functions, no model or network imports, so the gateway can use it as a cheap pre-filter.
"""
from __future__ import annotations

import re
from urllib.parse import unquote_plus, urlsplit

from ml.secrets.detector import detect as detect_secrets

MAX_VALUES = 64
MAX_VALUE_CHARS = 2000
_MAX_TARGET = 16384

_ACTIVE = re.compile(
    r"""['"`<>;|&$(){}\\\x00]|\.\.|"""
    r"""\bunion\s+(?:all\s+)?select\b|\bselect\s.+\sfrom\b|\bdrop\s+table\b|\binsert\s+into\b|"""
    r"""\bdelete\s+from\b|\bsleep\s*\(|\bbenchmark\s*\(|\bxp_cmdshell\b|\bexec\s*\(""",
    re.I,
)
_PLAIN_URL = re.compile(r"""^(?:https?|ftp)://[^\s'"<>`;|{}\\]+$""", re.I)
_TRAVERSAL = re.compile(
    r"(?:\.\.[/\\]+){2,}|(?:^|[/\\])\.\.[/\\]+(?:etc|windows|winnt|boot|proc|root|home|var)\b", re.I)
_SENSITIVE = re.compile(
    r"(?:^|[/\\=:])(?:etc[/\\]+(?:passwd|shadow|group|hosts)|windows[/\\]+win\.ini|boot\.ini|"
    r"proc[/\\]+self[/\\]+environ)\b", re.I)


def _decode(s: str) -> str:
    """Percent-decode up to twice (catches %252e%252e%252f); '+' becomes a space."""
    for _ in range(2):
        d = unquote_plus(s)
        if d == s:
            break
        s = d
    return s


def _split(target: str) -> tuple[str, str]:
    t = (target or "")[:_MAX_TARGET]
    try:
        sp = urlsplit(t)
        return sp.path, sp.query
    except ValueError:
        return t.split("?", 1)[0], (t.split("?", 1)[1] if "?" in t else "")


def _values(query: str) -> list[str]:
    out: list[str] = []
    for part in query.split("&"):
        _, eq, raw = part.partition("=")
        if not eq or not raw:
            continue
        out.append(_decode(raw))
    return out


def decoded(target: str) -> str:
    """The whole target percent-decoded (twice), fragment dropped — for secret scanning."""
    t = (target or "")[:_MAX_TARGET].split("#", 1)[0]
    return _decode(t)


def waf_values(target: str) -> list[str]:
    """Decoded query values that deserve a WAF-model look (active, not a plain URL), capped."""
    _, query = _split(target)
    keep: list[str] = []
    for v in _values(query):
        if not v.strip() or _PLAIN_URL.match(v) or not _ACTIVE.search(v):
            continue
        keep.append(v[:MAX_VALUE_CHARS])
        if len(keep) >= MAX_VALUES:
            break
    return keep


def signature_hits(target: str) -> list[str]:
    """High-precision regex findings on the decoded path + query (names only)."""
    path, query = _split(target)
    decoded = _decode(path) + "?" + _decode(query) if query else _decode(path)
    hits: list[str] = []
    if _TRAVERSAL.search(decoded):
        hits.append("path_traversal")
    if _SENSITIVE.search(decoded):
        hits.append("sensitive_file")
    return hits


def secret_hits(target: str) -> list[str]:
    """Names of secret patterns found in the decoded target (never the secret itself).
    A pasted API key has no attack characters, so the attack filters alone would never see it."""
    try:
        return sorted({f.kind for f in detect_secrets(decoded(target))})
    except Exception:  # noqa: BLE001 — a detector bug must never break request handling
        return []


def is_interesting(target: str) -> bool:
    """Cheap gateway pre-filter: does this target need analysis at all?"""
    return bool(signature_hits(target) or waf_values(target) or secret_hits(target))
