"""OCR-tolerant recognition of a few high-value secret shapes.

ml.secrets patterns are exact-regex, which is right for typed text but too
brittle for OCR output: Tesseract inserts spaces inside long tokens, swaps a
glyph for a symbol (J -> ')'), reads '@' as a letter, and drops dashes. These
rules recover only clear true positives, each anchored on a distinctive
prefix/shape plus a structure check, so they do not fire on prose, hashes or
UUIDs. They are used ONLY on the OCR path (ml.image.ocr_scan), never on text.

  prefixed tokens  ghp_/gho_ (36), AKIA (16), sk_live_ (>=24): re-join the
                   chunks after the prefix across spaces, treat stray symbol
                   glyphs as one wildcard character, require the exact length
                   and a letter/digit mix.
  private key      'BEGIN RSA|DSA|EC|OPENSSH PRIVATE KEY' with any dashes lost.
  db url           scheme://user:<non-numeric secret>  (a port is numeric, so a
                   non-numeric second part is a password even if OCR turned the
                   '@' into a letter).
"""
from __future__ import annotations

import re

# kind -> (prefix, body length, min_len_exact?, severity)
_PREFIXED = [
    ("GitHub PAT (classic)", "ghp_", 36, "critical"),
    ("GitHub OAuth Token", "gho_", 36, "critical"),
    ("AWS Access Key", "AKIA", 16, "critical"),
    ("Stripe Live Key", "sk_live_", 24, "critical"),
]
_NOISE = set(")(]}{|!¥€£§¢éè°©®?")
_MAX_CHUNK_GAPS = 5

_PRIVKEY = re.compile(r"BEGIN\s+(?:RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY")
_DBURL = re.compile(r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)\s*:\s*//\s*[A-Za-z0-9_.-]{2,}\s*:\s*([^\s/@:'\"]{8,})")


def _repair_body(line: str, start: int, n: int) -> str | None:
    """Collect n token chars after `start`, joining across spaces and mapping
    isolated noise glyphs to a wildcard. Returns the body or None."""
    if start >= len(line) or line[start] == " ":
        return None
    body: list[str] = []
    chunks: list[int] = []
    cur = 0
    i = start
    while i < len(line) and len(body) < n:
        c = line[i]
        if c == " ":
            if cur:
                chunks.append(cur)
                cur = 0
            if len(chunks) > _MAX_CHUNK_GAPS:
                return None
        elif c.isascii() and (c.isalnum() or c == "_"):
            body.append(c)
            cur += 1
        elif c in _NOISE:
            body.append("?")
            cur += 1
        else:
            break
        i += 1
    if cur:
        chunks.append(cur)
    # the first chunk must be substantial: stops prose like "ghp_ prefix tokens
    # are ..." from being stitched into a fake token
    if not chunks or chunks[0] < 6:
        return None
    if len(body) == n or (len(body) == n - 1 and (i >= len(line) or line[i] in "\"'`")):
        return "".join(body)
    return None


def _mixed(body: str, prefix: str) -> bool:
    core = body.replace("?", "")
    digits = sum(c.isdigit() for c in core)
    if prefix == "AKIA":
        return digits >= 2 and not core.isdigit()
    return digits >= 1 and any(c.isupper() for c in core) and any(c.islower() for c in core)


def tolerant_findings(text: str) -> list[tuple[str, str]]:
    """Return [(kind, severity)] for OCR-damaged secrets (deduplicated by kind)."""
    found: dict[str, str] = {}
    for line in text.splitlines():
        for kind, prefix, n, sev in _PREFIXED:
            start = 0
            while (idx := line.find(prefix, start)) >= 0:
                start = idx + len(prefix)
                if idx > 0 and (line[idx - 1].isalnum()):  # inside a longer word
                    continue
                body = _repair_body(line, idx + len(prefix), n)
                if body and _mixed(body, prefix) and len(set(body)) > 4:
                    found.setdefault(kind, sev)
    if _PRIVKEY.search(text):
        found.setdefault("Private Key Header", "critical")
    for m in _DBURL.finditer(text):
        pw = m.group(1)
        if not pw.isdigit() and any(c.isdigit() for c in pw) and any(c.isalpha() for c in pw):
            found.setdefault("DB Connection String with Credentials", "critical")
    return list(found.items())
