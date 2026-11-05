"""Decide WHAT part of an outbound body deserves a WAF look when the content router did not
send it there (route `code` / `prose`).

The router guesses the *shape* of a body (request / source code / prose). Injection payloads are
often shaped like code (`1 UNION SELECT ...`, shell one-liners, `<script>` blocks) or sit inside a
sentence, so the shape guess must not decide whether the WAF runs. Instead, bodies with a STRONG
injection marker are sent to the WAF - only the marked lines, percent-decoded - and everything
else still skips it (benign source code is full of `;` `(` `"`, so a loose filter such as
ml/waf/target.py's `_ACTIVE` would route all of it to the model).

Pure functions, regex only (~ sub-millisecond), no model imports.
"""
from __future__ import annotations

import re
from urllib.parse import unquote_plus

from ml.waf import target as _t

MAX_SCAN_CHARS = 100_000
MAX_LINE = 2000
MAX_PARTS = 8

_STRONG = re.compile(
    r"""
    # --- SQL injection
    \bunion\b[\s/*()+]+(?:all[\s/*()+]+|distinct[\s/*()+]+)?select\b
    |['"`)]\s*(?:or|and|\|\||&&)\s*['"(`]?\w+['"`)]?\s*(?:=|<|>|\blike\b)
    |\b(?:or|and)\s+\d+\s*=\s*\d+
    |\b(?:sleep|benchmark|pg_sleep)\s*\(\s*\d
    |\bwaitfor\s+delay\b
    |;\s*(?:drop|insert|update|delete|shutdown|truncate|alter)\s+\w
    |\b(?:xp_cmdshell|information_schema|load_file\s*\(|into\s+(?:out|dump)file|extractvalue\s*\(|updatexml\s*\()
    |'\s*(?:--|\#)(?:\s|$)|'\s*/\*|"\s*--\s*$
    |\bselect\b[^\n]{1,80}\bfrom\b[^\n]{0,80}\bwhere\b[^\n]{0,80}['"]?\s*(?:or|and)\b\s*['"\d]
    # --- XSS
    |<\s*script\b[^>]{0,200}\bsrc\s*=\s*['"]?(?:https?:)?//
    |<\s*script[^>]{0,100}>\s*(?:alert|prompt|confirm|eval|document\.(?:cookie|location|write)|window\.location|fetch|new\s+Image|String\.fromCharCode)
    |\b(?:alert|prompt|confirm)\s*\(\s*[\d'"`/]|\bdocument\.(?:cookie|location|domain)\b
    |<\s*(?:img|svg|iframe|body|details|marquee|video|audio|input|object|embed|style|form|a|div|button|select|textarea)\b[^>]{0,200}\bon[a-z]{3,20}\s*=\s*["']?[^>]{0,40}(?:alert|prompt|confirm|eval|document\.|fetch|location|\(\s*1\s*\)|String\.|constructor|\bx\b)
    |\bjavascript\s*:\s*(?!void\b)\w+
    |\bonerror\s*=
    # --- traversal / sensitive files
    |(?:\.\.[/\\]){3,}|(?:%2e%2e|%252e|\.\.%2f|\.\.%5c|%c0%af)
    |/etc/(?:passwd|shadow|group)\b|\bboot\.ini\b|windows[/\\]win\.ini|/proc/self/environ|php://(?:filter|input)|expect://
    # --- command injection
    |[;|&\n]\s*(?:cat|id|whoami|uname|nc|ncat|netcat|curl|wget|bash|sh|ping|rm|powershell|cmd|python\d?|perl|sleep)\b[^\n]{0,80}
        (?:/etc/|/bin/|\|\s*(?:sh|bash|nc)|\bhttp|\s-\w|\d|;|$)
    |\$\(\s*(?:id|whoami|uname|cat|ls|pwd|echo|curl|wget|nc|sleep|ping|hostname|printf|sh|bash|base64|env)\b[^)\n]{0,60}\)
    |(?<!`)`\s*(?:id|whoami|uname|cat|ls|pwd|echo|curl|wget|nc|sleep|ping|hostname|printf|sh|bash|base64|env)\b[^`\n]{0,60}`(?!`)
    |\$\{?IFS\}?
    |(?<!\#!)/bin/(?:ba|z)?sh\b|\bnc\s+(?:-\w+\s+)*[\w.-]+\s+\d{2,5}\b|\b(?:bash|sh)\s+-i\b
    # --- SSTI
    |\{\{[^}\n]{0,200}(?:__\w+__|\bconfig\b|\bself\b|lipsum|cycler|\brequest\b|\d+\s*\*\s*\d+)[^}\n]{0,200}\}\}
    |\$\{[^}\n]{0,200}(?:\d+\s*\*\s*\d+|Runtime|exec|__\w+__|System)[^}\n]{0,200}\}
    |<%=?[^%\n]{0,200}%>|\{%[^%\n]{0,200}%\}|\#\{[^}\n]{0,100}\}
    """,
    re.I | re.X,
)


def has_strong_marker(text: str) -> bool:
    """Does `text` carry a strong injection marker (cheap, regex only)?"""
    return bool(text) and bool(_STRONG.search(text[: 4 * MAX_LINE]))


def _decode(s: str) -> str:
    return _t._decode(s) if "%" in s or "+" in s else s


def waf_gate_parts(text: str) -> list[str]:
    """Lines (decoded, capped) of `text` that carry a strong injection marker; [] if none."""
    if not text:
        return []
    s = text[:MAX_SCAN_CHARS]
    if "%" in s:
        s = _decode(s)
    parts: list[str] = []
    for line in s.splitlines() or [s]:
        for seg in (line.split("&") if "=" in line and "&" in line and len(line) < MAX_LINE else [line]):
            m = _STRONG.search(seg[: 4 * MAX_LINE])
            if not m:
                continue
            lo = max(0, m.start() - 300)
            val = seg[lo: lo + MAX_LINE]
            if "=" in val[:60] and len(val) < MAX_LINE and re.match(r"^[\w.\[\]-]{1,40}=", val):
                val = val.split("=", 1)[1]  # score the value, as for query targets
            parts.append(val.strip())
            if len(parts) >= MAX_PARTS:
                return parts
    return parts
