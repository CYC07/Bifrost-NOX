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
    r"""\bunion\s+(?:all\s+)?select\b|\bselect\s.{1,200}?\sfrom\b|\bdrop\s+table\b|\binsert\s+into\b|"""
    r"""\bdelete\s+from\b|\bsleep\s*\(|\bbenchmark\s*\(|\bxp_cmdshell\b|\bexec\s*\(|"""
    # quote-free SQL injection: numeric tautologies, column probing, comments used as whitespace
    r"""\b(?:or|and)\s+\d+\s*=\s*\d+|\border\s+by\s+\d+\b|\bhaving\s+\d+\s*=|/\*""",
    re.I,
)
_PLAIN_URL = re.compile(r"""^(?!.*\$[({])(?:https?|ftp)://[^\s'"<>`;|{}\\]+$""", re.I)
_TRAVERSAL = re.compile(
    r"(?:\.\.[/\\]+){2,}"                          # ../../
    r"|(?:\.{2,8}[/\\]{1,4}){2,}"                  # ....//....//  (survives a one-pass '../' strip); bounded = linear time
    r"|(?:\ufffd{2,8}[/\\]{1,4}){2,}"              # overlong UTF-8 dots (%c0%ae%c0%ae/) decode to U+FFFD
    r"|(?:^|[/\\])\.\.[/\\]+(?:etc|windows|winnt|boot|proc|root|home|var)\b", re.I)
# a sensitive file only counts as a whole path segment (so /docs/etc/hosts-file-explained is not one)
_SENSITIVE = re.compile(
    r"(?:^|[/\\=:])(?:"
    r"etc[/\\]+(?:passwd|shadow|group|hosts|sudoers|hostname|fstab|crontab)(?![\w-])"
    r"|proc[/\\]+self[/\\]+(?:environ|cmdline|maps|status)(?![\w-])"
    r"|var[/\\]+log[/\\]+(?:auth\.log|secure|syslog|messages)(?![\w-])"
    r"|(?:root[/\\]+)?\.ssh[/\\]+(?:id_rsa|id_dsa|id_ecdsa|id_ed25519|authorized_keys)(?![\w-])"
    r"|windows[/\\]+win\.ini(?![\w-])|windows[/\\]+system32[/\\]+config[/\\]+(?:sam|system|security)(?![\w-])"
    r"|boot\.ini(?![\w-])|web-inf[/\\]+web\.xml(?![\w-])|\.git[/\\]+(?:config|head)(?![\w-])|\.env(?![\w-])"
    r")", re.I)


def _decode(s: str) -> str:
    """Percent-decode until stable, at most 4 layers (catches %252e%252e%252f and triple encoding); '+' becomes a space."""
    for _ in range(4):
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


_MAX_COLLECT = 512          # candidates examined before ranking (bounds the work an attacker can force)
TAIL_CHARS = 1500


def _value_parts(v: str) -> list[str]:
    """What the model is shown of one value: its first MAX_VALUE_CHARS, plus - when the value is longer - its
    last TAIL_CHARS if that tail is attack-shaped, so a payload placed after long padding is still offered."""
    out = [v[:MAX_VALUE_CHARS]]
    if len(v) > MAX_VALUE_CHARS:
        tail = v[-TAIL_CHARS:]
        if worth_scoring(tail):
            out.append(tail)
    return out


def _prioritise(parts: list[str]) -> list[str]:
    """Strong-marker parts first (stable), then the rest, capped at MAX_VALUES: harmless-but-active padding
    (O'Brien, prices, code comments) must not push the real payload past the cap."""
    from ml.waf.gate import has_strong_marker   # lazy: gate imports this module
    flags = [has_strong_marker(p[:MAX_VALUE_CHARS]) for p in parts]          # once per part, on the part's first 2000 chars
    strong = [p for p, f in zip(parts, flags) if f]
    rest = [p for p, f in zip(parts, flags) if not f]
    return (strong + rest)[:MAX_VALUES]


def _name_and_path_parts(path: str, query: str) -> list[str]:
    """Parameter NAMES and decoded path segments, kept only when they carry a strong injection marker: servers
    read both as input too, but inspecting every ordinary name/segment would cost precision."""
    from ml.waf.gate import has_strong_marker   # lazy: gate imports this module
    out: list[str] = []
    for part in query.split("&"):
        name, eq, _ = part.partition("=")
        if eq and name:
            n = _decode(name)
            if has_strong_marker(n):
                out.append(n[:MAX_VALUE_CHARS])
    for seg in path.split("/"):
        if seg:
            d = decode_text(seg)
            if has_strong_marker(d):
                out.append(d[:MAX_VALUE_CHARS])
    return out


def waf_values(target: str) -> list[str]:
    """Decoded query values that deserve a WAF-model look (active, not a plain URL), ranked, capped.
    Also parameter names and path segments that carry a strong injection marker."""
    path, query = _split(target)
    keep: list[str] = _name_and_path_parts(path, query)
    for v in _values(query):
        if not v.strip() or _PLAIN_URL.match(v) or not _ACTIVE.search(v):
            continue
        keep.extend(_value_parts(v))
        if len(keep) >= _MAX_COLLECT:
            break
    return _prioritise(keep)


_ESCAPE = re.compile(r"%[0-9a-fA-F]{2}")
_PATH_PREFIX = re.compile(r"^[^\s=&?#]*\?")
_FORM_START = re.compile(r"^[\w.\[\]-]{1,128}=")


def worth_scoring(v: str) -> bool:
    """Is this decoded value attack-shaped enough to show the model? An active character or SQL
    phrase, a traversal / sensitive-file signature, or undecodable bytes (overlong %c0%af
    sequences decode to U+FFFD). Plain words, paths and URLs are left alone."""
    return bool(_ACTIVE.search(v) or "\ufffd" in v or _TRAVERSAL.search(v) or _SENSITIVE.search(v))


def is_plain_url(v: str) -> bool:
    """An ordinary http(s)/ftp URL with no active characters (never worth a model look)."""
    return bool(_PLAIN_URL.match(v))


def has_escapes(s: str) -> bool:
    """True when `s` carries %XX escapes (so decoding it can change what the WAF sees)."""
    return bool(_ESCAPE.search(s or ""))


def decode_text(s: str) -> str:
    """Percent-decode until stable (at most 4 layers) WITHOUT turning '+' into a space (free text keeps its '+')."""
    from urllib.parse import unquote
    for _ in range(4):
        d = unquote(s, errors="replace")
        if d == s:
            break
        s = d
    return s


def _form_part(body: str) -> str | None:
    """The `k=v&k=v` part of a body (a leading `/path?` is dropped), or None if not form-shaped."""
    t = (body or "")[:_MAX_TARGET].lstrip("&\r\n\t ")
    m = _PATH_PREFIX.match(t)
    if m:
        t = t[m.end():]
    return t if _FORM_START.match(t) else None


def is_form(body: str) -> bool:
    return _form_part(body) is not None


def body_values(body: str) -> list[str]:
    """Decoded, attack-shaped values of a urlencoded-looking body (`a=1&q=...`, optionally with a
    leading `/path?`). Same precision filter as waf_values (an active character or SQL phrase,
    not a plain URL), capped. [] when the body is not key=value shaped."""
    t = _form_part(body)
    if t is None:
        return []
    keep: list[str] = []
    for part in t.split("&"):
        _, eq, raw = part.partition("=")
        if not eq or not raw:
            continue
        v = _decode(raw)
        if not v.strip() or _PLAIN_URL.match(v) or not worth_scoring(v):
            continue
        keep.extend(_value_parts(v))
        if len(keep) >= _MAX_COLLECT:
            break
    return _prioritise(keep)


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
    from ml.waf.signatures import signature_hits as attack_signatures   # lazy: signatures imports this module
    return bool(signature_hits(target) or waf_values(target) or secret_hits(target) or attack_signatures(target))
