"""Signatures for attack classes the WAF model has no label for.

The model's taxonomy is a contract with its trained weights (7 labels), so classes outside it - SSRF, XML external
entities, CRLF / response splitting, NoSQL operator injection, JNDI (Log4Shell) and Java/.NET/Python deserialization,
Shellshock, prototype pollution, LDAP and SSI/ESI injection - are covered here by precise regular expressions.

Precision first, like ml/waf/target.py: each rule needs the attack-specific shape rather than a topic word, so an XHTML
DOCTYPE, `localhost` URLs, LDAP URLs in a config, Mongo `{"$gt": 0}` queries and code containing `() { }` pass.
Every quantifier is bounded (no catastrophic backtracking) and input is capped, so it is safe on hostile bodies.
Pure functions, no model or network imports. Policy: WAF_SIGNATURES = block (default) | advisory | off.
"""
from __future__ import annotations

import html
import os
import re

from ml.waf.target import decode_text

HEAD_CHARS, TAIL_CHARS = 100_000, 50_000
_I = re.I

_RULES: dict[str, list[re.Pattern]] = {
    "ssrf": [
        # cloud metadata endpoints (AWS/GCP/Azure/Alibaba/ECS/Oracle/Equinix/Tencent)
        re.compile(r"(?<![\d.])(?:169\.254\.169\.254|169\.254\.170\.2|100\.100\.100\.200|192\.0\.0\.192)(?!\d)|metadata\.google\.internal|metadata\.azure\.com"
                   r"|metadata\.packet\.net|metadata\.platformequinix\.com|metadata\.tencentyun\.com|fd00:ec2::254", _I),
        # protocol smuggling schemes
        re.compile(r"\b(?:gopher|dict|tftp|netdoc)://", _I),
        # an address written to dodge naive filters, after any scheme://: hex (whole or per octet), octal, decimal dword,
        # mixed (169.254.43518), short loopback, IPv4-mapped / unspecified / link-local / unique-local IPv6
        re.compile(r"\b[a-z][a-z0-9+.-]{1,12}://(?:0x[0-9a-f]{1,16}(?:\.0x[0-9a-f]{1,8}){0,3}(?![\w])|0\d{2,6}\.\d{1,7}\.\d{1,7}\.\d{1,7}(?![\d])|0[0-7]{9,12}(?![\d.])"
                   r"|\d{8,10}(?![\d.])|\d{1,3}\.\d{6,9}(?![\d.])|\d{1,3}\.\d{1,3}\.\d{4,6}(?![\d.])|127\.1(?![\d.])"
                   r"|\[(?:(?:0:){5}ffff:|::ffff:|::\]|fe80:|f[cd][0-9a-f]{2}:)[0-9a-f.:%]{0,40}\]?)", _I),
        # the same addresses after http(s): with zero or one slash (scheme confusion); tel: and other schemes are left alone
        re.compile(r"\bhttps?:/?(?:0x[0-9a-f]{6,16}|\d{8,10}(?![\d.])|0\d{2,6}\.\d{1,7}\.\d{1,7}\.\d{1,7}|0[0-7]{9,12}|\[::ffff:[0-9a-f:.]{3,20}\]|127\.0\.0\.1)", _I),
        # lookalike characters in the authority: enclosed alphanumerics, fullwidth forms, ideographic full stop
        re.compile(r"\b[a-z][a-z0-9+.-]{1,12}://[^/\s?#]{0,80}[\u2460-\u24ff\uff00-\uffef\u3002]", _I),
    ],
    "xxe": [
        re.compile(r"<!DOCTYPE[^>\[]{0,300}\[[^\]]{0,600}?<!ENTITY\s+(?:%\s+)?[\w.:-]{1,40}\s+(?:SYSTEM|PUBLIC)\b", _I),
        re.compile(r"<!ENTITY\s+%\s*[\w.:-]{1,40}\s+(?:SYSTEM|PUBLIC)\b", _I),
        re.compile(r"<xi:include\b[^>]{0,300}\bhref\s*=", _I),
    ],
    "crlf": [   # percent-encoded or JSON-escaped line breaks followed by a header name; matched on the RAW text only
        re.compile(r"(?:%0d|%0a|\\r|\\n){1,8}\s*(?:set-cookie|location|content-(?:length|type)|refresh|transfer-encoding|remote-addr|x-forwarded-(?:for|host)|x-real-ip)\s*(?::|%3a)", _I),
        re.compile(r"(?:^|[?&])[^=&#\s]{0,100}(?:%0d|%0a)", _I),         # a line break inside a parameter NAME is never legitimate
        re.compile(r"(?:%0d%0a|%0a){2}\s*<(?:html|script|svg)", _I),
    ],
    "nosqli": [
        re.compile(r"\[\$(?:ne|nin|gt|gte|lt|lte|regex|where|exists|or|and|nor|in|expr)\]", _I),
        re.compile(r'"(?:user(?:name)?|login|email|pass(?:word)?|pwd|token|key|secret)"\s*:\s*\{\s*"\$(?:ne|nin|gt|gte|lt|lte|regex|exists|in)"', _I),
        re.compile(r'"\$(?:where|function|accumulator)"\s*:\s*"', _I),
    ],
    "jndi": [re.compile(r"\$\{\s*jndi\s*:", _I)],        # after the lookup obfuscations are unwrapped (see _unwrap_lookups)
    "deserialization": [
        re.compile(r"\brO0AB[A-Za-z0-9+/]+"), re.compile("\u00ac\u00ed\x00?\x05"), re.compile(r"AAEAAAD/{5}"), re.compile(r"\baced0005[0-9a-f]{2,}", _I), re.compile(r"%ac%ed%00%05", _I),
        re.compile(r"!!python/(?:object|name|module)"), re.compile(r"_\$\$ND_FUNC\$\$_"),
        re.compile(r"(?:^|\n)c(?:os|posix|nt|subprocess|builtins|__builtin__)\n(?:system|popen|eval|exec|getoutput|call)\b"),
        re.compile(r"org\.apache\.commons\.collections\d?\.functors\.(?:InvokerTransformer|ChainedTransformer|ConstantTransformer)|com\.sun\.rowset\.JdbcRowSetImpl"
                   r"|com\.sun\.org\.apache\.xalan\.internal\.xsltc\.trax\.TemplatesImpl|\bysoserial\b|javax\.management\.BadAttributeValueExpException", _I),
    ],
    "shellshock": [
        re.compile(r"(?<![\w$)\]])\(\)\s*\{\s*[:_]\s*;\s*\}\s*(?:;|>)"),
        re.compile(r"(?<![\w$)\]])\(\)\s*\{\s*[\w ]{1,20};\s*\}\s*;\s*(?:/bin/|/usr/bin/|wget\b|curl\b|echo\b|cat\b|ping\b|nc\b)"),
    ],
    "prototype_pollution": [
        re.compile(r"""["']__proto__["']\s*:"""), re.compile(r"\[__proto__\]"), re.compile(r"(?:^|[&.?\s])__proto__(?:\.|\[|=)"),
        re.compile(r'"constructor"\s*:\s*\{\s*"prototype"'), re.compile(r"(?:^|[?&])constructor(?:\.|\[)prototype(?:\.|\]|\[)[\w.\[\]%-]*="), re.compile(r"\[constructor\]\[prototype\]"),
    ],
    "ldap": [
        re.compile(r"\*\)\s*\(\s*[|&]?\s*\(?\s*(?:uid|cn|objectclass|userpassword|mail)\s*=\s*\*", _I),
        re.compile(r"\(\s*\|\s*\(\s*(?:uid|cn|objectclass|userpassword|mail)\s*=\s*\*", _I),
        re.compile(r"[\w*]\)\(&\)"),
        lambda view: _ldap_unbalanced(view),
    ],
    "ssi": [
        re.compile(r"<!--\s*#\s*(?:exec|include|echo|config|fsize|flastmod|printenv|set)\b[^>]{0,300}-->", _I),
        re.compile(r"<esi:(?:include|inline|vars|try|eval)\b[^>]{0,300}>", _I),
    ],
}
_LDAP_INJ = re.compile(r"[\w*]\)+\s*(?:[!|&]\s*)?\(\s*(?:[|&!]|[a-z][\w.-]{0,24}\s*(?:~?=|[<>]=))", _I)


def _ldap_unbalanced(view: str) -> bool:
    """`value)(uid=*`: a `)` that closes a parenthesis nothing opened, followed by a new filter term. A legitimate
    filter such as (&(objectClass=person)(uid=jsmith)) is balanced, so it never matches."""
    for n, m in enumerate(_LDAP_INJ.finditer(view)):
        if n >= 50:
            break
        prefix = view[max(0, m.start() - 2000): m.start() + 1]
        if prefix.count("(") - prefix.count(")") <= 0:
            return True
    return False


_RAW_ONLY = {"crlf"}                     # these rules read the undecoded text (percent-encoded line breaks vanish when decoded)
_U00 = re.compile(r"\\u00([0-7][0-9a-fA-F])")
_LOOKUP = re.compile(r"\$\{(?:lower:|upper:|:+-|[a-z]{2,8}:[^{}$:]{0,20}:-)([^{}$]{0,3})\}", _I)


def signature_policy() -> str:
    """block (default) | advisory | off; anything else means block."""
    v = os.environ.get("WAF_SIGNATURES", "block").strip().lower()
    return v if v in ("block", "advisory", "off") else "block"


def _unwrap_lookups(s: str) -> str:
    """Log4Shell obfuscation: ${${lower:j}ndi:...}, ${${::-j}...}, ${${env:NaN:-j}...} -> ${jndi:...}."""
    for _ in range(4):
        n = _LOOKUP.sub(lambda m: m.group(1), s)
        if n == s:
            break
        s = n
    return s


def _views_of(text: str) -> list[str]:
    """The text as the server may finally see it: raw, percent-decoded, \\u00XX-unescaped and HTML-entity-decoded,
    applied repeatedly (so $\\u0026lbrace;jndi: and %26%2336%3B%7Bjndi: unwrap). Bounded: at most 8 distinct views."""
    views = [text]
    for _ in range(3):
        grew = False
        for v in list(views):
            for new in (decode_text(v) if "%" in v else v,
                        _U00.sub(lambda m: chr(int(m.group(1), 16)), v) if "\\u00" in v else v,
                        html.unescape(v) if "&" in v and ";" in v else v):
                if new != v and new not in views and len(views) < 8:
                    views.append(new)
                    grew = True
        if not grew:
            break
    return views


def signature_hits(text) -> list[str]:
    """Sorted names of the attack classes whose signature appears in `text` (raw or percent-decoded). Never raises."""
    try:
        if isinstance(text, (bytes, bytearray)):
            text = bytes(text).decode("utf-8", "replace")
        if not isinstance(text, str) or not text:
            return []
        if len(text) > HEAD_CHARS + TAIL_CHARS:
            text = text[:HEAD_CHARS] + "\n" + text[-TAIL_CHARS:]
        views = _views_of(text)
        views += [_unwrap_lookups(v) for v in views if "${" in v]
        hits: set[str] = set()
        for name, rules in _RULES.items():
            for i, view in enumerate(views):
                if name in _RAW_ONLY and i != 0:
                    continue
                if any((rx(view) if callable(rx) else rx.search(view)) for rx in rules):
                    hits.add(name)
                    break
        return sorted(hits)
    except Exception:  # noqa: BLE001 - a detector bug must never break request handling
        return []
