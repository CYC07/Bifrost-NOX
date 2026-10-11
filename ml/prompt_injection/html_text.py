"""Reduce an HTML document to the text a language model would actually read.

The prompt-injection classifier was trained on prose; fed raw markup, CSS and JS
it scores nearly any web page as INJECTION (example.com's boilerplate: 0.999).
So HTML is reduced to: visible text nodes, comments, and text-bearing attributes
(alt/title/aria-label/placeholder/<meta content>). Comments and attributes are
kept deliberately: hidden text is the classic delivery route for *indirect*
prompt injection. <script>/<style> bodies are code, not language, and are dropped.

Non-HTML input is returned unchanged.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser

_LOOKS_LIKE_HTML = re.compile(r"<\s*(!doctype|html|head|body|div|p|span|a|img|script|style|meta|title|table|ul|ol|h[1-6])\b", re.I)
_TEXT_ATTRS = {"alt", "title", "aria-label", "placeholder", "content", "label"}
_SKIP_TAGS = {"script", "style"}
_PROSE_META = {"description", "keywords", "title", "subject", "abstract", "summary"}


class _Collector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag in _SKIP_TAGS:
            self._skip_depth += 1
        # <meta content=...> is only prose for description-like tags; viewport,
        # robots, theme-color etc. are layout/config strings, not language.
        meta_ok = True
        if tag == "meta":
            a = {k: (v or "").lower() for k, v in attrs}
            key = a.get("name") or a.get("property") or ""
            meta_ok = key in _PROSE_META or key.startswith(("og:", "twitter:"))
        for name, value in attrs:
            if name not in _TEXT_ATTRS or not value or not value.strip():
                continue
            if name == "content" and not meta_ok:
                continue
            self.parts.append(value.strip())

    def handle_endtag(self, tag):
        if tag in _SKIP_TAGS and self._skip_depth:
            self._skip_depth -= 1

    def handle_data(self, data):
        if not self._skip_depth and data.strip():
            self.parts.append(data.strip())

    def handle_comment(self, data):
        if data.strip():
            self.parts.append(data.strip())


def extract_text(text: str) -> str:
    if not text or not _LOOKS_LIKE_HTML.search(text):
        return text
    try:
        c = _Collector()
        c.feed(text)
        c.close()
    except Exception:  # noqa: BLE001 — malformed markup must never break inspection
        return text
    return " ".join(c.parts)
