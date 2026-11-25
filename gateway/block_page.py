"""The page the gateway serves when it blocks a request (HTTP 403), in the Bifrost NØX brand-kit style (mockup M2).

Design constraints, because this page is served on whatever site was blocked:
  * Fully self-contained: inline CSS, inline SVG, one tiny inline script. Nothing is loaded from outside (the client
    may be offline, and any fetch would go through the firewall again). A strict CSP enforces that.
  * Every value that came off the wire (host, reason, client address) is HTML-escaped and length-limited.
  * It only states what the gateway really knows: the detector module(s), the direction, the client address, the
    time and a fresh request id (logged by the gateway, so IT can look it up). The mockup's "prompt-guard 3.2 ·
    score 0.97" and client host name do not exist here, so they are not shown.
"""
from __future__ import annotations

import base64
import hashlib
import html as _html
import os
import re
import secrets
import sys
from dataclasses import dataclass, field
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.threat_taxonomy import classify_reason  # noqa: E402

# ---------------------------------------------------------------- verdict carrying the reason

class BlockVerdict(str):
    """What inspect_full returns for a block. It IS the string "block" (every existing `== "block"` check keeps
    working) and also carries why, so the page can explain it."""

    def __new__(cls, reason: str = "", category: str | None = None, detector: str | None = None):
        obj = super().__new__(cls, "block")
        obj.reason = reason or ""
        obj.category = category
        obj.detector = detector
        return obj


# ---------------------------------------------------------------- wording per category
# category -> (chip label, sentence when the user was SENDING, sentence when a RESPONSE was blocked)
_TEXT: dict[str, tuple[str, str, str]] = {
    "Prompt Injection": ("PROMPT INJECTION", "The text you were sending matched a prompt-injection pattern.",
                         "The content matched a prompt-injection pattern."),
    "SQL Injection": ("SQL INJECTION", "The request matched a SQL-injection pattern.",
                      "The content matched a SQL-injection pattern."),
    "Cross-Site Scripting": ("CROSS-SITE SCRIPTING", "The request matched a cross-site-scripting pattern.",
                             "The content matched a cross-site-scripting pattern."),
    "Command Injection": ("COMMAND INJECTION", "The request matched a command-injection pattern.",
                          "The content matched a command-injection pattern."),
    "Web Attack": ("WEB ATTACK", "The request matched a known web-attack pattern.",
                   "The content matched a known web-attack pattern."),
    "Malicious Request Target": ("MALICIOUS REQUEST", "The address you requested contained a known attack pattern.",
                                 "The address contained a known attack pattern."),
    "Secret Leak": ("SECRET LEAK", "The text you were sending appeared to contain a secret or credential.",
                    "The content appeared to contain a secret or credential."),
    "API Key Leak": ("API KEY LEAK", "The text you were sending appeared to contain an API key.",
                     "The content appeared to contain an API key."),
    "PII Exposure": ("PERSONAL DATA", "The text you were sending appeared to contain personal data.",
                     "The content appeared to contain personal data."),
    "PII Exfiltration": ("PERSONAL DATA", "The text you were sending appeared to contain personal data.",
                         "The content appeared to contain personal data."),
    "Data Loss Prevention": ("DATA LOSS PREVENTION", "The text you were sending matched a data-loss rule.",
                             "The content matched a data-loss rule."),
    "Malware Payload": ("MALWARE", "What you were sending matched a malware signature.",
                        "The content matched a malware signature."),
    "EICAR Test Signature": ("TEST MALWARE SIGNATURE", "What you were sending matched the EICAR antivirus test signature.",
                             "The content matched the EICAR antivirus test signature."),
    "Phishing Attempt": ("PHISHING", "The request looked like a phishing attempt.",
                         "The content looked like a phishing attempt."),
    "NSFW Content": ("UNSAFE CONTENT", "The content you were sending was flagged as unsafe.",
                     "The content was flagged as unsafe."),
    # gateway-originated categories (set by the gateway itself, not by an analyzer reason)
    "Scanner Tool": ("SCANNER TOOL", "The request came from a known scanning or attack tool.",
                     "The request came from a known scanning or attack tool."),
    "Scanner Behaviour": ("SCANNER BEHAVIOUR", "The pattern of requests looked like automated scanning.",
                          "The pattern of requests looked like automated scanning."),
    "Executable File": ("EXECUTABLE FILE", "What you were sending contained an executable file.",
                        "The content contained an executable file."),
    "Legacy Office File": ("LEGACY OFFICE FILE",
                           "What you were sending contained a legacy Office file, a common carrier for macros.",
                           "The content contained a legacy Office file, a common carrier for macros."),
    "High-Entropy Content": ("PACKED OR ENCRYPTED DATA", "What you were sending looked packed or encrypted.",
                             "The content looked packed or encrypted."),
    "Anomalous Content": ("SUSPICIOUS CONTENT", "The content was flagged as suspicious.",
                          "The content was flagged as suspicious."),
}


def category_for(reason: str) -> str:
    return classify_reason(reason)[0]


def detectors_for(reason: str) -> tuple[str, ...]:
    """Analyzer module names from a "Blocked by: a, b" reason; empty when the reason is a plain sentence."""
    m = re.match(r"\s*Blocked by:\s*(.+)$", reason or "", re.S)
    if not m:
        return ()
    return tuple(t for t in (x.strip() for x in m.group(1).split(",")) if re.fullmatch(r"[\w.\- ]{1,40}", t))[:6]


def new_request_id() -> str:
    h = secrets.token_hex(6)
    return f"nox-{h[0:4]}-{h[4:8]}-{h[8:12]}"


def _fail_closed() -> bool:
    return os.environ.get("AI_FAIL_MODE", "open").strip().lower() == "closed"


@dataclass(frozen=True)
class BlockInfo:
    reason: str = ""
    direction: str = "outbound"            # "outbound" = the user's request, "inbound" = a server's response
    host: str = ""
    client_ip: str = ""
    request_id: str = field(default_factory=new_request_id)
    when: datetime = field(default_factory=lambda: datetime.now().astimezone())
    is_https: bool = False
    fail_closed: bool = field(default_factory=_fail_closed)
    category: str = ""
    detectors: tuple = ()

    def __post_init__(self):
        if not self.category:
            object.__setattr__(self, "category", category_for(self.reason))
        if not self.detectors:
            object.__setattr__(self, "detectors", detectors_for(self.reason))

    @classmethod
    def from_verdict(cls, verdict, *, host="", direction="outbound", client_ip="", is_https=False, **kw):
        reason = getattr(verdict, "reason", "") or ""
        category = getattr(verdict, "category", None) or category_for(reason)
        detector = getattr(verdict, "detector", None)
        detectors = (detector,) if detector else detectors_for(reason)
        return cls(reason=reason, direction=direction, host=host, client_ip=client_ip, is_https=is_https,
                   category=category, detectors=detectors, **kw)


# ---------------------------------------------------------------- artwork (kit files, metadata stripped, inlined)

_VERDICT = ('<path fill="#A85A45" d="M64.6 424.6L154.6 334.6L145.4 325.4L55.4 415.4Z"/>'
            '<path fill="#B08A3E" d="M154.6 334.6L244.6 244.6L235.4 235.4L145.4 325.4Z"/>'
            '<path fill="#6B8E5A" d="M244.6 244.6L334.6 154.6L325.4 145.4L235.4 235.4Z"/>'
            '<path fill="#5E7A8E" d="M334.6 154.6L424.6 64.6L415.4 55.4L325.4 145.4Z"/>')
_DISC = ('d="M93.84 361.4L361.4 93.84A190 190 0 0 0 93.84 361.4ZM118.6 386.16L386.16 118.6'
         'A190 190 0 0 1 118.6 386.16Z"')


def _logo(css_class: str, disc_fill: str) -> str:
    return (f'<svg class="logo {css_class}" viewBox="50 50 380 380" role="img" aria-label="Bifrost NØX">'
            f'<path fill="{disc_fill}" {_DISC}/>{_VERDICT}</svg>')


_FAVICON = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><style>path{fill:#1A1714}'
            '@media (prefers-color-scheme:dark){path{fill:#FAF8F4}}</style>'
            '<path d="M2.04 12.55L12.55 2.04A7.5 7.5 0 0 0 2.04 12.55ZM3.45 13.96L13.96 3.45A7.5 7.5 0 0 1 3.45 13.96Z"/></svg>')
_FAVICON_URI = "data:image/svg+xml;base64," + base64.b64encode(_FAVICON.encode()).decode()

_ARROW = ('<svg class="arrow" viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">'
          '<path d="M13 8H3M7 4L3 8l4 4" fill="none" stroke="currentColor" stroke-width="1.6" '
          'stroke-linecap="round" stroke-linejoin="round"/></svg>')

_SCRIPT = (
    "(function(){var b=document.getElementById('back');"
    "if(b)b.addEventListener('click',function(){if(history.length>1)history.back();else window.close();});"
    "var r=document.getElementById('review');"
    "if(r&&r.tagName==='BUTTON')r.addEventListener('click',function(){var id=r.getAttribute('data-id');"
    "var fb=function(){r.textContent='Quote '+id+' to IT Security';};"
    "if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(id).then("
    "function(){r.textContent='Request ID copied \\u2014 quote it to IT Security';},fb);}else{fb();}});})();"
)
_SCRIPT_HASH = base64.b64encode(hashlib.sha256(_SCRIPT.encode("utf-8")).digest()).decode()

_CSP = ("default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
        f"script-src 'sha256-{_SCRIPT_HASH}'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")

_CSS = """
:root{--paper:#FAF8F4;--paper2:#F4F0E8;--border:#E5DFD2;--ink:#1A1714;--ink3:#6B6357;--ink4:#9A9083;
--block:#A85A45;--chip:#F1DFD7;--surface:#FFFFFF;
--sans:Archivo,"Helvetica Neue",Helvetica,Arial,"Segoe UI",system-ui,sans-serif;
--mono:"IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace}
@media (prefers-color-scheme: dark){:root{--paper:#16130F;--paper2:#1E1A15;--border:#2B251E;--ink:#FAF8F4;
--ink3:#B9B0A2;--ink4:#8A8173;--block:#E0917A;--chip:#2E1F1A;--surface:#1E1A15}}
*{box-sizing:border-box}
html{background:var(--paper)}
body{margin:0;background:var(--paper);color:var(--ink);font-family:var(--sans);-webkit-font-smoothing:antialiased}
.wrap{max-width:600px;margin:0 auto;padding:clamp(40px,12vh,112px) 24px 56px}
.logo{width:44px;height:44px;display:block}
.logo-dark{display:none}
@media (prefers-color-scheme: dark){.logo-light{display:none}.logo-dark{display:block}}
.chip{display:inline-block;margin:32px 0 18px;padding:4px 8px;border-radius:3px;background:var(--chip);color:var(--block);
font:500 11px/1.2 var(--mono);letter-spacing:.08em}
h1{margin:0 0 14px;font-size:clamp(30px,6vw,42px);line-height:1.08;font-weight:800;letter-spacing:-.025em}
.lead{margin:0 0 30px;max-width:520px;font-size:16px;line-height:1.5;color:var(--ink3)}
dl.facts{margin:0 0 30px;border-top:1px solid var(--border)}
dl.facts div{display:flex;gap:16px;align-items:baseline;padding:11px 0;border-bottom:1px solid var(--border)}
dt{flex:0 0 112px;font:500 10px/1.4 var(--mono);letter-spacing:.1em;color:var(--ink4)}
dd{margin:0;min-width:0;overflow-wrap:anywhere;font:12.5px/1.45 var(--mono);color:var(--ink)}
.actions{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:28px}
.btn{display:inline-flex;align-items:center;gap:8px;height:38px;padding:0 16px;border-radius:6px;cursor:pointer;
font:500 13px/1 var(--sans);text-decoration:none;border:1px solid var(--border);background:var(--surface);color:var(--ink)}
.btn.primary{background:var(--ink);border-color:var(--ink);color:var(--paper)}
.btn:hover{filter:brightness(.97)}.btn.primary:hover{filter:brightness(1.18)}
.btn:focus-visible{outline:2px solid var(--block);outline-offset:2px}
.note{margin:0;font:11.5px/1.7 var(--mono);color:var(--ink4)}
@media (max-width:480px){dl.facts div{flex-direction:column;gap:2px}dt{flex-basis:auto}}
"""


def _safe_review_url() -> str:
    url = os.environ.get("BLOCK_REVIEW_URL", "").strip()
    if re.fullmatch(r"mailto:[^\s\"'<>]{3,300}|https?://[^\s\"'<>]{3,500}", url):
        return url
    return ""


def _e(value, limit: int) -> str:
    return _html.escape(str(value if value is not None else "")[:limit], quote=True)


def render_block_page(info: BlockInfo) -> str:
    outbound = info.direction != "inbound"
    chip, out_sentence, in_sentence = _TEXT.get(info.category) or (
        info.category.upper()[:40], "The content was flagged by the firewall.", "The content was flagged by the firewall.")
    host = _e(info.host or "the server", 100)
    lead = (f"Your request to {host} was stopped before it left the network. {_e(out_sentence, 200)}" if outbound else
            f"A response from {host} was stopped before it reached your device. {_e(in_sentence, 200)}")
    detector = ", ".join(_e(d, 40) for d in info.detectors) or "inspection engine"
    policy = "Block on detection · " + ("outbound request" if outbound else "inbound response")
    when = info.when.strftime("%d %b %Y · %H:%M:%S %Z").strip()
    review_url = _safe_review_url()
    rid = _e(info.request_id, 40)
    review = (f'<a id="review" class="btn" href="{_html.escape(review_url, quote=True)}">Request a review</a>' if review_url
              else f'<button id="review" class="btn" type="button" data-id="{rid}">Request a review</button>')
    footer2 = ("Bifrost NØX fails closed — if inspection is unavailable, traffic is held." if info.fail_closed else
               "Bifrost NØX fails open — if inspection is ever unavailable, traffic passes.")
    rows = (("DETECTOR", detector), ("POLICY", policy), ("REQUEST ID", rid), ("TIME", _e(when, 60)),
            ("CLIENT", _e(info.client_ip or "unknown", 64)))
    facts = "".join(f"<div><dt>{k}</dt><dd>{v}</dd></div>" for k, v in rows)
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">'
        '<meta name="color-scheme" content="light dark"><title>Blocked — Bifrost NØX</title>'
        f'<link rel="icon" type="image/svg+xml" href="{_FAVICON_URI}"><style>{_CSS}</style></head><body>'
        f'<main class="wrap">{_logo("logo-light", "#1A1714")}{_logo("logo-dark", "#FAF8F4")}'
        f'<p class="chip">BLOCK · {_e(chip, 48)}</p><h1>Blocked by Bifrost NØX</h1><p class="lead">{lead}</p>'
        f'<dl class="facts">{facts}</dl>'
        f'<div class="actions"><button id="back" class="btn primary" type="button">{_ARROW}Go back</button>{review}</div>'
        '<p class="note">If this looks wrong, ask IT Security to review it and quote the request ID.<br>'
        f'{footer2}</p></main><script>{_SCRIPT}</script></body></html>'
    )


def render_block_response(info: BlockInfo | None = None) -> bytes:
    """The complete HTTP response (status line, headers, page). `None` gives the generic page."""
    info = info or BlockInfo()
    body = render_block_page(info).encode("utf-8")
    head = (
        "HTTP/1.1 403 Forbidden\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Cache-Control: no-store\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "Referrer-Policy: no-referrer\r\n"
        f"Content-Security-Policy: {_CSP}\r\n"
        f"X-Bifrost-Request-Id: {re.sub(r'[^A-Za-z0-9-]', '', info.request_id)[:40]}\r\n"
        "Connection: close\r\n\r\n"
    )
    return head.encode("latin-1") + body
