"""Scanner / recon-tool detection from request HEADERS.

The WAF model only sees bodies and request targets, but a vulnerability scanner announces itself in the
User-Agent header (and a few scanner-only headers), so the model's `scanner` class could never fire in
production. This module is the deterministic replacement: a precise list of tool names matched on token
boundaries ("NucleiViewer" and "sqlmapper" are not scanners), no model, no network.

Deliberately NOT matched: generic HTTP clients (curl, wget, python-requests, Go-http-client, Postman), search
and uptime bots, and proxies a pentester drives a browser through (Burp, ZAP send the browser's own UA).
Policy (SCANNER_UA_POLICY): block (default) | advisory (log only) | off.
"""
from __future__ import annotations

import os
import re

MAX_UA_CHARS = 8192            # real User-Agents are < 300 chars; scanned linearly, so padding it is not a bypass

# tool name -> the form reported in the verdict (lower case). Token-bounded below.
_TOOLS = [
    "sqlmap", "nikto", "nmap scripting engine", "nmap", "masscan", "zgrab", "censysinspect", "dirbuster", "dirsearch",
    "gobuster", "wfuzz", "ffuf", "feroxbuster", "nuclei", "acunetix", "netsparker", "appscan", "webinspect", "nessus",
    "openvas", "qualys", "w3af", "arachni", "skipfish", "wapiti", "whatweb", "wpscan", "joomscan", "droopescan",
    "cmsmap", "commix", "sqlninja", "havij", "jaeles", "paros", "n-stalker", "morfeus", "uniscan",
    # exploit / injection / fuzzing tools
    "bfac", "detectify", "dotdotpwn", "ghauri", "kadimus", "lfisuite", "lfimap", "fimap", "sstimap", "tinja", "tplmap",
    "xsser", "xsstrike", "jsql", "jbrofuzz", "libwhisker", "zmeu", "webshag", "webbandit", "whatwaf", "wprecon", "wpprobe",
    "shortscan", "graphql-cop", "graphw00f", "nettacker", "appspider", "ironwasp", "tsunamisecurityscanner", "qualysguard",
    "l9explore", "l9tcpid", "jorgee", "bewica-security-scan", "yeswehack-hunter", "fuzz faster u fool", "(hydra)",
]
_UA = re.compile(r"(?<![a-z0-9])(" + "|".join(re.escape(t).replace(r"\ ", r"\s+") for t in sorted(_TOOLS, key=len, reverse=True))
                 + r")(?![a-z0-9])", re.I)
# request headers only scanners send
_SCANNER_HEADERS = ("acunetix-aspect", "acunetix-aspect-password", "acunetix-aspect-queries", "x-scan-memo")


def scanner_policy() -> str:
    """block (default) | advisory | off; anything else means block."""
    v = os.environ.get("SCANNER_UA_POLICY", "block").strip().lower()
    return v if v in ("block", "advisory", "off") else "block"


def scanner_signature(headers) -> str | None:
    """Name of the scanner identified by the request headers, or None. Never raises."""
    try:
        if not isinstance(headers, dict):
            return None
        lowered = {}
        for k, v in headers.items():
            if isinstance(k, str):
                lowered[k.lower()] = v
        for h in _SCANNER_HEADERS:
            if h in lowered:
                return h
        ua = lowered.get("user-agent")
        if isinstance(ua, (bytes, bytearray)):
            ua = bytes(ua).decode("latin-1", "replace")
        if not isinstance(ua, str) or not ua:
            return None
        m = _UA.search(ua[:MAX_UA_CHARS])
        return re.sub(r"\s+", " ", m.group(1).lower()) if m else None
    except Exception:  # noqa: BLE001 - a detector bug must never break request handling
        return None
