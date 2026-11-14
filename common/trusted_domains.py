"""Trusted-domain policy: traffic to these domains (and all their subdomains) is treated as normal.

A network firewall cannot see which process sent a packet, so "Windows' own processes" is
approximated by "Windows' own infrastructure domains". Matching is on DNS label boundaries
(`evilmicrosoft.com` and `microsoft.com.evil.test` do not match). Domains an outsider can register
a subdomain under (`*.blob.core.windows.net`, `azurewebsites.net`) are deliberately not listed.

Config: config/trusted_domains.json -> {"domains": [...]}; hot-reloaded on mtime change.
Missing/corrupt file -> shipped defaults. An explicit empty list disables the policy.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import threading

from common import ip_ranges

logger = logging.getLogger("trusted_domains")

VERIFY_IP = os.getenv("TRUSTED_VERIFY_IP", "1").strip().lower() not in ("0", "false", "off", "no")

_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "config", "trusted_domains.json"))
DEFAULT_DOMAINS = ("microsoft.com", "windows.com")

_lock = threading.Lock()
_cache: tuple[float | None, tuple[str, ...]] | None = None


def _reset_cache() -> None:
    global _cache
    with _lock:
        _cache = None


def _clean(entries) -> tuple[str, ...]:
    out = []
    for e in entries if isinstance(entries, list) else []:
        if not isinstance(e, str):
            continue
        e = e.strip().lower().rstrip(".")
        if e.startswith("*."):
            e = e[2:]
        if "." in e and not e.startswith(".") and "*" not in e and " " not in e:
            out.append(e)
    return tuple(dict.fromkeys(out))


def _domains() -> tuple[str, ...]:
    global _cache
    try:
        mtime = os.stat(_PATH).st_mtime
    except OSError:
        mtime = None
    with _lock:
        if _cache is not None and _cache[0] == mtime:
            return _cache[1]
        domains = DEFAULT_DOMAINS
        if mtime is not None:
            try:
                with open(_PATH) as f:
                    data = json.load(f)
                if isinstance(data, dict) and isinstance(data.get("domains"), list):
                    domains = _clean(data["domains"])
            except Exception as exc:
                logger.error(f"Failed to load trusted domains, using defaults: {exc}")
        _cache = (mtime, domains)
        return domains


def _normalise(host) -> str:
    if not isinstance(host, str):
        return ""
    h = host.strip().lower()
    if not h or h.startswith("["):
        return ""
    if ":" in h:
        h, port = h.rsplit(":", 1)
        if not port.isdigit():
            return ""
    h = h.rstrip(".")
    if not h or ":" in h:
        return ""
    try:
        ipaddress.ip_address(h)
        return ""
    except ValueError:
        return h


def is_trusted(host) -> bool:
    """Name-only check. Names are claimed by the client; use is_trusted_connection for decisions."""
    h = _normalise(host)
    if not h:
        return False
    return any(h == d or h.endswith("." + d) for d in _domains())


def is_trusted_connection(names, dest_ip) -> bool:
    """A connection is trusted only if EVERY name the client presented (TLS SNI, Host header) is
    trusted - so SNI and Host must agree, defeating domain fronting - and the real destination IP
    lies in Microsoft's published ranges, defeating a spoofed SNI to an attacker's server.
    No range data -> not trusted (normal inspection). Set TRUSTED_VERIFY_IP=0 for name-only."""
    presented = [n for n in (names or []) if isinstance(n, str) and n.strip()]
    if not presented or not all(is_trusted(n) for n in presented):
        return False
    if not VERIFY_IP:
        return True
    return ip_ranges.contains(dest_ip)
