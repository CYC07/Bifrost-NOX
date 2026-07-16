"""DNS-layer domain filtering for the NFQUEUE path.

The C++ engine traps UDP/53 and hands the raw IP packet to ``ai_brain`` over
ZeroMQ. This module turns that into an actual decision: extract the queried
domain, then block it if it matches the static blocklist or a ``domain`` rule
in the shared rule engine. Replaces the old behaviour of shoving raw packet
bytes into the NLP text service, which inspected nothing meaningful.

All functions are pure/​side-effect-free and unit-testable without a live
NFQUEUE, root, or a hotspot interface.
"""
from __future__ import annotations

import json
import logging
import os

logger = logging.getLogger("dns_filter")

_BLOCKLIST_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "config", "dns_blocklist.json")
)


def load_blocklist(path: str = _BLOCKLIST_PATH) -> set[str]:
    """Load blocked domains from JSON: ``{"domains": ["ads.example.com", ...]}``."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return set()
    except Exception as exc:  # noqa: BLE001
        logger.error("blocklist load failed: %s", exc)
        return set()
    domains = data.get("domains", []) if isinstance(data, dict) else []
    return {d.strip().lower().rstrip(".") for d in domains if isinstance(d, str) and d.strip()}


def domain_blocked(domain: str, blocklist: set[str]) -> bool:
    """True if *domain* or any parent domain is in *blocklist*.

    Blocking ``example.com`` also blocks ``ads.example.com`` (suffix match on
    label boundaries — ``notexample.com`` is not matched).
    """
    d = (domain or "").strip().lower().rstrip(".")
    if not d or not blocklist:
        return False
    labels = d.split(".")
    for i in range(len(labels)):
        if ".".join(labels[i:]) in blocklist:
            return True
    return False


def extract_qname(ip_payload: bytes) -> str | None:
    """Extract the queried domain from a raw IPv4 packet carrying a DNS query.

    Returns the domain (no trailing dot) or ``None`` if the packet is not a
    parseable DNS query. Uses scapy (already a project dependency).
    """
    try:
        from scapy.layers.dns import DNS
        from scapy.layers.inet import IP

        pkt = IP(ip_payload)
        if not pkt.haslayer(DNS):
            return None
        dns = pkt[DNS]
        if dns.qd is None:
            return None
        qname = dns.qd.qname
        if isinstance(qname, bytes):
            qname = qname.decode("utf-8", errors="ignore")
        return qname.rstrip(".") or None
    except Exception as exc:  # noqa: BLE001 — malformed packet -> not a DNS query
        logger.debug("DNS parse failed: %s", exc)
        return None
