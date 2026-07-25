"""ZeroMQ bridge between the C++ NFQUEUE engine and the DNS filter.

The C++ engine sends, per trapped packet, a REQ message:
    header:  "check <src_ip> <dst_ip> <sport> <dport> <payload_len>"
    payload: the raw IPv4 packet bytes

For UDP/53 we parse the DNS query and decide ALLOW/BLOCK from the blocklist and
the shared rule engine's ``domain`` rules. Other trapped protocols (e.g. FTP)
are observed and allowed — we no longer feed raw packet bytes to the NLP model.

Contract with the C++ REQ socket (strict lockstep): **exactly one reply per
request, always.** Any parsing failure falls open to ALLOW so the NFQUEUE never
stalls. Dashboard logging happens *after* the reply is sent, off the packet
verdict path.
"""
from __future__ import annotations

import logging
import os
import sys
import threading

import requests
import zmq

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.utils import setup_logging  # noqa: E402
from network_inspector.dns_filter import (  # noqa: E402
    domain_blocked,
    extract_qname,
    load_blocklist,
)

try:
    from master_ai.rule_engine import get_engine  # noqa: E402
except Exception:  # noqa: BLE001 — rule engine optional for the DNS path
    get_engine = None

setup_logging("ai_brain")
logger = logging.getLogger("ai_brain")

ZMQ_ENDPOINT = "ipc:///tmp/firewall_pipeline"
MASTER_LOG_URL = "http://localhost:8000/log_event"

_BLOCKLIST = load_blocklist()


def _domain_rule_hit(domain: str) -> dict | None:
    """Return a matching ``domain`` block rule from the shared engine, if any."""
    if get_engine is None:
        return None
    try:
        hit = get_engine().evaluate({"destination_ip": domain, "text_content": ""})
    except Exception as exc:  # noqa: BLE001
        logger.debug("rule engine eval failed: %s", exc)
        return None
    if hit and hit.get("action") == "block":
        return hit
    return None


def decide(dst_port: str, payload: bytes) -> tuple[bool, str, str]:
    """Return (allowed, domain, reason). Never raises."""
    try:
        if dst_port == "53":
            domain = extract_qname(payload)
            if not domain:
                return True, "", "dns-unparsed"
            if domain_blocked(domain, _BLOCKLIST):
                return False, domain, "DNS blocklist match"
            rule = _domain_rule_hit(domain)
            if rule:
                return False, domain, f"DNS domain rule: {rule.get('value', '')}"
            return True, domain, "dns-allow"
    except Exception as exc:  # noqa: BLE001 — fail open
        logger.error("decide() failed: %s", exc)
        return True, "", "error"
    return True, "", "observed"


def _log_async(src_ip: str, domain: str, allowed: bool, reason: str) -> None:
    """Fire-and-forget dashboard event. Runs after the ZMQ reply is sent."""

    def _post() -> None:
        try:
            requests.post(
                MASTER_LOG_URL,
                json={
                    "source_ip": src_ip,
                    "destination_ip": domain,
                    "port": "53",
                    "proto": "DNS",
                    "status": "allow" if allowed else "block",
                    "risk_level": "safe" if allowed else "high",
                    "reason": reason,
                    "rule": "DNS-FILTER",
                },
                timeout=1.0,
            )
        except Exception:  # noqa: BLE001
            pass

    threading.Thread(target=_post, daemon=True).start()


def start_server() -> None:
    context = zmq.Context()
    sock = context.socket(zmq.REP)
    sock.bind(ZMQ_ENDPOINT)
    logger.info(
        "AI Brain (DNS filter) listening on %s | blocklist=%d domains",
        ZMQ_ENDPOINT, len(_BLOCKLIST),
    )

    while True:
        # Receive the full multipart request before replying. If a recv fails
        # mid-message we did not complete a request, so loop without replying.
        try:
            header = sock.recv_string()
            payload = sock.recv()
        except Exception as exc:  # noqa: BLE001
            logger.error("ZMQ recv error: %s", exc)
            continue

        # From here we owe exactly one reply. Compute it defensively.
        allowed, domain, reason, src_ip = True, "", "error", "unknown"
        try:
            parts = header.split(" ")
            if parts and parts[0] == "check" and len(parts) >= 2:
                src_ip = parts[1]
                dst_port = parts[4] if len(parts) > 4 else ""
                allowed, domain, reason = decide(dst_port, payload)
        except Exception as exc:  # noqa: BLE001 — fail open
            logger.error("verdict computation failed: %s", exc)
            allowed = True

        try:
            sock.send_string("ALLOW" if allowed else "BLOCK")
        except Exception as exc:  # noqa: BLE001
            logger.error("ZMQ send error: %s", exc)
            continue

        if domain and reason not in ("observed", "dns-unparsed", "error"):
            logger.info("DNS %s %s (%s)", "ALLOW" if allowed else "BLOCK", domain, reason)
            _log_async(src_ip, domain, allowed, reason)


if __name__ == "__main__":
    start_server()
