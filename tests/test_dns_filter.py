"""Unit tests for the DNS-layer domain filter.

The live NFQUEUE drop needs root + the C++ engine and is not exercised here;
these cover the pure decision logic and scapy-based query parsing.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from network_inspector import dns_filter  # noqa: E402


BLOCKLIST = {"doubleclick.net", "malware.wicar.org", "eicar.org"}


def test_exact_domain_blocked():
    assert dns_filter.domain_blocked("doubleclick.net", BLOCKLIST)


def test_subdomain_blocked_by_parent():
    assert dns_filter.domain_blocked("ads.g.doubleclick.net", BLOCKLIST)
    assert dns_filter.domain_blocked("www.eicar.org", BLOCKLIST)


def test_trailing_dot_and_case_normalized():
    assert dns_filter.domain_blocked("DoubleClick.NET.", BLOCKLIST)


def test_unrelated_domain_allowed():
    assert not dns_filter.domain_blocked("example.com", BLOCKLIST)


def test_no_partial_label_false_match():
    # "notdoubleclick.net" must NOT match "doubleclick.net"
    assert not dns_filter.domain_blocked("notdoubleclick.net", BLOCKLIST)


def test_empty_inputs():
    assert not dns_filter.domain_blocked("", BLOCKLIST)
    assert not dns_filter.domain_blocked("example.com", set())


def _dns_query_packet(qname: str) -> bytes:
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import IP, UDP

    pkt = IP(src="192.168.50.10", dst="8.8.8.8") / UDP(sport=54321, dport=53) / DNS(
        rd=1, qd=DNSQR(qname=qname)
    )
    return bytes(pkt)


def test_extract_qname_from_real_packet():
    raw = _dns_query_packet("ads.doubleclick.net")
    assert dns_filter.extract_qname(raw) == "ads.doubleclick.net"


def test_extract_qname_non_dns_returns_none():
    from scapy.layers.inet import IP, TCP

    raw = bytes(IP(src="1.1.1.1", dst="2.2.2.2") / TCP(dport=443))
    assert dns_filter.extract_qname(raw) is None


def test_extract_qname_garbage_returns_none():
    assert dns_filter.extract_qname(b"\x00\x01\x02not a packet") is None


def test_decide_blocks_blocklisted_domain(monkeypatch):
    from network_inspector import ai_brain

    monkeypatch.setattr(ai_brain, "_BLOCKLIST", BLOCKLIST)
    monkeypatch.setattr(ai_brain, "get_engine", None)
    raw = _dns_query_packet("malware.wicar.org")
    allowed, domain, reason = ai_brain.decide("53", raw)
    assert allowed is False
    assert domain == "malware.wicar.org"


def test_decide_allows_clean_domain(monkeypatch):
    from network_inspector import ai_brain

    monkeypatch.setattr(ai_brain, "_BLOCKLIST", BLOCKLIST)
    monkeypatch.setattr(ai_brain, "get_engine", None)
    raw = _dns_query_packet("example.com")
    allowed, domain, reason = ai_brain.decide("53", raw)
    assert allowed is True
    assert domain == "example.com"


def test_decide_non_dns_port_observed():
    from network_inspector import ai_brain

    allowed, domain, reason = ai_brain.decide("21", b"USER anonymous\r\n")
    assert allowed is True
    assert reason == "observed"
