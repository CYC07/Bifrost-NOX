"""The dashboard counters and the log level must reflect BLOCK verdicts.

update_stats() compared `str(verdict.status)` with VerdictStatus.BLOCK. str() of a (str, Enum) member is
"VerdictStatus.BLOCK", which never equals "block", so every block was counted as "allowed", the threat feed
stayed empty, and a block was logged at level ALLOW (the dashboard showed `blocked: 0` while the DNS brain and
the gateway were blocking). Found in the live VM lab.
"""
import os
import sys
from collections import deque

import pytest
from starlette.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.schemas import AggregatedVerdict, VerdictStatus  # noqa: E402
from master_ai import orchestrator as orch  # noqa: E402


@pytest.fixture(autouse=True)
def fresh_state(monkeypatch):
    monkeypatch.setattr(orch, "STATS", {"total": 0, "allowed": 0, "blocked": 0, "threats": 0})
    monkeypatch.setattr(orch, "RECENT_LOGS", deque(maxlen=1000))
    monkeypatch.setattr(orch, "RECENT_THREATS", deque(maxlen=1000))


def _v(status, reason="why", risk="high"):
    return AggregatedVerdict(status=status, risk_level=risk, reason=reason, detailed_findings={})


def test_a_block_is_counted_logged_and_listed_as_a_threat():
    orch.update_stats(_v(VerdictStatus.BLOCK, "DNS blocklist match"), "10.0.0.2", "malware.wicar.org", rule="DNS-FILTER")
    assert orch.STATS == {"total": 1, "allowed": 0, "blocked": 1, "threats": 1}
    row = orch.RECENT_LOGS[0]
    assert row["level"] == "BLOCK" and row["status"] == "block" and row["rule"] == "DNS-FILTER"
    assert len(orch.RECENT_THREATS) == 1 and orch.RECENT_THREATS[0]["dst"] == "malware.wicar.org"


def test_allow_and_censor_are_not_blocks():
    orch.update_stats(_v(VerdictStatus.ALLOW, risk="safe"), "a", "b")
    orch.update_stats(_v(VerdictStatus.CENSOR, risk="medium"), "a", "c")
    assert orch.STATS == {"total": 2, "allowed": 2, "blocked": 0, "threats": 0}
    assert [r["level"] for r in orch.RECENT_LOGS] == ["WARN", "ALLOW"]
    assert len(orch.RECENT_THREATS) == 0


def test_a_plain_string_status_works_too():
    orch.update_stats(_v("block"), "a", "b")                  # callers may pass the raw value
    assert orch.STATS["blocked"] == 1 and orch.RECENT_LOGS[0]["level"] == "BLOCK"


def test_gateway_style_log_event_with_block_status_counts_as_a_block():
    """The gateway/brain report blocks through POST /log_event (PINNED-TLS, DNS-FILTER...)."""
    c = TestClient(orch.app, client=("127.0.0.1", 50000))
    r = c.post("/log_event", json={"source_ip": "10.0.0.2", "destination_ip": "app.example", "port": "443",
                                   "status": "block", "risk_level": "high", "reason": "Client rejected MITM cert",
                                   "rule": "PINNED-TLS"})
    assert r.status_code == 200
    assert orch.STATS["blocked"] == 1 and orch.RECENT_LOGS[0]["level"] == "BLOCK"


def test_upstream_fail_event_is_an_allow_not_a_block():
    c = TestClient(orch.app, client=("127.0.0.1", 50000))
    c.post("/log_event", json={"source_ip": "10.0.0.2", "destination_ip": "203.0.113.1", "port": "80",
                               "status": "allow", "risk_level": "safe", "reason": "Upstream unreachable: timed out",
                               "rule": "UPSTREAM-FAIL"})
    assert orch.STATS == {"total": 1, "allowed": 1, "blocked": 0, "threats": 0}
    assert orch.RECENT_LOGS[0]["rule"] == "UPSTREAM-FAIL" and orch.RECENT_LOGS[0]["level"] == "ALLOW"
