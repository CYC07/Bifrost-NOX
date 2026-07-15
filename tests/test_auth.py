"""Unit tests for the control-plane authorization decision.

Exercises the pure ``_authorize`` function with real host strings — the loopback
branch cannot be tested through Starlette's TestClient (it reports a synthetic
peer, not 127.0.0.1).
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from master_ai.orchestrator import _authorize  # noqa: E402

HOTSPOT = "192.168.50.10"
LOOPBACK = "127.0.0.1"
TOKEN = "s3cret-admin-token"


# --- read-only paths are never gated ---------------------------------------
@pytest.mark.parametrize("path", ["/stats", "/overview", "/threats", "/rules", "/allowlist", "/dashboard/"])
def test_reads_open_from_hotspot(path):
    assert _authorize(HOTSPOT, path, "GET", "", TOKEN)


# --- mutations require loopback or token -----------------------------------
def test_mutation_from_loopback_allowed():
    assert _authorize(LOOPBACK, "/allowlist", "POST", "", "")


def test_mutation_from_hotspot_without_token_denied():
    assert not _authorize(HOTSPOT, "/allowlist", "POST", "", TOKEN)


def test_mutation_from_hotspot_with_valid_token_allowed():
    assert _authorize(HOTSPOT, "/allowlist", "POST", TOKEN, TOKEN)


def test_mutation_from_hotspot_with_wrong_token_denied():
    assert not _authorize(HOTSPOT, "/allowlist", "POST", "nope", TOKEN)


def test_delete_rule_from_hotspot_denied():
    assert not _authorize(HOTSPOT, "/rules/abc123", "DELETE", "", TOKEN)


def test_rule_toggle_from_hotspot_denied():
    assert not _authorize(HOTSPOT, "/rules/abc123/toggle", "POST", "", TOKEN)


def test_test_attack_from_hotspot_denied():
    assert not _authorize(HOTSPOT, "/test_attack", "POST", "", TOKEN)


# --- internal ingest endpoints are loopback/token only, any method ---------
def test_analyze_traffic_from_hotspot_denied():
    assert not _authorize(HOTSPOT, "/analyze_traffic", "POST", "", TOKEN)


def test_analyze_traffic_from_loopback_allowed():
    assert _authorize(LOOPBACK, "/analyze_traffic", "POST", "", "")


def test_log_event_from_loopback_allowed():
    assert _authorize(LOOPBACK, "/log_event", "POST", "", "")


def test_log_event_from_hotspot_denied():
    assert not _authorize(HOTSPOT, "/log_event", "POST", "", TOKEN)


# --- no configured token: only loopback can mutate -------------------------
def test_no_admin_token_configured_hotspot_always_denied():
    assert not _authorize(HOTSPOT, "/allowlist", "POST", "anything", "")


def test_ipv6_loopback_allowed():
    assert _authorize("::1", "/allowlist", "POST", "", "")


def test_not_partial_prefix_match():
    # "/rulesX" must not be treated as the "/rules" prefix
    assert _authorize(HOTSPOT, "/rulesX", "POST", "", TOKEN)
