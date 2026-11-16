"""The admin guard must trust the machine talking to ITSELF, not only 127.x.

Bug (seen live): the operator opened the dashboard on the lab laptop as http://192.168.56.1:8000 (the address the
VM lab prints for the CA cert). The kernel then uses 192.168.56.1 as the SOURCE of that connection, so the guard saw
a non-loopback client and answered 403 to every dashboard upload (POST /analyze_traffic), rule toggle and allowlist edit.

A connection whose source address equals the address it was made to cannot come from another machine (a remote
host cannot complete a TCP handshake with the server's own address as its source), so that is "the host itself".
The VM (192.168.56.103) and every other peer must stay blocked, and the token path is unchanged.
"""
import os
import sys

import pytest
from starlette.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from master_ai import orchestrator as orch  # noqa: E402
from master_ai.orchestrator import _authorize  # noqa: E402

HOST = "192.168.56.1"        # the laptop's vboxnet0 address
VM = "192.168.56.103"
TOKEN = "s3cret"


# --- the pure decision ------------------------------------------------------------------------
@pytest.mark.parametrize("path,method", [("/analyze_traffic", "POST"), ("/allowlist", "POST"), ("/rules/abc/toggle", "POST"),
                                         ("/rules/abc", "DELETE"), ("/test_attack", "POST"), ("/log_event", "POST")])
def test_host_using_its_own_lan_address_is_allowed(path, method):
    assert _authorize(HOST, path, method, "", "", server_host=HOST)


@pytest.mark.parametrize("own", ["10.0.0.5", "192.168.50.1", "172.16.4.2", "169.254.7.9"])
def test_any_of_the_hosts_own_addresses_counts(own):
    assert _authorize(own, "/analyze_traffic", "POST", "", "", server_host=own)


@pytest.mark.parametrize("client,server", [("::ffff:192.168.56.1", "192.168.56.1"), ("192.168.56.1", "::ffff:192.168.56.1"),
                                           ("::ffff:192.168.56.1", "::ffff:192.168.56.1"), ("fe80::1", "fe80::1"), ("2001:db8::7", "2001:db8::7")])
def test_ipv4_mapped_and_ipv6_forms_of_the_same_address_match(client, server):
    assert _authorize(client, "/analyze_traffic", "POST", "", "", server_host=server)


@pytest.mark.parametrize("client", [VM, "192.168.56.2", "10.0.0.9", "8.8.8.8", "::ffff:192.168.56.103"])
def test_other_machines_stay_blocked_even_when_they_reach_the_host_lan_address(client):
    assert not _authorize(client, "/analyze_traffic", "POST", "", TOKEN, server_host=HOST)


def test_the_vm_cannot_borrow_the_host_address_with_a_valid_looking_but_different_one():
    assert not _authorize("192.168.56.10", "/allowlist", "POST", "", TOKEN, server_host="192.168.56.1")


@pytest.mark.parametrize("client,server", [("", ""), ("unknown", "unknown"), ("testclient", "testclient"), ("not-an-ip", "not-an-ip"),
                                           ("0.0.0.0", "0.0.0.0"), ("::", "::"), (None, None), (HOST, ""), (HOST, None), ("", HOST)])
def test_unknown_unparseable_or_unspecified_addresses_never_count_as_the_host(client, server):
    assert not _authorize(client, "/analyze_traffic", "POST", "", "", server_host=server)


def test_the_token_path_and_open_reads_are_unchanged():
    assert _authorize(VM, "/allowlist", "POST", TOKEN, TOKEN, server_host=HOST)
    assert not _authorize(VM, "/allowlist", "POST", "nope", TOKEN, server_host=HOST)
    assert _authorize(VM, "/uploads", "GET", "", "", server_host=HOST)


def test_omitting_server_host_keeps_the_old_strict_behaviour():
    assert not _authorize(HOST, "/analyze_traffic", "POST", "", "")
    assert _authorize("127.0.0.1", "/analyze_traffic", "POST", "", "")


# --- the real middleware, with both addresses faked -------------------------------------------
FORM = {"content_type": "unknown", "source_ip": "dashboard", "destination_ip": "ai-intake"}


def _post(client_ip, server_ip="192.168.56.1", **kw):
    c = TestClient(orch.app, base_url=f"http://{server_ip}:8000", client=(client_ip, 50000))
    return c.post("/analyze_traffic", data=FORM, **kw)


def test_middleware_lets_the_laptop_upload_through_its_lan_address():
    r = _post(HOST)
    assert r.status_code == 200 and r.json()["status"] == "allow"


def test_middleware_still_refuses_the_vm():
    r = _post(VM)
    assert r.status_code == 403 and "forbidden" in r.json()["error"]


def test_middleware_ignores_spoofable_headers():
    r = _post(VM, headers={"x-forwarded-for": "127.0.0.1", "x-real-ip": HOST, "host": HOST, "forwarded": f"for={HOST}"})
    assert r.status_code == 403


def test_middleware_still_accepts_loopback_and_a_valid_token(monkeypatch):
    assert _post("127.0.0.1", server_ip="127.0.0.1").status_code == 200
    monkeypatch.setattr(orch, "ADMIN_TOKEN", TOKEN)
    assert _post(VM, headers={"x-admin-token": TOKEN}).status_code == 200
    assert _post(VM, headers={"x-admin-token": "wrong"}).status_code == 403
