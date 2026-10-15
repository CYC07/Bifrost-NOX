"""Trusted domains are *claimed* by the client (SNI / Host header), so they are verified:

1. every name the client presents must be trusted (SNI and Host header must agree), and
2. the real destination IP must be inside Microsoft's published ranges.

Without this, malware connecting to an attacker IP with SNI `client.wns.windows.com` would get an
uninspected tunnel. Residual, documented risk: anyone can rent an IP inside the Azure ranges.
"""
import asyncio
import json
import os
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "gateway"))
sys.path.insert(0, ROOT)
from common import ip_ranges as rng  # noqa: E402
from common import trusted_domains as td  # noqa: E402

GOOD_IP = "20.1.2.3"            # inside the fixture ranges
BAD_IP = "203.0.113.9"          # attacker box, outside
GOOD_V6 = "2603:1000::5"
MZ = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 200


@pytest.fixture(autouse=True)
def _cfg(tmp_path, monkeypatch):
    d = tmp_path / "trusted_domains.json"
    d.write_text(json.dumps({"domains": ["microsoft.com", "windows.com"]}))
    monkeypatch.setattr(td, "_PATH", str(d))
    td._reset_cache()
    r = tmp_path / "microsoft_ip_ranges.json"
    r.write_text(json.dumps({"ranges": ["20.0.0.0/8", "13.64.0.0/11", "20.1.0.0/16", "2603:1000::/24"]}))
    monkeypatch.setattr(rng, "_PATH", str(r))
    rng._reset_cache()
    monkeypatch.setattr(td, "VERIFY_IP", True)
    return r


# --- ip_ranges --------------------------------------------------------------------------------
@pytest.mark.parametrize("ip", [GOOD_IP, "20.255.255.255", "13.64.0.1", "13.95.255.255", GOOD_V6])
def test_ips_inside_ranges(ip):
    assert rng.contains(ip) is True


@pytest.mark.parametrize("ip", [BAD_IP, "19.255.255.255", "21.0.0.0", "13.96.0.0", "2603:2000::1", "127.0.0.1"])
def test_ips_outside_ranges(ip):
    assert rng.contains(ip) is False


@pytest.mark.parametrize("ip", ["", None, "not-an-ip", "20.1.2", "client.wns.windows.com", "20.1.2.3.4"])
def test_garbage_is_never_contained(ip):
    assert rng.contains(ip) is False


def test_overlapping_ranges_are_merged_correctly():
    # 20.1.0.0/16 sits inside 20.0.0.0/8; the boundary just past /16 must still be found
    assert rng.contains("20.2.0.1") and rng.contains("20.1.255.255")


def test_missing_or_corrupt_ranges_file_means_nothing_is_contained(_cfg):
    _cfg.write_text("{ broken")
    rng._reset_cache()
    assert rng.contains(GOOD_IP) is False
    os.remove(_cfg)
    rng._reset_cache()
    assert rng.contains(GOOD_IP) is False and rng.loaded() is False


def test_invalid_entries_are_skipped_not_fatal(_cfg):
    _cfg.write_text(json.dumps({"ranges": ["20.0.0.0/8", "nonsense", 5, None, "999.1.1.1/8", "0.0.0.0/0", "::/0"]}))
    rng._reset_cache()
    assert rng.contains(GOOD_IP)
    assert not rng.contains(BAD_IP), "a /0 entry must never turn the check into 'everything'"


# --- connection decision --------------------------------------------------------------------
def test_trusted_name_and_microsoft_ip_is_trusted():
    assert td.is_trusted_connection(["client.wns.windows.com"], GOOD_IP)
    assert td.is_trusted_connection(["client.wns.windows.com"], GOOD_V6)


def test_spoofed_sni_pointing_at_an_attacker_ip_is_not_trusted():
    assert not td.is_trusted_connection(["client.wns.windows.com"], BAD_IP)


@pytest.mark.parametrize("names", [
    ["client.wns.windows.com", "evil.example"],       # SNI trusted, Host header is not (fronting)
    ["evil.example", "client.wns.windows.com"],       # Host trusted, SNI is not
    ["evilmicrosoft.com", "www.microsoft.com"],
])
def test_name_mismatch_is_not_trusted_even_with_a_microsoft_ip(names):
    assert not td.is_trusted_connection(names, GOOD_IP)


def test_no_names_or_untrusted_names_are_not_trusted():
    assert not td.is_trusted_connection([], GOOD_IP)
    assert not td.is_trusted_connection(["", None], GOOD_IP)
    assert not td.is_trusted_connection(["example.com"], GOOD_IP)


def test_missing_destination_ip_is_not_trusted():
    assert not td.is_trusted_connection(["www.microsoft.com"], "")
    assert not td.is_trusted_connection(["www.microsoft.com"], None)


def test_no_range_data_fails_closed_to_normal_inspection(_cfg):
    os.remove(_cfg)
    rng._reset_cache()
    assert not td.is_trusted_connection(["www.microsoft.com"], GOOD_IP)


def test_ip_verification_can_be_switched_off_explicitly(monkeypatch):
    monkeypatch.setattr(td, "VERIFY_IP", False)
    assert td.is_trusted_connection(["www.microsoft.com"], BAD_IP)      # name-only, the old behaviour
    assert not td.is_trusted_connection(["evilmicrosoft.com"], BAD_IP)


# --- gateway inspector ----------------------------------------------------------------------
import proxy as gw  # noqa: E402


def _inspector():
    calls = []

    async def fake_send(*a, **k):
        calls.append(k)
        return {"status": "allow", "reason": ""}

    i = gw.IDPInspector()
    i.send_to_ai = fake_send
    return i, calls


def _inspect(i, body, host, dest_ip, server_name="", direction="inbound", path="/x"):
    return asyncio.run(i.inspect_full({"content-type": "application/octet-stream"}, body, direction, True,
                                      src_ip="a", dst_ip=host, dst_port=443, host=host, method="GET",
                                      path=path, server_name=server_name or host, dest_ip=dest_ip))


def test_verified_microsoft_download_is_allowed_unanalysed():
    i, calls = _inspector()
    assert _inspect(i, MZ, "dl.delivery.mp.microsoft.com", GOOD_IP) == "allow"
    assert calls == []


def test_same_name_from_an_attacker_ip_is_still_blocked_as_executable():
    i, calls = _inspector()
    assert _inspect(i, MZ, "dl.delivery.mp.microsoft.com", BAD_IP) == "block"


def test_host_header_fronting_is_not_trusted():
    i, calls = _inspector()
    # TLS to an attacker name inside Azure ranges, Host header claims Microsoft
    assert _inspect(i, MZ, "www.microsoft.com", GOOD_IP, server_name="evil.example") == "block"


def test_plain_http_uses_host_header_and_destination_ip():
    i, calls = _inspector()
    # for plain HTTP the engine's server_name is the destination IP itself (no SNI)
    assert _inspect(i, MZ, "www.microsoft.com", GOOD_IP, server_name=GOOD_IP) == "allow"
    assert _inspect(i, MZ, "www.microsoft.com", BAD_IP, server_name=BAD_IP) == "block"


def test_untrusted_traffic_is_unchanged():
    i, calls = _inspector()
    _inspect(i, b"hello world", "example.com", BAD_IP, direction="outbound")
    assert len(calls) == 1


# --- TLS bypass -----------------------------------------------------------------------------
import mitm_engine  # noqa: E402


def _engine(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return mitm_engine.TransparentProxy(host="127.0.0.1", port=0, inspector=None)


def test_tunnel_only_when_sni_is_trusted_and_ip_is_microsoft(tmp_path, monkeypatch):
    e = _engine(tmp_path, monkeypatch)
    monkeypatch.setattr(mitm_engine, "is_host_allowed", lambda h: False)
    assert e._bypass_mitm("client.wns.windows.com", True, GOOD_IP)
    assert not e._bypass_mitm("client.wns.windows.com", True, BAD_IP)       # spoofed SNI
    assert not e._bypass_mitm("client.wns.windows.com", False, GOOD_IP)     # plain HTTP is never tunnelled
    assert not e._bypass_mitm(GOOD_IP, True, GOOD_IP)                       # no SNI


def test_operator_allowlist_still_bypasses_regardless_of_ip(tmp_path, monkeypatch):
    e = _engine(tmp_path, monkeypatch)
    monkeypatch.setattr(mitm_engine, "is_host_allowed", lambda h: h == "chat.whatsapp.net")
    assert e._bypass_mitm("chat.whatsapp.net", True, BAD_IP)


# --- range updater --------------------------------------------------------------------------
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import update_microsoft_ranges as upd  # noqa: E402


def test_updater_merges_selected_tags_and_office_ranges_and_drops_junk():
    tags = {"values": [
        {"name": "AzureCloud", "properties": {"addressPrefixes": ["20.0.0.0/8", "2603:1000::/24", "junk"]}},
        {"name": "AzureCloud.westus", "properties": {"addressPrefixes": ["40.0.0.0/8"]}},
        {"name": "AzureActiveDirectory", "properties": {"addressPrefixes": ["13.64.0.0/11"]}},
        {"name": "Storage", "properties": {"addressPrefixes": ["52.0.0.0/8"]}},        # not selected
    ], "changeNumber": 7}
    o365 = [{"ips": ["104.40.0.0/13", "20.0.0.0/8"]}, {"urls": ["x"]}]
    out = upd.build(tags, o365)
    assert set(out["ranges"]) == {"20.0.0.0/8", "2603:1000::/24", "13.64.0.0/11", "104.40.0.0/13"}
    import ipaddress
    assert out["changeNumber"] == 7
    assert out["ranges"] == ["13.64.0.0/11", "20.0.0.0/8", "104.40.0.0/13", "2603:1000::/24"], "numeric order, v4 then v6"
    assert [ipaddress.ip_network(r).version for r in out["ranges"]] == [4, 4, 4, 6]
    assert not any(r in ("0.0.0.0/0", "::/0") for r in out["ranges"])


def test_updater_refuses_to_publish_a_suspiciously_small_result():
    with pytest.raises(ValueError):
        upd.build({"values": [], "changeNumber": 1}, [])
