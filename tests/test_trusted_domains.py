"""Trusted-domain policy: traffic to Windows/Microsoft infrastructure is treated as normal.

A firewall cannot see which *process* sent a packet, so "Windows' own processes" means
"Windows' own domains". Models were mis-judging OS telemetry (push-service replies, update and
Delivery-Optimization chatter, login endpoints), and the executable-file block would block
Windows Update downloads. Matching is by DNS label boundary: `evilmicrosoft.com`,
`microsoft.com.evil.test` and `*.blob.core.windows.net` (attacker-registrable storage accounts)
must NOT match.
"""
import asyncio
import json
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "gateway")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common import trusted_domains as td  # noqa: E402


@pytest.fixture(autouse=True)
def _cfg(tmp_path, monkeypatch):
    p = tmp_path / "trusted_domains.json"
    p.write_text(json.dumps({"domains": ["microsoft.com", "windows.com"]}))
    monkeypatch.setattr(td, "_PATH", str(p))
    td._reset_cache()
    return p


# --- matching ------------------------------------------------------------------------------
@pytest.mark.parametrize("host", [
    "microsoft.com", "www.microsoft.com", "client.wns.windows.com", "fd.api.iris.microsoft.com",
    "array601.prod.do.dsp.mp.microsoft.com", "v10.events.data.microsoft.com", "windows.com",
    "CLIENT.WNS.WINDOWS.COM", "client.wns.windows.com.", "  client.wns.windows.com  ",
])
def test_domains_and_all_their_subdomains_are_trusted(host):
    assert td.is_trusted(host)


@pytest.mark.parametrize("host", [
    "evilmicrosoft.com", "notwindows.com", "microsoft.com.evil.test", "windows.com.attacker.io",
    "microsoft.co", "microsoft.com.cn.evil.test", "xmicrosoft.com", "mymicrosoft.com",
    "evil.blob.core.windows.net",          # anyone can register a storage account
    "windows.net", "azurewebsites.net", "live.com", "msn.com", "bing.com", "oneclient.sfx.ms",
    "example.com", "httpbin.org", "xpal.com",
])
def test_lookalikes_and_attacker_registrable_hosts_are_not_trusted(host):
    assert not td.is_trusted(host)


@pytest.mark.parametrize("host", ["", None, "   ", ".", "..", "127.0.0.1", "10.0.0.5", "[::1]"])
def test_empty_and_ip_hosts_are_never_trusted(host):
    assert not td.is_trusted(host)


def test_host_with_port_is_handled():
    assert td.is_trusted("client.wns.windows.com:443")
    assert not td.is_trusted("evil.test:microsoft.com")


# --- config -------------------------------------------------------------------------------------
def test_config_hot_reloads(_cfg):
    assert not td.is_trusted("login.live.com")
    _cfg.write_text(json.dumps({"domains": ["microsoft.com", "windows.com", "live.com"]}))
    os.utime(_cfg, (time.time() + 5, time.time() + 5))
    assert td.is_trusted("login.live.com")


def test_missing_or_corrupt_config_falls_back_to_the_shipped_defaults(_cfg):
    _cfg.write_text("{ broken")
    td._reset_cache()
    assert td.is_trusted("client.wns.windows.com") and td.is_trusted("www.microsoft.com")
    assert not td.is_trusted("example.com")
    os.remove(_cfg)
    td._reset_cache()
    assert td.is_trusted("www.microsoft.com")


def test_an_empty_domains_list_disables_the_policy(_cfg):
    _cfg.write_text(json.dumps({"domains": []}))
    td._reset_cache()
    assert not td.is_trusted("www.microsoft.com")


def test_entries_are_normalised_and_junk_ignored(_cfg):
    _cfg.write_text(json.dumps({"domains": ["  Microsoft.COM ", "*.windows.com", "", 7, None, "com", "*"]}))
    td._reset_cache()
    assert td.is_trusted("a.microsoft.com") and td.is_trusted("a.windows.com")
    assert not td.is_trusted("example.com")          # a bare TLD / wildcard must never become "trust everything"


# --- gateway inspector --------------------------------------------------------------------------
import proxy as gw  # noqa: E402

MZ = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 200            # a Windows executable header


def _inspector():
    calls = []

    async def fake_send(*a, **k):
        calls.append(k)
        return {"status": "block", "reason": "should not be asked"}

    i = gw.IDPInspector()
    i.send_to_ai = fake_send
    return i, calls


def _inspect(i, body, host, direction="inbound", path="/x"):
    return asyncio.run(i.inspect_full({"content-type": "application/octet-stream"}, body, direction, True,
                                      src_ip="a", dst_ip="b", dst_port=443, host=host, method="GET", path=path))


def test_executable_download_from_a_trusted_host_is_allowed_without_analysis():
    i, calls = _inspector()
    assert _inspect(i, MZ, "dl.delivery.mp.microsoft.com") == "allow"
    assert calls == []


def test_the_same_executable_from_an_untrusted_host_is_still_blocked():
    i, calls = _inspector()
    assert _inspect(i, MZ, "evil.example") == "block"


def test_attack_looking_body_and_target_to_a_trusted_host_are_not_analysed():
    i, calls = _inspector()
    body = b"id=1' OR '1'='1' --"
    assert _inspect(i, body, "login.microsoft.com", direction="outbound",
                    path="/a?x=%27%20OR%201%3D1--") == "allow"
    assert calls == []


def test_lookalike_host_is_analysed_normally():
    i, calls = _inspector()
    assert _inspect(i, b"hello world", "evilmicrosoft.com", direction="outbound") == "block"
    assert len(calls) == 1


def test_untrusted_host_still_goes_through_the_target_check():
    i, calls = _inspector()
    _inspect(i, b"", "app.example", direction="outbound", path="/i?id=1%27%20OR%20%271%27%3D%271")
    assert any(c.get("kind") == "url" for c in calls)


# --- TLS bypass decision --------------------------------------------------------------------------
import mitm_engine  # noqa: E402


def _engine(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return mitm_engine.TransparentProxy(host="127.0.0.1", port=0, inspector=None)


def test_tls_to_a_trusted_domain_is_not_intercepted(tmp_path, monkeypatch):
    e = _engine(tmp_path, monkeypatch)
    monkeypatch.setattr(mitm_engine, "is_host_allowed", lambda h: False)
    assert e._bypass_mitm("client.wns.windows.com", is_tls=True)
    assert not e._bypass_mitm("client.wns.windows.com", is_tls=False)   # plain HTTP is analysed/ allowed by the inspector


def test_user_allowlist_still_bypasses_and_other_hosts_do_not(tmp_path, monkeypatch):
    e = _engine(tmp_path, monkeypatch)
    monkeypatch.setattr(mitm_engine, "is_host_allowed", lambda h: h == "chat.whatsapp.net")
    assert e._bypass_mitm("chat.whatsapp.net", is_tls=True)
    assert not e._bypass_mitm("example.com", is_tls=True)
    assert not e._bypass_mitm("evilmicrosoft.com", is_tls=True)
