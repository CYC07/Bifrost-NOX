"""Scanner / recon-tool detection from request HEADERS (ml/waf/scanner.py + the gateway hook).

Why: the WAF only ever sees bodies and request targets, but a scanner announces itself in the User-Agent
header, so the model's `scanner` class was unreachable in production (and, as a model, it recalled 3/60 real
scanner names). Detection is deterministic: a precise list of tool names matched on token boundaries, plus
a few scanner-only request headers. Ordinary clients (browsers, curl, python-requests, bots) are never matched.
"""
import asyncio
import os
import sys
import time

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "gateway"))
sys.path.insert(0, ROOT)
from ml.waf import scanner as sc  # noqa: E402
import proxy as gw  # noqa: E402

SCANNER_UAS = [
    "sqlmap/1.7.2#stable (https://sqlmap.org)",
    "Nikto/2.1.6",
    "Mozilla/5.00 (Nikto/2.1.5) (Evasions:None) (Test:Port Check)",
    "DirBuster-1.0-RC1 (http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)",
    "gobuster/3.5.0",
    "WPScan v3.8.24 (https://wpscan.com/wordpress-security-scanner)",
    "masscan/1.3 (https://github.com/robertdavidgraham/masscan)",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
    "Wfuzz/3.1.0",
    "Fuzz Faster U Fool v2.0.0 ffuf/2.0.0",
    "feroxbuster/2.10.1",
    "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
    "Mozilla/5.0 (compatible; Nessus)",
    "OpenVAS",
    "w3af.org",
    "Arachni/v1.6.1",
    "Mozilla/5.0 Acunetix-Product/WVS",
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; Netsparker)",
    "WhatWeb/0.5.5",
    "Skipfish/2.10b",
    "Mozilla/5.0 zgrab/0.x",
    "Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)",
    "dirsearch/0.4.3",
    "Wapiti/3.1.8 (wapiti-scanner.github.io)",
    "commix/3.9",
]
# Ordinary clients: must never be flagged.
ORDINARY_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "curl/8.4.0", "Wget/1.21.4", "python-requests/2.31.0", "Go-http-client/1.1", "okhttp/4.12.0", "axios/1.6.2", "node-fetch/1.0",
    "Apache-HttpClient/5.2.1 (Java/17.0.9)", "PostmanRuntime/7.36.0", "insomnia/8.4.5", "Dalvik/2.1.0 (Linux; U; Android 14)",
    "Microsoft-Delivery-Optimization/10.0", "Windows-Update-Agent/10.0.19045.0 Client-Protocol/2.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "CFNetwork/1485 Darwin/23.1.0", "Spotify/8.8.0 Android/34", "Slackbot-LinkExpanding 1.0", "Zoom/5.17.0",
    "Mozilla/5.0 (compatible; UptimeRobot/2.0)", "git/2.43.0", "docker/24.0.7 go/go1.20.10", "NucleiViewer/2.1 (Windows)",
    "sqlmapper-dashboard/1.0", "MyNiktoberfestApp/1.0", "",
]


@pytest.mark.parametrize("ua", SCANNER_UAS)
def test_known_scanner_user_agents_are_detected(ua):
    assert sc.scanner_signature({"user-agent": ua}), ua


EXTRA_TOOL_UAS = ["DotDotPwn", "Kadimus", "LFISuite", "SSTImap", "XSStrike", "xsser", "WPProbe", "tplmap", "Detectify", "Ghauri", "fimap",
                  "Mozilla/4.0 (Hydra)", "Mozilla (libwhisker/2.4)", "jSQL Injection", "TsunamiSecurityScanner", "nettacker", "zmeu", "WhatWaf",
                  "Mozilla/5.0 (compatible; Google Desktop) Paros/3.2.12"]


@pytest.mark.parametrize("ua", EXTRA_TOOL_UAS)
def test_further_exploit_and_fuzzing_tools_are_detected(ua):
    assert sc.scanner_signature({"user-agent": ua}), ua


@pytest.mark.parametrize("ua", ["Hydra-Client/2.0", "MyHydraApp (iOS)", "tplmapper/1.0", "Detectifyer/1.0", "libwhiskerdocs/1.0",
                                "Mozilla/5.0 (X11; Linux x86_64) Chrome/120 Vega/embed"])   # a hyphen IS a boundary (DirBuster-1.0-RC1)
def test_near_miss_names_are_not_flagged(ua):
    assert sc.scanner_signature({"user-agent": ua}) is None, ua


@pytest.mark.parametrize("ua", ORDINARY_UAS)
def test_ordinary_clients_are_never_flagged(ua):
    assert sc.scanner_signature({"user-agent": ua}) is None, ua


def test_detection_names_the_tool_not_the_whole_string():
    assert sc.scanner_signature({"user-agent": "sqlmap/1.7.2#stable (https://sqlmap.org)"}) == "sqlmap"
    assert sc.scanner_signature({"user-agent": "Mozilla/5.00 (Nikto/2.1.5) (Evasions:None)"}) == "nikto"


def test_header_names_and_user_agent_are_case_insensitive():
    assert sc.scanner_signature({"User-Agent": "NIKTO/2.1.6"})
    assert sc.scanner_signature({"USER-AGENT": "gobuster/3.5.0"})


@pytest.mark.parametrize("hdr", ["Acunetix-Aspect", "acunetix-aspect-password", "Acunetix-Aspect-Queries", "X-Scan-Memo"])
def test_scanner_only_request_headers_are_detected(hdr):
    assert sc.scanner_signature({"user-agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/120", hdr: "enabled"})


@pytest.mark.parametrize("headers", [None, {}, {"user-agent": None}, {"user-agent": 123}, {"user-agent": b"sqlmap/1.0"}, "not a dict", []])
def test_odd_header_input_never_raises(headers):
    sc.scanner_signature(headers)       # must not raise (bytes UA is decoded; the rest is simply not a match)


def test_huge_user_agent_is_checked_in_bounded_time():
    t0 = time.perf_counter()
    sc.scanner_signature({"user-agent": "a" * 200_000 + " sqlmap/1.0"})        # outcome not asserted: only the cost
    sc.scanner_signature({"user-agent": "Mozilla/5.0 " * 20_000})
    sc.scanner_signature({"user-agent": "sqlmap" * 40_000})
    assert time.perf_counter() - t0 < 0.5


def test_a_scanner_name_after_moderate_padding_is_still_found():
    """Real UAs are < 300 chars, but padding the header must not be a free bypass."""
    assert sc.scanner_signature({"user-agent": "Mozilla/5.0 " + "x" * 3000 + " Nikto/2.1.6"})


def test_policy_default_is_block_and_env_values_are_normalised(monkeypatch):
    monkeypatch.delenv("SCANNER_UA_POLICY", raising=False)
    assert sc.scanner_policy() == "block"
    for raw, want in (("advisory", "advisory"), (" OFF ", "off"), ("block", "block"), ("nonsense", "block")):
        monkeypatch.setenv("SCANNER_UA_POLICY", raw)
        assert sc.scanner_policy() == want


# --- gateway hook -----------------------------------------------------------------------------
class Spy:
    def __init__(self):
        self.calls = []

    async def __call__(self, c_type, *a, **k):
        self.calls.append(c_type)
        return {"status": "allow"}


def run(headers, body=b"", direction="outbound", host="app.example", path="/index.html"):
    i = gw.IDPInspector()
    spy = Spy()
    i.send_to_ai = spy
    v = asyncio.run(i.inspect_full(headers, body, direction, True, src_ip="a", dst_ip=host, dst_port=443, host=host, method="GET",
                                   path=path, server_name=host, dest_ip="203.0.113.9"))
    return v, spy


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.delenv("SCANNER_UA_POLICY", raising=False)


def test_outbound_scanner_request_is_blocked_before_any_analysis_even_without_a_body():
    v, spy = run({"user-agent": "sqlmap/1.7.2#stable (https://sqlmap.org)"})
    assert v == "block" and spy.calls == []


def test_outbound_scanner_request_with_a_body_is_blocked_too():
    v, spy = run({"user-agent": "Nikto/2.1.6", "content-type": "text/plain"}, body=b"hello")
    assert v == "block" and spy.calls == []


def test_ordinary_outbound_request_is_unaffected():
    v, spy = run({"user-agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/120", "content-type": "text/plain"}, body=b"hello there")
    assert v == "allow" and spy.calls == ["text"]


def test_inbound_direction_is_never_judged_on_these_headers():
    v, _ = run({"user-agent": "sqlmap/1.7.2"}, direction="inbound")
    assert v == "allow"


@pytest.mark.parametrize("policy", ["off", "advisory"])
def test_policy_off_and_advisory_do_not_block(monkeypatch, policy):
    monkeypatch.setenv("SCANNER_UA_POLICY", policy)
    assert run({"user-agent": "Nikto/2.1.6"})[0] == "allow"


def test_policy_block_explicit_works(monkeypatch):
    monkeypatch.setenv("SCANNER_UA_POLICY", "block")
    assert run({"user-agent": "gobuster/3.5.0"})[0] == "block"
