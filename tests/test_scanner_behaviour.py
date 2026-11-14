"""Behavioural scanner detection (ml/waf/behaviour.py + the gateway hook).

A User-Agent is one flag away from being spoofed; what a scanner cannot hide is that nearly everything it asks for
does not exist. Per (client, host) the tracker watches a sliding window of response statuses: a high share of
404/403/405/410 across MANY distinct paths is enumeration. Pages that really exist (an admin opening wp-admin and
phpmyadmin), a half-broken site, or a password brute force against one URL must NOT trigger it.
"""
import asyncio
import os
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "gateway"))
sys.path.insert(0, ROOT)
from ml.waf.behaviour import ScannerTracker, scanner_behaviour_policy  # noqa: E402
import proxy as gw  # noqa: E402

C, H = "10.0.0.7", "shop.example"


def drive(tr, paths, statuses, t0=1000.0, dt=0.1, client=C, host=H):
    """Request each path then record its response; returns the time after the last one."""
    t = t0
    for p, st in zip(paths, statuses):
        tr.observe_request(client, host, p, now=t)
        tr.observe_response(client, host, st, now=t + 0.01)
        t += dt
    return t


def first_flag(tr, paths, statuses, **kw):
    t = kw.get("t0", 1000.0)
    dt = kw.get("dt", 0.1)
    for i, (p, st) in enumerate(zip(paths, statuses), start=1):
        tr.observe_request(C, H, p, now=t)
        tr.observe_response(C, H, st, now=t + 0.01)
        if tr.blocked(C, H, now=t + 0.02):
            return i
        t += dt
    return None


WORDS = [f"/{w}" for w in ("admin", "backup", "old", "test", "tmp", "api", "dev", "cgi", "files", "img") * 40]
UNIQ = [f"/dir{i}" for i in range(400)]


def test_directory_wordlist_scan_is_flagged_within_a_few_dozen_requests():
    n = first_flag(ScannerTracker(), UNIQ, [404] * len(UNIQ))
    assert n is not None and n <= 80, n          # needs >= 5 s of sustained misses, so ~50 requests at 10/s


@pytest.mark.parametrize("dt,limit", [(1.0, 30), (0.1, 80), (0.02, 400), (0.005, 1500), (0.001, 7000)])
def test_scans_are_flagged_after_about_five_seconds_of_traffic_at_any_request_rate(dt, limit):
    """Regression: a per-entry history (600 items) covered only 3 s at 200 req/s, so fast scans were never flagged."""
    paths = [f"/w{i}" for i in range(12000)]
    n = first_flag(ScannerTracker(), paths, [404] * len(paths), dt=dt)
    assert n is not None and n <= limit, (dt, n)


def test_a_scan_that_finds_a_few_real_pages_is_still_flagged():
    sts = [200 if i % 25 == 0 else 404 for i in range(400)]            # 4% hits
    assert first_flag(ScannerTracker(), UNIQ, sts) is not None


def test_mixed_403_405_410_errors_count_as_misses_too():
    sts = [(403, 405, 410, 404)[i % 4] for i in range(400)]
    assert first_flag(ScannerTracker(), UNIQ, sts) is not None


def test_flag_blocks_that_client_and_host_for_the_cooldown_then_expires():
    tr = ScannerTracker(cooldown=300)
    first_flag(tr, UNIQ, [404] * len(UNIQ))
    t = 1000.0 + 50
    assert tr.blocked(C, H, now=t) and tr.blocked(C, H, now=t + 200)
    assert tr.blocked(C, H, now=t + 100000) is None


def test_other_clients_and_other_hosts_are_unaffected():
    tr = ScannerTracker()
    first_flag(tr, UNIQ, [404] * len(UNIQ))
    assert tr.blocked(C, H, now=1005.0)
    assert tr.blocked("10.0.0.8", H, now=1005.0) is None
    assert tr.blocked(C, "other.example", now=1005.0) is None


def test_ordinary_browsing_with_the_occasional_missing_asset_is_never_flagged():
    tr = ScannerTracker()
    paths, sts = [], []
    for page in range(120):
        paths += [f"/p/{page}"] + [f"/static/a{page}_{k}.js" for k in range(8)] + [f"/img/{page}.png"]
        sts += [200] + [200] * 8 + [404 if page % 9 == 0 else 304]
    assert first_flag(tr, paths, sts, dt=0.2) is None


def test_a_gallery_page_whose_thumbnails_are_all_missing_is_one_burst_not_a_scan():
    """40 distinct 404s inside ~1.2 s (a browser loading a broken page): errors are not spread over time."""
    paths = ["/gallery"] + [f"/thumb/{i}.jpg" for i in range(40)] + [f"/ok/{i}.css" for i in range(10)]
    sts = [200] + [404] * 40 + [200] * 10
    assert first_flag(ScannerTracker(), paths, sts, dt=0.03) is None


def test_a_half_broken_site_browsed_for_a_minute_is_not_flagged():
    paths = [f"/thumb/{i}.jpg" if i % 2 else f"/ok/{i}.css" for i in range(90)]
    sts = [404 if i % 2 else 200 for i in range(90)]                 # 50% missing, sustained: ratio below 85%
    assert first_flag(ScannerTracker(), paths, sts, dt=0.6) is None


def test_password_guessing_against_one_url_is_not_scanner_behaviour():
    assert first_flag(ScannerTracker(), ["/login"] * 200, [401] * 200) is None


def test_a_slow_scan_below_the_window_rate_is_a_documented_limit():
    """20 requests/minute never reaches 25 responses inside one 60 s window."""
    paths = [f"/slow{i}" for i in range(120)]
    assert first_flag(ScannerTracker(), paths, [404] * 120, dt=3.0) is None


def test_unknown_status_zero_never_counts():
    assert first_flag(ScannerTracker(), UNIQ, [0] * len(UNIQ)) is None


@pytest.mark.parametrize("paths", [
    ["/.env", "/wp-login.php", "/phpmyadmin/", "/server-status"],
    ["/.git/config", "/actuator/env", "/backup.sql", "/wp-admin/"],
    ["/xmlrpc.php", "/.htpasswd", "/manager/html", "/adminer.php"],
])
def test_three_recon_families_that_all_miss_are_flagged(paths):
    tr = ScannerTracker()
    drive(tr, paths + paths, [404] * (2 * len(paths)), dt=1.0)
    assert tr.blocked(C, H, now=1020.0)


def test_the_same_recon_paths_that_exist_are_just_an_admin_working():
    paths = ["/wp-admin/", "/phpmyadmin/", "/server-status", "/.env"]
    tr = ScannerTracker()
    drive(tr, paths * 3, [200, 200, 200, 403] * 3, dt=1.0)
    assert tr.blocked(C, H, now=1020.0) is None


def test_two_recon_families_are_not_enough():
    tr = ScannerTracker()
    drive(tr, ["/wp-login.php", "/phpmyadmin/"] * 5, [404] * 10, dt=1.0)
    assert tr.blocked(C, H, now=1015.0) is None


def test_host_names_are_normalised_for_case_and_port():
    tr = ScannerTracker()
    for i, p in enumerate(UNIQ):
        tr.observe_request(C, "Shop.Example:443", p, now=1000 + i * 0.1)
        tr.observe_response(C, "shop.example", 404, now=1000.01 + i * 0.1)
    assert tr.blocked(C, "SHOP.example:8443", now=1060.0)


def test_memory_is_bounded_under_a_flood_of_distinct_clients():
    tr = ScannerTracker(max_keys=500)
    for i in range(20_000):
        tr.observe_request(f"10.{i // 256 % 256}.{i % 256}.1", H, "/x", now=1000 + i * 0.001)
        tr.observe_response(f"10.{i // 256 % 256}.{i % 256}.1", H, 404, now=1000 + i * 0.001)
    assert tr.size() <= 500


def test_garbage_input_never_raises():
    tr = ScannerTracker()
    for args in [(None, None, None), (C, H, 12345), ("", "", ""), (C, H, "/x" * 100_000)]:
        tr.observe_request(*args, now=1.0)
    tr.observe_response(None, None, "404", now=1.0)
    tr.observe_response(C, H, None, now=1.0)
    assert tr.blocked(None, None, now=1.0) is None


def test_policy_default_and_values(monkeypatch):
    monkeypatch.delenv("SCANNER_BEHAVIOUR_POLICY", raising=False)
    assert scanner_behaviour_policy() == "block"
    for raw, want in (("advisory", "advisory"), (" OFF ", "off"), ("block", "block"), ("junk", "block")):
        monkeypatch.setenv("SCANNER_BEHAVIOUR_POLICY", raw)
        assert scanner_behaviour_policy() == want


# --- gateway wiring --------------------------------------------------------------------------------
class Spy:
    def __init__(self):
        self.calls = []

    async def __call__(self, c_type, *a, **k):
        self.calls.append(c_type)
        return {"status": "allow"}


class Clock:
    def __init__(self):
        self.t = 5000.0

    def __call__(self):
        return self.t


class Rig:
    def __init__(self):
        self.clock = Clock()
        self.i = gw.IDPInspector()
        self.i.scanner_tracker = ScannerTracker(clock=self.clock)
        self.spy = Spy()
        self.i.send_to_ai = self.spy

    def request(self, path, client=C, host=H, ua="Mozilla/5.0 (X11; Linux x86_64) Chrome/120"):
        return asyncio.run(self.i.inspect_full({"user-agent": ua}, b"", "outbound", True, src_ip=client, dst_ip=host, dst_port=443, host=host,
                                               method="GET", path=path, server_name=host, dest_ip="203.0.113.9"))

    def response(self, status, client=C, host=H):
        return asyncio.run(self.i.inspect_full({"content-type": "text/html"}, b"", "inbound", True, src_ip=host, dst_ip=client, dst_port=443,
                                               host=host, method="", path="", server_name=host, dest_ip="203.0.113.9", status=status))

    def scan(self, n, status=404, **kw):
        out = []
        for k in range(n):
            self.clock.t += 0.1                           # 10 requests a second
            out.append(self.request(f"/w{k}", **kw))
            self.response(status, **kw)
        return out


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.delenv("SCANNER_BEHAVIOUR_POLICY", raising=False)
    monkeypatch.delenv("SCANNER_UA_POLICY", raising=False)


def test_gateway_blocks_a_spoofed_browser_ua_once_it_enumerates_404s():
    rig = Rig()
    verdicts = rig.scan(300)
    assert "block" in verdicts and verdicts.index("block") <= 80
    assert rig.request("/anything") == "block"


def test_gateway_leaves_other_hosts_and_clients_alone_after_a_flag():
    rig = Rig()
    rig.scan(300)
    assert rig.request("/ok", host="other.example") == "allow"
    assert rig.request("/ok", client="10.0.0.99") == "allow"


def test_gateway_does_not_flag_normal_traffic():
    rig = Rig()
    verdicts = rig.scan(300, status=200)
    assert set(verdicts) == {"allow"}


@pytest.mark.parametrize("policy", ["off", "advisory"])
def test_policy_off_and_advisory_never_block(monkeypatch, policy):
    monkeypatch.setenv("SCANNER_BEHAVIOUR_POLICY", policy)
    assert set(Rig().scan(300)) == {"allow"}
