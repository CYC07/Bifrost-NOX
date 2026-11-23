"""The C++ BrainClient against the REAL network_inspector/ai_brain.py, with real DNS packets.

test_firewall_engine_brain.py proves the client's timeout/rebuild logic against a fake brain. This one
proves the two halves actually fit: the wire format, the blocklist verdicts, and what happens to DNS when
the real brain is killed, hung (SIGSTOP) and brought back.

The brain binds the fixed endpoint ipc:///tmp/firewall_pipeline, so the module is skipped when a live
firewall already owns it.
"""
import os
import shutil
import signal
import subprocess
import sys
import time

import pytest

zmq = pytest.importorskip("zmq")
pytest.importorskip("scapy")
pytest.importorskip("requests")
from scapy.layers.dns import DNS, DNSQR  # noqa: E402
from scapy.layers.inet import IP, UDP  # noqa: E402

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CPP = os.path.join(ROOT, "network_inspector", "cpp")
SOCKET_FILE = "/tmp/firewall_pipeline"
ENDPOINT = "ipc://" + SOCKET_FILE
TIMEOUT_MS, COOLDOWN_MS = 500, 700

pytestmark = pytest.mark.skipif(
    shutil.which("g++") is None or not os.path.exists("/usr/include/zmq.hpp") or os.path.exists(SOCKET_FILE),
    reason="needs g++, cppzmq, and no live firewall brain on " + SOCKET_FILE)


def dns_query_hex(name: str) -> str:
    return bytes(IP(src="10.0.0.2", dst="8.8.8.8") / UDP(sport=40000, dport=53) /
                 DNS(rd=1, qd=DNSQR(qname=name))).hex()


class Brain:
    def __init__(self, cwd):
        self.cwd = cwd
        self.proc = None

    def start(self):
        env = {**os.environ, "PYTHONPATH": ROOT}
        self.proc = subprocess.Popen([sys.executable, os.path.join(ROOT, "network_inspector", "ai_brain.py")],
                                     cwd=self.cwd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.time() + 40                        # scapy / rule engine import takes a few seconds
        while time.time() < deadline and not os.path.exists(SOCKET_FILE):
            assert self.proc.poll() is None, "brain exited during startup"
            time.sleep(0.1)
        assert os.path.exists(SOCKET_FILE), "brain never bound its socket"

    def kill(self):
        self.proc.kill()
        self.proc.wait(5)
        if os.path.exists(SOCKET_FILE):
            os.unlink(SOCKET_FILE)                         # a killed process leaves its socket file behind

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGCONT)
            self.proc.kill()
            self.proc.wait(5)
        if os.path.exists(SOCKET_FILE):
            os.unlink(SOCKET_FILE)


class Probe:
    def __init__(self, binary):
        self.p = subprocess.Popen([binary, ENDPOINT, str(TIMEOUT_MS), str(COOLDOWN_MS), "open"],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)

    def dns(self, name):
        return self._ask(f"askhex 53 {dns_query_hex(name)}")

    def raw(self, dport, hexdata):
        return self._ask(f"askhex {dport} {hexdata}")

    def _ask(self, line):
        self.p.stdin.write(line + "\n")
        self.p.stdin.flush()
        verdict, skipped, ms = self.p.stdout.readline().split()
        return verdict, skipped == "1", int(ms)

    def close(self):
        try:
            self.p.stdin.write("quit\n")
            self.p.stdin.flush()
        except Exception:
            pass
        self.p.wait(5)


@pytest.fixture(scope="module")
def probe_bin(tmp_path_factory):
    out = str(tmp_path_factory.mktemp("probe") / "brain_probe")
    r = subprocess.run(["g++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-o", out,
                        os.path.join(CPP, "brain_probe.cpp"), "-lzmq"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return out


@pytest.fixture()
def lab(tmp_path, probe_bin):
    brain = Brain(str(tmp_path))
    brain.start()
    probe = Probe(probe_bin)
    yield brain, probe
    probe.close()
    brain.stop()


def test_real_dns_verdicts(lab):
    _brain, probe = lab
    assert probe.dns("example.com")[0] == "ALLOW"
    assert probe.dns("malware.wicar.org")[0] == "BLOCK"          # on config/dns_blocklist.json
    assert probe.dns("sub.testmyids.com")[0] == "BLOCK"          # suffix match: subdomain of a listed domain
    assert probe.dns("notwicar.org")[0] == "ALLOW"               # label boundary: not a suffix match
    assert probe.raw(21, "deadbeef")[0] == "ALLOW"               # FTP-style traffic is observed and allowed
    assert probe.raw(53, "00")[0] == "ALLOW"                     # unparseable DNS fails open inside the brain


def test_killing_the_real_brain_never_stalls_dns_and_recovery_is_automatic(lab):
    brain, probe = lab
    assert probe.dns("malware.wicar.org")[0] == "BLOCK"
    brain.kill()

    verdict, skipped, ms = probe.dns("example.com")              # first lookup after the crash
    assert verdict == "UNAVAILABLE" and not skipped and ms < 1500
    for _ in range(5):                                           # the rest of the burst: no waiting at all
        verdict, skipped, ms = probe.dns("example.com")
        assert verdict == "UNAVAILABLE" and skipped and ms < 50

    brain.start()                                                # operator restarts the brain
    time.sleep(COOLDOWN_MS / 1000 + 0.3)
    assert probe.dns("malware.wicar.org")[0] == "BLOCK"          # filtering is back without restarting the engine
    assert probe.dns("example.com")[0] == "ALLOW"


def test_a_hung_real_brain_times_out_and_recovers_when_resumed(lab):
    brain, probe = lab
    assert probe.dns("example.com")[0] == "ALLOW"
    brain.proc.send_signal(signal.SIGSTOP)                       # alive, but answers nothing
    verdict, _skipped, ms = probe.dns("example.com")
    assert verdict == "UNAVAILABLE" and TIMEOUT_MS * 0.8 <= ms < TIMEOUT_MS + 800
    brain.proc.send_signal(signal.SIGCONT)
    time.sleep(COOLDOWN_MS / 1000 + 0.3)
    assert probe.dns("malware.wicar.org")[0] == "BLOCK"
