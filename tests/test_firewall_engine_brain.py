"""The C++ firewall engine must not stall DNS/FTP when the Python brain is dead or hung.

The engine asks ai_brain.py for a verdict over a ZeroMQ REQ socket from inside the NFQUEUE callback.
`recv` had no timeout, so a dead brain blocked the callback forever and every queued packet (DNS for the
whole lab) waited with it, contradicting the "fail-open" promise in start_network.sh. A REQ socket is also
unusable after a missed reply, so a timeout alone would not recover once the brain came back.

These tests build the real BrainClient (network_inspector/cpp/brain_client.hpp) into a small probe and
drive it against a fake brain written in Python.
"""
import os
import shutil
import subprocess
import threading
import time

import pytest

zmq = pytest.importorskip("zmq")

CPP = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "network_inspector", "cpp"))
TIMEOUT_MS = 400
COOLDOWN_MS = 600

pytestmark = pytest.mark.skipif(
    shutil.which("g++") is None or not os.path.exists("/usr/include/zmq.hpp"),
    reason="needs g++ and cppzmq headers")


@pytest.fixture(scope="module")
def probe_bin(tmp_path_factory):
    out = str(tmp_path_factory.mktemp("probe") / "brain_probe")
    r = subprocess.run(["g++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-o", out,
                        os.path.join(CPP, "brain_probe.cpp"), "-lzmq"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return out


class FakeBrain:
    """A REP socket whose behaviour the test switches: reply ALLOW, reply BLOCK, or never read."""

    def __init__(self, endpoint):
        self.endpoint = endpoint
        self._mode = "off"           # off | allow | block | hang
        self._loops = 0
        self.seen = []
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._run, daemon=True)
        self._ctx = zmq.Context()

    @property
    def mode(self):
        return self._mode

    @mode.setter
    def mode(self, value):
        """Switch behaviour and return only once the serving thread has applied it (no test races)."""
        self._mode = value
        start = self._loops
        deadline = time.time() + 2
        while self._loops < start + 2 and time.time() < deadline:
            time.sleep(0.005)

    def start(self):
        self._t.start()
        return self

    def _run(self):
        sock = self._ctx.socket(zmq.REP)
        sock.setsockopt(zmq.LINGER, 0)
        bound = False
        while not self._stop.is_set():
            self._loops += 1
            mode = self._mode                          # one snapshot per iteration
            if mode == "off":
                if bound:
                    sock.unbind(self.endpoint)
                    bound = False
                time.sleep(0.02)
                continue
            if not bound:
                sock.bind(self.endpoint)
                bound = True
            if mode == "hang":
                time.sleep(0.02)                       # connected and accepting, but never answers
                continue
            if sock.poll(50):
                parts = sock.recv_multipart()
                self.seen.append(parts[0].decode())
                sock.send(b"ALLOW" if mode == "allow" else b"BLOCK")
        sock.close(0)

    def stop(self):
        self._stop.set()
        self._t.join(2)
        self._ctx.term()


class Probe:
    def __init__(self, binary, endpoint, mode="open"):
        self.p = subprocess.Popen([binary, endpoint, str(TIMEOUT_MS), str(COOLDOWN_MS), mode],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)

    def ask(self):
        """-> (verdict, skipped, elapsed_ms)"""
        self.p.stdin.write("ask\n")
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


@pytest.fixture()
def rig(tmp_path, probe_bin):
    endpoint = f"ipc://{tmp_path}/brain.ipc"
    brain = FakeBrain(endpoint).start()
    probes = []

    def make(mode="open"):
        pr = Probe(probe_bin, endpoint, mode)
        probes.append(pr)
        return pr
    yield brain, make
    for pr in probes:
        pr.close()
    brain.stop()


def _wait_cooldown():
    time.sleep(COOLDOWN_MS / 1000 + 0.2)


def test_normal_verdicts_pass_through(rig):
    brain, make = rig
    brain.mode = "allow"
    probe = make()
    assert probe.ask()[0] == "ALLOW"
    brain.mode = "block"
    assert probe.ask()[0] == "BLOCK"
    assert len(brain.seen) == 2 and brain.seen[0].startswith("check ")


def test_dead_brain_fails_fast_instead_of_blocking_forever(rig):
    brain, make = rig
    brain.mode = "off"                                   # nothing is bound: the process is gone
    verdict, skipped, ms = make().ask()
    assert verdict == "UNAVAILABLE" and not skipped
    assert ms < 1500                                      # bounded (it used to block forever)


def test_hung_brain_times_out(rig):
    brain, make = rig
    brain.mode = "hang"                                  # alive, accepts the request, never answers
    verdict, skipped, ms = make().ask()
    assert verdict == "UNAVAILABLE"
    assert TIMEOUT_MS * 0.8 <= ms < TIMEOUT_MS + 700


def test_after_a_failure_the_next_flows_are_not_delayed(rig):
    brain, make = rig
    brain.mode = "off"
    probe = make()
    assert probe.ask()[0] == "UNAVAILABLE"
    verdict, skipped, ms = probe.ask()                    # inside the cool-down: no waiting at all
    assert verdict == "UNAVAILABLE" and skipped and ms < 50


def test_recovers_when_the_brain_comes_back_after_a_hang(rig):
    """The REQ-socket trap: after a missed reply the old socket can never send again. The client must
    have rebuilt it, otherwise it stays dead until the engine is restarted."""
    brain, make = rig
    brain.mode = "hang"
    probe = make()
    assert probe.ask()[0] == "UNAVAILABLE"
    brain.mode = "allow"
    _wait_cooldown()
    assert probe.ask()[0] == "ALLOW"
    assert probe.ask()[0] == "ALLOW"


def test_recovers_when_the_brain_is_restarted(rig):
    brain, make = rig
    brain.mode = "allow"
    probe = make()
    assert probe.ask()[0] == "ALLOW"
    brain.mode = "off"                                   # brain crashes
    assert probe.ask()[0] == "UNAVAILABLE"
    brain.mode = "block"                                 # brain restarted by the operator
    _wait_cooldown()
    assert probe.ask()[0] == "BLOCK"


def test_the_probe_reports_the_configured_failure_policy(rig):
    """open (default): an unavailable brain means ALLOW; closed: DROP. The engine applies this."""
    brain, make = rig
    brain.mode = "off"
    assert make("open").ask()[0] == "UNAVAILABLE"
    out = subprocess.run([make("closed").p.args[0], "ipc:///nonexistent", "100", "100", "closed"],
                         input="policy\nquit\n", capture_output=True, text=True, timeout=10).stdout
    assert out.strip() == "closed"


def test_a_non_positive_timeout_cannot_bring_back_the_infinite_wait(rig, probe_bin):
    """Constructing the client with timeout <= 0 used to mean ZeroMQ's -1 (block forever): the original bug."""
    brain, _make = rig
    brain.mode = "hang"
    p = subprocess.Popen([probe_bin, brain.endpoint, "-1", str(COOLDOWN_MS), "open"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
    try:
        p.stdin.write("ask\n")
        p.stdin.flush()
        verdict, _skipped, ms = p.stdout.readline().split()
        assert verdict == "UNAVAILABLE" and int(ms) < 3000
    finally:
        p.stdin.write("quit\n")
        p.stdin.flush()
        p.wait(5)


def test_a_zero_cooldown_means_every_request_is_tried(tmp_path, probe_bin):
    ep = f"ipc://{tmp_path}/none.ipc"                     # nothing bound
    p = subprocess.Popen([probe_bin, ep, str(TIMEOUT_MS), "0", "open"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
    try:
        for _ in range(2):
            p.stdin.write("ask\n")
            p.stdin.flush()
            verdict, skipped, _ms = p.stdout.readline().split()
            assert verdict == "UNAVAILABLE" and skipped == "0"
    finally:
        p.stdin.write("quit\n")
        p.stdin.flush()
        p.wait(5)
