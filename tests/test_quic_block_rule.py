"""Clients must not be able to bypass the firewall over QUIC (HTTP/3, UDP port 443).

The firewall redirects TCP 80/443 to its inspecting proxy. QUIC rides on UDP 443, which that redirect never sees, so a
browser that has learned a site supports HTTP/3 (Google advertises it via Alt-Svc) talks to it directly, and nothing on
that connection is inspected: in the VM lab Edge opened hundreds of QUIC packets to Google while the gateway saw almost
none of it, which is why Google Images blocked images at first and then stopped blocking them.

The fix is the standard one for an inspecting proxy: refuse UDP 443 from the client side (an immediate ICMP port
unreachable, not a silent drop), so the browser falls back to TCP at once. BLOCK_QUIC=0 turns it off.
These tests run the helper against a fake `iptables` that records its calls.
"""
import os
import stat
import subprocess

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
HELPER = os.path.join(ROOT, "network_inspector", "quic_rule.sh")
RULE = "-i wlan9 -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable"


@pytest.fixture()
def fake_iptables(tmp_path):
    """A stand-in iptables: logs every call; `-C` (check) answers from FAKE_C_SEQ, a space separated list of exit
    codes consumed one per -C call (default: rule absent)."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "calls.log"
    state = tmp_path / "c_count"
    script = bindir / "iptables"
    script.write_text(f"""#!/bin/bash
echo "$*" >> "{log}"
case " $* " in
  *" -C "*)
    n=$(cat "{state}" 2>/dev/null || echo 0); echo $((n+1)) > "{state}"
    seq=(${{FAKE_C_SEQ:-1}}); i=$n; [ $i -ge ${{#seq[@]}} ] && i=$((${{#seq[@]}}-1)); exit ${{seq[$i]}} ;;
esac
exit 0
""")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)

    def run(fn, iface="wlan9", **env):
        e = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}", **env}
        e.pop("BLOCK_QUIC", None) if "BLOCK_QUIC" not in env else None
        if log.exists():
            log.unlink()
        if state.exists():
            state.unlink()
        r = subprocess.run(["bash", "-c", f'source "{HELPER}"; {fn} {iface}'], capture_output=True, text=True, env=e)
        calls = log.read_text().splitlines() if log.exists() else []
        return r, calls
    return run


def test_blocking_adds_one_reject_rule_at_the_top_of_forward(fake_iptables):
    r, calls = fake_iptables("block_quic")
    assert r.returncode == 0
    assert calls == [f"-C FORWARD {RULE}", f"-I FORWARD 1 {RULE}"]       # check first, then insert at position 1


def test_blocking_is_idempotent(fake_iptables):
    r, calls = fake_iptables("block_quic", FAKE_C_SEQ="0")               # the rule already exists
    assert r.returncode == 0 and calls == [f"-C FORWARD {RULE}"]


def test_it_can_be_switched_off(fake_iptables):
    r, calls = fake_iptables("block_quic", BLOCK_QUIC="0")
    assert r.returncode == 0 and calls == []
    assert "disabled" in (r.stdout + r.stderr).lower()


def test_unblocking_removes_every_copy_and_stops(fake_iptables):
    r, calls = fake_iptables("unblock_quic", FAKE_C_SEQ="0 0 1")         # two copies present, then gone
    assert r.returncode == 0
    assert calls == [f"-C FORWARD {RULE}", f"-D FORWARD {RULE}", f"-C FORWARD {RULE}", f"-D FORWARD {RULE}",
                     f"-C FORWARD {RULE}"]


def test_unblocking_when_nothing_is_installed_is_a_no_op(fake_iptables):
    r, calls = fake_iptables("unblock_quic", FAKE_C_SEQ="1")
    assert r.returncode == 0 and calls == [f"-C FORWARD {RULE}"]


def test_the_rule_is_per_client_interface_and_only_udp_443(fake_iptables):
    _r, calls = fake_iptables("block_quic", iface="vboxnet0")
    assert all("-i vboxnet0 -p udp --dport 443" in c for c in calls)
    assert not any("--dport 80" in c or "-p tcp" in c for c in calls)    # TCP (what we inspect) is never touched


# ---------------------------------------------------------------- wiring into the scripts that manage the lab

def _text(rel):
    return open(os.path.join(ROOT, rel)).read()


def _code(rel):
    return "\n".join(l for l in _text(rel).splitlines() if not l.lstrip().startswith("#"))


def test_start_network_installs_the_rule_for_the_client_interface():
    code = _code("start_network.sh")
    assert 'source "$REPO_DIR/network_inspector/quic_rule.sh"' in code
    assert 'block_quic "$HOTSPOT_IF"' in code


def test_every_way_of_stopping_the_firewall_removes_it():
    assert 'unblock_quic "$HOTSPOT_IF"' in _code("stop_all.sh")
    assert 'unblock_quic "$LAB_IF"' in _code("vm-lab/vm_lab.sh")


@pytest.mark.parametrize("script", ["start_network.sh", "stop_all.sh", "vm-lab/vm_lab.sh", "network_inspector/quic_rule.sh"])
def test_scripts_still_parse(script):
    assert subprocess.run(["bash", "-n", os.path.join(ROOT, script)]).returncode == 0
