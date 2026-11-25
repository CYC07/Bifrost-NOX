"""The start/stop scripts must work from any checkout, because the README tells people to run them.

They hard-coded one developer's home directory (vm_lab.sh defaulted to /home/pentest/..., start_gateway.sh activated
/home/cyc0logy/...), and nothing started the AI services and gateway without also setting up the Wi-Fi hotspot, which
the VM lab needs. start_services.sh does that; these tests run it in dry-run mode against fakes.
"""
import os
import shutil
import stat
import subprocess

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPTS = ["start_all.sh", "start_network.sh", "start_services.sh", "start_gateway.sh", "stop_all.sh",
           "vm-lab/vm_lab.sh", "network_inspector/venv_python.sh", "network_inspector/quic_rule.sh"]


def _exe(path, body):
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


@pytest.mark.parametrize("script", SCRIPTS)
def test_scripts_parse_and_hard_code_no_home_directory(script):
    path = os.path.join(ROOT, script)
    assert subprocess.run(["bash", "-n", path]).returncode == 0
    assert "/home/" not in open(path).read(), f"{script} hard-codes a home directory"


def test_vm_lab_finds_the_checkout_it_lives_in():
    text = open(os.path.join(ROOT, "vm-lab/vm_lab.sh")).read()
    assert 'REPO="${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"' in text


@pytest.fixture()
def sandbox(tmp_path):
    """A minimal copy of the repo layout start_services.sh needs, plus a fake venv python and a fake pgrep."""
    (tmp_path / "network_inspector").mkdir()
    shutil.copy(os.path.join(ROOT, "start_services.sh"), tmp_path / "start_services.sh")
    shutil.copy(os.path.join(ROOT, "network_inspector/venv_python.sh"), tmp_path / "network_inspector/venv_python.sh")
    (tmp_path / "venv" / "bin").mkdir(parents=True)
    _exe(tmp_path / "venv/bin/python", "#!/bin/sh\nexit 0\n")              # "imports zmq" fine
    bindir = tmp_path / "fakebin"
    bindir.mkdir()

    def run(running: bool):
        _exe(bindir / "pgrep", f"#!/bin/sh\nexit {0 if running else 1}\n")
        env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}", "DRY_RUN": "1"}
        env.pop("PYTHON", None)
        r = subprocess.run(["bash", str(tmp_path / "start_services.sh")], capture_output=True, text=True, env=env)
        return r, str(tmp_path / "venv/bin/python")
    return run


def test_start_services_starts_the_four_services_and_the_gateway_with_the_venv_python(sandbox):
    r, py = sandbox(running=False)
    assert r.returncode == 0, r.stderr
    lines = [l for l in r.stdout.splitlines() if "would start" in l]
    assert len(lines) == 5
    for port, module in (("8000", "master_ai.orchestrator:app"), ("8001", "image_service.main:app"),
                         ("8002", "document_service.main:app"), ("8003", "text_service.main:app")):
        assert any(f"{py} -m uvicorn {module} --host 0.0.0.0 --port {port}" in l for l in lines), module
    assert any(f"{py} gateway/proxy.py" in l for l in lines)


def test_start_services_leaves_running_services_alone(sandbox):
    r, _ = sandbox(running=True)
    assert r.returncode == 0
    assert r.stdout.count("already running") == 5 and "would start" not in r.stdout


def test_start_services_refuses_to_run_without_the_venv(sandbox, tmp_path):
    shutil.rmtree(tmp_path / "venv")
    r, _ = sandbox(running=False)
    assert r.returncode != 0 and "venv" in r.stderr
