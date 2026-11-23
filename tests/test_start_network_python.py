"""start_network.sh must run ai_brain.py with the project's virtualenv Python, by absolute path.

It used a bare `python3`. Under `sudo` that is the system interpreter, which has no `zmq`: the brain
died at import (`ModuleNotFoundError: zmq`), the C++ engine then waited on it forever, and DNS through
the firewall stalled. Only vm-lab/vm_lab.sh worked around it (by prepending the venv to PATH).
"""
import os
import re
import stat
import subprocess

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPT = os.path.join(ROOT, "start_network.sh")
HELPER = os.path.join(ROOT, "network_inspector", "venv_python.sh")


def _fake_python(path, has_zmq=True):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write("#!/bin/sh\n" + ("exit 0\n" if has_zmq else "echo ModuleNotFoundError >&2; exit 1\n"))
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
    return path


def _resolve(repo, env_python=None):
    env = {k: v for k, v in os.environ.items() if k != "PYTHON"}
    if env_python is not None:
        env["PYTHON"] = env_python
    r = subprocess.run(["bash", "-c", f'source "{HELPER}"; resolve_venv_python "{repo}"'],
                       capture_output=True, text=True, env=env)
    return r.returncode, r.stdout.strip(), r.stderr


def test_uses_the_repo_venv_by_absolute_path(tmp_path):
    py = _fake_python(str(tmp_path / "venv" / "bin" / "python"))
    rc, out, _ = _resolve(str(tmp_path))
    assert rc == 0 and out == py and os.path.isabs(out)


def test_missing_venv_is_a_clear_error_not_a_silent_fallback(tmp_path):
    rc, out, err = _resolve(str(tmp_path))
    assert rc != 0 and out == ""
    assert "venv" in err and "python3 -m venv" in err        # tells the operator how to fix it


def test_interpreter_without_zmq_is_rejected_up_front(tmp_path):
    _fake_python(str(tmp_path / "venv" / "bin" / "python"), has_zmq=False)
    rc, out, err = _resolve(str(tmp_path))
    assert rc != 0 and "zmq" in err.lower()


def test_python_override_must_be_absolute_and_is_honoured(tmp_path):
    alt = _fake_python(str(tmp_path / "elsewhere" / "py"))
    assert _resolve(str(tmp_path), env_python=alt)[:2] == (0, alt)
    rc, _, err = _resolve(str(tmp_path), env_python="python3")
    assert rc != 0 and "absolute" in err.lower()


def test_script_has_valid_syntax():
    assert subprocess.run(["bash", "-n", SCRIPT]).returncode == 0
    assert subprocess.run(["bash", "-n", HELPER]).returncode == 0


def test_script_never_launches_the_brain_with_a_bare_python():
    text = open(SCRIPT).read()
    code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
    assert not re.search(r"\bpython3?\s+network_inspector/ai_brain\.py", code), "bare python on ai_brain.py"
    assert re.search(r'"\$PYTHON"\s+network_inspector/ai_brain\.py|"\$PYTHON"\s+"\$REPO_DIR/network_inspector/ai_brain\.py"', code)
    assert "resolve_venv_python" in code


def test_script_checks_the_brain_survived_startup_before_starting_the_engine():
    code = open(SCRIPT).read()
    brain = code.index("ai_brain.py")
    engine = code.index("firewall_engine", brain)
    between = code[brain:engine]
    assert "kill -0" in between, "must verify the brain is alive before launching the engine"


def test_interpreter_is_checked_before_any_firewall_rule_is_changed():
    """Failing after iptables is half-configured is avoidable: resolve the Python first."""
    code = "\n".join(l for l in open(SCRIPT).read().splitlines() if not l.lstrip().startswith("#"))
    assert code.index("resolve_venv_python \"$REPO_DIR\"") < code.index("iptables")
