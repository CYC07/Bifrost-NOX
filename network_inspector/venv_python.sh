#!/bin/bash
# Sourced by start_network.sh (and testable on its own).
#
# resolve_venv_python <repo_dir>
#   Prints the absolute path of the interpreter ai_brain.py must run with: $PYTHON when set (must be an
#   absolute path), else <repo_dir>/venv/bin/python. Fails with a clear message when it is missing or
#   cannot import zmq.
#
# Why: the script used a bare `python3`. Under sudo that is the system interpreter, which has no zmq, so the
# brain died at import and the C++ engine then waited on it forever (DNS through the firewall stalled).

resolve_venv_python() {
    local repo="$1"
    local py="${PYTHON:-$repo/venv/bin/python}"

    case "$py" in
        /*) ;;
        *) echo "ERROR: PYTHON must be an absolute path (got '$py')" >&2; return 1 ;;
    esac
    if [ ! -x "$py" ]; then
        echo "ERROR: virtualenv interpreter not found at $py" >&2
        echo "       create it:  python3 -m venv $repo/venv && $repo/venv/bin/pip install -r requirements.txt" >&2
        return 1
    fi
    if ! "$py" -c 'import zmq' 2>/dev/null; then
        echo "ERROR: $py cannot import zmq (the brain would die at startup)" >&2
        echo "       install it:  $py -m pip install pyzmq" >&2
        return 1
    fi
    printf '%s\n' "$py"
}
