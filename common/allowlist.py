"""Allowlist for cert-pinned apps that cannot be MITM-inspected.

Hosts matching an allowlist entry bypass MITM and pass through raw TCP.
Anything else is MITM'd normally; if the TLS upgrade fails (pinning),
the connection is dropped and the operator is hinted to allowlist it.

Entry syntax:
    exact.example.com     - exact hostname match
    *.whatsapp.net        - glob (fnmatch) wildcard match

Persistence: config/allowed_apps.json -> {"hosts": [...]}
"""
from __future__ import annotations

import json
import logging
import os
import threading
from fnmatch import fnmatch

logger = logging.getLogger("allowlist")

_CONFIG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "config"))
_PATH = os.path.join(_CONFIG_DIR, "allowed_apps.json")
_lock = threading.Lock()


def _load() -> list[str]:
    try:
        with open(_PATH) as f:
            data = json.load(f)
    except FileNotFoundError:
        return []
    except Exception as exc:
        logger.error(f"Failed to load allowlist: {exc}")
        return []
    hosts = data.get("hosts", []) if isinstance(data, dict) else []
    return [h.strip().lower() for h in hosts if isinstance(h, str) and h.strip()]


def _save(hosts: list[str]) -> None:
    os.makedirs(_CONFIG_DIR, exist_ok=True)
    tmp = _PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"hosts": hosts}, f, indent=2)
    os.replace(tmp, _PATH)


def list_hosts() -> list[str]:
    with _lock:
        return _load()


def add_host(host: str) -> bool:
    host = (host or "").strip().lower()
    if not host:
        return False
    with _lock:
        hosts = _load()
        if host in hosts:
            return False
        hosts.append(host)
        _save(hosts)
    logger.info(f"Allowlist: added {host}")
    return True


def remove_host(host: str) -> bool:
    host = (host or "").strip().lower()
    if not host:
        return False
    with _lock:
        hosts = _load()
        if host not in hosts:
            return False
        hosts.remove(host)
        _save(hosts)
    logger.info(f"Allowlist: removed {host}")
    return True


def is_allowed(host: str) -> bool:
    if not host:
        return False
    host_l = host.strip().lower()
    for pattern in list_hosts():
        if pattern == host_l or fnmatch(host_l, pattern):
            return True
    return False
