"""Is this request headed to an LLM endpoint?

Prompt-injection detection only makes sense for text that will reach an
instruction-following model, so the (expensive, false-positive-prone) PI
classifier is scoped to traffic identified here. A request is in scope when it
is OUTBOUND and any of:
  1. its host is on the admin list (config/llm_hosts.json "hosts"), or
  2. its path ends with a known LLM API path ("paths"), or
  3. its JSON body looks like an LLM call: a "model" key plus one of
     messages / prompt / input / contents.

Host patterns are exact or "*.suffix" (matches subdomains only — never a bare
suffix, which would let "evilopenai.azure.com" match "*openai.azure.com").
The config is re-read when its mtime changes. A missing or corrupt config
degrades to path/body-shape detection only.
"""
from __future__ import annotations

import json
import logging
import os
import threading

logger = logging.getLogger("llm_scope")

_CONFIG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "config")
_PATH = os.path.join(_CONFIG_DIR, "llm_hosts.json")

_lock = threading.Lock()
_cache: dict = {"mtime": None, "hosts": [], "paths": []}
_BODY_KEYS = ("messages", "prompt", "input", "contents")


def _reset_cache() -> None:
    with _lock:
        _cache.update(mtime=None, hosts=[], paths=[])


def _load() -> tuple[list[str], list[str]]:
    try:
        mtime = os.stat(_PATH).st_mtime
    except OSError:
        return [], []
    with _lock:
        if _cache["mtime"] == mtime:
            return _cache["hosts"], _cache["paths"]
        try:
            with open(_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            hosts = [str(h).strip().lower() for h in data.get("hosts", []) if str(h).strip()]
            paths = [str(p).strip() for p in data.get("paths", []) if str(p).strip()]
        except Exception as exc:  # noqa: BLE001 — never break inspection over config
            logger.warning("llm_hosts.json unreadable (%s); using path/body-shape detection only", exc)
            hosts, paths = [], []
        _cache.update(mtime=mtime, hosts=hosts, paths=paths)
        return hosts, paths


def _host_matches(host: str, pattern: str) -> bool:
    if pattern.startswith("*."):
        return host.endswith(pattern[1:]) and len(host) > len(pattern) - 1
    return host == pattern


def _body_looks_like_llm(body) -> bool:
    if not body or not isinstance(body, str) or not body.lstrip().startswith("{"):
        return False
    try:
        obj = json.loads(body)
    except Exception:  # noqa: BLE001
        return False
    return isinstance(obj, dict) and "model" in obj and any(k in obj for k in _BODY_KEYS)


def is_llm_request(host, path, body, direction) -> bool:
    if (direction or "outbound") != "outbound":
        return False
    hosts, paths = _load()
    h = (host or "").strip().lower()
    if h and any(_host_matches(h, p) for p in hosts):
        return True
    p = (path or "").split("?", 1)[0]
    if p and any(p.endswith(known) for known in paths):
        return True
    return _body_looks_like_llm(body)
