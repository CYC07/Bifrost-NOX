"""Behavioural scanner detection: per (client, host), what the server SAID to the client's requests.

A User-Agent is one flag away from being spoofed; what a scanner cannot hide is that nearly everything it asks for
does not exist. A sliding window of response statuses is kept per (client, host):

* enumeration - at least `min_responses` responses in `window` seconds, >= `min_ratio` of them 404/403/405/410, across
  >= `min_paths` distinct paths, with the errors spread over >= `min_span` seconds (a page whose 40 thumbnails are all
  missing is one burst, a scanner keeps going);
* recon paths - requests for >= `probe_families` different well-known recon families (.env, wp-login, phpmyadmin,
  actuator, ...) in `probe_window` seconds while most responses are errors (an admin opening pages that EXIST is not
  a scanner).

A flagged (client, host) is refused for `cooldown` seconds; other clients and other hosts are untouched. Pure,
bounded memory (LRU of `max_keys` keys, capped deques), no network, never raises.
Policy (SCANNER_BEHAVIOUR_POLICY): block (default) | advisory (log only) | off.
"""
from __future__ import annotations

import os
import re
import time
from collections import OrderedDict, deque

ERROR_STATUSES = frozenset({403, 404, 405, 410})

_FAMILIES: dict[str, re.Pattern] = {
    "dotfiles": re.compile(r"/\.(?:env|git|svn|hg|htaccess|htpasswd|ds_store|aws|ssh|npmrc|docker|bash_history)\b"),
    "cms-admin": re.compile(r"/(?:wp-login\.php|wp-admin\b|xmlrpc\.php|administrator/index\.php|wp-json/wp/v2/users)"),
    "db-admin": re.compile(r"/(?:phpmyadmin|pma|adminer(?:\.php)?|myadmin|phppgadmin|dbadmin)\b"),
    "server-info": re.compile(r"/(?:server-status|server-info|phpinfo\.php|nginx_status)\b"),
    "backup-config": re.compile(r"/(?:(?:backup|dump|database|db|site|www)\.(?:sql|zip|tar|tar\.gz|gz|bak|7z|rar)|wp-config\.php|web\.config|config\.(?:php|json|ya?ml|bak|old)|\.?settings\.py)\b"),
    "java-admin": re.compile(r"/(?:actuator(?:/\w+)?|manager/html|jmx-console|web-console|jenkins/script|solr/admin|console/login)\b"),
    "cgi-shell": re.compile(r"/(?:cgi-bin/|c99\.php|r57\.php|webshell|shell\.(?:php|jsp|asp)|eval-stdin\.php)"),
    "sensitive-files": re.compile(r"/(?:etc/passwd|proc/self/environ|boot\.ini|windows/win\.ini)"),
    "api-docs": re.compile(r"/(?:swagger(?:-ui)?(?:\.html|\.json)?|api-docs|openapi\.json|v2/api-docs|graphql/schema)\b"),
}
_PORT = re.compile(r":\d{1,5}$")


def scanner_behaviour_policy() -> str:
    """block (default) | advisory | off; anything else means block."""
    v = os.environ.get("SCANNER_BEHAVIOUR_POLICY", "block").strip().lower()
    return v if v in ("block", "advisory", "off") else "block"


class _State:
    """Time-bucketed so the window is real time at ANY request rate: memory per key is bounded
    (<= ~130 one-second buckets, <= 64 remembered paths, <= len(_FAMILIES) families)."""
    __slots__ = ("buckets", "paths", "families", "until", "reason")

    def __init__(self):
        self.buckets: deque = deque()             # [second, responses, errors]
        self.paths: OrderedDict = OrderedDict()   # path -> last seen (capped)
        self.families: dict = {}                  # family -> last seen
        self.until = 0.0
        self.reason = ""


class ScannerTracker:
    def __init__(self, window: float = 60.0, cooldown: float = 300.0, max_keys: int = 10_000, min_responses: int = 25, min_errors: int = 20,
                 min_ratio: float = 0.85, min_paths: int = 15, min_span: float = 5.0, probe_window: float = 120.0, probe_families: int = 3,
                 probe_min_responses: int = 6, probe_min_ratio: float = 0.6, clock=None) -> None:
        self.window, self.cooldown, self.max_keys = window, cooldown, max_keys
        self.min_responses, self.min_errors, self.min_ratio, self.min_paths, self.min_span = min_responses, min_errors, min_ratio, min_paths, min_span
        self.probe_window, self.probe_families = probe_window, probe_families
        self.probe_min_responses, self.probe_min_ratio = probe_min_responses, probe_min_ratio
        self._d: OrderedDict = OrderedDict()
        self._clock = clock or time.monotonic        # injectable so tests can drive time

    # -- helpers
    @staticmethod
    def _key(client, host):
        h = str(host or "").strip().lower()
        return str(client or ""), _PORT.sub("", h)

    def _state(self, key, create: bool):
        st = self._d.get(key)
        if st is not None:
            self._d.move_to_end(key)
            return st
        if not create:
            return None
        st = self._d[key] = _State()
        while len(self._d) > self.max_keys:
            self._d.popitem(last=False)
        return st

    def size(self) -> int:
        return len(self._d)

    # -- observations
    def observe_request(self, client, host, path, now: float | None = None) -> None:
        try:
            if not isinstance(path, str):
                return
            now = self._clock() if now is None else now
            st = self._state(self._key(client, host), True)
            p = path.split("?", 1)[0][:300].lower()
            st.paths[p] = now
            st.paths.move_to_end(p)
            while len(st.paths) > 64:
                st.paths.popitem(last=False)
            for name, rx in _FAMILIES.items():
                if rx.search(p):
                    st.families[name] = now
        except Exception:  # noqa: BLE001 - tracking must never break request handling
            pass

    def observe_response(self, client, host, status, now: float | None = None) -> None:
        try:
            code = int(status)
            if code <= 0:
                return
            now = self._clock() if now is None else now
            st = self._state(self._key(client, host), True)
            sec = int(now)
            if st.buckets and st.buckets[-1][0] == sec:
                st.buckets[-1][1] += 1
                st.buckets[-1][2] += code in ERROR_STATUSES
            else:
                st.buckets.append([sec, 1, int(code in ERROR_STATUSES)])
            self._evaluate(st, now)
        except Exception:  # noqa: BLE001
            pass

    def _evaluate(self, st: _State, now: float) -> None:
        horizon = max(self.window, self.probe_window)
        while st.buckets and st.buckets[0][0] < now - horizon:
            st.buckets.popleft()
        for d in (st.paths, st.families):
            for k in [k for k, t in d.items() if t < now - horizon]:
                del d[k]
        if st.until > now:
            return
        win = [b for b in st.buckets if b[0] >= now - self.window]
        n = sum(b[1] for b in win)
        errs = sum(b[2] for b in win)
        err_secs = [b[0] for b in win if b[2]]
        n_paths = sum(1 for t in st.paths.values() if t >= now - self.window)
        if (n >= self.min_responses and errs >= self.min_errors and errs / n >= self.min_ratio and n_paths >= self.min_paths
                and err_secs and err_secs[-1] - err_secs[0] >= self.min_span):
            self._flag(st, now, f"scan: {errs} of {n} responses were not-found/forbidden across {n_paths}+ distinct paths in {self.window:.0f}s")
            return
        fams = {f for f, t in st.families.items() if t >= now - self.probe_window}
        pn = sum(b[1] for b in st.buckets if b[0] >= now - self.probe_window)
        pe = sum(b[2] for b in st.buckets if b[0] >= now - self.probe_window)
        if len(fams) >= self.probe_families and pn >= self.probe_min_responses and pe / pn >= self.probe_min_ratio:
            self._flag(st, now, f"recon: probed {len(fams)} well-known admin/config path families ({', '.join(sorted(fams))}) that mostly do not exist")

    def _flag(self, st: _State, now: float, reason: str) -> None:
        st.until, st.reason = now + self.cooldown, reason

    # -- decision
    def blocked(self, client, host, now: float | None = None) -> str | None:
        """Reason this (client, host) is currently flagged, or None."""
        try:
            st = self._state(self._key(client, host), False)
            if st is None or not st.until:
                return None
            now = self._clock() if now is None else now
            if st.until > now:
                return st.reason
            self._d.pop(self._key(client, host), None)       # cooldown over: forget the history, start clean
            return None
        except Exception:  # noqa: BLE001
            return None
