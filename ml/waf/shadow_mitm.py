"""Shadow-mode WAF tester — run the trained model against LIVE traffic, enforce nothing.

This is a mitmproxy addon. It sees every request flowing through the proxy, asks
the SAME `WAFClassifier` the firewall will use for a verdict, and only *logs* it.
It never blocks, delays, or modifies a request. Safe to point real browsing at.

Run:
    cd <repo-root-or-worktree>
    PYTHONPATH=. mitmdump -s ml/waf/shadow_mitm.py --listen-port 8081

Then set your browser / system HTTP+HTTPS proxy to 127.0.0.1:8081 and browse /
attack a lab target (DVWA, Juice Shop). For HTTPS, install mitmproxy's CA once
(http://mitm.it while the proxy runs).

Point at a specific model:  WAF_MODEL_PATH=ml/waf/artifacts/waf_baseline.joblib
Verdict log (JSONL):        WAF_SHADOW_LOG=ml/waf/shadow_verdicts.jsonl (default)

DO NOT feed this confidential third-party pentest traffic — use your own lab.
"""
from __future__ import annotations

import json
import logging
import os
import time
from urllib.parse import unquote_plus

from ml.waf.ingest_har import _redact_free, _scrub_json, _scrub_kv  # structure-preserving scrub
from ml.waf.predictor import get_classifier
from ml.waf.taxonomy import is_attack

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("waf.shadow")

_HERE = os.path.dirname(__file__)
LOG_PATH = os.getenv("WAF_SHADOW_LOG", os.path.join(_HERE, "shadow_verdicts.jsonl"))
MAX_BODY = 4096  # cap body bytes fed to the model

# --- benign auto-collection (opt-in) ----------------------------------------
# Set WAF_COLLECT=1 to harvest allowed traffic into a scrubbed, deduped, clean
# training corpus. Predict on the RAW request (real decision); store the SCRUBBED
# text (secrets faked, shape kept) so a few days of normal browsing auto-builds
# data/external/. Regex scrub only — no Presidio inline (too slow per request);
# run ingest_har --scrub-pii offline if you want PII redaction on top.
COLLECT = os.getenv("WAF_COLLECT", "").lower() in ("1", "true", "yes", "on")
CLEAN_LOG = os.getenv("WAF_CLEAN_LOG", os.path.join(_HERE, "data", "external", "shadow_clean.jsonl"))
CLEAN_MAX_MB = float(os.getenv("WAF_CLEAN_MAX_MB", "50"))  # self-limiting cap


class WAFShadow:
    def __init__(self) -> None:
        self.clf = get_classifier()  # loads artifact once
        self.seen = 0
        self.flagged = 0
        self.collected = 0
        self._collect_stopped = False
        self._collect_seen: set[str] = set()  # in-session dedup
        loaded = getattr(self.clf, "_loaded", False)
        logger.info("[shadow] model loaded=%s -> %s (LOG-ONLY, blocks nothing)", loaded, self.clf.model_path)
        if COLLECT:
            logger.info("[shadow] COLLECT on -> scrubbed clean corpus -> %s (cap %.0f MB)", CLEAN_LOG, CLEAN_MAX_MB)

    def _parts(self, req) -> tuple[str, str, list[tuple[str, str]], str, str]:
        """Extract request components once: method, decoded path, query key/value
        pairs, decoded body, body mime. Reused to build both the raw (for the model)
        and scrubbed (for the corpus) strings."""
        method = req.method or ""
        # req.path includes the query string; drop it here (query is parsed
        # separately below) so the raw secret in it is not carried unscrubbed.
        path = unquote_plus((req.path or "").split("?", 1)[0])
        kvs: list[tuple[str, str]] = []
        try:
            for k, v in req.query.items(multi=True):
                if v:
                    kvs.append((k or "", unquote_plus(v)))
        except Exception:  # noqa: BLE001
            pass
        try:
            body = unquote_plus((req.get_text(strict=False) or "")[:MAX_BODY])
        except Exception:  # noqa: BLE001
            body = ""
        mime = (req.headers.get("content-type", "") or "").lower()
        return method, path, kvs, body, mime

    @staticmethod
    def _raw(parts: tuple) -> str:
        method, path, kvs, body, _mime = parts
        out = [method, path, *[v for _k, v in kvs]]
        if body:
            out.append(body)
        return " ".join(p for p in out if p)

    @staticmethod
    def _scrubbed(parts: tuple) -> str:
        """Structure-preserving scrub for the stored corpus — secrets faked, shape kept.
        Path is redacted too (REST-style tokens live in the path)."""
        method, path, kvs, body, mime = parts
        out = [method, _redact_free(path), *[_scrub_kv(k, v) for k, v in kvs]]
        if body:
            out.append(_scrub_json(body) if "json" in mime else _redact_free(body))
        return " ".join(p for p in out if p)

    # mitmproxy hook — fires on every request, enforces nothing
    def request(self, flow) -> None:
        parts = self._parts(flow.request)
        text = self._raw(parts)
        pred = self.clf.predict(text)  # decision on RAW traffic
        self.seen += 1

        host = flow.request.pretty_host
        line = f"{flow.request.method} {host}{flow.request.path}"
        if pred.blocked:  # the firewall's actual decision — score over threshold on an attack class
            self.flagged += 1
            logger.warning("[WOULD-BLOCK] %-18s %.2f  %-8s  %s",
                           pred.label, pred.score, pred.risk, line[:90])
            self._append(LOG_PATH, {
                "ts": time.time(), "verdict": "would_block",
                "label": pred.label, "score": round(pred.score, 4), "risk": pred.risk,
                "method": flow.request.method, "url": flow.request.pretty_url[:512],
                "text": text[:512],
            })
        else:
            tag = pred.label if is_attack(pred.label) else "clean"
            logger.info("[allow]        %-18s %.2f  %s", tag, pred.score, line[:90])
            if COLLECT:
                self._collect(text, self._scrubbed(parts))

    def _collect(self, raw: str, scrubbed: str) -> None:
        """Store an allowed request as a scrubbed clean sample. Dedup on the RAW
        text (stable) — scrubbing is randomized, so it can't be the dedup key."""
        if self._collect_stopped or not scrubbed or raw in self._collect_seen:
            return
        # check size occasionally (every 100 kept) so we do not stat every request
        if self.collected % 100 == 0 and os.path.exists(CLEAN_LOG):
            if os.path.getsize(CLEAN_LOG) >= CLEAN_MAX_MB * 1024 * 1024:
                self._collect_stopped = True
                logger.warning("[shadow] clean corpus hit %.0f MB cap -> stopped collecting", CLEAN_MAX_MB)
                return
        self._collect_seen.add(raw)
        self._append(CLEAN_LOG, {"text": scrubbed, "label": "clean", "source": "shadow"})
        self.collected += 1

    @staticmethod
    def _append(path: str, obj: dict) -> None:
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(obj) + "\n")
        except Exception as exc:  # noqa: BLE001 — logging must never break the proxy
            logger.error("[shadow] write failed (%s): %s", path, exc)

    def done(self) -> None:
        logger.info("[shadow] session end: %d requests, %d flagged -> %s", self.seen, self.flagged, LOG_PATH)
        if COLLECT:
            logger.info("[shadow] collected %d unique clean samples -> %s", self.collected, CLEAN_LOG)


addons = [WAFShadow()]
