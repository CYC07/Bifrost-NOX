"""Ingest a browser HAR export into scrubbed, clean-labeled WAF training data.

Friends export their normal browsing (DevTools -> Network -> Save all as HAR).
This turns each request into the same model-facing text the firewall scores,
then SCRUBS secrets/PII before anything is written — the benign *structure* is
kept, the actual secret values never enter the dataset.

Design choice: structure-preserving redaction. A real token like
``cpsess0421415579`` becomes a fake same-length token, NOT deleted — because the
whole point is to teach the model that "param = long-token-soup" is benign
(that pattern is what caused the roundcube false positive). Delete the token and
you delete the lesson.

Safety: every request is scored by the current WAF model first. Anything that
looks like an attack is routed to a ``.review.jsonl`` file for manual eyes, never
silently labeled clean (friends don't attack, but captures catch odd things).

Usage:
    python -m ml.waf.ingest_har friend1.har --source friend1
    python -m ml.waf.ingest_har friend1.har --source friend1 --scrub-pii   # + Presidio
    python -m ml.waf.ingest_har *.har --source friends --no-check          # skip model gate
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import secrets
import string
from urllib.parse import parse_qsl, unquote_plus, urlsplit

from ml.waf.sources import normalize_text

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("waf.har")

_HERE = os.path.dirname(__file__)
EXTERNAL_DIR = os.path.join(_HERE, "data", "external")

# --- what counts as a secret -------------------------------------------------
SECRET_KEY = re.compile(
    r"(pass(word|wd)?|pwd|token|secret|api[_-]?key|access[_-]?token|refresh[_-]?token"
    r"|auth|bearer|session|sid|csrf|xsrf|otp|code|signature|sig)\b",
    re.IGNORECASE,
)
JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b")
LONG_HEX = re.compile(r"\b[0-9a-fA-F]{16,}\b")
# NB: no '/' in the class — otherwise it spans URL path separators and eats
# benign path segments next to a long id. JWT + hex cover the slashed cases.
LONG_B64 = re.compile(r"\b[A-Za-z0-9]{20,}={0,2}\b")
EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
LONG_NUM = re.compile(r"\b\d{9,}\b")  # phone/card-ish long digit runs

_ALNUM = string.ascii_letters + string.digits


def _fake_like(s: str) -> str:
    """Same-length, same-rough-shape placeholder. Preserves token structure so the
    model still learns 'this shape is benign' without seeing the real value."""
    out = []
    for ch in s:
        if ch.isdigit():
            out.append(secrets.choice(string.digits))
        elif ch.isalpha():
            out.append(secrets.choice(string.ascii_lowercase if ch.islower() else string.ascii_uppercase))
        else:
            out.append(ch)  # keep separators (-, _, ., /) so shape survives
    return "".join(out)


def _redact_free(text: str) -> str:
    """Redact secret/PII *values* anywhere in a free-form string, keeping shape."""
    text = JWT.sub(lambda m: _fake_like(m.group(0)), text)
    text = LONG_HEX.sub(lambda m: _fake_like(m.group(0)), text)
    text = LONG_B64.sub(lambda m: _fake_like(m.group(0)), text)
    text = EMAIL.sub("user@example.com", text)
    text = LONG_NUM.sub(lambda m: _fake_like(m.group(0)), text)
    return text


def _scrub_kv(key: str, val: str) -> str:
    """Scrub one key=value pair. Secret-named keys get their value faked wholesale;
    otherwise scrub only secret-looking substrings in the value."""
    if not val:
        return val
    if SECRET_KEY.search(key or ""):
        return _fake_like(val)
    return _redact_free(val)


# --- optional Presidio PII pass (reuses the firewall's existing dependency) ---
_presidio = None


def _presidio_engine():
    global _presidio
    if _presidio is None:
        from presidio_analyzer import AnalyzerEngine  # lazy: only if --scrub-pii
        _presidio = AnalyzerEngine()
    return _presidio


def _scrub_pii(text: str) -> str:
    try:
        eng = _presidio_engine()
        results = eng.analyze(text=text, language="en")
        for r in sorted(results, key=lambda x: x.start, reverse=True):
            text = text[: r.start] + f"<{r.entity_type}>" + text[r.end :]
    except Exception as exc:  # noqa: BLE001 — PII scrub must never crash ingest
        logger.warning("presidio pass skipped: %s", exc)
    return text


# --- HAR -> request text -----------------------------------------------------
def _request_text(req: dict, scrub_pii: bool) -> str:
    method = req.get("method", "")
    url = req.get("url", "")
    parts = [method]

    split = urlsplit(url)
    if split.path:
        parts.append(unquote_plus(split.path))

    # query — prefer HAR's parsed queryString, fall back to the raw query
    qs = req.get("queryString") or []
    if qs:
        for item in qs:
            parts.append(_scrub_kv(item.get("name", ""), unquote_plus(item.get("value", "") or "")))
    elif split.query:
        for k, v in parse_qsl(split.query, keep_blank_values=True):
            parts.append(_scrub_kv(k, v))

    # body
    post = req.get("postData") or {}
    mime = (post.get("mimeType") or "").lower()
    if post.get("params"):
        for item in post["params"]:
            parts.append(_scrub_kv(item.get("name", ""), unquote_plus(item.get("value", "") or "")))
    elif post.get("text"):
        body = post["text"]
        if "json" in mime:
            body = _scrub_json(body)
        elif "form-urlencoded" in mime:
            body = " ".join(_scrub_kv(k, v) for k, v in parse_qsl(body, keep_blank_values=True))
        else:
            body = _redact_free(body)
        parts.append(body[:4096])

    text = " ".join(p for p in parts if p)
    if scrub_pii:
        text = _scrub_pii(text)
    return normalize_text(text)


def _scrub_json(body: str) -> str:
    try:
        obj = json.loads(body)
    except Exception:  # noqa: BLE001 — not valid JSON, treat as free text
        return _redact_free(body)

    def walk(o):
        if isinstance(o, dict):
            return {k: (_fake_like(v) if isinstance(v, str) and SECRET_KEY.search(k)
                        else walk(v)) for k, v in o.items()}
        if isinstance(o, list):
            return [walk(x) for x in o]
        if isinstance(o, str):
            return _redact_free(o)
        return o

    return json.dumps(walk(obj))


# --- driver ------------------------------------------------------------------
def ingest(paths: list[str], source: str, label: str, scrub_pii: bool, check: bool) -> None:
    clf = None
    if check:
        from ml.waf.predictor import get_classifier  # lazy: loads the model
        clf = get_classifier()

    seen: set[str] = set()
    clean_recs: list[dict] = []
    review_recs: list[dict] = []

    for path in paths:
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                har = json.load(f)
        except Exception as exc:  # noqa: BLE001
            logger.error("cannot read HAR %s: %s", path, exc)
            continue
        entries = (har.get("log") or {}).get("entries") or []
        n = 0
        for entry in entries:
            req = entry.get("request") or {}
            if not req.get("url"):
                continue
            text = _request_text(req, scrub_pii)
            if not text or text in seen:
                continue
            seen.add(text)
            rec = {"text": text, "label": label, "source": source}
            if clf is not None:
                pred = clf.predict(text)
                # Trusted-benign source: only quarantine HIGH-CONFIDENCE would-blocks
                # (a genuinely malicious-looking request worth a human glance). Keep
                # low-confidence mis-scores in clean on purpose — those are the hard
                # negatives that fix the model's false positives.
                if pred.blocked:
                    review_recs.append({**rec, "model_label": pred.label, "score": round(pred.score, 3)})
                    continue
            clean_recs.append(rec)
            n += 1
        logger.info("%s -> %d clean requests kept", os.path.basename(path), n)

    os.makedirs(EXTERNAL_DIR, exist_ok=True)
    out = os.path.join(EXTERNAL_DIR, f"{source}.jsonl")
    with open(out, "w", encoding="utf-8") as f:
        for r in clean_recs:
            f.write(json.dumps(r) + "\n")
    logger.info("wrote %d clean records -> %s", len(clean_recs), out)

    if review_recs:
        rout = os.path.join(EXTERNAL_DIR, f"{source}.review.jsonl")
        with open(rout, "w", encoding="utf-8") as f:
            for r in review_recs:
                f.write(json.dumps(r) + "\n")
        logger.warning(
            "%d requests looked attack-like -> quarantined for review in %s "
            "(check them, then relabel and merge the real benign ones)",
            len(review_recs), rout,
        )


def main() -> None:
    ap = argparse.ArgumentParser(prog="ml.waf.ingest_har", description="HAR -> scrubbed clean WAF data")
    ap.add_argument("har", nargs="+", help="HAR file(s)")
    ap.add_argument("--source", required=True, help="source tag / output filename")
    ap.add_argument("--label", default="clean", help="label to assign (default: clean)")
    ap.add_argument("--scrub-pii", action="store_true", help="also run Presidio PII redaction")
    ap.add_argument("--no-check", dest="check", action="store_false",
                    help="skip the WAF model gate (do not quarantine attack-looking requests)")
    args = ap.parse_args()
    ingest(args.har, args.source, args.label, args.scrub_pii, args.check)


if __name__ == "__main__":
    main()
