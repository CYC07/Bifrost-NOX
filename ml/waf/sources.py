"""Ingestion loaders that normalize every data source into one schema.

Record schema (one JSON object per sample):
    {"text": <str>, "label": <taxonomy label>, "source": <origin tag>}

Sources supported:
  * JSONL   — our seed files and any pre-labeled export
  * CSV     — downloaded public datasets (map text/label columns)
  * writeup — markdown pentest writeups: extract candidate payloads from code
              fences for review (emitted UNLABELED with a heading hint)

Keeping it stdlib-only (no pandas) so it runs on the constrained box.
"""
from __future__ import annotations

import csv
import json
import logging
import os
import re
from typing import Iterable, Iterator

from ml.waf.taxonomy import LABEL_TO_ID

logger = logging.getLogger("waf.sources")

MAX_LEN = 2048  # cap absurdly long samples; attacks fit well under this


def normalize_text(s: str) -> str:
    """Collapse whitespace and cap length. Preserve payload characters."""
    if s is None:
        return ""
    s = s.replace("\x00", "")
    s = re.sub(r"[ \t]+", " ", s.replace("\r\n", "\n")).strip()
    return s[:MAX_LEN]


def _record(text: str, label: str, source: str) -> dict | None:
    text = normalize_text(text)
    if not text:
        return None
    return {"text": text, "label": label, "source": source}


def load_jsonl(path: str) -> Iterator[dict]:
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                logger.warning("%s:%d bad JSON: %s", path, lineno, exc)
                continue
            rec = _record(obj.get("text", ""), obj.get("label", ""), obj.get("source", os.path.basename(path)))
            if rec and rec["label"] in LABEL_TO_ID:
                yield rec
            elif rec:
                logger.warning("%s:%d unknown label %r — skipped", path, lineno, obj.get("label"))


def load_csv(
    path: str,
    text_col: str,
    label_col: str,
    source: str | None = None,
    label_map: dict[str, str] | None = None,
) -> Iterator[dict]:
    """Load a downloaded dataset. ``label_map`` renames dataset labels onto our
    taxonomy (e.g. {"Anomaly": "sqli", "Normal": "clean"})."""
    src = source or os.path.basename(path)
    with open(path, encoding="utf-8", errors="ignore", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            raw_label = (row.get(label_col) or "").strip()
            label = (label_map or {}).get(raw_label, raw_label)
            rec = _record(row.get(text_col, ""), label, src)
            if rec and rec["label"] in LABEL_TO_ID:
                yield rec


_FENCE = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)
_HEADING = re.compile(r"^#{1,6}\s+(.*)$", re.MULTILINE)
# Lines inside writeups that tend to carry payloads worth reviewing.
_PAYLOAD_HINT = re.compile(r"(curl|sqlmap|wget|nc |ncat|' OR |UNION SELECT|<script|\.\./|\{\{|;\s*(cat|id|whoami|bash))", re.IGNORECASE)


def extract_writeup_candidates(path: str) -> Iterator[dict]:
    """Pull candidate payloads from a markdown writeup for later labeling.

    Emits records with ``label: ""`` (UNLABELED) plus a ``hint`` from the nearest
    heading. You review + assign labels before these enter training — writeups
    are free-form, so we never auto-label them into the training set.
    """
    with open(path, encoding="utf-8", errors="ignore") as f:
        content = f.read()

    # Map each character offset to the most recent heading for a rough hint.
    headings = [(m.start(), m.group(1).strip()) for m in _HEADING.finditer(content)]

    def hint_for(pos: int) -> str:
        current = ""
        for off, text in headings:
            if off <= pos:
                current = text
            else:
                break
        return current

    seen: set[str] = set()
    for m in _FENCE.finditer(content):
        block = m.group(1)
        for line in block.splitlines():
            line = line.strip()
            if len(line) < 4 or not _PAYLOAD_HINT.search(line):
                continue
            norm = normalize_text(line)
            if norm and norm not in seen:
                seen.add(norm)
                yield {"text": norm, "label": "", "source": f"writeup:{os.path.basename(path)}", "hint": hint_for(m.start())}


def dedupe(records: Iterable[dict]) -> list[dict]:
    """Drop exact-text duplicates, keeping the first (attack seeds before external)."""
    seen: set[str] = set()
    out: list[dict] = []
    for rec in records:
        key = rec["text"]
        if key in seen:
            continue
        seen.add(key)
        out.append(rec)
    return out
