"""Build the 3-way router dataset: code / web_request / prose.

Sources:
    code        claudios/code_search_net (Parquet mirror of CodeSearchNet),
                6 languages, function-level snippets — real source code, not
                synthetic, so the router sees genuine syntax diversity.
    web_request the WAF corpus already built for ml/waf/ (query strings, form
                bodies, JSON API payloads, attack payloads — all structurally
                "this is an HTTP request/parameter", whether malicious or not,
                which is the shape distinction this router cares about, not
                threat classification).
    prose       Faker-generated paragraphs — natural-language sentences, same
                technique as ml/waf/synth_benign.py's contact-form messages.

Usage:
    python -m ml.router.build_dataset
"""
from __future__ import annotations

import collections
import glob
import json
import logging
import os
import random
import re

from ml.router.taxonomy import LABELS

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("router.build")

_HERE = os.path.dirname(__file__)
DATA_DIR = os.path.join(_HERE, "data")
BUILD_DIR = os.path.join(DATA_DIR, "build")

WAF_DATA_DIR = os.path.join(_HERE, "..", "waf", "data")
MAX_LEN = 2048
PER_CLASS_TARGET = 12000

CODE_LANGUAGES = ["python", "javascript", "java", "php", "ruby", "go"]


def _normalize(s: str) -> str:
    s = re.sub(r"[ \t]+", " ", (s or "").replace("\r\n", "\n")).strip()
    return s[:MAX_LEN]


def _record(text: str, label: str, source: str) -> dict | None:
    text = _normalize(text)
    if not text:
        return None
    return {"text": text, "label": label, "source": source}


def collect_code(per_language: int) -> list[dict]:
    from datasets import load_dataset

    records = []
    for lang in CODE_LANGUAGES:
        try:
            ds = load_dataset("claudios/code_search_net", lang, split=f"train[:{per_language}]")
        except Exception as exc:  # noqa: BLE001
            logger.warning("code_search_net %s failed: %s — skipping", lang, exc)
            continue
        n = 0
        for row in ds:
            rec = _record(row.get("func_code_string", ""), "code", f"codesearchnet_{lang}")
            if rec:
                records.append(rec)
                n += 1
        logger.info("code_search_net %s -> %d snippets", lang, n)
    return records


def collect_web_request() -> list[dict]:
    records = []
    paths = [
        os.path.join(WAF_DATA_DIR, "seed_attacks.jsonl"),
        os.path.join(WAF_DATA_DIR, "seed_benign.jsonl"),
        *glob.glob(os.path.join(WAF_DATA_DIR, "external", "*.jsonl")),
    ]
    for path in paths:
        if not os.path.exists(path):
            continue
        n = 0
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                rec = _record(row.get("text", ""), "web_request", os.path.basename(path))
                if rec:
                    records.append(rec)
                    n += 1
        logger.info("%s -> %d web_request records", os.path.basename(path), n)
    return records


def collect_prose(count: int, seed: int = 42) -> list[dict]:
    from faker import Faker

    Faker.seed(seed)
    fake = Faker()
    rng = random.Random(seed)
    records = []
    for _ in range(count):
        para = fake.paragraph(nb_sentences=rng.randint(2, 6))
        rec = _record(para, "prose", "faker_paragraph")
        if rec:
            records.append(rec)
    return records


def _dedupe_cap(records: list[dict], cap: int, seed: int = 42) -> list[dict]:
    rng = random.Random(seed)
    seen: set[str] = set()
    deduped = []
    for r in records:
        if r["text"] in seen:
            continue
        seen.add(r["text"])
        deduped.append(r)
    rng.shuffle(deduped)
    return deduped[:cap]


def stratified_split(records: list[dict], val: float = 0.15, test: float = 0.15, seed: int = 42) -> dict[str, list[dict]]:
    rng = random.Random(seed)
    buckets: dict[str, list[dict]] = collections.defaultdict(list)
    for r in records:
        buckets[r["label"]].append(r)
    train, val_set, test_set = [], [], []
    for items in buckets.values():
        rng.shuffle(items)
        n = len(items)
        n_test, n_val = int(n * test), int(n * val)
        test_set += items[:n_test]
        val_set += items[n_test:n_test + n_val]
        train += items[n_test + n_val:]
    return {"train": train, "val": val_set, "test": test_set}


def main() -> None:
    os.makedirs(BUILD_DIR, exist_ok=True)

    code = _dedupe_cap(collect_code(per_language=3000), PER_CLASS_TARGET)
    web_request = _dedupe_cap(collect_web_request(), PER_CLASS_TARGET)
    prose = _dedupe_cap(collect_prose(PER_CLASS_TARGET + 2000), PER_CLASS_TARGET)  # buffer for dedupe loss

    all_records = code + web_request + prose
    dist = collections.Counter(r["label"] for r in all_records)
    logger.info("final distribution: %s (total %d)", dict(dist), len(all_records))
    assert all(dist.get(l, 0) > 0 for l in LABELS), "a class has 0 samples"

    splits = stratified_split(all_records)
    for name, recs in splits.items():
        path = os.path.join(BUILD_DIR, f"{name}.jsonl")
        with open(path, "w", encoding="utf-8") as f:
            for r in recs:
                f.write(json.dumps(r) + "\n")
        logger.info("%s -> %d records -> %s", name, len(recs), path)


if __name__ == "__main__":
    main()
