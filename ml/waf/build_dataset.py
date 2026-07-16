"""Build the WAF training dataset from all sources into train/val/test splits.

Merges the curated seed with anything you drop into ``ml/waf/data/external/``
(pre-labeled ``*.jsonl`` exports, or converted public datasets), de-dupes,
stratifies by label, and writes JSONL splits plus a stats report.

Usage:
    python -m ml.waf.build_dataset
    python -m ml.waf.build_dataset --val 0.15 --test 0.15 --seed 42
"""
from __future__ import annotations

import argparse
import collections
import json
import logging
import os
import random

from ml.waf import sources
from ml.waf.taxonomy import LABELS

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("waf.build")

_HERE = os.path.dirname(__file__)
DATA_DIR = os.path.join(_HERE, "data")
EXTERNAL_DIR = os.path.join(DATA_DIR, "external")
BUILD_DIR = os.path.join(DATA_DIR, "build")

SEED_FILES = [
    os.path.join(DATA_DIR, "seed_attacks.jsonl"),
    os.path.join(DATA_DIR, "seed_benign.jsonl"),
]


def collect() -> list[dict]:
    records: list[dict] = []
    for path in SEED_FILES:
        if os.path.exists(path):
            n = 0
            for rec in sources.load_jsonl(path):
                records.append(rec)
                n += 1
            logger.info("seed %s -> %d records", os.path.basename(path), n)

    # Anything the user drops in data/external/*.jsonl (already labeled).
    if os.path.isdir(EXTERNAL_DIR):
        for name in sorted(os.listdir(EXTERNAL_DIR)):
            if name.endswith(".jsonl"):
                path = os.path.join(EXTERNAL_DIR, name)
                n = 0
                for rec in sources.load_jsonl(path):
                    records.append(rec)
                    n += 1
                logger.info("external %s -> %d records", name, n)

    return sources.dedupe(records)


def stratified_split(
    records: list[dict], val: float, test: float, seed: int
) -> dict[str, list[dict]]:
    by_label: dict[str, list[dict]] = collections.defaultdict(list)
    for rec in records:
        by_label[rec["label"]].append(rec)

    rng = random.Random(seed)
    splits: dict[str, list[dict]] = {"train": [], "val": [], "test": []}
    for label, items in by_label.items():
        rng.shuffle(items)
        n = len(items)
        n_test = int(n * test)
        n_val = int(n * val)
        splits["test"].extend(items[:n_test])
        splits["val"].extend(items[n_test:n_test + n_val])
        splits["train"].extend(items[n_test + n_val:])

    for name in splits:
        rng.shuffle(splits[name])
    return splits


def _write_jsonl(path: str, records: list[dict]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps({"text": rec["text"], "label": rec["label"], "source": rec.get("source", "")}) + "\n")


def _distribution(records: list[dict]) -> dict[str, int]:
    counts = collections.Counter(r["label"] for r in records)
    return {label: counts.get(label, 0) for label in LABELS}


def build(val: float = 0.15, test: float = 0.15, seed: int = 42) -> dict:
    records = collect()
    if not records:
        raise SystemExit("no records collected — check seed files")

    splits = stratified_split(records, val, test, seed)
    for name, recs in splits.items():
        _write_jsonl(os.path.join(BUILD_DIR, f"{name}.jsonl"), recs)

    stats = {
        "total": len(records),
        "splits": {name: len(recs) for name, recs in splits.items()},
        "distribution": _distribution(records),
        "distribution_by_split": {name: _distribution(recs) for name, recs in splits.items()},
    }
    with open(os.path.join(BUILD_DIR, "stats.json"), "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2)

    logger.info("built %d records -> %s", len(records), BUILD_DIR)
    logger.info("distribution: %s", stats["distribution"])
    logger.info("splits: %s", stats["splits"])
    return stats


def main() -> None:
    ap = argparse.ArgumentParser(description="Build the WAF dataset")
    ap.add_argument("--val", type=float, default=0.15)
    ap.add_argument("--test", type=float, default=0.15)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    build(val=args.val, test=args.test, seed=args.seed)


if __name__ == "__main__":
    main()
