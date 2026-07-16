"""One-command ingestion of new data into the WAF dataset.

Subcommands:

  writeup — extract candidate payloads from markdown pentest writeups into a
            review file (labels left blank + a heading hint). You fill in the
            labels, then rebuild — blank-label rows are skipped until labeled.

  csv     — convert a downloaded public dataset (CSV) to our schema, mapping its
            label column onto our taxonomy.

Both write to ``ml/waf/data/external/`` which ``build_dataset`` picks up.

Examples:
    python -m ml.waf.ingest writeup ~/writeups/kioptrix.md ~/writeups/mrrobot.md
    python -m ml.waf.ingest csv cicids.csv --text-col payload --label-col Label \\
        --map "SQL Injection=sqli,BENIGN=clean,XSS=xss" --source cicids2017
"""
from __future__ import annotations

import argparse
import json
import logging
import os

from ml.waf import sources
from ml.waf.taxonomy import LABELS

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("waf.ingest")

_HERE = os.path.dirname(__file__)
EXTERNAL_DIR = os.path.join(_HERE, "data", "external")


def _write_jsonl(path: str, records: list[dict]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")


def cmd_writeup(args: argparse.Namespace) -> None:
    for md_path in args.files:
        if not os.path.exists(md_path):
            logger.warning("missing: %s", md_path)
            continue
        cands = list(sources.extract_writeup_candidates(md_path))
        base = os.path.splitext(os.path.basename(md_path))[0]
        out = os.path.join(EXTERNAL_DIR, f"review_{base}.jsonl")
        _write_jsonl(out, cands)
        logger.info("%s -> %d candidates -> %s", os.path.basename(md_path), len(cands), out)
    logger.info("Fill in the empty \"label\" fields (one of %s), then run build_dataset. "
                "Blank-label rows are skipped until you label them.", LABELS)


def cmd_csv(args: argparse.Namespace) -> None:
    label_map = {}
    if args.map:
        for pair in args.map.split(","):
            if "=" in pair:
                k, v = pair.split("=", 1)
                label_map[k.strip()] = v.strip()
    source = args.source or os.path.splitext(os.path.basename(args.file))[0]
    records = list(sources.load_csv(args.file, args.text_col, args.label_col, source=source, label_map=label_map))
    out = os.path.join(EXTERNAL_DIR, f"{source}.jsonl")
    _write_jsonl(out, records)
    logger.info("%s -> %d records (mapped to our taxonomy) -> %s", os.path.basename(args.file), len(records), out)
    if not records:
        logger.warning("0 records — check --text-col/--label-col names and --map values")


def main() -> None:
    ap = argparse.ArgumentParser(prog="ml.waf.ingest", description="Ingest data into the WAF dataset")
    sub = ap.add_subparsers(dest="cmd", required=True)

    w = sub.add_parser("writeup", help="extract payload candidates from markdown writeups")
    w.add_argument("files", nargs="+", help="markdown writeup file(s)")
    w.set_defaults(func=cmd_writeup)

    c = sub.add_parser("csv", help="convert a downloaded CSV dataset to our schema")
    c.add_argument("file", help="path to the CSV")
    c.add_argument("--text-col", required=True, help="column holding the request/payload text")
    c.add_argument("--label-col", required=True, help="column holding the label")
    c.add_argument("--map", default="", help="comma-separated dataset_label=our_label pairs")
    c.add_argument("--source", default="", help="source tag (defaults to filename)")
    c.set_defaults(func=cmd_csv)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
