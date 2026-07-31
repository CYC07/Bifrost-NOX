"""Conversion of the 2026-07-31 Kaggle/GitHub benign-corpus batch into
ml/waf/data/external/*.jsonl (our {"text","label","source"} schema).

Not part of the CLI surface (inputs are large downloads outside the repo, not
reproducible via a generic --text-col/--label-col mapping like ml.waf.ingest
csv) — kept as a script so the conversion is reproducible/inspectable.

Sources (see ~/Downloads/waf_datasets/):
  goodqueries.txt        FWAF benign URL paths+queries         -> clean
  ecml_pkdd_2007.csv     Gemius HTTP requests (Valid/Anomalous) -> clean (Valid only)
  malicious_phish.csv    URL reputation dataset                 -> clean (benign only)
  access.log             Zanbil e-commerce nginx log, sampled    -> clean
"""
from __future__ import annotations

import csv
import json
import os
import re

DL = os.path.expanduser("~/Downloads/waf_datasets")
OUT = os.path.join(os.path.dirname(__file__), "data", "external")
os.makedirs(OUT, exist_ok=True)


def write_jsonl(name: str, records: list[dict]) -> None:
    path = os.path.join(OUT, name)
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    print(f"{name}: {len(records)} records")


def normalize(s: str, cap: int = 2000) -> str:
    s = re.sub(r"\s+", " ", s).strip()
    return s[:cap]


# --- 1. goodqueries.txt (plain lines, all benign) --------------------------
recs = []
with open(os.path.join(DL, "goodqueries.txt"), encoding="utf-8", errors="ignore") as f:
    for line in f:
        t = normalize(line)
        if t:
            recs.append({"text": t, "label": "clean", "source": "fwaf_goodqueries"})
write_jsonl("fwaf_goodqueries.jsonl", recs)

# --- 2. ecml_pkdd_2007.csv (Valid rows only -> clean) -----------------------
recs = []
with open(os.path.join(DL, "ecml_pkdd_2007.csv"), encoding="utf-8", errors="ignore", newline="") as f:
    for row in csv.DictReader(f):
        if row.get("Class") != "Valid":
            continue
        parts = [row.get("Method", ""), row.get("URI", ""), row.get("GET-Query", ""), row.get("POST-Data", "")]
        t = normalize(" ".join(p for p in parts if p))
        if t:
            recs.append({"text": t, "label": "clean", "source": "ecml_pkdd_2007"})
write_jsonl("ecml_pkdd_2007.jsonl", recs)

# --- 3. malicious_phish.csv (benign rows only -> clean) ---------------------
recs = []
with open(os.path.join(DL, "malicious-urls-dataset", "malicious_phish.csv"),
          encoding="utf-8", errors="ignore", newline="") as f:
    for row in csv.DictReader(f):
        if row.get("type") != "benign":
            continue
        t = normalize(row.get("url", ""))
        if t:
            recs.append({"text": t, "label": "clean", "source": "malicious_phish_benign"})
write_jsonl("malicious_phish_benign.jsonl", recs)

# --- 4. access.log (Zanbil nginx combined log, strided sample) -------------
LOG_RE = re.compile(r'"[A-Z]+ (\S+) HTTP/[\d.]+"')
recs = []
STRIDE = 30  # ~10.4M lines / 30 ≈ 345k sampled
with open(os.path.join(DL, "web-server-access-logs", "access.log"), encoding="utf-8", errors="ignore") as f:
    for i, line in enumerate(f):
        if i % STRIDE != 0:
            continue
        m = LOG_RE.search(line)
        if not m:
            continue
        t = normalize(m.group(1))
        if t:
            recs.append({"text": t, "label": "clean", "source": "zanbil_access_log"})
write_jsonl("zanbil_access_log.jsonl", recs)

print("done.")
