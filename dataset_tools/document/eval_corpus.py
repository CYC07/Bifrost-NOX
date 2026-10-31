"""Measure document_service FP / detection on the corpora from build_corpus.py.

Run from repo root:
  PYTHONPATH=. python -I dataset_tools/document/eval_corpus.py [--json out.json]

A file is "flagged" by a sub-model when its score crosses the level at which the
aggregator would act on it alone (>0.8 for max-score block; sub-model score >0.5
is reported as 'soft'). Combined verdict = document_service.main._aggregate.
"""

from __future__ import annotations

import asyncio
import collections
import json
import os
import sys

sys.path.insert(0, os.getcwd())
ROOT = os.path.expanduser("~/FYP/corpora")
SETS = ["doc_benign", "doc_benign_system", "doc_ambiguous", "doc_malicious_real", "doc_malicious_synth"]


def main() -> None:
    from document_service import content_model, main as dmain, malware_model, metadata_model, structure_model

    structure_model.load_model()
    malware_model.load_rules()
    rows = []
    for s in SETS:
        d = os.path.join(ROOT, s)
        man = json.load(open(os.path.join(d, "manifest.json")))
        for fn, m in sorted(man.items()):
            data = open(os.path.join(d, fn), "rb").read()
            rs = [structure_model.analyze(data), content_model.analyze(data),
                  asyncio.run(malware_model.analyze(data)), metadata_model.analyze(data)]
            v = dmain._aggregate(rs)
            rows.append({"set": s, "file": fn, "source": m["source"], "category": m["category"],
                         "kind": m["kind"], "status": str(v.status.value if hasattr(v.status, "value") else v.status),
                         "scores": {r.module: round(r.score, 3) for r in rs},
                         "findings": [f for r in rs for f in r.findings if r.score > 0.5][:4]})
    if "--json" in sys.argv:
        json.dump(rows, open(sys.argv[sys.argv.index("--json") + 1], "w"), indent=1)

    def is_block(r):
        return r["status"].lower() == "block"

    for s in SETS:
        rs = [r for r in rows if r["set"] == s]
        print(f"\n== {s}: N={len(rs)}  combined BLOCK={sum(map(is_block, rs))}")
        for mod in ("structure", "malware", "metadata", "content"):
            print(f"   {mod:9s} score>0.5: {sum(1 for r in rs if r['scores'][mod] > 0.5)}")
        by = collections.defaultdict(lambda: [0, 0])
        for r in rs:
            k = (r["source"], r["category"] if not s.startswith("doc_benign") else r["kind"])
            by[k][0] += 1
            by[k][1] += is_block(r)
        for k, (n, b) in sorted(by.items()):
            print(f"   {k[0]:13s} {k[1]:32s} {b}/{n}")
        if s.startswith("doc_benign"):
            for r in rs:
                if is_block(r):
                    print("   FP:", r["file"], r["scores"], r["findings"])
        elif s != "doc_ambiguous":
            for r in rs:
                if not is_block(r):
                    print("   MISS:", r["file"], r["category"], r["scores"])


if __name__ == "__main__":
    main()
