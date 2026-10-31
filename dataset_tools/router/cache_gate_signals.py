"""Run each analyzer once per eval body and cache the per-body signals, so routing policies can be
compared offline (policy = which bodies the WAF/sensitive analyzers run on) without re-running models.

    python -I runner dataset_tools.router.cache_gate_signals --out signals.json [--router-path P]
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import time

sys.path.insert(0, os.getcwd())
logging.disable(logging.CRITICAL)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=os.path.expanduser("~/FYP/corpora/router_gate_eval"))
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    from text_service import main as svc
    asyncio.run(svc.load_models())
    rows = []
    for name in ("attacks", "benign"):
        for l in open(os.path.join(a.dir, name + ".jsonl"), encoding="utf-8"):
            r = json.loads(l)
            r["set"] = name
            rows.append(r)
    for r in rows:
        t = r["text"]
        t0 = time.perf_counter()
        d = svc.router_classifier.route(t)
        r["route"], r["route_scores"] = d.route, d.scores
        r["t_route"] = (time.perf_counter() - t0) * 1000
        base = [svc.model_code_analysis(t, "outbound"), svc.model_patterns(t, "outbound"), svc.model_pi_signatures(t, False)]
        r["base_block"] = any(x.blocked for x in base)
        t0 = time.perf_counter()
        w = svc.model_web_attack(t)
        r["t_waf"] = (time.perf_counter() - t0) * 1000
        r["waf_block"] = bool(w.blocked)
        s = svc.model_sensitive(t)
        r["sens_block"] = bool(s.blocked)
    json.dump(rows, open(a.out, "w"))
    print("rows", len(rows))


if __name__ == "__main__":
    main()
