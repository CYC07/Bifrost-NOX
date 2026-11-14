"""Paired, interleaved latency of the WAF input preparation (old raw-text vs decoded-values).

The box is shared, so absolute timings drift; each affected body is timed old/new alternately in the
SAME process (min of N reps each) and the delta is what the change adds. Bodies whose WAF parts are
identical under both preparations add exactly zero (same code path) and are counted as such.

    python -I runner dataset_tools.router.measure_waf_inputs_latency [--reps 3]
"""
from __future__ import annotations

import argparse
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
    ap.add_argument("--reps", type=int, default=3)
    a = ap.parse_args()
    from text_service import main as svc
    from ml.waf.predictor import WAFClassifier
    w = WAFClassifier(threshold=svc.WAF_ATTACK_THRESHOLD)
    assert w.load()
    svc.waf_classifier = w
    new_inputs = svc._waf_inputs

    def old_inputs(t):  # the pre-change preparation: JSON per value, everything else raw
        return new_inputs(t) if t.lstrip().startswith(("{", "[")) else [t[:svc.WAF_MAX_VALUE_CHARS]]

    rows = [json.loads(l) for f in ("attacks", "benign") for l in open(os.path.join(a.dir, f + ".jsonl"))]
    w.predict("warm up")
    deltas, affected, extra_parts = [], 0, []
    for r in rows:
        t = r["text"]
        po, pn = old_inputs(t), new_inputs(t)
        if po == pn:
            deltas.append(0.0)
            continue
        affected += 1
        extra_parts.append(len(pn) - len(po))
        bo = bn = None
        for _ in range(a.reps):
            t0 = time.perf_counter(); svc.model_web_attack(t, parts=po); d1 = (time.perf_counter() - t0) * 1000
            t0 = time.perf_counter(); svc.model_web_attack(t, parts=pn); d2 = (time.perf_counter() - t0) * 1000
            bo = d1 if bo is None else min(bo, d1)
            bn = d2 if bn is None else min(bn, d2)
        deltas.append(bn - bo)
    ds = sorted(deltas)
    n = len(ds)
    aff = sorted(d for d in deltas if d != 0.0)
    out = {"bodies": n, "affected": affected, "mean_extra_parts_when_affected": round(sum(extra_parts) / max(1, len(extra_parts)), 2),
           "delta_ms_all_bodies": {"p50": round(ds[n // 2], 1), "p95": round(ds[int(n * .95)], 1), "p99": round(ds[int(n * .99)], 1), "max": round(ds[-1], 1)},
           "delta_ms_affected_only": {"p50": round(aff[len(aff) // 2], 1), "p95": round(aff[int(len(aff) * .95)], 1)} if aff else {}}
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
