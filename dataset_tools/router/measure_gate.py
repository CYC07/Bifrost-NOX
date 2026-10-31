"""Measure router route distribution + end-to-end block rate on the gate eval corpora.

    ROUTER_MODEL_PATH=... python -I -m dataset_tools.router.measure_gate [--dir DIR] [--tag name]
Prints JSON. Requires models (one model-loading process at a time!).
"""
from __future__ import annotations

import argparse
import asyncio
import collections
import json
import logging
import os
import sys
import time

sys.path.insert(0, os.getcwd())
logging.disable(logging.CRITICAL)


def _load(p):
    return [json.loads(l) for l in open(p, encoding="utf-8")]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=os.path.expanduser("~/FYP/corpora/router_gate_eval"))
    ap.add_argument("--tag", default="run")
    ap.add_argument("--dump", default="")
    ap.add_argument("--oracle", action="store_true", help="ceiling: WAF runs on every outbound body (router forced to web_request)")
    ap.add_argument("--no-gate", action="store_true", help="baseline: disable the marker gate")
    ap.add_argument("--sets", default="attack,stress,benign")
    ap.add_argument("--reps", type=int, default=1, help="time each body this many times, keep the min (idle-process latency)")
    a = ap.parse_args()
    from text_service import main as svc
    asyncio.run(svc.load_models())
    if a.oracle:
        from ml.router.predictor import RouteDecision
        svc.router_classifier.route = lambda t: RouteDecision("web_request", 1.0)
    if a.no_gate:
        svc.waf_gate_parts = lambda t: []
    blk = lambda o: str(o.get("status")).lower().endswith("block")
    atk, ben = _load(os.path.join(a.dir, "attacks.jsonl")), _load(os.path.join(a.dir, "benign.jsonl"))
    stress = _load(os.path.join(a.dir, "attacks_stress.jsonl"))
    res = {"tag": a.tag}
    lat = {}
    dump = {}
    for name, rows in (("attack", atk), ("stress", stress), ("benign", ben)):
        if name not in a.sets.split(","):
            continue
        routes = collections.Counter()
        blocked = 0
        per = collections.defaultdict(lambda: [0, 0])
        shp = collections.defaultdict(lambda: [0, 0])
        times = []
        miss = []
        blocks = []
        for r in rows:
            best = None
            for _ in range(max(1, a.reps)):
                t0 = time.perf_counter()
                o = svc._analyze_sync(r["text"], False, "outbound")
                dt = (time.perf_counter() - t0) * 1000
                best = dt if best is None else min(best, dt)
            times.append(best)
            route = (o.get("detailed_findings") or {}).get("route")
            routes[route] += 1
            b = blk(o)
            blocked += b
            blocks.append(b)
            key = (r.get("label") if name == "attack" else r.get("shape") if name == "stress" else r.get("kind"))
            per[key][0] += b
            per[key][1] += 1
            if name == "attack":
                shp[r.get("shape")][0] += b
                shp[r.get("shape")][1] += 1
            if (name != "benign") != b:
                miss.append({"text": r["text"][:200], "route": route, "key": key})
        dump[name + "_times"] = list(times)
        dump[name + "_blocked"] = [bool(x) for x in blocks]
        times.sort()
        res[name] = {"n": len(rows), "blocked": blocked, "rate": round(blocked / len(rows), 4),
                     "routes": dict(routes), "by_key": {k: f"{v[0]}/{v[1]}" for k, v in sorted(per.items())},
                     "by_shape": {k: f"{v[0]}/{v[1]}" for k, v in sorted(shp.items())}}
        lat[name] = {"p50": round(times[len(times) // 2], 1), "p95": round(times[int(len(times) * .95)], 1)}
        dump[name] = miss
    res["latency_ms"] = lat
    print(json.dumps(res, indent=1))
    if a.dump:
        json.dump(dump, open(a.dump, "w"), indent=1)


if __name__ == "__main__":
    main()
