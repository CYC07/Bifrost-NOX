"""Real-model, real-router end-to-end check (text_service._analyze_sync, outbound) of consumer questions and
real-source positives, each sent plain and as chat-API JSON (with and without system prompts, multi-turn).

    python -I dataset_tools/sensitive/chat_e2e.py --repo <tree under test> [--tools <this repo>] [--n 100] [--json out.json]

Run it once per tree (base c173e0e, A4 0b08965, current) to get the before/after table; one model-loading
process at a time. Presidio and the WAF are not loaded (they are not part of the sensitive path).
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import logging
import os
import random
import sys
import time


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--tools", default=os.getcwd())
    ap.add_argument("--n", type=int, default=100, help="benign texts to sample")
    ap.add_argument("--npos", type=int, default=40)
    ap.add_argument("--json", default="")
    a = ap.parse_args()
    logging.disable(logging.CRITICAL)
    sys.path.insert(0, a.repo)
    spec = importlib.util.spec_from_file_location("build_chat_eval", os.path.join(a.tools, "dataset_tools/sensitive/build_chat_eval.py"))
    bce = importlib.util.module_from_spec(spec); spec.loader.exec_module(bce)
    from ml.router.predictor import RouterClassifier
    from ml.sensitive.predictor import SensitiveClassifier
    from text_service import main as svc
    svc.router_classifier = RouterClassifier(); assert svc.router_classifier.load()
    svc.sensitive_classifier = SensitiveClassifier(); assert svc.sensitive_classifier.load()
    svc.presidio_analyzer = None; svc.waf_classifier = None

    E = os.path.expanduser("~/FYP/corpora/sens_eval")
    chat_recs = [json.loads(l) for l in open(f"{E}/chat_eval.jsonl")]
    ben = [r["text"] for r in chat_recs if r["set"] not in ("chatq_multiturn",)]
    random.Random(3).shuffle(ben)
    ben = ben[:a.n]
    pos = [json.loads(l) for l in open(f"{E}/eval.jsonl")]
    pos = [r["text"] for r in pos if r["set"] in ("pos_medical_mtsamples", "pos_fin_gretel", "pos_contract_cuad")]
    random.Random(3).shuffle(pos)
    pos = pos[:a.npos]
    forms = ["plain", "chat_user", "chat_sys0", "chat_sys2", "chat_multi"]

    def run(texts):
        res = {f: 0 for f in forms}
        for t in texts:
            bodies = bce.chat_bodies(t)
            for f in forms:
                svc._cache_clear()
                out = svc._analyze_sync(bodies[f], False, "outbound")
                res[f] += str(out["status"]).lower().endswith("block")
        return res

    t0 = time.time()
    rb, rp = run(ben), run(pos)
    print(f"tree={a.repo}  ({time.time() - t0:.0f}s)")
    print(f"  benign consumer texts (N={len(ben)}) blocked per form: " + ", ".join(f"{f} {rb[f]} ({100 * rb[f] / len(ben):.1f}%)" for f in forms)
          + f"  | all {sum(rb.values())}/{len(ben) * len(forms)} ({100 * sum(rb.values()) / (len(ben) * len(forms)):.1f}%)")
    print(f"  real-source positives (N={len(pos)}) blocked per form: " + ", ".join(f"{f} {rp[f]} ({100 * rp[f] / len(pos):.1f}%)" for f in forms))
    if a.json:
        json.dump({"repo": a.repo, "benign": rb, "n_benign": len(ben), "positives": rp, "n_pos": len(pos)}, open(a.json, "w"))


if __name__ == "__main__":
    main()
