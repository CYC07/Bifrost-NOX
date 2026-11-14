"""Re-tune the per-label thresholds with the consumer-question set in the benign pool.

    python -I dataset_tools/sensitive/sweep_chat.py --repo . [--qa-cap 0.02]

Fixed structure (what A4 shipped plus the question rule): 4 labels, ToS contrast margin 0.1, evidence tier,
identity bundle 2, question rule.  Searched: each label's `block` threshold and `low` (evidence tier) threshold.
Selection on DEV: max core_real recall s.t. dev FP(all benign) <= fp-cap, dev FP(ToS) <= tos-cap and dev
FP(consumer questions/statements) <= qa-cap; ties -> fewer FP.  Reported on TEST and all.
"""
from __future__ import annotations

import argparse
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sweep_lib as L  # noqa: E402
from baseline_report import pct  # noqa: E402
from chat_report import a4_rule  # noqa: E402

GRID = [0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.98, 1.01]
LOWG = [0.1, 0.2, 0.3, 0.5, 1.01]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=os.getcwd())
    ap.add_argument("--fp-cap", type=float, default=0.03)
    ap.add_argument("--tos-cap", type=float, default=0.06)
    ap.add_argument("--qa-cap", type=float, default=0.02)
    a = ap.parse_args()
    d = L.load(a.repo, need_stage2=True)
    A = L.arrays(d)
    qa_sets = L.NEG_GROUPS["consumer_qa"]
    M = {}
    for sp in ("dev", "test", "all"):
        M[sp] = dict(cr=A.sel(label="pos", group="core_real", split=sp), cs=A.sel(label="pos", group="core_synth", split=sp),
                     neg=A.sel(label="neg", split=sp), tos=A.sel(label="neg", group="tos_policy", split=sp),
                     qa=A.sel(label="neg", group="consumer_qa", split=sp), old=A.sel(label="neg", split=sp) & ~np.isin(A.set, qa_sets))

    def counts(rule, sp):
        b = L.vblock(rule, A)
        return {k: (int((b & m).sum()), int(m.sum())) for k, m in M[sp].items()}

    def key(rule):
        c = counts(rule, "dev")
        if c["old"][0] > a.fp_cap * c["old"][1] or c["tos"][0] > a.tos_cap * c["tos"][1] or c["qa"][0] > a.qa_cap * c["qa"][1]:
            return None
        return (c["cr"][0], c["cs"][0], -c["old"][0] - c["qa"][0])

    conf, fin, med, leg = L.T0[0], L.T0[2], L.T0[3], L.T0[5]
    keys = [conf, fin, med, leg]
    cur = {**a4_rule(), "question": True}
    print("start (A4 + question rule):", counts(cur, "dev")["qa"], key(cur))
    for _ in range(3):
        for k in keys:
            best, bk = cur, key(cur)
            for t in GRID:
                for lo in LOWG:
                    if lo > 1.0 and t > 1.0:
                        continue
                    r = {**cur, "thr": {**cur["thr"], k: t}, "low": {**cur["low"], k: lo}}
                    kk = key(r)
                    if kk is not None and (bk is None or kk > bk):
                        best, bk = r, kk
            cur = best
    print("\nchosen thresholds:", {k.split(":")[1][:16]: (cur["thr"][k], cur["low"][k]) for k in keys})
    for nm, r in (("A4 + question rule", {**a4_rule(), "question": True}), ("re-tuned", cur)):
        print(f"\n{nm}")
        for sp in ("dev", "test", "all"):
            c = counts(r, sp)
            print(f"  {sp:4s} core_real {pct(*c['cr']):>20s} core_synth {pct(*c['cs']):>20s} | FP old-benign {pct(*c['old']):>20s} ToS {pct(*c['tos']):>18s} consumer-QA {pct(*c['qa']):>20s}")


if __name__ == "__main__":
    main()
