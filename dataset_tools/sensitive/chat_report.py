"""Consumer-question false positives: base policy vs A4 policy vs the current labels.py, per source set, plus the
recall cost on the real-source positives.  (Run build_chat_eval.py, nli_pool.py --stage 1/3 and features.py on
chat_eval.jsonl first; see README.)

    python -I dataset_tools/sensitive/chat_report.py --repo . [--show-fp 12]
"""
from __future__ import annotations

import argparse
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sweep_lib as L  # noqa: E402
from baseline_report import pct  # noqa: E402

A4_RULE = None  # filled in main (the rule shipped by commit 0b08965: fin 0.4 / med 0.5 / conf 0.8 / legal 0.95, ToS contrast 0.1)


def a4_rule():
    conf, fin, med, leg = L.T0[0], L.T0[2], L.T0[3], L.T0[5]
    return {"keys": [conf, fin, med, leg], "thr": {conf: .8, fin: .4, med: .5, leg: .95}, "low": {k: .2 for k in (conf, fin, med, leg)},
            "min_ev": 1, "contrast": ["b2:tos"], "margin": 0.1, "identity_bundle": 2}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=os.getcwd())
    ap.add_argument("--show-fp", type=int, default=0)
    a = ap.parse_args()
    d = L.load(a.repo, need_stage2=True)
    A = L.arrays(d)
    rules = {"base (6 labels @0.6)": L.base_rule(0.6), "A4 (0b08965)": a4_rule(), "A4 + question rule": {**a4_rule(), "question": True},
             "labels.py now": L.shipped_rule()}
    qa_sets = L.NEG_GROUPS["consumer_qa"]
    cr = A.sel(label="pos", group="core_real")
    old_neg = A.sel(label="neg") & ~np.isin(A.set, qa_sets)
    print(f"consumer-QA docs {int(np.isin(A.set, qa_sets).sum())}; real-source positives {int(cr.sum())} (with stage-2 scores); old benign {int(old_neg.sum())}")
    print(f"\n{'rule':24s} | " + " | ".join(f"{s[6:]:>17s}" for s in qa_sets) + f" | {'ALL consumer-QA':>18s} | {'old benign':>18s} | {'core_real recall':>18s}")
    for nm, r in rules.items():
        b = L.vblock(r, A)
        cells = [pct((b & (A.set == s)).sum(), (A.set == s).sum()) for s in qa_sets]
        qa = np.isin(A.set, qa_sets)
        print(f"{nm:24s} | " + " | ".join(f"{c:>17s}" for c in cells) + f" | {pct((b & qa).sum(), qa.sum()):>18s} | {pct((b & old_neg).sum(), old_neg.sum()):>18s} | {pct((b & cr).sum(), cr.sum()):>18s}")
    if a.show_fp:
        b = L.vblock(rules["A4 (0b08965)"], A)
        qa = np.isin(A.set, qa_sets)
        print("\nA4 false positives on consumer questions (top score label):")
        for i in np.where(b & qa)[0][: a.show_fp]:
            k = max(L.T0, key=lambda k: A.S[k][i])
            print(f"  {A.S[k][i]:.2f} {k[3:25]:22s} ev={d.ev[i]} | {d.recs[i]['text'][:110]!r}")


if __name__ == "__main__":
    main()
