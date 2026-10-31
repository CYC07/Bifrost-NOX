"""Baseline measurements of the shipped sensitive analyzer (6 production hypotheses, threshold 0.6):
per-label score distribution per set, routing share, ROC/PR points, end-to-end gate, length buckets.

    python -I dataset_tools/sensitive/baseline_report.py --repo . [--split test|dev|all]
"""
from __future__ import annotations

import argparse
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sweep_lib as L  # noqa: E402


def pct(k: int, n: int) -> str:
    lo, hi = L.wilson(int(k), int(n))
    return f"{int(k)}/{int(n)}={100 * k / max(n, 1):4.1f}%[{100 * lo:.0f}-{100 * hi:.0f}]"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=os.getcwd())
    ap.add_argument("--split", default="all")
    a = ap.parse_args()
    d = L.load(a.repo, need_stage2=False)
    A = L.arrays(d)
    print(f"docs scored (stage 1): {len(d.recs)}; dropped (no scores yet): {len(d.dropped)} {sorted({s for _, s in d.dropped})}")
    sp = a.split
    pos_core = A.sel(label="pos", group="core_real", split=sp)
    pos_synth = A.sel(label="pos", group="core_synth", split=sp)
    pos_weak = A.sel(label="pos", group="weak", split=sp)
    pos_all = A.sel(label="pos", split=sp)
    neg_all = A.sel(label="neg", split=sp)
    neg_conf = A.sel(label="neg", group=["tos_policy", "legal_public", "medical_public", "financial_public"], split=sp)
    print(f"split={sp}: pos core_real {pos_core.sum()}, core_synth {pos_synth.sum()}, weak {pos_weak.sum()}, all {pos_all.sum()}; neg all {neg_all.sum()}, confusable {neg_conf.sum()}\n")

    top = np.max([A.S[k] for k in L.T0], axis=0)
    print("== per set: N, share routed to prose (bare text / JSON body / HTML page), block@0.6 (analyzer), median & p90 top score")
    print(f"{'set':27s} {'N':>3s} {'prose raw':>9s} {'json':>5s} {'html':>5s} | {'block@0.6':>9s} | median / p90")
    for s in sorted(set(A.set), key=lambda s: (s.startswith("neg"), s)):
        m = (A.set == s) & ((A.split == sp) if sp != "all" else True)
        if not m.any():
            continue
        fr = lambda key: 100 * np.mean([d.feats[i].get(key) == "prose" for i in np.where(m)[0]]) if d.feats[0] else float("nan")
        print(f"{s:27s} {m.sum():3d} {fr('route_raw'):8.0f}% {fr('route_json'):4.0f}% {fr('route_html'):4.0f}% | {int((top[m] >= .6).sum()):3d}/{m.sum():<3d}   | {np.median(top[m]):.2f} / {np.quantile(top[m], .9):.2f}")

    print("\n== per label: share of docs with that label >= 0.6, by group (analyzer)")
    groups = list(L.POS_GROUPS) + list(L.NEG_GROUPS)
    print(f"{'group':18s} {'N':>4s} " + " ".join(f"{k[3:14]:>13s}" for k in L.T0))
    for g in groups:
        m = A.sel(group=g, split=sp)
        if m.any():
            print(f"{g:18s} {m.sum():4d} " + " ".join(f"{100 * np.mean(A.S[k][m] >= .6):12.0f}%" for k in L.T0))

    print("\n== ROC / PR points, analyzer-only (block if top-label score >= t); recall on core_real / core_synth / weak / all-pos; FP on all neg / confusable / tos_policy")
    _, auc = L.roc_points(d, list(np.where(pos_core)[0]), list(np.where(neg_all)[0]))
    _, auc_c = L.roc_points(d, list(np.where(pos_core)[0]), list(np.where(neg_conf)[0]))
    print(f"AUC core_real-vs-all-neg = {auc:.3f}; core_real-vs-confusable-neg = {auc_c:.3f}")
    print(f"{'thr':>5s} {'core_real':>20s} {'core_synth':>20s} {'weak':>20s} | {'FP all neg':>20s} {'FP confusable':>20s} {'FP tos_policy':>20s} {'prec(core_real)':>14s}")
    tos = A.sel(label="neg", group="tos_policy", split=sp)
    for t in (0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.85, 0.9, 0.95):
        b = L.vblock(L.base_rule(t), A)
        kp = (b & pos_core).sum(); kn = (b & neg_all).sum()
        print(f"{t:5.2f} {pct(kp, pos_core.sum()):>20s} {pct((b & pos_synth).sum(), pos_synth.sum()):>20s} {pct((b & pos_weak).sum(), pos_weak.sum()):>20s} | {pct(kn, neg_all.sum()):>20s} {pct((b & neg_conf).sum(), neg_conf.sum()):>20s} {pct((b & tos).sum(), tos.sum()):>20s} {kp / max(kp + kn, 1):14.2f}")

    print("\n== end-to-end at the shipped 0.6 with the BASE gate (sensitive only when route == prose; PII/secret analyzers counted)")
    base = L.base_rule(0.6)
    for direction in ("outbound", "inbound"):
        blk, cen, sens_only = L.e2e(d, A, base, direction, evidence_gate=False, inbound_mode="block")
        for name, m in (("core_real pos", pos_core), ("core_synth pos", pos_synth), ("all neg", neg_all), ("confusable neg", neg_conf), ("tos_policy neg", tos)):
            print(f"  {direction:8s} {name:15s} blocked {pct((blk & m).sum(), m.sum())}   (sensitive-only {(sens_only & m).sum()})")

    print("\n== length buckets (chars), analyzer @0.6: block rate on all neg / all pos")
    for lo, hi in ((0, 120), (120, 300), (300, 600), (600, 1000)):
        n = A.sel(label="neg", min_len=lo, max_len=hi - 1, split=sp); p = A.sel(label="pos", min_len=lo, max_len=hi - 1, split=sp)
        b = top >= .6
        print(f"  {lo:4d}-{hi:4d}: neg {pct((b & n).sum(), n.sum()):>22s}   pos {pct((b & p).sum(), p.sum()):>22s}")

    t = L.load(a.repo, need_stage2=False, include_tiny=True)
    print("\n== tiny user set (analyzer top score, route of the bare text)")
    for i, r in enumerate(t.recs):
        if r["set"].startswith("tiny"):
            k = max(L.T0, key=lambda k: t.scores[i][k])
            print(f"  {r['set']:11s} {t.scores[i][k]:.2f} {k[3:30]:28s} route={t.feats[i].get('route_raw')}  | {r['text'][:60]}")


if __name__ == "__main__":
    main()
