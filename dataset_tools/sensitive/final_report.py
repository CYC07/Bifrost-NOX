"""Before/after tables for the policy currently configured in ml/sensitive/labels.py versus the shipped baseline
(6 hypotheses, 0.6), on the SAME documents and thresholds, plus the direction / calibration / gate option matrix.

    python -I dataset_tools/sensitive/final_report.py --repo . [--split test|all] [--baseline-fp-match 0.05]

'baseline @0.6' is what shipped; 'baseline @FP-match' is the baseline with one global threshold raised until its
dev false-positive rate is <= the cap, i.e. the fairest 'what did the calibration buy' comparison.
"""
from __future__ import annotations

import argparse
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sweep_lib as L  # noqa: E402
from baseline_report import pct  # noqa: E402

GROUPS_POS = ["core_real", "core_synth", "weak"]
GROUPS_NEG = ["tos_policy", "legal_public", "medical_public", "financial_public", "docs", "other"]


def table(title, d, A, rules: dict, sp: str, **kw):
    print(f"\n### {title}   (split={sp})")
    ms = {g: A.sel(label="pos", group=g, split=sp) for g in GROUPS_POS}
    ms["pos_all"] = A.sel(label="pos", split=sp)
    mn = {g: A.sel(label="neg", group=g, split=sp) for g in GROUPS_NEG}
    mn["neg_all"] = A.sel(label="neg", split=sp)
    mn["neg_confusable"] = A.sel(label="neg", group=["tos_policy", "legal_public", "medical_public", "financial_public"], split=sp)
    cols = list(ms) + list(mn)
    print(f"{'config':34s} | " + " | ".join(f"{c[:15]:>20s}" for c in cols))
    for name, fn in rules.items():
        blk = fn()
        print(f"{name:34s} | " + " | ".join(f"{pct((blk & (ms.get(c) if c in ms else mn[c])).sum(), (ms.get(c) if c in ms else mn[c]).sum()):>20s}" for c in cols))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=os.getcwd())
    ap.add_argument("--split", default="test")
    ap.add_argument("--cap", type=float, default=0.03)
    a = ap.parse_args()
    d = L.load(a.repo, need_stage2=True)
    A = L.arrays(d)
    print(f"documents with all scores: {len(d.recs)} (dev {int((A.split == 'dev').sum())}, test {int((A.split == 'test').sum())}); dropped {len(d.dropped)}")
    final = L.shipped_rule()
    base = L.base_rule(0.6)
    # baseline with one global threshold chosen on dev under the cap
    negdev = A.sel(label="neg", split="dev")
    thr_m = next((t for t in (0.5, 0.6, 0.7, 0.8, 0.85, 0.9, 0.95, 0.98, 0.995) if (L.vblock(L.base_rule(t), A) & negdev).sum() <= a.cap * negdev.sum()), 0.999)
    base_m = L.base_rule(thr_m)
    print(f"baseline FP-matched global threshold (dev FP <= {a.cap:.0%}): {thr_m}")
    print("final rule:", {k: (v if k != 'thr' else {kk.split(':')[1][:14]: vv for kk, vv in v.items()}) for k, v in final.items()})

    for sp in (a.split, "all"):
        table("ANALYZER ONLY (model_sensitive on every body; no router, no PII analyzers)", d, A, {
            "baseline @0.6 (shipped)": lambda: L.vblock(base, A),
            f"baseline @{thr_m} (FP-matched)": lambda: L.vblock(base_m, A),
            "final policy": lambda: L.vblock(final, A)}, sp)

    # end-to-end option matrix, OUTBOUND (the gate)
    for sp in (a.split, "all"):
        table("END-TO-END OUTBOUND (router gate + PII/secret analyzers + sensitive), the 5% gate is measured here", d, A, {
            "base gate, baseline @0.6 (shipped)": lambda: L.e2e(d, A, base, "outbound", evidence_gate=False)[0],
            "base gate, final policy": lambda: L.e2e(d, A, final, "outbound", evidence_gate=False)[0],
            "evidence gate, baseline @0.6": lambda: L.e2e(d, A, base, "outbound", evidence_gate=True)[0],
            "evidence gate, final policy (= shipped now)": lambda: L.e2e(d, A, final, "outbound", evidence_gate=True)[0]}, sp)

    # what the gate itself adds
    ev_only = L.e2e(d, A, final, "outbound", evidence_gate=True)[0] & ~L.e2e(d, A, final, "outbound", evidence_gate=False)[0]
    nonprose = np.array([f.get("route_raw") != "prose" for f in d.feats])
    for nm, m in (("benign", A.sel(label="neg")), ("positive", A.sel(label="pos"))):
        print(f"\nevidence gate adds: {nm} bodies newly blocked = {(ev_only & m).sum()} of {m.sum()};  "
              f"non-prose bodies that now reach the NLI = {((A.ev > 0) & nonprose & m).sum()} (non-prose total {(nonprose & m).sum()})")

    # INBOUND: the direction option
    for sp in (a.split, "all"):
        print(f"\n### INBOUND (a server's reply; the same benign documents seen as responses)   split={sp}")
        negm = A.sel(label="neg", split=sp); posm = A.sel(label="pos", split=sp)
        print(f"{'config':44s} | {'benign BLOCKED':>22s} | {'benign CENSOR(WARN)':>22s} | {'core_real BLOCKED':>22s} | {'core_real CENSOR':>22s}")
        cr = A.sel(label="pos", group="core_real", split=sp)
        for name, rule, mode in (("old: baseline, inbound blocks", base, "block"), ("baseline + inbound advisory (direction only)", base, "advisory"),
                                 ("final calibration, inbound blocks", final, "block"), ("final calibration + inbound advisory (default)", final, "advisory")):
            blk, cen, _ = L.e2e(d, A, rule, "inbound", evidence_gate=True, inbound_mode=mode)
            print(f"{name:44s} | {pct((blk & negm).sum(), negm.sum()):>22s} | {pct((cen & negm).sum(), negm.sum()):>22s} | {pct((blk & cr).sum(), cr.sum()):>22s} | {pct((cen & cr).sum(), cr.sum()):>22s}")

    print("\n### per set, final policy vs baseline @0.6 (analyzer-only), all documents")
    bf, bb = L.vblock(final, A), L.vblock(base, A)
    for s in sorted(set(A.set), key=lambda s: (s.startswith("neg"), s)):
        m = A.set == s
        print(f"  {s:27s} N={m.sum():3d}  baseline {int((bb & m).sum()):3d}  final {int((bf & m).sum()):3d}   ({'recall' if s.startswith('pos') else 'FALSE POSITIVES'})")


if __name__ == "__main__":
    main()
