"""Rule sweep: choose every setting on DEV, report on TEST. Needs pool_s1/s2 + features (nli_pool.py, features.py).

    python -I dataset_tools/sensitive/sweep.py --repo . [--fp-cap 0.03] [--tos-cap 0.06] [--json out.json]

Selection protocol (identical for every step, so the comparison is fair):
  maximise dev recall on core_real positives subject to  dev FP(all benign) <= fp-cap  and
  dev FP(terms-of-service / privacy-policy benign) <= tos-cap; ties -> core_synth recall, then fewer false
  positives, then fewer hypotheses. The chosen rule is then scored once on the TEST half and on everything.
Steps are cumulative (each keeps the previous winner's settings) AND each option is also scored on its own.
"""
from __future__ import annotations

import argparse
import itertools
import json
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sweep_lib as L  # noqa: E402
from baseline_report import pct  # noqa: E402

GRID = [0.5, 0.6, 0.7, 0.8, 0.85, 0.9, 0.95, 0.98]
THR_GRID = [0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.98, 1.01]
T2_OF = {"t2:conf": "t0:confidential or internal company document", "t2:med": "t0:private medical or health record",
         "t2:legal": "t0:confidential legal or contractual document"}
BEN = ["b2:tos", "b2:publaw", "b2:news", "b2:pubhealth", "b2:pubfin", "b2:docs"]


class Ctx:
    def __init__(self, d: L.Data, A: L.Arrays, fp_cap: float, tos_cap: float):
        self.d, self.A, self.fp_cap, self.tos_cap = d, A, fp_cap, tos_cap
        sel = A.sel
        self.m = {sp: {"core_real": sel(label="pos", group="core_real", split=sp), "core_synth": sel(label="pos", group="core_synth", split=sp),
                       "weak": sel(label="pos", group="weak", split=sp), "pos_all": sel(label="pos", split=sp),
                       "neg": sel(label="neg", split=sp), "tos": sel(label="neg", group="tos_policy", split=sp),
                       "conf": sel(label="neg", group=["tos_policy", "legal_public", "medical_public", "financial_public"], split=sp)}
                  for sp in ("dev", "test", "all")}

    def score(self, rule, sp="dev") -> dict:
        b = L.vblock(rule, self.A)
        m = self.m[sp]
        return {k: (int((b & v).sum()), int(v.sum())) for k, v in m.items()}

    def key(self, rule):
        """Selection key on DEV (higher is better); None = violates a cap."""
        s = self.score(rule, "dev")
        if s["neg"][0] > self.fp_cap * s["neg"][1] or s["tos"][0] > self.tos_cap * s["tos"][1]:
            return None
        return (s["core_real"][0], s["core_synth"][0], -s["neg"][0], -len(rule["keys"]) - len(rule.get("contrast") or []))

    def pick(self, cands):
        best, bk = None, None
        for r in cands:
            k = self.key(r)
            if k is not None and (bk is None or k > bk):
                best, bk = r, k
        return best


def coord_thresholds(ctx: Ctx, keys, extra=None, rounds=3):
    """Per-key threshold by coordinate ascent from 'off' (1.01), maximising the dev key."""
    extra = extra or {}
    thr = {k: 1.01 for k in keys}
    for _ in range(rounds):
        for k in keys:
            best_t, best_key = thr[k], ctx.key({"keys": keys, "thr": thr, **extra})
            for t in THR_GRID:
                kk = ctx.key({"keys": keys, "thr": {**thr, k: t}, **extra})
                if kk is not None and (best_key is None or kk > best_key):
                    best_t, best_key = t, kk
            thr[k] = best_t
    return {"keys": list(keys), "thr": dict(thr), **extra}


def fmt(rule) -> str:
    if rule is None:
        return "-- (nothing satisfies the caps)"
    thr = {k: v for k, v in rule["thr"].items() if v <= 1.0}
    s = "thr[" + ", ".join(f"{k.split(':', 1)[1][:12]}={v}" for k, v in thr.items()) + "]"
    if rule.get("contrast"):
        s += f" contrast={[c.split(':')[1] for c in rule['contrast']]} margin>={rule.get('margin')}"
    if rule.get("low"):
        s += f" low={ {k.split(':', 1)[1][:8]: v for k, v in rule['low'].items()} } min_ev={rule.get('min_ev')}"
    if rule.get("identity_bundle"):
        s += f" identity_bundle={rule['identity_bundle']}"
    return s


def row(ctx: Ctx, name: str, rule) -> dict:
    if rule is None:
        print(f"{name:44s} --")
        return {}
    dev, tst, al = ctx.score(rule, "dev"), ctx.score(rule, "test"), ctx.score(rule, "all")
    print(f"{name:44s} | DEV core_real {pct(*dev['core_real']):>19s} FP {pct(*dev['neg']):>19s} || TEST core_real {pct(*tst['core_real']):>19s} core_synth {pct(*tst['core_synth']):>19s} "
          f"weak {pct(*tst['weak']):>19s} | FP all {pct(*tst['neg']):>19s} conf {pct(*tst['conf']):>19s} tos {pct(*tst['tos']):>18s}")
    print(f"{'':44s}   {fmt(rule)}")
    return {"rule": rule, "dev": dev, "test": tst, "all": al}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=os.getcwd())
    ap.add_argument("--fp-cap", type=float, default=0.03)
    ap.add_argument("--tos-cap", type=float, default=0.06)
    ap.add_argument("--json", default="")
    ap.add_argument("--smoke", action="store_true", help="code-path check only: fabricate random stage-2 scores (numbers are meaningless)")
    a = ap.parse_args()
    d = L.load(a.repo, need_stage2=not a.smoke)
    if a.smoke:
        from hypotheses import POOL
        rng = np.random.default_rng(0)
        for s in d.scores:
            for k in POOL:
                s.setdefault(k, float(rng.random()))
    A = L.arrays(d)
    ctx = Ctx(d, A, a.fp_cap, a.tos_cap)
    print(f"docs with stage1+2 scores: {len(d.recs)} (dropped {len(d.dropped)}); caps: dev FP<={a.fp_cap:.0%}, dev ToS-FP<={a.tos_cap:.0%}")
    for sp in ("dev", "test"):
        m = ctx.m[sp]
        print(f"  {sp}: core_real {m['core_real'].sum()} core_synth {m['core_synth'].sum()} weak {m['weak'].sum()} | neg {m['neg'].sum()} (confusable {m['conf'].sum()}, tos {m['tos'].sum()})")
    out = {}
    print("\n" + "=" * 30 + " each option on its own, then cumulative " + "=" * 30)
    out["E0 baseline shipped (6 labels, 0.6)"] = row(ctx, "E0 baseline shipped (6 labels, 0.6)", L.base_rule(0.6))
    out["E1 baseline, one global threshold"] = row(ctx, "E1 baseline, one global threshold", ctx.pick([L.base_rule(t) for t in GRID + [0.99]]))

    # label ablation under per-label thresholds
    subsets = {"all 6": L.T0, "drop code": [k for k in L.T0 if "source code" not in k],
               "drop code+gov": [k for k in L.T0 if "source code" not in k and "classified" not in k]}
    best_sub = {}
    for nm, ks in subsets.items():
        r = coord_thresholds(ctx, ks)
        best_sub[nm] = r
        out[f"E2 per-label thr, labels={nm}"] = row(ctx, f"E2 per-label thr, labels={nm}", r)
    # choose label subset: fewest labels within one dev-recall unit of the best
    cand = [(ctx.key(r), nm, r) for nm, r in best_sub.items() if ctx.key(r) is not None]
    top = max(c[0][0] for c in cand) if cand else 0
    base_rule_ = sorted([c for c in cand if c[0][0] >= top], key=lambda c: len(c[2]["keys"]))[0][2] if cand else L.base_rule(0.99)
    keys0 = base_rule_["keys"]

    # template: swap t0 -> t2 for conf/med/legal
    keys_t2 = [next((k2 for k2, k0 in T2_OF.items() if k0 == k), k) for k in keys0]
    r = coord_thresholds(ctx, keys_t2)
    out["E3 template t2 on conf/med/legal"] = row(ctx, "E3 template t2 on conf/med/legal", r)
    keys_best = keys_t2 if (ctx.key(r) or (-1,))[0] > (ctx.key(base_rule_) or (-1,))[0] else keys0
    base1 = coord_thresholds(ctx, keys_best)

    # contrast: greedy forward selection of benign classes, margin grid, thresholds re-tuned
    chosen: list[str] = []
    cur = base1
    print("\n-- greedy contrast selection (cumulative)")
    for step in range(len(BEN)):
        best, bk, bn = None, ctx.key(cur), None
        for b in BEN:
            if b in chosen:
                continue
            for m in (0.0, 0.1, 0.2, 0.3, 0.5, 0.7):
                r = coord_thresholds(ctx, keys_best, {"contrast": chosen + [b], "margin": m}, rounds=2)
                kk = ctx.key(r)
                if kk is not None and (bk is None or kk > bk):
                    best, bk, bn = r, kk, b
        if best is None:
            break
        chosen.append(bn)
        cur = best
        out[f"E4 + contrast {chosen}"] = row(ctx, f"E4 + contrast ({len(chosen)}) +{bn.split(':')[1]}", cur)
    contrast_rule = cur
    # contrast alone: contrast classes added to a flat 0.6 threshold (no per-label tuning)
    flat = {"keys": list(keys_best), "thr": {k: 0.6 for k in keys_best}, "contrast": chosen, "margin": contrast_rule.get("margin", 0.0)}
    out["E4b contrast only (flat 0.6 thresholds)"] = row(ctx, "E4b contrast only (flat 0.6 thresholds)", flat)

    # evidence tier
    cands = []
    for low in (0.05, 0.1, 0.2, 0.3, 0.4, 0.5):
        for me in (1, 2):
            r = {**contrast_rule, "low": {k: low for k in contrast_rule["keys"] if contrast_rule["thr"][k] > low}, "min_ev": me}
            cands.append(r)
    ev_rule = ctx.pick(cands) or contrast_rule
    out["E5 + evidence tier"] = row(ctx, "E5 + evidence tier (on contrast rule)", ev_rule)
    cands = [{**ev_rule, "identity_bundle": n} for n in (1, 2)] + [ev_rule]
    id_rule = ctx.pick(cands) or ev_rule
    out["E6 + identity bundle (FINAL candidate)"] = row(ctx, "E6 + identity bundle (FINAL candidate)", id_rule)
    # evidence on its own, without contrast, on the per-label rule
    cands = [{**base1, "low": {k: low for k in base1["keys"] if base1["thr"][k] > low}, "min_ev": me} for low in (0.05, 0.1, 0.2, 0.3, 0.4, 0.5) for me in (1, 2)]
    out["E5b evidence tier only (per-label thr)"] = row(ctx, "E5b evidence tier only (per-label thr)", ctx.pick(cands))
    out["E6b identity bundle only (baseline 0.6)"] = row(ctx, "E6b identity bundle only (baseline 0.6)", {**L.base_rule(0.6), "identity_bundle": 2})
    # E7: the rule that carries no contrast hypotheses (cheaper): per-label thr + evidence tier + identity bundle
    for lowgrid, nm in (((0.05, 0.1, 0.2, 0.3, 0.4, 0.5), "E7 per-label thr + evidence tier + identity bundle (no contrast)"),):
        cands = []
        for low in lowgrid:
            for me in (1, 2):
                for ib in (0, 1, 2):
                    r = {**base1, "low": {k: low for k in base1["keys"] if base1["thr"][k] > low}, "min_ev": me}
                    if ib:
                        r["identity_bundle"] = ib
                    cands.append(r)
        out[nm] = row(ctx, nm, ctx.pick(cands))
    if a.json:
        json.dump({k: v for k, v in out.items() if v}, open(a.json, "w"), indent=1, default=lambda o: list(o))
        print("wrote", a.json)


if __name__ == "__main__":
    main()
