"""Offline evaluation + rule sweep for the sensitive-content analyzer (no model needed).

Inputs (all under ~/FYP/corpora/sens_eval/): eval.jsonl, tiny.jsonl, pool_s1/s2.jsonl (NLI scores from
nli_pool.py), features.jsonl (router + Presidio + secrets from features.py).

A *rule* is a plain dict of parameters. `decide()` is the readable reference implementation, `vblock()` the
vectorised one used by the sweep; the production policy in ml/sensitive/predictor.py (`decide_from_scores`)
is checked against both in dataset_tools/tests/test_sensitive_tools.py, so the numbers reported from here
are the numbers the shipped code produces.
"""
from __future__ import annotations

import json
import math
import os
import sys
from dataclasses import dataclass, field

import numpy as np

DIR = os.path.expanduser("~/FYP/corpora/sens_eval")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from hypotheses import BASE_LABELS  # noqa: E402

T0 = [f"t0:{l}" for l in BASE_LABELS]
IDENT = ("id-number", "date-of-birth", "home-address")

# ---- evaluation groups (by set name) ---------------------------------------------------------------
# Positives. core_real = real-source documents (clinical notes, LLM-synthesised financial documents, SEC contracts);
# core_synth = generated here (pay lists / unreleased results / identity sentences), whose evidence recall is by
# construction; weak = label-doubtful (prompt-like PII sentences, mostly-mundane email). Regrouped (weak) on
# 2026-10-31 AFTER the baseline scores of those sets had been seen; pos_all is always reported too.
POS_GROUPS = {
    "core_real": ["pos_medical_mtsamples", "pos_fin_gretel", "pos_contract_cuad"],
    "core_synth": ["pos_synth_hrfin_marked", "pos_synth_hrfin_unmarked", "pos_pii_synth_ids"],
    "weak": ["pos_pii_ai4_highvalue", "pos_pii_ai4_nameonly", "pos_email_enron_marked", "pos_email_enron_plain"],
}
# Negatives, by what they are (the first four are the public-facing legal / medical / financial prose where a
# topic detector confuses public with confidential).
NEG_GROUPS = {
    "tos_policy": ["neg_tos_online", "neg_tos_opp115_privacy", "neg_tos_privacyqa", "neg_tos_github"],
    "legal_public": ["neg_legal_eurlex", "neg_legal_constitutions", "neg_legal_cfpb_cardagr", "neg_legal_licenses"],
    "medical_public": ["neg_med_textbook", "neg_med_nih_qa"],
    "financial_public": ["neg_fin_news_bbc", "neg_fin_filings_sec"],
    "docs": ["neg_docs_man", "neg_docs_readme"],
    "other": ["neg_news_cnn", "neg_news_xsum", "neg_wiki", "neg_blogs", "neg_recipes"],
}
SET2GROUP = {s: g for gs in (POS_GROUPS, NEG_GROUPS) for g, ss in gs.items() for s in ss}


def jl(path: str) -> list[dict]:
    return [json.loads(l) for l in open(path, encoding="utf-8")] if os.path.exists(path) else []


@dataclass
class Data:
    recs: list[dict]
    scores: list[dict[str, float]]
    feats: list[dict]
    ev: list[list[str]]
    dropped: list[tuple[str, str]] = field(default_factory=list)   # (id, set) without the needed scores
    idx: dict[str, int] = field(default_factory=dict)

    def sel(self, f) -> list[int]:
        return [i for i, r in enumerate(self.recs) if f(r)]


def load(repo: str, need_stage2: bool = True, include_tiny: bool = False) -> Data:
    sys.path.insert(0, repo)
    from ml.sensitive.evidence import find_evidence
    recs = jl(f"{DIR}/eval.jsonl") + (jl(f"{DIR}/tiny.jsonl") if include_tiny else [])
    s1 = {r["id"]: r["s"] for r in jl(f"{DIR}/pool_s1.jsonl") + jl(f"{DIR}/pool_tiny_s1.jsonl")}
    s2 = {r["id"]: r["s"] for r in jl(f"{DIR}/pool_s2.jsonl") + jl(f"{DIR}/pool_tiny_s2.jsonl")}
    ft = {r["id"]: r for r in jl(f"{DIR}/features.jsonl")}
    out = Data([], [], [], [])
    for r in recs:
        if r["id"] not in s1 or (need_stage2 and r["id"] not in s2):
            out.dropped.append((r["id"], r["set"]))
            continue
        out.recs.append(r)
        out.scores.append({**s1[r["id"]], **s2.get(r["id"], {})})
        out.feats.append(ft.get(r["id"], {}))
        out.ev.append(find_evidence(r["text"]))
    out.idx = {r["id"]: i for i, r in enumerate(out.recs)}
    return out


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


# ----------------------------------------------------------------------------- rules
def base_rule(thr: float = 0.6, keys=None) -> dict:
    keys = keys or T0
    return {"keys": list(keys), "thr": {k: thr for k in keys}}


def decide(rule: dict, s: dict[str, float], ev: list[str]) -> tuple[bool, str]:
    """Reference implementation (mirrors ml.sensitive.predictor.decide_from_scores).

    rule keys:
      keys             sensitive hypothesis keys considered
      thr              per-key block threshold (score >= thr): NLI alone
      low              optional per-key lower threshold: blocks with >= min_ev evidence signals
      min_ev           corroborating signals required for the low tier
      contrast/margin  benign keys; sens - max(benign) must be >= margin (applies to both tiers)
      identity_bundle  identity signals (ID number / DOB / home address) that block on their own
    """
    keys = rule["keys"]
    best_k = max(keys, key=lambda k: s.get(k, 0.0))
    ident = sum(1 for e in ev if e in IDENT)
    if rule.get("identity_bundle") and ident >= rule["identity_bundle"]:
        return True, "identity-bundle"
    contrast = rule.get("contrast")
    cmax = max((s.get(c, 0.0) for c in contrast), default=0.0) if contrast else 0.0
    for k in keys:
        v = s.get(k, 0.0)
        if contrast and v - cmax < rule.get("margin", 0.0):
            continue
        if v >= rule["thr"][k]:
            return True, k
        low = rule.get("low", {}).get(k)
        if low is not None and v >= low and len(ev) >= rule.get("min_ev", 1):
            return True, k
    return False, best_k


@dataclass
class Arrays:
    S: dict[str, np.ndarray]
    ev: np.ndarray
    ident: np.ndarray
    n: int
    set: np.ndarray
    split: np.ndarray
    label: np.ndarray
    group: np.ndarray
    length: np.ndarray

    def sel(self, *, label: str | None = None, group: str | list[str] | None = None, sets: list[str] | None = None,
            split: str = "all", min_len: int = 0, max_len: int = 10**9) -> np.ndarray:
        m = np.ones(self.n, bool)
        if label:
            m &= self.label == label
        if group:
            gs = [group] if isinstance(group, str) else group
            m &= np.isin(self.group, gs)
        if sets:
            m &= np.isin(self.set, sets)
        if split != "all":
            m &= self.split == split
        return m & (self.length >= min_len) & (self.length <= max_len)


def arrays(d: Data) -> Arrays:
    keys = sorted({k for s in d.scores for k in s})
    S = {k: np.array([s.get(k, 0.0) for s in d.scores]) for k in keys}
    return Arrays(
        S, np.array([len(e) for e in d.ev]), np.array([sum(1 for x in e if x in IDENT) for e in d.ev]), len(d.recs),
        np.array([r["set"] for r in d.recs]), np.array([r["split"] for r in d.recs]), np.array([r["label"] for r in d.recs]),
        np.array([SET2GROUP.get(r["set"], "tiny") for r in d.recs]), np.array([len(r["text"]) for r in d.recs]))


def vblock(rule: dict, A: Arrays) -> np.ndarray:
    """Vectorised `decide(...)[0]` over all documents."""
    out = np.zeros(A.n, bool)
    if rule.get("identity_bundle"):
        out |= A.ident >= rule["identity_bundle"]
    contrast = rule.get("contrast")
    cmax = np.max([A.S[c] for c in contrast], axis=0) if contrast else None
    for k in rule["keys"]:
        s = A.S[k]
        hit = s >= rule["thr"][k]
        low = rule.get("low", {}).get(k)
        if low is not None:
            hit = hit | ((s >= low) & (A.ev >= rule.get("min_ev", 1)))
        if contrast:
            hit = hit & (s - cmax >= rule.get("margin", 0.0))
        out |= hit
    return out


def shipped_rule() -> dict:
    """The policy currently configured in ml/sensitive/labels.py, as a sweep rule over the pool keys.
    Every shipped hypothesis must be one of the pooled (= measured) hypotheses."""
    from hypotheses import POOL
    from ml.sensitive import labels as lb
    rev = {v: k for k, v in POOL.items()}
    keys, thr, low = [], {}, {}
    for h, spec in lb.sensitive_labels().items():
        k = rev[h]
        keys.append(k)
        thr[k] = spec.block
        if spec.low is not None:
            low[k] = spec.low
    contrast = [rev[h] for h in lb.contrast_labels()]
    return {"keys": keys, "thr": thr, "low": low, "min_ev": lb.MIN_EVIDENCE, "contrast": contrast or None,
            "margin": lb.MARGIN, "identity_bundle": lb.IDENTITY_BUNDLE}


# ----------------------------------------------------------------------------- end-to-end gate
def e2e(d: Data, A: Arrays, rule: dict, direction: str, *, evidence_gate: bool, inbound_mode: str = "advisory"):
    """Per-document outcome of the text-service pipeline restricted to what this task touches:
    PII / secret analyzers (real functions, features.jsonl) + the sensitive analyzer behind the router gate.

    evidence_gate=False reproduces the base gate (route == prose); True the new one
    (prose, or outbound with find_evidence(text)). Inbound the sensitive finding is advisory unless
    inbound_mode == 'block'. Returns (blocked, censored, by_sensitive_only) boolean arrays."""
    tag = "out" if direction == "outbound" else "in"
    other = np.array([bool(f.get(f"pat_{tag}", {}).get("blocked") or f.get(f"sec_{tag}", {}).get("blocked")) for f in d.feats])
    prose = np.array([f.get("route_raw") == "prose" for f in d.feats])
    gate = prose | ((A.ev > 0) if (evidence_gate and direction == "outbound") else False)
    hit = vblock(rule, A) & gate & ~other
    advisory = np.array([bool(f.get(f"pat_{tag}", {}).get("advisory") or f.get(f"sec_{tag}", {}).get("advisory")) for f in d.feats])
    if direction == "outbound" or inbound_mode == "block":
        blocked, censored = other | hit, advisory & ~(other | hit)
    else:
        blocked, censored = other, (hit | advisory) & ~other
    return blocked, censored, hit & ~other


def roc_points(data: Data, pos: list[int], neg: list[int], keys=T0, grid=None):
    grid = grid or [0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.85, 0.9, 0.95]
    ps = np.array([max(data.scores[i].get(k, 0) for k in keys) for i in pos])
    ns = np.array([max(data.scores[i].get(k, 0) for k in keys) for i in neg])
    rows = [(t, float((ps >= t).mean()), float((ns >= t).mean())) for t in grid]
    auc = float(((ps[:, None] > ns[None, :]).sum() + 0.5 * (ps[:, None] == ns[None, :]).sum()) / (len(ps) * len(ns))) if len(ps) and len(ns) else float("nan")
    return rows, auc
