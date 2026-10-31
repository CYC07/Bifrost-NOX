"""Ship gate for the WAF v2 bake-off.

    python -m dataset_tools.waf.v2.gate --results waf_v2_results.json --artifact ml/waf/artifacts/waf_distilbert_v2
    python -m dataset_tools.waf.v2.gate --replay-only --artifact ml/waf/artifacts/waf_distilbert --arm A   # a measurement, not a verdict

Prints PASS/FAIL per gate and exits non-zero on any FAIL.

* Every metric is recomputed from the raw numbers in ``waf_v2_results.json``; the notebook's own PASS
  flags are ignored. A missing, NaN or non-numeric metric is a FAIL, never a crash.
* The artifact and the results must belong together (same arm, same recommended threshold).
* The production-path replay loads the artifact through ``ml.waf.predictor`` inside ``text_service``
  (a subprocess: the model path and thresholds are read at import time) and sends the 25 probes plus the
  realistic benign bodies through ``text_service.main._analyze_sync(text, False, "outbound")``.

``GATES`` and ``gate_checks`` are the ONE definition of the notebook gates: ``make_notebook`` embeds
their source into cell 9 of the Colab notebook, so the two cannot drift. Keep ``gate_checks``
self-contained (``math`` only).
"""
from __future__ import annotations

import argparse
import json
import math
import os
import subprocess
import sys
import tempfile

from dataset_tools import paths
from dataset_tools.waf.v2 import probes

ARM_A = "A_softmax7"
ARM_B = "B_sigmoid6"
_ARM_ALIASES = {"A": ARM_A, "A_SOFTMAX7": ARM_A, "B": ARM_B, "B_SIGMOID6": ARM_B}

GATES: dict[str, float] = {
    "test_fp": 0.01,                 # clean rows of the test split flagged
    "shape_fp": 0.03,                # same, worst carrier shape
    "recall": 0.90,                  # attack rows of the test split flagged
    "ood_fp": 0.02,                  # clean rows in the held-out carrier shapes
    "ood_recall": 0.80,
    "ind_benign_fp_frac": 0.20,      # hand-written benign probes flagged (fraction of the probes)
    "ind_attacks_missed_max": 1,     # hand-written attack probes allowed to slip through
    "holdout_recall": 0.80,          # attacks from the held-out payload SOURCE
    "holdout_benign_fp": 0.02,       # realistic hand-written benign bodies (+ benign probes) flagged
    "replay_benign_block": 0.10,     # production path: benign probes/bodies blocked
    "replay_attack_block": 0.90,     # production path: attack probes blocked
}
NOTEBOOK_GATE_KEYS = tuple(k for k in GATES if not k.startswith("replay_"))


def gate_checks(m, gates):
    """Notebook gates for ONE arm. ``m`` = {"test","ood","holdout": evaluate() dicts, "ind": {...}}.
    Returns [(name, ok, detail)]. Self-contained on purpose (embedded in the Colab notebook)."""
    def num(x):
        return math.nan if isinstance(x, bool) or not isinstance(x, (int, float)) else float(x)

    def field(d, key):
        return num(d.get(key)) if isinstance(d, dict) else math.nan

    def pct(v):
        return "n/a" if v != v else f"{v:.2%}"

    def whole(v):
        return int(v) if math.isfinite(v) else "?"

    def part(key):
        return m.get(key) if isinstance(m, dict) else None

    test, ood, hold, ind = part("test"), part("ood"), part("holdout"), part("ind")
    out = []

    def add(name, ok, detail):
        out.append((name, bool(ok), detail))

    t_fp = field(test, "fp")
    add(f"test clean FP <= {gates['test_fp']:.0%}", t_fp <= gates["test_fp"], pct(t_fp))
    shape_fp = test.get("shape_fp") if isinstance(test, dict) else None
    per_shape = {str(k): num(v) for k, v in shape_fp.items()} if isinstance(shape_fp, dict) else {}
    worst = math.nan
    if per_shape and all(v == v for v in per_shape.values()):
        worst_name = max(per_shape, key=per_shape.get)
        worst = per_shape[worst_name]
    add(f"worst shape clean FP <= {gates['shape_fp']:.0%}", worst <= gates["shape_fp"],
        f"{pct(worst)} ({worst_name})" if worst == worst else "n/a")
    t_rec = field(test, "recall")
    add(f"test recall >= {gates['recall']:.0%}", t_rec >= gates["recall"], pct(t_rec))
    o_fp, o_rec = field(ood, "fp"), field(ood, "recall")
    add(f"OOD clean FP <= {gates['ood_fp']:.0%}", o_fp <= gates["ood_fp"], pct(o_fp))
    add(f"OOD recall >= {gates['ood_recall']:.0%}", o_rec >= gates["ood_recall"], pct(o_rec))

    n_b, n_a = field(ind, "n_benign"), field(ind, "n_attack")
    b_fp, a_ok = field(ind, "benign_fp"), field(ind, "attacks_caught")
    b_lim = math.floor(n_b * gates["ind_benign_fp_frac"] + 1e-9) if math.isfinite(n_b) else math.nan
    a_lim = n_a - gates["ind_attacks_missed_max"]
    add(f"independent benign FP <= {gates['ind_benign_fp_frac']:.0%} of {whole(n_b)} probes ({whole(b_lim)})",
        b_fp <= b_lim, f"{whole(b_fp)} flagged")
    add(f"independent attacks caught >= {whole(a_lim)} of {whole(n_a)}", a_ok >= a_lim, f"{whole(a_ok)} caught")

    h_rec, h_fp = field(hold, "recall"), field(hold, "fp")
    h_na, h_nc = field(hold, "n_attack"), field(hold, "n_clean")
    add(f"holdout-source recall >= {gates['holdout_recall']:.0%}",
        h_rec >= gates["holdout_recall"] and h_na > 0, f"{pct(h_rec)} of {whole(h_na)} attack rows")
    add(f"holdout benign FP <= {gates['holdout_benign_fp']:.0%}",
        h_fp <= gates["holdout_benign_fp"] and h_nc > 0, f"{pct(h_fp)} of {whole(h_nc)} clean rows")
    return out


# --- production-path replay ---------------------------------------------------------------------------------
def replay_cases() -> list[dict]:
    """The 25 hand-written probes plus the realistic benign bodies, as {name, kind, label, text}."""
    cases = [{"name": n, "kind": "benign" if lab == "clean" else "attack", "label": lab, "text": t}
             for n, lab, t in probes.PROBES]
    cases += [{"name": f"body: {n}", "kind": "benign", "label": "clean", "text": t}
              for n, t in probes.REALISTIC_BENIGN]
    return cases


def _rate(items, key=lambda p: p["blocked"]):
    return sum(1 for p in items if key(p)) / len(items) if items else math.nan


def replay_checks(doc, gates):
    """Gate the output of the replay worker. Pure; tolerates any garbage (-> FAIL)."""
    d = doc if isinstance(doc, dict) else {}
    loaded = bool(d.get("waf_loaded"))
    valid = [p for p in (d.get("probes") or []) if isinstance(p, dict)
             and p.get("kind") in ("benign", "attack") and isinstance(p.get("blocked"), bool)]
    benign = [p for p in valid if p["kind"] == "benign"]
    attack = [p for p in valid if p["kind"] == "attack"]

    def reach(items):
        return f"{sum(1 for p in items if p.get('reached_waf'))}/{len(items)} reached the WAF model"

    b_rate, a_rate = _rate(benign), _rate(attack)
    info = d.get("error") or f"threshold {d.get('waf_threshold')}, backend {d.get('waf_backend')}"
    return [
        ("production replay: WAF loaded from the artifact inside text_service", loaded, str(info)),
        (f"production replay: benign block rate <= {gates['replay_benign_block']:.0%}",
         b_rate <= gates["replay_benign_block"],
         f"{sum(p['blocked'] for p in benign)}/{len(benign)} blocked; {reach(benign)}"),
        (f"production replay: attack block rate >= {gates['replay_attack_block']:.0%}",
         a_rate >= gates["replay_attack_block"],
         f"{sum(p['blocked'] for p in attack)}/{len(attack)} blocked; {reach(attack)}"),
    ]


def replay_misses(doc) -> list[str]:
    """Human-readable lines: benign probes blocked and attack probes let through."""
    out = []
    for p in (doc or {}).get("probes") or []:
        if not isinstance(p, dict):
            continue
        if p.get("kind") == "benign" and p.get("blocked"):
            out.append(f"benign BLOCKED: {p.get('name')} (route={p.get('route')}, by={','.join(p.get('blockers') or [])})")
        if p.get("kind") == "attack" and not p.get("blocked"):
            out.append(f"attack PASSED:  {p.get('name')} (route={p.get('route')}, reached_waf={p.get('reached_waf')})")
    return out


def run_replay(artifact: str, arm: str, threshold: float, timeout: int = 3600) -> dict:
    """Run the worker in a fresh interpreter (WAF_MODEL_PATH / WAF_ATTACK_THRESHOLD are read at import)."""
    env = dict(os.environ)
    env["WAF_MODEL_PATH"] = artifact
    env.pop("WAF_THRESHOLD", None)           # arm B: the artifact's own threshold decides; arm A: unused here
    if arm == ARM_A:
        env["WAF_ATTACK_THRESHOLD"] = repr(float(threshold))   # what text_service passes to the classifier
    else:
        env.pop("WAF_ATTACK_THRESHOLD", None)                  # ignored by arm B anyway
    fd, out_path = tempfile.mkstemp(prefix="waf_replay_", suffix=".json")
    os.close(fd)
    cmd = [sys.executable, "-m", "dataset_tools.waf.v2.gate", "--replay-worker", "--artifact", artifact,
           "--arm", arm, "--replay-out", out_path]
    failed = {"waf_loaded": False, "probes": []}
    try:
        try:
            cp = subprocess.run(cmd, cwd=paths.REPO, env=env, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return {**failed, "error": f"replay worker timed out after {timeout}s"}
        try:
            with open(out_path, encoding="utf-8") as f:
                doc = json.load(f)
        except (OSError, ValueError):
            doc = None
        if cp.returncode != 0 or not isinstance(doc, dict):
            tail = (cp.stderr or cp.stdout or "")[-800:]
            return {**failed, "error": f"replay worker exit {cp.returncode}: {tail}"}
        return doc
    finally:
        try:
            os.remove(out_path)
        except OSError:
            pass


def _replay_worker(artifact: str, out_path: str) -> int:
    """Runs inside the subprocess: the real text_service, the real WAFClassifier, every probe."""
    import asyncio
    from text_service import main as svc
    asyncio.run(svc.load_models())
    waf = svc.waf_classifier
    loaded = bool(waf is not None and getattr(waf, "_loaded", False)
                  and os.path.realpath(waf.model_path) == os.path.realpath(artifact))
    doc: dict = {"waf_loaded": loaded, "waf_model_path": getattr(waf, "model_path", None),
                 "waf_backend": getattr(waf, "_backend", None), "waf_threshold": getattr(waf, "threshold", None),
                 "probes": []}
    if loaded:
        for case in replay_cases():
            res = svc._analyze_sync(case["text"], False, "outbound")
            status = res.get("status")
            det = res.get("detailed_findings") or {}
            reason = str(res.get("reason") or "")
            blockers = [b.strip() for b in reason.split(":", 1)[1].split(",")] if reason.startswith("Blocked by:") else []
            doc["probes"].append({
                "name": case["name"], "kind": case["kind"], "label": case["label"],
                "blocked": str(getattr(status, "value", status)).lower() == "block",
                "route": det.get("route"), "blockers": blockers,
                "reached_waf": "web_attack" in (det.get("scores") or {}),
            })
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(doc, f)
    return 0


# --- CLI ---------------------------------------------------------------------------------------------------------
def _norm_arm(s):
    return _ARM_ALIASES.get(str(s).strip().upper()) if s else None


def _read_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


class _Report:
    def __init__(self):
        self.fails = 0

    def emit(self, name, ok, detail=""):
        self.fails += 0 if ok else 1
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"   [{detail}]" if detail else ""))

    def emit_all(self, checks):
        for name, ok, detail in checks:
            self.emit(name, ok, detail)


def _close(a, b):
    try:
        return math.isclose(float(a), float(b), rel_tol=1e-9, abs_tol=1e-12)
    except (TypeError, ValueError):
        return False


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--results", help="waf_v2_results.json from the Colab notebook")
    ap.add_argument("--artifact", required=True, help="unzipped model directory (contains waf_v2.json)")
    ap.add_argument("--arm", help="A / B / A_softmax7 / B_sigmoid6 (default: the artifact's waf_v2.json)")
    ap.add_argument("--skip-replay", action="store_true", help="skip the production-path replay (unit tests only)")
    ap.add_argument("--replay-only", action="store_true", help="run only the replay (measure any artifact)")
    ap.add_argument("--threshold", type=float, help="arm A replay threshold (replay-only; default 0.8 = text_service)")
    ap.add_argument("--replay-worker", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--replay-out", help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    if a.replay_worker:
        return _replay_worker(a.artifact, a.replay_out)
    rep = _Report()
    artifact = os.path.abspath(os.path.expanduser(a.artifact))
    cfg = None
    have_dir = os.path.isdir(artifact)
    if not a.replay_only:
        rep.emit("artifact directory exists", have_dir, artifact)
    if have_dir:
        try:
            path = os.path.join(artifact, "waf_v2.json")
            cfg = _read_json(path) if os.path.isfile(path) else None
        except (OSError, ValueError) as exc:
            cfg = None
            rep.emit("artifact waf_v2.json readable", False, str(exc))
    arm = _norm_arm(a.arm)
    if a.arm and not arm:
        rep.emit("--arm is one of A / B / A_softmax7 / B_sigmoid6", False, a.arm)
        return _finish(rep, False)
    cfg_arm = cfg.get("arm") if isinstance(cfg, dict) else None
    if arm and cfg_arm and cfg_arm != arm:
        rep.emit("--arm matches the artifact's waf_v2.json arm", False, f"{arm} vs {cfg_arm}")
        return _finish(rep, False)
    arm = arm or cfg_arm or (ARM_A if a.replay_only else None)
    if arm not in (ARM_A, ARM_B):
        rep.emit("arm can be determined (--arm or artifact waf_v2.json)", False, str(arm))
        return _finish(rep, False)
    print(f"== WAF v2 ship gate: arm {arm}, artifact {artifact}")

    threshold = a.threshold if a.threshold is not None else 0.8
    if not a.replay_only:
        threshold = _results_gates(rep, a.results, arm, cfg)
    if a.skip_replay:
        print("SKIP  production replay (--skip-replay): this is NOT a complete ship decision")
        return _finish(rep, True)
    if not have_dir:
        rep.emit("production replay", False, "artifact directory missing")
        return _finish(rep, False)
    doc = run_replay(artifact, arm, threshold)
    rep.emit_all(replay_checks(doc, GATES))
    for line in replay_misses(doc):
        print("      " + line)
    return _finish(rep, False)


def _finish(rep, skipped) -> int:
    word = "FAIL" if rep.fails else ("PASS (INCOMPLETE: replay skipped)" if skipped else "PASS")
    print(f"RESULT: {word}" + (f" - {rep.fails} gate(s) failed" if rep.fails else ""))
    return 1 if rep.fails else 0


def _results_gates(rep, results_path, arm, cfg) -> float:
    """Emit the notebook gates + artifact/results consistency for ``arm``; return the replay threshold."""
    res = None
    try:
        res = _read_json(results_path) if results_path else None
        rep.emit("results file readable", isinstance(res, dict), str(results_path))
    except (OSError, ValueError) as exc:
        rep.emit("results file readable", False, f"{results_path}: {exc}")
    res = res if isinstance(res, dict) else {}
    thr = (res.get("THR") or {}).get(arm) if isinstance(res.get("THR"), dict) else None
    c_thr = cfg.get("recommended_threshold") if isinstance(cfg, dict) else None
    rep.emit("artifact waf_v2.json present with the same arm", isinstance(cfg, dict) and cfg.get("arm") == arm,
             "missing" if cfg is None else str(cfg.get("arm") if isinstance(cfg, dict) else cfg))
    rep.emit("artifact recommended_threshold == results threshold", _close(c_thr, thr), f"artifact {c_thr}, results {thr}")
    R = res.get("R") if isinstance(res.get("R"), dict) else {}
    arm_r = R.get(arm) if isinstance(R.get(arm), dict) else {}
    ind = (res.get("IND") or {}).get(arm) if isinstance(res.get("IND"), dict) else None
    rep.emit_all(gate_checks({**arm_r, "ind": ind}, GATES))
    try:
        return float(thr)
    except (TypeError, ValueError):
        return float(c_thr) if isinstance(c_thr, (int, float)) else 0.8


if __name__ == "__main__":
    sys.exit(main())
