"""Ship gate for the WAF v2 bake-off: `python -m dataset_tools.waf.v2.gate --results ... --artifact DIR`.

The gate recomputes every verdict from the raw metrics in waf_v2_results.json (the notebook's own
PASS flags are ignored), treats a missing / NaN metric as a FAIL, cross-checks that the artifact and
the results file belong together, and replays the probes through the production code path
(text_service._analyze_sync) in a subprocess. These tests use stub results and a stub subprocess:
the real replay needs the full model stack and is run by hand.
"""
import copy
import json
import math
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from dataset_tools.waf.v2 import gate, probes  # noqa: E402

ARM_A, ARM_B = "A_softmax7", "B_sigmoid6"


def split(fp=0.004, recall=0.95, shape_fp=None, n_clean=1000, n_attack=1000):
    return {"fp": fp, "recall": recall, "exact": recall - 0.02, "n_clean": n_clean, "n_attack": n_attack,
            "shape_fp": shape_fp or {"json": 0.01, "form": 0.0, "bare": 0.02},
            "per_class_recall": {"sqli": 0.97, "xss": 0.93}}


def good_arm():
    return {"test": split(), "ood": split(fp=0.01, recall=0.9), "holdout": split(fp=0.0, recall=0.9, n_clean=135, n_attack=1400)}


def good_results(arm=ARM_B, thr=0.42):
    return {"R": {arm: good_arm()},
            "IND": {arm: {"benign_fp": 1, "attacks_caught": 9, "n_benign": 15, "n_attack": 9}},
            "THR": {arm: thr}, "PASS": {arm: True}}


def metrics_of(results, arm=ARM_B):
    return {**results["R"][arm], "ind": results["IND"][arm]}


def names(checks):
    return [n for n, _ok, _d in checks]


def verdict(checks):
    return {n: ok for n, ok, _d in checks}


# --- the pure gate -----------------------------------------------------------------------------------
def test_gates_are_defined_in_one_place_and_cover_every_requirement():
    g = gate.GATES
    assert g["test_fp"] == 0.01 and g["shape_fp"] == 0.03 and g["recall"] == 0.90
    assert g["ood_fp"] == 0.02 and g["ood_recall"] == 0.80
    assert g["ind_benign_fp_frac"] == 0.20 and g["ind_attacks_missed_max"] == 1
    assert g["holdout_recall"] == 0.80 and g["holdout_benign_fp"] == 0.02
    assert g["replay_benign_block"] == 0.10 and g["replay_attack_block"] == 0.90


def test_a_good_result_passes_every_check():
    checks = gate.gate_checks(metrics_of(good_results()), gate.GATES)
    assert len(checks) == 9 and all(ok for _n, ok, _d in checks), [c for c in checks if not c[1]]
    assert len(set(names(checks))) == 9


@pytest.mark.parametrize("mutate,failing", [
    (lambda m: m["test"].update(fp=0.0101), "test clean FP"),
    (lambda m: m["test"].update(shape_fp={"json": 0.031, "form": 0.0}), "worst shape"),
    (lambda m: m["test"].update(recall=0.8999), "test recall"),
    (lambda m: m["ood"].update(fp=0.0201), "OOD clean FP"),
    (lambda m: m["ood"].update(recall=0.7999), "OOD recall"),
    (lambda m: m["ind"].update(benign_fp=4), "independent benign FP"),
    (lambda m: m["ind"].update(attacks_caught=7), "independent attacks caught"),
    (lambda m: m["holdout"].update(recall=0.7999), "holdout-source recall"),
    (lambda m: m["holdout"].update(fp=0.0201), "holdout benign FP"),
])
def test_each_gate_fails_just_past_its_limit(mutate, failing):
    m = copy.deepcopy(metrics_of(good_results()))
    mutate(m)
    v = verdict(gate.gate_checks(m, gate.GATES))
    assert [n for n, ok in v.items() if not ok and failing in n], v
    assert sum(not ok for ok in v.values()) == 1, "only the mutated gate may fail"


@pytest.mark.parametrize("mutate", [
    lambda m: m["test"].update(fp=0.01),
    lambda m: m["test"].update(shape_fp={"json": 0.03}),
    lambda m: m["test"].update(recall=0.90),
    lambda m: m["ood"].update(fp=0.02),
    lambda m: m["ood"].update(recall=0.80),
    lambda m: m["ind"].update(benign_fp=3),
    lambda m: m["ind"].update(attacks_caught=8),
    lambda m: m["holdout"].update(recall=0.80),
    lambda m: m["holdout"].update(fp=0.02),
])
def test_each_limit_itself_passes(mutate):
    m = copy.deepcopy(metrics_of(good_results()))
    mutate(m)
    assert all(ok for _n, ok, _d in gate.gate_checks(m, gate.GATES))


def test_independent_probe_limits_scale_with_the_number_of_probes():
    m = copy.deepcopy(metrics_of(good_results()))
    m["ind"].update(n_benign=25, n_attack=10, benign_fp=5, attacks_caught=9)
    assert all(ok for _n, ok, _d in gate.gate_checks(m, gate.GATES))
    m["ind"].update(benign_fp=6)
    assert not verdict(gate.gate_checks(m, gate.GATES))["independent benign FP <= 20% of 25 probes (5)"]


@pytest.mark.parametrize("break_it", [
    lambda m: m.pop("holdout"),
    lambda m: m["holdout"].pop("recall"),
    lambda m: m["holdout"].update(recall=float("nan")),
    lambda m: m["test"].update(fp=None),
    lambda m: m["test"].update(fp="0.001"),
    lambda m: m["test"].update(fp=True),
    lambda m: m["ood"].update(recall=float("nan")),
    lambda m: m["test"].update(shape_fp={}),
    lambda m: m["test"].update(shape_fp={"json": float("nan")}),
    lambda m: m["holdout"].update(n_attack=0),
    lambda m: m["holdout"].update(n_clean=0),
    lambda m: m["holdout"].pop("n_clean"),
    lambda m: m.pop("ind"),
    lambda m: m["ind"].pop("n_benign"),
    lambda m: m["ind"].update(attacks_caught=float("nan")),
])
def test_missing_or_nan_metrics_fail_instead_of_crashing(break_it):
    m = copy.deepcopy(metrics_of(good_results()))
    break_it(m)
    checks = gate.gate_checks(m, gate.GATES)
    assert len(checks) == 9
    assert any(not ok for _n, ok, _d in checks)


def test_check_is_self_contained_so_the_notebook_can_embed_its_source():
    """The Colab notebook embeds inspect.getsource(gate_checks); it may use nothing but math."""
    import inspect
    ns = {"math": math}
    exec(inspect.getsource(gate.gate_checks), ns)      # noqa: S102 - our own source
    m = metrics_of(good_results())
    assert ns["gate_checks"](m, gate.GATES) == gate.gate_checks(m, gate.GATES)


# --- replay checks (pure) ---------------------------------------------------------------------------------
def replay_doc(n_benign=59, n_attack=10, benign_blocked=0, attacks_blocked=10, loaded=True):
    pr = []
    for i in range(n_benign):
        pr.append({"name": f"b{i}", "kind": "benign", "route": "web_request", "blocked": i < benign_blocked,
                   "blockers": ["web_attack"] if i < benign_blocked else [], "reached_waf": True})
    for i in range(n_attack):
        pr.append({"name": f"a{i}", "kind": "attack", "route": "web_request", "blocked": i < attacks_blocked,
                   "blockers": ["web_attack"] if i < attacks_blocked else [], "reached_waf": True})
    return {"waf_loaded": loaded, "waf_model_path": "/x", "probes": pr}


def test_replay_passes_within_limits_and_reports_reach():
    checks = gate.replay_checks(replay_doc(benign_blocked=5, attacks_blocked=9), gate.GATES)
    assert all(ok for _n, ok, _d in checks) and len(checks) == 3
    assert "reached" in " ".join(d for _n, _ok, d in checks)


@pytest.mark.parametrize("doc,failing", [
    (dict(benign_blocked=6), "benign"),          # 6/59 = 10.2 %
    (dict(attacks_blocked=8), "attack"),         # 8/10 = 80 %
    (dict(loaded=False), "loaded"),
])
def test_replay_fails_outside_limits(doc, failing):
    v = verdict(gate.replay_checks(replay_doc(**doc), gate.GATES))
    assert [n for n, ok in v.items() if not ok and failing in n.lower()], v


def test_replay_with_no_probes_or_garbage_fails():
    for bad in ({}, {"waf_loaded": True, "probes": []}, None, {"waf_loaded": True, "probes": [{"kind": "benign"}]}):
        checks = gate.replay_checks(bad, gate.GATES)
        assert checks and any(not ok for _n, ok, _d in checks)


def test_replay_probe_set_is_the_25_probes_plus_the_realistic_bodies():
    cases = gate.replay_cases()
    assert len(cases) == len(probes.PROBES) + len(probes.REALISTIC_BENIGN)
    assert sum(c["kind"] == "attack" for c in cases) == 10
    assert sum(c["kind"] == "benign" for c in cases) == 15 + len(probes.REALISTIC_BENIGN)
    assert len({c["name"] for c in cases}) == len(cases)


# --- replay subprocess plumbing (stubbed) --------------------------------------------------------------------
class FakeRun:
    def __init__(self, doc=None, returncode=0, stderr=""):
        self.doc, self.returncode, self.stderr, self.calls = doc, returncode, stderr, []

    def __call__(self, cmd, **kw):
        self.calls.append((cmd, kw))
        out = cmd[cmd.index("--replay-out") + 1]
        if self.doc is not None:
            open(out, "w").write(json.dumps(self.doc))
        return subprocess.CompletedProcess(cmd, self.returncode, stdout="log noise", stderr=self.stderr)


def test_replay_runs_in_a_subprocess_with_arm_a_threshold_in_the_env(monkeypatch, tmp_path):
    monkeypatch.setenv("WAF_THRESHOLD", "0.123")
    fake = FakeRun(replay_doc())
    monkeypatch.setattr(subprocess, "run", fake)
    doc = gate.run_replay(str(tmp_path), ARM_A, 0.37)
    assert doc["waf_loaded"]
    (cmd, kw), = fake.calls
    assert cmd[0] == sys.executable and "dataset_tools.waf.v2.gate" in cmd and "--replay-worker" in cmd
    env = kw["env"]
    assert env["WAF_MODEL_PATH"] == str(tmp_path) and float(env["WAF_ATTACK_THRESHOLD"]) == 0.37
    assert kw["cwd"] and os.path.isdir(kw["cwd"]) and kw.get("timeout")


def test_arm_b_replay_leaves_the_threshold_to_the_artifact(monkeypatch, tmp_path):
    monkeypatch.setenv("WAF_THRESHOLD", "0.123")
    fake = FakeRun(replay_doc())
    monkeypatch.setattr(subprocess, "run", fake)
    gate.run_replay(str(tmp_path), ARM_B, 0.37)
    env = fake.calls[0][1]["env"]
    assert "WAF_THRESHOLD" not in env, "arm B must use the json's recommended_threshold, not a stray env value"
    assert env["WAF_MODEL_PATH"] == str(tmp_path)


def test_failed_worker_becomes_a_failed_gate_not_an_exception(monkeypatch, tmp_path):
    monkeypatch.setattr(subprocess, "run", FakeRun(None, returncode=1, stderr="Traceback ... boom"))
    doc = gate.run_replay(str(tmp_path), ARM_A, 0.5)
    checks = gate.replay_checks(doc, gate.GATES)
    assert any(not ok for _n, ok, _d in checks) and "boom" in json.dumps(doc)


def test_worker_timeout_becomes_a_failed_gate(monkeypatch, tmp_path):
    def boom(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, 1)
    monkeypatch.setattr(subprocess, "run", boom)
    doc = gate.run_replay(str(tmp_path), ARM_A, 0.5)
    assert any(not ok for _n, ok, _d in gate.replay_checks(doc, gate.GATES))


# --- CLI ---------------------------------------------------------------------------------------------------------
def write_artifact(tmp_path, arm=ARM_B, thr=0.42, name="art"):
    d = tmp_path / name
    d.mkdir()
    (d / "waf_v2.json").write_text(json.dumps({"arm": arm, "recommended_threshold": thr, "labels": [], "attack_labels": [],
                                                "max_len": 256}))
    return str(d)


def write_results(tmp_path, results, name="res.json"):
    p = tmp_path / name
    p.write_text(json.dumps(results))
    return str(p)


def run_cli(*argv):
    return gate.main(list(argv))


def test_cli_passes_on_good_results_and_prints_per_gate_lines(tmp_path, capsys):
    rc = run_cli("--results", write_results(tmp_path, good_results()), "--artifact", write_artifact(tmp_path),
                 "--skip-replay")
    out = capsys.readouterr().out
    assert rc == 0
    assert out.count("PASS") >= 9 and "FAIL" not in out and "SKIP" in out and "replay" in out.lower()


def test_cli_exits_non_zero_on_any_fail(tmp_path, capsys):
    res = good_results()
    res["R"][ARM_B]["holdout"]["recall"] = 0.5
    rc = run_cli("--results", write_results(tmp_path, res), "--artifact", write_artifact(tmp_path), "--skip-replay")
    out = capsys.readouterr().out
    assert rc != 0 and "FAIL" in out and "holdout-source recall" in out


def test_cli_ignores_the_notebooks_own_pass_flags(tmp_path):
    res = good_results()
    res["R"][ARM_B]["test"]["fp"] = 0.2
    res["PASS"][ARM_B] = True
    assert run_cli("--results", write_results(tmp_path, res), "--artifact", write_artifact(tmp_path), "--skip-replay") != 0


def test_cli_missing_holdout_section_is_a_fail_not_a_crash(tmp_path):
    res = good_results()
    del res["R"][ARM_B]["holdout"]
    assert run_cli("--results", write_results(tmp_path, res), "--artifact", write_artifact(tmp_path), "--skip-replay") != 0


def test_cli_rejects_an_artifact_that_does_not_match_the_results(tmp_path, capsys):
    res = good_results(thr=0.42)
    p = write_results(tmp_path, res)
    assert run_cli("--results", p, "--artifact", write_artifact(tmp_path, thr=0.43, name="a1"), "--skip-replay") != 0
    assert "threshold" in capsys.readouterr().out.lower()
    res2 = good_results(arm=ARM_B)
    res2["R"][ARM_A] = res2["R"][ARM_B]
    res2["IND"][ARM_A] = res2["IND"][ARM_B]
    res2["THR"][ARM_A] = 0.42
    p2 = write_results(tmp_path, res2, "res2.json")
    assert run_cli("--results", p2, "--artifact", write_artifact(tmp_path, arm=ARM_A, name="a2"), "--arm", "B",
                   "--skip-replay") != 0, "--arm contradicting the artifact's own arm"
    assert run_cli("--results", p2, "--artifact", write_artifact(tmp_path, arm=ARM_A, name="a3"), "--skip-replay") == 0


def test_cli_arm_aliases_resolve(tmp_path):
    p = write_results(tmp_path, good_results(arm=ARM_A))
    art = write_artifact(tmp_path, arm=ARM_A)
    assert run_cli("--results", p, "--artifact", art, "--arm", "A", "--skip-replay") == 0
    assert run_cli("--results", p, "--artifact", art, "--arm", "A_softmax7", "--skip-replay") == 0
    assert run_cli("--results", p, "--artifact", art, "--arm", "nonsense", "--skip-replay") != 0


def test_cli_artifact_without_waf_v2_json_cannot_be_verified(tmp_path):
    """No json = nothing ties the weights to the results file (or says which arm it is): FAIL."""
    art = tmp_path / "plain"
    art.mkdir()
    p = write_results(tmp_path, good_results(arm=ARM_A))
    assert run_cli("--results", p, "--artifact", str(art), "--arm", "A", "--skip-replay") != 0
    assert run_cli("--results", p, "--artifact", str(art), "--skip-replay") != 0


def test_cli_missing_artifact_or_unreadable_results_fail(tmp_path):
    assert run_cli("--results", write_results(tmp_path, good_results()), "--artifact", str(tmp_path / "nope"),
                   "--skip-replay") != 0
    bad = tmp_path / "bad.json"
    bad.write_text("{nope")
    assert run_cli("--results", str(bad), "--artifact", write_artifact(tmp_path), "--skip-replay") != 0
    assert run_cli("--results", str(tmp_path / "absent.json"), "--artifact", write_artifact(tmp_path, name="z"),
                   "--skip-replay") != 0


def test_cli_runs_the_replay_unless_skipped_and_fails_on_it(tmp_path, monkeypatch, capsys):
    p = write_results(tmp_path, good_results())
    art = write_artifact(tmp_path)
    monkeypatch.setattr(subprocess, "run", FakeRun(replay_doc(benign_blocked=20)))
    assert run_cli("--results", p, "--artifact", art) != 0
    assert "benign" in capsys.readouterr().out.lower()
    monkeypatch.setattr(subprocess, "run", FakeRun(replay_doc()))
    assert run_cli("--results", p, "--artifact", art) == 0


def test_replay_only_mode_needs_no_results(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(subprocess, "run", FakeRun(replay_doc(benign_blocked=30)))
    rc = run_cli("--replay-only", "--artifact", str(tmp_path), "--arm", "A", "--threshold", "0.8")
    out = capsys.readouterr().out
    assert rc != 0 and "benign" in out.lower()
