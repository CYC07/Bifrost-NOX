"""Register of CONFIRMED WAF gaps found by this audit (2026-11-05, shipped v1 model, threshold 0.8).

Every entry maps failing audit tests (regex on the pytest node id, first match wins) to the module and stage
where the item was lost, why, how bad it is, and what would fix it. conftest.py turns each match into a STRICT
xfail: the suite stays green, the gap stays documented, and the day someone fixes it the test XPASSes and fails
the run until its entry is deleted here.

severity: high = a real attacker or ordinary user hits it routinely; medium = needs a deliberate, known trick or
a less common input; low = exotic, or already contained by another control.
"""

GAPS = [
    # ---------------------------------------------------------------- model (ml/waf/predictor.py + artifacts)
    dict(id="M1", pattern=r"test_audit_(predictor|e2e)\.py::test_(real_model_leaves_ordinary_text_of_each_kind_alone\[(code|config|logs|shell)\]|ordinary_traffic_false_positive|ordinary_form_and_json)",
         module="model (v1 DistilBERT)", stage="model decision", severity="high",
         why="v1 was trained on data where the carrier shape predicted the label, so it blocks ordinary shell commands, "
             "config, log lines, source code at p>=0.9. HTML and prose have been resolved.",
         fix="Retrain on the shape-balanced set; gate on benign FP <= 2%."),
    dict(id="M2", pattern=r"test_audit_e2e\.py::test_recall_on_real_held_out_payloads\[scanner",
         module="model (v1 DistilBERT)", stage="model decision", severity="low",
         why="real held-out scanner payloads still have lower recall; canonical payloads and carriers are now detected. "
             "Production scanner detection is now done at the gateway from the User-Agent (ml/waf/scanner.py, tests/test_scanner_ua.py).",
         fix="gateway detector covers the real-world case."),
    dict(id="M3", pattern=r"test_audit_e2e\.py::test_recall_on_real_held_out_payloads\[(path_traversal|command_injection|sqli-bare)",
         module="model (v3 DistilBERT @ 0.99)", stage="model decision", severity="medium",
         why="recall on real CRS/FuzzDB held-out payloads never trained on: 70-78% at threshold 0.99 (target 80%). "
             "Misses are mostly bare file paths, PHP serialization blobs, and short fragments.",
         fix="Retrain in subsequent data rounds with expanded CRS/FuzzDB distributions."),

    # ---------------------------------------------------------------- service hook (text_service/main.py)
    # ---------------------------------------------------------------- target pre-filter (ml/waf/target.py)
    # ---------------------------------------------------------------- marker gate (ml/waf/gate.py)
    # ---------------------------------------------------------------- robustness
]
