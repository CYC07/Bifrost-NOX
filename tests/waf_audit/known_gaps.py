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
    dict(id="M1", pattern=r"test_audit_(predictor|e2e)\.py::test_(real_model_leaves_ordinary_text_of_each_kind_alone\[(code|config|html|logs|names and prose|shell)\]|ordinary_traffic_false_positive|ordinary_form_and_json)",
         module="model (v1 DistilBERT)", stage="model decision", severity="high",
         why="v1 was trained on data where the carrier shape predicted the label, so it blocks ordinary shell commands, HTML, "
             "config, log lines, source code and even 'Select your plan' at p>=0.9 (the raw model blocks 31 of 61 benign samples).",
         fix="Retrain on the shape-balanced v2 set (build_v2, now with real benign shell/config/HTML/logs); gate on benign FP <= 2%."),
    dict(id="M2", pattern=r"test_audit_(predictor|e2e)\.py::test_(real_model_(blocks_canonical_payloads_of_each_class|names_the_right_class_when_it_blocks)\[scanner\]|recall_by_class_and_carrier\[scanner|recall_on_real_held_out_payloads\[scanner)",
         module="model (v1 DistilBERT)", stage="model decision", severity="low",
         why="the MODEL's scanner class is barely learned (canonical 25%, real held-out 5-17%; sqlmap's User-Agent is called sqli) and it never sees request headers. "
             "Production scanner detection is now done at the gateway from the User-Agent (ml/waf/scanner.py, tests/test_scanner_ua.py); these tests measure the model only.",
         fix="v2 retrain may improve the model class; the gateway detector already covers the real-world case."),
    dict(id="M3", pattern=r"test_audit_e2e\.py::test_recall_on_real_held_out_payloads\[(path_traversal|command_injection)-bare\]",
         module="model (v1 DistilBERT)", stage="model decision", severity="medium",
         why="recall on real payloads the model never trained on: path_traversal 64%, command_injection 78% (target 80%). "
             "Misses are mostly bare file paths (/tmp/, .local/bin/) and short fragments the model sees as plain text.",
         fix="v2 retrain; the new held-out set (crs+fuzzdb) measures exactly this."),

    # ---------------------------------------------------------------- service hook (text_service/main.py)
    # ---------------------------------------------------------------- target pre-filter (ml/waf/target.py)
    # ---------------------------------------------------------------- marker gate (ml/waf/gate.py)
    # ---------------------------------------------------------------- robustness
]
