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
         why="the scanner class is barely learned (canonical 25%, real held-out 5-17%; sqlmap's User-Agent is called sqli). "
             "It also cannot matter in production: the WAF never sees request headers, only bodies and targets.",
         fix="Either inspect the User-Agent header at the gateway, or drop the class; v2 builder now has 85 real held-out scanner strings to measure it."),
    dict(id="M3", pattern=r"test_audit_e2e\.py::test_recall_on_real_held_out_payloads\[(path_traversal|command_injection)-bare\]",
         module="model (v1 DistilBERT)", stage="model decision", severity="medium",
         why="recall on real payloads the model never trained on: path_traversal 64%, command_injection 78% (target 80%). "
             "Misses are mostly bare file paths (/tmp/, .local/bin/) and short fragments the model sees as plain text.",
         fix="v2 retrain; the new held-out set (crs+fuzzdb) measures exactly this."),

    # ---------------------------------------------------------------- service hook (text_service/main.py)
    dict(id="S4", pattern=r"test_audit_robustness\.py::test_pipeline_does_not_raise_on_non_string_input",
         module="text_service endpoint", stage="request parsing", severity="low",
         why="analyze_text does len(text) on whatever 'text' the JSON holds; None/number/list/dict raise inside the handler (HTTP 500, the gateway then fails open). "
             "Only the gateway/orchestrator call it and they send strings, so this is an internal-contract gap.",
         fix="coerce or reject non-string 'text' with a 400 before analysis."),

    # ---------------------------------------------------------------- target pre-filter (ml/waf/target.py)
    # ---------------------------------------------------------------- marker gate (ml/waf/gate.py)
    dict(id="G1", pattern=r"test_audit_gate\.py::test_obfuscated_variants_are_still_routed\[(newline as space|split by inline comments|mysql version comment)",
         module="ml/waf/gate.py", stage="marker regex", severity="medium",
         why="the regex runs line by line, so 'UNION' and 'SELECT' separated by a newline are never seen together; inline-comment splitting (UN/**/ION) and "
             "MySQL version comments (/*!50000UNION*/) are not normalised before matching.",
         fix="collapse whitespace and strip /**/ and /*!NNNNN */ before matching."),
    dict(id="G2", pattern=r"test_audit_gate\.py::test_obfuscated_variants_are_still_routed\[utf8 overlong slash",
         module="ml/waf/gate.py", stage="decode before match", severity="low",
         why="the gate percent-decodes first, which turns %c0%af into U+FFFD, so its own %c0%af marker can no longer match.",
         fix="match markers on both raw and decoded text."),
    dict(id="G3", pattern=r"test_audit_gate\.py::test_canonical_payload_is_routed_to_the_waf\[ssti freemarker",
         module="ml/waf/gate.py", stage="marker regex", severity="low",
         why="the SSTI marker needs words like exec/Runtime/System inside ${...}; FreeMarker's ${ex(\"id\")} after an <#assign> has none.",
         fix="add <#assign ...Execute and ?new() patterns."),
    dict(id="G4", pattern=r"test_audit_gate\.py::test_payload_far_beyond_the_scan_window",
         module="ml/waf/gate.py", stage="MAX_SCAN_CHARS=100000", severity="low",
         why="bytes after the first 100,000 characters are never scanned; an attacker who can send a larger body pads past it.",
         fix="scan the tail as well, or reject oversize bodies."),

    # ---------------------------------------------------------------- robustness
]
