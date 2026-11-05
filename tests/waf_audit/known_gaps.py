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
    dict(id="S1", pattern=r"test_audit_robustness\.py::test_payload_cannot_be_hidden_by_position_or_padding\[(sqli|xss)-json, payload after 2\.2 KB of hex padding|test_audit_robustness\.py::test_payload_cannot_be_hidden_by_position_or_padding\[(sqli|xss)-form, payload after 2\.2 KB of hex padding|test_audit_service\.py::test_payload_after_long_benign_text_in_one_json_value",
         module="text_service hook", stage="input selection (_waf_inputs) + route gating", severity="high",
         why="a body routed web_request is judged on the first 2000 characters of each value (the model reads 256 tokens). The marker gate "
             "finds the payload (gate_parts=1) but is skipped when route == web_request, so 2.2 KB of hex/ID padding in front of the payload is ALLOWED. "
             "Prose padding only 'works' for the defence because it flips the route to prose, where the gate runs.",
         fix="Run waf_gate_parts() for every outbound route (cheap regex), or score long values in overlapping 1500-char windows."),
    dict(id="S2", pattern=r"test_audit_robustness\.py::test_payload_cannot_be_hidden_by_position_or_padding\[(sqli|xss)-json, payload as (the 200th of 400 values|value 71 of 71)|test_audit_service\.py::test_leaf_count_cap",
         module="text_service hook", stage="input selection (_waf_inputs)", severity="high",
         why="JSON bodies are scored leaf by leaf but only the first WAF_MAX_VALUES=64 leaves; a payload as leaf 71 is never offered to the model.",
         fix="Prioritise attack-shaped leaves (worth_scoring) before applying the cap, or raise/window the cap."),
    dict(id="S3", pattern=r"test_audit_service\.py::test_payload_in_a_json_key",
         module="text_service hook", stage="input selection (_waf_inputs)", severity="medium",
         why="only JSON values are walked; object keys are never offered to the model.",
         fix="include keys in the walk."),
    dict(id="S4", pattern=r"test_audit_robustness\.py::test_pipeline_does_not_raise_on_non_string_input",
         module="text_service endpoint", stage="request parsing", severity="low",
         why="analyze_text does len(text) on whatever 'text' the JSON holds; None/number/list/dict raise inside the handler (HTTP 500, the gateway then fails open). "
             "Only the gateway/orchestrator call it and they send strings, so this is an internal-contract gap.",
         fix="coerce or reject non-string 'text' with a 400 before analysis."),

    # ---------------------------------------------------------------- target pre-filter (ml/waf/target.py)
    dict(id="T1", pattern=r"test_audit_target\.py::test_classic_sqli_without_quotes_is_worth_scoring",
         module="ml/waf/target.py", stage="pre-filter (worth_scoring)", severity="high",
         why="the 'precision first' filter only forwards values with a quote, <>;|&$(){}\\, '..' or a few SQL phrases. Numeric injection (1 OR 1=1, "
             "1 ORDER BY 5, 1 HAVING 1=1) and comment-split keywords (UNION/**/SELECT) contain none of those, so the model never sees them.",
         fix="add tautology/ORDER BY/HAVING patterns and '/**/' to the active set."),
    dict(id="T2", pattern=r"test_audit_target\.py::test_(padding_with_64|payload_after_long_benign_padding_inside_one_value)",
         module="ml/waf/target.py", stage="value caps (MAX_VALUES=64, MAX_VALUE_CHARS=2000)", severity="high",
         why="64 harmless-but-active values (O'Brien-style) fill the budget so the 65th, real payload is dropped; and a payload after 2000 characters in one value is cut off.",
         fix="rank values by attack-likeness before capping; window long values."),
    dict(id="T3", pattern=r"test_audit_target\.py::test_(parameter_names_are_inspected_too|payload_hidden_in_the_url_path_is_inspected)",
         module="ml/waf/target.py", stage="what is inspected", severity="medium",
         why="only query VALUES are examined; parameter names and URL path segments carrying an injection (/user/1' OR '1'='1/profile, ?<script>=1) are ignored (path gets traversal signatures only).",
         fix="scan names and path segments with the same active-character filter."),
    dict(id="T4", pattern=r"test_audit_target\.py::test_command_substitution_inside_a_url_valued_parameter",
         module="ml/waf/target.py", stage="pre-filter (_PLAIN_URL)", severity="medium",
         why="_PLAIN_URL allows '$', '(' and ')' so http://a.example/$(id) is treated as an ordinary URL and skipped.",
         fix="exclude $( , ` and ( ) from the plain-URL character class."),
    dict(id="T5", pattern=r"test_audit_target\.py::test_(form_with_leading|form_key_longer)",
         module="ml/waf/target.py", stage="form detection (_FORM_START)", severity="low",
         why="a body that starts with '&' or a newline, or whose first key is over 64 characters, is not recognised as a form so its values are not split and decoded.",
         fix="strip leading separators; allow longer keys."),
    dict(id="T6", pattern=r"test_audit_target\.py::test_traversal_variants_and_adjacent_sensitive_files_are_caught\[(?!/f\?p=\.\.%252f)",
         module="ml/waf/target.py", stage="signature_hits", severity="medium",
         why="the sensitive-file list is short (etc/passwd|shadow|group|hosts, win.ini, boot.ini, proc/self/environ). Nested '....//', overlong UTF-8 dots, "
             ".ssh/id_rsa, auth.log, sudoers, SAM, web.xml, .git/config and .env are not caught.",
         fix="extend _SENSITIVE and _TRAVERSAL from the SecLists LFI lists."),
    dict(id="T7", pattern=r"test_audit_target\.py::test_documentation_page_about_the_hosts_file",
         module="ml/waf/target.py", stage="signature_hits", severity="low",
         why="'/docs/etc/hosts-file-explained' matches the etc/hosts signature (a path segment named etc followed by hosts) - a false positive on a documentation URL.",
         fix="require the match to be the whole segment or follow a traversal."),
    dict(id="T8", pattern=r"test_audit_target\.py::test_decode_reaches_a_fixpoint",
         module="ml/waf/target.py", stage="_decode", severity="low",
         why="decodes at most twice; triple-encoded %25252e%25252e%25252f stays encoded.",
         fix="decode until stable (bounded at 4)."),

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
    dict(id="R1", pattern=r"test_audit_robustness\.py::test_worth_scoring_is_linear_even_without_the_callers_size_caps\[select x20000\]",
         module="ml/waf/target.py", stage="_ACTIVE regex (select\\s.+\\sfrom)", severity="low",
         why="quadratic backtracking: 140 KB of 'select ' takes 21 s. In production the caps (16 KB target = 0.27 s, 2 KB value = 0.004 s) contain it, "
             "so it is latent, but the function does not protect itself.",
         fix="bound the .+ (e.g. {1,200}) or truncate inside worth_scoring."),
]
