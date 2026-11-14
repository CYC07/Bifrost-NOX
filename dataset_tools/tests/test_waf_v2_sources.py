"""WAF v2 extra data sources: OWASP CRS regression tests, Nuclei DAST payloads, loghub logs, real local text.

Why: the first v2 build had no real held-out ssti/scanner payloads (path_traversal: 9 rows) and its benign
shell/HTML/log/config examples were hand-written. These loaders add real ones. All tests use tiny fixture
trees in tmp_path: the real corpora are never read here.
"""
import json
import os
import random
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from dataset_tools.waf.v2 import benign_real, build, payloads  # noqa: E402


# --- OWASP CRS ----------------------------------------------------------------------------------
def _crs_test(tmp_path, category, name, body):
    d = tmp_path / "crs" / "tests" / "regression" / "tests" / category
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(body)


def _stage(uri="/get", data=None, ua="OWASP CRS test agent", expect="[930100]", negative=False):
    key = "no_expect_ids" if negative else "expect_ids"
    data_line = f'          data: "{data}"\n' if data else ""
    return (
        "tests:\n  - test_id: 1\n    desc: x\n    stages:\n      - input:\n          method: GET\n"
        f'          headers:\n            User-Agent: "{ua}"\n          uri: "{uri}"\n{data_line}'
        f"        output:\n          log:\n            {key}: {expect}\n"
    )


def _by_label(rows):
    out = {}
    for r in rows:
        out.setdefault(r["label"], []).append(r["text"])
    return out


def test_crs_positive_query_values_become_labelled_payloads(tmp_path):
    _crs_test(tmp_path, "REQUEST-930-APPLICATION-ATTACK-LFI", "930100.yaml", _stage(uri="/get?foo=.../.../WINDOWS/win.ini"))
    _crs_test(tmp_path, "REQUEST-942-APPLICATION-ATTACK-SQLI", "942100.yaml",
              _stage(uri="/post", data="a=1 UNION SELECT user,pass FROM users--", expect="[942100]"))
    rows = payloads.load_crs(str(tmp_path))
    got = _by_label(rows)
    assert ".../.../WINDOWS/win.ini" in got["path_traversal"]
    assert any("UNION SELECT" in t for t in got["sqli"])
    assert all(r["source"].startswith("crs:") for r in rows)


def test_crs_negative_tests_are_not_attacks(tmp_path):
    _crs_test(tmp_path, "REQUEST-942-APPLICATION-ATTACK-SQLI", "942101.yaml",
              _stage(uri="/get?q=' OR 1=1--", expect="[942100]", negative=True))
    assert payloads.load_crs(str(tmp_path)) == []


def test_crs_fully_encoded_body_loses_its_parameter_name(tmp_path):
    """CRS posts bodies like 'pay%3D%3B+Foo': the '=' is encoded, so the key must be found after decoding."""
    _crs_test(tmp_path, "REQUEST-942-APPLICATION-ATTACK-SQLI", "942210.yaml",
              _stage(uri="/post", data="pay%3D%3B+UpdateUserTypeTracking%26b%3D1%27+OR+%271%27%3D%271", expect="[942210]"))
    texts = [r["text"] for r in payloads.load_crs(str(tmp_path))]
    assert not any(t.startswith(("pay=", "b=")) for t in texts), texts
    assert any("OR '1'='1" in t or "OR+'1'='1" in t for t in texts), texts


def test_crs_category_maps_to_label(tmp_path):
    cases = {"REQUEST-931-APPLICATION-ATTACK-RFI": ("/get?u=http://evil.example/shell.txt?../../x", "path_traversal"),
             "REQUEST-932-APPLICATION-ATTACK-RCE": ("/get?c=;cat /etc/passwd", "command_injection"),
             "REQUEST-941-APPLICATION-ATTACK-XSS": ("/get?x=<script>alert(1)</script>", "xss")}
    for cat, (uri, _label) in cases.items():
        _crs_test(tmp_path, cat, "1.yaml", _stage(uri=uri))
    got = _by_label(payloads.load_crs(str(tmp_path)))
    for _cat, (uri, label) in cases.items():
        assert any(uri.split("=", 1)[1] in t or t in uri for t in got.get(label, [])), label


def test_crs_scanner_user_agent_is_a_scanner_payload_only_in_scanner_tests(tmp_path):
    _crs_test(tmp_path, "REQUEST-913-SCANNER-DETECTION", "913100.yaml", _stage(ua="Nikto/2.1.6", expect="[913100]"))
    _crs_test(tmp_path, "REQUEST-941-APPLICATION-ATTACK-XSS", "941100.yaml",
              _stage(uri="/get?x=<script>alert(1)</script>", ua="Mozilla/5.0 (X11; Linux)", expect="[941100]"))
    got = _by_label(payloads.load_crs(str(tmp_path)))
    assert got["scanner"] == ["Nikto/2.1.6"]
    assert "Mozilla/5.0 (X11; Linux)" not in got.get("scanner", [])


def test_crs_protocol_categories_and_odd_headers_produce_nothing_or_no_crash(tmp_path):
    """920/921 test protocol enforcement, not payload classes: they must not yield rows (a None label would
    poison the build). A non-string User-Agent in a scanner test is skipped, not a crash."""
    _crs_test(tmp_path, "REQUEST-920-PROTOCOL-ENFORCEMENT", "920100.yaml", _stage(uri="/get?x=<script>alert(1)</script>", expect="[920100]"))
    _crs_test(tmp_path, "REQUEST-913-SCANNER-DETECTION", "913101.yaml",
              _stage(expect="[913100]").replace('User-Agent: "OWASP CRS test agent"', "User-Agent: 12345"))
    assert payloads.load_crs(str(tmp_path)) == []


def test_crs_generic_category_only_keeps_template_syntax_as_ssti(tmp_path):
    _crs_test(tmp_path, "REQUEST-934-APPLICATION-ATTACK-GENERIC", "934120.yaml",
              _stage(uri="/get?a={{7*7}}&b=http://169.254.169.254/latest", expect="[934100]"))
    got = _by_label(payloads.load_crs(str(tmp_path)))
    assert "{{7*7}}" in got["ssti"]
    assert not any("169.254" in t for t in sum(got.values(), []))


def test_crs_data_files_feed_scanner_and_traversal_lists(tmp_path):
    rules = tmp_path / "crs" / "rules"
    rules.mkdir(parents=True)
    (rules / "scanners-user-agents.data").write_text("# comment\nsqlmap\nnikto\n")
    (rules / "lfi-os-files.data").write_text("etc/passwd\n../../boot.ini\nx\n")
    (rules / "unix-shell.data").write_text("cat\nid\n")        # bare words: not payloads
    got = _by_label(payloads.load_crs(str(tmp_path)))
    assert set(got["scanner"]) == {"sqlmap", "nikto"}
    assert "../../boot.ini" in got["path_traversal"]
    assert "cat" not in sum(got.values(), [])


def test_crs_loader_tolerates_missing_and_broken_files(tmp_path):
    assert payloads.load_crs(str(tmp_path)) == []
    _crs_test(tmp_path, "REQUEST-942-APPLICATION-ATTACK-SQLI", "bad.yaml", "tests: [unclosed\n  - : :")
    assert payloads.load_crs(str(tmp_path)) == []


# --- Nuclei DAST templates -------------------------------------------------------------------------
def _nuclei(tmp_path, sub, tags, body_payloads):
    d = tmp_path / "nuclei" / "dast" / "vulnerabilities" / sub
    d.mkdir(parents=True, exist_ok=True)
    plist = "\n".join(f"        - {json.dumps(p)}" for p in body_payloads)
    (d / "t.yaml").write_text(
        f"id: t\ninfo:\n  name: t\n  tags: {tags}\nhttp:\n  - payloads:\n      injection:\n{plist}\n"
        "    fuzzing:\n      - part: query\n        fuzz:\n          - \"{{injection}}\"\n")


def test_nuclei_payload_lists_are_labelled_from_tags(tmp_path):
    _nuclei(tmp_path, "cmdi", "cmdi,dast,rce", [";id", "$(sleep 5)"])
    _nuclei(tmp_path, "ssti", "ssti,dast", ["{{7*7}}", "${7*7}"])
    _nuclei(tmp_path, "lfi", "lfi,dast", ["../../../etc/passwd"])
    got = _by_label(payloads.load_nuclei(str(tmp_path)))
    assert {";id", "$(sleep 5)"} <= set(got["command_injection"])
    assert {"{{7*7}}", "${7*7}"} <= set(got["ssti"])
    assert "../../../etc/passwd" in got["path_traversal"]


def test_nuclei_variables_unknown_tags_and_bad_yaml_are_ignored(tmp_path):
    _nuclei(tmp_path, "ssti", "ssti,dast", ["{{BaseURL}}", "{{randstr}}", "{{7*7}}"])
    _nuclei(tmp_path, "redirect", "redirect,dast", ["//evil.example"])      # not a WAF class
    broken = tmp_path / "nuclei" / "dast" / "vulnerabilities" / "xss"
    broken.mkdir(parents=True)
    (broken / "bad.yaml").write_text("info: [unclosed")
    rows = payloads.load_nuclei(str(tmp_path))
    assert [r["text"] for r in rows] == ["{{7*7}}"]
    assert all(r["source"].startswith("nuclei:") for r in rows)
    assert payloads.load_nuclei(str(tmp_path / "missing")) == []


# --- real benign text ----------------------------------------------------------------------------------
def test_loghub_lines_become_clean_log_snippets(tmp_path):
    d = tmp_path / "loghub" / "Apache"
    d.mkdir(parents=True)
    (d / "Apache_2k.log").write_text("\n".join(f"[Sun Dec 04 04:47:{i:02d} 2005] [error] mod_jk child workerEnv in error state {i}" for i in range(40)))
    rows = benign_real.load_loghub(str(tmp_path), random.Random(1), n_per_system=10)
    assert 0 < len(rows) <= 10
    assert all(r["label"] == "clean" and r["source"] == "loghub:Apache" and len(r["text"]) <= 600 for r in rows)
    assert any("\n" in r["text"] for r in rows) or any("mod_jk" in r["text"] for r in rows)


def _write(p, text):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def test_system_text_keeps_real_shell_config_html_and_drops_secrets(tmp_path):
    root = tmp_path / "share"
    _write(root / "a" / "run.sh", "#!/bin/sh\nset -e\nfor f in *.txt; do\n  echo \"$f\" | grep -v '^#' > out.log\ndone\n")
    _write(root / "a" / "app.conf", "[server]\nlisten = 0.0.0.0:8080\nworkers = 4\n")
    _write(root / "a" / "index.html", "<html><body><h1>Docs</h1><p>Select a plan</p></body></html>")
    _write(root / "a" / "data.json", '{"name": "demo", "items": [1, 2, 3]}')
    _write(root / "b" / "leak.conf", "db_password = hunter2secret\nhost = db\n")
    _write(root / "b" / "key.sh", "echo '-----BEGIN RSA PRIVATE KEY-----'\n")
    _write(root / "b" / "internal.md", "# notes about acmecorp internal hosts\n")
    (root / "b" / "blob.sh").write_bytes(b"\x00\x01\x02" * 100)
    rows = benign_real.load_system_text((str(root),), random.Random(2), denylist=("acmecorp",), per_kind=50)
    kinds = {r["source"] for r in rows}
    assert {"sysfile:sh", "sysfile:conf", "sysfile:html", "sysfile:json"} <= kinds
    joined = "\n".join(r["text"] for r in rows)
    assert "hunter2secret" not in joined and "PRIVATE KEY" not in joined and "acmecorp" not in joined
    assert "\x00" not in joined, "binary files must be skipped, not decoded with errors ignored"
    assert all(r["label"] == "clean" and 3 <= len(r["text"]) <= 600 for r in rows)


def test_system_text_drops_base64_blobs_and_long_hex(tmp_path):
    root = tmp_path / "share"
    blob = "".join(random.Random(3).choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") for _ in range(400))
    _write(root / "cert.md", "# key\n" + blob + "\n")
    _write(root / "hex.conf", "blob = " + "ab12cd34" * 40 + "\n")
    _write(root / "ok.conf", "[main]\nname = demo\nmode = fast\n")
    rows = benign_real.load_system_text((str(root),), random.Random(1), per_kind=50)
    assert [r["source"] for r in rows] == ["sysfile:conf"]
    assert "demo" in rows[0]["text"]


def test_system_text_is_deterministic_and_capped_per_kind(tmp_path):
    root = tmp_path / "share"
    for i in range(30):
        _write(root / f"s{i}.sh", f"#!/bin/sh\necho {i}\nls -la /tmp/dir{i}\n")
    a = benign_real.load_system_text((str(root),), random.Random(5), per_kind=7)
    b = benign_real.load_system_text((str(root),), random.Random(5), per_kind=7)
    assert a == b and len([r for r in a if r["source"] == "sysfile:sh"]) <= 7
    assert benign_real.load_system_text((str(tmp_path / "nope"),), random.Random(1)) == []


# --- build integration --------------------------------------------------------------------------------
@pytest.fixture(scope="module")
def built_with_real(tmp_path_factory):
    src = tmp_path_factory.mktemp("src")
    (src / "patt" / "SQL Injection" / "Intruder").mkdir(parents=True)
    (src / "patt" / "SQL Injection" / "Intruder" / "a.txt").write_text("\n".join(f"' OR {i}={i}--" for i in range(400)))
    (src / "fuzzdb" / "attack" / "xss").mkdir(parents=True)
    (src / "fuzzdb" / "attack" / "xss" / "x.txt").write_text("\n".join(f"<img src=x onerror=alert({i})>" for i in range(200)))
    for i in range(30):
        _crs_test(src, "REQUEST-930-APPLICATION-ATTACK-LFI", f"9301{i:02d}.yaml", _stage(uri=f"/get?foo=../../../crsfile{i}/etc/passwd"))
        _crs_test(src, "REQUEST-913-SCANNER-DETECTION", f"9131{i:02d}.yaml", _stage(ua=f"Nikto/2.1.{i}", expect="[913100]"))
        _crs_test(src, "REQUEST-934-APPLICATION-ATTACK-GENERIC", f"9341{i:02d}.yaml", _stage(uri="/get?a={{" + f"{i}*{i}" + "}}", expect="[934100]"))
    ld = src / "loghub" / "Linux"
    ld.mkdir(parents=True)
    (ld / "Linux_2k.log").write_text("\n".join(f"Jun 14 15:16:{i % 60:02d} combo sshd(pam_unix)[19939]: authentication failure; user{i}" for i in range(300)))
    out = tmp_path_factory.mktemp("out")
    rep = build.build(str(src), str(out), seed=3, n_clean=800, include_local_pools=False,
                      holdout_source="fuzzdb,crs", system_text_roots=())
    return str(out), rep


def _rows(d, name):
    with open(os.path.join(d, name)) as f:
        return [json.loads(x) for x in f]


def test_holdout_crs_payloads_never_reach_training_splits(built_with_real):
    d, _ = built_with_real
    for split in ("train", "val", "test", "test_ood"):
        for r in _rows(d, f"{split}.jsonl"):
            assert not r["source"].startswith(("crs:", "fuzzdb:")), (split, r["source"])
            assert "crsfile" not in r["text"]


def test_holdout_file_now_has_real_scanner_ssti_and_traversal_rows(built_with_real):
    d, rep = built_with_real
    held = rep["holdout"]["attack_labels"]
    assert held.get("scanner", 0) > 0 and held.get("ssti", 0) > 0 and held.get("path_traversal", 0) > 0
    assert any(r["source"].startswith("crs:") for r in _rows(d, "test_holdout.jsonl"))


def test_loghub_lines_are_clean_training_rows(built_with_real):
    d, _ = built_with_real
    rows = [r for r in _rows(d, "train.jsonl") if r["source"].startswith("loghub:")]
    assert rows and all(r["label"] == "clean" for r in rows)
