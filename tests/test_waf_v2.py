"""WAF dataset v2: attacks and benign values wrapped in the same shapes, leakage-free splits.

v1 problem (measured): every benign JSON body scored sqli and benign HTML scored xss because the
clean class had no JSON/HTML shapes at all, so *shape* predicted the label. v2 wraps clean and
attack values in identical templates, splits by payload group (no payload in two splits) and holds
some shapes out entirely to measure out-of-distribution recall.
"""
import html
import json
import os
import sys
from urllib.parse import parse_qs, unquote

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ml.waf.v2 import benign, build, payloads, shapes  # noqa: E402
from ml.waf.taxonomy import LABELS  # noqa: E402

import random  # noqa: E402

VALUES = ["' OR '1'='1' --", "<script>alert(1)</script>", "../../etc/passwd", "; cat /etc/passwd",
          "{{7*7}}", "O'Brien & Sons", "5\" screen, 'quoted' text", "100% sure; a=b&c=d"]


# --- shapes ----------------------------------------------------------------------------------
@pytest.mark.parametrize("value", VALUES)
def test_every_shape_carries_the_value_losslessly(value):
    rng = random.Random(1)
    for name, fn in shapes.SHAPES.items():
        wrapped = fn(value, rng)
        assert shapes.recover(name, wrapped, value) == value, name


def test_json_shapes_are_valid_json_with_the_value_as_a_leaf():
    rng = random.Random(2)
    for name in ("json", "json_nested"):
        for v in VALUES:
            doc = json.loads(shapes.SHAPES[name](v, rng))
            leaves = []

            def walk(x):
                if isinstance(x, dict):
                    [walk(i) for i in x.values()]
                elif isinstance(x, list):
                    [walk(i) for i in x]
                else:
                    leaves.append(x)
            walk(doc)
            assert v in leaves


def test_form_and_query_shapes_round_trip_through_a_real_parser():
    rng = random.Random(3)
    for v in VALUES:
        form = shapes.SHAPES["form"](v, rng)
        assert v in [x for vs in parse_qs(form, keep_blank_values=True).values() for x in vs]
        q = shapes.SHAPES["urlquery"](v, rng)
        assert q.startswith("/") and v in [x for vs in parse_qs(q.split("?", 1)[1]).values() for x in vs]


def test_shapes_are_deterministic_for_a_seed():
    a = [shapes.SHAPES[n]("x' or 1=1", random.Random(5)) for n in sorted(shapes.SHAPES)]
    b = [shapes.SHAPES[n]("x' or 1=1", random.Random(5)) for n in sorted(shapes.SHAPES)]
    assert a == b


def test_there_are_held_out_shapes_and_they_are_real_shapes():
    assert shapes.HELD_OUT and shapes.HELD_OUT <= set(shapes.SHAPES)
    assert len(set(shapes.SHAPES) - shapes.HELD_OUT) >= 5


# --- payload loaders ---------------------------------------------------------------------------
def _fake_root(tmp_path):
    (tmp_path / "patt" / "SQL Injection" / "Intruder").mkdir(parents=True)
    (tmp_path / "patt" / "SQL Injection" / "Intruder" / "a.txt").write_text(
        "' OR 1=1--\n=\n'\n# heading\n" + ("A" * 500) + "\nadmin' --\n")
    (tmp_path / "patt" / "SQL Injection" / "README.md").write_text(
        "# SQLi\n```sql\n' UNION SELECT NULL,NULL--\n1; DROP TABLE users\n```\ntext\n")
    (tmp_path / "seclists" / "Fuzzing" / "XSS" / "robot-friendly").mkdir(parents=True)
    (tmp_path / "seclists" / "Fuzzing" / "XSS" / "robot-friendly" / "x.txt").write_text("<script>alert(1)</script>\n%3Cscript%3Ealert(2)%3C/script%3E\n")
    (tmp_path / "fuzzdb" / "attack" / "lfi").mkdir(parents=True)
    (tmp_path / "fuzzdb" / "attack" / "lfi" / "l.txt").write_text("../../../etc/passwd\n..\\..\\boot.ini\n")
    return str(tmp_path)


def test_loader_maps_directories_to_labels_and_cleans_lines(tmp_path):
    recs = payloads.load_attacks(_fake_root(tmp_path))
    by = {}
    for r in recs:
        by.setdefault(r["label"], []).append(r["text"])
    assert "' OR 1=1--" in by["sqli"] and "' UNION SELECT NULL,NULL--" in by["sqli"]
    assert not any(t in ("=", "'") or t.startswith("# ") or len(t) > 400 for t in by["sqli"])
    assert "<script>alert(1)</script>" in by["xss"]
    assert "<script>alert(2)</script>" in by["xss"], "percent-encoded payloads are also kept decoded"
    assert "../../../etc/passwd" in by["path_traversal"]
    assert set(by) <= set(LABELS) and "clean" not in by
    assert all(r["source"] for r in recs)


def test_loader_dedupes_case_insensitively(tmp_path):
    root = _fake_root(tmp_path)
    p = tmp_path / "fuzzdb" / "attack" / "lfi" / "dup.txt"
    p.write_text("../../../ETC/PASSWD\n")
    texts = [r["text"].lower() for r in payloads.load_attacks(root) if r["label"] == "path_traversal"]
    assert len(texts) == len(set(texts))


def test_xss_human_friendly_description_lists_are_not_payloads(tmp_path):
    d = tmp_path / "seclists" / "Fuzzing" / "XSS"
    (d / "human-friendly").mkdir(parents=True)
    (d / "robot-friendly").mkdir(parents=True)
    (d / "human-friendly" / "h.txt").write_text("Exploit Name: with() executing alert\nMalformed IMG Tags\n<img src=x onerror=alert(1)>\n")
    (d / "robot-friendly" / "r.txt").write_text("<svg onload=alert(1)>\n")
    texts = [r["text"] for r in payloads.load_attacks(str(tmp_path)) if r["label"] == "xss"]
    assert "<svg onload=alert(1)>" in texts
    assert not any(t.startswith(("Exploit", "Malformed")) for t in texts)


def test_per_label_validators_drop_non_payload_lines(tmp_path):
    d = tmp_path / "patt" / "Server Side Template Injection"
    d.mkdir(parents=True)
    (d / "README.md").write_text("```\n#end\n*{ ... }\n{{7*7}}\n${7*7}\n<%= 7*7 %>\n```\n")
    s = tmp_path / "patt" / "SQL Injection"
    s.mkdir(parents=True)
    (s / "a.txt").write_text("hello world\n' or 1=1--\nUNION SELECT 1,2\nplain words here\n")
    got = {(r["label"], r["text"]) for r in payloads.load_attacks(str(tmp_path))}
    assert ("ssti", "{{7*7}}") in got and ("ssti", "${7*7}") in got and ("ssti", "<%= 7*7 %>") in got
    assert ("ssti", "#end") not in got and ("ssti", "*{ ... }") not in got
    assert ("sqli", "' or 1=1--") in got and ("sqli", "UNION SELECT 1,2") in got
    assert ("sqli", "hello world") not in got and ("sqli", "plain words here") not in got


def test_one_file_cannot_dominate_a_label(tmp_path):
    d = tmp_path / "seclists" / "Fuzzing"
    d.mkdir(parents=True)
    (d / "command-injection-commix.txt").write_text("\n".join(f";echo X{i}ZZ$(id)" for i in range(500)))
    (tmp_path / "fuzzdb" / "attack" / "os-cmd-execution").mkdir(parents=True)
    (tmp_path / "fuzzdb" / "attack" / "os-cmd-execution" / "o.txt").write_text("; cat /etc/passwd\n| id\n")
    recs = payloads.load_attacks(str(tmp_path), cap_per_file=50)
    commix = [r for r in recs if "commix" in r["source"]]
    assert len(commix) == 50
    assert len([r for r in recs if "o.txt" in r["source"]]) == 2


def test_synthetic_ssti_grid_is_valid_deterministic_and_documented():
    a = payloads.synth_ssti()
    assert len(a) >= 100 and a == payloads.synth_ssti()
    assert all(r["label"] == "ssti" and r["source"] == "builtin:synth-ssti" for r in a)
    assert all(payloads._valid("ssti", r["text"]) for r in a)
    assert len({r["text"] for r in a}) == len(a)


def test_loader_tolerates_missing_roots(tmp_path):
    assert payloads.load_attacks(str(tmp_path)) == []


# --- benign values -----------------------------------------------------------------------------
def test_benign_values_cover_the_hard_negative_families():
    vals = benign.generate(3000, seed=7)
    assert len(vals) >= 2500 and len(set(vals)) > 2000
    joined = "\n".join(vals)
    assert "'" in joined                      # apostrophes (O'Brien)
    assert any(v.startswith("http") for v in vals)
    assert any("<" in v and ">" in v for v in vals)   # benign HTML
    assert any("select" in v.lower() or "union" in v.lower() or "drop" in v.lower() for v in vals)
    assert any("/" in v and " " not in v and not v.startswith("http") for v in vals)   # file paths


def test_credential_forms_use_common_admin_style_values_as_clean_native_bodies():
    forms = benign.credential_forms(200, seed=4)
    assert len(forms) >= 150 and len(set(forms)) == len(forms)
    joined = "\n".join(forms)
    assert "username=admin&password=" in joined or "user=admin&pass=" in joined
    assert '"username": "admin"' in joined or '"username":"admin"' in joined
    assert forms == benign.credential_forms(200, seed=4)
    assert all(len(f) < 300 for f in forms)


def test_benign_generation_is_deterministic():
    assert benign.generate(300, seed=3) == benign.generate(300, seed=3)


# --- build ---------------------------------------------------------------------------------------
@pytest.fixture(scope="module")
def built(tmp_path_factory):
    d = tmp_path_factory.mktemp("v2")
    src = tmp_path_factory.mktemp("src")
    root = _fake_root(src)
    # enough payloads for a meaningful split
    many = "\n".join(f"' OR {i}={i}--" for i in range(400))
    (src / "patt" / "SQL Injection" / "Intruder" / "many.txt").write_text(many)
    many_x = "\n".join(f"<img src=x onerror=alert({i})>" for i in range(300))
    (src / "seclists" / "Fuzzing" / "XSS" / "robot-friendly" / "many.txt").write_text(many_x)
    rep = build.build(root, str(d), seed=11, n_clean=1500, include_local_pools=False)
    return str(d), rep


def _read(d, name):
    with open(os.path.join(d, name)) as f:
        return [json.loads(x) for x in f]


def test_build_writes_splits_and_a_card(built):
    d, rep = built
    for n in ("train.jsonl", "val.jsonl", "test.jsonl", "test_ood.jsonl", "DATASET_CARD.md"):
        assert os.path.exists(os.path.join(d, n)), n
    assert rep["counts"]["train"] > rep["counts"]["val"] > 0


def test_no_payload_group_crosses_splits(built):
    d, _ = built
    seen = {}
    for split in ("train", "val", "test"):
        for r in _read(d, f"{split}.jsonl"):
            seen.setdefault(r["group"], set()).add(split)
    assert all(len(s) == 1 for s in seen.values())


def test_held_out_shapes_appear_only_in_test_ood(built):
    d, _ = built
    for split in ("train", "val", "test"):
        assert not {r["shape"] for r in _read(d, f"{split}.jsonl")} & shapes.HELD_OUT
    ood = _read(d, "test_ood.jsonl")
    assert ood and {r["shape"] for r in ood} <= shapes.HELD_OUT
    train_groups = {r["group"] for r in _read(d, "train.jsonl")}
    assert not train_groups & {r["group"] for r in ood}, "OOD set must use unseen values too"


def test_shape_is_not_predictive_of_the_label(built):
    d, _ = built
    from collections import Counter
    c = Counter((r["shape"], r["label"] == "clean") for r in _read(d, "train.jsonl"))
    for shape in {s for s, _ in c}:
        clean, attack = c[(shape, True)], c[(shape, False)]
        if clean + attack >= 50:
            assert 0.15 < clean / (clean + attack) < 0.85, (shape, clean, attack)


def test_labels_are_valid_and_text_is_bounded(built):
    d, _ = built
    for r in _read(d, "train.jsonl"):
        assert r["label"] in LABELS and 0 < len(r["text"]) <= 2048


def test_native_clean_form_bodies_are_included_when_available(tmp_path, monkeypatch):
    """Realistic login/checkout form bodies must be in the clean class as-is (v2's first
    independent probe regressed on `username=admin&password=...` without them)."""
    data = tmp_path / "data"
    (data / "external").mkdir(parents=True)
    (data / "external" / "synth_benign_forms.jsonl").write_text(
        "\n".join(json.dumps({"text": f"username=user{i}&password=pw{i}!&remember=true", "label": "clean",
                              "source": "synth"}) for i in range(40)) + "\n")
    monkeypatch.setattr(build, "DATA_DIR", str(data))
    root = _fake_root(tmp_path / "s")
    out = tmp_path / "o"
    rep = build.build(root, str(out), seed=2, n_clean=200, include_local_pools=True)
    rows = [json.loads(x) for n in ("train.jsonl", "val.jsonl", "test.jsonl") for x in open(out / n)]
    native = [r for r in rows if r["shape"] == "native"]
    assert native and all(r["label"] == "clean" for r in native)
    assert any(r["text"].startswith("username=") for r in native)


def test_notebook_is_valid_and_every_code_cell_compiles():
    """The bake-off notebook cannot be run here (Colab GPU), so at least prove it parses, every
    cell compiles, it matches the predictor's max length/labels and has no hard-coded paths."""
    import ast
    import re
    from ml.waf.v2 import make_notebook
    nb = make_notebook.build()
    assert nb["nbformat"] == 4 and len(nb["cells"]) >= 10
    src_all = ""
    for c in nb["cells"]:
        if c["cell_type"] != "code":
            continue
        src = "".join(c["source"])
        src_all += src + "\n"
        py = "\n".join(l for l in src.splitlines() if not l.lstrip().startswith(("!", "%")))
        ast.parse(py)
    from ml.waf import predictor
    m = re.search(r'MODEL, MAX_LEN, EPOCHS = "[^"]+", (\d+), (\d+)', src_all)
    assert m, "training cell must declare MAX_LEN"
    assert int(m.group(1)) == predictor.TRANSFORMER_MAX_LENGTH, "notebook max_len must match the predictor"
    m2 = re.search(r"LABELS = \[([^\]]+)\]", src_all)
    assert [x.strip().strip('"') for x in m2.group(1).split(",")] == LABELS, "label order must match taxonomy"
    assert not re.search(r"/home/|~/FYP|xpal", src_all, re.I), "no local paths or engagement names"


def test_privacy_denylist_removes_records(tmp_path):
    src = tmp_path / "s"
    root = _fake_root(src)
    (src / "patt" / "SQL Injection" / "Intruder" / "leak.txt").write_text("' OR 'secretcorp'='secretcorp\n")
    out = tmp_path / "o"
    build.build(root, str(out), seed=1, n_clean=200, include_local_pools=False, denylist=("secretcorp",))
    blob = "".join(open(os.path.join(out, n)).read() for n in ("train.jsonl", "val.jsonl", "test.jsonl", "test_ood.jsonl"))
    assert "secretcorp" not in blob.lower()


def test_build_is_deterministic(tmp_path):
    root = _fake_root(tmp_path / "s")
    a, b = tmp_path / "a", tmp_path / "b"
    build.build(root, str(a), seed=5, n_clean=300, include_local_pools=False)
    build.build(root, str(b), seed=5, n_clean=300, include_local_pools=False)
    assert open(a / "train.jsonl").read() == open(b / "train.jsonl").read()
