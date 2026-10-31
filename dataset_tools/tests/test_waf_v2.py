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
from dataset_tools.waf.v2 import benign, build, payloads, shapes  # noqa: E402
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


def test_benign_generation_never_reads_the_wall_clock(monkeypatch):
    """Faker's iso8601/date/time are relative to 'now', so two builds a second apart differ
    (an intermittent determinism failure). The generator must build timestamps from its own RNG."""
    import faker.providers.date_time as dt

    def boom(*a, **k):
        raise AssertionError("wall-clock Faker date/time function used")
    for name in ("iso8601", "date", "time", "date_time", "date_this_year", "date_between"):
        if hasattr(dt.Provider, name):
            monkeypatch.setattr(dt.Provider, name, boom)
    vals = benign.generate(3000, seed=9)
    assert any(len(v) == 19 and v[4] == "-" and v[10] == "T" for v in vals), "ISO timestamps still generated"


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
    from dataset_tools.waf.v2 import make_notebook
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
    assert not re.search(r"/home/|~/FYP", src_all, re.I), "no local paths in the notebook"


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


# --- shared fixtures for the holdout-source / byte-identity tests ---------------------------------
def _rich_root(src):
    """`_fake_root` plus enough unique payloads in every repo (incl. fuzzdb) for a meaningful split."""
    root = _fake_root(src)
    p = src / "patt" / "SQL Injection" / "Intruder"
    (p / "many.txt").write_text("\n".join(f"' OR {i}={i}--" for i in range(400)))
    (src / "seclists" / "Fuzzing" / "XSS" / "robot-friendly" / "many.txt").write_text(
        "\n".join(f"<img src=x onerror=alert({i})>" for i in range(300)))
    fz = src / "fuzzdb" / "attack"
    for sub, name, body in (
            ("sql-injection", "f1.txt", "\n".join(f"' OR 'fz{i}'='fz{i}'--" for i in range(150))),
            ("xss", "fx.txt", "\n".join(f"<svg onload=fzalert({i})>" for i in range(150))),
            ("path-traversal", "pt.txt", "\n".join(f"../../fzdir{i}/../../etc/passwd" for i in range(100))),
            ("os-cmd-execution", "oc.txt", "\n".join(f"; fzcmd{i} /etc/passwd" for i in range(100)))):
        (fz / sub).mkdir(parents=True, exist_ok=True)
        (fz / sub / name).write_text(body)
    return root


def _stub_generators(monkeypatch, extra=()):
    """Pure-python stand-ins for the Faker-based generators, so golden hashes cannot be broken by a
    Faker upgrade (the byte-identity test is about build.py, not about Faker). `extra` values are
    appended to the generated clean values (used to prove probes cannot leak into training)."""
    monkeypatch.setattr(benign, "generate",
                        lambda n, seed=0, pool=None: [f"benign value {i} o'brien {seed}" for i in range(n)] + list(extra))
    monkeypatch.setattr(benign, "credential_forms",
                        lambda n, seed=0: [f"username=u{i}&password=p{i}{seed}" for i in range(n)])


OUT_FILES = ("train.jsonl", "val.jsonl", "test.jsonl", "test_ood.jsonl", "DATASET_CARD.md")


def _digests(out_dir):
    import hashlib
    return {n: hashlib.sha256(open(os.path.join(out_dir, n), "rb").read()).hexdigest() for n in OUT_FILES}


# sha256 of the five default outputs of `_rich_root` + stubbed generators (seed=7, n_clean=600) as
# produced by the code BEFORE --holdout-source existed. A change here means the default build changed.
GOLDEN_DEFAULT = {
    "train.jsonl": "ecc46ec3cd029f24809a4ace0de86f76f9f1d2dc2b508a6e456bc272619e6976",
    "val.jsonl": "c72686073826acbf578beed8e5f9c30f5782d1f2a70fd66af57461d818366f79",
    "test.jsonl": "565c5918bdd1bee49ee40d13c66af53414d3d07e4ffd0798ee769205802e493a",
    "test_ood.jsonl": "6a169d0d9e2d14793f24847cc3f2a90db6bd9a95953fce729d296de09350d7b8",
    "DATASET_CARD.md": "c8244312701102c71a02d4fdc628d0c0989b15ecc7b9739ebdfde675a0551b89",
}


def test_default_build_is_byte_identical_to_the_pre_holdout_build(tmp_path, monkeypatch):
    _stub_generators(monkeypatch)
    out = tmp_path / "o"
    build.build(_rich_root(tmp_path / "s"), str(out), seed=7, n_clean=600, include_local_pools=False)
    assert _digests(str(out)) == GOLDEN_DEFAULT
    assert not (out / "test_holdout.jsonl").exists()


def test_explicit_no_holdout_equals_default(tmp_path, monkeypatch):
    _stub_generators(monkeypatch)
    out = tmp_path / "o"
    build.build(_rich_root(tmp_path / "s"), str(out), seed=7, n_clean=600, include_local_pools=False,
                holdout_source=None)
    assert _digests(str(out)) == GOLDEN_DEFAULT


def test_default_build_drops_a_stale_holdout_file_and_zip_ignores_it(tmp_path, monkeypatch):
    """A leftover test_holdout.jsonl from an earlier holdout build in the same directory must not be
    silently packed into the zip of a default build."""
    import zipfile
    _stub_generators(monkeypatch)
    out = tmp_path / "o"
    out.mkdir()
    (out / "test_holdout.jsonl").write_text('{"text": "stale"}\n')
    build.build(_rich_root(tmp_path / "s"), str(out), seed=7, n_clean=600, include_local_pools=False)
    assert not (out / "test_holdout.jsonl").exists()
    names = zipfile.ZipFile(build.make_zip(str(out))).namelist()
    assert "test_holdout.jsonl" not in names and sorted(names) == sorted(OUT_FILES)


# --- hold out a whole payload source -------------------------------------------------------------
FZ_MARKERS = ("fzalert", "fzdir", "fzcmd", "'fz")        # only ever appear in the fuzzdb fixture files
PROBE_TEXT = "Please contact our support team if you have any questions."


@pytest.fixture(scope="module")
def held(tmp_path_factory):
    """Holdout build whose clean generator also emits probe texts (they must be kept out of training)."""
    from dataset_tools.waf.v2 import probes
    mp = pytest.MonkeyPatch()
    try:
        _stub_generators(mp, extra=[PROBE_TEXT, probes.REALISTIC_BENIGN[0][1]])
        src = tmp_path_factory.mktemp("hsrc")
        out = tmp_path_factory.mktemp("hout")
        rep = build.build(_rich_root(src), str(out), seed=7, n_clean=600, include_local_pools=False,
                          holdout_source="fuzzdb")
    finally:
        mp.undo()
    return str(out), rep


def test_holdout_writes_a_separate_file_and_reports_it(held):
    d, rep = held
    rows = _read(d, "test_holdout.jsonl")
    assert rows and rep["counts"]["test_holdout"] == len(rows)
    assert rep["holdout"]["source"] == ["fuzzdb"]
    for r in rows:
        assert set(r) >= {"text", "label", "source", "shape", "group"} and r["label"] in LABELS
        assert 0 < len(r["text"]) <= 2048
    assert "fuzzdb" in open(os.path.join(d, "DATASET_CARD.md")).read().lower()


def test_no_row_outside_the_holdout_file_carries_the_held_out_source(held):
    d, _ = held
    for split in ("train", "val", "test", "test_ood"):
        rows = _read(d, f"{split}.jsonl")
        assert rows
        assert not [r for r in rows if r["source"].split(":")[0] == "fuzzdb"], split
        blob = "\n".join(r["text"] for r in rows)
        assert not [m for m in FZ_MARKERS if m in blob], (split, "held-out payload text leaked")


def test_holdout_file_holds_only_held_out_payloads_plus_handwritten_probes(held):
    d, _ = held
    rows = _read(d, "test_holdout.jsonl")
    srcs = {r["source"].split(":")[0] for r in rows}
    assert srcs == {"fuzzdb", "handwritten"}
    attacks = [r for r in rows if r["source"].startswith("fuzzdb")]
    assert {r["label"] for r in attacks} >= {"sqli", "xss", "path_traversal", "command_injection"}
    assert all(r["label"] != "clean" for r in attacks)
    assert any(any(m in r["text"] for m in FZ_MARKERS) for r in attacks)


def test_holdout_attacks_use_only_the_training_shapes(held):
    """Source shift must be measured alone: no OOD carrier shapes mixed in."""
    d, _ = held
    shp = {r["shape"] for r in _read(d, "test_holdout.jsonl") if r["source"].startswith("fuzzdb")}
    assert "bare" in shp and not shp & shapes.HELD_OUT and shp <= set(shapes.SHAPES)


def test_holdout_groups_never_appear_in_any_other_split(held):
    d, _ = held
    hold_groups = {r["group"] for r in _read(d, "test_holdout.jsonl")}
    for split in ("train", "val", "test", "test_ood"):
        assert not hold_groups & {r["group"] for r in _read(d, f"{split}.jsonl")}, split


def test_probe_texts_cannot_leak_into_training(held):
    from dataset_tools.waf.v2 import probes
    d, _ = held
    leaked = {build._group(t) for t in probes.all_texts()}
    for split in ("train", "val", "test", "test_ood"):
        assert not leaked & {r["group"] for r in _read(d, f"{split}.jsonl")}, split
    assert build._group(PROBE_TEXT) in leaked


def test_holdout_file_contains_all_probes_and_realistic_benign_bodies(held):
    from dataset_tools.waf.v2 import probes
    d, _ = held
    rows = _read(d, "test_holdout.jsonl")
    pr = [r for r in rows if r["shape"] == "probe"]
    assert len(pr) == len(probes.PROBES) == 25
    assert sum(r["label"] == "clean" for r in pr) == 15 and sum(r["label"] != "clean" for r in pr) == 10
    assert {r["text"] for r in pr} == {t for _, _, t in probes.PROBES}
    native = [r for r in rows if r["shape"] == "native"]
    assert {r["text"] for r in native} == {t for _, t in probes.REALISTIC_BENIGN if len(t) <= 2048}
    assert all(r["label"] == "clean" for r in native) and len(native) >= 40
    wrapped = [r for r in rows if r["source"].startswith("handwritten:benign") and r["shape"] != "native"]
    assert wrapped and all(r["label"] == "clean" for r in wrapped)


def test_encoded_twin_of_a_training_payload_is_dropped_from_the_holdout(tmp_path, monkeypatch):
    """The loader keeps a fuzzdb percent-encoded payload when patt already supplied its decoded form
    (exact-text dedupe cannot see they are the same payload). Such near-twins must not be in the holdout."""
    _stub_generators(monkeypatch)
    root = _rich_root(tmp_path / "s")
    (tmp_path / "s" / "fuzzdb" / "attack" / "sql-injection" / "twin.txt").write_text(
        "%27%20OR%205%3D5--\n  ' or  5=5--  \nfzunique' OR 'x'='x\n")
    out = tmp_path / "o"
    rep = build.build(root, str(out), seed=7, n_clean=300, include_local_pools=False, holdout_source="fuzzdb")
    hold = open(out / "test_holdout.jsonl").read()
    assert "%27%20OR%205%3D5--" not in hold, "encoded twin of a training payload leaked into the holdout"
    assert "fzunique" in hold, "a genuinely new fuzzdb payload must stay"
    assert rep["holdout"]["dropped_near_twins"] >= 1
    assert "near-twin" in open(out / "DATASET_CARD.md").read().lower()
    for n in ("train.jsonl", "val.jsonl", "test.jsonl", "test_ood.jsonl"):
        assert "%27%20OR%205%3D5--" not in open(out / n).read(), "dropped, not moved to training"


def test_holdout_build_is_deterministic(tmp_path, monkeypatch):
    _stub_generators(monkeypatch)
    root = _rich_root(tmp_path / "s")
    a, b = tmp_path / "a", tmp_path / "b"
    for o in (a, b):
        build.build(root, str(o), seed=7, n_clean=600, include_local_pools=False, holdout_source="fuzzdb")
    for n in OUT_FILES + ("test_holdout.jsonl",):
        assert open(a / n, "rb").read() == open(b / n, "rb").read(), n


def test_holdout_denylist_applies_to_the_holdout_file(tmp_path, monkeypatch):
    _stub_generators(monkeypatch)
    root = _rich_root(tmp_path / "s")
    out = tmp_path / "o"
    build.build(root, str(out), seed=7, n_clean=300, include_local_pools=False, holdout_source="fuzzdb",
                denylist=("fzcmd5",))
    blob = "".join(open(out / n).read() for n in OUT_FILES[:4] + ("test_holdout.jsonl",))
    assert "fzcmd5" not in blob and "fzcmd6" in blob


def test_holdout_of_a_source_with_no_payloads_is_an_error(tmp_path, monkeypatch):
    """An empty holdout would make the holdout-recall gate vacuous."""
    _stub_generators(monkeypatch)
    with pytest.raises(ValueError, match="nosuchsource"):
        build.build(_rich_root(tmp_path / "s"), str(tmp_path / "o"), seed=7, n_clean=100,
                    include_local_pools=False, holdout_source="nosuchsource")


def test_zip_includes_the_holdout_file_only_when_built(held, tmp_path):
    import zipfile
    d, _ = held
    assert "test_holdout.jsonl" in zipfile.ZipFile(build.make_zip(d)).namelist()


def test_cli_accepts_holdout_source(tmp_path, monkeypatch, capsys):
    _stub_generators(monkeypatch)
    root = _rich_root(tmp_path / "s")
    data = tmp_path / "data"
    data.mkdir()
    monkeypatch.setattr(build, "DATA_DIR", str(data))
    out = tmp_path / "o"
    monkeypatch.setattr(sys, "argv", ["build", "--root", root, "--out", str(out), "--n-clean", "200",
                                      "--holdout-source", "fuzzdb"])
    build.main()
    assert (out / "test_holdout.jsonl").exists() and (out / "dataset_v2.zip").exists()


def test_probe_data_is_self_consistent():
    from dataset_tools.waf.v2 import probes
    texts = probes.all_texts()
    assert len(texts) == len(set(texts)), "probe texts must be unique"
    assert len(probes.REALISTIC_BENIGN) >= 40
    assert {lab for _, lab, _ in probes.PROBES} <= set(LABELS)
    assert max(len(t) for t in texts) < 2048
    assert all(t.strip() for t in texts)


# --- notebook: holdout evaluation + gates generated from gate.py ----------------------------------------------
def _nb_cell(prefix):
    from dataset_tools.waf.v2 import make_notebook
    for c in make_notebook.build()["cells"]:
        src = "".join(c["source"])
        if src.startswith(prefix):
            return src
    raise AssertionError(f"no notebook cell starts with {prefix!r}")


def test_notebook_gate_cell_is_generated_from_gate_py():
    import ast
    from dataset_tools.waf.v2 import gate
    src = _nb_cell("# 9. ship gates")
    lit = next(n for n in ast.parse(src).body
               if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "GATES")
    assert ast.literal_eval(lit.value) == {k: gate.GATES[k] for k in gate.NOTEBOOK_GATE_KEYS}
    assert "def gate_checks" in src and "replay" not in ast.literal_eval(lit.value)


def test_committed_notebook_is_the_generators_output():
    from dataset_tools.waf.v2 import make_notebook
    with open(make_notebook.OUT, encoding="utf-8") as f:
        assert json.load(f) == make_notebook.build(), "run: python -m dataset_tools.waf.v2.make_notebook"


def test_notebook_requires_the_holdout_file_and_says_how_to_build_it():
    src = _nb_cell("# 2. data")
    assert "test_holdout.jsonl" in src and "--holdout-source" in src
    assert "assert os.path.exists" in src, "an old default-build zip must stop the notebook, not pass silently"


def test_notebook_after_download_names_the_right_env_vars_and_the_gate():
    from dataset_tools.waf.v2 import make_notebook
    md = "\n".join("".join(c["source"]) for c in make_notebook.build()["cells"] if c["cell_type"] == "markdown")
    assert "WAF_ATTACK_THRESHOLD" in md and "dataset_tools.waf.v2.gate" in md and "WAF_THRESHOLD" in md


def _run_eval_cells(flag_for):
    """Execute notebook cells 7 (evaluate), 8 (independent battery) and 9 (gates) with stub scorers."""
    import numpy as np
    from dataset_tools.waf.v2 import probes as pr
    rows = {}

    def mk(label, shape, text, source="x:y", name=None):
        r = {"text": text, "label": label, "shape": shape, "source": source}
        if name:
            r["name"] = name
        return r
    clean = [mk("clean", s, f"clean {s} {i}") for s in ("json", "form") for i in range(60)]
    attack = [mk("sqli", s, f"attack {s} {i}") for s in ("json", "form") for i in range(60)]
    test_rows = clean + attack
    ood_rows = [mk("clean", "cookie", f"clean cookie {i}") for i in range(50)] + [mk("xss", "cookie", f"attack cookie {i}") for i in range(50)]
    hold_rows = ([mk("clean", "native", t, "handwritten:benign_bodies", n) for n, t in pr.REALISTIC_BENIGN]
                 + [mk("clean", "json", f"wrapped {n}", "handwritten:benign_bodies", n) for n, _ in pr.REALISTIC_BENIGN[:15]]
                 + [mk("sqli", "bare", f"fuzzdb attack {i}", "fuzzdb:x") for i in range(100)])
    probe_rows = [mk(lab, "probe", t, "handwritten:waf_probe", n) for n, lab, t in pr.PROBES]
    every = test_rows + ood_rows + hold_rows + probe_rows
    label_of = {r["text"]: r["label"] for r in every}

    def scorer(texts):
        flags = np.array([flag_for(t, label_of[t]) for t in texts], dtype=float)
        return flags, ["sqli" if f > 0.5 else "clean" for f in flags]
    ns = {"np": np, "json": json, "ATTACKS": LABELS[1:], "test": test_rows, "ood": ood_rows, "hold": hold_rows,
          "probe_rows": probe_rows, "ARMS": {"A_softmax7": scorer}, "THR": {"A_softmax7": 0.5}}
    for prefix in ("# 7.", "# 8.", "# 9."):
        exec(compile(_nb_cell(prefix), prefix, "exec"), ns)       # noqa: S102 - the notebook's own cells
    return ns


def test_notebook_evaluates_holdout_and_independent_battery_and_gates_on_stub_scorers(tmp_path, capsys):
    from dataset_tools.waf.v2 import gate, probes as pr
    ns = _run_eval_cells(lambda t, lab: 0.9 if lab != "clean" else 0.1)
    h = ns["R"]["A_softmax7"]["holdout"]
    assert h["n_clean"] == len(pr.REALISTIC_BENIGN) + 15 and h["n_attack"] == 100 and h["fp"] == 0 and h["recall"] == 1
    assert ns["IND"]["A_softmax7"] == {"benign_fp": 0, "attacks_caught": 9, "n_benign": 15, "n_attack": 9}
    assert ns["PASS"]["A_softmax7"] is True
    # what the notebook exports is accepted by the standalone gate (same checks, same verdict)
    res = {k: ns[k] for k in ("R", "IND", "THR", "PASS")}
    rp = tmp_path / "r.json"
    rp.write_text(json.dumps(res))
    art = tmp_path / "art"
    art.mkdir()
    (art / "waf_v2.json").write_text(json.dumps({"arm": "A_softmax7", "recommended_threshold": 0.5}))
    assert gate.main(["--results", str(rp), "--artifact", str(art), "--skip-replay"]) == 0
    assert [(n, ok) for n, ok, _d in ns["CHECKS"]["A_softmax7"]] == [(n, ok) for n, ok, _d in gate.gate_checks(
        {**ns["R"]["A_softmax7"], "ind": ns["IND"]["A_softmax7"]}, gate.GATES)]


def test_notebook_gate_fails_when_the_model_blocks_realistic_benign_bodies(tmp_path):
    from dataset_tools.waf.v2 import gate
    ns = _run_eval_cells(lambda t, lab: 0.9 if (lab != "clean" or "wrapped" in t) else 0.1)
    h = ns["R"]["A_softmax7"]["holdout"]
    assert h["fp"] > gate.GATES["holdout_benign_fp"]
    assert ns["PASS"]["A_softmax7"] is False
    failed = [n for n, ok, _d in ns["CHECKS"]["A_softmax7"] if not ok]
    assert any("holdout benign FP" in n for n in failed)
