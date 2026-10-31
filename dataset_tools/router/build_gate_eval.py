"""Build the router->WAF gate evaluation corpora (attacks + benign outbound bodies).

Only this script is committed; the data is generated into --out (default
~/FYP/corpora/router_gate_eval/) and never lives in the repo.

ATTACKS  (held out from the WAF training data)
  Pool A  payload lines from public-list files that the WAF v2 builder never reads
          (dataset_tools/waf/v2/payloads.py SPEC): FuzzDB all-attacks/*, html_js_fuzz/*, xpath/nosql/ldap, SecLists login_bypass,
          Windows/UnixAttacks.fuzzdb, big-list-of-naughty-strings,
          SecLists Fuzzing/HTML5sec-Injections-Jhaddix.txt, template-engines-*.txt,
          Fuzzing/Databases/*.fuzzdb.txt.
  Pool B  lines of files that ARE in SPEC but that the builder did not emit (its per-file cap
          of 1500 lines / dedupe), i.e. the tail the model never saw.
  Leakage guard: a candidate is dropped when its lower-cased text equals ANY emitted v2 payload
  OR (length >= 15, to avoid dropping every short payload) is a substring of ANY text in the
  WAF v2 train/val/test/test_ood splits (when those files exist). Reported counts are printed. Payloads are then wrapped in carriers the way a
  client would send them: bare, single form field, multi-field form, query string, JSON value,
  nested JSON, percent-encoded form.

BENIGN  realistic outbound bodies
  real code snippets (/usr/share, /usr/lib, this repo), logs, JSON/YAML/INI/config files,
  markdown/docs/man pages/licences, plus synthetic forms/JSON API bodies/prose from the
  v2 benign generator.

Usage:
    python -I -m dataset_tools.router.build_gate_eval [--out DIR] [--seed 7]
"""
from __future__ import annotations

import argparse
import glob
import gzip
import hashlib
import json
import os
import random
import re
import sys
from urllib.parse import quote, quote_plus

from dataset_tools.waf.v2 import payloads as P

WAF_ROOT = os.path.expanduser(os.getenv("WAF_DATASETS", "~/waf_datasets"))
SPLITS_DIR = os.path.join(WAF_ROOT, "build_v2")

HELD_OUT_FILES = [  # (relative to WAF_ROOT, label or None = classify per line)
    ("fuzzdb/attack/all-attacks/all-attacks-unix.txt", None),
    ("fuzzdb/attack/all-attacks/all-attacks-win.txt", None),
    ("fuzzdb/attack/all-attacks/all-attacks-xplatform.txt", None),
    ("seclists/Fuzzing/login_bypass.txt", "sqli"),
    ("seclists/Fuzzing/Windows-Attacks.fuzzdb.txt", None),
    ("seclists/Fuzzing/UnixAttacks.fuzzdb.txt", None),
    ("seclists/Fuzzing/big-list-of-naughty-strings.txt", None),
    ("fuzzdb/attack/xpath/xpath-injection.txt", "sqli"),
    ("fuzzdb/attack/no-sql-injection/mongodb.txt", "sqli"),
    ("fuzzdb/attack/ldap/ldap-injection.txt", "sqli"),
    ("fuzzdb/attack/html_js_fuzz/HTML5sec_Injections.txt", "xss"),
    ("fuzzdb/attack/html_js_fuzz/js_inject.txt", "xss"),
    ("fuzzdb/attack/html_js_fuzz/javascript_events.txt", "xss"),
    ("seclists/Fuzzing/HTML5sec-Injections-Jhaddix.txt", "xss"),
    ("seclists/Fuzzing/template-engines-special-vars.txt", "ssti"),
    ("seclists/Fuzzing/template-engines-identification.txt", "ssti"),
    ("seclists/Fuzzing/Databases/MSSQL-Enumeration.fuzzdb.txt", "sqli"),
    ("seclists/Fuzzing/Databases/MySQL-Read-Local-Files.fuzzdb.txt", "sqli"),
    ("seclists/Fuzzing/Databases/Postgres-Enumeration.fuzzdb.txt", "sqli"),
    ("seclists/Fuzzing/Databases/db2enumeration.fuzzdb.txt", "sqli"),
]

# strong markers used only to label the mixed all-attacks files
_STRONG = [
    ("sqli", re.compile(r"\bunion\b.{0,20}\bselect\b|'\s*or\s*['\d]|\bsleep\s*\(|waitfor\s+delay|;\s*(drop|select|insert|update|delete)\b|\bselect\b.{1,60}\bfrom\b|--\s*$|'\s*--", re.I)),
    ("xss", re.compile(r"<\s*script|<\s*img[^>]+on\w+=|\bon(error|load|mouseover|focus)\s*=|javascript\s*:|<\s*svg|<\s*iframe|alert\s*\(", re.I)),
    ("path_traversal", re.compile(r"(\.\.[/\\]|\.\.%2f|\.\.%5c|%2e%2e|%c0%af)|/etc/(passwd|shadow|hosts)|boot\.ini|win\.ini|windows[/\\]system32", re.I)),
    ("command_injection", re.compile(r"[;|&`]\s*(id|ls|cat|whoami|uname|ping|dir|type|net|wget|curl|nc|sleep)\b|\$\(\s*\w+|%0a\s*(id|cat|ls)|`\w+`", re.I)),
    ("ssti", re.compile(r"\{\{.+\}\}|\$\{.+\}|<%.*%>|\{%.+%\}|#\{.+\}")),
]
_SQLI_LOOSE = re.compile(r"\b(select|union|sleep|waitfor|benchmark|insert|drop|having|order\s+by|or|and)\b.*(--|#|/\*|=|\()|'\s*(or|and|;|--)", re.I)
_NOISE = ["a=1", "lang=en", "page=2", "sort=asc", "ref=home", "utm_source=news", "v=3"]
_KEYS = ["q", "search", "name", "title", "comment", "message", "id", "username", "email", "note", "text",
         "query", "value", "data", "input", "content", "file", "page", "cmd", "host", "template"]
_PER_CLASS = {"sqli": 110, "xss": 110, "path_traversal": 100, "command_injection": 100, "ssti": 60}


def _lines(path: str):
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            for raw in f:
                s = P._clean(raw)
                if s:
                    yield s
    except OSError:
        return


def _label_line(s: str) -> str | None:
    for lab, rx in _STRONG:
        if rx.search(s):
            return lab
    return None


def _split_blob() -> str:
    parts = []
    for n in ("train", "val", "test", "test_ood"):
        p = os.path.join(SPLITS_DIR, n + ".jsonl")
        if os.path.exists(p):
            with open(p, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    try:
                        parts.append(json.loads(line)["text"].lower())
                    except Exception:  # noqa: BLE001
                        pass
    return "\x00".join(parts)


def collect_attack_pool(stats: dict) -> list[dict]:
    emitted = {r["text"].lower() for r in P.load_attacks(WAF_ROOT)}
    blob = _split_blob()
    stats["v2_emitted_payloads"] = len(emitted)
    stats["v2_split_blob_chars"] = len(blob)
    cand: list[dict] = []
    for rel, lab in HELD_OUT_FILES:  # pool A
        for s in _lines(os.path.join(WAF_ROOT, rel)):
            l = lab or _label_line(s)
            if l and P._valid(l, s) and len(s) >= 5:
                cand.append({"payload": s, "label": l, "pool": "A", "source": rel})
    for label, locs in P.SPEC.items():  # pool B: SPEC files, lines never emitted by the builder
        for repo, rel in locs:
            base = os.path.join(WAF_ROOT, repo, rel)
            if not os.path.exists(base):
                continue
            for path in P._files(base):
                for raw in P._lines_of(path, repo):
                    s = P._clean(raw)
                    if s and len(s) >= 5 and P._valid(label, s) and (_label_line(s) == label or (label == "sqli" and _SQLI_LOOSE.search(s))):
                        cand.append({"payload": s, "label": label, "pool": "B",
                                     "source": f"{repo}:{os.path.relpath(path, os.path.join(WAF_ROOT, repo))}"})
    seen, out = set(), []
    stats["candidates"] = len(cand)
    leaked = 0
    for c in cand:
        k = c["payload"].lower()
        if k in seen:
            continue
        seen.add(k)
        if k in emitted or (len(k) >= 15 and blob and k in blob):
            leaked += 1
            continue
        out.append(c)
    stats["dropped_as_leaky"] = leaked
    stats["held_out_unique"] = len(out)
    return out


def _wrap(v: str, shape: str, rng: random.Random) -> str:
    k = rng.choice(_KEYS)
    if shape == "bare":
        return v
    if shape == "form_single":
        return f"{k}={v}"
    if shape == "form_multi":
        parts = [rng.choice(_NOISE), f"{k}={v}", rng.choice(_NOISE)]
        rng.shuffle(parts)
        return "&".join(parts)
    if shape == "form_encoded":
        return f"{rng.choice(_NOISE)}&{k}={quote_plus(v)}"
    if shape == "query":
        return f"/{rng.choice(['search', 'api/items', 'view', 'download'])}?{k}={quote(v, safe='')}&{rng.choice(_NOISE)}"
    if shape == "json":
        return json.dumps({k: v, "n": rng.randint(0, 999)})
    if shape == "json_nested":
        return json.dumps({"data": {"items": [{k: v, "ok": True}], "meta": {"page": rng.randint(1, 9)}}})
    # --- stress carriers: shapes that make the content router say "code" or "prose" ---
    if shape == "sql_stmt":
        return rng.choice([f"SELECT * FROM users WHERE id = {v}", f"{v}\nSELECT name, email FROM accounts WHERE active = 1;",
                           f"UPDATE accounts SET balance = 0 WHERE name = '{v}';", f"1 {v}"])
    if shape == "shell_line":
        return rng.choice([f"{v}", f"ping -c 1 127.0.0.1 {v}", f"cat /var/log/app.log {v}", f"ls -la /tmp {v} && echo done"])
    if shape == "script_block":
        return rng.choice([f"<script>\n  var x = 1;\n  {v}\n</script>", f"<div class=\"c\">{v}</div>\n<p>hello</p>",
                           f"function f() {{\n  return \"{v}\";\n}}"])
    if shape == "sentence":
        return rng.choice([f"Hi team, please try this input in the form: {v} and tell me what happens.",
                           f"I was testing the search box and when I typed {v} the page changed, any idea why?",
                           f"Release notes: fixed the bug where {v} was rejected by the parser."])
    if shape == "config_line":
        return rng.choice([f"[server]\nname = demo\npath = {v}\ndebug = false", f"export TARGET=\"{v}\"",
                           f"$query = \"{v}\";", f"const q = '{v}';  // user supplied"])
    raise ValueError(shape)


STRESS_SHAPES = ["sql_stmt", "shell_line", "script_block", "sentence", "config_line"]
SHAPES = ["bare", "form_single", "form_multi", "form_encoded", "query", "json", "json_nested"]


def build_attacks(seed: int, stats: dict):
    rng = random.Random(seed)
    pool = collect_attack_pool(stats)
    by: dict[str, list[dict]] = {}
    for c in pool:
        by.setdefault(c["label"], []).append(c)
    out = []
    for lab, n in _PER_CLASS.items():
        items = by.get(lab, [])
        rng.shuffle(items)
        stats.setdefault("available", {})[lab] = len(items)
        for c in items[:n]:
            shape = rng.choice(SHAPES)
            out.append({"text": _wrap(c["payload"], shape, rng), "label": lab, "shape": shape,
                        "payload": c["payload"], "pool": c["pool"], "source": c["source"]})
    stress = []  # same held-out pool (payloads NOT used above), code/prose-looking carriers
    for lab, n in _PER_CLASS.items():
        items = by.get(lab, [])
        for c in items[_PER_CLASS[lab]:_PER_CLASS[lab] + (40 if lab != "ssti" else 0)]:
            shape = rng.choice(STRESS_SHAPES)
            if shape == "sql_stmt" and lab != "sqli":
                shape = "sentence"
            stress.append({"text": _wrap(c["payload"], shape, rng), "label": lab, "shape": shape,
                           "payload": c["payload"], "pool": c["pool"], "source": c["source"]})
    stats["n_stress"] = len(stress)
    return out, stress


# ------------------------------------------------------------------ benign
_CODE_GLOBS = ["/usr/share/**/*.py", "/usr/lib/python3*/*.py", "/usr/share/**/*.js", "/usr/share/**/*.sh",
               "/usr/share/**/*.php", "/usr/share/**/*.c", "/usr/share/**/*.h", "/usr/share/**/*.css",
               "/usr/share/**/*.html", "/usr/share/**/*.sql", "/usr/share/**/*.pl", "/usr/share/**/*.rb"]
_DOC_GLOBS = ["/usr/share/doc/**/*.md", "/usr/share/doc/**/README*", "/usr/share/licenses/**/*",
              "/usr/share/doc/**/*.txt", "/usr/share/doc/**/NEWS*", "/usr/share/doc/**/CHANGELOG*"]
_CFG_GLOBS = ["/etc/*.conf", "/usr/share/**/*.ini", "/usr/share/**/*.yaml", "/usr/share/**/*.yml",
              "/usr/share/**/*.toml", "/usr/share/**/*.cfg", "/etc/**/*.conf"]
_JSON_GLOBS = ["/usr/share/**/*.json", "/usr/lib/**/package.json"]


def _read(path: str, limit=60000) -> str | None:
    try:
        if os.path.getsize(path) > 2_000_000 or not os.path.isfile(path):
            return None
        op = gzip.open if path.endswith(".gz") else open
        with op(path, "rt", encoding="utf-8", errors="strict") as f:
            return f.read(limit)
    except Exception:  # noqa: BLE001
        return None


def _files(globs, rng, want, repo_root=None):
    paths = []
    for g in globs:
        paths += glob.glob(g, recursive=True)
    if repo_root:
        for ext in ("py", "md", "json", "yml", "yaml", "sh", "txt"):
            paths += glob.glob(os.path.join(repo_root, "**", f"*.{ext}"), recursive=True)
    paths = sorted(set(p for p in paths if "/artifacts/" not in p and "/.claude/" not in p and "/venv/" not in p))
    rng.shuffle(paths)
    return paths[: want * 6]


def _window(txt: str, rng, lo=3, hi=25, cap=1800) -> str | None:
    ls = txt.splitlines()
    if len(ls) < lo:
        return None
    n = min(len(ls), rng.randint(lo, hi))
    st = rng.randint(0, len(ls) - n)
    s = "\n".join(ls[st:st + n]).strip()
    return s[:cap] if len(s) >= 40 else None


def build_benign(seed: int, repo_root: str, want_real=360, want_synth=180) -> list[dict]:
    rng = random.Random(seed)
    out, seen = [], set()

    def add(kind, text):
        h = hashlib.sha1(text.encode()).hexdigest()
        if text and h not in seen:
            seen.add(h)
            out.append({"text": text, "label": "benign", "kind": kind})

    plan = [("code", _CODE_GLOBS, 130, True), ("docs", _DOC_GLOBS, 70, False), ("config", _CFG_GLOBS, 50, False)]
    for kind, globs, n, use_repo in plan:
        got = 0
        for p in _files(globs, rng, n, repo_root if use_repo else None):
            t = _read(p)
            w = _window(t, rng) if t else None
            if w:
                add(kind, w)
                got += 1
            if got >= n:
                break
    # whole small JSON documents (API-body-like)
    got = 0
    for p in _files(_JSON_GLOBS, rng, 40, repo_root):
        t = _read(p, 3000)
        if t and 30 < len(t) < 2500:
            try:
                json.loads(t)
            except Exception:  # noqa: BLE001
                continue
            add("json_file", t.strip())
            got += 1
            if got >= 40:
                break
    # man pages (gz roff) as prose-ish text
    got = 0
    for p in _files(["/usr/share/man/man1/*.gz", "/usr/share/man/man5/*.gz"], rng, 30):
        t = _read(p)
        w = _window(t, rng, 4, 14) if t else None
        if w:
            add("manpage", w)
            got += 1
            if got >= 30:
                break
    # real logs when readable
    for p in ("/var/log/pacman.log", "/var/log/ly.log"):
        t = _read(p, 200000)
        if t:
            for _ in range(15):
                w = _window(t, rng, 2, 10)
                if w:
                    add("log", w)
    # synthetic: v2 benign values wrapped as forms / JSON / prose bodies (same carriers as attacks)
    try:
        from dataset_tools.waf.v2 import benign as B
        vals = B.generate(want_synth * 2, seed=seed)
        for i, v in enumerate(vals):
            if len([o for o in out if o["kind"].startswith("synth")]) >= want_synth:
                break
            shape = SHAPES[i % len(SHAPES)]
            add("synth_" + shape, _wrap(v, shape, rng))
        for body in B.credential_forms(20, seed=seed):
            add("synth_login", body)
    except Exception as e:  # noqa: BLE001
        print("benign synthetic generator unavailable:", e, file=sys.stderr)
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.expanduser("~/FYP/corpora/router_gate_eval"))
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--repo", default=os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    stats: dict = {}
    atk, stress = build_attacks(a.seed, stats)
    ben = build_benign(a.seed, a.repo)
    for name, rows in (("attacks.jsonl", atk), ("attacks_stress.jsonl", stress), ("benign.jsonl", ben)):
        with open(os.path.join(a.out, name), "w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
    stats.update(n_attacks=len(atk), n_benign=len(ben))
    with open(os.path.join(a.out, "stats.json"), "w") as f:
        json.dump(stats, f, indent=1)
    print(json.dumps(stats, indent=1))


if __name__ == "__main__":
    main()
