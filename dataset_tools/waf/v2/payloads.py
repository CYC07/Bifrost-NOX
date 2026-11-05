"""Attack payload loaders for public repositories (PayloadsAllTheThings, SecLists, FuzzDB).

`root` holds the clones as root/patt, root/seclists, root/fuzzdb. A missing directory yields
nothing (the build must work with whatever was downloaded). Lines are cleaned, percent-encoded
payloads are also kept decoded (the gateway scores decoded values), and the result is deduped
case-insensitively.
"""
from __future__ import annotations

import os
import re
from urllib.parse import unquote

MIN_LEN, MAX_LEN = 3, 400

# label -> [(repo dir, path inside it)]; a path may be a directory or a single file
SPEC: dict[str, list[tuple[str, str]]] = {
    "sqli": [("patt", "SQL Injection"), ("seclists", "Fuzzing/Databases/SQLi"), ("fuzzdb", "attack/sql-injection")],
    # human-friendly/ holds descriptions ("Exploit Name: ...") interleaved with payloads: skipped
    "xss": [("patt", "XSS Injection"), ("seclists", "Fuzzing/XSS/robot-friendly"),
            ("seclists", "Fuzzing/XSS/Polyglots"), ("fuzzdb", "attack/xss")],
    "path_traversal": [("patt", "Directory Traversal"), ("patt", "File Inclusion"), ("seclists", "Fuzzing/LFI"),
                       ("fuzzdb", "attack/lfi"), ("fuzzdb", "attack/path-traversal")],
    "command_injection": [("patt", "Command Injection"), ("fuzzdb", "attack/os-cmd-execution"),
                          ("seclists", "Fuzzing/command-injection-commix.txt")],
    "ssti": [("patt", "Server Side Template Injection")],
}
_SKIP_NAMES = {"readme.md", "license", "license.md", "manifest.json", ".gitignore"}
_TEXT_SUFFIX = {".txt", ".fuzz", ".lst", ""}
_FENCE = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)
_HEADING = re.compile(r"^#{1,6}\s")


def _clean(line: str) -> str | None:
    s = line.strip("\r\n").strip()
    if not (MIN_LEN <= len(s) <= MAX_LEN) or _HEADING.match(s) or s.startswith("//"):
        return None
    return s


def _lines_of(path: str, repo: str = ""):
    name = os.path.basename(path).lower()
    suffix = os.path.splitext(name)[1]
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
    except OSError:
        return
    # PayloadsAllTheThings keeps its payload lists inside each directory's README (fenced blocks);
    # everywhere else README/LICENSE files are documentation, not payloads.
    if name in _SKIP_NAMES and suffix != ".txt" and not (repo == "patt" and name == "readme.md"):
        return
    if suffix == ".md":
        for block in _FENCE.findall(text):
            yield from block.splitlines()
    elif suffix in _TEXT_SUFFIX:
        yield from text.splitlines()


def _files(path: str):
    if os.path.isfile(path):
        yield path
        return
    for d, _dirs, names in os.walk(path):
        for n in sorted(names):
            yield os.path.join(d, n)


_VALID = {
    # a line only counts as a payload for a label if it carries at least one active marker; this
    # drops prose, headings and placeholder tokens that README fences / list files contain.
    "sqli": re.compile(r"['\"`]|--|/\*|#|;|\b(select|union|sleep|benchmark|waitfor|having|order\s+by|insert|update|"
                       r"delete|drop|exec|declare|cast|convert|extractvalue|load_file|or|and)\b|0x[0-9a-f]+", re.I),
    "xss": re.compile(r"<|>|javascript:|\bon\w+\s*=|alert\s*\(|prompt\s*\(|confirm\s*\(|eval\s*\(|document\.|&#|%3c", re.I),
    "path_traversal": re.compile(r"\.\.|/etc/|/proc/|/var/|/windows|\\windows|boot\.ini|%2e|%c0|%e0|\\\\|\.\.%|file://|"
                                 r"php://|expect://|data://|c:\\|/usr/|/home/|/opt/|/root|/tmp/|/bin/|/sys/", re.I),
    "command_injection": re.compile(r"[;|&`$]|%0a|%3b|%7c|%26|%24|\$\(|\bcat\b|\bid\b|\bwhoami\b|\bping\b|\bsleep\b|"
                                    r"\bnc\b|\bcurl\b|\bwget\b|/bin/", re.I),
    "ssti": re.compile(r"\{\{|\{%|\{#|\$\{|<%|#\{|@\(|\*\{|\[\[|\$\w+\{|<\w+:\w+|\{\w+\}"),
}
_PLACEHOLDER = re.compile(r"\.\.\.(\s|$)|^\W*(end|if|else)\W*$", re.I)
DEFAULT_CAP_PER_FILE = 1500


def _valid(label: str, s: str) -> bool:
    if label == "ssti" and (_PLACEHOLDER.search(s) or s.lower().strip("#") in ("end", "if", "else")):
        return False
    rx = _VALID.get(label)
    return rx is None or bool(rx.search(s))


def load_attacks(root: str, cap_per_file: int = DEFAULT_CAP_PER_FILE) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    for label, locations in SPEC.items():
        for repo, rel in locations:
            base = os.path.join(root, repo, rel)
            if not os.path.exists(base):
                continue
            for path in _files(base):
                taken = 0
                for raw in _lines_of(path, repo):
                    if taken >= cap_per_file:
                        break
                    s = _clean(raw)
                    if s is None or not _valid(label, s):
                        continue
                    variants = [s]
                    if "%" in s:
                        dec = unquote(s)
                        if dec != s and MIN_LEN <= len(dec) <= MAX_LEN:
                            variants.append(dec)
                    for v in variants:
                        k = v.lower()
                        if k in seen:
                            continue
                        seen.add(k)
                        taken += 1
                        out.append({"text": v, "label": label,
                                    "source": f"{repo}:{os.path.relpath(path, os.path.join(root, repo))}"})
    return out


_SSTI_DELIMS = [("{{", "}}"), ("${", "}"), ("<%= ", " %>"), ("#{", "}"), ("{% print ", " %}"), ("*{", "}"),
                ("@(", ")"), ("[[${", "}]]")]
_SSTI_EXPRS = ["7*7", "7*'7'", "49", "1+1", "config", "self.__class__", "''.__class__.__mro__[1].__subclasses__()",
               "request.application.__globals__", "lipsum.__globals__['os'].popen('id').read()",
               "T(java.lang.Runtime).getRuntime().exec('id')", "cycler.__init__.__globals__.os.popen('id').read()",
               "system('id')", "__import__('os').popen('id').read()", "''.getClass().forName('java.lang.Runtime')",
               "constructor.constructor('return process')()", "namespace.__init__.__globals__"]


def synth_ssti() -> list[dict]:
    """Delimiter x expression grid across common template engines. Synthetic and documented as
    such in the dataset card; it exists because public SSTI lists are only ~200 lines."""
    out, seen = [], set()
    for lo, hi in _SSTI_DELIMS:
        for ex in _SSTI_EXPRS:
            t = f"{lo}{ex}{hi}"
            if t not in seen:
                seen.add(t)
                out.append({"text": t, "label": "ssti", "source": "builtin:synth-ssti"})
    return out


# A small, honest scanner set: automated tool user-agents/probes. Documented as synthetic and tiny.
_SCANNER_TOOLS = ["sqlmap/1.7.{n}#stable (https://sqlmap.org)", "Nikto/2.1.{n}", "DirBuster-1.0-RC{n}",
                  "gobuster/3.{n}.0", "wfuzz/3.{n}.0", "Acunetix-Aspect/{n}", "Nmap Scripting Engine; https://nmap.org/book/nse.html",
                  "masscan/1.{n}", "WPScan v3.8.{n} (https://wpscan.com/wordpress-security-scanner)",
                  "Mozilla/5.00 (Nikto/2.1.{n}) (Evasions:None) (Test:Port Check)", "Hydra/{n}.0", "feroxbuster/2.{n}.0",
                  "nuclei - Open-source project (github.com/projectdiscovery/nuclei)", "ZAP/2.{n}.0"]


def scanner_probes(n_versions: int = 12) -> list[dict]:
    out = []
    for tool in _SCANNER_TOOLS:
        if "{n}" in tool:
            out += [{"text": tool.format(n=i), "label": "scanner", "source": "builtin:scanner-ua"}
                    for i in range(n_versions)]
        else:
            out.append({"text": tool, "label": "scanner", "source": "builtin:scanner-ua"})
    return out


# --- OWASP Core Rule Set regression tests (real request test cases written by the CRS project) --------
# category prefix -> label. 934 (generic) mixes SSRF/XXE/Node/templates: only template syntax is kept (ssti).
_CRS_LABEL = {"REQUEST-913": "scanner", "REQUEST-930": "path_traversal", "REQUEST-931": "path_traversal",
              "REQUEST-932": "command_injection", "REQUEST-933": "command_injection", "REQUEST-934": "ssti",
              "REQUEST-941": "xss", "REQUEST-942": "sqli"}
# bare words/names, not payloads: unix-shell*.data ("cat", "id"), restricted-files.data (".htaccess") are skipped
_CRS_DATA = {"scanners-user-agents.data": "scanner", "lfi-os-files.data": "path_traversal"}


def _yaml_load(path: str):
    import yaml                      # lazy: the loaders must not make pyyaml a hard import of this module
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return yaml.safe_load(f)
    except (OSError, yaml.YAMLError, ValueError, RecursionError):
        return None


def _pairs(text: str):
    """Candidate payload strings from a query string / form body: every raw value and its decoded form;
    a body without 'k=v' structure is itself one candidate."""
    if "=" not in text and "%3d" in text.lower():
        text = unquote(text)          # CRS sends whole bodies encoded ('pay%3D%3B+x'): find the key after decoding
    if "=" not in text or "\n" in text:
        yield text
        yield unquote(text)
        return
    for pair in text.split("&"):
        _k, _eq, v = pair.partition("=")
        yield v
        yield unquote(v.replace("+", " "))


def _crs_stage_values(label: str, inp: dict):
    uri = str(inp.get("uri") or "")
    path, _q, query = uri.partition("?")
    if label == "path_traversal":
        yield unquote(path)
    if query:
        yield from _pairs(query)
    data = inp.get("data")
    if isinstance(data, str) and data.strip():
        yield from _pairs(data.strip())


def load_crs(root: str, cap_per_file: int = DEFAULT_CAP_PER_FILE) -> list[dict]:
    """Attack payloads from root/crs: positive regression tests (output.log.expect_ids) plus two rule data
    lists. Negative tests (no_expect_ids) and requests the rule is NOT expected to flag are never attacks."""
    base = os.path.join(root, "crs")
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(label: str, s: str, rel: str, taken: list) -> None:
        s = (s or "").strip()
        if not (MIN_LEN <= len(s) <= MAX_LEN) or (label != "scanner" and not _valid(label, s)):
            return
        if (label, s.lower()) in seen or taken[0] >= cap_per_file:
            return
        seen.add((label, s.lower()))
        taken[0] += 1
        out.append({"text": s, "label": label, "source": f"crs:{rel}"})

    tests_dir = os.path.join(base, "tests", "regression", "tests")
    for path in _files(tests_dir) if os.path.isdir(tests_dir) else ():
        if not path.endswith((".yaml", ".yml")):
            continue
        category = os.path.basename(os.path.dirname(path))
        label = _CRS_LABEL.get(category[:11])
        doc = _yaml_load(path)
        if label is None or not isinstance(doc, dict):
            continue
        rel, taken = os.path.relpath(path, base), [0]
        for test in doc.get("tests") or []:
            for stage in (test.get("stages") or []) if isinstance(test, dict) else []:
                if not isinstance(stage, dict):
                    continue
                inp = stage.get("input") or {}
                log = ((stage.get("output") or {}).get("log") or {}) if isinstance(stage.get("output"), dict) else {}
                if not isinstance(inp, dict) or not log.get("expect_ids"):
                    continue                                    # negative / non-rule test: not an attack
                if label == "scanner":
                    ua = (inp.get("headers") or {}).get("User-Agent") if isinstance(inp.get("headers"), dict) else None
                    if isinstance(ua, str):
                        add("scanner", ua, rel, taken)
                    continue
                for s in _crs_stage_values(label, inp):
                    add(label, s, rel, taken)
    rules = os.path.join(base, "rules")
    for name, label in _CRS_DATA.items():
        p = os.path.join(rules, name)
        taken = [0]
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                raw_lines = f.read().splitlines()
        except OSError:
            continue
        for raw in raw_lines:                  # .data is not a suffix _lines_of reads, so read it directly
            s = _clean(raw)
            if s is not None and not s.startswith("#"):
                add(label, s, f"rules/{name}", taken)
    return out


# --- Nuclei DAST templates: payload lists with category tags ---------------------------------------------
_NUCLEI_TAG_LABEL = {"sqli": "sqli", "xss": "xss", "cmdi": "command_injection", "lfi": "path_traversal",
                     "rfi": "path_traversal", "ssti": "ssti", "csti": "ssti"}
_NUCLEI_VARS = ("baseurl", "rooturl", "hostname", "host", "port", "path", "file", "scheme", "randstr", "rand_",
                "interactsh", "oast", "md5", "base64", "url_encode", "to_lower", "to_upper")
_VAR_TOKEN = re.compile(r"\{\{\s*([A-Za-z_][\w-]*)")


def _nuclei_placeholder(s: str, set_names: set[str]) -> bool:
    for tok in _VAR_TOKEN.findall(s):
        low = tok.lower()
        if tok in set_names or any(low.startswith(v) for v in _NUCLEI_VARS):
            return True
    return False


def load_nuclei(root: str, cap_per_file: int = DEFAULT_CAP_PER_FILE) -> list[dict]:
    base = os.path.join(root, "nuclei")
    dast = os.path.join(base, "dast", "vulnerabilities")
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for path in _files(dast) if os.path.isdir(dast) else ():
        if not path.endswith((".yaml", ".yml")):
            continue
        doc = _yaml_load(path)
        info = doc.get("info") if isinstance(doc, dict) else None
        tags = info.get("tags") if isinstance(info, dict) else None
        if not isinstance(tags, str):
            continue
        label = next((_NUCLEI_TAG_LABEL[t.strip()] for t in tags.split(",") if t.strip() in _NUCLEI_TAG_LABEL), None)
        if label is None:
            continue
        taken = 0
        for req in doc.get("http") or []:
            if not isinstance(req, dict):
                continue
            sets = req.get("payloads") if isinstance(req.get("payloads"), dict) else {}
            names = set(sets)
            cands = [s for v in sets.values() if isinstance(v, list) for s in v if isinstance(s, str)]
            for fz in req.get("fuzzing") or []:
                if isinstance(fz, dict) and isinstance(fz.get("fuzz"), list):
                    cands += [s for s in fz["fuzz"] if isinstance(s, str)]
            for raw in cands:
                s = raw.strip()
                if (taken >= cap_per_file or not (MIN_LEN <= len(s) <= MAX_LEN) or _nuclei_placeholder(s, names)
                        or not _valid(label, s) or (label, s.lower()) in seen):
                    continue
                seen.add((label, s.lower()))
                taken += 1
                out.append({"text": s, "label": label, "source": f"nuclei:{os.path.relpath(path, base)}"})
    return out
