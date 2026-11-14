"""Real (not hand-written) benign text for the clean class: log lines and system shell/config/HTML text.

Why: v1 blocked benign shell commands, HTML, logs and config because the clean class never contained
real examples of them; v2's first build only had hand-written ones. Everything here is read as text,
never executed, and files that look secret-bearing or match the denylist are dropped whole.
"""
from __future__ import annotations

import json
import os
import random
import re

from ml.waf.gate import has_strong_marker

MAX_SNIPPET = 600
MIN_SNIPPET = 3
DEFAULT_SYSTEM_ROOTS = ("/usr/share",)
_MAX_FILE_BYTES = 60_000

# suffix -> kind (the kind becomes the row source "sysfile:<kind>")
_KINDS = {".sh": "sh", ".bash": "sh", ".conf": "conf", ".cfg": "conf", ".ini": "conf", ".cnf": "conf",
          ".toml": "conf", ".yaml": "conf", ".yml": "conf", ".html": "html", ".htm": "html", ".json": "json",
          ".md": "md"}
# a secret-looking assignment, a key block, or a well-known token prefix anywhere in the file drops the file
_SECRET = re.compile(
    r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|auth)\w*\s*[:=]\s*[\"']?\S{4,}"
    r"|BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16}|ghp_[0-9A-Za-z]{20,}|sk_live_[0-9A-Za-z]{10,}|xox[abp]-[0-9A-Za-z-]{10,}")


# a long unbroken base64/hex run is a key, certificate or blob: noise that would teach "random-looking = benign"
_BLOB = re.compile(r"[A-Za-z0-9+/=_-]{80,}")


def _denied(text: str, denylist) -> bool:
    low = text.lower()
    return any(d and d.lower() in low for d in denylist)


def load_loghub(root: str, rng: random.Random, n_per_system: int = 300) -> list[dict]:
    """Snippets (one line, or up to three consecutive lines) from root/loghub/<System>/*.log samples."""
    base = os.path.join(root, "loghub")
    if not os.path.isdir(base):
        return []
    out: list[dict] = []
    for system in sorted(os.listdir(base)):
        d = os.path.join(base, system)
        if not os.path.isdir(d):
            continue
        lines: list[str] = []
        for name in sorted(os.listdir(d)):
            if name.endswith(".log"):
                try:
                    with open(os.path.join(d, name), "r", encoding="utf-8", errors="ignore") as f:
                        lines += [l.strip() for l in f.read().splitlines()]
                except OSError:
                    continue
        usable = [i for i, l in enumerate(lines) if 8 <= len(l) <= 300]
        if not usable:
            continue
        for i in rng.sample(usable, min(n_per_system, len(usable))):
            block = [lines[i]]
            if rng.random() < 0.3:                                  # some multi-line log excerpts
                for j in (i + 1, i + 2):
                    if j < len(lines) and 8 <= len(lines[j]) <= 300:
                        block.append(lines[j])
            text = "\n".join(block)[:MAX_SNIPPET]
            out.append({"text": text, "label": "clean", "source": f"loghub:{system}"})
    return out


def _snippet(text: str, kind: str, rng: random.Random) -> str | None:
    if kind == "json":
        try:
            compact = json.dumps(json.loads(text), separators=(",", ":"), ensure_ascii=False)
            if MIN_SNIPPET <= len(compact) <= MAX_SNIPPET:
                return compact
        except ValueError:
            pass
    lines = text.splitlines()
    if not lines:
        return None
    start = rng.randrange(len(lines)) if len(lines) > 12 else 0
    picked, size = [], 0
    for ln in lines[start:]:
        if size + len(ln) + 1 > MAX_SNIPPET and picked:
            break
        picked.append(ln[:MAX_SNIPPET])
        size += len(ln) + 1
        if size >= 160:
            break
    snippet = "\n".join(picked).strip()
    return snippet if MIN_SNIPPET <= len(snippet) <= MAX_SNIPPET else None


def load_system_text(roots=DEFAULT_SYSTEM_ROOTS, rng: random.Random | None = None, denylist=(),
                     per_kind: int = 400) -> list[dict]:
    """One snippet per sampled file of each kind (sh/conf/html/json/md) found under `roots`."""
    rng = rng or random.Random(0)
    by_kind: dict[str, list[str]] = {}
    for root in roots:
        if not os.path.isdir(root):
            continue
        for d, _dirs, names in os.walk(root):
            for n in sorted(names):
                kind = _KINDS.get(os.path.splitext(n)[1].lower())
                if kind:
                    by_kind.setdefault(kind, []).append(os.path.join(d, n))
    out: list[dict] = []
    for kind in sorted(by_kind):
        files = sorted(by_kind[kind])
        rng.shuffle(files)
        taken = 0
        for path in files:
            if taken >= per_kind:
                break
            try:
                if os.path.islink(path) or os.path.getsize(path) > _MAX_FILE_BYTES:
                    continue
                with open(path, "rb") as f:
                    raw = f.read(_MAX_FILE_BYTES)
            except OSError:
                continue
            if b"\x00" in raw:
                continue
            text = raw.decode("utf-8", errors="ignore")
            if _SECRET.search(text) or _denied(text, denylist):
                continue
            snippet = _snippet(text, kind, rng)
            if snippet is None or _SECRET.search(snippet) or _BLOB.search(snippet):
                continue
            taken += 1
            out.append({"text": snippet, "label": "clean", "source": f"sysfile:{kind}"})
    return out


# ---- data round 3: short, complete, benign developer snippets -------------------------------------
# tldr-pages (CC-BY-4.0), MDN interactive-examples (CC0), docker/awesome-compose (CC0) and
# b-mc2/sql-create-context (CC-BY-4.0). Each loader returns [] when its directory is absent and only
# touches `rng` once it has candidates, so a build without the corpora is unchanged byte for byte.
MAX_COMMAND = 300

# commands/snippets that look like an attack to the model (and to a human): never teach them as clean
_ATTACKISH = re.compile(
    r"(?i)\b(nc|ncat|netcat|socat)\b|/dev/(tcp|udp)|\|\s*(sudo\s+)?(ba|z|da)?sh\b|\bbash\s+-i\b"
    r"|/etc/(passwd|shadow)|\b(sqlmap|nikto|hydra|nmap|masscan|msfvenom|metasploit|mimikatz)\b"
    r"|base64\s+(-d|--decode)|\beval\b|<script|\bwhoami\b|\$\(\s*(id|whoami|uname|cat|ls|sleep)\b"
    r"|;\s*(cat|ls|id|wget|curl|rm)\b|javascript:|\bon[a-z]+\s*=|alert\s*\(|document\.(cookie|write)|innerHTML")
# template/expansion syntax (SSTI and command-substitution look-alikes), path traversal, and credentials baked
# into a flag or URL (placeholder or not, they teach "secret-shaped = clean")
_TEMPLATEISH = re.compile(r"\$\{|\$\(|\{\{|\{%|<%|\#\{|\.\./")
_CREDISH = re.compile(r"(?i)\bsshpass\b|(?:^|\s)-p\w{4,}|--(?:pass(?:word)?|pwd)(?:\s|=)\S|://[^/\s:@]+:[^/\s@]+@")
_PLACEHOLDER = re.compile(r"\{\{([^{}]*)\}\}")
_UNSAFE = re.compile(r"[^A-Za-z0-9_./:@%=+,~-]")


def _fill_placeholder(m: re.Match, rng: random.Random) -> str:
    inner = m.group(1).strip()
    if inner.startswith("[") and inner.endswith("]") and "|" in inner:    # {{[-a|--all]}}: short|long form
        return rng.choice([a.strip() for a in inner[1:-1].split("|") if a.strip()] or ["arg"])
    return _UNSAFE.sub("_", inner.replace('"', "").replace("'", "")) or "arg"


def _clean_candidate(text: str, denylist, lo: int = MIN_SNIPPET, hi: int = MAX_SNIPPET) -> bool:
    return (lo <= len(text) <= hi and not _ATTACKISH.search(text) and not _SECRET.search(text)
            and not _BLOB.search(text) and not _TEMPLATEISH.search(text) and not _CREDISH.search(text)
            and not has_strong_marker(text) and not _denied(text, denylist))


def _pick(cands: list[tuple[str, str]], rng: random.Random, n_max: int) -> list[dict]:
    """cands: (text, source) pairs. Sorted + deduped, then a seeded sample of at most n_max."""
    uniq = sorted(set(cands))
    if len(uniq) > n_max:
        uniq = sorted(rng.sample(uniq, n_max))
    return [{"text": t, "label": "clean", "source": s} for t, s in uniq]


def _read_text(path: str) -> str | None:
    try:
        if os.path.islink(path) or os.path.getsize(path) > _MAX_FILE_BYTES:
            return None
        with open(path, "rb") as f:
            raw = f.read(_MAX_FILE_BYTES)
    except OSError:
        return None
    return None if b"\x00" in raw else raw.decode("utf-8", errors="ignore")


def load_tldr(root: str, rng: random.Random, denylist=(), n_max: int = 4000) -> list[dict]:
    """Single-line command examples from root/tldr/pages/{common,linux}/*.md (the backticked lines)."""
    cands: list[tuple[str, str]] = []
    for platform in ("common", "linux"):
        d = os.path.join(root, "tldr", "pages", platform)
        if not os.path.isdir(d):
            continue
        for name in sorted(os.listdir(d)):
            text = _read_text(os.path.join(d, name)) if name.endswith(".md") else None
            for line in (text or "").splitlines():
                if not (line.startswith("`") and line.endswith("`") and len(line) > 2 and "`" not in line[1:-1]):
                    continue
                cmd = _PLACEHOLDER.sub(lambda m: _fill_placeholder(m, rng), line[1:-1]).strip()
                if "{{" not in cmd and "}}" not in cmd and _clean_candidate(cmd, denylist, hi=MAX_COMMAND):
                    cands.append((cmd, f"tldr:{platform}"))
    return _pick(cands, rng, n_max)


def load_mdn_examples(root: str, rng: random.Random, denylist=(), n_max: int = 3000) -> list[dict]:
    """Short HTML/CSS/JS examples (whole files, plus single HTML lines) from root/mdn_examples/live-examples."""
    base = os.path.join(root, "mdn_examples", "live-examples")
    if not os.path.isdir(base):
        return []
    kinds = {".html": "html", ".css": "css", ".js": "js"}
    cands: list[tuple[str, str]] = []
    for d, dirs, names in os.walk(base):
        dirs.sort()
        for name in sorted(names):
            kind = kinds.get(os.path.splitext(name)[1].lower())
            text = _read_text(os.path.join(d, name)) if kind else None
            if text is None:
                continue
            whole = text.strip()
            if _clean_candidate(whole, denylist):
                cands.append((whole, f"mdn:{kind}"))
            if kind == "html":
                for line in (l.strip() for l in text.splitlines()):
                    if line.startswith("<") and line != whole and _clean_candidate(line, denylist, hi=200):
                        cands.append((line, "mdn:html"))
    return _pick(cands, rng, n_max)


_COMPOSE_NAMES = ("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml")


def load_awesome_compose(root: str, rng: random.Random, denylist=(), n_max: int = 2000) -> list[dict]:
    """Real Docker Compose files from root/awesome_compose (whole file, or a block when it is long)."""
    base = os.path.join(root, "awesome_compose")
    if not os.path.isdir(base):
        return []
    cands: list[tuple[str, str]] = []
    for d, dirs, names in os.walk(base):
        dirs.sort()
        for name in sorted(names):
            if name.lower() not in _COMPOSE_NAMES:
                continue
            text = _read_text(os.path.join(d, name))
            if text is None or _SECRET.search(text) or _denied(text, denylist):
                continue
            whole = text.strip()
            snippet = whole if len(whole) <= MAX_SNIPPET else _snippet(text, "conf", rng)
            if snippet and _clean_candidate(snippet, denylist):
                cands.append((snippet, "compose:yaml"))
    return _pick(cands, rng, n_max)


_SQL_ATTACKISH = re.compile(
    r"(?i)\bunion\b|--|/\*|#|;|\bsleep\s*\(|\bbenchmark\b|information_schema|\bxp_|\bor\s+1\s*=\s*1|\bor\s+'")


def load_sql_create_context(root: str, rng: random.Random, denylist=(), n_max: int = 4000) -> list[dict]:
    """Complete SELECT statements (`answer`) and CREATE TABLE statements (`context`) from root/sql_create_context."""
    d = os.path.join(root, "sql_create_context")
    if not os.path.isdir(d):
        return []
    selects: set[str] = set()
    creates: set[str] = set()
    for name in sorted(os.listdir(d)):
        if not name.endswith(".json"):
            continue
        try:
            with open(os.path.join(d, name), "r", encoding="utf-8") as f:
                records = json.load(f)
        except (OSError, ValueError):
            continue
        if not isinstance(records, list):
            continue
        for rec in records:
            if not isinstance(rec, dict):
                continue
            for field, upper, bucket in (("answer", "SELECT", selects), ("context", "CREATE TABLE", creates)):
                s = rec.get(field)
                if (isinstance(s, str) and s.strip().upper().startswith(upper) and 8 <= len(s.strip()) <= MAX_COMMAND
                        and not _SQL_ATTACKISH.search(s) and not has_strong_marker(s)
                        and not _denied(s, denylist)):
                    bucket.add(s.strip())
    out: list[dict] = []
    for bucket, source in ((sorted(selects), "sqlctx:select"), (sorted(creates), "sqlctx:create")):
        take = rng.sample(bucket, min(n_max // 2, len(bucket))) if bucket else []
        for s in sorted(take):
            out.append({"text": s + (";" if rng.random() < 0.5 else ""), "label": "clean", "source": source})
    return out
