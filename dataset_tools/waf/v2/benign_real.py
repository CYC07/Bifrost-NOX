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
