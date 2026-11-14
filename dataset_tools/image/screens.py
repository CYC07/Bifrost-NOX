"""Rendered-screenshot corpus generator for OCR evaluation.

Draws code / log / terminal screenshots with PIL across many installed fonts
(monospace AND sans), sizes and light/dark/syntax-coloured themes. Positive
images embed FAKE (randomly generated, never real) secrets and PII; benign
images contain secret-LOOKING but non-secret strings (UUIDs, hashes, base64,
vendor placeholder keys, dates, ids).

Everything is deterministic from a seed. Images are written OUTSIDE the repo
(default ~/FYP/corpora/image_screens) together with manifest.json:

    {"images": [{"file", "label": "secret"|"benign", "font", "mono", "size",
                 "theme", "scenario", "secrets": [{"kind", "text"}]}]}

CLI:  python -m dataset_tools.image.screens --out ~/FYP/corpora/image_screens
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import random
import re
import string
import uuid

from PIL import Image, ImageDraw, ImageFont

# (family label, is_monospace, candidate paths). First existing path wins; a
# family with no installed file is skipped, so the corpus adapts to the box.
FONT_CANDIDATES = [
    ("LiberationMono", True, ["/usr/share/fonts/liberation/LiberationMono-Regular.ttf",
                              "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf"]),
    ("FreeMono", True, ["/usr/share/fonts/gnu-free/FreeMono.otf",
                        "/usr/share/fonts/truetype/freefont/FreeMono.ttf"]),
    ("DejaVuSansMono", True, ["/usr/share/fonts/TTF/DejaVuSansMono.ttf",
                              "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"]),
    ("NimbusMono", True, ["/usr/share/fonts/gsfonts/NimbusMonoPS-Regular.otf"]),
    ("FiraCodeMono", True, ["/usr/share/fonts/TTF/FiraCodeNerdFontMono-Regular.ttf"]),
    ("JetBrainsMono", True, ["/usr/share/fonts/TTF/JetBrainsMonoNerdFontMono-Regular.ttf"]),
    ("AdwaitaMono", True, ["/usr/share/fonts/Adwaita/AdwaitaMono-Regular.ttf"]),
    ("DejaVuSans", False, ["/usr/share/fonts/TTF/DejaVuSans.ttf",
                           "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"]),
    ("LiberationSans", False, ["/usr/share/fonts/liberation/LiberationSans-Regular.ttf",
                               "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf"]),
    ("Carlito", False, ["/usr/share/fonts/carlito/Carlito-Regular.ttf"]),
    ("FiraSans", False, ["/usr/share/fonts/Fira_Sans/FiraSans-Regular.ttf"]),
]

SIZES = (12, 14, 18, 24)

THEMES = {
    "light_ide": dict(bg="#ffffff", fg="#24292e", comment="#6a737d", string="#032f62",
                      keyword="#d73a49", number="#005cc5", gutter="#8c959f", prompt="#22863a"),
    "dark_term": dict(bg="#0c0c0c", fg="#cccccc", comment="#767676", string="#13a10e",
                      keyword="#3a96dd", number="#c19c00", gutter="#555555", prompt="#16c60c"),
    "dark_ide": dict(bg="#272822", fg="#f8f8f2", comment="#75715e", string="#e6db74",
                     keyword="#f92672", number="#ae81ff", gutter="#90908a", prompt="#a6e22e"),
}

_ALNUM = string.ascii_letters + string.digits
_UP = string.ascii_uppercase + string.digits


def available_fonts():
    out = []
    for name, mono, paths in FONT_CANDIDATES:
        for p in paths:
            if os.path.exists(p):
                out.append((name, mono, p))
                break
    return out


# ---------------------------------------------------------------- fake secrets
def _luhn_card(rng: random.Random) -> str:
    digits = [4] + [rng.randint(0, 9) for _ in range(14)]
    total = 0
    for i, d in enumerate(reversed(digits)):
        d = d * 2 if i % 2 == 0 else d
        total += d - 9 if d > 9 else d
    digits.append((10 - total % 10) % 10)
    s = "".join(map(str, digits))
    return f"{s[:4]} {s[4:8]} {s[8:12]} {s[12:]}"


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def make_secret(kind: str, rng: random.Random) -> str:
    if kind == "aws":
        return "AKIA" + "".join(rng.choice(_UP) for _ in range(16))
    if kind == "github":
        return "ghp_" + "".join(rng.choice(_ALNUM) for _ in range(36))
    if kind == "stripe":
        return "sk_live_" + "".join(rng.choice(_ALNUM) for _ in range(24))
    if kind == "jwt":
        hdr = _b64u(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        pay = _b64u(json.dumps({"sub": str(rng.randint(10**7, 10**8)), "iat": 1700000000 + rng.randint(0, 10**6)}).encode())
        sig = _b64u(bytes(rng.randrange(256) for _ in range(32)))
        return f"{hdr}.{pay}.{sig}"
    if kind == "privkey":
        return "-----BEGIN RSA PRIVATE KEY-----"
    if kind == "dburl":
        pw = "".join(rng.choice(_ALNUM) for _ in range(12))
        return f"postgres://svc_app:{pw}@db{rng.randint(1, 9)}.corp.internal:5432/orders"
    if kind == "ssn":
        return f"{rng.randint(100, 665)}-{rng.randint(10, 99)}-{rng.randint(1000, 9999)}"
    if kind == "card":
        return _luhn_card(rng)
    raise ValueError(kind)


# Each template line has one {S} slot for the secret. Contexts are realistic
# code / config / log / terminal snippets.
_CODE_CTX = {
    "aws": ['AWS_ACCESS_KEY_ID = "{S}"', 'export AWS_ACCESS_KEY_ID={S}', 'aws_access_key_id = {S}'],
    "github": ['GITHUB_TOKEN="{S}"', 'git clone https://x:{S}@github.com/acme/api.git', 'token: {S}'],
    "stripe": ['stripe.api_key = "{S}"', 'STRIPE_SECRET={S}', 'const stripe = Stripe("{S}");'],
    "jwt": ['Authorization: Bearer {S}', 'session_token = "{S}"', 'curl -H "Authorization: Bearer {S}" $API'],
    "privkey": ['{S}', 'echo "{S}" > deploy.pem', 'head -1 id_rsa  # {S}'],
    "dburl": ['DATABASE_URL={S}', 'db = connect("{S}")', 'DATABASE_URL="{S}"'],
    "ssn": ['customer.ssn = "{S}"', 'INFO  applicant ssn {S} verified', 'SSN: {S}'],
    "card": ['card_number = "{S}"', 'INFO  charge card {S} amount=49.00', 'Card: {S}'],
}

_FILLER_CODE = [
    "# configuration loaded at startup", "import os, sys, json", "def load_config(path):",
    "    with open(path) as fh:", "        return json.load(fh)", "", "class Client:",
    "    def __init__(self, host, port=8080):", "        self.host = host", "        self.port = port",
    "    def request(self, route, retries=3):", "        for attempt in range(retries):",
    "            if self._ok(route):", "                return True", "        return False",
    "// TODO: rotate credentials", "const retries = 5;", "if (retries > 3) { log(\"retrying\"); }",
]
_FILLER_LOG = [
    "2026-10-31 09:12:44 INFO  server started on :8080", "2026-10-31 09:12:45 DEBUG loaded 42 routes",
    "2026-10-31 09:12:47 WARN  slow query 1280ms users.find", "2026-10-31 09:13:02 INFO  request id={u} 200 OK",
    "2026-10-31 09:13:09 INFO  worker 3 heartbeat ok", "2026-10-31 09:13:15 ERROR timeout contacting cache",
    "2026-10-31 09:13:16 INFO  retry 1/3 succeeded",
]
_FILLER_TERM = [
    "$ ls -la", "drwxr-xr-x  4 dev dev 4096 Oct 31 09:10 src", "-rw-r--r--  1 dev dev  812 Oct 31 09:10 README.md",
    "$ git status", "On branch main", "nothing to commit, working tree clean", "$ make build", "gcc -O2 -o app main.c",
    "$ ./app --version", "app 2.4.1",
]


def make_secret_lines(rng: random.Random, scenario: str):
    """Return (lines, secrets) for a 'code' or 'term' scenario."""
    if scenario == "code":
        kinds = ["aws", "github", "stripe", "dburl", "privkey"]
        filler = _FILLER_CODE
    else:
        kinds = ["jwt", "ssn", "card", "aws", "github"]
        filler = _FILLER_LOG + _FILLER_TERM
    secrets = []
    pool = [x.replace("{u}", str(uuid.UUID(int=rng.getrandbits(128)))) for x in filler]
    rng.shuffle(pool)
    out = []
    pi = 0
    # simple interleave: 3 filler lines between secret lines
    for kind in kinds:
        for _ in range(rng.randint(2, 3)):
            out.append(pool[pi % len(pool)]); pi += 1
        s = make_secret(kind, rng)
        out.append(rng.choice(_CODE_CTX[kind]).replace("{S}", s))
        secrets.append({"kind": kind, "text": s})
    out.append(pool[pi % len(pool)])
    return out, secrets


def make_benign_lines(rng: random.Random, scenario: str):
    """Secret-LOOKING but non-secret content."""
    b64 = base64.b64encode(bytes(rng.randrange(256) for _ in range(30))).decode()
    sha = "".join(rng.choice("0123456789abcdef") for _ in range(64))
    sha1 = sha[:40]
    u = lambda: str(uuid.UUID(int=rng.getrandbits(128)))  # noqa: E731
    # Vendor placeholder keys are real-looking but deliberately non-secret.
    ph_aws = "AKIA" + "IOSFODNN7" + "EXAMPLE"
    code = [
        "# Build metadata (generated, not secret)", f"BUILD_ID = \"{u()}\"", f"COMMIT = \"{sha1}\"",
        f"CHECKSUM_SHA256 = \"{sha}\"", f"ICON_DATA = \"{b64}\"", f"aws_access_key_id = {ph_aws}  # docs example",
        "def checksum(path):", "    h = hashlib.sha256()", "    with open(path, 'rb') as fh:",
        "        h.update(fh.read())", "    return h.hexdigest()", f"REQUEST_ID = \"{u()}\"",
        "order_id = 4821907356", "version = \"2.14.0-rc.3\"", "released = \"2026-10-31\"",
        "host = \"10.20.30.40\"  # internal LB", "ticket = \"PAY-1234-5678\"", f"etag = \"W/{sha[:32]}\"",
        "const url = \"https://example.com/api/v1/items?page=2&sort=name\";",
    ]
    log = [
        "2026-10-31 09:12:44 INFO  server started on :8080", f"2026-10-31 09:12:45 INFO  request id={u()} 200 OK",
        f"2026-10-31 09:12:46 DEBUG trace={sha[:32]} span={sha[32:48]}", f"2026-10-31 09:12:47 INFO  upload etag={b64[:24]} size=20480",
        "2026-10-31 09:12:48 WARN  slow query 1280ms users.find", f"2026-10-31 09:12:49 INFO  session {u()} opened",
        "2026-10-31 09:12:50 INFO  invoice 2026-000417 total=1,249.50 USD", "2026-10-31 09:12:51 INFO  phone ext 4421 transferred",
        f"2026-10-31 09:12:52 DEBUG image digest sha256:{sha}", "2026-10-31 09:12:53 INFO  zip 90210 shipping calculated",
        f"2026-10-31 09:12:54 INFO  placeholder key {ph_aws} ignored", "2026-10-31 09:12:55 INFO  build 8841-22-1307 queued",
    ]
    term = [
        "$ sha256sum release.tar.gz", f"{sha}  release.tar.gz", "$ uuidgen", u(), "$ git log -1 --format=%H", sha1,
        "$ echo $AWS_ACCESS_KEY_ID", ph_aws, "$ base64 < logo.png | head -c 40", b64, "$ date -I", "2026-10-31",
        "$ docker images --digests", f"app  latest  sha256:{sha[:48]}", "$ ls", "README.md  src  build  docs",
    ]
    docs = [
        "Release notes 2.14", "", "Fixes", " - Improved cache hit ratio by 12%", " - Resolved crash on empty config",
        f" - Tracking id {u()}", "", "Verification", f"   sha256: {sha}", "", "Contact the platform team for access.",
        "Issue PAY-1234-5678 and PAY-1235-0001 are closed.", f"Signature (base64): {b64}", "",
    ]
    src = {"code": code, "term": term + log[:5], "log": log, "docs": docs}
    return list(src.get(scenario, code))


# ------------------------------------------------------------------- rendering
_KW = re.compile(r"\b(def|class|import|return|if|for|in|with|const|export|from|else|True|False|None)\b")
_STR = re.compile(r"\"[^\"]*\"|'[^']*'")
_NUM = re.compile(r"\b\d[\d.,:-]*\b")


def _segments(line: str, theme: dict, scenario: str):
    """Split a line into (text, colour) runs: comment > string > keyword > number."""
    if line.startswith("$ ") and scenario in ("term", "code"):
        return [("$ ", theme["prompt"]), (line[2:], theme["fg"])]
    cidx = min([i for i in (line.find("#"), line.find("//")) if i >= 0] or [-1], default=-1)
    code, comment = (line, "") if cidx < 0 else (line[:cidx], line[cidx:])
    marks = []  # (start, end, colour)
    for rx, key in ((_STR, "string"), (_KW, "keyword"), (_NUM, "number")):
        for m in rx.finditer(code):
            if not any(a < m.end() and m.start() < b for a, b, _ in marks):
                marks.append((m.start(), m.end(), theme[key]))
    marks.sort()
    segs, pos = [], 0
    for a, b, c in marks:
        if a > pos:
            segs.append((code[pos:a], theme["fg"]))
        segs.append((code[a:b], c))
        pos = b
    if pos < len(code):
        segs.append((code[pos:], theme["fg"]))
    if comment:
        segs.append((comment, theme["comment"]))
    return segs


def render(lines, font_path: str, size: int, theme_name: str, scenario: str = "code",
           gutter: bool | None = None) -> Image.Image:
    theme = THEMES[theme_name]
    font = ImageFont.truetype(font_path, size)
    asc, desc = font.getmetrics()
    lh = int((asc + desc) * 1.25)
    pad = max(8, size)
    if gutter is None:
        gutter = theme_name.endswith("_ide")
    gw = int(font.getlength("000 ")) if gutter else 0
    width = pad * 2 + gw + max(int(font.getlength(l)) for l in lines) + 4
    height = pad * 2 + lh * len(lines)
    img = Image.new("RGB", (width, height), theme["bg"])
    d = ImageDraw.Draw(img)
    y = pad
    for n, line in enumerate(lines, 1):
        if gutter:
            d.text((pad, y), f"{n:>3}", fill=theme["gutter"], font=font)
        x = pad + gw
        for text, colour in _segments(line, theme, scenario):
            d.text((x, y), text, fill=colour, font=font)
            x += font.getlength(text)
        y += lh
    return img


def generate(out_dir: str, seed: int = 1337, sizes=SIZES, themes=None, per_cell: int = 2, fonts=None):
    """Write the corpus. Per (font, size, theme) cell: `per_cell` secret images
    (code + term scenarios) and `per_cell` benign images."""
    themes = themes or list(THEMES)
    os.makedirs(out_dir, exist_ok=True)
    items = []
    scenarios = ["code", "term"]
    for fname, mono, fpath in available_fonts():
        if fonts and fname not in fonts:
            continue
        for size in sizes:
            for theme in themes:
                for k in range(per_cell):
                    cell_seed = f"{seed}/{fname}/{size}/{theme}/{k}"
                    rng = random.Random(cell_seed)
                    sc = scenarios[k % 2]
                    lines, secrets = make_secret_lines(rng, sc)
                    items.append(_emit(out_dir, "secret", fname, mono, fpath, size, theme, sc, k, lines, secrets))
                    brng = random.Random(cell_seed + "/b")
                    bsc = ["code", "term", "log", "docs"][(k * 2 + (size // 6)) % 4]
                    items.append(_emit(out_dir, "benign", fname, mono, fpath, size, theme, bsc, k,
                                       make_benign_lines(brng, bsc), []))
    with open(os.path.join(out_dir, "manifest.json"), "w") as fh:
        json.dump({"seed": seed, "images": items}, fh, indent=1)
    return items


def _emit(out_dir, label, fname, mono, fpath, size, theme, scenario, k, lines, secrets):
    name = f"{label}_{fname}_{size}_{theme}_{scenario}{k}.png"
    render(lines, fpath, size, theme, scenario).save(os.path.join(out_dir, name))
    return {"file": name, "label": label, "font": fname, "mono": mono, "size": size,
            "theme": theme, "scenario": scenario, "secrets": secrets}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.expanduser("~/FYP/corpora/image_screens"))
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--per-cell", type=int, default=2)
    a = ap.parse_args()
    items = generate(a.out, a.seed, per_cell=a.per_cell)
    n_sec = sum(len(i["secrets"]) for i in items)
    print(f"wrote {len(items)} images ({n_sec} embedded fake secrets) to {a.out}")


if __name__ == "__main__":
    main()
