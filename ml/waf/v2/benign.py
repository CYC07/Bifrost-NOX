"""Benign value generator, heavy on hard negatives.

Real clean traffic is not just words: names with apostrophes, SQL/shell-ish *prose* ("Select your
plan", "Union Station"), benign HTML, file paths, URLs, JSON-in-strings, quoted text. v1's clean
class lacked these shapes, so the model keyed on punctuation. Values only; the carrier is added by
shapes.py exactly as for attacks.
"""
from __future__ import annotations

import base64
import random
import uuid

from faker import Faker

_APOS_NAMES = ["O'Brien", "D'Angelo", "N'Golo Kanté", "McDonald's", "O'Connor & Sons", "L'Oréal Paris",
               "Rock 'n' Roll", "Dunkin' Donuts", "Jean-Luc Picard", "St. John's Wort"]
_SQLISH = ["Select your plan: monthly or yearly", "Union Station, Washington DC", "drop shadow effect",
           "insert coupon code here", "update my profile", "delete my account", "where to buy",
           "order by price ascending", "from London to Paris", "1 or 2 items", "Is 5 > 3 or 2 < 4?",
           "create new project", "alter table settings (dining)", "exec summary", "like and subscribe",
           "having a great time", "join the team", "truncate long text", "and then there were none",
           "SELECT a color", "Table of contents", "Grant access to a friend", "union of states"]
_HTML = ["<p>Hello <b>world</b></p>", '<a href="https://example.com/page">read more</a>', "<br>",
         "<ul><li>one</li><li>two</li></ul>", "<h1>Title</h1>", "<em>note</em>: see below",
         '<img src="/static/logo.png" alt="logo">', "<div class=\"card\">Welcome</div>", "<span>5 &lt; 7</span>"]
_PATHS = ["/var/log/app.log", "/usr/local/bin/python3", "C:\\Program Files\\App\\run.exe", "docs/readme.md",
          "~/projects/site/index.html", "../images/photo.jpg", "src/main/java/App.java", "/home/user/notes.txt"]
_CODEISH = ["function add(a, b) { return a + b; }", "const total = items.reduce((s, i) => s + i.price, 0);",
            "if (user && user.active) { show(); }", "print('hello world')", "x = [i * 2 for i in range(10)]",
            "SELECT is a keyword in SQL", "background: url(img/bg.png) no-repeat;", "@media (max-width: 600px)"]
_QUOTED = ['He said "hello" and left', "it's fine", '5" screen, 2" bezel', "she said 'maybe' twice",
           "Use \"quotes\" and 'apostrophes'", "100% sure; a=b&c=d", "50% off -- today only", "R&D / QA; ops"]


_USERS = ["admin", "root", "guest", "test", "administrator", "user", "demo", "support", "john", "alice"]
_PASSES = ["password", "secret123", "admin123", "123456", "letmein", "qwerty", "Passw0rd!", "changeme", "welcome1", "hunter2"]
_UKEYS = [("username", "password"), ("user", "pass"), ("login", "passwd"), ("email", "password")]
_EXTRA = ["remember=true", "remember=on", "csrf_token=a1b2c3d4e5", "submit=Login", "lang=en", "redirect=%2Fhome", ""]


def credential_forms(n: int, seed: int = 42) -> list[str]:
    """Whole login bodies with the most common (and SQLi-looking) usernames/passwords, as
    form-encoded and JSON. 'admin' is such a strong SQLi token that without these the model
    flags `username=admin&password=secret123`."""
    rng = random.Random(seed)
    out: list[str] = []
    seen: set[str] = set()
    tries = 0
    while len(out) < n and tries < n * 20:
        tries += 1
        uk, pk = rng.choice(_UKEYS)
        u, p = rng.choice(_USERS), rng.choice(_PASSES)
        if uk == "email":
            u = f"{u}@example.com"
        if rng.random() < 0.7:
            parts = [f"{uk}={u}", f"{pk}={p}"]
            extra = [e for e in rng.sample(_EXTRA, rng.randint(0, 2)) if e]
            body = "&".join(parts + extra)
        else:
            import json as _json
            body = _json.dumps({uk: u, pk: p, **({"remember": True} if rng.random() < 0.4 else {})})
        if body not in seen:
            seen.add(body)
            out.append(body)
    return out


def generate(n: int, seed: int = 42, pool: list[str] | None = None) -> list[str]:
    rng = random.Random(seed)
    fake = Faker("en_US")
    Faker.seed(seed)
    fake.seed_instance(seed)
    pool = pool or []

    def one() -> str:
        r = rng.random()
        if r < 0.10:
            return fake.name()
        if r < 0.14:
            return rng.choice(_APOS_NAMES)
        if r < 0.20:
            return rng.choice([fake.email, fake.user_name, fake.domain_name, fake.url])()
        if r < 0.32:
            return fake.sentence(nb_words=rng.randint(2, 14))
        if r < 0.37:
            return fake.paragraph(nb_sentences=rng.randint(1, 3))
        if r < 0.42:
            return rng.choice([fake.address, fake.phone_number, fake.company, fake.job])().replace("\n", ", ")
        if r < 0.47:
            return rng.choice([fake.iso8601, fake.date, fake.time])()
        if r < 0.51:
            return rng.choice([lambda: str(uuid.UUID(int=rng.getrandbits(128))),
                               lambda: "%032x" % rng.getrandbits(128),
                               lambda: base64.b64encode(rng.randbytes(rng.randint(6, 24))).decode()])()
        if r < 0.55:
            return rng.choice([f"${rng.randint(1, 999)}.{rng.randint(0, 99):02d}", f"{rng.randint(1, 9)},{rng.randint(100, 999)}.00",
                               f"{rng.randint(1, 100)}%", str(rng.randint(0, 10**6))])
        if r < 0.62:
            return rng.choice(_SQLISH)
        if r < 0.68:
            return rng.choice(_HTML)
        if r < 0.73:
            return rng.choice(_PATHS)
        if r < 0.78:
            return rng.choice(_CODEISH)
        if r < 0.84:
            return rng.choice(_QUOTED)
        if r < 0.88:
            return fake.password(length=rng.randint(8, 16), special_chars=True)
        if pool:
            return rng.choice(pool)
        return fake.sentence()

    out: list[str] = []
    seen: set[str] = set()
    attempts = 0
    while len(out) < n and attempts < n * 4:
        attempts += 1
        v = one().strip()
        if 3 <= len(v) <= 400 and v not in seen:
            seen.add(v)
            out.append(v)
    return out
