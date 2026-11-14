"""AUDIT - end to end: real router + real WAF through text_service, for the four ways an attack is delivered.

Recall per (class, carrier) must be >= 80% (the project's own held-out gate uses 0.80); the ordinary-traffic
false-positive rate must be <= 3%. The failure message lists exactly which payloads got through, so the
audit shows WHERE the WAF is blind, not just that it is.
"""
import json
import os
import random
from urllib.parse import quote

import pytest

from audit_helpers import blocked, target_blocked
from test_audit_predictor import BENIGN, CANON

HOLDOUT = os.path.expanduser("~/FYP/waf_datasets/build_v2/test_holdout.jsonl")


def bare(p):
    return p


def form(p):
    return f"q={quote(p, safe='')}&submit=Go"


def json_body(p):
    return json.dumps({"query": p, "page": 1})


def mixed_form(p):
    return f"name=Bob&email=bob%40example.com&comment={quote(p, safe='')}&remember=on"


CARRIERS = {"bare": bare, "form": form, "json": json_body, "mixed_form": mixed_form}


@pytest.mark.parametrize("carrier", sorted(CARRIERS))
@pytest.mark.parametrize("label", sorted(CANON))
def test_recall_by_class_and_carrier(svc, label, carrier):
    wrap = CARRIERS[carrier]
    miss = [p for p in CANON[label] if not blocked(svc, wrap(p))]
    rate = 1 - len(miss) / len(CANON[label])
    assert rate >= 0.8, f"{label} via {carrier}: recall {rate:.0%}; not blocked: {miss}"


@pytest.mark.parametrize("label", ["sqli", "xss", "path_traversal", "command_injection"])
def test_recall_as_a_request_target_query_string(svc, label):
    miss = [p for p in CANON[label] if not target_blocked(svc, "/search?q=" + quote(p, safe=""))]
    rate = 1 - len(miss) / len(CANON[label])
    assert rate >= 0.8, f"{label} via query string: recall {rate:.0%}; not blocked: {miss}"


def test_ordinary_traffic_false_positive_rate_across_carriers(svc):
    texts = [t for group in BENIGN.values() for t in group]
    fp = []
    for t in texts:
        for name, wrap in CARRIERS.items():
            if blocked(svc, wrap(t)):
                fp.append((name, t[:50]))
    total = len(texts) * len(CARRIERS)
    assert len(fp) / total <= 0.03, f"{len(fp)}/{total} benign bodies blocked: {fp[:12]}"


ORDINARY_BODIES = [
    "username=alice&password=Passw0rd%21&remember=on", "q=best+pizza+near+me&sort=popularity",
    "first_name=Michael&last_name=O%27Connor&company=Acme%20Corp", "email=bob%40example.com&subject=Hello&message=Can+we+meet+at+3pm%3F",
    '{"username":"alice","password":"hunter2"}', '{"items":[{"sku":"A1","qty":2},{"sku":"B2","qty":1}],"note":"gift wrap, please"}',
    '{"title":"Q&A: it\'s 5\\" wide","body":"<p>Hello <b>world</b></p>"}', "from=2026-10-01T00%3A00%3A00Z&to=2026-10-31T23%3A59%3A59Z",
    "street=221B%20Baker%20St.&city=London&note=ring%20bell%20twice", "comment=I%27m%20happy%20with%20it%2C%20thanks%21",
    "code=for%20f%20in%20*.txt%3B%20do%20echo%20%24f%3B%20done", "bio=I%20love%20SELECT%20statements%20and%20UNION%20stations",
    '{"query":"how do I use the UNION operator in SQL?"}', '{"cmd":"ls -la"}', "path=%2Fhome%2Fuser%2Fdocuments%2Freport.pdf",
    "html=%3Cp%3EHello%3C%2Fp%3E", "regex=%5E%5Ba-z%5D%2B%24", "price=%245.00&currency=USD", "csv=a%2Cb%2Cc%0A1%2C2%2C3",
    '{"template":"Hello {{ name }}, welcome!"}', "markdown=%23+Title%0A%0ASome+*text*",
]


def test_ordinary_form_and_json_bodies_are_not_blocked(svc):
    fp = [b for b in ORDINARY_BODIES if blocked(svc, b)]
    assert len(fp) / len(ORDINARY_BODIES) <= 0.03, f"{len(fp)}/{len(ORDINARY_BODIES)} ordinary bodies blocked: {fp}"


# ---------------------------------------------------------------- independent real attacks (held out of v1 training)
def _holdout(label, n=60, seed=5):
    rows = []
    with open(HOLDOUT, encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if r["label"] == label and r["shape"] == "bare" and r["source"].split(":")[0] in ("crs", "fuzzdb"):
                rows.append(r["text"])
    random.Random(seed).shuffle(rows)
    return rows[:n]


@pytest.mark.skipif(not os.path.exists(HOLDOUT), reason="held-out set not built on this machine")
@pytest.mark.parametrize("carrier", ["bare", "form"])
@pytest.mark.parametrize("label", ["sqli", "xss", "path_traversal", "command_injection", "ssti", "scanner"])
def test_recall_on_real_held_out_payloads(svc, label, carrier):
    pay = _holdout(label)
    if len(pay) < 10:
        pytest.skip(f"only {len(pay)} held-out {label} payloads")
    miss = [p for p in pay if not blocked(svc, CARRIERS[carrier](p))]
    rate = 1 - len(miss) / len(pay)
    assert rate >= 0.8, f"{label} via {carrier}: recall {rate:.0%} on {len(pay)} real held-out payloads; e.g. missed {[m[:60] for m in miss[:6]]}"


ORDINARY_TARGETS = [
    "/api/items?page=2&sort=name", "/search?q=best+pizza", "/oauth/callback?code=abc123&state=xyz", "/p?utm_source=news&utm_medium=email",
    "/p?q=caf%C3%A9", "/p?ids=1,2,3", "/p?redirect=https://example.com/home", "/p?id=dGVzdA==", "/docs/../images/logo.png",
    "/search?q=O%27Brien", "/search?q=select+a+plan", "/search?q=union+station", "/p?price=%245.00&cur=USD", "/p?name=Smith+%26+Sons",
    "/p?from=2026-10-01T00%3A00%3A00Z&to=2026-10-31T23%3A59%3A59Z", "/p?next=%2Faccount%3Ftab%3Dbilling%26id%3D42", "/p?q=how+to+use+sudo",
    "/p?html=%3Cb%3Ebold%3C%2Fb%3E", "/p?lang=en-US&tz=Europe%2FBerlin", "/p?file=report_final(2).pdf",
]


def test_ordinary_request_targets_are_not_blocked(svc):
    fp = [u for u in ORDINARY_TARGETS if target_blocked(svc, u)]
    assert len(fp) / len(ORDINARY_TARGETS) <= 0.03, f"{len(fp)}/{len(ORDINARY_TARGETS)} ordinary targets blocked: {fp}"
