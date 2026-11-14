"""Does scoring JSON *values* (not the whole blob) fix the WAF false positives without retraining?"""
import json, logging, os, sys
logging.disable(logging.CRITICAL)
sys.path.insert(0, os.getcwd())
from ml.waf.predictor import WAFClassifier

w = WAFClassifier(threshold=0.8)
assert w.load()

def leaves(o):
    if isinstance(o, dict):
        for v in o.values(): yield from leaves(v)
    elif isinstance(o, list):
        for v in o: yield from leaves(v)
    elif isinstance(o, (str, int, float)) and str(o).strip():
        yield str(o)

def per_value(body):
    try: obj = json.loads(body)
    except Exception: return [body]
    return list(leaves(obj)) or [body]

BENIGN = {
 "json login": json.dumps({"username": "alice", "password": "hunter2"}),
 "json login email": json.dumps({"email": "bob@example.com", "password": "S3cure!pass"}),
 "json register": json.dumps({"name": "Carol", "email": "c@example.com", "password": "pw123456", "age": 31}),
 "json search": json.dumps({"query": "best pizza near me", "page": 2}),
 "json token refresh": json.dumps({"refresh_token": "abc123def456", "grant_type": "refresh_token"}),
 "json telemetry": json.dumps({"deviceId": "abc123", "events": [{"t": 1, "n": "heartbeat"}], "ver": "10.0.19045"}),
 "json echo reply": '{"args": {}, "data": "", "files": {}, "form": {"username": "admin", "password": "secret123"}, "headers": {"Accept": "*/*", "Host": "httpbin.org"}, "url": "http://httpbin.org/post"}',
 "json nested api": json.dumps({"user": {"id": 42, "prefs": {"theme": "dark", "lang": "en-US"}}, "items": [{"sku": "A-1", "qty": 2}]}),
 "json with url": json.dumps({"redirect": "https://example.com/account?tab=settings", "title": "O'Brien & Sons"}),
}
ATTACKS = {
 "sqli in json value": json.dumps({"username": "admin' OR '1'='1' --", "password": "x"}),
 "union in json": json.dumps({"id": "1 UNION SELECT username, password FROM users--"}),
 "xss in json": json.dumps({"comment": "<script>alert(document.cookie)</script>"}),
 "cmdi in json": json.dumps({"ip": "8.8.8.8 && whoami"}),
 "traversal in json": json.dumps({"file": "../../../../etc/passwd"}),
 "nested sqli": json.dumps({"filter": {"where": ["name", "=", "x' OR 1=1; DROP TABLE users;--"]}}),
 "ssti in json": json.dumps({"name": "{{7*7}}{{config.items()}}"}),
}
def verdict(body, mode):
    parts = [body] if mode == "whole" else per_value(body)
    preds = [w.predict(p) for p in parts]
    blk = [p for p in preds if p.blocked]
    return bool(blk), (blk[0].label if blk else "")

for name, items in (("BENIGN", BENIGN), ("ATTACK", ATTACKS)):
    print(f"\n{name:22s} {'whole-body':14s} {'per-value':14s}")
    for k, t in items.items():
        wb, wl = verdict(t, "whole"); pb, pl = verdict(t, "value")
        print(f"{k:22s} {('BLOCK '+wl) if wb else 'allow':14s} {('BLOCK '+pl) if pb else 'allow':14s}")
    for mode in ("whole", "value"):
        n = sum(verdict(t, mode)[0] for t in items.values())
        print(f"  -> {mode}: blocked {n}/{len(items)}")
