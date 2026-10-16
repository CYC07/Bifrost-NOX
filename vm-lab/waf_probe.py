"""How well does the WAF separate benign bodies (JSON logins etc.) from real attacks? Raw scores."""
import json, logging, os, sys
logging.disable(logging.CRITICAL)
sys.path.insert(0, os.getcwd())
from ml.waf.predictor import WAFClassifier

w = WAFClassifier(threshold=0.8)
assert w.load(), "WAF model failed to load"

BENIGN = {
 "json login (alice)": json.dumps({"username": "alice", "password": "hunter2"}),
 "json login (email)": json.dumps({"email": "bob@example.com", "password": "S3cure!pass"}),
 "json login spaced": '{"username": "alice", "password": "hunter2"}',
 "json register": json.dumps({"name": "Carol", "email": "c@example.com", "password": "pw123456", "age": 31}),
 "json search": json.dumps({"query": "best pizza near me", "page": 2}),
 "json token refresh": json.dumps({"refresh_token": "abc123def456", "grant_type": "refresh_token"}),
 "json telemetry": json.dumps({"deviceId": "abc123", "events": [{"t": 1, "n": "heartbeat"}]}),
 "json echo reply": '{"args": {}, "data": "", "files": {}, "form": {"username": "admin", "password": "secret123"}, "headers": {"Accept": "*/*", "Host": "httpbin.org"}, "url": "http://httpbin.org/post"}',
 "robots.txt": "User-agent: *\nDisallow: /admin\nSitemap: https://example.com/sitemap.xml",
 "form login": "username=admin&password=secret123&remember=true",
 "form search": "q=best pizza near me&sort=popularity",
 "form contact": "first_name=Michael&last_name=Chen&company=Acme%20Corp",
 "html snippet": "<html><body><h1>Welcome</h1><p>Hello, world</p></body></html>",
 "plain prose": "Please contact our support team if you have any questions.",
 "url path": "GET /static/css/site.css?v=3 HTTP/1.1",
}
ATTACKS = {
 "sqli or": "id=1' OR '1'='1' --",
 "sqli union": "id=1 UNION SELECT username, password FROM users--",
 "sqli json": json.dumps({"username": "admin' OR '1'='1' --", "password": "x"}),
 "xss script": "q=<script>alert(document.cookie)</script>",
 "xss img": "name=<img src=x onerror=alert(1)>",
 "traversal": "file=../../../../etc/passwd",
 "cmdi": "host=127.0.0.1; cat /etc/passwd",
 "cmdi json": json.dumps({"ip": "8.8.8.8 && whoami"}),
 "ssti": "name={{7*7}}{{config.items()}}",
 "scanner": "GET /wp-login.php?x=sqlmap HTTP/1.1\nUser-Agent: sqlmap/1.7",
}

def row(name, t):
    p = w.predict(t)
    sc = p.scores or {}
    clean = sc.get("clean", 0.0)
    return name, p.label, p.score, clean, p.blocked

print(f"{'BENIGN':22s} {'top':16s} {'score':>8s} {'p(clean)':>9s}  blocked")
b = [row(n, t) for n, t in BENIGN.items()]
for n, l, s, c, bl in b: print(f"{n:22s} {l:16s} {s:8.4f} {c:9.4f}  {'BLOCK' if bl else ''}")
print(f"\n{'ATTACK':22s} {'top':16s} {'score':>8s} {'p(clean)':>9s}  blocked")
a = [row(n, t) for n, t in ATTACKS.items()]
for n, l, s, c, bl in a: print(f"{n:22s} {l:16s} {s:8.4f} {c:9.4f}  {'BLOCK' if bl else 'MISS'}")

fp_scores = [s for n, l, s, c, bl in b if l != "clean"]
tp_scores = [s for n, l, s, c, bl in a if l != "clean"]
print(f"\nbenign flagged as attack: {len(fp_scores)}/{len(b)}  (their scores: {sorted(round(x,3) for x in fp_scores)})")
print(f"attacks flagged:          {len(tp_scores)}/{len(a)}  (lowest attack score: {min(tp_scores) if tp_scores else None})")
for th in (0.5, 0.8, 0.9, 0.95, 0.99):
    fp = sum(1 for n, l, s, c, bl in b if l != "clean" and s >= th)
    tp = sum(1 for n, l, s, c, bl in a if l != "clean" and s >= th)
    print(f"threshold {th:<5}: benign blocked {fp}/{len(b)}   attacks caught {tp}/{len(a)}")
