"""How does the WAF behave on request targets (path + query)? Whole-target vs per-value."""
import logging, os, sys
from urllib.parse import urlsplit, parse_qsl, unquote
logging.disable(logging.CRITICAL)
sys.path.insert(0, os.getcwd())
from ml.waf.predictor import WAFClassifier
w = WAFClassifier(threshold=0.8); assert w.load()

BENIGN = [
 "/search?q=best+pizza+near+me&page=2", "/get?q=hello", "/watch?v=dQw4w9WgXcQ&t=42s",
 "/product?id=123&utm_source=google&utm_medium=cpc&utm_campaign=spring_sale",
 "/oauth/authorize?client_id=abc123&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&response_type=code&scope=openid+profile&state=xyz789",
 "/login?next=/account/settings", "/login?continue=https://accounts.example.com/signin?a=1&b=2",
 "/api/items?fields=id,name,email&sort=-created&limit=50", "/track?cb=1696843200000&ref=https%3A%2F%2Fwww.google.com%2F",
 "/jsonp?callback=jQuery1124035&_=1696843200123", "/img?src=%2Fstatic%2Fphoto%20name.jpg&w=300&h=200",
 "/auth?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
 "/session?sid=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
 "/page?lang=en-US&theme=dark&name=O%27Brien+%26+Sons", "/cal?date=2026-10-09&tz=America%2FNew_York",
 "/files?path=docs/report_2026.pdf&download=1", "/s?wd=%E4%BD%A0%E5%A5%BD&ie=utf-8", "/mail?to=bob%40example.com&subject=Hello+there",
 "/maps?q=40.7128,-74.0060&z=12", "/cdn/app.js?v=3.2.1&build=abcdef0", "/ping?host=example.com", "/health", "/index.html",
 "/api/v1/users/42/posts?include=comments&per_page=20", "/redirect?url=http%3A%2F%2Fexample.com%2Fhome",
 "/shop?cat=shoes&price=10-50&color=black%2Cwhite", "/.well-known/acme-challenge/abc_DEF-123", "/a/b/c/../d.html",
]
ATTACKS = [
 "/item?id=1%27%20OR%20%271%27%3D%271%27%20--", "/item?id=1%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--",
 "/search?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E", "/img?src=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
 "/download?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd", "/download?file=....//....//etc/passwd", "/../../../../etc/passwd",
 "/ping?host=127.0.0.1%3B%20cat%20%2Fetc%2Fpasswd", "/run?cmd=whoami%20%26%26%20id", "/tpl?name=%7B%7B7*7%7D%7D%7B%7Bconfig.items()%7D%7D",
 "/cgi-bin/test.cgi?x=%27%3B%20DROP%20TABLE%20users%3B--", "/login?user=admin%27--&pass=x",
]

def values(target):
    sp = urlsplit(target)
    vals = [v for _, v in parse_qsl(sp.query, keep_blank_values=False)]
    path = unquote(sp.path)
    return ([path] if ("%" in sp.path or ".." in path) else []) + [unquote(v) for v in vals]

def blocked_whole(t):
    return w.predict(unquote(t)).blocked
def blocked_values(t):
    r = [w.predict(v) for v in values(t) if v.strip()]
    b = [p for p in r if p.blocked]
    return (b[0].label, [v for v in values(t)][0][:30]) if b else None

fw = fv = 0
print("BENIGN (whole-target | per-value)")
for t in BENIGN:
    a = blocked_whole(t); b = blocked_values(t); fw += bool(a); fv += bool(b)
    if a or b: print(f"  {'BLOCK' if a else 'allow':5s} | {('BLOCK '+b[0]) if b else 'allow':22s} {t[:78]}")
print(f"  -> false positives: whole={fw}/{len(BENIGN)}  per-value={fv}/{len(BENIGN)}")
tw = tv = 0
print("ATTACKS")
for t in ATTACKS:
    a = blocked_whole(t); b = blocked_values(t); tw += bool(a); tv += bool(b)
    print(f"  {'BLOCK' if a else 'MISS ':5s} | {('BLOCK '+b[0]) if b else 'MISS':22s} {t[:78]}")
print(f"  -> caught: whole={tw}/{len(ATTACKS)}  per-value={tv}/{len(ATTACKS)}")
