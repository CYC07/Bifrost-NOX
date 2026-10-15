"""Request-target (path + query) inspection: precision first.

Only values with an *active* character reach the WAF model; plain URLs, tokens, comma lists and
non-ASCII text are skipped (measured: sending every value to the model gave 5 false positives on
28 ordinary targets - JWT, fields=id,name,email, a Chinese search term, an OAuth redirect URL).
Path traversal and sensitive files are caught by high-precision regex instead of the model.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ml.waf import target as T  # noqa: E402

BENIGN = [
    "/search?q=best+pizza+near+me&page=2", "/get?q=hello", "/watch?v=dQw4w9WgXcQ&t=42s",
    "/product?id=123&utm_source=google&utm_medium=cpc&utm_campaign=spring_sale",
    "/oauth/authorize?client_id=abc123&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&response_type=code&scope=openid+profile&state=xyz789",
    "/login?next=/account/settings", "/login?continue=https://accounts.example.com/signin?a=1&b=2",
    "/api/items?fields=id,name,email&sort=-created&limit=50", "/track?cb=1696843200000&ref=https%3A%2F%2Fwww.google.com%2F",
    "/jsonp?callback=jQuery1124035&_=1696843200123", "/img?src=%2Fstatic%2Fphoto%20name.jpg&w=300&h=200",
    "/auth?token=abc.def-ghi_jklMNOpqr0123456789",          # opaque token, not a secret pattern
    "/session?sid=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "/cal?date=2026-10-09&tz=America%2FNew_York", "/files?path=docs/report_2026.pdf&download=1",
    "/s?wd=%E4%BD%A0%E5%A5%BD&ie=utf-8", "/mail?to=bob%40example.com&subject=Hello+there",
    "/maps?q=40.7128,-74.0060&z=12", "/cdn/app.js?v=3.2.1&build=abcdef0", "/ping?host=example.com",
    "/health", "/index.html", "/api/v1/users/42/posts?include=comments&per_page=20",
    "/redirect?url=http%3A%2F%2Fexample.com%2Fhome", "/shop?cat=shoes&price=10-50&color=black%2Cwhite",
    "/.well-known/acme-challenge/abc_DEF-123", "/a/b/c/../d.html",
]
ATTACKS = [
    "/item?id=1%27%20OR%20%271%27%3D%271%27%20--", "/item?id=1%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--",
    "/search?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E", "/img?src=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
    "/download?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd", "/download?file=....//....//etc/passwd", "/../../../../etc/passwd",
    "/ping?host=127.0.0.1%3B%20cat%20%2Fetc%2Fpasswd", "/run?cmd=whoami%20%26%26%20id",
    "/tpl?name=%7B%7B7*7%7D%7D%7B%7Bconfig.items()%7D%7D", "/cgi-bin/test.cgi?x=%27%3B%20DROP%20TABLE%20users%3B--",
    "/login?user=admin%27--&pass=x",
]


@pytest.mark.parametrize("t", BENIGN)
def test_ordinary_targets_are_not_interesting(t):
    assert T.waf_values(t) == [] and T.signature_hits(t) == [] and not T.is_interesting(t)


@pytest.mark.parametrize("t", ATTACKS)
def test_attack_targets_are_interesting(t):
    assert T.is_interesting(t)


# --- secrets in the URL must reach the analyzer (the pre-filter used to ignore them) ----------
AWS = "AKIA" + "IOSFODNN7REALKEYX"
JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." "eyJzdWIiOiIxMjM0NTY3ODkwIn0." "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")


@pytest.mark.parametrize("t", [
    f"/export?api_key={AWS}&format=csv",                 # no active character at all
    f"/auth?token={JWT}",                                 # advisory downstream, but must be seen
    f"/cb?x=ghp_{'A1b2C3d4E5' * 3}F6g7H8",
    f"/p?next=%2Fa%3Fkey%3D{AWS}",                        # encoded
])
def test_targets_containing_secrets_are_interesting(t):
    assert T.is_interesting(t)


def test_a_secret_alone_does_not_send_values_to_the_waf_model():
    assert T.waf_values(f"/export?api_key={AWS}") == []        # secrets go to the secrets analyzer
    assert T.secret_hits(f"/export?api_key={AWS}") == ["AWS Access Key"]


def test_secret_hits_do_not_contain_the_secret():
    assert AWS not in repr(T.secret_hits(f"/export?api_key={AWS}"))


# --- decoding ----------------------------------------------------------------
def test_values_are_percent_decoded_and_plus_is_a_space():
    assert T.waf_values("/q?a=x%27%20OR%20%271%27%3D%271") == ["x' OR '1'='1"]
    assert T.waf_values("/q?a=1+UNION+SELECT+1,2") == ["1 UNION SELECT 1,2"]


def test_double_encoding_is_decoded():
    assert T.waf_values("/q?f=%2527%2520OR%25201%253D1--") == ["' OR 1=1--"]
    assert "path_traversal" in T.signature_hits("/d?f=%252e%252e%252f%252e%252e%252fetc")


def test_repeated_or_blank_params_and_fragments():
    assert T.waf_values("/q?a=<b>&a=<i>&c=&d") == ["<b>", "<i>"]
    assert T.waf_values("/page#frag'x") == []     # fragments never reach the server


# --- precision filters -----------------------------------------------------------
def test_plain_url_values_are_skipped_but_urls_with_markup_are_not():
    # these URLs contain active characters ( ) $ — only the plain-URL rule keeps them away from the model
    assert T.waf_values("/r?u=https%3A%2F%2Fa.example%2Fp%3Fx%3D(1)%24y") == []
    assert T.waf_values("/r?u=https%3A%2F%2Fa.example%2Ffn(arg)") == []
    assert T.waf_values("/r?u=https%3A%2F%2Fa.example%2Fp%3Fx%3D1%26y%3D2") == []
    assert T.waf_values("/r?u=http%3A%2F%2Fa.example%2F%3Cscript%3E") != []
    assert T.waf_values("/r?u=http%3A%2F%2Fa.example%2F%27+OR+1%3D1") != []


def test_sql_phrases_without_special_characters_still_reach_the_model():
    assert T.waf_values("/i?id=1%20UNION%20SELECT%201,2,3") != []
    assert T.waf_values("/i?id=1;SLEEP(5)") != []
    assert T.waf_values("/i?id=1%20and%20benchmark(1000000,md5(1))") != []


def test_apostrophe_and_ampersand_in_a_name_reaches_the_model_but_is_not_a_signature():
    t = "/p?name=O%27Brien+%26+Sons"
    assert T.waf_values(t) == ["O'Brien & Sons"] and T.signature_hits(t) == []


# --- signatures ------------------------------------------------------------------------
@pytest.mark.parametrize("t", [
    "/../../../../etc/passwd", "/d?f=..%2F..%2Fsecret", "/d?f=..\\..\\windows\\win.ini",
    "/d?file=/etc/passwd", "/d?file=C:\\windows\\win.ini", "/d?f=/proc/self/environ", "/x/%2e%2e/%2e%2e/etc/shadow",
])
def test_traversal_and_sensitive_file_signatures(t):
    assert T.signature_hits(t), t


@pytest.mark.parametrize("t", [
    "/a/b/c/../d.html", "/docs?page=etc", "/blog/how-the-etc-passwd-file-works", "/files?path=docs/report.pdf",
    "/static/../static/app.js",
])
def test_single_dotdot_and_innocent_words_do_not_match(t):
    assert T.signature_hits(t) == []


def test_path_alone_is_checked_for_signatures_not_the_model():
    assert T.waf_values("/../../../../etc/passwd") == []        # handled by signatures
    assert T.signature_hits("/../../../../etc/passwd") != []


def test_malformed_targets_never_raise():
    for t in ("", "?", "??&&==", "/%zz?x=%", "/\x00", "http://[::1", "/q?" + "a=1&" * 5000):
        T.is_interesting(t)
        T.waf_values(t)
        T.signature_hits(t)


def test_value_count_and_length_are_capped():
    assert len(T.waf_values("/q?" + "&".join(f"k{i}=%27x" for i in range(500)))) <= T.MAX_VALUES
    assert all(len(v) <= T.MAX_VALUE_CHARS for v in T.waf_values("/q?a=%27" + "x" * 100000))
