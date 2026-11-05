"""AUDIT - ml/waf/target.py: the cheap request-target / body pre-filter. Pure functions, no model.

Each test states what a WAF filter SHOULD do. The module documents itself as "precision first", so
misses on exotic input are the price of that design; the audit still lists them so the trade is explicit.
"""
import pytest

from ml.waf import target as t


# ---------------------------------------------------------------- _decode / decode_text
@pytest.mark.parametrize("raw,want", [
    ("%2e%2e%2f", "../"),
    ("%252e%252e%252f", "../"),                     # double encoding is decoded
    ("a+b", "a b"),                                 # '+' is a space in a query
    ("%zz", "%zz"),                                 # invalid escape stays as is
    ("100%", "100%"),
    ("%", "%"),
    ("%00", "\x00"),
    ("", ""),
])
def test_decode_basic_cases(raw, want):
    assert t._decode(raw) == want


def test_decode_reaches_a_fixpoint_for_triple_encoding():
    """Three layers (rare, but it is a known bypass of two-pass decoders)."""
    assert t._decode("%25252e%25252e%25252f") == "../"


def test_decode_overlong_utf8_does_not_raise_and_marks_bad_bytes():
    out = t._decode("%c0%ae%c0%ae/")
    assert "\ufffd" in out


def test_decode_text_keeps_plus_but_decodes_escapes():
    assert t.decode_text("a+b%27c") == "a+b'c"
    assert t.decode_text("%2527") == "'"            # twice


def test_decode_survives_huge_input_quickly():
    import time
    s = "%41" * 200_000
    t0 = time.perf_counter()
    assert len(t._decode(s)) == 200_000
    assert time.perf_counter() - t0 < 1.0


# ---------------------------------------------------------------- _split
@pytest.mark.parametrize("target,path,query", [
    ("/a/b?x=1&y=2", "/a/b", "x=1&y=2"),
    ("/a/b", "/a/b", ""),
    ("http://h.example/p?q=1#frag", "/p", "q=1"),
    ("/p?q=1#frag?not=query", "/p", "q=1"),
    ("", "", ""),
    (None, "", ""),
])
def test_split_paths_queries_and_fragments(target, path, query):
    assert t._split(target) == (path, query)


def test_split_malformed_ipv6_host_falls_back_instead_of_raising():
    p, q = t._split("http://[::1/x?id=1' OR 1=1--")
    assert "id=1" in q


def test_split_truncates_absurdly_long_targets():
    p, q = t._split("/p?" + "a=1&" * 100_000)
    assert len(q) <= 16384


# ---------------------------------------------------------------- waf_values
def test_plain_urls_are_not_sent_to_the_model():
    assert t.waf_values("/cb?next=https://example.com/home?tab=1") == []


def test_active_values_are_kept_and_decoded():
    assert t.waf_values("/s?q=1%27%20OR%20%271%27%3D%271") == ["1' OR '1'='1"]


def test_keys_without_values_and_empty_values_are_ignored():
    assert t.waf_values("/s?flag&q=&x=1'") == ["1'"]


def test_repeated_parameters_are_all_inspected():
    assert t.waf_values("/s?a=1'&a=2'") == ["1'", "2'"]


def test_value_cap_is_64_and_each_value_is_truncated_to_2000():
    q = "&".join(f"a{i}=x'" for i in range(200))
    assert len(t.waf_values("/s?" + q)) == 64
    assert len(t.waf_values("/s?q=" + "'" * 5000)[0]) == 2000


def test_padding_with_64_harmless_active_values_cannot_hide_a_payload():
    """Fill the 64-slot budget with ordinary O'Brien-style values, put the payload at position 65."""
    pad = "&".join(f"n{i}=O%27Brien" for i in range(64))
    payload = "1%27%20UNION%20SELECT%20password%20FROM%20users--"
    got = t.waf_values(f"/s?{pad}&id={payload}")
    assert any("UNION SELECT" in v for v in got), "payload at slot 65 was dropped by the value cap"


def test_payload_after_long_benign_padding_inside_one_value_is_still_inspected():
    v = "A" * 2100 + "' OR 1=1--"
    parts = t.waf_values("/s?q=" + v)
    assert any("OR 1=1" in p for p in parts), "payload past char 2000 was truncated away"


def test_parameter_names_are_inspected_too():
    """Servers read parameter NAMES as input as well (PHP, Rails arrays, JSON keys)."""
    assert t.is_interesting("/s?<script>alert(1)</script>=1")


def test_payload_hidden_in_the_url_path_is_inspected():
    assert t.is_interesting("/user/1'%20OR%20'1'='1/profile")


def test_command_substitution_inside_a_url_valued_parameter_is_inspected():
    assert t.is_interesting("/fetch?u=http://a.example/$(id)")


# ---------------------------------------------------------------- worth_scoring
ACTIVE_CHARS = ["'", '"', "`", "<", ">", ";", "|", "&", "$", "(", ")", "{", "}", "\\", "..", "\x00"]


@pytest.mark.parametrize("ch", ACTIVE_CHARS)
def test_each_documented_active_character_is_worth_scoring(ch):
    assert t.worth_scoring(f"a{ch}b")


@pytest.mark.parametrize("phrase", [
    "1 UNION SELECT 1,2", "1 union   all select 2", "select name from users", "drop table x", "insert into t values",
    "delete from t", "x sleep(5)", "benchmark(1,2)", "xp_cmdshell", "exec(", "UnIoN\tSeLeCt 1", "union%0aselect 1",
])
def test_sql_phrases_are_worth_scoring(phrase):
    assert t.worth_scoring(t.decode_text(phrase))


@pytest.mark.parametrize("benign", [
    "hello world", "john.doe@example.com", "2026-11-05", "a,b,c", "naïve café", "100", "best pizza near me",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJl", "dGVzdA==", "https://example.com/a?b=c",
])
def test_ordinary_values_are_left_alone(benign):
    assert not t.worth_scoring(benign)


@pytest.mark.parametrize("evasion", [
    "1 OR 1=1",                         # numeric boolean tautology: no quote, no active character
    "1 AND 1=1",
    "1 ORDER BY 5",                     # column-count probing
    "1 UNION/**/SELECT/**/user",        # comment as whitespace
    "1 UN/**/ION SEL/**/ECT 1",
    "1 HAVING 1=1",
])
def test_classic_sqli_without_quotes_is_worth_scoring(evasion):
    assert t.worth_scoring(evasion)


# ---------------------------------------------------------------- is_form / body_values
@pytest.mark.parametrize("body,expected", [
    ("a=1&b=2", True), ("/p?a=1", True), ("user.name[0]=x", True), ('{"a": 1}', False), ("plain text", False),
    ("", False), (None, False),
])
def test_is_form_recognises_urlencoded_bodies(body, expected):
    assert t.is_form(body) is expected


def test_form_values_are_decoded_filtered_and_split_on_first_equals():
    vals = t.body_values("a=1&q=x%27%20OR%20%271%27%3D%271&u=http%3A%2F%2Fexample.com%2Fp")
    assert vals == ["x' OR '1'='1"]


def test_form_with_leading_ampersand_or_newline_is_still_a_form():
    assert t.is_form("&q=1%27%20OR%201%3D1--")
    assert t.is_form("\nq=1%27%20OR%201%3D1--")


def test_form_key_longer_than_64_chars_is_still_inspected():
    assert t.body_values("k" * 100 + "=1%27%20OR%20%271%27%3D%271")


# ---------------------------------------------------------------- signature_hits
@pytest.mark.parametrize("target", [
    "/a/../../etc/passwd", "/f?p=..\\..\\windows\\win.ini", "/f?p=%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/f?p=%252e%252e%252f%252e%252e%252fboot.ini", "/f?p=..%2f..%2fapp%2fsettings.py", "/f?p=..%5c..%5capp%5cx.cfg",
    "/f?p=/etc/passwd", "/f?p=c:\\windows\\win.ini", "/f?p=/proc/self/environ", "/f?p=/etc/shadow",
])
def test_traversal_and_documented_sensitive_files_are_caught(target):
    assert t.signature_hits(target)


@pytest.mark.parametrize("target", [
    "/f?p=....//....//....//app/config.php",            # nested ../ (survives a single non-recursive strip)
    "/f?p=%c0%ae%c0%ae/%c0%ae%c0%ae/app/x.cfg",         # overlong UTF-8 dot-dot
    "/f?p=..%252f..%252fapp/x.cfg",
    "/f?p=/root/.ssh/id_rsa", "/f?p=/var/log/auth.log", "/f?p=C:\\Windows\\System32\\config\\SAM",
    "/f?p=/etc/sudoers", "/f?p=/proc/self/cmdline", "/f?p=WEB-INF/web.xml", "/.git/config", "/.env",
])
def test_traversal_variants_and_adjacent_sensitive_files_are_caught(target):
    assert t.signature_hits(target), target


@pytest.mark.parametrize("target", [
    "/docs/../images/logo.png", "/blog/2026/how-etc-passwd-works", "/f?path=/home/user/report.pdf",
    "/s?q=how+to+edit+boot.ini", "/static/css/main.css", "/a/b/../c",
])
def test_ordinary_paths_do_not_trigger_signatures(target):
    assert t.signature_hits(target) == []


def test_documentation_page_about_the_hosts_file_is_not_flagged():
    assert t.signature_hits("/docs/etc/hosts-file-explained") == []


# ---------------------------------------------------------------- secret_hits
def test_secrets_in_the_decoded_target_are_named_not_returned():
    aws = "AKIAJ4X7QW2M5N8P3R6T"        # not the documented AKIA...EXAMPLE key: the detector ignores placeholders on purpose
    hits = t.secret_hits(f"/x?k={aws}")
    assert hits and all(aws not in h for h in hits)


@pytest.mark.parametrize("secret", ["ghp_" + "a1B2c3D4e5" * 3 + "a1B2c3", "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"])
def test_common_provider_tokens_are_detected(secret):
    assert t.secret_hits(f"/x?token={secret}")


def test_a_jwt_in_a_query_string_is_flagged_as_a_leaked_credential():
    """Policy, not a false positive: a bearer token in a URL ends up in logs and Referer headers."""
    assert "JWT" in t.secret_hits("/p?token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2ln")


def test_documented_placeholder_keys_are_ignored():
    assert t.secret_hits("/x?k=AKIAIOSFODNN7EXAMPLE") == []


def test_encoded_secret_is_detected_after_decoding():
    assert t.secret_hits("/x?k=%41%4B%49%41J4X7QW2M5N8P3R6T")


@pytest.mark.parametrize("benign", ["/x?id=550e8400-e29b-41d4-a716-446655440000", "/x?sha=" + "ab" * 20, "/x?password=", "/x?q=api+key+help"])
def test_identifiers_and_the_word_password_are_not_secrets(benign):
    assert t.secret_hits(benign) == []


def test_detector_failure_never_breaks_request_handling(monkeypatch):
    monkeypatch.setattr(t, "detect_secrets", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("boom")))
    assert t.secret_hits("/x?k=AKIAIOSFODNN7EXAMPLE") == []


# ---------------------------------------------------------------- is_interesting (composite)
@pytest.mark.parametrize("target", [
    "/search?q=1%27%20UNION%20SELECT%20password%20FROM%20users--", "/p?f=../../../etc/passwd",
    "/p?c=%3Bcat%20/etc/passwd", "/p?x=%3Cscript%3Ealert(1)%3C/script%3E", "/p?k=AKIAJ4X7QW2M5N8P3R6T",
])
def test_canonical_attack_targets_are_interesting(target):
    assert t.is_interesting(target)


@pytest.mark.parametrize("target", [
    "/api/items?page=2&sort=name", "/search?q=best+pizza", "/oauth/callback?code=abc123&state=xyz",
    "/p?utm_source=news&utm_medium=email", "/p?q=caf%C3%A9",
    "/p?ids=1,2,3", "/p?redirect=https://example.com/home", "/p?id=dGVzdA==", "/", "",
])
def test_ordinary_targets_are_not_interesting(target):
    assert not t.is_interesting(target)
