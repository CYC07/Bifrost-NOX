"""Decide whether a request is traffic to an LLM endpoint (host list, path, or body shape)."""
import json
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common import llm_scope  # noqa: E402

CHAT = json.dumps({"model": "gpt-x", "messages": [{"role": "user", "content": "hi"}]})


@pytest.fixture(autouse=True)
def _cfg(tmp_path, monkeypatch):
    p = tmp_path / "llm_hosts.json"
    p.write_text(json.dumps({
        "hosts": ["api.openai.com", "*.openai.azure.com", "llm.corp.example"],
        "paths": ["/v1/chat/completions", "/api/generate"],
    }))
    monkeypatch.setattr(llm_scope, "_PATH", str(p))
    llm_scope._reset_cache()
    return p


def S(host="example.com", path="/", body="x", direction="outbound"):
    return llm_scope.is_llm_request(host=host, path=path, body=body, direction=direction)


def test_listed_host_is_llm():
    assert S(host="api.openai.com")
    assert S(host="llm.corp.example")


def test_wildcard_host_matches_subdomain_only():
    assert S(host="my-res.openai.azure.com")
    assert not S(host="evilopenai.azure.com")          # no bare-suffix match (allowlist gotcha)
    assert not S(host="openai.azure.com.evil.test")


def test_known_path_is_llm_on_any_host():
    assert S(host="10.0.0.5", path="/v1/chat/completions")
    assert S(host="gpu-box.lan", path="/api/generate?stream=true")


def test_path_must_end_with_known_path_not_merely_contain_it():
    assert not S(host="example.com", path="/blog/v1/chat/completions-explained")


def test_body_shape_is_llm_on_unknown_host():
    assert S(host="unlisted.example", path="/x", body=CHAT)
    assert S(host="unlisted.example", body=json.dumps({"model": "m", "prompt": "hi"}))
    assert S(host="unlisted.example", body=json.dumps({"model": "m", "input": "hi"}))


def test_ordinary_json_and_forms_are_not_llm():
    assert not S(body=json.dumps({"username": "a", "password": "b"}))
    assert not S(body=json.dumps({"messages": ["a", "b"]}))     # no "model"
    assert not S(body="username=admin&password=secret123")
    assert not S(body="not json at all {")


def test_inbound_is_never_scoped():
    assert not S(host="api.openai.com", body=CHAT, direction="inbound")


def test_missing_context_is_not_llm():
    assert not S(host="", path="", body="")
    assert not S(host=None, path=None, body=None)


def test_config_hot_reloads(_cfg):
    assert not S(host="new-llm.example")
    time.sleep(0.01)
    _cfg.write_text(json.dumps({"hosts": ["new-llm.example"], "paths": []}))
    os.utime(_cfg, (time.time() + 5, time.time() + 5))
    assert S(host="new-llm.example")


def test_missing_or_corrupt_config_falls_back_to_shape_only(_cfg):
    _cfg.write_text("{ broken")
    llm_scope._reset_cache()
    assert not S(host="api.openai.com")          # list unavailable
    assert S(host="api.openai.com", body=CHAT)   # body shape still works
