"""Secret-handling policy on the wire (availability over security).

Vendor secrets that should never leave your network (AWS keys, private keys, Stripe live keys,
GitHub/Slack tokens, DB connection strings) BLOCK when sent outbound. Credentials that legitimately
travel in requests and responses — JWTs (SSO callbacks, magic links, every login API reply),
client-side Google API keys, a generic password= — are ADVISORY: reported on the dashboard, never
blocking. Inbound replies are advisory only: a server sending the client its own token isn't an
exfiltration, and blocking it broke every login response that carries a JWT.
"""
import asyncio
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from text_service import main as svc  # noqa: E402

JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." "eyJzdWIiOiIxMjM0NTY3ODkwIn0." "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
GOOGLE = "AIza" + "SyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q"
GENERIC = 'api_key = "' + "abcdef0123456789abcd" + '"'
AWS = "AKIA" + "IOSFODNN7REALKEYX"
GITHUB = "ghp_" + "A1b2C3d4E5" * 3 + "F6g7H8"
STRIPE_LIVE = "sk_live_" + "a1B2c3D4e5F6g7H8i9J0k1L2"
PRIVKEY = "-----BEGIN RSA " + "PRIVATE KEY-----"
DBCONN = "postgres://admin:hunter2" + "@db.internal:5432/prod"

TOLERATED = {"JWT": f"token {JWT}", "Google API Key": f"key {GOOGLE}", "Generic Secret": GENERIC}
VENDOR = {"AWS": f"key {AWS}", "GitHub PAT": f"t {GITHUB}", "Stripe live": f"k {STRIPE_LIVE}",
          "private key": PRIVKEY, "DB connection string": f"conn {DBCONN}"}


@pytest.mark.parametrize("name", VENDOR)
def test_vendor_secrets_block_outbound(name):
    r = svc.model_code_analysis(VENDOR[name])
    assert r.blocked and r.findings


@pytest.mark.parametrize("name", TOLERATED)
def test_tolerated_credentials_are_advisory_outbound(name):
    r = svc.model_code_analysis(TOLERATED[name])
    assert not r.blocked and r.findings and r.raw_data.get("advisory") is True


def test_mixed_outbound_blocks_and_risk_comes_from_the_vendor_secret():
    r = svc.model_code_analysis(f"{JWT} {AWS}")
    assert r.blocked and r.risk.value == "critical"


@pytest.mark.parametrize("name", list(VENDOR) + list(TOLERATED))
def test_inbound_secrets_are_advisory_only(name):
    text = {**VENDOR, **TOLERATED}[name]
    r = svc.model_code_analysis(text, direction="inbound")
    assert not r.blocked and r.findings and r.raw_data.get("advisory") is True


def test_clean_text_has_no_findings_either_direction():
    for d in ("outbound", "inbound"):
        r = svc.model_code_analysis("just a normal sentence", direction=d)
        assert not r.blocked and not r.findings


def test_findings_never_contain_the_secret_itself():
    for text in ({**VENDOR, **TOLERATED}).values():
        r = svc.model_code_analysis(text)
        blob = " ".join(r.findings)
        for secret in (JWT, GOOGLE, AWS, GITHUB, STRIPE_LIVE, DBCONN, "abcdef0123456789abcd"):
            assert secret not in blob


# --- through the whole service ----------------------------------------------------------
class _Req:
    def __init__(self, text, md):
        self._t, self._md = text, md

    async def json(self):
        return {"text": self._t, "metadata": self._md}


def _call(text, md):
    svc._cache_clear()
    svc._reset_semaphore()
    return json.loads(asyncio.run(svc.analyze_text(_Req(text, md))).body)


@pytest.fixture(autouse=True)
def _cheap_pipeline(monkeypatch):
    from common.schemas import AnalysisResult
    ok = lambda m: (lambda *a, **k: AnalysisResult(module=m, score=0.0, findings=[]))
    monkeypatch.setattr(svc, "_route", lambda t: "code")
    monkeypatch.setattr(svc, "model_patterns", ok("pattern"))


def test_login_response_carrying_a_jwt_is_allowed_with_an_advisory():
    body = json.dumps({"access_token": JWT, "token_type": "Bearer", "expires_in": 3600})
    out = _call(body, {"host": "api.example", "direction": "inbound"})
    assert out["status"] == "censor" and "advisory" in out["reason"].lower()


def test_outbound_request_with_a_jwt_bearer_in_the_body_is_allowed_with_an_advisory():
    out = _call(json.dumps({"id_token": JWT}), {"host": "api.example", "direction": "outbound"})
    assert out["status"] == "censor"


def test_aws_key_in_an_outbound_body_still_blocks():
    out = _call(f"note=here is the key {AWS}", {"host": "evil.example", "direction": "outbound"})
    assert out["status"] == "block" and "code" in out["reason"]


def test_aws_key_in_an_inbound_reply_is_advisory():
    out = _call(f"echo: {AWS}", {"host": "api.example", "direction": "inbound"})
    assert out["status"] == "censor"


def test_jwt_in_a_url_is_advisory_through_the_target_path_too():
    out = _call(f"/auth?token={JWT}", {"host": "app.example", "direction": "outbound", "kind": "url"})
    assert out["status"] in ("censor", "allow")


def test_vendor_secret_in_a_url_still_blocks():
    out = _call(f"/export?api_key={AWS}", {"host": "app.example", "direction": "outbound", "kind": "url"})
    assert out["status"] == "block"
