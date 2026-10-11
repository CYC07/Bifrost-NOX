"""PII (Presidio) policy: block on evidence, not on entity type.

Found by capturing live blocks: Windows' push-notification service reply
(`client.wns.windows.com`, `<id>Mtp1.404/118127381.cb79...</id>`) and an app login body
(`"usernumber":"710823890"`) were BLOCKED as US_SSN although Presidio itself scored them 0.05.
model_patterns blocked on the entity type and ignored the score. Presidio's scores separate the
cases well for SSNs (bare 9 digits 0.05; formatted 0.5; with context 0.85) but a Luhn-valid number
is always 1.0, so cards additionally need card formatting or card-ish context.
Availability over security: inbound replies are advisory only.
"""
import json
import os
import random
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from presidio_analyzer import AnalyzerEngine  # noqa: E402
from text_service import main as svc  # noqa: E402


@pytest.fixture(scope="module", autouse=True)
def _presidio():
    old = svc.presidio_analyzer
    svc.presidio_analyzer = AnalyzerEngine()
    yield
    svc.presidio_analyzer = old


def P(text, direction="outbound"):
    return svc.model_patterns(text, direction)


VALID_CARD = "4111 1111 1111 1111"
LUHN_ID = "4012888888881881"           # Luhn-valid, used here as a bare identifier


# --- false positives that were observed live -------------------------------------------------
@pytest.mark.parametrize("text", [
    "<connect-response><ver>1</ver><session><id>Mtp1.404/118127381.cb79b7e7-fbcf-d790-2152-d11b3bd01a60</id></session></connect-response>",
    '{"usernumber":"710823890","password":"2822b771df0c5a1b81fdb99be6","x":1}',
    "order 536904399 shipped",
])
@pytest.mark.parametrize("direction", ["outbound", "inbound"])
def test_bare_nine_digit_identifiers_never_block(text, direction):
    assert not P(text, direction).blocked


# --- real sensitive data still blocks outbound -------------------------------------------
@pytest.mark.parametrize("text", [
    "536-90-4399",
    "employee social security number is 536-90-4399 on file",
    "ssn: 536904399",
    f"card={VALID_CARD} exp 12/29 cvv 123",
    "4111-1111-1111-1111",
    '{"cardNumber":"4111111111111111","cvv":"123"}',
    "credit card 4111111111111111",
])
def test_real_ssn_and_card_data_blocks_outbound(text):
    r = P(text)
    assert r.blocked and r.findings


# --- a Luhn-valid number is not a card unless it looks like one ------------------------------
@pytest.mark.parametrize("text", [
    LUHN_ID,
    f'{{"id":"{LUHN_ID}","ts":1696843200123}}',
    f"correlation {LUHN_ID} trace",
])
def test_bare_luhn_valid_identifier_is_advisory_not_blocked(text):
    r = P(text)
    assert not r.blocked
    assert r.raw_data and r.raw_data.get("advisory") is True


def test_random_telemetry_blobs_are_never_blocked():
    rng = random.Random(11)
    blocked = []
    for _ in range(400):
        b = json.dumps({"id": str(rng.randrange(10**15, 10**16)), "ts": rng.randrange(10**12, 10**13),
                        "channel": "wns", "ver": "10.0.19045", "n": rng.randrange(10**8, 10**9)})
        if P(b).blocked:
            blocked.append(b)
    assert blocked == []


# --- inbound is advisory only ----------------------------------------------------------------
@pytest.mark.parametrize("text", [f"card {VALID_CARD}", "ssn 536-90-4399", "536-90-4399"])
def test_inbound_sensitive_findings_are_advisory(text):
    r = P(text, "inbound")
    assert not r.blocked and r.findings
    assert r.raw_data and r.raw_data.get("advisory") is True


# --- unchanged behaviour ----------------------------------------------------------------------
def test_contact_info_is_still_informational_only():
    r = P("mail me at bob@example.com or call +1 415 555 0123")
    assert not r.blocked and not (r.raw_data or {}).get("advisory")


def test_clean_text_has_no_findings():
    r = P("just a normal sentence about nothing")
    assert not r.blocked and not r.findings


def test_findings_never_contain_the_number_itself():
    r = P(f"card={VALID_CARD}")
    assert VALID_CARD not in " ".join(r.findings) and "4111" not in " ".join(r.findings)


def test_default_direction_is_outbound():
    assert svc.model_patterns(f"card={VALID_CARD}").blocked


def test_min_score_is_configurable(monkeypatch):
    # Presidio scores: formatted SSN 0.5, SSN with context 0.85
    monkeypatch.setattr(svc, "PII_MIN_SCORE", 0.8)
    assert not P("536-90-4399").blocked          # 0.5 < 0.8
    assert P("ssn 536-90-4399").blocked          # 0.85 >= 0.8
    monkeypatch.setattr(svc, "PII_MIN_SCORE", 0.9)
    assert not P("ssn 536-90-4399").blocked      # 0.85 < 0.9


# --- through the whole service ----------------------------------------------------------------
import asyncio  # noqa: E402


class _Req:
    def __init__(self, text, md):
        self._t, self._md = text, md

    async def json(self):
        return {"text": self._t, "metadata": self._md}


def _call(text, md):
    svc._cache_clear()
    svc._reset_semaphore()
    return json.loads(asyncio.run(svc.analyze_text(_Req(text, md))).body)


def test_wns_style_reply_is_allowed_end_to_end(monkeypatch):
    monkeypatch.setattr(svc, "_route", lambda t: "code")
    body = "<connect-response><session><id>Mtp1.404/118127381.cb79</id></session></connect-response>"
    out = _call(body, {"host": "client.wns.windows.com", "direction": "inbound"})
    assert out["status"] in ("allow", "censor")


def test_card_in_an_outbound_post_still_blocks_end_to_end(monkeypatch):
    monkeypatch.setattr(svc, "_route", lambda t: "code")
    out = _call(f"card={VALID_CARD} cvv 123", {"host": "shop.example", "direction": "outbound"})
    assert out["status"] == "block" and "pattern" in out["reason"]
