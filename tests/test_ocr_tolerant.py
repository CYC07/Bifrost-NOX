"""OCR-tolerant secret shapes (ml.image.ocr_tolerant + ocr_scan fuzzy JWT). No OCR involved."""
import pytest

from common.schemas import RiskLevel
from ml.image import ocr_scan
from ml.image.ocr_tolerant import tolerant_findings


@pytest.fixture(scope="module")
def presidio():
    from presidio_analyzer import AnalyzerEngine
    return AnalyzerEngine()


def kinds(text):
    return {k for k, _ in tolerant_findings(text)}


@pytest.mark.parametrize("text,kind", [
    ('token = "ghp_z1xdIy9xYt 4gB3gECm1bAtoGDXenP HmELY Ew"', "GitHub PAT (classic)"),   # injected spaces
    ('token = "ghp_z1xdTy9x¥¢ 4gBIgECRbAL0GDXenPHRELYEW"', "GitHub PAT (classic)"),  # glyph noise
    ('AWS_ACCESS_KEY_ID = "AKIAG9IV2UG5 YXX0040M"', "AWS Access Key"),
    ('stripe.api_key = "sk_live_rNbNgejgqyhF4SzYcl lxs3BtO"', "Stripe Live Key"),
    ('head -1 id_rsa # BEGIN RSA PRIVATE KEY', "Private Key Header"),                       # dashes lost
    ('DATABASE_URL=postgres://svc_app:Fv1gbéUSJZ3GURdb2.corp.internal:5432/orders', "DB Connection String with Credentials"),
])
def test_damaged_secrets_recovered(text, kind):
    assert kind in kinds(text)


@pytest.mark.parametrize("text", [
    "ghp_ prefix tokens are for personal access tokens issued by the platform",   # prose after prefix
    "sha256: 4f4816345cd58127135b5bf43425e285957661e1a0b9c33d0f07a2d9b1c3e4f5",
    "id = 3f2b8c1e-9d4a-4e7b-8a21-5c6d7e8f9a0b",
    "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",                                   # vendor placeholder shape
    "url = postgres://localhost:5432/app",                                        # port is numeric
    "mongodb://db.internal:27017",
    "see the README for the BEGIN PRIVATE KEY block format",                      # PKCS8 header is not in scope
])
def test_benign_lookalikes_not_flagged(text):
    assert not kinds(text)


def test_fuzzy_jwt_blocks_damaged_token_only(presidio):
    damaged = ('Authorization: Bearer eyJhbGciOiAISFMyNTYiLCAidHIwljoglkpXVC)9.ey)zdWIiOiAiMzY 10DIzOTciLCAiaWFO0ljogMTcwMDYw'
               'OTAWM 30.XMUgrD9X5C4hm1wHiL4ulUxroO88ZwmKOjT xljtjwvo')
    r = ocr_scan.scan_ocr_text(damaged, presidio)
    assert r.blocked and r.risk in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    # base64-looking prose / random blobs that are not eyJ.eyJ.sig must not block
    assert not ocr_scan.scan_ocr_text("eyJmb28 is the start of a base64 string eyJiYXI", presidio).blocked
    assert not ocr_scan.scan_ocr_text("eyJzzzzzzzzzzzzzzzz.eyJqqqqqqqqqqqq.abcdefghijklmnopqrstuvwxyz", presidio).blocked


def test_near_placeholder_with_inserted_char_not_blocked(presidio):
    assert not ocr_scan.scan_ocr_text("aws_access_key_id = AKIATIOSFODNNT7EXAMPLE # docs", presidio).blocked
