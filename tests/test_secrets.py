"""Unit tests for the expanded secret-detection module (ml/secrets/).

Covers the FP-reduction techniques added 2026-08-01: vendor-specific
patterns, structural validation (JWT), known-placeholder exclusion, and
severity tiering (live vs test-mode credentials).
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ml.secrets.detector import detect  # noqa: E402
from ml.secrets.validators import is_valid_jwt  # noqa: E402


# --- vendor patterns ---------------------------------------------------------
def test_detects_aws_access_key():
    findings = detect("AWS_KEY=AKIAABCDEFGHIJKLMNOP")
    assert any(f.kind == "AWS Access Key" for f in findings)


def test_detects_stripe_live_key_as_critical():
    # Built via concatenation, not a literal — a contiguous fake-but-shaped
    # key trips GitHub's own push-protection secret scanner on this file.
    fake_key = "sk_" + "live_" + "abcdefghijklmnopqrstuvwx"
    findings = detect(f"stripe_key = {fake_key}")
    matches = [f for f in findings if f.kind == "Stripe Live Key"]
    assert matches and matches[0].severity == "critical"


def test_detects_stripe_test_key_as_low_severity():
    fake_key = "sk_" + "test_" + "abcdefghijklmnopqrstuvwx"
    findings = detect(f"stripe_key = {fake_key}")
    matches = [f for f in findings if f.kind == "Stripe Test Key"]
    assert matches and matches[0].severity == "low"


def test_detects_github_classic_pat():
    findings = detect("token: ghp_" + "a" * 36)
    assert any(f.kind == "GitHub PAT (classic)" for f in findings)


def test_detects_slack_bot_token():
    findings = detect("SLACK_TOKEN=xoxb-1234567890-1234567890-" + "a" * 24)
    assert any(f.kind == "Slack Bot Token" for f in findings)


def test_detects_db_connection_string_with_credentials():
    findings = detect("DATABASE_URL=postgres://admin:hunter2@db.internal:5432/prod")
    assert any(f.kind == "DB Connection String with Credentials" for f in findings)


def test_publishable_keys_are_not_flagged():
    # Stripe publishable keys are meant to be public by design — flagging
    # them is pure noise, not a real secret leak.
    findings = detect("stripe_pk = pk_live_abcdefghijklmnopqrstuvwx")
    assert not findings


# --- JWT structural validation ----------------------------------------------
def test_jwt_validator_accepts_real_jwt_shape():
    header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    payload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0"
    sig = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    assert is_valid_jwt(f"{header}.{payload}.{sig}") is True


def test_jwt_validator_rejects_lookalike_non_jwt():
    # Starts with "eyJ" (common false-positive trigger) but isn't valid
    # base64-JSON in the header/payload segments.
    assert is_valid_jwt("eyJnotreal.eyJalsonotreal.notasignature") is False


def test_detect_skips_jwt_lookalike_that_fails_structural_check():
    findings = detect("token=eyJnotreal.eyJalsonotreal.notasignature")
    assert not any(f.kind == "JWT" for f in findings)


def test_detect_flags_structurally_valid_jwt():
    header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    payload = "eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    sig = "dGVzdHNpZ25hdHVyZQ"
    findings = detect(f"Authorization: Bearer {header}.{payload}.{sig}")
    assert any(f.kind == "JWT" for f in findings)


# --- known-placeholder exclusion ---------------------------------------------
def test_aws_official_docs_example_key_not_flagged():
    findings = detect("AWS_KEY=AKIAIOSFODNN7EXAMPLE")
    assert not findings


def test_stripe_official_docs_test_key_not_flagged():
    real_docs_key = "sk_" + "test_" + "4eC39HqLyjWDarjtT1zdp7dc"
    findings = detect(real_docs_key)
    assert not findings


def test_generic_placeholder_values_not_flagged():
    findings = detect('api_key = "xxxxxxxxxxxxxxxxxxxxxxxx"')
    assert not findings


# --- never leak the raw secret -----------------------------------------------
def test_finding_never_contains_the_raw_secret_value():
    secret = "AKIAABCDEFGHIJKLMNOP"
    findings = detect(f"AWS_KEY={secret}")
    for f in findings:
        assert secret not in repr(f)
        assert secret not in str(f.kind)


# --- benign text ---------------------------------------------------------
def test_benign_text_yields_no_findings():
    assert detect("The weather in London is expected to be sunny.") == []
