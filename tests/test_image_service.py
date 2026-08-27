import io

from PIL import Image

from ml.image import synth_cases


# --- Task 1: eval corpus ---------------------------------------------------

def test_corpus_has_all_cases():
    expected = {
        "benign_gradient", "secret_screenshot", "pii_screenshot",
        "business_doc", "trailing_zip", "exif_gps", "gif_payload_frame2",
    }
    assert expected <= set(synth_cases.SYNTH_CASES.keys())


def test_secret_screenshot_decodes():
    img = Image.open(io.BytesIO(synth_cases.SYNTH_CASES["secret_screenshot"]))
    assert img.width > 0 and img.height > 0


def test_trailing_zip_has_bytes_past_png_end():
    data = synth_cases.SYNTH_CASES["trailing_zip"]
    iend = data.rfind(b"IEND")
    assert iend != -1
    assert b"PK\x03\x04" in data[iend:]


def test_gif_has_two_frames():
    img = Image.open(io.BytesIO(synth_cases.SYNTH_CASES["gif_payload_frame2"]))
    assert getattr(img, "n_frames", 1) >= 2


# --- Task 2: OCR text -> secrets + PII -------------------------------------

from ml.image import ocr_scan  # noqa: E402
from presidio_analyzer import AnalyzerEngine  # noqa: E402
from common.schemas import RiskLevel  # noqa: E402

_PRESIDIO = AnalyzerEngine()


def test_ocr_scan_blocks_on_aws_key():
    r = ocr_scan.scan_ocr_text("here is the key AKIAIOSFODNN7REALKEYX and more", _PRESIDIO)
    assert r.blocked is True
    assert r.risk in (RiskLevel.HIGH, RiskLevel.CRITICAL)


def test_ocr_scan_blocks_on_credit_card():
    r = ocr_scan.scan_ocr_text("card on file 4111 1111 1111 1111 expires soon", _PRESIDIO)
    assert r.blocked is True
    assert r.risk == RiskLevel.CRITICAL


def test_ocr_scan_blocks_on_ssn():
    # Presidio (this version) does not detect US_SSN; ocr_scan carries a regex
    # fallback so a screenshot of an SSN still blocks. Regression guard for that.
    r = ocr_scan.scan_ocr_text("employee ssn 123-45-6789 on file", _PRESIDIO)
    assert r.blocked is True
    assert r.risk == RiskLevel.CRITICAL


def test_ocr_scan_keyword_only_is_nonblocking():
    r = ocr_scan.scan_ocr_text("Q4 revenue summary confidential", _PRESIDIO)
    assert r.blocked is False
    assert r.findings  # keyword signal still surfaced


def test_ocr_scan_benign_is_clean():
    r = ocr_scan.scan_ocr_text("a photo of a golden retriever in a park", _PRESIDIO)
    assert r.blocked is False
    assert r.score == 0.0


def test_analyze_blocks_secret_screenshot():
    from starlette.testclient import TestClient
    from image_service.main import app
    with TestClient(app) as client:  # lifespan -> load_models
        resp = client.post(
            "/analyze",
            files={"file": ("s.png", synth_cases.SYNTH_CASES["secret_screenshot"], "image/png")},
        )
    assert resp.status_code == 200
    assert resp.json()["status"] == "block"


def test_analyze_allows_benign_gradient():
    from starlette.testclient import TestClient
    from image_service.main import app
    with TestClient(app) as client:
        resp = client.post(
            "/analyze",
            files={"file": ("g.png", synth_cases.SYNTH_CASES["benign_gradient"], "image/png")},
        )
    assert resp.status_code == 200
    assert resp.json()["status"] == "allow"
