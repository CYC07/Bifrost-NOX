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


# --- Task 3: CLIP classifier with cached embeddings ------------------------

def test_clip_classifier_caches_text_embeddings():
    from image_service.main import _get_clip_classifier
    clf = _get_clip_classifier()
    assert clf is not None
    assert clf.text_embeds is not None
    assert clf.text_embeds.shape[0] == len(clf.labels)


def test_clip_classify_returns_result_for_benign():
    from image_service.main import _get_clip_classifier
    clf = _get_clip_classifier()
    img = Image.open(io.BytesIO(synth_cases.SYNTH_CASES["benign_gradient"])).convert("RGB")
    r = clf.classify(img)
    assert r.module == "semantic_clip"
    assert r.blocked is False


# --- Task 4: multi-label CLIP with per-group max-softmax-prob --------------

def test_clip_multilabel_reports_all_group_scores():
    from image_service.main import _get_clip_classifier
    clf = _get_clip_classifier()
    img = Image.open(io.BytesIO(synth_cases.SYNTH_CASES["benign_gradient"])).convert("RGB")
    r = clf.classify(img)
    gs = r.raw_data["group_scores"]
    assert set(gs) >= {"pii_nsfw", "sensitive", "benign"}
    assert all(0.0 <= v <= 1.0 for v in gs.values())


def test_clip_benign_fires_nothing_blocking():
    from image_service.main import _get_clip_classifier
    clf = _get_clip_classifier()
    for name in ("benign_gradient", "business_doc", "exif_gps"):
        img = Image.open(io.BytesIO(synth_cases.SYNTH_CASES[name])).convert("RGB")
        r = clf.classify(img)
        # benign images must not trip the strict pii/nsfw visual block
        assert r.blocked is False, name
        assert r.raw_data["group_scores"]["pii_nsfw"] < 0.4, name


def test_clip_multilabel_can_fire_multiple_groups():
    # A source-code screenshot fires the sensitive group; the API surfaces a
    # list of fired groups rather than a single argmax label.
    from image_service.main import _get_clip_classifier
    clf = _get_clip_classifier()
    img = Image.open(io.BytesIO(synth_cases.SYNTH_CASES["secret_screenshot"])).convert("RGB")
    r = clf.classify(img)
    assert "groups_fired" in r.raw_data
    assert "sensitive" in r.raw_data["groups_fired"]


# --- Task 5: file safety + stego + aggregation -----------------------------

from ml.image import file_safety, stego  # noqa: E402


def test_file_safety_blocks_trailing_zip():
    r = file_safety.check_bytes(synth_cases.SYNTH_CASES["trailing_zip"])
    assert r.blocked is True


def test_file_safety_allows_clean_png():
    r = file_safety.check_bytes(synth_cases.SYNTH_CASES["benign_gradient"])
    assert r.blocked is False


def test_file_safety_flags_exif_gps_nonblocking():
    r = file_safety.check_bytes(synth_cases.SYNTH_CASES["exif_gps"])
    assert r.blocked is False
    assert any("gps" in f.lower() for f in r.findings)


def test_file_safety_rejects_svg():
    svg = b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
    r = file_safety.check_bytes(svg)
    assert r.blocked is True


def test_file_safety_blocks_empty():
    r = file_safety.check_bytes(b"")
    assert r.blocked is True


def test_stego_clean_image_does_not_block():
    img = Image.open(io.BytesIO(synth_cases.SYNTH_CASES["benign_gradient"])).convert("RGB")
    r = stego.chi_square_lsb(img)
    assert r.blocked is False


def test_analyze_blocks_trailing_zip_end_to_end():
    from starlette.testclient import TestClient
    from image_service.main import app
    with TestClient(app) as client:
        resp = client.post(
            "/analyze",
            files={"file": ("p.png", synth_cases.SYNTH_CASES["trailing_zip"], "image/png")},
        )
    assert resp.status_code == 200
    assert resp.json()["status"] == "block"


def test_analyze_blocks_secret_in_gif_frame2():
    # Multi-frame OCR: a secret hidden in frame 2 of a GIF must not bypass.
    from starlette.testclient import TestClient
    from image_service.main import app
    with TestClient(app) as client:
        resp = client.post(
            "/analyze",
            files={"file": ("a.gif", synth_cases.SYNTH_CASES["gif_payload_frame2"], "image/gif")},
        )
    assert resp.status_code == 200
    assert resp.json()["status"] == "block"
