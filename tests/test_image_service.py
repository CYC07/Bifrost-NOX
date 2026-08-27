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
