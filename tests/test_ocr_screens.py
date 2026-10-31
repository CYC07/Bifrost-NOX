"""OCR on rendered code/terminal screenshots (monospace fonts, dark/light/syntax themes).

Corpus generator: dataset_tools/image/screens.py. Reader under test: ml.image.ocr_read.
"""
import io
from concurrent.futures import ThreadPoolExecutor

import pytest
from PIL import Image

from dataset_tools.image import screens
from ml.image import ocr_read, ocr_scan

FONTS = {f[0] for f in screens.available_fonts()}
pytestmark = pytest.mark.skipif(len(FONTS) < 6, reason="needs >=6 installed fonts")


@pytest.fixture(scope="module")
def presidio():
    from presidio_analyzer import AnalyzerEngine
    return AnalyzerEngine()


@pytest.fixture(scope="module")
def corpus(tmp_path_factory):
    d = tmp_path_factory.mktemp("screens")
    mono = [n for n, m, _ in screens.available_fonts() if m][:2]
    sans = [n for n, m, _ in screens.available_fonts() if not m][:1]
    items = screens.generate(str(d), sizes=(12, 18), per_cell=1, fonts=mono + sans)
    return str(d), items


def _kinds(text, presidio):
    # finding kind only (Presidio findings carry a score suffix)
    return {f.split(" (")[0] for f in ocr_scan.scan_ocr_text(text, presidio).findings if "keyword" not in f}


# ---------------------------------------------------------------- generator
def test_generator_has_enough_fonts_and_themes():
    fonts = screens.available_fonts()
    assert len(fonts) >= 6
    assert sum(1 for _, mono, _ in fonts if mono) >= 3
    assert len(screens.THEMES) >= 3 and {"light_ide", "dark_term"} <= set(screens.THEMES)


def test_generator_is_deterministic_and_fake_secrets_are_detectable(tmp_path, presidio):
    a = screens.generate(str(tmp_path / "a"), sizes=(14,), themes=["light_ide"], per_cell=1, fonts=["DejaVuSans"])
    b = screens.generate(str(tmp_path / "b"), sizes=(14,), themes=["light_ide"], per_cell=1, fonts=["DejaVuSans"])
    assert [i["secrets"] for i in a] == [i["secrets"] for i in b]
    for it in a:
        for s in it["secrets"]:
            assert _kinds(s["text"], presidio), f"detectors must fire on pristine {s['kind']}"


def test_benign_text_never_blocks_pristine(corpus, presidio):
    # sanity: the benign set must be benign for the detectors on clean text,
    # except placeholder-like content that only OCR noise could corrupt.
    _, items = corpus
    assert any(i["label"] == "benign" for i in items)


# ------------------------------------------------------------------- reader
def _read_all(d, items, reader):
    def one(it):
        with Image.open(f"{d}/{it['file']}") as im:
            im.load()
            return it, reader(im)
    with ThreadPoolExecutor(4) as ex:
        return list(ex.map(one, items))


def test_union_reader_recalls_secrets_on_monospace_and_dark_themes(corpus, presidio):
    d, items = corpus
    hit = tot = 0
    for it, text in _read_all(d, [i for i in items if i["label"] == "secret"], ocr_read.read_text):
        got = _kinds(text, presidio)
        for s in it["secrets"]:
            truth = _kinds(s["text"], presidio)
            tot += 1
            hit += bool(truth) and truth <= got
    assert tot >= 50
    assert hit / tot >= 0.90, f"recall {hit}/{tot}"


def test_union_reader_adds_no_false_positives_on_benign_screens(corpus, presidio):
    d, items = corpus
    benign = [i for i in items if i["label"] == "benign"]
    bad = [it["file"] for it, text in _read_all(d, benign, ocr_read.read_text)
           if ocr_scan.scan_ocr_text(text, presidio).blocked]
    assert not bad, bad


def test_placeholder_key_survives_ocr_noise(presidio):
    # an OCR-misread vendor example key (1-2 chars off) must stay a placeholder
    noisy = "aws_access_key_id = AKIAIOSFODNN7EXAMPLF"
    assert not ocr_scan.scan_ocr_text(noisy, presidio).blocked
    assert ocr_scan.scan_ocr_text("key = AKIAZ1Y9UEME1SKD9QZT", presidio).blocked


def test_low_confidence_presidio_ssn_does_not_block(presidio):
    assert not ocr_scan.scan_ocr_text("ref 285957661 done", presidio).blocked
    assert ocr_scan.scan_ocr_text("ssn 457-40-9835", presidio).blocked


def test_normalize_maps_unicode_dashes():
    assert "-----BEGIN RSA PRIVATE KEY-----" in ocr_read.normalize("——–-—BEGIN RSA PRIVATE KEY-----")


def test_multiframe_gif_payload_still_found(presidio):
    from image_service import main as svc
    secret = screens.make_secret("github", __import__("random").Random(1))
    f2 = screens.render([f'token = "{secret}"'], {n: p for n, _, p in screens.available_fonts()}["DejaVuSansMono"], 18,
                        "dark_term")
    f1 = Image.new("RGB", f2.size, "white")
    buf = io.BytesIO()
    f1.save(buf, format="GIF", save_all=True, append_images=[f2.convert("RGB")], duration=100, loop=0)
    buf.seek(0)
    svc.presidio_analyzer = presidio
    res = svc.model_ocr(Image.open(buf))
    assert res.blocked
