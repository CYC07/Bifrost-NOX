"""The image service under a burst, like a Google Images page loading dozens of thumbnails at once.

Measured on the live lab: one image takes about 1 s, but 10 at once took a median 17.6 s and 20 at once took 60 s each,
so most images blew the orchestrator's 8 s timeout, were never analysed and failed open (allowed unseen). Causes:
the concurrency limit only wrapped the CLIP step (OCR, object detection and steganography ran unbounded, OCR spawning
a Tesseract process each), nothing remembered repeated images, and tiny icons got the full model treatment.

Fixes under test: (1) the WHOLE analysis is bounded to IMAGE_MAX_CONCURRENCY at a time and the rest queue,
(2) verdicts are cached by SHA-256, (3) images under IMAGE_MIN_ANALYSIS_BYTES / IMAGE_MIN_PIXELS skip the models but keep
the cheap file-safety check.  The models themselves are replaced by recording fakes here: this tests the serving logic.
"""
import asyncio
import io
import os
import random
import sys
import threading
import time

import httpx
import pytest
from PIL import Image

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.schemas import AnalysisResult, RiskLevel  # noqa: E402
from image_service import main as ims  # noqa: E402


class Recorder:
    """Stands in for OCR / YOLO / stego / CLIP: counts calls and the peak number of analyses running at once."""

    def __init__(self, delay=0.04, clip_blocks=False):
        self.lock = threading.Lock()
        self.calls = 0                 # CLIP calls = one per fully analysed image
        self.running = 0
        self.peak = 0
        self.delay = delay
        self.clip_blocks = clip_blocks

    def _work(self, module):
        with self.lock:
            self.running += 1
            self.peak = max(self.peak, self.running)
        time.sleep(self.delay)
        with self.lock:
            self.running -= 1
        return AnalysisResult(module=module, score=0.0, findings=[])

    def ocr(self, image):
        return self._work("ocr")

    def yolo(self, image):
        return self._work("object_detection")

    def stego(self, image):
        return self._work("stego")

    def clip(self, image):
        r = self._work("semantic_clip")
        with self.lock:
            self.calls += 1
        if self.clip_blocks:
            return AnalysisResult(module="semantic_clip", score=0.98, findings=["CRITICAL: test"], blocked=True,
                                  risk=RiskLevel.CRITICAL)
        return r


@pytest.fixture()
def rec(monkeypatch):
    r = Recorder()
    monkeypatch.setattr(ims, "model_ocr", r.ocr)
    monkeypatch.setattr(ims, "model_object_detection", r.yolo)
    monkeypatch.setattr(ims.stego, "chi_square_lsb", r.stego)
    monkeypatch.setattr(ims, "_clip_classifier", type("C", (), {"classify": staticmethod(r.clip)})())
    monkeypatch.setattr(ims, "_ANALYSIS_SEM", asyncio.Semaphore(2))       # fresh per test: it binds to a loop on contention
    ims._VERDICT_CACHE.clear()
    ims._INFLIGHT.clear()
    for k in ("IMAGE_CACHE_SIZE", "IMAGE_MIN_ANALYSIS_BYTES", "IMAGE_MIN_PIXELS"):
        monkeypatch.delenv(k, raising=False)
    yield r
    assert ims._INFLIGHT == {}, "an analysis was left registered as in-flight"
    ims._VERDICT_CACHE.clear()


def photo(seed, size=(200, 160)) -> bytes:
    """A noisy JPEG well above the tiny-image thresholds, different for every seed."""
    rnd = random.Random(seed)
    im = Image.new("RGB", size)
    im.putdata([(rnd.randrange(256), rnd.randrange(256), rnd.randrange(256)) for _ in range(size[0] * size[1])])
    b = io.BytesIO()
    im.save(b, "JPEG", quality=90)
    return b.getvalue()


def png(size, colour=(200, 30, 30)) -> bytes:
    b = io.BytesIO()
    Image.new("RGB", size, colour).save(b, "PNG")
    return b.getvalue()


async def post_all(blobs):
    transport = httpx.ASGITransport(app=ims.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://img") as c:
        return await asyncio.gather(*[
            c.post("/analyze", files={"file": (f"i{n}.jpg", blob, "image/jpeg")}) for n, blob in enumerate(blobs)])


def run(blobs):
    return asyncio.run(post_all(blobs))


# ---------------------------------------------------------------- 1. the whole analysis is bounded

def test_a_burst_never_runs_more_than_the_limit_at_once(rec):
    rs = run([photo(i) for i in range(12)])
    assert all(r.status_code == 200 for r in rs)
    assert rec.calls == 12                                    # every distinct image really was analysed
    assert rec.peak <= 2 * 3, f"peak concurrent model calls {rec.peak}"   # 2 images x (OCR + YOLO + stego) in flight


def test_the_limit_applies_to_ocr_yolo_and_stego_not_just_clip(rec, monkeypatch):
    """Before: only the CLIP step was inside the semaphore, so these three ran for every queued image at once."""
    monkeypatch.setattr(ims, "_ANALYSIS_SEM", asyncio.Semaphore(1))
    rec.delay = 0.05
    run([photo(i) for i in range(8)])
    assert rec.peak <= 3                                      # one image at a time: at most its three parallel parts


def test_the_limit_is_configurable():
    assert ims._env_int("IMAGE_MAX_CONCURRENCY", 2, 1) == 2
    os.environ["IMAGE_MAX_CONCURRENCY"] = "5"
    try:
        assert ims._env_int("IMAGE_MAX_CONCURRENCY", 2, 1) == 5
        os.environ["IMAGE_MAX_CONCURRENCY"] = "0"
        assert ims._env_int("IMAGE_MAX_CONCURRENCY", 2, 1) == 2          # below the minimum: default
        os.environ["IMAGE_MAX_CONCURRENCY"] = "lots"
        assert ims._env_int("IMAGE_MAX_CONCURRENCY", 2, 1) == 2          # garbage: default
    finally:
        del os.environ["IMAGE_MAX_CONCURRENCY"]


# ---------------------------------------------------------------- 2. cache by image hash

def test_the_same_image_is_analysed_once_and_gets_the_same_verdict(rec):
    blob = photo(1)
    first = run([blob])[0].json()
    second = run([blob])[0].json()
    third = run([blob])[0].json()
    assert rec.calls == 1
    assert first == second == third and first["status"] == "allow"


def test_identical_images_arriving_together_are_analysed_once(rec):
    """The page asks for the same thumbnail several times at once: the second waits in the queue, then finds the
    verdict the first one just stored."""
    rs = run([photo(7)] * 6)
    assert [r.status_code for r in rs] == [200] * 6
    assert rec.calls == 1


def test_if_the_first_analysis_fails_the_waiting_copies_analyse_it_themselves(rec, monkeypatch):
    """One failed analysis must not fail every identical image that was waiting on it."""
    state = {"n": 0}
    real = rec.clip

    def flaky(image):
        state["n"] += 1
        if state["n"] == 1:
            raise RuntimeError("model hiccup")
        return real(image)
    monkeypatch.setattr(ims, "_clip_classifier", type("C", (), {"classify": staticmethod(flaky)})())
    blob = photo(21)

    async def go():
        transport = httpx.ASGITransport(app=ims.app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://img") as c:
            return await asyncio.gather(*[c.post("/analyze", files={"file": ("a.jpg", blob, "image/jpeg")}) for _ in range(4)])
    codes = sorted(r.status_code for r in asyncio.run(go()))
    assert codes == [200, 200, 200, 500]


def test_a_cached_block_stays_a_block(rec):
    rec.clip_blocks = True
    blob = photo(2)
    a, b = run([blob])[0].json(), run([blob])[0].json()
    assert rec.calls == 1
    assert a == b and a["status"] == "block" and a["reason"] == "Blocked by: semantic_clip"


def test_different_images_are_not_confused(rec):
    run([photo(1)])
    run([photo(2)])
    assert rec.calls == 2


def test_cache_is_bounded_and_evicts_the_oldest(rec, monkeypatch):
    monkeypatch.setenv("IMAGE_CACHE_SIZE", "2")
    a, b, c = photo(11), photo(12), photo(13)
    run([a]), run([b]), run([c])                              # a is evicted
    assert rec.calls == 3 and len(ims._VERDICT_CACHE) == 2
    run([a])
    assert rec.calls == 4                                     # recomputed
    run([c])
    assert rec.calls == 4                                     # still cached


def test_cache_can_be_switched_off(rec, monkeypatch):
    monkeypatch.setenv("IMAGE_CACHE_SIZE", "0")
    blob = photo(3)
    run([blob]), run([blob])
    assert rec.calls == 2 and len(ims._VERDICT_CACHE) == 0


def test_invalid_images_are_not_cached(rec):
    r = run([b"definitely not an image" * 20])[0]
    assert r.status_code in (200, 400) and len(ims._VERDICT_CACHE) <= 1
    assert rec.calls == 0


# ---------------------------------------------------------------- 3. tiny images skip the models

def test_tiny_files_skip_the_models_but_are_allowed_with_a_note(rec):
    tiny = png((40, 40))                                      # ~100 bytes
    assert len(tiny) < 4096
    v = run([tiny])[0].json()
    assert rec.calls == 0 and rec.peak == 0
    assert v["status"] == "allow" and v["reason"] == "No analyzer flagged a block"
    assert any("skipped" in f.lower() for f in v["detailed_findings"]["findings"])


def test_small_dimensions_skip_the_models_even_when_the_file_is_large(rec, monkeypatch):
    monkeypatch.setenv("IMAGE_MIN_ANALYSIS_BYTES", "0")
    v = run([photo(5, size=(40, 40))])[0].json()              # 1,600 px < 4,096 px
    assert rec.calls == 0 and v["status"] == "allow"


def test_a_normal_sized_image_is_still_fully_analysed(rec):
    run([photo(6)])
    assert rec.calls == 1


def test_thresholds_are_configurable(rec, monkeypatch):
    monkeypatch.setenv("IMAGE_MIN_ANALYSIS_BYTES", "0")
    monkeypatch.setenv("IMAGE_MIN_PIXELS", "0")
    run([png((40, 40))])
    assert rec.calls == 1                                     # skipping switched off


def test_tiny_hostile_files_are_still_stopped_by_the_cheap_safety_check(rec):
    """Skipping the models must not become a bypass: file_safety runs first, on every image."""
    polyglot = png((40, 40)) + b"PK\x03\x04" + b"\x00" * 60           # PNG with a ZIP appended
    v = run([polyglot])[0].json()
    assert v["status"] == "block" and v["reason"] == "Blocked by: file_safety"
    exe = b"MZ" + b"\x90\x00" * 40                                    # an executable posing as an image
    v = run([exe])[0].json()
    assert v["status"] == "block" and rec.calls == 0


# ---------------------------------------------------------------- the verdict itself is unchanged

def test_verdict_shape_matches_the_original_contract(rec):
    v = run([photo(9)])[0].json()
    assert set(v) >= {"status", "risk_level", "reason", "detailed_findings"}
    assert v["status"] == "allow" and v["risk_level"] == "safe"
    assert set(v["detailed_findings"]["scores"]) == {"file_safety", "ocr", "semantic_clip", "object_detection", "stego"}
