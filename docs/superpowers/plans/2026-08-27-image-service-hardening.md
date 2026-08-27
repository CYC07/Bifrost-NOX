# Image Service Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Improve the detection power, robustness, and plumbing of `image_service/` **without changing any model weights** (CLIP, YOLOv8, Tesseract stay exactly as pinned).

**Architecture:** Extract the inline logic in `image_service/main.py` into a focused `ml/image/` package (mirroring the existing `ml/waf`, `ml/secrets`, `ml/sensitive` layout), add the repo's first image test suite, then layer real detection on top: pipe OCR text through the already-built secrets + PII detectors, calibrate CLIP to multi-label with cached embeddings, harden against malicious file inputs, and improve OCR/CLIP preprocessing. Each phase is independently testable and committed on its own.

**Tech Stack:** Python 3.13 (venv at repo root), Starlette, Pillow, pytesseract, transformers CLIP, ultralytics YOLO, scipy (chi-square), pytest. Reuses `ml/secrets/` and Presidio from the text side.

## Global Constraints

- **NEVER change model weights or model IDs.** CLIP stays `openai/clip-vit-base-patch32`, YOLO stays `yolov8n.pt`, OCR stays Tesseract. Only the glue/calibration/preprocessing around them changes.
- **Venv interpreter is fragile.** `venv/bin/python` must point at `/usr/bin/python3.13` (system upgraded to 3.14; `python3.13` is apt-flagged auto-removable). If imports break with ModuleNotFoundError for installed packages, re-run `ln -sf /usr/bin/python3.13 venv/bin/python3`. Always run Python as `venv/bin/python`, tests as `venv/bin/python -m pytest`, with `PYTHONPATH=.`.
- **Fail-open per analyzer.** Every analyzer catches its own exceptions and returns a neutral `AnalysisResult` — one broken analyzer never takes down `/analyze`. This matches the existing image + text service pattern.
- **Decision-level aggregation.** Reuse `AnalysisResult.blocked: bool` + `AnalysisResult.risk: RiskLevel` (already in `common/schemas.py`). Each analyzer sets its own calibrated decision; aggregation ORs decisions and takes max risk — never one global threshold over incomparable scores. (Port the text_service pattern; the current image_service still uses the old max/weighted-score path.)
- **CPU only, ~15GB free disk, ~15GB RAM.** No new model downloads. New pip deps must be justified; prefer stdlib/PIL/scipy already installed.
- **Test-then-trust.** Held-out/eval numbers alone never accept a change — re-run the full adversarial case set (the T5 suite) after every phase. This is the hard-won lesson from the WAF arc.

## File Structure

**New package `ml/image/`:**
- `ml/image/__init__.py` — package marker.
- `ml/image/synth_cases.py` — deterministic PIL-drawn test-image generators (the eval corpus; no real sensitive images needed/stored).
- `ml/image/file_safety.py` — pure-function checks on raw bytes: decompression-bomb / pixel-bomb guard, trailing-bytes (polyglot) detection, SVG/format reject, EXIF-GPS leak.
- `ml/image/stego.py` — chi-square LSB steganalysis (replaces the broken single-plane heuristic in main.py).
- `ml/image/ocr_scan.py` — runs `ml.secrets.detect` + Presidio PII over OCR'd text.
- `ml/image/clip_labels.py` — `SEMANTIC_LABELS`, label→group map, per-group cutoffs (moved out of main.py, single source of truth).
- `ml/image/clip_classifier.py` — CLIP wrapper: cached text embeddings, `torch.inference_mode`, multi-label sigmoid over calibrated per-group cutoffs.
- `ml/image/preprocess.py` — OCR preprocessing (grayscale/upscale/threshold) + CLIP multi-crop helpers.

**New tests:**
- `tests/test_image_service.py` — the suite (repo's first image tests).

**Modified:**
- `image_service/main.py` — slims down to: load models, call `ml/image/` analyzers, aggregate by decision. Keeps its port (8001) and `/analyze` contract unchanged so the orchestrator wiring at `master_ai/orchestrator.py:237` still works.

---

## Task 1 (Phase T5): Eval corpus + failing baseline test suite

**Why first:** No tests exist for image_service and there is no labeled set, so thresholds/labels can't be tuned honestly. Build the measurement harness before touching detection — every later phase re-runs this suite as its accept/reject gate.

**Files:**
- Create: `ml/image/__init__.py`
- Create: `ml/image/synth_cases.py`
- Create: `tests/test_image_service.py`

**Interfaces:**
- Produces: `ml.image.synth_cases.SYNTH_CASES: dict[str, bytes]` — maps a case name to encoded image bytes. Cases: `benign_gradient` (plain PNG, no text), `secret_screenshot` (PNG with an AWS key `AKIA...` + `password:` rendered as text), `pii_screenshot` (PNG with a US SSN `123-45-6789` + credit-card-shaped number rendered), `business_doc` (PNG with `CONFIDENTIAL Q4 revenue` text), `trailing_zip` (valid PNG bytes with a ZIP appended past IEND), `pixel_bomb` (tiny file whose header declares enormous dimensions — use a crafted small PNG with large width/height in the IHDR is complex; instead a real but oversized-in-pixels image is generated at a size just over the guard so the guard can be unit-tested), `exif_gps` (JPEG carrying GPS EXIF tags), `gif_payload_frame2` (2-frame GIF, benign frame 1, `AKIA...` secret text drawn in frame 2).
- Produces: helper `ml.image.synth_cases.render_text_png(lines: list[str], size=(600,400)) -> bytes`.
- Produces: helper `ml.image.synth_cases.make_gif(frame_texts: list[list[str]]) -> bytes`.

- [ ] **Step 1: Write `ml/image/__init__.py`** (empty package marker).

- [ ] **Step 2: Write the failing test file `tests/test_image_service.py`** asserting the corpus exists and each case decodes/behaves as labeled. Start with tests that only depend on `synth_cases` (not on main.py yet):

```python
import io
from PIL import Image
from ml.image import synth_cases

def test_corpus_has_all_cases():
    expected = {
        "benign_gradient", "secret_screenshot", "pii_screenshot",
        "business_doc", "trailing_zip", "exif_gps", "gif_payload_frame2",
    }
    assert expected <= set(synth_cases.SYNTH_CASES.keys())

def test_secret_screenshot_contains_key_text():
    # The rendered image must actually carry the secret as pixels (OCR-able).
    img = Image.open(io.BytesIO(synth_cases.SYNTH_CASES["secret_screenshot"]))
    assert img.width > 0 and img.height > 0

def test_trailing_zip_has_bytes_past_png_end():
    data = synth_cases.SYNTH_CASES["trailing_zip"]
    iend = data.rfind(b"IEND")
    assert iend != -1
    # ZIP local-file-header signature appended after the PNG stream end.
    assert b"PK\x03\x04" in data[iend:]

def test_gif_has_two_frames():
    img = Image.open(io.BytesIO(synth_cases.SYNTH_CASES["gif_payload_frame2"]))
    n = getattr(img, "n_frames", 1)
    assert n >= 2
```

- [ ] **Step 3: Run to verify it fails**

Run: `cd /home/cyc0logy/FYP/ai_firewall && PYTHONPATH=. venv/bin/python -m pytest tests/test_image_service.py -q`
Expected: FAIL — `ModuleNotFoundError: ml.image.synth_cases`.

- [ ] **Step 4: Implement `ml/image/synth_cases.py`.** Use PIL `ImageDraw` with the default font to render text lines onto a white background; build the GIF via `save(..., save_all=True, append_images=...)`; build `trailing_zip` by encoding a PNG then concatenating a minimal in-memory ZIP (`zipfile` into a `BytesIO`); build `exif_gps` by writing a JPEG with GPS EXIF via Pillow's `Image.Exif` / `getexif()` and `save(exif=...)`. Compute `SYNTH_CASES` once at import.

- [ ] **Step 5: Run to verify pass**

Run: `PYTHONPATH=. venv/bin/python -m pytest tests/test_image_service.py -q`
Expected: PASS (4 tests).

- [ ] **Step 6: Commit**

```bash
git add ml/image/__init__.py ml/image/synth_cases.py tests/test_image_service.py
git commit -m "test(image): synthetic eval corpus + first image_service test suite"
```

---

## Task 2 (Phase T1): OCR text → secrets + PII detectors

**Why:** `model_ocr` currently only substring-matches 12 keywords. A screenshot containing a live AWS key or an SSN passes clean unless a literal keyword is present. The repo already has precise `ml.secrets.detect` and Presidio PII — run the OCR output through them. This is the single biggest detection gain and reuses built code.

**Files:**
- Create: `ml/image/ocr_scan.py`
- Test: `tests/test_image_service.py` (add cases)
- Modify: `image_service/main.py` (`model_ocr` calls the new scan)

**Interfaces:**
- Consumes: `ml.secrets.detector.detect(text) -> list[SecretFinding]` (fields `.kind`, `.severity`), and a Presidio `AnalyzerEngine` instance.
- Produces: `ml.image.ocr_scan.scan_ocr_text(text: str, presidio) -> AnalysisResult` with `module="ocr"`. Sets `blocked=True`, `risk` from the finding severity when a secret or a financial/gov PII entity (`CREDIT_CARD`, `US_SSN`, `IBAN`) is found; keeps the existing sensitive-keyword hit as a non-blocking `MEDIUM` signal; benign text → neutral.

- [ ] **Step 1: Write failing tests** (append to `tests/test_image_service.py`):

```python
from ml.image import ocr_scan
from presidio_analyzer import AnalyzerEngine
from common.schemas import RiskLevel

_PRESIDIO = AnalyzerEngine()

def test_ocr_scan_blocks_on_aws_key():
    r = ocr_scan.scan_ocr_text("here is the key AKIAIOSFODNN7REALKEYX and more", _PRESIDIO)
    assert r.blocked is True
    assert r.risk in (RiskLevel.HIGH, RiskLevel.CRITICAL)

def test_ocr_scan_blocks_on_ssn():
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
```

- [ ] **Step 2: Run to verify fail**

Run: `PYTHONPATH=. venv/bin/python -m pytest tests/test_image_service.py -k ocr_scan -q`
Expected: FAIL — `ModuleNotFoundError: ml.image.ocr_scan`.

- [ ] **Step 3: Implement `ml/image/ocr_scan.py`.** Import `detect` from `ml.secrets.detector` and `RiskLevel`/`AnalysisResult` from `common.schemas`. Run secrets first (blocking, severity→risk via `max(... key=list(RiskLevel).index)`), then Presidio entities restricted to `["CREDIT_CARD","US_SSN","IBAN","EMAIL_ADDRESS","PHONE_NUMBER"]` (financial/gov block, contact info non-blocking — mirror `text_service.model_patterns`), then the sensitive-keyword list (non-blocking MEDIUM). OR the decisions. Wrap in try/except → neutral result on failure.

- [ ] **Step 4: Run to verify pass**

Run: `PYTHONPATH=. venv/bin/python -m pytest tests/test_image_service.py -k ocr_scan -q`
Expected: PASS (4 tests).

- [ ] **Step 5: Wire into `image_service/main.py`.** Replace the body of `model_ocr` so that after `pytesseract.image_to_string`, it delegates to `ocr_scan.scan_ocr_text(text, presidio_analyzer)` (add a module-global Presidio engine loaded in `load_models`, same as text_service). Keep `raw_data={"extracted_text": text[:500]}`.

- [ ] **Step 6: Add an end-to-end handler test** that POSTs `secret_screenshot` bytes to the app and asserts BLOCK. Use Starlette `TestClient`:

```python
from starlette.testclient import TestClient

def test_analyze_blocks_secret_screenshot():
    from image_service.main import app
    with TestClient(app) as client:  # triggers lifespan → load_models
        resp = client.post("/analyze", files={"file": ("s.png", synth_cases.SYNTH_CASES["secret_screenshot"], "image/png")})
        assert resp.status_code == 200
        assert resp.json()["status"] == "block"
```

- [ ] **Step 7: Run full image suite**

Run: `PYTHONPATH=. venv/bin/python -m pytest tests/test_image_service.py -q`
Expected: PASS (all). If the rendered secret isn't OCR-readable at default font size, bump render size in `synth_cases.render_text_png` until Tesseract reads it (verify with a scratch print), then re-run.

- [ ] **Step 8: Commit**

```bash
git add ml/image/ocr_scan.py image_service/main.py tests/test_image_service.py
git commit -m "feat(image): pipe OCR text through secrets + PII detectors"
```

---

## Task 3 (Phase T11): CLIP label-embedding cache + inference_mode + concurrency guard

**Why:** `model_semantic_clip` re-encodes all ~43 label strings through the CLIP text encoder on every request — pure wasted compute. Precompute once at startup. Add `torch.inference_mode()` and a concurrency semaphore so N parallel images don't blow up RAM on the laptop.

**Files:**
- Create: `ml/image/clip_labels.py`
- Create: `ml/image/clip_classifier.py`
- Test: `tests/test_image_service.py` (add cases)
- Modify: `image_service/main.py` (use the classifier; add semaphore)

**Interfaces:**
- Produces: `ml.image.clip_labels.SEMANTIC_LABELS: list[str]`, `LABEL_GROUP: dict[str,str]` (values in `{"pii_nsfw","sensitive","benign"}`), `GROUP_CUTOFF: dict[str,float]`.
- Produces: `ml.image.clip_classifier.ClipClassifier` with `__init__(self, model, processor)` (precomputes + caches text embeddings), and `classify(self, image) -> AnalysisResult` (module `"semantic_clip"`). At this phase preserve current single-argmax behavior/thresholds exactly — this task is a pure refactor + cache, no scoring change (Task 4 changes scoring). Assert-equal verdicts before/after on the corpus.

- [ ] **Step 1: Write failing test** — classifier caches embeddings and reproduces the argmax label on a known image:

```python
def test_clip_classifier_caches_text_embeddings():
    from image_service.main import _get_clip_classifier
    clf = _get_clip_classifier()
    assert clf is not None
    assert clf.text_embeds is not None
    assert clf.text_embeds.shape[0] == len(clf.labels)

def test_clip_classify_returns_result_for_benign():
    from image_service.main import _get_clip_classifier
    from PIL import Image
    import io
    clf = _get_clip_classifier()
    img = Image.open(io.BytesIO(synth_cases.SYNTH_CASES["benign_gradient"])).convert("RGB")
    r = clf.classify(img)
    assert r.module == "semantic_clip"
    assert r.blocked is False
```

- [ ] **Step 2: Run to verify fail**

Run: `PYTHONPATH=. venv/bin/python -m pytest tests/test_image_service.py -k clip -q`
Expected: FAIL — `_get_clip_classifier` / module not defined.

- [ ] **Step 3: Implement `ml/image/clip_labels.py`** — move `SEMANTIC_LABELS` out of main.py verbatim, add `LABEL_GROUP` mapping each existing label to `pii_nsfw` / `sensitive` / `benign` (derived from the current `is_pii` test and `SENSITIVE_LABELS` membership), and `GROUP_CUTOFF = {"pii_nsfw": 0.4, "sensitive": 0.6, "benign": 1.0}` (same numbers the current code uses).

- [ ] **Step 4: Implement `ml/image/clip_classifier.py`** — in `__init__`, run the processor on `SEMANTIC_LABELS` once and store `self.text_embeds = model.get_text_features(...)` (L2-normalized) under `torch.inference_mode()`. In `classify`, compute image features, dot against cached text embeds → logits → softmax, then reproduce the EXISTING decision logic (argmax label, `is_pii and score>0.4 → block critical`; `sensitive and score>0.6 → 0.5 warn` — note the OCR-cross-check moves to aggregation, so at this phase set the sensitive-visual result non-blocking `MEDIUM` and let the handler keep prior behavior). Set `blocked`/`risk` accordingly.

- [ ] **Step 5: Wire into `image_service/main.py`** — add module global `_clip_classifier`, build it in `load_models` after CLIP loads, expose `_get_clip_classifier()`. Replace `model_semantic_clip(image, ocr_result)` call site with `_clip_classifier.classify(image)`. Add `_CLIP_SEM = asyncio.Semaphore(int(os.getenv("IMAGE_MAX_CONCURRENCY", "2")))` and wrap the CLIP call in `async with _CLIP_SEM:`.

- [ ] **Step 6: Run to verify pass + no regression**

Run: `PYTHONPATH=. venv/bin/python -m pytest tests/test_image_service.py -q`
Expected: PASS. Confirm benign_gradient still ALLOW, secret_screenshot still BLOCK (via OCR path from Task 2).

- [ ] **Step 7: Commit**

```bash
git add ml/image/clip_labels.py ml/image/clip_classifier.py image_service/main.py tests/test_image_service.py
git commit -m "perf(image): cache CLIP label embeddings, inference_mode, concurrency guard"
```

---

## Task 4 (Phase T2): Multi-label + calibrated CLIP decisions

**Why:** softmax-argmax reports one label even when an image is simultaneously an ID card AND nsfw AND a logo, and the score is uncalibrated (depends on label count). Move to per-label sigmoid on the raw `logits_per_image` (temperature-scaled), evaluate every group's max-label against its own cutoff, and report ALL groups over cutoff. Calibrate cutoffs against the T5 corpus.

**Files:**
- Modify: `ml/image/clip_classifier.py`
- Modify: `ml/image/clip_labels.py` (final cutoffs)
- Test: `tests/test_image_service.py` (multi-label assertions)

**Interfaces:**
- Produces: `ClipClassifier.classify` now returns `raw_data={"group_scores": {group: max_prob}, "labels_fired": [...]}` and `findings` listing every fired group; `blocked=True` if any `pii_nsfw` label ≥ its cutoff; `sensitive` group over cutoff → non-blocking `MEDIUM` finding (final block on sensitive-visual is decided in aggregation together with the OCR signal — Task 5).

- [ ] **Step 1: Write failing tests** — a benign image fires no blocking group; the classifier surfaces per-group scores:

```python
def test_clip_multilabel_benign_fires_nothing_blocking():
    from image_service.main import _get_clip_classifier
    from PIL import Image; import io
    clf = _get_clip_classifier()
    img = Image.open(io.BytesIO(synth_cases.SYNTH_CASES["benign_gradient"])).convert("RGB")
    r = clf.classify(img)
    assert "group_scores" in r.raw_data
    assert set(r.raw_data["group_scores"]) >= {"pii_nsfw", "sensitive", "benign"}
    assert r.blocked is False

def test_clip_sigmoid_scores_are_independent():
    # sigmoid on scaled logits: each group score is in [0,1] and not forced to sum to 1
    from image_service.main import _get_clip_classifier
    from PIL import Image; import io
    clf = _get_clip_classifier()
    img = Image.open(io.BytesIO(synth_cases.SYNTH_CASES["business_doc"])).convert("RGB")
    r = clf.classify(img)
    gs = r.raw_data["group_scores"]
    assert all(0.0 <= v <= 1.0 for v in gs.values())
```

- [ ] **Step 2: Run to verify fail**

Run: `PYTHONPATH=. venv/bin/python -m pytest tests/test_image_service.py -k "multilabel or sigmoid" -q`
Expected: FAIL — `group_scores` not in raw_data.

- [ ] **Step 3: Implement** — in `classify`, compute `logits = logits_per_image[0]`, apply `probs = torch.sigmoid(logits / TEMPERATURE)` (start `TEMPERATURE=100.0`; CLIP logits are large post logit-scale — tune so benign corpus stays below cutoffs and the pii/sensitive synth cases clear them). For each group, take the max prob over that group's labels. Block if `pii_nsfw` group ≥ `GROUP_CUTOFF["pii_nsfw"]`.

- [ ] **Step 4: Calibrate** — write a scratch script (not committed) printing per-group scores for all 7 synth cases; pick `TEMPERATURE` and per-group cutoffs so benign_gradient/business_doc don't trip pii_nsfw and the intended cases do where determinable. Record chosen values in `clip_labels.GROUP_CUTOFF` with a comment citing the corpus.

- [ ] **Step 5: Run to verify pass + full adversarial re-run**

Run: `PYTHONPATH=. venv/bin/python -m pytest tests/test_image_service.py -q`
Expected: PASS. Re-run the WHOLE suite (the accept/reject gate), not just the new cases.

- [ ] **Step 6: Commit**

```bash
git add ml/image/clip_classifier.py ml/image/clip_labels.py tests/test_image_service.py
git commit -m "feat(image): multi-label sigmoid CLIP with calibrated per-group cutoffs"
```

---

## Task 5 (Phase T3): File-safety hardening + real stego + decision aggregation

**Why:** `Image.open` is called on untrusted bytes with no guards — no decompression-bomb limit, no polyglot/appended-payload check, no format allow-list, no EXIF-GPS leak detection. The stego heuristic is a single R-channel LSB test that flags near-random images (most natural photos). Replace with chi-square LSB. Finally port decision-level aggregation so the verdict is an OR of calibrated analyzer decisions, not the current dead `final_score`/magic-weight path.

**Files:**
- Create: `ml/image/file_safety.py`
- Create: `ml/image/stego.py`
- Test: `tests/test_image_service.py`
- Modify: `image_service/main.py` (call file_safety first, new stego, decision aggregation, remove dead `final_score`)

**Interfaces:**
- Produces: `ml.image.file_safety.check_bytes(data: bytes) -> AnalysisResult` (module `"file_safety"`): blocks on trailing bytes past image EOF (PNG after IEND CRC, JPEG after EOI `FFD9`), on SVG/unknown magic, and sets `Image.MAX_IMAGE_PIXELS` guard; EXIF-GPS present → non-blocking `MEDIUM`.
- Produces: `ml.image.stego.chi_square_lsb(image) -> AnalysisResult` (module `"stego"`): non-blocking `LOW`/`MEDIUM` signal from the chi-square statistic on the LSB plane.

- [ ] **Step 1: Write failing tests:**

```python
from ml.image import file_safety, stego
from PIL import Image; import io

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

def test_stego_clean_image_low_signal():
    img = Image.open(io.BytesIO(synth_cases.SYNTH_CASES["benign_gradient"])).convert("RGB")
    r = stego.chi_square_lsb(img)
    assert r.blocked is False
```

- [ ] **Step 2: Run to verify fail**

Run: `PYTHONPATH=. venv/bin/python -m pytest tests/test_image_service.py -k "file_safety or stego" -q`
Expected: FAIL — modules not defined.

- [ ] **Step 3: Implement `ml/image/file_safety.py`.** Magic-byte sniff (PNG `89504E47`, JPEG `FFD8`, GIF `GIF8`); reject anything else (incl. SVG/XML) as blocked. For PNG: find `IEND` + 4-byte CRC, block if bytes remain. For JPEG: find last `FFD9`, block if trailing bytes. Set `Image.MAX_IMAGE_PIXELS` and catch `DecompressionBombError` from a probe `Image.open(...).verify()` → block. EXIF: `Image.open(...).getexif()` GPS IFD present → non-blocking MEDIUM finding.

- [ ] **Step 4: Implement `ml/image/stego.py`.** Chi-square test on the LSB plane of each channel (classic pairs-of-values chi-square steganalysis via scipy `chisquare`); map the statistic/p-value to a non-blocking LOW/MEDIUM signal. Never blocks alone (steganalysis is advisory here). Replace the old `model_stego`.

- [ ] **Step 5: Run to verify pass**

Run: `PYTHONPATH=. venv/bin/python -m pytest tests/test_image_service.py -k "file_safety or stego" -q`
Expected: PASS.

- [ ] **Step 6: Rewrite the `analyze_image` aggregation in `image_service/main.py`.** Call `file_safety.check_bytes(contents)` FIRST — if it blocks (polyglot/bomb/bad-format), short-circuit to a BLOCK verdict before even decoding for the models. Otherwise run OCR / CLIP / YOLO / stego, collect `AnalysisResult`s, and aggregate by decision exactly like `text_service.analyze_text`: `blocked_results = [r for r in results if r.blocked]`; block with max risk if any; **delete the dead `final_score` line and the max/weighted-score branch**. Add the sensitive-visual + sensitive-OCR cross-check here: if CLIP `sensitive` group fired AND OCR flagged sensitive text, escalate to blocking (preserves the original intent that now lives in aggregation).

- [ ] **Step 7: Run full suite + regression sweep**

Run: `PYTHONPATH=. venv/bin/python -m pytest tests/test_image_service.py -q`
Expected: PASS. Verify: benign_gradient ALLOW, secret_screenshot/pii_screenshot BLOCK, trailing_zip BLOCK, business_doc (keyword-only, no secret) not falsely CRITICAL.

- [ ] **Step 8: Commit**

```bash
git add ml/image/file_safety.py ml/image/stego.py image_service/main.py tests/test_image_service.py
git commit -m "feat(image): file-safety guards, chi-square stego, decision-level aggregation"
```

---

## Task 6 (Phase T6): OCR + CLIP preprocessing ensemble

**Why:** Tesseract accuracy on screenshots jumps with grayscale/upscale/threshold and correct `--psm`; a small ID card in the corner of a large screenshot is missed by a single global CLIP view. Add multi-crop max-pool for CLIP and a preprocessing pass for OCR. Pure signal-in improvement, no weights touched.

**Files:**
- Create: `ml/image/preprocess.py`
- Modify: `image_service/main.py` (OCR uses preprocessed image)
- Modify: `ml/image/clip_classifier.py` (multi-crop max-pool)
- Test: `tests/test_image_service.py`

**Interfaces:**
- Produces: `ml.image.preprocess.for_ocr(image) -> Image` (grayscale, upscale ≤2x if small, Otsu-ish threshold via `PIL.ImageOps.autocontrast` + point threshold).
- Produces: `ml.image.preprocess.crops(image) -> list[Image]` (whole + center crop + quadrant tiles, each resized to CLIP input).
- Modifies: `ClipClassifier.classify` to max-pool group scores over `crops(image)`.

- [ ] **Step 1: Write failing tests:**

```python
from ml.image import preprocess
from PIL import Image; import io

def test_for_ocr_returns_image():
    img = Image.open(io.BytesIO(synth_cases.SYNTH_CASES["secret_screenshot"])).convert("RGB")
    out = preprocess.for_ocr(img)
    assert out.size[0] >= img.size[0]  # upscaled or equal

def test_crops_includes_whole_and_tiles():
    img = Image.open(io.BytesIO(synth_cases.SYNTH_CASES["benign_gradient"])).convert("RGB")
    cs = preprocess.crops(img)
    assert len(cs) >= 3
```

- [ ] **Step 2: Run to verify fail**

Run: `PYTHONPATH=. venv/bin/python -m pytest tests/test_image_service.py -k "for_ocr or crops" -q`
Expected: FAIL — module not defined.

- [ ] **Step 3: Implement `ml/image/preprocess.py`** (`for_ocr`, `crops`).

- [ ] **Step 4: Wire OCR** — in `model_ocr`, call `pytesseract.image_to_string(preprocess.for_ocr(image), config="--psm 6")` and keep delegating text to `ocr_scan`.

- [ ] **Step 5: Wire CLIP multi-crop** — in `classify`, compute group scores for each crop, take the element-wise max per group. Guard cost with `IMAGE_MAX_CROPS` env (default 3) so laptop CPU stays bounded.

- [ ] **Step 6: Run full suite + adversarial re-run**

Run: `PYTHONPATH=. venv/bin/python -m pytest tests/test_image_service.py -q`
Expected: PASS. Re-confirm no benign regression (the recurring lesson: re-run the whole set, don't trust a single new green test).

- [ ] **Step 7: Commit**

```bash
git add ml/image/preprocess.py image_service/main.py ml/image/clip_classifier.py tests/test_image_service.py
git commit -m "feat(image): OCR preprocessing + CLIP multi-crop max-pool"
```

---

## Final: whole-repo regression + summary

- [ ] Run the entire repo suite: `PYTHONPATH=. venv/bin/python -m pytest tests/ -q`. Expected: all pass except the 3 known root-owned-log `test_dns_filter` failures if those root files reappear (fix: `rm -f logs/*.log`).
- [ ] Update the memory file `project_bifrost_firewall_modelswap.md` — image_service is no longer "deferred/untouched"; record what changed and that model weights stayed fixed.
- [ ] Summarize the branch diff for the user; do NOT merge to main without explicit approval (user is cautious about main — PR flow).

## Self-Review notes

- **Spec coverage:** T5→Task1, T1→Task2, T11→Task3, T2→Task4, T3→Task5, T6→Task6. T7 (pHash) / T8 (cross-signal fusion) / T9 (multi-frame beyond the GIF corpus case) / T10 (broader adversarial) deliberately deferred — not in the recommended order the user accepted; can be follow-ups.
- **Model-weight constraint honored:** no task loads a different CLIP/YOLO/OCR model; all changes are glue/calibration/preprocessing.
- **Type consistency:** every analyzer returns `common.schemas.AnalysisResult`; aggregation uses `.blocked`/`.risk` identically to `text_service.analyze_text`.
- **Ambiguity resolved:** sensitive-visual final block decision lives in aggregation (Task 5 Step 6), not in the CLIP classifier, so CLIP + OCR signals combine in one place.
