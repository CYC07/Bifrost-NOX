from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.requests import Request
from starlette.datastructures import UploadFile
import uvicorn
import sys
import os
import logging
from PIL import Image, ImageSequence
import io
import pytesseract
import torch
from transformers import CLIPProcessor, CLIPModel
from ultralytics import YOLO
import asyncio
import dataclasses
import hashlib
import json
from collections import OrderedDict
from contextlib import asynccontextmanager

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from common.schemas import VerdictStatus, AggregatedVerdict, RiskLevel, AnalysisResult
from common.utils import setup_logging
from presidio_analyzer import AnalyzerEngine
from ml.image import ocr_scan, ocr_read, file_safety, stego, preprocess
from ml.image.clip_classifier import ClipClassifier

setup_logging("image_service")
logger = logging.getLogger("image_service")

# --- MODELS CONFIG ---
TESSDATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'tesseract-5.5.2', 'tessdata'))
if os.path.exists(os.path.join(TESSDATA_DIR, 'eng.traineddata')):
    os.environ["TESSDATA_PREFIX"] = TESSDATA_DIR

CLIP_MODEL_ID = "openai/clip-vit-base-patch32"
clip_model = None
clip_processor = None
yolo_model = None
presidio_analyzer = None
_clip_classifier = None

def _env_int(name: str, default: int, minimum: int = 0) -> int:
    """Integer setting from the environment; unusable or below `minimum` -> the default."""
    try:
        value = int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default
    return value if value >= minimum else default


# At most IMAGE_MAX_CONCURRENCY images go through the models at a time; the rest queue. The whole analysis is bounded,
# not just CLIP: OCR (a Tesseract process per image), object detection and the steganography check used to run for
# every queued image at once, and a page of 20 thumbnails took 60 s each instead of about 1 s (swap thrash), so most
# timed out unanalysed and were let through.
_ANALYSIS_SEM = asyncio.Semaphore(_env_int("IMAGE_MAX_CONCURRENCY", 2, 1))

# Verdicts by SHA-256 of the image bytes (IMAGE_CACHE_SIZE entries, 0 = off): pages repeat thumbnails and icons.
_VERDICT_CACHE: "OrderedDict[str, dict]" = OrderedDict()
_INFLIGHT: "dict[str, asyncio.Future]" = {}   # analyses running right now, by image hash


def _cache_get(key: str):
    if _env_int("IMAGE_CACHE_SIZE", 512) <= 0:
        return None
    hit = _VERDICT_CACHE.get(key)
    if hit is not None:
        _VERDICT_CACHE.move_to_end(key)
    return hit


def _cache_put(key: str, verdict: dict) -> None:
    size = _env_int("IMAGE_CACHE_SIZE", 512)
    if size <= 0:
        return
    _VERDICT_CACHE[key] = verdict
    _VERDICT_CACHE.move_to_end(key)
    while len(_VERDICT_CACHE) > size:
        _VERDICT_CACHE.popitem(last=False)


def _get_clip_classifier():
    return _clip_classifier


def _init_clip_classifier(model, processor):
    global _clip_classifier
    _clip_classifier = ClipClassifier(model, processor)


async def load_models():
    global clip_model, clip_processor, yolo_model, presidio_analyzer
    logger.info("Loading Presidio PII engine...")
    try:
        presidio_analyzer = AnalyzerEngine()
        logger.info("Presidio Loaded.")
    except Exception as e:
        logger.error(f"Failed to load Presidio: {e}")

    logger.info(f"Loading Semantic Model: {CLIP_MODEL_ID}...")
    try:
        clip_model = CLIPModel.from_pretrained(CLIP_MODEL_ID)
        clip_processor = CLIPProcessor.from_pretrained(CLIP_MODEL_ID)
        _init_clip_classifier(clip_model, clip_processor)
        logger.info("Semantic Model Loaded Successfully.")
    except Exception as e:
        logger.error(f"Failed to load CLIP model: {e}")

    logger.info("Loading YOLOv8 Nano...")
    try:
        yolo_model = YOLO("yolov8n.pt") 
        logger.info("YOLO Model Loaded.")
    except Exception as e:
        logger.error(f"Failed to load YOLO: {e}")

# --- MODEL LOGIC (UNCHANGED) ---
OCR_MAX_FRAMES = int(os.getenv("IMAGE_OCR_MAX_FRAMES", "8"))


def model_ocr(image: Image.Image):
    """OCR the image, then run the extracted text through the firewall's real
    text detectors (secrets + PII + SSN-fallback + keywords) via ml.image.ocr_scan
    — replaces the old 12-keyword substring match.

    Animated/multi-page images (GIF/APNG/TIFF) are sampled across frames: a
    payload hidden in frame 2+ would otherwise bypass frame-1-only OCR."""
    try:
        n_frames = getattr(image, "n_frames", 1)
        if n_frames > 1:
            texts = []
            for i, frame in enumerate(ImageSequence.Iterator(image)):
                if i >= OCR_MAX_FRAMES:
                    break
                texts.append(ocr_read.read_text(frame))
            text = "\n".join(texts)
        else:
            text = ocr_read.read_text(image)
        return ocr_scan.scan_ocr_text(text, presidio_analyzer)
    except Exception as e:
        logger.error(f"OCR Error: {e}")
        return AnalysisResult(module="ocr", score=0.0, findings=[f"OCR Error: {str(e)}"])

def model_object_detection(image: Image.Image):
    if not yolo_model:
        return AnalysisResult(module="object_detection", score=0.0, findings=["Model not loaded"])
    try:
        results = yolo_model(image, verbose=False)
        findings = []
        score = 0.0
        risky_objects = {63: "Laptop Screen", 67: "Cell Phone"}
        for r in results:
            for box in r.boxes:
                cls_id = int(box.cls[0])
                conf = float(box.conf[0])
                label = r.names[cls_id]
                if cls_id in risky_objects and conf > 0.5:
                    findings.append(f"Detected Risky Device: {label} ({conf:.2f})")
                    score = max(score, 0.4) 
                elif conf > 0.6:
                    findings.append(f"Detected Object: {label}")
        return AnalysisResult(module="object_detection", score=score, findings=findings)
    except Exception as e:
        logger.error(f"YOLO Error: {e}")
        return AnalysisResult(module="object_detection", score=0.0, findings=[f"YOLO Error: {e}"])

# --- HANDLERS ---

async def analyze_image(request: Request):
    form = await request.form()
    file_item = form.get("file")
    
    if not file_item:
        return JSONResponse({"error": "No file provided"}, status_code=400)

    contents = await file_item.read()

    # Same bytes, same verdict: answer repeats from the cache without touching the models.
    key = hashlib.sha256(contents).hexdigest()
    cached = _cache_get(key)
    if cached is not None:
        return JSONResponse(cached)

    # File-safety runs FIRST, on raw bytes, before any model decode. A polyglot,
    # decompression bomb, or rejected format short-circuits to BLOCK — we never
    # hand crafted-malicious bytes to the model decoders. It is cheap, so it runs for every image,
    # including the tiny ones that skip the models below.
    r_safety = file_safety.check_bytes(contents)
    if r_safety.blocked:
        verdict = AggregatedVerdict(
            status=VerdictStatus.BLOCK,
            risk_level=r_safety.risk,
            reason="Blocked by: file_safety",
            detailed_findings={"findings": r_safety.findings, "scores": {"file_safety": r_safety.score}},
        )
        body = dataclasses.asdict(verdict)
        _cache_put(key, body)
        return JSONResponse(body)

    try:
        image = Image.open(io.BytesIO(contents))
    except Exception:
        return JSONResponse({"detail": "Invalid image file"}, status_code=400)

    # Icons and 1x1 trackers cannot carry readable text or explicit imagery, and CLIP resizes everything to 224 px
    # anyway: analysing them only delays the real images behind them (most of the timeouts were 1-5 KB files).
    min_bytes = _env_int("IMAGE_MIN_ANALYSIS_BYTES", 4096)
    min_pixels = _env_int("IMAGE_MIN_PIXELS", 4096)
    if len(contents) < min_bytes or image.width * image.height < min_pixels:
        note = (f"Model analysis skipped: image too small to judge ({len(contents)} bytes, "
                f"{image.width}x{image.height}); file-safety check only")
        verdict = AggregatedVerdict(
            status=VerdictStatus.ALLOW,
            risk_level=RiskLevel.SAFE,
            reason="No analyzer flagged a block",
            detailed_findings={"findings": list(r_safety.findings) + [note], "scores": {"file_safety": r_safety.score}},
        )
        body = dataclasses.asdict(verdict)
        _cache_put(key, body)
        return JSONResponse(body)

    # Identical images that arrive together share ONE analysis: the first request does the work, the others wait for
    # its result (a page asks for the same thumbnail several times at once). If the first one fails, they try themselves.
    while True:
        pending = _INFLIGHT.get(key)
        if pending is None:
            break
        shared = await asyncio.shield(pending)
        if shared is not None:
            return JSONResponse(shared)

    pending = asyncio.get_running_loop().create_future()
    _INFLIGHT[key] = pending
    try:
        body = await _run_models(image, r_safety, file_item.filename, key)
        pending.set_result(body)
        return JSONResponse(body)
    except BaseException:
        if not pending.done():
            pending.set_result(None)
        raise
    finally:
        if _INFLIGHT.get(key) is pending:
            del _INFLIGHT[key]


async def _run_models(image, r_safety, filename, key) -> dict:
    """The expensive part: OCR + object detection + steganography + CLIP, bounded by _ANALYSIS_SEM. Returns the verdict dict."""
    async with _ANALYSIS_SEM:
        # An identical image may have been analysed while this one waited its turn.
        cached = _cache_get(key)
        if cached is not None:
            return cached

        logger.info(f"Analyzing image: {filename} ({image.width}x{image.height})")

        future_ocr = asyncio.to_thread(model_ocr, image)
        future_obj = asyncio.to_thread(model_object_detection, image)
        future_stego = asyncio.to_thread(stego.chi_square_lsb, image.convert("RGB"))

        r_ocr, r_obj, r_stego = await asyncio.gather(future_ocr, future_obj, future_stego)
        if _clip_classifier is not None:
            r_clip = await asyncio.to_thread(_clip_classifier.classify, image.convert("RGB"))
        else:
            r_clip = AnalysisResult(module="semantic_clip", score=0.0, findings=["Model not loaded"])

    # Sensitive-visual + real-secret/PII cross-check: a DLP-relevant visual
    # (source code, financial sheet, phishing page) is advisory alone, but when
    # OCR also finds an ACTUAL secret or financial/gov PII on the same image the
    # combination is unambiguous. Escalation keys off r_ocr.blocked (a real
    # detected secret/PII), NOT the advisory keyword score — a bare keyword like
    # "password" or "q4" substring-matching in a benign code screenshot must not
    # turn a high-scoring "source code screenshot" visual into a block. (When
    # OCR blocks the verdict is already BLOCK anyway; the escalation exists to
    # raise the risk level and record the visual+text correlation.)
    if r_clip.raw_data and "sensitive" in r_clip.raw_data.get("groups_fired", []) and r_ocr.blocked:
        r_clip = dataclasses.replace(
            r_clip, blocked=True, risk=r_ocr.risk,
            findings=r_clip.findings + ["ESCALATED: sensitive visual + real secret/PII in OCR text"],
        )

    results = [r_safety, r_ocr, r_clip, r_obj, r_stego]

    findings = []
    detailed_scores = {}
    for r in results:
        findings.extend(r.findings)
        detailed_scores[r.module] = r.score

    # Decision-level aggregation (same as text_service.analyze_text): each
    # analyzer already made its own calibrated block/allow call; OR them and
    # report the highest risk among those that fired. No global threshold over
    # incomparable scores, no dead weighted-score path.
    blocked_results = [r for r in results if r.blocked]
    if blocked_results:
        status = VerdictStatus.BLOCK
        risk = max((r.risk for r in blocked_results), key=list(RiskLevel).index)
        reason = "Blocked by: " + ", ".join(sorted({r.module for r in blocked_results}))
    else:
        # Match text_service + the original image contract: an ALLOW verdict is
        # SAFE. Advisory non-blocking findings (EXIF GPS, stego signal) are kept
        # in detailed_findings but do not raise the top-level risk_level, which
        # downstream (orchestrator/dashboard) reads as the block severity.
        status = VerdictStatus.ALLOW
        risk = RiskLevel.SAFE
        reason = "No analyzer flagged a block"

    verdict = AggregatedVerdict(
        status=status,
        risk_level=risk,
        reason=reason,
        detailed_findings={"findings": findings, "scores": detailed_scores},
    )

    body = dataclasses.asdict(verdict)
    # A model that was not loaded gave a placeholder result, not a real one: do not remember that verdict.
    if _clip_classifier is not None:
        _cache_put(key, body)
    return body

routes = [
    Route("/analyze", analyze_image, methods=["POST"]),
]

@asynccontextmanager
async def lifespan(app):
    await load_models()
    yield

app = Starlette(debug=False, routes=routes, lifespan=lifespan)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)
