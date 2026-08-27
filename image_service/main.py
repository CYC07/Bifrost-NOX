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
import json
from contextlib import asynccontextmanager

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from common.schemas import VerdictStatus, AggregatedVerdict, RiskLevel, AnalysisResult
from common.utils import setup_logging
from presidio_analyzer import AnalyzerEngine
from ml.image import ocr_scan, file_safety, stego, preprocess
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

# Bound concurrent CLIP forwards so N parallel images don't exhaust the
# laptop's RAM (each forward holds the model + activations).
_CLIP_SEM = asyncio.Semaphore(int(os.getenv("IMAGE_MAX_CONCURRENCY", "2")))


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
                texts.append(pytesseract.image_to_string(preprocess.for_ocr(frame)))
            text = "\n".join(texts)
        else:
            text = pytesseract.image_to_string(preprocess.for_ocr(image))
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

    # File-safety runs FIRST, on raw bytes, before any model decode. A polyglot,
    # decompression bomb, or rejected format short-circuits to BLOCK — we never
    # hand crafted-malicious bytes to the model decoders.
    r_safety = file_safety.check_bytes(contents)
    if r_safety.blocked:
        verdict = AggregatedVerdict(
            status=VerdictStatus.BLOCK,
            risk_level=r_safety.risk,
            reason="Blocked by: file_safety",
            detailed_findings={"findings": r_safety.findings, "scores": {"file_safety": r_safety.score}},
        )
        return JSONResponse(dataclasses.asdict(verdict))

    try:
        image = Image.open(io.BytesIO(contents))
    except Exception:
        return JSONResponse({"detail": "Invalid image file"}, status_code=400)

    logger.info(f"Analyzing image: {file_item.filename} ({image.width}x{image.height})")

    future_ocr = asyncio.to_thread(model_ocr, image)
    future_obj = asyncio.to_thread(model_object_detection, image)
    future_stego = asyncio.to_thread(stego.chi_square_lsb, image.convert("RGB"))

    r_ocr, r_obj, r_stego = await asyncio.gather(future_ocr, future_obj, future_stego)
    if _clip_classifier is not None:
        async with _CLIP_SEM:
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

    return JSONResponse(dataclasses.asdict(verdict))

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
