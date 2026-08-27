from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.requests import Request
from starlette.datastructures import UploadFile
import uvicorn
import sys
import os
import logging
from PIL import Image
import io
import pytesseract
import torch
from transformers import CLIPProcessor, CLIPModel
import numpy as np
from ultralytics import YOLO
import asyncio
import dataclasses
import json
from contextlib import asynccontextmanager

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from common.schemas import VerdictStatus, AggregatedVerdict, RiskLevel, AnalysisResult
from common.utils import setup_logging
from presidio_analyzer import AnalyzerEngine
from ml.image import ocr_scan
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
def model_ocr(image: Image.Image):
    """OCR the image, then run the extracted text through the firewall's real
    text detectors (secrets + PII + SSN-fallback + keywords) via ml.image.ocr_scan
    — replaces the old 12-keyword substring match."""
    try:
        text = pytesseract.image_to_string(image)
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

def model_stego(image_bytes: bytes):
    try:
        image = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        img_array = np.array(image)
        lsb_plane = img_array[:, :, 0] & 1
        avg_density = np.mean(lsb_plane)
        distance_from_random = abs(avg_density - 0.5)
        score = 0.0
        findings = []
        if distance_from_random < 0.005: 
            score = 0.3 
            findings.append("Suspicious LSB pattern detected (Possible Steganography)")
        return AnalysisResult(module="stego", score=score, findings=findings)
    except Exception as e:
        logger.error(f"Stego Error: {e}")
        return AnalysisResult(module="stego", score=0.0, findings=[])

# --- HANDLERS ---

async def analyze_image(request: Request):
    form = await request.form()
    file_item = form.get("file")
    
    if not file_item:
        return JSONResponse({"error": "No file provided"}, status_code=400)

    contents = await file_item.read()
    try:
        image = Image.open(io.BytesIO(contents))
    except Exception as e:
        return JSONResponse({"detail": "Invalid image file"}, status_code=400)

    logger.info(f"Analyzing image: {file_item.filename} ({image.width}x{image.height})")

    future_ocr = asyncio.to_thread(model_ocr, image)
    future_obj = asyncio.to_thread(model_object_detection, image)
    future_stego = asyncio.to_thread(model_stego, contents)

    r_ocr, r_obj, r_stego = await asyncio.gather(future_ocr, future_obj, future_stego)
    if _clip_classifier is not None:
        async with _CLIP_SEM:
            r_clip = await asyncio.to_thread(_clip_classifier.classify, image.convert("RGB"))
    else:
        r_clip = AnalysisResult(module="semantic_clip", score=0.0, findings=["Model not loaded"])
    
    results = [r_ocr, r_clip, r_obj, r_stego]
    
    max_score = max(r.score for r in results)
    weighted_score = (
        (r_clip.score * 0.4) +
        (r_ocr.score * 0.3) +
        (r_stego.score * 0.2) +
        (r_obj.score * 0.1)
    )
    
    findings = []
    detailed_scores = {}
    for r in results:
        findings.extend(r.findings)
        detailed_scores[r.module] = r.score
        
    status = VerdictStatus.ALLOW
    risk = RiskLevel.SAFE
    
    final_score = max(max_score, weighted_score)
    
    if max_score > 0.8: 
        status = VerdictStatus.BLOCK
        risk = RiskLevel.CRITICAL
        reason = f"Critical Threat Detected (Score: {max_score})"
    elif weighted_score > 0.5: 
        status = VerdictStatus.BLOCK 
        risk = RiskLevel.MEDIUM
        reason = f"Combined Risk Threshold Exceeded (Score: {weighted_score:.2f})"
    else:
        reason = "Safe"

    verdict = AggregatedVerdict(
        status=status,
        risk_level=risk,
        reason=reason,
        detailed_findings={"findings": findings, "scores": detailed_scores}
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
