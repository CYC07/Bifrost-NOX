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

SEMANTIC_LABELS = [
    # --- Sensitive content (original) ---
    "proprietary source code screenshot with api keys",
    "internal financial spreadsheet with sensitive data",
    "server network diagram with ip addresses",
    "official id card passport document",
    "pakistani cnic national identity card",
    "smart identity card with chip",
    "nsfw nude explicit sexual content",
    "pornography and adult content",
    "bikini lingerie or semi-nude person",
    "architectural blueprint of secure facility",

    # --- Generic logo / branding detection ---
    "corporate logo or brand watermark on an image",
    "company logo prominently displayed on a document",
    "brand logo on product packaging or advertisement",
    "generic business trademark or registered brand mark",
    "sports team or athletic brand logo",
    "luxury fashion brand logo",

    # --- Phishing / brand impersonation login pages ---
    "microsoft office 365 or outlook login page with logo",
    "google or gmail account sign in page with logo",
    "apple id icloud sign in page with logo",
    "paypal payment or login page with logo",
    "amazon account sign in page with logo",
    "facebook or meta login page with logo",
    "instagram login page with logo",
    "linkedin login page with logo",
    "netflix or streaming service login with logo",
    "dropbox or cloud storage login page with logo",
    "whatsapp or telegram login page with logo",

    # --- Banking / financial logos ---
    "bank login page with financial institution logo",
    "visa mastercard or credit card company logo",
    "major bank logo like hsbc chase citi bank of america",
    "cryptocurrency exchange logo like binance coinbase kraken",
    "digital wallet or payment app logo",

    # --- Government / official emblems ---
    "government official seal or national emblem",
    "police law enforcement or military badge logo",
    "tax authority or revenue department logo",

    # --- Corporate / DLP relevant ---
    "internal corporate document with company logo header",
    "employee id badge with company logo",
    "corporate presentation slide with company branding",
    "confidential report watermarked with company logo",

    # --- Benign / baseline ---
    "standard photo of nature or animals",
    "public website screenshot without branding",
    "generic bar chart or graph",
    "plain photograph with no logos or branding",
]

SENSITIVE_LABELS = [
    # Original sensitive content
    "proprietary source code screenshot with api keys",
    "internal financial spreadsheet with sensitive data",
    "server network diagram with ip addresses",
    "official id card passport document",
    "pakistani cnic national identity card",
    "smart identity card with chip",
    "nsfw nude explicit sexual content",
    "pornography and adult content",
    "bikini lingerie or semi-nude person",
    "architectural blueprint of secure facility",

    # Phishing / brand impersonation (high risk)
    "microsoft office 365 or outlook login page with logo",
    "google or gmail account sign in page with logo",
    "apple id icloud sign in page with logo",
    "paypal payment or login page with logo",
    "amazon account sign in page with logo",
    "facebook or meta login page with logo",
    "instagram login page with logo",
    "linkedin login page with logo",
    "netflix or streaming service login with logo",
    "dropbox or cloud storage login page with logo",
    "whatsapp or telegram login page with logo",
    "bank login page with financial institution logo",
    "cryptocurrency exchange logo like binance coinbase kraken",

    # Corporate DLP
    "internal corporate document with company logo header",
    "employee id badge with company logo",
    "corporate presentation slide with company branding",
    "confidential report watermarked with company logo",
]

async def load_models():
    global clip_model, clip_processor, yolo_model
    logger.info(f"Loading Semantic Model: {CLIP_MODEL_ID}...")
    try:
        clip_model = CLIPModel.from_pretrained(CLIP_MODEL_ID)
        clip_processor = CLIPProcessor.from_pretrained(CLIP_MODEL_ID)
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
    try:
        text = pytesseract.image_to_string(image)
        text_lower = text.lower()
        findings = []
        score = 0.0
        sensitive_keywords = ["confidential", "secret", "password", "private key", "internal use only", "revenue", "q1", "q2", "q3", "q4", "budget", "ssn"]
        for keyword in sensitive_keywords:
            if keyword in text_lower:
                findings.append(f"Sensitive keyword detected: {keyword}")
                score = max(score, 0.9)
        return AnalysisResult(module="ocr", score=score, findings=findings, raw_data={"extracted_text": text[:500]})
    except Exception as e:
        logger.error(f"OCR Error: {e}")
        return AnalysisResult(module="ocr", score=0.0, findings=[f"OCR Error: {str(e)}"])

def model_semantic_clip(image: Image.Image, ocr_result: AnalysisResult):
    if not clip_model or not clip_processor:
        return AnalysisResult(module="semantic_clip", score=0.0, findings=["Model not loaded"])
    try:
        inputs = clip_processor(text=SEMANTIC_LABELS, images=image, return_tensors="pt", padding=True)
        outputs = clip_model(**inputs)
        probs = outputs.logits_per_image.softmax(dim=1).detach().numpy()[0]
        best_idx = probs.argmax()
        best_label = SEMANTIC_LABELS[best_idx]
        best_score = float(probs[best_idx])
        findings = [f"Classified as: {best_label} ({best_score:.2f})"]
        risk_score = 0.0
        logger.info(f"CLIP: {best_label} score={best_score}")
        is_pii = ("passport" in best_label or "id card" in best_label or "cnic" in best_label or "identity" in best_label or "nsfw" in best_label or "porn" in best_label or "nude" in best_label or "lingerie" in best_label)
        if is_pii and best_score > 0.4:
             risk_score = 0.95
             findings.append(f"CRITICAL: PII/NSFW Detected '{best_label}' (Strict Block)")
        elif best_label in SENSITIVE_LABELS and best_score > 0.6:
            has_sensitive_text = ocr_result.score > 0.5
            if has_sensitive_text:
                risk_score = 0.9 
                findings.append(f"CRITICAL: Sensitive Visual '{best_label}' + Sensitive Text Match")
            else:
                risk_score = 0.5 
                findings.append(f"WARNING: Sensitive Visual '{best_label}' detected (No text confirmation)")
        return AnalysisResult(module="semantic_clip", score=risk_score, findings=findings, raw_data={"top_label": best_label, "confidence": best_score})
    except Exception as e:
        logger.error(f"CLIP Error: {e}")
        return AnalysisResult(module="semantic_clip", score=0.0, findings=[f"CLIP Error: {str(e)}"])

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
    r_clip = await asyncio.to_thread(model_semantic_clip, image, r_ocr)
    
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

app = Starlette(debug=True, routes=routes, lifespan=lifespan)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)
