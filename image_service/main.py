from fastapi import FastAPI, HTTPException, UploadFile, File
from pydantic import BaseModel
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

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from common.schemas import VerdictStatus, AggregatedVerdict, RiskLevel, AnalysisResult

app = FastAPI(title="Image Analysis Service")
logger = logging.getLogger("image_service")
logging.basicConfig(level=logging.INFO)

# --- OCR CONFIGURATION ---
TESSDATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'tesseract-5.5.2', 'tessdata'))
if os.path.exists(os.path.join(TESSDATA_DIR, 'eng.traineddata')):
    os.environ["TESSDATA_PREFIX"] = TESSDATA_DIR

# --- CLIP MODEL (Semantic Analysis) ---
CLIP_MODEL_ID = "openai/clip-vit-base-patch32"
clip_model = None
clip_processor = None
yolo_model = None

# Labels to classify against
SEMANTIC_LABELS = [
    "proprietary source code screenshot with api keys", 
    "internal financial spreadsheet with sensitive data", 
    "server network diagram with ip addresses", 
    "official id card passport document", 
    "pakistani cnic national identity card",
    "smart identity card with chip",
    "nsfw nude explicit sexual content",
    "pornography and adult content",
    "bikini lingerie or semi-nude person",
    "standard photo of nature or animals", 
    "architectural blueprint of secure facility",
    "public website screenshot",
    "generic bar chart or graph"
]

SENSITIVE_LABELS = [
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
]

@app.on_event("startup")
async def load_models():
    """Load AI Models into Memory on Startup"""
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
        yolo_model = YOLO("yolov8n.pt") # Downloads on first run
        logger.info("YOLO Model Loaded.")
    except Exception as e:
        logger.error(f"Failed to load YOLO: {e}")

# --- MODELS ---

def model_ocr(image: Image.Image):
    """Real Tesseract OCR Analysis"""
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
    """Real CLIP Semantic Analysis (Refined with Hybrid Logic)"""
    if not clip_model or not clip_processor:
        return AnalysisResult(module="semantic_clip", score=0.0, findings=["Model not loaded"])

    try:
        # Zero-Shot Classification
        inputs = clip_processor(text=SEMANTIC_LABELS, images=image, return_tensors="pt", padding=True)
        outputs = clip_model(**inputs)
        
        probs = outputs.logits_per_image.softmax(dim=1).detach().numpy()[0]
        best_idx = probs.argmax()
        best_label = SEMANTIC_LABELS[best_idx]
        best_score = float(probs[best_idx])
        
        findings = [f"Classified as: {best_label} ({best_score:.2f})"]
        risk_score = 0.0
        
        # DEBUG: Log what CLIP sees
        logger.info(f"CLIP: {best_label} score={best_score}")

        # PII EXCEPTION: Lower threshold (0.4) because IDs are hard to classify perfectly
        is_pii = ("passport" in best_label or "id card" in best_label or "cnic" in best_label or "identity" in best_label or "nsfw" in best_label or "porn" in best_label or "nude" in best_label or "lingerie" in best_label)
        
        if is_pii and best_score > 0.4:
             risk_score = 0.95
             findings.append(f"CRITICAL: PII/NSFW Detected '{best_label}' (Strict Block)")
             
        # STANDARD SENSITIVE (Charts, Code): High threshold (0.6) + Hybrid Logic
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
    """Real YOLOv8 Object Detection"""
    if not yolo_model:
        return AnalysisResult(module="object_detection", score=0.0, findings=["Model not loaded"])
        
    try:
        # Run inference
        results = yolo_model(image, verbose=False)
        
        findings = []
        score = 0.0
        
        # Check detected classes
        # YOLOv8n COCO Classes: 63=laptop, 67=cell phone
        risky_objects = {63: "Laptop Screen", 67: "Cell Phone"}
        
        for r in results:
            for box in r.boxes:
                cls_id = int(box.cls[0])
                conf = float(box.conf[0])
                
                label = r.names[cls_id]
                
                if cls_id in risky_objects and conf > 0.5:
                    findings.append(f"Detected Risky Device: {label} ({conf:.2f})")
                    score = max(score, 0.4) # Medium risk for screens (DLP)
                elif conf > 0.6:
                    findings.append(f"Detected Object: {label}")
                    
        return AnalysisResult(module="object_detection", score=score, findings=findings)
        
    except Exception as e:
        logger.error(f"YOLO Error: {e}")
        return AnalysisResult(module="object_detection", score=0.0, findings=[f"YOLO Error: {e}"])

def model_stego(image_bytes: bytes):
    """Fast Statistical Steganography Detection (LSB Variance)"""
    try:
        image = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        # Convert to numpy array
        img_array = np.array(image)
        
        # Extract LSB of Red Channel (often used for stego)
        # Bitwise AND with 1
        lsb_plane = img_array[:, :, 0] & 1
        
        # Calculate Variance of LSBs
        # High randomness in LSBs (approx 0.5 mean, high entropy) suggests encryption/stego
        # Clean images usually have patterns in LSBs
        
        # Simple heuristic: Block Variance
        # We look at local variance.
        
        # Fast Global Metric for Prototype:
        # Calculate the average of LSBs. 
        # Encrypted data (Stego) usually tends towards exactly 0.5 average density.
        avg_density = np.mean(lsb_plane)
        distance_from_random = abs(avg_density - 0.5)
        
        score = 0.0
        findings = []
        
        # If it is suspiciously random (close to 0.5)
        if distance_from_random < 0.005: 
            # This is a crude heuristic. 
            # Real stego tools (SRNet) use residual noise.
            # But for a "lightweight" check, this catches simple random-noise embedding.
            score = 0.3 # Low confidence on simple statistic
            findings.append("Suspicious LSB pattern detected (Possible Steganography)")
            
        return AnalysisResult(module="stego", score=score, findings=findings)

    except Exception as e:
        logger.error(f"Stego Error: {e}")
        return AnalysisResult(module="stego", score=0.0, findings=[])

# -------------------

@app.post("/analyze", response_model=AggregatedVerdict)
async def analyze_image(file: UploadFile = File(...)):
    contents = await file.read()
    try:
        image = Image.open(io.BytesIO(contents))
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid image file")

    logger.info(f"Analyzing image: {file.filename} ({image.width}x{image.height})")

    # 1. PARALLEL EXECUTION (Independent Models)
    # We use to_thread because these models are CPU-bound blocking functions
    future_ocr = asyncio.to_thread(model_ocr, image)
    future_obj = asyncio.to_thread(model_object_detection, image)
    future_stego = asyncio.to_thread(model_stego, contents)

    r_ocr, r_obj, r_stego = await asyncio.gather(future_ocr, future_obj, future_stego)

    # 2. DEPENDENT EXECUTION (CLIP needs OCR)
    r_clip = await asyncio.to_thread(model_semantic_clip, image, r_ocr)
    
    results = [r_ocr, r_clip, r_obj, r_stego]
    
    # 3. WEIGHTED AGGREGATION
    # If any model reports CRITICAL (>0.8), we block immediately regardless of average.
    max_score = max(r.score for r in results)
    
    # Weighted Average for nuance (if no critical threat)
    # Weights: CLIP (40%), OCR (30%), Stego (20%), Object (10%)
    weighted_score = (
        (r_clip.score * 0.4) +
        (r_ocr.score * 0.3) +
        (r_stego.score * 0.2) +
        (r_obj.score * 0.1)
    )
    
    findings = []
    for r in results:
        findings.extend(r.findings)
        
    status = VerdictStatus.ALLOW
    risk = RiskLevel.SAFE
    
    # Decision Logic
    final_score = max(max_score, weighted_score)
    
    if max_score > 0.8: # Immediate Critical Block
        status = VerdictStatus.BLOCK
        risk = RiskLevel.CRITICAL
        reason = f"Critical Threat Detected (Score: {max_score})"
    elif weighted_score > 0.5: # Accumulation of medium risks
        status = VerdictStatus.BLOCK # Strict policy
        risk = RiskLevel.MEDIUM
        reason = f"Combined Risk Threshold Exceeded (Score: {weighted_score:.2f})"
    else:
        reason = "Safe"

    return AggregatedVerdict(
        status=status,
        risk_level=risk,
        reason=reason,
        detailed_findings={"findings": findings, "scores": {r.module: r.score for r in results}}
    )

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)
