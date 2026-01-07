from fastapi import FastAPI, HTTPException, UploadFile, File
from pydantic import BaseModel
import uvicorn
import sys
import os
import logging
from PIL import Image
import io
import pytesseract

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from common.schemas import VerdictStatus, AggregatedVerdict, RiskLevel, AnalysisResult

app = FastAPI(title="Image Analysis Service")
logger = logging.getLogger("image_service")

# --- OCR CONFIGURATION ---
# If you provide traineddata in the tesseract-5.5.2/tessdata folder, 
# uncomment the lines below to use that specific version's data.
# TESSDATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'tesseract-5.5.2', 'tessdata'))
# if os.path.exists(os.path.join(TESSDATA_DIR, 'eng.traineddata')):
#     os.environ["TESSDATA_PREFIX"] = TESSDATA_DIR

def model_ocr(image: Image.Image):
    """Real Tesseract OCR Analysis"""
    try:
        # Perform OCR
        text = pytesseract.image_to_string(image)
        text_lower = text.lower()
        
        findings = []
        score = 0.0
        
        # Check for sensitive keywords in image text
        sensitive_keywords = ["confidential", "secret", "password", "private key", "internal use only"]
        for keyword in sensitive_keywords:
            if keyword in text_lower:
                findings.append(f"Sensitive keyword detected in image: {keyword}")
                score = max(score, 0.9)
        
        if text.strip() and not findings:
            # Found text but no sensitive keywords
            score = max(score, 0.1)
            
        return AnalysisResult(
            module="ocr", 
            score=score, 
            findings=findings, 
            raw_data={"extracted_text": text[:500]}
        )
    except Exception as e:
        logger.error(f"OCR Error: {e}")
        return AnalysisResult(module="ocr", score=0.0, findings=[f"OCR Error: {str(e)}"])

def model_object_detection(image: Image.Image):
    """YOLO Mock"""
    # Mock: Random detection
    return AnalysisResult(module="object_detection", score=0.0, findings=[])

def model_stego(image_bytes: bytes):
    """Steganography Mock"""
    # Mock: Check file size vs dimensions ratio (crude heuristic)
    return AnalysisResult(module="stego", score=0.0, findings=[])

def model_semantic(image: Image.Image):
    """CLIP Mock"""
    return AnalysisResult(module="semantic", score=0.0, findings=[])
# -------------------

@app.post("/analyze", response_model=AggregatedVerdict)
async def analyze_image(file: UploadFile = File(...)):
    contents = await file.read()
    try:
        image = Image.open(io.BytesIO(contents))
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid image file")

    logger.info(f"Analyzing image: {file.filename} ({image.width}x{image.height})")

    # Run models
    r1 = model_ocr(image)
    r2 = model_object_detection(image)
    r3 = model_stego(contents)
    r4 = model_semantic(image)
    
    results = [r1, r2, r3, r4]
    
    # Aggregation
    max_score = max(r.score for r in results)
    findings = []
    for r in results:
        findings.extend(r.findings)
        
    status = VerdictStatus.ALLOW
    risk = RiskLevel.SAFE
    
    if max_score > 0.8:
        status = VerdictStatus.BLOCK
        risk = RiskLevel.CRITICAL
    elif max_score > 0.6:
        risk = RiskLevel.MEDIUM

    return AggregatedVerdict(
        status=status,
        risk_level=risk,
        reason=f"Image Analysis Score: {max_score}",
        detailed_findings={"findings": findings, "scores": {r.module: r.score for r in results}}
    )

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)