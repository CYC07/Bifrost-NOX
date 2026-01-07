from fastapi import FastAPI, UploadFile, File
import uvicorn
import sys
import os
import logging

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from common.schemas import VerdictStatus, AggregatedVerdict, RiskLevel, AnalysisResult

app = FastAPI(title="Document Analysis Service")
logger = logging.getLogger("document_service")

# --- MOCK MODELS ---
def model_structure(data: bytes):
    return AnalysisResult(module="structure", score=0.0, findings=[])

def model_content_understanding(data: bytes):
    # Mock: Check for "CONFIDENTIAL" string in bytes (simplistic)
    if b"CONFIDENTIAL" in data.upper():
        return AnalysisResult(module="content", score=1.0, findings=["CONFIDENTIAL marker found"])
    return AnalysisResult(module="content", score=0.0, findings=[])

def model_malware(data: bytes):
    # Mock: Check for EICAR signature test
    if b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" in data:
        return AnalysisResult(module="malware", score=1.0, findings=["EICAR Test Signature"])
    return AnalysisResult(module="malware", score=0.0, findings=[])

def model_metadata(data: bytes):
    return AnalysisResult(module="metadata", score=0.0, findings=[])
# -------------------

@app.post("/analyze", response_model=AggregatedVerdict)
async def analyze_document(file: UploadFile = File(...)):
    contents = await file.read()
    logger.info(f"Analyzing document: {file.filename} ({len(contents)} bytes)")

    r1 = model_structure(contents)
    r2 = model_content_understanding(contents)
    r3 = model_malware(contents)
    r4 = model_metadata(contents)
    
    results = [r1, r2, r3, r4]
    
    max_score = max(r.score for r in results)
    findings = []
    for r in results:
        findings.extend(r.findings)
        
    status = VerdictStatus.ALLOW
    risk = RiskLevel.SAFE
    
    if max_score > 0.9:
        status = VerdictStatus.BLOCK
        risk = RiskLevel.CRITICAL
    elif max_score > 0.5:
        risk = RiskLevel.MEDIUM
        status = VerdictStatus.BLOCK # Block confidential docs too

    return AggregatedVerdict(
        status=status,
        risk_level=risk,
        reason=f"Document Threat Score: {max_score}",
        detailed_findings={"findings": findings, "scores": {r.module: r.score for r in results}}
    )

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8002)
