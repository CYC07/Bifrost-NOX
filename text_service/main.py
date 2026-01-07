from fastapi import FastAPI, HTTPException, Body
from pydantic import BaseModel
import uvicorn
import sys
import os
import random
import logging

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from common.schemas import VerdictStatus, AggregatedVerdict, RiskLevel, AnalysisResult

app = FastAPI(title="Text Analysis Service")
logger = logging.getLogger("text_service")

# --- MOCK MODELS ---
# In production, these would be separate classes loading RoBERTa, Tree-sitter, etc.

def model_nlp_semantic(text):
    """Detects sentiment and intent (Mock)"""
    words = text.lower().split()
    if "attack" in words or "kill" in words:
        return AnalysisResult(module="nlp", score=0.9, findings=["Hostile intent detected"])
    if "secret" in words:
        return AnalysisResult(module="nlp", score=0.7, findings=["Confidential topic"])
    return AnalysisResult(module="nlp", score=0.1, findings=[])

def model_code_analysis(text):
    """Detects code and vulnerabilities (Mock)"""
    if "def " in text or "function" in text or ";" in text:
        if "eval(" in text or "exec(" in text:
            return AnalysisResult(module="code", score=0.95, findings=["Dangerous code execution code detected"])
        return AnalysisResult(module="code", score=0.3, findings=["Source code detected"])
    return AnalysisResult(module="code", score=0.0, findings=[])

def model_patterns(text):
    """Detects PII/Keys (Mock)"""
    # Simple mock regex for SSN-like or Key-like
    if "API_KEY" in text:
        return AnalysisResult(module="pattern", score=1.0, findings=["API Key detected"])
    return AnalysisResult(module="pattern", score=0.0, findings=[])

def model_context(text, metadata):
    """Context anomaly detection (Mock)"""
    # Mocking anomaly based on IP or random for demo
    return AnalysisResult(module="context", score=0.1, findings=[])

# -------------------

class TextRequest(BaseModel):
    text: str
    metadata: dict = {}

@app.post("/analyze", response_model=AggregatedVerdict)
async def analyze_text(request: TextRequest):
    text = request.text
    logger.info(f"Analyzing text length: {len(text)}")
    
    # Run models in parallel (mock sequential here)
    r1 = model_nlp_semantic(text)
    r2 = model_code_analysis(text)
    r3 = model_patterns(text)
    r4 = model_context(text, request.metadata)
    
    results = [r1, r2, r3, r4]
    
    # Aggregation Logic
    max_score = max(r.score for r in results)
    findings = []
    for r in results:
        findings.extend(r.findings)
        
    status = VerdictStatus.ALLOW
    risk = RiskLevel.SAFE
    
    if max_score > 0.8:
        status = VerdictStatus.BLOCK
        risk = RiskLevel.CRITICAL
    elif max_score > 0.5:
        risk = RiskLevel.MEDIUM
        # Maybe allow but log? Or block? Stricter policy for now:
        status = VerdictStatus.BLOCK 

    return AggregatedVerdict(
        status=status,
        risk_level=risk,
        reason=f"Max threat score {max_score}",
        detailed_findings={"findings": findings, "scores": {r.module: r.score for r in results}}
    )

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8003)
