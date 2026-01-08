from fastapi import FastAPI, HTTPException, Body
from pydantic import BaseModel
import uvicorn
import sys
import os
import logging
import re
from presidio_analyzer import AnalyzerEngine
from sentence_transformers import SentenceTransformer, util

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from common.schemas import VerdictStatus, AggregatedVerdict, RiskLevel, AnalysisResult

app = FastAPI(title="Text Analysis Service")
logger = logging.getLogger("text_service")
logging.basicConfig(level=logging.INFO)

# --- GLOBAL MODELS ---
semantic_model = None
presidio_analyzer = None
dangerous_embeddings = None

# Concepts to block (Semantic Search)
DANGEROUS_CONCEPTS = [
    "leak confidential internal data",
    "attack corporate network infrastructure",
    "bypass firewall security controls",
    "steal password and credentials",
    "proprietary algorithm source code",
    "financial revenue report q3",
    "employee salary list"
]

@app.on_event("startup")
async def load_models():
    global semantic_model, presidio_analyzer, dangerous_embeddings
    logger.info("Loading NLP Models...")
    try:
        # 1. Semantic Similarity (MiniLM - 80MB)
        semantic_model = SentenceTransformer('all-MiniLM-L6-v2')
        dangerous_embeddings = semantic_model.encode(DANGEROUS_CONCEPTS, convert_to_tensor=True)
        
        # 2. PII Analyzer (Presidio)
        presidio_analyzer = AnalyzerEngine()
        
        logger.info("NLP Models Loaded Successfully.")
    except Exception as e:
        logger.error(f"Failed to load NLP models: {e}")

# --- MODELS ---

def model_nlp_semantic(text):
    """Detects Semantic Threats (MiniLM Similarity)"""
    if not semantic_model:
        return AnalysisResult(module="nlp", score=0.0, findings=["Model not loaded"])
    
    try:
        # Encode input text
        text_emb = semantic_model.encode(text, convert_to_tensor=True)
        
        # Compute Cosine Similarity
        cosine_scores = util.cos_sim(text_emb, dangerous_embeddings)[0]
        
        # Find max similarity
        max_score_tensor = cosine_scores.max()
        best_match_idx = cosine_scores.argmax()
        
        score_val = float(max_score_tensor)
        findings = []
        risk_score = 0.0
        
        if score_val > 0.5: # 50% Similarity Threshold
            matched_concept = DANGEROUS_CONCEPTS[best_match_idx]
            findings.append(f"Semantic Threat Detected: '{matched_concept}' (Confidence: {score_val:.2f})")
            risk_score = 0.8
        elif score_val > 0.35:
            findings.append(f"Potential Semantic Risk ({score_val:.2f})")
            risk_score = 0.4

        return AnalysisResult(module="nlp", score=risk_score, findings=findings)
    except Exception as e:
        logger.error(f"NLP Error: {e}")
        return AnalysisResult(module="nlp", score=0.0, findings=[])

def model_code_analysis(text):
    """Detects Secrets & Keys (Regex Signature)"""
    findings = []
    score = 0.0
    
    # Common Secret Patterns (Simplified from Gitleaks/TruffleHog)
    patterns = {
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
        "Private Key Header": r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
        "Generic Secret": r"(?i)(api_key|secret|password)[\s]*=[\s]*['\"][0-9a-zA-Z\-_]{16,}['\"]"
    }
    
    for name, pattern in patterns.items():
        if re.search(pattern, text):
            findings.append(f"Secret Detected: {name}")
            score = 1.0 # CRITICAL
            
    # dangerous code patterns
    if "eval(" in text or "exec(" in text or "os.system(" in text:
         findings.append("Potential RCE (Remote Code Execution) pattern")
         score = max(score, 0.7)

    return AnalysisResult(module="code", score=score, findings=findings)

def model_patterns(text):
    """Detects PII (Presidio)"""
    if not presidio_analyzer:
        return AnalysisResult(module="pattern", score=0.0, findings=["Presidio not loaded"])
        
    try:
        results = presidio_analyzer.analyze(text=text, entities=["PHONE_NUMBER", "EMAIL_ADDRESS", "IBAN", "CREDIT_CARD", "US_SSN"], language='en')
        
        findings = []
        score = 0.0
        
        for res in results:
            findings.append(f"PII Detected: {res.entity_type} ({res.score:.2f})")
            # Score based on sensitivity
            if res.entity_type in ["CREDIT_CARD", "US_SSN", "IBAN"]:
                score = max(score, 0.9)
            elif res.entity_type in ["PHONE_NUMBER", "EMAIL_ADDRESS"]:
                score = max(score, 0.4) # Low risk for email, unless mass list
                
        return AnalysisResult(module="pattern", score=score, findings=findings)
    except Exception as e:
        logger.error(f"Presidio Error: {e}")
        return AnalysisResult(module="pattern", score=0.0, findings=[])

def model_context(text, metadata):
    return AnalysisResult(module="context", score=0.1, findings=[])

# -------------------

class TextRequest(BaseModel):
    text: str
    metadata: dict = {}

@app.post("/analyze", response_model=AggregatedVerdict)
async def analyze_text(request: TextRequest):
    text = request.text
    logger.info(f"Analyzing text length: {len(text)}")
    
    # Run models (Sequential for now, lightweight enough)
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
        status = VerdictStatus.BLOCK 

    return AggregatedVerdict(
        status=status,
        risk_level=risk,
        reason=f"Max threat score {max_score}",
        detailed_findings={"findings": findings, "scores": {r.module: r.score for r in results}}
    )

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8003)
