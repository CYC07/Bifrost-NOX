from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.requests import Request
import uvicorn
import sys
import os
import logging
import re
import dataclasses
from contextlib import asynccontextmanager
from presidio_analyzer import AnalyzerEngine
from sentence_transformers import SentenceTransformer, util

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from common.schemas import VerdictStatus, AggregatedVerdict, RiskLevel, AnalysisResult
from common.utils import setup_logging

setup_logging("text_service")
logger = logging.getLogger("text_service")

# --- GLOBAL MODELS ---
semantic_model = None
presidio_analyzer = None
dangerous_embeddings = None

DANGEROUS_CONCEPTS = [
    "leak confidential internal data",
    "attack corporate network infrastructure",
    "bypass firewall security controls",
    "steal password and credentials",
    "proprietary algorithm source code",
    "financial revenue report q3",
    "employee salary list"
]

async def load_models():
    global semantic_model, presidio_analyzer, dangerous_embeddings
    logger.info("Loading NLP Models...")
    try:
        semantic_model = SentenceTransformer('all-MiniLM-L6-v2')
        dangerous_embeddings = semantic_model.encode(DANGEROUS_CONCEPTS, convert_to_tensor=True)
        presidio_analyzer = AnalyzerEngine()
        logger.info("NLP Models Loaded Successfully.")
    except Exception as e:
        logger.error(f"Failed to load NLP models: {e}")

def model_nlp_semantic(text):
    if not semantic_model:
        return AnalysisResult(module="nlp", score=0.0, findings=["Model not loaded"])
    try:
        text_emb = semantic_model.encode(text, convert_to_tensor=True)
        cosine_scores = util.cos_sim(text_emb, dangerous_embeddings)[0]
        max_score_tensor = cosine_scores.max()
        best_match_idx = cosine_scores.argmax()
        score_val = float(max_score_tensor)
        findings = []
        risk_score = 0.0
        if score_val > 0.5: 
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
    findings = []
    score = 0.0
    patterns = {
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
        "Private Key Header": r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
        "Generic Secret": r"(?i)(api_key|secret|password)[\s]*=[\s]*['\"][0-9a-zA-Z\-_]{16,}['\"]"
    }
    for name, pattern in patterns.items():
        if re.search(pattern, text):
            findings.append(f"Secret Detected: {name}")
            score = 1.0 
    if "eval(" in text or "exec(" in text or "os.system(" in text:
         findings.append("Potential RCE (Remote Code Execution) pattern")
         score = max(score, 0.7)
    return AnalysisResult(module="code", score=score, findings=findings)

def model_patterns(text):
    if not presidio_analyzer:
        return AnalysisResult(module="pattern", score=0.0, findings=["Presidio not loaded"])
    try:
        results = presidio_analyzer.analyze(text=text, entities=["PHONE_NUMBER", "EMAIL_ADDRESS", "IBAN", "CREDIT_CARD", "US_SSN"], language='en')
        findings = []
        score = 0.0
        for res in results:
            findings.append(f"PII Detected: {res.entity_type} ({res.score:.2f})")
            if res.entity_type in ["CREDIT_CARD", "US_SSN", "IBAN"]:
                score = max(score, 0.9)
            elif res.entity_type in ["PHONE_NUMBER", "EMAIL_ADDRESS"]:
                score = max(score, 0.4) 
        return AnalysisResult(module="pattern", score=score, findings=findings)
    except Exception as e:
        logger.error(f"Presidio Error: {e}")
        return AnalysisResult(module="pattern", score=0.0, findings=[])

def model_context(text, metadata):
    return AnalysisResult(module="context", score=0.1, findings=[])

async def analyze_text(request: Request):
    try:
        body = await request.json()
    except:
        return JSONResponse({"detail": "Invalid JSON"}, status_code=400)
        
    text = body.get("text", "")
    metadata = body.get("metadata", {})
    
    logger.info(f"Analyzing text length: {len(text)}")
    
    r1 = model_nlp_semantic(text)
    r2 = model_code_analysis(text)
    r3 = model_patterns(text)
    r4 = model_context(text, metadata)
    
    results = [r1, r2, r3, r4]
    
    max_score = max(r.score for r in results)
    findings = []
    detailed_scores = {}
    for r in results:
        findings.extend(r.findings)
        detailed_scores[r.module] = r.score
        
    status = VerdictStatus.ALLOW
    risk = RiskLevel.SAFE
    
    if max_score > 0.8:
        status = VerdictStatus.BLOCK
        risk = RiskLevel.CRITICAL
    elif max_score > 0.5:
        risk = RiskLevel.MEDIUM
        status = VerdictStatus.BLOCK 

    verdict = AggregatedVerdict(
        status=status,
        risk_level=risk,
        reason=f"Max threat score {max_score}",
        detailed_findings={"findings": findings, "scores": detailed_scores}
    )
    
    return JSONResponse(dataclasses.asdict(verdict))

routes = [
    Route("/analyze", analyze_text, methods=["POST"]),
]

@asynccontextmanager
async def lifespan(app):
    await load_models()
    yield

app = Starlette(debug=True, routes=routes, lifespan=lifespan)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8003)
