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

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from common.schemas import VerdictStatus, AggregatedVerdict, RiskLevel, AnalysisResult
from common.utils import setup_logging
from ml.waf.predictor import WAFClassifier
from ml.sensitive.predictor import SensitiveClassifier

setup_logging("text_service")
logger = logging.getLogger("text_service")

# WAF web-attack classifier threshold. Kept high (0.8) on purpose: the model
# still over-flags some benign traffic (see shadow-mode findings), so we only
# enforce on high-confidence detections until the clean corpus is grown.
WAF_ATTACK_THRESHOLD = float(os.getenv("WAF_ATTACK_THRESHOLD", "0.8"))

# --- GLOBAL MODELS ---
presidio_analyzer = None
waf_classifier = None
sensitive_classifier = None

async def load_models():
    global presidio_analyzer, waf_classifier, sensitive_classifier
    logger.info("Loading NLP Models...")
    try:
        presidio_analyzer = AnalyzerEngine()
        logger.info("Presidio PII analyzer loaded.")
    except Exception as e:
        logger.error(f"Failed to load Presidio: {e}")

    # Sensitive-content zero-shot classifier (DeBERTa-v3 NLI) — replaces the old
    # MiniLM cosine heuristic. Loaded separately, fail-open.
    try:
        sensitive_classifier = SensitiveClassifier()
        if sensitive_classifier.load():
            logger.info("Sensitive-content model loaded (threshold %.2f).", sensitive_classifier.threshold)
        else:
            logger.error("Sensitive model failed to load — sensitive analyzer disabled.")
            sensitive_classifier = None
    except Exception as e:
        logger.error(f"Failed to load sensitive model: {e}")
        sensitive_classifier = None

    # WAF web-attack classifier (our own trained model) — loaded separately so a
    # failure here never takes down the other models, and vice versa.
    try:
        waf_classifier = WAFClassifier(threshold=WAF_ATTACK_THRESHOLD)
        if waf_classifier.load():
            logger.info("WAF web-attack model loaded (threshold %.2f).", WAF_ATTACK_THRESHOLD)
        else:
            logger.error("WAF web-attack model failed to load — web_attack analyzer disabled.")
            waf_classifier = None
    except Exception as e:
        logger.error(f"Failed to load WAF model: {e}")
        waf_classifier = None

def model_sensitive(text):
    """Zero-shot sensitive-content detection (DeBERTa-v3 NLI) — replaces the old
    MiniLM cosine heuristic. Emits a decisive score only on the model's own
    calibrated block decision, so its verdict survives the max-score aggregation.
    Below threshold it contributes nothing (public/benign text scores near zero)."""
    if not sensitive_classifier:
        return AnalysisResult(module="sensitive", score=0.0, findings=["Sensitive model not loaded"])
    try:
        pred = sensitive_classifier.predict(text)
        if pred.blocked:
            return AnalysisResult(
                module="sensitive",
                score=0.9,  # decisive -> BLOCK in aggregation
                findings=[f"Sensitive content: {pred.label} (risk={pred.risk}, conf={pred.score:.2f})"],
            )
        return AnalysisResult(module="sensitive", score=0.0, findings=[])
    except Exception as e:
        logger.error(f"Sensitive Error: {e}")
        return AnalysisResult(module="sensitive", score=0.0, findings=[])

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

def model_web_attack(text):
    """Our trained WAF classifier — SQLi/XSS/traversal/cmd-injection/SSTI/scanner.
    Emits a decisive score only when the model's own calibrated decision blocks,
    so its verdict survives the max-score aggregation without being second-guessed
    by a different threshold. Below its threshold it contributes nothing (allow)."""
    if not waf_classifier:
        return AnalysisResult(module="web_attack", score=0.0, findings=["WAF model not loaded"])
    try:
        pred = waf_classifier.predict(text)
        if pred.blocked:
            return AnalysisResult(
                module="web_attack",
                score=0.95,  # decisive -> maps to BLOCK/CRITICAL in aggregation
                findings=[f"Web attack: {pred.label} (risk={pred.risk}, conf={pred.score:.2f})"],
            )
        return AnalysisResult(module="web_attack", score=0.0, findings=[])
    except Exception as e:
        logger.error(f"WAF Error: {e}")
        return AnalysisResult(module="web_attack", score=0.0, findings=[])

async def analyze_text(request: Request):
    try:
        body = await request.json()
    except:
        return JSONResponse({"detail": "Invalid JSON"}, status_code=400)
        
    text = body.get("text", "")
    metadata = body.get("metadata", {})
    
    logger.info(f"Analyzing text length: {len(text)}")
    
    r1 = model_sensitive(text)
    r2 = model_code_analysis(text)
    r3 = model_patterns(text)
    r4 = model_web_attack(text)

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
