from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.requests import Request
import uvicorn
import sys
import os
import logging
import dataclasses
from contextlib import asynccontextmanager
from presidio_analyzer import AnalyzerEngine

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from common.schemas import VerdictStatus, AggregatedVerdict, RiskLevel, AnalysisResult
from common.utils import setup_logging
from ml.waf.predictor import WAFClassifier
from ml.sensitive.predictor import SensitiveClassifier
from ml.secrets.detector import detect as detect_secrets
from ml.router.predictor import RouterClassifier
from ml.prompt_injection.predictor import PromptInjectionClassifier

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
router_classifier = None
prompt_injection_classifier = None

async def load_models():
    global presidio_analyzer, waf_classifier, sensitive_classifier, router_classifier, prompt_injection_classifier
    logger.info("Loading NLP Models...")

    # Content-shape router — cheap (TF-IDF+LogReg, no GPU), decides which of
    # the expensive analyzers below actually need to run on a given text
    # blob. Loaded first since everything after it is conditional on it.
    try:
        router_classifier = RouterClassifier()
        if router_classifier.load():
            logger.info("Content-shape router loaded.")
        else:
            logger.error("Router failed to load — every request treated as web_request (safe default).")
            router_classifier = None
    except Exception as e:
        logger.error(f"Failed to load router: {e}")
        router_classifier = None
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

    # Prompt-injection classifier (protectai deberta) — flags text attempting
    # to manipulate an LLM's instructions. Runs on web_request + prose routes
    # (injection payloads aren't code-shaped, but can appear in free text or
    # smuggled into a form field).
    try:
        prompt_injection_classifier = PromptInjectionClassifier()
        if prompt_injection_classifier.load():
            logger.info("Prompt-injection model loaded (threshold %.2f).", prompt_injection_classifier.threshold)
        else:
            logger.error("Prompt-injection model failed to load — analyzer disabled.")
            prompt_injection_classifier = None
    except Exception as e:
        logger.error(f"Failed to load prompt-injection model: {e}")
        prompt_injection_classifier = None

def model_sensitive(text):
    """Zero-shot sensitive-content detection (DeBERTa-v3 NLI) — replaces the old
    MiniLM cosine heuristic. The model's own calibrated block decision (and its
    taxonomy risk level) is surfaced directly, not re-derived from a score."""
    if not sensitive_classifier:
        return AnalysisResult(module="sensitive", score=0.0, findings=["Sensitive model not loaded"])
    try:
        pred = sensitive_classifier.predict(text)
        if pred.blocked:
            return AnalysisResult(
                module="sensitive",
                score=pred.score,
                findings=[f"Sensitive content: {pred.label} (risk={pred.risk}, conf={pred.score:.2f})"],
                blocked=True,
                risk=RiskLevel(pred.risk),
            )
        return AnalysisResult(module="sensitive", score=0.0, findings=[])
    except Exception as e:
        logger.error(f"Sensitive Error: {e}")
        return AnalysisResult(module="sensitive", score=0.0, findings=[])

def model_code_analysis(text):
    """Secret detection — deterministic regex (ml/secrets/), kept on purpose
    (precision beats a model here; see ml/secrets/patterns.py). Vendor-specific
    patterns + structural validation (JWT) + known-placeholder exclusion, added
    2026-08-01 to cut false positives beyond the original 4 generic patterns.
    The old eval(/exec(/os.system( substring check was removed separately: it
    was a bare string-contains with no context, and the WAF command_injection
    class already does real semantic RCE detection."""
    try:
        secret_findings = detect_secrets(text)
    except Exception as e:
        logger.error(f"Secret detection error: {e}")
        return AnalysisResult(module="code", score=0.0, findings=[])
    if not secret_findings:
        return AnalysisResult(module="code", score=0.0, findings=[])
    findings = [f"Secret Detected: {f.kind} (severity={f.severity})" for f in secret_findings]
    risk = max((RiskLevel(f.severity) for f in secret_findings), key=list(RiskLevel).index)
    return AnalysisResult(module="code", score=1.0, findings=findings, blocked=True, risk=risk)

def model_patterns(text):
    """Presidio PII detection. Financial/government identifiers (credit card,
    SSN, IBAN) block outright — those are never benign in transit. Contact
    info (phone/email) alone is informational only, not blocking — it's
    routine in normal traffic (contact forms, headers) and blocking on it
    would be a firewall that can't pass an email address."""
    if not presidio_analyzer:
        return AnalysisResult(module="pattern", score=0.0, findings=["Presidio not loaded"])
    try:
        results = presidio_analyzer.analyze(text=text, entities=["PHONE_NUMBER", "EMAIL_ADDRESS", "IBAN", "CREDIT_CARD", "US_SSN"], language='en')
        findings = []
        blocked = False
        for res in results:
            findings.append(f"PII Detected: {res.entity_type} ({res.score:.2f})")
            if res.entity_type in ["CREDIT_CARD", "US_SSN", "IBAN"]:
                blocked = True
        score = 0.9 if blocked else (0.4 if findings else 0.0)
        risk = RiskLevel.CRITICAL if blocked else RiskLevel.SAFE
        return AnalysisResult(module="pattern", score=score, findings=findings, blocked=blocked, risk=risk)
    except Exception as e:
        logger.error(f"Presidio Error: {e}")
        return AnalysisResult(module="pattern", score=0.0, findings=[])

def model_web_attack(text):
    """Our trained WAF classifier — SQLi/XSS/traversal/cmd-injection/SSTI/scanner.
    The model's own calibrated block decision (WAF_ATTACK_THRESHOLD) and its
    taxonomy risk level are surfaced directly, not re-derived from a score."""
    if not waf_classifier:
        return AnalysisResult(module="web_attack", score=0.0, findings=["WAF model not loaded"])
    try:
        pred = waf_classifier.predict(text)
        if pred.blocked:
            return AnalysisResult(
                module="web_attack",
                score=pred.score,
                findings=[f"Web attack: {pred.label} (risk={pred.risk}, conf={pred.score:.2f})"],
                blocked=True,
                risk=RiskLevel(pred.risk),
            )
        return AnalysisResult(module="web_attack", score=0.0, findings=[])
    except Exception as e:
        logger.error(f"WAF Error: {e}")
        return AnalysisResult(module="web_attack", score=0.0, findings=[])

def model_prompt_injection(text):
    """Prompt-injection detection (protectai deberta) — flags text attempting
    to manipulate an LLM's instructions (ignore-previous-instructions,
    role-override jailbreaks, fake embedded system directives)."""
    if not prompt_injection_classifier:
        return AnalysisResult(module="prompt_injection", score=0.0, findings=["Prompt-injection model not loaded"])
    try:
        pred = prompt_injection_classifier.predict(text)
        if pred.blocked:
            return AnalysisResult(
                module="prompt_injection",
                score=pred.score,
                findings=[f"Prompt injection detected (conf={pred.score:.2f})"],
                blocked=True,
                risk=RiskLevel(pred.risk),
            )
        return AnalysisResult(module="prompt_injection", score=0.0, findings=[])
    except Exception as e:
        logger.error(f"Prompt-injection Error: {e}")
        return AnalysisResult(module="prompt_injection", score=0.0, findings=[])

def _route(text: str) -> str:
    if not router_classifier:
        return "web_request"  # safe default: still runs WAF, won't miss injection payloads
    return router_classifier.route(text).route


async def analyze_text(request: Request):
    try:
        body = await request.json()
    except:
        return JSONResponse({"detail": "Invalid JSON"}, status_code=400)

    text = body.get("text", "")
    metadata = body.get("metadata", {})

    logger.info(f"Analyzing text length: {len(text)}")

    # Secrets + PII + prompt-injection always run — cheap (regex/non-transformer)
    # for the first two, and credential/PII leaks are too high-stakes to make
    # conditional on the router's guess. Prompt-injection is unconditional too,
    # despite being an expensive transformer call: adversarial testing found the
    # router occasionally misroutes an injection-bearing form field to "code"
    # (low-confidence edge case, ~0.47), and unlike the router's other known
    # gap (misrouted benign code — a pure efficiency miss), this one means a
    # real attack payload goes unchecked. Manipulating the firewall's own AI
    # pipeline is high-severity enough that coupling its detection to router
    # accuracy is the wrong tradeoff — sensitive-content and web_attack are
    # the only two analyzers the router actually gates.
    route = _route(text)
    results = [model_code_analysis(text), model_patterns(text), model_prompt_injection(text)]
    if route == "web_request":
        results.append(model_web_attack(text))
    elif route == "prose":
        results.append(model_sensitive(text))
    # route == "code": secrets + PII + prompt-injection already cover the real
    # risk, skip the other two.

    findings = []
    detailed_scores = {}
    for r in results:
        findings.extend(r.findings)
        detailed_scores[r.module] = r.score

    # Decision-level aggregation: each analyzer already made its own calibrated
    # block/allow call above, using whatever threshold fits its own score scale
    # (regex hit, softmax confidence, PII entity score aren't comparable on one
    # shared cutoff). Aggregation just ORs those decisions and reports the
    # highest risk among the ones that fired — no re-interpretation of raw scores.
    blocked_results = [r for r in results if r.blocked]
    if blocked_results:
        status = VerdictStatus.BLOCK
        risk = max((r.risk for r in blocked_results), key=list(RiskLevel).index)
        reason = "Blocked by: " + ", ".join(sorted({r.module for r in blocked_results}))
    else:
        status = VerdictStatus.ALLOW
        risk = RiskLevel.SAFE
        reason = "No analyzer flagged a block"

    verdict = AggregatedVerdict(
        status=status,
        risk_level=risk,
        reason=reason,
        detailed_findings={"findings": findings, "scores": detailed_scores, "route": route}
    )
    
    return JSONResponse(dataclasses.asdict(verdict))

routes = [
    Route("/analyze", analyze_text, methods=["POST"]),
]

@asynccontextmanager
async def lifespan(app):
    await load_models()
    yield

app = Starlette(debug=False, routes=routes, lifespan=lifespan)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8003)
