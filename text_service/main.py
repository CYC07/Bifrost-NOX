from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.requests import Request
import uvicorn
import sys
import os
import asyncio
import hashlib
import json
import re
import logging
import threading
import dataclasses
from collections import OrderedDict
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
from ml.prompt_injection import signatures as pi_signatures
from ml.prompt_injection.prompts import extract_prompts
from common import llm_scope
from ml.waf import target as request_target

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

# Credentials that legitimately travel in requests/responses and URLs: JWTs (SSO callbacks, magic
# links, every login API reply), client-side Google API keys, a generic password=. Reported as
# advisory, never blocked. Vendor secrets that should never leave the network still block outbound.
_TOLERATED_SECRETS = {"JWT", "Google API Key", "Generic Secret", "Stripe Test Key"}


def model_code_analysis(text, direction="outbound"):
    """Secret detection — deterministic regex (ml/secrets/), kept on purpose
    (precision beats a model here; see ml/secrets/patterns.py). Vendor-specific
    patterns + structural validation (JWT) + known-placeholder exclusion, added
    2026-08-01 to cut false positives beyond the original 4 generic patterns.
    The old eval(/exec(/os.system( substring check was removed separately: it
    was a bare string-contains with no context, and the WAF command_injection
    class already does real semantic RCE detection.

    Policy (availability over security): outbound, vendor secrets block and tolerated
    credentials are advisory; inbound, everything is advisory — a server sending the client
    its own token is not an exfiltration, and blocking it broke login responses."""
    try:
        secret_findings = detect_secrets(text)
    except Exception as e:
        logger.error(f"Secret detection error: {e}")
        return AnalysisResult(module="code", score=0.0, findings=[])
    if not secret_findings:
        return AnalysisResult(module="code", score=0.0, findings=[])
    findings = [f"Secret Detected: {f.kind} (severity={f.severity})" for f in secret_findings]
    hard = [f for f in secret_findings if f.kind not in _TOLERATED_SECRETS] if direction == "outbound" else []
    if hard:
        risk = max((RiskLevel(f.severity) for f in hard), key=list(RiskLevel).index)
        return AnalysisResult(module="code", score=1.0, findings=findings, blocked=True, risk=risk)
    return AnalysisResult(module="code", score=0.5, findings=findings, risk=RiskLevel.LOW,
                          raw_data={"advisory": True})

PII_MIN_SCORE = float(os.getenv("PII_MIN_SCORE", "0.4"))
_PII_SENSITIVE = {"CREDIT_CARD", "US_SSN", "IBAN"}
# A Luhn-valid number scores 1.0 whatever it is (device ids, session ids...), so a card needs
# card formatting (groups separated by space/dash) or card-ish words just before it.
_CARD_CONTEXT = re.compile(r"card|credit|debit|visa|master|amex|\bcc\b|cc_|ccnum|cvv|cvc|expir|payment|\bpan\b", re.I)
_CARD_GROUPED = re.compile(r"\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{1,7}$")


def _looks_like_card(text: str, start: int, end: int) -> bool:
    return bool(_CARD_GROUPED.search(text[start:end].strip()) or _CARD_CONTEXT.search(text[max(0, start - 60):start]))


def model_patterns(text, direction="outbound"):
    """Presidio PII detection, blocking on evidence rather than entity type.

    Found live: a Windows push-service reply and an app login body were blocked as US_SSN
    although Presidio itself scored them 0.05 (any bare 9-digit id). So: a sensitive entity
    blocks only at score >= PII_MIN_SCORE (bare 9 digits 0.05; formatted SSN 0.5; with
    context 0.85), and a credit card additionally needs card formatting or card-ish context.
    Anything weaker that still matched is reported as advisory. Inbound replies are advisory
    only (a server's own reply is not exfiltration). Contact info (phone/email) is
    informational: routine in normal traffic."""
    if not presidio_analyzer:
        return AnalysisResult(module="pattern", score=0.0, findings=["Presidio not loaded"])
    try:
        results = presidio_analyzer.analyze(text=text, entities=["PHONE_NUMBER", "EMAIL_ADDRESS", "IBAN", "CREDIT_CARD", "US_SSN"], language='en')
        findings: list[str] = []
        hard = soft = False
        for res in results:
            if res.entity_type not in _PII_SENSITIVE:
                findings.append(f"PII Detected: {res.entity_type} ({res.score:.2f})")      # contact info
                continue
            if res.score < PII_MIN_SCORE:
                continue                                  # Presidio itself says "unlikely"
            findings.append(f"PII Detected: {res.entity_type} ({res.score:.2f})")
            card_ok = res.entity_type != "CREDIT_CARD" or _looks_like_card(text, res.start, res.end)
            if direction == "outbound" and card_ok:
                hard = True
            else:
                soft = True
        if hard:
            return AnalysisResult(module="pattern", score=0.9, findings=findings, blocked=True, risk=RiskLevel.CRITICAL)
        if soft:
            return AnalysisResult(module="pattern", score=0.4, findings=findings, risk=RiskLevel.LOW,
                                  raw_data={"advisory": True})
        return AnalysisResult(module="pattern", score=0.4 if findings else 0.0, findings=findings)
    except Exception as e:
        logger.error(f"Presidio Error: {e}")
        return AnalysisResult(module="pattern", score=0.0, findings=[])

WAF_MAX_VALUES = int(os.getenv("WAF_MAX_VALUES", "64"))
WAF_MAX_VALUE_CHARS = int(os.getenv("WAF_MAX_VALUE_CHARS", "2000"))


def _waf_inputs(text: str) -> list[str]:
    """What the WAF should look at. JSON bodies are scored value-by-value (the way real
    WAFs inspect parameters): the model was trained on bare payloads/URLs and classifies
    the *shape* of a JSON blob (braces, quotes, "username"/"password") as SQL injection,
    while the individual values are judged on their content. Anything else is scored whole."""
    s = text.lstrip()
    if not s.startswith(("{", "[")):
        return [text[:WAF_MAX_VALUE_CHARS]]
    try:
        obj = json.loads(text)
    except Exception:  # noqa: BLE001 — malformed JSON: fall back to the whole text
        return [text[:WAF_MAX_VALUE_CHARS]]
    out: list[str] = []

    def walk(o):
        if len(out) >= WAF_MAX_VALUES:
            return
        if isinstance(o, dict):
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
        elif o is not None and not isinstance(o, bool):
            v = str(o).strip()
            if v:
                out.append(v[:WAF_MAX_VALUE_CHARS])
    walk(obj)
    return out


def model_web_attack(text, parts=None):
    """Our trained WAF classifier — SQLi/XSS/traversal/cmd-injection/SSTI/scanner.
    The model's own calibrated block decision (WAF_ATTACK_THRESHOLD) and its
    taxonomy risk level are surfaced directly, not re-derived from a score.
    `parts` overrides what is scored (request targets pass their pre-filtered values)."""
    if not waf_classifier:
        return AnalysisResult(module="web_attack", score=0.0, findings=["WAF model not loaded"])
    try:
        for part in (parts if parts is not None else _waf_inputs(text)):
            pred = waf_classifier.predict(part)
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
        # Score the language an LLM would read (message contents), windowed so padding
        # can't push an injection past the model's input limit — not the JSON wrapper.
        pred = prompt_injection_classifier.predict_texts(extract_prompts(text))
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

def model_pi_signatures(text, in_scope):
    """IDS-style prompt-injection signatures (ml/prompt_injection/signatures.py).
    Runs on all traffic: in LLM scope a hit blocks; elsewhere it is advisory only
    (reported as a WARN on the dashboard, never blocks), because stock override
    phrases in ordinary web traffic don't threaten anything."""
    scan = "\n".join(extract_prompts(text)) if in_scope else text
    hits = pi_signatures.detect(scan)
    if not hits:
        return AnalysisResult(module="prompt_injection_signature", score=0.0, findings=[])
    names = sorted({h.kind for h in hits})
    return AnalysisResult(
        module="prompt_injection_signature",
        score=1.0,
        findings=[f"Prompt-injection signature: {', '.join(names)}"],
        blocked=in_scope,
        risk=RiskLevel.CRITICAL if in_scope else RiskLevel.LOW,
        raw_data={"advisory": not in_scope, "signatures": names},
    )


def _route(text: str) -> str:
    if not router_classifier:
        return "web_request"  # safe default: still runs WAF, won't miss injection payloads
    return router_classifier.route(text).route


# --- Throughput controls -----------------------------------------------------
# Verdicts are deterministic per body, and real traffic repeats bodies heavily
# (OS/app telemetry), so identical bodies are analysed once (bounded LRU).
# Model inference is blocking CPU work: it runs in worker threads, capped at
# TEXT_MAX_CONCURRENCY, so one slow request can't freeze the event loop and
# a burst queues cheaply instead of piling up inside the loop.
_CACHE_MAX = int(os.getenv("TEXT_CACHE_SIZE", "2048"))
_MAX_CONC = int(os.getenv("TEXT_MAX_CONCURRENCY", "2"))
_cache: "OrderedDict[bytes, dict]" = OrderedDict()
_cache_lock = threading.Lock()
_sem: "asyncio.Semaphore | None" = None


def _cache_clear() -> None:
    with _cache_lock:
        _cache.clear()


def _reset_semaphore() -> None:
    global _sem
    _sem = None


def _analyze_cached(text: str, in_scope: bool = False, direction: str = "outbound", kind: str = "") -> dict:
    # The verdict depends on LLM scope, direction and whether this is a body or a request
    # target, as well as the text, so all three are in the key.
    tag = (b"L" if in_scope else b"W") + (b"o" if direction == "outbound" else b"i") + (b"u" if kind == "url" else b"b")
    key = hashlib.sha256(tag + text.encode("utf-8", "ignore")).digest()
    with _cache_lock:
        if key in _cache:
            _cache.move_to_end(key)
            return _cache[key]
    if kind == "url":
        # request targets are only ever inspected outbound (the gateway enforces it too)
        result = _analyze_target(text) if direction == "outbound" else _aggregate([], "request_target")
    else:
        result = _analyze_sync(text, in_scope, direction)
    with _cache_lock:
        _cache[key] = result
        while len(_cache) > _CACHE_MAX:
            _cache.popitem(last=False)
    return result


def _analyze_sync(text: str, in_scope: bool = False, direction: str = "outbound") -> dict:
    # Secrets + PII + prompt-injection *signatures* always run — cheap regex, and
    # credential/PII leaks are too high-stakes to make conditional on the router's
    # guess. The prompt-injection MODEL runs only for traffic to an LLM endpoint
    # (in_scope, see common/llm_scope.py): it scores text bound for an
    # instruction-following model, and on ordinary web traffic (logins, pages, JSON
    # echoes) it false-positives at saturated confidence, so no threshold fixes it.
    # Outside LLM scope a signature hit is advisory (CENSOR -> dashboard WARN).
    # sensitive-content and web_attack are the only analyzers the router gates.
    route = _route(text)
    results = [model_code_analysis(text, direction), model_patterns(text, direction), model_pi_signatures(text, in_scope)]
    # Expensive analyzers run last and only if nothing has blocked yet: the verdict
    # is an OR of block decisions, so once one has fired, running a slower analyzer
    # can only add findings, not change the outcome.
    if in_scope and not any(r.blocked for r in results):
        results.append(model_prompt_injection(text))
    if not any(r.blocked for r in results):
        if route == "web_request":
            # The WAF is a request-side control (it protects servers from what clients
            # send). Inbound replies (pages, JSON echoes, robots.txt) were its main
            # source of false positives, so it doesn't run on them: availability first.
            if direction == "outbound":
                results.append(model_web_attack(text))
        elif route == "prose":
            results.append(model_sensitive(text))
    # route == "code": secrets + PII + prompt-injection already cover the real
    # risk, skip the other two.
    return _aggregate(results, route)


def _analyze_target(target: str) -> dict:
    """A request target (path + query string), not a body. Precision first: secrets in the
    decoded URL, high-precision traversal/sensitive-file signatures, then the WAF model on the
    few values with active characters (ml/waf/target.py). No router, PII, prompt-injection or
    sensitive-content analysis: URLs are full of tokens/domains that would only add noise."""
    results = []
    sig = request_target.signature_hits(target)
    if sig:
        results.append(AnalysisResult(
            module="request_target", score=1.0, findings=[f"Request target: {', '.join(sig)}"],
            blocked=True, risk=RiskLevel.HIGH))
    # Secrets in the URL: same policy as bodies (vendor secrets block, JWT/Google key/generic are
    # advisory — a JWT in an SSO callback or magic link is normal).
    results.append(model_code_analysis(request_target.decoded(target), "outbound"))
    values = request_target.waf_values(target)
    if values and not any(r.blocked for r in results):
        results.append(model_web_attack("", parts=values))
    return _aggregate(results, "request_target")


def _aggregate(results, route: str) -> dict:
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
        advisories = [r for r in results if (r.raw_data or {}).get("advisory") and r.findings]
        if advisories:
            status = VerdictStatus.CENSOR   # allowed through; shows as a WARN row, no threat entry
            risk = RiskLevel.LOW
            reason = "Advisory (not blocked): " + "; ".join(f for r in advisories for f in r.findings)
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

    return dataclasses.asdict(verdict)


async def analyze_text(request: Request):
    global _sem
    try:
        body = await request.json()
    except:
        return JSONResponse({"detail": "Invalid JSON"}, status_code=400)

    text = body.get("text", "")
    md = body.get("metadata") or {}
    direction = md.get("direction") or "outbound"
    kind = md.get("kind") or ""
    in_scope = False if kind == "url" else llm_scope.is_llm_request(
        host=md.get("host"), path=md.get("path"), body=text, direction=direction)
    logger.info(f"Analyzing text length: {len(text)} direction={direction} kind={kind or 'body'} llm_scope={in_scope}")

    if _sem is None:
        _sem = asyncio.Semaphore(_MAX_CONC)
    async with _sem:
        payload = await asyncio.to_thread(_analyze_cached, text, in_scope, direction, kind)
    return JSONResponse(payload)

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
