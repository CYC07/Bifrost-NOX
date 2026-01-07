from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
import httpx
import uvicorn
import os
import logging
from typing import Optional, List, Dict
import datetime
from collections import deque

# Import common schemas
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from common.schemas import VerdictStatus, TrafficPacket, AggregatedVerdict, ContentType

app = FastAPI(title="Master AI Orchestrator")
logger = logging.getLogger("master_ai")
logging.basicConfig(level=logging.INFO)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration for Sub-services
IMAGE_SERVICE_URL = os.getenv("IMAGE_SERVICE_URL", "http://localhost:8001")
DOCUMENT_SERVICE_URL = os.getenv("DOCUMENT_SERVICE_URL", "http://localhost:8002")
TEXT_SERVICE_URL = os.getenv("TEXT_SERVICE_URL", "http://localhost:8003")

# --- IN-MEMORY STATS ---
STATS = {
    "total": 0,
    "allowed": 0,
    "blocked": 0,
    "threats": 0
}
RECENT_LOGS = deque(maxlen=50) # Keep last 50 logs

def update_stats(verdict: AggregatedVerdict, src: str, dst: str):
    STATS["total"] += 1
    if verdict.status == VerdictStatus.BLOCK:
        STATS["blocked"] += 1
        STATS["threats"] += 1
    else:
        STATS["allowed"] += 1
    
    log_entry = {
        "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
        "source": src,
        "destination": dst,
        "status": verdict.status,
        "reason": verdict.reason
    }
    RECENT_LOGS.appendleft(log_entry)

@app.post("/analyze_traffic", response_model=AggregatedVerdict)
async def analyze_traffic(
    content_type: ContentType = Form(...),
    source_ip: str = Form(...),
    destination_ip: str = Form(...),
    text_content: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None)
):
    """
    Main entry point for the Gateway. 
    Receives traffic content and routes to the correct Lower Master.
    """
    logger.info(f"Received analysis request: {content_type} from {source_ip}")
    
    verdict = AggregatedVerdict(
        status=VerdictStatus.ALLOW,
        risk_level="safe",
        reason="No threats detected",
        detailed_findings={}
    )

    try:
        async with httpx.AsyncClient() as client:
            if content_type == ContentType.TEXT:
                if not text_content:
                    # Could be empty text body
                    text_content = ""
                
                response = await client.post(
                    f"{TEXT_SERVICE_URL}/analyze",
                    json={"text": text_content, "metadata": {"src": source_ip, "dst": destination_ip}}
                )
                if response.status_code == 200:
                    verdict = AggregatedVerdict(**response.json())
                else:
                    logger.error(f"Text service error: {response.text}")

            elif content_type == ContentType.IMAGE:
                if file:
                    files = {"file": (file.filename, await file.read(), file.content_type)}
                    response = await client.post(f"{IMAGE_SERVICE_URL}/analyze", files=files)
                    if response.status_code == 200:
                        verdict = AggregatedVerdict(**response.json())

            elif content_type == ContentType.DOCUMENT:
                if file:
                    files = {"file": (file.filename, await file.read(), file.content_type)}
                    response = await client.post(f"{DOCUMENT_SERVICE_URL}/analyze", files=files)
                    if response.status_code == 200:
                        verdict = AggregatedVerdict(**response.json())

    except Exception as exc:
        logger.error(f"Analysis failed: {exc}")
        # Default fail-open or fail-closed logic
        pass

    update_stats(verdict, source_ip, destination_ip)
    return verdict

# --- DASHBOARD ENDPOINTS ---

@app.get("/stats")
async def get_stats():
    return {
        **STATS,
        "recent_logs": list(RECENT_LOGS)
    }

@app.post("/test_attack")
async def trigger_test(type: str):
    """
    Simulates a request for the dashboard test buttons
    """
    fake_src = "192.168.1.100"
    fake_dst = "10.0.0.5"
    
    if type == "safe":
        # Simulate safe text
        await analyze_traffic(ContentType.TEXT, fake_src, fake_dst, text_content="Hello world, this is a safe message.")
    elif type == "malware":
        # Simulate EICAR signature (handled by Doc or Text service usually, here sending as text for simplicity)
        await analyze_traffic(ContentType.TEXT, fake_src, fake_dst, text_content="X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
    elif type == "sql":
        # Simulate SQL Injection
        await analyze_traffic(ContentType.TEXT, fake_src, fake_dst, text_content="SELECT * FROM users WHERE id = 1 OR 1=1;")
        
    return {"status": "Test sent"}

# Serve Dashboard Static Files
# We mount this last so it doesn't conflict with API routes
app.mount("/dashboard", StaticFiles(directory="dashboard", html=True), name="dashboard")

@app.get("/")
async def root():
    return FileResponse('dashboard/index.html')

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
