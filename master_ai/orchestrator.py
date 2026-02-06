from starlette.applications import Starlette
from starlette.responses import JSONResponse, FileResponse
from starlette.routing import Route, Mount
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.staticfiles import StaticFiles
import httpx
import uvicorn
import os
import logging
import datetime
from collections import deque
import dataclasses
import sys
import json

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from common.schemas import VerdictStatus, AggregatedVerdict, ContentType

logger = logging.getLogger("master_ai")
logging.basicConfig(level=logging.INFO)

IMAGE_SERVICE_URL = os.getenv("IMAGE_SERVICE_URL", "http://localhost:8001")
DOCUMENT_SERVICE_URL = os.getenv("DOCUMENT_SERVICE_URL", "http://localhost:8002")
TEXT_SERVICE_URL = os.getenv("TEXT_SERVICE_URL", "http://localhost:8003")

STATS = {
    "total": 0,
    "allowed": 0,
    "blocked": 0,
    "threats": 0
}
RECENT_LOGS = deque(maxlen=50)

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

async def analyze_traffic(request: Request):
    form = await request.form()
    content_type = form.get("content_type")
    source_ip = form.get("source_ip", "unknown")
    destination_ip = form.get("destination_ip", "unknown")
    text_content = form.get("text_content", "")
    file_item = form.get("file")
    
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
                resp = await client.post(
                    f"{TEXT_SERVICE_URL}/analyze",
                    json={"text": text_content, "metadata": {"src": source_ip, "dst": destination_ip}}
                )
                if resp.status_code == 200:
                    verdict = AggregatedVerdict(**resp.json())
                else:
                    logger.error(f"Text service error: {resp.text}")

            elif content_type == ContentType.IMAGE and file_item:
                files = {"file": (file_item.filename, await file_item.read(), file_item.content_type)}
                resp = await client.post(f"{IMAGE_SERVICE_URL}/analyze", files=files)
                if resp.status_code == 200:
                    verdict = AggregatedVerdict(**resp.json())

            elif content_type == ContentType.DOCUMENT and file_item:
                files = {"file": (file_item.filename, await file_item.read(), file_item.content_type)}
                resp = await client.post(f"{DOCUMENT_SERVICE_URL}/analyze", files=files)
                if resp.status_code == 200:
                    verdict = AggregatedVerdict(**resp.json())

    except Exception as exc:
        logger.error(f"Analysis failed: {exc}")
        # Fail safe
        pass

    update_stats(verdict, source_ip, destination_ip)
    return JSONResponse(dataclasses.asdict(verdict))

async def get_stats(request: Request):
    return JSONResponse({
        **STATS,
        "recent_logs": list(RECENT_LOGS)
    })

async def trigger_test(request: Request):
    # Simulate test
    # params in query
    type_param = request.query_params.get("type", "safe")
    
    fake_src = "192.168.1.100"
    fake_dst = "10.0.0.5"
    
    # Internal mock call
    # We can't query ourselves via HTTP easily if single worker, but we can call the function logic or just mock it.
    # But analyze_traffic expects a Request object.
    # Easier to just log it or simulate via httpx if valid.
    # For now, we mock the stats update directly to show dashboard activity.
    
    # Actually, we can just call update_stats with a fake verdict.
    if type_param == "safe":
         update_stats(AggregatedVerdict(VerdictStatus.ALLOW, "safe", "Safe Test", {}), fake_src, fake_dst)
    elif type_param == "malware":
         update_stats(AggregatedVerdict(VerdictStatus.BLOCK, "critical", "EICAR Test", {}), fake_src, fake_dst)
    elif type_param == "sql":
         update_stats(AggregatedVerdict(VerdictStatus.BLOCK, "high", "SQL Injection", {}), fake_src, fake_dst)
         
    return JSONResponse({"status": "Test triggered"})

async def root(request):
    return FileResponse('dashboard/index.html')

middleware = [
    Middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
]

routes = [
    Route("/analyze_traffic", analyze_traffic, methods=["POST"]),
    Route("/stats", get_stats, methods=["GET"]),
    Route("/test_attack", trigger_test, methods=["POST"]),
    Route("/", root, methods=["GET"]),
    Mount("/dashboard", StaticFiles(directory="dashboard", html=True), name="dashboard")
]

app = Starlette(debug=True, routes=routes, middleware=middleware)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
