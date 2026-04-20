from __future__ import annotations

import asyncio
import dataclasses
import datetime
import json
import logging
import os
import random
import sys
import threading
from collections import Counter, deque
from typing import Any

import httpx
import uvicorn
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, RedirectResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.schemas import AggregatedVerdict, ContentType, VerdictStatus  # noqa: E402
from common.allowlist import (  # noqa: E402
    add_host as add_allow_host,
    list_hosts as list_allow_hosts,
    remove_host as remove_allow_host,
)
from common.utils import setup_logging  # noqa: E402
from master_ai.rule_engine import get_engine  # noqa: E402

setup_logging("master_ai")
logger = logging.getLogger("master_ai")

IMAGE_SERVICE_URL = os.getenv("IMAGE_SERVICE_URL", "http://localhost:8001")
DOCUMENT_SERVICE_URL = os.getenv("DOCUMENT_SERVICE_URL", "http://localhost:8002")
TEXT_SERVICE_URL = os.getenv("TEXT_SERVICE_URL", "http://localhost:8003")

STATS: dict[str, int] = {"total": 0, "allowed": 0, "blocked": 0, "threats": 0}
RECENT_LOGS: deque[dict[str, Any]] = deque(maxlen=1000)
RECENT_THREATS: deque[dict[str, Any]] = deque(maxlen=1000)
UPLOAD_QUEUE: deque[dict[str, Any]] = deque(maxlen=100)

# Rolling 48-point time-series
SERIES_LEN = 48
TIME_SERIES: dict[str, deque[float]] = {
    "throughput": deque([0.0] * SERIES_LEN, maxlen=SERIES_LEN),
    "blocked": deque([0.0] * SERIES_LEN, maxlen=SERIES_LEN),
    "sessions": deque([0.0] * SERIES_LEN, maxlen=SERIES_LEN),
    "latency": deque([0.0] * SERIES_LEN, maxlen=SERIES_LEN),
}
_last_totals = {"total": 0, "blocked": 0}

# Reason → threat classification heuristic (used to populate RECENT_THREATS)
THREAT_PATTERNS: list[tuple[str, str, str, float]] = [
    # (substring, type, severity, confidence)
    ("sql", "SQL Injection", "high", 0.94),
    ("xss", "Cross-Site Scripting", "high", 0.90),
    ("injection", "Command Injection", "critical", 0.98),
    ("malware", "Malware Payload", "critical", 0.96),
    ("eicar", "EICAR Test Signature", "medium", 0.99),
    ("pii", "PII Exfiltration", "high", 0.92),
    ("dlp", "Data Loss Prevention", "high", 0.90),
    ("brute", "Brute Force", "medium", 0.85),
    ("scan", "Port Scan", "low", 0.72),
    ("credential", "Credential Stuffing", "high", 0.91),
    ("phish", "Phishing Attempt", "high", 0.88),
    ("nsfw", "NSFW Content", "medium", 0.86),
    ("api key", "API Key Leak", "critical", 0.95),
    ("api_key", "API Key Leak", "critical", 0.95),
]


def _classify_reason(reason: str) -> tuple[str, str, float]:
    low = reason.lower()
    for sub, t, sev, conf in THREAT_PATTERNS:
        if sub in low:
            return t, sev, conf
    return "Anomalous Content", "medium", 0.80


def _level_for(status: str) -> str:
    s = str(status).lower()
    if s == "block":
        return "BLOCK"
    if s == "censor":
        return "WARN"
    return "ALLOW"


def _short_msg(reason: str, max_len: int = 100) -> str:
    return (reason or "").strip()[:max_len]


def update_stats(
    verdict: AggregatedVerdict,
    src: str,
    dst: str,
    *,
    proto: str = "TCP",
    rule: str = "AI-ANALYSIS",
    byte_count: str = "—",
) -> None:
    STATS["total"] += 1
    status = str(verdict.status)
    if status == VerdictStatus.BLOCK:
        STATS["blocked"] += 1
        STATS["threats"] += 1
    else:
        STATS["allowed"] += 1

    now = datetime.datetime.now()
    ts_short = now.strftime("%H:%M:%S")
    ts_full = now.strftime("%H:%M:%S") + f".{int(now.microsecond / 1000):03d}"

    log_entry = {
        "timestamp": ts_short,
        "t": ts_full,
        "level": _level_for(status),
        "source": src,
        "destination": dst,
        "src": src,
        "dst": dst,
        "proto": proto,
        "rule": rule,
        "bytes": byte_count,
        "status": status,
        "risk_level": str(verdict.risk_level),
        "reason": verdict.reason,
        "msg": _short_msg(verdict.reason),
    }
    RECENT_LOGS.appendleft(log_entry)

    if status == VerdictStatus.BLOCK:
        t_type, sev, conf = _classify_reason(verdict.reason)
        threat_id = f"T-{STATS['blocked']:05d}"
        threat_entry = {
            "id": threat_id,
            "time": ts_short,
            "severity": sev,
            "type": t_type,
            "src": src,
            "srcCountry": _country_guess(src),
            "dst": dst,
            "rule": rule,
            "action": "Blocked",
            "confidence": conf,
        }
        RECENT_THREATS.appendleft(threat_entry)


def _country_guess(ip: str) -> str:
    if not ip or ip == "unknown":
        return "??"
    if ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "127.")):
        return "LAN"
    # No geo database available — return placeholder derived from octet for variety
    try:
        oct1 = int(ip.split(".")[0])
    except (ValueError, IndexError):
        return "??"
    buckets = ["US", "DE", "GB", "RU", "CN", "NL", "BR", "IN", "FR", "JP"]
    return buckets[oct1 % len(buckets)]


async def analyze_traffic(request: Request) -> JSONResponse:
    form = await request.form()
    content_type = form.get("content_type")
    source_ip = form.get("source_ip", "unknown")
    destination_ip = form.get("destination_ip", "unknown")
    text_content = form.get("text_content", "")
    file_item = form.get("file")

    logger.info(f"Received analysis request: {content_type} from {source_ip}")

    port = form.get("port", "")
    ctx = {
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "port": port,
        "text_content": text_content,
    }
    rule_hit = get_engine().evaluate(ctx)
    if rule_hit is not None:
        status = VerdictStatus.BLOCK if rule_hit["action"] == "block" else VerdictStatus.ALLOW
        verdict = AggregatedVerdict(
            status=status,
            risk_level="critical" if status == VerdictStatus.BLOCK else "safe",
            reason=f"Static rule match ({rule_hit['match_type']}={rule_hit['value']}): {rule_hit['action'].upper()}",
            detailed_findings={"rule": rule_hit},
        )
        update_stats(verdict, source_ip, destination_ip, rule=f"R-{rule_hit['id']}")
        return JSONResponse(dataclasses.asdict(verdict))

    verdict = AggregatedVerdict(
        status=VerdictStatus.ALLOW,
        risk_level="safe",
        reason="No threats detected",
        detailed_findings={},
    )

    upload_record: dict[str, Any] | None = None

    try:
        async with httpx.AsyncClient() as client:
            if content_type == ContentType.TEXT:
                resp = await client.post(
                    f"{TEXT_SERVICE_URL}/analyze",
                    json={"text": text_content, "metadata": {"src": source_ip, "dst": destination_ip}},
                )
                if resp.status_code == 200:
                    verdict = AggregatedVerdict(**resp.json())
                else:
                    logger.error(f"Text service error: {resp.text}")

            elif content_type == ContentType.IMAGE and file_item:
                blob = await file_item.read()
                upload_record = _build_upload_record(file_item, blob, "IMG")
                files = {"file": (file_item.filename, blob, file_item.content_type)}
                resp = await client.post(f"{IMAGE_SERVICE_URL}/analyze", files=files)
                if resp.status_code == 200:
                    verdict = AggregatedVerdict(**resp.json())

            elif content_type == ContentType.DOCUMENT and file_item:
                blob = await file_item.read()
                upload_record = _build_upload_record(file_item, blob, "DOC")
                files = {"file": (file_item.filename, blob, file_item.content_type)}
                resp = await client.post(f"{DOCUMENT_SERVICE_URL}/analyze", files=files)
                if resp.status_code == 200:
                    verdict = AggregatedVerdict(**resp.json())

    except Exception as exc:
        logger.error(f"Analysis failed: {exc}")

    if upload_record is not None:
        status = str(verdict.status).lower()
        upload_record["status"] = (
            "flagged" if status == "block" else "indexed" if status == "allow" else "analyzing"
        )
        upload_record["tags"] = _upload_tags(verdict)
        UPLOAD_QUEUE.appendleft(upload_record)

    update_stats(verdict, source_ip, destination_ip)
    return JSONResponse(dataclasses.asdict(verdict))


def _build_upload_record(file_item: Any, blob: bytes, kind: str) -> dict[str, Any]:
    size_bytes = len(blob)
    if size_bytes > 1024 * 1024:
        size_str = f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        size_str = f"{size_bytes / 1024:.0f} KB"
    name = getattr(file_item, "filename", "upload") or "upload"
    ext = name.rsplit(".", 1)[-1].upper()[:4] if "." in name else kind
    return {
        "name": name,
        "size": size_str,
        "type": ext,
        "status": "analyzing",
        "time": datetime.datetime.now().strftime("%H:%M:%S"),
        "tags": ["Queued for AI analysis"],
    }


def _upload_tags(verdict: AggregatedVerdict) -> list[str]:
    tags = [f"risk={verdict.risk_level}"]
    if verdict.reason:
        tags.append(_short_msg(verdict.reason, 60))
    return tags


async def get_stats(request: Request) -> JSONResponse:
    return JSONResponse({**STATS, "recent_logs": list(RECENT_LOGS)[:1000]})


async def log_event(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        body = {}

    status_str = str(body.get("status", "allow")).lower()
    status = VerdictStatus.BLOCK if status_str == "block" else VerdictStatus.ALLOW
    verdict = AggregatedVerdict(
        status=status,
        risk_level=body.get("risk_level", "safe"),
        reason=body.get("reason", "connection observed"),
        detailed_findings={},
    )
    update_stats(
        verdict,
        body.get("source_ip", "unknown"),
        body.get("destination_ip", "unknown"),
        proto=body.get("proto", "TCP"),
        rule=body.get("rule", "PROXY"),
        byte_count=body.get("bytes", "—"),
    )
    return JSONResponse({"ok": True})


async def trigger_test(request: Request) -> JSONResponse:
    type_param = request.query_params.get("type", "safe")
    fake_src = "192.168.1.100"
    fake_dst = "10.0.0.5"

    if type_param == "safe":
        update_stats(AggregatedVerdict(VerdictStatus.ALLOW, "safe", "Safe Test", {}), fake_src, fake_dst)
    elif type_param == "malware":
        update_stats(
            AggregatedVerdict(VerdictStatus.BLOCK, "critical", "EICAR malware signature", {}),
            fake_src,
            fake_dst,
            rule="AV-EICAR",
        )
    elif type_param == "sql":
        update_stats(
            AggregatedVerdict(VerdictStatus.BLOCK, "high", "SQL Injection pattern detected", {}),
            fake_src,
            fake_dst,
            rule="WAF-SQL",
        )

    return JSONResponse({"status": "Test triggered"})


async def list_rules(request: Request) -> JSONResponse:
    return JSONResponse({"rules": get_engine().list_rules()})


async def add_rule(request: Request) -> JSONResponse:
    try:
        body = await request.json()
        rule = get_engine().add_rule(
            action=body.get("action", ""),
            match_type=body.get("match_type", ""),
            value=body.get("value", ""),
            priority=int(body.get("priority", 100)),
            enabled=bool(body.get("enabled", True)),
            description=body.get("description", ""),
        )
        return JSONResponse({"ok": True, "rule": rule})
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    except Exception as exc:
        logger.error(f"add_rule failed: {exc}")
        return JSONResponse({"ok": False, "error": "server error"}, status_code=500)


async def delete_rule(request: Request) -> JSONResponse:
    rule_id = request.path_params.get("rule_id", "")
    ok = get_engine().delete_rule(rule_id)
    return JSONResponse({"ok": ok}, status_code=200 if ok else 404)


async def toggle_rule(request: Request) -> JSONResponse:
    rule_id = request.path_params.get("rule_id", "")
    updated = get_engine().toggle_rule(rule_id)
    if updated is None:
        return JSONResponse({"ok": False, "error": "not found"}, status_code=404)
    return JSONResponse({"ok": True, "rule": updated})


async def get_allowlist(request: Request) -> JSONResponse:
    return JSONResponse({"hosts": list_allow_hosts()})


async def post_allowlist(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        body = {}
    host = (body.get("host") or "").strip()
    if not host:
        return JSONResponse({"ok": False, "error": "host is required"}, status_code=400)
    added = add_allow_host(host)
    return JSONResponse({"ok": True, "added": added, "hosts": list_allow_hosts()})


async def delete_allowlist(request: Request) -> JSONResponse:
    host = request.path_params.get("host", "")
    removed = remove_allow_host(host)
    return JSONResponse(
        {"ok": removed, "hosts": list_allow_hosts()},
        status_code=200 if removed else 404,
    )


async def get_threats(request: Request) -> JSONResponse:
    return JSONResponse({"threats": list(RECENT_THREATS)})


async def get_series(request: Request) -> JSONResponse:
    return JSONResponse({k: list(v) for k, v in TIME_SERIES.items()})


async def get_protocols(request: Request) -> JSONResponse:
    counts: Counter[str] = Counter()
    for entry in RECENT_LOGS:
        counts[entry.get("proto", "TCP")] += 1
    total = sum(counts.values()) or 1
    palette = {
        "TCP": "HTTPS / TLS 1.3",
        "UDP": "DNS / UDP",
        "ICMP": "ICMP",
        "HTTP": "HTTP / 1.1",
    }
    protocols = [
        {
            "name": palette.get(proto, proto),
            "pct": round(count * 100 / total, 1),
            "bytes": f"{count * 12} KB",
        }
        for proto, count in counts.most_common(6)
    ]
    if not protocols:
        protocols = [
            {"name": "HTTPS / TLS 1.3", "pct": 0, "bytes": "0 KB"},
        ]
    return JSONResponse({"protocols": protocols})


async def get_countries(request: Request) -> JSONResponse:
    counts: Counter[str] = Counter()
    kinds: dict[str, str] = {}
    for entry in RECENT_LOGS:
        src = entry.get("src", "")
        code = _country_guess(src)
        counts[code] += 1
        kinds[code] = "block" if entry.get("level") == "BLOCK" else kinds.get(code, "allow")
    total = sum(counts.values()) or 1
    result = [
        {
            "code": code,
            "name": code,
            "pct": round(count * 100 / total, 1),
            "hits": count,
            "kind": kinds.get(code, "allow"),
        }
        for code, count in counts.most_common(8)
    ]
    return JSONResponse({"countries": result})


async def get_devices(request: Request) -> JSONResponse:
    targets = [
        ("master-ai", "Master Orchestrator", f"http://localhost:8000/stats"),
        ("image-service", "Image AI (CLIP/YOLO/OCR)", f"{IMAGE_SERVICE_URL}/"),
        ("document-service", "Document AI (YARA/meta)", f"{DOCUMENT_SERVICE_URL}/"),
        ("text-service", "Text AI (Presidio/NLP)", f"{TEXT_SERVICE_URL}/"),
    ]
    devices: list[dict[str, Any]] = []
    async with httpx.AsyncClient(timeout=1.5) as client:
        for name, role, url in targets:
            status = "healthy"
            try:
                resp = await client.get(url)
                if resp.status_code >= 500:
                    status = "degraded"
            except Exception:
                status = "offline"
            cpu = random.randint(15, 70) if status == "healthy" else random.randint(70, 95)
            mem = random.randint(20, 70) if status == "healthy" else random.randint(60, 90)
            devices.append(
                {
                    "name": name,
                    "role": role,
                    "zone": "local",
                    "status": status,
                    "cpu": cpu,
                    "mem": mem,
                    "tput": "—" if status == "offline" else f"{random.randint(1, 50)}.{random.randint(0, 9)} Mbps",
                    "uptime": "—" if status == "offline" else f"{random.randint(1, 48)}h",
                }
            )
    devices.append(
        {
            "name": "mitm-gateway",
            "role": "MITM TLS Proxy",
            "zone": "local",
            "status": "healthy",
            "cpu": random.randint(10, 50),
            "mem": random.randint(20, 60),
            "tput": f"{random.randint(1, 20)}.{random.randint(0, 9)} Mbps",
            "uptime": "live",
        }
    )
    return JSONResponse({"devices": devices})


async def get_reports(request: Request) -> JSONResponse:
    now = datetime.datetime.now()
    period = f"{(now - datetime.timedelta(days=7)).strftime('%b %d')} – {now.strftime('%b %d')}"
    reports = [
        {"name": "Weekly Threat Summary", "scope": "All gateways", "period": period, "size": "—", "status": "scheduled"},
        {"name": "Rule Hit Report", "scope": "Static rules", "period": "Last 24h", "size": f"{len(RECENT_LOGS)} rows", "status": "ready"},
        {"name": "Blocked Traffic Export", "scope": "Blocked only", "period": "Last 24h", "size": f"{STATS['blocked']} events", "status": "ready"},
        {"name": "AI Intake Audit", "scope": "Uploads", "period": "Session", "size": f"{len(UPLOAD_QUEUE)} files", "status": "ready"},
        {"name": "Device Health Report", "scope": "All services", "period": "Live", "size": "—", "status": "generating"},
    ]
    return JSONResponse({"reports": reports})


async def list_uploads(request: Request) -> JSONResponse:
    return JSONResponse({"uploads": list(UPLOAD_QUEUE)})


async def get_overview(request: Request) -> JSONResponse:
    total = STATS["total"]
    blocked = STATS["blocked"]
    return JSONResponse(
        {
            "stats": STATS,
            "kpis": {
                "throughput": round(max(0.1, total / 60), 2),
                "blocked_24h": blocked,
                "active_sessions": STATS["allowed"],
                "p95_latency": round(8 + random.random() * 6, 1),
            },
            "series": {k: list(v) for k, v in TIME_SERIES.items()},
            "recent_logs": list(RECENT_LOGS)[:1000],
            "threats": list(RECENT_THREATS)[:100],
        }
    )


async def _sampler() -> None:
    while True:
        try:
            total = STATS["total"]
            blocked = STATS["blocked"]
            delta_total = max(0, total - _last_totals["total"])
            delta_blocked = max(0, blocked - _last_totals["blocked"])
            _last_totals["total"] = total
            _last_totals["blocked"] = blocked

            TIME_SERIES["throughput"].append(float(delta_total))
            TIME_SERIES["blocked"].append(float(delta_blocked))
            TIME_SERIES["sessions"].append(float(STATS["allowed"]))
            TIME_SERIES["latency"].append(round(8.0 + random.random() * 8.0, 1))
        except Exception as exc:
            logger.error(f"sampler error: {exc}")
        await asyncio.sleep(3)


async def on_startup() -> None:
    asyncio.create_task(_sampler())


async def root(request: Request) -> RedirectResponse:
    return RedirectResponse(url="/dashboard/")


async def dashboard_index(request: Request) -> FileResponse:
    return FileResponse("dashboard/index.html")


middleware = [
    Middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]),
]

routes = [
    Route("/analyze_traffic", analyze_traffic, methods=["POST"]),
    Route("/log_event", log_event, methods=["POST"]),
    Route("/stats", get_stats, methods=["GET"]),
    Route("/test_attack", trigger_test, methods=["POST"]),
    Route("/rules", list_rules, methods=["GET"]),
    Route("/rules", add_rule, methods=["POST"]),
    Route("/rules/{rule_id}", delete_rule, methods=["DELETE"]),
    Route("/rules/{rule_id}/toggle", toggle_rule, methods=["POST"]),
    Route("/allowlist", get_allowlist, methods=["GET"]),
    Route("/allowlist", post_allowlist, methods=["POST"]),
    Route("/allowlist/{host:path}", delete_allowlist, methods=["DELETE"]),
    Route("/threats", get_threats, methods=["GET"]),
    Route("/series", get_series, methods=["GET"]),
    Route("/protocols", get_protocols, methods=["GET"]),
    Route("/countries", get_countries, methods=["GET"]),
    Route("/devices", get_devices, methods=["GET"]),
    Route("/reports", get_reports, methods=["GET"]),
    Route("/uploads", list_uploads, methods=["GET"]),
    Route("/overview", get_overview, methods=["GET"]),
    Route("/", root, methods=["GET"]),
    Mount("/dashboard", StaticFiles(directory="dashboard", html=True), name="dashboard"),
]

app = Starlette(debug=True, routes=routes, middleware=middleware, on_startup=[on_startup])

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
