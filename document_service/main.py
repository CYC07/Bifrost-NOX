"""Document analysis microservice (port 8002).

Mirrors the architecture of ``image_service/main.py``: warm models on startup,
run all four analysers in parallel via ``asyncio.to_thread``, and combine the
results into an :class:`AggregatedVerdict` using both a max-score floor and a
weighted score.
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import os
import sys
from typing import List

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.schemas import (
    AggregatedVerdict,
    AnalysisResult,
    RiskLevel,
    VerdictStatus,
)
from common.utils import setup_logging

from document_service import (
    content_model,
    malware_model,
    metadata_model,
    structure_model,
)

setup_logging("document_service")
logger = logging.getLogger("document_service")


async def load_models() -> None:
    logger.info("Warming document_service models...")
    await asyncio.to_thread(structure_model.load_model)
    await asyncio.to_thread(malware_model.load_rules)
    await asyncio.to_thread(content_model.load_model)
    logger.info("document_service models ready")


def _aggregate(results: List[AnalysisResult]) -> AggregatedVerdict:
    by_module = {r.module: r for r in results}
    max_score = max((r.score for r in results), default=0.0)

    weighted = (
        by_module.get("malware", AnalysisResult("malware", 0.0, [])).score * 0.4
        + by_module.get("structure", AnalysisResult("structure", 0.0, [])).score * 0.25
        + by_module.get("content", AnalysisResult("content", 0.0, [])).score * 0.20
        + by_module.get("metadata", AnalysisResult("metadata", 0.0, [])).score * 0.15
    )

    findings: List[str] = []
    detailed_scores = {}
    for r in results:
        findings.extend(r.findings)
        detailed_scores[r.module] = r.score

    if max_score > 0.8:
        status = VerdictStatus.BLOCK
        risk = RiskLevel.CRITICAL
        reason = f"Critical document threat (max={max_score:.2f})"
    elif weighted > 0.5:
        status = VerdictStatus.BLOCK
        risk = RiskLevel.MEDIUM
        reason = f"Combined document risk threshold exceeded (weighted={weighted:.2f})"
    else:
        status = VerdictStatus.ALLOW
        risk = RiskLevel.SAFE
        reason = "Safe"

    return AggregatedVerdict(
        status=status,
        risk_level=risk,
        reason=reason,
        detailed_findings={
            "findings": findings,
            "scores": detailed_scores,
            "weighted_score": weighted,
            "max_score": max_score,
        },
    )


async def analyze_document(request: Request) -> JSONResponse:
    form = await request.form()
    file_item = form.get("file")
    if not file_item:
        return JSONResponse({"error": "No file provided"}, status_code=400)

    contents = await file_item.read()
    logger.info(
        "Analyzing document: %s (%d bytes)",
        getattr(file_item, "filename", "<unnamed>"),
        len(contents),
    )

    r_struct, r_content, r_malware, r_meta = await asyncio.gather(
        asyncio.to_thread(structure_model.analyze, contents),
        asyncio.to_thread(content_model.analyze, contents),
        malware_model.analyze(contents),
        asyncio.to_thread(metadata_model.analyze, contents),
    )

    verdict = _aggregate([r_struct, r_content, r_malware, r_meta])
    return JSONResponse(dataclasses.asdict(verdict))


routes = [
    Route("/analyze", analyze_document, methods=["POST"]),
]

app = Starlette(debug=True, routes=routes, on_startup=[load_models])

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8002)
