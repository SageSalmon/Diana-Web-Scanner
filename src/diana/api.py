"""Diana REST API — FastAPI application."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Security
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field

from diana import __version__
from diana.config import ScanConfig
from diana.core.models import ScanResult, ScanStatus
from diana.core.orchestrator import ScanOrchestrator
from diana.engagement.models import EngagementConfig


class ScanRequest(BaseModel):
    target: str
    engagement_file: str
    modules: list[str] = Field(default_factory=lambda: [
        "xss", "sqli", "ssrf", "headers", "info_disclosure", "auth",
    ])
    depth: int = 3
    rate_limit: int = 10
    no_ai: bool = False


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str


# In-memory scan storage (replace with DB in production)
_scans: dict[str, ScanResult] = {}
_tasks: dict[str, asyncio.Task] = {}

_api_key_header = APIKeyHeader(name="X-API-Key")


def _get_api_key() -> str:
    key = os.environ.get("DIANA_API_KEY", "")
    if not key:
        raise RuntimeError("DIANA_API_KEY environment variable not set")
    return key


async def _verify_api_key(api_key: str = Security(_api_key_header)) -> str:
    expected = _get_api_key()
    if api_key != expected:
        raise HTTPException(403, "Invalid API key")
    return api_key


def create_app() -> FastAPI:
    api = FastAPI(
        title="Diana API",
        description="AI-Enabled Web Vulnerability Scanner",
        version=__version__,
    )

    # Health check is unauthenticated (ALB needs it)
    @api.get("/health")
    async def health():
        return {"status": "healthy", "version": __version__}

    @api.post("/api/v1/scans", response_model=ScanResponse)
    async def create_scan(request: ScanRequest, _: str = Depends(_verify_api_key)):
        try:
            engagement = EngagementConfig.from_yaml(request.engagement_file)
        except Exception as e:
            raise HTTPException(400, f"Invalid engagement file: {e}")

        config = ScanConfig(
            target=request.target,
            engagement_file=request.engagement_file,
            depth=request.depth,
            rate_limit=request.rate_limit,
            no_ai=request.no_ai,
        )
        config.scan.modules = request.modules

        orchestrator = ScanOrchestrator(engagement, config)

        async def run_scan():
            result = await orchestrator.run()
            _scans[orchestrator.scan_id] = result

        task = asyncio.create_task(run_scan())
        _tasks[orchestrator.scan_id] = task

        return ScanResponse(
            scan_id=orchestrator.scan_id,
            status="started",
            message="Scan initiated",
        )

    @api.get("/api/v1/scans/{scan_id}")
    async def get_scan(scan_id: str, _: str = Depends(_verify_api_key)):
        if scan_id in _scans:
            result = _scans[scan_id]
            return result.model_dump(mode="json")
        if scan_id in _tasks:
            return {"scan_id": scan_id, "status": "running"}
        raise HTTPException(404, "Scan not found")

    @api.get("/api/v1/scans")
    async def list_scans(_: str = Depends(_verify_api_key)):
        return {
            sid: {"status": r.status.value, "findings": len(r.findings)}
            for sid, r in _scans.items()
        }

    @api.get("/api/v1/modules")
    async def list_modules(_: str = Depends(_verify_api_key)):
        return {
            "modules": [
                {"name": "xss", "description": "Cross-Site Scripting"},
                {"name": "sqli", "description": "SQL Injection"},
                {"name": "ssrf", "description": "Server-Side Request Forgery"},
                {"name": "headers", "description": "Security Headers Analysis"},
                {"name": "info_disclosure", "description": "Information Disclosure"},
                {"name": "auth", "description": "Broken Auth / IDOR"},
            ]
        }

    return api
