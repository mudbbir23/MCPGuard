"""
MCPGuard — Scans Router
~~~~~~~~~~~~~~~~~~~~~~~~
API endpoints for starting, polling, and listing security scans.
"""

from __future__ import annotations

import os
import re
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

import redis
import json

from backend.database.models import (
    ErrorResponse,
    ScanCreate,
    ScanListResponse,
    ScanResponse,
    ScanStartResponse,
    ScanStatus,
    TargetType,
)
from backend.dependencies import get_current_user, optional_user
from backend.database.client import get_supabase

router = APIRouter()

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)

# ─── Validators ──────────────────────────────────────────────

GITHUB_URL_PATTERN = re.compile(
    r'^https?://github\.com/[\w\-\.]+/[\w\-\.]+/?$'
)
NPM_PACKAGE_PATTERN = re.compile(
    r'^@?[\w\-\.]+(/[\w\-\.]+)?$'
)

def _detect_target_type(url: str) -> TargetType:
    """Auto-detect target type from URL format."""
    if GITHUB_URL_PATTERN.match(url):
        return TargetType.GITHUB
    if NPM_PACKAGE_PATTERN.match(url) and not url.startswith("http"):
        return TargetType.NPM
    return TargetType.LOCAL


# ─── POST /scans — Start a new scan ─────────────────────────

@router.post(
    "",
    response_model=ScanStartResponse,
    status_code=status.HTTP_202_ACCEPTED,
    responses={400: {"model": ErrorResponse}},
)
async def start_scan(
    body: ScanCreate,
    user: Optional[dict] = Depends(optional_user),
):
    """
    Start a new security scan on an MCP server.

    Accepts a GitHub URL or npm package name, validates the format,
    creates a scan record, and dispatches the background scan task.
    """
    target_url = body.target_url.strip()

    # Validate URL format
    if body.target_type == TargetType.GITHUB:
        if not GITHUB_URL_PATTERN.match(target_url):
            raise HTTPException(
                status_code=400,
                detail={"error": {"code": "invalid_url", "message": "Invalid GitHub URL."}},
            )
    elif body.target_type == TargetType.NPM:
        if not NPM_PACKAGE_PATTERN.match(target_url):
            raise HTTPException(
                status_code=400,
                detail={"error": {"code": "invalid_package", "message": "Invalid npm package name."}},
            )

    try:
        supabase = get_supabase()
    except ValueError:
        raise HTTPException(status_code=500, detail="Database not configured")

    # Create scan record
    scan_id = str(uuid4())
    user_id = user.get("id") if user else None

    scan_record = {
        "id": scan_id,
        "target_url": target_url,
        "target_type": body.target_type.value,
        "status": "pending",
        "user_id": user_id
    }

    try:
        supabase.table("scans").insert(scan_record).execute()
    except Exception:
        scan_record["user_id"] = None
        supabase.table("scans").insert(scan_record).execute()

    # Dispatch Celery task
    try:
        from backend.tasks.scan_tasks import run_scan
        run_scan.delay(scan_id)
    except Exception as e:
        print(f"Error starting Celery task: {e}")

    return ScanStartResponse(
        scan_id=scan_id,
        status=ScanStatus.PENDING,
        estimated_seconds=45,
    )


# ─── GET /scans/{scan_id} — Poll scan status ────────────────

@router.get(
    "/{scan_id}",
    response_model=ScanResponse,
    responses={404: {"model": ErrorResponse}},
)
async def get_scan(scan_id: str):
    """
    Get the current status and results of a scan.

    Returns the full scan record including result_json when complete.
    If the scan is running, includes a progress field with the current layer.
    """
    try:
        supabase = get_supabase()
    except ValueError:
        raise HTTPException(status_code=500, detail="Database not configured")

    response = supabase.table("scans").select("*").eq("id", scan_id).execute()
    if not response.data:
        raise HTTPException(
            status_code=404,
            detail={"error": {"code": "not_found", "message": f"Scan {scan_id} not found."}},
        )

    scan = response.data[0]
    
    # Check redis for progress if not complete
    if scan.get("status") in ["pending", "running"]:
        progress = redis_client.get(f"scan_progress:{scan_id}")
        scan["progress"] = progress if progress else "Scanning..."

    return ScanResponse(**scan)


# ─── GET /scans — List user's scan history ───────────────────

@router.get(
    "",
    response_model=ScanListResponse,
)
async def list_scans(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=50),
    scan_status: Optional[str] = Query(None, alias="status"),
    user: dict = Depends(get_current_user),
):
    """
    List the authenticated user's scan history with pagination.

    Supports filtering by scan status.
    """
    try:
        supabase = get_supabase()
    except ValueError:
        return ScanListResponse(scans=[], total=0, page=page, limit=limit)

    user_id = user.get("id")
    
    query = supabase.table("scans").select("*", count="exact").eq("user_id", user_id)

    if scan_status:
        query = query.eq("status", scan_status)

    start = (page - 1) * limit
    end = start + limit - 1
    
    response = query.order("created_at", desc=True).range(start, end).execute()
    
    total = response.count if response.count else 0

    return ScanListResponse(
        scans=[ScanResponse(**s) for s in response.data],
        total=total,
        page=page,
        limit=limit,
    )
