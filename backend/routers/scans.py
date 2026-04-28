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

router = APIRouter()

# ─── In-memory store (replace with Supabase in production) ───

_scans_store: dict[str, dict] = {}


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
                detail={"error": {"code": "invalid_url", "message": "Invalid GitHub URL. Expected format: https://github.com/owner/repo"}},
            )
    elif body.target_type == TargetType.NPM:
        if not NPM_PACKAGE_PATTERN.match(target_url):
            raise HTTPException(
                status_code=400,
                detail={"error": {"code": "invalid_package", "message": "Invalid npm package name. Expected format: @scope/package or package-name"}},
            )

    # Create scan record
    scan_id = str(uuid4())
    user_id = user.get("id") if user else None

    scan_record = {
        "id": scan_id,
        "created_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        "user_id": user_id,
        "target_url": target_url,
        "target_type": body.target_type.value,
        "status": "pending",
        "overall_score": None,
        "result_json": None,
        "scan_duration_ms": None,
        "error_message": None,
        "progress": None,
    }

    _scans_store[scan_id] = scan_record

    # Dispatch Celery task (try import, graceful fallback)
    try:
        from backend.tasks.scan_tasks import run_scan
        run_scan.delay(scan_id)
    except Exception:
        # If Celery not available, update status for demo
        scan_record["status"] = "pending"

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
    scan = _scans_store.get(scan_id)
    if not scan:
        raise HTTPException(
            status_code=404,
            detail={"error": {"code": "not_found", "message": f"Scan {scan_id} not found."}},
        )

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
    user_id = user.get("id")

    # Filter scans
    user_scans = [
        s for s in _scans_store.values()
        if s.get("user_id") == user_id
    ]

    if scan_status:
        user_scans = [s for s in user_scans if s.get("status") == scan_status]

    # Sort by created_at descending
    user_scans.sort(key=lambda s: s.get("created_at", ""), reverse=True)

    # Paginate
    total = len(user_scans)
    start = (page - 1) * limit
    end = start + limit
    page_scans = user_scans[start:end]

    return ScanListResponse(
        scans=[ScanResponse(**s) for s in page_scans],
        total=total,
        page=page,
        limit=limit,
    )
