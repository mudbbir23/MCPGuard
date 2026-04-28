"""
MCPGuard — Registry Router
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
API endpoints for the MCP Security Registry: browse, submit, and manage servers.
"""

from __future__ import annotations

import os
import re
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status

from backend.database.models import (
    Advisory,
    AdvisoryCreate,
    ErrorResponse,
    RegistryServer,
    RegistryServerList,
    RegistryServerSubmit,
    ScanStartResponse,
    ScanStatus,
    ServerCategory,
    SeverityScore,
)
from backend.dependencies import get_current_user, optional_user

router = APIRouter()

# ─── In-memory store (replace with Supabase in production) ───

_registry_store: dict[str, dict] = {}
_advisory_store: dict[str, dict] = {}
_watchlist_store: dict[str, list[str]] = {}  # user_id -> [server_id]


# ─── GET /registry — List registry servers ───────────────────

@router.get(
    "",
    response_model=RegistryServerList,
)
async def list_registry_servers(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    category: Optional[str] = Query(None),
    min_score: Optional[str] = Query(None),
    language: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    sort: str = Query("updated_at", regex="^(updated_at|latest_score|name)$"),
):
    """
    List registry servers with filtering, search, and pagination.
    """
    servers = list(_registry_store.values())

    # Apply filters
    if category:
        servers = [s for s in servers if s.get("category") == category]
    if language:
        servers = [s for s in servers if s.get("language", "").lower() == language.lower()]
    if search:
        q = search.lower()
        servers = [
            s for s in servers
            if q in s.get("name", "").lower() or q in s.get("description", "").lower()
        ]

    # Sort
    if sort == "name":
        servers.sort(key=lambda s: s.get("name", ""))
    elif sort == "latest_score":
        score_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "SAFE": 4, None: 5}
        servers.sort(key=lambda s: score_order.get(s.get("latest_score"), 5))
    else:
        servers.sort(key=lambda s: s.get("updated_at", ""), reverse=True)

    total = len(servers)
    start = (page - 1) * limit
    page_servers = servers[start:start + limit]

    return RegistryServerList(
        servers=[RegistryServer(**s) for s in page_servers],
        total=total,
        page=page,
        limit=limit,
    )


# ─── GET /registry/{server_id} — Get server details ─────────

@router.get(
    "/{server_id}",
    response_model=RegistryServer,
    responses={404: {"model": ErrorResponse}},
)
async def get_registry_server(server_id: str):
    """Get detailed information about a specific registry server."""
    server = _registry_store.get(server_id)
    if not server:
        raise HTTPException(
            status_code=404,
            detail={"error": {"code": "not_found", "message": f"Server {server_id} not found."}},
        )
    return RegistryServer(**server)


# ─── POST /registry/submit — Submit a server ────────────────

@router.post(
    "/submit",
    response_model=ScanStartResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def submit_server(
    body: RegistryServerSubmit,
    user: Optional[dict] = Depends(optional_user),
):
    """
    Submit a new MCP server to the registry.

    Creates the server record and queues an initial scan.
    """
    github_pattern = re.compile(r'^https?://github\.com/[\w\-\.]+/[\w\-\.]+/?$')
    if not github_pattern.match(body.github_url):
        raise HTTPException(
            status_code=400,
            detail={"error": {"code": "invalid_url", "message": "Invalid GitHub URL format."}},
        )

    # Check for duplicates
    for s in _registry_store.values():
        if s.get("github_url") == body.github_url:
            raise HTTPException(
                status_code=409,
                detail={"error": {"code": "duplicate", "message": "This server is already in the registry."}},
            )

    server_id = str(uuid4())
    now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()

    # Extract name from GitHub URL
    parts = body.github_url.rstrip("/").split("/")
    name = parts[-1] if parts else "unknown"

    server_record = {
        "id": server_id,
        "name": name,
        "description": "",
        "github_url": body.github_url,
        "npm_package": body.npm_package,
        "language": "unknown",
        "category": body.category.value,
        "latest_score": None,
        "latest_scan_id": None,
        "scan_count": 0,
        "created_at": now,
        "updated_at": now,
    }

    _registry_store[server_id] = server_record

    # Queue scan
    scan_id = str(uuid4())
    try:
        from backend.tasks.scan_tasks import run_scan
        run_scan.delay(scan_id)
    except Exception:
        pass

    return ScanStartResponse(
        scan_id=scan_id,
        status=ScanStatus.PENDING,
        estimated_seconds=120,
    )


# ─── GET /registry/{server_id}/advisories ───────────────────

@router.get("/{server_id}/advisories")
async def get_server_advisories(server_id: str):
    """List all advisories for a specific server."""
    if server_id not in _registry_store:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Server not found."}})

    advisories = [
        a for a in _advisory_store.values()
        if a.get("server_id") == server_id
    ]
    return {"advisories": advisories, "total": len(advisories)}


# ─── POST /registry/{server_id}/advisories ──────────────────

@router.post("/{server_id}/advisories", status_code=status.HTTP_201_CREATED)
async def create_advisory(server_id: str, body: AdvisoryCreate):
    """Submit a security advisory for a registry server."""
    if server_id not in _registry_store:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Server not found."}})

    advisory_id = str(uuid4())
    now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()

    advisory = {
        "id": advisory_id,
        "server_id": server_id,
        "cve_id": body.cve_id,
        "title": body.title,
        "description": body.description,
        "severity": body.severity.value,
        "disclosed_at": now,
        "reporter_email": body.reporter_email,
        "verified": False,
        "created_at": now,
    }

    _advisory_store[advisory_id] = advisory
    return advisory


# ─── POST /registry/{server_id}/watch ───────────────────────

@router.post("/{server_id}/watch", status_code=status.HTTP_201_CREATED)
async def watch_server(server_id: str, user: dict = Depends(get_current_user)):
    """Add a server to the user's watchlist."""
    if server_id not in _registry_store:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Server not found."}})

    user_id = user.get("id", "anonymous")
    if user_id not in _watchlist_store:
        _watchlist_store[user_id] = []

    if server_id not in _watchlist_store[user_id]:
        _watchlist_store[user_id].append(server_id)

    return {"status": "watching", "server_id": server_id}


# ─── DELETE /registry/{server_id}/watch ──────────────────────

@router.delete("/{server_id}/watch")
async def unwatch_server(server_id: str, user: dict = Depends(get_current_user)):
    """Remove a server from the user's watchlist."""
    user_id = user.get("id", "anonymous")
    if user_id in _watchlist_store:
        _watchlist_store[user_id] = [
            s for s in _watchlist_store[user_id] if s != server_id
        ]
    return {"status": "unwatched", "server_id": server_id}
