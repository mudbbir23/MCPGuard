"""
MCPGuard — Registry Router
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
API endpoints for the MCP Security Registry: browse, submit, and manage servers.
Uses Supabase PostgreSQL backend.
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
from backend.database.client import get_supabase

router = APIRouter()

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
    List registry servers with filtering, search, and pagination via Supabase.
    """
    try:
        supabase = get_supabase()
    except ValueError:
        # Fallback empty list if Supabase is not configured
        return RegistryServerList(servers=[], total=0, page=page, limit=limit)

    query = supabase.table("registry_servers").select("*", count="exact")

    if category:
        query = query.eq("category", category)
    if language:
        query = query.eq("language", language.lower())
    if search:
        # Supabase ilike search
        query = query.or_(f"name.ilike.%{search}%,description.ilike.%{search}%")
    
    # Sort
    if sort == "name":
        query = query.order("name", desc=False)
    elif sort == "latest_score":
        # Note: ordering by ENUM in Supabase respects the ENUM defined order if created correctly, 
        # or we just order by latest_score as text.
        query = query.order("latest_score", desc=False)
    else:
        query = query.order("updated_at", desc=True)

    start = (page - 1) * limit
    end = start + limit - 1
    
    response = query.range(start, end).execute()
    
    servers = [RegistryServer(**row) for row in response.data]
    total = response.count if response.count else 0

    return RegistryServerList(
        servers=servers,
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
    try:
        supabase = get_supabase()
    except ValueError:
        raise HTTPException(status_code=500, detail="Database not configured")

    response = supabase.table("registry_servers").select("*").eq("id", server_id).execute()
    if not response.data:
        raise HTTPException(
            status_code=404,
            detail={"error": {"code": "not_found", "message": f"Server {server_id} not found."}},
        )
    return RegistryServer(**response.data[0])


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

    try:
        supabase = get_supabase()
    except ValueError:
        raise HTTPException(status_code=500, detail="Database not configured")

    # Check for duplicates
    dup_res = supabase.table("registry_servers").select("id").eq("github_url", body.github_url).execute()
    if dup_res.data:
        raise HTTPException(
            status_code=409,
            detail={"error": {"code": "duplicate", "message": "This server is already in the registry."}},
        )

    server_id = str(uuid4())
    
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
    }

    # Insert into registry_servers
    supabase.table("registry_servers").insert(server_record).execute()

    # Create scan record in DB
    scan_id = str(uuid4())
    user_id = user.get("id") if user else None
    
    scan_record = {
        "id": scan_id,
        "target_url": body.github_url,
        "target_type": "github",
        "status": "pending",
        "user_id": user_id
    }
    
    # We ignore errors if user_id UUID parsing fails since we just use Supabase auth
    try:
        supabase.table("scans").insert(scan_record).execute()
    except Exception as e:
        # If user_id is not a valid UUID in our DB, insert without user_id
        scan_record["user_id"] = None
        supabase.table("scans").insert(scan_record).execute()

    # Queue scan in celery
    try:
        from backend.tasks.scan_tasks import run_scan
        run_scan.delay(scan_id)
    except Exception as e:
        print(f"Error queueing scan: {e}")

    return ScanStartResponse(
        scan_id=scan_id,
        status=ScanStatus.PENDING,
        estimated_seconds=120,
    )


# ─── GET /registry/{server_id}/advisories ───────────────────

@router.get("/{server_id}/advisories")
async def get_server_advisories(server_id: str):
    """List all advisories for a specific server."""
    try:
        supabase = get_supabase()
    except ValueError:
        return {"advisories": [], "total": 0}

    # Verify server exists
    srv = supabase.table("registry_servers").select("id").eq("id", server_id).execute()
    if not srv.data:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Server not found."}})

    res = supabase.table("registry_advisories").select("*").eq("server_id", server_id).execute()
    return {"advisories": res.data, "total": len(res.data)}


# ─── POST /registry/{server_id}/advisories ──────────────────

@router.post("/{server_id}/advisories", status_code=status.HTTP_201_CREATED)
async def create_advisory(server_id: str, body: AdvisoryCreate):
    """Submit a security advisory for a registry server."""
    try:
        supabase = get_supabase()
    except ValueError:
        raise HTTPException(status_code=500, detail="Database not configured")

    srv = supabase.table("registry_servers").select("id").eq("id", server_id).execute()
    if not srv.data:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Server not found."}})

    advisory_id = str(uuid4())

    advisory = {
        "id": advisory_id,
        "server_id": server_id,
        "cve_id": body.cve_id,
        "title": body.title,
        "description": body.description,
        "severity": body.severity.value,
        "reporter_email": body.reporter_email,
        "verified": False,
    }

    res = supabase.table("registry_advisories").insert(advisory).execute()
    return res.data[0]


# ─── POST /registry/{server_id}/watch ───────────────────────

@router.post("/{server_id}/watch", status_code=status.HTTP_201_CREATED)
async def watch_server(server_id: str, user: dict = Depends(get_current_user)):
    """Add a server to the user's watchlist."""
    try:
        supabase = get_supabase()
    except ValueError:
        raise HTTPException(status_code=500, detail="Database not configured")

    srv = supabase.table("registry_servers").select("id").eq("id", server_id).execute()
    if not srv.data:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Server not found."}})

    user_id = user.get("id")
    try:
        supabase.table("watchlist").insert({"user_id": user_id, "server_id": server_id}).execute()
    except Exception:
        # Ignore if already exists (primary key constraint)
        pass

    return {"status": "watching", "server_id": server_id}


# ─── DELETE /registry/{server_id}/watch ──────────────────────

@router.delete("/{server_id}/watch")
async def unwatch_server(server_id: str, user: dict = Depends(get_current_user)):
    """Remove a server from the user's watchlist."""
    try:
        supabase = get_supabase()
        supabase.table("watchlist").delete().eq("user_id", user.get("id")).eq("server_id", server_id).execute()
    except Exception:
        pass
        
    return {"status": "unwatched", "server_id": server_id}
