"""
MCPGuard — Celery Scan Tasks
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Background tasks for running security scans on MCP servers.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import tempfile
import time
from uuid import uuid4

from celery import Celery

# ─── Celery App ──────────────────────────────────────────────

celery_app = Celery(
    "mcpguard",
    broker=os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0"),
    backend=os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/1"),
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=300,  # 5 minutes max
    task_soft_time_limit=240,  # 4 minutes soft limit
)


import redis
redis_client = redis.Redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True)

def _update_scan(scan_id: str, **kwargs):
    """Update scan record in Supabase and progress in Redis."""
    try:
        from backend.database.client import get_supabase
        supabase = get_supabase()
        
        db_kwargs = {k: v for k, v in kwargs.items() if k != "progress"}
        if db_kwargs:
            supabase.table("scans").update(db_kwargs).eq("id", scan_id).execute()
            
        if "progress" in kwargs:
            if kwargs["progress"]:
                redis_client.setex(f"scan_progress:{scan_id}", 3600, kwargs["progress"])
            else:
                redis_client.delete(f"scan_progress:{scan_id}")
    except Exception as e:
        print(f"Error updating scan {scan_id}: {e}")


# ─── Main Scan Task ──────────────────────────────────────────

@celery_app.task(bind=True, max_retries=2, name="run_scan")
def run_scan(self, scan_id: str):
    """
    Run a full security scan on the target MCP server.

    Steps:
    1. Update status to "running"
    2. Clone/download the target into a temp directory
    3. Run all scanner modules in sequence
    4. Build combined report
    5. Update scan with results
    6. Clean up temp directory (always)

    Args:
        scan_id: UUID of the scan record to process.
    """
    start_time = time.time()
    tmp_dir = None

    try:
        try:
            from backend.database.client import get_supabase
            supabase = get_supabase()
            response = supabase.table("scans").select("*").eq("id", scan_id).execute()
            scan = response.data[0] if response.data else None
        except Exception as e:
            print(f"Error fetching scan {scan_id}: {e}")
            scan = None

        if not scan:
            return {"error": f"Scan {scan_id} not found"}

        target_url = scan["target_url"]
        target_type = scan["target_type"]

        # Step 1: Update status
        _update_scan(scan_id, status="running", progress="Preparing scan environment...")

        # Step 2: Download target
        tmp_dir = tempfile.mkdtemp(prefix="mcpguard_scan_")
        _update_scan(scan_id, progress="Downloading target...")

        if target_type == "github":
            result = subprocess.run(
                ["git", "clone", "--depth", "1", target_url, tmp_dir],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode != 0:
                _update_scan(
                    scan_id,
                    status="failed",
                    error_message=f"Git clone failed: {result.stderr[:500]}",
                )
                return {"error": "Git clone failed"}

        elif target_type == "npm":
            # Use npm pack to download the package
            result = subprocess.run(
                ["npm", "pack", target_url, "--pack-destination", tmp_dir],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode != 0:
                _update_scan(
                    scan_id,
                    status="failed",
                    error_message=f"npm pack failed: {result.stderr[:500]}",
                )
                return {"error": "npm pack failed"}

            # Extract the tarball
            tarballs = [f for f in os.listdir(tmp_dir) if f.endswith(".tgz")]
            if tarballs:
                subprocess.run(
                    ["tar", "xzf", os.path.join(tmp_dir, tarballs[0]), "-C", tmp_dir],
                    capture_output=True,
                    timeout=30,
                )

        # Step 3: Run scanner modules
        all_findings = []

        # 3a: Dependency Audit
        _update_scan(scan_id, progress="Running dependency audit...")
        try:
            from scanner.dependency_audit import run_full_dependency_audit
            dep_findings = asyncio.run(run_full_dependency_audit(tmp_dir))
            all_findings.extend(dep_findings)
        except Exception as e:
            from scanner.dependency_audit import Finding
            all_findings.append(Finding(
                id=str(uuid4()),
                category="dependency-audit",
                severity="INFO",
                title="Dependency audit error",
                description=f"Error during dependency audit: {str(e)[:200]}",
                remediation="Run dependency audit manually.",
            ))

        # 3b: Static Analysis
        _update_scan(scan_id, progress="Running static analysis...")
        try:
            from scanner.static_analysis import scan_directory
            static_findings = scan_directory(tmp_dir)
            all_findings.extend(static_findings)
        except Exception as e:
            from scanner.dependency_audit import Finding
            all_findings.append(Finding(
                id=str(uuid4()),
                category="static-analysis",
                severity="INFO",
                title="Static analysis error",
                description=f"Error during static analysis: {str(e)[:200]}",
                remediation="Run static analysis manually.",
            ))

        # 3c: Tool Analysis
        _update_scan(scan_id, progress="Analyzing tool descriptions...")
        try:
            from scanner.tool_analysis import (
                analyze_tool_descriptions,
                check_unicode_tricks,
                extract_tool_definitions,
            )
            tools = extract_tool_definitions(tmp_dir)
            if tools:
                unicode_findings = check_unicode_tricks(tools)
                all_findings.extend(unicode_findings)

                api_key = os.getenv("ANTHROPIC_API_KEY")
                tool_findings = asyncio.run(analyze_tool_descriptions(tools, api_key))
                all_findings.extend(tool_findings)
        except Exception as e:
            from scanner.dependency_audit import Finding
            all_findings.append(Finding(
                id=str(uuid4()),
                category="tool-analysis",
                severity="INFO",
                title="Tool analysis error",
                description=f"Error during tool analysis: {str(e)[:200]}",
                remediation="Run tool analysis manually.",
            ))

        # 3d: Permission Audit
        _update_scan(scan_id, progress="Auditing permissions...")
        try:
            from scanner.permission_audit import audit_permissions
            perm_findings = audit_permissions(tmp_dir)
            all_findings.extend(perm_findings)
        except Exception as e:
            from scanner.dependency_audit import Finding
            all_findings.append(Finding(
                id=str(uuid4()),
                category="permission-audit",
                severity="INFO",
                title="Permission audit error",
                description=f"Error during permission audit: {str(e)[:200]}",
                remediation="Run permission audit manually.",
            ))

        # Step 4: Build report
        _update_scan(scan_id, progress="Building report...")
        scan_duration_ms = int((time.time() - start_time) * 1000)

        from scanner.report_builder import build_report
        report = build_report(
            findings=all_findings,
            target_url=target_url,
            target_type=target_type,
            scan_duration_ms=scan_duration_ms,
        )

        # Step 5: Update scan with results
        _update_scan(
            scan_id,
            status="complete",
            overall_score=report["overall_score"],
            result_json=report,
            scan_duration_ms=scan_duration_ms,
            progress=None,
        )

        return {"scan_id": scan_id, "status": "complete", "overall_score": report["overall_score"]}

    except Exception as e:
        scan_duration_ms = int((time.time() - start_time) * 1000)
        _update_scan(
            scan_id,
            status="failed",
            error_message=f"Scan failed: {str(e)[:500]}",
            scan_duration_ms=scan_duration_ms,
            progress=None,
        )

        # Retry on transient errors
        if self.request.retries < self.max_retries:
            raise self.retry(exc=e, countdown=30)

        return {"error": str(e)[:500]}

    finally:
        # ALWAYS clean up temp directory
        if tmp_dir and os.path.exists(tmp_dir):
            try:
                shutil.rmtree(tmp_dir, ignore_errors=True)
            except Exception:
                pass
