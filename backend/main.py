"""
MCPGuard — FastAPI Backend
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Main application entry point with CORS, rate limiting, and health check.
"""

from __future__ import annotations

import os

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

load_dotenv()

from backend.routers import scans, registry


# ─── Rate Limiter ────────────────────────────────────────────

limiter = Limiter(key_func=get_remote_address)

# ─── App Init ────────────────────────────────────────────────

app = FastAPI(
    title="MCPGuard API",
    description="Security scanning API for MCP (Model Context Protocol) servers",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ─── CORS ────────────────────────────────────────────────────

cors_origins = os.getenv("BACKEND_CORS_ORIGINS", "http://localhost:3000").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Routers ─────────────────────────────────────────────────

app.include_router(scans.router, prefix="/scans", tags=["scans"])
app.include_router(registry.router, prefix="/registry", tags=["registry"])

# ─── Health Check ────────────────────────────────────────────

@app.get("/health", tags=["system"])
async def health_check():
    """Health check endpoint for monitoring and load balancers."""
    return {"status": "ok", "version": "0.1.0"}


# ─── Global Error Handler ───────────────────────────────────

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Catch-all error handler to prevent leaking stack traces."""
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": "internal_error",
                "message": "An unexpected error occurred. Please try again later.",
            }
        },
    )
