"""
MCPGuard — Database Pydantic Models
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Pydantic models matching the database schema for request/response validation.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, EmailStr, Field, field_validator


# ─── Enum Types ──────────────────────────────────────────────

class PlanType(str, Enum):
    FREE = "free"
    PRO = "pro"
    TEAM = "team"


class TargetType(str, Enum):
    GITHUB = "github"
    NPM = "npm"
    LOCAL = "local"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"


class SeverityScore(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    SAFE = "SAFE"


class ServerCategory(str, Enum):
    FILESYSTEM = "filesystem"
    COMMUNICATION = "communication"
    DEVELOPMENT = "development"
    DATABASE = "database"
    OTHER = "other"


class AdvisorySeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# ─── User Models ────────────────────────────────────────────

class UserBase(BaseModel):
    email: str
    plan: PlanType = PlanType.FREE


class UserCreate(UserBase):
    pass


class User(UserBase):
    id: UUID
    api_key: Optional[str] = None
    created_at: datetime

    model_config = {"from_attributes": True}


# ─── Scan Models ────────────────────────────────────────────

class ScanCreate(BaseModel):
    target_url: str
    target_type: TargetType

    @field_validator("target_url")
    @classmethod
    def validate_target_url(cls, v: str, info) -> str:
        v = v.strip()
        if not v:
            raise ValueError("target_url cannot be empty")
        return v


class ScanResponse(BaseModel):
    id: UUID
    created_at: datetime
    user_id: Optional[UUID] = None
    target_url: str
    target_type: TargetType
    status: ScanStatus
    overall_score: Optional[SeverityScore] = None
    result_json: Optional[dict[str, Any]] = None
    scan_duration_ms: Optional[int] = None
    error_message: Optional[str] = None
    progress: Optional[str] = None

    model_config = {"from_attributes": True}


class ScanStartResponse(BaseModel):
    scan_id: UUID
    status: ScanStatus = ScanStatus.PENDING
    estimated_seconds: int = 45


class ScanListResponse(BaseModel):
    scans: list[ScanResponse]
    total: int
    page: int
    limit: int


# ─── Registry Server Models ─────────────────────────────────

class RegistryServerBase(BaseModel):
    name: str
    description: str = ""
    github_url: str
    npm_package: Optional[str] = None
    language: str = "unknown"
    category: ServerCategory = ServerCategory.OTHER


class RegistryServerCreate(RegistryServerBase):
    pass


class RegistryServerSubmit(BaseModel):
    github_url: str
    npm_package: Optional[str] = None
    category: ServerCategory = ServerCategory.OTHER
    email: Optional[str] = None


class RegistryServer(RegistryServerBase):
    id: UUID
    latest_score: Optional[SeverityScore] = None
    latest_scan_id: Optional[UUID] = None
    scan_count: int = 0
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class RegistryServerList(BaseModel):
    servers: list[RegistryServer]
    total: int
    page: int
    limit: int


# ─── Registry Advisory Models ───────────────────────────────

class AdvisoryBase(BaseModel):
    cve_id: Optional[str] = None
    title: str
    description: str
    severity: AdvisorySeverity
    reporter_email: Optional[str] = None


class AdvisoryCreate(AdvisoryBase):
    server_id: UUID


class Advisory(AdvisoryBase):
    id: UUID
    server_id: UUID
    disclosed_at: datetime
    verified: bool = False
    created_at: datetime

    model_config = {"from_attributes": True}


# ─── Watchlist Models ───────────────────────────────────────

class WatchlistEntry(BaseModel):
    user_id: UUID
    server_id: UUID
    notify_on_score_change: bool = True
    created_at: datetime

    model_config = {"from_attributes": True}


class WatchlistAdd(BaseModel):
    server_id: UUID
    notify_on_score_change: bool = True


# ─── Error Response Model ───────────────────────────────────

class ErrorDetail(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    error: ErrorDetail
