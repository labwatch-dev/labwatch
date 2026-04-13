"""Pydantic models for the labwatch API."""

from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field


# --- Registration ---

class RegisterRequest(BaseModel):
    hostname: str = Field(max_length=255)
    os: str = Field("", max_length=64)
    arch: str = Field("", max_length=32)
    agent_version: str = Field("", max_length=32)


class RegisterResponse(BaseModel):
    lab_id: str
    token: str
    message: str


class SignupRequest(BaseModel):
    email: str = Field(..., max_length=254)
    hostname: str = Field("my-server", max_length=64)
    password: Optional[str] = Field(None, max_length=128)


# --- Metrics ---

class MetricPayload(BaseModel):
    lab_id: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    collectors: dict[str, Any] = Field(
        default_factory=dict,
        description="Collector data keyed by type: system, docker, services",
    )


# --- Status / Display ---

class LabStatus(BaseModel):
    lab_id: str
    hostname: str
    last_seen: Optional[str] = None
    uptime_seconds: Optional[float] = None
    cpu_percent: Optional[float] = None
    memory_percent: Optional[float] = None
    disk_percent: Optional[float] = None
    container_count: Optional[int] = None
    alerts: list["Alert"] = Field(default_factory=list)


class Alert(BaseModel):
    id: Optional[int] = None
    lab_id: str
    type: str
    severity: str  # info, warning, critical
    message: str
    created_at: Optional[str] = None
