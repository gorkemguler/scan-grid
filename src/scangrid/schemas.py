"""Wire formats for the worker <-> orchestrator API."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class JobSpec(BaseModel):
    """The resolved work unit handed to a worker."""

    job_id: int
    target_id: int
    target_name: str
    hosts: list[str]
    nmap_args: str


class ClaimRequest(BaseModel):
    worker_id: str
    capabilities: dict[str, Any] = Field(default_factory=dict)


class ClaimResponse(BaseModel):
    job: JobSpec | None = None


class PortResult(BaseModel):
    port: int
    proto: str = "tcp"
    state: str = "open"
    name: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    cpe: str = ""


class HostResult(BaseModel):
    ip: str
    hostname: str = ""
    mac: str = ""
    vendor: str = ""
    os_guess: str = ""
    state: str = "up"
    ports: list[PortResult] = Field(default_factory=list)


class JobResult(BaseModel):
    job_id: int
    worker_id: str
    ok: bool = True
    error: str = ""
    started_at: datetime | None = None
    finished_at: datetime | None = None
    hosts: list[HostResult] = Field(default_factory=list)
    raw_nmap_args: str = ""


class IngestAck(BaseModel):
    accepted: bool = True
    scan_id: int | None = None
    hosts_upserted: int = 0
    services_upserted: int = 0
    changes: int = 0
    cve_enrich_queued: int = 0


class HealthReport(BaseModel):
    status: Literal["ok", "degraded"] = "ok"
    version: str
    role: str
    detail: dict[str, Any] = Field(default_factory=dict)
