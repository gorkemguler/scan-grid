"""Persisted data model (SQLModel / SQLite).

Targets define *what* to scan; jobs are queued units of work; scans are
completed runs used for diffing; hosts/services are the rolling asset
inventory; findings are CVE matches; changes are the diff event log.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlmodel import Field, SQLModel


def _now() -> datetime:
    return datetime.now(UTC)


class Target(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True)
    # Space/comma/newline separated: CIDRs, single IPs, "a.b.c.d-e" ranges.
    spec: str
    nmap_args: str = Field(default="", description="Blank => orchestrator default_nmap_args.")
    interval_minutes: int = Field(default=1440, description="0 disables scheduling (manual only).")
    enabled: bool = Field(default=True)
    created_at: datetime = Field(default_factory=_now)
    last_queued_at: datetime | None = Field(default=None)
    last_scan_at: datetime | None = Field(default=None)


class ScanJob(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id", index=True)
    state: str = Field(default="queued", index=True)  # queued|claimed|running|done|error
    spec_json: str = Field(description="Resolved {hosts:[...], nmap_args:'...'}.")
    worker_id: str = Field(default="")
    attempts: int = Field(default=0)
    created_at: datetime = Field(default_factory=_now, index=True)
    claimed_at: datetime | None = Field(default=None)
    finished_at: datetime | None = Field(default=None)
    error: str = Field(default="")


class Scan(SQLModel, table=True):
    """A completed scan run - the unit that diffing compares."""

    id: int | None = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id", index=True)
    job_id: int | None = Field(default=None, foreign_key="scanjob.id")
    started_at: datetime = Field(default_factory=_now, index=True)
    finished_at: datetime = Field(default_factory=_now)
    hosts_total: int = Field(default=0)
    hosts_up: int = Field(default=0)
    services_open: int = Field(default=0)
    # Frozen snapshot used to diff against the next scan of this target.
    snapshot_json: str = Field(default="{}")


class Host(SQLModel, table=True):
    ip: str = Field(primary_key=True)
    hostname: str = Field(default="")
    mac: str = Field(default="")
    vendor: str = Field(default="")
    os_guess: str = Field(default="")
    state: str = Field(default="up", description="up|down (last observation)")
    first_seen: datetime = Field(default_factory=_now)
    last_seen: datetime = Field(default_factory=_now, index=True)


class Service(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    host_ip: str = Field(foreign_key="host.ip", index=True)
    port: int = Field(index=True)
    proto: str = Field(default="tcp")
    state: str = Field(default="open")
    name: str = Field(default="")
    product: str = Field(default="")
    version: str = Field(default="")
    extrainfo: str = Field(default="")
    cpe: str = Field(default="", index=True)
    first_seen: datetime = Field(default_factory=_now)
    last_seen: datetime = Field(default_factory=_now, index=True)
    last_scan_id: int | None = Field(default=None)
    needs_cve: bool = Field(default=True, index=True, description="Pending CVE enrichment.")


class Finding(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    host_ip: str = Field(index=True)
    service_id: int = Field(foreign_key="service.id", index=True)
    cve_id: str = Field(index=True)
    cvss: float = Field(default=0.0, index=True)
    severity: str = Field(default="unknown", description="low|medium|high|critical|unknown")
    summary: str = Field(default="")
    cpe: str = Field(default="")
    source: str = Field(default="")
    published: str = Field(default="")
    created_at: datetime = Field(default_factory=_now, index=True)
    muted: bool = Field(default=False, index=True)


class Change(SQLModel, table=True):
    """Diff event: what changed between the previous scan and the latest."""

    id: int | None = Field(default=None, primary_key=True)
    ts: datetime = Field(default_factory=_now, index=True)
    target_id: int = Field(index=True)
    scan_id: int | None = Field(default=None)
    host_ip: str = Field(default="", index=True)
    kind: str = Field(index=True)  # host.up|host.down|port.open|port.close|service.change|cve.new
    severity: str = Field(default="info")
    detail_json: str = Field(default="{}")
    notified: bool = Field(default=False, index=True)


class CveCache(SQLModel, table=True):
    """Cache of provider lookups keyed by the query (cpe or product|version)."""

    query: str = Field(primary_key=True)
    result_json: str = Field(default="[]")
    checked_at: datetime = Field(default_factory=_now, index=True)
