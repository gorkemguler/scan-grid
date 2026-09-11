"""Operator REST API (bearer auth).

Targets CRUD, manual scan trigger, asset inventory, findings, changes, stats.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlmodel import Session, func, select

from .. import __version__
from ..allowlist import resolve_spec
from ..db import get_session
from ..models import Change, Finding, Host, Scan, ScanJob, Service, Target
from ..schemas import HealthReport
from ..security import require_api_token
from .queue import enqueue_target

router = APIRouter(tags=["api"])
guard = [Depends(require_api_token)]


class TargetIn(BaseModel):
    name: str
    spec: str
    nmap_args: str = ""
    interval_minutes: int = 1440
    enabled: bool = True


@router.get("/healthz", response_model=HealthReport, tags=["meta"])
def healthz(session: Session = Depends(get_session)) -> HealthReport:
    queued = session.exec(
        select(func.count()).select_from(ScanJob).where(ScanJob.state == "queued")
    ).one()
    return HealthReport(
        status="ok", version=__version__, role="orchestrator", detail={"jobs_queued": queued}
    )


# --------------------------------------------------------------------- targets
@router.get("/api/targets", dependencies=guard)
def list_targets(session: Session = Depends(get_session)) -> list[Target]:
    return list(session.exec(select(Target).order_by(Target.name)))


@router.post("/api/targets", dependencies=guard, status_code=201)
def create_target(body: TargetIn, session: Session = Depends(get_session)) -> Target:
    if session.exec(select(Target).where(Target.name == body.name)).first():
        raise HTTPException(409, "a target with that name exists")
    res = resolve_spec(body.spec)
    if not res.allowed:
        raise HTTPException(
            422,
            {
                "error": "nothing in this spec is inside SCANGRID_ALLOWLIST",
                "rejected": res.rejected,
            },
        )
    target = Target(**body.model_dump())
    session.add(target)
    session.flush()
    return target


@router.get("/api/targets/{target_id}", dependencies=guard)
def get_target(target_id: int, session: Session = Depends(get_session)) -> Target:
    t = session.get(Target, target_id)
    if t is None:
        raise HTTPException(404, "target not found")
    return t


@router.patch("/api/targets/{target_id}", dependencies=guard)
def update_target(
    target_id: int, body: TargetIn, session: Session = Depends(get_session)
) -> Target:
    t = session.get(Target, target_id)
    if t is None:
        raise HTTPException(404, "target not found")
    for k, v in body.model_dump().items():
        setattr(t, k, v)
    session.add(t)
    return t


@router.delete("/api/targets/{target_id}", dependencies=guard, status_code=204)
def delete_target(target_id: int, session: Session = Depends(get_session)) -> None:
    t = session.get(Target, target_id)
    if t is None:
        raise HTTPException(404, "target not found")
    session.delete(t)


@router.post("/api/targets/{target_id}/scan", dependencies=guard)
def scan_now(target_id: int, session: Session = Depends(get_session)) -> dict:
    t = session.get(Target, target_id)
    if t is None:
        raise HTTPException(404, "target not found")
    job = enqueue_target(session, t, force=True)
    if job is None:
        return {"queued": False, "reason": "a job is already pending or nothing in scope"}
    return {"queued": True, "job_id": job.id}


@router.get("/api/targets/{target_id}/preview", dependencies=guard)
def preview_spec(target_id: int, session: Session = Depends(get_session)) -> dict:
    t = session.get(Target, target_id)
    if t is None:
        raise HTTPException(404, "target not found")
    res = resolve_spec(t.spec)
    return {"in_scope": res.allowed, "rejected": res.rejected}


# ----------------------------------------------------------------------- jobs
@router.get("/api/jobs", dependencies=guard)
def list_jobs(
    session: Session = Depends(get_session),
    state: str | None = None,
    limit: int = Query(50, ge=1, le=500),
) -> list[ScanJob]:
    stmt = select(ScanJob).order_by(ScanJob.created_at.desc()).limit(limit)
    if state:
        stmt = stmt.where(ScanJob.state == state)
    return list(session.exec(stmt))


# ------------------------------------------------------------------- inventory
@router.get("/api/hosts", dependencies=guard)
def list_hosts(
    session: Session = Depends(get_session),
    active_days: int | None = Query(None, ge=1),
) -> list[dict]:
    stmt = select(Host).order_by(Host.last_seen.desc())
    if active_days:
        stmt = stmt.where(Host.last_seen >= datetime.now(UTC) - timedelta(days=active_days))
    out = []
    for h in session.exec(stmt):
        svcs = session.exec(
            select(Service).where(Service.host_ip == h.ip, Service.state == "open")
        ).all()
        finds = session.exec(
            select(func.count())
            .select_from(Finding)
            .where(Finding.host_ip == h.ip, Finding.muted == False)  # noqa: E712
        ).one()
        out.append(
            {
                **h.model_dump(),
                "open_ports": sorted(s.port for s in svcs),
                "services": [
                    {
                        "port": s.port,
                        "proto": s.proto,
                        "name": s.name,
                        "product": s.product,
                        "version": s.version,
                        "cpe": s.cpe,
                    }
                    for s in svcs
                ],
                "open_findings": finds,
            }
        )
    return out


@router.get("/api/hosts/{ip}", dependencies=guard)
def host_detail(ip: str, session: Session = Depends(get_session)) -> dict:
    h = session.get(Host, ip)
    if h is None:
        raise HTTPException(404, "host not found")
    svcs = session.exec(select(Service).where(Service.host_ip == ip)).all()
    finds = session.exec(
        select(Finding).where(Finding.host_ip == ip).order_by(Finding.cvss.desc())
    ).all()
    return {
        "host": h.model_dump(),
        "services": [s.model_dump() for s in svcs],
        "findings": [f.model_dump() for f in finds],
    }


@router.get("/api/findings", dependencies=guard)
def list_findings(
    session: Session = Depends(get_session),
    min_cvss: float = Query(0.0, ge=0, le=10),
    severity: str | None = None,
    include_muted: bool = False,
    limit: int = Query(200, ge=1, le=2000),
) -> list[Finding]:
    stmt = (
        select(Finding).where(Finding.cvss >= min_cvss).order_by(Finding.cvss.desc()).limit(limit)
    )
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if not include_muted:
        stmt = stmt.where(Finding.muted == False)  # noqa: E712
    return list(session.exec(stmt))


@router.post("/api/findings/{finding_id}/mute", dependencies=guard)
def mute_finding(
    finding_id: int, muted: bool = True, session: Session = Depends(get_session)
) -> Finding:
    f = session.get(Finding, finding_id)
    if f is None:
        raise HTTPException(404, "finding not found")
    f.muted = muted
    session.add(f)
    return f


@router.get("/api/changes", dependencies=guard)
def list_changes(
    session: Session = Depends(get_session),
    kind: str | None = None,
    since_hours: int = Query(168, ge=1, le=8760),
    limit: int = Query(200, ge=1, le=2000),
) -> list[Change]:
    cutoff = datetime.now(UTC) - timedelta(hours=since_hours)
    stmt = select(Change).where(Change.ts >= cutoff).order_by(Change.ts.desc()).limit(limit)
    if kind:
        stmt = stmt.where(Change.kind == kind)
    return list(session.exec(stmt))


@router.get("/api/scans", dependencies=guard)
def list_scans(
    session: Session = Depends(get_session),
    target_id: int | None = None,
    limit: int = Query(50, ge=1, le=500),
) -> list[Scan]:
    stmt = select(Scan).order_by(Scan.started_at.desc()).limit(limit)
    if target_id:
        stmt = stmt.where(Scan.target_id == target_id)
    return list(session.exec(stmt))


@router.get("/api/stats", dependencies=guard, tags=["meta"])
def stats(session: Session = Depends(get_session)) -> dict:
    def count(model, *where):
        return session.exec(select(func.count()).select_from(model).where(*where)).one()

    sev_rows = session.exec(
        select(Finding.severity, func.count())
        .where(Finding.muted == False)  # noqa: E712
        .group_by(Finding.severity)
    ).all()
    return {
        "targets": count(Target),
        "hosts": count(Host),
        "hosts_up": count(Host, Host.state == "up"),
        "services_open": count(Service, Service.state == "open"),
        "jobs_queued": count(ScanJob, ScanJob.state == "queued"),
        "jobs_running": count(ScanJob, ScanJob.state.in_(("claimed", "running"))),  # type: ignore[attr-defined]
        "findings_by_severity": dict(sev_rows),
        "changes_24h": count(Change, Change.ts >= datetime.now(UTC) - timedelta(hours=24)),
        "generated_at": datetime.now(UTC).isoformat(),
    }
