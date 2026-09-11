"""Server-rendered dashboard (Jinja2, no build step)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, func, select

from .. import __version__
from ..db import get_session
from ..models import Change, Finding, Host, Scan, ScanJob, Service, Target
from ..security import require_dashboard_user

_HERE = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=_HERE / "templates")


def _ago(dt: datetime | None) -> str:
    if dt is None:
        return "never"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    s = int((datetime.now(UTC) - dt).total_seconds())
    if s < 60:
        return f"{s}s ago"
    if s < 3600:
        return f"{s // 60}m ago"
    if s < 86400:
        return f"{s // 3600}h ago"
    return f"{s // 86400}d ago"


templates.env.filters["ago"] = _ago

router = APIRouter(dependencies=[Depends(require_dashboard_user)], include_in_schema=False)


def _render(request: Request, name: str, **extra):
    return templates.TemplateResponse(
        request, name, {"version": __version__, "now": datetime.now(UTC), **extra}
    )


@router.get("/", response_class=HTMLResponse)
def index(request: Request, session: Session = Depends(get_session)) -> HTMLResponse:
    def count(model, *where):
        return session.exec(select(func.count()).select_from(model).where(*where)).one()

    sev = dict(
        session.exec(
            select(Finding.severity, func.count())
            .where(Finding.muted == False)  # noqa: E712
            .group_by(Finding.severity)
        ).all()
    )
    counters = {
        "targets": count(Target),
        "hosts_up": count(Host, Host.state == "up"),
        "services_open": count(Service, Service.state == "open"),
        "jobs_queued": count(ScanJob, ScanJob.state == "queued"),
        "crit_high": sev.get("critical", 0) + sev.get("high", 0),
    }
    top_findings = session.exec(
        select(Finding)
        .where(Finding.muted == False)  # noqa: E712
        .order_by(Finding.cvss.desc())
        .limit(10)
    ).all()
    recent_changes = session.exec(select(Change).order_by(Change.ts.desc()).limit(12)).all()
    return _render(
        request,
        "index.html",
        counters=counters,
        sev=sev,
        top_findings=top_findings,
        recent_changes=recent_changes,
    )


@router.get("/targets", response_class=HTMLResponse)
def targets_page(request: Request, session: Session = Depends(get_session)) -> HTMLResponse:
    rows = session.exec(select(Target).order_by(Target.name)).all()
    return _render(request, "targets.html", targets=rows)


@router.get("/hosts", response_class=HTMLResponse)
def hosts_page(request: Request, session: Session = Depends(get_session)) -> HTMLResponse:
    hosts = session.exec(select(Host).order_by(Host.last_seen.desc())).all()
    data = []
    for h in hosts:
        svcs = session.exec(
            select(Service).where(Service.host_ip == h.ip, Service.state == "open")
        ).all()
        nf = session.exec(
            select(func.count())
            .select_from(Finding)
            .where(
                Finding.host_ip == h.ip,
                Finding.muted == False,  # noqa: E712
            )
        ).one()
        data.append((h, svcs, nf))
    return _render(request, "hosts.html", rows=data)


@router.get("/findings", response_class=HTMLResponse)
def findings_page(request: Request, session: Session = Depends(get_session)) -> HTMLResponse:
    rows = session.exec(
        select(Finding, Service)
        .join(Service, Service.id == Finding.service_id)
        .where(Finding.muted == False)  # noqa: E712
        .order_by(Finding.cvss.desc())
        .limit(400)
    ).all()
    return _render(request, "findings.html", rows=rows)


@router.get("/changes", response_class=HTMLResponse)
def changes_page(request: Request, session: Session = Depends(get_session)) -> HTMLResponse:
    cutoff = datetime.now(UTC) - timedelta(days=14)
    rows = session.exec(
        select(Change).where(Change.ts >= cutoff).order_by(Change.ts.desc()).limit(400)
    ).all()
    return _render(request, "changes.html", changes=rows)


@router.get("/jobs", response_class=HTMLResponse)
def jobs_page(request: Request, session: Session = Depends(get_session)) -> HTMLResponse:
    rows = session.exec(select(ScanJob).order_by(ScanJob.created_at.desc()).limit(100)).all()
    scans = session.exec(select(Scan).order_by(Scan.started_at.desc()).limit(30)).all()
    return _render(request, "jobs.html", jobs=rows, scans=scans)
