"""Job queue operations.

A single orchestrator process serialises writes to SQLite, but claiming is still
written defensively (conditional UPDATE + rowcount check) so more than one worker
can safely poll.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta

from sqlmodel import Session, select

from ..allowlist import resolve_spec
from ..config import get_settings
from ..models import ScanJob, Target
from ..schemas import JobSpec

log = logging.getLogger("scangrid.queue")


def enqueue_target(session: Session, target: Target, *, force: bool = False) -> ScanJob | None:
    """Create a queued job for a target unless one is already pending."""
    if not target.enabled and not force:
        return None
    existing = session.exec(
        select(ScanJob).where(
            ScanJob.target_id == target.id,
            ScanJob.state.in_(("queued", "claimed", "running")),  # type: ignore[attr-defined]
        )
    ).first()
    if existing:
        return None

    res = resolve_spec(target.spec)
    if res.rejected:
        log.warning(
            "target %s: %d spec entr(y/ies) refused, e.g. %s",
            target.name,
            len(res.rejected),
            res.rejected[:3],
        )
    if not res.allowed:
        log.error("target %s: nothing in scope, not enqueuing", target.name)
        return None

    args = target.nmap_args.strip() or get_settings().default_nmap_args
    job = ScanJob(
        target_id=target.id,
        state="queued",
        spec_json=json.dumps({"hosts": res.allowed, "nmap_args": args}),
    )
    session.add(job)
    target.last_queued_at = datetime.now(UTC)
    session.add(target)
    session.flush()
    log.info("queued job %s for target %s (%d hosts)", job.id, target.name, len(res.allowed))
    return job


def claim_next(session: Session, worker_id: str) -> JobSpec | None:
    row = session.exec(
        select(ScanJob).where(ScanJob.state == "queued").order_by(ScanJob.created_at).limit(1)
    ).first()
    if row is None:
        return None

    updated = session.exec(
        select(ScanJob).where(ScanJob.id == row.id, ScanJob.state == "queued")
    ).first()
    if updated is None:  # someone else took it
        return None
    updated.state = "claimed"
    updated.worker_id = worker_id
    updated.attempts += 1
    updated.claimed_at = datetime.now(UTC)
    session.add(updated)
    session.flush()

    target = session.get(Target, updated.target_id)
    spec = json.loads(updated.spec_json)
    return JobSpec(
        job_id=updated.id,
        target_id=updated.target_id,
        target_name=target.name if target else "?",
        hosts=spec["hosts"],
        nmap_args=spec["nmap_args"],
    )


def requeue_stale(session: Session) -> int:
    """Return claimed/running jobs that never reported back to the queue."""
    settings = get_settings()
    cutoff = datetime.now(UTC) - timedelta(seconds=settings.job_timeout_seconds + 120)
    stale = session.exec(
        select(ScanJob).where(
            ScanJob.state.in_(("claimed", "running")),  # type: ignore[attr-defined]
            ScanJob.claimed_at < cutoff,
        )
    ).all()
    n = 0
    for job in stale:
        if job.attempts >= settings.job_max_attempts:
            job.state = "error"
            job.error = "exceeded max attempts"
            job.finished_at = datetime.now(UTC)
        else:
            job.state = "queued"
            job.worker_id = ""
            job.claimed_at = None
        session.add(job)
        n += 1
    if n:
        log.info("requeued/failed %d stale job(s)", n)
    return n
