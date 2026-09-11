"""Worker-facing API (bearer auth).

* ``POST /api/worker/claim``            - hand out the next queued job.
* ``POST /api/worker/jobs/{id}/running`` - optional progress ping.
* ``POST /api/worker/jobs/{id}/result``  - submit results.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session

from ..allowlist import AllowlistError, assert_hosts_allowed
from ..db import get_session
from ..models import ScanJob
from ..schemas import ClaimRequest, ClaimResponse, IngestAck, JobResult
from ..security import require_api_token
from .ingest import process_result
from .queue import claim_next

log = logging.getLogger("scangrid.worker_api")

router = APIRouter(prefix="/api/worker", dependencies=[Depends(require_api_token)], tags=["worker"])


@router.post("/claim", response_model=ClaimResponse)
def claim(req: ClaimRequest, session: Session = Depends(get_session)) -> ClaimResponse:
    spec = claim_next(session, req.worker_id)
    if spec is None:
        return ClaimResponse(job=None)
    # Defence in depth: never dispatch hosts that aren't in the allowlist,
    # even if a stale job row somehow contains them.
    try:
        assert_hosts_allowed(spec.hosts)
    except AllowlistError as exc:
        job = session.get(ScanJob, spec.job_id)
        if job:
            job.state = "error"
            job.error = str(exc)
            session.add(job)
        log.error("job %s blocked by allowlist: %s", spec.job_id, exc)
        return ClaimResponse(job=None)
    return ClaimResponse(job=spec)


@router.post("/jobs/{job_id}/running")
def mark_running(job_id: int, session: Session = Depends(get_session)) -> dict:
    job = session.get(ScanJob, job_id)
    if job is None:
        raise HTTPException(404, "job not found")
    if job.state == "claimed":
        job.state = "running"
        session.add(job)
    return {"ok": True, "state": job.state}


@router.post("/jobs/{job_id}/result", response_model=IngestAck)
def submit_result(
    job_id: int, result: JobResult, session: Session = Depends(get_session)
) -> IngestAck:
    if result.job_id != job_id:
        raise HTTPException(400, "job id mismatch")
    return process_result(session, result)
