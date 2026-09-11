"""Turn a worker :class:`JobResult` into a Scan, inventory updates and changes."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

from sqlmodel import Session, select

from ..cve.cpe import build_cpe
from ..diffing import diff_snapshots, snapshot_from_hosts
from ..models import Change, Host, Scan, ScanJob, Service, Target
from ..schemas import IngestAck, JobResult

log = logging.getLogger("scangrid.ingest")


def process_result(session: Session, result: JobResult) -> IngestAck:
    job = session.get(ScanJob, result.job_id)
    if job is None:
        log.error("result for unknown job %s", result.job_id)
        return IngestAck(accepted=False)

    if not result.ok:
        job.state = "error"
        job.error = result.error[:500]
        job.finished_at = datetime.now(UTC)
        session.add(job)
        log.warning("job %s failed on worker: %s", job.id, result.error)
        return IngestAck(accepted=True)

    target = session.get(Target, job.target_id)
    now = datetime.now(UTC)

    current = snapshot_from_hosts(result.hosts)
    previous = _previous_snapshot(session, job.target_id)

    scan = Scan(
        target_id=job.target_id,
        job_id=job.id,
        started_at=result.started_at or now,
        finished_at=result.finished_at or now,
        hosts_total=len(result.hosts),
        hosts_up=sum(1 for h in result.hosts if h.state == "up"),
        services_open=sum(len(h.ports) for h in result.hosts),
        snapshot_json=json.dumps(current),
    )
    session.add(scan)
    session.flush()

    services_upserted = _apply_inventory(session, result, scan.id, now)
    changes = _record_changes(session, job.target_id, scan.id, previous, current)

    job.state = "done"
    job.finished_at = now
    session.add(job)
    if target:
        target.last_scan_at = now
        session.add(target)

    pending_cve = session.exec(
        select(Service).where(Service.needs_cve == True)  # noqa: E712
    ).all()

    return IngestAck(
        accepted=True,
        scan_id=scan.id,
        hosts_upserted=len(result.hosts),
        services_upserted=services_upserted,
        changes=changes,
        cve_enrich_queued=len(pending_cve),
    )


def _previous_snapshot(session: Session, target_id: int) -> dict:
    row = session.exec(
        select(Scan).where(Scan.target_id == target_id).order_by(Scan.started_at.desc()).limit(1)
    ).first()
    if row is None:
        return {}
    try:
        return json.loads(row.snapshot_json)
    except json.JSONDecodeError:
        return {}


def _apply_inventory(session: Session, result: JobResult, scan_id: int, now: datetime) -> int:
    upserted = 0
    for h in result.hosts:
        host = session.get(Host, h.ip)
        if host is None:
            host = Host(ip=h.ip, first_seen=now)
        host.hostname = h.hostname or host.hostname
        host.mac = h.mac or host.mac
        host.vendor = h.vendor or host.vendor
        host.os_guess = h.os_guess or host.os_guess
        host.state = h.state
        host.last_seen = now
        session.add(host)

        seen_keys: set[tuple[int, str]] = set()
        for p in h.ports:
            seen_keys.add((p.port, p.proto))
            svc = session.exec(
                select(Service).where(
                    Service.host_ip == h.ip,
                    Service.port == p.port,
                    Service.proto == p.proto,
                )
            ).first()
            cpe = build_cpe(p.product, p.version, p.cpe)
            if svc is None:
                svc = Service(host_ip=h.ip, port=p.port, proto=p.proto, first_seen=now)
                svc.needs_cve = bool(p.product)
            else:
                if (svc.product, svc.version) != (p.product, p.version):
                    svc.needs_cve = bool(p.product)
            svc.state = "open"
            svc.name = p.name
            svc.product = p.product
            svc.version = p.version
            svc.extrainfo = p.extrainfo
            svc.cpe = cpe
            svc.last_seen = now
            svc.last_scan_id = scan_id
            session.add(svc)
            upserted += 1

        # Mark services not seen this scan as closed (kept for history).
        for svc in session.exec(select(Service).where(Service.host_ip == h.ip)).all():
            if (svc.port, svc.proto) not in seen_keys and svc.state == "open":
                svc.state = "closed"
                svc.last_seen = now
                session.add(svc)
    return upserted


def _record_changes(
    session: Session, target_id: int, scan_id: int, previous: dict, current: dict
) -> int:
    if not previous:
        return 0  # first scan of this target: nothing to diff against
    diffs = diff_snapshots(previous, current)
    for ch in diffs:
        session.add(
            Change(
                target_id=target_id,
                scan_id=scan_id,
                host_ip=ch["host_ip"],
                kind=ch["kind"],
                severity=ch["severity"],
                detail_json=json.dumps(ch["detail"]),
            )
        )
    if diffs:
        log.info("target %s scan %s: %d change(s)", target_id, scan_id, len(diffs))
    return len(diffs)
