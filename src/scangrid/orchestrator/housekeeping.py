"""Scheduled maintenance: enqueue due targets, notify changes, prune history."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta

from sqlmodel import delete, select

from ..config import get_settings
from ..db import session_scope
from ..models import Change, Scan, ScanJob, Target
from ..notify import Notifier
from .queue import enqueue_target, requeue_stale

log = logging.getLogger("scangrid.housekeeping")

_CHANGE_TITLE = {
    "host.up": "New / returned host",
    "host.down": "Host went down",
    "port.open": "New open port",
    "port.close": "Port closed",
    "service.change": "Service version changed",
    "cve.new": "New CVE match",
}


def enqueue_due_targets() -> int:
    now = datetime.now(UTC)
    made = 0
    with session_scope() as session:
        requeue_stale(session)
        for target in session.exec(select(Target).where(Target.enabled == True)).all():  # noqa: E712
            if target.interval_minutes <= 0:
                continue
            due = target.last_queued_at is None or (
                now - target.last_queued_at.replace(tzinfo=UTC)
                >= timedelta(minutes=target.interval_minutes)
            )
            if due and enqueue_target(session, target):
                made += 1
    if made:
        log.info("enqueued %d scheduled scan(s)", made)
    return made


def notify_pending_changes(batch: int = 25) -> int:
    notifier = Notifier()
    sent = 0
    with session_scope() as session:
        rows = session.exec(
            select(Change)
            .where(Change.notified == False)  # noqa: E712
            .order_by(Change.ts)
            .limit(batch)
        ).all()
        # Group by (kind) for a compact digest per tick.
        by_kind: dict[str, list[Change]] = {}
        for c in rows:
            by_kind.setdefault(c.kind, []).append(c)

        for kind, items in by_kind.items():
            worst = _worst_severity(items)
            title = f"{_CHANGE_TITLE.get(kind, kind)} ({len(items)})"
            body = "\n".join(_one_line(c) for c in items[:10])
            if notifier.send(title, body, worst):
                for c in items:
                    c.notified = True
                    session.add(c)
                sent += len(items)
    if sent:
        log.info("notified %d change(s)", sent)
    return sent


def prune_history() -> dict[str, int]:
    keep = get_settings().scan_history_keep
    removed_scans = removed_jobs = 0
    with session_scope() as session:
        for target_id in session.exec(select(Target.id)).all():
            old = list(
                session.exec(
                    select(Scan.id)
                    .where(Scan.target_id == target_id)
                    .order_by(Scan.started_at.desc())
                    .offset(keep)
                ).all()
            )
            if old:
                session.exec(delete(Scan).where(Scan.id.in_(old)))  # type: ignore[attr-defined]
                removed_scans += len(old)
        cutoff = datetime.now(UTC) - timedelta(days=30)
        res = session.exec(
            delete(ScanJob).where(
                ScanJob.state.in_(("done", "error")),  # type: ignore[attr-defined]
                ScanJob.finished_at < cutoff,
            )
        )
        removed_jobs = res.rowcount or 0
    if removed_scans or removed_jobs:
        log.info("pruned %d scan(s), %d job(s)", removed_scans, removed_jobs)
    return {"scans": removed_scans, "jobs": removed_jobs}


def _one_line(c: Change) -> str:
    d = json.loads(c.detail_json or "{}")
    if c.kind == "cve.new":
        return f"- {c.host_ip} {d.get('port', '')} {d.get('cve')} (CVSS {d.get('cvss')})"
    if c.kind in {"port.open", "port.close", "service.change"}:
        return f"- {c.host_ip} {d.get('port', '')}"
    return f"- {c.host_ip}"


def _worst_severity(items: list[Change]) -> str:
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return max(items, key=lambda c: order.get(c.severity, 2)).severity
