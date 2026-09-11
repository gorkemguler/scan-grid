from datetime import UTC, datetime, timedelta

from scangrid.models import Change, Scan, Target
from scangrid.orchestrator.housekeeping import (
    enqueue_due_targets,
    notify_pending_changes,
    prune_history,
)


def test_prune_history_keeps_recent_scans(session, monkeypatch):
    from scangrid import config

    monkeypatch.setattr(config.get_settings(), "scan_history_keep", 3, raising=False)

    t = Target(name="t1", spec="10.0.0.0/30", interval_minutes=0)
    session.add(t)
    session.flush()
    base = datetime(2026, 1, 1, tzinfo=UTC)
    for i in range(10):
        session.add(Scan(target_id=t.id, started_at=base + timedelta(hours=i)))
    session.commit()

    result = prune_history()
    assert result["scans"] == 7
    remaining = session.exec(_all(Scan)).all()
    assert len(remaining) == 3


def test_notify_pending_marks_notified(session):
    session.add(Change(target_id=0, host_ip="10.0.0.5", kind="port.open", severity="high"))
    session.add(Change(target_id=0, host_ip="10.0.0.6", kind="port.open", severity="medium"))
    session.commit()

    sent = notify_pending_changes()
    assert sent == 2
    left = session.exec(_all(Change)).all()
    assert all(c.notified for c in left)


def test_enqueue_due_targets_creates_jobs(session):
    session.add(Target(name="due", spec="10.0.0.0/30", interval_minutes=60))
    session.add(Target(name="manual", spec="10.0.0.0/30", interval_minutes=0))
    session.commit()

    made = enqueue_due_targets()
    assert made == 1  # only the scheduled one


def _all(model):
    from sqlmodel import select

    return select(model)
