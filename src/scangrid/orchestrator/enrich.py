"""CVE enrichment pass.

Runs on a scheduler tick: takes a bounded batch of services flagged
``needs_cve``, asks the configured provider (with a DB cache in front of it),
writes :class:`Finding` rows and a ``cve.new`` :class:`Change` for anything new.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta

from sqlmodel import Session, select

from ..config import get_settings
from ..cve import Vulnerability, get_provider
from ..cve.cpe import query_key
from ..db import session_scope
from ..models import Change, CveCache, Finding, Service

log = logging.getLogger("scangrid.enrich")


def enrich_batch(limit: int = 15) -> dict[str, int]:
    settings = get_settings()
    provider = get_provider()
    processed = findings_new = 0

    with session_scope() as session:
        services = session.exec(
            select(Service)
            .where(Service.needs_cve == True, Service.product != "")  # noqa: E712
            .limit(limit)
        ).all()

        for svc in services:
            vulns = _lookup_cached(session, provider, svc, settings.cve_cache_days)
            findings_new += _write_findings(session, svc, vulns, settings.cve_min_cvss)
            svc.needs_cve = False
            session.add(svc)
            processed += 1

    if processed:
        log.info("CVE enrichment: %d service(s), %d new finding(s)", processed, findings_new)
    return {"services": processed, "new_findings": findings_new}


def _lookup_cached(
    session: Session, provider, svc: Service, cache_days: int
) -> list[Vulnerability]:
    key = query_key(svc.product, svc.version, svc.cpe)
    cached = session.get(CveCache, key)
    fresh = cached and datetime.now(UTC) - cached.checked_at.replace(tzinfo=UTC) < timedelta(
        days=cache_days
    )
    if fresh:
        return [Vulnerability(**v) for v in json.loads(cached.result_json)]

    try:
        vulns = provider.lookup(svc.product, svc.version, svc.cpe)
    except Exception as exc:  # pragma: no cover - provider/network dependent
        log.warning("provider lookup failed for %s: %s", key, exc)
        return []

    row = cached or CveCache(query=key)
    row.result_json = json.dumps([v.model_dump() for v in vulns])
    row.checked_at = datetime.now(UTC)
    session.add(row)
    return vulns


def _write_findings(
    session: Session, svc: Service, vulns: list[Vulnerability], min_cvss: float
) -> int:
    new = 0
    for v in vulns:
        if v.cvss < min_cvss:
            continue
        exists = session.exec(
            select(Finding).where(Finding.service_id == svc.id, Finding.cve_id == v.cve_id)
        ).first()
        if exists:
            continue
        session.add(
            Finding(
                host_ip=svc.host_ip,
                service_id=svc.id,
                cve_id=v.cve_id,
                cvss=v.cvss,
                severity=v.severity,
                summary=v.summary,
                cpe=svc.cpe or v.cpe,
                source=v.source,
                published=v.published,
            )
        )
        session.add(
            Change(
                target_id=0,
                host_ip=svc.host_ip,
                kind="cve.new",
                severity=v.severity if v.severity in {"high", "critical"} else "medium",
                detail_json=json.dumps(
                    {
                        "cve": v.cve_id,
                        "cvss": v.cvss,
                        "port": f"{svc.port}/{svc.proto}",
                        "product": f"{svc.product} {svc.version}".strip(),
                        "summary": v.summary[:280],
                    }
                ),
            )
        )
        new += 1
    return new
