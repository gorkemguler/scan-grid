"""Run nmap and parse its XML into :class:`HostResult` objects.

Uses ``-oX -`` and the stdlib XML parser - no third-party nmap binding, so the
package imports fine on a machine without nmap installed (only the worker needs
the binary).
"""

from __future__ import annotations

import logging
import shlex
import subprocess
import xml.etree.ElementTree as ET
from datetime import UTC, datetime

from .config import get_settings
from .schemas import HostResult, JobResult, PortResult

log = logging.getLogger("scangrid.nmap")

# nmap flags we refuse to run: this is a detection tool, not an exploitation one.
_FORBIDDEN = {"--script-args-file"}
_FORBIDDEN_SCRIPT_CATEGORIES = {"exploit", "brute", "dos", "malware"}


def sanitise_args(args: str) -> list[str]:
    """Split args and strip anything that would turn a scan into an attack."""
    parts = shlex.split(args)
    out: list[str] = []
    skip_next = False
    for i, p in enumerate(parts):
        if skip_next:
            skip_next = False
            continue
        if p in _FORBIDDEN:
            skip_next = True
            continue
        if p == "--script" and i + 1 < len(parts):
            cats = {c.strip().lower() for c in parts[i + 1].replace(" ", "").split(",")}
            if cats & _FORBIDDEN_SCRIPT_CATEGORIES:
                log.warning("dropping --script %s (forbidden category)", parts[i + 1])
                skip_next = True
                continue
        # never let the caller redirect output away from stdout
        if p in {"-oN", "-oX", "-oG", "-oA", "-oS"}:
            skip_next = True
            continue
        out.append(p)
    return out


def run(hosts: list[str], nmap_args: str, job_id: int, worker_id: str) -> JobResult:
    settings = get_settings()
    started = datetime.now(UTC)
    cmd = [settings.nmap_path, *sanitise_args(nmap_args), "-oX", "-", *hosts]
    log.info("job %s: %s", job_id, " ".join(cmd))
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=settings.job_timeout_seconds,
            check=False,
        )
    except FileNotFoundError:
        return JobResult(job_id=job_id, worker_id=worker_id, ok=False, error="nmap not found")
    except subprocess.TimeoutExpired:
        return JobResult(job_id=job_id, worker_id=worker_id, ok=False, error="nmap timed out")

    if not proc.stdout.strip():
        return JobResult(
            job_id=job_id,
            worker_id=worker_id,
            ok=False,
            error=f"nmap produced no XML: {proc.stderr.strip()[:300]}",
        )

    hosts_out = parse_nmap_xml(proc.stdout)
    return JobResult(
        job_id=job_id,
        worker_id=worker_id,
        ok=True,
        started_at=started,
        finished_at=datetime.now(UTC),
        hosts=hosts_out,
        raw_nmap_args=" ".join(sanitise_args(nmap_args)),
    )


def parse_nmap_xml(xml_text: str) -> list[HostResult]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        log.error("nmap XML parse error: %s", exc)
        return []

    results: list[HostResult] = []
    for host in root.findall("host"):
        state_el = host.find("status")
        state = state_el.get("state", "unknown") if state_el is not None else "unknown"
        # Only carry hosts that are actually up; the orchestrator infers
        # "host.down" from a host disappearing between scans.
        if state != "up":
            continue

        ip = mac = vendor = hostname = os_guess = ""
        for addr in host.findall("address"):
            t = addr.get("addrtype")
            if t in {"ipv4", "ipv6"}:
                ip = addr.get("addr", "")
            elif t == "mac":
                mac = (addr.get("addr", "") or "").lower()
                vendor = addr.get("vendor", "") or ""
        hn = host.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name", "")
        osm = host.find("os/osmatch")
        if osm is not None:
            os_guess = f"{osm.get('name', '')} ({osm.get('accuracy', '?')}%)"

        if not ip:
            continue

        ports: list[PortResult] = []
        for port in host.findall("ports/port"):
            pst = port.find("state")
            if pst is None or pst.get("state") != "open":
                continue
            svc = port.find("service")
            cpe = ""
            name = product = version = extrainfo = ""
            if svc is not None:
                name = svc.get("name", "")
                product = svc.get("product", "")
                version = svc.get("version", "")
                extrainfo = svc.get("extrainfo", "")
                cpe_el = svc.find("cpe")
                if cpe_el is not None and cpe_el.text:
                    cpe = cpe_el.text.strip()
            ports.append(
                PortResult(
                    port=int(port.get("portid", "0")),
                    proto=port.get("protocol", "tcp"),
                    state="open",
                    name=name,
                    product=product,
                    version=version,
                    extrainfo=extrainfo,
                    cpe=cpe,
                )
            )

        results.append(
            HostResult(
                ip=ip,
                hostname=hostname,
                mac=mac,
                vendor=vendor,
                os_guess=os_guess,
                state=state,
                ports=sorted(ports, key=lambda p: (p.proto, p.port)),
            )
        )
    return results
