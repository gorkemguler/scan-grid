"""Change detection between two scans of the same target.

Pure functions over lightweight dict "snapshots" so the logic is trivially
unit-testable. The orchestrator builds snapshots from :class:`HostResult`
payloads and from the stored inventory.
"""

from __future__ import annotations

from typing import Any

# A snapshot is:  { ip: {"state": "up"/"down",
#                        "ports": { "80/tcp": {"name":..,"product":..,"version":..} } } }
Snapshot = dict[str, dict[str, Any]]


def _get(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def snapshot_from_hosts(hosts: list[Any]) -> Snapshot:
    """Build a snapshot from a list of schemas.HostResult (or plain dicts)."""
    snap: Snapshot = {}
    for h in hosts:
        ip = str(_get(h, "ip"))
        state = _get(h, "state", "up") or "up"
        ports: dict[str, dict[str, str]] = {}
        for p in _get(h, "ports", []) or []:
            key = f"{_get(p, 'port')}/{_get(p, 'proto', 'tcp') or 'tcp'}"
            ports[key] = {
                "name": _get(p, "name", "") or "",
                "product": _get(p, "product", "") or "",
                "version": _get(p, "version", "") or "",
            }
        snap[ip] = {"state": "up" if state == "up" else state, "ports": ports}
    return snap


def _sev_for_port(port_key: str) -> str:
    sensitive = {"22", "23", "445", "3389", "5900", "3306", "5432", "6379", "9200", "27017"}
    return "high" if port_key.split("/")[0] in sensitive else "medium"


def diff_snapshots(previous: Snapshot, current: Snapshot) -> list[dict]:
    """Return a list of change dicts: {kind, host_ip, severity, detail}."""
    changes: list[dict] = []

    for ip, cur in current.items():
        prev = previous.get(ip)
        if prev is None:
            if cur["state"] == "up":
                changes.append(
                    {
                        "kind": "host.up",
                        "host_ip": ip,
                        "severity": "medium",
                        "detail": {"new": True, "ports": sorted(cur["ports"])},
                    }
                )
            continue
        if prev["state"] != "up" and cur["state"] == "up":
            changes.append({"kind": "host.up", "host_ip": ip, "severity": "medium", "detail": {}})

        prev_ports, cur_ports = prev["ports"], cur["ports"]
        for pk in cur_ports.keys() - prev_ports.keys():
            changes.append(
                {
                    "kind": "port.open",
                    "host_ip": ip,
                    "severity": _sev_for_port(pk),
                    "detail": {"port": pk, "service": cur_ports[pk]},
                }
            )
        for pk in prev_ports.keys() - cur_ports.keys():
            changes.append(
                {"kind": "port.close", "host_ip": ip, "severity": "low", "detail": {"port": pk}}
            )
        for pk in cur_ports.keys() & prev_ports.keys():
            a, b = prev_ports[pk], cur_ports[pk]
            if (a.get("product"), a.get("version")) != (b.get("product"), b.get("version")):
                changes.append(
                    {
                        "kind": "service.change",
                        "host_ip": ip,
                        "severity": "low",
                        "detail": {"port": pk, "from": a, "to": b},
                    }
                )

    for ip, prev in previous.items():
        cur = current.get(ip)
        if prev["state"] == "up" and (cur is None or cur["state"] != "up"):
            changes.append({"kind": "host.down", "host_ip": ip, "severity": "low", "detail": {}})

    return changes
