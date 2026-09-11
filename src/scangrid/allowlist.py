"""Target authorisation - the safety rail of the whole project.

``SCANGRID_ALLOWLIST`` is a set of CIDRs / IPs / ranges the operator has
declared they are authorised to scan. Everything else is refused:

* when a job is created on the orchestrator, and
* again on the worker, right before nmap is executed.

Public (non-RFC1918) targets are rejected unless
``SCANGRID_ALLOW_PUBLIC_TARGETS=true`` is set explicitly.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from functools import lru_cache

from .config import get_settings

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

_RANGE_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3})$")
# Cap how many hosts a single spec token may expand to, to avoid a typo like
# "10.0.0.0/8" turning into 16M nmap targets.
MAX_EXPANSION = 8192


class AllowlistError(ValueError):
    """Raised when a spec cannot be authorised."""


@dataclass
class Resolution:
    allowed: list[str] = field(default_factory=list)
    rejected: list[tuple[str, str]] = field(default_factory=list)  # (token/ip, reason)

    @property
    def ok(self) -> bool:
        return bool(self.allowed) and not self.rejected


@lru_cache(maxsize=1)
def _allow_networks() -> list[IPNetwork]:
    raw = get_settings().allowlist
    nets: list[IPNetwork] = []
    for tok in re.split(r"[\s,]+", raw.strip()):
        if not tok:
            continue
        try:
            nets.append(ipaddress.ip_network(tok, strict=False))
        except ValueError as exc:
            raise AllowlistError(f"bad allowlist entry {tok!r}: {exc}") from exc
    if not nets:
        raise AllowlistError("SCANGRID_ALLOWLIST is empty - refusing to scan anything")
    return nets


def reload_cache() -> None:
    _allow_networks.cache_clear()


def _is_private(ip: IPAddress) -> bool:
    return ip.is_private and not ip.is_loopback and not ip.is_link_local


def is_allowed(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    # Loopback (scanning yourself) is always fine to *consider*; it still has to
    # be listed in the allowlist. Other non-RFC1918 space needs the opt-in.
    if not get_settings().allow_public_targets and not _is_private(ip) and not ip.is_loopback:
        return False
    return any(ip in net for net in _allow_networks())


def _expand_token(tok: str) -> list[str]:
    """Turn one spec token into a list of concrete IP strings."""
    m = _RANGE_RE.match(tok)
    if m:
        base, last = m.group(1), int(m.group(2))
        first = int(base.rsplit(".", 1)[1])
        if not (0 <= first <= 255 and first <= last <= 255):
            raise AllowlistError(f"bad range {tok!r}")
        prefix = base.rsplit(".", 1)[0]
        return [f"{prefix}.{i}" for i in range(first, last + 1)]

    try:
        net = ipaddress.ip_network(tok, strict=False)
    except ValueError:
        net = None
    if net is not None:
        if net.num_addresses > MAX_EXPANSION:
            raise AllowlistError(
                f"{tok!r} expands to {net.num_addresses} hosts (limit {MAX_EXPANSION})"
            )
        if net.num_addresses == 1:
            return [str(net.network_address)]
        return [str(h) for h in net.hosts()]

    # Treat as a hostname: resolve now so the allowlist check is on the IP.
    try:
        infos = socket.getaddrinfo(tok, None)
    except OSError as exc:
        raise AllowlistError(f"cannot resolve {tok!r}: {exc}") from exc
    return sorted({info[4][0] for info in infos})


def resolve_spec(spec: str) -> Resolution:
    """Expand a target spec and split it into authorised / refused IPs."""
    res = Resolution()
    seen: set[str] = set()
    for tok in re.split(r"[\s,]+", spec.strip()):
        if not tok:
            continue
        try:
            ips = _expand_token(tok)
        except AllowlistError as exc:
            res.rejected.append((tok, str(exc)))
            continue
        for ip in ips:
            if ip in seen:
                continue
            seen.add(ip)
            if is_allowed(ip):
                res.allowed.append(ip)
            else:
                res.rejected.append((ip, "outside SCANGRID_ALLOWLIST"))
    return res


def assert_hosts_allowed(hosts: list[str]) -> None:
    """Worker-side gate: raise if *any* host is not authorised."""
    bad = [h for h in hosts if not is_allowed(h)]
    if bad:
        raise AllowlistError(f"refusing to scan unauthorised hosts: {bad[:10]}")
