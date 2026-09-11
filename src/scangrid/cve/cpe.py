"""Best-effort CPE construction from nmap service banners.

nmap sometimes emits a real ``<cpe>`` element - prefer that. When it doesn't we
build a loose ``cpe:2.3:a:*:<product>:<version>:*...`` guess that is still useful
as an NVD keyword / partial match.
"""

from __future__ import annotations

import re

_CLEAN = re.compile(r"[^a-z0-9._\-]+")


def normalise_token(value: str) -> str:
    value = value.strip().lower().replace(" ", "_")
    return _CLEAN.sub("", value)


def version_number(version: str) -> str:
    """Pull a dotted version out of a messy nmap version string."""
    m = re.search(r"\d+(?:\.\d+){0,3}[a-z]?\d*", version or "")
    return m.group(0) if m else ""


def build_cpe(product: str, version: str, nmap_cpe: str = "") -> str:
    if nmap_cpe:
        # nmap gives cpe:/a:openbsd:openssh:9.2p1 - upgrade to 2.3 form.
        c = nmap_cpe.strip()
        if c.startswith("cpe:/"):
            body = c[5:]
            parts = body.split(":")
            kind = parts[0] if parts else "a"
            # 10 trailing fields after <part>: vendor product version update
            # edition language sw_edition target_sw target_hw other.
            fields = (parts[1:] + ["*"] * 10)[:10]
            return "cpe:2.3:" + kind + ":" + ":".join(f or "*" for f in fields)
        return c
    p = normalise_token(product)
    if not p:
        return ""
    v = version_number(version) or "*"
    return f"cpe:2.3:a:*:{p}:{v}:*:*:*:*:*:*:*"


def has_concrete_version(cpe: str) -> bool:
    """True when the CPE's version field is a real value, not '*' / '-'."""
    parts = cpe.split(":")
    return len(parts) > 5 and parts[5] not in {"", "*", "-"}


def query_key(product: str, version: str, nmap_cpe: str = "") -> str:
    """Stable cache key for a (product, version) lookup.

    A CPE with a concrete version keys by that CPE; otherwise we fall back to a
    keyword key so the NVD keyword search is used instead of an exact match.
    """
    cpe = build_cpe(product, version, nmap_cpe)
    if cpe and has_concrete_version(cpe):
        return cpe
    return f"kw:{normalise_token(product)}|{version_number(version)}".rstrip("|")
