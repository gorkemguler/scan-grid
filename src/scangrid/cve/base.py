"""Provider interface + shared value types."""

from __future__ import annotations

import abc

from pydantic import BaseModel


class Vulnerability(BaseModel):
    cve_id: str
    cvss: float = 0.0
    severity: str = "unknown"  # low | medium | high | critical | unknown
    summary: str = ""
    published: str = ""
    cpe: str = ""
    source: str = ""


def severity_from_cvss(score: float) -> str:
    if score <= 0:
        return "unknown"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


class CveProvider(abc.ABC):
    name = "base"

    @abc.abstractmethod
    def lookup(self, product: str, version: str, cpe: str = "") -> list[Vulnerability]:
        """Return known vulnerabilities for a product/version (or a full CPE)."""

    def healthy(self) -> bool:  # pragma: no cover - overridden where meaningful
        return True


class NullProvider(CveProvider):
    name = "none"

    def lookup(self, product: str, version: str, cpe: str = "") -> list[Vulnerability]:
        return []
