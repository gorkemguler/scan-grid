"""NVD 2.0 REST API provider.

Docs: https://nvd.nist.gov/developers/vulnerabilities

Rate limits (enforced here with a simple sleep): ~5 requests / 30 s without an
API key, ~50 / 30 s with one. Results are cached one level up in the
``cvecache`` table, so on a Pi the API is hit at most once per unique
product/version per ``cve_cache_days``.
"""

from __future__ import annotations

import logging
import threading
import time

import httpx

from ..config import get_settings
from .base import CveProvider, Vulnerability, severity_from_cvss
from .cpe import build_cpe, has_concrete_version, normalise_token, version_number

log = logging.getLogger("scangrid.cve.nvd")

_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NvdApiProvider(CveProvider):
    name = "nvd_api"

    def __init__(self) -> None:
        s = get_settings()
        self._key = s.nvd_api_key
        self._min_interval = 0.7 if self._key else 6.5
        self._lock = threading.Lock()
        self._last = 0.0
        headers = {"apiKey": self._key} if self._key else {}
        self._client = httpx.Client(timeout=30, headers=headers)

    def _throttle(self) -> None:
        with self._lock:
            wait = self._min_interval - (time.monotonic() - self._last)
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()

    def _get(self, params: dict) -> dict:
        self._throttle()
        for attempt in range(3):
            try:
                r = self._client.get(_ENDPOINT, params=params)
                if r.status_code == 403 or r.status_code == 429:
                    time.sleep(6 * (attempt + 1))
                    continue
                r.raise_for_status()
                return r.json()
            except httpx.HTTPError as exc:  # pragma: no cover - network dependent
                log.warning("NVD request failed (%s/3): %s", attempt + 1, exc)
                time.sleep(3 * (attempt + 1))
        return {}

    def lookup(self, product: str, version: str, cpe: str = "") -> list[Vulnerability]:
        product = (product or "").strip()
        if not product:
            return []
        built = build_cpe(product, version, cpe)
        if built and has_concrete_version(built):
            data = self._get({"cpeName": built, "resultsPerPage": 50})
        else:
            kw = " ".join(x for x in (normalise_token(product), version_number(version)) if x)
            data = self._get({"keywordSearch": kw, "resultsPerPage": 30})
        return _parse(data)

    def healthy(self) -> bool:  # pragma: no cover - network dependent
        try:
            r = self._client.get(_ENDPOINT, params={"resultsPerPage": 1})
            return r.is_success
        except httpx.HTTPError:
            return False


def _parse(data: dict) -> list[Vulnerability]:
    out: list[Vulnerability] = []
    for item in data.get("vulnerabilities", []):
        c = item.get("cve", {})
        cve_id = c.get("id", "")
        if not cve_id:
            continue
        desc = ""
        for d in c.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        score, sev = _best_score(c.get("metrics", {}))
        out.append(
            Vulnerability(
                cve_id=cve_id,
                cvss=score,
                severity=sev or severity_from_cvss(score),
                summary=desc[:600],
                published=c.get("published", "")[:10],
                source="nvd",
            )
        )
    out.sort(key=lambda v: v.cvss, reverse=True)
    return out


def _best_score(metrics: dict) -> tuple[float, str]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        cvss = entries[0].get("cvssData", {})
        score = float(cvss.get("baseScore", 0.0) or 0.0)
        sev = (entries[0].get("baseSeverity") or cvss.get("baseSeverity") or "").lower()
        return score, sev
    return 0.0, ""
