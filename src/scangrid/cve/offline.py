"""Offline provider - matches against NVD JSON feeds on local disk.

Point ``SCANGRID_NVD_FEED_DIR`` at a directory of decompressed NVD feed files
(``nvdcve-1.1-*.json`` or the 2.0 ``nvdcve-2.0-*.json`` format). ``scripts/
fetch-nvd-feeds.sh`` downloads and unpacks them.

Trade-off: the full feed set is a few GB and building the in-memory index costs
~1-2 minutes and a few hundred MB of RAM on a Pi 4. Fine for a nightly batch,
not for interactive use - prefer ``nvd_api`` unless you need to run air-gapped.
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from functools import lru_cache
from pathlib import Path

from ..config import get_settings
from .base import CveProvider, Vulnerability, severity_from_cvss
from .cpe import normalise_token, version_number

log = logging.getLogger("scangrid.cve.offline")


class OfflineNvdProvider(CveProvider):
    name = "offline"

    def lookup(self, product: str, version: str, cpe: str = "") -> list[Vulnerability]:
        idx = _index()
        key = normalise_token(product)
        if not key or key not in idx:
            return []
        want = version_number(version)
        hits = []
        for vuln, versions in idx[key]:
            if not want or not versions or want in versions:
                hits.append(vuln)
        hits.sort(key=lambda v: v.cvss, reverse=True)
        return hits[:50]

    def healthy(self) -> bool:
        d = get_settings().nvd_feed_dir
        return d.exists() and any(d.glob("*.json"))


@lru_cache(maxsize=1)
def _index() -> dict[str, list[tuple[Vulnerability, set[str]]]]:
    d: Path = get_settings().nvd_feed_dir
    index: dict[str, list[tuple[Vulnerability, set[str]]]] = defaultdict(list)
    files = sorted(d.glob("*.json")) if d.exists() else []
    if not files:
        log.warning("offline CVE provider: no feed files in %s", d)
        return index

    for fp in files:
        try:
            raw = json.loads(fp.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            log.error("skipping feed %s: %s", fp.name, exc)
            continue
        items = raw.get("CVE_Items") or raw.get("vulnerabilities") or []
        for it in items:
            vuln, products = _parse_item(it)
            if not vuln:
                continue
            for prod, versions in products.items():
                index[prod].append((vuln, versions))
    log.info("offline CVE index: %d products from %d feed file(s)", len(index), len(files))
    return index


def _parse_item(it: dict) -> tuple[Vulnerability | None, dict[str, set[str]]]:
    # Support both feed schemas loosely.
    cve = it.get("cve", it)
    cve_id = cve.get("id") or cve.get("CVE_data_meta", {}).get("ID") or ""
    if not cve_id:
        return None, {}

    summary = ""
    descs = cve.get("descriptions") or cve.get("description", {}).get("description_data", [])
    for d in descs:
        if d.get("lang") in {"en", "eng"}:
            summary = d.get("value", "")
            break

    score = 0.0
    impact = it.get("impact", {})
    metrics = cve.get("metrics", {})
    if metrics:
        for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(k):
                score = float(metrics[k][0].get("cvssData", {}).get("baseScore", 0.0) or 0.0)
                break
    elif impact:
        score = float(
            impact.get("baseMetricV3", {}).get("cvssV3", {}).get("baseScore")
            or impact.get("baseMetricV2", {}).get("cvssV2", {}).get("baseScore")
            or 0.0
        )

    products: dict[str, set[str]] = defaultdict(set)
    nodes = (
        it.get("configurations", {}).get("nodes")
        if isinstance(it.get("configurations"), dict)
        else it.get("configurations")
    ) or cve.get("configurations", [])
    for node in _walk_nodes(nodes):
        for match in node.get("cpeMatch", node.get("cpe_match", [])):
            uri = match.get("criteria") or match.get("cpe23Uri") or ""
            parts = uri.split(":")
            if len(parts) > 5 and parts[2] == "a":
                products[parts[4]].add(parts[5] if parts[5] not in {"*", "-"} else "")
    products.pop("", None)

    vuln = Vulnerability(
        cve_id=cve_id,
        cvss=score,
        severity=severity_from_cvss(score),
        summary=summary[:600],
        published=(cve.get("published") or it.get("publishedDate") or "")[:10],
        source="nvd-offline",
    )
    return vuln, {k: {v for v in vs if v} for k, vs in products.items()}


def _walk_nodes(nodes) -> list[dict]:
    out: list[dict] = []
    for n in nodes or []:
        out.append(n)
        out.extend(_walk_nodes(n.get("children", [])))
    return out
