"""ScanGrid - distributed, authorised vulnerability scanner + asset inventory.

Two runtimes over an authenticated HTTP API:

* ``scangrid.orchestrator`` - job queue, asset DB, CVE matching, change
  detection, REST API and dashboard.
* ``scangrid.worker``       - claims scan jobs, runs ``nmap``, returns results.

Every host that gets scanned must fall inside the operator-configured
allowlist (``SCANGRID_ALLOWLIST``). This is enforced when a job is created
*and* again on the worker immediately before nmap runs.
"""

from __future__ import annotations

__version__ = "0.1.0"
__all__ = ["__version__"]
