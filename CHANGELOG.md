# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning aims to follow [SemVer](https://semver.org/).

## [Unreleased]

### Docs
- README: new **Hardware & requirements** (board matrix, per-role RAM, SD sizing,
  OS/software) and **Deployment topologies** (two Pis / one Pi / many workers)
  sections; CVE-data notes tightened.
- `docs/SETUP.md`: requirements checklist + a single-Pi (orchestrator + worker)
  walkthrough.
- Ansible: `inventory.example.ini` shows the one-Pi and many-workers variants.
- README laptop quickstart now sets `SCANGRID_ALLOWLIST=127.0.0.1/32` so the
  localhost demo target is accepted.

## [0.1.0] - 2026-09-09

### Added
- Orchestrator: job queue (SQLite/WAL), REST API, Jinja2 dashboard, APScheduler
  housekeeping (enqueue due targets, requeue stale jobs, CVE enrichment,
  notify, prune).
- Worker: claim → allowlist re-check → `nmap -sV` → XML parse → submit; N
  workers supported; per-worker concurrency.
- Allowlist enforcement (`SCANGRID_ALLOWLIST`) at target creation, job creation
  and on the worker before nmap; public targets opt-in only; nmap arg
  sanitisation (drops `exploit`/`brute`/`dos`/`malware` scripts + output redirs).
- Asset inventory: hosts + services with first/last-seen; per-scan snapshots.
- Change detection: `host.up/down`, `port.open/close`, `service.change`,
  `cve.new`; sensitive ports raise severity.
- CVE matching: `nvd_api` (live, throttled, DB-cached), `offline` (NVD feeds),
  `none`. Banner → CPE heuristic.
- Notifications with a severity floor: `log`, `ntfy`, `telegram`, `webhook`.
- Deploy: systemd units, per-Pi install scripts, Ansible playbook,
  `docker compose` demo (worker scans `127.0.0.1`).
- Tests: 24 passing (allowlist, nmap parse + arg sanitiser, CPE, diffing,
  full worker↔orchestrator round trip, enrichment). Ruff clean.
- CI: ruff + pytest on 3.11 / 3.12, multi-arch docker build.

[Unreleased]: https://github.com/gorkemguler/scan-grid/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/gorkemguler/scan-grid/releases/tag/v0.1.0
