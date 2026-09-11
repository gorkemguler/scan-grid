# Architecture

## Processes

| Process | Entry | Long-running work |
|---|---|---|
| **orchestrator** | `scangrid orchestrator` → `uvicorn scangrid.orchestrator.app:app` | HTTP API + dashboard; APScheduler jobs: `enqueue` (60 s), `enrich` (45 s), `notify` (30 s), `prune` (6 h) |
| **worker** | `scangrid worker` → `scangrid.worker.runner:main` | poll/claim loop; a `ThreadPoolExecutor` running `nmap` |

One package; `SCANGRID_ROLE` + subcommand select the runtime. Only the
orchestrator touches SQLite.

## Job lifecycle

```
Target (spec, interval)
   │  scheduler / POST /api/targets/{id}/scan
   ▼
ScanJob(state=queued, spec_json={hosts:[in-scope only], nmap_args})
   │  POST /api/worker/claim   (conditional UPDATE -> state=claimed, worker_id)
   ▼
worker: assert_hosts_allowed()  ──fail──►  POST result ok=false  ──►  state=error
   │  nmap -oX -  →  parse
   ▼
POST /api/worker/jobs/{id}/result  →  process_result()
   │
   ├─ Scan row (+ snapshot_json)         used as the "previous" for next diff
   ├─ upsert Host / Service (inventory)  ports missing this run → state=closed
   ├─ diff_snapshots(prev, cur)          → Change rows
   └─ mark new/changed services needs_cve=True
   ▼
scheduler `enrich`:  needs_cve services  →  CveProvider (cache)  →  Finding rows + cve.new Change
scheduler `notify`:  un-notified Change rows  →  Notifier (digest per kind)
```

`requeue_stale` returns jobs stuck in `claimed`/`running` past
`job_timeout_seconds + 120` to `queued` (or `error` after `job_max_attempts`).

## Storage model (`scangrid/models.py`)

| Table | Key | Notes |
|---|---|---|
| `target` | `id` (unique `name`) | `spec`, `nmap_args`, `interval_minutes`, `last_queued_at` |
| `scanjob` | `id` | `state`, `spec_json`, `worker_id`, `attempts` |
| `scan` | `id` | one completed run; `snapshot_json` frozen for diffing |
| `host` | `ip` | rolling inventory; `state`, first/last seen |
| `service` | `id` | `(host_ip, port, proto)`; `product`/`version`/`cpe`; `needs_cve` |
| `finding` | `id` | `(service_id, cve_id)`; `cvss`, `severity`, `muted` |
| `change` | `id` | diff event log; `kind`, `severity`, `notified` |
| `cvecache` | `query` | provider results, TTL `cve_cache_days` |

## Diffing (`scangrid/diffing.py`)

Pure functions over `Snapshot = {ip: {"state", "ports": {"p/proto": {...}}}}`.
`diff_snapshots(previous, current)` yields `host.up`, `host.down`, `port.open`,
`port.close`, `service.change`. Sensitive ports (22, 23, 445, 3389, 5900, 3306,
5432, 6379, 9200, 27017) make a `port.open` `high` instead of `medium`.

## CVE subsystem (`scangrid/cve/`)

`get_provider()` → `nvd_api` | `offline` | `none`.

* **cpe.py** - `build_cpe()` upgrades nmap's `cpe:/a:...` to 2.3 form or guesses
  `cpe:2.3:a:*:<product>:<version>:*...`; `query_key()` picks an exact-CPE key
  or a keyword key for the cache.
* **nvd_api.py** - NVD 2.0 REST; self-throttles (~1 req / 6.5 s without a key,
  ~1 / 0.7 s with one); retries on 403/429.
* **offline.py** - indexes NVD JSON feeds by product token; for air-gapped use.

Enrichment (`orchestrator/enrich.py`) is a bounded batch per tick with the
`cvecache` table in front of the provider, so the API is hit at most once per
unique product/version per `cve_cache_days`.

## Why these choices

* **Pull-based workers** - the worker only needs outbound HTTPS to the
  orchestrator; add capacity by starting more workers, no config on the
  orchestrator.
* **Snapshot-per-scan** - diffing needs no historical join; a scan row carries
  everything required to compare with the next one.
* **Allowlist checked three times** - creation, queueing, and on the box that
  runs nmap - because the consequences of scanning the wrong thing are real.
* **SQLite/WAL** - fits a 2 GB Pi; `scan_history_keep` bounds growth.

## Extending

* New scan type → richer `nmap_args` per target, or a new field in `JobSpec`
  + `nmap_runner`.
* New CVE source → implement `CveProvider`, register in `cve/__init__.py`.
* New change kind → add to `diff_snapshots` + a test; add a title in
  `housekeeping._CHANGE_TITLE`.
