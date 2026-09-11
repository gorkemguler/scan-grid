# HTTP API

Base URL `http://<orchestrator>:8090`. Swagger `/docs`, ReDoc `/redoc`.

Auth: every `/api/*` route needs `Authorization: Bearer <SCANGRID_API_TOKEN>`.
`/healthz` is open. Dashboard routes use optional HTTP-basic.

## Meta

`GET /healthz` → `{"status":"ok","version":"0.1.0","role":"orchestrator","detail":{"jobs_queued":0}}`

`GET /api/stats`
```json
{
  "targets": 2, "hosts": 30, "hosts_up": 24, "services_open": 71,
  "jobs_queued": 0, "jobs_running": 1,
  "findings_by_severity": {"critical": 1, "high": 4, "medium": 12},
  "changes_24h": 6, "generated_at": "2026-09-09T12:00:00+00:00"
}
```

## Targets

| Method | Path | Body / query |
|---|---|---|
| `GET` | `/api/targets` | - |
| `POST` | `/api/targets` | `{name, spec, nmap_args?, interval_minutes?, enabled?}` → `201` |
| `GET` | `/api/targets/{id}` | - |
| `PATCH` | `/api/targets/{id}` | same body as POST |
| `DELETE` | `/api/targets/{id}` | → `204` |
| `POST` | `/api/targets/{id}/scan` | queue now → `{"queued": true, "job_id": 5}` |
| `GET` | `/api/targets/{id}/preview` | `{"in_scope": [...], "rejected": [["8.8.8.8","outside ..."]]}` |

`spec` accepts CIDRs, single IPs, and `a.b.c.d-e` ranges, space/comma separated.
`POST` returns `422` if nothing in the spec is inside `SCANGRID_ALLOWLIST`.

## Inventory & findings

| Method | Path | Query |
|---|---|---|
| `GET` | `/api/hosts` | `active_days` |
| `GET` | `/api/hosts/{ip}` | full detail: host + services + findings |
| `GET` | `/api/findings` | `min_cvss`, `severity`, `include_muted`, `limit` |
| `POST` | `/api/findings/{id}/mute` | `?muted=true|false` |
| `GET` | `/api/changes` | `kind`, `since_hours`, `limit` |
| `GET` | `/api/scans` | `target_id`, `limit` |
| `GET` | `/api/jobs` | `state`, `limit` |

`change.kind` ∈ `host.up`, `host.down`, `port.open`, `port.close`,
`service.change`, `cve.new`.

## Worker protocol

| Method | Path | Body |
|---|---|---|
| `POST` | `/api/worker/claim` | `{"worker_id": "w1"}` → `{"job": {job_id, target_id, target_name, hosts, nmap_args}}` or `{"job": null}` |
| `POST` | `/api/worker/jobs/{id}/running` | - (progress ping) |
| `POST` | `/api/worker/jobs/{id}/result` | `JobResult` (see below) |

`JobResult`:
```json
{
  "job_id": 5, "worker_id": "w1", "ok": true,
  "started_at": "...", "finished_at": "...",
  "hosts": [
    { "ip": "192.168.1.10", "hostname": "nas", "mac": "...", "state": "up",
      "ports": [
        { "port": 22, "proto": "tcp", "name": "ssh", "product": "OpenSSH",
          "version": "9.2p1", "cpe": "cpe:/a:openbsd:openssh:9.2p1" }
      ] }
  ]
}
```
Response `IngestAck`: `{accepted, scan_id, hosts_upserted, services_upserted, changes, cve_enrich_queued}`.

## Errors

FastAPI shape `{"detail": ...}` - `401` bad token, `404` unknown id, `409`
duplicate target name, `422` validation / out-of-scope spec.
