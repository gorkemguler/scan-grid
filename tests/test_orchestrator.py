def _mk_target(client, name="home", spec="192.168.5.0/30", **kw):
    body = {"name": name, "spec": spec, "interval_minutes": 0, **kw}
    return client.post("/api/targets", json=body)


def test_healthz_public(client):
    client.headers.pop("Authorization", None)
    r = client.get("/healthz")
    assert r.status_code == 200 and r.json()["role"] == "orchestrator"


def test_target_creation_rejects_out_of_scope(client):
    r = client.post("/api/targets", json={"name": "bad", "spec": "8.8.8.8", "interval_minutes": 0})
    assert r.status_code == 422


def test_worker_claim_requires_token(client):
    client.headers.pop("Authorization", None)
    r = client.post("/api/worker/claim", json={"worker_id": "w1"})
    assert r.status_code == 401


def test_full_scan_roundtrip_and_change_detection(client):
    tid = _mk_target(client).json()["id"]

    assert client.post(f"/api/targets/{tid}/scan").json()["queued"] is True

    claim = client.post("/api/worker/claim", json={"worker_id": "w1"}).json()
    assert claim["job"] is not None
    job_id = claim["job"]["job_id"]
    assert set(claim["job"]["hosts"]) == {"192.168.5.1", "192.168.5.2"}

    result = {
        "job_id": job_id,
        "worker_id": "w1",
        "ok": True,
        "hosts": [
            {
                "ip": "192.168.5.1",
                "hostname": "nas",
                "state": "up",
                "ports": [
                    {
                        "port": 22,
                        "proto": "tcp",
                        "name": "ssh",
                        "product": "OpenSSH",
                        "version": "9.2p1",
                    },
                    {
                        "port": 80,
                        "proto": "tcp",
                        "name": "http",
                        "product": "nginx",
                        "version": "1.22.1",
                    },
                ],
            }
        ],
    }
    ack = client.post(f"/api/worker/jobs/{job_id}/result", json=result).json()
    assert ack["accepted"] and ack["scan_id"] and ack["changes"] == 0  # first scan: no diff

    hosts = client.get("/api/hosts").json()
    assert hosts[0]["ip"] == "192.168.5.1" and hosts[0]["open_ports"] == [22, 80]
    assert client.get("/api/stats").json()["services_open"] == 2

    # second scan: 80 closes, 4444 opens -> change rows
    client.post(f"/api/targets/{tid}/scan")
    job2 = client.post("/api/worker/claim", json={"worker_id": "w1"}).json()["job"]["job_id"]
    result2 = dict(result, job_id=job2)
    result2["hosts"] = [
        {
            "ip": "192.168.5.1",
            "state": "up",
            "ports": [
                {
                    "port": 22,
                    "proto": "tcp",
                    "name": "ssh",
                    "product": "OpenSSH",
                    "version": "9.2p1",
                },
                {"port": 4444, "proto": "tcp", "name": "metasploit", "product": "", "version": ""},
            ],
        }
    ]
    ack2 = client.post(f"/api/worker/jobs/{job2}/result", json=result2).json()
    assert ack2["changes"] >= 2

    kinds = {c["kind"] for c in client.get("/api/changes").json()}
    assert {"port.open", "port.close"} <= kinds


def test_enrichment_creates_findings(client, monkeypatch):
    from scangrid.cve.base import CveProvider, Vulnerability
    from scangrid.orchestrator import enrich

    class FakeProvider(CveProvider):
        name = "fake"

        def lookup(self, product, version, cpe=""):
            if product.lower() == "openssh":
                return [
                    Vulnerability(
                        cve_id="CVE-2024-9999",
                        cvss=9.8,
                        severity="critical",
                        summary="fake RCE",
                        source="fake",
                    )
                ]
            return []

    monkeypatch.setattr(enrich, "get_provider", lambda: FakeProvider())

    tid = _mk_target(client).json()["id"]
    client.post(f"/api/targets/{tid}/scan")
    job_id = client.post("/api/worker/claim", json={"worker_id": "w1"}).json()["job"]["job_id"]
    client.post(
        f"/api/worker/jobs/{job_id}/result",
        json={
            "job_id": job_id,
            "worker_id": "w1",
            "ok": True,
            "hosts": [
                {
                    "ip": "192.168.5.1",
                    "state": "up",
                    "ports": [
                        {
                            "port": 22,
                            "proto": "tcp",
                            "name": "ssh",
                            "product": "OpenSSH",
                            "version": "9.2p1",
                        }
                    ],
                }
            ],
        },
    )

    stats = enrich.enrich_batch(limit=10)
    assert stats["new_findings"] == 1

    findings = client.get("/api/findings").json()
    assert findings and findings[0]["cve_id"] == "CVE-2024-9999"
    assert findings[0]["severity"] == "critical"
