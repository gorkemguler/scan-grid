from scangrid.diffing import diff_snapshots, snapshot_from_hosts
from scangrid.schemas import HostResult, PortResult


def _host(ip, ports, state="up"):
    return HostResult(
        ip=ip,
        state=state,
        ports=[PortResult(port=p, name=n, product=pr, version=v) for p, n, pr, v in ports],
    )


def test_snapshot_shape():
    snap = snapshot_from_hosts([_host("192.168.1.1", [(22, "ssh", "OpenSSH", "9.2")])])
    assert snap["192.168.1.1"]["state"] == "up"
    assert "22/tcp" in snap["192.168.1.1"]["ports"]


def test_new_host_and_new_port():
    prev = snapshot_from_hosts([_host("192.168.1.1", [(22, "ssh", "OpenSSH", "9.2")])])
    cur = snapshot_from_hosts(
        [
            _host("192.168.1.1", [(22, "ssh", "OpenSSH", "9.2"), (445, "microsoft-ds", "", "")]),
            _host("192.168.1.2", [(80, "http", "nginx", "1.22")]),
        ]
    )
    kinds = {(c["kind"], c["host_ip"]) for c in diff_snapshots(prev, cur)}
    assert ("port.open", "192.168.1.1") in kinds
    assert ("host.up", "192.168.1.2") in kinds
    # 445 is a sensitive port -> high severity
    opened = next(c for c in diff_snapshots(prev, cur) if c["kind"] == "port.open")
    assert opened["severity"] == "high"


def test_closed_port_and_service_change_and_host_down():
    prev = snapshot_from_hosts(
        [
            _host(
                "192.168.1.1",
                [
                    (22, "ssh", "OpenSSH", "9.2"),
                    (8080, "http", "nginx", "1.20"),
                    (139, "netbios", "", ""),
                ],
            ),
            _host("192.168.1.9", [(53, "domain", "dnsmasq", "2.89")]),
        ]
    )
    cur = snapshot_from_hosts(
        [_host("192.168.1.1", [(22, "ssh", "OpenSSH", "9.2"), (8080, "http", "nginx", "1.24")])]
    )
    kinds = {c["kind"] for c in diff_snapshots(prev, cur)}
    assert "port.close" in kinds  # 139 disappeared
    assert "service.change" in kinds  # nginx 1.20 -> 1.24 on 8080
    assert "host.down" in kinds  # 192.168.1.9 gone


def test_no_changes_when_identical():
    snap = snapshot_from_hosts([_host("10.0.0.1", [(22, "ssh", "OpenSSH", "9.2")])])
    assert diff_snapshots(snap, snap) == []
