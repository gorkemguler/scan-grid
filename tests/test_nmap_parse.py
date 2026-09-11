from pathlib import Path

from scangrid.nmap_runner import parse_nmap_xml, sanitise_args

FIXTURE = (Path(__file__).parent / "fixtures" / "nmap-sv.xml").read_text()


def test_parse_hosts_ports_services():
    hosts = parse_nmap_xml(FIXTURE)
    assert len(hosts) == 1  # the "down" host is dropped
    h = hosts[0]
    assert h.ip == "192.168.1.10"
    assert h.mac == "b8:27:eb:11:22:33"
    assert h.vendor == "Raspberry Pi Foundation"
    assert h.hostname == "octopi.lan"
    assert h.os_guess.startswith("Linux 5.x")
    assert [p.port for p in h.ports] == [22, 443]  # 8888 closed -> excluded
    ssh = h.ports[0]
    assert ssh.product == "OpenSSH" and ssh.cpe == "cpe:/a:openbsd:openssh:9.2p1"


def test_parse_garbage_is_safe():
    assert parse_nmap_xml("<not-nmap/>") == []
    assert parse_nmap_xml("garbage") == []


def test_sanitise_args_drops_dangerous_flags():
    out = sanitise_args("-sV --script exploit,vuln -oN out.txt -T4")
    assert "--script" not in out  # forbidden category present -> dropped
    assert "-oN" not in out and "out.txt" not in out
    assert "-sV" in out and "-T4" in out


def test_sanitise_args_keeps_safe_scripts():
    out = sanitise_args("-sV --script default,banner")
    assert out == ["-sV", "--script", "default,banner"]
