from scangrid.cve.base import severity_from_cvss
from scangrid.cve.cpe import build_cpe, has_concrete_version, query_key, version_number


def test_version_number_extraction():
    assert version_number("9.2p1 Debian 2+deb12u2") == "9.2p1"
    assert version_number("1.22.1") == "1.22.1"
    assert version_number("Apache/2.4.57 (Debian)") == "2.4.57"
    assert version_number("unknown") == ""


def test_build_cpe_from_nmap_cpe_upgrades_to_2_3():
    cpe = build_cpe("OpenSSH", "9.2p1", "cpe:/a:openbsd:openssh:9.2p1")
    assert cpe.startswith("cpe:2.3:a:openbsd:openssh:9.2p1:")
    assert has_concrete_version(cpe)


def test_build_cpe_guess_when_no_nmap_cpe():
    cpe = build_cpe("nginx", "1.22.1")
    assert cpe == "cpe:2.3:a:*:nginx:1.22.1:*:*:*:*:*:*:*"


def test_query_key_prefers_cpe_then_keyword():
    assert query_key("OpenSSH", "9.2p1", "cpe:/a:openbsd:openssh:9.2p1").startswith("cpe:2.3:")
    assert query_key("SomeThing", "") == "kw:something"


def test_severity_bands():
    assert severity_from_cvss(0) == "unknown"
    assert severity_from_cvss(3.9) == "low"
    assert severity_from_cvss(6.9) == "medium"
    assert severity_from_cvss(8.9) == "high"
    assert severity_from_cvss(9.8) == "critical"
