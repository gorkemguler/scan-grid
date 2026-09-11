import pytest

from scangrid.allowlist import AllowlistError, assert_hosts_allowed, is_allowed, resolve_spec


def test_in_scope_cidr_expands():
    res = resolve_spec("192.168.1.0/30")
    assert set(res.allowed) == {"192.168.1.1", "192.168.1.2"}
    assert res.rejected == []
    assert res.ok


def test_single_ip_and_range():
    res = resolve_spec("10.0.0.5, 10.0.0.10-12")
    assert res.allowed == ["10.0.0.5", "10.0.0.10", "10.0.0.11", "10.0.0.12"]


def test_out_of_scope_ip_rejected():
    res = resolve_spec("192.168.1.1 172.16.9.9")
    assert res.allowed == ["192.168.1.1"]
    assert res.rejected and res.rejected[0][0] == "172.16.9.9"


def test_public_ip_rejected_by_default():
    assert not is_allowed("8.8.8.8")
    res = resolve_spec("8.8.8.8")
    assert res.allowed == []
    assert res.rejected


def test_oversized_cidr_refused():
    res = resolve_spec("10.0.0.0/8")
    assert res.allowed == []
    assert "expands to" in res.rejected[0][1]


def test_assert_hosts_allowed_raises_on_bad_host():
    assert_hosts_allowed(["192.168.5.5", "10.1.2.3"])  # fine
    with pytest.raises(AllowlistError):
        assert_hosts_allowed(["192.168.5.5", "1.1.1.1"])
