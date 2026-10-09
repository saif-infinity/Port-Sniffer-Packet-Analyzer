import pytest

from psa.scope import ScopeError, check_target, load_allowed_networks, parse_ports


def test_default_scope_allows_private_and_loopback():
    nets = load_allowed_networks()
    assert check_target("192.168.1.10", nets) == ["192.168.1.10"]
    assert check_target("10.1.2.3", nets) == ["10.1.2.3"]
    assert check_target("127.0.0.1", nets) == ["127.0.0.1"]
    assert check_target("localhost", nets)  # resolves to loopback


def test_public_addresses_are_refused_by_default():
    nets = load_allowed_networks()
    with pytest.raises(ScopeError, match="outside the allowed scope"):
        check_target("8.8.8.8", nets)


def test_env_extends_scope(monkeypatch):
    monkeypatch.setenv("PSA_ALLOWED_NETWORKS", "203.0.113.0/24")
    nets = load_allowed_networks()
    assert check_target("203.0.113.7", nets) == ["203.0.113.7"]
    with pytest.raises(ScopeError):
        check_target("198.51.100.1", nets)


def test_empty_target_rejected():
    with pytest.raises(ScopeError):
        check_target("   ", load_allowed_networks())


def test_unresolvable_hostname_rejected():
    with pytest.raises(ScopeError, match="Cannot resolve"):
        check_target("this-host-does-not-exist.invalid", load_allowed_networks())


@pytest.mark.parametrize("spec,expected", [
    ("22", [22]),
    ("22,80", [22, 80]),
    ("8000-8002", [8000, 8001, 8002]),
    ("80,22,80", [22, 80]),
    (" 22 , 443 ", [22, 443]),
])
def test_parse_ports_valid(spec, expected):
    assert parse_ports(spec) == expected


def test_parse_ports_presets():
    assert 22 in parse_ports("top") and 80 in parse_ports("")
    assert len(parse_ports("all")) == 65535


@pytest.mark.parametrize("spec", ["0", "65536", "100-50", "abc", "1-70000", ",", "-"])
def test_parse_ports_invalid(spec):
    with pytest.raises(ValueError):
        parse_ports(spec)
