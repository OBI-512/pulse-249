import pytest

from app.discovery.batch import expand_targets


def test_expand_explicit_ips():
    targets = expand_targets(["192.168.1.2", "192.168.1.1"])
    assert [x.ip_address for x in targets] == ["192.168.1.1", "192.168.1.2"]


def test_expand_cidr_and_deduplicate():
    targets = expand_targets(["192.168.1.1"], ["192.168.1.0/30"])
    assert [x.ip_address for x in targets] == [
        "192.168.1.1",
        "192.168.1.2",
    ]


def test_target_limit():
    with pytest.raises(ValueError):
        expand_targets(cidrs=["10.0.0.0/24"], max_targets=10)
