"""Tests for domain models."""

from ipaddress import IPv4Address, IPv4Network

import pytest

from nebula_config_kit.exceptions import ConfigFileError, DuplicateIPError
from nebula_config_kit.models import (
    FirewallConfig,
    HostConfig,
    HostsConfig,
    NebulaNetworkConfig,
    NetworkConfig,
    SecurityGroup,
)
from nebula_config_kit.types import Direction, Protocol


def test_nebula_network_config_accepts_valid_input(sample_network_config: NebulaNetworkConfig) -> None:
    assert sample_network_config.network is not None
    assert sample_network_config.network.cidr == IPv4Network("10.10.0.0/16")
    assert sample_network_config.hosts is not None
    assert len(sample_network_config.hosts.hosts) == 2


def test_nebula_network_config_optional_fields() -> None:
    config = NebulaNetworkConfig()
    assert config.network is None
    assert config.hosts is None
    assert config.firewall is None


def test_hosts_config_rejects_duplicate_ips() -> None:
    with pytest.raises(DuplicateIPError, match="Duplicate IP"):
        HostsConfig(
            hosts={
                "host-a": HostConfig(nebula_ip=IPv4Address("10.0.0.1")),
                "host-b": HostConfig(nebula_ip=IPv4Address("10.0.0.1")),
            },
        )


def test_hosts_config_allows_unique_ips() -> None:
    config = HostsConfig(
        hosts={
            "host-a": HostConfig(nebula_ip=IPv4Address("10.0.0.1")),
            "host-b": HostConfig(nebula_ip=IPv4Address("10.0.0.2")),
        },
    )
    assert len(config.hosts) == 2


def test_network_config_cidr() -> None:
    config = NetworkConfig(cidr=IPv4Network("192.168.0.0/24"))
    assert config.cidr == IPv4Network("192.168.0.0/24")


def test_host_config_rejects_invalid_ip() -> None:
    with pytest.raises(ValueError, match=r"not.*valid"):
        HostConfig(nebula_ip="not-an-ip")  # ty: ignore[invalid-argument-type]


def test_network_config_rejects_invalid_cidr() -> None:
    with pytest.raises(ValueError, match=r"not.*valid"):
        NetworkConfig(cidr="garbage")  # ty: ignore[invalid-argument-type]


def test_firewall_config_rejects_unknown_sg_in_default() -> None:
    with pytest.raises(ConfigFileError, match="unknown security group 'missing'"):
        FirewallConfig(
            security_groups={},
            firewall_default={"all": ["missing"]},
        )


def test_firewall_config_rejects_unknown_sg_in_rules() -> None:
    with pytest.raises(ConfigFileError, match="unknown security group 'bogus'"):
        FirewallConfig(
            security_groups={
                "icmp": SecurityGroup(port="any", proto=Protocol.ICMP, direction=Direction.ANY),
            },
            firewall_rules={"myhost": {"all": ["icmp", "bogus"]}},
        )


def test_firewall_config_accepts_valid_sg_refs() -> None:
    config = FirewallConfig(
        security_groups={
            "icmp": SecurityGroup(port="any", proto=Protocol.ICMP, direction=Direction.ANY),
        },
        firewall_default={"all": ["icmp"]},
        firewall_rules={"myhost": {"all": ["icmp"]}},
    )
    assert "icmp" in config.security_groups
