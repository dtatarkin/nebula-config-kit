"""Shared test fixtures."""

from ipaddress import IPv4Address, IPv4Network

import pytest

from nebula_config_kit.models import (
    FirewallConfig,
    HostConfig,
    HostDefaults,
    HostsConfig,
    NebulaNetworkConfig,
    NetworkConfig,
    SecurityGroup,
)
from nebula_config_kit.types import Direction, Protocol


@pytest.fixture
def sample_network_config() -> NebulaNetworkConfig:
    return NebulaNetworkConfig(
        network=NetworkConfig(cidr=IPv4Network("10.10.0.0/16")),
        hosts=HostsConfig(
            defaults=HostDefaults(listen_port=4242, tun_dev="nebula1"),
            hosts={
                "lighthouse1": HostConfig(
                    nebula_ip=IPv4Address("10.10.0.1"),
                    public_endpoints=["1.2.3.4:4242"],
                    listen_port=4242,
                ),
                "node1": HostConfig(
                    nebula_ip=IPv4Address("10.10.0.2"),
                ),
            },
        ),
        firewall=FirewallConfig(
            security_groups={
                "icmp": SecurityGroup(port="any", proto=Protocol.ICMP, direction=Direction.ANY),
                "ssh": SecurityGroup(port=22, proto=Protocol.TCP, direction=Direction.IN),
            },
            firewall_default={"all": ["icmp"]},
        ),
    )
