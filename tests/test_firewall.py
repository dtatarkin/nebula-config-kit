"""Tests for firewall rule resolution."""

from nebula_config_kit.firewall import resolve_firewall_rules
from nebula_config_kit.models import FirewallConfig, NebulaNetworkConfig, SecurityGroup
from nebula_config_kit.types import Direction, HostName, Protocol


def test_default_rules_applied_for_unknown_host(sample_network_config: NebulaNetworkConfig) -> None:
    assert sample_network_config.firewall is not None
    inbound, outbound = resolve_firewall_rules(HostName("node1"), config=sample_network_config.firewall)
    # firewall_default is {"all": ["icmp"]}, direction=ANY → both lists
    assert len(inbound) == 1
    assert len(outbound) == 1
    assert inbound[0]["port"] == "any"
    assert inbound[0]["proto"] == "icmp"
    assert inbound[0]["host"] == "any"


def test_host_specific_rules_override_defaults() -> None:
    config = FirewallConfig(
        security_groups={
            "ssh": SecurityGroup(port=22, proto=Protocol.TCP, direction=Direction.IN),
        },
        firewall_rules={
            "node1": {"admin": ["ssh"]},
        },
        firewall_default={"all": ["ssh"]},
    )
    inbound, outbound = resolve_firewall_rules(HostName("node1"), config=config)
    assert len(inbound) == 1
    assert inbound[0]["port"] == 22
    assert inbound[0]["group"] == "admin"
    assert "host" not in inbound[0]
    assert outbound == []


def test_direction_in_only_goes_to_inbound() -> None:
    config = FirewallConfig(
        security_groups={
            "ssh": SecurityGroup(port=22, proto=Protocol.TCP, direction=Direction.IN),
        },
        firewall_default={"all": ["ssh"]},
    )
    inbound, outbound = resolve_firewall_rules(HostName("x"), config=config)
    assert len(inbound) == 1
    assert outbound == []


def test_direction_out_only_goes_to_outbound() -> None:
    config = FirewallConfig(
        security_groups={
            "web": SecurityGroup(port=443, proto=Protocol.TCP, direction=Direction.OUT),
        },
        firewall_default={"all": ["web"]},
    )
    inbound, outbound = resolve_firewall_rules(HostName("x"), config=config)
    assert inbound == []
    assert len(outbound) == 1
    assert outbound[0]["port"] == 443


def test_direction_any_goes_to_both() -> None:
    config = FirewallConfig(
        security_groups={
            "icmp": SecurityGroup(port="any", proto=Protocol.ICMP, direction=Direction.ANY),
        },
        firewall_default={"all": ["icmp"]},
    )
    inbound, outbound = resolve_firewall_rules(HostName("x"), config=config)
    assert len(inbound) == 1
    assert len(outbound) == 1
    assert inbound[0] == outbound[0]


def test_direction_any_produces_independent_copies() -> None:
    config = FirewallConfig(
        security_groups={
            "icmp": SecurityGroup(port="any", proto=Protocol.ICMP, direction=Direction.ANY),
        },
        firewall_default={"all": ["icmp"]},
    )
    inbound, outbound = resolve_firewall_rules(HostName("x"), config=config)
    assert inbound[0] is not outbound[0]


def test_peer_group_all_sets_host_any() -> None:
    config = FirewallConfig(
        security_groups={
            "ssh": SecurityGroup(port=22, proto=Protocol.TCP, direction=Direction.IN),
        },
        firewall_default={"all": ["ssh"]},
    )
    inbound, _ = resolve_firewall_rules(HostName("x"), config=config)
    assert inbound[0]["host"] == "any"
    assert "group" not in inbound[0]


def test_named_peer_group_sets_group() -> None:
    config = FirewallConfig(
        security_groups={
            "ssh": SecurityGroup(port=22, proto=Protocol.TCP, direction=Direction.IN),
        },
        firewall_default={"servers": ["ssh"]},
    )
    inbound, _ = resolve_firewall_rules(HostName("x"), config=config)
    assert inbound[0]["group"] == "servers"
    assert "host" not in inbound[0]


def test_multiple_security_groups_per_peer_group() -> None:
    config = FirewallConfig(
        security_groups={
            "ssh": SecurityGroup(port=22, proto=Protocol.TCP, direction=Direction.IN),
            "icmp": SecurityGroup(port="any", proto=Protocol.ICMP, direction=Direction.IN),
        },
        firewall_default={"all": ["ssh", "icmp"]},
    )
    inbound, _ = resolve_firewall_rules(HostName("x"), config=config)
    assert len(inbound) == 2
    ports = {r["port"] for r in inbound}
    assert ports == {22, "any"}


def test_empty_rules_returns_empty_lists() -> None:
    config = FirewallConfig(
        security_groups={},
        firewall_default={},
    )
    inbound, outbound = resolve_firewall_rules(HostName("x"), config=config)
    assert inbound == []
    assert outbound == []
