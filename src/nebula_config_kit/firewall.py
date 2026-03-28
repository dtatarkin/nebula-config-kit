"""Firewall rule resolution."""

from nebula_config_kit.models import FirewallConfig, SecurityGroup
from nebula_config_kit.types import Direction, FirewallRule, HostName


def _build_rule(*, sg: SecurityGroup, peer_group: str) -> FirewallRule:
    """Build a single firewall rule from a security group and peer group."""
    if peer_group == "all":
        return {"port": sg.port, "proto": str(sg.proto), "host": "any"}
    return {"port": sg.port, "proto": str(sg.proto), "group": peer_group}


def resolve_firewall_rules(name: HostName, *, config: FirewallConfig) -> tuple[list[FirewallRule], list[FirewallRule]]:
    """Resolve inbound and outbound firewall rules for a host.

    Returns (inbound_rules, outbound_rules).
    """
    rules_map = config.firewall_rules.get(name, config.firewall_default)

    inbound: list[FirewallRule] = []
    outbound: list[FirewallRule] = []

    for peer_group, sg_names in rules_map.items():
        for sg_name in sg_names:
            sg = config.security_groups[sg_name]

            if sg.direction in (Direction.IN, Direction.ANY):
                inbound.append(_build_rule(sg=sg, peer_group=peer_group))
            if sg.direction in (Direction.OUT, Direction.ANY):
                outbound.append(_build_rule(sg=sg, peer_group=peer_group))

    return inbound, outbound
