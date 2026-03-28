"""nebula-config-kit — Nebula overlay network configuration management."""

from ipaddress import IPv4Address, IPv4Network

from nebula_config_kit.config_gen import render_host_config
from nebula_config_kit.config_loader import DEFAULT_NEBULA_NETWORK_CONFIG_FILENAME, load_config
from nebula_config_kit.exceptions import (
    ConfigFileError,
    ConfigRenderError,
    DuplicateIPError,
    HostNotFoundError,
    LighthouseConfigError,
    NebulaConfigError,
)
from nebula_config_kit.firewall import resolve_firewall_rules
from nebula_config_kit.hosts import (
    extract_lighthouses,
    resolve_host_overrides,
    resolve_lighthouses_for_host,
    resolve_relays_for_host,
)
from nebula_config_kit.models import (
    CertsConfig,
    FirewallConfig,
    HostConfig,
    HostDefaults,
    HostsConfig,
    LighthouseInfo,
    NebulaNetworkConfig,
    NetworkConfig,
    SecurityGroup,
)
from nebula_config_kit.network import get_prefix_length, make_sign_ip
from nebula_config_kit.orchestration import ResolvedHost, generate_host_config, resolve_host
from nebula_config_kit.types import Direction, FirewallRule, HostName, Protocol

__all__ = [
    "DEFAULT_NEBULA_NETWORK_CONFIG_FILENAME",
    "CertsConfig",
    "ConfigFileError",
    "ConfigRenderError",
    "Direction",
    "DuplicateIPError",
    "FirewallConfig",
    "FirewallRule",
    "HostConfig",
    "HostDefaults",
    "HostName",
    "HostNotFoundError",
    "HostsConfig",
    "IPv4Address",
    "IPv4Network",
    "LighthouseConfigError",
    "LighthouseInfo",
    "NebulaConfigError",
    "NebulaNetworkConfig",
    "NetworkConfig",
    "Protocol",
    "ResolvedHost",
    "SecurityGroup",
    "extract_lighthouses",
    "generate_host_config",
    "get_prefix_length",
    "load_config",
    "make_sign_ip",
    "render_host_config",
    "resolve_firewall_rules",
    "resolve_host",
    "resolve_host_overrides",
    "resolve_lighthouses_for_host",
    "resolve_relays_for_host",
]
