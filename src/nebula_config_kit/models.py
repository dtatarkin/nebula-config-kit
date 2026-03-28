"""Pydantic domain models for nebula-config-kit."""

import re
from datetime import timedelta
from ipaddress import IPv4Address, IPv4Network
from typing import Annotated, Self

from pydantic import BaseModel, BeforeValidator, Field, model_validator

from nebula_config_kit.exceptions import ConfigFileError, DuplicateIPError
from nebula_config_kit.types import Direction, HostName, Protocol

_DURATION_RE = re.compile(r"^(\d+)\s*([smhd])$")
_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def _parse_duration(value: object) -> timedelta:
    if isinstance(value, timedelta):
        return value
    if isinstance(value, int | float):
        return timedelta(seconds=value)
    if isinstance(value, str):
        m = _DURATION_RE.match(value.strip())
        if m:
            return timedelta(seconds=int(m.group(1)) * _DURATION_UNITS[m.group(2)])
        raise ValueError(f"Invalid duration string: {value!r}. Use '<number><s|m|h|d>', e.g. '365d'.")
    raise TypeError(f"Expected timedelta, int, float, or str, got {type(value).__name__}")


Duration = Annotated[timedelta, BeforeValidator(_parse_duration)]


class NetworkConfig(BaseModel):
    """Network-level configuration."""

    cidr: IPv4Network


class CertsConfig(BaseModel):
    """Certificate issuance parameters."""

    ca_name: str = "Nebula CA"
    ca_duration: Duration = timedelta(days=3650)
    ca_min_validity: Duration = timedelta(days=365)
    host_duration: Duration = timedelta(days=365)
    host_min_validity: Duration = timedelta(days=30)


class SecurityGroup(BaseModel):
    """A single security group rule template."""

    port: str | int
    proto: Protocol
    direction: Direction


class FirewallConfig(BaseModel):
    """Firewall configuration: security groups, host groups, and rules."""

    security_groups: dict[str, SecurityGroup] = Field(default_factory=dict)
    host_groups: dict[str, list[str]] = Field(default_factory=dict)
    firewall_rules: dict[str, dict[str, list[str]]] = Field(default_factory=dict)
    firewall_default: dict[str, list[str]] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _check_security_group_refs(self) -> Self:
        for source, rules_map in [("firewall_default", self.firewall_default), *self.firewall_rules.items()]:
            for sg_name in (name for names in rules_map.values() for name in names):
                if sg_name not in self.security_groups:
                    raise ConfigFileError(
                        message=f"'{source}' references unknown security group '{sg_name}'.",
                    )
        return self


class LighthouseInfo(BaseModel):
    """Resolved lighthouse connection info."""

    nebula_ip: IPv4Address
    public_endpoints: list[str]
    listen_port: int


class HostDefaults(BaseModel):
    """Default values applied to all hosts."""

    tun_dev: str | None = None
    listen_port: int | None = None
    relays: list[str] | None = None


class HostConfig(BaseModel):
    """Per-host configuration."""

    nebula_ip: IPv4Address
    public_endpoints: list[str] | None = None
    tun_dev: str | None = None
    listen_port: int | None = None
    am_relay: bool = False
    relays: list[str] | None = None


class HostsConfig(BaseModel):
    """Hosts section with defaults and per-host overrides."""

    defaults: HostDefaults = Field(default_factory=HostDefaults)
    hosts: dict[str, HostConfig] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _check_unique_ips(self) -> Self:
        seen: dict[IPv4Address, str] = {}
        for name, host in self.hosts.items():
            ip = host.nebula_ip
            if ip in seen:
                raise DuplicateIPError(ip=str(ip), host_a=HostName(seen[ip]), host_b=HostName(name))
            seen[ip] = name
        return self


class NebulaNetworkConfig(BaseModel):
    """Top-level nebula-network.config.yml model."""

    network: NetworkConfig | None = None
    certs: CertsConfig | None = None
    hosts: HostsConfig | None = None
    firewall: FirewallConfig | None = None
