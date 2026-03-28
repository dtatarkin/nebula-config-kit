"""Host resolution: defaults merging, lighthouse extraction, relay resolution."""

from ipaddress import IPv4Address

from nebula_config_kit.exceptions import HostNotFoundError, LighthouseConfigError
from nebula_config_kit.models import HostDefaults, HostsConfig, LighthouseInfo
from nebula_config_kit.types import HostName


def resolve_host_overrides(name: HostName, *, hosts_config: HostsConfig) -> HostDefaults:
    """Merge per-host overrides with defaults."""
    defaults = hosts_config.defaults
    per_host = hosts_config.hosts.get(name)
    if per_host is None:
        raise HostNotFoundError(name=name)
    return HostDefaults(
        tun_dev=per_host.tun_dev if per_host.tun_dev is not None else defaults.tun_dev,
        listen_port=per_host.listen_port if per_host.listen_port is not None else defaults.listen_port,
        relays=per_host.relays if per_host.relays is not None else defaults.relays,
    )


def extract_lighthouses(*, hosts_config: HostsConfig) -> dict[HostName, LighthouseInfo]:
    """Identify lighthouses: hosts with public_endpoints."""
    result: dict[HostName, LighthouseInfo] = {}
    for name, host in hosts_config.hosts.items():
        if host.public_endpoints:
            overrides = resolve_host_overrides(HostName(name), hosts_config=hosts_config)
            if overrides.listen_port is None:
                raise LighthouseConfigError(
                    name=HostName(name),
                    message="has public_endpoints but no listen_port configured",
                )
            result[HostName(name)] = LighthouseInfo(
                nebula_ip=host.nebula_ip,
                public_endpoints=host.public_endpoints,
                listen_port=overrides.listen_port,
            )
    return result


def resolve_lighthouses_for_host(
    name: HostName, *, lighthouses: dict[HostName, LighthouseInfo]
) -> tuple[bool, list[LighthouseInfo]]:
    """Return (am_lighthouse, other_lighthouses) for a given host."""
    am_lighthouse = name in lighthouses
    filtered = [cfg for lh_name, cfg in lighthouses.items() if lh_name != name]
    return am_lighthouse, filtered


def resolve_relays_for_host(name: HostName, *, hosts_config: HostsConfig) -> tuple[bool, list[IPv4Address]]:
    """Return (am_relay, relay_ips) for a given host."""
    host = hosts_config.hosts.get(name)
    am_relay = host.am_relay if host is not None else False

    relay_names: list[str] | None = None
    if host is not None and host.relays is not None:
        relay_names = host.relays
    elif hosts_config.defaults.relays is not None:
        relay_names = hosts_config.defaults.relays

    if relay_names is None:
        return am_relay, []

    relay_ips: list[IPv4Address] = []
    for relay_name in relay_names:
        if relay_name == name:
            continue
        relay_host = hosts_config.hosts.get(relay_name)
        if relay_host is None:
            raise HostNotFoundError(name=HostName(relay_name))
        relay_ips.append(relay_host.nebula_ip)

    return am_relay, relay_ips
