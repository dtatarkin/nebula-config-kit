"""Tests for host resolution."""

from ipaddress import IPv4Address

import pytest

from nebula_config_kit.exceptions import HostNotFoundError, LighthouseConfigError
from nebula_config_kit.hosts import (
    extract_lighthouses,
    resolve_host_overrides,
    resolve_lighthouses_for_host,
    resolve_relays_for_host,
)
from nebula_config_kit.models import HostConfig, HostDefaults, HostsConfig, LighthouseInfo, NebulaNetworkConfig
from nebula_config_kit.types import HostName


def test_resolve_host_overrides_raises_on_unknown_host(sample_network_config: NebulaNetworkConfig) -> None:
    assert sample_network_config.hosts is not None
    with pytest.raises(HostNotFoundError, match="no-such-host"):
        resolve_host_overrides(HostName("no-such-host"), hosts_config=sample_network_config.hosts)


def test_resolve_host_overrides_merges_known_host(sample_network_config: NebulaNetworkConfig) -> None:
    assert sample_network_config.hosts is not None
    result = resolve_host_overrides(HostName("node1"), hosts_config=sample_network_config.hosts)
    assert result.listen_port == 4242
    assert result.tun_dev == "nebula1"


def test_resolve_relays_for_host_raises_on_unknown_relay() -> None:
    hosts_config = HostsConfig(
        hosts={
            "node1": HostConfig(
                nebula_ip=IPv4Address("10.0.0.1"),
                relays=["nonexistent-relay"],
            ),
        },
    )
    with pytest.raises(HostNotFoundError, match="nonexistent-relay"):
        resolve_relays_for_host(HostName("node1"), hosts_config=hosts_config)


def test_resolve_relays_for_host_resolves_known_relay() -> None:
    hosts_config = HostsConfig(
        hosts={
            "relay1": HostConfig(nebula_ip=IPv4Address("10.0.0.1"), am_relay=True),
            "node1": HostConfig(nebula_ip=IPv4Address("10.0.0.2"), relays=["relay1"]),
        },
    )
    am_relay, relay_ips = resolve_relays_for_host(HostName("node1"), hosts_config=hosts_config)
    assert am_relay is False
    assert relay_ips == [IPv4Address("10.0.0.1")]


# --- extract_lighthouses ---


def test_extract_lighthouses_identifies_hosts_with_public_endpoints() -> None:
    hosts_config = HostsConfig(
        defaults=HostDefaults(listen_port=4242),
        hosts={
            "lh1": HostConfig(nebula_ip=IPv4Address("10.0.0.1"), public_endpoints=["1.2.3.4"], listen_port=4242),
            "node1": HostConfig(nebula_ip=IPv4Address("10.0.0.2")),
        },
    )
    result = extract_lighthouses(hosts_config=hosts_config)
    assert HostName("lh1") in result
    assert HostName("node1") not in result
    assert result[HostName("lh1")].nebula_ip == IPv4Address("10.0.0.1")
    assert result[HostName("lh1")].public_endpoints == ["1.2.3.4"]
    assert result[HostName("lh1")].listen_port == 4242


def test_extract_lighthouses_uses_default_listen_port() -> None:
    hosts_config = HostsConfig(
        defaults=HostDefaults(listen_port=5555),
        hosts={
            "lh1": HostConfig(nebula_ip=IPv4Address("10.0.0.1"), public_endpoints=["1.2.3.4"]),
        },
    )
    result = extract_lighthouses(hosts_config=hosts_config)
    assert result[HostName("lh1")].listen_port == 5555


def test_extract_lighthouses_raises_without_listen_port() -> None:
    hosts_config = HostsConfig(
        hosts={
            "lh1": HostConfig(nebula_ip=IPv4Address("10.0.0.1"), public_endpoints=["1.2.3.4"]),
        },
    )
    with pytest.raises(LighthouseConfigError, match="lh1"):
        extract_lighthouses(hosts_config=hosts_config)


def test_extract_lighthouses_returns_empty_when_no_lighthouses() -> None:
    hosts_config = HostsConfig(
        hosts={
            "node1": HostConfig(nebula_ip=IPv4Address("10.0.0.1")),
            "node2": HostConfig(nebula_ip=IPv4Address("10.0.0.2")),
        },
    )
    result = extract_lighthouses(hosts_config=hosts_config)
    assert result == {}


def test_extract_lighthouses_multiple() -> None:
    hosts_config = HostsConfig(
        defaults=HostDefaults(listen_port=4242),
        hosts={
            "lh1": HostConfig(nebula_ip=IPv4Address("10.0.0.1"), public_endpoints=["1.1.1.1"]),
            "lh2": HostConfig(nebula_ip=IPv4Address("10.0.0.2"), public_endpoints=["2.2.2.2"]),
            "node1": HostConfig(nebula_ip=IPv4Address("10.0.0.3")),
        },
    )
    result = extract_lighthouses(hosts_config=hosts_config)
    assert len(result) == 2
    assert HostName("lh1") in result
    assert HostName("lh2") in result


# --- resolve_lighthouses_for_host ---


def test_resolve_lighthouses_for_host_lighthouse_is_true() -> None:
    lh_info = LighthouseInfo(nebula_ip=IPv4Address("10.0.0.1"), public_endpoints=["1.1.1.1"], listen_port=4242)
    lighthouses = {HostName("lh1"): lh_info}
    am_lighthouse, others = resolve_lighthouses_for_host(HostName("lh1"), lighthouses=lighthouses)
    assert am_lighthouse is True
    assert others == []


def test_resolve_lighthouses_for_host_client_gets_others() -> None:
    lh1 = LighthouseInfo(nebula_ip=IPv4Address("10.0.0.1"), public_endpoints=["1.1.1.1"], listen_port=4242)
    lh2 = LighthouseInfo(nebula_ip=IPv4Address("10.0.0.2"), public_endpoints=["2.2.2.2"], listen_port=4242)
    lighthouses = {HostName("lh1"): lh1, HostName("lh2"): lh2}
    am_lighthouse, others = resolve_lighthouses_for_host(HostName("node1"), lighthouses=lighthouses)
    assert am_lighthouse is False
    assert others == [lh1, lh2]


def test_resolve_lighthouses_for_host_excludes_self() -> None:
    lh1 = LighthouseInfo(nebula_ip=IPv4Address("10.0.0.1"), public_endpoints=["1.1.1.1"], listen_port=4242)
    lh2 = LighthouseInfo(nebula_ip=IPv4Address("10.0.0.2"), public_endpoints=["2.2.2.2"], listen_port=4242)
    lighthouses = {HostName("lh1"): lh1, HostName("lh2"): lh2}
    am_lighthouse, others = resolve_lighthouses_for_host(HostName("lh1"), lighthouses=lighthouses)
    assert am_lighthouse is True
    assert others == [lh2]


def test_resolve_lighthouses_for_host_empty_lighthouses() -> None:
    lighthouses: dict[HostName, LighthouseInfo] = {}
    am_lighthouse, others = resolve_lighthouses_for_host(HostName("node1"), lighthouses=lighthouses)
    assert am_lighthouse is False
    assert others == []
