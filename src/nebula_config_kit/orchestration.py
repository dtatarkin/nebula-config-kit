"""Orchestration: high-level workflows combining multiple library modules."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from nebula_config_kit.config_gen import render_host_config
from nebula_config_kit.exceptions import ConfigFileError
from nebula_config_kit.firewall import resolve_firewall_rules
from nebula_config_kit.hosts import (
    extract_lighthouses,
    resolve_host_overrides,
    resolve_lighthouses_for_host,
    resolve_relays_for_host,
)
from nebula_config_kit.network import make_sign_ip

if TYPE_CHECKING:
    from ipaddress import IPv4Address
    from pathlib import Path

    from pki.backends.nebula.pki import NebulaPki

    from nebula_config_kit.models import HostConfig, HostDefaults, LighthouseInfo, NebulaNetworkConfig
    from nebula_config_kit.types import FirewallRule, HostName


@dataclass(frozen=True)
class ResolvedHost:
    """Fully resolved host configuration."""

    name: HostName
    host: HostConfig
    overrides: HostDefaults
    am_lighthouse: bool
    lighthouses: list[LighthouseInfo]
    am_relay: bool
    relay_ips: list[IPv4Address]
    inbound_rules: list[FirewallRule]
    outbound_rules: list[FirewallRule]


def resolve_host(name: HostName, *, config: NebulaNetworkConfig) -> ResolvedHost:
    """Resolve complete host configuration from the network config.

    Merges defaults with per-host overrides, extracts lighthouses,
    resolves relays, and resolves firewall rules.

    Raises ConfigFileError if the hosts section is missing.
    Raises HostNotFoundError if the host is not in the configuration.
    """
    if config.hosts is None:
        raise ConfigFileError(message="Required configuration section 'hosts' is missing.")

    overrides = resolve_host_overrides(name, hosts_config=config.hosts)
    host = config.hosts.hosts[name]

    all_lighthouses = extract_lighthouses(hosts_config=config.hosts)
    am_lighthouse, other_lighthouses = resolve_lighthouses_for_host(name, lighthouses=all_lighthouses)
    am_relay, relay_ips = resolve_relays_for_host(name, hosts_config=config.hosts)

    inbound: list[FirewallRule] = []
    outbound: list[FirewallRule] = []
    if config.firewall is not None:
        inbound, outbound = resolve_firewall_rules(name, config=config.firewall)

    return ResolvedHost(
        name=name,
        host=host,
        overrides=overrides,
        am_lighthouse=am_lighthouse,
        lighthouses=other_lighthouses,
        am_relay=am_relay,
        relay_ips=relay_ips,
        inbound_rules=inbound,
        outbound_rules=outbound,
    )


def generate_host_config(
    name: HostName,
    *,
    config: NebulaNetworkConfig,
    pki: NebulaPki,
    template_path: Path | None = None,
) -> str:
    """Generate complete Nebula host configuration YAML.

    Resolves host details, manages certificates via pki-kit, and renders
    the final Nebula configuration.

    Raises ConfigFileError if required config sections are missing.
    Raises HostNotFoundError if the host is not in the configuration.
    """
    from datetime import UTC, datetime

    from pki.backends.nebula.pki import NebulaCertificateRequest
    from pki.models import Subject
    from pki.types import CertificateStatus

    if config.network is None:
        raise ConfigFileError(message="Required configuration section 'network' is missing.")
    if config.certs is None:
        raise ConfigFileError(message="Required configuration section 'certs' is missing.")

    resolved = resolve_host(name, config=config)
    certs = config.certs
    now = datetime.now(tz=UTC)

    # Ensure valid CA
    ca_cert = pki.get_ca_certificate(common_name=certs.ca_name)
    if ca_cert is None or ca_cert.not_after < now + certs.ca_min_validity:
        ca_request = NebulaCertificateRequest(
            subject=Subject(common_name=certs.ca_name),
            is_ca=True,
            duration=certs.ca_duration,
        )
        ca_cert = pki.issue_certificate(ca_request)

    # Get or issue host certificate
    sign_ip = make_sign_ip(resolved.host.nebula_ip, cidr=config.network.cidr)
    host_groups = config.firewall.host_groups.get(name, []) if config.firewall else []

    host_request = NebulaCertificateRequest(
        subject=Subject(common_name=name),
        is_ca=False,
        duration=certs.host_duration,
        ip=sign_ip,
        groups=host_groups,
    )
    host_cert = pki.get_or_issue_certificate(
        host_request,
        not_expired_at=now + certs.host_min_validity,
        ca_serial_number=ca_cert.serial_number,
    )

    # Extract PEM data
    ca_cert_pem = pki.export_certificate_pem(ca_cert.serial_number).decode()
    host_cert_pem = pki.export_certificate_pem(host_cert.serial_number).decode()
    host_key_pem = pki.export_private_key_pem(host_cert.serial_number).decode()

    # Collect blocklist
    revoked_certs = pki.list_certificates(status=CertificateStatus.REVOKED)
    blocklist = [str(cert.backend_data.parsed.fingerprint) for cert in revoked_certs]

    return render_host_config(
        ca_cert_pem=ca_cert_pem,
        host_cert_pem=host_cert_pem,
        host_key_pem=host_key_pem,
        lighthouses=resolved.lighthouses,
        am_lighthouse=resolved.am_lighthouse,
        tun_dev=resolved.overrides.tun_dev or "nebula1",
        listen_port=resolved.overrides.listen_port,
        inbound_rules=resolved.inbound_rules or None,
        outbound_rules=resolved.outbound_rules or None,
        blocklist=blocklist,
        am_relay=resolved.am_relay,
        relays=[str(ip) for ip in resolved.relay_ips],
        ca_cert_info=ca_cert.backend_data.parsed.model_dump(),
        host_cert_info=host_cert.backend_data.parsed.model_dump(),
        template_path=template_path,
    )
