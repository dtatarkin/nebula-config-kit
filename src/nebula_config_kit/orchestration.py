"""Orchestration: high-level workflows combining multiple library modules."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from nebula_config_kit.config_gen import render_host_config
from nebula_config_kit.exceptions import ConfigFileError, HostCertificateNotFoundError
from nebula_config_kit.firewall import resolve_firewall_rules
from nebula_config_kit.hosts import (
    extract_lighthouses,
    resolve_host_overrides,
    resolve_lighthouses_for_host,
    resolve_relays_for_host,
)
from nebula_config_kit.network import make_sign_ip

if TYPE_CHECKING:
    from datetime import datetime
    from ipaddress import IPv4Address
    from pathlib import Path

    from pki.backends.nebula.pki import NebulaCertData, NebulaCertificateRequest, NebulaPki
    from pki.models import CertificateInfo

    from nebula_config_kit.models import CertsConfig, HostConfig, HostDefaults, LighthouseInfo, NebulaNetworkConfig
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

    Two modes, chosen by the network config:

    - Neither the host's ``key_path`` nor ``certs.trusted_ca_serials`` set: the CA and
      the host certificate are issued when missing or close to expiry, and the
      host's private key, from the key store, is inlined in the config.
    - Either set: nothing is issued. The trusted CAs are ``certs.trusted_ca_serials``
      (or else the current CA named ``certs.ca_name``), and the host certificate is
      the newest valid one for the host's name, IP and groups signed by one of them.
      With ``key_path`` the config points at the key on the host and carries no
      private key; without it the stored key is inlined.

    Raises ConfigFileError if required config sections are missing or a trusted CA
    is not usable.
    Raises HostNotFoundError if the host is not in the configuration.
    Raises HostCertificateNotFoundError if no stored certificate fits the host.
    """
    from datetime import UTC, datetime

    from pki.backends.nebula.pki import NebulaCertificateRequest
    from pki.models import Subject

    if config.network is None:
        raise ConfigFileError(message="Required configuration section 'network' is missing.")
    if config.certs is None:
        raise ConfigFileError(message="Required configuration section 'certs' is missing.")

    resolved = resolve_host(name, config=config)
    certs = config.certs
    now = datetime.now(tz=UTC)
    sign_ip = make_sign_ip(resolved.host.nebula_ip, cidr=config.network.cidr)
    host_groups = config.firewall.host_groups.get(name, []) if config.firewall else []

    if resolved.overrides.key_path is not None or certs.trusted_ca_serials is not None:
        return _render_from_stored_certificates(
            resolved=resolved,
            pki=pki,
            certs=certs,
            sign_ip=sign_ip,
            host_groups=host_groups,
            now=now,
            template_path=template_path,
        )

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
        blocklist=_blocklist(pki=pki),
        am_relay=resolved.am_relay,
        relays=[str(ip) for ip in resolved.relay_ips],
        ca_cert_info=_cert_info(cert=ca_cert),
        host_cert_info=_cert_info(cert=host_cert),
        template_path=template_path,
    )


def _blocklist(*, pki: NebulaPki) -> list[str]:
    from pki.types import CertificateStatus

    revoked_certs = pki.list_certificates(status=CertificateStatus.REVOKED)
    return [str(cert.backend_data.parsed.fingerprint) for cert in revoked_certs]


def _cert_info(*, cert: CertificateInfo[NebulaCertificateRequest, NebulaCertData]) -> dict[str, object]:
    # The public key says nothing a reader of the config needs, and records stored
    # before it was kept would show it empty.
    return cert.backend_data.parsed.model_dump(exclude={"public_key"})


def _trusted_cas(
    *, pki: NebulaPki, certs: CertsConfig, now: datetime
) -> list[CertificateInfo[NebulaCertificateRequest, NebulaCertData]]:
    from pki.types import CertificateStatus, SerialNumber

    if certs.trusted_ca_serials is None:
        current = pki.get_ca_certificate(common_name=certs.ca_name)
        if current is None:
            raise ConfigFileError(message=f"No issued CA certificate named '{certs.ca_name}'.")
        return [current]

    if not certs.trusted_ca_serials:
        raise ConfigFileError(message="'certs.trusted_ca_serials' is empty: no host could be trusted.")
    cas: list[CertificateInfo[NebulaCertificateRequest, NebulaCertData]] = []
    for serial in certs.trusted_ca_serials:
        ca = pki.get_certificate(SerialNumber(serial))
        if ca is None or not ca.request.is_ca:
            raise ConfigFileError(message=f"Trusted CA {serial} is not a CA certificate of this PKI.")
        if ca.status != CertificateStatus.ISSUED or ca.not_after < now:
            raise ConfigFileError(message=f"Trusted CA {serial} is revoked or expired.")
        cas.append(ca)
    return cas


def _select_host_certificate(
    *,
    resolved: ResolvedHost,
    pki: NebulaPki,
    trusted_ca_serials: set[int],
    sign_ip: str,
    host_groups: list[str],
    now: datetime,
) -> CertificateInfo[NebulaCertificateRequest, NebulaCertData]:
    from pki.types import CertificateStatus

    candidates = [
        cert
        for cert in pki.list_certificates(status=CertificateStatus.ISSUED, common_name=resolved.name, is_ca=False)
        if cert.not_after >= now and cert.ca_serial_number in trusted_ca_serials
    ]
    if not candidates:
        raise HostCertificateNotFoundError(
            name=resolved.name,
            message="no valid certificate signed by a trusted CA; issue one from the host's public key.",
        )
    candidates.sort(key=lambda cert: cert.issue_date, reverse=True)
    newest = candidates[0]
    if newest.request.ip != sign_ip or sorted(newest.request.groups) != sorted(host_groups):
        raise HostCertificateNotFoundError(
            name=resolved.name,
            message=(
                f"the newest certificate ({newest.serial_number}) has IP {newest.request.ip} and groups "
                f"{sorted(newest.request.groups)}, the network config {sign_ip} and {sorted(host_groups)}; "
                "issue or renew a certificate that matches."
            ),
        )
    return newest


def _render_from_stored_certificates(
    *,
    resolved: ResolvedHost,
    pki: NebulaPki,
    certs: CertsConfig,
    sign_ip: str,
    host_groups: list[str],
    now: datetime,
    template_path: Path | None,
) -> str:
    import os

    cas = _trusted_cas(pki=pki, certs=certs, now=now)
    host_cert = _select_host_certificate(
        resolved=resolved,
        pki=pki,
        trusted_ca_serials={int(ca.serial_number) for ca in cas},
        sign_ip=sign_ip,
        host_groups=host_groups,
        now=now,
    )

    key_path = resolved.overrides.key_path
    host_key_path: str | None = None
    host_key_pem: str | None = None
    if key_path is not None:
        host_key_path = os.path.expanduser(key_path.replace("{name}", resolved.name))
    else:
        host_key_pem = pki.export_private_key_pem(host_cert.serial_number).decode()

    return render_host_config(
        ca_cert_pem="".join(pki.export_certificate_pem(ca.serial_number).decode().strip() + "\n" for ca in cas),
        host_cert_pem=pki.export_certificate_pem(host_cert.serial_number).decode(),
        host_key_pem=host_key_pem,
        host_key_path=host_key_path,
        lighthouses=resolved.lighthouses,
        am_lighthouse=resolved.am_lighthouse,
        tun_dev=resolved.overrides.tun_dev or "nebula1",
        listen_port=resolved.overrides.listen_port,
        inbound_rules=resolved.inbound_rules or None,
        outbound_rules=resolved.outbound_rules or None,
        blocklist=_blocklist(pki=pki),
        am_relay=resolved.am_relay,
        relays=[str(ip) for ip in resolved.relay_ips],
        ca_cert_infos=[_cert_info(cert=ca) for ca in cas],
        host_cert_info=_cert_info(cert=host_cert),
        template_path=template_path,
    )


def issue_host_certificate(
    name: HostName,
    *,
    config: NebulaNetworkConfig,
    pki: NebulaPki,
    public_key_pem: str,
    ca_serial: int | None = None,
) -> CertificateInfo[NebulaCertificateRequest, NebulaCertData]:
    """Sign a host's own public key with the name, IP, groups and duration the network config gives it.

    The signing CA is *ca_serial*, or else the last of ``certs.trusted_ca_serials``,
    or else the current CA named ``certs.ca_name``; it must be one of the trusted CAs
    when ``certs.trusted_ca_serials`` is set. No private key is generated or stored.

    Raises ConfigFileError if required config sections are missing or the CA is not usable.
    Raises HostNotFoundError if the host is not in the configuration.
    Raises pki.exceptions.PkiError if signing fails, including when the public key is
    already signed for another host.
    """
    from datetime import UTC, datetime

    from pki.backends.nebula.pki import NebulaCertificateRequest, NebulaPublicKey
    from pki.models import Subject
    from pki.types import PEMString

    if config.network is None:
        raise ConfigFileError(message="Required configuration section 'network' is missing.")
    if config.certs is None:
        raise ConfigFileError(message="Required configuration section 'certs' is missing.")

    resolved = resolve_host(name, config=config)
    cas = _trusted_cas(pki=pki, certs=config.certs, now=datetime.now(tz=UTC))
    if ca_serial is None:
        ca = cas[-1]
    else:
        matching = [candidate for candidate in cas if int(candidate.serial_number) == ca_serial]
        if not matching:
            raise ConfigFileError(message=f"CA {ca_serial} is not a trusted CA of this network.")
        ca = matching[0]

    public_key = NebulaPublicKey.from_pem(pem=public_key_pem)
    request = NebulaCertificateRequest(
        subject=Subject(common_name=name),
        is_ca=False,
        duration=config.certs.host_duration,
        ip=make_sign_ip(resolved.host.nebula_ip, cidr=config.network.cidr),
        groups=config.firewall.host_groups.get(name, []) if config.firewall else [],
        key_algorithm=public_key.key_algorithm,
        public_key=PEMString(public_key_pem),
    )
    return pki.issue_certificate(request, ca_serial_number=ca.serial_number)
