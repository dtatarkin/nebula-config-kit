"""Tests for orchestration.py: host configs from stored certificates, key paths and CA bundles."""

from __future__ import annotations

import shutil
import subprocess
from datetime import timedelta
from ipaddress import IPv4Address, IPv4Network
from typing import TYPE_CHECKING, Any

import pytest
from pki.backends.nebula.pki import NebulaCertData, NebulaCertificateRequest, NebulaPki
from pki.certificate_stores import InMemoryCertificateStore
from pki.key_stores import InMemoryKeyStore
from pki.models import Subject
from pki.types import KeyAlgorithm, PEMString, SerialNumber
from ruamel.yaml import YAML
from ruamel.yaml.compat import StringIO

from nebula_config_kit.exceptions import ConfigFileError, HostCertificateNotFoundError
from nebula_config_kit.models import (
    CertsConfig,
    FirewallConfig,
    HostConfig,
    HostDefaults,
    HostsConfig,
    NebulaNetworkConfig,
    NetworkConfig,
)
from nebula_config_kit.orchestration import generate_host_config, issue_host_certificate
from nebula_config_kit.types import HostName

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.skipif(condition=shutil.which("nebula-cert") is None, reason="nebula-cert not found on PATH")

_SERVER_KEY = "/etc/nebula/host.key"
_WORKSTATION_KEY = "~/.config/mesh/{name}.key"


def _parse_yaml(text: str) -> dict[str, Any]:
    result: dict[str, Any] = YAML().load(stream=StringIO(text))
    return result


def _make_pki() -> NebulaPki:
    return NebulaPki(
        key_store=InMemoryKeyStore(),
        certificate_store=InMemoryCertificateStore[NebulaCertificateRequest, NebulaCertData](),
    )


def _issue_ca(*, pki: NebulaPki, name: str) -> SerialNumber:
    return pki.issue_certificate(
        request=NebulaCertificateRequest(
            subject=Subject(common_name=name),
            duration=timedelta(days=3650),
            key_algorithm=KeyAlgorithm.ED25519,
            is_ca=True,
        ),
    ).serial_number


def _keygen(*, directory: Path, name: str) -> tuple[Path, PEMString]:
    """Generate a host key pair the way its owner does; return the key path and the public key."""
    subprocess.run(
        [
            "nebula-cert",
            "keygen",
            "-out-key",
            str(directory / f"{name}.key"),
            "-out-pub",
            str(directory / f"{name}.pub"),
        ],
        check=True,
        capture_output=True,
    )
    return directory / f"{name}.key", PEMString((directory / f"{name}.pub").read_text())


def _issue_host(
    *,
    pki: NebulaPki,
    ca_serial: SerialNumber,
    name: str,
    ip: str,
    groups: list[str],
    public_key: PEMString | None,
) -> SerialNumber:
    return pki.issue_certificate(
        request=NebulaCertificateRequest(
            subject=Subject(common_name=name),
            duration=timedelta(days=365),
            ip=ip,
            groups=groups,
            key_algorithm=KeyAlgorithm.ED25519,
            public_key=public_key,
        ),
        ca_serial_number=ca_serial,
    ).serial_number


def _network(
    *,
    trusted_ca_serials: list[int] | None = None,
    default_key_path: str | None = _WORKSTATION_KEY,
    server_key_path: str | None = _SERVER_KEY,
) -> NebulaNetworkConfig:
    return NebulaNetworkConfig(
        network=NetworkConfig(cidr=IPv4Network("10.10.0.0/16")),
        certs=CertsConfig(ca_name="Test CA", trusted_ca_serials=trusted_ca_serials),
        hosts=HostsConfig(
            defaults=HostDefaults(listen_port=4242, tun_dev="nebula1", key_path=default_key_path),
            hosts={
                "lighthouse1": HostConfig(
                    nebula_ip=IPv4Address("10.10.0.1"),
                    public_endpoints=["203.0.113.10"],
                    key_path=server_key_path,
                ),
                "laptop": HostConfig(nebula_ip=IPv4Address("10.10.1.1")),
            },
        ),
        firewall=FirewallConfig(host_groups={"lighthouse1": ["server"], "laptop": ["developer"]}),
    )


class TestKeyPath:
    def test_config_references_key_and_holds_no_private_key(self, tmp_path: Path) -> None:
        pki = _make_pki()
        ca = _issue_ca(pki=pki, name="Test CA")
        _, public_key = _keygen(directory=tmp_path, name="lighthouse1")
        _issue_host(
            pki=pki, ca_serial=ca, name="lighthouse1", ip="10.10.0.1/16", groups=["server"], public_key=public_key
        )

        raw = generate_host_config(HostName("lighthouse1"), config=_network(), pki=pki)

        assert "PRIVATE KEY" not in raw
        assert _parse_yaml(raw)["pki"]["key"] == _SERVER_KEY

    def test_default_key_path_expands_name_and_home(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HOME", str(tmp_path / "home"))
        pki = _make_pki()
        ca = _issue_ca(pki=pki, name="Test CA")
        _, public_key = _keygen(directory=tmp_path, name="laptop")
        _issue_host(
            pki=pki, ca_serial=ca, name="laptop", ip="10.10.1.1/16", groups=["developer"], public_key=public_key
        )

        raw = generate_host_config(HostName("laptop"), config=_network(), pki=pki)

        assert "PRIVATE KEY" not in raw
        assert _parse_yaml(raw)["pki"]["key"] == str(tmp_path / "home" / ".config" / "mesh" / "laptop.key")

    def test_stored_key_is_inlined_without_key_path(self) -> None:
        pki = _make_pki()
        ca = _issue_ca(pki=pki, name="Test CA")
        _issue_host(pki=pki, ca_serial=ca, name="laptop", ip="10.10.1.1/16", groups=["developer"], public_key=None)

        raw = generate_host_config(
            HostName("laptop"),
            config=_network(trusted_ca_serials=[ca], default_key_path=None),
            pki=pki,
        )

        assert "PRIVATE KEY" in _parse_yaml(raw)["pki"]["key"]

    def test_nothing_is_issued(self) -> None:
        pki = _make_pki()
        _issue_ca(pki=pki, name="Test CA")

        with pytest.raises(HostCertificateNotFoundError, match="'laptop'"):
            generate_host_config(HostName("laptop"), config=_network(), pki=pki)
        assert len(pki.list_certificates()) == 1

    def test_certificate_must_match_groups(self, tmp_path: Path) -> None:
        pki = _make_pki()
        ca = _issue_ca(pki=pki, name="Test CA")
        _, public_key = _keygen(directory=tmp_path, name="laptop")
        _issue_host(pki=pki, ca_serial=ca, name="laptop", ip="10.10.1.1/16", groups=["admin"], public_key=public_key)

        with pytest.raises(HostCertificateNotFoundError, match="groups"):
            generate_host_config(HostName("laptop"), config=_network(), pki=pki)

    def test_newest_certificate_wins(self, tmp_path: Path) -> None:
        pki = _make_pki()
        ca = _issue_ca(pki=pki, name="Test CA")
        _, public_key = _keygen(directory=tmp_path, name="laptop")
        older = _issue_host(
            pki=pki, ca_serial=ca, name="laptop", ip="10.10.1.1/16", groups=["developer"], public_key=public_key
        )
        newer = pki.renew_certificate(serial_number=older)

        raw = generate_host_config(HostName("laptop"), config=_network(), pki=pki)

        assert _parse_yaml(raw)["pki"]["cert"] == pki.export_certificate_pem(serial_number=newer.serial_number).decode()


class TestTrustedCaBundle:
    def test_bundle_holds_every_trusted_ca(self, tmp_path: Path) -> None:
        pki = _make_pki()
        old_ca = _issue_ca(pki=pki, name="Old CA")
        new_ca = _issue_ca(pki=pki, name="New CA")
        _, public_key = _keygen(directory=tmp_path, name="laptop")
        _issue_host(
            pki=pki, ca_serial=new_ca, name="laptop", ip="10.10.1.1/16", groups=["developer"], public_key=public_key
        )

        raw = generate_host_config(HostName("laptop"), config=_network(trusted_ca_serials=[old_ca, new_ca]), pki=pki)

        bundle = _parse_yaml(raw)["pki"]["ca"]
        for ca in (old_ca, new_ca):
            assert pki.export_certificate_pem(serial_number=ca).decode().strip() in bundle
        assert "name: Old CA" in raw
        assert "name: New CA" in raw

    def test_certificate_of_untrusted_ca_is_not_selected(self, tmp_path: Path) -> None:
        pki = _make_pki()
        old_ca = _issue_ca(pki=pki, name="Old CA")
        new_ca = _issue_ca(pki=pki, name="New CA")
        _, public_key = _keygen(directory=tmp_path, name="laptop")
        _issue_host(
            pki=pki, ca_serial=old_ca, name="laptop", ip="10.10.1.1/16", groups=["developer"], public_key=public_key
        )

        with pytest.raises(HostCertificateNotFoundError, match="trusted CA"):
            generate_host_config(HostName("laptop"), config=_network(trusted_ca_serials=[new_ca]), pki=pki)

    @pytest.mark.parametrize("bad", ["unknown", "host", "empty"])
    def test_unusable_trusted_ca_is_refused(self, tmp_path: Path, bad: str) -> None:
        pki = _make_pki()
        ca = _issue_ca(pki=pki, name="Test CA")
        _, public_key = _keygen(directory=tmp_path, name="laptop")
        host = _issue_host(
            pki=pki, ca_serial=ca, name="laptop", ip="10.10.1.1/16", groups=["developer"], public_key=public_key
        )
        serials: list[int] = {"unknown": [int(ca), 12345], "host": [int(ca), int(host)], "empty": []}[bad]

        with pytest.raises(ConfigFileError):
            generate_host_config(HostName("laptop"), config=_network(trusted_ca_serials=serials), pki=pki)

    @pytest.mark.skipif(condition=shutil.which("nebula") is None, reason="nebula not found on PATH")
    def test_two_ca_config_passes_nebula_test(self, tmp_path: Path) -> None:
        pki = _make_pki()
        old_ca = _issue_ca(pki=pki, name="Old CA")
        new_ca = _issue_ca(pki=pki, name="New CA")
        key_path, public_key = _keygen(directory=tmp_path, name="laptop")
        _issue_host(
            pki=pki, ca_serial=new_ca, name="laptop", ip="10.10.1.1/16", groups=["developer"], public_key=public_key
        )
        config = _network(trusted_ca_serials=[old_ca, new_ca], default_key_path=str(key_path))

        raw = generate_host_config(HostName("laptop"), config=config, pki=pki)
        (tmp_path / "laptop.yml").write_text(raw)

        result = subprocess.run(
            ["nebula", "-test", "-config", str(tmp_path / "laptop.yml")],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "PRIVATE KEY" not in raw


class TestLegacyMode:
    def test_ca_and_host_certificate_issued_and_key_inlined(self) -> None:
        pki = _make_pki()

        raw = generate_host_config(
            HostName("laptop"),
            config=_network(default_key_path=None, server_key_path=None),
            pki=pki,
        )

        assert "PRIVATE KEY" in _parse_yaml(raw)["pki"]["key"]
        assert "public_key" not in raw
        assert len(pki.list_certificates()) == 2


class TestIssueHostCertificate:
    def test_signs_public_key_with_network_identity(self, tmp_path: Path) -> None:
        pki = _make_pki()
        old_ca = _issue_ca(pki=pki, name="Old CA")
        new_ca = _issue_ca(pki=pki, name="New CA")
        _, public_key = _keygen(directory=tmp_path, name="laptop")
        config = _network(trusted_ca_serials=[old_ca, new_ca])

        cert = issue_host_certificate(HostName("laptop"), config=config, pki=pki, public_key_pem=public_key)

        assert cert.ca_serial_number == new_ca
        assert cert.request.ip == "10.10.1.1/16"
        assert cert.request.groups == ["developer"]
        assert cert.request.public_key == public_key
        # The config of that host now generates from it.
        raw = generate_host_config(HostName("laptop"), config=config, pki=pki)
        assert _parse_yaml(raw)["pki"]["cert"] == pki.export_certificate_pem(serial_number=cert.serial_number).decode()

    def test_explicit_ca_must_be_trusted(self, tmp_path: Path) -> None:
        pki = _make_pki()
        trusted = _issue_ca(pki=pki, name="Trusted CA")
        other = _issue_ca(pki=pki, name="Other CA")
        _, public_key = _keygen(directory=tmp_path, name="laptop")

        with pytest.raises(ConfigFileError, match="not a trusted CA"):
            issue_host_certificate(
                HostName("laptop"),
                config=_network(trusted_ca_serials=[trusted]),
                pki=pki,
                public_key_pem=public_key,
                ca_serial=other,
            )

    def test_explicit_trusted_ca_is_used(self, tmp_path: Path) -> None:
        pki = _make_pki()
        first = _issue_ca(pki=pki, name="First CA")
        second = _issue_ca(pki=pki, name="Second CA")
        _, public_key = _keygen(directory=tmp_path, name="laptop")

        cert = issue_host_certificate(
            HostName("laptop"),
            config=_network(trusted_ca_serials=[first, second]),
            pki=pki,
            public_key_pem=public_key,
            ca_serial=first,
        )

        assert cert.ca_serial_number == first
