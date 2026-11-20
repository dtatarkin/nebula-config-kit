"""Tests for the `certs issue` CLI command: signing a host's public key with an external CA key."""

from __future__ import annotations

import shutil
import subprocess
from datetime import timedelta
from typing import TYPE_CHECKING

import pytest
from pki.backends.nebula.pki import NebulaCertData, NebulaCertificateRequest, NebulaPki
from pki.certificate_stores.filesystem import FilesystemCertificateStore
from pki.key_stores import InMemoryKeyStore
from pki.models import Subject
from pki.state_stores.filesystem import FilesystemStateStore
from pki.types import CertificateStatus, KeyAlgorithm, PkiType
from typer.testing import CliRunner

from nebula_config_kit.cli import app

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.skipif(condition=shutil.which("nebula-cert") is None, reason="nebula-cert not found on PATH")

_NETWORK = """\
network:
  cidr: 10.10.0.0/16
certs:
  ca_name: Test CA
  trusted_ca_serials: [{ca}]
hosts:
  defaults:
    listen_port: 4242
    key_path: ~/.config/mesh/{{name}}.key
  hosts:
    lighthouse1:
      nebula_ip: 10.10.0.1
      public_endpoints: ["203.0.113.10"]
    laptop:
      nebula_ip: 10.10.1.1
firewall:
  host_groups:
    laptop: [developer]
"""


def _cert_store(*, base: Path) -> FilesystemCertificateStore[NebulaCertificateRequest, NebulaCertData]:
    return FilesystemCertificateStore(
        base_dir=base / "certs",
        cert_request_type=NebulaCertificateRequest,
        cert_data_type=NebulaCertData,
        pki_type=PkiType.NEBULA,
    )


def test_issue_with_ca_key_from_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base = tmp_path / "pki"
    holder = InMemoryKeyStore()
    pki = NebulaPki(key_store=holder, certificate_store=_cert_store(base=base))
    ca = pki.issue_certificate(
        request=NebulaCertificateRequest(
            subject=Subject(common_name="Test CA"),
            duration=timedelta(days=3650),
            key_algorithm=KeyAlgorithm.ED25519,
            is_ca=True,
        ),
    )
    FilesystemStateStore(base_dir=base).save_state(state=pki.export_state())
    ca_key = holder.get_key(serial_number=ca.serial_number)
    assert ca_key is not None
    (tmp_path / "ca.key").write_bytes(ca_key)
    (tmp_path / "network.yml").write_text(_NETWORK.format(ca=ca.serial_number))
    subprocess.run(
        ["nebula-cert", "keygen", "-out-key", str(tmp_path / "laptop.key"), "-out-pub", str(tmp_path / "laptop.pub")],
        check=True,
        capture_output=True,
    )
    monkeypatch.setenv("PKI_NEBULA_CA_KEY", str(tmp_path / "ca.key"))

    result = CliRunner().invoke(
        app,
        [
            "--config",
            str(tmp_path / "network.yml"),
            "--pki-base-path",
            str(base),
            "certs",
            "issue",
            "laptop",
            "--public-key",
            str(tmp_path / "laptop.pub"),
        ],
    )

    assert result.exit_code == 0, result.output
    loaded = NebulaPki(
        pki_state=FilesystemStateStore(base_dir=base).load_state(),
        certificate_store=_cert_store(base=base),
    )
    hosts = loaded.list_certificates(status=CertificateStatus.ISSUED, common_name="laptop")
    assert len(hosts) == 1
    assert hosts[0].request.groups == ["developer"]
    assert hosts[0].request.ip == "10.10.1.1/16"
    for path in base.rglob("*"):
        if path.is_file():
            assert "PRIVATE KEY" not in path.read_text(), path


def test_issue_without_ca_key_fails(tmp_path: Path) -> None:
    base = tmp_path / "pki"
    pki = NebulaPki(key_store=InMemoryKeyStore(), certificate_store=_cert_store(base=base))
    ca = pki.issue_certificate(
        request=NebulaCertificateRequest(
            subject=Subject(common_name="Test CA"),
            duration=timedelta(days=3650),
            key_algorithm=KeyAlgorithm.ED25519,
            is_ca=True,
        ),
    )
    FilesystemStateStore(base_dir=base).save_state(state=pki.export_state())
    (tmp_path / "network.yml").write_text(_NETWORK.format(ca=ca.serial_number))
    subprocess.run(
        ["nebula-cert", "keygen", "-out-key", str(tmp_path / "laptop.key"), "-out-pub", str(tmp_path / "laptop.pub")],
        check=True,
        capture_output=True,
    )

    result = CliRunner().invoke(
        app,
        [
            "--config",
            str(tmp_path / "network.yml"),
            "--pki-base-path",
            str(base),
            "certs",
            "issue",
            "laptop",
            "--public-key",
            str(tmp_path / "laptop.pub"),
        ],
        env={"PKI_NEBULA_CA_KEY": ""},
    )

    assert result.exit_code == 1
    assert "Key not found" in result.output
