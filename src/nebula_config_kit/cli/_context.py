"""CLI context and pki-kit session factories."""

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum, auto
from pathlib import Path

from pki.backends.nebula.pki import NebulaPki


class OutputFormat(StrEnum):
    TABLE = auto()
    JSON = auto()
    YAML = auto()


@dataclass(frozen=True)
class CliContext:
    config_path: Path
    pki_base_path: Path
    pki_name: str
    sops_args: tuple[str, ...]
    output_format: OutputFormat


@contextmanager
def nebula_pki_session(ctx: CliContext, *, save_state: bool = True) -> Iterator[NebulaPki]:
    """Create a fully-wired NebulaPki with filesystem stores."""
    from pki.backends.nebula.pki import NebulaCertData, NebulaCertificateRequest, NebulaPki
    from pki.certificate_stores.filesystem import FilesystemCertificateStore
    from pki.key_stores.filesystem import FilesystemKeyStore
    from pki.state_stores.filesystem import FilesystemStateStore
    from pki.types import PkiType

    key_store = FilesystemKeyStore(
        ctx.pki_base_path / "keys",
        pki_name=ctx.pki_name,
        sops_args=ctx.sops_args,
    )
    cert_store = FilesystemCertificateStore(
        ctx.pki_base_path / "certs",
        NebulaCertificateRequest,
        NebulaCertData,
        pki_type=PkiType.NEBULA,
        pki_name=ctx.pki_name,
    )
    state_store = FilesystemStateStore(ctx.pki_base_path, pki_name=ctx.pki_name)
    pki_state = state_store.load_state()

    pki = NebulaPki(pki_state=pki_state, key_store=key_store, certificate_store=cert_store)
    yield pki

    if save_state:
        state_store.save_state(pki.export_state())
