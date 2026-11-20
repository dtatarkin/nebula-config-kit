"""Certificate CLI subcommands."""

from pathlib import Path
from typing import Annotated

import typer

from nebula_config_kit.cli._context import CliContext

certs_app = typer.Typer(name="certs", help="Host certificates.", no_args_is_help=True)


def _get_ctx(ctx: typer.Context) -> CliContext:
    result: CliContext = ctx.obj
    return result


@certs_app.command("issue")
def issue(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Host name.")],
    public_key: Annotated[
        Path,
        typer.Option(help="The host's public key (`nebula-cert keygen -out-pub`)."),
    ],
    ca_serial: Annotated[
        int | None,
        typer.Option(help="Signing CA. Default: the last of certs.trusted_ca_serials, else the current CA."),
    ] = None,
    ca_key: Annotated[
        Path | None,
        typer.Option(
            envvar="PKI_NEBULA_CA_KEY",
            help="File holding the signing CA's private key, read instead of the key store.",
        ),
    ] = None,
) -> None:
    """Sign a host's public key with the IP, groups and duration the network config gives it.

    The host keeps its private key; only the certificate is stored.
    """
    from pki.exceptions import PkiError

    from nebula_config_kit.cli._context import nebula_pki_session
    from nebula_config_kit.config_loader import load_config
    from nebula_config_kit.exceptions import ConfigFileError
    from nebula_config_kit.orchestration import issue_host_certificate
    from nebula_config_kit.types import HostName

    cli_ctx = _get_ctx(ctx=ctx)
    config = load_config(cli_ctx.config_path)
    if config is None:
        raise ConfigFileError(message="Configuration file not found.")

    try:
        public_key_pem = public_key.read_text()
    except OSError as exc:
        raise ConfigFileError(message=f"Cannot read public key {public_key}: {exc.strerror}") from exc

    try:
        with nebula_pki_session(cli_ctx, ca_key_path=ca_key) as pki:
            cert = issue_host_certificate(
                HostName(name),
                config=config,
                pki=pki,
                public_key_pem=public_key_pem,
                ca_serial=ca_serial,
            )
    except PkiError as exc:
        from rich.console import Console

        Console(stderr=True).print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from None

    print(f"Issued certificate {cert.serial_number} for {name} (CA {cert.ca_serial_number}, until {cert.not_after})")
