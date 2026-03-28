"""nebula-config CLI — optional command-line interface."""

from typing import Annotated

import typer

from nebula_config_kit.cli._context import CliContext, OutputFormat
from nebula_config_kit.config_loader import DEFAULT_NEBULA_NETWORK_CONFIG_FILENAME
from nebula_config_kit.exceptions import NebulaConfigError

app = typer.Typer(
    name="nebula-config",
    help="Nebula overlay network configuration management.",
    no_args_is_help=True,
)


def _version_callback(value: bool) -> None:
    if value:
        from importlib.metadata import version

        print(f"nebula-config {version('nebula-config-kit')}")
        raise typer.Exit


@app.callback()
def main_callback(
    ctx: typer.Context,
    config: Annotated[
        str,
        typer.Option(envvar="NEBULA_NETWORK_CONFIG", help="Path to network config file."),
    ] = DEFAULT_NEBULA_NETWORK_CONFIG_FILENAME,
    pki_base_path: Annotated[
        str,
        typer.Option(envvar="NEBULA_CONFIG_KIT_PKI_PATH", help="Root directory for pki-kit stores."),
    ] = ".",
    pki_name: Annotated[
        str,
        typer.Option(envvar="NEBULA_CONFIG_KIT_PKI_NAME", help="PKI instance name."),
    ] = "default",
    sops_args: Annotated[
        str | None,
        typer.Option(envvar="NEBULA_CONFIG_KIT_SOPS_ARGS", help="Extra SOPS arguments (space-separated)."),
    ] = None,
    output_format: Annotated[
        OutputFormat,
        typer.Option("--output-format", "-f", envvar="NEBULA_CONFIG_KIT_OUTPUT_FORMAT", help="Output format."),
    ] = OutputFormat.TABLE,
    _version: Annotated[
        bool | None,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version and exit."),
    ] = None,
) -> None:
    """Nebula overlay network configuration management."""
    from pathlib import Path

    ctx.obj = CliContext(
        config_path=Path(config),
        pki_base_path=Path(pki_base_path),
        pki_name=pki_name,
        sops_args=tuple(sops_args.split()) if sops_args else (),
        output_format=output_format,
    )


# Register subcommand groups (import after app is defined to avoid circular imports)
from nebula_config_kit.cli._config import config_app  # noqa: E402
from nebula_config_kit.cli._hosts import hosts_app  # noqa: E402

app.add_typer(config_app)
app.add_typer(hosts_app)


def main() -> None:
    """Entry point for the nebula-config CLI."""
    try:
        app()
    except NebulaConfigError as exc:
        from rich.console import Console

        Console(stderr=True).print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from None
