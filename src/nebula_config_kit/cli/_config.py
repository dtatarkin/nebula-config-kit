"""Config generation CLI subcommands."""

from pathlib import Path
from typing import Annotated

import typer

from nebula_config_kit.cli._context import CliContext

config_app = typer.Typer(name="config", help="Configuration generation.", no_args_is_help=True)


def _get_ctx(ctx: typer.Context) -> CliContext:
    result: CliContext = ctx.obj
    return result


@config_app.command("generate")
def generate(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Host name to generate config for.")],
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Path to write the generated config file.")
    ] = None,
    template: Annotated[Path | None, typer.Option(help="Custom Nebula config template.")] = None,
) -> None:
    """Generate Nebula configuration for a host."""
    from nebula_config_kit.cli._context import nebula_pki_session
    from nebula_config_kit.config_loader import load_config
    from nebula_config_kit.exceptions import ConfigFileError
    from nebula_config_kit.orchestration import generate_host_config
    from nebula_config_kit.types import HostName

    cli_ctx = _get_ctx(ctx=ctx)
    config = load_config(cli_ctx.config_path)
    if config is None:
        raise ConfigFileError(message="Configuration file not found.")

    with nebula_pki_session(cli_ctx) as pki:
        config_yaml = generate_host_config(
            HostName(name),
            config=config,
            pki=pki,
            template_path=template,
        )

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(config_yaml)
        print(f"Config written to {output}")
    else:
        print(config_yaml, end="")
