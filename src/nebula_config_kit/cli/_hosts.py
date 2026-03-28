"""Hosts CLI subcommands."""

from typing import Annotated

import typer

from nebula_config_kit.cli._context import CliContext

hosts_app = typer.Typer(name="hosts", help="Host management.", no_args_is_help=True)


def _get_ctx(ctx: typer.Context) -> CliContext:
    result: CliContext = ctx.obj
    return result


@hosts_app.command("list")
def list_hosts(ctx: typer.Context) -> None:
    """List all hosts from the network config file."""
    from nebula_config_kit.cli._output import print_hosts_table
    from nebula_config_kit.config_loader import load_config
    from nebula_config_kit.exceptions import ConfigFileError
    from nebula_config_kit.hosts import extract_lighthouses
    from nebula_config_kit.types import HostName

    cli_ctx = _get_ctx(ctx=ctx)
    config = load_config(cli_ctx.config_path)
    if config is None:
        raise ConfigFileError(message="Configuration file not found.")
    if config.hosts is None:
        raise ConfigFileError(message="Required configuration section 'hosts' is missing.")
    hosts = {HostName(k): v for k, v in config.hosts.hosts.items()}
    lighthouses = extract_lighthouses(hosts_config=config.hosts)
    print_hosts_table(hosts, lighthouses=lighthouses, output_format=cli_ctx.output_format)


@hosts_app.command("show")
def show_host(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Host name.")],
) -> None:
    """Show resolved configuration for a specific host."""
    from nebula_config_kit.cli._output import print_host_detail
    from nebula_config_kit.config_loader import load_config
    from nebula_config_kit.exceptions import ConfigFileError
    from nebula_config_kit.orchestration import resolve_host
    from nebula_config_kit.types import HostName

    cli_ctx = _get_ctx(ctx=ctx)
    config = load_config(cli_ctx.config_path)
    if config is None:
        raise ConfigFileError(message="Configuration file not found.")

    resolved = resolve_host(HostName(name), config=config)

    record: dict[str, object] = {
        "name": name,
        "nebula_ip": str(resolved.host.nebula_ip),
        "tun_dev": resolved.overrides.tun_dev,
        "listen_port": resolved.overrides.listen_port,
        "lighthouse": resolved.am_lighthouse,
        "public_endpoints": resolved.host.public_endpoints or [],
        "lighthouses": [
            {"nebula_ip": str(lh.nebula_ip), "endpoints": lh.public_endpoints, "port": lh.listen_port}
            for lh in resolved.lighthouses
        ],
        "relay": resolved.am_relay,
        "relay_ips": [str(ip) for ip in resolved.relay_ips],
        "firewall_inbound": resolved.inbound_rules,
        "firewall_outbound": resolved.outbound_rules,
    }

    print_host_detail(record, output_format=cli_ctx.output_format)
