"""Output formatting helpers for the CLI."""

import json
from collections.abc import Sequence

from rich.console import Console
from rich.table import Table
from ruamel.yaml import YAML
from ruamel.yaml.compat import StringIO

from nebula_config_kit.cli._context import OutputFormat
from nebula_config_kit.models import HostConfig, LighthouseInfo
from nebula_config_kit.types import HostName


def _hosts_to_records(
    hosts: dict[HostName, HostConfig],
    lighthouses: dict[HostName, LighthouseInfo],
) -> list[dict[str, object]]:
    """Convert hosts into serialisable records."""
    records: list[dict[str, object]] = []
    for name, host in hosts.items():
        records.append(
            {
                "name": str(name),
                "nebula_ip": str(host.nebula_ip),
                "lighthouse": name in lighthouses,
                "relay": host.am_relay,
                "public_endpoints": host.public_endpoints or [],
            }
        )
    return records


def print_hosts_table(
    hosts: dict[HostName, HostConfig],
    *,
    lighthouses: dict[HostName, LighthouseInfo],
    output_format: OutputFormat,
) -> None:
    """Print host list in the requested format."""
    records = _hosts_to_records(hosts, lighthouses)
    console = Console()

    if output_format == OutputFormat.JSON:
        console.print_json(json.dumps(records))
        return

    if output_format == OutputFormat.YAML:
        yaml = YAML()
        stream = StringIO()
        yaml.dump(records, stream)
        console.print(stream.getvalue(), end="")
        return

    # TABLE (default)
    table = Table(show_header=True, header_style="bold")
    table.add_column("Name")
    table.add_column("Nebula IP")
    table.add_column("Lighthouse")
    table.add_column("Relay")
    table.add_column("Public Endpoints")
    for rec in records:
        endpoints = rec["public_endpoints"]
        table.add_row(
            str(rec["name"]),
            str(rec["nebula_ip"]),
            "yes" if rec["lighthouse"] else "",
            "yes" if rec["relay"] else "",
            ", ".join(str(e) for e in endpoints) if isinstance(endpoints, list) and endpoints else "",
        )
    console.print(table)


def print_host_detail(
    record: dict[str, object],
    *,
    output_format: OutputFormat,
) -> None:
    """Print resolved host detail in the requested format."""
    console = Console()

    if output_format == OutputFormat.JSON:
        console.print_json(json.dumps(record))
        return

    if output_format == OutputFormat.YAML:
        yaml = YAML()
        stream = StringIO()
        yaml.dump(record, stream)
        console.print(stream.getvalue(), end="")
        return

    # TABLE (default) — key/value pairs
    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column("Key", style="bold")
    table.add_column("Value")
    for key, value in record.items():
        if isinstance(value, list) and not value:
            continue
        if isinstance(value, list):
            table.add_row(key, _format_list(value))
        elif isinstance(value, bool):
            table.add_row(key, "yes" if value else "no")
        elif value is None:
            continue
        else:
            table.add_row(key, str(value))
    console.print(table)


def _format_list(items: Sequence[object]) -> str:
    """Format a list for table display."""
    if not items:
        return ""
    if isinstance(items[0], dict):
        return "\n".join(", ".join(f"{k}={v}" for k, v in item.items()) for item in items if isinstance(item, dict))
    return ", ".join(str(i) for i in items)
