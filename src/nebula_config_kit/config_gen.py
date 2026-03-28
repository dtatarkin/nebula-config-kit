"""Nebula configuration generation via ruamel.yaml template loading."""

from datetime import datetime
from pathlib import Path

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq
from ruamel.yaml.compat import StringIO
from ruamel.yaml.scalarstring import DoubleQuotedScalarString, LiteralScalarString

from nebula_config_kit.models import LighthouseInfo
from nebula_config_kit.types import FirewallRule

BUILTIN_TEMPLATE = Path(__file__).parent / "nebula.config.template.yml"

DEFAULT_OUTBOUND_RULES: list[FirewallRule] = [
    {"port": "any", "proto": "any", "host": "any"},
]
DEFAULT_INBOUND_RULES: list[FirewallRule] = [
    {"port": "any", "proto": "icmp", "host": "any"},
]


def _rule_to_map(rule: FirewallRule) -> CommentedMap:
    """Convert a firewall rule dict to a CommentedMap preserving key order."""
    m = CommentedMap()
    m["port"] = rule["port"]
    m["proto"] = rule["proto"]
    if "host" in rule:
        m["host"] = rule["host"]
    if "group" in rule:
        m["group"] = rule["group"]
    if "groups" in rule:
        m["groups"] = rule["groups"]
    return m


def _format_cert_info(info: dict[str, object]) -> str:
    """Format certificate info dict as a multi-line comment string."""
    lines: list[str] = []
    for key, value in info.items():
        if isinstance(value, list):
            if value:
                lines.append(f"{key}: {', '.join(str(v) for v in value)}")
        elif isinstance(value, datetime):
            lines.append(f"{key}: {value.isoformat()}")
        else:
            lines.append(f"{key}: {value}")
    return "\n".join(lines)


def _apply_pki(
    cfg: CommentedMap,
    *,
    ca_cert_pem: str,
    host_cert_pem: str,
    host_key_pem: str,
    blocklist: list[str],
    ca_cert_info: dict[str, object] | None,
    host_cert_info: dict[str, object] | None,
) -> None:
    """Override PKI certificate data and add cert info comments."""
    if "pki" not in cfg:
        cfg["pki"] = CommentedMap()
    pki: CommentedMap = cfg["pki"]

    pki["ca"] = LiteralScalarString(ca_cert_pem.strip() + "\n")
    pki["cert"] = LiteralScalarString(host_cert_pem.strip() + "\n")
    pki["key"] = LiteralScalarString(host_key_pem.strip() + "\n")

    if ca_cert_info is not None:
        pki.yaml_set_comment_before_after_key("ca", before=_format_cert_info(info=ca_cert_info), indent=2)

    if host_cert_info is not None:
        pki.yaml_set_comment_before_after_key("cert", before=_format_cert_info(info=host_cert_info), indent=2)

    if blocklist:
        pki["blocklist"] = CommentedSeq(blocklist)


def _apply_static_host_map(
    cfg: CommentedMap,
    *,
    lighthouses: list[LighthouseInfo],
) -> None:
    """Populate static_host_map with lighthouse endpoint mappings."""
    shm = CommentedMap()
    for lh in lighthouses:
        endpoints = CommentedSeq([DoubleQuotedScalarString(f"{ep}:{lh.listen_port}") for ep in lh.public_endpoints])
        shm[DoubleQuotedScalarString(str(lh.nebula_ip))] = endpoints
    cfg["static_host_map"] = shm


def _apply_lighthouse(
    cfg: CommentedMap,
    *,
    am_lighthouse: bool,
    lighthouses: list[LighthouseInfo],
) -> None:
    """Set lighthouse mode and configure hosts/dns accordingly."""
    if "lighthouse" not in cfg:
        cfg["lighthouse"] = CommentedMap()
    lh: CommentedMap = cfg["lighthouse"]
    lh["am_lighthouse"] = am_lighthouse

    if am_lighthouse:
        # Lighthouse: enable DNS, remove hosts list
        if "serve_dns" not in lh:
            lh["serve_dns"] = True
        if "dns" not in lh:
            dns = CommentedMap()
            dns["host"] = "0.0.0.0"  # noqa: S104
            dns["port"] = 53
            lh["dns"] = dns
        if "hosts" in lh:
            del lh["hosts"]
    else:
        # Client: set hosts list, remove serve_dns/dns
        hosts = CommentedSeq([DoubleQuotedScalarString(str(lighthouse.nebula_ip)) for lighthouse in lighthouses])
        lh["hosts"] = hosts
        if "serve_dns" in lh:
            del lh["serve_dns"]
        if "dns" in lh:
            del lh["dns"]


def _apply_listen(
    cfg: CommentedMap,
    *,
    listen_port: int | None,
) -> None:
    """Set listen port if configured."""
    if "listen" not in cfg:
        cfg["listen"] = CommentedMap()
    listen: CommentedMap = cfg["listen"]
    if listen_port is not None:
        listen["port"] = listen_port
    elif "port" in listen:
        del listen["port"]


def _apply_relay(
    cfg: CommentedMap,
    *,
    am_relay: bool,
    relays: list[str],
) -> None:
    """Set relay configuration."""
    if "relay" not in cfg:
        cfg["relay"] = CommentedMap()
    relay: CommentedMap = cfg["relay"]
    relay["am_relay"] = am_relay
    if relays:
        relay["relays"] = CommentedSeq([DoubleQuotedScalarString(ip) for ip in relays])
    elif "relays" in relay:
        del relay["relays"]


def _apply_tun(
    cfg: CommentedMap,
    *,
    tun_dev: str,
) -> None:
    """Set tun device name."""
    if "tun" not in cfg:
        cfg["tun"] = CommentedMap()
    tun: CommentedMap = cfg["tun"]
    tun["dev"] = tun_dev


def _apply_firewall(
    cfg: CommentedMap,
    *,
    inbound_rules: list[FirewallRule],
    outbound_rules: list[FirewallRule],
) -> None:
    """Override firewall rules."""
    if "firewall" not in cfg:
        cfg["firewall"] = CommentedMap()
    fw: CommentedMap = cfg["firewall"]
    fw["outbound"] = CommentedSeq([_rule_to_map(rule=r) for r in outbound_rules])
    fw["inbound"] = CommentedSeq([_rule_to_map(rule=r) for r in inbound_rules])


def render_host_config(
    *,
    ca_cert_pem: str,
    host_cert_pem: str,
    host_key_pem: str,
    lighthouses: list[LighthouseInfo],
    am_lighthouse: bool = False,
    tun_dev: str = "nebula1",
    listen_port: int | None = None,
    inbound_rules: list[FirewallRule] | None = None,
    outbound_rules: list[FirewallRule] | None = None,
    blocklist: list[str] | None = None,
    am_relay: bool = False,
    relays: list[str] | None = None,
    ca_cert_info: dict[str, object] | None = None,
    host_cert_info: dict[str, object] | None = None,
    template_path: Path | None = None,
) -> str:
    """Render a complete Nebula host configuration as YAML with comments.

    Loads a YAML template (user-provided or built-in), overrides dynamic values,
    and returns the result as a string with comments preserved.
    """
    yaml = YAML()
    yaml.preserve_quotes = True
    source = template_path if template_path is not None else BUILTIN_TEMPLATE
    with source.open() as fh:
        loaded = yaml.load(stream=fh)
    cfg: CommentedMap = loaded if loaded is not None else CommentedMap()

    _apply_pki(
        cfg,
        ca_cert_pem=ca_cert_pem,
        host_cert_pem=host_cert_pem,
        host_key_pem=host_key_pem,
        blocklist=blocklist or [],
        ca_cert_info=ca_cert_info,
        host_cert_info=host_cert_info,
    )
    _apply_static_host_map(cfg, lighthouses=lighthouses)
    _apply_lighthouse(cfg, am_lighthouse=am_lighthouse, lighthouses=lighthouses)
    _apply_listen(cfg, listen_port=listen_port)
    _apply_relay(cfg, am_relay=am_relay, relays=relays or [])
    _apply_tun(cfg, tun_dev=tun_dev)
    _apply_firewall(
        cfg,
        inbound_rules=inbound_rules if inbound_rules is not None else DEFAULT_INBOUND_RULES,
        outbound_rules=outbound_rules if outbound_rules is not None else DEFAULT_OUTBOUND_RULES,
    )

    stream = StringIO()
    yaml.dump(data=cfg, stream=stream)
    result: str = stream.getvalue()
    return result
