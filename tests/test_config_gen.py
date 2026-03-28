"""Tests for config_gen.py — ruamel.yaml-based Nebula config generation."""

from datetime import UTC, datetime
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any

import pytest
from ruamel.yaml import YAML
from ruamel.yaml.compat import StringIO

from nebula_config_kit.config_gen import DEFAULT_INBOUND_RULES, DEFAULT_OUTBOUND_RULES, render_host_config
from nebula_config_kit.models import LighthouseInfo

CA_PEM = "-----BEGIN NEBULA CERTIFICATE V2-----\nca_data\n-----END NEBULA CERTIFICATE V2-----"
CERT_PEM = "-----BEGIN NEBULA CERTIFICATE V2-----\ncert_data\n-----END NEBULA CERTIFICATE V2-----"
KEY_PEM = "-----BEGIN NEBULA X25519 PRIVATE KEY-----\nkey_data\n-----END NEBULA X25519 PRIVATE KEY-----"


def _parse_yaml(text: str) -> dict[str, Any]:
    yaml = YAML()
    result: dict[str, Any] = yaml.load(stream=StringIO(text))
    return result


def _render_lighthouse(**kwargs: Any) -> str:
    defaults: dict[str, Any] = {
        "ca_cert_pem": CA_PEM,
        "host_cert_pem": CERT_PEM,
        "host_key_pem": KEY_PEM,
        "lighthouses": [],
        "am_lighthouse": True,
        "tun_dev": "nebula",
        "listen_port": 44600,
        "am_relay": True,
    }
    defaults.update(kwargs)
    return render_host_config(**defaults)


def _render_client(**kwargs: Any) -> str:
    defaults: dict[str, Any] = {
        "ca_cert_pem": CA_PEM,
        "host_cert_pem": CERT_PEM,
        "host_key_pem": KEY_PEM,
        "lighthouses": [
            LighthouseInfo(
                nebula_ip=IPv4Address("10.46.0.1"),
                public_endpoints=["1.2.3.4"],
                listen_port=44600,
            ),
        ],
        "am_lighthouse": False,
        "tun_dev": "nebula",
        "listen_port": None,
        "am_relay": False,
    }
    defaults.update(kwargs)
    return render_host_config(**defaults)


class TestBasicStructure:
    def test_top_level_keys_present(self) -> None:
        result = _parse_yaml(_render_lighthouse())
        # Template defines section order; check key sections exist
        assert "pki" in result
        assert "static_host_map" in result
        assert "lighthouse" in result
        assert "listen" in result
        assert "firewall" in result

    def test_top_level_keys_client(self) -> None:
        result = _parse_yaml(_render_client())
        assert "relay" in result
        assert result["relay"]["am_relay"] is False


class TestPki:
    def test_pem_blocks_preserved(self) -> None:
        result = _parse_yaml(_render_lighthouse())
        pki = result["pki"]
        assert "ca_data" in pki["ca"]
        assert "cert_data" in pki["cert"]
        assert "key_data" in pki["key"]

    def test_cert_info_comments_in_output(self) -> None:
        ca_info: dict[str, object] = {
            "name": "Nebula CA",
            "fingerprint": "abc123",
            "not_before": datetime(2026, 3, 21, tzinfo=UTC),
            "not_after": datetime(2036, 3, 21, tzinfo=UTC),
            "is_ca": True,
            "groups": [],
            "networks": [],
            "unsafe_networks": [],
            "curve": "25519",
        }
        host_info: dict[str, object] = {
            "name": "host1",
            "fingerprint": "def456",
            "not_before": datetime(2026, 3, 21, tzinfo=UTC),
            "not_after": datetime(2027, 3, 21, tzinfo=UTC),
            "is_ca": False,
            "groups": ["admin", "server"],
            "networks": ["10.46.0.2/16"],
            "unsafe_networks": [],
            "curve": "25519",
        }
        raw = _render_lighthouse(ca_cert_info=ca_info, host_cert_info=host_info)
        assert "name: Nebula CA" in raw
        assert "fingerprint: abc123" in raw
        assert "not_after: 2036-03-21T00:00:00+00:00" in raw
        assert "name: host1" in raw
        assert "fingerprint: def456" in raw
        assert "groups: admin, server" in raw
        assert "networks: 10.46.0.2/16" in raw

    def test_no_cert_info_comments_when_none(self) -> None:
        raw = _render_lighthouse(ca_cert_info=None, host_cert_info=None)
        assert "fingerprint:" not in raw

    def test_blocklist_included(self) -> None:
        result = _parse_yaml(_render_lighthouse(blocklist=["abc123"]))
        assert "abc123" in result["pki"]["blocklist"]

    def test_blocklist_empty_from_template(self) -> None:
        result = _parse_yaml(_render_lighthouse())
        # Template has `blocklist: []`, preserved when no blocklist passed
        assert result["pki"]["blocklist"] == []


class TestStaticHostMap:
    def test_empty_for_lighthouse(self) -> None:
        result = _parse_yaml(_render_lighthouse())
        shm = result["static_host_map"]
        assert shm == {} or shm is None

    def test_populated_for_client(self) -> None:
        result = _parse_yaml(_render_client())
        shm = result["static_host_map"]
        assert "10.46.0.1" in shm
        assert shm["10.46.0.1"] == ["1.2.3.4:44600"]

    def test_multiple_endpoints(self) -> None:
        result = _parse_yaml(
            _render_client(
                lighthouses=[
                    LighthouseInfo(
                        nebula_ip=IPv4Address("10.46.0.1"),
                        public_endpoints=["1.2.3.4", "5.6.7.8"],
                        listen_port=4242,
                    ),
                ],
            )
        )
        shm = result["static_host_map"]
        assert shm["10.46.0.1"] == ["1.2.3.4:4242", "5.6.7.8:4242"]


class TestLighthouse:
    def test_lighthouse_mode(self) -> None:
        result = _parse_yaml(_render_lighthouse())
        lh = result["lighthouse"]
        assert lh["am_lighthouse"] is True
        assert lh["serve_dns"] is True
        assert lh["interval"] == 60
        assert "hosts" not in lh

    def test_client_mode(self) -> None:
        result = _parse_yaml(_render_client())
        lh = result["lighthouse"]
        assert lh["am_lighthouse"] is False
        assert "serve_dns" not in lh
        assert "dns" not in lh
        assert lh["hosts"] == ["10.46.0.1"]
        assert lh["interval"] == 60


class TestListen:
    def test_listen_with_port(self) -> None:
        result = _parse_yaml(_render_lighthouse(listen_port=44600))
        listen = result["listen"]
        assert listen["port"] == 44600

    def test_listen_port_omitted_when_none(self) -> None:
        result = _parse_yaml(_render_client(listen_port=None))
        listen = result["listen"]
        assert "port" not in listen


class TestRelay:
    def test_relay_present_when_am_relay(self) -> None:
        result = _parse_yaml(_render_lighthouse(am_relay=True, relays=[]))
        assert "relay" in result
        assert result["relay"]["am_relay"] is True
        assert result["relay"]["use_relays"] is True

    def test_relay_defaults_when_not_needed(self) -> None:
        result = _parse_yaml(_render_client(am_relay=False, relays=[]))
        assert result["relay"]["am_relay"] is False
        assert "relays" not in result["relay"]

    def test_relay_with_relays_list(self) -> None:
        result = _parse_yaml(_render_client(relays=["10.46.0.1"]))
        relay = result["relay"]
        assert relay["relays"] == ["10.46.0.1"]
        assert relay["am_relay"] is False
        assert relay["use_relays"] is True


class TestFirewall:
    def test_default_rules(self) -> None:
        result = _parse_yaml(_render_lighthouse())
        fw = result["firewall"]
        assert fw["outbound"] == DEFAULT_OUTBOUND_RULES
        assert fw["inbound"] == DEFAULT_INBOUND_RULES

    def test_custom_rules(self) -> None:
        custom_inbound = [{"port": 53, "proto": "udp", "host": "any"}]
        custom_outbound = [{"port": "any", "proto": "any", "host": "any"}]
        result = _parse_yaml(
            _render_lighthouse(
                inbound_rules=custom_inbound,
                outbound_rules=custom_outbound,
            )
        )
        fw = result["firewall"]
        assert fw["inbound"] == custom_inbound
        assert fw["outbound"] == custom_outbound

    def test_firewall_static_values(self) -> None:
        result = _parse_yaml(_render_lighthouse())
        fw = result["firewall"]
        assert fw["outbound_action"] == "drop"
        assert fw["inbound_action"] == "drop"
        assert fw["conntrack"]["tcp_timeout"] == "12m"
        assert fw["conntrack"]["udp_timeout"] == "3m"
        assert fw["conntrack"]["default_timeout"] == "10m"

    def test_group_rules(self) -> None:
        rules = [{"port": "any", "proto": "any", "group": "admin"}]
        result = _parse_yaml(_render_lighthouse(inbound_rules=rules))
        assert result["firewall"]["inbound"][0]["group"] == "admin"


class TestStaticSections:
    def test_punchy(self) -> None:
        result = _parse_yaml(_render_lighthouse())
        p = result["punchy"]
        assert p["punch"] is True

    def test_tun(self) -> None:
        result = _parse_yaml(_render_lighthouse(tun_dev="nebula"))
        t = result["tun"]
        assert t["disabled"] is False
        assert t["dev"] == "nebula"
        assert t["drop_local_broadcast"] is False
        assert t["drop_multicast"] is False
        assert t["tx_queue"] == 500
        assert t["mtu"] == 1300

    def test_logging(self) -> None:
        result = _parse_yaml(_render_lighthouse())
        log = result["logging"]
        assert log["level"] == "info"
        assert log["format"] == "text"


class TestComments:
    def test_file_header_comment(self) -> None:
        raw = _render_lighthouse()
        assert "nebula example configuration file" in raw

    def test_section_comments_present(self) -> None:
        raw = _render_lighthouse()
        assert "PKI defines the location of credentials" in raw
        assert "static host map defines a set of hosts" in raw
        assert "am_lighthouse is used to enable lighthouse" in raw
        assert "Port Nebula will be listening on" in raw
        assert "Configure the private interface" in raw
        assert "Configure logging level" in raw
        assert "Nebula security group configuration" in raw

    @pytest.mark.parametrize("render_fn", [_render_lighthouse, _render_client])
    def test_output_is_valid_yaml(self, render_fn: Any) -> None:
        raw = render_fn()
        parsed = _parse_yaml(raw)
        assert isinstance(parsed, dict)
        assert "pki" in parsed


class TestCustomTemplate:
    def test_custom_template_preserves_comments(self, tmp_path: Path) -> None:
        template = tmp_path / "custom.yml"
        template.write_text(
            "# My custom comment\n"
            "pki:\n"
            "  ca: placeholder\n"
            "  cert: placeholder\n"
            "  key: placeholder\n"
            "static_host_map:\n"
            "lighthouse:\n"
            "  am_lighthouse: false\n"
            "  interval: 60\n"
            "  hosts: []\n"
            "listen:\n"
            '  host: "0.0.0.0"\n'
            "  port: 4242\n"
            "tun:\n"
            "  dev: nebula1\n"
            "firewall:\n"
            "  outbound: []\n"
            "  inbound: []\n"
        )
        raw = render_host_config(
            ca_cert_pem=CA_PEM,
            host_cert_pem=CERT_PEM,
            host_key_pem=KEY_PEM,
            lighthouses=[],
            am_lighthouse=True,
            listen_port=4242,
            template_path=template,
        )
        assert "My custom comment" in raw
        parsed = _parse_yaml(raw)
        assert "ca_data" in parsed["pki"]["ca"]

    def test_custom_template_without_relay(self, tmp_path: Path) -> None:
        template = tmp_path / "minimal.yml"
        template.write_text(
            "pki:\n"
            "  ca: placeholder\n"
            "  cert: placeholder\n"
            "  key: placeholder\n"
            "static_host_map:\n"
            "lighthouse:\n"
            "  am_lighthouse: false\n"
            "  interval: 60\n"
            "  hosts: []\n"
            "listen:\n"
            '  host: "0.0.0.0"\n'
            "tun:\n"
            "  dev: nebula1\n"
            "firewall:\n"
            "  outbound: []\n"
            "  inbound: []\n"
        )
        raw = render_host_config(
            ca_cert_pem=CA_PEM,
            host_cert_pem=CERT_PEM,
            host_key_pem=KEY_PEM,
            lighthouses=[],
            am_lighthouse=True,
            am_relay=True,
            template_path=template,
        )
        parsed = _parse_yaml(raw)
        # relay section created with dynamic values even if not in template
        assert parsed["relay"]["am_relay"] is True

    def test_empty_template(self, tmp_path: Path) -> None:
        template = tmp_path / "empty.yml"
        template.write_text("")
        raw = render_host_config(
            ca_cert_pem=CA_PEM,
            host_cert_pem=CERT_PEM,
            host_key_pem=KEY_PEM,
            lighthouses=[],
            am_lighthouse=True,
            listen_port=4242,
            template_path=template,
        )
        parsed = _parse_yaml(raw)
        assert "ca_data" in parsed["pki"]["ca"]
        assert parsed["lighthouse"]["am_lighthouse"] is True
