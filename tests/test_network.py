"""Tests for network utility functions."""

from ipaddress import IPv4Address, IPv4Network

from nebula_config_kit.network import get_prefix_length, make_sign_ip


def test_get_prefix_length() -> None:
    assert get_prefix_length(IPv4Network("10.0.0.0/24")) == 24
    assert get_prefix_length(IPv4Network("10.0.0.0/16")) == 16
    assert get_prefix_length(IPv4Network("10.0.0.0/8")) == 8


def test_make_sign_ip() -> None:
    result = make_sign_ip(IPv4Address("10.0.0.1"), cidr=IPv4Network("10.0.0.0/24"))
    assert result == "10.0.0.1/24"


def test_make_sign_ip_different_prefix() -> None:
    result = make_sign_ip(IPv4Address("10.10.5.3"), cidr=IPv4Network("10.10.0.0/16"))
    assert result == "10.10.5.3/16"
