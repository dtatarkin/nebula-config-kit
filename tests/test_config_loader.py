"""Tests for configuration file loading."""

from ipaddress import IPv4Network
from pathlib import Path

import pytest

from nebula_config_kit.config_loader import load_config
from nebula_config_kit.exceptions import ConfigFileError


def test_load_config_returns_none_for_missing_file(tmp_path: Path) -> None:
    result = load_config(config_path=tmp_path / "nonexistent.yml")
    assert result is None


def test_load_config_raises_on_empty_file(tmp_path: Path) -> None:
    config_file = tmp_path / "nebula-network.config.yml"
    config_file.write_text("")
    with pytest.raises(ConfigFileError, match="empty"):
        load_config(config_path=config_file)


def test_load_config_loads_valid_file(tmp_path: Path) -> None:
    config_file = tmp_path / "nebula-network.config.yml"
    config_file.write_text("network:\n  cidr: 10.0.0.0/16\n")
    result = load_config(config_path=config_file)
    assert result is not None
    assert result.network is not None
    assert result.network.cidr == IPv4Network("10.0.0.0/16")
