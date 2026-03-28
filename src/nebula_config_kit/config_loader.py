"""Configuration file loading."""

from pathlib import Path

from pydantic import ValidationError
from ruamel.yaml import YAML

from nebula_config_kit.exceptions import ConfigFileError
from nebula_config_kit.models import NebulaNetworkConfig

DEFAULT_NEBULA_NETWORK_CONFIG_FILENAME = "nebula-network.config.yml"


def load_config(config_path: Path) -> NebulaNetworkConfig | None:
    """Load and validate nebula-network.config.yml.

    Returns None if the file does not exist.
    Raises ConfigFileError if the file exists but is empty or invalid.
    """
    if not config_path.exists():
        return None
    yaml = YAML()
    with config_path.open() as fh:
        data = yaml.load(fh)
    if not data:
        raise ConfigFileError(message=f"{config_path} exists but is empty.")
    try:
        return NebulaNetworkConfig.model_validate(data)
    except ValidationError as exc:
        raise ConfigFileError(message=f"{config_path} is invalid: {exc}") from exc
