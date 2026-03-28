"""Exception hierarchy for nebula-config-kit."""

from nebula_config_kit.types import HostName


class NebulaConfigError(Exception):
    """Base exception for nebula-config-kit."""


class ConfigFileError(NebulaConfigError):
    """Network config file missing or invalid."""

    def __init__(self, message: str = "Network config file is missing or invalid.") -> None:
        super().__init__(message)


class HostNotFoundError(NebulaConfigError):
    """Host not found in configuration."""

    def __init__(self, name: HostName) -> None:
        self.name = name
        super().__init__(f"Host '{name}' not found in configuration.")


class DuplicateIPError(NebulaConfigError):
    """Duplicate nebula IP assignment."""

    def __init__(self, *, ip: str, host_a: HostName, host_b: HostName) -> None:
        self.ip = ip
        self.host_a = host_a
        self.host_b = host_b
        super().__init__(f"Duplicate IP '{ip}': assigned to both '{host_a}' and '{host_b}'.")


class LighthouseConfigError(NebulaConfigError):
    """Invalid lighthouse configuration."""

    def __init__(self, *, name: HostName, message: str) -> None:
        self.name = name
        super().__init__(f"Lighthouse '{name}': {message}")


class ConfigRenderError(NebulaConfigError):
    """Configuration rendering failed."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
