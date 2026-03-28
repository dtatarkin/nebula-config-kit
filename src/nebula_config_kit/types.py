"""Enums, type aliases, and constants for nebula-config-kit."""

from enum import StrEnum, auto
from typing import NewType, NotRequired, TypedDict

HostName = NewType("HostName", str)


class FirewallRule(TypedDict):
    """A resolved firewall rule ready for config rendering."""

    port: str | int
    proto: str
    host: NotRequired[str]
    group: NotRequired[str]
    groups: NotRequired[list[str]]


class Protocol(StrEnum):
    ANY = auto()
    TCP = auto()
    UDP = auto()
    ICMP = auto()


class Direction(StrEnum):
    IN = auto()
    OUT = auto()
    ANY = auto()
