"""Network and CIDR utility functions."""

from ipaddress import IPv4Address, IPv4Network


def get_prefix_length(cidr: IPv4Network) -> int:
    """Extract the prefix length from an IPv4 network."""
    return cidr.prefixlen


def make_sign_ip(host_ip: IPv4Address, *, cidr: IPv4Network) -> str:
    """Combine a host IP with the network prefix length for certificate signing."""
    return f"{host_ip}/{cidr.prefixlen}"
