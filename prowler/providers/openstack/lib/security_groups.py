"""Helper utilities for OpenStack security group checks."""

from ipaddress import IPv4Network, IPv6Network, ip_network
from typing import List, Optional

from prowler.providers.openstack.services.network.network_service import (
    SecurityGroupRule,
)


def check_security_group_rule(
    rule: SecurityGroupRule,
    protocol: Optional[str] = None,
    ports: Optional[List[int]] = None,
    any_address: bool = False,
    direction: str = "ingress",
) -> bool:
    """
    Check if a security group rule matches specified criteria.

    Args:
        rule: SecurityGroupRule to check
        protocol: Protocol to match (tcp/udp/icmp/None for any)
        ports: List of ports to check
        any_address: If True, only match 0.0.0.0/0 or ::/0. If False, match public IPs  # noqa: E501
        direction: Direction to check (ingress/egress)

    Returns:
        True if rule matches all criteria, False otherwise
    """
    # Check direction
    if rule.direction != direction:
        return False

    # Check protocol
    if protocol is not None:
        # None protocol means all protocols in OpenStack
        if rule.protocol is not None and rule.protocol != protocol:
            return False

    # Check ports
    if ports is not None and len(ports) > 0:
        # If rule has no port range, it allows all ports (protocol-level rule)
        if rule.port_range_min is None and rule.port_range_max is None:
            # Only match if protocol is None (all protocols/ports)
            if rule.protocol is not None:
                return False
        else:
            # Check if any of the target ports fall within the rule's range
            port_matches = False
            for port in ports:
                if is_port_in_range(
                    port, rule.port_range_min, rule.port_range_max
                ):  # noqa: E501
                    port_matches = True
                    break
            if not port_matches:
                return False

    # Check CIDR - must be publicly accessible
    if rule.remote_ip_prefix:
        if not is_cidr_public(rule.remote_ip_prefix, any_address=any_address):
            return False
    elif rule.remote_group_id:
        # Remote group rules are not public
        return False
    else:
        # No IP prefix or group means all IPs (0.0.0.0/0)
        pass

    return True


def is_port_in_range(
    port: int, range_min: Optional[int], range_max: Optional[int]
) -> bool:
    """
    Check if a port falls within the specified range.

    Args:
        port: Port number to check
        range_min: Minimum port in range (None means no minimum)
        range_max: Maximum port in range (None means no maximum)

    Returns:
        True if port is in range, False otherwise
    """
    if range_min is None and range_max is None:
        return True

    if range_min is None:
        return port <= range_max

    if range_max is None:
        return port >= range_min

    return range_min <= port <= range_max


def is_cidr_public(cidr: str, any_address: bool = False) -> bool:
    """
    Check if a CIDR block represents public/internet access.

    Args:
        cidr: CIDR block to check (e.g., "0.0.0.0/0", "10.0.0.0/8")
        any_address: If True, only match 0.0.0.0/0 or ::/0.
                     If False, match any globally routable IP.

    Returns:
        True if CIDR represents public access, False otherwise
    """
    if not cidr:
        return False

    try:
        network = ip_network(cidr, strict=False)

        if any_address:
            # Only match 0.0.0.0/0 or ::/0
            if isinstance(network, IPv4Network):
                return str(network) == "0.0.0.0/0"
            elif isinstance(network, IPv6Network):
                return str(network) == "::/0"
            return False
        else:
            # Match any globally routable (public) IP
            # is_global means not private, loopback, link-local, etc.
            return network.is_global or str(network) in ["0.0.0.0/0", "::/0"]

    except (ValueError, TypeError):
        return False
