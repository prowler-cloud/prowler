"""Helpers to evaluate OCI security rules and CIDR blocks."""

from typing import Any, Optional

# OCI security lists and network security groups accept both IPv4 and IPv6
# rules, so both "any address" blocks expose a resource to the whole internet.
UNRESTRICTED_CIDRS = ("0.0.0.0/0", "::/0")
UNRESTRICTED_CIDRS_TEXT = " or ".join(UNRESTRICTED_CIDRS)

# Protocol codes used by OCI security rules: IANA "6" is TCP and "all" matches
# every protocol.
TCP_PROTOCOL = "6"
ALL_PROTOCOLS = "all"


def is_public_cidr(cidr: Optional[str]) -> bool:
    """Return True when the CIDR block represents unrestricted internet access."""
    if not cidr:
        return False
    return cidr.strip() in UNRESTRICTED_CIDRS


def rule_allows_tcp_port(rule: dict[str, Any], port: int) -> bool:
    """
    Return True when an OCI security rule allows TCP traffic to the given port.

    The rule exposes the port when it applies to TCP or to every protocol and
    the destination port range covers `port`. OCI omits the destination port
    range when every port is allowed, so a rule without port options exposes
    all TCP ports.

    Args:
        rule: OCI security rule, as produced by `oci.util.to_dict`.
        port: destination TCP port to look for.

    Returns:
        True if the rule allows TCP traffic to `port`.
    """
    protocol = rule.get("protocol")
    if protocol not in (TCP_PROTOCOL, ALL_PROTOCOLS, None, ""):
        return False

    tcp_options = rule.get("tcp_options") or {}
    destination_port_range = tcp_options.get("destination_port_range") or {}

    # No port range means every TCP port is allowed.
    if not destination_port_range:
        return True

    port_min = int(destination_port_range.get("min") or 0)
    port_max = int(destination_port_range.get("max") or 65535)
    return port_min <= port <= port_max


def find_unrestricted_tcp_rule(
    rules: list[dict[str, Any]],
    port: int,
    direction: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    """
    Return the first rule that exposes `port` to any IP address, or None.

    Args:
        rules: OCI security rules, as produced by `oci.util.to_dict`.
        port: destination TCP port to look for.
        direction: when set, only rules with this direction are evaluated. OCI
            security list rules have no direction because they are already split
            into ingress and egress collections.

    Returns:
        The offending rule, or None when no rule exposes the port.
    """
    for rule in rules or []:
        if direction is not None and rule.get("direction") != direction:
            continue
        if not is_public_cidr(rule.get("source")):
            continue
        if rule_allows_tcp_port(rule, port):
            return rule
    return None
