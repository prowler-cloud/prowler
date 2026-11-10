def is_public_cidr(cidr: str) -> bool:
    """Return True when the CIDR represents public/unrestricted access."""
    return cidr in ("0.0.0.0/0", "::/0")


def rule_source_is_public(rule: dict) -> bool:
    """Return whether an ingress rule allows every IPv4 or IPv6 address.

    Alibaba stores those sources on different attributes. A rule open only
    through ipv6_source_cidr_ip is still public.
    """
    for field in ("source_cidr_ip", "ipv6_source_cidr_ip"):
        if is_public_cidr(str(rule.get(field) or "")):
            return True
    return False


def port_in_range(port_range: str, target_port: int) -> bool:
    """
    Check if target_port is within the provided port range.

    Port range examples:
    - "3389/3389" -> single port range
    - "22" -> single port
    - "-1/-1" -> every port, which is how Alibaba Cloud writes an all-port rule
    """
    if not port_range:
        return False

    try:
        port_range = port_range.strip()
        if "/" in port_range:
            from_port, to_port = map(int, port_range.split("/"))
            if from_port == -1 and to_port == -1:
                return True
            return from_port <= target_port <= to_port
        if port_range == "-1":
            return True
        return int(port_range) == target_port
    except (ValueError, AttributeError):
        return False
