def is_public_cidr(cidr: str) -> bool:
    """Return True when the CIDR represents public/unrestricted access."""
    return cidr in ("0.0.0.0/0", "::/0")


def port_in_range(port_range: str, target_port: int) -> bool:
    """
    Check if target_port is within the provided port range.

    Port range examples:
    - "3389/3389" -> single port range
    - "22" -> single port
    """
    if not port_range:
        return False

    try:
        if "/" in port_range:
            from_port, to_port = map(int, port_range.split("/"))
            return from_port <= target_port <= to_port
        return int(port_range) == target_port
    except (ValueError, AttributeError):
        return False
