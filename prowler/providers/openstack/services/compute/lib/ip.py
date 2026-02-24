import ipaddress


def is_public_ip(ip_str: str) -> bool:
    """Check if an IP address is public (globally routable, non-multicast)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_global and not ip.is_multicast
    except ValueError:
        return False
