import ipaddress
from typing import Any


def check_security_group(
    ingress_rule: Any,
    protocol: str,
    ports: list | None = None,
    any_address: bool = False,
    all_ports: bool = False,
) -> bool:
    """
    Check if the security group ingress rule has public access to the check_ports using the protocol.

    @param ingress_rule: AWS Security Group IpPermissions Ingress Rule
    {
        'FromPort': 123,
        'IpProtocol': 'string',
        'IpRanges': [
            {
                'CidrIp': 'string',
                'Description': 'string'
            },
        ],
        'Ipv6Ranges': [
            {
                'CidrIpv6': 'string',
                'Description': 'string'
            },
        ],
        'ToPort': 123,
    }

    @param protocol: Protocol to check. If -1, all protocols will be checked.

    @param ports: List of ports to check. If not provided all ports will be checked unless all_ports is False. (Default: None)

    @param any_address: If True, only 0.0.0.0/0 or "::/0" will be public and do not search for public addresses. (Default: False)

    @param all_ports: If True, empty ports list will be treated as all ports. (Default: False)

    @return: True if the security group has public access to the check_ports using the protocol
    """
    if ports is None:
        ports = []

    # Check for all traffic ingress rules regardless of the protocol
    if ingress_rule["IpProtocol"] == "-1":
        for ip_ingress_rule in ingress_rule["IpRanges"]:
            if _is_cidr_public(ip_ingress_rule["CidrIp"], any_address):
                return True
        for ip_ingress_rule in ingress_rule["Ipv6Ranges"]:
            if _is_cidr_public(ip_ingress_rule["CidrIpv6"], any_address):
                return True

    if (
        ingress_rule["IpProtocol"] != "-1"
        and protocol != "-1"
        and ingress_rule["IpProtocol"] != protocol
    ):
        return False

    # Check for specific ports in ingress rules
    if "FromPort" in ingress_rule:

        # If the ports are not the same create a covering range.
        # Note range is exclusive of the end value so we add 1 to the ToPort.
        if ingress_rule["FromPort"] != ingress_rule["ToPort"]:
            ingress_port_range = set(
                range(ingress_rule["FromPort"], ingress_rule["ToPort"] + 1)
            )
        else:
            ingress_port_range = {int(ingress_rule["FromPort"])}

        # Combine IPv4 and IPv6 ranges to facilitate a single check loop.
        all_ingress_rules = []
        all_ingress_rules.extend(ingress_rule["IpRanges"])
        all_ingress_rules.extend(ingress_rule["Ipv6Ranges"])

        for ip_ingress_rule in all_ingress_rules:
            # We only check public CIDRs
            if _is_cidr_public(
                ip_ingress_rule.get("CidrIp", ip_ingress_rule.get("CidrIpv6")),
                any_address,
            ):
                for port in ports:
                    if port in ingress_port_range and (
                        ingress_rule["IpProtocol"] == protocol or protocol == "-1"
                    ):
                        # Direct match for a port in the specified port range
                        return True

                # We did not find a specific port for the given protocol for
                # a public cidr so let's see if all the ports are open
                all_ports_open = len(ingress_port_range) == 65536

                # Use the all_ports flag to determine if empty ports should be treated as all ports.
                empty_ports_same_as_all_ports_open = all_ports and not ports

                return all_ports_open or empty_ports_same_as_all_ports_open

    return False


def _is_cidr_public(cidr: str, any_address: bool = False) -> bool:
    """
    Check if an input CIDR is public

    @param cidr: CIDR 10.22.33.44/8

    @param any_address: If True, only 0.0.0.0/0 or "::/0" will be public and do not search for public addresses. (Default: False)
    """
    public_IPv4 = "0.0.0.0/0"
    public_IPv6 = "::/0"
    if cidr in (public_IPv4, public_IPv6):
        return True
    if not any_address:
        return ipaddress.ip_network(cidr).is_global
    return False
