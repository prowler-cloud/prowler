import ipaddress
from typing import Any


def check_security_group(
    ingress_rule: Any,
    protocol: str,
    ports: list | None = None,
    any_address: bool = False,
) -> bool:
    """
    Check if the security group ingress rule has public access to the check_ports using the protocol

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

    @param ports: List of ports to check. If None or an empty list, any port will be checked. (Default: None)

    @param any_address: If True, only 0.0.0.0/0 or "::/0" will be public and do not search for public addresses. (Default: False)

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
        # If there is a port range
        if ingress_rule["FromPort"] != ingress_rule["ToPort"]:
            # Calculate port range, adding 1
            diff = (ingress_rule["ToPort"] - ingress_rule["FromPort"]) + 1
            ingress_port_range = []
            for x in range(diff):
                ingress_port_range.append(int(ingress_rule["FromPort"]) + x)
        # If FromPort and ToPort are the same
        else:
            ingress_port_range = []
            ingress_port_range.append(int(ingress_rule["FromPort"]))

        # Test Security Group
        # IPv4
        for ip_ingress_rule in ingress_rule["IpRanges"]:
            if _is_cidr_public(ip_ingress_rule["CidrIp"], any_address):
                # If there are input ports to check
                for port in ports:
                    if (
                        port in ingress_port_range
                        and ingress_rule["IpProtocol"] == protocol
                    ):
                        return True

                # We did not find a specific port for the given protocol for
                # a public cidr so let's see if all the ports are open
                all_ports_open = len(set(ingress_port_range)) == 65536

                # At this point we might have all ports open, return True
                # otherwise we didn't have any ports to check yet we have a public cidr
                # so that is the same as all ports open for our purposes
                ports_are_empty = not ports
                return all_ports_open or ports_are_empty

        # IPv6
        for ip_ingress_rule in ingress_rule["Ipv6Ranges"]:
            if _is_cidr_public(ip_ingress_rule["CidrIpv6"], any_address):
                # If there are input ports to check
                for port in ports:
                    if (
                        port in ingress_port_range
                        and ingress_rule["IpProtocol"] == protocol
                    ):
                        return True
                # We did not find a specific port for the given protocol for
                # a public cidr so let's see if all the ports are open
                all_ports_open = len(set(ingress_port_range)) == 65536

                # At this point we might have all ports open, return True
                # otherwise we didn't have any ports to check yet we have a public cidr
                # so that is the same as all ports open for our purposes
                ports_are_empty = not ports
                return all_ports_open or ports_are_empty

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
