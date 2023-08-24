import ipaddress
from typing import Any


################## Security Groups
def check_security_group(
    ingress_rule: Any, protocol: str, ports: list = [], any_address: bool = False
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

    @param procotol: Protocol to check.


    @param ports: List of ports to check. (Default: [])

    @param any_address: If True, only 0.0.0.0/0 or "::/0" will be public and do not search for public addresses. (Default: False)
    """
    # Check for all traffic ingress rules regardless of the protocol
    if ingress_rule["IpProtocol"] == "-1":
        for ip_ingress_rule in ingress_rule["IpRanges"]:
            if _is_cidr_public(ip_ingress_rule["CidrIp"], any_address):
                return True
        for ip_ingress_rule in ingress_rule["Ipv6Ranges"]:
            if _is_cidr_public(ip_ingress_rule["CidrIpv6"], any_address):
                return True

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
                if ports:
                    for port in ports:
                        if (
                            port in ingress_port_range
                            and ingress_rule["IpProtocol"] == protocol
                        ):
                            return True
                # If no input ports check if all ports are open
                if len(set(ingress_port_range)) == 65536:
                    return True

        # IPv6
        for ip_ingress_rule in ingress_rule["Ipv6Ranges"]:
            if _is_cidr_public(ip_ingress_rule["CidrIpv6"], any_address):
                # If there are input ports to check
                if ports:
                    for port in ports:
                        if (
                            port in ingress_port_range
                            and ingress_rule["IpProtocol"] == protocol
                        ):
                            return True
                # If no input ports check if all ports are open
                if len(set(ingress_port_range)) == 65536:
                    return True

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


def is_changed_default_security_group(security_group: Any) -> bool:
    is_changed_default_security_group = True
    if (
        len(security_group.ingress_rules) <= 1
        and not is_changed_default_security_group_ingress_rule(
            security_group.ingress_rules
        )
    ) and (
        len(security_group.egress_rules) == 1
        and not is_changed_default_security_group_egress_rule(
            security_group.egress_rules
        )
    ):
        is_changed_default_security_group = False
    return is_changed_default_security_group


def is_changed_default_security_group_ingress_rule(ingress_rules: Any) -> bool:
    """
    Default SG ingress rule -> It can be also an empty rule
    {
        "IpProtocol": "-1",
        "IpRanges": [],
        "Ipv6Ranges": [],
        "PrefixListIds": [],
        "UserIdGroupPairs": [
            {
                "GroupId": "sg-XXXXXX",
                "UserId": "XXXXXXXXX"
            }
        ]
    }
    """
    default_sg_has_changed = False

    if ingress_rules and (
        ingress_rules[0]["IpProtocol"] != "-1"
        or ingress_rules[0]["IpRanges"]
        or ingress_rules[0]["Ipv6Ranges"]
        or "FromPort" in ingress_rules
        or "ToPort" in ingress_rules
    ):
        # Check ingress rule conditions
        default_sg_has_changed = True

    return default_sg_has_changed


def is_changed_default_security_group_egress_rule(egress_rules: Any) -> bool:
    """
    Default SG egress rule
    {
        "IpProtocol": "-1",
        "IpRanges": [
            {
                "CidrIp": "0.0.0.0/0"
            }
        ],
        "Ipv6Ranges": [],
        "PrefixListIds": [],
        "UserIdGroupPairs": []
    }
    """
    default_sg_has_changed = False

    if (
        egress_rules[0]["IpProtocol"] != "-1"
        or len(egress_rules[0]["IpRanges"]) > 1
        or "CidrIp" not in egress_rules[0]["IpRanges"][0]
        or (
            "CidrIp" in egress_rules[0]["IpRanges"][0]
            and egress_rules[0]["IpRanges"][0]["CidrIp"] != "0.0.0.0/0"
        )
        or egress_rules[0]["Ipv6Ranges"]
        or "FromPort" in egress_rules[0]
        or "ToPort" in egress_rules[0]
    ):
        default_sg_has_changed = True

    return default_sg_has_changed
