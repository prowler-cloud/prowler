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


def check_if_open_security_group_is_attached_to_instance(
    security_group: Any, vpc_client: Any, port: str
) -> list:
    """
    Check if the security group is attached to any EC2 instance

    Args:
        security_group: AWS Security Group
        vpc_client: VPC Client
        port: Port to check
    Returns:
        list: List of reports for each EC2 instance attached to the security group
    """
    reports = []
    # Check if the security group is attached to any EC2 instance
    for network_interface in security_group.network_interfaces:
        instance_attached = network_interface.attachment.get("InstanceId")
        if instance_attached:
            report = {}
            report["severity"] = "high"
            # Check if the EC2 instance has a public IP
            if not network_interface.association.get("PublicIp"):
                report["details"] = (
                    f"EC2 Instance {instance_attached} has {port} exposed to 0.0.0.0/0 on private ip address {network_interface.private_ip}."
                )
            else:
                report["details"] = (
                    f"EC2 Instance {instance_attached} has {port} exposed to 0.0.0.0/0 on public ip address {network_interface.association.get('PublicIp')}."
                )
                # Check if EC2 instance is in a public subnet
                if vpc_client.vpc_subnets[network_interface.subnet_id].public:
                    report["details"] = (
                        f"EC2 Instance {instance_attached} has {port} exposed to 0.0.0.0/0 on public ip address {network_interface.association.get('PublicIp')} within public subnet {network_interface.subnet_id}."
                    )
                    report["severity"] = "critical"
            report["instance_id"] = instance_attached
            reports.append(report)
    return reports
