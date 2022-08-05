from typing import Any


################## Security Groups
# Check if the security group ingress rule has public access to the check_ports using the protocol
def check_security_group(ingress_rule: Any, protocol: str, ports: list = []) -> bool:
    public_IPv4 = "0.0.0.0/0"
    public_IPv6 = "::/0"

    # Check for all traffic ingress rules regardless of the protocol
    if ingress_rule["IpProtocol"] == "-1" and (
        (
            "0.0.0.0/0" in str(ingress_rule["IpRanges"])
            or "::/0" in str(ingress_rule["Ipv6Ranges"])
        )
    ):
        return True

    # Check for specific ports in ingress rules
    if "FromPort" in ingress_rule:
        # All ports
        if ingress_rule["FromPort"] == 0 and ingress_rule["ToPort"] == 65535:
            return True

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
        for port in ports:
            if (
                (
                    public_IPv4 in str(ingress_rule["IpRanges"])
                    or public_IPv6 in str(ingress_rule["Ipv6Ranges"])
                )
                and port in ingress_port_range
                and ingress_rule["IpProtocol"] == protocol
            ):
                return True
    return False
