from typing import Any


################## Network ACLs
# Check if the network acls ingress rule has public access to the check_ports using the protocol
def check_network_acl(entry: Any, protocol: str, port: str, ip_version: str) -> bool:
    # For IPv4
    if ip_version == "IPv4":
        entry_value = "CidrBlock"
        public_ip = "0.0.0.0/0"
    # For IPv6
    elif ip_version == "IPv6":
        entry_value = "Ipv6CidrBlock"
        public_ip = "::/0"

    if (
        entry[entry_value] == public_ip
        and entry["RuleAction"] == "allow"
        and not entry["Egress"]
    ):
        if entry["Protocol"] == "-1" or (
            entry["PortRange"]["From"] == port
            and entry["PortRange"]["To"] == port
            and entry["Protocol"] == protocol
        ):
            return True

    return False
