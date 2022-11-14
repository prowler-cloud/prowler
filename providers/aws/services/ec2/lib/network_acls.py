from typing import Any


# Network ACLs
# Check if the network acls rules has ingress public access to the check_ports using the protocol
def check_network_acl(rules: Any, protocol: str, port: str) -> bool:

    # Spliting IPv6 from IPv4 rules
    rules_IPv6 = list(
        filter(lambda rule: rule.get("CidrBlock") is None and not rule["Egress"], rules)
    )

    # For IPv6
    # Rules must order by RuleNumber
    for rule in sorted(rules_IPv6, key=lambda rule: rule["RuleNumber"]):
        if (
            rule["Ipv6CidrBlock"] == "::/0"
            and rule["RuleAction"] == "deny"
            and (
                rule["Protocol"] == "-1"
                or (
                    rule["Protocol"] == protocol
                    and rule["PortRange"]["From"] <= port <= rule["PortRange"]["To"]
                )
            )
        ):
            # Exist IPv6 deny for this port
            break

        if (
            rule["Ipv6CidrBlock"] == "::/0"
            and rule["RuleAction"] == "allow"
            and (
                rule["Protocol"] == "-1"
                or (
                    rule["Protocol"] == protocol
                    and rule["PortRange"]["From"] <= port <= rule["PortRange"]["To"]
                )
            )
        ):
            # Exist IPv6 allow for this port
            return True

    # There are not IPv6 Public access here

    # Spliting IPv4 from IPv6 rules
    rules_IPv4 = list(
        filter(
            lambda rule: rule.get("Ipv6CidrBlock") is None and not rule["Egress"], rules
        )
    )

    # For IPv4
    # Rules must order by RuleNumber
    for rule in sorted(rules_IPv4, key=lambda rule: rule["RuleNumber"]):
        if (
            rule["CidrBlock"] == "0.0.0.0/0"
            and rule["RuleAction"] == "deny"
            and (
                rule["Protocol"] == "-1"
                or (
                    rule["Protocol"] == protocol
                    and rule["PortRange"]["From"] <= port <= rule["PortRange"]["To"]
                )
            )
        ):

            # Exist IPv4 deny for this port and if exist IPv6 there are not IPv6 Public access here
            return False

        if (
            rule["CidrBlock"] == "0.0.0.0/0"
            and rule["RuleAction"] == "allow"
            and (
                rule["Protocol"] == "-1"
                or (
                    rule["Protocol"] == protocol
                    and rule["PortRange"]["From"] <= port <= rule["PortRange"]["To"]
                )
            )
        ):
            return True

    return False
