"""Check Ensure no network security groups allow ingress from 0.0.0.0/0 to port 3389."""

from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.network.network_client import network_client


class network_security_group_ingress_from_internet_to_rdp_port(Check):
    """Check Ensure no network security groups allow ingress from 0.0.0.0/0 to port 3389."""

    def execute(self) -> Check_Report_OCI:
        """Execute the network_security_group_ingress_from_internet_to_rdp_port check."""
        findings = []

        for nsg in network_client.network_security_groups:
            report = Check_Report_OCI(
                metadata=self.metadata(),
                resource=nsg,
                region=nsg.region,
                resource_name=nsg.display_name,
                resource_id=nsg.id,
                compartment_id=nsg.compartment_id,
            )

            # Check NSG rules for 0.0.0.0/0 to port 3389
            has_rdp_from_internet = False
            for rule in nsg.security_rules:
                if (
                    rule.get("direction") == "INGRESS"
                    and rule.get("source") == "0.0.0.0/0"
                ):
                    protocol = rule.get("protocol")
                    # Protocol 6 is TCP
                    if protocol == "6":
                        tcp_options = rule.get("tcp_options")
                        # If tcp_options is None, all TCP ports are allowed
                        if not tcp_options:
                            has_rdp_from_internet = True
                            break
                        # If tcp_options exists, check destination port range
                        dst_port = tcp_options.get("destination_port_range")
                        if dst_port:
                            port_min = dst_port.get("min", 0)
                            port_max = dst_port.get("max", 0)
                            if port_min <= 3389 <= port_max:
                                has_rdp_from_internet = True
                                break
                        # If no destination port range specified, all ports are allowed
                        else:
                            has_rdp_from_internet = True
                            break
                    # Protocol "all" or if protocol is not specified
                    elif protocol == "all" or not protocol:
                        has_rdp_from_internet = True
                        break

            if has_rdp_from_internet:
                report.status = "FAIL"
                report.status_extended = f"Network security group {nsg.display_name} allows ingress from 0.0.0.0/0 to port 3389 (RDP)."
            else:
                report.status = "PASS"
                report.status_extended = f"Network security group {nsg.display_name} does not ingress from 0.0.0.0/0 to port 3389 (RDP)."

            findings.append(report)

        return findings
