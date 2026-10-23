"""Check if network security groups allow ingress from the internet to port 22."""

from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.network.lib.security_rules import (
    UNRESTRICTED_CIDRS_TEXT,
    find_unrestricted_tcp_rule,
)
from prowler.providers.oraclecloud.services.network.network_client import network_client

SSH_PORT = 22


class network_security_group_ingress_from_internet_to_ssh_port(Check):
    """Check if network security groups allow ingress from the internet to port 22."""

    def execute(self) -> Check_Report_OCI:
        """Execute the network_security_group_ingress_from_internet_to_ssh_port check.

        Returns:
            List of Check_Report_OCI objects with findings
        """
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

            public_rule = find_unrestricted_tcp_rule(
                nsg.security_rules, SSH_PORT, direction="INGRESS"
            )

            if public_rule:
                report.status = "FAIL"
                report.status_extended = (
                    f"Network security group {nsg.display_name} allows ingress from "
                    f"{public_rule.get('source')} to port {SSH_PORT} (SSH)."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Network security group {nsg.display_name} does not allow ingress "
                    f"from {UNRESTRICTED_CIDRS_TEXT} to port {SSH_PORT} (SSH)."
                )

            findings.append(report)

        return findings
