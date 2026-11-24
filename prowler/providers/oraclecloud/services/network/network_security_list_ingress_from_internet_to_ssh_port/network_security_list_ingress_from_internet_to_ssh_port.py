"""Check if security lists allow ingress from the internet to port 22."""

from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.network.lib.security_rules import (
    UNRESTRICTED_CIDRS_TEXT,
    find_unrestricted_tcp_rule,
)
from prowler.providers.oraclecloud.services.network.network_client import network_client

SSH_PORT = 22


class network_security_list_ingress_from_internet_to_ssh_port(Check):
    """Check if security lists allow ingress from the internet to port 22."""

    def execute(self) -> Check_Report_OCI:
        """Execute the network_security_list_ingress_from_internet_to_ssh_port check.

        Returns:
            List of Check_Report_OCI objects with findings
        """
        findings = []

        for security_list in network_client.security_lists:
            report = Check_Report_OCI(
                metadata=self.metadata(),
                resource=security_list,
                region=security_list.region,
                resource_name=security_list.display_name,
                resource_id=security_list.id,
                compartment_id=security_list.compartment_id,
            )

            public_rule = find_unrestricted_tcp_rule(
                security_list.ingress_security_rules, SSH_PORT
            )

            if public_rule:
                report.status = "FAIL"
                report.status_extended = (
                    f"Security list {security_list.display_name} allows ingress from "
                    f"{public_rule.get('source')} to port {SSH_PORT} (SSH)."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Security list {security_list.display_name} does not allow ingress "
                    f"from {UNRESTRICTED_CIDRS_TEXT} to port {SSH_PORT} (SSH)."
                )

            findings.append(report)

        return findings
