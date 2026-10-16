"""Check Ensure no security lists allow ingress from the internet to port 3389."""

from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.network.lib.security_rules import (
    UNRESTRICTED_CIDRS_TEXT,
    find_unrestricted_tcp_rule,
)
from prowler.providers.oraclecloud.services.network.network_client import network_client

RDP_PORT = 3389


class network_security_list_ingress_from_internet_to_rdp_port(Check):
    """Check Ensure no security lists allow ingress from the internet to port 3389."""

    def execute(self) -> Check_Report_OCI:
        """Execute the network_security_list_ingress_from_internet_to_rdp_port check."""
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
                security_list.ingress_security_rules, RDP_PORT
            )

            if public_rule:
                report.status = "FAIL"
                report.status_extended = (
                    f"Security list {security_list.display_name} allows ingress from "
                    f"{public_rule.get('source')} to port {RDP_PORT} (RDP)."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Security list {security_list.display_name} does not allow ingress "
                    f"from {UNRESTRICTED_CIDRS_TEXT} to port {RDP_PORT} (RDP)."
                )

            findings.append(report)

        return findings
