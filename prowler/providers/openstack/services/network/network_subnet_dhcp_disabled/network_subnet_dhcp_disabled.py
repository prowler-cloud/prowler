"""OpenStack Network Subnet DHCP Check."""

from typing import List

from prowler.lib.check.models import Check, CheckReportOpenStack
from prowler.providers.openstack.services.network.network_client import network_client


class network_subnet_dhcp_disabled(Check):
    """Ensure DHCP is enabled on subnets."""

    def execute(self) -> List[CheckReportOpenStack]:
        """Execute network_subnet_dhcp_disabled check.

        Iterates over all subnets and verifies that DHCP is enabled
        to ensure instances can obtain IP addresses automatically.

        Returns:
            list[CheckReportOpenStack]: List of findings for each subnet.
        """
        findings: List[CheckReportOpenStack] = []

        for subnet in network_client.subnets:
            report = CheckReportOpenStack(
                metadata=self.metadata(), resource=subnet
            )
            report.resource_id = subnet.id
            report.resource_name = subnet.name
            report.region = subnet.region

            if not subnet.enable_dhcp:
                report.status = "FAIL"
                report.status_extended = f"Subnet {subnet.name} ({subnet.id}) on network {subnet.network_id} has DHCP disabled, which may prevent instances from obtaining IP addresses automatically."
            else:
                report.status = "PASS"
                report.status_extended = f"Subnet {subnet.name} ({subnet.id}) has DHCP enabled."

            findings.append(report)

        return findings
