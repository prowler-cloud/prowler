"""OpenStack Network Admin State Check."""

from typing import List

from prowler.lib.check.models import Check, CheckReportOpenStack
from prowler.providers.openstack.services.network.network_client import network_client


class network_admin_state_down(Check):
    """Ensure networks are administratively enabled."""

    def execute(self) -> List[CheckReportOpenStack]:
        """Execute network_admin_state_down check.

        Iterates over all networks and verifies that admin_state_up is True,
        meaning networks are administratively enabled and operational.

        Returns:
            list[CheckReportOpenStack]: List of findings for each network.
        """
        findings: List[CheckReportOpenStack] = []

        for network in network_client.networks:
            report = CheckReportOpenStack(
                metadata=self.metadata(), resource=network
            )
            report.resource_id = network.id
            report.resource_name = network.name
            report.region = network.region

            if not network.admin_state_up:
                report.status = "FAIL"
                report.status_extended = f"Network {network.name} ({network.id}) is administratively disabled (admin_state_up=False) and cannot carry traffic."  # noqa: E501
            else:
                report.status = "PASS"
                report.status_extended = f"Network {network.name} ({network.id}) is administratively enabled."  # noqa: E501

            findings.append(report)

        return findings
