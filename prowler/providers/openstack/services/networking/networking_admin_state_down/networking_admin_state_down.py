"""OpenStack Network Admin State Check."""

from typing import List

from prowler.lib.check.models import Check, CheckReportOpenStack
from prowler.providers.openstack.services.networking.networking_client import (
    networking_client,
)


class networking_admin_state_down(Check):
    """Ensure networks are administratively enabled."""

    def execute(self) -> List[CheckReportOpenStack]:
        """Execute networking_admin_state_down check.

        Iterates over all networks and verifies that admin_state_up is True,
        meaning networks are administratively enabled and operational.

        Returns:
            list[CheckReportOpenStack]: List of findings for each network.
        """
        findings: List[CheckReportOpenStack] = []

        for network in networking_client.networks:
            report = CheckReportOpenStack(metadata=self.metadata(), resource=network)
            report.resource_id = network.id
            report.resource_name = network.name
            report.region = network.region

            if not network.admin_state_up:
                report.status = "FAIL"
                report.status_extended = f"Network {network.name} ({network.id}) is administratively disabled (admin_state_up=False) and cannot carry traffic."
            else:
                report.status = "PASS"
                report.status_extended = f"Network {network.name} ({network.id}) is administratively enabled."

            findings.append(report)

        return findings
