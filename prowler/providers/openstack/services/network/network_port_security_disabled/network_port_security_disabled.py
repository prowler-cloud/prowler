"""OpenStack Network Port Security Check."""

from typing import List

from prowler.lib.check.models import Check, CheckReportOpenStack
from prowler.providers.openstack.services.network.network_client import network_client


class network_port_security_disabled(Check):
    """Ensure port security is enabled on networks and ports."""

    def execute(self) -> List[CheckReportOpenStack]:
        """Execute network_port_security_disabled check.

        Iterates over all networks and ports and verifies that port security
        is enabled to prevent MAC/IP spoofing attacks.

        Returns:
            list[CheckReportOpenStack]: List of findings for each network/port.
        """
        findings: List[CheckReportOpenStack] = []

        # Check networks
        for network in network_client.networks:
            report = CheckReportOpenStack(metadata=self.metadata(), resource=network)
            report.resource_id = network.id
            report.resource_name = network.name
            report.region = network.region

            if not network.port_security_enabled:
                report.status = "FAIL"
                report.status_extended = f"Network {network.name} ({network.id}) has port security disabled, which allows MAC and IP address spoofing attacks."
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Network {network.name} ({network.id}) has port security enabled."
                )

            findings.append(report)

        # Check ports
        for port in network_client.ports:
            report = CheckReportOpenStack(metadata=self.metadata(), resource=port)
            report.resource_id = port.id
            report.resource_name = port.name or f"port-{port.id[:8]}"
            report.region = port.region

            if not port.port_security_enabled:
                report.status = "FAIL"
                report.status_extended = f"Port {report.resource_name} ({port.id}) on network {port.network_id} has port security disabled, which allows MAC and IP address spoofing."
            else:
                report.status = "PASS"
                report.status_extended = f"Port {report.resource_name} ({port.id}) has port security enabled."

            findings.append(report)

        return findings
