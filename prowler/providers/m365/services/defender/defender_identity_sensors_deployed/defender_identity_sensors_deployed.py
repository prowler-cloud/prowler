"""Check for deployed sensors in Microsoft Defender for Identity.

This module provides a security check that verifies MDI sensors are deployed
to monitor Domain Controllers and detect identity-based threats.
"""

from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.defender.defender_identity_client import (
    defender_identity_client,
)


class defender_identity_sensors_deployed(Check):
    """Ensure Microsoft Defender for Identity has sensors deployed.

    This check evaluates whether MDI sensors are deployed to monitor
    Domain Controllers for identity-based threats.

    - PASS: At least one sensor is deployed.
    - FAIL: No sensors are deployed or data is unavailable.
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the check for deployed MDI sensors.

        This method verifies that MDI sensors are deployed to provide
        visibility into identity-based threats on Domain Controllers.

        Returns:
            List[CheckReportM365]: A list of reports containing the result of the check.
        """
        findings = []

        # If sensors is None, the API call failed (tenant not onboarded or missing permissions)
        if defender_identity_client.sensors is None:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Defender for Identity",
                resource_id="defenderIdentity",
            )
            report.status = "FAIL"
            report.status_extended = (
                "Defender for Identity data is unavailable. "
                "Ensure the tenant is onboarded to Microsoft Defender for Identity "
                "and the required permissions are granted."
            )
            findings.append(report)
            return findings

        # If no sensors are deployed
        if not defender_identity_client.sensors:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Defender for Identity",
                resource_id="defenderIdentity",
            )
            report.status = "FAIL"
            report.status_extended = (
                "No Defender for Identity sensors are deployed. "
                "Deploy sensors on Domain Controllers to detect identity-based threats."
            )
            findings.append(report)
            return findings

        # Report on each sensor
        for sensor in defender_identity_client.sensors:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=sensor,
                resource_name=sensor.display_name,
                resource_id=sensor.id,
            )

            health_status = (sensor.health_status or "").lower()

            if health_status == "healthy":
                report.status = "PASS"
                report.status_extended = f"Defender for Identity sensor {sensor.display_name} is deployed and healthy."
            else:
                report.status = "FAIL"
                report.status_extended = f"Defender for Identity sensor {sensor.display_name} is deployed but has health status: {sensor.health_status or 'unknown'}."

            findings.append(report)

        return findings
