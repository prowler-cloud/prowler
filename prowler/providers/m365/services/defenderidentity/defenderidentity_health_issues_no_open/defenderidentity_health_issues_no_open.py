"""Check for open health issues in Microsoft Defender for Identity.

This module provides a security check that verifies there are no unresolved
health issues in the Microsoft Defender for Identity deployment.
"""

from typing import List

from prowler.lib.check.models import Check, CheckReportM365, Severity
from prowler.providers.m365.services.defenderidentity.defenderidentity_client import (
    defenderidentity_client,
)


class defenderidentity_health_issues_no_open(Check):
    """Ensure Microsoft Defender for Identity has no unresolved health issues.

    This check evaluates whether there are open health issues in the MDI deployment
    that require attention to maintain proper hybrid identity protection.

    - PASS: The health issue has been resolved (status is not open).
    - FAIL: The health issue is open and requires attention.
    - FAIL: No sensors are deployed (MDI cannot protect the environment).
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the check for open MDI health issues.

        This method iterates through all health issues from Microsoft Defender
        for Identity and reports on their status. Open issues indicate potential
        configuration problems or sensor health concerns that need resolution.

        Returns:
            List[CheckReportM365]: A list of reports containing the result of the check.
        """
        findings = []

        # Check sensors first - None means API error, empty list means no sensors
        sensors_api_failed = defenderidentity_client.sensors is None
        health_issues_api_failed = defenderidentity_client.health_issues is None
        has_sensors = (
            defenderidentity_client.sensors and len(defenderidentity_client.sensors) > 0
        )

        # If both APIs failed, it's likely a permission issue
        if sensors_api_failed and health_issues_api_failed:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Defender for Identity",
                resource_id="defenderIdentity",
            )
            report.status = "FAIL"
            report.status_extended = (
                "Defender for Identity APIs are not accessible. "
                "Ensure the Service Principal has SecurityIdentitiesSensors.Read.All and "
                "SecurityIdentitiesHealth.Read.All permissions granted."
            )
            findings.append(report)
            return findings

        # If only health issues API failed but we have sensors
        if health_issues_api_failed and has_sensors:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Defender for Identity",
                resource_id="defenderIdentity",
            )
            report.status = "FAIL"
            report.status_extended = (
                f"Cannot read health issues from Defender for Identity "
                f"(found {len(defenderidentity_client.sensors)} sensor(s) deployed). "
                "Ensure the Service Principal has SecurityIdentitiesHealth.Read.All permission."
            )
            findings.append(report)
            return findings

        # If no sensors are deployed (empty list, not None), MDI cannot monitor
        if not has_sensors and not sensors_api_failed:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Defender for Identity",
                resource_id="defenderIdentity",
            )
            report.status = "FAIL"
            report.status_extended = (
                "No sensors deployed in Defender for Identity. "
                "Without sensors, MDI cannot monitor health issues in the environment. "
                "Deploy sensors on domain controllers to enable protection."
            )
            findings.append(report)
            return findings

        # If health_issues is empty list - no issues exist, this is compliant
        if not defenderidentity_client.health_issues:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Defender for Identity",
                resource_id="defenderIdentity",
            )
            report.status = "PASS"
            report.status_extended = (
                "No open health issues found in Defender for Identity."
            )
            findings.append(report)
            return findings

        for health_issue in defenderidentity_client.health_issues:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=health_issue,
                resource_name=health_issue.display_name,
                resource_id=health_issue.id,
            )

            issue_type = health_issue.health_issue_type or "unknown"
            severity = health_issue.severity or "unknown"
            status = (health_issue.status or "").lower()

            if status != "open":
                report.status = "PASS"
                report.status_extended = f"Defender for Identity {issue_type} health issue {health_issue.display_name} is resolved."
            else:
                report.status = "FAIL"
                report.status_extended = f"Defender for Identity {issue_type} health issue {health_issue.display_name} is open with {severity} severity."

                # Adjust severity based on issue severity
                if severity == "high":
                    report.check_metadata.Severity = Severity.high
                elif severity == "medium":
                    report.check_metadata.Severity = Severity.medium
                elif severity == "low":
                    report.check_metadata.Severity = Severity.low

            findings.append(report)

        return findings
