"""Check for open health issues in Microsoft Defender for Identity.

This module provides a security check that verifies there are no unresolved
health issues in the Microsoft Defender for Identity deployment.
"""

from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.defender.defender_identity_client import (
    defender_identity_client,
)


class defender_identity_health_issues_no_open(Check):
    """Ensure Microsoft Defender for Identity has no unresolved health issues.

    This check evaluates whether there are open health issues in the MDI deployment
    that require attention to maintain proper hybrid identity protection.

    - PASS: The health issue has been resolved (status is not open).
    - FAIL: The health issue is open and requires attention.
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

        # If health_issues is None, the API call failed (tenant not onboarded or missing permissions)
        if defender_identity_client.health_issues is None:
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

        # If health_issues is empty list, no issues exist - this is compliant
        if not defender_identity_client.health_issues:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Defender for Identity",
                resource_id="defenderIdentity",
            )
            report.status = "PASS"
            report.status_extended = "No health issues found in Defender for Identity."
            findings.append(report)
            return findings

        for health_issue in defender_identity_client.health_issues:
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
                report.status_extended = f"Defender for Identity {issue_type} health issue '{health_issue.display_name}' is resolved."
            else:
                report.status = "FAIL"
                report.status_extended = f"Defender for Identity {issue_type} health issue '{health_issue.display_name}' is open with {severity} severity."

                # Adjust severity based on issue severity
                if severity == "high":
                    report.check_metadata.Severity = "high"
                elif severity == "medium":
                    report.check_metadata.Severity = "medium"
                elif severity == "low":
                    report.check_metadata.Severity = "low"

            findings.append(report)

        return findings
