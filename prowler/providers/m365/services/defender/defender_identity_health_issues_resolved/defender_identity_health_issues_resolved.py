from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.defender.defender_client import defender_client
from prowler.providers.m365.services.defender.defender_service import HealthIssueStatus


class defender_identity_health_issues_resolved(Check):
    """Check if Microsoft Defender for Identity has no open health issues.

    Microsoft Defender for Identity (MDI) monitors the health of your hybrid identity
    infrastructure including sensors and configuration. Health issues indicate problems
    that may impact the protection capabilities of MDI.

    - PASS: No open health issues exist in Microsoft Defender for Identity.
    - FAIL: One or more open health issues exist that need to be resolved.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the check for Microsoft Defender for Identity health issues.

        This method evaluates the health status of Microsoft Defender for Identity
        by checking for any open health issues. Issues with status 'open' indicate
        problems that require attention.

        Returns:
            List[CheckReportM365]: A list of reports containing the result of the check.
        """
        findings = []
        health_issues = defender_client.identity_health_issues

        # Filter to only include non-suppressed issues for reporting
        active_issues = [
            issue
            for issue in health_issues
            if issue.status != HealthIssueStatus.SUPPRESSED
        ]

        # Count open issues
        open_issues = [
            issue for issue in active_issues if issue.status == HealthIssueStatus.OPEN
        ]

        if active_issues:
            # Create a single report for the overall health status
            # Using the first issue as the resource reference
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={"health_issues": [issue.dict() for issue in active_issues]},
                resource_name="Defender for Identity Health",
                resource_id=defender_client.tenant_domain or "defenderIdentity",
            )

            if open_issues:
                open_count = len(open_issues)
                total_count = len(active_issues)
                report.status = "FAIL"
                report.status_extended = f"Microsoft Defender for Identity has {open_count} open health issue(s) out of {total_count} total issue(s) that require attention."
            else:
                report.status = "PASS"
                report.status_extended = "Microsoft Defender for Identity has no open health issues. All issues have been resolved."

            findings.append(report)
        else:
            # No health issues found - this is a passing state
            # It could mean MDI is healthy or not configured
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Defender for Identity Health",
                resource_id=defender_client.tenant_domain or "defenderIdentity",
            )
            report.status = "PASS"
            report.status_extended = (
                "Microsoft Defender for Identity has no health issues reported."
            )
            findings.append(report)

        return findings
