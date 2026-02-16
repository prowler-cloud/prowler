from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.defender.defender_client import defender_client


class defender_cam_pending_approvals(Check):
    """Check for pending Critical Asset Management approvals in Microsoft Defender.

    This check queries Advanced Hunting to identify assets with low classification
    confidence scores that have not been reviewed by a security administrator.

    - PASS: No pending approvals for Critical Asset Management are found.
    - FAIL: At least one asset classification has pending approvals.
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the check for pending CAM approvals.

        Evaluates whether there are any pending Critical Asset Management
        approvals that require administrator review.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        pending_approvals = defender_client.pending_cam_approvals

        if not pending_approvals:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Critical Asset Management",
                resource_id="criticalAssetManagement",
            )
            report.status = "PASS"
            report.status_extended = "No pending approvals for Critical Asset Management classifications are found."
            findings.append(report)
        else:
            for approval in pending_approvals:
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource=approval,
                    resource_name=f"CAM Classification: {approval.classification}",
                    resource_id=f"cam/{approval.classification}",
                )
                report.status = "FAIL"
                assets_summary = ", ".join(approval.assets[:5])
                if len(approval.assets) > 5:
                    assets_summary += f" and {len(approval.assets) - 5} more"
                report.status_extended = (
                    f"Critical Asset Management classification '{approval.classification}' "
                    f"has {approval.pending_count} asset(s) pending approval: {assets_summary}."
                )
                findings.append(report)

        return findings
