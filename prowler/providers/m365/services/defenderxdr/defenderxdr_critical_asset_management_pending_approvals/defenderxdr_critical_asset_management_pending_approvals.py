"""Check for pending Critical Asset Management approvals in Defender XDR.

This check identifies asset classifications with low confidence scores
that require security administrator review and approval.
"""

from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.defenderxdr.defenderxdr_client import (
    defenderxdr_client,
)


class defenderxdr_critical_asset_management_pending_approvals(Check):
    """Check for pending Critical Asset Management approvals in Microsoft Defender XDR.

    This check queries Advanced Hunting to identify assets with low classification
    confidence scores that have not been reviewed by a security administrator.

    Prerequisites:
    1. ThreatHunting.Read.All permission granted
    2. Microsoft Defender XDR with Security Exposure Management enabled

    Results:
    - PASS: No pending approvals for Critical Asset Management are found.
    - FAIL: At least one asset classification has pending approvals.
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the check for pending Critical Asset Management approvals.

        Evaluates whether there are any pending Critical Asset Management
        approvals that require administrator review.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        pending_approvals = defenderxdr_client.pending_cam_approvals

        # API call failed - likely missing ThreatHunting.Read.All permission
        if pending_approvals is None:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Critical Asset Management",
                resource_id="criticalAssetManagement",
            )
            report.status = "FAIL"
            report.status_extended = (
                "Unable to query Critical Asset Management status. "
                "Verify that ThreatHunting.Read.All permission is granted."
            )
            findings.append(report)
            return findings

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
