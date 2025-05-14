from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.admincenter.admincenter_client import (
    admincenter_client,
)


class admincenter_groups_not_public_visibility(Check):
    """Check if groups in Microsoft Admin Center have public visibility.

    This check verifies whether the visibility of groups in Microsoft Admin Center
    is set to 'Private'. If any group has a 'Public' visibility, the check fails.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the check for groups with public visibility.

        This method iterates through all groups in Microsoft Admin Center and checks
        if any group has 'Public' visibility. If so, the check fails for that group.

        Returns:
            List[CheckReportM365]: A list containing the results of the check for each group.
        """
        findings = []
        for group in admincenter_client.groups.values():
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=group,
                resource_name=group.name,
                resource_id=group.id,
            )
            report.status = "FAIL"
            report.status_extended = f"Group {group.name} has {group.visibility} visibility and should be Private."

            if group.visibility != "Public":
                report.status = "PASS"
                report.status_extended = (
                    f"Group {group.name} has {group.visibility} visibility."
                )

            findings.append(report)

        return findings
