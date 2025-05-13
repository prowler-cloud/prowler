from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client


class entra_dynamic_group_for_guests_created(Check):
    """
    Check if a dynamic group for guest users is created in Microsoft Entra.

    This check verifies that a dynamic group exists for guest users in Microsoft Entra.
    A dynamic group for guest users should have the group type 'DynamicMembership' and a membership rule
    that restricts membership to users with a userType equal to 'Guest'. This configuration enables
    automated enforcement of conditional access policies and reduces manual management of guest access.
    """

    def execute(self) -> List[CheckReportM365]:
        """
        Execute the dynamic group for guest users check.

        Iterates over the groups retrieved from the Microsoft Entra client and generates a report
        indicating whether at least one dynamic group exists with a membership rule targeting guest users.

        Returns:
            List[CheckReportM365]: A list containing a single report with the result of the check.
        """
        findings = []
        if entra_client.groups:
            dynamic_group = None
            for group in entra_client.groups:
                if "DynamicMembership" in group.groupTypes and group.membershipRule:
                    if 'user.userType -eq "Guest"' in group.membershipRule:
                        dynamic_group = group
                        break

            report = CheckReportM365(
                self.metadata(),
                resource=dynamic_group if dynamic_group else {},
                resource_name=dynamic_group.name if dynamic_group else "Group",
                resource_id=dynamic_group.id if dynamic_group else "group",
            )
            report.status = "FAIL"
            report.status_extended = (
                "No dynamic group for guest users was found in Microsoft Entra."
            )

            if dynamic_group:
                report.status = "PASS"
                report.status_extended = (
                    "A dynamic group for guest users is created in Microsoft Entra."
                )

            findings.append(report)
        return findings
