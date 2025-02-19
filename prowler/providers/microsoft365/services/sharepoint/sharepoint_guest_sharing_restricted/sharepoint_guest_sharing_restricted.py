from typing import List

from prowler.lib.check.models import Check, Check_Report_Microsoft365
from prowler.providers.microsoft365.services.sharepoint.sharepoint_client import (
    sharepoint_client,
)


class sharepoint_guest_sharing_restricted(Check):
    """
    Check if Microsoft 365 SharePoint guest sharing is restricted.

    This check verifies that guest users in SharePoint cannot share items they do not own.
    When guest resharing is enabled, external users might share content they don't own,
    increasing the risk of unauthorized data exposure. This control ensures that the setting
    to prevent external users from resharing is enabled.
    """

    def execute(self) -> List[Check_Report_Microsoft365]:
        """
        Execute the SharePoint guest sharing restriction check.

        Iterates over the SharePoint settings retrieved from the Microsoft 365 SharePoint client
        and generates a report indicating whether guest users are prevented from sharing items they do not own.

        Returns:
            List[Check_Report_Microsoft365]: A list containing a report with the result of the check.
        """
        findings = []
        for settings in sharepoint_client.settings.values():
            report = Check_Report_Microsoft365(self.metadata(), resource=settings)
            report.status = "FAIL"
            report.status_extended = "Guest sharing is not restricted; guest users can share items they do not own."
            if not settings.resharingEnabled:
                report.status = "PASS"
                report.status_extended = "Guest sharing is restricted; guest users cannot share items they do not own."

            findings.append(report)
        return findings
