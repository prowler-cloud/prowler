from typing import List

from prowler.lib.check.models import Check, CheckReportMicrosoft365
from prowler.providers.microsoft365.services.sharepoint.sharepoint_client import (
    sharepoint_client,
)


class sharepoint_settings_guest_sharing_restricted(Check):
    """
    Check if Microsoft 365 SharePoint guest sharing is restricted.

    This check verifies that guest users in SharePoint cannot share items they do not own.
    When guest resharing is enabled, external users might share content they don't own,
    increasing the risk of unauthorized data exposure. This control ensures that the setting
    to prevent external users from resharing is enabled.
    """

    def execute(self) -> List[CheckReportMicrosoft365]:
        """
        Execute the SharePoint guest sharing restriction check.

        Iterates over the SharePoint settings retrieved from the Microsoft 365 SharePoint client
        and generates a report indicating whether guest users are prevented from sharing items they do not own.

        Returns:
            List[CheckReportMicrosoft365]: A list containing a report with the result of the check.
        """
        findings = []
        settings = sharepoint_client.settings
        if settings:
            report = CheckReportMicrosoft365(
                self.metadata(),
                resource=settings if settings else {},
                resource_name="SharePoint Settings",
                resource_id=sharepoint_client.tenant_domain,
            )
            report.status = "FAIL"
            report.status_extended = "Guest sharing is not restricted; guest users can share items they do not own."
            if not settings.resharingEnabled:
                report.status = "PASS"
                report.status_extended = "Guest sharing is restricted; guest users cannot share items they do not own."

            findings.append(report)
        return findings
