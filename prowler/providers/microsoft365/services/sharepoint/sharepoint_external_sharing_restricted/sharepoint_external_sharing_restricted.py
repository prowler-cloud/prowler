from typing import List

from prowler.lib.check.models import Check, CheckReportMicrosoft365
from prowler.providers.microsoft365.services.sharepoint.sharepoint_client import (
    sharepoint_client,
)


class sharepoint_external_sharing_restricted(Check):
    """
    Check if Microsoft 365 SharePoint restricts external sharing at organization level.

    This check verifies that external sharing settings in SharePoint are configured to allow only "New and existing guests"
    (i.e., ExternalUserSharingOnly), which enforces authentication and limits access to external users. If a more permissive
    setting is used, legacy sharing may be allowed, increasing the risk of unauthorized data access.
    """

    def execute(self) -> List[CheckReportMicrosoft365]:
        """
        Execute the SharePoint external sharing restriction check.

        Iterates over the SharePoint settings retrieved from the Microsoft 365 SharePoint client and generates a report
        indicating whether external sharing is restricted to 'New and existing guests' (ExternalUserSharingOnly).

        Returns:
            List[Check_Report_Microsoft365]: A list containing a report with the result of the check.
        """
        findings = []
        settings = sharepoint_client.settings
        report = CheckReportMicrosoft365(
            self.metadata(),
            resource=settings if settings else {},
            resource_name="SharePoint Settings",
            resource_id=sharepoint_client.tenant_domain,
        )
        if settings:
            report.status = "FAIL"
            report.status_extended = (
                "External sharing is not restricted and guests users can access."
            )

            if settings.sharingCapability in [
                "ExistingExternalUserSharingOnly",
                "ExternalUserSharingOnly",
                "Disabled",
            ]:
                report.status = "PASS"
                report.status_extended = "External sharing is restricted to external user sharing or more restrictive."
        else:
            report.status = "FAIL"
            report.status_extended = "SharePoint settings were not found."

        findings.append(report)
        return findings
