from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.sharepoint.sharepoint_client import (
    sharepoint_client,
)


class sharepoint_default_sharing_link_permission_configured(Check):
    """
    Check if Microsoft 365 SharePoint default sharing link permission is set to View.

    This check verifies that the default sharing link permission in SharePoint is configured to "View"
    rather than "Edit". Setting the default to "View" enforces the principle of least privilege by
    ensuring that new sharing links grant read-only access by default, reducing the risk of accidental
    oversharing with edit permissions.
    """

    def execute(self) -> List[CheckReportM365]:
        """
        Execute the SharePoint default sharing link permission check.

        Iterates over the SharePoint settings retrieved from the Microsoft 365 SharePoint client and
        generates a report indicating whether the default sharing link permission is set to "View".

        Returns:
            List[CheckReportM365]: A list containing a report with the result of the check.
        """
        findings = []
        settings = sharepoint_client.settings
        if settings:
            report = CheckReportM365(
                self.metadata(),
                resource=settings if settings else {},
                resource_name="SharePoint Settings",
                resource_id="sharepointSettings",
            )
            report.status = "FAIL"
            report.status_extended = f"The default sharing link permission is set to {settings.defaultLinkPermission} instead of View."

            if settings.defaultLinkPermission == "View":
                report.status = "PASS"
                report.status_extended = (
                    "The default sharing link permission is set to View."
                )

            findings.append(report)
        return findings
