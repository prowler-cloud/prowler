from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.sharepoint.sharepoint_client import (
    sharepoint_client,
)


class sharepoint_default_sharing_link_permission_configured(Check):
    """
    Check if SharePoint default sharing link permission is set to View.

    This check verifies that the default sharing link permission in SharePoint is configured to 'View'
    rather than 'Edit'. Defaulting new sharing links to Edit grants unnecessary write access and increases
    the blast radius of accidental oversharing.
    """

    def execute(self) -> List[CheckReportM365]:
        """
        Execute the SharePoint default sharing link permission check.

        Returns:
            List[CheckReportM365]: A list containing a report with the result of the check.
        """
        findings = []
        settings = sharepoint_client.settings
        if (
            settings
            and hasattr(settings, "defaultLinkPermission")
            and settings.defaultLinkPermission is not None
        ):
            report = CheckReportM365(
                self.metadata(),
                resource=settings,
                resource_name="SharePoint Settings",
                resource_id="sharepointSettings",
            )
            report.status = "FAIL"
            report.status_extended = f"SharePoint default sharing link permission is set to '{settings.defaultLinkPermission}'."

            if settings.defaultLinkPermission == "View":
                report.status = "PASS"
                report.status_extended = (
                    "SharePoint default sharing link permission is set to 'View'."
                )

            findings.append(report)
        return findings
