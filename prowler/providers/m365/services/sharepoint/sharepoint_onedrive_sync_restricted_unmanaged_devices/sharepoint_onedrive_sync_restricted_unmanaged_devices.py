from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.sharepoint.sharepoint_client import (
    sharepoint_client,
)


class sharepoint_onedrive_sync_restricted_unmanaged_devices(Check):
    """
    Check if OneDrive sync is restricted for unmanaged devices.

    This check verifies that OneDrive sync is restricted to managed devices only.
    Unmanaged devices can pose a security risk by allowing users to sync sensitive data to unauthorized devices,
    potentially leading to data leakage or unauthorized access.

    The check fails if OneDrive sync is not restricted to managed devices (AllowedDomainGuidsForSyncApp is empty).
    """

    def execute(self) -> List[CheckReportM365]:
        """
        Execute the OneDrive sync restriction check.

        Retrieves the OneDrive sync settings from the Microsoft 365 SharePoint client and
        generates a report indicating whether OneDrive sync is restricted to managed devices only.

        Returns:
            List[CheckReportM365]: A list containing the report object with the result of the check.
        """
        findings = []
        settings = sharepoint_client.settings
        if settings:
            report = CheckReportM365(
                self.metadata(),
                resource=settings if settings else {},
                resource_name="SharePoint Settings",
                resource_id=sharepoint_client.tenant_domain,
            )
            report.status = "PASS"
            report.status_extended = "Microsoft 365 SharePoint does not allow OneDrive sync to unmanaged devices."

            if len(settings.allowedDomainGuidsForSyncApp) == 0:
                report.status = "FAIL"
                report.status_extended = "Microsoft 365 SharePoint allows OneDrive sync to unmanaged devices."

            findings.append(report)

        return findings
