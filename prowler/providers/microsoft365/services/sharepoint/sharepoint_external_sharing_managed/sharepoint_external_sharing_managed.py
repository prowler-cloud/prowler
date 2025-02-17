from typing import List

from prowler.lib.check.models import Check, Check_Report_Microsoft365
from prowler.providers.microsoft365.services.sharepoint.sharepoint_client import (
    sharepoint_client,
)


class sharepoint_external_sharing_managed(Check):
    """
    Check if Microsoft 365 SharePoint external sharing is managed through domain whitelists/blacklists.

    This check verifies that SharePoint external sharing settings are configured to restrict document sharing
    to external domains by enforcing domain-based restrictions. This means that the setting
    'sharingDomainRestrictionMode' must be set to either "AllowList" or "BlockList". If it is not, then
    external sharing is not managed via domain restrictions, increasing the risk of unauthorized access.

    Note: This check only evaluates the domain restriction mode and does not enforce the optional check
    of verifying that the allowed/blocked domain list is not empty.
    """

    def execute(self) -> List[Check_Report_Microsoft365]:
        """
        Execute the SharePoint external sharing management check.

        Iterates over the SharePoint settings retrieved from the Microsoft 365 SharePoint client and
        generates a report indicating whether external sharing is managed via domain restrictions.

        Returns:
            List[Check_Report_Microsoft365]: A list containing a report with the result of the check.
        """
        findings = []
        for settings in sharepoint_client.settings.values():
            report = Check_Report_Microsoft365(self.metadata(), resource=settings)
            report.status = "FAIL"
            report.status_extended = "SharePoint external sharing is not managed through domain restrictions."
            if settings.sharingDomainRestrictionMode in ["allowList", "blockList"]:
                report.status_extended = f"SharePoint external sharing is managed through domain restrictions with mode '{settings.sharingDomainRestrictionMode}' but the list is empty."
                if (
                    settings.sharingDomainRestrictionMode == "allowList"
                    and settings.sharingAllowedDomainList
                ):
                    report.status = "PASS"
                    report.status_extended = f"SharePoint external sharing is managed through domain restrictions with mode '{settings.sharingDomainRestrictionMode}'."
                elif (
                    settings.sharingDomainRestrictionMode == "blockList"
                    and settings.sharingBlockedDomainList
                ):
                    report.status = "PASS"
                    report.status_extended = f"SharePoint external sharing is managed through domain restrictions with mode '{settings.sharingDomainRestrictionMode}'."

            findings.append(report)
        return findings
