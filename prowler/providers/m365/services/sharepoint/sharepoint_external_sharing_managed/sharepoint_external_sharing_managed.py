from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.sharepoint.sharepoint_client import (
    sharepoint_client,
)


class sharepoint_external_sharing_managed(Check):
    """
    Check if Microsoft 365 SharePoint external sharing is managed through domain whitelists/blacklists.

    This check verifies that SharePoint external sharing settings are configured to restrict document sharing
    to external domains by enforcing domain-based restrictions. When external sharing is enabled, the setting
    'sharingDomainRestrictionMode' must be set to either "AllowList" or "BlockList" with a corresponding
    domain list. If external sharing is disabled at the organization level, the check passes.
    """

    def execute(self) -> List[CheckReportM365]:
        """
        Execute the SharePoint external sharing management check.

        Iterates over the SharePoint settings retrieved from the Microsoft 365 SharePoint client and
        generates a report indicating whether external sharing is managed via domain restrictions.

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
            report.status_extended = "SharePoint external sharing is not managed through domain restrictions."
            if settings.sharingCapability == "Disabled":
                report.status = "PASS"
                report.status_extended = (
                    "External sharing is disabled at organization level."
                )
            elif settings.sharingDomainRestrictionMode in ["allowList", "blockList"]:
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
