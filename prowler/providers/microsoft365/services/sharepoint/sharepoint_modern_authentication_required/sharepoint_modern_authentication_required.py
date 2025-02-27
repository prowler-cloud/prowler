from typing import List

from prowler.lib.check.models import Check, CheckReportMicrosoft365
from prowler.providers.microsoft365.services.sharepoint.sharepoint_client import (
    sharepoint_client,
)


class sharepoint_modern_authentication_required(Check):
    """
    Check if Microsoft 365 SharePoint requires modern authentication.

    This check verifies that modern authentication is enforced for SharePoint applications in Microsoft 365.
    Modern authentication leverages OAuth 2.0 and supports advanced security features such as multi-factor
    authentication (MFA) and conditional access. Legacy authentication protocols (e.g., basic authentication)
    do not support these features and increase the risk of credential compromise.

    The check fails if modern authentication is not enforced, indicating that legacy protocols may be used.
    """

    def execute(self) -> List[CheckReportMicrosoft365]:
        """
        Execute the SharePoint modern authentication requirement check.

        Iterates over the SharePoint configuration retrieved from the Microsoft 365 SharePoint client and
        generates a report indicating whether modern authentication is required for SharePoint applications.

        Returns:
            List[CheckReportMicrosoft365]: A list containing the report object with the result of the check.
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
            report.status = "PASS"
            report.status_extended = "Microsoft 365 SharePoint does not allow access to apps that don't use modern authentication."

            if settings.modernAuthentication:
                report.status = "FAIL"
                report.status_extended = "Microsoft 365 SharePoint allows access to apps that don't use modern authentication."
        else:
            report.status = "FAIL"
            report.status_extended = "SharePoint settings were not found."

        findings.append(report)

        return findings
