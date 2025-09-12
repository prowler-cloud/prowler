from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.exchange.exchange_client import exchange_client


class exchange_organization_modern_authentication_enabled(Check):
    """
    Check if Modern Authentication is enabled for Exchange Online.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """
        Execute the check for Modern Authentication in Exchange Online.

        This method checks if Modern Authentication is enabled in the Exchange organization configuration.

        Returns:
            List[CheckReportM365]: A list of reports containing the result of the check.
        """
        findings = []
        organization_config = exchange_client.organization_config
        if organization_config:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=organization_config,
                resource_name=organization_config.name,
                resource_id=organization_config.guid,
            )
            report.status = "FAIL"
            report.status_extended = (
                "Modern Authentication is not enabled for Exchange Online."
            )

            if organization_config.oauth_enabled:
                report.status = "PASS"
                report.status_extended = (
                    "Modern Authentication is enabled for Exchange Online."
                )

            findings.append(report)

        return findings
