from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.admincenter.admincenter_client import (
    admincenter_client,
)


class admincenter_organization_customer_lockbox_enabled(Check):
    """
    Ensure the customer lockbox feature is enabled.

    Customer Lockbox ensures that Microsoft support engineers cannot access content
    in your tenant to perform a service operation without explicit approval. This feature
    provides an additional layer of control and transparency over data access requests.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """
        Execute the check for the Customer Lockbox feature in Microsoft 365.

        This method checks if the Customer Lockbox feature is enabled in the organization configuration.

        Returns:
            List[CheckReportM365]: A list of reports containing the result of the check.
        """
        findings = []
        organization_config = admincenter_client.organization_config
        if organization_config:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=organization_config,
                resource_name=organization_config.name,
                resource_id=organization_config.guid,
            )
            report.status = "FAIL"
            report.status_extended = (
                "Customer Lockbox is not enabled at organization level."
            )

            if organization_config.customer_lockbox_enabled:
                report.status = "PASS"
                report.status_extended = (
                    "Customer Lockbox is enabled at organization level."
                )

            findings.append(report)

        return findings
