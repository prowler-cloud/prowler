from typing import List

from prowler.lib.check.models import Check, CheckReportMicrosoft365
from prowler.providers.microsoft365.services.exchange.exchange_client import (
    exchange_client,
)


class exchange_organization_mailbox_auditing_enabled(Check):
    """Check if Exchange mailbox auditing is enabled.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportMicrosoft365]:
        """Execute the check for Exchange mailbox auditing.

        This method checks if mailbox auditing is enabled in the Exchange organization configuration.

        Returns:
            List[CheckReportMicrosoft365]: A list of reports containing the result of the check.
        """
        findings = []
        organization_config = exchange_client.organization_config
        if organization_config:
            report = CheckReportMicrosoft365(
                metadata=self.metadata(),
                resource=organization_config,
                resource_name=organization_config.name,
                resource_id=organization_config.guid,
            )
            report.status = "FAIL"
            report.status_extended = (
                "Exchange mailbox auditing is not enabled on your organization."
            )

            if not exchange_client.organization_config.audit_disabled:
                report.status = "PASS"
                report.status_extended = (
                    "Exchange mailbox auditing is enabled on your organization."
                )

            findings.append(report)

        return findings
