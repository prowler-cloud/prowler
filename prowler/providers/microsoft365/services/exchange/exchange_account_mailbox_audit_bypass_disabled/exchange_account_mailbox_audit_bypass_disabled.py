from typing import List

from prowler.lib.check.models import Check, CheckReportMicrosoft365
from prowler.providers.microsoft365.services.exchange.exchange_client import (
    exchange_client,
)


class exchange_account_mailbox_audit_bypass_disabled(Check):
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
        for mailbox_config in exchange_client.mailboxes_config:
            report = CheckReportMicrosoft365(
                metadata=self.metadata(),
                resource=mailbox_config,
                resource_name=mailbox_config.name,
                resource_id=mailbox_config.id,
            )
            report.status = "FAIL"
            report.status_extended = f"Exchange mailbox auditing is bypass and not enabled on this mailbox: {mailbox_config.name}."

            if not mailbox_config.audit_bypass_enabled:
                report.status = "PASS"
                report.status_extended = f"Exchange mailbox auditing is enabled on this mailbox: {mailbox_config.name}."

            findings.append(report)

        return findings
