from typing import List

from prowler.lib.check.models import Check, CheckReportMicrosoft365
from prowler.providers.microsoft365.services.exchange.exchange_client import (
    exchange_client,
)


class exchange_account_mailbox_audit_bypass_disabled(Check):
    """Verify if Exchange mailbox auditing is enabled.

    This check ensures that mailbox auditing is not bypassed and is properly enabled.
    """

    def execute(self) -> List[CheckReportMicrosoft365]:
        """Run the check to validate Exchange mailbox auditing.

        Iterates through the mailbox configurations to determine if auditing is enabled
        and generates a report for each mailbox.

        Returns:
            List[CheckReportMicrosoft365]: A list of reports with the audit status for each mailbox.
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
            report.status_extended = f"Exchange mailbox auditing is bypassed and not enabled for mailbox: {mailbox_config.name}."

            if not mailbox_config.audit_bypass_enabled:
                report.status = "PASS"
                report.status_extended = f"Exchange mailbox auditing is enabled for mailbox: {mailbox_config.name}."

            findings.append(report)

        return findings
