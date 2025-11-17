from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.exchange.exchange_client import exchange_client


class exchange_mailbox_policy_additional_storage_restricted(Check):
    """Check if Exchange mailbox policy restricts additional storage providers.

    This check ensures that the mailbox policy does not allow additional storage providers.
    """

    def execute(self) -> List[CheckReportM365]:
        """Run the check to validate Exchange mailbox policy restrictions.

        Iterates through all mailbox policies to determine if additional storage
        providers are restricted and generates reports for each policy.

        Returns:
            List[CheckReportM365]: A list of reports with the restriction status for each mailbox policy.
        """
        findings = []
        for mailbox_policy in exchange_client.mailbox_policies:
            if mailbox_policy:
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource=mailbox_policy,
                    resource_name=f"Exchange Mailbox Policy - {mailbox_policy.id}",
                    resource_id=mailbox_policy.id,
                )
                report.status = "FAIL"
                report.status_extended = f"Exchange mailbox policy '{mailbox_policy.id}' allows additional storage providers."

                if not mailbox_policy.additional_storage_enabled:
                    report.status = "PASS"
                    report.status_extended = f"Exchange mailbox policy '{mailbox_policy.id}' restricts additional storage providers."

                findings.append(report)

        return findings
