from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.exchange.exchange_client import exchange_client


class exchange_mailbox_policy_additional_storage_restricted(Check):
    """Check if Exchange mailbox policy restricts additional storage providers.

    This check ensures that the mailbox policy does not allow additional storage providers.
    """

    def execute(self) -> List[CheckReportM365]:
        """Run the check to validate Exchange mailbox policy restrictions.

        Iterates through the mailbox policy configuration to determine if additional storage
        providers are restricted and generates a report based on the policy status.

        Returns:
            List[CheckReportM365]: A list of reports with the restriction status for the mailbox policy.
        """
        findings = []
        mailbox_policy = exchange_client.mailbox_policy
        if mailbox_policy:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=mailbox_policy,
                resource_name="Exchange Mailbox Policy",
                resource_id=mailbox_policy.id,
            )
            report.status = "FAIL"
            report.status_extended = (
                "Exchange mailbox policy allows additional storage providers."
            )

            if not mailbox_policy.additional_storage_enabled:
                report.status = "PASS"
                report.status_extended = (
                    "Exchange mailbox policy restricts additional storage providers."
                )

            findings.append(report)

        return findings
