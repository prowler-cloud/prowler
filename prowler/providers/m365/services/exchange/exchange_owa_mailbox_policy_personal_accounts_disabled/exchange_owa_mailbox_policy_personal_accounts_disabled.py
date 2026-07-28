from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.exchange.exchange_client import exchange_client


class exchange_owa_mailbox_policy_personal_accounts_disabled(Check):
    """Check if the default OWA mailbox policy disables personal account integration.

    Outlook on the web mailbox policies expose PersonalAccountsEnabled and
    PersonalAccountCalendarsEnabled, which control whether users can add personal
    email accounts and personal calendars in the new Outlook for Windows. Only the
    default OWA mailbox policy is required for compliance with this control.

    - PASS: The default OWA mailbox policy disables personal accounts and personal
      account calendars.
    - FAIL: The default OWA mailbox policy allows personal accounts and/or personal
      account calendars.
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the check for the default OWA mailbox policy personal account settings.

        Returns:
            List[CheckReportM365]: A list of reports containing the result of the check.
        """
        findings = []
        for mailbox_policy in exchange_client.mailbox_policies:
            if not mailbox_policy or not mailbox_policy.is_default:
                continue

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=mailbox_policy,
                resource_name=f"Exchange Mailbox Policy - {mailbox_policy.id}",
                resource_id=mailbox_policy.id,
            )
            report.status = "FAIL"
            report.status_extended = f"Default OWA mailbox policy '{mailbox_policy.id}' allows personal account integration."

            if (
                not mailbox_policy.personal_accounts_enabled
                and not mailbox_policy.personal_account_calendars_enabled
            ):
                report.status = "PASS"
                report.status_extended = f"Default OWA mailbox policy '{mailbox_policy.id}' disables personal account integration."

            findings.append(report)

        return findings
