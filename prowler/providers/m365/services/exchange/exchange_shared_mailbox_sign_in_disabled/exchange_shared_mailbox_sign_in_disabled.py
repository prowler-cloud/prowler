from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.exchange.exchange_client import exchange_client


class exchange_shared_mailbox_sign_in_disabled(Check):
    """
    Verify that sign-in is blocked for all shared mailboxes.

    Shared mailboxes are designed for collaboration and should not permit direct
    sign-in. Users should access shared mailboxes through delegation only, which
    ensures accountability and proper access controls.

    - PASS: Shared mailbox has sign-in blocked (AccountEnabled = False in Entra ID).
    - FAIL: Shared mailbox has sign-in enabled (AccountEnabled = True in Entra ID).
    """

    def execute(self) -> List[CheckReportM365]:
        """
        Execute the check to verify shared mailbox sign-in status.

        Cross-references shared mailboxes from Exchange Online with user accounts
        in Entra ID to determine if sign-in is blocked.

        Returns:
            List[CheckReportM365]: A list of reports with the sign-in status for
            each shared mailbox.
        """
        findings = []

        for shared_mailbox in exchange_client.shared_mailboxes:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=shared_mailbox,
                resource_name=shared_mailbox.name or shared_mailbox.user_principal_name,
                resource_id=shared_mailbox.external_directory_object_id
                or shared_mailbox.identity,
            )

            # Look up the user in Entra ID by their external directory object ID
            entra_user = entra_client.users.get(
                shared_mailbox.external_directory_object_id
            )

            if not entra_user:
                report.status = "FAIL"
                report.status_extended = f"Shared mailbox {shared_mailbox.user_principal_name} could not be found in Entra ID for verification."
            elif entra_user.account_enabled:
                report.status = "FAIL"
                report.status_extended = f"Shared mailbox {shared_mailbox.user_principal_name} has sign-in enabled."
            else:
                report.status = "PASS"
                report.status_extended = f"Shared mailbox {shared_mailbox.user_principal_name} has sign-in blocked."

            findings.append(report)

        return findings
