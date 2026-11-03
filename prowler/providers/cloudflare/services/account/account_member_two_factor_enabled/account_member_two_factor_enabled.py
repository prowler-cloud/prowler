from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.lib.service.scope import manual_account_report
from prowler.providers.cloudflare.services.account.account_client import (
    account_client,
)


class account_member_two_factor_enabled(Check):
    """Ensure that every accepted account member has two-factor authentication enabled."""

    def execute(self) -> list[CheckReportCloudflare]:
        """Evaluate the 2FA status of every accepted account member.

        Pending invitations are not evaluated. Accounts whose members could not
        be listed, or whose members' 2FA status was not returned, get one
        account-level MANUAL finding.

        Returns:
            PASS/FAIL findings per member and MANUAL findings per account.
        """
        findings = []
        for account_id in sorted(account_client.members_failed_accounts):
            report = manual_account_report(self, account_client, account_id, "")
            report.status_extended = (
                f"Cannot evaluate member two-factor authentication for account "
                f"{report.resource_name}: the account members could not be listed. "
                "Verify that the scanning token has the Account Settings Read permission."
            )
            findings.append(report)

        unknown_accounts = set()
        for member in account_client.members:
            if member.status != "accepted":
                continue
            if member.two_factor_enabled is None:
                unknown_accounts.add(member.account_id)
                continue
            report = CheckReportCloudflare(metadata=self.metadata(), resource=member)
            if member.two_factor_enabled:
                report.status = "PASS"
                report.status_extended = f"Account member {member.name} has two-factor authentication enabled."
            else:
                report.status = "FAIL"
                report.status_extended = f"Account member {member.name} does not have two-factor authentication enabled."
            findings.append(report)

        for account_id in sorted(unknown_accounts):
            report = manual_account_report(self, account_client, account_id, "")
            report.status_extended = (
                f"Cannot evaluate two-factor authentication for some members of account "
                f"{report.resource_name}: the API did not return their 2FA status."
            )
            findings.append(report)
        return findings
