from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.lib.service.scope import manual_account_report
from prowler.providers.cloudflare.services.account.account_client import (
    account_client,
)

MISSING_DATA = (
    "Cannot evaluate two-factor authentication enforcement for account {name}: "
    "the account settings could not be retrieved. Verify that the scanning token "
    "has the Account Settings Read permission."
)


class account_two_factor_enforced(Check):
    """Ensure that two-factor authentication is enforced for all account members.

    When 2FA enforcement is enabled, every member must configure a second factor
    before accessing the account, protecting it against password reuse and
    credential stuffing.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Evaluate the 2FA enforcement setting of every audited account.

        Returns:
            One finding per account: PASS when 2FA is enforced, FAIL when it is
            not, or MANUAL when the setting could not be retrieved.
        """
        findings = []
        for account_id in sorted(account_client.settings_failed_accounts):
            report = manual_account_report(self, account_client, account_id, "")
            report.status_extended = MISSING_DATA.format(name=report.resource_name)
            findings.append(report)

        for account in account_client.accounts:
            if account.enforce_twofactor is None:
                report = manual_account_report(self, account_client, account.id, "")
                report.status_extended = MISSING_DATA.format(name=account.name)
                findings.append(report)
                continue
            report = CheckReportCloudflare(metadata=self.metadata(), resource=account)
            if account.enforce_twofactor:
                report.status = "PASS"
                report.status_extended = f"Account {account.name} enforces two-factor authentication for all members."
            else:
                report.status = "FAIL"
                report.status_extended = f"Account {account.name} does not enforce two-factor authentication for its members."
            findings.append(report)
        return findings
