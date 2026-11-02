from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.account.account_client import (
    account_client,
)


class account_two_factor_enforced(Check):
    """Ensure that two-factor authentication is enforced for all account members.

    When 2FA enforcement is enabled, every member must configure a second factor
    before accessing the account, protecting it against password reuse and
    credential stuffing.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        findings = []
        for account in account_client.accounts:
            if account.enforce_twofactor is None:
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
