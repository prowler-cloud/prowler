from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.account.account_client import (
    account_client,
)


class account_member_two_factor_enabled(Check):
    """Ensure that every accepted account member has two-factor authentication enabled."""

    def execute(self) -> list[CheckReportCloudflare]:
        findings = []
        for member in account_client.members:
            # Pending invitations have no user yet; unknown 2FA status is not reported.
            if member.status != "accepted" or member.two_factor_enabled is None:
                continue
            report = CheckReportCloudflare(metadata=self.metadata(), resource=member)
            if member.two_factor_enabled:
                report.status = "PASS"
                report.status_extended = f"Account member {member.name} has two-factor authentication enabled."
            else:
                report.status = "FAIL"
                report.status_extended = f"Account member {member.name} does not have two-factor authentication enabled."
            findings.append(report)
        return findings
